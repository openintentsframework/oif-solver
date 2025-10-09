# solver-discovery: Intent Discovery System

## Table of Contents
1. [Executive Summary](#executive-summary)
2. [Architectural Overview](#architectural-overview)
3. [Core Abstractions](#core-abstractions)
4. [Implementation Deep-Dive](#implementation-deep-dive)
5. [Configuration System](#configuration-system)
6. [Error Handling](#error-handling)
7. [Testing Strategy](#testing-strategy)
8. [Performance Considerations](#performance-considerations)
9. [Security Considerations](#security-considerations)
10. [Integration Patterns](#integration-patterns)

---

## Executive Summary

The `solver-discovery` crate is the **intent ingestion layer** for the OIF (Open Intent Framework) solver system. It provides a pluggable, trait-based architecture for discovering EIP-7683 cross-chain orders from multiple sources.

### Key Responsibilities
- **Intent Discovery**: Detect new cross-chain orders from various channels
- **Multi-Source Support**: Both on-chain (blockchain events) and off-chain (HTTP API) sources
- **Intent Normalization**: Convert discovered orders into standardized `Intent` format
- **Lifecycle Management**: Start/stop monitoring with graceful shutdown
- **Validation**: Early-stage validation before intents reach the solver core

### Why Discovery Matters
Discovery is the **entry point** for all intents in the system. The design philosophy is:
- **Single Responsibility**: Discovery owns intent ingestion, solver-service owns orchestration
- **Extensibility**: Easy to add new discovery sources (webhooks, message queues, etc.)
- **Independence**: Can be deployed/scaled separately from solver logic
- **Consistency**: All intents pass through the same pipeline regardless of source

---

## Architectural Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    DISCOVERY SERVICE                         │
│                                                              │
│  ┌────────────────┐              ┌────────────────┐        │
│  │   On-Chain     │              │   Off-Chain    │        │
│  │   Discovery    │              │   Discovery    │        │
│  │  (EIP-7683)    │              │  (HTTP API)    │        │
│  └───────┬────────┘              └────────┬───────┘        │
│          │                                 │                │
│          │  Events via                     │  Orders via    │
│          │  WebSocket/Polling              │  POST /intent  │
│          │                                 │                │
│          └────────────┬────────────────────┘                │
│                       │                                     │
│                       ▼                                     │
│            ┌──────────────────────┐                        │
│            │  Intent Normalization│                        │
│            │   & Validation       │                        │
│            └──────────┬───────────┘                        │
│                       │                                     │
│                       ▼                                     │
│            ┌──────────────────────┐                        │
│            │  mpsc::UnboundedSender│                       │
│            │    (Intent Channel)  │                        │
│            └──────────┬───────────┘                        │
└────────────────────────┼────────────────────────────────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │   Solver Engine      │
              │  (solver-core)       │
              └──────────────────────┘
```

### Component Breakdown

```rust
// Core trait all implementations must satisfy
pub trait DiscoveryInterface: Send + Sync {
    fn config_schema(&self) -> Box<dyn ConfigSchema>;
    async fn start_monitoring(&self, sender: mpsc::UnboundedSender<Intent>) 
        -> Result<(), DiscoveryError>;
    async fn stop_monitoring(&self) -> Result<(), DiscoveryError>;
    fn get_url(&self) -> Option<String> { None }
}
```

**Design Rationale:**
1. **Async-first**: All operations are async to support I/O-bound operations (RPC calls, HTTP servers)
2. **Channel-based**: Uses mpsc unbounded channels for backpressure-free intent streaming
3. **Send + Sync**: Required for multi-threaded Tokio runtime
4. **Configuration Schema**: Each implementation declares its own config requirements

---

## Core Abstractions

### 1. DiscoveryInterface Trait

```rust:1:80:/Users/nahimdhaney/openzeppelin/oif-solver/crates/solver-discovery/src/lib.rs
//! Intent discovery module for the OIF solver system.
//!
//! This module handles the discovery of new intents from various implementations.
//! It provides abstractions for different discovery mechanisms such as
//! on-chain event monitoring, off-chain APIs, or other intent implementations.

use async_trait::async_trait;
use solver_types::{ConfigSchema, ImplementationRegistry, Intent, NetworksConfig};
use std::collections::HashMap;
use thiserror::Error;
use tokio::sync::mpsc;

/// Re-export implementations
pub mod implementations {
	pub mod onchain {
		pub mod _7683;
	}
	pub mod offchain {
		pub mod _7683;
	}
}

/// Errors that can occur during intent discovery operations.
#[derive(Debug, Error)]
pub enum DiscoveryError {
	/// Error that occurs when connecting to a discovery implementation fails.
	#[error("Connection error: {0}")]
	Connection(String),
	/// Error that occurs when trying to start monitoring on an already active implementation.
	#[error("Already monitoring")]
	AlreadyMonitoring,
	/// Error that occurs when parsing or decoding data fails.
	#[error("Parse error: {0}")]
	ParseError(String),
	/// Error that occurs when validating intent data.
	#[error("Validation error: {0}")]
	ValidationError(String),
}

/// Trait defining the interface for intent discovery implementations.
///
/// This trait must be implemented by any discovery implementation that wants to
/// integrate with the solver system. It provides methods for starting and
/// stopping intent monitoring.
#[async_trait]
pub trait DiscoveryInterface: Send + Sync {
	/// Returns the configuration schema for this discovery implementation.
	///
	/// This allows each implementation to define its own configuration requirements
	/// with specific validation rules. The schema is used to validate TOML configuration
	/// before initializing the discovery implementation.
	fn config_schema(&self) -> Box<dyn ConfigSchema>;

	/// Starts monitoring for new intents from this implementation.
	///
	/// Discovered intents are sent through the provided channel. The implementation
	/// should continue monitoring until stop_monitoring is called or an error occurs.
	async fn start_monitoring(
		&self,
		sender: mpsc::UnboundedSender<Intent>,
	) -> Result<(), DiscoveryError>;

	/// Stops monitoring for new intents from this implementation.
	///
	/// This method should cleanly shut down any active monitoring tasks
	/// and release associated resources.
	async fn stop_monitoring(&self) -> Result<(), DiscoveryError>;

	/// Returns the URL for external API access if this discovery implementation provides one.
	///
	/// This is primarily used by offchain discovery implementations that expose
	/// an HTTP API for intent submission. Most implementations will return None.
	///
	/// # Returns
	/// * `Some(String)` - The URL for the discovery service API
	/// * `None` - If this implementation doesn't provide an external API
	fn get_url(&self) -> Option<String> {
		None
	}
}
```

**Key Design Decisions:**

1. **config_schema() returns Box&lt;dyn ConfigSchema&gt;**: Enables runtime configuration validation with implementation-specific rules
2. **start_monitoring() takes UnboundedSender**: Non-blocking intent streaming; solver can process at its own pace
3. **stop_monitoring() is async**: Allows graceful cleanup of async tasks (WebSocket connections, HTTP servers)
4. **get_url() is optional**: Only off-chain implementations need to expose an API endpoint

### 2. DiscoveryService

```rust:114:173:/Users/nahimdhaney/openzeppelin/oif-solver/crates/solver-discovery/src/lib.rs
/// Service that manages multiple intent discovery implementations.
///
/// The DiscoveryService coordinates multiple discovery implementations, allowing
/// the solver to find intents from various channels simultaneously.
pub struct DiscoveryService {
	/// Map of implementation names to their interfaces.
	implementations: HashMap<String, Box<dyn DiscoveryInterface>>,
}

impl DiscoveryService {
	/// Creates a new DiscoveryService with the specified implementations.
	///
	/// Each implementation will be monitored independently when monitoring is started.
	pub fn new(implementations: HashMap<String, Box<dyn DiscoveryInterface>>) -> Self {
		Self { implementations }
	}

	/// Gets a specific discovery implementation by name.
	///
	/// Returns None if the implementation doesn't exist.
	pub fn get(&self, name: &str) -> Option<&dyn DiscoveryInterface> {
		self.implementations.get(name).map(|b| b.as_ref())
	}

	/// Gets the URL for a specific discovery implementation.
	///
	/// Returns None if the implementation doesn't exist or doesn't provide a URL.
	pub fn get_url(&self, implementation_name: &str) -> Option<String> {
		self.implementations
			.get(implementation_name)
			.and_then(|impl_| impl_.get_url())
	}

	/// Starts monitoring on all configured discovery implementations.
	///
	/// All discovered intents from any implementation will be sent through the
	/// provided channel. If any implementation fails to start, the entire operation
	/// fails and no implementations will be monitoring.
	pub async fn start_all(
		&self,
		sender: mpsc::UnboundedSender<Intent>,
	) -> Result<(), DiscoveryError> {
		for implementation in self.implementations.values() {
			implementation.start_monitoring(sender.clone()).await?;
		}
		Ok(())
	}

	/// Stops monitoring on all active discovery implementations.
	///
	/// This method attempts to stop all implementations, even if some fail.
	/// The first error encountered is returned, but all implementations are
	/// attempted to be stopped.
	pub async fn stop_all(&self) -> Result<(), DiscoveryError> {
		for implementation in self.implementations.values() {
			implementation.stop_monitoring().await?;
		}
		Ok(())
	}
}
```

**Service Layer Responsibilities:**
- **Multiplexing**: Manages multiple discovery sources simultaneously
- **Unified Channel**: All implementations send to the same Intent channel
- **Lifecycle Management**: Start/stop all implementations as a unit
- **Discovery**: Query implementations by name or URL

### 3. Factory Pattern

```rust:82:112:/Users/nahimdhaney/openzeppelin/oif-solver/crates/solver-discovery/src/lib.rs
/// Type alias for discovery factory functions.
///
/// This is the function signature that all discovery implementations must provide
/// to create instances of their discovery interface.
pub type DiscoveryFactory =
	fn(&toml::Value, &NetworksConfig) -> Result<Box<dyn DiscoveryInterface>, DiscoveryError>;

/// Registry trait for discovery implementations.
///
/// This trait extends the base ImplementationRegistry to specify that
/// discovery implementations must provide a DiscoveryFactory.
pub trait DiscoveryRegistry: ImplementationRegistry<Factory = DiscoveryFactory> {}

/// Get all registered discovery implementations.
///
/// Returns a vector of (name, factory) tuples for all available discovery implementations.
/// This is used by the factory registry to automatically register all implementations.
pub fn get_all_implementations() -> Vec<(&'static str, DiscoveryFactory)> {
	use implementations::{offchain, onchain};

	vec![
		(
			onchain::_7683::Registry::NAME,
			onchain::_7683::Registry::factory(),
		),
		(
			offchain::_7683::Registry::NAME,
			offchain::_7683::Registry::factory(),
		),
	]
}
```

**Factory Pattern Benefits:**
- **Deferred Instantiation**: Implementations created only when needed
- **Configuration-Driven**: Factory receives TOML config and NetworksConfig
- **Extensibility**: New implementations just add to `get_all_implementations()`
- **Type Safety**: Compile-time guarantee that factories return correct types

---

## Implementation Deep-Dive

### On-Chain Discovery (EIP-7683)

#### Architecture

```
┌──────────────────────────────────────────────────────────┐
│              Eip7683Discovery                             │
│                                                           │
│  ┌─────────────┐         ┌─────────────┐                │
│  │  HTTP Mode  │         │  WS Mode    │                │
│  │  (Polling)  │         │(Subscriptions)│              │
│  └──────┬──────┘         └──────┬──────┘                │
│         │                       │                        │
│         │ Every N seconds       │ Real-time events       │
│         │                       │                        │
│         ▼                       ▼                        │
│  ┌──────────────────────────────────────┐               │
│  │  Filter Open Events                   │              │
│  │  topic[0] = Open.SIGNATURE_HASH      │              │
│  │  address = input_settler_address      │              │
│  └──────────┬────────────────────────────┘              │
│             │                                            │
│             ▼                                            │
│  ┌──────────────────────────────────────┐               │
│  │  Parse Log → StandardOrder           │               │
│  │  Decode ABI-encoded event data       │               │
│  └──────────┬────────────────────────────┘              │
│             │                                            │
│             ▼                                            │
│  ┌──────────────────────────────────────┐               │
│  │  Convert StandardOrder → Intent      │               │
│  │  Extract inputs/outputs              │               │
│  │  Add metadata (timestamp, source)    │               │
│  └──────────┬────────────────────────────┘              │
│             │                                            │
│             ▼                                            │
│  ┌──────────────────────────────────────┐               │
│  │  Send to Intent Channel              │               │
│  └──────────────────────────────────────┘               │
└──────────────────────────────────────────────────────────┘
```

#### Core Structure

```rust:71:94:/Users/nahimdhaney/openzeppelin/oif-solver/crates/solver-discovery/src/implementations/onchain/_7683.rs
/// EIP-7683 on-chain discovery implementation.
///
/// This implementation monitors blockchain events for new EIP-7683 cross-chain
/// orders and converts them into intents for the solver to process.
/// Supports monitoring multiple chains concurrently using either HTTP polling
/// or WebSocket subscriptions (when polling_interval_secs = 0).
pub struct Eip7683Discovery {
	/// RPC providers for each monitored network.
	providers: HashMap<u64, ProviderType>,
	/// The chain IDs being monitored.
	network_ids: Vec<u64>,
	/// Networks configuration for settler lookups.
	networks: NetworksConfig,
	/// The last processed block number for each chain (HTTP mode only).
	last_blocks: Arc<Mutex<HashMap<u64, u64>>>,
	/// Flag indicating if monitoring is active.
	is_monitoring: Arc<AtomicBool>,
	/// Handles for monitoring tasks.
	monitoring_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
	/// Channel for signaling monitoring shutdown.
	stop_signal: Arc<Mutex<Option<broadcast::Sender<()>>>>,
	/// Polling interval for monitoring loop in seconds (0 = WebSocket mode).
	polling_interval_secs: u64,
}
```

**Field Analysis:**

| Field | Type | Purpose | Design Rationale |
|-------|------|---------|------------------|
| `providers` | `HashMap<u64, ProviderType>` | RPC providers per chain | Enum allows HTTP or WebSocket per chain |
| `network_ids` | `Vec<u64>` | Chains to monitor | Immutable after construction |
| `last_blocks` | `Arc<Mutex<HashMap<u64, u64>>>` | Block tracking (HTTP mode) | Shared across async tasks; prevents duplicate event processing |
| `is_monitoring` | `Arc<AtomicBool>` | Active state flag | Lock-free reads; prevents double-start |
| `monitoring_handles` | `Arc<Mutex<Vec<JoinHandle<()>>>>` | Task handles | Enables graceful shutdown by awaiting completion |
| `stop_signal` | `Arc<Mutex<Option<broadcast::Sender<()>>>>` | Shutdown broadcast | One signal stops all chain monitors |
| `polling_interval_secs` | `u64` | Polling frequency | 0 = WebSocket mode, >0 = polling interval |

#### Event Structure

The EIP-7683 `Open` event is defined using the Alloy `sol!` macro:

```rust:26:58:/Users/nahimdhaney/openzeppelin/oif-solver/crates/solver-discovery/src/implementations/onchain/_7683.rs
// Event definition for the OIF contracts.
//
// We need to redefine the types here because sol! macro doesn't support external type references.
// These match the types in solver_types::standards::eip7683::interfaces.
sol! {
	/// MandateOutput specification for cross-chain orders.
	struct SolMandateOutput {
		bytes32 oracle;
		bytes32 settler;
		uint256 chainId;
		bytes32 token;
		uint256 amount;
		bytes32 recipient;
		bytes call;
		bytes context;
	}

	/// StandardOrder structure used in the OIF contracts.
	struct StandardOrder {
		address user;
		uint256 nonce;
		uint256 originChainId;
		uint32 expires;
		uint32 fillDeadline;
		address inputOracle;
		uint256[2][] inputs;
		SolMandateOutput[] outputs;
	}

	/// Event emitted when a new order is opened.
	/// The order parameter is the StandardOrder struct (not indexed).
	event Open(bytes32 indexed orderId, StandardOrder order);
}
```

**Why Redefine Types?**
The `sol!` macro generates Rust types from Solidity definitions but doesn't support importing types from other crates. Even though `solver_types` has the same definitions, we must redefine them here for the macro to work. The types are structurally identical.

#### Polling Mode Implementation

```rust:266:354:/Users/nahimdhaney/openzeppelin/oif-solver/crates/solver-discovery/src/implementations/onchain/_7683.rs
	/// Polling-based monitoring for a single chain.
	///
	/// Periodically polls the blockchain for new Open events and sends
	/// discovered intents through the provided channel.
	async fn monitor_chain_polling(
		provider: DynProvider,
		chain_id: u64,
		networks: NetworksConfig,
		last_blocks: Arc<Mutex<HashMap<u64, u64>>>,
		sender: mpsc::UnboundedSender<Intent>,
		mut stop_rx: broadcast::Receiver<()>,
		polling_interval_secs: u64,
	) {
		let mut interval =
			tokio::time::interval(std::time::Duration::from_secs(polling_interval_secs));

		// Set the interval to skip missed ticks instead of bursting
		interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
		// Skip the first immediate tick to avoid immediate polling
		interval.tick().await;

		loop {
			tokio::select! {
				_ = interval.tick() => {
					// Get last processed block for this chain
					let last_block_num = {
						let blocks = last_blocks.lock().await;
						*blocks.get(&chain_id).unwrap_or(&0)
					};

					// Get current block
					let current_block = match provider.get_block_number().await {
						Ok(block) => block,
						Err(e) => {
							tracing::error!(chain = chain_id, "Failed to get block number: {}", e);
							continue;
						}
					};

					if current_block <= last_block_num {
						continue; // No new blocks
					}

					// Create filter for Open events
					let open_sig = Open::SIGNATURE_HASH;

					// Get the input settler address for this chain
					let settler_address = match networks.get(&chain_id) {
						Some(network) => {
							if network.input_settler_address.0.len() != 20 {
								tracing::error!(chain = chain_id, "Invalid settler address length");
								continue;
							}
							AlloyAddress::from_slice(&network.input_settler_address.0)
						}
						None => {
							tracing::error!("Chain ID {} not found in networks config", chain_id);
							continue;
						}
					};

					let filter = Filter::new()
						.address(vec![settler_address])
						.event_signature(vec![open_sig])
						.from_block(last_block_num + 1)
						.to_block(current_block);

					// Get logs
					let logs = match provider.get_logs(&filter).await {
						Ok(logs) => logs,
						Err(e) => {
							tracing::error!(chain = chain_id, "Failed to get logs: {}", e);
							continue;
						}
					};

					// Process discovered logs
					Self::process_discovered_logs(logs, &sender, chain_id);

					// Update last block for this chain
					last_blocks.lock().await.insert(chain_id, current_block);
				}
				_ = stop_rx.recv() => {
					tracing::info!(chain = chain_id, "Stopping monitor");
					break;
				}
			}
		}
	}
```

**Polling Strategy Analysis:**

1. **Interval Management**:
   - Uses `tokio::time::interval` for periodic ticking
   - `MissedTickBehavior::Skip`: If processing takes longer than the interval, skip missed ticks (don't burst)
   - Initial `tick().await` consumes the immediate first tick

2. **Block Range Querying**:
   - Tracks `last_block_num` per chain to avoid reprocessing
   - Queries `from_block(last_block_num + 1)` to `to_block(current_block)`
   - Updates `last_blocks` only after successful processing

3. **Event Filtering**:
   ```rust
   Filter::new()
       .address(vec![settler_address])      // Only from InputSettler contract
       .event_signature(vec![open_sig])     // Only Open events
       .from_block(last_block_num + 1)
       .to_block(current_block)
   ```

4. **Error Handling**:
   - RPC failures: Log error, continue polling (transient network issues)
   - Invalid settler address: Log error, continue (configuration issue)
   - Parse failures: Silently skip (handled in `process_discovered_logs`)

5. **Graceful Shutdown**:
   - `tokio::select!` listens for stop signal
   - Exits loop cleanly on shutdown

#### WebSocket Mode Implementation

```rust:356:416:/Users/nahimdhaney/openzeppelin/oif-solver/crates/solver-discovery/src/implementations/onchain/_7683.rs
	/// Subscription-based monitoring for a single chain.
	///
	/// Uses WebSocket connection to subscribe to Open events via eth_subscribe
	/// and processes events as they arrive in real-time.
	async fn monitor_chain_subscription(
		provider: DynProvider,
		chain_id: u64,
		networks: NetworksConfig,
		sender: mpsc::UnboundedSender<Intent>,
		mut stop_rx: broadcast::Receiver<()>,
	) {
		// Get the input settler address for this chain
		let settler_address = match networks.get(&chain_id) {
			Some(network) => {
				if network.input_settler_address.0.len() != 20 {
					tracing::error!(chain = chain_id, "Invalid settler address length");
					return;
				}
				AlloyAddress::from_slice(&network.input_settler_address.0)
			},
			None => {
				tracing::error!("Chain ID {} not found in networks config", chain_id);
				return;
			},
		};

		// Create filter for Open events
		let open_sig = Open::SIGNATURE_HASH;
		let filter = Filter::new()
			.address(vec![settler_address])
			.event_signature(vec![open_sig]);

		// Subscribe to logs
		let subscription = match provider.subscribe_logs(&filter).await {
			Ok(sub) => sub,
			Err(e) => {
				tracing::error!(chain = chain_id, "Failed to subscribe to logs: {}", e);
				return;
			},
		};

		let mut stream = subscription.into_stream();
		tracing::info!(
			chain = chain_id,
			"WebSocket monitoring started for settler {}",
			settler_address
		);

		loop {
			tokio::select! {
				Some(log) = stream.next() => {
					// Process single log as it arrives
					Self::process_discovered_logs(vec![log], &sender, chain_id);
				}
				_ = stop_rx.recv() => {
					tracing::info!(chain = chain_id, "Stopping WebSocket monitor");
					break;
				}
			}
		}
	}
```

**WebSocket vs. Polling Trade-offs:**

| Aspect | WebSocket (polling_interval_secs = 0) | HTTP Polling (polling_interval_secs > 0) |
|--------|---------------------------------------|------------------------------------------|
| **Latency** | ~1-2 seconds (real-time) | Polling interval (default 3s) |
| **RPC Load** | Minimal (subscription only) | High (constant `eth_getLogs` calls) |
| **Connection** | Persistent WebSocket | Short-lived HTTP |
| **Reliability** | Connection can drop | Stateless, self-healing |
| **Block Tracking** | Not needed | Must track `last_blocks` |
| **Use Case** | Low-latency, stable RPC | Unreliable networks, rate-limited RPCs |

**When to Use Each Mode:**
- **WebSocket**: Production with reliable RPC provider (Infura, Alchemy)
- **Polling**: Development, public RPCs, or networks without WebSocket support

#### Event Parsing

```rust:171:249:/Users/nahimdhaney/openzeppelin/oif-solver/crates/solver-discovery/src/implementations/onchain/_7683.rs
	/// Parses an Open event log into an Intent.
	///
	/// Decodes the EIP-7683 event data and converts it into the internal
	/// Intent format used by the solver.
	fn parse_open_event(log: &Log) -> Result<Intent, DiscoveryError> {
		// Convert RPC log to primitives log for decoding
		let prim_log = PrimLog {
			address: log.address(),
			data: LogData::new_unchecked(log.topics().to_vec(), log.data().data.clone()),
		};

		// Decode the Open event
		let open_event = Open::decode_log_validate(&prim_log).map_err(|e| {
			DiscoveryError::ParseError(format!("Failed to decode Open event: {}", e))
		})?;

		let order_id = open_event.orderId;
		let order = open_event.order.clone();

		// Validate that order has outputs
		if order.outputs.is_empty() {
			return Err(DiscoveryError::ValidationError(
				"Order must have at least one output".to_string(),
			));
		}

		// Get the ABI-encoded bytes
		let abi_encoded_bytes = alloy_primitives::Bytes::from(order.abi_encode());

		// Convert to the format expected by the order implementation
		// The order implementation expects Eip7683OrderData with specific fields
		let order_data = Eip7683OrderData {
			user: with_0x_prefix(&hex::encode(order.user)),
			nonce: order.nonce,
			origin_chain_id: order.originChainId,
			expires: order.expires,
			fill_deadline: order.fillDeadline,
			input_oracle: with_0x_prefix(&hex::encode(order.inputOracle)),
			inputs: order.inputs.clone(),
			order_id: order_id.0,
			gas_limit_overrides: GasLimitOverrides::default(),
			outputs: order
				.outputs
				.iter()
				.map(|output| MandateOutput {
					oracle: output.oracle.0,
					settler: output.settler.0,
					chain_id: output.chainId,
					token: output.token.0,
					amount: output.amount,
					recipient: output.recipient.0,
					call: output.call.clone().into(),
					context: output.context.clone().into(),
				})
				.collect::<Vec<_>>(),
			// Use consistent hex encoding with 0x prefix
			raw_order_data: Some(with_0x_prefix(&hex::encode(&abi_encoded_bytes))),
			signature: None,
			sponsor: None,
			lock_type: Some(LockType::Permit2Escrow),
		};

		Ok(Intent {
			id: hex::encode(order_id),
			source: "on-chain".to_string(),
			standard: "eip7683".to_string(),
			metadata: IntentMetadata {
				requires_auction: false,
				exclusive_until: None,
				discovered_at: current_timestamp(),
			},
			data: serde_json::to_value(&order_data).map_err(|e| {
				DiscoveryError::ParseError(format!("Failed to serialize order data: {}", e))
			})?,
			order_bytes: abi_encoded_bytes,
			quote_id: None,
			lock_type: LockType::Permit2Escrow.to_string(),
		})
	}
```

**Parsing Pipeline:**

```
Log (alloy_rpc_types::Log)
    │
    ▼
PrimLog (alloy_primitives::Log)
    │  [Convert for decoding]
    ▼
Open::decode_log_validate()
    │  [ABI decode using Alloy]
    ▼
Open { orderId, order: StandardOrder }
    │
    ▼
Validation
    │  [Check order.outputs not empty]
    ▼
Eip7683OrderData
    │  [Map fields, add metadata]
    ▼
Intent
    │  [Serialize to JSON, add order_bytes]
    ▼
Send to channel
```

**Key Transformations:**

1. **Address Encoding**:
   ```rust
   user: with_0x_prefix(&hex::encode(order.user))
   ```
   All addresses are hex-encoded with "0x" prefix for consistency.

2. **bytes32 Handling**:
   ```rust
   oracle: output.oracle.0  // Extract inner [u8; 32] from FixedBytes<32>
   ```
   Alloy's `B256` type is unwrapped to raw byte arrays.

3. **Order ID**:
   - On-chain events already have the order ID (indexed parameter)
   - Off-chain submissions must compute it via contract call

4. **Lock Type**:
   - On-chain events always assume `Permit2Escrow`
   - Off-chain submissions derive lock type from order structure

---

### Off-Chain Discovery (HTTP API)

#### Architecture

```
┌──────────────────────────────────────────────────────────────┐
│              Eip7683OffchainDiscovery                         │
│                                                               │
│  ┌────────────────────────────────────────────────────┐     │
│  │             Axum HTTP Server                        │     │
│  │  POST /intent                                       │     │
│  │  ┌──────────────────────────────────────┐          │     │
│  │  │ handle_intent_submission             │          │     │
│  │  └─────────────┬────────────────────────┘          │     │
│  │                │                                    │     │
│  │                ▼                                    │     │
│  │  ┌──────────────────────────────────────┐          │     │
│  │  │ Deserialize PostOrderRequest         │          │     │
│  │  │ - order: OifOrder                    │          │     │
│  │  │ - signature: Bytes                   │          │     │
│  │  │ - quote_id: Option<String>           │          │     │
│  │  └─────────────┬────────────────────────┘          │     │
│  │                │                                    │     │
│  │                ▼                                    │     │
│  │  ┌──────────────────────────────────────┐          │     │
│  │  │ Convert OifOrder → StandardOrder     │          │     │
│  │  └─────────────┬────────────────────────┘          │     │
│  │                │                                    │     │
│  │                ▼                                    │     │
│  │  ┌──────────────────────────────────────┐          │     │
│  │  │ Extract sponsor from signature       │          │     │
│  │  │ Derive lock_type from order          │          │     │
│  │  └─────────────┬────────────────────────┘          │     │
│  │                │                                    │     │
│  │                ▼                                    │     │
│  │  ┌──────────────────────────────────────┐          │     │
│  │  │ order_to_intent()                    │          │     │
│  │  │ - Compute order ID via RPC           │          │     │
│  │  │ - Parse inputs/outputs               │          │     │
│  │  │ - Create Intent with metadata        │          │     │
│  │  └─────────────┬────────────────────────┘          │     │
│  │                │                                    │     │
│  │                ▼                                    │     │
│  │  ┌──────────────────────────────────────┐          │     │
│  │  │ Send to Intent Channel               │          │     │
│  │  └──────────────────────────────────────┘          │     │
│  │                                                     │     │
│  └────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────┘
```

#### Core Structure

```rust:271:284:/Users/nahimdhaney/openzeppelin/oif-solver/crates/solver-discovery/src/implementations/offchain/_7683.rs
#[derive(Debug)]
pub struct Eip7683OffchainDiscovery {
	/// API server configuration
	api_host: String,
	api_port: u16,
	/// RPC providers for each supported network
	providers: HashMap<u64, DynProvider>,
	/// Networks configuration for settler lookups
	networks: NetworksConfig,
	/// Flag indicating if the server is running
	is_running: Arc<AtomicBool>,
	/// Channel for signaling server shutdown
	shutdown_signal: Arc<Mutex<Option<mpsc::Sender<()>>>>,
}
```

**Why HTTP API in Discovery Module?**

From the module documentation:

```rust:7:16:/Users/nahimdhaney/openzeppelin/oif-solver/crates/solver-discovery/src/implementations/offchain/_7683.rs
//! The API is exposed directly from the discovery module rather than solver-service for several key reasons:
//!
//! 1. **Consistency**: Discovery is the entry point for ALL intents - both on-chain and off-chain
//! 2. **Single Responsibility**: Each module has a clear purpose:
//!    - solver-discovery: Intent ingestion and lifecycle management
//!    - solver-service: Solver orchestration, health, metrics, quotes
//! 3. **Extensibility**: Provides a pattern for custom discovery implementations (e.g., webhooks, other APIs)
//! 4. **Independence**: Discovery can be deployed/scaled separately from the solver service
//! 5. **Source of Truth**: Discovery owns the intent lifecycle and should expose intent-related endpoints
```

#### API Endpoint: POST /intent

**Request Format:**

```json
{
  "order": {
    // OifOrder variant (Permit2Escrow, Eip3009Escrow, ResourceLock, or Generic)
    "orderDataType": "0x...",
    "orderData": "0x..."
  },
  "signature": "0x...",  // EIP-712 signature
  "quoteId": "optional-quote-id",
  "originSubmission": null
}
```

**Response Format:**

```json
{
  "orderId": "0x1234...",
  "status": "received" | "rejected" | "error",
  "message": "Basic validation passed, pending profitability validation...",
  "order": {
    // Parsed StandardOrder as JSON
    "user": "0x...",
    "nonce": "123",
    ...
  }
}
```

#### Request Handler

```rust:666:777:/Users/nahimdhaney/openzeppelin/oif-solver/crates/solver-discovery/src/implementations/offchain/_7683.rs
async fn handle_intent_submission(
	State(state): State<ApiState>,
	Json(request): Json<PostOrderRequest>,
) -> impl IntoResponse {
	// Convert OifOrder to StandardOrder
	let order = match StandardOrder::try_from(&request.order) {
		Ok(order) => order,
		Err(e) => {
			tracing::warn!(error = %e, "Failed to convert OifOrder to StandardOrder");
			return (
				StatusCode::BAD_REQUEST,
				Json(IntentResponse {
					order_id: None,
					status: IntentResponseStatus::Rejected,
					message: Some(format!("Failed to convert order: {}", e)),
					order: None,
				}),
			)
				.into_response();
		},
	};

	// Serialize the parsed order once for all responses
	let order_json = match serde_json::to_value(ApiStandardOrder::from(&order)) {
		Ok(json) => Some(json),
		Err(e) => {
			tracing::warn!(error = %e, "Failed to serialize order");
			None
		},
	};

	let signature = request.signature;

	// Extract sponsor from the order using our new helper
	let sponsor = match request.order.extract_sponsor(Some(&signature)) {
		Ok(sponsor) => sponsor,
		Err(e) => {
			tracing::warn!(error = %e, "Failed to extract sponsor from order");
			return (
				StatusCode::BAD_REQUEST,
				Json(IntentResponse {
					order_id: None,
					status: IntentResponseStatus::Rejected,
					message: Some(format!("Failed to extract sponsor: {}", e)),
					order: order_json,
				}),
			)
				.into_response();
		},
	};

	// Derive lock type from the order
	let lock_type = LockType::from(&request.order);

	// Convert to intent
	match Eip7683OffchainDiscovery::order_to_intent(
		&order,
		&sponsor,
		&signature,
		lock_type,
		&state.providers,
		&state.networks,
		request.quote_id,
	)
	.await
	{
		Ok(intent) => {
			let order_id = intent.id.clone();

			// Send intent through channel
			if let Err(e) = state.intent_sender.send(intent) {
				tracing::warn!(error = %e, "Failed to send intent to solver channel");
				return (
					StatusCode::INTERNAL_SERVER_ERROR,
					Json(IntentResponse {
						order_id: Some(order_id),
						status: IntentResponseStatus::Error,
						message: Some(format!("Failed to process intent: {}", e)),
						order: order_json.clone(),
					}),
				)
					.into_response();
			}

			(
				StatusCode::ACCEPTED,
				Json(IntentResponse {
					order_id: Some(order_id),
					status: IntentResponseStatus::Received,
					message: Some(
						"Basic validation passed, pending profitability validation and oracle route validation".to_string(),
					),
					order: order_json,
				}),
			)
				.into_response()
		},
		Err(e) => {
			tracing::warn!(error = %e, "Failed to convert order to intent");
			(
				StatusCode::BAD_REQUEST,
				Json(IntentResponse {
					order_id: None,
					status: IntentResponseStatus::Rejected,
					message: Some(e.to_string()),
					order: order_json,
				}),
			)
				.into_response()
		},
	}
}
```

**Handler Flow:**

1. **Deserialize**: Axum extracts `PostOrderRequest` from JSON body
2. **Convert Order**: `OifOrder` → `StandardOrder` (validates order structure)
3. **Extract Sponsor**: Recover signer from signature
4. **Derive Lock Type**: Determine custody mechanism from order type
5. **Compute Order ID**: Call settler contract via RPC
6. **Create Intent**: Bundle everything into `Intent` format
7. **Send**: Non-blocking send to intent channel
8. **Respond**: Return order ID and status to client

**Error Handling Strategy:**

| Error Type | HTTP Status | Example |
|------------|-------------|---------|
| Invalid order format | 400 Bad Request | Malformed JSON, missing fields |
| Signature extraction failed | 400 Bad Request | Invalid signature, wrong signer |
| Order ID computation failed | 400 Bad Request | RPC failure, invalid settler |
| Channel send failed | 500 Internal Server Error | Solver shutdown, channel closed |

#### Order ID Computation

```rust:505:577:/Users/nahimdhaney/openzeppelin/oif-solver/crates/solver-discovery/src/implementations/offchain/_7683.rs
	/// Computes order ID from order data.
	///
	/// Determines which settler interface to use based on the lock_type and calls
	/// the appropriate `orderIdentifier` function to compute the canonical order ID.
	///
	/// # Lock Types
	///
	/// * 1 = permit2-escrow (uses IInputSettlerEscrow)
	/// * 2 = 3009-escrow (uses IInputSettlerEscrow)
	/// * 3 = resource-lock/TheCompact (uses IInputSettlerCompact)
	/// * Other values default to IInputSettlerEscrow
	///
	/// # Arguments
	///
	/// * `order_bytes` - The encoded order bytes to compute ID for
	/// * `provider` - RPC provider for calling the settler contract
	/// * `settler_address` - Address of the appropriate settler contract
	/// * `lock_type` - The custody/lock type determining which interface to use
	///
	/// # Returns
	///
	/// Returns the 32-byte order ID.
	///
	/// # Errors
	///
	/// Returns `DiscoveryError::Connection` if the contract call fails or
	/// `DiscoveryError::ParseError` if order decoding fails for compact orders.
	async fn compute_order_id(
		order_bytes: &Bytes,
		provider: &DynProvider,
		settler_address: AlloyAddress,
		lock_type: LockType,
	) -> Result<[u8; 32], DiscoveryError> {
		match lock_type {
			LockType::ResourceLock => {
				// Resource Lock (TheCompact) - use IInputSettlerCompact
				let std_order = StandardOrder::abi_decode_validate(order_bytes).map_err(|e| {
					DiscoveryError::ParseError(format!("Failed to decode StandardOrder: {}", e))
				})?;
				let compact = IInputSettlerCompact::new(settler_address, provider);
				let resp = compact
					.orderIdentifier(std_order)
					.call()
					.await
					.map_err(|e| {
						DiscoveryError::Connection(format!(
							"Failed to get order ID from compact contract: {}",
							e
						))
					})?;
				Ok(resp.0)
			},
			LockType::Permit2Escrow | LockType::Eip3009Escrow => {
				// Escrow types - use IInputSettlerEscrow
				// Decode the order bytes to StandardOrder
				let std_order = StandardOrder::abi_decode_validate(order_bytes).map_err(|e| {
					DiscoveryError::ParseError(format!("Failed to decode StandardOrder: {}", e))
				})?;
				let escrow = IInputSettlerEscrow::new(settler_address, provider);
				let resp = escrow
					.orderIdentifier(std_order)
					.call()
					.await
					.map_err(|e| {
						DiscoveryError::Connection(format!(
							"Failed to get order ID from escrow contract: {}",
							e
						))
					})?;
				Ok(resp.0)
			},
		}
	}
```

**Why Compute Order ID via Contract?**

The order ID is **deterministic** but **not trivial** to compute:

```solidity
// Simplified order ID computation (actual logic in settler contract)
function orderIdentifier(StandardOrder memory order) public view returns (bytes32) {
    return keccak256(abi.encode(
        order.user,
        order.nonce,
        order.originChainId,
        order.expires,
        order.fillDeadline,
        order.inputOracle,
        order.inputs,
        order.outputs,
        // Additional context...
    ));
}
```

**Benefits of Contract Call:**
- **Correctness**: Guaranteed to match on-chain computation
- **Version Agnostic**: If settler contract changes logic, solver automatically adapts
- **Simplicity**: Don't need to maintain parallel Rust implementation

**Drawbacks:**
- **RPC Dependency**: Requires RPC call for every submission
- **Latency**: Adds 50-200ms to submission time
- **Cost**: Consumes RPC quota (read-only call, no gas cost)

#### Server Lifecycle

```rust:599:637:/Users/nahimdhaney/openzeppelin/oif-solver/crates/solver-discovery/src/implementations/offchain/_7683.rs
	async fn run_server(
		api_host: String,
		api_port: u16,
		intent_sender: mpsc::UnboundedSender<Intent>,
		providers: HashMap<u64, DynProvider>,
		networks: NetworksConfig,
		mut shutdown_rx: mpsc::Receiver<()>,
	) -> Result<(), String> {
		let state = ApiState {
			intent_sender,
			providers,
			networks,
		};

		let app = Router::new()
			.route("/intent", post(handle_intent_submission))
			.layer(CorsLayer::permissive())
			.with_state(state);

		let addr = format!("{}:{}", api_host, api_port)
			.parse::<SocketAddr>()
			.map_err(|e| format!("Invalid address '{}:{}': {}", api_host, api_port, e))?;

		let listener = tokio::net::TcpListener::bind(addr)
			.await
			.map_err(|e| format!("Failed to bind address {}: {}", addr, e))?;

		tracing::info!("EIP-7683 offchain discovery API listening on {}", addr);

		axum::serve(listener, app)
			.with_graceful_shutdown(async move {
				let _ = shutdown_rx.recv().await;
				tracing::info!("Shutting down API server");
			})
			.await
			.map_err(|e| format!("Server error: {}", e))?;

		Ok(())
	}
```

**Server Features:**

1. **Axum Framework**: High-performance async HTTP framework built on Tokio
2. **CORS**: `CorsLayer::permissive()` allows cross-origin requests (useful for web UIs)
3. **Graceful Shutdown**: Server waits for `shutdown_rx` signal, then stops accepting new connections
4. **State Sharing**: `ApiState` is cloned for each request (cheap due to Arc internals)

---

## Configuration System

### Schema-Based Validation

Each discovery implementation defines its own configuration schema:

#### On-Chain Schema

```rust:424:467:/Users/nahimdhaney/openzeppelin/oif-solver/crates/solver-discovery/src/implementations/onchain/_7683.rs
pub struct Eip7683DiscoverySchema;

impl Eip7683DiscoverySchema {
	/// Static validation method for use before instance creation
	pub fn validate_config(config: &toml::Value) -> Result<(), solver_types::ValidationError> {
		let instance = Self;
		instance.validate(config)
	}
}

impl ConfigSchema for Eip7683DiscoverySchema {
	fn validate(&self, config: &toml::Value) -> Result<(), solver_types::ValidationError> {
		let schema = Schema::new(
			// Required fields
			vec![Field::new(
				"network_ids",
				FieldType::Array(Box::new(FieldType::Integer {
					min: Some(1),
					max: None,
				})),
			)
			.with_validator(|value| {
				if let Some(arr) = value.as_array() {
					if arr.is_empty() {
						return Err("network_ids cannot be empty".to_string());
					}
					Ok(())
				} else {
					Err("network_ids must be an array".to_string())
				}
			})],
			// Optional fields
			vec![Field::new(
				"polling_interval_secs",
				FieldType::Integer {
					min: Some(0),                                // 0 = WebSocket mode
					max: Some(MAX_POLLING_INTERVAL_SECS as i64), // Maximum 5 minutes
				},
			)],
		);

		schema.validate(config)
	}
}
```

#### Off-Chain Schema

```rust:789:825:/Users/nahimdhaney/openzeppelin/oif-solver/crates/solver-discovery/src/implementations/offchain/_7683.rs
pub struct Eip7683OffchainDiscoverySchema;

impl Eip7683OffchainDiscoverySchema {
	/// Static validation method for use before instance creation
	pub fn validate_config(config: &toml::Value) -> Result<(), solver_types::ValidationError> {
		let instance = Self;
		instance.validate(config)
	}
}

impl ConfigSchema for Eip7683OffchainDiscoverySchema {
	fn validate(&self, config: &toml::Value) -> Result<(), solver_types::ValidationError> {
		let schema = Schema::new(
			// Required fields
			vec![
				Field::new("api_host", FieldType::String),
				Field::new(
					"api_port",
					FieldType::Integer {
						min: Some(1),
						max: Some(65535),
					},
				),
				Field::new(
					"network_ids",
					FieldType::Array(Box::new(FieldType::Integer {
						min: Some(1),
						max: None,
					})),
				),
			],
			vec![],
		);

		schema.validate(config)
	}
}
```

### Example Configuration

```toml
# config/demo.toml

[discovery.onchain_eip7683]
network_ids = [1, 10, 137, 8453]  # Ethereum, Optimism, Polygon, Base
polling_interval_secs = 3          # Poll every 3 seconds (or 0 for WebSocket)

[discovery.offchain_eip7683]
api_host = "0.0.0.0"              # Bind to all interfaces
api_port = 8081                    # Listen on port 8081
network_ids = [1, 10, 137, 8453]  # Support same networks
```

---

## Error Handling

### Error Types

```rust:23:38:/Users/nahimdhaney/openzeppelin/oif-solver/crates/solver-discovery/src/lib.rs
#[derive(Debug, Error)]
pub enum DiscoveryError {
	/// Error that occurs when connecting to a discovery implementation fails.
	#[error("Connection error: {0}")]
	Connection(String),
	/// Error that occurs when trying to start monitoring on an already active implementation.
	#[error("Already monitoring")]
	AlreadyMonitoring,
	/// Error that occurs when parsing or decoding data fails.
	#[error("Parse error: {0}")]
	ParseError(String),
	/// Error that occurs when validating intent data.
	#[error("Validation error: {0}")]
	ValidationError(String),
}
```

### Error Handling Philosophy

1. **Connection Errors**: Transient RPC/network issues
   - **On-Chain**: Log and continue polling (self-healing)
   - **Off-Chain**: Return 500 to client

2. **Parse Errors**: Invalid event data or order format
   - **On-Chain**: Silently skip (malformed on-chain data is rare)
   - **Off-Chain**: Return 400 to client with details

3. **Validation Errors**: Configuration or business logic issues
   - **On-Chain**: Fail fast during initialization
   - **Off-Chain**: Return 400 to client

4. **AlreadyMonitoring**: Prevent duplicate monitoring tasks
   - Both implementations: Return error immediately

---

## Testing Strategy

### Unit Tests Coverage

#### On-Chain Discovery Tests

```rust:701:769:/Users/nahimdhaney/openzeppelin/oif-solver/crates/solver-discovery/src/implementations/onchain/_7683.rs
	#[test]
	fn test_config_schema_validation_valid() {
		let config = toml::Value::try_from(HashMap::from([
			(
				"network_ids",
				toml::Value::Array(vec![toml::Value::Integer(1)]),
			),
			("polling_interval_secs", toml::Value::Integer(5)),
		]))
		.unwrap();

		let result = Eip7683DiscoverySchema::validate_config(&config);
		assert!(result.is_ok());
	}

	#[test]
	fn test_config_schema_validation_missing_network_ids() {
		let config = toml::Value::try_from(HashMap::from([(
			"polling_interval_secs",
			toml::Value::Integer(5),
		)]))
		.unwrap();

		let result = Eip7683DiscoverySchema::validate_config(&config);
		assert!(result.is_err());
	}

	#[test]
	fn test_config_schema_validation_empty_network_ids() {
		let config =
			toml::Value::try_from(HashMap::from([("network_ids", toml::Value::Array(vec![]))]))
				.unwrap();

		let result = Eip7683DiscoverySchema::validate_config(&config);
		assert!(result.is_err());
	}

	#[test]
	fn test_config_schema_validation_invalid_polling_interval() {
		let config = toml::Value::try_from(HashMap::from([
			(
				"network_ids",
				toml::Value::Array(vec![toml::Value::Integer(1)]),
			),
			(
				"polling_interval_secs",
				toml::Value::Integer((MAX_POLLING_INTERVAL_SECS + 100) as i64),
			),
		]))
		.unwrap();

		let result = Eip7683DiscoverySchema::validate_config(&config);
		assert!(result.is_err());
	}

	#[test]
	fn test_config_schema_validation_websocket_mode() {
		let config = toml::Value::try_from(HashMap::from([
			(
				"network_ids",
				toml::Value::Array(vec![toml::Value::Integer(1)]),
			),
			("polling_interval_secs", toml::Value::Integer(0)), // WebSocket mode
		]))
		.unwrap();

		let result = Eip7683DiscoverySchema::validate_config(&config);
		assert!(result.is_ok());
	}
```

#### Off-Chain Discovery Tests

```rust:1221:1308:/Users/nahimdhaney/openzeppelin/oif-solver/crates/solver-discovery/src/implementations/offchain/_7683.rs
	#[tokio::test]
	async fn test_discovery_interface_start_stop() {
		let networks = create_test_networks_config();
		let discovery = Eip7683OffchainDiscovery::new(
			"127.0.0.1".to_string(),
			0, // Use port 0 to let OS assign a free port
			vec![1],
			&networks,
		)
		.unwrap();

		let (tx, _rx) = mpsc::unbounded_channel();

		// Test start monitoring
		let start_result = discovery.start_monitoring(tx).await;
		assert!(start_result.is_ok());
		assert!(discovery.is_running.load(Ordering::SeqCst));

		// Test stop monitoring
		let stop_result = discovery.stop_monitoring().await;
		assert!(stop_result.is_ok());
		assert!(!discovery.is_running.load(Ordering::SeqCst));
	}

	#[tokio::test]
	async fn test_discovery_interface_already_monitoring() {
		let networks = create_test_networks_config();
		let discovery =
			Eip7683OffchainDiscovery::new("127.0.0.1".to_string(), 0, vec![1], &networks).unwrap();

		let (tx1, _rx1) = mpsc::unbounded_channel();
		let (tx2, _rx2) = mpsc::unbounded_channel();

		// Start monitoring
		discovery.start_monitoring(tx1).await.unwrap();

		// Try to start again - should fail
		let result = discovery.start_monitoring(tx2).await;
		assert!(result.is_err());
		matches!(result.unwrap_err(), DiscoveryError::AlreadyMonitoring);

		// Cleanup
		discovery.stop_monitoring().await.unwrap();
	}

	#[test]
	fn test_get_url() {
		let networks = create_test_networks_config();
		let discovery =
			Eip7683OffchainDiscovery::new("127.0.0.1".to_string(), 8080, vec![1], &networks)
				.unwrap();

		let url = discovery.get_url();
		assert_eq!(url, Some("127.0.0.1:8080".to_string()));
	}

	#[tokio::test]
	async fn test_handle_intent_submission_invalid_order() {
		use axum::extract::State;
		use axum::Json;
		use solver_types::api::OifOrder;

		let (tx, _rx) = mpsc::unbounded_channel();
		let state = ApiState {
			intent_sender: tx,
			providers: HashMap::new(),
			networks: create_test_networks_config(),
		};

		// Create invalid request with malformed OifOrder
		// Using OifGenericV0 with invalid data that will fail StandardOrder conversion
		let invalid_request = PostOrderRequest {
			order: OifOrder::OifGenericV0 {
				payload: serde_json::json!({
					"invalid": "data_that_cannot_be_converted_to_standard_order"
				}),
			},
			signature: Bytes::from_static(b"signature"),
			quote_id: None,
			origin_submission: None,
		};

		let response = handle_intent_submission(State(state), Json(invalid_request)).await;

		// Should return BAD_REQUEST status due to parsing failure
		assert_eq!(response.into_response().status(), StatusCode::BAD_REQUEST);
	}
```

### Test Categories

| Category | Purpose | Examples |
|----------|---------|----------|
| **Schema Validation** | Ensure configuration is validated correctly | Valid config, missing fields, invalid ranges |
| **Event Parsing** | Verify log decoding and Intent creation | Valid logs, invalid logs, empty outputs |
| **Lifecycle** | Test start/stop monitoring | Start, stop, double-start error |
| **API Handlers** | Test HTTP endpoint behavior | Valid requests, invalid orders, malformed JSON |
| **Serialization** | Verify JSON/ABI encoding | StandardOrder ↔ ApiStandardOrder, bytes32 handling |

---

## Performance Considerations

### On-Chain Discovery

#### Polling Mode Performance

**RPC Call Frequency:**
```
Calls per chain per hour = 3600 / polling_interval_secs
Default (3s) = 1200 calls/chain/hour
```

**Optimization Strategies:**
1. **Block Range Limiting**: Only query new blocks since `last_block_num`
2. **Event Filtering**: Filter by settler address + event signature at RPC level
3. **Missed Tick Behavior**: Skip missed ticks to prevent burst polling after delays

#### WebSocket Mode Performance

**Advantages:**
- Near-zero RPC load (single subscription per chain)
- Real-time event delivery (~1-2s latency)
- No block tracking overhead

**Disadvantages:**
- Requires persistent connection
- Connection drops require reconnection logic (not implemented)
- Some RPC providers charge per subscription

### Off-Chain Discovery

#### HTTP Server Performance

**Axum Performance Characteristics:**
- Async handlers allow high concurrency
- Request handling is non-blocking
- State is cheaply cloneable (Arc-based)

**Bottlenecks:**
1. **Order ID Computation**: 50-200ms RPC call per submission
2. **Channel Send**: Effectively zero cost (unbounded channel)
3. **JSON Parsing**: ~1-5ms for typical orders

**Scalability:**
- Single Axum instance can handle 1000+ req/s
- For higher throughput, deploy multiple discovery instances
- Each instance sends to the same solver's intent channel

---

## Security Considerations

### On-Chain Discovery

#### Trust Assumptions
- **RPC Provider**: Trusted to return correct blockchain data
- **Settler Contracts**: Trusted to emit correct events
- **Event Ordering**: Blockchain provides canonical ordering

#### Attack Vectors
1. **Malicious RPC Provider**:
   - Could inject fake events
   - Mitigation: Use multiple providers, verify via consensus layer

2. **Front-Running**:
   - Solver sees on-chain orders that could be front-run
   - Mitigation: Orders are already committed on-chain, no additional risk

3. **DOS via Gas-less Orders**:
   - Attacker could spam on-chain orders
   - Mitigation: Orders must pay gas to emit events

### Off-Chain Discovery

#### Trust Assumptions
- **Signature Verification**: Sponsor is recovered from EIP-712 signature
- **Order ID Computation**: Settler contract computes canonical order ID
- **No Double-Submission Check**: Discovery layer doesn't track duplicates (handled by solver-core)

#### Attack Vectors
1. **Spam Submissions**:
   - Attacker submits many invalid orders
   - Mitigation: Early validation rejects malformed orders, rate limiting (not implemented)

2. **Signature Forgery**:
   - Attacker tries to impersonate user
   - Mitigation: EIP-712 signature verification in solver-core

3. **Order ID Collision**:
   - Attacker tries to submit orders with same ID
   - Mitigation: Solver-core deduplicates by order ID

4. **DOS via Slow RPC**:
   - Attacker submits orders that cause slow order ID computation
   - Mitigation: RPC timeout (implicit in provider), async handling prevents blocking

---

## Integration Patterns

### Starting Discovery Service

```rust
use solver_discovery::{DiscoveryService, get_all_implementations};
use solver_types::{Intent, NetworksConfig};
use tokio::sync::mpsc;

async fn start_discovery(networks: NetworksConfig) -> DiscoveryService {
    // Create intent channel
    let (intent_tx, mut intent_rx) = mpsc::unbounded_channel::<Intent>();
    
    // Load configuration
    let config = load_toml_config("config/demo.toml");
    
    // Create factory registry
    let mut registry = HashMap::new();
    for (name, factory) in get_all_implementations() {
        registry.insert(name.to_string(), factory);
    }
    
    // Instantiate implementations
    let mut implementations = HashMap::new();
    for (name, config_value) in config.get("discovery").as_table() {
        if let Some(factory) = registry.get(name) {
            let implementation = factory(config_value, &networks)?;
            implementations.insert(name.clone(), implementation);
        }
    }
    
    // Create service
    let service = DiscoveryService::new(implementations);
    
    // Start monitoring
    service.start_all(intent_tx).await?;
    
    // Spawn intent processor
    tokio::spawn(async move {
        while let Some(intent) = intent_rx.recv().await {
            // Send to solver engine
            process_intent(intent).await;
        }
    });
    
    service
}
```

### Graceful Shutdown

```rust
async fn shutdown_discovery(service: DiscoveryService) {
    // Stop all monitoring
    if let Err(e) = service.stop_all().await {
        tracing::error!("Error stopping discovery: {}", e);
    }
    
    // Intent channel will close automatically when all senders are dropped
    tracing::info!("Discovery service stopped");
}
```

### Adding Custom Discovery Implementation

```rust
// 1. Implement DiscoveryInterface
pub struct CustomDiscovery {
    // ... fields
}

#[async_trait]
impl DiscoveryInterface for CustomDiscovery {
    fn config_schema(&self) -> Box<dyn ConfigSchema> {
        Box::new(CustomDiscoverySchema)
    }
    
    async fn start_monitoring(&self, sender: mpsc::UnboundedSender<Intent>) 
        -> Result<(), DiscoveryError> {
        // Start monitoring logic
        Ok(())
    }
    
    async fn stop_monitoring(&self) -> Result<(), DiscoveryError> {
        // Stop monitoring logic
        Ok(())
    }
}

// 2. Define configuration schema
pub struct CustomDiscoverySchema;

impl ConfigSchema for CustomDiscoverySchema {
    fn validate(&self, config: &toml::Value) -> Result<(), ValidationError> {
        // Validation logic
        Ok(())
    }
}

// 3. Create factory function
pub fn create_discovery(
    config: &toml::Value,
    networks: &NetworksConfig,
) -> Result<Box<dyn DiscoveryInterface>, DiscoveryError> {
    CustomDiscoverySchema::validate_config(config)?;
    let discovery = CustomDiscovery::new(/* ... */)?;
    Ok(Box::new(discovery))
}

// 4. Register implementation
pub struct Registry;

impl ImplementationRegistry for Registry {
    const NAME: &'static str = "custom_discovery";
    type Factory = DiscoveryFactory;
    
    fn factory() -> Self::Factory {
        create_discovery
    }
}

impl DiscoveryRegistry for Registry {}

// 5. Add to get_all_implementations()
pub fn get_all_implementations() -> Vec<(&'static str, DiscoveryFactory)> {
    vec![
        // ... existing implementations
        (custom::Registry::NAME, custom::Registry::factory()),
    ]
}
```

---

## Summary

### Key Strengths

1. **Pluggable Architecture**: Easy to add new discovery sources
2. **Dual-Mode Support**: Both on-chain (polling/WebSocket) and off-chain (HTTP API)
3. **Type Safety**: Strong typing with trait-based abstractions
4. **Async-First**: Built on Tokio for high concurrency
5. **Configuration Validation**: Schema-based validation prevents misconfiguration
6. **Graceful Shutdown**: Clean lifecycle management
7. **Comprehensive Testing**: Unit tests cover critical paths

### Key Weaknesses

1. **No Connection Recovery**: WebSocket mode doesn't handle reconnections
2. **No Rate Limiting**: Off-chain API vulnerable to spam
3. **No Deduplication**: Discovery layer doesn't track duplicate intents
4. **RPC Dependency**: Off-chain order ID computation requires RPC call
5. **No Metrics**: Missing observability (Prometheus metrics, etc.)

### Future Enhancements

1. **WebSocket Reconnection**: Auto-reconnect on connection drop
2. **Rate Limiting**: Token bucket or leaky bucket for API
3. **Metrics**: Instrument with `prometheus` crate
4. **Health Checks**: Add `/health` endpoint to off-chain API
5. **Batch Order Submission**: Accept multiple orders in single API call
6. **Event Buffering**: Buffer events during solver downtime
7. **Multi-Provider Support**: Query multiple RPC providers for redundancy

---

## Dependency Graph

```
solver-discovery
├── solver-types (Intent, NetworksConfig, ConfigSchema)
├── alloy-* (Ethereum types, RPC providers)
│   ├── alloy-primitives (Address, Bytes, U256)
│   ├── alloy-provider (DynProvider, HTTP/WS)
│   ├── alloy-sol-types (sol! macro, ABI encoding)
│   └── alloy-rpc-types (Log, Filter)
├── tokio (async runtime, mpsc channels)
├── axum (HTTP server framework)
├── serde/serde_json (serialization)
├── thiserror (error handling)
├── hex (hex encoding)
└── tracing (logging)
```

---

## Conclusion

The `solver-discovery` crate is a **well-architected intent ingestion system** that successfully abstracts multiple discovery sources behind a unified interface. Its strengths lie in its:

- **Modularity**: Clear separation between on-chain and off-chain discovery
- **Extensibility**: Easy to add new implementations via factory pattern
- **Performance**: Async-first design with efficient event processing
- **Type Safety**: Strong Rust typing prevents entire classes of bugs

The crate serves as the **entry point** for all intents in the OIF solver system, ensuring consistent handling regardless of source. While there are opportunities for improvement (reconnection logic, rate limiting, metrics), the current implementation is production-ready for moderate-scale deployments.

The dual-mode support (polling vs. WebSocket) demonstrates thoughtful design, allowing operators to choose between low-latency (WebSocket) and reliability (polling) based on their RPC provider characteristics.

Overall, `solver-discovery` exemplifies **good Rust systems programming**—leveraging the type system for correctness, async for concurrency, and traits for abstraction.


