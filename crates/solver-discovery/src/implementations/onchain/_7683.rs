//! Intent discovery implementations for the solver service.
//!
//! This module provides concrete implementations of the DiscoveryInterface trait,
//! currently supporting on-chain EIP-7683 event monitoring using the Alloy library.

use crate::{DiscoveryError, DiscoveryInterface};
use alloy_primitives::{Address as AlloyAddress, Log as PrimLog, LogData};
use alloy_provider::{DynProvider, Provider};
use alloy_rpc_types::{BlockNumberOrTag, Filter, Log};
use alloy_sol_types::sol;
use alloy_sol_types::{SolEvent, SolValue};
use async_trait::async_trait;
use futures::StreamExt;
use solver_types::{
	create_http_provider, create_ws_provider, current_timestamp,
	standards::eip7683::{GasLimitOverrides, LockType, MandateOutput},
	with_0x_prefix, ConfigSchema, Eip7683OrderData, Field, FieldType, Intent, IntentMetadata,
	NetworksConfig, ProviderError, Schema,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::task::JoinHandle;

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
		bytes callbackData;
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

const DEFAULT_POLLING_INTERVAL_SECS: u64 = 3;
const MAX_POLLING_INTERVAL_SECS: u64 = 300;
const DEFAULT_FINALITY_BLOCKS: u64 = 20;
const MAX_FINALITY_BLOCKS: u64 = 100_000;

fn numeric_finality_head(current_block: u64, finality_blocks: u64) -> Option<u64> {
	current_block.checked_sub(finality_blocks)
}

fn next_poll_range(last_processed: u64, safe_to_block: Option<u64>) -> Option<(u64, u64)> {
	let safe_to_block = safe_to_block?;
	if safe_to_block <= last_processed {
		return None;
	}
	Some((last_processed + 1, safe_to_block))
}

fn finality_blocks_for_config(
	chain_id: u64,
	default_finality_blocks: u64,
	finality_blocks: &HashMap<u64, u64>,
) -> u64 {
	finality_blocks
		.get(&chain_id)
		.copied()
		.unwrap_or(default_finality_blocks)
}

async fn block_number_for_tag(provider: &DynProvider, tag: BlockNumberOrTag) -> Option<u64> {
	match provider.get_block_by_number(tag).await {
		Ok(Some(block)) => Some(block.number()),
		Ok(None) => None,
		Err(e) => {
			tracing::debug!(?tag, "RPC finality tag lookup failed; falling back: {}", e);
			None
		},
	}
}

async fn resolve_finality_head(
	provider: &DynProvider,
	finality_blocks: u64,
) -> Result<Option<u64>, DiscoveryError> {
	if let Some(block) = block_number_for_tag(provider, BlockNumberOrTag::Finalized).await {
		return Ok(Some(block));
	}

	if let Some(block) = block_number_for_tag(provider, BlockNumberOrTag::Safe).await {
		return Ok(Some(block));
	}

	let latest = provider
		.get_block_number()
		.await
		.map_err(|e| DiscoveryError::Connection(format!("Failed to get block number: {e}")))?;

	Ok(numeric_finality_head(latest, finality_blocks))
}

fn validate_finality_blocks_object(
	value: &serde_json::Value,
) -> Result<(), solver_types::ValidationError> {
	let Some(object) = value.as_object() else {
		return Err(solver_types::ValidationError::TypeMismatch {
			field: "finality_blocks".to_string(),
			expected: "object".to_string(),
			actual: "non-object".to_string(),
		});
	};

	for (chain_id, depth) in object {
		chain_id
			.parse::<u64>()
			.map_err(|_| solver_types::ValidationError::InvalidValue {
				field: "finality_blocks".to_string(),
				message: format!("chain id key '{chain_id}' is not a u64"),
			})?;

		let depth = depth
			.as_i64()
			.ok_or_else(|| solver_types::ValidationError::TypeMismatch {
				field: format!("finality_blocks.{chain_id}"),
				expected: "integer".to_string(),
				actual: "non-integer".to_string(),
			})?;

		if !(0..=MAX_FINALITY_BLOCKS as i64).contains(&depth) {
			return Err(solver_types::ValidationError::InvalidValue {
				field: format!("finality_blocks.{chain_id}"),
				message: format!("Value {depth} must be between 0 and {MAX_FINALITY_BLOCKS}"),
			});
		}
	}

	Ok(())
}

fn parse_finality_blocks_config(config: &serde_json::Value) -> HashMap<u64, u64> {
	config
		.get("finality_blocks")
		.and_then(|v| v.as_object())
		.map(|object| {
			object
				.iter()
				.filter_map(|(chain_id, depth)| {
					Some((chain_id.parse::<u64>().ok()?, depth.as_u64()?))
				})
				.collect()
		})
		.unwrap_or_default()
}

/// Provider types for different transport modes.
enum ProviderType {
	/// HTTP provider for polling mode.
	Http(DynProvider),
	/// WebSocket provider for subscription mode.
	WebSocket(DynProvider),
}

struct PollingMonitorContext {
	networks: NetworksConfig,
	last_blocks: Arc<Mutex<HashMap<u64, u64>>>,
	polling_interval_secs: u64,
	finality_blocks: u64,
}

/// EIP-7683 on-chain discovery implementation.
///
/// This implementation monitors blockchain events for new EIP-7683 cross-chain
/// orders and converts them into intents for the solver to process.
/// Supports monitoring multiple chains concurrently using either HTTP polling
/// WebSocket subscriptions are disabled until removed-log handling is buffered
/// behind a finality gate.
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
	/// Default source-chain finality depth, in blocks.
	default_finality_blocks: u64,
	/// Per-chain source finality depth overrides.
	finality_blocks: HashMap<u64, u64>,
}

impl Eip7683Discovery {
	/// Creates a new EIP-7683 discovery instance.
	///
	/// Configures monitoring for the settler contracts on the specified chains.
	pub async fn new(
		network_ids: Vec<u64>,
		networks: NetworksConfig,
		polling_interval_secs: Option<u64>,
		default_finality_blocks: u64,
		finality_blocks: HashMap<u64, u64>,
	) -> Result<Self, DiscoveryError> {
		// Validate at least one network
		if network_ids.is_empty() {
			return Err(DiscoveryError::ValidationError(
				"At least one network_id must be specified".to_string(),
			));
		}

		let interval = polling_interval_secs.unwrap_or(DEFAULT_POLLING_INTERVAL_SECS);
		if interval == 0 {
			return Err(DiscoveryError::ValidationError(
				"polling_interval_secs must be greater than 0; WebSocket on-chain discovery is disabled until removed-log finality buffering is implemented"
					.to_string(),
			));
		}
		let use_websocket = interval == 0;

		// Create providers and get initial blocks for each network
		let mut providers = HashMap::new();
		let mut last_blocks = HashMap::new();

		for network_id in &network_ids {
			if use_websocket {
				// WebSocket mode
				let provider =
					create_ws_provider(*network_id, &networks)
						.await
						.map_err(|e| match e {
							ProviderError::NetworkConfig(msg) => {
								DiscoveryError::ValidationError(msg)
							},
							ProviderError::Connection(msg) => DiscoveryError::Connection(msg),
							ProviderError::InvalidUrl(msg) => DiscoveryError::Connection(msg),
						})?;

				tracing::info!("Created WebSocket provider for network {}", network_id);

				providers.insert(*network_id, ProviderType::WebSocket(provider));
			} else {
				// HTTP polling mode
				let provider =
					create_http_provider(*network_id, &networks).map_err(|e| match e {
						ProviderError::NetworkConfig(msg) => DiscoveryError::ValidationError(msg),
						ProviderError::Connection(msg) => DiscoveryError::Connection(msg),
						ProviderError::InvalidUrl(msg) => DiscoveryError::Connection(msg),
					})?;

				let finality_depth = finality_blocks_for_config(
					*network_id,
					default_finality_blocks,
					&finality_blocks,
				);

				// Initialize the cursor to the current finality head. Logs newer
				// than this are intentionally left for a later poll once they are
				// confirmed at the configured depth.
				let current_block = resolve_finality_head(&provider, finality_depth)
					.await
					.map_err(|e| {
						DiscoveryError::Connection(format!(
							"Failed to get finality head for chain {network_id}: {e}"
						))
					})?
					.unwrap_or(0);

				tracing::info!(
					chain = network_id,
					current_block,
					finality_depth,
					"Initialized on-chain discovery cursor at source finality head"
				);

				providers.insert(*network_id, ProviderType::Http(provider));
				last_blocks.insert(*network_id, current_block);
			}
		}

		Ok(Self {
			providers,
			network_ids,
			networks,
			last_blocks: Arc::new(Mutex::new(last_blocks)),
			is_monitoring: Arc::new(AtomicBool::new(false)),
			monitoring_handles: Arc::new(Mutex::new(Vec::new())),
			stop_signal: Arc::new(Mutex::new(None)),
			polling_interval_secs: interval,
			default_finality_blocks,
			finality_blocks,
		})
	}

	fn finality_blocks_for_chain(&self, chain_id: u64) -> u64 {
		finality_blocks_for_config(
			chain_id,
			self.default_finality_blocks,
			&self.finality_blocks,
		)
	}

	/// Creates a new EIP-7683 discovery instance with default finality settings.
	///
	/// This test helper preserves the historical constructor shape for call sites
	/// that do not need to override source finality.
	#[cfg(test)]
	async fn new_with_default_finality(
		network_ids: Vec<u64>,
		networks: NetworksConfig,
		polling_interval_secs: Option<u64>,
	) -> Result<Self, DiscoveryError> {
		Self::new(
			network_ids,
			networks,
			polling_interval_secs,
			DEFAULT_FINALITY_BLOCKS,
			HashMap::new(),
		)
		.await
	}

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
		let open_event = Open::decode_log_validate(&prim_log)
			.map_err(|e| DiscoveryError::ParseError(format!("Failed to decode Open event: {e}")))?;

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
					call: output.callbackData.clone().into(),
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
				DiscoveryError::ParseError(format!("Failed to serialize order data: {e}"))
			})?,
			order_bytes: abi_encoded_bytes,
			quote_id: None,
			lock_type: LockType::Permit2Escrow.to_string(),
		})
	}

	/// Process discovered logs into intents and send them.
	///
	/// Common logic for both polling and subscription modes.
	async fn process_discovered_logs(
		logs: Vec<Log>,
		sender: &mpsc::Sender<Intent>,
		_chain_id: u64,
	) -> bool {
		for log in logs {
			if let Ok(intent) = Self::parse_open_event(&log) {
				if sender.send(intent).await.is_err() {
					tracing::warn!("Failed to send discovered intent to solver channel");
					return false;
				}
			}
		}
		true
	}

	/// Polling-based monitoring for a single chain.
	///
	/// Periodically polls the blockchain for new Open events and sends
	/// discovered intents through the provided channel.
	async fn monitor_chain_polling(
		provider: DynProvider,
		chain_id: u64,
		context: PollingMonitorContext,
		sender: mpsc::Sender<Intent>,
		mut stop_rx: broadcast::Receiver<()>,
	) {
		let mut interval = tokio::time::interval(std::time::Duration::from_secs(
			context.polling_interval_secs,
		));

		// Set the interval to skip missed ticks instead of bursting
		interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
		// Skip the first immediate tick to avoid immediate polling
		interval.tick().await;

		loop {
			tokio::select! {
				_ = interval.tick() => {
					// Get last processed block for this chain
					let last_block_num = {
						let blocks = context.last_blocks.lock().await;
						*blocks.get(&chain_id).unwrap_or(&0)
					};

					let safe_to_block = match resolve_finality_head(&provider, context.finality_blocks).await {
						Ok(block) => block,
						Err(e) => {
							tracing::error!(chain = chain_id, "Failed to resolve finality head: {}", e);
							continue;
						}
					};

					let Some((from_block, to_block)) =
						next_poll_range(last_block_num, safe_to_block)
					else {
						continue;
					};

					// Create filter for Open events
					let open_sig = Open::SIGNATURE_HASH;

					// Get the input settler address for this chain
					let settler_address = match context.networks.get(&chain_id) {
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
						.from_block(from_block)
						.to_block(to_block);

					// Get logs
					let logs = match provider.get_logs(&filter).await {
						Ok(logs) => logs,
						Err(e) => {
							tracing::error!(chain = chain_id, "Failed to get logs: {}", e);
							continue;
						}
					};

					// Process discovered logs
					if !Self::process_discovered_logs(logs, &sender, chain_id).await {
						break;
					}

					// Update last block for this chain
					context.last_blocks.lock().await.insert(chain_id, to_block);
				}
				_ = stop_rx.recv() => {
					tracing::info!(chain = chain_id, "Stopping monitor");
					break;
				}
			}
		}
	}

	/// Subscription-based monitoring for a single chain.
	///
	/// Uses WebSocket connection to subscribe to Open events via eth_subscribe
	/// and processes events as they arrive in real-time.
	async fn monitor_chain_subscription(
		provider: DynProvider,
		chain_id: u64,
		networks: NetworksConfig,
		sender: mpsc::Sender<Intent>,
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
					if !Self::process_discovered_logs(vec![log], &sender, chain_id).await {
						break;
					}
				}
				_ = stop_rx.recv() => {
					tracing::info!(chain = chain_id, "Stopping WebSocket monitor");
					break;
				}
			}
		}
	}
}

/// Configuration schema for EIP-7683 on-chain discovery.
///
/// This schema validates the configuration for on-chain discovery,
/// ensuring all required fields are present and have valid values
/// for monitoring blockchain events.
pub struct Eip7683DiscoverySchema;

impl Eip7683DiscoverySchema {
	/// Static validation method for use before instance creation
	pub fn validate_config(
		config: &serde_json::Value,
	) -> Result<(), solver_types::ValidationError> {
		let instance = Self;
		instance.validate(config)
	}
}

impl ConfigSchema for Eip7683DiscoverySchema {
	fn validate(&self, config: &serde_json::Value) -> Result<(), solver_types::ValidationError> {
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
			vec![
				Field::new(
					"polling_interval_secs",
					FieldType::Integer {
						min: Some(1),
						max: Some(MAX_POLLING_INTERVAL_SECS as i64), // Maximum 5 minutes
					},
				),
				Field::new(
					"default_finality_blocks",
					FieldType::Integer {
						min: Some(0),
						max: Some(MAX_FINALITY_BLOCKS as i64),
					},
				),
			],
		);

		schema.validate(config)?;

		if let Some(value) = config.get("finality_blocks") {
			validate_finality_blocks_object(value)?;
		}

		Ok(())
	}
}

#[async_trait]
impl DiscoveryInterface for Eip7683Discovery {
	fn config_schema(&self) -> Box<dyn ConfigSchema> {
		Box::new(Eip7683DiscoverySchema)
	}
	async fn start_monitoring(&self, sender: mpsc::Sender<Intent>) -> Result<(), DiscoveryError> {
		if self.is_monitoring.load(Ordering::SeqCst) {
			return Err(DiscoveryError::AlreadyMonitoring);
		}

		// Create broadcast channel for shutdown
		let (stop_tx, _) = broadcast::channel(1);
		*self.stop_signal.lock().await = Some(stop_tx.clone());

		let mut handles = Vec::new();

		// Spawn monitoring task for each network
		for network_id in &self.network_ids {
			let provider = self.providers.get(network_id).unwrap();
			let networks = self.networks.clone();
			let sender = sender.clone();
			let stop_rx = stop_tx.subscribe();
			let chain_id = *network_id;

			let handle = match provider {
				ProviderType::Http(http_provider) => {
					let provider = http_provider.clone();
					let context = PollingMonitorContext {
						networks,
						last_blocks: self.last_blocks.clone(),
						polling_interval_secs: self.polling_interval_secs,
						finality_blocks: self.finality_blocks_for_chain(chain_id),
					};
					tokio::spawn(async move {
						Self::monitor_chain_polling(provider, chain_id, context, sender, stop_rx)
							.await;
					})
				},
				ProviderType::WebSocket(ws_provider) => {
					let provider = ws_provider.clone();
					tokio::spawn(async move {
						Self::monitor_chain_subscription(
							provider, chain_id, networks, sender, stop_rx,
						)
						.await;
					})
				},
			};

			handles.push(handle);
		}

		*self.monitoring_handles.lock().await = handles;
		self.is_monitoring.store(true, Ordering::SeqCst);
		Ok(())
	}

	async fn stop_monitoring(&self) -> Result<(), DiscoveryError> {
		if !self.is_monitoring.load(Ordering::SeqCst) {
			return Ok(());
		}

		// Send shutdown signal to all monitoring tasks
		if let Some(stop_tx) = self.stop_signal.lock().await.take() {
			let _ = stop_tx.send(());
		}

		// Wait for all monitoring tasks to complete
		let handles = self
			.monitoring_handles
			.lock()
			.await
			.drain(..)
			.collect::<Vec<_>>();
		for handle in handles {
			let _ = handle.await;
		}

		self.is_monitoring.store(false, Ordering::SeqCst);
		tracing::info!("Stopped monitoring all chains");
		Ok(())
	}
}

/// Factory function to create an EIP-7683 discovery provider from configuration.
///
/// This function reads the discovery configuration and creates an Eip7683Discovery
/// instance. Required configuration parameters:
/// - `network_ids`: Array of chain IDs to monitor
///
/// Optional configuration parameters:
/// - `polling_interval_secs`: Polling interval in seconds (defaults to 3)
///
/// # Errors
///
/// Returns an error if:
/// - `network_ids` is not provided or is empty
/// - Any network_id is not found in the networks configuration
/// - The discovery service cannot be created (e.g., connection failure)
pub fn create_discovery(
	config: &serde_json::Value,
	networks: &NetworksConfig,
) -> Result<Box<dyn DiscoveryInterface>, DiscoveryError> {
	// Validate configuration first
	Eip7683DiscoverySchema::validate_config(config)
		.map_err(|e| DiscoveryError::ValidationError(format!("Invalid configuration: {e}")))?;

	// Parse network_ids (required field)
	let network_ids = config
		.get("network_ids")
		.and_then(|v| v.as_array())
		.map(|arr| {
			arr.iter()
				.filter_map(|v| v.as_i64().map(|i| i as u64))
				.collect::<Vec<_>>()
		})
		.ok_or_else(|| DiscoveryError::ValidationError("network_ids is required".to_string()))?;

	if network_ids.is_empty() {
		return Err(DiscoveryError::ValidationError(
			"network_ids cannot be empty".to_string(),
		));
	}

	let polling_interval_secs = config
		.get("polling_interval_secs")
		.and_then(|v| v.as_i64())
		.map(|v| v as u64);

	let default_finality_blocks = config
		.get("default_finality_blocks")
		.and_then(|v| v.as_u64())
		.unwrap_or(DEFAULT_FINALITY_BLOCKS);
	let finality_blocks = parse_finality_blocks_config(config);

	// Create discovery service synchronously
	let discovery = tokio::task::block_in_place(|| {
		tokio::runtime::Handle::current().block_on(async {
			Eip7683Discovery::new(
				network_ids,
				networks.clone(),
				polling_interval_secs,
				default_finality_blocks,
				finality_blocks,
			)
			.await
		})
	})?;

	Ok(Box::new(discovery))
}

/// Registry for the onchain EIP-7683 discovery implementation.
pub struct Registry;

impl solver_types::ImplementationRegistry for Registry {
	const NAME: &'static str = "onchain_eip7683";
	type Factory = crate::DiscoveryFactory;

	fn factory() -> Self::Factory {
		create_discovery
	}
}

impl crate::DiscoveryRegistry for Registry {}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::{Address as AlloyAddress, Bytes, B256, U256};
	use alloy_rpc_types::Log;
	use solver_types::utils::tests::builders::{NetworkConfigBuilder, NetworksConfigBuilder};
	use solver_types::NetworksConfig;
	use tokio::sync::mpsc;

	// Helper function to create a test networks config
	fn create_test_networks() -> NetworksConfig {
		NetworksConfigBuilder::new()
			.add_network(1, NetworkConfigBuilder::new().build())
			.build()
	}

	// Helper function to create a test StandardOrder
	fn create_test_standard_order() -> StandardOrder {
		StandardOrder {
			user: AlloyAddress::from([3u8; 20]),
			nonce: U256::from(123),
			originChainId: U256::from(1),
			expires: 1000000000,
			fillDeadline: 1000000100,
			inputOracle: AlloyAddress::from([4u8; 20]),
			inputs: vec![[U256::from(100), U256::from(200)]],
			outputs: vec![SolMandateOutput {
				oracle: B256::from([5u8; 32]),
				settler: B256::from([6u8; 32]),
				chainId: U256::from(2),
				token: B256::from([7u8; 32]),
				amount: U256::from(1000),
				recipient: B256::from([8u8; 32]),
				callbackData: vec![1, 2, 3].into(),
				context: vec![4, 5, 6].into(),
			}],
		}
	}

	// Helper function to create a test Open event log
	fn create_test_open_log() -> Log {
		let order = create_test_standard_order();
		let order_id = B256::from([9u8; 32]);

		let open_event = Open {
			orderId: order_id,
			order,
		};

		// Encode the event data (only non-indexed parameters)
		use alloy_sol_types::SolEvent;
		let event_data = open_event.encode_data();

		Log {
			inner: alloy_primitives::Log {
				address: AlloyAddress::from([1u8; 20]),
				data: LogData::new_unchecked(
					vec![Open::SIGNATURE_HASH, order_id],
					event_data.into(),
				),
			},
			block_hash: Some(B256::from([10u8; 32])),
			block_number: Some(100),
			block_timestamp: Some(1000000000),
			transaction_hash: Some(B256::from([11u8; 32])),
			transaction_index: Some(0),
			log_index: Some(0),
			removed: false,
		}
	}

	#[test]
	fn test_config_schema_validation_valid() {
		let config = serde_json::json!({
			"network_ids": [1],
			"polling_interval_secs": 5
		});

		let result = Eip7683DiscoverySchema::validate_config(&config);
		assert!(result.is_ok());
	}

	#[test]
	fn test_config_schema_validation_missing_network_ids() {
		let config = serde_json::json!({
			"polling_interval_secs": 5
		});

		let result = Eip7683DiscoverySchema::validate_config(&config);
		assert!(result.is_err());
	}

	#[test]
	fn test_config_schema_validation_empty_network_ids() {
		let config = serde_json::json!({
			"network_ids": []
		});

		let result = Eip7683DiscoverySchema::validate_config(&config);
		assert!(result.is_err());
	}

	#[test]
	fn test_config_schema_validation_invalid_polling_interval() {
		let config = serde_json::json!({
			"network_ids": [1],
			"polling_interval_secs": (MAX_POLLING_INTERVAL_SECS + 100)
		});

		let result = Eip7683DiscoverySchema::validate_config(&config);
		assert!(result.is_err());
	}

	#[test]
	fn test_config_schema_validation_rejects_websocket_mode() {
		let config = serde_json::json!({
			"network_ids": [1],
			"polling_interval_secs": 0
		});

		let result = Eip7683DiscoverySchema::validate_config(&config);
		assert!(result.is_err());
	}

	#[test]
	fn test_config_schema_validation_accepts_existing_finality_fields() {
		let config = serde_json::json!({
			"network_ids": [1],
			"polling_interval_secs": 5,
			"default_finality_blocks": 20,
			"finality_blocks": { "1": 64 }
		});

		let result = Eip7683DiscoverySchema::validate_config(&config);
		assert!(result.is_ok());
	}

	#[test]
	fn test_config_schema_validation_rejects_negative_default_finality_blocks() {
		let config = serde_json::json!({
			"network_ids": [1],
			"default_finality_blocks": -1
		});

		let result = Eip7683DiscoverySchema::validate_config(&config);
		assert!(result.is_err());
	}

	#[test]
	fn test_config_schema_validation_rejects_negative_per_chain_finality_blocks() {
		let config = serde_json::json!({
			"network_ids": [1],
			"finality_blocks": { "1": -1 }
		});

		let result = Eip7683DiscoverySchema::validate_config(&config);
		assert!(result.is_err());
	}

	#[test]
	fn numeric_finality_head_subtracts_configured_depth() {
		assert_eq!(numeric_finality_head(100, 20), Some(80));
		assert_eq!(numeric_finality_head(100, 0), Some(100));
	}

	#[test]
	fn numeric_finality_head_returns_none_before_depth_elapses() {
		assert_eq!(numeric_finality_head(2, 20), None);
	}

	#[test]
	fn next_poll_range_only_advances_when_finality_head_advances() {
		assert_eq!(next_poll_range(80, Some(80)), None);
		assert_eq!(next_poll_range(80, Some(83)), Some((81, 83)));
		assert_eq!(next_poll_range(80, None), None);
	}

	#[test]
	fn test_parse_open_event_success() {
		let log = create_test_open_log();
		let result = Eip7683Discovery::parse_open_event(&log);

		assert!(result.is_ok());
		let intent = result.unwrap();

		// Verify intent structure
		assert_eq!(intent.source, "on-chain");
		assert_eq!(intent.standard, "eip7683");
		assert!(!intent.metadata.requires_auction);
		assert!(intent.metadata.exclusive_until.is_none());
		assert!(intent.quote_id.is_none());

		// Verify the intent data can be deserialized
		let order_data: Eip7683OrderData = serde_json::from_value(intent.data).unwrap();
		assert_eq!(order_data.nonce, U256::from(123));
		assert_eq!(order_data.origin_chain_id, U256::from(1));
		assert_eq!(order_data.outputs.len(), 1);
		assert_eq!(order_data.outputs[0].chain_id, U256::from(2));
		assert_eq!(order_data.outputs[0].amount, U256::from(1000));
	}

	#[test]
	fn test_parse_open_event_no_outputs() {
		// Create order with no outputs
		let mut order = create_test_standard_order();
		order.outputs = vec![];

		let order_id = B256::from([9u8; 32]);

		let open_event = Open {
			orderId: order_id,
			order,
		};

		// Encode the event data (only non-indexed parameters)
		use alloy_sol_types::SolEvent;
		let event_data = open_event.encode_data();

		let log = Log {
			inner: alloy_primitives::Log {
				address: AlloyAddress::from([1u8; 20]),
				data: LogData::new_unchecked(
					vec![Open::SIGNATURE_HASH, order_id],
					event_data.into(),
				),
			},
			block_hash: Some(B256::from([10u8; 32])),
			block_number: Some(100),
			block_timestamp: Some(1000000000),
			transaction_hash: Some(B256::from([11u8; 32])),
			transaction_index: Some(0),
			log_index: Some(0),
			removed: false,
		};

		let result = Eip7683Discovery::parse_open_event(&log);
		assert!(result.is_err());

		if let Err(DiscoveryError::ValidationError(msg)) = result {
			assert!(msg.contains("at least one output"));
		} else {
			panic!("Expected ValidationError");
		}
	}

	#[test]
	fn test_parse_open_event_invalid_log_data() {
		let log = Log {
			inner: alloy_primitives::Log {
				address: AlloyAddress::from([1u8; 20]),
				data: LogData::new_unchecked(
					vec![Open::SIGNATURE_HASH],
					Bytes::from(vec![1, 2, 3]), // Invalid order data
				),
			},
			block_hash: Some(B256::from([10u8; 32])),
			block_number: Some(100),
			block_timestamp: Some(1000000000),
			transaction_hash: Some(B256::from([11u8; 32])),
			transaction_index: Some(0),
			log_index: Some(0),
			removed: false,
		};

		let result = Eip7683Discovery::parse_open_event(&log);
		assert!(result.is_err());

		if let Err(DiscoveryError::ParseError(_)) = result {
			// Expected
		} else {
			panic!("Expected ParseError");
		}
	}

	#[tokio::test]
	async fn test_process_discovered_logs() {
		let (sender, mut receiver) = mpsc::channel(16);

		// First, let's test if we can parse the log directly
		let log = create_test_open_log();
		match Eip7683Discovery::parse_open_event(&log) {
			Ok(intent) => println!("Direct parse succeeded: {}", intent.id),
			Err(e) => println!("Direct parse failed: {e:?}"),
		}

		let logs = vec![log];
		assert!(Eip7683Discovery::process_discovered_logs(logs, &sender, 1).await);

		// Should receive one intent
		match receiver.try_recv() {
			Ok(intent) => {
				assert_eq!(intent.source, "on-chain");
				assert_eq!(intent.standard, "eip7683");
			},
			Err(_) => {
				// If no intent received, the parsing failed silently
				panic!("No intent received - parsing likely failed");
			},
		}

		// Should not receive any more intents
		assert!(receiver.try_recv().is_err());
	}

	#[tokio::test]
	async fn test_process_discovered_logs_invalid_log() {
		let (sender, mut receiver) = mpsc::channel(16);

		// Create invalid log
		let invalid_log = Log {
			inner: alloy_primitives::Log {
				address: AlloyAddress::from([1u8; 20]),
				data: LogData::new_unchecked(
					vec![Open::SIGNATURE_HASH],
					Bytes::from(vec![1, 2, 3]), // Invalid data
				),
			},
			block_hash: Some(B256::from([10u8; 32])),
			block_number: Some(100),
			block_timestamp: Some(1000000000),
			transaction_hash: Some(B256::from([11u8; 32])),
			transaction_index: Some(0),
			log_index: Some(0),
			removed: false,
		};

		let logs = vec![invalid_log];
		assert!(Eip7683Discovery::process_discovered_logs(logs, &sender, 1).await);

		// Should not receive any intents due to invalid log
		assert!(receiver.try_recv().is_err());
	}

	#[tokio::test]
	async fn test_eip7683_discovery_new_empty_network_ids() {
		let networks = create_test_networks();
		let network_ids = vec![];

		let result =
			Eip7683Discovery::new_with_default_finality(network_ids, networks, Some(5)).await;
		assert!(result.is_err());

		if let Err(DiscoveryError::ValidationError(msg)) = result {
			assert!(msg.contains("At least one network_id"));
		} else {
			panic!("Expected ValidationError");
		}
	}

	#[tokio::test]
	async fn test_eip7683_discovery_new_unknown_network() {
		let networks = create_test_networks();
		let network_ids = vec![999]; // Unknown network

		let result =
			Eip7683Discovery::new_with_default_finality(network_ids, networks, Some(5)).await;
		assert!(result.is_err());

		if let Err(DiscoveryError::ValidationError(msg)) = result {
			assert!(msg.contains("Network 999 not found"));
		} else {
			panic!("Expected ValidationError");
		}
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn test_create_discovery_invalid_config() {
		let config = serde_json::json!({
			"polling_interval_secs": 5
		}); // Missing network_ids

		let networks = create_test_networks();
		let result = create_discovery(&config, &networks);
		assert!(result.is_err());

		if let Err(DiscoveryError::ValidationError(msg)) = result {
			assert!(msg.contains("required field: network_ids"));
		} else {
			panic!("Expected ValidationError");
		}
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn test_create_discovery_empty_network_ids() {
		let config = serde_json::json!({
			"network_ids": []
		});

		let networks = create_test_networks();
		let result = create_discovery(&config, &networks);
		assert!(result.is_err());

		if let Err(DiscoveryError::ValidationError(msg)) = result {
			assert!(msg.contains("cannot be empty"));
		} else {
			panic!("Expected ValidationError");
		}
	}

	#[test]
	fn test_registry_name() {
		assert_eq!(
			<Registry as solver_types::ImplementationRegistry>::NAME,
			"onchain_eip7683"
		);
	}

	#[test]
	fn test_order_data_serialization() {
		let order_data = Eip7683OrderData {
			user: with_0x_prefix(&hex::encode([3u8; 20])),
			nonce: U256::from(123),
			origin_chain_id: U256::from(1),
			expires: 1000000000,
			fill_deadline: 1000000100,
			input_oracle: with_0x_prefix(&hex::encode([4u8; 20])),
			inputs: vec![[U256::from(100), U256::from(200)]],
			order_id: [9u8; 32],
			gas_limit_overrides: GasLimitOverrides::default(),
			outputs: vec![MandateOutput {
				oracle: [5u8; 32],
				settler: [6u8; 32],
				chain_id: U256::from(2),
				token: [7u8; 32],
				amount: U256::from(1000),
				recipient: [8u8; 32],
				call: vec![1, 2, 3],
				context: vec![4, 5, 6],
			}],
			raw_order_data: Some(with_0x_prefix("deadbeef")),
			signature: None,
			sponsor: None,
			lock_type: Some(LockType::Permit2Escrow),
		};

		// Test serialization to JSON
		let json_value = serde_json::to_value(&order_data).unwrap();
		assert!(json_value.is_object());

		// Test deserialization from JSON
		let deserialized: Eip7683OrderData = serde_json::from_value(json_value).unwrap();
		assert_eq!(deserialized.nonce, order_data.nonce);
		assert_eq!(deserialized.outputs.len(), order_data.outputs.len());
	}

	#[test]
	fn test_constants() {
		assert_eq!(DEFAULT_POLLING_INTERVAL_SECS, 3);
		assert_eq!(MAX_POLLING_INTERVAL_SECS, 300);
	}

	#[test]
	fn test_sol_types_compilation() {
		// Verify that the sol! macro generated types correctly
		let mandate_output = SolMandateOutput {
			oracle: B256::from([1u8; 32]),
			settler: B256::from([2u8; 32]),
			chainId: U256::from(1),
			token: B256::from([3u8; 32]),
			amount: U256::from(1000),
			recipient: B256::from([4u8; 32]),
			callbackData: vec![1, 2, 3].into(),
			context: vec![4, 5, 6].into(),
		};

		let standard_order = StandardOrder {
			user: AlloyAddress::from([5u8; 20]),
			nonce: U256::from(123),
			originChainId: U256::from(1),
			expires: 1000000000,
			fillDeadline: 1000000100,
			inputOracle: AlloyAddress::from([6u8; 20]),
			inputs: vec![[U256::from(100), U256::from(200)]],
			outputs: vec![mandate_output],
		};

		// Test ABI encoding/decoding
		let encoded = standard_order.abi_encode();
		assert!(!encoded.is_empty());

		let decoded = StandardOrder::abi_decode_validate(&encoded).unwrap();
		assert_eq!(decoded.nonce, standard_order.nonce);
		assert_eq!(decoded.outputs.len(), standard_order.outputs.len());
	}
}
