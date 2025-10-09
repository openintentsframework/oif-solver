# solver-delivery: Transaction Delivery Crate

## Executive Summary

The `solver-delivery` crate is the **transaction submission and monitoring subsystem** for the OIF (Order Intent Framework) solver. It provides a robust, extensible architecture for signing, submitting, and tracking blockchain transactions across multiple EVM-compatible networks. This crate abstracts away the complexities of blockchain interaction, providing a unified interface for transaction delivery regardless of the underlying blockchain implementation.

**Key Responsibilities:**
- Transaction signing and submission to blockchain networks
- Real-time transaction monitoring and confirmation tracking
- Multi-chain support with chain-specific configuration
- Blockchain state queries (balances, nonces, gas prices, etc.)
- Contract interaction (eth_call, gas estimation)

**Core Design Pattern:** Strategy Pattern + Service Layer + Registry Pattern

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Core Components](#core-components)
3. [The DeliveryInterface Trait](#the-deliveryinterface-trait)
4. [DeliveryService: The Orchestrator](#deliveryservice-the-orchestrator)
5. [Alloy Implementation Deep Dive](#alloy-implementation-deep-dive)
6. [Transaction Monitoring System](#transaction-monitoring-system)
7. [Configuration Architecture](#configuration-architecture)
8. [Registry Pattern](#registry-pattern)
9. [Data Flow Analysis](#data-flow-analysis)
10. [Error Handling Strategy](#error-handling-strategy)
11. [Network Resilience](#network-resilience)
12. [Testing Strategy](#testing-strategy)
13. [Integration Points](#integration-points)
14. [Technical Decisions](#technical-decisions)

---

## Architecture Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        DeliveryService                          │
│                     (Service Orchestrator)                      │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │     Multi-Chain Routing & Tracking Configuration         │  │
│  │     - Chain ID → Implementation Mapping                  │  │
│  │     - Global Confirmation Settings                       │  │
│  │     - Monitoring Timeout Configuration                   │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ Routes by chain_id
                              ▼
         ┌────────────────────────────────────────┐
         │      DeliveryInterface Trait           │
         │    (Abstraction for Implementations)   │
         └────────────────────────────────────────┘
                       │
                       │ Implemented by
                       ▼
    ┌──────────────────────────────────────────────────┐
    │           AlloyDelivery (EVM)                    │
    │                                                  │
    │  ┌────────────────────────────────────────────┐ │
    │  │   Provider Pool (per chain_id)             │ │
    │  │   ┌─────────┐  ┌─────────┐  ┌─────────┐   │ │
    │  │   │Chain 1  │  │Chain 137│  │Chain 10 │   │ │
    │  │   │Provider │  │Provider │  │Provider │   │ │
    │  │   └─────────┘  └─────────┘  └─────────┘   │ │
    │  └────────────────────────────────────────────┘ │
    │                                                  │
    │  Features:                                       │
    │  • Per-chain signing with EthereumWallet        │
    │  • Automatic nonce management                   │
    │  • Gas estimation and filling                   │
    │  • Retry with exponential backoff               │
    │  • Transaction monitoring in background tasks   │
    │  └──────────────────────────────────────────────┘
                       │
                       │ Communicates via
                       ▼
         ┌────────────────────────────────┐
         │   Blockchain Networks (RPC)    │
         │   • Ethereum Mainnet           │
         │   • Polygon                    │
         │   • Optimism                   │
         │   • Arbitrum                   │
         │   • Base                       │
         └────────────────────────────────┘
```

### Architectural Layers

1. **Service Layer** (`DeliveryService`): High-level orchestration and routing
2. **Interface Layer** (`DeliveryInterface`): Abstract contract for implementations
3. **Implementation Layer** (`AlloyDelivery`): Concrete blockchain interaction
4. **Transport Layer** (Alloy providers): Network communication with retry logic

---

## Core Components

### 1. DeliveryError

```rust
#[derive(Debug, Error)]
pub enum DeliveryError {
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("Transaction failed: {0}")]
    TransactionFailed(String),
    
    #[error("No implementation available")]
    NoImplementationAvailable,
}
```

**Purpose:** Unified error type for all delivery operations.

**Error Categories:**
- **Network**: RPC communication failures, invalid URLs, timeout
- **TransactionFailed**: Transaction reverted, monitoring timeout, confirmation failure
- **NoImplementationAvailable**: Chain ID not supported by any registered implementation

**Design Decision:** Uses `thiserror` for ergonomic error handling with automatic `Display` and `Error` trait implementations.

---

### 2. Transaction Monitoring Types

#### TransactionMonitoringEvent

```rust
#[derive(Debug, Clone)]
pub enum TransactionMonitoringEvent {
    Confirmed {
        id: String,              // order_id or other identifier
        tx_hash: TransactionHash,
        tx_type: TransactionType,
        receipt: TransactionReceipt,
    },
    Failed {
        id: String,
        tx_hash: TransactionHash,
        tx_type: TransactionType,
        error: String,
    },
}
```

**Purpose:** Event emitted when transaction state changes.

**Key Insights:**
- **Polymorphic Events**: Single enum handles both success and failure paths
- **Context-Rich**: Includes transaction type (Intent, Approval, Settlement, etc.)
- **Identification**: Uses generic `id` field for flexible tracking (order_id, request_id, etc.)
- **Receipt Attachment**: Success events include full transaction receipt with logs

#### TransactionCallback

```rust
pub type TransactionCallback = Box<dyn Fn(TransactionMonitoringEvent) + Send + Sync>;
```

**Purpose:** Async callback function invoked when transaction monitoring detects state change.

**Thread Safety:**
- `Send`: Can be transferred between threads
- `Sync`: Can be shared between threads
- Boxed for dynamic dispatch (different callback implementations)

#### TransactionTracking

```rust
pub struct TransactionTracking {
    pub id: String,
    pub tx_type: TransactionType,
    pub callback: TransactionCallback,
}
```

**Purpose:** Packages together all information needed to track a transaction.

**Why No Debug for Callback?** Function pointers cannot implement Debug, so custom Debug implementation excludes the callback field.

#### TransactionTrackingWithConfig

```rust
#[derive(Debug)]
pub struct TransactionTrackingWithConfig {
    pub tracking: TransactionTracking,
    pub min_confirmations: u64,
    pub monitoring_timeout_seconds: u64,
}
```

**Purpose:** Extends base tracking with service-level configuration.

**Separation of Concerns:**
- User provides: `id`, `tx_type`, `callback`
- Service provides: `min_confirmations`, `monitoring_timeout_seconds`

This allows users to track transactions without knowing about global service configuration.

---

## The DeliveryInterface Trait

### Complete Trait Definition

```rust
#[async_trait]
pub trait DeliveryInterface: Send + Sync {
    fn config_schema(&self) -> Box<dyn ConfigSchema>;
    
    async fn submit(
        &self,
        tx: Transaction,
        tracking: Option<TransactionTrackingWithConfig>,
    ) -> Result<TransactionHash, DeliveryError>;
    
    async fn get_receipt(
        &self,
        hash: &TransactionHash,
        chain_id: u64,
    ) -> Result<TransactionReceipt, DeliveryError>;
    
    async fn get_gas_price(&self, chain_id: u64) -> Result<String, DeliveryError>;
    
    async fn get_balance(
        &self,
        address: &str,
        token: Option<&str>,
        chain_id: u64,
    ) -> Result<String, DeliveryError>;
    
    async fn get_allowance(
        &self,
        owner: &str,
        spender: &str,
        token_address: &str,
        chain_id: u64,
    ) -> Result<String, DeliveryError>;
    
    async fn get_nonce(&self, address: &str, chain_id: u64) -> Result<u64, DeliveryError>;
    
    async fn get_block_number(&self, chain_id: u64) -> Result<u64, DeliveryError>;
    
    async fn estimate_gas(&self, tx: Transaction) -> Result<u64, DeliveryError>;
    
    async fn eth_call(&self, tx: Transaction) -> Result<Bytes, DeliveryError>;
}
```

### Method Analysis

#### 1. `config_schema()` - Self-Describing Configuration

**Purpose:** Returns validation schema for TOML configuration.

**Why?** Each implementation has different configuration needs:
- Alloy needs: `network_ids`, optional per-network `accounts`
- Future implementations might need: API keys, custom endpoints, etc.

**Design Pattern:** Self-documenting configuration with compile-time validation.

#### 2. `submit()` - Core Transaction Submission

**Signature Analysis:**
```rust
async fn submit(
    &self,
    tx: Transaction,              // What to send
    tracking: Option<...>,         // How to monitor
) -> Result<TransactionHash, DeliveryError>
```

**Key Design Decisions:**

1. **Async**: Transaction submission is I/O-bound
2. **Ownership**: Takes `tx` by value (transaction is consumed)
3. **Optional Tracking**: Monitoring is opt-in for flexibility
4. **Returns Hash Immediately**: Doesn't wait for confirmation (fire-and-forget with optional monitoring)

**Implementation Responsibilities:**
- Parse transaction to native format (Alloy's `TransactionRequest`)
- Sign with appropriate key for `tx.chain_id`
- Submit to RPC endpoint
- Spawn background task for monitoring (if tracking provided)
- Return transaction hash immediately

#### 3. `get_receipt()` - Transaction Status Query

**Purpose:** Retrieve transaction receipt after submission.

**Use Cases:**
- Manual polling for transaction status
- Recovery after crash (re-query using persisted tx_hash)
- Confirmation before proceeding with dependent operations

**Why Separate from Monitoring?** Decouples synchronous queries from asynchronous event callbacks.

#### 4. `get_gas_price()` - Dynamic Fee Estimation

**Returns:** String representation of gas price in **wei**.

**Why String?** 
- Avoids precision loss for large numbers (U256)
- Cross-platform serialization (JSON)
- Language-agnostic representation

#### 5. `get_balance()` - Balance Query

**Polymorphic Design:**
```rust
token: Option<&str>
```

- `None`: Native token balance (ETH, MATIC, etc.)
- `Some(address)`: ERC-20 token balance

**Implementation Strategy:**
- Native: Direct RPC call (`eth_getBalance`)
- ERC-20: Contract call with `balanceOf(address)` selector

#### 6. `get_allowance()` - ERC-20 Approval Check

**Purpose:** Query how much a spender can transfer on behalf of an owner.

**Critical for Intent System:** Before submitting intents, solver must verify it has sufficient allowance to transfer user tokens.

**Flow:**
```
1. Check allowance
2. If insufficient → Submit approval transaction
3. Wait for approval confirmation
4. Submit intent transaction
```

#### 7. `estimate_gas()` - Pre-Execution Gas Estimation

**Purpose:** Calculate gas required without submitting transaction.

**Use Cases:**
- Gas estimation for user quotes
- Profitability calculation before execution
- Setting optimal `gas_limit` to avoid out-of-gas failures

**Alloy Implementation:** Calls `eth_estimateGas` RPC method.

#### 8. `eth_call()` - Read-Only Contract Interaction

**Purpose:** Simulate transaction execution without state changes.

**Use Cases:**
- Reading contract state
- Simulating transaction outcomes
- Checking if transaction would revert
- Decoding complex contract return values

**Returns:** Raw `Bytes` - caller responsible for ABI decoding.

---

## DeliveryService: The Orchestrator

### Structure

```rust
pub struct DeliveryService {
    implementations: HashMap<u64, Arc<dyn DeliveryInterface>>,
    min_confirmations: u64,
    monitoring_timeout_seconds: u64,
}
```

### Field Analysis

#### `implementations: HashMap<u64, Arc<dyn DeliveryInterface>>`

**Why HashMap?** O(1) lookup by chain ID for fast routing.

**Why Arc?** 
- Shared ownership across multiple async tasks
- Thread-safe reference counting
- Multiple service methods can use same implementation concurrently

**Type Erasure:** `dyn DeliveryInterface` allows heterogeneous implementations:
```rust
// Hypothetical multi-implementation scenario
implementations = {
    1: Arc<AlloyDelivery>,      // Ethereum via Alloy
    137: Arc<AlloyDelivery>,    // Polygon via Alloy
    999: Arc<CustomDelivery>,   // Custom chain via different implementation
}
```

#### `min_confirmations: u64`

**Purpose:** Number of blocks to wait before considering transaction "confirmed".

**Why Configurable?**
- Different chains have different finality guarantees
- Different use cases have different risk tolerances

**Typical Values:**
- Ethereum L1: 12-15 confirmations (high security)
- Optimism/Arbitrum: 1-2 confirmations (faster finality)
- Polygon: 128 confirmations (for bridge security)

#### `monitoring_timeout_seconds: u64`

**Purpose:** Maximum time to wait for transaction confirmation.

**Why Needed?**
- Prevents indefinite hanging on stuck transactions
- Allows retry logic at higher levels
- Resource cleanup (background monitoring tasks)

**Typical Value:** 300 seconds (5 minutes)

### Key Methods

#### `deliver()` - Main Entry Point

```rust
pub async fn deliver(
    &self,
    tx: Transaction,
    tracking: Option<TransactionTracking>,
) -> Result<TransactionHash, DeliveryError>
```

**Flow:**
```
1. Extract chain_id from transaction
2. Lookup implementation by chain_id
3. If tracking provided:
   - Enhance with service configuration (min_confirmations, timeout)
4. Delegate to implementation.submit()
5. Return transaction hash
```

**Key Pattern:** **Decorator Pattern** - Service enhances user-provided tracking with its configuration.

#### `get_chain_data()` - Aggregated State Query

```rust
pub async fn get_chain_data(&self, chain_id: u64) -> Result<ChainData, DeliveryError>
```

**What it does:**
```rust
ChainData {
    chain_id,
    gas_price,        // From get_gas_price()
    block_number,     // From get_block_number()
    timestamp,        // Current system time
}
```

**Purpose:** Single call to get all state needed for transaction construction.

**Use Case:** Before submitting transactions, solver queries chain data to:
- Set appropriate gas price
- Check if transaction deadline is still valid
- Log execution context

---

## Alloy Implementation Deep Dive

### AlloyDelivery Structure

```rust
pub struct AlloyDelivery {
    providers: HashMap<u64, DynProvider>,
}
```

**Design Decision:** Single struct manages multiple chains via provider pool.

**Alternative Design (Rejected):**
```rust
// One implementation per chain
struct AlloyDeliveryEthereum { provider: DynProvider }
struct AlloyDeliveryPolygon { provider: DynProvider }
```

**Why Rejected?** Code duplication, harder configuration, unnecessary complexity.

### Provider Architecture

```
DynProvider = ProviderBuilder
    .filler(NonceFiller)           // Auto-fills nonces
    .filler(GasFiller)              // Auto-fills gas estimates
    .filler(ChainIdFiller)          // Auto-fills chain ID
    .wallet(EthereumWallet)         // Signs transactions
    .connect_client(RpcClient)      // HTTP transport with retry
```

#### Fillers Explained

**1. NonceFiller (SimpleNonceManager)**
```rust
.filler(NonceFiller::new(SimpleNonceManager::default()))
```

**Purpose:** Automatically tracks and assigns transaction nonces.

**Why Needed?** 
- Each account on Ethereum has a nonce (transaction counter)
- Nonces must be sequential: 0, 1, 2, 3...
- If nonce is wrong → transaction rejected
- Manual nonce management is error-prone

**How it Works:**
```
1. First transaction → Query RPC for current nonce
2. Subsequent transactions → Increment locally
3. Cache prevents redundant RPC calls
4. Thread-safe for concurrent transactions
```

**2. GasFiller**
```rust
.filler(GasFiller)
```

**Purpose:** Automatically estimates and sets gas parameters.

**What it fills:**
- `gas_limit`: Maximum gas transaction can consume
- `max_fee_per_gas`: Maximum willing to pay (EIP-1559)
- `max_priority_fee_per_gas`: Miner tip (EIP-1559)

**Estimation Logic:**
1. Calls `eth_estimateGas` with transaction
2. Adds buffer (typically 20-30%) to prevent out-of-gas
3. Queries `eth_feeHistory` for fee recommendations
4. Sets EIP-1559 or legacy gas parameters based on chain support

**3. ChainIdFiller**
```rust
.filler(ChainIdFiller::default())
```

**Purpose:** Ensures transaction includes correct chain ID for replay protection.

**Replay Attack Prevention:**
- Without chain ID, transaction valid on all chains
- Attacker could submit your Ethereum transaction on Polygon
- Chain ID in signature prevents cross-chain replay

#### Wallet Integration

```rust
let signer = PrivateKeySigner::from_str(private_key)?
    .with_chain_id(Some(network_id));

let wallet = EthereumWallet::from(signer);
```

**Signing Flow:**
```
1. Provider receives unsigned transaction
2. Fillers populate missing fields
3. Wallet signs transaction with ECDSA
4. Signed transaction submitted to RPC
```

**Security Note:** Private keys never leave the process - signing is local.

### Constructor Analysis

```rust
pub async fn new(
    network_ids: Vec<u64>,
    networks: &NetworksConfig,
    signers: HashMap<u64, PrivateKeySigner>,
    default_signer: PrivateKeySigner,
) -> Result<Self, DeliveryError>
```

**Parameters:**

1. **network_ids**: Which chains to support
2. **networks**: RPC URLs and config for each chain
3. **signers**: Per-network signing keys (optional, for multi-account scenarios)
4. **default_signer**: Fallback key if no specific signer for a chain

**Why Per-Network Signers?**

**Use Case:** Multi-account portfolio management
```
Chain 1 (Ethereum):  Account A (high-value operations)
Chain 137 (Polygon): Account B (high-frequency operations)
Chain 10 (Optimism): Account A (same as Ethereum)
```

Different risk profiles → different keys.

**Construction Flow:**

```rust
for network_id in &network_ids {
    // 1. Get network config
    let network = networks.get(network_id)?;
    
    // 2. Extract RPC URL
    let http_url = network.get_http_url()?;
    
    // 3. Get signer (per-network or default)
    let signer = signers.get(network_id).unwrap_or(&default_signer);
    
    // 4. Create wallet with chain ID
    let chain_signer = signer.clone().with_chain_id(Some(*network_id));
    let wallet = EthereumWallet::from(chain_signer);
    
    // 5. Configure retry layer
    let retry_policy = RateLimitRetryPolicy::default()
        .or(|error| /* custom retry logic */);
    let retry_layer = RetryBackoffLayer::new_with_policy(3, 1500, 10, retry_policy);
    
    // 6. Build provider
    let provider = ProviderBuilder::new()
        .filler(NonceFiller::new(SimpleNonceManager::default()))
        .filler(GasFiller)
        .filler(ChainIdFiller::default())
        .wallet(wallet)
        .connect_client(RpcClient::builder().layer(retry_layer).http(url));
    
    // 7. Store in providers map
    providers.insert(*network_id, provider.erased());
}
```

### Retry Policy Deep Dive

```rust
let retry_policy = RateLimitRetryPolicy::default().or(|error: &TransportError| {
    match error {
        TransportError::ErrorResp(payload) => {
            // Retry execution reverts (error code 3)
            payload.code == 3 && payload.message.contains("execution reverted")
        },
        _ => false,
    }
});

let retry_layer = RetryBackoffLayer::new_with_policy(
    3,      // max_retry: up to 3 retries
    1500,   // backoff: 1.5 second initial delay
    10,     // cups: compute units per second (rate limit)
    retry_policy,
);
```

**Default Policy (RateLimitRetryPolicy):**
- HTTP 429 (Too Many Requests)
- HTTP 503 (Service Unavailable)
- Connection timeouts
- DNS failures

**Custom Extension:**
- **Error Code 3**: Execution reverted
- **Why Retry?** Some reverts are temporary:
  - Oracle price updates in progress
  - Contract state changing rapidly
  - Race condition in mempool

**Backoff Strategy:**
```
Attempt 1: 1500ms delay
Attempt 2: 3000ms delay (exponential)
Attempt 3: 6000ms delay
```

**Rate Limiting:**
- `cups = 10`: 10 compute units per second
- Prevents overwhelming RPC provider
- Complies with rate limit policies (e.g., Infura, Alchemy)

---

## Transaction Monitoring System

### Core Function: `monitor_transaction()`

```rust
async fn monitor_transaction(
    pending_tx: PendingTransactionBuilder<Ethereum>,
    min_confirmations: u64,
    monitoring_timeout_seconds: u64,
) -> Result<TransactionReceipt, DeliveryError>
```

**Purpose:** Wait for transaction confirmation in background task.

**Implementation:**

```rust
let timeout_duration = Duration::from_secs(monitoring_timeout_seconds);

match pending_tx
    .with_required_confirmations(min_confirmations)
    .with_timeout(Some(timeout_duration))
    .get_receipt()  // Blocks until confirmed or timeout
    .await
{
    Ok(receipt) => Ok(TransactionReceipt::from(&receipt)),
    Err(e) => Err(DeliveryError::TransactionFailed(format!("...: {}", e))),
}
```

**Why `get_receipt()` Instead of `watch()`?**

**Problem with `watch()`:**
```rust
// watch() uses WebSocket subscriptions to new blocks
// Race condition: if transaction mined before subscription establishes,
// block is missed and monitoring hangs indefinitely
```

**Solution with `get_receipt()`:**
```rust
// get_receipt() uses polling fallback
// Directly queries eth_getTransactionReceipt in loop
// Cannot miss transaction even if initial block is skipped
```

**Reference:** [Alloy Issue #389](https://github.com/alloy-rs/alloy/issues/389)

### Monitoring Lifecycle

```
                           submit()
                              │
                              ├─ Submit transaction to RPC
                              │
                              ├─ Get tx_hash immediately
                              │
                              ├─ Return tx_hash to caller
                              │
                              └─ IF tracking provided:
                                    │
                                    └─ tokio::spawn(async {
                                          │
                                          ├─ Call monitor_transaction()
                                          │
                                          ├─ Wait for min_confirmations
                                          │
                                          └─ Invoke callback with event
                                              │
                                              ├─ Confirmed { receipt }
                                              │     OR
                                              └─ Failed { error }
                                       })
```

**Key Insight:** Monitoring is **non-blocking** - caller doesn't wait for confirmation.

**Implications:**
1. **Fast Response**: Submit many transactions quickly
2. **Async Notifications**: Learn about results via callbacks
3. **Resource Efficient**: No polling loops in caller code
4. **Failure Recovery**: Timeout ensures cleanup even if transaction stuck

---

## Configuration Architecture

### Configuration Schema System

```rust
pub trait ConfigSchema {
    fn validate(&self, config: &toml::Value) -> Result<(), ValidationError>;
}
```

**Purpose:** Type-safe validation of TOML configuration files.

### Alloy Schema Implementation

```rust
pub struct AlloyDeliverySchema;

impl ConfigSchema for AlloyDeliverySchema {
    fn validate(&self, config: &toml::Value) -> Result<(), ValidationError> {
        let schema = Schema::new(
            // Required fields
            vec![
                Field::new(
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
                })
            ],
            // Optional fields
            vec![
                Field::new(
                    "accounts",
                    FieldType::Table(Schema::new(vec![], vec![])),
                )
                .with_validator(|value| {
                    if let Some(table) = value.as_table() {
                        for (key, val) in table {
                            // Validate key is valid network ID
                            if key.parse::<u64>().is_err() {
                                return Err(format!("Invalid network ID: {}", key));
                            }
                            // Validate value is string (account name)
                            if !val.is_str() {
                                return Err(format!(
                                    "Account name for network {} must be a string",
                                    key
                                ));
                            }
                        }
                        Ok(())
                    } else {
                        Err("accounts must be a table".to_string())
                    }
                })
            ],
        );
        
        schema.validate(config)
    }
}
```

### Configuration Example

```toml
[delivery]
type = "evm_alloy"
network_ids = [1, 137, 10, 42161]

# Optional: Per-network account mapping
[delivery.accounts]
1 = "ethereum_main"     # Use account named "ethereum_main" for Ethereum
137 = "polygon_main"     # Use account named "polygon_main" for Polygon
```

**Validation Flow:**

```
1. Load TOML file
2. Find [delivery] section
3. Lookup factory by type ("evm_alloy")
4. Call schema.validate(config)
   ├─ Check network_ids exists
   ├─ Check network_ids is array
   ├─ Check network_ids not empty
   ├─ Check all network_ids >= 1
   ├─ If accounts exists:
   │  ├─ Check accounts is table
   │  ├─ Check all keys are valid u64
   │  └─ Check all values are strings
5. If validation passes → call factory
6. Factory creates AlloyDelivery instance
```

**Why Schema Validation?**

**Without Validation:**
```toml
[delivery]
type = "evm_alloy"
network_ids = "oops"  # Should be array
```

**Error:**
```
thread 'main' panicked at 'called `Option::unwrap()` on a `None` value'
```

**With Validation:**
```
Error: Invalid configuration: network_ids must be an array
```

**Benefits:**
- Early error detection (config load vs. first use)
- Clear error messages
- Self-documenting configuration structure

---

## Registry Pattern

### Purpose

Enable **compile-time registration** of implementations without modifying core service code.

### Implementation

```rust
pub trait DeliveryRegistry: ImplementationRegistry<Factory = DeliveryFactory> {}

pub fn get_all_implementations() -> Vec<(&'static str, DeliveryFactory)> {
    use implementations::evm::alloy;
    
    vec![
        (alloy::Registry::NAME, alloy::Registry::factory())
    ]
}
```

### Registry for Alloy Implementation

```rust
pub struct Registry;

impl solver_types::ImplementationRegistry for Registry {
    const NAME: &'static str = "evm_alloy";
    type Factory = crate::DeliveryFactory;
    
    fn factory() -> Self::Factory {
        create_http_delivery
    }
}

impl crate::DeliveryRegistry for Registry {}
```

### Factory Function

```rust
pub type DeliveryFactory = fn(
    &toml::Value,                                  // Configuration
    &NetworksConfig,                               // Network endpoints
    &solver_types::SecretString,                   // Default private key
    &HashMap<u64, solver_types::SecretString>,     // Per-network keys
) -> Result<Box<dyn DeliveryInterface>, DeliveryError>;
```

### How Registration Works

**1. Define Implementation:**
```rust
// implementations/evm/alloy.rs
pub struct AlloyDelivery { /* ... */ }

impl DeliveryInterface for AlloyDelivery { /* ... */ }
```

**2. Define Factory:**
```rust
pub fn create_http_delivery(
    config: &toml::Value,
    networks: &NetworksConfig,
    default_private_key: &SecretString,
    network_private_keys: &HashMap<u64, SecretString>,
) -> Result<Box<dyn DeliveryInterface>, DeliveryError> {
    // Validate config
    AlloyDeliverySchema::validate_config(config)?;
    
    // Parse configuration
    let network_ids = /* extract from config */;
    
    // Create signers
    let default_signer = default_private_key.with_exposed(|key| key.parse())?;
    let network_signers = /* parse network keys */;
    
    // Create instance (async in sync context)
    let delivery = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            AlloyDelivery::new(network_ids, networks, network_signers, default_signer).await
        })
    })?;
    
    Ok(Box::new(delivery))
}
```

**3. Register Implementation:**
```rust
pub struct Registry;

impl ImplementationRegistry for Registry {
    const NAME: &'static str = "evm_alloy";
    type Factory = DeliveryFactory;
    
    fn factory() -> Self::Factory {
        create_http_delivery
    }
}
```

**4. Collect All Implementations:**
```rust
pub fn get_all_implementations() -> Vec<(&'static str, DeliveryFactory)> {
    vec![
        (alloy::Registry::NAME, alloy::Registry::factory()),
        // Future: (cosmos::Registry::NAME, cosmos::Registry::factory()),
        // Future: (solana::Registry::NAME, solana::Registry::factory()),
    ]
}
```

### Dynamic Dispatch at Runtime

```rust
// In main application startup
let implementations = solver_delivery::get_all_implementations();
let factory_map: HashMap<&str, DeliveryFactory> = implementations.into_iter().collect();

// When loading config
let delivery_type = config.get("delivery").get("type").as_str(); // "evm_alloy"
let factory = factory_map.get(delivery_type).unwrap();

let delivery_impl = factory(
    &config,
    &networks,
    &default_key,
    &network_keys,
)?;
```

**Benefits:**
- **Extensibility**: Add new implementations without modifying core
- **Type Safety**: Factory signature enforced at compile time
- **No Macros**: Pure Rust, no proc macros or reflection
- **Documentation**: Each implementation self-describes via schema

---

## Data Flow Analysis

### Transaction Submission Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│ 1. Application Layer (e.g., solver-core)                           │
└─────────────────────────────────────────────────────────────────────┘
                            │
                            │ Creates Transaction
                            │
                            ▼
                   ┌─────────────────┐
                   │   Transaction   │
                   │   {             │
                   │     chain_id: 1 │
                   │     to: 0x...   │
                   │     data: [...]  │
                   │     value: 0    │
                   │   }             │
                   └─────────────────┘
                            │
                            │ + TransactionTracking (optional)
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 2. DeliveryService.deliver()                                        │
│    - Lookup implementation by chain_id                              │
│    - Enhance tracking with service config                           │
└─────────────────────────────────────────────────────────────────────┘
                            │
                            │ Routes to chain-specific implementation
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 3. AlloyDelivery.submit()                                           │
│    - Get provider for chain_id                                      │
│    - Convert Transaction → TransactionRequest                       │
└─────────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 4. Alloy Provider Pipeline                                          │
│    ┌──────────────────────────────────────────────────────────────┐│
│    │ NonceFiller: Query/fill nonce                                ││
│    └──────────────────────────────────────────────────────────────┘│
│    ┌──────────────────────────────────────────────────────────────┐│
│    │ GasFiller: Estimate gas, fill gas parameters                ││
│    └──────────────────────────────────────────────────────────────┘│
│    ┌──────────────────────────────────────────────────────────────┐│
│    │ ChainIdFiller: Fill chain_id                                 ││
│    └──────────────────────────────────────────────────────────────┘│
│    ┌──────────────────────────────────────────────────────────────┐│
│    │ Wallet: Sign transaction with private key                    ││
│    └──────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────┘
                            │
                            │ Signed transaction
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 5. RPC Client with Retry Layer                                      │
│    - Execute: eth_sendRawTransaction                                │
│    - On failure: Retry with exponential backoff                     │
└─────────────────────────────────────────────────────────────────────┘
                            │
                            │ HTTP POST
                            │
                            ▼
                   ┌──────────────────┐
                   │  Blockchain RPC  │
                   │   (Alchemy,      │
                   │    Infura, etc.) │
                   └──────────────────┘
                            │
                            │ Returns tx_hash
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 6. Response Handling                                                 │
│    - Extract tx_hash                                                │
│    - Return to caller immediately                                   │
│    - IF tracking: spawn monitoring task                             │
└─────────────────────────────────────────────────────────────────────┘
        │                               │
        │                               │ (if tracking enabled)
        │                               │
        ▼                               ▼
   Caller receives            ┌─────────────────────────────┐
   tx_hash and                │  Background Monitoring Task │
   continues                  │  tokio::spawn(async {       │
   execution                  │    monitor_transaction()     │
                              │  })                         │
                              └─────────────────────────────┘
                                        │
                                        │ Polls for receipt
                                        │
                                        ▼
                              ┌─────────────────────────────┐
                              │ Wait for confirmations      │
                              │ (get_receipt with timeout)  │
                              └─────────────────────────────┘
                                        │
                     ┌──────────────────┴─────────────────┐
                     │                                    │
              Success│                                    │ Failure/Timeout
                     ▼                                    ▼
         ┌────────────────────────┐         ┌────────────────────────┐
         │ TransactionMonitoring  │         │ TransactionMonitoring  │
         │ Event::Confirmed       │         │ Event::Failed          │
         │ {                      │         │ {                      │
         │   id, tx_hash,         │         │   id, tx_hash,         │
         │   receipt              │         │   error                │
         │ }                      │         │ }                      │
         └────────────────────────┘         └────────────────────────┘
                     │                                    │
                     └──────────────┬─────────────────────┘
                                    │
                                    │ Invoke callback
                                    │
                                    ▼
                          ┌──────────────────────┐
                          │ Application callback │
                          │ processes event      │
                          └──────────────────────┘
```

### ERC-20 Balance Query Flow

```
Application calls delivery_service.get_balance(chain_id, address, Some(token_address))
                                │
                                ▼
              DeliveryService routes to AlloyDelivery by chain_id
                                │
                                ▼
              AlloyDelivery.get_balance(address, Some(token_address), chain_id)
                                │
                                ├─ Parse addresses
                                │
                                ├─ Construct call data:
                                │    Function: balanceOf(address)
                                │    Selector: 0x70a08231
                                │    Parameter: address (padded to 32 bytes)
                                │
                                ▼
              provider.call(TransactionRequest {
                  to: token_address,
                  data: selector + padded_address,
              })
                                │
                                │ eth_call RPC
                                │
                                ▼
                    Blockchain executes call (read-only)
                                │
                                │ Returns bytes
                                │
                                ▼
              Parse response as U256 (32 bytes)
                                │
                                │
                                ▼
              Return balance.to_string()
                                │
                                ▼
              Application receives "1234567890000000000" (1.23 tokens with 18 decimals)
```

---

## Error Handling Strategy

### Error Propagation Pattern

```rust
// Layer 1: Transport errors (Alloy internal)
TransportError::ErrorResp { code, message }

// Layer 2: Delivery errors (this crate)
DeliveryError::Network("Failed to send transaction: ...")

// Layer 3: Service errors (caller)
match delivery_service.deliver(tx, tracking).await {
    Ok(tx_hash) => { /* success */ },
    Err(DeliveryError::Network(msg)) => { /* retry? */ },
    Err(DeliveryError::TransactionFailed(msg)) => { /* log and alert */ },
    Err(DeliveryError::NoImplementationAvailable) => { /* configuration error */ },
}
```

### Error Context Enrichment

**Bad:**
```rust
Err(DeliveryError::Network("Failed to send transaction".to_string()))
```

**Good:**
```rust
provider.send_transaction(request)
    .await
    .map_err(|e| {
        tracing::error!("Transaction submission failed on chain {}: {}", chain_id, e);
        DeliveryError::Network(format!("Failed to send transaction: {}", e))
    })?
```

**Why?**
- Includes chain_id for debugging multi-chain scenarios
- Logs error before returning (preserves stack trace)
- Wraps original error message for context

### Retry vs. Fail Fast

**Retryable Errors:**
- Rate limits (429)
- Temporary network failures (503)
- Temporary execution reverts (state in flux)

**Fail Fast Errors:**
- Invalid addresses (parse error)
- Insufficient funds (permanent until balance changes)
- Invalid nonce (indicates out-of-sync state)
- Authentication failures (invalid private key)

**Implementation:**
```rust
// In retry policy
TransportError::ErrorResp(payload) => {
    payload.code == 3 && payload.message.contains("execution reverted")
}
```

Only retries reverts (code 3), not other errors.

---

## Network Resilience

### Timeout Configuration

```rust
provider.client().set_poll_interval(Duration::from_secs(7));
```

**Purpose:** How often to poll for new blocks/transaction receipts.

**Why 7 seconds?**
- Ethereum block time: ~12 seconds
- Poll interval: ~60% of block time
- Balance between responsiveness and RPC load

### Monitoring Timeout

```rust
let timeout_duration = Duration::from_secs(monitoring_timeout_seconds);

pending_tx
    .with_timeout(Some(timeout_duration))
    .get_receipt()
    .await
```

**Failure Scenarios:**

1. **Network Partition**: RPC provider unreachable
   - Timeout prevents indefinite hanging
   - Caller can retry with different RPC provider

2. **Stuck Transaction**: Gas price too low, transaction never mined
   - Timeout allows resubmission with higher gas
   - User alerted of failure

3. **Chain Reorganization**: Transaction included then reverted
   - Monitoring catches revert
   - Callback invoked with Failed event

### Connection Pooling

Alloy's `DynProvider` internally manages:
- HTTP connection pool (via `reqwest`)
- Keep-alive connections
- Automatic reconnection on connection loss

**Configuration:**
```rust
// Implicit in RpcClient::builder().http(url)
// Uses reqwest defaults:
// - Pool size: based on system resources
// - Connection timeout: 30s
// - Keep-alive: enabled
```

---

## Testing Strategy

### Unit Tests

#### 1. Configuration Validation Tests

```rust
#[test]
fn test_config_schema_validation_valid() {
    let schema = AlloyDeliverySchema;
    let config = toml::Value::Table({
        let mut table = toml::map::Map::new();
        table.insert(
            "network_ids".to_string(),
            toml::Value::Array(vec![toml::Value::Integer(1)]),
        );
        table
    });
    
    let result = schema.validate(&config);
    assert!(result.is_ok());
}
```

**Tests:**
- Valid configuration passes
- Empty network_ids rejected
- Invalid account mapping rejected
- Type mismatches caught

#### 2. Constructor Tests

```rust
#[tokio::test]
async fn test_alloy_delivery_new_success() {
    let networks = create_test_networks();
    let signer = create_test_signer();
    
    let result = AlloyDelivery::new(
        vec![1],
        &networks,
        HashMap::new(),
        signer
    ).await;
    
    assert!(result.is_ok());
    let delivery = result.unwrap();
    assert!(delivery.providers.contains_key(&1));
}
```

**Tests:**
- Successful initialization
- Empty networks rejected
- Missing network configuration handled
- Provider correctly stored per chain

#### 3. Factory Tests

```rust
#[tokio::test(flavor = "multi_thread")]
async fn test_create_http_delivery_success() {
    let config = /* TOML config */;
    let networks = create_test_networks();
    let default_key = SecretString::from("0x...");
    let network_keys = HashMap::new();
    
    let result = create_http_delivery(
        &config,
        &networks,
        &default_key,
        &network_keys
    );
    
    assert!(result.is_ok());
}
```

**Note:** Uses `multi_thread` flavor because factory spawns async tasks.

### Integration Testing Strategy

**Challenge:** Testing blockchain interaction requires:
- Running blockchain node (expensive)
- Managing test accounts with funds
- Dealing with transaction finality delays

**Solution:** Layered testing approach

**Layer 1: Mock RPC Server**
```rust
// Not shown in code, but recommended approach
use wiremock::{MockServer, Mock, ResponseTemplate};

#[tokio::test]
async fn test_submit_transaction_success() {
    let mock_server = MockServer::start().await;
    
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200)
            .set_body_json(json!({
                "jsonrpc": "2.0",
                "result": "0xabcd...",
                "id": 1
            })))
        .mount(&mock_server)
        .await;
    
    // Test with mock server URL
}
```

**Layer 2: Local Testnet (Anvil/Hardhat)**
```bash
# Start local Ethereum node
anvil --chain-id 1

# Run integration tests
cargo test --test integration
```

**Layer 3: Public Testnet (Goerli, Sepolia)**
```bash
# Requires funded test account
export TEST_PRIVATE_KEY="0x..."
export TEST_RPC_URL="https://..."

cargo test --test testnet_integration
```

---

## Integration Points

### 1. solver-types

**Dependencies:**
```rust
use solver_types::{
    Transaction,
    TransactionHash,
    TransactionReceipt,
    ChainData,
    NetworksConfig,
    SecretString,
    ConfigSchema,
    ImplementationRegistry,
};
```

**Purpose:** Shared type definitions used across all solver crates.

### 2. solver-account

**Dependency:**
```toml
solver-account = { path = "../solver-account" }
```

**Usage:** Not directly used in code, but conceptually related.

**Relationship:** 
- solver-account: Manages account state (balances, nonces)
- solver-delivery: Executes transactions to modify account state

### 3. solver-core

**Integration:**
```rust
// In solver-core
let delivery_service = DeliveryService::new(
    implementations,
    min_confirmations,
    monitoring_timeout_seconds,
);

// Submit settlement transaction
let tx = Transaction {
    chain_id: 1,
    to: Some(settlement_contract),
    data: encoded_call,
    value: U256::ZERO,
    gas_limit: Some(500_000),
    // ...
};

let tx_hash = delivery_service.deliver(tx, Some(tracking)).await?;
```

### 4. Configuration System

**File:** `config/demo.toml`
```toml
[delivery]
type = "evm_alloy"
network_ids = [1, 137, 10]
min_confirmations = 12
monitoring_timeout_seconds = 300
```

**Loading:**
```rust
// In solver-config
let config = load_config("config/demo.toml")?;
let delivery_config = config.get("delivery")?;

// Get factory from registry
let implementations = solver_delivery::get_all_implementations();
let factory_map: HashMap<_, _> = implementations.into_iter().collect();
let factory = factory_map.get("evm_alloy")?;

// Create delivery implementation
let delivery_impl = factory(
    &delivery_config,
    &networks_config,
    &default_private_key,
    &network_private_keys,
)?;

// Create service
let delivery_service = DeliveryService::new(
    [(1, Arc::new(delivery_impl))].into_iter().collect(),
    12,
    300,
);
```

---

## Technical Decisions

### 1. Why Alloy Instead of ethers-rs?

**Alloy Advantages:**
- **Modern Architecture**: Built for async/await from ground up
- **Type Safety**: Stronger type system, fewer runtime errors
- **Performance**: More efficient serialization/deserialization
- **Modular**: Use only what you need (smaller binaries)
- **Active Development**: ethers-rs in maintenance mode

**Trade-offs:**
- **Maturity**: ethers-rs has larger production track record
- **Ecosystem**: Some tools still use ethers-rs
- **Documentation**: ethers-rs has more examples

**Decision:** Alloy chosen for future-proofing and performance.

### 2. Why Separate Service and Interface Layers?

**Benefits:**

**Flexibility:**
```rust
// Service can aggregate multiple implementations
implementations = {
    1: Arc<AlloyDelivery>,      // EVM chains via Alloy
    999: Arc<CosmosDelivery>,   // Cosmos via custom impl
}
```

**Cross-Cutting Concerns:**
```rust
// Service handles concerns common to all implementations
- Global confirmation policy
- Unified monitoring timeout
- Logging/metrics
- Rate limiting across all chains
```

**Testability:**
```rust
// Mock implementation for testing
struct MockDelivery { /* ... */ }
impl DeliveryInterface for MockDelivery { /* ... */ }

let test_service = DeliveryService::new(
    [(1, Arc::new(MockDelivery::new()))].into_iter().collect(),
    1,  // Minimal confirmations for fast tests
    10, // Short timeout for fast tests
);
```

### 3. Why Arc Instead of Box for Implementations?

**Arc (Chosen):**
```rust
implementations: HashMap<u64, Arc<dyn DeliveryInterface>>
```

**Allows:**
- Sharing implementations across threads
- Multiple concurrent transactions to same chain
- Background monitoring tasks holding references

**Box (Alternative):**
```rust
implementations: HashMap<u64, Box<dyn DeliveryInterface>>
```

**Problem:**
- Exclusive ownership
- Cannot share between async tasks
- Would require cloning entire implementation

**Decision:** Arc enables concurrent access critical for high-throughput systems.

### 4. Why String for Balances and Gas Prices?

**Alternatives Considered:**

**u128:**
```rust
fn get_balance(&self, ...) -> Result<u128, DeliveryError>
```
**Problem:** Insufficient for 256-bit values (EVM uses U256)

**U256:**
```rust
fn get_balance(&self, ...) -> Result<U256, DeliveryError>
```
**Problem:** 
- Requires importing specific U256 type
- Different crates have different U256 types (alloy vs ethers)
- Serialization issues (JSON doesn't support 256-bit integers)

**String (Chosen):**
```rust
fn get_balance(&self, ...) -> Result<String, DeliveryError>
```

**Benefits:**
- Universal representation
- No precision loss
- Easy serialization (JSON, TOML, etc.)
- Caller chooses parsing strategy (U256, BigInt, etc.)

**Trade-off:** Parsing overhead, but negligible compared to network I/O.

### 5. Why Sync Factory Function Instead of Async?

**Current:**
```rust
pub type DeliveryFactory = fn(
    &toml::Value,
    &NetworksConfig,
    &SecretString,
    &HashMap<u64, SecretString>,
) -> Result<Box<dyn DeliveryInterface>, DeliveryError>;
```

**Alternative:**
```rust
pub type DeliveryFactory = fn(...) -> Pin<Box<dyn Future<Output = Result<...>>>>;
```

**Problem with Async Factory:**
- Complex type signature
- Harder to store in collections
- Registry becomes more complex

**Solution:**
```rust
// Use block_in_place for sync factory with async initialization
pub fn create_http_delivery(...) -> Result<Box<dyn DeliveryInterface>, DeliveryError> {
    let delivery = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            AlloyDelivery::new(...).await
        })
    })?;
    
    Ok(Box::new(delivery))
}
```

**Benefits:**
- Simple factory signature
- Called during application startup (blocking acceptable)
- Keeps registry pattern clean

### 6. Why Optional Tracking Instead of Always On?

**Design:**
```rust
async fn submit(
    &self,
    tx: Transaction,
    tracking: Option<TransactionTrackingWithConfig>,
) -> Result<TransactionHash, DeliveryError>
```

**Scenarios:**

**Scenario 1: Fire-and-Forget**
```rust
// Submit approval transaction, don't care about confirmation
delivery.submit(approval_tx, None).await?;
```

**Scenario 2: Manual Polling**
```rust
let tx_hash = delivery.submit(tx, None).await?;

// Later, in separate task
loop {
    match delivery.get_receipt(&tx_hash, chain_id).await {
        Ok(receipt) => { /* process */ break; },
        Err(_) => tokio::time::sleep(Duration::from_secs(2)).await,
    }
}
```

**Scenario 3: Event-Driven**
```rust
let tracking = TransactionTracking {
    id: order_id.clone(),
    tx_type: TransactionType::Intent,
    callback: Box::new(move |event| {
        match event {
            TransactionMonitoringEvent::Confirmed { ... } => { /* update order */ },
            TransactionMonitoringEvent::Failed { ... } => { /* retry logic */ },
        }
    }),
};

delivery.submit(tx, Some(tracking)).await?;
```

**Decision:** Optional tracking provides maximum flexibility for different use cases.

---

## Conclusion

The `solver-delivery` crate is a **well-architected transaction delivery system** that demonstrates:

### Architectural Excellence
- **Separation of Concerns**: Clean boundaries between service, interface, and implementation
- **Extensibility**: Registry pattern enables adding new blockchain implementations without modifying core
- **Type Safety**: Comprehensive schema validation and strong typing throughout

### Production Readiness
- **Network Resilience**: Retry logic with exponential backoff, configurable timeouts
- **Multi-Chain Support**: Single service manages multiple chains with chain-specific configuration
- **Async-First Design**: Non-blocking operations, efficient resource usage

### Code Quality
- **Comprehensive Documentation**: Every type, method, and design decision documented
- **Error Handling**: Context-rich errors with proper propagation
- **Testing**: Unit tests for critical paths, integration test strategy defined

### Performance Considerations
- **Connection Pooling**: Reuses HTTP connections for RPC calls
- **Background Monitoring**: Non-blocking transaction tracking
- **Efficient Nonce Management**: Local caching reduces RPC calls

### Security Features
- **Local Signing**: Private keys never leave process
- **Replay Protection**: Chain ID in signatures
- **Rate Limiting**: Prevents overwhelming RPC providers

---

## Metrics and Observability

### Logging Points

```rust
// 1. Transaction submission
tracing::debug!(
    "Sending transaction on chain {}: to={:?}, value={:?}",
    chain_id, request.to, request.value
);

// 2. Transaction failure
tracing::error!(
    "Transaction submission failed on chain {}: {}",
    chain_id, e
);
```

### Recommended Additional Metrics

**Transaction Metrics:**
```rust
// Pseudo-code - not implemented
metrics::counter!("delivery.transactions.submitted", 1, "chain_id" => chain_id.to_string());
metrics::histogram!("delivery.transactions.gas_used", gas_used);
metrics::gauge!("delivery.transactions.pending", pending_count);
```

**Network Metrics:**
```rust
metrics::histogram!("delivery.rpc.latency", duration.as_millis(), "chain_id" => chain_id);
metrics::counter!("delivery.rpc.errors", 1, "error_type" => "rate_limit");
```

**Monitoring Metrics:**
```rust
metrics::histogram!("delivery.monitoring.confirmation_time", duration.as_secs());
metrics::counter!("delivery.monitoring.timeouts", 1);
```

---

## Future Enhancements

### 1. Multi-Provider Redundancy

**Current:** Single RPC provider per chain.

**Enhancement:**
```rust
providers: HashMap<u64, Vec<DynProvider>>  // Multiple providers per chain

// Fallback logic
for provider in providers.get(&chain_id) {
    match provider.send_transaction(request).await {
        Ok(result) => return Ok(result),
        Err(e) => {
            tracing::warn!("Provider failed, trying next: {}", e);
            continue;
        }
    }
}
```

### 2. Gas Price Optimization

**Current:** Uses default gas filler strategy.

**Enhancement:**
```rust
// Analyze recent blocks to find optimal gas price
async fn optimize_gas_price(&self, chain_id: u64) -> Result<u128, DeliveryError> {
    let history = provider.get_fee_history(20, "latest").await?;
    
    // Analyze percentiles
    let base_fee = history.base_fee_per_gas.last()?;
    let priority_fee = calculate_priority_fee(&history.reward)?;
    
    Ok(base_fee + priority_fee)
}
```

### 3. Transaction Replacement (Speed Up)

**Current:** No support for replacing pending transactions.

**Enhancement:**
```rust
async fn replace_transaction(
    &self,
    original_tx_hash: &TransactionHash,
    new_gas_price: u128,
) -> Result<TransactionHash, DeliveryError> {
    // Resubmit with same nonce but higher gas price
}
```

### 4. Batch Transaction Submission

**Current:** One transaction at a time.

**Enhancement:**
```rust
async fn submit_batch(
    &self,
    txs: Vec<Transaction>,
) -> Result<Vec<TransactionHash>, DeliveryError> {
    // Submit multiple transactions concurrently
    // Manage nonce sequencing
}
```

### 5. Non-EVM Blockchain Support

**Current:** Only EVM chains via Alloy.

**Potential Additions:**
- Cosmos chains (via cosmrs)
- Solana (via solana-sdk)
- Bitcoin (via bitcoin crate)

**Implementation:**
```rust
// implementations/cosmos/tendermint.rs
pub struct CosmosDelivery { /* ... */ }
impl DeliveryInterface for CosmosDelivery { /* ... */ }

pub struct Registry;
impl ImplementationRegistry for Registry {
    const NAME: &'static str = "cosmos_tendermint";
    // ...
}
```

---

## Appendix: Type Reference

### Transaction

```rust
pub struct Transaction {
    pub to: Option<Address>,              // Recipient (None = contract creation)
    pub data: Vec<u8>,                    // Calldata
    pub value: U256,                      // Native token amount
    pub chain_id: u64,                    // Network identifier
    pub nonce: Option<u64>,               // Transaction sequence number
    pub gas_limit: Option<u64>,           // Maximum gas
    pub gas_price: Option<u128>,          // Legacy gas price
    pub max_fee_per_gas: Option<u128>,    // EIP-1559 max fee
    pub max_priority_fee_per_gas: Option<u128>,  // EIP-1559 priority fee
}
```

### TransactionHash

```rust
pub struct TransactionHash(pub Vec<u8>);
```

**Why Vec instead of [u8; 32]?**
- Future-proofing for non-EVM chains (variable hash sizes)
- Easier serialization/deserialization

### TransactionReceipt

```rust
pub struct TransactionReceipt {
    pub hash: TransactionHash,       // Transaction identifier
    pub block_number: u64,           // Block inclusion height
    pub success: bool,               // Execution status
    pub logs: Vec<Log>,              // Emitted events
    pub block_timestamp: Option<u64>,  // Block time (if available)
}
```

### Log

```rust
pub struct Log {
    pub address: Address,        // Contract that emitted event
    pub topics: Vec<H256>,       // Indexed parameters
    pub data: Vec<u8>,           // Non-indexed data
}
```

**Topics Explained:**
- `topics[0]`: Event signature hash (e.g., keccak256("Transfer(address,address,uint256)"))
- `topics[1..n]`: Indexed parameters

**Example Transfer Event:**
```solidity
event Transfer(address indexed from, address indexed to, uint256 value);
```

**Log Structure:**
```rust
Log {
    address: "0x...token_address",
    topics: [
        H256("0x...transfer_signature"),  // keccak256("Transfer(address,address,uint256)")
        H256("0x...from_address"),
        H256("0x...to_address"),
    ],
    data: [...value_bytes...],  // uint256 value (not indexed)
}
```

---

## Summary

The `solver-delivery` crate exemplifies **modern Rust async systems design**:

✅ **Trait-based abstraction** for multiple implementations  
✅ **Service layer** for cross-cutting concerns  
✅ **Registry pattern** for extensibility  
✅ **Comprehensive error handling** with context  
✅ **Network resilience** with retry and timeout  
✅ **Type-safe configuration** with schema validation  
✅ **Production-ready** with logging and testing  
✅ **Well-documented** with extensive inline comments  

This crate serves as the **reliable foundation** for blockchain transaction delivery in the OIF solver system, handling the complexities of multi-chain transaction submission while providing a clean, simple API to higher-level components.

