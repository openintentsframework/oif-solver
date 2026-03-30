# Automated Cross-Chain Rebalancing via LayerZero OFT

**Date:** 2026-03-27
**Status:** Draft
**Target:** April 10, 2026 (MVP)
**Chains (MVP):** Katana (747474) <-> Ethereum (1)
**Token (MVP):** USDC / vbUSDC (Vaultbridge)
**Bridge Protocol:** LayerZero V2 OFT

---

## 1. Problem

The OIF Solver holds token balances on each chain it operates on. When a chain's liquidity depletes, an admin must manually bridge funds — a slow process that creates operational risk and limits the solver's ability to fill orders.

## 2. Solution

Automated cross-chain rebalancing. The admin configures a target balance and tolerance band per token per chain. A background monitor checks balances at a configurable interval and automatically bridges tokens via LayerZero OFT when they drift outside the band.

## 3. Key Design Decisions

| Dimension | Choice | Rationale |
|-----------|--------|-----------|
| Bridge Protocol | LayerZero V2 OFT | Vaultbridge tokens (vbUSDC) are native OFTs on Katana; official Katana recommendation |
| Crate Pattern | New `solver-bridge` crate | Mirrors `solver-settlement` pattern; clean separation of concerns |
| Trait Design | `BridgeInterface` for N chains | Pluggable backends; MVP implements LayerZero only |
| Threshold Model | Target + deviation band (bps) | Single config per token; flexible balancing |
| Balance Calculation | On-chain balance - pending fills + pending claims | Ignores speculative quotes; accounts for confirmed obligations |
| Transfer FSM | 3-state: Submitted -> Relaying -> Completed/Failed | Simple, sufficient for fire-and-forget OFT sends |
| Persistence | Redis via StorageService | Transfers survive solver restarts; consistent with existing patterns |
| Direction (MVP) | Bilateral (2 chains) | Interface supports N chains; algorithm handles only the 2-chain case |

### Why LayerZero Instead of Hyperlane Warp Routes?

The original spec proposed Hyperlane Warp Routes. After team review:

1. **Katana officially recommends LayerZero** for bridging (see [Katana docs](https://docs.katana.network/katana/how-to/bridge-to-katana-with-layerzero/))
2. **Vaultbridge tokens (vbUSDC, vbETH, etc.) are already deployed as LayerZero OFTs** — no new contract deployments needed
3. **Hyperlane has zero warp route activity on Katana** (verified on Hyperlane Explorer)
4. **Hyperlane remains the oracle** for settlement — this is a separate concern from rebalancing

### Why a New Crate Instead of Extending solver-settlement?

Rebalancing is **not** settlement. Settlement proves fills and processes claims. Bridging moves liquidity. Mixing them would muddy the `SettlementInterface` abstraction and confuse the domain model.

---

## 4. Architecture Overview

```
                    solver-service
  ┌───────────────────────────────────────────────┐
  │  Admin API (existing)    Rebalance API (NEW)  │
  │  GET/PUT/POST /admin/*   GET/PUT/POST         │
  │                          /admin/rebalance/*    │
  └────────┬────────────────────────┬──────────────┘
           │                        │
           │       solver-core      │
  ┌────────┼────────────────────────┼──────────────┐
  │  SolverEngine ───spawns───> RebalanceMonitor   │
  │  (event loop)               (background task)  │
  │                                    │           │
  │  Shares: transaction_semaphore     │           │
  │          dynamic_config            │           │
  │          token_manager             │           │
  └────────────────────────────────────┼───────────┘
                                       │
           solver-bridge (NEW)         │
  ┌────────────────────────────────────┼───────────┐
  │                                    ▼           │
  │  BridgeInterface ◄── LayerZeroBridge           │
  │  (trait)              (OFT send/quoteSend)     │
  │                                                │
  │  BridgeService ──> TransferTracker (Redis)     │
  │  (orchestrator)    (state machine persistence) │
  └────────────────────────────────────────────────┘
```

**Key interactions:**
- `RebalanceMonitor` runs as a background tokio task spawned **inside `SolverEngine::run()`** (same pattern as the existing cleanup task), where `transaction_semaphore` is in scope
- It acquires the `transaction_semaphore` before submitting bridge txs (prevents nonce conflicts with fill/claim txs)
- Transfer state persisted in Redis with TTL (7 days for completed; active transfers have a max age of 24h after which they auto-transition to `Failed`)
- **Policy** (enabled, thresholds, intervals, pairs) is hot-reloadable via `Arc<RwLock<Config>>` — admin can change thresholds without restart
- **Transport wiring** (bridge implementation constructor, OFT contract bindings) is static at startup — changing `bridge_config` endpoint IDs or OFT addresses requires a restart, consistent with how settlement/delivery services work today

---

## 5. LayerZero OFT Integration

### Token Flow: Vaultbridge Architecture

Vaultbridge combines ERC-4626 yield vaults with LayerZero OFT:

- **Ethereum**: Solver holds USDC. To bridge to Katana: deposit USDC into vault -> get vault shares -> bridge shares via OFT Adapter
- **Katana**: Solver holds vbUSDC (vault share OFT). To bridge to Ethereum: OFT `send()` burns vbUSDC -> shares unlocked on Ethereum OFT Adapter

### Contract Addresses (USDC)

| Contract | Chain | Address |
|---|---|---|
| USDC | Ethereum | `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` |
| USDC Vault Bridge | Ethereum | `0x53E82ABbb12638F09d9e624578ccB666217a765e` |
| Share OFT Adapter | Ethereum | `0xb5bADA33542a05395d504a25885e02503A957Bb3` |
| OVault Composer | Ethereum | `0x8A35897fda9E024d2aC20a937193e099679eC477` |
| Share OFT (vbUSDC) | Katana | `0x807275727Dd3E640c5F2b5DE7d1eC72B4Dd293C0` |

### LayerZero Endpoint IDs

| Chain | EID | Chain ID |
|---|---|---|
| Ethereum | `30101` | 1 |
| Katana | `30375` | 747474 |

### Call Flow: Katana -> Ethereum (send vbUSDC back, redeem to USDC)

```
1. quoteSend(sendParam, false)  on Share OFT (Katana 0x8072...)  -> MessagingFee
2. send(sendParam, fee, solver) on Share OFT (Katana 0x8072...)  -> burns vbUSDC
   msg.value = fee.nativeFee
3. Track via MessagingReceipt.guid
4. ~4-5 min: vault shares auto-unlock at OFT Adapter on Ethereum
5. approve(VaultBridge, shares)  on vault share token (Ethereum)
6. vault.redeem(shares, solver, solver)  on ERC-4626 vault -> returns USDC
```

**Important:** Step 4 only unlocks vault shares, NOT USDC. Steps 5-6 are required to convert shares back to spendable USDC. The `LayerZeroBridge` implementation must handle the full sequence: after detecting that shares arrived on Ethereum (transfer enters `Relaying` -> shares confirmed on-chain), it must submit a second transaction to redeem the vault shares. This means the Katana->Ethereum direction involves **two on-chain transactions on Ethereum** (one automatic unlock by LZ, one explicit redeem by the solver), and the transfer is only `Completed` after the redeem tx confirms.

The ERC-4626 vault's `previewRedeem(shares)` must be called to determine the exact USDC output, which may differ from the original USDC amount due to yield accrual on the vault shares.

### Call Flow: Ethereum -> Katana (deposit USDC, bridge as vbUSDC)

```
1. approve(OVaultComposer, amount) on USDC (Ethereum)
2. Call OVault Composer which:
   a. Deposits USDC into ERC-4626 vault -> receives shares
   b. Bridges shares via OFT Adapter -> sends LZ message
   msg.value = fee.nativeFee
3. Track via MessagingReceipt.guid
4. ~4-5 min: vbUSDC minted on Katana
```

### Solidity Interface (what we call from Rust via alloy)

```solidity
interface IOFT {
    function send(
        SendParam calldata _sendParam,
        MessagingFee calldata _fee,
        address _refundAddress
    ) external payable returns (MessagingReceipt memory, OFTReceipt memory);

    function quoteSend(
        SendParam calldata _sendParam,
        bool _payInLzToken
    ) external view returns (MessagingFee memory);

    function quoteOFT(
        SendParam calldata _sendParam
    ) external view returns (OFTLimit memory, OFTFeeDetail[] memory, OFTReceipt memory);
}

struct SendParam {
    uint32 dstEid;           // Destination LayerZero endpoint ID
    bytes32 to;              // Recipient address (left-padded to 32 bytes)
    uint256 amountLD;        // Amount in local decimals
    uint256 minAmountLD;     // Minimum amount (slippage protection)
    bytes extraOptions;      // Encoded executor options (TYPE_3)
    bytes composeMsg;        // Empty for simple transfers
    bytes oftCmd;            // Empty for standard sends
}

struct MessagingFee {
    uint256 nativeFee;       // Fee in native gas (ETH)
    uint256 lzTokenFee;      // Usually 0
}

struct MessagingReceipt {
    bytes32 guid;            // Globally unique message ID (tracking)
    uint64 nonce;
    MessagingFee fee;
}

struct OFTReceipt {
    uint256 amountSentLD;
    uint256 amountReceivedLD;
}
```

### extraOptions Encoding (TYPE_3 binary format)

For `lzReceive` gas specification:

```
0x0003              // TYPE_3 prefix (2 bytes)
0x01                // WORKER_ID = executor (1 byte)
0x0011              // option_size = 17 (2 bytes)
0x01                // OPTION_TYPE_LZRECEIVE (1 byte)
<uint128 gas>       // gas limit, 16 bytes big-endian
```

---

## 6. `solver-bridge` Crate

### File Structure

```
crates/solver-bridge/
├── Cargo.toml
└── src/
    ├── lib.rs                        # BridgeInterface trait, BridgeService, errors, registry
    ├── types.rs                      # BridgeTransferId, BridgeTransferStatus, PendingBridgeTransfer
    ├── monitor.rs                    # RebalanceMonitor background task
    └── implementations/
        ├── mod.rs
        └── layerzero_oft/
            └── mod.rs                # LayerZeroBridge implementation
```

### BridgeInterface Trait

```rust
#[async_trait]
pub trait BridgeInterface: Send + Sync {
    /// Returns all supported (source_chain, dest_chain) pairs.
    fn supported_routes(&self) -> Vec<(u64, u64)>;

    /// Execute a cross-chain token bridge transfer.
    async fn bridge_asset(
        &self,
        source_chain: u64,
        dest_chain: u64,
        token: &Address,
        amount: U256,
        recipient: &Address,
    ) -> Result<BridgeDepositResult, BridgeError>;

    /// Check the current status of a pending transfer.
    async fn check_status(
        &self,
        transfer_id: &BridgeTransferId,
    ) -> Result<BridgeTransferStatus, BridgeError>;

    /// Estimate the bridge fee for a transfer (in native gas token).
    async fn estimate_fee(
        &self,
        source_chain: u64,
        dest_chain: u64,
        token: &Address,
        amount: U256,
    ) -> Result<U256, BridgeError>;
}
```

### Error Types

```rust
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Bridge not found: {0}")]
    BridgeNotFound(String),
    #[error("Unsupported route: {0} -> {1}")]
    UnsupportedRoute(u64, u64),
    #[error("Transaction failed: {0}")]
    TransactionFailed(String),
    #[error("Fee estimation failed: {0}")]
    FeeEstimation(String),
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Delivery error: {0}")]
    Delivery(String),
    #[error("Max pending transfers reached")]
    MaxPendingReached,
    #[error("Cooldown active for {0} on chain {1}")]
    CooldownActive(String, u64),
}
```

### Transfer Types

All types derive `Serialize, Deserialize` for Redis persistence.

```rust
/// Unique identifier for a bridge transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeTransferId {
    /// Transaction hash on the source chain
    pub tx_hash: String,
    /// LayerZero message GUID (bytes32)
    pub message_guid: Option<String>,
    /// Source chain ID
    pub source_chain: u64,
}

/// Result from initiating a bridge transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeDepositResult {
    pub transfer_id: BridgeTransferId,
    pub estimated_arrival: Option<u64>,  // unix timestamp
}

/// Transfer state machine
///
/// For Katana->Ethereum, the flow adds a redemption step:
///   Submitted -> Relaying -> PendingRedemption -> Completed
/// For Ethereum->Katana (via Composer), it's simpler:
///   Submitted -> Relaying -> Completed
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BridgeTransferStatus {
    Submitted,              // bridge tx submitted, awaiting source chain confirmation
    Relaying,               // confirmed on source; LayerZero delivering to destination
    PendingRedemption,      // shares arrived on Ethereum; vault redeem tx needed
    Completed,              // final tokens available in solver wallet
    Failed(String),         // unrecoverable error
}

/// What triggered the transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RebalanceTrigger {
    Auto,     // triggered by RebalanceMonitor
    Manual,   // triggered by admin API
}

/// Persistent transfer record (stored in Redis)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingBridgeTransfer {
    pub id: String,                       // UUID
    pub transfer_id: BridgeTransferId,
    pub token_symbol: String,
    pub token_address: Address,
    pub amount: String,                   // decimal string
    pub source_chain: u64,
    pub dest_chain: u64,
    pub status: BridgeTransferStatus,
    pub created_at: u64,                  // unix timestamp
    pub updated_at: u64,
    pub trigger: RebalanceTrigger,
    pub fee_paid: Option<String>,         // native gas paid for LZ fee
}
```

**Redis key pattern:** `{solver_id}-bridge:transfer:{uuid}`

### LayerZeroBridge Implementation

```rust
pub struct LayerZeroBridge {
    config: LayerZeroConfig,
    delivery: Arc<DeliveryService>,
    account: Arc<AccountService>,
}

pub struct LayerZeroConfig {
    /// Maps (chain_id, token_address) -> OFT contract address
    pub oft_addresses: HashMap<(u64, Address), Address>,
    /// Maps chain_id -> LayerZero endpoint ID (EID)
    pub endpoint_ids: HashMap<u64, u32>,
    /// Supported routes as (source, dest) pairs
    pub routes: Vec<(u64, u64)>,
    /// Gas limit for lzReceive on destination (default: 200_000)
    pub lz_receive_gas: u128,
    /// Composer address for Ethereum -> Katana (vault deposit + bridge)
    pub composer_addresses: HashMap<u64, Address>,
    /// Vault bridge addresses for USDC -> vault share conversion
    pub vault_bridge_addresses: HashMap<u64, Address>,
}
```

**Implementation flow for `bridge_asset()`:**

1. Look up OFT contract address from config
2. Determine direction:
   - **Katana -> Ethereum**: Direct OFT `send()` on vbUSDC contract
   - **Ethereum -> Katana**: Approve + call OVault Composer (handles vault deposit + OFT send)
3. Build `SendParam` with destination EID, left-padded recipient, amount, extraOptions
4. Call `quoteSend()` via `eth_call` to get `MessagingFee`
5. Build transaction: call `send()` with `value = nativeFee`
6. Submit via `DeliveryService::deliver()`
7. Parse `MessagingReceipt.guid` from return data
8. Return `BridgeDepositResult`

**Implementation for `check_status()`:**

**MVP approach — receipt-based + token arrival event parsing:**

1. **Submitted -> Relaying**: Poll source chain for tx receipt. Success receipt -> `Relaying`. Failed receipt -> `Failed`.
2. **Relaying -> PendingRedemption (Katana->ETH only)**: Query the OFT Adapter contract's `Transfer` event logs on Ethereum for the solver's address, filtering by block range since the source tx was confirmed. When a matching `Transfer` event is found with amount consistent with the bridge, transition to `PendingRedemption` and submit the vault `redeem()` tx.
3. **Relaying -> Completed (ETH->Katana)**: Query the Share OFT contract's `Transfer` event logs on Katana for the solver's address. Matching mint event -> `Completed`.
4. **PendingRedemption -> Completed**: Poll for the redeem tx receipt. Success -> `Completed`.
5. **Timeout**: Active transfers older than 30 min in `Relaying` state -> `Failed`. Active transfers older than 24h in any non-terminal state -> `Failed`.

**Why not balance-delta?** The solver's balances change from fills, claims, and admin withdrawals. A balance-increase heuristic would produce false positives in an automated control loop. Event log parsing on the specific OFT/Adapter contracts is deterministic and avoids this.

**Post-MVP**: Integrate LayerZero Scan API (`GET /api/v1/messages?srcTxHash={hash}`) for GUID-based tracking, replacing event log polling with a single API call.

### BridgeService

Orchestrates bridge implementations and manages transfer lifecycle:

```rust
pub struct BridgeService {
    implementations: HashMap<String, Arc<dyn BridgeInterface>>,
    storage: Arc<StorageService>,
    solver_id: String,
}

impl BridgeService {
    /// Initiate a rebalance transfer. Creates persistent record.
    pub async fn rebalance_token(
        &self,
        bridge_impl: &str,
        source_chain: u64,
        dest_chain: u64,
        token: &Address,
        amount: U256,
        token_symbol: &str,
        trigger: RebalanceTrigger,
    ) -> Result<PendingBridgeTransfer, BridgeError>;

    /// Advance all pending transfers through the state machine.
    pub async fn process_pending_transfers(&self) -> Result<(), BridgeError>;

    /// Get all active (non-terminal) transfers.
    pub async fn get_active_transfers(&self) -> Result<Vec<PendingBridgeTransfer>, BridgeError>;

    /// Get completed/failed transfers (paginated).
    pub async fn get_transfer_history(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<PendingBridgeTransfer>, BridgeError>;

    /// Compute current balance vs threshold status for all configured tokens.
    /// Accepts pre-fetched balances to avoid a dependency on `TokenManager`
    /// (which lives in `solver-core`). The caller (engine or API handler)
    /// queries balances via `TokenManager` and passes them in.
    pub async fn get_rebalance_status(
        &self,
        config: &RebalanceRuntimeConfig,
        balances: &HashMap<(u64, Address), U256>,
    ) -> Result<Vec<TokenRebalanceStatus>, BridgeError>;

    /// Count active (non-terminal) transfers.
    pub async fn active_transfer_count(&self) -> Result<usize, BridgeError>;
}
```

### RebalanceMonitor

Background task spawned **inside** `SolverEngine::run()` (where `transaction_semaphore` is in scope), following the same pattern as the existing cleanup task:

```rust
pub struct RebalanceMonitor {
    bridge_service: Arc<BridgeService>,
    delivery: Arc<DeliveryService>,        // for balance queries
    account: Arc<AccountService>,          // for solver address
    dynamic_config: Arc<RwLock<Config>>,
    storage: Arc<StorageService>,          // also used for persistent cooldown tracking
    transaction_semaphore: Arc<Semaphore>, // passed from run() scope
}

// Cooldown is persisted in Redis, NOT in-memory, so it survives restarts.
// Key: "{solver_id}-bridge:cooldown:{chain_id}:{token_address}"
// Value: unix timestamp of last rebalance trigger
// TTL: cooldown_seconds (auto-expires when cooldown elapses)

impl RebalanceMonitor {
    /// Main polling loop. Runs until shutdown signal.
    pub async fn run(mut self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {
                    self.tick().await;
                }
                _ = shutdown.changed() => {
                    break;
                }
            }
        }
    }

    /// Single monitoring cycle:
    /// 1. Advance pending transfers (Submitted -> Relaying -> Completed)
    /// 2. Check balances against thresholds
    /// 3. Trigger rebalance if needed (respecting cooldown + max pending)
    async fn tick(&mut self) { /* ... */ }
}
```

**Threshold logic (per pair):**

For each pair (e.g., USDC: chain_a=Ethereum, chain_b=Katana):

```
For each side (A and B):
  lower_bound = target_balance_{side} * (10000 - deviation_band_bps) / 10000
  upper_bound = target_balance_{side} * (10000 + deviation_band_bps) / 10000

  if balance_{side} < lower_bound:
      deficit = target_balance_{side} - balance_{side}
      amount = min(deficit, max_bridge_amount)
      bridge from OTHER side -> this side

  if balance_{side} > upper_bound:
      surplus = balance_{side} - target_balance_{side}
      amount = min(surplus, max_bridge_amount)
      bridge from this side -> OTHER side
```

Note: If both sides are below their lower bound simultaneously (e.g., due to high order activity on both chains), no rebalance is triggered — the monitor logs a warning and skips. Only one direction can be active at a time per pair.

**Available balance calculation:**

The ideal formula would subtract committed fills and add pending claims, but the current order model does not maintain a reservation ledger, and the tracked assets differ by chain (USDC on Ethereum vs vbUSDC on Katana), making aggregation direction-sensitive.

**MVP approach — conservative suppression:**

```
effective_balance = on_chain_balance - sum(active_bridge_transfer_amounts_outbound)
```

- Only subtract outbound bridge transfers that are in-flight (Submitted, Relaying, PendingRedemption) to avoid double-counting
- Do NOT attempt to subtract pending fills or add pending claims — the deviation band (default +/-20%) provides sufficient buffer for normal order flow
- If order volume is high enough to routinely swing balances beyond the band, the admin should increase the deviation band or the cooldown period

**Why this is safe for MVP:**
- The cooldown (default 1h) prevents the monitor from reacting to transient balance swings caused by fill bursts
- The deviation band is intentionally wide (+/-20%) to absorb normal order activity
- Auto-rebalance can be disabled entirely if the solver is in a high-activity period

**Post-MVP:** Add an `OrderReservationService` that maintains a real-time ledger of committed fill amounts per chain, enabling precise available-balance calculation.

**Safety guards:**
- Cooldown: skip if Redis key `{solver_id}-bridge:cooldown:{pair_symbol}` exists (TTL = cooldown_seconds, auto-expires)
- Max pending: skip if `active_transfer_count >= max_pending_transfers`
- Max amount: cap transfer at `min(needed_amount, max_bridge_amount)`
- Native gas check: skip + warn if native gas balance on source chain < `min_native_gas_balance`
- Disabled: skip entirely if `config.rebalance.enabled == false`

---

## 7. Configuration Schema

### OperatorConfig (stored in Redis, hot-reloadable)

```rust
pub struct OperatorConfig {
    // ... existing fields ...
    #[serde(default)]
    pub rebalance: Option<OperatorRebalanceConfig>,
}

pub struct OperatorRebalanceConfig {
    /// Master switch for auto-rebalancing
    pub enabled: bool,
    /// Which bridge backend to use (e.g., "layerzero_oft")
    pub bridge_implementation: String,
    /// How often the monitor checks balances (seconds)
    #[serde(default = "default_monitor_interval")]
    pub monitor_interval_seconds: u64,       // default: 60
    /// Minimum time between auto-rebalances for same pair (seconds)
    #[serde(default = "default_cooldown")]
    pub cooldown_seconds: u64,               // default: 3600
    /// Maximum concurrent bridge transfers
    #[serde(default = "default_max_pending")]
    pub max_pending_transfers: u32,          // default: 3
    /// Cross-chain rebalance pairs (each pair is one logical asset across two chains)
    #[serde(default)]
    pub pairs: Vec<OperatorRebalancePairConfig>,
    /// Implementation-specific config (e.g., LayerZero endpoint IDs, composer addresses).
    /// Stored as JSON value, deserialized by the specific BridgeInterface implementation.
    #[serde(default)]
    pub bridge_config: Option<serde_json::Value>,
}

/// A rebalance pair represents ONE logical asset bridged between TWO chains.
/// For Vaultbridge: USDC on Ethereum <-> vbUSDC on Katana.
/// Each side has its own token address and OFT contract, but they share
/// thresholds and represent a single rebalanceable position.
pub struct OperatorRebalancePairConfig {
    /// Human-readable label (e.g., "USDC")
    pub symbol: String,
    /// Chain A configuration (e.g., Ethereum)
    pub chain_a: RebalancePairSide,
    /// Chain B configuration (e.g., Katana)
    pub chain_b: RebalancePairSide,
    /// Target balance for chain A in base units (decimal string)
    pub target_balance_a: String,
    /// Target balance for chain B in base units (decimal string)
    pub target_balance_b: String,
    /// Acceptable deviation in basis points (e.g., 2000 = +/-20%)
    pub deviation_band_bps: u32,
    /// Maximum amount per bridge operation (decimal string, in chain A token units)
    pub max_bridge_amount: String,
    /// Minimum native gas balance per chain; monitor logs warning if below
    #[serde(default)]
    pub min_native_gas_balance: Option<String>,
}

pub struct RebalancePairSide {
    /// Chain ID
    pub chain_id: u64,
    /// Token contract address on this chain (e.g., USDC on ETH, vbUSDC on Katana)
    pub token_address: Address,
    /// OFT contract address on this chain
    pub oft_address: Address,
}
```

### Runtime Config

```rust
pub struct Config {
    // ... existing fields ...
    #[serde(default)]
    pub bridge: Option<BridgeConfig>,
}

pub struct BridgeConfig {
    /// Bridge backend configs, keyed by implementation name
    pub implementations: HashMap<String, serde_json::Value>,
    /// Rebalance monitor settings (built from OperatorRebalanceConfig)
    pub rebalance: Option<RebalanceRuntimeConfig>,
}
```

### Bootstrap JSON Example

```json
{
  "rebalance": {
    "enabled": true,
    "bridge_implementation": "layerzero_oft",
    "monitor_interval_seconds": 60,
    "cooldown_seconds": 3600,
    "max_pending_transfers": 3,
    "pairs": [
      {
        "symbol": "USDC",
        "chain_a": {
          "chain_id": 1,
          "token_address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
          "oft_address": "0xb5bADA33542a05395d504a25885e02503A957Bb3"
        },
        "chain_b": {
          "chain_id": 747474,
          "token_address": "0x807275727Dd3E640c5F2b5DE7d1eC72B4Dd293C0",
          "oft_address": "0x807275727Dd3E640c5F2b5DE7d1eC72B4Dd293C0"
        },
        "target_balance_a": "5000000000",
        "target_balance_b": "5000000000",
        "deviation_band_bps": 2000,
        "max_bridge_amount": "2000000000"
      }
    ],
    "bridge_config": {
      "endpoint_ids": { "1": 30101, "747474": 30375 },
      "lz_receive_gas": 200000,
      "composer_addresses": { "1": "0x8A35897fda9E024d2aC20a937193e099679eC477" },
      "vault_bridge_addresses": { "1": "0x53E82ABbb12638F09d9e624578ccB666217a765e" },
      "vault_addresses": { "1": "0x53E82ABbb12638F09d9e624578ccB666217a765e" }
    }
  }
}
```

Note: The LayerZero-specific config (`endpoint_ids`, `composer_addresses`, etc.) is embedded in `rebalance.bridge_config` rather than a separate top-level `bridge.implementations` map. This keeps all rebalance config in one place in Redis and avoids a split between static and dynamic config for the bridge backend.

---

## 8. Admin API Endpoints

All under `/api/v1/admin/rebalance/`:

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/config` | JWT | Get current rebalance config (global + per-token) |
| `PUT` | `/config` | EIP-712 | Update global settings (enabled, intervals, limits) |
| `PUT` | `/config/threshold` | EIP-712 | Update per-token threshold (target, deviation, max) |
| `POST` | `/trigger` | EIP-712 | Manually trigger a single rebalance |
| `GET` | `/status` | JWT | Current balance vs. threshold analysis |
| `GET` | `/transfers` | JWT | Active + recent transfer history |

### EIP-712 Action Types

Following the existing pattern in `solver-service/src/auth/admin/types.rs`:

```solidity
sol! {
    /// Update global rebalance settings (enable/disable, intervals, limits)
    struct UpdateRebalanceConfig {
        bool enabled;
        uint256 monitorIntervalSeconds;
        uint256 cooldownSeconds;
        uint256 maxPendingTransfers;
        uint256 nonce;
        uint256 deadline;
    }

    /// Update per-pair threshold (identified by symbol)
    struct UpdatePairThreshold {
        string symbol;
        uint256 targetBalanceA;
        uint256 targetBalanceB;
        uint256 deviationBandBps;
        uint256 maxBridgeAmount;
        uint256 nonce;
        uint256 deadline;
    }

    /// Manually trigger a single rebalance operation
    struct TriggerRebalance {
        uint256 sourceChain;
        uint256 destChain;
        address token;
        uint256 amount;
        uint256 nonce;
        uint256 deadline;
    }
}
```

This splits config updates into two actions:
- `UpdateRebalanceConfig`: global settings (enabled, intervals, limits)
- `UpdatePairThreshold`: per-pair settings (target balances, deviation, max amount)

The `PUT /config` endpoint accepts `UpdateRebalanceConfig`. A new `PUT /config/threshold` endpoint accepts `UpdatePairThreshold`. This keeps EIP-712 structs flat (no nested arrays) while supporting full configurability. Pairs are identified by `symbol` (e.g., "USDC").

### Response Types

```rust
/// GET /config response
pub struct RebalanceConfigResponse {
    pub enabled: bool,
    pub bridge_implementation: String,
    pub monitor_interval_seconds: u64,
    pub cooldown_seconds: u64,
    pub max_pending_transfers: u32,
    pub chains: Vec<ChainRebalanceConfigResponse>,
}

/// GET /status response
pub struct RebalanceStatusResponse {
    pub tokens: Vec<TokenRebalanceStatus>,
    pub active_transfers: usize,
    pub last_check: Option<String>,  // ISO 8601
}

pub struct TokenRebalanceStatus {
    pub chain_id: u64,
    pub token_symbol: String,
    pub token_address: String,
    pub current_balance: String,
    pub target_balance: String,
    pub deviation_band_bps: u32,
    pub lower_bound: String,
    pub upper_bound: String,
    pub within_band: bool,
    pub direction_needed: Option<String>,  // "inbound" | "outbound"
}

/// GET /transfers response
pub struct RebalanceTransfersResponse {
    pub active: Vec<BridgeOperationResponse>,
    pub history: Vec<BridgeOperationResponse>,
}

pub struct BridgeOperationResponse {
    pub id: String,
    pub token_symbol: String,
    pub token_address: String,
    pub amount: String,
    pub source_chain_id: u64,
    pub destination_chain_id: u64,
    pub status: String,
    pub trigger: String,
    pub created_at: String,
    pub updated_at: String,
    pub tx_hash: Option<String>,
    pub message_guid: Option<String>,
    pub fee_paid: Option<String>,
    pub error: Option<String>,
}

/// POST /trigger response
pub struct TriggerRebalanceResponse {
    pub success: bool,
    pub message: String,
    pub admin: String,
    pub operation_id: Option<String>,
    pub tx_hash: Option<String>,
}
```

### Handler File

New file: `solver-service/src/apis/rebalance.rs`

Router registration in `server.rs`:

```rust
let rebalance_routes = Router::new()
    .route("/config", get(handle_get_rebalance_config))
    .route("/config", put(handle_update_rebalance_config))
    .route("/config/threshold", put(handle_update_pair_threshold))
    .route("/trigger", post(handle_trigger_rebalance))
    .route("/status", get(handle_get_rebalance_status))
    .route("/transfers", get(handle_get_rebalance_transfers))
    .with_state(admin_state.clone());

admin_routes = admin_routes.nest("/rebalance", rebalance_routes);
```

---

## 9. Backend Integration Points

### Cargo Workspace

```toml
# Root Cargo.toml
members = [
    # ... existing ...
    "crates/solver-bridge",
]
```

### solver-bridge/Cargo.toml Dependencies

```toml
[dependencies]
solver-types = { path = "../solver-types" }
solver-storage = { path = "../solver-storage" }
solver-delivery = { path = "../solver-delivery" }
solver-account = { path = "../solver-account" }
alloy-primitives = { workspace = true }
alloy-sol-types = { workspace = true }
async-trait = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
tokio = { workspace = true }
tracing = { workspace = true }
thiserror = { workspace = true }
uuid = { version = "1", features = ["v4"] }
```

### SolverEngine Integration

```rust
// solver-core/src/engine/mod.rs
pub struct SolverEngine {
    // ... existing fields ...
    pub(crate) bridge_service: Option<Arc<BridgeService>>,
}
```

### RebalanceMonitor Spawning

The monitor is spawned **inside `SolverEngine::run()`**, not in `main.rs`. This is required because `transaction_semaphore` is a local variable created inside `run()` and is not accessible externally. This follows the same pattern as the existing cleanup task.

In `solver-core/src/engine/mod.rs`, inside `run()`, after creating semaphores and before the main `loop`:

```rust
// Spawn rebalance monitor alongside the cleanup task
let rebalance_handle = if let Some(bridge_service) = &self.bridge_service {
    let config = self.dynamic_config.clone();
    let config_read = config.read().await;
    if config_read.bridge.as_ref().and_then(|b| b.rebalance.as_ref()).map_or(false, |r| r.enabled) {
        drop(config_read);
        let monitor = RebalanceMonitor::new(
            bridge_service.clone(),
            self.delivery.clone(),
            self.account.clone(),
            self.dynamic_config.clone(),
            self.storage.clone(),
            transaction_semaphore.clone(),  // in scope here
        );
        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(async move { monitor.run(rx).await });
        tracing::info!("Rebalance monitor started");
        Some((handle, tx))
    } else { None }
} else { None };

// ... main event loop ...

// On shutdown, stop the monitor
if let Some((handle, tx)) = rebalance_handle {
    let _ = tx.send(true);
    handle.abort();
}
```

### AdminApiState Extension

```rust
pub struct AdminApiState {
    // ... existing fields ...
    pub bridge_service: Option<Arc<BridgeService>>,
}
```

### Factory Registry

Define `BridgeFactory` type alias in `solver-bridge/src/lib.rs`, consistent with the existing factory pattern:

```rust
/// Factory function for creating bridge implementations.
/// Takes JSON config, network config, and required services.
pub type BridgeFactory = fn(
    &serde_json::Value,
    &NetworksConfig,
    Arc<DeliveryService>,
    Arc<AccountService>,
) -> Result<Box<dyn BridgeInterface>, BridgeError>;
```

Note: unlike `SettlementFactory` (which only takes config + networks + storage), `BridgeFactory` also needs `DeliveryService` and `AccountService` because bridge operations submit transactions and need the solver address. These services are available at factory construction time in `build_solver_from_config()`.

Register in `solver-service/src/factory_registry.rs`:

```rust
pub struct FactoryRegistry {
    // ... existing ...
    pub bridge: HashMap<String, BridgeFactory>,
}

// In initialize_registry():
for (name, factory) in solver_bridge::get_all_implementations() {
    registry.register_bridge(name, factory);
}
```

### Config Merge

Extend `solver-service/src/config_merge.rs` to roundtrip `rebalance` field between `OperatorConfig` and `Config` (same pattern as existing gas/pricing configs).

**Config origin flow:**
1. **Bootstrap JSON** contains `rebalance` with everything: global settings, pairs, and `bridge_config` (LayerZero-specific)
2. On first boot, merged into `OperatorConfig.rebalance` and stored in Redis
3. `config_merge.rs` builds runtime `Config.bridge.rebalance` from `OperatorConfig.rebalance`
4. **Static vs dynamic split:**
   - **Hot-reloadable** (policy): `enabled`, `monitor_interval_seconds`, `cooldown_seconds`, `max_pending_transfers`, pair thresholds (`target_balance_a/b`, `deviation_band_bps`, `max_bridge_amount`)
   - **Static at startup** (transport): `bridge_implementation`, `bridge_config` (endpoint IDs, composer addresses, OFT addresses). Changing these requires a restart.
   - The `RebalanceMonitor` reads policy from `dynamic_config` on each tick, but uses the bridge implementation instance constructed at startup

---

## 10. Frontend Deliverables

### New Page: `/solver/dashboard/[solverId]/bridge`

Layout (top to bottom):
1. **AutoRebalanceStatusBar** — enabled/disabled indicator, last check time
2. **ActiveOperationsCard** — live table of in-progress transfers (polls every 15s)
3. **ThresholdConfigCard** — form to edit target balance + deviation per token (EIP-712 submit)
4. **ManualTriggerCard** — token/chain/amount selector to trigger one-off rebalance
5. **RebalancingHistoryCard** — paginated table of completed/failed transfers

### New Components (6)

| Component | Description |
|-----------|-------------|
| `BridgeOperationStatusBadge` | 4-state badge (Submitted/Relaying/Completed/Failed); Relaying pulses amber |
| `ActiveOperationsCard` | Table: Token, Amount, Direction, Status, Created, Updated |
| `AutoRebalanceStatusBar` | Thin card: enabled dot, last check, next check |
| `ThresholdConfigCard` | Form per token: target, deviation, max amount; EIP-712 save |
| `ManualTriggerCard` | Source/dest chain + token + amount; EIP-712 trigger |
| `RebalancingHistoryCard` | Paginated completed/failed operations |

### Dashboard Integration

- **Active transfers banner** on main dashboard when transfers in progress
- **Pulsing dot** on token table rows with active bridge operations
- **Sidebar**: rename "Bridge" -> "Rebalancing"
- **Modals**: `RebalanceModal` and `WithdrawModal` call real API (replace mocks)

### React Hooks

```typescript
// Queries
useRebalancingConfig(solverUrl)     // staleTime: 60s
useRebalancingStatus(solverUrl)     // refetchInterval: 15s
useRebalancingTransfers(solverUrl)  // refetchInterval: 30s

// Mutations (EIP-712 signed)
useRebalancingActions(solverUrl) -> {
    handleTriggerRebalance,
    handleUpdateConfig,
    isTriggeringRebalance,
    isUpdatingConfig,
}
```

---

## 11. Implementation Phases

### Phase 1: Backend Types & Crate Skeleton
1. Add `OperatorRebalanceConfig` to `solver-types/src/operator_config.rs`
2. Add `BridgeConfig` + `RebalanceRuntimeConfig` to `solver-config/src/lib.rs`
3. Create `solver-bridge` crate with `Cargo.toml`
4. Implement `BridgeInterface` trait, error types, transfer types in `lib.rs` + `types.rs`
5. Stub `LayerZeroBridge` implementation
6. `cargo check --all-targets --all-features`

### Phase 2: LayerZero OFT Implementation
7. Implement `LayerZeroBridge::bridge_asset()` — alloy contract calls for OFT `send()` + `quoteSend()`
8. Handle direction-specific logic (Katana->ETH vs ETH->Katana via Composer)
9. Implement `check_status()` with receipt polling
10. Implement `estimate_fee()` via `quoteSend()`
11. Unit tests for encoding, option building, address padding

### Phase 3: BridgeService & Monitor
12. Implement `BridgeService` with Redis persistence (store/retrieve/query transfers)
13. Implement `RebalanceMonitor` background task with threshold logic
14. Available balance calculation (on-chain - pending fills + pending claims)
15. Cooldown tracking, max pending enforcement
16. Integration tests with mock delivery

### Phase 4: API & Wiring
17. Add EIP-712 types for `UpdateRebalanceConfig`, `UpdatePairThreshold`, and `TriggerRebalance`
18. Create `solver-service/src/apis/rebalance.rs` with 6 endpoint handlers (including `/config/threshold`)
19. Register routes in `server.rs`
20. Extend `AdminApiState` with `bridge_service`
21. Update `config_merge.rs` for rebalance config roundtrip (including `bridge_config` JSON value)
22. Update `factory_registry.rs` to register bridge implementations with `BridgeFactory` type
23. Wire `BridgeService` into `SolverEngine`
24. Spawn `RebalanceMonitor` inside `SolverEngine::run()` (where `transaction_semaphore` is in scope)
25. `cargo build` + `cargo test`

### Phase 5: Frontend
26. Types, API functions, query keys
27. React hooks (queries + mutations with EIP-712)
28. 6 new components
29. Bridge page
30. Dashboard integration (banner, badge, sidebar rename)
31. Replace modal mocks with real API calls

---

## 12. Concerns & Risks

### Nonce Conflicts
Bridge transactions share the solver's signing key with fill/claim transactions. The `transaction_semaphore` (already exists, capacity 1) serializes all tx submissions. The `RebalanceMonitor` is spawned inside `SolverEngine::run()` where this semaphore is in scope, and must acquire it before submitting any bridge transaction.

### Ethereum -> Katana Complexity
The Composer flow (approve USDC -> deposit into vault -> bridge shares) involves multiple transactions or a multicall. Need to verify the Composer contract handles this atomically. If not, we need to handle partial failure (USDC approved but vault deposit fails, etc.).

**Mitigation:** Read the Composer contract ABI carefully. If it's a single `depositAndBridge()` call, this is clean. If it requires multiple txs, implement as a transaction sequence with rollback awareness.

### Transfer Status Tracking (MVP Limitation)
MVP uses receipt polling + balance change heuristic for status tracking. This can produce false positives (balance increased from a fill, not from the bridge).

**Mitigation:** For MVP this is acceptable since rebalances are infrequent and admin-monitored. Post-MVP: integrate LayerZero Scan API (`GET /api/v1/ofts/{guid}`) for precise GUID-based tracking.

### Vault Share Conversion Rate
vbUSDC is a yield-bearing vault share — 1 vbUSDC != 1 USDC. The conversion rate changes over time as yield accrues. The rebalance logic needs to account for this when computing how much USDC to deposit on Ethereum to get the desired vbUSDC amount on Katana.

**Mitigation:** Use the ERC-4626 `previewDeposit()` / `previewRedeem()` functions to get accurate conversion rates before computing bridge amounts.

### Gas on Katana
The solver needs native gas (POL or ETH) on Katana to pay for OFT `send()` transactions. If the solver runs out of gas on Katana, auto-rebalancing from Katana -> Ethereum will fail silently.

**Mitigation:** The monitor should check native gas balance on each chain and log warnings when it's low. Post-MVP: add native gas alerts to the dashboard.

### Race Condition: Concurrent Fills Draining Balance
Between the monitor detecting a healthy balance and the next check cycle, multiple fills could drain the balance. The rebalance then triggers but the balance is already being replenished by incoming claims.

**Mitigation:** The cooldown period and conservative deviation band (default +/-20%) provide a natural buffer. The available balance calculation (subtracting pending fills) further reduces this risk.

---

## 13. Testing Strategy

### Unit Tests
- Threshold calculation: lower/upper bounds from target + deviation_band_bps
- Direction logic: inbound vs outbound determination
- Transfer state machine transitions
- extraOptions TYPE_3 encoding
- Address left-padding to bytes32
- Config JSON serialization roundtrip

### Integration Tests
- Mock `DeliveryService` -> full `bridge_asset()` flow -> verify Redis persistence
- `BridgeService` lifecycle: create transfer -> advance state -> query history
- Config merge roundtrip: `OperatorConfig` <-> `Config`
- Admin API endpoints with mock bridge service

### Manual E2E
1. Configure thresholds via `PUT /admin/rebalance/config`
2. Drain token balance below lower threshold
3. Verify monitor detects imbalance within `monitor_interval_seconds`
4. Verify OFT `send()` tx submitted on source chain
5. Verify transfer appears in `GET /admin/rebalance/transfers` as `Relaying`
6. Verify tokens arrive on destination (~5 min)
7. Verify status updates to `Completed`
8. Verify cooldown prevents immediate re-trigger
9. Test manual trigger via `POST /admin/rebalance/trigger`

---

## 14. API Reference

See [docs/layerzero-oft-api-reference.md](../layerzero-oft-api-reference.md) for complete LayerZero V2 OFT documentation links, contract addresses, and Solidity interfaces.
