# Cross-Chain Rebalancing

Automated cross-chain token rebalancing for the OIF Solver. The solver monitors token balances across configured chain pairs and automatically bridges funds when balances drift outside a target band.

## Enabling Rebalancing

Add a `rebalance` section to your bootstrap config JSON:

```json
{
  "rebalance": {
    "enabled": true,
    "implementation": "layerzero",
    "monitor_interval_seconds": 60,
    "cooldown_seconds": 3600,
    "max_pending_transfers": 3,
    "pairs": [
      {
        "pair_id": "usdc-eth-arb",
        "chain_a": {
          "chain_id": 1,
          "token_address": "0x<token_address_chain_a>",
          "oft_address": "0x<oft_address_chain_a>"
        },
        "chain_b": {
          "chain_id": 42161,
          "token_address": "0x<token_address_chain_b>",
          "oft_address": "0x<oft_address_chain_b>"
        },
        "target_balance_a": "10000000",
        "target_balance_b": "10000000",
        "deviation_band_bps": 2000,
        "max_bridge_amount": "5000000"
      }
    ],
    "bridge_config": {
      "endpoint_ids": { "1": 30101, "42161": 30110 },
      "lz_receive_gas": 200000,
      "composer_addresses": {},
      "vault_addresses": {}
    }
  }
}
```

## Config Reference

### Global Settings

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `enabled` | bool | Yes | Enable/disable auto-rebalancing |
| `implementation` | string | Yes | Bridge backend name (`"layerzero"`) |
| `monitor_interval_seconds` | u64 | Yes | Polling interval for balance checks (must be > 0) |
| `cooldown_seconds` | u64 | Yes | Minimum time between auto-rebalances for the same pair (must be > 0) |
| `max_pending_transfers` | u32 | Yes | Maximum concurrent bridge transfers (must be > 0) |
| `pairs` | array | Yes | List of token pairs to rebalance (at least one when enabled) |
| `bridge_config` | object | Yes | Implementation-specific transport config (required when enabled) |

### Pair Config

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `pair_id` | string | Yes | Unique operator-chosen identifier (e.g., `"usdc-eth-arb"`). Used as key for cooldowns, transfer lookups, and API responses. Must be unique across all pairs. |
| `chain_a` | object | Yes | One side of the pair |
| `chain_b` | object | Yes | Other side of the pair. Must be a different chain than chain_a. |
| `target_balance_a` | string | Yes | Target balance for chain_a in base units (decimal string, e.g., `"10000000"` for 10 USDC with 6 decimals) |
| `target_balance_b` | string | Yes | Target balance for chain_b in base units |
| `deviation_band_bps` | u32 | Yes | Acceptable deviation in basis points. `2000` = +/-20%. Clamped to max 10000. |
| `max_bridge_amount` | string | Yes | Maximum amount per bridge operation in base units |

### Pair Side Config

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `chain_id` | u64 | Yes | Chain ID. Must exist in the solver's `networks` config. |
| `token_address` | string | Yes | ERC-20 token contract address (for balance queries and approvals). **Use `0x000…0000` to declare this side as native** (see "Native-asset pairs" below). |
| `oft_address` | string | Yes | LayerZero OFT contract address (for quoteSend/send operations) |

### Bridge Config (LayerZero)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `endpoint_ids` | object | Yes | Maps chain_id (as string key) to LayerZero Endpoint ID (EID). E.g., `{"1": 30101, "42161": 30110}` |
| `lz_receive_gas` | u128 | No | Gas limit for lzReceive on destination (default: 200000) |
| `composer_addresses` | object | No | **Legacy chain-keyed shape.** Maps chain_id to OVault Composer contract address. Used by pairs that don't declare a per-pair `bridge_route`. Prefer per-pair routing for new pairs. |
| `vault_addresses` | object | No | **Legacy chain-keyed shape.** Maps chain_id to ERC-4626 vault contract address. Used by non-composer flows that don't declare a per-pair `bridge_route`. |

### Per-pair `bridge_route` (required for native-asset pairs and recommended for new pairs)

A pair can carry its own routing data in `bridge_route`. This supersedes the legacy chain-keyed `composer_addresses` / `vault_addresses` and is **required** when either side is native (token_address = `0x000…`). The route is opaque at the generic config level — the bridge implementation deserializes its own shape.

For LayerZero, the shape is:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `composer` | string | Yes | OVault Composer address on the vault's chain. |
| `composer_chain_id` | u64 | Yes | Chain ID where the composer + vault live. Must match one of the pair's chain IDs. |
| `vault` | address | Yes | ERC-4626 vault address. Must equal `composer.VAULT()`. |
| `chain_a` | object | Yes | Route data for the side whose `chain_id` matches `pair.chain_a.chain_id`. |
| `chain_b` | object | Yes | Route data for `pair.chain_b`. |

Each `chain_a`/`chain_b` block:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `chain_id` | u64 | Yes | Mirrors the pair side's chain_id (self-describing). |
| `approval_required` | bool | Yes | Whether the OFT on this side needs `approve` before `send`. Verified at startup against `IOFT.approvalRequired()`. |
| `wrapper` | object | When native | Required when this side's `token_address` is `0x000…`. Carries the WETH9-compatible wrapper address and strategy. |

The `wrapper` block:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `address` | string | Yes | Wrapper contract address (e.g., WETH on Ethereum, vbETH on Katana). Must expose WETH9 `deposit()` / `withdraw(uint256)`. |
| `strategy` | enum | Yes | Currently only `"Weth9"`. Scaffolded so non-WETH9 wrappers can be added later. |

### Native-asset pairs (e.g., native ETH ↔ native ETH)

When the asset on either side is the chain's native token, set that side's `token_address` to the zero address and declare a `bridge_route` whose corresponding `chain_a`/`chain_b` block carries a `wrapper`. The solver automatically wraps native to the ERC-20 wrapper before the bridge and unwraps on the destination side.

Example (native ETH on Ethereum ↔ native ETH on Katana via the WETH/vbETH OVault):

```json
{
  "pair_id": "eth-native-katana",
  "chain_a": {
    "chain_id": 1,
    "token_address": "0x0000000000000000000000000000000000000000",
    "oft_address":   "0x8F45F7ACD4b9FC0B446902790F304d444dfF949b"
  },
  "chain_b": {
    "chain_id": 747474,
    "token_address": "0x0000000000000000000000000000000000000000",
    "oft_address":   "0x694D1697F6909361775139357d99fb60B5cab683"
  },
  "target_balance_a": "1000000000000000000",
  "target_balance_b": "1000000000000000000",
  "deviation_band_bps": 3000,
  "max_bridge_amount": "500000000000000000",
  "bridge_route": {
    "composer":          "0xC4c76Ae67f7d0f741B56d013D14359A6C7b7De11",
    "composer_chain_id": 1,
    "vault":             "0x2DC70fb75b88d2eB4715bc06E1595E6D97c34DFF",
    "chain_a": {
      "chain_id": 1,
      "approval_required": true,
      "wrapper": { "address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "strategy": "Weth9" }
    },
    "chain_b": {
      "chain_id": 747474,
      "approval_required": false,
      "wrapper": { "address": "0xEE7D8BCFb72bC1880D0Cf19822eB0A2e6577aB62", "strategy": "Weth9" }
    }
  }
}
```

The solver's logical balance for a native side is `eth_getBalance + wrapper.balanceOf` so funds parked in the wrapper during an in-flight unwrap are not missed by the threshold check. `min_native_gas_reserve` continues to count native ETH only.

### Startup preflight

When a pair carries a `bridge_route`, the engine runs an async preflight at startup that cross-checks the declared route against on-chain state:

- `IOFT.approvalRequired()` on each side's OFT must match the declared `approval_required`.
- `composer.VAULT()` must equal `route.vault`.
- `composer.SHARE_OFT()` must equal the vault-side `oft_address` (catches the common mistake of putting the Asset OFT in the slot where the Share OFT Adapter belongs).
- `composer.ASSET_ERC20()` must equal the vault-side wrapper (for native sides) or pair token (for ERC-20 sides).
- `vault.asset()` must equal `composer.ASSET_ERC20()`.
- Remote-side `OFT.token()` must equal the remote side's wrapper or pair token.
- `peers(remote_eid)` is set in both directions and matches the configured remote OFT.

If any of these fail, the engine refuses to start the rebalance monitor with a specific error message naming the offending pair, side, and the on-chain vs declared mismatch. Legacy pairs without `bridge_route` skip preflight.

## How It Works

### Threshold Model

Each pair has a target balance and a deviation band for each side. The monitor computes:

```
lower_bound = target * (10000 - deviation_band_bps) / 10000
upper_bound = target * (10000 + deviation_band_bps) / 10000
```

When a balance falls below `lower_bound`, the monitor bridges funds FROM the other side. The transfer amount is capped by:
1. The deficit (how far below target)
2. `max_bridge_amount`
3. The donor's headroom above their own lower bound (won't drain the donor below their threshold)

When a balance exceeds `upper_bound`, the surplus is bridged to the other side, capped by the receiver's headroom below their upper bound.

### Transfer Lifecycle

ERC-20 pairs (e.g., USDC):

```
Submitted --> Relaying --> Completed                              (Composer / outbound)
Submitted --> Relaying --> PendingRedemption --> Completed         (OFT send + vault redeem)
```

Native-asset pairs (e.g., ETH ↔ ETH via WETH/vbETH) add `WrapPending` before and `UnwrapPending` after:

```
WrapPending --> Submitted --> Relaying --> UnwrapPending --> Completed                       (Composer / outbound)
WrapPending --> Submitted --> Relaying --> PendingRedemption --> UnwrapPending --> Completed (Non-composer / inbound)
```

Any non-terminal state can transition to `Failed` (unrecoverable, no funds at risk) or `NeedsIntervention` (admin-resolvable).

| Status | Description |
|--------|-------------|
| `wrap_pending` | Native source: `WETH.deposit{value}` / `vbETH.deposit{value}` submitted, awaiting confirmation. |
| `submitted` | Bridge tx submitted, awaiting source chain confirmation. |
| `relaying` | Confirmed on source; LayerZero delivering to destination. |
| `pending_redemption` | Shares arrived on destination; vault redeem tx needed (non-composer flow only). |
| `unwrap_pending` | Native destination: `vbETH.withdraw` / `WETH.withdraw` submitted to convert wrapper back to native. |
| `completed` | Final tokens available in solver wallet. |
| `failed` | Unrecoverable error, no funds at risk. |
| `needs_intervention` | Timed out, ambiguous broadcast, or retry exhausted — admin must resolve. |

#### Crash-window discipline

Each tx-submission phase (`approve`, `bridge`, `wrap`, `redeem`, `unwrap`) persists a `*_submit_attempted` marker BEFORE the broadcast and the tx hash AFTER. If the process crashes between the two saves:

- If the error path is pre-broadcast (`InsufficientNativeGas`, `NonceTooLow`), the marker rolls back and the phase retries cleanly.
- If the error is ambiguous (generic), the marker stays set and the next monitor tick escalates to `NeedsIntervention` rather than risk a double-submit.

#### Dropped-tx recovery

After a phase tx hash is persisted, the monitor polls the receipt every tick. If `get_receipt` fails, it falls back to `tx_exists`. After `WRAP_MISSING_CHECKS_MAX` / `UNWRAP_MISSING_CHECKS_MAX` (3) consecutive `Ok(false)` responses, the hash and marker are cleared and the phase re-submits on the next tick.

### Safety Guards

| Guard | Description |
|-------|-------------|
| Cooldown | After a rebalance, the same pair is blocked for `cooldown_seconds` |
| Max pending | No new auto-rebalances if `max_pending_transfers` active transfers exist |
| Per-pair lock | Only one active transfer per pair_id at a time |
| Transaction semaphore | Bridge and redeem transactions are serialized to prevent nonce conflicts |
| Timeout escalation | Transfers stuck >30 min (Submitted/Relaying/WrapPending/UnwrapPending) or >24h (PendingRedemption) escalate to NeedsIntervention |
| Preflight | At startup, pairs with `bridge_route` are cross-checked against on-chain state (composer/vault/OFT/peer wiring + `approvalRequired`). Mismatches refuse the engine boot. |
| Approve-phase timeout | An approve tx that has been broadcast (or has a stored hash) but never advances the bridge phase within `APPROVE_PHASE_TIMEOUT_SECS` (1h) escalates to NeedsIntervention. Guard fires on `approve_was_broadcast OR approve_tx_hash.is_some()` so a stored hash with the flag unset cannot bypass the timeout. |
| Allowance precheck fallback | A transient RPC failure during the pre-broadcast allowance read defaults to `0` and falls through to approve, instead of escalating. ERC-20 approve is a *set* operation — a redundant approve is a safe operational fallback. |
| Malformed approve hash | If `approve_tx_hash` is stored but cannot be decoded as 32 hex bytes, the monitor escalates to NeedsIntervention rather than retrying — corrupt state must not be auto-recovered. |
| Nonce-cache rollback | When `eth_sendRawTransaction` returns a definite rejection (e.g. plain `transaction underpriced`, `insufficient funds`), the delivery layer resets the local nonce cache to the chain's `pending` count instead of leaving it advanced. Prevents the next tx from colliding on a phantom nonce. |
| Redeem retry limit | 3 consecutive redeem failures escalate to NeedsIntervention |
| Non-composer vault guard | Routes without a vault address are rejected for non-composer flows |

### NeedsIntervention Resolution

Transfers in `needs_intervention` lock the pair and require admin action via `POST /admin/rebalance/transfers/{id}/resolve`:

| Resolution | When to use |
|-----------|-------------|
| `mark_completed` | Funds arrived but detection failed (verified manually) |
| `mark_failed` | Funds are confirmed lost or unrecoverable |
| `retry` | Resets failure count and restores previous status for the monitor to re-attempt |

### Insufficient Native Gas

If a transfer enters `needs_intervention` with a reason containing `Insufficient native gas`, the solver did not submit the transaction. The signer address did not have enough native gas token to cover the up-front reservation:

```text
gas_limit * max_fee_per_gas + value
```

Top up the solver EOA on the source chain, then use the resolve endpoint with `retry` for the affected transfer. The `statusReason` includes the current balance, required wei, and shortfall wei.

## API Endpoints

All under `/api/v1/admin/rebalance/`. See `api-spec/rebalance-api.yaml` for the full OpenAPI spec.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/config` | JWT | Current rebalance configuration |
| PUT | `/config` | EIP-712 | Update global settings (enabled, cooldown, max_pending) |
| PUT | `/config/threshold` | EIP-712 | Update per-pair thresholds |
| GET | `/status` | JWT | Real-time balance vs threshold analysis with monitor freshness |
| GET | `/transfers` | JWT | Active + historical transfers |
| POST | `/trigger` | EIP-712 | Manually trigger a rebalance |
| POST | `/transfers/{id}/resolve` | EIP-712 | Resolve a NeedsIntervention transfer |

## Runtime Updates

Global settings and per-pair thresholds can be updated at runtime via the PUT endpoints without restarting the solver. Changes are validated before persisting and take effect on the next monitor tick via hot-reload.

## Enabling live post-fill gas estimation (per chain)

The `live_post_fill_estimate_chain_ids` field on `GasConfig` is a set of destination chain IDs allowed to use the override-based `eth_estimateGas` path for the post-fill (Hyperlane `submit(...)`) leg. Empty set = the override path is disabled everywhere and the solver falls back to the static `gas.flows.<flow>.post_fill` default. Add chain IDs **one at a time** after validating each.

The override path pre-populates the OutputSettler's `_fillRecords[orderId][outputHash]` slot via `stateOverride` so `eth_estimateGas` for a synthetic Hyperlane post-fill `submit(...)` returns a realistic gas number instead of reverting with `FillNotRecorded`. Storage layout assumed: slot index `1` for `_fillRecords`. If a chain redeploys the OutputSettler with a layout change (any new state variable inserted before `_fillRecords`), the integration test below MUST be re-run for that chain before its ID stays in the set.

### 1. Verify storage layout against the destination chain RPC

Run the live integration test against the destination chain whose ID you want to add. The test sends two `eth_estimateGas` calls for a synthetic post-fill `submit(...)` — one bare (which must revert) and one with the override (which must return realistic units):

```bash
OIF_LIVE_RPC=1 \
OIF_TEST_DEST_RPC_URL=<destination_chain_rpc_url> \
OIF_TEST_DEST_CHAIN_ID=<chain_id_to_validate> \
OIF_TEST_ORIGIN_CHAIN_ID=<origin_chain_id> \
OIF_TEST_OUTPUT_SETTLER=<output_settler_address_on_dest> \
OIF_TEST_OUTPUT_ORACLE=<hyperlane_output_oracle_on_dest> \
OIF_TEST_RECIPIENT_ORACLE=<hyperlane_input_oracle_on_origin> \
cargo test -p solver-core --features test-helpers \
    --test post_fill_override_integration -- --nocapture
```

The destination chain RPC MUST honor `eth_estimateGas` `stateOverride` (Alchemy, Infura, and self-hosted Geth/Reth all do; some lightweight providers strip it silently — if so, the test fails and the chain is unsafe to enable). If the test fails at the override step but the bare step reverted as expected, the override mechanism is broken on that chain and the chain ID must NOT be added.

### 2. Add the chain ID via signed UpdateGasConfig

Use the existing `PUT /config` admin endpoint (signed EIP-712 `UpdateGasConfig`) to APPEND the new chain ID to `live_post_fill_estimate_chain_ids` — do NOT replace the set, or you will silently disable previously-validated chains. Verify via `GET /config` immediately after that the set contains both the old and new IDs.

### 3. Watch outcome events for 24h

Every quote with the chain enabled emits exactly one structured `tracing` event with the constant message `"post-fill gas estimate"` and the `outcome=` field set to one of: `success`, `fallback_zero`, `fallback_error`, `skipped_build_tx`, `skipped_disabled`, `skipped_unsupported_chain`. The `chain_id=` field is also set on the surrounding `calculate_cost_context` span. Query log aggregation for the new chain over the next 24 hours:

- `outcome=success` count per `chain_id` — should dominate.
- `outcome=fallback_error` count per `chain_id` — should be `<1%` of total. Sustained `>5%` indicates a broken override path (RPC provider drift, layout change) and triggers rollback.
- `outcome=fallback_zero` count per `chain_id` — should be `0` or near-zero. A non-trivial rate means the contract returned `0` units, which usually points at an oracle-side check we missed.
- `delta_pct` distribution (only emitted on `success`) — should center near `0` with stddev `<30%`. A persistent positive bias `>30%` means the static default was too low; a persistent negative bias `<-30%` means we're now over-quoting and losing competitive edge.

### 4. Promote, or roll back

If the success rate is healthy and `delta_pct` is in band: promote the next chain on the list and repeat. If the failure rate exceeds threshold OR `delta_pct` is wildly off: roll back by emitting another signed `UpdateGasConfig` that REMOVES that chain ID from `live_post_fill_estimate_chain_ids`. Takes effect on the next quote. No deploy needed. The override path silently falls back to the static default for that chain, restoring today's behavior. If a layout change is suspected, re-run the integration test against the chain (Step 1) before considering re-enabling.
