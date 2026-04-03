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
| `token_address` | string | Yes | ERC-20 token contract address (for balance queries and approvals) |
| `oft_address` | string | Yes | LayerZero OFT contract address (for quoteSend/send operations) |

### Bridge Config (LayerZero)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `endpoint_ids` | object | Yes | Maps chain_id (as string key) to LayerZero Endpoint ID (EID). E.g., `{"1": 30101, "42161": 30110}` |
| `lz_receive_gas` | u128 | No | Gas limit for lzReceive on destination (default: 200000) |
| `composer_addresses` | object | No | Maps chain_id to OVault Composer contract address. Chains with a composer use the deposit+bridge flow. |
| `vault_addresses` | object | No | Maps chain_id to ERC-4626 vault contract address. Required for non-composer flows that need vault redemption. |

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

```
Submitted --> Relaying --> Completed                        (Composer flow)
Submitted --> Relaying --> PendingRedemption --> Completed   (OFT send + vault redeem flow)
     |            |              |
     v            v              v
  Failed    NeedsIntervention  NeedsIntervention
```

| Status | Description |
|--------|-------------|
| `submitted` | Bridge tx submitted, awaiting source chain confirmation |
| `relaying` | Confirmed on source; LayerZero delivering to destination |
| `pending_redemption` | Shares arrived on destination; vault redeem tx needed (non-composer flows only) |
| `completed` | Final tokens available in solver wallet |
| `failed` | Unrecoverable error, no funds at risk |
| `needs_intervention` | Timed out or retry exhausted; admin must resolve |

### Safety Guards

| Guard | Description |
|-------|-------------|
| Cooldown | After a rebalance, the same pair is blocked for `cooldown_seconds` |
| Max pending | No new auto-rebalances if `max_pending_transfers` active transfers exist |
| Per-pair lock | Only one active transfer per pair_id at a time |
| Transaction semaphore | Bridge and redeem transactions are serialized to prevent nonce conflicts |
| Timeout escalation | Transfers stuck >30 min (Submitted/Relaying) or >24h (PendingRedemption) escalate to NeedsIntervention |
| Redeem retry limit | 3 consecutive redeem failures escalate to NeedsIntervention |
| Non-composer vault guard | Routes without a vault address are rejected for non-composer flows |

### NeedsIntervention Resolution

Transfers in `needs_intervention` lock the pair and require admin action via `POST /admin/rebalance/transfers/{id}/resolve`:

| Resolution | When to use |
|-----------|-------------|
| `mark_completed` | Funds arrived but detection failed (verified manually) |
| `mark_failed` | Funds are confirmed lost or unrecoverable |
| `retry` | Resets failure count and restores previous status for the monitor to re-attempt |

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
