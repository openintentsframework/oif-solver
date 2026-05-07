# Fee Policy

The solver prices and submits EVM transactions using a per-chain EIP-1559 fee policy. This document covers what each knob does, the auto-generated defaults, and how to override them via your bootstrap config.

## At a glance

- **Where it lives:** the `fee_policy` block in your bootstrap JSON.
- **Scope:** every EVM chain the solver delivers transactions on.
- **Default behavior** (no `fee_policy` block):
  - `0.01 gwei` priority floor and fallback on every chain
  - 85th-percentile recent-block tip estimate (`"fast"` speed)
  - `buffered_effective_125` quote-cost strategy (`base × 1.25 + priority`)
  - No `gas_price_cap`

If those defaults work for you, you don't need to add anything. The block exists so you can tune per-chain.

## EIP-1559 in 30 seconds

Every EIP-1559 transaction has three numbers:

| Field | Source | Goes to |
|---|---|---|
| `base_fee_per_gas` | Protocol, auto-set per block | Burned |
| `max_priority_fee_per_gas` | You (the tip) | Validator |
| `max_fee_per_gas` | You (your ceiling) | Caps total cost |

The validator picks transactions by priority fee (highest first). If you tip too low, you wait. If you tip too high, you waste money.

The solver's job is to read live network state (`eth_feeHistory`) and pick reasonable values for `max_priority_fee_per_gas` and `max_fee_per_gas`. The fee policy controls *how* it picks them.

## Schema

```json
{
  "fee_policy": {
    "default_speed": "fast",
    "chains": {
      "1": {
        "min_priority_fee_per_gas": "10000000",
        "priority_fee_fallback": "10000000",
        "quote_cost_strategy": "buffered_effective_125",
        "gas_price_cap": "300000000000"
      }
    }
  }
}
```

### Top level

- **`default_speed`** *(optional, default `"fast"`)* — drives the percentile passed to `eth_feeHistory`. See speed table below.
- **`chains`** *(optional)* — per-chain overrides keyed by chain id stringified. Whatever you don't specify keeps the auto-generated default.

### Per-chain (every field optional)

All wei values are decimal strings to avoid JSON's 53-bit float precision pit.

- **`min_priority_fee_per_gas`** *(default `"10000000"` = 0.01 gwei)* — hard floor on `max_priority_fee_per_gas`. Use a higher value if you operate on a chain where validators routinely orphan low-tip transactions.
- **`priority_fee_fallback`** *(default `"10000000"` = 0.01 gwei)* — kicks in when `eth_feeHistory` returns all-zero rewards. Without this, priority would be 0 and your transaction could sit forever.
- **`quote_cost_strategy`** *(default `"buffered_effective_125"`)* — how the user is charged for gas. See strategy table below.
- **`gas_price_cap`** *(default: no ceiling)* — hard ceiling on `max_fee_per_gas`. Use as a panic stop against extreme spikes.

### Speed → percentile mapping

| Speed | Percentile | Best for |
|---|---|---|
| `safe_low` | 30th | Cheapest. Fine for non-time-sensitive ops on calm chains. |
| `average` | 50th | Median tip. Tracks typical user transactions. Recommended for cross-chain solvers with multi-minute deadlines. |
| `fast` *(default)* | 85th | Inclusion within 1–2 blocks during normal load. May over-tip on chains where MEV bundles inflate the upper percentiles. |
| `fastest` | 99th | Top of MEV bundle territory. Only justified if you're racing other solvers on the same intent. |

### Quote-cost strategies

Submit-side `max_fee_per_gas` is what the chain might charge you. Quote-side `cost_per_gas` is what you bill the user. They don't have to match.

| Strategy | Formula | When to use |
|---|---|---|
| `max_fee` | `max_fee_per_gas` | Most conservative. User pays your worst-case ceiling — over-charges in calm regimes. |
| `effective` | `base_fee + priority` | Least conservative. User pays observed cost — underprices if base spikes between quote and execution. |
| `buffered_effective_125` *(default)* | `base × 1.25 + priority` | Middle ground. Absorbs one block of base-fee growth without billing the full ceiling. |

## Worked examples

### Default behavior (no `fee_policy` block)

Every chain in `network_ids` gets the auto-generated defaults: 0.01 gwei floor, 0.01 gwei fallback, `fast` speed, `buffered_effective_125` strategy, no cap. This is what you get without writing anything.

### Lower percentile to track median (recommended for most cross-chain solvers)

```json
{
  "fee_policy": {
    "default_speed": "average"
  }
}
```

Drops the percentile from 85 to 50 for every chain. Per-chain defaults stay. Useful when you're not racing for inclusion — the 30-min fill deadline of a typical cross-chain intent has plenty of slack for median-tip inclusion. Expect 50–80% lower mainnet priority versus `"fast"` in calm regimes.

### Production-hardened mainnet + L2

```json
{
  "fee_policy": {
    "default_speed": "average",
    "chains": {
      "1": {
        "min_priority_fee_per_gas": "500000000",
        "gas_price_cap": "300000000000"
      }
    }
  }
}
```

- `default_speed: "average"` — median tip across all chains.
- Chain 1 (Ethereum mainnet) gets a 0.5 gwei priority floor (slightly above current "fast" tier on etherscan, well below the median during congestion) and a 300 gwei panic ceiling.
- Other chains inherit all defaults — 0.01 gwei floor, no cap.

## How to verify it's working

Two log lines tell you everything.

### At quote time

```
INFO Quote gas fee params resolved
  origin_chain_id=747474 origin_fee_model=Eip1559
  origin_cost_per_gas=11250000     origin_max_priority_fee_per_gas=10000000
  dest_chain_id=1        dest_fee_model=Eip1559
  dest_cost_per_gas=2643633593     dest_max_priority_fee_per_gas=1999600000
```

This is what the cost engine charges the user for this quote.

### At submit time

```
INFO Applied transaction fee policy
  chain_id=1  fee_model=Eip1559
  max_fee_per_gas=2387565905  max_priority_fee_per_gas=2000000000
  cost_per_gas=2387565905
```

This is what the actual transaction was signed with. For a single intent, expect one `Quote gas fee params resolved` line at quote time and four `Applied transaction fee policy` lines through the lifecycle (Prepare, Fill, PostFill, Claim).

### What good values look like

- `max_priority_fee_per_gas` should match either:
  - your configured `min_priority_fee_per_gas` (when network is quieter than your floor), or
  - the percentile estimate from `eth_feeHistory` (when network is busier).
- `max_fee_per_gas ≈ base_fee × 2 + max_priority_fee_per_gas`. If you set a `gas_price_cap` and the network is hot, expect `max_fee_per_gas == cap`.
- Quote-time and submit-time values for the same chain should match within the cache TTL window (3s mainnet, 1s Katana, 2s others). Mismatch beyond that = a fresh resolution between quote and submit.

## Troubleshooting

### Mainnet priority is higher than I expected

`fast` (85th percentile) of `eth_feeHistory` includes MEV bundles, which inflate the upper percentiles past what etherscan calls "Rapid." If you're seeing ~2 gwei priorities while etherscan says 0.5 gwei rapid, switch `default_speed` to `"average"` (50th) or `"safe_low"` (30th). Verify by checking the next `Quote gas fee params resolved` log.

### Quote rejected with `cannot be zero after cost adjustment`

Not a fee-policy bug. The cost engine is correctly refusing a quote where total gas cost exceeds the requested output amount. Common on small swaps where mainnet gas (~$1–2 per Fill+PostFill at 2 gwei priority) exceeds the requested output. Retry with a larger amount, or lower the percentile if priority is the dominant cost.

### Transaction stuck in the mempool

Tip is too low for the current network state. Two recovery paths:

- **Short term:** raise `min_priority_fee_per_gas` for the affected chain.
- **Long term:** raise `default_speed` from `safe_low` to `average`, or from `average` to `fast`.

### `Insufficient native gas for transaction preflight`

Unrelated to fee policy. The signer wallet on that chain doesn't have enough native ETH to cover `(gas_limit × max_fee_per_gas) + value`. Top up the wallet and retry. Lowering `max_fee_per_gas` via a lower percentile shrinks the per-tx burn but doesn't replace the need to keep ETH on the signer.

## Behavior notes

- **Required for every chain in `network_ids`.** Startup validation rejects configs whose `network_ids` includes a chain with no `fee_policy.chains.<id>` entry. The auto-generated block covers every configured chain by default — you only hit this error if you hand-wrote a `chains` block and forgot one.
- **Per-chain TTL on resolved fee params.** Mainnet 3s, Katana 1s, others 2s. Submit calls within the TTL hit the cache and reuse the quote-time values, keeping quote ↔ submit cost consistent.
- **EIP-1559 vs legacy is decided at runtime, not by config.** If `eth_feeHistory` errors or the chain has no `base_fee_per_gas`, the solver falls back to legacy `eth_gasPrice` for that single quote. Look for `Falling back to legacy gas price after feeHistory failure` in the logs — if you see it repeatedly, your RPC may not support EIP-1559 properly.

## Related code

- `crates/solver-types/src/seed_overrides.rs` — `FeePolicyOverride` schema (operator-facing).
- `crates/solver-service/src/config_merge.rs` — `build_delivery_config_from_operator` (override merging + defaults).
- `crates/solver-delivery/src/implementations/evm/fees.rs` — `SolverEip1559Estimator` and `ChainFeePolicy` (runtime estimator).
- `crates/solver-delivery/src/implementations/evm/alloy.rs` — `get_fee_params` (RPC + cache + EIP-1559/legacy fallback ladder).
