# Settlement Timing Configuration

Purpose:
- Explain how the solver decides if an intent has enough time left to be accepted.
- Document the JSON fields to tune timing for `hyperlane`, `direct`, and `broadcaster`.

## 1) How intent time gating works

At intent handling time, solver computes:

- `expires_remaining_seconds = order.expires - now`

Then it finds settlement implementation(s) that support this order (route + oracle match).  
For each matching implementation, it computes a required window and applies:

- Skip intent when: `expires_remaining_seconds < required_window_seconds`

If more than one implementation matches, solver uses the **maximum** required window.

Code path: `crates/solver-core/src/handlers/intent.rs`

## 2) Common field name across oracles

Yes. The same key name is used across implementations:

- `intent_min_expiry_seconds`

Supported JSON paths:

- `settlement.hyperlane.intent_min_expiry_seconds`
- `settlement.direct.intent_min_expiry_seconds`
- `settlement.broadcaster.intent_min_expiry_seconds`

When set, this value is used as a fixed minimum window for that implementation.

## 3) Broadcaster computed window (when explicit min is not set)

If `settlement.broadcaster.intent_min_expiry_seconds` is absent, solver estimates:

`required_window_seconds = proof_wait_time_seconds + max_finality_seconds + storage_proof_timeout_seconds + (2 * settlement_poll_interval_seconds) + intent_safety_buffer_seconds`

Where:

- `max_finality_seconds = max(for each cross-chain output: finality_blocks_for_chain * block_time_for_chain)`
- `finality_blocks_for_chain` uses:
  - `settlement.broadcaster.finality_blocks[chain_id]` when present
  - otherwise `settlement.broadcaster.default_finality_blocks`
- `block_time_for_chain` uses:
  - `settlement.broadcaster.chain_block_time_seconds[chain_id]` when present
  - otherwise defaults:
    - OP Stack + Arbitrum IDs: `2s`
    - fallback: `12s`

## 4) Timing fields and defaults

### 4.1 Hyperlane

- `settlement.hyperlane.intent_min_expiry_seconds` (optional, no default)

### 4.2 Direct

- `settlement.direct.intent_min_expiry_seconds` (optional, no default)

### 4.3 Broadcaster

- `settlement.broadcaster.intent_min_expiry_seconds` (optional, no default; fixed window when set)
- `settlement.broadcaster.proof_wait_time_seconds` (default: `30`)
- `settlement.broadcaster.storage_proof_timeout_seconds` (default: `30`)
- `settlement.broadcaster.default_finality_blocks` (default: `20`)
- `settlement.broadcaster.finality_blocks` (optional per-chain map)
- `settlement.broadcaster.chain_block_time_seconds` (optional per-chain map)
- `settlement.broadcaster.intent_safety_buffer_seconds` (default: `90`)

### 4.4 Poll interval (global settlement loop)

- `settlement.settlement_poll_interval_seconds` (in stored operator config; seed defaults usually `3`)

Broadcaster budget includes `2 * settlement_poll_interval_seconds`.

## 5) JSON examples

### 5.1 Hyperlane fixed minimum window

```json
{
  "settlement": {
    "type": "hyperlane",
    "hyperlane": {
      "intent_min_expiry_seconds": 180
    }
  }
}
```

### 5.2 Direct fixed minimum window

```json
{
  "settlement": {
    "type": "direct",
    "direct": {
      "intent_min_expiry_seconds": 180
    }
  }
}
```

### 5.3 Broadcaster computed budget with per-chain tuning

```json
{
  "settlement": {
    "type": "broadcaster",
    "broadcaster": {
      "proof_wait_time_seconds": 45,
      "storage_proof_timeout_seconds": 45,
      "default_finality_blocks": 20,
      "finality_blocks": {
        "11155420": 30,
        "421614": 40
      },
      "chain_block_time_seconds": {
        "11155420": 2,
        "421614": 2
      },
      "intent_safety_buffer_seconds": 120
    }
  }
}
```

### 5.4 Broadcaster fixed minimum window (overrides computed budget)

```json
{
  "settlement": {
    "type": "broadcaster",
    "broadcaster": {
      "intent_min_expiry_seconds": 360
    }
  }
}
```

## 6) Practical recommendation

1. Start with explicit `intent_min_expiry_seconds` for each settlement.
2. Measure real settlement latency by route.
3. Keep a safety margin for reorgs/prover delays.
4. For broadcaster, only move to computed budgeting when per-chain finality and block-time inputs are accurate.

## 7) Type references

- Seed override JSON model: `crates/solver-types/src/seed_overrides.rs`
- Stored operator config model: `crates/solver-types/src/operator_config.rs`
- Runtime config merge: `crates/solver-service/src/config_merge.rs`
- Admission gate logic: `crates/solver-core/src/handlers/intent.rs`
