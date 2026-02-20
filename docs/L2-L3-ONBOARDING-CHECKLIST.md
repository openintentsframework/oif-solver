# L2/L3 Onboarding Checklist (Seeded + Non-Seeded Networks)

Date: February 19, 2026

Purpose:
- Onboard a brand new L2/L3 (`type = "new"`) and pair it with at least one other network.
- Boot the solver from JSON bootstrap config.
- Validate contract bundle + settlement/oracle configuration before first run.

## 1) Current System Behavior (Implemented)

- You must configure at least 2 unique networks.
- Tokens can be empty at boot.
- Chain IDs can be seeded or non-seeded.
- Non-seeded networks are supported by default (no feature flags).
- First boot supports:
  - Seedless mode: `--bootstrap-config <json>` (preferred)
  - Seed-backed mode: `--seed <preset> --bootstrap-config <json>`
  - Deprecated alias: `--seed-overrides` (maps to `--bootstrap-config`)
- Settlement implementation is selected by JSON:
  - `settlement.type = "hyperlane"` (default when omitted)
  - `settlement.type = "direct"`
  - `settlement.type = "broadcaster"`
- Runtime emits only the selected settlement implementation.
- `routing_defaults` is currently parsed but not used for route generation.
- Intent expiry/time budget tuning is documented in `docs/oracles/settlement-timing-configuration.md`.

## 2) Required Data For Non-Seeded Networks

Provide this network bundle in `networks[]`:

- `chain_id`
- `name`
- `type`
- `rpc_urls` (at least one)
- `input_settler_address`
- `output_settler_address`

Mode-specific rule:

- Seedless mode: required for every configured chain.
- Seed-backed mode: required only for chains not present in selected seed preset.

Optional network fields:

- `input_settler_compact_address`
- `the_compact_address`
- `allocator_address`

## 3) Settlement/Oracle Requirements

### 3.1 Hyperlane (`settlement.type = "hyperlane"`)

For each configured chain, ensure:

- `settlement.hyperlane.mailboxes[chain_id]`
- `settlement.hyperlane.igp_addresses[chain_id]`
- `settlement.hyperlane.oracles.input[chain_id]` (non-empty)
- `settlement.hyperlane.oracles.output[chain_id]` (non-empty)

Routes:

- Optional `settlement.hyperlane.routes`
- If omitted/empty, routes default to full mesh among selected chains
- If provided, every route source/destination chain must be in `networks[]`

### 3.2 Direct (`settlement.type = "direct"`)

Required:

- `settlement.direct.oracles.input[chain_id]` for all chains
- `settlement.direct.oracles.output[chain_id]` for all chains

Optional:

- `settlement.direct.routes` (defaults to full mesh if omitted/empty)
- `settlement.direct.dispute_period_seconds` (default `300`)
- `settlement.direct.oracle_selection_strategy` (`First`, `RoundRobin`, `Random`)
- If routes are provided, every source/destination chain must be in `networks[]`

Validation rule:

- If `settlement.type = "direct"` and `settlement.direct` is missing, seeding fails.

### 3.3 Broadcaster (`settlement.type = "broadcaster"`)

Required:

- `settlement.broadcaster.oracles.input[chain_id]` for source/input chains
- `settlement.broadcaster.oracles.output[chain_id]` for destination/output chains
- `settlement.broadcaster.routes` (or omit/empty for full mesh default)
- `settlement.broadcaster.broadcaster_addresses[destination_chain_id]`
- `settlement.broadcaster.receiver_addresses[source_chain_id]`
- `settlement.broadcaster.broadcaster_ids[remote_chain_id]`
- `settlement.broadcaster.proof_service_url`

Timing:

- Uses the same fixed-key override as other settlements:
  - `settlement.broadcaster.intent_min_expiry_seconds`
- Broadcaster-only timing knobs:
  - `proof_wait_time_seconds`
  - `storage_proof_timeout_seconds`
  - `default_finality_blocks`
  - `finality_blocks`
  - `chain_block_time_seconds`
  - `intent_safety_buffer_seconds`

See full timing guide: `docs/oracles/settlement-timing-configuration.md`.

## 4) Deterministic Deployment Matrix (Observed In Current Seeds)

| Contract field | Deterministic across all seeded networks? | Recommendation |
|---|---|---|
| `the_compact` | Often same, but still verify | Treat as deterministic candidate only after verification |
| `input_settler` | No | Treat as per-network |
| `output_settler` | No | Treat as per-network |
| `input_settler_compact` | No | Treat as per-network |
| `allocator` | No | Treat as per-network |
| `hyperlane_mailbox` | No | Resolve per chain |
| `hyperlane_igp` | No | Resolve per chain |
| `hyperlane_oracle` | No | Resolve per chain/environment |

## 5) Boot Checklist

### 5.1 Planning

- [ ] Choose settlement type (`hyperlane`, `direct`, or `broadcaster`).
- [ ] Define network set (minimum 2).
- [ ] Confirm route policy (explicit routes or fallback full mesh).
- [ ] Note: `routing_defaults` is not active today; do not rely on it.

### 5.2 JSON Readiness

- [ ] Every non-seeded network has required non-seeded fields.
- [ ] `settlement.type` is correct for intended mode.
- [ ] If `direct`, `settlement.direct` is present and complete.
- [ ] If `broadcaster`, `settlement.broadcaster` is present and complete.
- [ ] If `hyperlane` with non-seeded chains, chain maps are complete.
- [ ] Intent minimum expiry/time budgets are configured for the selected settlement.
- [ ] Token arrays are intentionally set (empty allowed).

### 5.3 First Boot Validation

- [ ] Run first boot command:
  - Seedless (preferred): `cargo run -- --bootstrap-config config/example.json --force-seed`
  - Seed-backed: `cargo run -- --seed testnet --bootstrap-config config/seed-overrides-testnet.json --force-seed`
- [ ] Ensure local signer is configured if using local account (`SOLVER_PRIVATE_KEY` valid 32-byte hex key).
- [ ] Check `GET /health`.
- [ ] Check `GET /api/v1/tokens`.
- [ ] If admin enabled, check `GET /api/v1/admin/config`.

## 6) JSON Templates

### 6.1 Non-Seeded + Hyperlane

```json
{
  "networks": [
    {
      "chain_id": 1234,
      "name": "new-l2",
      "type": "new",
      "rpc_urls": ["https://rpc.new-l2.example"],
      "input_settler_address": "0x1000000000000000000000000000000000000001",
      "output_settler_address": "0x2000000000000000000000000000000000000002",
      "tokens": []
    },
    {
      "chain_id": 8453,
      "name": "base",
      "type": "parent",
      "rpc_urls": ["https://mainnet.base.org"],
      "input_settler_address": "0x9000000000000000000000000000000000000009",
      "output_settler_address": "0xa00000000000000000000000000000000000000a",
      "tokens": []
    }
  ],
  "settlement": {
    "type": "hyperlane",
    "hyperlane": {
      "mailboxes": {
        "1234": "0x3000000000000000000000000000000000000003",
        "8453": "0x4000000000000000000000000000000000000004"
      },
      "igp_addresses": {
        "1234": "0x5000000000000000000000000000000000000005",
        "8453": "0x6000000000000000000000000000000000000006"
      },
      "oracles": {
        "input": {
          "1234": ["0x7000000000000000000000000000000000000007"],
          "8453": ["0x8000000000000000000000000000000000000008"]
        },
        "output": {
          "1234": ["0x7000000000000000000000000000000000000007"],
          "8453": ["0x8000000000000000000000000000000000000008"]
        }
      },
      "routes": {
        "1234": [8453],
        "8453": [1234]
      }
    }
  }
}
```

### 6.2 Direct

```json
{
  "networks": [
    {
      "chain_id": 11155420,
      "name": "optimism-sepolia",
      "type": "parent",
      "rpc_urls": ["https://sepolia.optimism.io"],
      "input_settler_address": "0x1100000000000000000000000000000000000011",
      "output_settler_address": "0x1200000000000000000000000000000000000012",
      "tokens": []
    },
    {
      "chain_id": 84532,
      "name": "base-sepolia",
      "type": "hub",
      "rpc_urls": ["https://sepolia.base.org"],
      "input_settler_address": "0x2100000000000000000000000000000000000021",
      "output_settler_address": "0x2200000000000000000000000000000000000022",
      "tokens": []
    }
  ],
  "settlement": {
    "type": "direct",
    "direct": {
      "dispute_period_seconds": 900,
      "oracle_selection_strategy": "RoundRobin",
      "oracles": {
        "input": {
          "11155420": ["0x7100000000000000000000000000000000000007"],
          "84532": ["0x8200000000000000000000000000000000000008"]
        },
        "output": {
          "11155420": ["0x7100000000000000000000000000000000000007"],
          "84532": ["0x8200000000000000000000000000000000000008"]
        }
      }
    }
  }
}
```

## 7) Key References

- Merge + validation: `crates/solver-service/src/config_merge.rs`
- Seed override schema: `crates/solver-types/src/seed_overrides.rs`
- Operator runtime model: `crates/solver-types/src/operator_config.rs`
- Settlement implementations: `crates/solver-settlement/src/implementations/hyperlane.rs`, `crates/solver-settlement/src/implementations/direct.rs`, `crates/solver-settlement/src/implementations/broadcaster.rs`
- Timing budget guide: `docs/oracles/settlement-timing-configuration.md`
