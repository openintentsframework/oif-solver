# Plan: Non-Seeded Network Seeding with Oracle Type Selection

Date: February 19, 2026
Branch context: `setup-empty-tokens`
Status: Implemented in codebase (kept as design record)

## Goal

Support seeding for non-seeded networks and allow choosing settlement/oracle type from JSON.

Default remains:
- `settlement.type = "hyperlane"`

Also supported in this plan:
- `settlement.type = "direct"`

## Scope

In scope:
- Non-seeded networks accepted during seed merge when required fields are present.
- JSON-driven settlement selection: `hyperlane` (default) or `direct`.
- JSON-driven settlement config payload per type.
- Dry-run validation mode via CLI (no public endpoint).
- Backward compatibility with existing stored configs.

Out of scope:
- Runtime add/remove network APIs.
- New oracle protocols beyond current `hyperlane` and `direct`.

## Current Gaps

1. Merge currently rejects unknown chain IDs.
2. `OperatorConfig.settlement` is hyperlane-shaped, not type-selectable.
3. Runtime config merge hardcodes `hyperlane` implementation.
4. Seed merge builds full-mesh routes by default and does not accept JSON settlement payload.

## Target JSON Contract

Top-level in `SeedOverrides`:

- `settlement.type`: `"hyperlane" | "direct"` (default `"hyperlane"`)
- `settlement.hyperlane`: optional object (required when type is `hyperlane` and non-seeded chains are present)
- `settlement.direct`: optional object (required when type is `direct`)

Optional routing helper:
- `routing_defaults.parent_chain_id`
- `routing_defaults.hub_chain_id`

## Phase 0: Type and Schema Abstractions

Files:
- `crates/solver-types/src/seed_overrides.rs`
- `crates/solver-types/src/operator_config.rs`

### 0.1 SeedOverrides additions

Add settlement override structs:
- `SettlementTypeOverride` enum: `Hyperlane`, `Direct`
- `SettlementOverride { type, hyperlane, direct }`
- `HyperlaneSettlementOverride` fields:
  - `mailboxes`, `igp_addresses`
  - `oracles.input`, `oracles.output`
  - `routes`
  - optional `default_gas_limit`, `message_timeout_seconds`, `finalization_required`
- `DirectSettlementOverride` fields:
  - `oracles.input`, `oracles.output`
  - `routes`
  - optional `dispute_period_seconds`, `oracle_selection_strategy`

### 0.2 OperatorConfig settlement refactor

Refactor `OperatorSettlementConfig` to carry both type and per-type configs:
- `settlement_type: OperatorSettlementType` (default `Hyperlane` for backward compatibility)
- `hyperlane: Option<OperatorHyperlaneConfig>`
- `direct: Option<OperatorDirectConfig>`

Add `OperatorDirectConfig` with:
- `dispute_period_seconds`
- `oracles` (input/output)
- `routes`
- `oracle_selection_strategy`

Backward compatibility rule:
- Existing configs without `settlement_type` deserialize as `Hyperlane`.
- Implementation detail:

```rust
#[serde(default = "default_settlement_type")]
pub settlement_type: OperatorSettlementType,

fn default_settlement_type() -> OperatorSettlementType {
    OperatorSettlementType::Hyperlane
}
```

## Phase 1: Non-Seeded Networks in Merge Layer

File:
- `crates/solver-service/src/config_merge.rs`

### 1.1 Unknown chain handling

Replace unconditional unknown-chain rejection with:
- If seeded: allow (with seed defaults + optional overrides)
- If non-seeded: require network contract bundle

Required for non-seeded network:
- `name`
- `network_type`
- `input_settler_address`
- `output_settler_address`
- at least one HTTP RPC in `rpc_urls`

Validation errors must include:
- `chain_id`
- exact missing fields list

### 1.2 Mixed-source network builder

Update network builder to:
- Use seed defaults for seeded chains when fields absent
- Use JSON-only fields for non-seeded chains

## Phase 2: Settlement Builder by Type

File:
- `crates/solver-service/src/config_merge.rs`

### 2.1 Merge to OperatorConfig

In `merge_to_operator_config`:
- Determine settlement type:
  - explicit `seed_overrides.settlement.type`
  - fallback default `hyperlane`
- Build only selected settlement config:
  - `hyperlane`: from JSON override if provided, else seed-derived fallback
  - `direct`: from JSON direct payload only
  - if `settlement.type = "direct"` and `settlement.direct` is missing -> fail validation (do not silently default)

### 2.2 Runtime Config generation

In `build_settlement_config_from_operator`:
- If type `hyperlane`, insert `implementations["hyperlane"]`
- If type `direct`, insert `implementations["direct"]`
- Never insert both as active unless explicitly designed later
- Guardrail: runtime output must contain exactly one selected settlement implementation.

In `build_settlement_config` (seed path):
- Keep default `hyperlane` behavior for legacy flows

### 2.3 Validation per type

For `hyperlane`:
- require consistent `oracles`, `routes`, `mailboxes`, `igp_addresses`

For `direct`:
- require `oracles` and `routes`
- require valid `dispute_period_seconds` bounds

## Phase 3: Routing Fallback Rules

If routes are not provided:
- Use explicit `routing_defaults.parent_chain_id` / `hub_chain_id` if set
- Else if exactly one parent/hub exists among selected networks, use it
- Else fail validation and require explicit routes

Do not auto full-mesh by default for non-seeded onboarding.

## Phase 4: Dry-Run Validation Mode (CLI)

No public endpoint.

Add CLI flag:
- `--seed-validate-only`

Behavior:
- Parse + merge + validate
- print structured result (`valid`, `errors[]`, `warnings[]`, `summary`)
- exit without writing Redis

## Phase 5: Tests

Files:
- `crates/solver-service/src/config_merge.rs`
- `crates/solver-types/src/seed_overrides.rs`
- `crates/solver-types/src/operator_config.rs`
- CLI seed tests in `crates/solver-service/src/main.rs` test module (or dedicated integration tests)

Required tests:
1. Non-seeded + `hyperlane` complete payload -> success
2. Non-seeded + `direct` complete payload -> success
3. `settlement.type = "direct"` with missing `settlement.direct` -> validation error
4. Missing required fields for non-seeded chain -> error with missing field list
5. `settlement.type` omitted -> defaults to `hyperlane`
6. Existing stored operator config without `settlement_type` -> loads as `hyperlane`
7. Runtime config emits only chosen settlement implementation
8. Empty-token behavior remains unchanged

## Rollout

1. Default behavior (no feature flags):
- non-seeded networks are supported by default when required fields are provided
- settlement type selection is always enabled (`hyperlane` default, `direct` optional)

2. Staging matrix:
- Seeded + non-seeded with `hyperlane`
- Seeded + non-seeded with `direct`
- smoke: `/health`, `/api/v1/tokens`, quote path, settlement init

3. Production:
- enforce dry-run step before any seeding
- keep default settlement type as `hyperlane`

## Acceptance Criteria

1. Seeding supports non-seeded networks with JSON-defined contracts.
2. Settlement/oracle type is selectable via JSON (`hyperlane` default, `direct` optional).
3. Runtime activates the selected settlement implementation correctly.
4. Backward compatibility preserved for existing configs.
5. No public validation endpoint introduced.

## Estimated Timeline

- Phase 0 + 1: 1.5 to 2 days
- Phase 2 + 3: 1 to 1.5 days
- Phase 4 + 5 + staging: 1 day

Total: ~3.5 to 4.5 engineering days
