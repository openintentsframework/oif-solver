# Plan: Seedless First Boot Using JSON + Shared Defaults

Date: February 19, 2026

## Goal

Allow first boot with only:

```bash
cargo run -- --bootstrap-config config/example.json
```

without requiring `--seed testnet|mainnet`, while still using shared defaults from `COMMON_DEFAULTS`.

## Why This Makes Sense

- You already provide full network and settlement values in JSON for non-seeded onboarding.
- `--seed` is currently acting as a bootstrap gate in CLI flow, even when JSON is complete.
- Shared defaults (gas/pricing/solver defaults) are environment-agnostic and can come from `COMMON_DEFAULTS` directly.

## Current Behavior (What Blocks Seedless)

In `crates/solver-service/src/main.rs`:

- Seeding path is only entered when both `--seed` and `--seed-overrides` are present (legacy flag name).
- If `--seed` is omitted, solver tries storage load via `SOLVER_ID` and never seeds.

In `crates/solver-service/src/config_merge.rs`:

- `merge_to_operator_config` requires a `&SeedConfig` and reads both:
  - network seed values (for seeded chains fallback)
  - shared defaults (`seed.defaults`)

## Target Behavior

### First boot modes

1. Seed-backed mode (existing):
- `--seed + --bootstrap-config`
- keeps current behavior

2. Seedless mode (new):
- `--bootstrap-config` only
- treats all chains as explicit JSON chains (no seed network fallback)
- uses `COMMON_DEFAULTS` for global defaults

### Subsequent boot mode

3. Storage-load mode (existing):
- no seeding flags
- requires `SOLVER_ID`

## Implementation Plan

## Phase 1: Add Seedless Seeding Path in CLI

File: `crates/solver-service/src/main.rs`

Changes:

- Add new branch before storage-load fallback:
  - if `args.bootstrap_config.is_some()` and `args.seed.is_none()` -> seedless bootstrap mode
- Parse `bootstrap_config` JSON exactly as current parser does.
- Build operator config via new merge function (Phase 2).
- Persist to Redis exactly like existing seed path.
- Keep `--force-seed` behavior identical.

Validation rule for CLI arguments:

- If `--seed` is present but `--bootstrap-config` missing -> return explicit error.
- If `--force-seed` is present but `--bootstrap-config` missing -> return explicit error.
- If `--bootstrap-config` present and `--seed` omitted -> use seedless mode (new).
- Keep `--seed-overrides` as deprecated alias to `--bootstrap-config` for one release cycle.
- Deprecation warning text:
  - `WARN: --seed-overrides is deprecated, use --bootstrap-config instead`

## Phase 2: Introduce Merge API That Uses Shared Defaults Without Seed Preset

File: `crates/solver-service/src/config_merge.rs`

Add function:

- `merge_to_operator_config_seedless(initializer: SeedOverrides) -> Result<OperatorConfig, MergeError>`

Behavior:

- Uses `COMMON_DEFAULTS` for global defaults.
  - Source: `crates/solver-service/src/seeds/types.rs` (`COMMON_DEFAULTS` constant).
- Does not use `SeedConfig.networks` fallback.
- Requires explicit non-seeded bundle for every network:
  - `name`
  - `type`
  - `input_settler_address`
  - `output_settler_address`
  - `rpc_urls` (>= 1)
- Allows empty token arrays (already supported).
- `solver_id` remains optional (same as seed-backed mode):
  - if missing, auto-generate UUID-based solver ID.

Refactor internals to avoid duplication:

- Extract shared builder that accepts:
  - optional `SeedConfig` for seeded fallback
  - `SeedDefaults` for global defaults
- Keep existing `merge_to_operator_config(initializer, seed)` as wrapper over refactored core.
- Add seedless wrapper using `COMMON_DEFAULTS` and no seed network fallback.

## Phase 3: Settlement Rules in Seedless Mode

File: `crates/solver-service/src/config_merge.rs`

Rules:

- `settlement.type = "hyperlane"` (or omitted):
  - require `settlement.hyperlane` explicit and complete for all configured chain IDs
  - complete means, for every configured `chain_id`:
    - `mailboxes[chain_id]` exists
    - `igp_addresses[chain_id]` exists
    - `oracles.input[chain_id]` exists and is non-empty
    - `oracles.output[chain_id]` exists and is non-empty
  - `routes` behavior:
    - if provided, validate sources/destinations against configured chain IDs
    - if omitted/empty, fallback to full mesh across configured chain IDs
  - no seed-derived mailbox/IGP/oracle fallback
- `settlement.type = "direct"`:
  - keep current direct validation (`settlement.direct` required)

Error wording in seedless mode:

- Validation failures should explicitly mention seedless mode context.
- Example:
  - `seedless mode requires explicit input_settler_address for chain 1234`

Reason:

- Without seed preset there is no trusted per-chain source for Hyperlane addresses.

## Phase 4: Docs and Examples

Files:

- `README.md`
- `docs/config-storage.md`
- `config/non-seeded-networks-example.json`

Update docs to show new first-boot command:

```bash
cargo run -- --bootstrap-config config/non-seeded-networks-example.json
```

Keep existing seeded command documented for convenience mode:

```bash
cargo run -- --seed testnet --bootstrap-config config/seed-overrides-testnet.json
```

## Phase 5: Tests

### Unit tests (`crates/solver-service/src/config_merge.rs`)

Add:

1. `merge_to_operator_config_seedless` with full explicit network + hyperlane -> success
2. seedless with missing network required fields -> clear error list
3. seedless with partial required fields (e.g., only missing `input_settler_address`) -> error lists exact missing field
4. seedless with omitted hyperlane payload and `type=hyperlane` -> validation error
5. seedless with `type=direct` and valid direct payload -> success

### CLI/load tests (`crates/solver-service/src/main.rs` or integration tests)

Add:

6. `--bootstrap-config` only triggers seeding path (not storage-load path)
7. no seeding flags and no `SOLVER_ID` still errors as before
8. existing `--seed testnet --bootstrap-config ...` works
9. deprecated alias `--seed-overrides` still works with warning
10. `--force-seed` without `--bootstrap-config` returns explicit CLI error

## Backward Compatibility

- No breaking change for existing commands.
- Existing stored `OperatorConfig` loading remains unchanged.
- Existing seed-backed first boot remains unchanged.

## Acceptance Criteria

1. First boot works with JSON only (`--bootstrap-config`), no `--seed` required.
2. Shared defaults still come from `COMMON_DEFAULTS`.
3. Seed-backed mode still works exactly as today.
4. Seedless mode enforces explicit per-network + settlement requirements.
5. Docs and examples use `--bootstrap-config`.

## Effort Estimate

- Phase 1-3 (core behavior): 0.5 to 1 day
- Phase 4-5 (docs + tests): 0.5 day

Total: ~1 to 1.5 engineering days

## Recommended Rollout

1. Implement + unit tests.
2. Test locally with:
   - `config/non-seeded-networks-example.json`
   - existing `config/seed-overrides-testnet.json`
3. Ship once both modes pass regression tests.
