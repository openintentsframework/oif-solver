# oif-solver — Agent Guide

OIF cross-chain solver. Discovers intents on supported chains, fills them on destination chains, then settles back on origin.

This file is the source of truth for AI coding assistants working in this repo. Claude Code reads it via `CLAUDE.md` (which imports this file with `@AGENTS.md`). Cursor, Codex, Aider, Copilot, and Windsurf read it directly.

## Workspace map

14 crates under `crates/`. Default members (built by `cargo build` with no `-p`): `solver-service`, `solver-demo`.

| Crate | Path | Purpose | Crate-specific `AGENTS.md`? |
|---|---|---|---|
| solver-account | `crates/solver-account` | Account abstractions, signers (local + AWS KMS) | No |
| solver-bridge | `crates/solver-bridge` | Cross-chain bridge orchestrator (LayerZero VaultBridge + Redis state) | No |
| solver-config | `crates/solver-config` | Config load/validation with optimistic locking | No |
| solver-core | `crates/solver-core` | Orchestration: discovery → order → delivery → settlement | **Yes** |
| solver-delivery | `crates/solver-delivery` | Transaction delivery abstraction across chains | No |
| solver-demo | `crates/solver-demo` | CLI for cross-chain intent testing (default-member binary) | **Yes** |
| solver-discovery | `crates/solver-discovery` | Intent discovery (on-chain events + off-chain APIs) | No |
| solver-e2e-tests | `crates/solver-e2e-tests` | End-to-end harness with real Anvil chains + Foundry | **Yes** |
| solver-order | `crates/solver-order` | Order validation, fill, transaction generation | No |
| solver-pricing | `crates/solver-pricing` | Pricing oracle trait + mock impls | No |
| solver-service | `crates/solver-service` | HTTP service (Axum); the `solver` binary (default-member) | **Yes** |
| solver-settlement | `crates/solver-settlement` | Settlement lifecycle orchestration | No |
| solver-storage | `crates/solver-storage` | Persistence abstractions (Redis + file backends) | No |
| solver-types | `crates/solver-types` | Shared types: orders, events, auth, admin | No |

## Walk the tree before editing

Before editing a file in `crates/<X>/`, read root `AGENTS.md` (this file) and, if present, `crates/<X>/AGENTS.md`. Crate-specific files override or refine the defaults stated here.

## Build / test / lint — canonical commands

Per-crate default (preferred in interactive sessions):

```
cargo test  -p <crate>
cargo check -p <crate>
```

After changes that affect cross-crate types or shared deps:

```
cargo check --all-targets --all-features
```

Format and lint (must match CI):

```
cargo fmt   --all -- --check                                                       # verify
cargo fmt                                                                          # apply
cargo clippy --all-features --all-targets -- -D warnings --allow deprecated        # lint
```

MSRV check (rare, but exact CI command):

```
cargo hack check --feature-powerset --locked --rust-version --all-targets
```

Avoid `cargo test --workspace` in interactive sessions — it's slow and floods context. Only on explicit request.

## Rebuild decision tree

- Edited only one crate? → `cargo build -p <crate>` + `cargo test -p <crate>`.
- Edited `solver-types` or a workspace dep used elsewhere? → `cargo check --all-targets --all-features`.
- Edited `solver-e2e-tests`? → See `crates/solver-e2e-tests/AGENTS.md` for the required setup.

## Capture-to-file rule

Never re-run the same test/clippy invocation just to slice output. Capture once, read from the file:

```
cargo test -p <crate> 2>&1 | tee /tmp/test.log
cargo clippy --all-features --all-targets 2>&1 | tee /tmp/clippy.log
```

## Required environment variables

- `REDIS_URL` — default `redis://localhost:6379`.
- `STORAGE_BACKEND` — `redis` (default) or `file` (used in e2e).
- `STORAGE_PATH` — used only when `STORAGE_BACKEND=file`. Default `./data/storage`.
- `OIF_CONTRACTS_PATH` — e2e only. Defaults to `../oif-contracts`.
- `RUST_LOG` — auto-defaulted in the e2e harness.

`.env` is gitignored; never commit one. Templates (`.env.example`, `crates/solver-demo/.env.example`, `config/example.env.docker`) are tracked and safe to read.

## Tool routing

- **LSP** for: `goToImplementation`, `findReferences`, `incomingCalls`, hover. Trait impls, cross-crate references, disambiguating identically named symbols.
- **ripgrep** / file-discovery for: strings, log messages, config keys, finding files by name.
- Read the file once to get `line:char` before issuing LSP position-based calls.

## Conventions worth knowing

- **Alloy ecosystem only.** No ethers-rs, no web3. Don't introduce a second EVM library.
- **`edition = "2021"`** in workspace `Cargo.toml`. **MSRV `1.88.0`** pinned in `rust-toolchain.toml`.
- Note: `rustfmt.toml` currently has `edition = "2024"`. This is a known internal inconsistency. Do not "fix" by bumping the workspace edition.
- rustfmt: 100-column max width, hard tabs (intentional).
- Workspace deps are pinned in root `[workspace.dependencies]`. Add new deps there, not per-crate.
- Toolchain components: `llvm-tools` + `rust-src` (used by `cargo llvm-cov` in CI).
- Schema/storage refactors: clean breaks with drain/migration, not coexistence layers.
- OIF contracts enforce on-chain idempotency (single fill/claim/settle). Failure mode is stranded funds, not double-execution; preserve that invariant in retry/replacement design.

## Verification before claiming done

- Run the actual command (`cargo test -p X`, `cargo clippy ...`, `curl`) and quote relevant output before reporting completion.
- For UI bugs: confirm the dev server rebuilt fresh artifacts before debugging behavior.
- For runtime / deploy work: an empirical probe (a real transaction, a live `/health` poll) beats a plausibility argument.
- Type-checking and tests verify code correctness, not feature correctness. If you can't test the feature, say so explicitly rather than claiming success.

## Before non-trivial or high-risk edits

State briefly:
1. exact file path and function you'll change,
2. call sites that exercise that path,
3. data shape the backend currently expects (when relevant).

Wait for confirmation only when the user explicitly asked for approval, or when the path/scope is uncertain. For routine work in a clearly correct location, proceed and report results. This catches the "wrong file / wrong code path" class of mistake without stalling on trivial edits.

## Default to minimal

- Minimal, focused implementations win. Push back on scope creep.
- For code or plan review: verify every factual claim against the codebase with grep/read before commenting. Reasoning alone isn't enough.
- Bug-fix PRs: write the failing test first (RED), then the fix (GREEN). Confirm the test fails for the right reason before writing the fix.

## Don't

- Don't edit `target/`, `dump.rdb`, `*.log`, `data/`, `.oif-demo/`, `.logs/`, `.pids/` (also denied at the permissions layer).
- Don't run `cargo test --workspace` unless explicitly asked.
- Don't add backwards-compat shims when a clean break + migration is feasible.
- Don't introduce a second EVM library alongside alloy.
- Don't confuse SHA3-256 with Keccak-256 when deriving Ethereum addresses.

## Where to find more

- `docs/config-storage.md`, `docs/fee-policy.md`, `docs/rebalance.md` — feature design docs.
- `docs/superpowers/specs/` and `docs/superpowers/plans/` — Claude-driven design specs and implementation plans.
- `api-spec/*.yaml` — OpenAPI surface.
- `.github/workflows/ci.yaml` and `.github/workflows/e2e.yaml` — canonical commands.
