# solver-e2e-tests

Live end-to-end tests for the OIF solver. Each test:

1. Spawns two real Anvil chains (31337 origin, 31338 destination).
2. Deploys real contracts (`MockERC20` × 2 + `AlwaysYesOracle` +
   `InputSettlerEscrow` + `OutputSettlerSimple`) on each chain via the
   compiled artifacts in `oif-contracts/out/`.
3. Spawns the real `solver` binary (built from `crates/solver-service`) as a
   subprocess against the freshly-deployed addresses.
4. As the user, calls `open(StandardOrder)` directly on the input settler.
5. Polls on-chain logs and asserts the orderId from the user's `Open` event
   matches the orderId in the solver's `OutputFilled` event on the destination
   chain and the `Finalised` event on the origin chain.

No mocks. No HTTP API in the loop. The flow under test is the actual
on-chain path operators run.

## Prerequisites

- **Foundry** (provides `anvil` and the `forge` toolchain).
  `curl -L https://foundry.paradigm.xyz | bash && foundryup`
- **`oif-contracts` checkout, built**. See
  https://github.com/openintentsframework/oif-contracts. By default the
  harness expects it as a sibling directory of `oif-solver`:
  ```bash
  cd /path/to/parent
  git clone https://github.com/openintentsframework/oif-contracts.git
  cd oif-contracts && forge build
  ```
  Override the location with `OIF_CONTRACTS_PATH=/abs/path/to/oif-contracts`.
- **`lsof`** (POSIX). Used by the harness to nuke orphan listeners on the
  fixed test ports. Default on macOS / most Linux distros.

## Running

```bash
cargo test -p solver-e2e-tests -- --ignored --test-threads=1 --nocapture
```

- `--ignored` is required; tests are `#[ignore]` by default so a plain
  `cargo test` doesn't try to spawn Anvil on every dev machine.
- `--test-threads=1` is required; tests share fixed Anvil ports
  (8545 / 8546) and the solver API port (3000).
- `--nocapture` is recommended; the harness prints orderIds, deployed
  addresses, and event observations as the flow progresses.

For more solver-side detail:
```bash
RUST_LOG=info,solver=debug,solver_core=debug \
  cargo test -p solver-e2e-tests -- --ignored --test-threads=1 --nocapture
```

## What's in the test today

| File | Path tested | Auth | Settlement | Status |
|---|---|---|---|---|
| `tests/happy_e2e_open_fill_settle.rs` | on-chain `open()` | none (ERC20 approve) | Direct + AlwaysYesOracle | happy path |

## Planned additions

- Off-chain `openFor()` with Permit2.
- Off-chain `openFor()` with EIP-3009.
- Failure paths: insufficient solver balance on destination, expired order,
  fill that reverts, settlement timeout, slippage breach.

## Design decisions

### 1. New crate, excluded from `default-members`

A new crate keeps test-only deps (`tempfile`, `alloy-*`) out of every other
crate's compile graph and gives us a `src/lib.rs` to share a `Harness`
across many test files.

### 2. Drop `solver-demo` as a dependency

Earlier iterations of this harness used `solver-demo` as a library to
orchestrate Anvils, deploy contracts, and bootstrap config. Reasons we
moved away from it:

- `solver-demo`'s `EnvOps::deploy` unconditionally deploys Permit2 + The
  Compact + an allocator + the EIP-3009 mock + the on-chain settlers. Most
  of that is wasted for the no-signatures `open()` flow we're testing.
- `solver-demo`'s deploy reads the canonical Permit2 bytecode from a hex
  file the README documents as a manual one-time fetch — adding a soft
  network dependency to the test suite.
- `solver-demo`'s deploy and config ops mutate JSON files in place, which
  conflicts with how the test wants to render configs (typed Rust →
  serialized JSON, no in-place edits).

The test crate now does its own minimal deploy via direct alloy
`send_transaction(Create)` calls, reading bytecode straight from the
Foundry artifacts in `oif-contracts/out/`.

### 3. Subprocess `solver`, not in-process

`solver-service` is a library too (since #306) and the `SolverEngine` can
be embedded in the test process. We chose subprocess anyway because:

- It tests what operators actually run, including arg parsing, storage
  bootstrap, and `tracing` subscriber setup.
- Process kill on test failure is cleaner than untangling async Tokio
  handles inside a panicking test.
- The cost (~30s `cargo build` on first run, instant thereafter) is
  acceptable.

In-process remains a plausible follow-up if test latency becomes a problem.

### 4. Build the bootstrap config programmatically

`solver --bootstrap-config <path>` parses JSON as `solver_types::SeedOverrides`,
which is **a different shape** than the runtime `Config` (e.g. `networks`
is `Vec<NetworkOverride>`, not a `HashMap`). Hand-writing JSON in the
runtime shape is what was breaking earlier runs with a serde error.

The harness now builds a typed `SeedOverrides` from the deployed addresses
and `serde_json::to_string`s it. This eliminates an entire class of
schema-drift bugs.

### 5. Reuse `solver-types`, not `solver-discovery` for event ABIs

The `sol! { event Open(...) }` declaration in `solver-discovery` is
private to the impl module, so the test can't `use` it. Rather than
re-export it from a different solver crate (which would change the
solver crates), the harness redeclares the events it needs (~30 lines).
Source of truth for the ABI is `oif-contracts`, not the solver.

### 6. Direct alloy for deploys + tx submission + log polling

`solver-delivery::AlloyDelivery` wraps an alloy provider with retry +
nonce management for solver-side use. For test driver use (deploys,
user-side `open()`, balance reads, log polling) raw alloy is simpler and
doesn't pull in `AccountSigner` machinery.

### 7. Fixed Anvil dev accounts

The solver private key in `solver_config`'s `local` account default is
the canonical Anvil-account-0 (`0xac09...`). The harness uses Anvil dev
accounts deterministically:

| Role | Anvil index | Address |
|---|---|---|
| solver | 0 | `0xf39F...92266` |
| user | 1 | `0x7099...79C8` |
| recipient | 2 | `0x3C44...93BC` |

This means the solver's signer matches its preconfigured private key
without any extra wiring.

### 8. AlwaysYesOracle for both input + output

`AlwaysYesOracle.isProven(...)` always returns `true`. Using it as both
the input and output oracle short-circuits the cross-chain proof step
entirely — the direct settlement path on the input side accepts the
fill the moment the dispute period elapses (configured to 1s).

This keeps the test focused on the solver's discovery → fill → claim
flow without dragging in oracle-bridge complexity. Real-oracle flows
(Hyperlane, Polymer, Wormhole) deserve their own tests.

### 9. Balance assertions + event-matching assertions, not status assertions

The test asserts on:

- The orderId emitted by the user's `Open` event.
- That same orderId appearing in `OutputFilled` on the destination chain.
- That same orderId appearing in `Finalised` on the origin chain.
- Token balance deltas on both chains.

This is stronger than checking solver-internal storage because:

- It tests what the system actually delivers (money moved + on-chain proofs).
- It doesn't break when solver-internal state machines change.
- It does verify the *specific order* you submitted is the one that was
  filled — balance-only assertions can't tell.

### 10. Sequential tests, fixed ports, aggressive cleanup

Sequential because the harness uses fixed Anvil + solver API ports.
`Harness::boot()` and `Drop` both kill anything listening on those ports
via `lsof -t -i:PORT -sTCP:LISTEN | xargs kill -9`. Without this, a
crashed previous run leaves orphan processes and the next `boot` either
fails to bind or silently reuses stale state.

### 11. Per-test tempdir for solver storage

Each test gets a fresh `TempDir`. `STORAGE_BACKEND=file` and
`STORAGE_PATH=<tempdir>/data/storage` ensure no state crosses tests.
Default solver-service storage is Redis; we override.

### 12. `#[ignore]` by default

Default `cargo test` shouldn't fail on dev machines that lack Foundry.
The opt-in invocation is one flag (`--ignored`) and is documented above.

## Adding a new test

1. New file under `tests/`. Each test file is its own binary, giving
   process isolation between cases.
2. `Harness::boot().await?` does the entire setup. Use the public
   methods (`user_approve`, `user_open`, `await_event`, `balance`).
3. Mark with `#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]`.
4. Prefer event-matching assertions. Use balance assertions as a sanity
   bound — they catch wrong-amount bugs the orderId match doesn't.

## Known limitations

- Anvil + `oif-contracts/out` must be present locally. There's no embedded
  fallback.
- POSIX-only port cleanup (`lsof`). Windows isn't currently supported.
- First run compiles the `solver` binary. ~30s on a warm machine.
- No parallelism across tests.
