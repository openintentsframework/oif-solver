# solver-e2e-tests — Agent Guide

End-to-end harness for the OIF solver. Spawns two real Anvil chains, deploys test contracts via Foundry, runs the solver as a subprocess, and validates on-chain events. **Cannot be run with plain `cargo test`.**

## Required setup

- **Foundry** installed (`foundryup`).
- **Sibling `oif-contracts/` checkout** at `../oif-contracts/` relative to this repo, OR `OIF_CONTRACTS_PATH` env var pointing at one.
- **Anvil** reachable on ports `8545` and `8546`. The harness binds these directly.
- **Redis** reachable at `REDIS_URL` (default `redis://localhost:6379`) — unless `STORAGE_BACKEND=file` is set.
- **Port 3000** free (admin API).

The harness will `lsof`-kill orphan listeners on `3000`, `8545`, `8546` between runs. That is expected, not a bug.

## Canonical invocation

```
cargo test -p solver-e2e-tests -- --ignored --test-threads=1 --nocapture
```

`--ignored` is required: tests are annotated `#[ignore]` so plain `cargo test` skips them. `--test-threads=1` is required because the harness binds fixed ports. `--nocapture` is recommended to surface harness logs.

## CI

CI entry point: `scripts/e2e/solver_all.sh`. Workflow: `.github/workflows/e2e.yaml`.

## See also

`crates/solver-e2e-tests/README.md` has the full setup walkthrough including admin-API authentication and Redis seeding. This file is the short version.
