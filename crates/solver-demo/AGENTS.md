# solver-demo — Agent Guide

A CLI tool for demonstrating and testing OIF solver cross-chain intent execution. Default-member binary (built by `cargo build` without `-p`). The `oif-demo` invocation in repo scripts points here.

## Footguns the README doesn't loudly flag

### Default chains are local Anvil

The `init new` template defaults to chain IDs `31337` and `31338` — local Anvil instances. Testnet flows need:
- Explicit chain IDs (e.g., Optimism Sepolia `11155420`, Base Sepolia `84532`).
- A running `solver-service` API reachable at the configured `SOLVER_URL`.

If `solver-service` is not running, `quote get` and `intent submit` fail with HTTP errors that look like network problems but aren't.

### Three distinct init modes — do not mix

- `init new` — fresh template config.
- `init load` — load from a config file.
- `init load-storage` — load from the storage backend (Redis or file) used by `solver-service`.

State left from one mode will confuse another. Pick one per session.

### Persistent state in `.oif-demo/`

Sessions, deployed contract addresses, JWT tokens, request/response logs accumulate in `.oif-demo/` at the repo root. There is no built-in reset command. To start clean:

```
rm -rf .oif-demo/
```

`.oif-demo/` is gitignored.

### Permit2 approvals differ between local and testnet

- **Local mode:** `env setup` auto-approves Permit2.
- **Testnet:** you must manually run `token approve` before escrow settlement will work. Skipping this causes silent failures during intent submission.

## Required environment

See `crates/solver-demo/.env.example` for the full set. Common ones:

- `SOLVER_URL` — base URL of the running `solver-service`.
- Per-chain RPC URLs and private keys (for testnet flows).

## Local-mode quick start

```
./oif-demo init new
./oif-demo env setup
./oif-demo quote test compact permit2 A2B
```

## See also

`crates/solver-demo/README.md` for the full command reference.
