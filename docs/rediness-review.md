# Solver Readiness Review (L2/L3 Onboarding)

Date: February 19, 2026

Input reviewed:
- `/Users/nahimdhaney/Downloads/Private & Shared 32/OIF Solver Request 2fccbd12786080478bd2fab1aad95432.csv`
- Current code paths for seed merge, runtime build, settlement/oracle validation, and API routes

## Executive Status

`NOT READY` to spin up from the CSV alone.

The current request has enough metadata to start onboarding, but not enough to boot a solver yet.

Critical blockers:
1. Chain `1234` is not in current seed presets, so boot will fail (`UnknownChainId`).
2. Token lists are missing in the request, and boot currently rejects empty token arrays (`NoTokens`).
3. Required on-chain contract addresses for a new network are missing.
4. Only one network is present in the CSV, but boot requires at least 2 networks.

## What The Solver Requires On First Boot

When using `--seed <mainnet|testnet> --seed-overrides <json>`, first boot requires:

1. At least 2 unique networks in `networks[]`.
2. Every `networks[].chain_id` must exist in the selected seed preset.
3. Every `networks[].tokens` must be non-empty.
4. Optional: `rpc_urls`, `admin`, `auth_enabled`, fee overrides.

Operationally, first boot is:
- Seeds (hardcoded) + initializer JSON -> `OperatorConfig` in Redis
- Runtime config is built from `OperatorConfig` on all following boots

## CSV vs Required Data (Gap Analysis)

From your CSV row:
- `Chain Name`: `Test L2`
- `Chain ID`: `1234`
- `RPC URL`: `https://qweasd.com`
- `Block Explorer URL`: `https://qwec.com`
- `Rollup Stack`: `op`
- `Parent Network`: `base`
- `Hub Chain`: `arbitrum`
- `Wallet Address`: `0x3333333351e46fe70247B7082Ae505c85daBeC7c`

| Area | Status | Notes |
|---|---|---|
| Network identity (name/id) | Present | Good start (`Test L2`, `1234`) |
| Parent/hub intent | Present | `base` and `arbitrum` are useful for route planning |
| RPC endpoint | Partial | Single URL only; production should use redundancy |
| Token config per network | Missing | Required today; cannot boot with empty token arrays |
| Minimum network set | Missing | Need 2+ networks in initializer |
| Seed support for new chain | Missing | `1234` not in current `mainnet`/`testnet` seeds |
| New chain contract addresses | Missing | Required in seed for new L2/L3 |
| Oracle + mailbox + IGP addresses | Missing | Required for Hyperlane settlement |
| Admin/auth config | Optional | Needed only if you want protected admin/auth flows |

## Manual Deployment Scope For A New L2/L3

For each new chain added to seed, you must have addresses for:

1. `input_settler`
2. `output_settler`
3. `input_settler_compact`
4. `the_compact`
5. `allocator`
6. `hyperlane_mailbox`
7. `hyperlane_igp`
8. `hyperlane_oracle`

Without these, chain onboarding cannot be completed in current architecture.

## Oracle And Routes: What Is Actually True In This Repo

Important correction:
- `config/demo.toml` shows `settlement.implementations.direct.routes`, but seeded boot path generates and uses `settlement.implementations.hyperlane`.

Current seeded behavior:
1. Input/output oracle arrays are auto-populated from each selected chain's `hyperlane_oracle` in seed.
2. Routes are auto-generated as full mesh across selected chains (`chain -> all other selected chains`).
3. Runtime stores these values in `OperatorConfig.settlement.hyperlane.{oracles,routes}`.

Validation rules enforced by settlement config parsing:
1. `oracles.input` required and each chain list must be non-empty.
2. `oracles.output` required and each chain list must be non-empty.
3. `routes` required and each source route must have at least one destination.
4. Every route source must exist in input oracles.
5. Every route destination must exist in output oracles.

Example target route intent for your case (if onboarding `1234` with Base + Arbitrum):

```toml
[routes]
1234 = [8453, 42161]
8453 = [1234]
42161 = [1234]
```

Note: if you keep auto-generated full mesh, Base<->Arbitrum will also be enabled whenever both are selected.

## Can You Start Solver With No Assets Defined?

Not with current code.

`merge_config` and `merge_to_operator_config` currently return `NoTokens(chain_id)` when `tokens` is empty for any network.

## How To Check What You Need To Deploy (Practical Runbook)

1. Confirm seed support for requested chain IDs.

```bash
rg "chain_id:" crates/solver-service/src/seeds/mainnet.rs crates/solver-service/src/seeds/testnet.rs
```

2. If new chain is absent, add a new `NetworkSeed` entry with all required addresses.

3. Build initializer JSON and verify structural readiness before boot.

```bash
jq -e '
  (.networks | length) >= 2 and
  (all(.networks[]; (.tokens | length) > 0))
' config/seed-overrides-<env>.json
```

4. Boot once with seed + overrides.

```bash
cargo run -- --seed mainnet --seed-overrides config/seed-overrides-<env>.json
```

5. Verify runtime config and token visibility.
- `GET /health`
- `GET /api/v1/tokens`
- `GET /api/v1/admin/config` (if admin enabled)

6. If onboarding with initially small token set, add more later using admin token endpoints.

## Minimal Onboarding JSON Shape (Template)

```json
{
  "solver_name": "OIF <network> Solver",
  "networks": [
    {
      "chain_id": 1234,
      "name": "test-l2",
      "type": "new",
      "rpc_urls": ["https://your-l2-rpc"],
      "tokens": [
        {
          "symbol": "USDC",
          "name": "USD Coin",
          "address": "0x...",
          "decimals": 6
        }
      ]
    },
    {
      "chain_id": 8453,
      "name": "base",
      "type": "parent",
      "tokens": [
        {
          "symbol": "USDC",
          "name": "USD Coin",
          "address": "0x...",
          "decimals": 6
        }
      ]
    },
    {
      "chain_id": 42161,
      "name": "arbitrum",
      "type": "hub",
      "tokens": [
        {
          "symbol": "USDC",
          "name": "USD Coin",
          "address": "0x...",
          "decimals": 6
        }
      ]
    }
  ],
  "auth_enabled": false
}
```

## Final Recommendation

Proceed in this order:
1. Decide target environment (`mainnet` vs `testnet`) and supported chain set.
2. Add/prepare new chain seed entry for `1234` with all required deployed contract addresses.
3. Define at least one token per network for first boot.
4. Run first seed boot and verify API/runtime config.
5. Then expand tokens/routes/oracles through operator config/admin flow as needed.
