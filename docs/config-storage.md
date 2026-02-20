# Config Storage with Redis

This document describes how to use the Redis-based configuration storage system for the OIF Solver.

## Overview

The solver uses Redis as the single source of truth for runtime configuration. Configuration is:
- **Seeded once** when deploying a new solver
- **Loaded from Redis** on subsequent startups
- **Versioned** with optimistic locking for safe updates

## Quick Start

### Prerequisites

- Redis running (default: `localhost:6379`)
- Environment variables set:

```bash
export REDIS_URL=redis://localhost:6379
export SOLVER_PRIVATE_KEY=your_64_hex_character_private_key
```

### First Run: Seed Configuration

```bash
# Seedless configuration (all values from JSON)
cargo run -- --bootstrap-config config/example.json

# Seed testnet configuration (preset fallback for known chains)
cargo run -- --seed testnet --bootstrap-config config/seed-overrides-testnet.json

# Seed mainnet configuration (preset fallback for known chains)
cargo run -- --seed mainnet --bootstrap-config config/seed-overrides-mainnet.json

# Seed using a non-seeded networks JSON example
cargo run -- --seed testnet --bootstrap-config config/non-seeded-networks-example.json

# Or pass JSON directly (useful for deployment services)
cargo run -- --seed testnet --bootstrap-config '{"solver_id":"my-solver","networks":[{"chain_id":11155420,"tokens":[{"symbol":"USDC","address":"0x191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6","decimals":6}]},{"chain_id":84532,"tokens":[{"symbol":"USDC","address":"0x73c83DAcc74bB8a704717AC09703b959E74b9705","decimals":6}]}]}'
```

### Subsequent Runs: Load from Redis

```bash
# Configuration is automatically loaded from Redis
cargo run --
```

## CLI Flags

| Flag | Description |
|------|-------------|
| `--seed <preset>` | Seed configuration using a preset (`testnet` or `mainnet`) |
| `--bootstrap-config <value>` | Bootstrap config as JSON file path OR raw JSON string |
| `--seed-overrides <value>` | Deprecated alias for `--bootstrap-config` |
| `--force-seed` | Overwrite existing configuration in Redis |

## Bootstrap Config Format

Bootstrap config specifies which networks your solver will support. Networks can be:
- Preset-backed (`mainnet` / `testnet` seed)
- Non-seeded (new chain IDs) when required fields are provided

```json
{
  "solver_id": "my-solver-instance",
  "networks": [
    {
      "chain_id": 11155420,
      "tokens": [
        {
          "symbol": "USDC",
          "address": "0x191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6",
          "decimals": 6
        }
      ]
    },
    {
      "chain_id": 84532,
      "tokens": [
        {
          "symbol": "USDC",
          "address": "0x73c83DAcc74bB8a704717AC09703b959E74b9705",
          "decimals": 6
        }
      ],
      "rpc_urls": ["https://my-custom-rpc.com"]
    }
  ]
}
```

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `solver_id` | No | Unique solver identifier. If provided, enables idempotent seeding. If omitted, a UUID is generated. |
| `networks` | Yes | Array of networks to support |
| `networks[].chain_id` | Yes | Chain ID (seeded or non-seeded) |
| `networks[].tokens` | Yes | Tokens for this network (can be empty at boot) |
| `networks[].tokens[].symbol` | Yes | Token symbol (e.g., "USDC") |
| `networks[].tokens[].address` | Yes | Token contract address |
| `networks[].tokens[].decimals` | Yes | Token decimals |
| `networks[].rpc_urls` | No | Custom RPC URLs (falls back to seed defaults) |
| `settlement.type` | No | `"hyperlane"` (default) or `"direct"` |
| `settlement.hyperlane` | Conditional | Required for non-seeded chains when `settlement.type = "hyperlane"` |
| `settlement.direct` | Conditional | Required when `settlement.type = "direct"` |

### Required Fields For Non-Seeded Networks

For each non-seeded network, provide:
- `name`
- `type`
- `input_settler_address`
- `output_settler_address`
- `rpc_urls` (at least one URL)

Optional per-network fields:
- `input_settler_compact_address`
- `the_compact_address`
- `allocator_address`

### Settlement Examples

`hyperlane` is the default settlement type when `settlement` is omitted.

See `config/non-seeded-networks-example.json` for a full non-seeded Hyperlane example (both chain IDs are non-seeded).

Example `direct` settlement:

```json
{
  "networks": [
    { "chain_id": 11155420, "tokens": [] },
    { "chain_id": 84532, "tokens": [] }
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

**Note:** Providing a `solver_id` makes seeding idempotent - running bootstrap again with the same config will detect existing configuration and skip seeding (unless `--force-seed` is used).

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `REDIS_URL` | Yes | `redis://localhost:6379` | Redis connection URL |
| `SOLVER_PRIVATE_KEY` | Yes | - | 64-character hex private key (without 0x prefix) |
| `SOLVER_ID` | For loading | - | Solver ID to load from Redis (required when not seeding) |

**Note:** After seeding, the solver outputs the `SOLVER_ID` to use for subsequent runs. Set this environment variable before running without `--bootstrap-config`.

## Supported Networks

### Testnet Preset

| Chain | Chain ID | Name |
|-------|----------|------|
| Optimism Sepolia | 11155420 | optimism-sepolia |
| Base Sepolia | 84532 | base-sepolia |

### Mainnet Preset

| Chain | Chain ID | Name |
|-------|----------|------|
| Optimism | 10 | optimism |
| Base | 8453 | base |
| Arbitrum | 42161 | arbitrum |

You can also seed non-seeded chain IDs with the required non-seeded network fields and settlement config.

## How It Works

### 1. Seeding

When you run with bootstrap flags, the solver:

1. Optionally loads the seed preset (testnet/mainnet) when `--seed` is provided
2. Merges your bootstrap config with defaults
   - seeded chains can reuse seed values
   - non-seeded chains must provide required network bundle and settlement data
3. Generates a unique `solver_id` (e.g., `solver-abc123-...`)
4. Stores the complete configuration in Redis

```
┌─────────────────────┐     ┌─────────────────────┐     ┌─────────────────┐
│  Optional Seeds     │     │  Bootstrap Config   │     │  Final Config   │
│  (testnet/mainnet)  │  +  │  (your JSON file)   │  =  │  (in Redis)     │
│                     │     │                     │     │                 │
│  - Contract addrs   │     │  - Chain IDs        │     │  Complete       │
│  - Oracle addrs     │     │  - Tokens           │     │  solver         │
│  - Default RPCs     │     │  - RPC URLs (opt)   │     │  configuration  │
│  - Gas settings     │     │                     │     │                 │
└─────────────────────┘     └─────────────────────┘     └─────────────────┘
```

### 2. Loading

On subsequent runs (without bootstrap flags), the solver:

1. Reads the `SOLVER_ID` from environment or uses the last seeded ID
2. Loads the full configuration from Redis
3. Starts the solver with the loaded configuration

### 3. Versioning

Configuration in Redis includes version tracking:

```json
{
  "data": { /* full config */ },
  "version": 1,
  "updated_at": 1705849200
}
```

Updates use optimistic locking - if another process modified the config, your update will fail with a version mismatch error.

## Redis Key Structure

```
{prefix}:config:{solver_id}  →  Versioned<Config>
```

Default prefix: `oif-solver`

Example: `oif-solver:config:solver-abc123-def456-...`

## Troubleshooting

### "Configuration not found for solver"

The solver ID in your environment doesn't have configuration in Redis. Either:
- Run with `--bootstrap-config` to create new configuration
- Check `SOLVER_ID` environment variable matches an existing solver

### "Configuration already exists"

You're trying to seed when configuration already exists. Use `--force-seed` to overwrite:

```bash
cargo run -- --seed testnet --bootstrap-config config/seed-overrides-testnet.json --force-seed
```

### "Private key must be 64 hex characters"

Ensure your private key:
- Is exactly 64 hex characters (32 bytes)
- Does NOT include the `0x` prefix
- Is exported in your shell: `export SOLVER_PRIVATE_KEY=...`

### "Redis connection timeout"

Check that Redis is running and accessible:

```bash
redis-cli ping
# Should return: PONG
```

## API Endpoints

When running, the solver exposes these API endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/tokens` | GET | List supported tokens |
| `/api/v1/quotes` | POST | Request a quote |
| `/api/v1/orders` | POST | Submit an order |
| `/api/v1/orders/{id}` | GET | Get order status |

The API server runs on `127.0.0.1:3000` by default.

## Integration Tests

Run the integration tests (requires Redis running locally):

```bash
cargo test --package solver-storage config_store_integration -- --ignored
```

## Example: Full Setup

```bash
# 1. Start Redis
redis-server

# 2. Set environment variables
export REDIS_URL=redis://localhost:6379
export SOLVER_PRIVATE_KEY=your_private_key_here

# 3. Create bootstrap config
cat > config/my-overrides.json << 'EOF'
{
  "networks": [
    {
      "chain_id": 11155420,
      "tokens": [
        {"symbol": "USDC", "address": "0x191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6", "decimals": 6}
      ]
    },
    {
      "chain_id": 84532,
      "tokens": [
        {"symbol": "USDC", "address": "0x73c83DAcc74bB8a704717AC09703b959E74b9705", "decimals": 6}
      ]
    }
  ]
}
EOF

# 4. Seed configuration
cargo run -- --seed testnet --bootstrap-config config/my-overrides.json

# 5. Subsequent runs just load from Redis
cargo run --
```
