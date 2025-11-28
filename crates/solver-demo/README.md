# OIF Solver Demo

The `solver-demo` crate is a command-line interface (CLI) tool for demonstrating and testing the Open Intent Framework (OIF) Solver's cross-chain intent execution capabilities. It provides a complete development and testing environment for cross-chain swaps, supporting both local (Anvil-based) and production (testnet/mainnet) deployments with multiple settlement mechanisms and authentication schemes.

## Table of Contents

- [Technical Architecture](#technical-architecture)
- [Quick Start](#quick-start)
- [Usage Workflows](#usage-workflows)
  - [Local Development](#local-development-workflow)
  - [Testnet](#testnet-workflow)
  - [Batch Processing](#batch-processing)
- [Configuration](#configuration)
- [Commands Reference](#commands-reference)
- [Settlement Types](#settlement-types)
- [Troubleshooting](#troubleshooting)
- [Advanced Features](#advanced-features)

## Technical Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                          solver-demo CLI                               │
├────────────────────────────────────────────────────────────────────────┤
│    ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐      │
│    │   CLI      │  │   Core     │  │Operations  │  │   Types    │      │
│    │  Commands  │  │Components  │  │  Modules   │  │  & Models  │      │
│    └────────────┘  └────────────┘  └────────────┘  └────────────┘      │
│        │               │               │                │              │
│        └───────────────┴───────────────┴────────────────┘              │
│                                 │                                      │
│                          ┌──────▼──────┐                               │
│                          │   Context    │                              │
│                          │  (Central    │                              │
│                          │   State)     │                              │
│                          └──────────────┘                              │
│                                 │                                      │
│         ┌───────────────────────┼───────────────────────┐              │
│         ▼                       ▼                       ▼              │
│     ┌──────────┐          ┌──────────┐          ┌──────────┐           │
│     │ Storage  │          │ Session  │          │   API    │           │
│     │  Layer   │          │  Store   │          │  Client  │           │
│     └──────────┘          └──────────┘          └──────────┘           │
└────────────────────────────────────────────────────────────────────────┘
```

## Core Components

### Context - Central State Manager

- Configuration management
- Storage layer
- Session persistence
- Token registry
- Contract addresses
- Signing service
- JWT authentication

### Operations Layer
- **Environment Ops**: Anvil management, contract deployment
- **Intent Ops**: Intent building and submission
- **Quote Ops**: Quote retrieval and signing
- **Token Ops**: Balance checking, minting, approvals

### Core Services
- **Storage**: File-based JSON persistence
- **Session**: State management across runs
- **Provider**: Blockchain RPC interaction
- **API Client**: RESTful solver API communication
- **JWT Service**: Authentication token management

## Quick Start

```bash
# Create alias for convenience
alias oif-demo='cargo run --bin solver-demo --'
```

> **Note**: All session data, configuration, and request/response files are stored in the `.oif-demo` directory
> in your current working directory. This includes:
> - Session state and JWT tokens
> - Deployed contract addresses
> - Generated quote requests (`requests/get_quote.req.json`)
> - Quote responses (`requests/get_quote.res.json`)
> - Signed orders (`requests/post_order.req.json`)

## Usage Workflows

### Local Development Workflow

#### 1. Initialize Environment
```bash
# Create and load configuration
oif-demo init new config/demo.toml --force
oif-demo init load config/demo.toml --local

# Start local chains
oif-demo env start

# Deploy contracts
oif-demo env deploy --all --force

# Setup test environment (mint tokens, approve allowances)
oif-demo env setup
```

#### 2. Verify Setup
```bash
# Check accounts
oif-demo account list

# List tokens
oif-demo token list

# Check balances
oif-demo token balance
```

#### 3. Build and Execute Intent

**Compact Settlement:**
```bash
# Build intent
oif-demo intent build \
  --from-chain 31337 \
  --to-chain 31338 \
  --from-token TOKA \
  --to-token TOKB \
  --amount 1 \
  --settlement compact

# Get and sign quote
oif-demo quote get ./.oif-demo/requests/get_quote.req.json
oif-demo quote sign ./.oif-demo/requests/get_quote.res.json

# Submit intent
oif-demo intent submit ./.oif-demo/requests/post_order.req.json
```

**Permit2 Settlement:**
```bash
oif-demo intent build \
  --from-chain 31337 \
  --to-chain 31338 \
  --from-token TOKA \
  --to-token TOKB \
  --amount 1 \
  --settlement escrow \
  --auth permit2
```

**EIP-3009 Settlement:**
```bash
oif-demo intent build \
  --from-chain 31337 \
  --to-chain 31338 \
  --from-token TOKA \
  --to-token TOKB \
  --amount 1 \
  --settlement escrow \
  --auth eip3009
```

### Testnet Workflow

> **Note**: In production/testnet environments, you must manually approve tokens for Permit2.
> Use `oif-demo token approve` to grant Permit2 permission to spend your tokens.
> This is done automatically in local mode via `env setup`.

#### 1. Setup Environment
```bash
# Load testnet configuration
oif-demo init load config/testnet.toml

# List tokens and accounts
oif-demo token list
oif-demo account list

# Mint tokens for testing (Optimism Sepolia - Chain 11155420)
oif-demo token mint --chain 11155420 --token USDC --amount 100 --to user
oif-demo token mint --chain 11155420 --token USDC --amount 100 --to solver

# Mint tokens for testing (Base Sepolia - Chain 84532)
oif-demo token mint --chain 84532 --token USDC --amount 100 --to user
oif-demo token mint --chain 84532 --token USDC --amount 100 --to solver

# Check accounts and balances
oif-demo token balance

# Approve tokens for Permit2 (required for escrow settlement)
oif-demo token approve \
  --chain 11155420 \
  --token USDC \
  --spender 0x000000000022D473030F116dDEE9F6B43aC78BA3 \
  --amount 1000000
```

#### 2. Build Intent
```bash
# Exact output swap
oif-demo intent build \
  --to-chain 84532 \
  --from-chain 11155420 \
  --from-token USDC \
  --to-token USDC \
  --swap-type exact-output \
  --amount 1 \
  --settlement compact
```

#### 3. Get Quote and Submit
```bash
# Get quote
oif-demo quote get ./.oif-demo/requests/get_quote.req.json

# Sign quote
oif-demo quote sign ./.oif-demo/requests/get_quote.res.json

# Submit order
oif-demo intent submit ./.oif-demo/requests/post_order.req.json
```

### Batch Processing

#### 1. Create Batch File (`batch_intents.json`)
```json
{
  "intents": [
    {
      "description": "USDC to USDC exact-input swap",
      "enabled": true,
      "origin_chain_id": 11155420,
      "dest_chain_id": 84532,
      "origin_token": {
        "address": "0x191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6",
        "symbol": "USDC",
        "decimals": 6
      },
      "dest_token": {
        "address": "0x73c83DAcc74bB8a704717AC09703b959E74b9705",
        "symbol": "USDC",
        "decimals": 6
      },
      "amounts": {
        "input": "1"
      },
      "settlement": "escrow",
      "auth": "permit2"
    }
  ]
}
```

#### 2. Process Batch
```bash
# Build all intents
oif-demo intent build-batch ./.oif-demo/requests/batch_intents.json

# Get and sign all quotes
oif-demo quote test ./.oif-demo/requests/get_quotes.req.json

# Submit all orders
oif-demo intent test ./.oif-demo/requests/post_orders.req.json
```

## Configuration

### Environment Variables (`.env`)
```bash
# User Account (creates intents)
export USER_ADDRESS=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
export USER_PRIVATE_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d

# Solver Account (executes settlements)
export SOLVER_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
export SOLVER_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

# Recipient Account (receives tokens)
export RECIPIENT_ADDRESS=0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC

# API Configuration
export JWT_SECRET=MySuperDuperSecureSecret123!
```

## Commands Reference

### Init Commands
```bash
# Create new configuration
oif-demo init new <path> [--force] [--chains <chain_ids>]

# Load configuration
oif-demo init load <path> [--local]
```

### Environment Commands
```bash
# Start local environment
oif-demo env start

# Stop environment
oif-demo env stop

# Check status
oif-demo env status

# Deploy contracts
oif-demo env deploy [--all] [--contract <name>] [--force] [--list] [--path <path>] [--chain <id>]

# Setup test environment
oif-demo env setup [--chain <id>] [--amount <tokens>]
```

### Token Commands
```bash
# List tokens
oif-demo token list [--chains <ids>]

# Check balance
oif-demo token balance [--account <name>] [--follow <seconds>]

# Mint tokens (local only)
oif-demo token mint --chain <id> --token <symbol> --amount <amount> [--to <address>]

# Approve tokens
oif-demo token approve --chain <id> --token <symbol> --spender <address> --amount <amount>
```

### Intent Commands
```bash
# Build single intent
oif-demo intent build \
  --from-chain <id> --to-chain <id> \
  --from-token <symbol> --to-token <symbol> \
  --amount <amount> \
  --settlement <compact|escrow> \
  [--auth <permit2|eip3009>] \
  [--swap-type <exact-input|exact-output>] \
  [--callback-data <hex>] \
  [--callback-recipient <address>] \
  [--output <path>]

# Build batch intents
oif-demo intent build-batch <input.json> [--output <path>]

# Submit intent
oif-demo intent submit <order.json> [--onchain] [--chain <id>]

# Check status
oif-demo intent status <order-id>

# Test batch submission
oif-demo intent test <orders.json>
```

### Quote Commands
```bash
# Get quote
oif-demo quote get <request.json> [--output <path>]

# Sign quote
oif-demo quote sign <response.json> [--quote-index <n>] [--signature <sig>] [--output <path>]

# Test batch quotes
oif-demo quote test <requests.json>
```

## Settlement Types

### Compact Settlement
- Uses TheCompact protocol for resource locks
- No separate auth required
- Most gas-efficient

### Escrow Settlement
Requires authentication method:
- **Permit2**: Gasless approval via Uniswap's Permit2
- **EIP-3009**: Transfer with authorization

## Troubleshooting

### Common Issues

#### Anvil Not Starting
```bash
# Check if port is already in use
lsof -i :8545

# Kill existing Anvil processes
pkill anvil
```

#### Contract Deployment Fails
```bash
# Ensure chains are running
oif-demo env status

# Force redeploy
oif-demo env deploy --all --force
```

#### Quote Retrieval Fails
```bash
# Check solver API is running
curl http://localhost:3000/health

# Verify JWT token
oif-demo config
```

#### Balance Not Updating
```bash
# Use follow mode to monitor
oif-demo token balance --follow 5

# Check specific account
oif-demo token balance --account user
```

#### Intent Build Fails - "Insufficient Allowance" or "No Balance"
```bash
# For LOCAL environments - Did you forget to run env setup?
# This command mints tokens and approves Permit2
oif-demo env setup

# Verify tokens were minted
oif-demo token balance

# For TESTNET environments - Manually approve Permit2
oif-demo token approve \
  --chain <chain-id> \
  --token <token-symbol> \
  --spender 0x000000000022D473030F116dDEE9F6B43aC78BA3 \
  --amount <amount>
```

## Advanced Features

### Callback Data (Settlement Callbacks)

The solver supports callback data for intents, allowing you to trigger contract calls on the destination chain when the intent is filled. This is useful for integrating with protocols that need to be notified of the settlement.

#### Building Intents with Callback Data

```bash
# Build intent with callback data
oif-demo intent build \
  --from-chain 31337 \
  --to-chain 31338 \
  --from-token TOKA \
  --to-token TOKB \
  --amount 1 \
  --settlement compact \
  --callback-data 0xdeadbeef \
  --callback-recipient 0xYourContractAddress
```

**Parameters:**
- `--callback-data`: Hex-encoded bytes to pass to the callback (e.g., `0xabcd1234`)
- `--callback-recipient`: Address of the contract on the destination chain that will receive the callback (defaults to the regular recipient if not specified)

#### How Callbacks Work

1. When an intent is filled, the `callbackData` is included in the `MandateOutput` struct
2. The destination chain's OutputSettler calls the callback recipient with the provided data
3. The callback recipient contract should implement the expected callback interface

#### Gas Simulation for Callbacks

Before accepting an order with callback data, the solver automatically:

1. **Generates the fill transaction** with the callback data included
2. **Simulates the transaction** using `eth_estimateGas` to:
   - Detect if the callback would revert (order is rejected if so)
   - Get the accurate gas cost including callback execution
3. **Uses the simulated gas** in profitability calculations

This ensures the solver:
- Never attempts fills that would fail due to callback reverts
- Accurately accounts for callback gas costs in profit margins

Example log output:
```
✅ Callback simulation passed for order 0x57bc92.. - estimated gas: 79850 units on chain 84532
Using simulated fill gas: 79850 units (config default was: 77298 units)
```

#### Solver Configuration for Callbacks

Solvers can configure callback safety checks in their config file:

```toml
[order]
# Whitelisted callback contract addresses in EIP-7930 InteropAddress format
# Format: "0x" + Version(2 bytes) + ChainType(2 bytes) + ChainRefLen(1 byte) + ChainRef + AddrLen(1 byte) + Address
callback_whitelist = [
  "0x0001000002210514154c8bb598df835e9617c2cdcb8c84838bd329c6",  # Base (8453)
  "0x0001000003014a3414154c8bb598df835e9617c2cdcb8c84838bd329c6",  # Base Sepolia (84532)
]

# Enable gas simulation for callbacks before filling (default: true)
simulate_callbacks = true
```

**EIP-7930 InteropAddress Format:**
- Bytes 0-1: Version (always `0001`)
- Bytes 2-3: ChainType (`0000` for EIP155/Ethereum)
- Byte 4: ChainRefLen (number of bytes for chain ID)
- Next N bytes: ChainRef (chain ID in big-endian)
- Next byte: AddrLen (`14` = 20 for Ethereum addresses)
- Remaining: Address (20 bytes)

Example for Base (chain ID 8453 = 0x2105):
`0x0001` + `0000` + `02` + `2105` + `14` + `154c8bb598df835e9617c2cdcb8c84838bd329c6`

The solver will only fill intents with callback data if:
1. The callback recipient is in the whitelist
2. The callback simulation passes (transaction doesn't revert)

**Note:** If `callback_whitelist` is empty, all callback recipients are allowed (but simulation still runs).

#### Example: Intent with Callback

```bash
# Build intent that calls a contract on settlement
oif-demo intent build \
  --from-chain 11155420 \
  --to-chain 84532 \
  --from-token USDC \
  --to-token USDC \
  --amount 10 \
  --settlement escrow \
  --auth permit2 \
  --callback-data 0x12345678 \
  --callback-recipient 0x154C8BB598dF835e9617c2cdcb8c84838Bd329C6
```

### Monitoring Balances
```bash
# Follow all accounts every 5 seconds
oif-demo token balance --account all --follow 5
```

### Custom Contract Deployment
```bash
# Deploy specific contract to specific chain
oif-demo env deploy --contract MyToken --chain 31337
```

### On-chain Intent Submission
```bash
# Submit directly to blockchain (bypasses API)
oif-demo intent submit order.json --onchain
```