# Demo Guide

The OIF Solver includes a comprehensive CLI demo tool (`./oif-demo`) for testing cross-chain intent execution between two local blockchain networks. This guide covers all demo functionality and testing scenarios.

**Note:** The demo has been tested on macOS systems only.

## Prerequisites

Ensure you have the following tools installed:

- **[Foundry](https://book.getfoundry.sh/getting-started/installation)** - For Anvil, Forge, and Cast
- **Rust toolchain** (stable) - [Install Rust](https://rustup.rs/)
- **Bash version > 4.0**
- **Additional utilities**: `jq`, `curl`, `bc`, `perl`

## Quick Start

### 1. Set Up Environment

```bash
# Start local blockchain networks, deploy contracts, and generate configuration
./oif-demo env up
```

This command will:

- Start Origin chain (ID: 31337) on port 8545
- Start Destination chain (ID: 31338) on port 8546
- Deploy test tokens (TokenA, TokenB) on both chains
- Deploy settlement contracts (escrow and compact)
- Deploy oracle contracts for attestations
- Generate complete configuration at `config/demo.toml`
- Fund test accounts with initial token balances
- Set up necessary token approvals

### 2. Start the Solver

In a new terminal window:

```bash
# Build and run the solver with demo configuration
cargo run --bin solver -- --config config/demo.toml

# Optional: Run with debug logging
RUST_LOG=solver_core=debug,solver_delivery=info,info cargo run --bin solver -- --config config/demo.toml
```

### 3. Test Complete Flow

```bash
# Execute a full quote flow: build → get quote → accept → monitor
./oif-demo quote test escrow permit2 A2B
```

### 4. Monitor Results

```bash
# Watch balances update in real-time (refresh every 3 seconds)
./oif-demo monitor 3 all
```

## Command Reference

### Environment Management

#### Start local environment

```bash
./oif-demo env up
```

Starts the complete demo environment with blockchain networks and contract deployments.

#### Check Status

```bash
./oif-demo env status
```

Verifies that all components are running and accessible.

#### Stop local environment

```bash
./oif-demo env down
```

Stops all Anvil blockchain networks.

#### Reset Everything

```bash
./oif-demo env reset
```

Completely resets the environment, removing all data and stopping networks.

### Configuration

#### Initialize Configuration

```bash
./oif-demo init config/demo.toml
```

Generates a fresh configuration file with current contract addresses.

### Intent Operations

The demo supports two submission modes:

- **Offchain (default)**: Submit intents via the solver's REST API
- **Onchain**: Submit intents directly to blockchain contracts

#### Offchain Intent Submission

Build intents for API submission:

```bash
# Format: intent build <lock_type> <auth_type> <origin_chain> <dest_chain> <from_token> <to_token>
./oif-demo intent build escrow permit2 31337 31338 TokenA TokenB
./oif-demo intent build escrow eip3009 31337 31338 TokenA TokenB
./oif-demo intent build compact permit2 31337 31338 TokenB TokenA
```

Submit to solver API:

```bash
./oif-demo intent submit demo-output/post_intent.req.json
```

Test with single command:

```bash
# Format: intent test <lock_type> <auth_type> <token_pair>
./oif-demo intent test escrow permit2 A2B   # TokenA → TokenB with escrow
./oif-demo intent test escrow eip3009 A2B   # TokenA → TokenB with EIP-3009
./oif-demo intent test compact permit2 B2A  # TokenB → TokenA with compact lock
```

#### Onchain Intent Submission

Build for direct blockchain submission:

```bash
# Format: intent build --onchain <lock_type> <origin_chain> <dest_chain> <from_token> <to_token>
./oif-demo intent build --onchain escrow 31337 31338 TokenA TokenB
```

Submit directly to blockchain:

```bash
./oif-demo intent submit --onchain demo-output/post_intent.req.json
```

Test with single command:

```bash
# Format: intent test --onchain <lock_type> <token_pair>
./oif-demo intent test --onchain escrow A2B
./oif-demo intent test --onchain escrow B2A
```

**Note**: Onchain submission only supports escrow intents and requires prior token approval.

### Quote Operations

#### Get Quote

```bash
./oif-demo quote get demo-output/get_quote.req.json
```

#### Accept Quote

```bash
./oif-demo quote accept demo-output/get_quote.res.json
```

#### Full Quote Flow

```bash
# Format: quote test <lock_type> <auth_type> <token_pair>
./oif-demo quote test escrow permit2 A2B   # Complete flow with escrow + Permit2
./oif-demo quote test escrow eip3009 A2B   # Complete flow with escrow + EIP-3009
./oif-demo quote test compact permit2 B2A  # Complete flow with compact + Permit2
```

### Balance Monitoring

#### Check Balances

```bash
./oif-demo balance all        # All balance types
./oif-demo balance user       # User wallet balances
./oif-demo balance recipient  # Recipient balances
./oif-demo balance solver     # Solver balances
./oif-demo balance settlers   # All settler contracts
./oif-demo balance escrow     # Escrow settlers only
./oif-demo balance compact    # Compact settlers only
```

#### Real-Time Monitoring

```bash
./oif-demo monitor 5 all      # Refresh every 5 seconds, show all
./oif-demo monitor 3 user     # Refresh every 3 seconds, user only
./oif-demo monitor 10 settlers # Refresh every 10 seconds, settlers only
```

## Testing Scenarios

### Lock Types

#### Escrow Lock

- **Description**: Traditional escrow pattern where funds are held in a settler contract
- **Use Cases**: Most common cross-chain transfers
- **Commands**: Use `escrow` in intent commands
- **Support**: Both offchain and onchain submission

#### Compact Lock

- **Description**: More efficient settlement with reduced gas costs
- **Use Cases**: High-frequency or cost-sensitive transfers
- **Commands**: Use `compact` in intent commands
- **Support**: Offchain submission only, requires Permit2 authorization

### Authorization Types

#### Permit2

- **Description**: EIP-2612 style permits for token authorization
- **Commands**: Use `permit2` in intent commands
- **Support**: Both escrow and compact locks

#### EIP-3009

- **Description**: Transfer with authorization pattern
- **Commands**: Use `eip3009` in intent commands
- **Support**: Escrow locks only

### Token Pairs

The demo supports various token combinations:

```bash
# Symbolic names
TokenA, TokenB

# Address format
0x5FbDB2315678afecb367f032d93F642f64180aa3

# Test pair shortcuts
A2A  # TokenA → TokenA (same token, different chains)
A2B  # TokenA → TokenB
B2A  # TokenB → TokenA
B2B  # TokenB → TokenB
```

## Output Files

The demo generates structured output files in `demo-output/`:

| File                   | Description                 | Generated By    |
| ---------------------- | --------------------------- | --------------- |
| `post_intent.req.json` | Intent submission request   | `intent build`  |
| `post_intent.res.json` | Intent submission response  | `intent submit` |
| `get_quote.req.json`   | Quote request payload       | `intent build`  |
| `get_quote.res.json`   | Quote response with pricing | `quote get`     |
| `post_quote.req.json`  | Signed quote acceptance     | `quote accept`  |
| `post_quote.res.json`  | Quote acceptance response   | `quote accept`  |

**File Naming Convention:**

- `.req.json` - Request payloads sent to APIs
- `.res.json` - Responses received from APIs

## Example Workflows

### Complete Cross-Chain Transfer

```bash
# 1. Start environment
./oif-demo env up

# 2. Start solver (in another terminal)
cargo run --bin solver -- --config config/demo.toml

# 3. Execute transfer
./oif-demo quote test escrow permit2 A2B

# 4. Monitor results
./oif-demo monitor 5 all
```

### Testing Different Lock Types

```bash
# Test escrow lock
./oif-demo intent test escrow permit2 A2B

# Test compact lock (more efficient)
./oif-demo intent test compact permit2 B2A
```

### Testing Authorization Methods

```bash
# Using Permit2 authorization
./oif-demo intent test escrow permit2 A2B

# Using EIP-3009 authorization
./oif-demo intent test escrow eip3009 A2B
```

### Onchain vs Offchain Submission

```bash
# Submit via solver API (default)
./oif-demo intent test escrow permit2 A2B

# Submit directly to blockchain
./oif-demo intent test --onchain escrow A2B
```

## Troubleshooting

### Common Issues

#### Port Conflicts

```bash
# Check if ports are in use
lsof -i :8545 -i :8546 -i :3000

# Kill processes if needed
./oif-demo env reset
```

#### Configuration Issues

```bash
# Regenerate configuration
./oif-demo init config/demo.toml

# Verify configuration
cargo run --bin solver -- --config config/demo.toml --dry-run
```

#### Balance Issues

```bash
# Check if accounts have sufficient balances
./oif-demo balance all

# Reset environment to restore initial balances
./oif-demo env reset && ./oif-demo env up
```

#### Network Connectivity

```bash
# Test network connectivity
./oif-demo env status

# Check if Anvil processes are running
ps aux | grep anvil
```

### Debug Mode

Run the solver with debug logging for detailed troubleshooting:

```bash
RUST_LOG=debug cargo run --bin solver -- --config config/demo.toml
```

### Log Files

Demo processes create log files for debugging:

- `origin_anvil.log` - Origin chain logs
- `destination_anvil.log` - Destination chain logs
- Process ID files: `*.pid`

## Next Steps

- Learn about production configuration in [Configuration Guide](configuration.md)
- Understand the API for integration in [API Reference](api-reference.md)
- Explore the technical architecture in [Developer Documentation](../DEVELOPER_DOCUMENTATION.md)
