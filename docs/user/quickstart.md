# Quickstart Guide

This guide will help you get the OIF Solver up and running quickly for testing and development purposes.

## Prerequisites

Before you begin, ensure you have the following installed:

- **Rust toolchain** (stable) - [Install Rust](https://rustup.rs/)
- **Foundry** (for local testing) - [Install Foundry](https://book.getfoundry.sh/getting-started/installation)
- **Git** for cloning the repository

### Additional Tools (for demo)

- `Bash` version > 4.0
- `jq`, `curl`, `bc`, `perl`

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/openintentsframework/oif-solver.git
cd oif-solver
```

### 2. Build the Project

```bash
# Build all components
cargo build

# Build in release mode for better performance
cargo build --release
```

### 3. Run Tests

```bash
# Run the test suite to ensure everything is working
cargo test
```

## Quick Setup with Demo Environment

The fastest way to see the solver in action is using the included demo environment.

### 1. Start the Demo Environment

```bash
# This will start local blockchain networks, deploy contracts, and generate configuration
./oif-demo env up
```

This command will:

- Start two local Anvil chains (Origin: port 8545, Destination: port 8546)
- Deploy test tokens and settlement contracts
- Generate a complete configuration file at `config/demo.toml`
- Set up test accounts with initial token balances

### 2. Start the Solver

In a new terminal window:

```bash
# Run the solver with the generated demo configuration
cargo run --bin solver -- --config config/demo.toml
```

You should see output indicating the solver has started and is monitoring for intents:

```
[INFO] OIF Solver starting with config: config/demo.toml
[INFO] Discovery service started, monitoring chain 31337
[INFO] Solver ready and monitoring for intents
```

### 3. Test Cross-Chain Intent Execution

In another terminal, test a complete cross-chain transfer:

```bash
# Execute a test intent
./oif-demo intent test
```

This will:

1. Build a cross-chain intent order
2. Submit it to the solver via API
3. Get a quote with pricing
4. Accept and execute the quote
5. Monitor the complete execution process

### 4. Monitor Results

You can monitor balances and see the cross-chain transfer in action:

```bash
# Watch balances update in real-time
./oif-demo monitor 3 all
```

## Manual Configuration

If you prefer to set up your own configuration instead of using the demo:

### 1. Create Configuration File

Copy the example configuration:

```bash
cp config/example.toml config/my-config.toml
```

### 2. Edit Configuration

Edit `config/my-config.toml` to match your setup. Key sections to configure:

```toml
# Solver identity
[solver]
id = "my-solver"
monitoring_timeout_minutes = 5

# Networks - add your target networks
[networks.1]  # Ethereum Mainnet
input_settler_address = "0x..."
# ... add your network configurations

# Account management
[account.implementations.local]
private_key = "0x..."  # Your private key

# Discovery sources
[discovery.implementations.onchain_eip7683]
network_id = 1  # Network to monitor
```

### 3. Run with Custom Configuration

```bash
cargo run --bin solver -- --config config/my-config.toml
```

## Basic Usage Examples

### Submitting an Intent via API

Once the solver is running, you can submit intents through the REST API:

```bash
# Submit a cross-chain intent
curl -X POST http://localhost:3000/api/orders \
  -H "Content-Type: application/json" \
  -d '{
    "order": "0x...",
    "sponsor": "0x...",
    "signature": "0x..."
  }'
```

### Checking Order Status

```bash
# Get order status by ID
curl http://localhost:3000/api/orders/{order_id}
```

### Querying Supported Tokens

```bash
# Get all supported tokens
curl http://localhost:3000/api/tokens

# Get tokens for specific chain
curl http://localhost:3000/api/tokens/1
```

## Environment Variables

### Logging Configuration

Control logging output with the `RUST_LOG` environment variable:

```bash
# Debug logs for solver components only
RUST_LOG=solver_core=debug,solver_delivery=debug,info cargo run -- --config config/demo.toml

# Reduce noise from external crates
RUST_LOG=info,hyper=warn,alloy_provider=warn cargo run -- --config config/demo.toml

# Full debug logging (very verbose)
RUST_LOG=debug cargo run -- --config config/demo.toml
```

### Configuration File Path

```bash
# Set config file via environment variable
CONFIG_FILE=config/my-config.toml cargo run
```

## Troubleshooting

### Common Issues

1. **Build Errors**: Ensure you have the latest stable Rust toolchain
2. **Port Conflicts**: Make sure ports 8545, 8546, and 3000 are available for the demo
3. **Permission Errors**: Ensure the solver has write access to the storage directory

### Getting Help

- Check the [Configuration Guide](configuration.md) for detailed setup instructions
- Review logs with `RUST_LOG=debug` for detailed debugging information
- Consult the [API Reference](api-reference.md) for API usage details

## Next Steps

Now that you have the solver running:

1. **Explore Configuration**: Learn about advanced configuration options in the [Configuration Guide](configuration.md)
2. **Try the Demo**: Use the [Demo Guide](demo.md) to explore all available testing scenarios
3. **Understand the API**: Read the [API Reference](api-reference.md) to integrate with your applications
4. **Learn the Architecture**: For deeper understanding, check the [Developer Documentation](../DEVELOPER_DOCUMENTATION.md)
