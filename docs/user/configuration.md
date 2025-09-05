# Configuration Guide

The OIF Solver uses TOML configuration files with support for modular configuration through file includes. This guide covers all configuration options and provides examples for different deployment scenarios.

## Configuration Approaches

### Modular Configuration (Recommended)

Split your configuration into multiple files for better organization and maintainability:

```toml
# config/demo.toml - Main configuration file
include = [
    "demo/networks.toml",  # Network and token configurations
    "demo/api.toml",       # API server settings
    "demo/cli.toml",       # CLI-specific settings
    "demo/gas.toml",       # Gas pricing configuration
]

[solver]
id = "oif-solver-demo"
monitoring_timeout_minutes = 5
```

### Single File Configuration

You can also use a single configuration file. See the complete example in the [Single File Example](#single-file-example) section below.

## Configuration Sections

### Solver Settings

```toml
[solver]
id = "oif-solver-local"              # Unique identifier for this solver instance
monitoring_timeout_minutes = 5       # Timeout for monitoring operations
```

### Networks Configuration

Define the blockchain networks your solver will operate on:

```toml
[networks.31337]  # Network ID (chain ID)
input_settler_address = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"   # InputSettler contract
output_settler_address = "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"  # OutputSettler contract

# Define supported tokens on this network
[[networks.31337.tokens]]
address = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
symbol = "TOKA"
decimals = 18

[[networks.31337.tokens]]
address = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"
symbol = "TOKB"
decimals = 18
```

**Key Points:**

- Each network needs both input and output settler addresses
- Tokens array defines the supported assets on each network
- Network ID must match the actual blockchain chain ID

### Storage Configuration

Configure persistent storage with TTL (time-to-live) management:

```toml
[storage]
primary = "file"                     # Storage backend to use
cleanup_interval_seconds = 3600      # How often to clean up expired data

[storage.implementations.file]
storage_path = "./data/storage"      # Directory for file-based storage
ttl_orders = 0                       # Permanent storage for orders (0 = no expiration)
ttl_intents = 86400                  # 24 hours for intent data
ttl_order_by_tx_hash = 86400         # 24 hours for transaction hash lookups
```

**TTL Values:**

- `0` = Permanent storage (never expires)
- `> 0` = Expiration time in seconds

### Account Management

Configure cryptographic keys for transaction signing:

```toml
[account]
primary = "local"  # Default account implementation

[account.implementations.local]
private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# Optional: Additional accounts for different networks
[account.implementations.mainnet]
private_key = "0x..."

[account.implementations.testnet]
private_key = "0x..."
```

**Security Note**: Never commit private keys to version control. Use environment variables or secure key management systems in production.

### Transaction Delivery

Configure how transactions are submitted to blockchain networks:

```toml
[delivery]
min_confirmations = 1                # Minimum confirmations before considering a transaction final

[delivery.implementations.evm_alloy]
network_ids = [31337, 31338]         # Networks this implementation supports

# Optional: Map specific networks to different accounts
accounts = { 31337 = "local", 31338 = "testnet" }
```

### Intent Discovery

Configure sources for discovering new cross-chain intents:

#### On-Chain Discovery

```toml
[discovery.implementations.onchain_eip7683]
network_id = 31337                   # Required: chain to monitor for events
```

#### Off-Chain API Discovery

```toml
[discovery.implementations.offchain_eip7683]
api_host = "127.0.0.1"               # API server host
api_port = 8081                      # API server port
network_ids = [31337]                # Optional: networks this API supports
```

### Order Processing

Configure order validation and execution strategies:

```toml
[order]
[order.implementations.eip7683]
# Uses networks configuration for settler addresses

[order.strategy]
primary = "simple"                   # Execution strategy to use

[order.strategy.implementations.simple]
max_gas_price_gwei = 100            # Maximum gas price for execution
```

### Settlement Configuration

Configure settlement verification and claim processing:

```toml
[settlement]
[settlement.domain]
chain_id = 1                         # Chain ID for EIP-712 signatures
address = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"

[settlement.implementations.eip7683]
network_ids = [31337, 31338]         # Networks to monitor for settlement
oracle_addresses = {
    31337 = "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9",
    31338 = "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9"
}
dispute_period_seconds = 1           # How long to wait before allowing claims
```

### API Server (Optional)

Configure the REST API server for receiving off-chain intents:

```toml
[api]
enabled = true                       # Enable/disable API server
host = "127.0.0.1"                  # Host to bind to
port = 3000                         # Port to listen on
timeout_seconds = 30                # Request timeout
max_request_size = 1048576          # Maximum request size (1MB)
```

## Complete Configuration Examples

### Single File Example

```toml
# Complete single-file configuration example
[solver]
id = "oif-solver-local"
monitoring_timeout_minutes = 5

# Network configurations
[networks.31337]  # Origin chain
input_settler_address = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
output_settler_address = "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"

[[networks.31337.tokens]]
address = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
symbol = "TOKA"
decimals = 18

[[networks.31337.tokens]]
address = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"
symbol = "TOKB"
decimals = 18

[networks.31338]  # Destination chain
input_settler_address = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
output_settler_address = "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"

[[networks.31338.tokens]]
address = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
symbol = "TOKA"
decimals = 18

# Storage configuration
[storage]
primary = "file"
cleanup_interval_seconds = 3600

[storage.implementations.file]
storage_path = "./data/storage"
ttl_orders = 0
ttl_intents = 86400
ttl_order_by_tx_hash = 86400

# Account configuration
[account]
primary = "local"

[account.implementations.local]
private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# Delivery configuration
[delivery]
min_confirmations = 1

[delivery.implementations.evm_alloy]
network_ids = [31337, 31338]

# Discovery configuration
[discovery.implementations.onchain_eip7683]
network_id = 31337

[discovery.implementations.offchain_eip7683]
api_host = "127.0.0.1"
api_port = 8081
network_ids = [31337]

# Order configuration
[order]
[order.implementations.eip7683]

[order.strategy]
primary = "simple"

[order.strategy.implementations.simple]
max_gas_price_gwei = 100

# Settlement configuration
[settlement]
[settlement.domain]
chain_id = 1
address = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"

[settlement.implementations.eip7683]
network_ids = [31337, 31338]
oracle_addresses = { 31337 = "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9", 31338 = "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9" }
dispute_period_seconds = 1

# API server configuration
[api]
enabled = true
host = "127.0.0.1"
port = 3000
timeout_seconds = 30
max_request_size = 1048576
```

## Configuration Validation

The solver validates all configuration on startup and will report detailed errors for:

- Missing required fields
- Invalid addresses or network IDs
- Duplicate configuration sections (in modular configs)
- Invalid TTL values
- Network/account mismatches

## Loading Configuration

### Command Line

```bash
# Specify configuration file via command line
cargo run --bin solver -- --config path/to/config.toml
```

### Environment Variable

```bash
# Set configuration via environment variable
CONFIG_FILE=path/to/config.toml cargo run --bin solver
```

## Best Practices

1. **Use Modular Configuration**: Split large configurations into logical files
2. **Secure Private Keys**: Never commit private keys; use environment variables or secure vaults
3. **Set Appropriate TTLs**: Balance storage efficiency with data retention needs
4. **Monitor Gas Prices**: Set reasonable gas price limits for your use case
5. **Test Configurations**: Use the demo environment to validate configurations before production deployment

## Troubleshooting

- **Configuration Parse Errors**: Check TOML syntax and ensure all required fields are present
- **Network Connection Issues**: Verify network RPC endpoints and chain IDs
- **Permission Errors**: Ensure the solver has write access to the storage directory
- **Account Issues**: Verify private key format and sufficient balance for gas fees
