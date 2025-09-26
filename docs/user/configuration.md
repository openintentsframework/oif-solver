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
min_profitability_pct = 1.0          # Minimum profitability percentage required for order execution
```

### Networks Configuration

Define the blockchain networks your solver will operate on:

```toml
[networks.31337]  # Network ID (chain ID)
input_settler_address = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"   # InputSettler contract
input_settler_compact_address = "0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6"  # Compact InputSettler contract
the_compact_address = "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"      # The Compact contract
allocator_address = "0x0165878A594ca255338adfa4d48449f69242Eb8F"        # Allocator contract
output_settler_address = "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"  # OutputSettler contract

# RPC endpoints with both HTTP and WebSocket support
[[networks.31337.rpc_urls]]
http = "http://localhost:8545"
ws = "ws://localhost:8545"

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

- Each network needs input/output settler addresses and additional contract addresses for different settlement types
- RPC endpoints support both HTTP and WebSocket connections for real-time event monitoring
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
network_ids = [31337, 31338]         # Networks to monitor for events (supports multiple)
polling_interval_secs = 0            # Use WebSocket subscriptions (0) or polling interval in seconds
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

### Pricing Configuration

Configure price feeds for token valuation and profitability calculations:

```toml
[pricing]
primary = "coingecko"                # Primary pricing implementation to use

[pricing.implementations.mock]
# Uses default ETH/USD price of 4615.16 for testing

[pricing.implementations.coingecko]
# Free tier configuration (no API key required)
# api_key = "CG-YOUR-API-KEY-HERE"   # Optional: API key for higher rate limits
cache_duration_seconds = 60          # How long to cache price data
rate_limit_delay_ms = 1200           # Delay between API calls to respect rate limits

# Custom prices for demo/test tokens (in USD)
[pricing.implementations.coingecko.custom_prices]
TOKA = "200.00"
TOKB = "195.00"
```

### Settlement Configuration

Configure settlement verification and claim processing:

#### Direct Settlement

```toml
[settlement]
[settlement.domain]
chain_id = 1                         # Chain ID for EIP-712 signatures
address = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"

[settlement.implementations.direct]
order = "eip7683"                    # Order implementation to use
network_ids = [31337, 31338]         # Networks to monitor for settlement
dispute_period_seconds = 1           # How long to wait before allowing claims
oracle_selection_strategy = "First"  # Strategy when multiple oracles available (First, RoundRobin, Random)

# Oracle configuration with multiple oracle support
[settlement.implementations.direct.oracles]
# Input oracles (on origin chains)
input = { 31337 = [
    "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9",
], 31338 = [
    "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9",
] }
# Output oracles (on destination chains)
output = { 31337 = [
    "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9",
], 31338 = [
    "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9",
] }

# Valid routes: from origin chain -> to destination chains
[settlement.implementations.direct.routes]
31337 = [31338] # Can go from origin to destination
31338 = [31337] # Can go from destination to origin
```

#### Hyperlane Settlement (Cross-Chain Messaging)

```toml
[settlement.implementations.hyperlane]
order = "eipXXXX"                    # Order implementation for Hyperlane
network_ids = [31337, 31338]         # Networks supporting Hyperlane
default_gas_limit = 500000           # Default gas limit for Hyperlane messages
message_timeout_seconds = 600        # Timeout for cross-chain messages
finalization_required = false        # Whether to wait for finalization (set true for production)

# Oracle addresses for Hyperlane settlement
[settlement.implementations.hyperlane.oracles]
input = { 31337 = [
    "0x0000000000000000000000000000000000000999",
], 31338 = [
    "0x0000000000000000000000000000000000000999",
] }
output = { 31337 = [
    "0x0000000000000000000000000000000000000999",
], 31338 = [
    "0x0000000000000000000000000000000000000999",
] }

# Route configuration for Hyperlane
[settlement.implementations.hyperlane.routes]
31337 = [31338]
31338 = [31337]

# Mailbox addresses for Hyperlane messaging
[settlement.implementations.hyperlane.mailboxes]
31337 = "0x0000000000000000000000000000000000000001"
31338 = "0x0000000000000000000000000000000000000001"

# Interchain Gas Paymaster (IGP) addresses
[settlement.implementations.hyperlane.igp_addresses]
31337 = "0x0000000000000000000000000000000000000002"
31338 = "0x0000000000000000000000000000000000000002"
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

[api.implementations]
discovery = "offchain_eip7683"      # Discovery implementation for API

# JWT Authentication Configuration
[api.auth]
enabled = true                      # Enable JWT authentication
jwt_secret = "${JWT_SECRET:-MySuperDuperSecureSecret123!}"  # JWT signing secret (use env var in production)
access_token_expiry_hours = 1       # Access token validity period
refresh_token_expiry_hours = 720    # Refresh token validity period (30 days)
issuer = "oif-solver-demo"          # JWT issuer identifier

# Quote Configuration
[api.quote]
validity_seconds = 60               # How long quotes remain valid (in seconds)
```

### Gas Estimation Configuration

Configure gas estimates for different transaction flows:

```toml
[gas]

[gas.flows.compact_resource_lock]
# Gas units for Compact resource lock flows
open = 0                            # Gas for opening positions
fill = 76068                        # Gas for filling orders
claim = 121995                      # Gas for claiming settlements

[gas.flows.permit2_escrow]
# Gas units for Permit2 escrow flows
open = 143116                       # Gas for opening escrow
fill = 76068                        # Gas for filling orders
claim = 59953                       # Gas for claiming from escrow

[gas.flows.eip3009_escrow]
# Gas units for EIP-3009 escrow flows
open = 130254                       # Gas for opening EIP-3009 escrow
fill = 77298                        # Gas for filling orders
claim = 60084                       # Gas for claiming from escrow
```

### CLI Configuration (Demo/Testing)

Configure accounts for CLI tools and demo scripts:

```toml
[accounts]
user_address = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
user_private_key = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
solver_address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
recipient_address = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
```

**Note**: This section is used by demo scripts and CLI tools for testing purposes.

## Complete Configuration Examples

### Single File Example

```toml
# Complete single-file configuration example
[solver]
id = "oif-solver-local"
monitoring_timeout_minutes = 5
min_profitability_pct = 1.0

# Network configurations
[networks.31337]  # Origin chain
input_settler_address = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
input_settler_compact_address = "0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6"
the_compact_address = "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"
allocator_address = "0x0165878A594ca255338adfa4d48449f69242Eb8F"
output_settler_address = "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"

[[networks.31337.rpc_urls]]
http = "http://localhost:8545"
ws = "ws://localhost:8545"

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
input_settler_compact_address = "0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6"
the_compact_address = "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"
allocator_address = "0x0165878A594ca255338adfa4d48449f69242Eb8F"
output_settler_address = "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"

[[networks.31338.rpc_urls]]
http = "http://localhost:8546"
ws = "ws://localhost:8546"

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
network_ids = [31337, 31338]
polling_interval_secs = 0

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

# Pricing configuration
[pricing]
primary = "coingecko"

[pricing.implementations.coingecko]
cache_duration_seconds = 60
rate_limit_delay_ms = 1200

[pricing.implementations.coingecko.custom_prices]
TOKA = "200.00"
TOKB = "195.00"

# Settlement configuration
[settlement]
[settlement.domain]
chain_id = 1
address = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"

[settlement.implementations.direct]
order = "eip7683"
network_ids = [31337, 31338]
dispute_period_seconds = 1
oracle_selection_strategy = "First"

[settlement.implementations.direct.oracles]
input = { 31337 = [
    "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9",
], 31338 = [
    "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9",
] }
output = { 31337 = [
    "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9",
], 31338 = [
    "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9",
] }

[settlement.implementations.direct.routes]
31337 = [31338]
31338 = [31337]

# API server configuration
[api]
enabled = true
host = "127.0.0.1"
port = 3000
timeout_seconds = 30
max_request_size = 1048576

[api.auth]
enabled = true
jwt_secret = "${JWT_SECRET:-MySuperDuperSecureSecret123!}"
access_token_expiry_hours = 1
refresh_token_expiry_hours = 720
issuer = "oif-solver-demo"

[api.quote]
validity_seconds = 60

# Gas estimation configuration
[gas]
[gas.flows.compact_resource_lock]
open = 0
fill = 76068
claim = 121995

[gas.flows.permit2_escrow]
open = 143116
fill = 76068
claim = 59953

[gas.flows.eip3009_escrow]
open = 130254
fill = 77298
claim = 60084
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
5. **Configure Pricing**: Use appropriate pricing implementations and cache settings for your deployment
6. **Choose Settlement Strategy**: Select between direct and Hyperlane settlement based on your cross-chain requirements
7. **Enable Authentication**: Use JWT authentication for production API deployments
8. **Test Configurations**: Use the demo environment to validate configurations before production deployment

## Troubleshooting

- **Configuration Parse Errors**: Check TOML syntax and ensure all required fields are present
- **Network Connection Issues**: Verify network RPC endpoints and chain IDs
- **Permission Errors**: Ensure the solver has write access to the storage directory
- **Account Issues**: Verify private key format and sufficient balance for gas fees
