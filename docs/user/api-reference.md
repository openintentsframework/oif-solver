# API Reference

The OIF Solver provides a REST API for interacting with the system and submitting off-chain intents. The API is enabled by default on port 3000 when the solver is running.

## Base URL

```
http://localhost:3000/api
```

## API Specifications

Complete OpenAPI specifications are available in the `api-spec/` directory:

- **[Orders API](../../api-spec/orders-api.yaml)** - Submit and track cross-chain intent orders
- **[Tokens API](../../api-spec/tokens-api.yaml)** - Query supported tokens and networks

## Authentication

The API supports JWT (JSON Web Token) authentication for secure access in production deployments. Authentication can be configured in the solver settings.

### JWT Authentication

When JWT authentication is enabled, include the token in the `Authorization` header:

```bash
curl -X POST http://localhost:3000/api/orders \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"order": "0x...", "sponsor": "0x...", "signature": "0x..."}'
```

### Configuration

Enable JWT authentication in your configuration file:

```toml
[api]
enabled = true
host = "127.0.0.1"
port = 3000
jwt_secret = "your-secret-jwt-token"  # Required for JWT validation
require_auth = true             # Enable JWT authentication
```

**Note**: For development and testing, authentication can be disabled by setting `require_auth = false`.

## Endpoints

### Orders

#### Submit Intent Order

**POST** `/api/orders`

Submit a new EIP-7683 compliant cross-chain intent order for execution.

**Request Body:** (To be modified?)

```json
{
  "order": "0x00000000000000000000000000000000...", // Hex-encoded StandardOrder data
  "sponsor": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", // Sponsor address
  "signature": "0x1234..." // Order signature (or "0x00..." for unsigned)
}
```

**Parameters:** (To be modified?)

- `order` (string, required): ABI-encoded EIP-7683 order data in hexadecimal format
- `sponsor` (string, required): Ethereum address of the user sponsoring the order
- `signature` (string, required): EIP-712 ryptographic signature of the order

**Response:**

```json
{
  "status": "success",
  "order_id": "1fa518079ecf01372290adf75c55858771efcbcee080594cc8bc24e3309a3a09",
  "message": null
}
```

**Response Fields:**

- `status`: Either "success" or "error"
- `order_id`: Unique identifier for tracking the order (only present on success)
- `message`: Error message (only present on error)

**Example:**

```bash
curl -X POST http://localhost:3000/api/orders \
  -H "Content-Type: application/json" \
  -d '{
    "order": "0x00000000000000000000000000000000...",
    "sponsor": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    "signature": "0x00..."
  }'
```

#### Get Order Status

**GET** `/api/orders/{order_id}`

Retrieve the current status and details of a submitted order.

**Parameters:**

- `order_id` (path parameter): The order ID returned from the submission

**Response:**

```json
{
  "order_id": "1fa518079ecf01372290adf75c55858771efcbcee080594cc8bc24e3309a3a09",
  "status": "Finalized",
  "order": {
    // Complete order data structure
    "info": {
      "reactor": "0x...",
      "swapper": "0x...",
      "nonce": 0,
      "deadline": 1234567890,
      "additionalValidationContract": "0x0000000000000000000000000000000000000000",
      "additionalValidationData": "0x"
    },
    "input": {
      "token": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
      "amount": "1000000000000000000",
      "maxAmount": "1000000000000000000"
    },
    "outputs": [
      {
        "token": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
        "amount": "990000000000000000",
        "recipient": "0x...",
        "chainId": "31338"
      }
    ],
    "fillInstructions": {
      // Fill instruction details
    }
  },
  "amounts": {
    "input_amount": "1000000000000000000",
    "output_amount": "990000000000000000"
  },
  "settlement": {
    // Settlement data if available
    "fill_tx_hash": "0x...",
    "chain_id": 31337
  },
  "fill_tx": {
    "hash": "0x...",
    "chain_id": 31337,
    "block_number": 123,
    "status": "confirmed"
  }
}
```

**Order Status Values:**

- `Pending`: Order received and queued for processing
- `Executing`: Order is being processed
- `Executed`: Fill transaction submitted and confirmed
- `PostFilled`: Post-fill processing completed
- `PreClaimed`: Pre-claim transaction completed (if required)
- `Finalized`: Order fully completed with claim transaction

**Example:**

```bash
curl http://localhost:3000/api/orders/1fa518079ecf01372290adf75c55858771efcbcee080594cc8bc24e3309a3a09
```

### Tokens

#### Get All Supported Tokens

**GET** `/api/tokens`

Retrieve all supported tokens across all configured networks.

**Response:**

```json
{
  "31337": {
    "input_settler_address": "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0",
    "output_settler_address": "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9",
    "tokens": [
      {
        "address": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
        "symbol": "TOKA",
        "decimals": 18
      },
      {
        "address": "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
        "symbol": "TOKB",
        "decimals": 18
      }
    ]
  },
  "31338": {
    "input_settler_address": "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0",
    "output_settler_address": "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9",
    "tokens": [
      {
        "address": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
        "symbol": "TOKA",
        "decimals": 18
      }
    ]
  }
}
```

**Example:**

```bash
curl http://localhost:3000/api/tokens
```

#### Get Tokens for Specific Chain

**GET** `/api/tokens/{chain_id}`

Retrieve supported tokens for a specific blockchain network.

**Parameters:**

- `chain_id` (path parameter): The blockchain network chain ID

**Response:**

```json
{
  "input_settler_address": "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0",
  "output_settler_address": "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9",
  "tokens": [
    {
      "address": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
      "symbol": "TOKA",
      "decimals": 18
    },
    {
      "address": "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
      "symbol": "TOKB",
      "decimals": 18
    }
  ]
}
```

**Example:**

```bash
# Get tokens for Ethereum Mainnet
curl http://localhost:3000/api/tokens/1

# Get tokens for local test chain
curl http://localhost:3000/api/tokens/31337
```

## API Configuration

Enable or configure the API server in your configuration file:

```toml
[api]
enabled = true              # Enable/disable API server
host = "127.0.0.1"         # Host to bind to (use "0.0.0.0" to accept external connections)
port = 3000                # Port to listen on
timeout_seconds = 30       # Request timeout
max_request_size = 1048576 # Maximum request size (1MB)
jwt_secret = "your-secret-key-token"  # JWT secret for token validation (optional)
require_auth = false       # Enable JWT authentication (optional, defaults to false)
```

## Next Steps

- Learn about creating orders in the [Demo Guide](demo.md)
- Understand the solver architecture in the [Developer Documentation](../DEVELOPER_DOCUMENTATION.md)
- Explore advanced configuration in the [Configuration Guide](configuration.md)
