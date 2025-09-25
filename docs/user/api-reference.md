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
- **Quotes API** (`/api/quotes`) - Generate price quotes for cross-chain token transfers
- **Authentication API** (`/api/register`) - Register clients and manage JWT authentication

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

[api.auth]
enabled = true
issuer = "oif-solver"
jwt_secret = "your-secret-jwt-token"
```

**Note**: For development and testing, authentication can be disabled by setting `enabled = false` in the `[api.auth]` section.

## Endpoints

### Quotes

#### Get Quote

**POST** `/api/quotes`

Generate price quotes for cross-chain token transfers. This endpoint analyzes your transfer intent and returns multiple execution options with different optimization strategies.

**Request Body:**

```json
{
  "user": "1:0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1",
  "availableInputs": [
    {
      "user": "1:0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1",
      "asset": "1:0x5FbDB2315678afecb367f032d93F642f64180aa3",
      "amount": "1000000000000000000",
      "lock": null
    }
  ],
  "requestedOutputs": [
    {
      "receiver": "31338:0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
      "asset": "31338:0x5FbDB2315678afecb367f032d93F642f64180aa3",
      "amount": "990000000000000000",
      "calldata": null
    }
  ],
  "minValidUntil": 300,
  "preference": "price"
}
```

**Parameters:**

- `user` (string, required): User making the request in ERC-7930 interoperable format (chainId:address)
- `availableInputs` (array, required): Available input tokens for the quote
  - `user` (string): User address in ERC-7930 interoperable format
  - `asset` (string): Asset address in ERC-7930 interoperable format
  - `amount` (string): Amount as a decimal string (to handle large numbers)
  - `lock` (object, optional): Lock information if asset is already locked
    - `kind` (string): Lock mechanism type ("the-compact")
    - `params` (object, optional): Lock-specific parameters
- `requestedOutputs` (array, required): Desired output tokens and destinations
  - `receiver` (string): Receiver address in ERC-7930 interoperable format
  - `asset` (string): Asset address in ERC-7930 interoperable format
  - `amount` (string): Desired amount as a decimal string
  - `calldata` (string, optional): Optional calldata for the output
- `minValidUntil` (number, optional): Minimum quote validity duration in seconds
- `preference` (string, optional): User preference for optimization
  - `"price"`: Optimize for lowest cost
  - `"speed"`: Optimize for fastest execution
  - `"input-priority"`: Prioritize specific input tokens (order significant)
  - `"trust-minimization"`: Maximum trust minimization

**Response:**

For **Permit2 Escrow** orders (`lockType: "permit2_escrow"`):

```json
{
  "quotes": [
    {
      "orders": [
        {
          "signatureType": "eip712",
          "domain": {
            "name": "Permit2",
            "chainId": "1",
            "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3"
          },
          "primaryType": "PermitBatchWitnessTransferFrom",
          "message": {
            "permitted": [
              {
                "token": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
                "amount": "1000000000000000000"
              }
            ],
            "spender": "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0",
            "nonce": "123456789",
            "deadline": "1234567890",
            "witness": {
              "expires": "1234567890",
              "inputOracle": "0xDf7C8BD0DfC2F3F3a7d46F8D4c5C5C5C5C5C5C5C",
              "outputs": [
                {
                  "oracle": "0x000000000000000000000000DdDdDdDdDdDdDdDdDdDdDdDdDdDdDdDdDdDdDdDd",
                  "settler": "0x000000000000000000000000CcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCc",
                  "chainId": "31338",
                  "token": "0x0000000000000000000000005FbDB2315678afecb367f032d93F642f64180aa3",
                  "amount": "990000000000000000",
                  "recipient": "0x00000000000000000000000070997970C51812dc3A010C7d01b50e0d17dc79C8",
                  "call": "0x",
                  "context": "0x"
                }
              ]
            }
          }
        }
      ],
      "details": {
        "requestedOutputs": [
          {
            "receiver": "31338:0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
            "asset": "31338:0x5FbDB2315678afecb367f032d93F642f64180aa3",
            "amount": "990000000000000000",
            "calldata": null
          }
        ],
        "availableInputs": [
          {
            "user": "1:0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1",
            "asset": "1:0x5FbDB2315678afecb367f032d93F642f64180aa3",
            "amount": "1000000000000000000",
            "lock": null
          }
        ]
      },
      "validUntil": 1234567890,
      "eta": 300,
      "quoteId": "quote_abc123",
      "provider": "oif-solver",
      "lockType": "permit2_escrow",
      "cost": {
        "totalFee": "10000000000000000",
        "gasEstimate": "150000",
        "breakdown": {
          "solverFee": "5000000000000000",
          "gasCost": "5000000000000000"
        }
      }
    }
  ]
}
```

For **TheCompact Resource Lock** orders (`lockType: "compact_resource_lock"`):

```json
{
  "quotes": [
    {
      "orders": [
        {
          "signatureType": "eip712",
          "domain": {
            "name": "TheCompact",
            "version": "1",
            "chainId": "1",
            "verifyingContract": "0x00000000009aF2B3Cf5D78eb6C28A1F9dB8E1234"
          },
          "primaryType": "BatchCompact",
          "message": {
            "arbiter": "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0",
            "sponsor": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1",
            "nonce": "1234567890123",
            "expires": "1234567890",
            "commitments": [
              {
                "lockTag": "0x000000000000000000000000",
                "token": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
                "amount": "1000000000000000000"
              }
            ],
            "mandate": {
              "fillDeadline": "1234567890",
              "inputOracle": "0xDf7C8BD0DfC2F3F3a7d46F8D4c5C5C5C5C5C5C5C",
              "outputs": [
                {
                  "oracle": "0x000000000000000000000000DdDdDdDdDdDdDdDdDdDdDdDdDdDdDdDdDdDdDdDd",
                  "settler": "0x000000000000000000000000CcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCc",
                  "chainId": "31338",
                  "token": "0x0000000000000000000000005FbDB2315678afecb367f032d93F642f64180aa3",
                  "amount": "990000000000000000",
                  "recipient": "0x00000000000000000000000070997970C51812dc3A010C7d01b50e0d17dc79C8",
                  "call": "0x",
                  "context": "0x"
                }
              ]
            },
            "digest": "0xabcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
            "eip712": {
              "types": "...",
              "domain": "...",
              "primaryType": "BatchCompact",
              "message": "..."
            }
          }
        }
      ],
      "details": {
        "requestedOutputs": [
          {
            "receiver": "31338:0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
            "asset": "31338:0x5FbDB2315678afecb367f032d93F642f64180aa3",
            "amount": "990000000000000000",
            "calldata": null
          }
        ],
        "availableInputs": [
          {
            "user": "1:0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1",
            "asset": "1:0x5FbDB2315678afecb367f032d93F642f64180aa3",
            "amount": "1000000000000000000",
            "lock": null
          }
        ]
      },
      "validUntil": 1234567890,
      "eta": 300,
      "quoteId": "quote_def456",
      "provider": "oif-solver",
      "lockType": "compact_resource_lock",
      "cost": {
        "totalFee": "8000000000000000",
        "gasEstimate": "120000",
        "breakdown": {
          "solverFee": "4000000000000000",
          "gasCost": "4000000000000000"
        }
      }
    }
  ]
}
```

**Response Fields:**

- `quotes` (array): Array of available quote options
  - `orders` (array): EIP-712 compliant order structures ready for signing
    - `signatureType` (string): Signature type ("eip712" or "erc3009")
    - `domain` (object): EIP-712 domain object with contract details
    - `primaryType` (string): Primary type for EIP-712 signing
    - `message` (object): Complete message object to be signed
  - `details` (object): Quote details matching the original request structure
    - `requestedOutputs` (array): Requested outputs from the original request
    - `availableInputs` (array): Available inputs from the original request
  - `validUntil` (number, optional): Quote validity timestamp
  - `eta` (number, optional): Estimated time to completion in seconds
  - `quoteId` (string): Unique quote identifier
  - `provider` (string): Provider identifier
  - `cost` (object, optional): Cost breakdown
    - `totalFee` (string): Total fee in wei
    - `gasEstimate` (string): Estimated gas cost
    - `breakdown` (object): Detailed cost breakdown
  - `lockType` (string): Settlement mechanism type

**Signature Types:**

- `eip712`: EIP-712 structured data signing

## User Signing Process

**Important**: Users must manually compute the EIP-712 digest and sign it. The quote response provides the standard EIP-712 components but does not include a pre-computed digest.

### Required Steps:

1. **Extract Signing Components** from each `order` in the quote:

   - `domain`: EIP-712 domain object
   - `primaryType`: The main struct type (e.g., "PermitBatchWitnessTransferFrom")
   - `message`: The structured data to sign

2. **Compute EIP-712 Digest**: Use standard EIP-712 hashing with the provided components

3. **Sign the Digest**: Use your wallet/library to sign the EIP-712 structured data

### Domain Object Structure:

The `domain` field contains a structured object, not a string:

```json
{
  "name": "Permit2",
  "chainId": 1,
  "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3"
}
```

### EIP-712 Type Definitions:

For **Permit2** orders (`primaryType: "PermitBatchWitnessTransferFrom"`):

```javascript
const types = {
  PermitBatchWitnessTransferFrom: [
    { name: "permitted", type: "TokenPermissions[]" },
    { name: "spender", type: "address" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" },
    { name: "witness", type: "Witness" },
  ],
  TokenPermissions: [
    { name: "token", type: "address" },
    { name: "amount", type: "uint256" },
  ],
  Witness: [
    { name: "expires", type: "uint256" },
    { name: "inputOracle", type: "address" },
    { name: "outputs", type: "Output[]" },
  ],
  Output: [
    { name: "oracle", type: "bytes32" },
    { name: "settler", type: "bytes32" },
    { name: "chainId", type: "uint256" },
    { name: "token", type: "bytes32" },
    { name: "amount", type: "uint256" },
    { name: "recipient", type: "bytes32" },
    { name: "call", type: "bytes" },
    { name: "context", type: "bytes" },
  ],
};
```

For **TheCompact Resource Lock** orders (`primaryType: "CompactLock"` or `primaryType: "BatchCompact"`):

```javascript
const types = {
  BatchCompact: [
    { name: "arbiter", type: "address" },
    { name: "sponsor", type: "address" },
    { name: "nonce", type: "uint256" },
    { name: "expires", type: "uint256" },
    { name: "commitments", type: "Lock[]" },
    { name: "mandate", type: "Mandate" },
  ],
  Lock: [
    { name: "lockTag", type: "bytes12" },
    { name: "token", type: "address" },
    { name: "amount", type: "uint256" },
  ],
  Mandate: [
    { name: "fillDeadline", type: "uint32" },
    { name: "inputOracle", type: "address" },
    { name: "outputs", type: "MandateOutput[]" },
  ],
  MandateOutput: [
    { name: "oracle", type: "bytes32" },
    { name: "settler", type: "bytes32" },
    { name: "chainId", type: "uint256" },
    { name: "token", type: "bytes32" },
    { name: "amount", type: "uint256" },
    { name: "recipient", type: "bytes32" },
    { name: "call", type: "bytes" },
    { name: "context", type: "bytes" },
  ],
};
```

**Example:**

```bash
curl -X POST http://localhost:3000/api/quotes \
  -H "Content-Type: application/json" \
  -d '{
    "user": "1:0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1",
    "availableInputs": [
      {
        "user": "1:0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1",
        "asset": "1:0x5FbDB2315678afecb367f032d93F642f64180aa3",
        "amount": "1000000000000000000",
        "lock": null
      }
    ],
    "requestedOutputs": [
      {
        "receiver": "31338:0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "asset": "31338:0x5FbDB2315678afecb367f032d93F642f64180aa3",
        "amount": "990000000000000000",
        "calldata": null
      }
    ],
    "minValidUntil": 300,
    "preference": "price"
  }'
```

### Authentication

#### Register Client

**POST** `/api/auth/register`

Register a new client and receive both access and refresh tokens for API authentication. This endpoint allows self-service registration for API access with dual-token authentication.

**Request Body:**

```json
{
  "client_id": "my-app-v1.0",
  "client_name": "My Trading Application"
}
```

**Parameters:**

- `client_id` (string, required): Unique identifier for your client (3-100 characters)
- `client_name` (string, optional): Display name for your application
- `scopes` (array, optional): Requested permissions (defaults to ["read-orders"])

**Available Scopes:**

- `read-orders`: Retrieve order status and details
- `create-orders`: Submit new orders
- `admin-all`: Full administrative access

**Response:**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "client_id": "my-app-v1.0",
  "access_token_expires_at": 1234567890,
  "refresh_token_expires_at": 1234567890,
  "scopes": ["read-orders", "create-orders"],
  "token_type": "Bearer"
}
```

**Response Fields:**

- `access_token`: JWT access token for API requests (short-lived, typically 1 hour)
- `refresh_token`: JWT refresh token for obtaining new access tokens (long-lived, typically 30 days)
- `client_id`: Your client identifier
- `access_token_expires_at`: Unix timestamp when access token expires
- `refresh_token_expires_at`: Unix timestamp when refresh token expires
- `scopes`: Granted permissions
- `token_type`: Always "Bearer"

**Example:**

```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "my-trading-bot",
    "client_name": "Advanced Trading Bot",
    "scopes": ["read-orders", "create-orders"]
  }'
```

**Using the Access Token:**

Include the access token in subsequent API requests:

```bash
curl -X POST http://localhost:3000/api/orders \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{"order_data": "..."}'
```

#### Refresh Token

**POST** `/api/auth/refresh`

Exchange a valid refresh token for new access and refresh tokens. This endpoint allows you to obtain fresh tokens without re-authentication. The old refresh token is invalidated and cannot be reused.

**Request Body:**

```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Parameters:**

- `refresh_token` (string, required): The refresh token obtained from registration or previous refresh

**Response:**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "client_id": "my-app-v1.0",
  "access_token_expires_at": 1234567890,
  "refresh_token_expires_at": 1234567890,
  "scopes": ["read-orders", "create-orders"],
  "token_type": "Bearer"
}
```

**Response Fields:**

- `access_token`: New JWT access token for API requests
- `refresh_token`: New JWT refresh token (the old one is invalidated)
- `client_id`: Your client identifier
- `access_token_expires_at`: Unix timestamp when new access token expires
- `refresh_token_expires_at`: Unix timestamp when new refresh token expires
- `scopes`: Your granted permissions (same as original registration)
- `token_type`: Always "Bearer"

**Example:**

```bash
curl -X POST http://localhost:3000/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'
```

**Token Lifecycle:**

1. **Register**: Get initial access + refresh tokens via `/api/auth/register`
2. **Use Access Token**: Make API calls with the access token in Authorization header
3. **Refresh**: Before access token expires, use `/api/auth/refresh` to get new tokens
4. **Repeat**: Continue using the refresh cycle to maintain authentication

**Security Notes:**

- Access tokens are short-lived (typically 1 hour) for security
- Refresh tokens are long-lived (typically 30 days) but are invalidated after use
- Store refresh tokens securely and never expose them in client-side code
- Token expiry times are configured server-side and cannot be modified via API

### Orders

#### Submit Intent Order

**POST** `/api/orders`

Submit cross-chain intent orders for execution. This endpoint accepts both EIP-7683 compliant orders and quote acceptance requests. Orders are forwarded to the configured discovery service for processing.

**Authentication:** Requires `create-orders` scope when JWT authentication is enabled.

**Request Body Options:**

**Option 1: Quote Acceptance**

```json
{
  "quoteId": "quote_id",
  "signature": "0x1234567890abcdef..."
}
```

**Option 2: Direct Order Submission**

```json
{
  "order": "0x00000000000000000000000000000000...",
  "sponsor": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "signature": "0x1234..."
}
```

**Parameters:**

For Quote Acceptance:

- `quoteId` (string, required): ID of a previously generated quote
- `signature` (string, required): EIP-712 signature accepting the quote terms

For Direct Submission:

- `order` (string, required): ABI-encoded EIP-7683 order data in hexadecimal format
- `sponsor` (string, required): Ethereum address of the user sponsoring the order
- `signature` (string, required): EIP-712 cryptographic signature of the order

**Response:**

The response format depends on the configured discovery service and request type.

**For Quote Acceptance (Not Yet Implemented):**

```json
{
  "error": "Quote acceptance not yet implemented",
  "message": "Quote ID submission is recognized but not yet supported",
  "quoteId": "quote_abc123",
  "status": "pending_implementation"
}
```

**For Direct Order Submission:**

```json
{
  "status": "success",
  "order_id": "1fa518079ecf01372290adf75c55858771efcbcee080594cc8bc24e3309a3a09",
  "message": null
}
```

**Error Response:**

```json
{
  "error": "Failed to submit intent: network error"
}
```

**Examples:**

**Quote Acceptance:**

```bash
curl -X POST http://localhost:3000/api/orders \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "quoteId": "quote_abc123",
    "signature": "0x1234567890abcdef..."
  }'
```

**Direct Order Submission:**

```bash
curl -X POST http://localhost:3000/api/orders \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "order": "0x00000000000000000000000000000000...",
    "sponsor": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    "signature": "0x1234..."
  }'
```

**Note:** Order submission requires the `offchain_eip7683` discovery source to be configured in the solver settings.

#### Get Order Status

**GET** `/api/orders/{order_id}`

Retrieve the current status and details of a submitted order.

**Authentication:** Requires `read-orders` scope when JWT authentication is enabled.

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
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  http://localhost:3000/api/orders/1fa518079ecf01372290adf75c55858771efcbcee080594cc8bc24e3309a3a09
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

# Optional JWT authentication
[api.auth]
enabled = false            # Enable JWT authentication (defaults to false)
issuer = "oif-solver"      # JWT issuer name
jwt_secret = "your-secret-key-token"  # JWT secret for token validation

# Optional quote settings
[api.quote]
validity_seconds = 300     # Quote validity period (5 minutes)
```

## Next Steps

- Learn about creating orders in the [Demo Guide](demo.md)
- Understand the solver architecture in the [Developer Documentation](../DEVELOPER_DOCUMENTATION.md)
- Explore advanced configuration in the [Configuration Guide](configuration.md)
