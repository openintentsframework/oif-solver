//! ERC-7683 Off-chain Intent Discovery API Implementation
//!
//! This module implements an HTTP API server that accepts ERC-7683 cross-chain intents
//! directly from users or other systems. It provides an endpoint for receiving
//! gasless cross-chain orders that follow the ERC-7683 standard.
//!
//! ## Overview
//!
//! The ERC-7683 standard defines a universal cross-chain intent framework that enables:
//! - Users to express cross-chain intents with gasless order submission
//! - Solvers/fillers to discover and fulfill these intents across chains
//! - Settlement through standardized contracts on origin and destination chains
//!
//! ## Architecture
//!
//! This implementation:
//! 1. Spins up an HTTP API server with intent submission endpoints
//! 2. Receives GaslessCrossChainOrder intents via POST requests
//! 3. Validates and normalizes the intent data
//! 4. Publishes validated intents to the solver's event bus
//! 5. Enables the delivery service to pick up and process these intents
//!
//! ## Intent Flow
//!
//! 1. **Submission**: Users POST GaslessCrossChainOrder to `/intents` endpoint
//! 2. **Validation**: Verify intent structure matches ERC-7683 standard
//! 3. **Normalization**: Convert to internal Intent representation
//! 4. **Publication**: Emit to event bus for downstream processing
//! 5. **Response**: Return intent ID and status to submitter
//!
//! ## Implementation Requirements
//!
//! To complete this implementation:
//!
//! 1. **API Server Setup**
//!    - Create HTTP server (e.g., using Axum, Actix-web, or Warp)
//!    - Define POST `/intents` endpoint
//!    - Implement request parsing and validation
//!    - Add health check and metrics endpoints
//!
//! 2. **Intent Recognition**
//!    - Parse GaslessCrossChainOrder structure from request body
//!    - Validate all required fields are present
//!    - Check signature validity (if provided)
//!    - Verify deadlines haven't expired
//!
//! 3. **Event Bus Integration**
//!    - Convert validated intents to internal Intent type
//!    - Publish to the configured event bus topic
//!    - Handle retry logic for failed publications
//!
//! ## GaslessCrossChainOrder Structure
//!
//! The standard ERC-7683 order structure that this module processes:
//!
//! ```solidity
//! struct GaslessCrossChainOrder {
//!     address originSettler;      // Settlement contract on origin chain
//!     address user;              // User initiating the cross-chain swap
//!     uint256 nonce;            // Replay protection nonce
//!     uint256 originChainId;    // Chain ID where order originates
//!     uint32 openDeadline;      // Deadline to open the order
//!     uint32 fillDeadline;      // Deadline to fill on destination
//!     bytes32 orderDataType;    // EIP-712 typehash for order data
//!     bytes orderData;          // Order-specific data (tokens, amounts, etc.)
//! }
//! ```
//!
//! ## Configuration
//!
//! Expected configuration parameters:
//! - `api_port`: Port to bind the HTTP server (default: 8080)
//! - `api_host`: Host address to bind (default: 0.0.0.0)
//! - `auth_token`: Optional bearer token for API authentication
//! - `rate_limit`: Max requests per minute per IP (default: 100)
//! - `event_bus_topic`: Where to publish discovered intents
//!
//! ## API Endpoints
//!
//! - `POST /intent` - Submit a new GaslessCrossChainOrder
//! - `GET /intent/{orderId}` - Get the status of submitted intent
//!
//! ## Example Usage
//!
//! ```rust
//! // Initialize the discovery API server
//! let discovery = Erc7683OffchainDiscovery::new(config)?;
//!
//! // Start the API server
//! discovery.start_server().await?;
//!
//! // Server now accepts POST requests with GaslessCrossChainOrder
//! // at http://localhost:8080/intent
//! ```
//!
//! ## Example API Request
//!
//! ```bash
//! curl -X POST http://localhost:8080/intent \
//!   -H "Content-Type: application/json" \
//!   -H "Authorization: Bearer YOUR_TOKEN" \
//!   -d '{
//!     "originSettler": "0x...",
//!     "user": "0x...",
//!     "nonce": "123",
//!     "originChainId": "1",
//!     "openDeadline": 1234567890,
//!     "fillDeadline": 1234567900,
//!     "orderDataType": "0x...",
//!     "orderData": "0x..."
//!   }'
//! ```
//!
//! ## Security Considerations
//!
//! - Validate all intent data before processing
//! - Verify signatures match the claimed user address
//! - Check deadlines haven't expired
//! - Rate limit API requests to prevent abuse
//! - Use secure storage for API credentials
//!
//! ## TODO Implementation Steps
//!
//! 1. Define the API server structure and routes
//! 2. Implement GaslessCrossChainOrder request handler
//! 3. Create intent parser and validator
//! 4. Integrate with solver's event bus
//! 5. Add authentication and rate limiting middleware
//! 6. Implement monitoring and metrics collection
//! 7. Write comprehensive tests for all endpoints
