# Solver Service Documentation

**Version**: 0.1.0  
**Crate**: `solver-service`  
**Binary**: `solver`  
**Architecture**: HTTP API Service Layer for Cross-Chain Intent Execution

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Architecture Overview](#architecture-overview)
3. [Core Components](#core-components)
4. [API Endpoints](#api-endpoints)
5. [Authentication System](#authentication-system)
6. [Quote Processing Pipeline](#quote-processing-pipeline)
7. [Order Processing](#order-processing)
8. [Signature Validation](#signature-validation)
9. [Factory Registry Pattern](#factory-registry-pattern)
10. [Security Considerations](#security-considerations)
11. [Configuration](#configuration)
12. [Error Handling](#error-handling)

---

## Executive Summary

The `solver-service` crate is the **HTTP API service layer** that exposes the OIF (Open Intent Framework) solver functionality to external clients. It provides a production-ready REST API for:

- **Quote Generation**: Creating executable cross-chain swap quotes with cryptographic signatures
- **Order Submission**: Validating and forwarding orders to discovery services
- **Order Tracking**: Retrieving order status and execution details
- **Token Discovery**: Querying supported tokens and networks
- **Authentication**: JWT-based API access control with scope-based permissions

### Key Characteristics

- **Framework**: Built on Axum 0.8 (async web framework)
- **Architecture**: Clean separation between API layer and business logic (solver-core)
- **Modularity**: Plugin-based factory registry for implementation swapping
- **Security**: EIP-712 signature validation, JWT authentication, CORS support
- **Standards Support**: EIP-7683 (cross-chain intents), EIP-3009 (gasless transfers), Permit2

---

## Architecture Overview

### High-Level Design

```
┌─────────────────────────────────────────────────────────────┐
│                     solver-service                           │
│                                                              │
│  ┌────────────┐     ┌──────────────┐     ┌──────────────┐ │
│  │   main.rs  │────▶│  server.rs   │────▶│     APIs     │ │
│  │  (binary)  │     │ (HTTP setup) │     │  (handlers)  │ │
│  └────────────┘     └──────────────┘     └──────────────┘ │
│         │                                         │         │
│         │                                         │         │
│         ▼                                         ▼         │
│  ┌────────────────┐                    ┌──────────────────┐│
│  │factory_registry│                    │   Middleware     ││
│  │  (plugin sys)  │                    │ (auth, cors...)  ││
│  └────────────────┘                    └──────────────────┘│
│         │                                         │         │
└─────────┼─────────────────────────────────────────┼─────────┘
          │                                         │
          ▼                                         ▼
 ┌─────────────────┐                    ┌──────────────────┐
 │  solver-core    │                    │   External APIs  │
 │ (business logic)│                    │  (discovery...)  │
 └─────────────────┘                    └──────────────────┘
```

### Request Flow

1. **HTTP Request** → Axum Router
2. **Middleware** → Authentication (if enabled), CORS, normalization
3. **Handler** → Extract parameters, validate input
4. **Business Logic** → Delegate to solver-core services
5. **Response** → Serialize and return JSON

---

## Core Components

### 1. Main Entry Point (`main.rs`)

**Purpose**: Binary entrypoint that orchestrates system startup

```rust:main.rs
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    // Initialize tracing with env filter
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(args.log_level));
    
    // Load configuration
    let config = Config::from_file(args.config).await?;
    
    // Build solver engine with implementations using the factory registry
    let solver = build_solver_from_config(config.clone()).await?;
    let solver = Arc::new(solver);
    
    // Check if API server should be started
    if config.api.as_ref().is_some_and(|api| api.enabled) {
        // Start both the solver and the API server concurrently
        tokio::select! {
            result = solver.run() => result?,
            result = server::start_server(api_config, api_solver) => result?,
        }
    } else {
        solver.run().await?;
    }
    
    Ok(())
}
```

**Key Responsibilities**:
- Parse CLI arguments (config path, log level)
- Initialize structured logging (tracing-subscriber)
- Load TOML configuration
- Build solver engine via factory registry
- Conditionally start API server alongside solver
- Handle graceful shutdown

**Design Pattern**: Uses `tokio::select!` to run solver and API server concurrently, allowing either to terminate the application.

---

### 2. HTTP Server (`server.rs`)

**Purpose**: Configure and run the Axum HTTP server

#### Application State

```rust:server.rs
#[derive(Clone)]
pub struct AppState {
    pub solver: Arc<SolverEngine>,
    pub config: Config,
    pub http_client: reqwest::Client,
    pub discovery_url: Option<String>,
    pub jwt_service: Option<Arc<JwtService>>,
    pub signature_validation: Arc<SignatureValidationService>,
}
```

**State Components**:
- `solver`: Reference to core business logic engine
- `config`: Full system configuration
- `http_client`: Reusable HTTP client with connection pooling
- `discovery_url`: Pre-formatted URL for order forwarding
- `jwt_service`: Optional authentication service
- `signature_validation`: Signature verification for orders

#### Server Configuration

```rust:server.rs
pub async fn start_server(
    api_config: ApiConfig,
    solver: Arc<SolverEngine>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create HTTP client with connection pooling
    let http_client = reqwest::Client::builder()
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(10)
        .timeout(Duration::from_secs(30))
        .build()?;
    
    // Initialize JWT service if auth is enabled
    let jwt_service = match &api_config.auth {
        Some(auth_config) if auth_config.enabled => {
            Some(Arc::new(JwtService::new(auth_config.clone())?))
        },
        _ => None,
    };
    
    // Build router with /api base path
    let app = Router::new()
        .nest("/api", api_routes)
        .layer(ServiceBuilder::new().layer(CorsLayer::permissive()))
        .with_state(app_state);
    
    let listener = TcpListener::bind(&bind_address).await?;
    axum::serve(listener, NormalizePath::trim_trailing_slash(app)).await?;
    
    Ok(())
}
```

**Middleware Stack**:
1. **CORS**: Permissive policy for cross-origin requests
2. **Path Normalization**: Handles trailing slashes
3. **Authentication**: Scope-based JWT verification (conditional)

#### Route Structure

```
/api
├── /quotes (POST) - Generate price quotes
├── /orders (POST) - Submit orders [AUTH: CreateOrders]
├── /orders/{id} (GET) - Get order details [AUTH: ReadOrders]
├── /tokens (GET) - List all tokens
├── /tokens/{chain_id} (GET) - List chain-specific tokens
└── /auth
    ├── /register (POST) - Client registration
    └── /refresh (POST) - Token refresh
```

---

### 3. Factory Registry (`factory_registry.rs`)

**Purpose**: Dynamic dependency injection for solver implementations

#### Architecture

```rust:factory_registry.rs
// Type aliases for factory functions
pub type StorageFactory = fn(&toml::Value) 
    -> Result<Box<dyn StorageInterface>, StorageError>;
pub type AccountFactory = fn(&toml::Value) 
    -> Result<Box<dyn AccountInterface>, AccountError>;
// ... similar for all other interfaces
```

#### Registry Structure

```rust:factory_registry.rs
pub struct FactoryRegistry {
    pub storage: HashMap<String, StorageFactory>,
    pub account: HashMap<String, AccountFactory>,
    pub delivery: HashMap<String, DeliveryFactory>,
    pub discovery: HashMap<String, DiscoveryFactory>,
    pub order: HashMap<String, OrderFactory>,
    pub pricing: HashMap<String, PricingFactory>,
    pub settlement: HashMap<String, SettlementFactory>,
    pub strategy: HashMap<String, StrategyFactory>,
}
```

#### Initialization Pattern

```rust:factory_registry.rs
pub fn initialize_registry() -> &'static FactoryRegistry {
    REGISTRY.get_or_init(|| {
        let mut registry = FactoryRegistry::new();
        
        // Auto-register all storage implementations
        for (name, factory) in solver_storage::get_all_implementations() {
            registry.register_storage(name, factory);
        }
        
        // ... repeat for all interface types
        
        registry
    })
}
```

**Key Features**:
- **Lazy Initialization**: Uses `once_cell::OnceLock` for thread-safe singleton
- **Auto-Discovery**: Implementations self-register via exported functions
- **Type Safety**: Strong typing through trait objects
- **Configuration-Driven**: Maps TOML config keys to factory functions

#### Building the Solver

```rust:factory_registry.rs
pub async fn build_solver_from_config(
    config: Config,
) -> Result<SolverEngine, Box<dyn std::error::Error>> {
    let registry = get_registry();
    let builder = SolverBuilder::new(config.clone());
    
    // Build factories for each component type
    let storage_factories = build_factories!(
        registry, 
        config.storage.implementations, 
        storage, 
        "storage"
    );
    // ... similar for all other types
    
    let factories = SolverFactories {
        storage_factories,
        account_factories,
        delivery_factories,
        // ...
    };
    
    Ok(builder.build(factories).await?)
}
```

**Design Pattern**: Abstract Factory + Registry pattern for plugin architecture

---

## API Endpoints

### 1. Quote Endpoint (`/api/quotes`)

**Method**: `POST`  
**Authentication**: None (public endpoint)  
**Purpose**: Generate executable cross-chain swap quotes

#### Request Schema

```json
{
  "user": "0x01000001011234...", // ERC-7930 InteropAddress
  "intent": {
    "intentType": "oif-swap",
    "inputs": [{
      "user": "0x01000001011234...",
      "asset": "0x01000001011234...", // Token address
      "amount": "1000000000000000000", // Optional for ExactOutput
      "lock": null // Optional resource lock reference
    }],
    "outputs": [{
      "receiver": "0x01000001891234...",
      "asset": "0x01000089011234...",
      "amount": "990000000000000000", // Optional for ExactInput
      "calldata": null
    }],
    "swapType": "ExactInput", // or "ExactOutput"
    "minValidUntil": 1704067200, // Optional timestamp
    "preference": "Speed", // Speed|Price|TrustMinimization|InputPriority
    "originSubmission": {
      "mode": "User",
      "schemes": ["Permit2", "Eip3009"]
    },
    "failureHandling": ["RefundAutomatic"],
    "partialFill": false,
    "metadata": {}
  },
  "supportedTypes": ["oif-escrow-v0", "oif-resource-lock-v0"]
}
```

#### Response Schema

```json
{
  "quotes": [{
    "quoteId": "uuid-v4",
    "order": {
      "OifEscrowV0": {
        "payload": {
          "signatureType": "Eip712",
          "domain": {
            "name": "Permit2",
            "chainId": "1",
            "verifyingContract": "0x000000000022D473..."
          },
          "primaryType": "PermitBatchWitnessTransferFrom",
          "message": {
            "permitted": [{"token": "0x...", "amount": "1000000"}],
            "spender": "0x...",
            "nonce": "1234567890",
            "deadline": "1704067800",
            "witness": {
              "expires": 1704067800,
              "inputOracle": "0x...",
              "outputs": [...]
            }
          },
          "types": { /* EIP-712 type definitions */ }
        }
      }
    },
    "failureHandling": "RefundAutomatic",
    "partialFill": false,
    "validUntil": 1704067800,
    "eta": 120,
    "provider": "oif-solver",
    "preview": {
      "inputs": [{"asset": "0x...", "amount": "1000000"}],
      "outputs": [{"asset": "0x...", "amount": "990000"}]
    }
  }]
}
```

#### Processing Pipeline

```
1. Validate Request Structure
   ├─ Intent type checking
   ├─ Address validation (ERC-7930)
   ├─ Supported types verification
   └─ Swap type logic validation

2. Calculate Cost Context
   ├─ Estimate gas costs
   ├─ Calculate protocol fees
   ├─ Compute pricing ratios
   └─ Adjust amounts for costs

3. Validate Capabilities
   ├─ Check network support
   ├─ Verify token availability
   ├─ Confirm sufficient balances
   └─ Validate settlement routes

4. Generate Quotes
   ├─ Decide custody mechanisms
   │  ├─ Resource locks (TheCompact)
   │  └─ Escrow (Permit2/EIP-3009)
   ├─ Build signature payloads
   ├─ Calculate ETAs and expiry
   └─ Sort by preference

5. Store and Return
   ├─ Persist with TTL
   └─ Return quote array
```

**Code Reference**:
```rust:apis/quote/mod.rs
pub async fn process_quote_request(
    request: GetQuoteRequest,
    solver: &SolverEngine,
    config: &Config,
) -> Result<GetQuoteResponse, QuoteError> {
    // Validation
    let validated_context = QuoteValidator::validate_quote_request(&request, solver)?;
    
    // Cost calculation
    let cost_context = cost_profit_service
        .calculate_cost_context(&request, &validated_context, config)
        .await?;
    
    // Quote generation
    let quotes = quote_generator
        .generate_quotes_with_costs(&request, &validated_context, &cost_context, config)
        .await?;
    
    // Persistence
    store_quotes(solver, &quotes, &cost_context).await;
    
    Ok(GetQuoteResponse { quotes })
}
```

---

### 2. Order Endpoint (`/api/orders`)

**Method**: `POST`  
**Authentication**: Required (`CreateOrders` scope)  
**Purpose**: Submit signed orders to discovery service

#### Request Types

**Type 1: Quote Acceptance**
```json
{
  "quoteId": "uuid-from-quote-endpoint",
  "signature": "0x1234..." // User's EIP-712 signature
}
```

**Type 2: Direct Submission**
```json
{
  "order": {
    "OifEscrowV0": {
      "payload": {
        "signatureType": "Eip712",
        "domain": {...},
        "primaryType": "PermitBatchWitnessTransferFrom",
        "message": {...},
        "types": {...}
      }
    }
  },
  "sponsor": "0x01000001011234...",
  "signature": "0x1234...",
  "lockType": "Permit2Escrow"
}
```

#### Processing Flow

```rust:server.rs
async fn handle_order(
    State(state): State<AppState>,
    claims: Option<Extension<JwtClaims>>,
    Json(payload): Json<Value>,
) -> axum::response::Response {
    // 1. Extract intent request (quote acceptance or direct)
    let intent_request = extract_intent_request(payload, &state, "eip7683").await?;
    
    // 2. Validate the order
    let order = validate_intent_request(&intent_request, &state, "eip7683").await?;
    
    // 3. Forward to discovery service
    forward_to_discovery_service(&state, &intent_request).await
}
```

**Validation Steps**:
1. **Quote Retrieval**: If `quoteId` present, fetch from storage
2. **Signature Recovery**: Extract sponsor address from signature
3. **User Injection**: For Permit2, inject recovered user into message
4. **EIP-712 Validation**: Verify signature against domain separator
5. **Order Creation**: Build `Order` object with order ID callback
6. **Forwarding**: POST to discovery service URL

**Special Handling: Permit2 User Injection**

```rust:server.rs
// If this order requires ecrecover, inject the recovered user
if intent.order.requires_ecrecover() {
    let sponsor = intent.order.extract_sponsor(Some(&intent.signature))?;
    
    // Inject the recovered user into Permit2 orders
    if let solver_types::OifOrder::OifEscrowV0 { payload } = &mut intent.order {
        if let Some(message_obj) = payload.message.as_object_mut() {
            message_obj.insert(
                "user".to_string(),
                serde_json::Value::String(sponsor.to_string()),
            );
        }
    }
}
```

**Why?** Permit2 orders don't include the `user` field in the signature payload. The user address is recovered from the signature and must be injected before forwarding to the discovery service.

---

### 3. Get Order Endpoint (`/api/orders/{id}`)

**Method**: `GET`  
**Authentication**: Required (`ReadOrders` scope)  
**Purpose**: Retrieve order status and execution details

#### Response Schema

```json
{
  "order": {
    "id": "0x1234...",
    "status": "Executed",
    "createdAt": 1704060000,
    "updatedAt": 1704067800,
    "quoteId": "uuid-optional",
    "inputAmounts": [{
      "asset": "0x01000001011234...", // InteropAddress with chain
      "amount": "1000000000000000000"
    }],
    "outputAmounts": [{
      "asset": "0x01000089891234...",
      "amount": "990000000000000000"
    }],
    "settlement": {
      "settlementType": "Escrow",
      "data": {
        "rawOrderData": {},
        "signature": "0x...",
        "nonce": "42",
        "expires": "1704067800"
      }
    },
    "fillTransaction": {
      "hash": "0xabcd...",
      "status": "executed",
      "timestamp": 1704067800
    }
  }
}
```

#### Order Status Values

```rust
pub enum OrderStatus {
    Created,
    Pending,
    Executing,
    Executed,
    PostFilled,
    PreClaimed,
    Settled,
    Finalized,
    Failed(TransactionType),
}
```

**Status Transitions**:
```
Created → Pending → Executing → Executed → PostFilled → PreClaimed → Settled → Finalized
   ↓         ↓          ↓           ↓            ↓            ↓          ↓
Failed     Failed    Failed      Failed       Failed       Failed    Failed
```

#### Implementation Details

```rust:apis/order.rs
async fn process_order_request(
    order_id: &str,
    solver: &SolverEngine,
) -> Result<OrderResponse, GetOrderError> {
    // Retrieve order from storage
    let order = solver
        .storage()
        .retrieve::<Order>(StorageKey::Orders.as_str(), order_id)
        .await?;
    
    // Convert to API response format
    convert_order_to_response(order).await
}
```

**EIP-7683 Conversion**:
- Extracts `inputs` and `outputs` arrays from order data
- Converts token addresses from bytes32 to InteropAddress format
- Determines fill transaction status based on order status
- Builds settlement metadata from raw order data

---

### 4. Tokens Endpoint (`/api/tokens`)

**Method**: `GET`  
**Authentication**: None (public endpoint)  
**Purpose**: List all supported tokens across all networks

#### Response Schema

```json
{
  "networks": {
    "1": {
      "chainId": 1,
      "inputSettler": "0x...",
      "outputSettler": "0x...",
      "tokens": [
        {
          "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
          "symbol": "USDC",
          "decimals": 6
        },
        {
          "address": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
          "symbol": "USDT",
          "decimals": 6
        }
      ]
    },
    "137": {
      "chainId": 137,
      "inputSettler": "0x...",
      "outputSettler": "0x...",
      "tokens": [...]
    }
  }
}
```

**Purpose**: Enables clients to:
- Discover available trading pairs
- Get token contract addresses for transactions
- Identify settlement contract addresses
- Build UI dropdowns for token selection

---

## Authentication System

### Architecture

The authentication system implements **JWT (JSON Web Token)** based authentication with:
- **Access Tokens**: Short-lived (1 hour default) for API requests
- **Refresh Tokens**: Long-lived (30 days default) for obtaining new access tokens
- **Scope-Based Authorization**: Fine-grained permissions
- **Stateless Design**: No server-side session storage

### JWT Service (`auth/mod.rs`)

```rust:auth/mod.rs
pub struct JwtService {
    config: AuthConfig,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    validation: Validation,
}
```

#### Token Generation

```rust:auth/mod.rs
pub fn generate_access_token(
    &self,
    client_id: &str,
    scopes: Vec<AuthScope>,
) -> Result<String, AuthError> {
    let claims = JwtClaims {
        sub: client_id.to_string(),
        exp: (Utc::now() + Duration::hours(expiry_hours)).timestamp(),
        iat: Utc::now().timestamp(),
        iss: self.config.issuer.clone(),
        scope: scopes,
        nonce: None, // Access tokens don't need nonces
    };
    
    encode(&Header::default(), &claims, &self.encoding_key)
        .map_err(|e| AuthError::TokenGeneration(e.to_string()))
}
```

**Refresh Token Flow**:
```rust:auth/mod.rs
pub async fn refresh_access_token(
    &self,
    refresh_token: &str,
) -> Result<(String, String), AuthError> {
    // Validate refresh token
    let claims = decode::<JwtClaims>(refresh_token, &self.decoding_key, &self.validation)?;
    
    // Check expiry
    if claims.exp <= Utc::now().timestamp() {
        return Err(AuthError::InvalidRefreshToken("Token expired".to_string()));
    }
    
    // Generate new access token
    let access_token = self.generate_access_token(&claims.sub, claims.scope.clone())?;
    
    // Generate new refresh token (token rotation for security)
    let new_refresh_token = self.generate_refresh_token(&claims.sub, claims.scope).await?;
    
    Ok((access_token, new_refresh_token))
}
```

**Token Rotation**: Each refresh generates a **new** refresh token, invalidating the old one. This enhances security by:
- Limiting token lifespan
- Detecting token theft
- Enabling revocation by expiry

### Scope System

```rust
pub enum AuthScope {
    ReadOrders,      // GET /api/orders/{id}
    CreateOrders,    // POST /api/orders
    ReadQuotes,      // GET /api/quotes (future)
    CreateQuotes,    // POST /api/quotes (future)
    AdminAll,        // All permissions
}
```

**Scope Checking**:
```rust:auth/mod.rs
pub fn check_scope(claims: &JwtClaims, required: &AuthScope) -> bool {
    claims.scope.iter().any(|s| s.grants(required))
}
```

**Grants Relationship**:
- `AdminAll` grants all scopes
- Specific scopes grant only themselves
- Future: hierarchical scopes (e.g., `Orders:*` grants all order operations)

### Middleware (`auth/middleware.rs`)

```rust:auth/middleware.rs
pub async fn auth_middleware(
    State(state): State<AuthState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    // Skip auth for OPTIONS requests (CORS preflight)
    if request.method() == Method::OPTIONS {
        return next.run(request).await;
    }
    
    // Extract bearer token
    let token = match extract_bearer_token(request.headers()) {
        Some(token) => token,
        None => return unauthorized("Missing or invalid Authorization header"),
    };
    
    // Validate token
    let claims = match state.jwt_service.validate_token(token) {
        Ok(claims) => claims,
        Err(e) => return unauthorized(&format!("Invalid token: {}", e)),
    };
    
    // Check required scope
    if !JwtService::check_scope(&claims, &state.required_scope) {
        return forbidden("Insufficient permissions");
    }
    
    // Add claims to request extensions
    request.extensions_mut().insert(claims);
    
    next.run(request).await
}
```

**Middleware Application**:
```rust:server.rs
// POST /orders requires CreateOrders scope
let order_post_route = Router::new()
    .route("/orders", post(handle_order))
    .layer(middleware::from_fn_with_state(
        AuthState {
            jwt_service: jwt.clone(),
            required_scope: AuthScope::CreateOrders,
        },
        auth_middleware,
    ));

// GET /orders/{id} requires ReadOrders scope  
let order_get_route = Router::new()
    .route("/orders/{id}", get(handle_get_order_by_id))
    .layer(middleware::from_fn_with_state(
        AuthState {
            jwt_service: jwt.clone(),
            required_scope: AuthScope::ReadOrders,
        },
        auth_middleware,
    ));
```

### Registration Endpoint (`/api/auth/register`)

**Purpose**: Self-service client registration (no admin approval required)

```rust:apis/auth.rs
pub async fn register_client(
    State(jwt_service): State<Option<Arc<JwtService>>>,
    Json(request): Json<RegisterRequest>,
) -> impl IntoResponse {
    // Validate client_id format
    if request.client_id.len() < 3 || request.client_id.len() > 100 {
        return bad_request("Client ID must be between 3 and 100 characters");
    }
    
    // Parse requested scopes or use defaults
    let scopes = parse_scopes(request.scopes)
        .unwrap_or_else(|_| vec![AuthScope::ReadOrders]);
    
    // Generate both tokens
    let access_token = jwt_service.generate_access_token(&request.client_id, scopes.clone())?;
    let refresh_token = jwt_service.generate_refresh_token(&request.client_id, scopes).await?;
    
    // Return tokens with expiry info
    Ok(RegisterResponse {
        access_token,
        refresh_token,
        client_id: request.client_id,
        access_token_expires_at: ...,
        refresh_token_expires_at: ...,
        scopes: ...,
        token_type: "Bearer",
    })
}
```

**Security Considerations**:
- **No Secrets**: Clients don't need pre-shared keys
- **Self-Service**: Automated registration for permissionless access
- **Scope Limits**: Defaults to minimal permissions (ReadOrders)
- **Rate Limiting**: Should be added for production (not implemented)

---

## Quote Processing Pipeline

The quote processing system is the most complex component, implementing a sophisticated multi-stage pipeline.

### Architecture

```
QuoteValidator        QuoteGenerator       CustodyStrategy
     │                      │                     │
     ▼                      ▼                     ▼
┌────────────┐      ┌────────────┐      ┌────────────┐
│  Validate  │─────▶│  Generate  │─────▶│   Decide   │
│  Request   │      │   Quotes   │      │  Custody   │
└────────────┘      └────────────┘      └────────────┘
     │                      │                     │
     ▼                      ▼                     ▼
ValidatedContext    Quote Objects      CustodyDecision
```

### 1. Quote Validator (`apis/quote/validation.rs`)

**Purpose**: Multi-stage request validation with comprehensive error messages

#### Validation Stages

```rust:apis/quote/validation.rs
pub fn validate_quote_request(
    request: &GetQuoteRequest,
    solver: &SolverEngine,
) -> Result<ValidatedQuoteContext, QuoteError> {
    // 1. Intent structure validation
    Self::validate_intent_structure(&request.intent)?;
    
    // 2. supportedTypes validation  
    Self::validate_supported_types(&request.supported_types, solver)?;
    
    // 3. SwapType-aware input/output validation
    let context = Self::validate_swap_type_logic(&request.intent)?;
    
    // 4. Lock and auth scheme validation
    Self::validate_capabilities(request, solver, &context)?;
    
    Ok(context)
}
```

#### Swap Type Logic

**ExactInput** (user specifies input amount):
```rust:apis/quote/validation.rs
SwapType::ExactInput => {
    // Input amounts must be provided and non-zero
    let mut known_inputs = Vec::new();
    for input in &intent.inputs {
        let amount = input.amount_as_u256()?.ok_or(QuoteError::MissingInputAmount)?;
        if amount.is_zero() {
            return Err(QuoteError::InvalidRequest("Input amount cannot be zero"));
        }
        known_inputs.push((input.clone(), amount));
    }
    
    // Output amounts are optional constraints (minimums)
    let mut constraint_outputs = Vec::new();
    for output in &intent.outputs {
        let amount = output.amount_as_u256()?; // Optional
        constraint_outputs.push((output.clone(), amount));
    }
    
    Ok(ValidatedQuoteContext {
        swap_type: SwapType::ExactInput,
        known_inputs: Some(known_inputs),
        known_outputs: None,
        constraint_inputs: None,
        constraint_outputs: Some(constraint_outputs),
    })
}
```

**ExactOutput** (user specifies output amount):
```rust:apis/quote/validation.rs
SwapType::ExactOutput => {
    // Output amounts must be provided and non-zero
    let mut known_outputs = Vec::new();
    for output in &intent.outputs {
        let amount = output.amount_as_u256()?.ok_or(QuoteError::MissingOutputAmount)?;
        if amount.is_zero() {
            return Err(QuoteError::InvalidRequest("Output amount cannot be zero"));
        }
        known_outputs.push((output.clone(), amount));
    }
    
    // Input amounts are optional constraints (maximums)
    let mut constraint_inputs = Vec::new();
    for input in &intent.inputs {
        let amount = input.amount_as_u256()?; // Optional
        constraint_inputs.push((input.clone(), amount));
    }
    
    Ok(ValidatedQuoteContext {
        swap_type: SwapType::ExactOutput,
        known_inputs: None,
        known_outputs: Some(known_outputs),
        constraint_inputs: Some(constraint_inputs),
        constraint_outputs: None,
    })
}
```

**Key Insight**: The `ValidatedQuoteContext` distinguishes between:
- **Known amounts**: User-specified, must be exact
- **Constraint amounts**: Optional limits (minimums for outputs, maximums for inputs)

#### Network and Token Validation

```rust:apis/quote/validation.rs
pub fn validate_supported_networks(
    request: &GetQuoteRequest,
    solver: &SolverEngine,
) -> Result<(), QuoteError> {
    let networks = solver.token_manager().get_networks();
    
    // At least ONE input must be on a supported origin chain
    let has_valid_input = request.intent.inputs.iter().any(|input| {
        let chain_id = input.asset.ethereum_chain_id().ok();
        chain_id
            .and_then(|id| networks.get(&id))
            .is_some_and(|net| !net.input_settler_address.0.is_empty())
    });
    
    if !has_valid_input {
        return Err(QuoteError::UnsupportedAsset("No supported origin chains"));
    }
    
    // ALL outputs must be on supported destination chains
    for output in &request.intent.outputs {
        let chain_id = output.asset.ethereum_chain_id()?;
        let is_dest = networks
            .get(&chain_id)
            .is_some_and(|net| !net.output_settler_address.0.is_empty());
        
        if !is_dest {
            return Err(QuoteError::UnsupportedAsset(
                format!("Chain {} not supported as destination", chain_id)
            ));
        }
    }
    
    Ok(())
}
```

**Policy**:
- **Inputs**: At least one supported (allows multi-chain inputs)
- **Outputs**: All must be supported (strict requirement)

#### Balance Validation

```rust:apis/quote/validation.rs
pub async fn ensure_destination_balances_with_costs(
    solver: &SolverEngine,
    outputs: &[SupportedAsset],
    context: &ValidatedQuoteContext,
    cost_context: &CostContext,
) -> Result<(), QuoteError> {
    let token_manager = solver.token_manager();
    
    // Parallel balance checks
    let balance_checks = outputs.iter().map(|output| async move {
        let (chain_id, token_addr) = extract_chain_and_address(&output.asset)?;
        
        // Get balance from token manager
        let balance_str = token_manager
            .check_balance(chain_id, &token_addr)
            .await?;
        let balance = U256::from_str_radix(&balance_str, 10)?;
        
        // Adjust required amount based on swap type
        let required_amount = if matches!(context.swap_type, SwapType::ExactInput) {
            // For ExactInput, subtract costs from first output
            let is_first = outputs.first().map(|f| f.asset == output.asset).unwrap_or(false);
            if is_first {
                let cost = cost_context
                    .cost_amounts_in_tokens
                    .get(&output.asset)
                    .map(|info| info.amount)
                    .unwrap_or(U256::ZERO);
                output.amount.saturating_sub(cost)
            } else {
                output.amount
            }
        } else {
            // For ExactOutput, amounts are unchanged
            output.amount
        };
        
        // Verify sufficient balance
        if balance < required_amount {
            return Err(QuoteError::InsufficientLiquidity);
        }
        
        Ok(())
    });
    
    // Execute all checks in parallel
    try_join_all(balance_checks).await?;
    
    Ok(())
}
```

**Performance**: Uses `futures::try_join_all` for parallel RPC calls, reducing latency significantly for multi-output quotes.

---

### 2. Quote Generator (`apis/quote/generation.rs`)

**Purpose**: Orchestrate quote creation with custody decisions and signature generation

#### Core Algorithm

```rust:apis/quote/generation.rs
pub async fn generate_quotes_with_costs(
    &self,
    request: &GetQuoteRequest,
    context: &ValidatedQuoteContext,
    cost_context: &CostContext,
    config: &Config,
) -> Result<Vec<Quote>, QuoteError> {
    // 1. Build cost-adjusted request
    let adjusted_request = self.build_cost_adjusted_request(request, context, cost_context)?;
    
    // 2. Validate no zero amounts after adjustment
    self.validate_no_zero_amounts(&adjusted_request, context)?;
    
    // 3. Validate constraints on adjusted amounts
    self.validate_swap_amount_constraints(&adjusted_request, context)?;
    
    // 4. Generate quotes for each available input
    let mut quotes = Vec::new();
    for input in &adjusted_request.intent.inputs {
        let order_input: OrderInput = input.try_into()?;
        
        // Decide custody mechanism
        let custody_decision = self.custody_strategy
            .decide_custody(&order_input, request.intent.origin_submission.as_ref())
            .await?;
        
        // Generate quote for this custody decision
        if let Ok(quote) = self
            .generate_quote_for_settlement(request, config, &custody_decision)
            .await
        {
            quotes.push(quote);
        }
    }
    
    if quotes.is_empty() {
        return Err(QuoteError::InsufficientLiquidity);
    }
    
    // 5. Sort by user preference
    self.sort_quotes_by_preference(&mut quotes, &request.intent.preference);
    
    Ok(quotes)
}
```

#### Cost Adjustment

**ExactInput Flow**:
```rust:apis/quote/generation.rs
SwapType::ExactInput => {
    // Input amounts are known from request
    // Output amounts need swap calculation minus costs
    
    for output in adjusted.intent.outputs.iter_mut() {
        // Get base swap amount
        if let Some(base_info) = cost_context.swap_amounts.get(&output.asset) {
            // Get cost in this token
            let cost_amount = cost_context
                .cost_amounts_in_tokens
                .get(&output.asset)
                .map(|info| info.amount)
                .unwrap_or(U256::ZERO);
            
            // Apply full cost to first output, others get base amount
            let is_first_output = /* ... */;
            let adjusted_amount = if is_first_output {
                base_info.amount.saturating_sub(cost_amount)
            } else {
                base_info.amount
            };
            
            output.amount = Some(adjusted_amount.to_string());
        }
    }
}
```

**Why first output?** Simplifies UX by applying all costs to one output rather than distributing across all.

**ExactOutput Flow**:
```rust:apis/quote/generation.rs
SwapType::ExactOutput => {
    // Output amounts are known from request
    // Input amounts need swap calculation plus costs
    
    for input in adjusted.intent.inputs.iter_mut() {
        if let Some(base_info) = cost_context.swap_amounts.get(&input.asset) {
            let cost_amount = cost_context
                .cost_amounts_in_tokens
                .get(&input.asset)
                .map(|info| info.amount)
                .unwrap_or(U256::ZERO);
            
            let is_first_input = /* ... */;
            let adjusted_amount = if is_first_input {
                base_info.amount.saturating_add(cost_amount)
            } else {
                base_info.amount
            };
            
            input.amount = Some(adjusted_amount.to_string());
        }
    }
}
```

#### Quote Assembly

```rust:apis/quote/generation.rs
async fn generate_quote_for_settlement(
    &self,
    request: &GetQuoteRequest,
    config: &Config,
    custody_decision: &CustodyDecision,
) -> Result<Quote, QuoteError> {
    let quote_id = Uuid::new_v4().to_string();
    
    // Generate order based on custody decision
    let order = match custody_decision {
        CustodyDecision::ResourceLock { lock } => {
            self.generate_resource_lock_order(request, config, lock).await?
        },
        CustodyDecision::Escrow { lock_type } => {
            self.generate_escrow_order(request, config, lock_type).await?
        },
    };
    
    let eta = self.calculate_eta(&request.intent.preference);
    let validity_seconds = self.get_quote_validity_seconds(config);
    
    let failure_handling = request.intent.failure_handling
        .as_ref()
        .and_then(|modes| modes.first())
        .cloned()
        .unwrap_or(FailureHandlingMode::RefundAutomatic);
    
    let partial_fill = request.intent.partial_fill.unwrap_or(false);
    
    Ok(Quote {
        order,
        failure_handling,
        partial_fill,
        valid_until: Utc::now().timestamp() as u64 + validity_seconds,
        eta: Some(eta),
        quote_id,
        provider: Some("oif-solver".to_string()),
        preview: QuotePreview::from_order_and_user(&order, &request.user),
    })
}
```

---

### 3. Custody Strategy (`apis/quote/custody.rs`)

**Purpose**: Intelligent selection of token custody mechanisms

```rust:apis/quote/custody.rs
pub enum CustodyDecision {
    ResourceLock { lock: AssetLockReference },
    Escrow { lock_type: LockType },
}
```

#### Decision Logic

```rust:apis/quote/custody.rs
pub async fn decide_custody(
    &self,
    input: &OrderInput,
    origin_submission: Option<&OriginSubmission>,
) -> Result<CustodyDecision, QuoteError> {
    // 1. Check for explicit lock (highest priority)
    if let Some(lock) = &input.lock {
        return self.handle_explicit_lock(lock);
    }
    
    // 2. Decide escrow strategy
    self.decide_escrow_strategy(input, origin_submission).await
}
```

**Explicit Lock Handling**:
```rust:apis/quote/custody.rs
fn handle_explicit_lock(
    &self,
    lock: &AssetLockReference,
) -> Result<CustodyDecision, QuoteError> {
    match lock.kind {
        LockKind::TheCompact => Ok(CustodyDecision::ResourceLock { lock: lock.clone() }),
        LockKind::Rhinestone => Ok(CustodyDecision::ResourceLock { lock: lock.clone() }),
    }
}
```

**Escrow Strategy Selection**:
```rust:apis/quote/custody.rs
async fn decide_escrow_strategy(
    &self,
    input: &OrderInput,
    origin_submission: Option<&OriginSubmission>,
) -> Result<CustodyDecision, QuoteError> {
    let chain_id = input.asset.ethereum_chain_id()?;
    let token_address = input.asset.ethereum_address()?;
    
    // Query token capabilities
    let capabilities = PROTOCOL_REGISTRY
        .get_token_capabilities(chain_id, token_address, self.delivery_service.clone())
        .await;
    
    // Respect user's explicit auth scheme preference
    if let Some(origin) = origin_submission {
        if let Some(schemes) = &origin.schemes {
            // Check for explicit EIP-3009 preference
            if schemes.contains(&AuthScheme::Eip3009) {
                if capabilities.supports_eip3009 {
                    return Ok(CustodyDecision::Escrow {
                        lock_type: LockType::Eip3009Escrow,
                    });
                } else {
                    return Err(QuoteError::UnsupportedSettlement(
                        "EIP-3009 requested but not supported by this token"
                    ));
                }
            }
            
            // Check for explicit Permit2 preference
            if schemes.contains(&AuthScheme::Permit2) {
                if capabilities.permit2_available {
                    return Ok(CustodyDecision::Escrow {
                        lock_type: LockType::Permit2Escrow,
                    });
                } else {
                    return Err(QuoteError::UnsupportedSettlement(
                        "Permit2 requested but not available on this chain"
                    ));
                }
            }
        }
    }
    
    // Fallback to automatic selection
    if capabilities.supports_eip3009 {
        Ok(CustodyDecision::Escrow {
            lock_type: LockType::Eip3009Escrow,
        })
    } else if capabilities.permit2_available {
        Ok(CustodyDecision::Escrow {
            lock_type: LockType::Permit2Escrow,
        })
    } else {
        Err(QuoteError::UnsupportedSettlement(
            "No supported settlement mechanism available for this token"
        ))
    }
}
```

**Selection Priority**:
1. **User Preference**: If `originSubmission.schemes` specified, respect it
2. **EIP-3009**: Prefer native gasless transfers (lower gas, better UX)
3. **Permit2**: Universal fallback (works with any ERC-20)

---

### 4. Protocol Registry (`apis/quote/registry.rs`)

**Purpose**: Centralized knowledge about protocol deployments and token capabilities

#### Registry Structure

```rust:apis/quote/registry.rs
pub struct ProtocolRegistry {
    permit2_deployments: HashMap<u64, Address>,
    eip3009_tokens: HashMap<u64, HashSet<Address>>,
}
```

#### Initialization

```rust:apis/quote/registry.rs
impl Default for ProtocolRegistry {
    fn default() -> Self {
        let mut registry = Self {
            permit2_deployments: HashMap::new(),
            eip3009_tokens: HashMap::new(),
        };
        
        // Permit2 canonical address (same on most chains)
        const PERMIT2_CANONICAL: &str = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
        
        // Register Permit2 on mainnet chains
        registry.add_permit2_deployment(1, PERMIT2_CANONICAL); // Ethereum
        registry.add_permit2_deployment(137, PERMIT2_CANONICAL); // Polygon
        registry.add_permit2_deployment(42161, PERMIT2_CANONICAL); // Arbitrum
        registry.add_permit2_deployment(10, PERMIT2_CANONICAL); // Optimism
        registry.add_permit2_deployment(8453, PERMIT2_CANONICAL); // Base
        
        // Register EIP-3009 tokens (USDC variants)
        registry.add_eip3009_token(1, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
        registry.add_eip3009_token(137, "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359");
        registry.add_eip3009_token(42161, "0xaf88d065e77c8cC2239327C5EDb3A432268e5831");
        // ... more chains
        
        registry
    }
}
```

**Why Static Registry?** Most protocols have deterministic addresses (CREATE2) or well-known deployments. Static registration avoids repeated RPC calls.

#### Dynamic Detection

```rust:apis/quote/registry.rs
pub async fn supports_eip3009_with_rpc(
    &self,
    chain_id: u64,
    token_address: Address,
    delivery_service: Arc<DeliveryService>,
) -> bool {
    // Check static registry first
    if self.supports_eip3009(chain_id, token_address) {
        return true;
    }
    
    // Detect via RPC using function selector
    self.detect_eip3009_via_rpc(chain_id, token_address, delivery_service)
        .await
        .unwrap_or(false)
}

async fn detect_eip3009_via_rpc(
    &self,
    chain_id: u64,
    token_address: Address,
    delivery_service: Arc<DeliveryService>,
) -> Result<bool, Box<dyn std::error::Error>> {
    // Function selector for RECEIVE_WITH_AUTHORIZATION_TYPEHASH()
    let call_data = hex::decode("7f2eecc3")?;
    
    let tx = Transaction {
        to: Some(Address(token_address.to_vec())),
        data: call_data,
        value: U256::ZERO,
        chain_id,
        // ... other fields
    };
    
    match delivery_service.contract_call(chain_id, tx).await {
        Ok(result) => {
            // Check if returned value matches expected EIP-3009 constant
            let expected = hex::decode(
                "d099cc98ef71107a616c4f0f941f04c322d8e254fe26b3c6668db87aae413de8"
            )?;
            Ok(result.len() == 32 && result[..] == expected[..])
        },
        Err(_) => Ok(false), // Function doesn't exist
    }
}
```

**Why Function Selector Check?** EIP-3009 tokens implement `RECEIVE_WITH_AUTHORIZATION_TYPEHASH()` constant. Checking for this function's existence is a reliable detection method.

---

## Signature Validation

### Architecture

EIP-712 signature validation is critical for order security. The system implements a pluggable validation architecture.

```
SignatureValidationService
         │
         ├─── Eip7683SignatureValidator
         ├─── (Future validators)
         └─── ...
```

### Signature Validation Service (`signature_validator.rs`)

```rust:signature_validator.rs
pub struct SignatureValidationService {
    validators: HashMap<String, Box<dyn OrderSignatureValidator>>,
}

impl SignatureValidationService {
    pub fn new() -> Self {
        let mut validators: HashMap<String, Box<dyn OrderSignatureValidator>> = HashMap::new();
        
        // Register EIP-7683 validator
        validators.insert("eip7683".to_string(), Box::new(Eip7683SignatureValidator));
        
        Self { validators }
    }
    
    pub async fn validate_signature(
        &self,
        standard: &str,
        intent: &PostOrderRequest,
        networks_config: &NetworksConfig,
        delivery_service: &Arc<DeliveryService>,
    ) -> Result<(), APIError> {
        let validator = self.validators.get(standard)
            .ok_or_else(|| APIError::BadRequest {
                error_type: ApiErrorType::OrderValidationFailed,
                message: format!("No signature validator for standard: {}", standard),
                details: None,
            })?;
        
        validator.validate_signature(intent, networks_config, delivery_service).await
    }
    
    pub fn requires_signature_validation(&self, standard: &str, lock_type: &LockType) -> bool {
        if let Some(validator) = self.validators.get(standard) {
            validator.requires_signature_validation(lock_type)
        } else {
            false
        }
    }
}
```

### EIP-7683 Validator

```rust:signature_validator.rs
pub struct Eip7683SignatureValidator;

impl OrderSignatureValidator for Eip7683SignatureValidator {
    fn requires_signature_validation(&self, lock_type: &LockType) -> bool {
        matches!(lock_type, LockType::ResourceLock)
    }
    
    async fn validate_signature(
        &self,
        intent: &PostOrderRequest,
        networks_config: &NetworksConfig,
        delivery_service: &Arc<DeliveryService>,
    ) -> Result<(), APIError> {
        // 1. Convert to StandardOrder
        let standard_order = OifStandardOrder::try_from(&intent.order)?;
        let order_bytes = Bytes::from(OifStandardOrder::abi_encode(&standard_order));
        
        let origin_chain_id = standard_order.originChainId.to::<u64>();
        let network = networks_config.get(&origin_chain_id)
            .ok_or_else(|| APIError::BadRequest {
                error_type: ApiErrorType::OrderValidationFailed,
                message: format!("Network {} not configured", origin_chain_id),
                details: None,
            })?;
        
        // 2. Get TheCompact contract address
        let the_compact_address = network.the_compact_address.as_ref()
            .ok_or_else(|| APIError::BadRequest {
                error_type: ApiErrorType::OrderValidationFailed,
                message: "TheCompact contract not configured".to_string(),
                details: None,
            })?;
        
        // 3. Get domain separator from TheCompact contract
        let domain_separator = get_domain_separator(
            delivery_service,
            the_compact_address,
            origin_chain_id
        ).await?;
        
        // 4. Create compact-specific implementations
        let message_hasher = compact::create_message_hasher();
        let signature_validator = compact::create_signature_validator();
        
        // 5. Compute message hash
        let contract_address = network.input_settler_compact_address
            .clone()
            .unwrap_or_else(|| network.input_settler_address.clone());
        let struct_hash = message_hasher.compute_message_hash(
            &order_bytes,
            AlloyAddress::from_slice(&contract_address.0)
        )?;
        
        // 6. Extract and validate signature
        let signature = signature_validator.extract_signature(&intent.signature);
        let expected_signer = standard_order.user;
        
        let is_valid = signature_validator.validate_signature(
            domain_separator,
            struct_hash,
            &signature,
            expected_signer,
        )?;
        
        if !is_valid {
            return Err(APIError::BadRequest {
                error_type: ApiErrorType::OrderValidationFailed,
                message: "Invalid EIP-712 signature".to_string(),
                details: None,
            });
        }
        
        Ok(())
    }
}
```

**Why only ResourceLock?** Escrow orders (Permit2, EIP-3009) have their signatures validated by the respective protocols (Permit2 contract, USDC contract). ResourceLock orders use TheCompact which requires pre-validation.

### EIP-712 Module (`eip712/mod.rs`)

#### Generic Interfaces

```rust:eip712/mod.rs
pub trait MessageHashComputer {
    fn compute_message_hash(
        &self,
        order_bytes: &[u8],
        contract_address: AlloyAddress,
    ) -> Result<FixedBytes<32>, APIError>;
}

pub trait SignatureValidator {
    fn validate_signature(
        &self,
        domain_separator: FixedBytes<32>,
        struct_hash: FixedBytes<32>,
        signature: &Bytes,
        expected_signer: AlloyAddress,
    ) -> Result<bool, APIError>;
    
    fn extract_signature(&self, signature: &Bytes) -> Bytes;
}
```

**Design**: Trait-based abstraction allows different protocols (TheCompact, Rhinestone, etc.) to implement custom validation logic.

#### Domain Separator

```rust:eip712/mod.rs
pub async fn get_domain_separator(
    delivery: &Arc<DeliveryService>,
    contract_address: &Address,
    chain_id: u64,
) -> Result<FixedBytes<32>, APIError> {
    use ITheCompact::DOMAIN_SEPARATORCall;
    
    let call = DOMAIN_SEPARATORCall {};
    let encoded = call.abi_encode();
    
    let tx = Transaction {
        to: Some(contract_address.clone()),
        data: encoded,
        value: U256::ZERO,
        chain_id,
        // ... other fields
    };
    
    let result = delivery.contract_call(chain_id, tx).await
        .map_err(|e| APIError::BadRequest {
            error_type: ApiErrorType::OrderValidationFailed,
            message: format!("Failed to get domain separator: {}", e),
            details: None,
        })?;
    
    let domain_separator = DOMAIN_SEPARATORCall::abi_decode_returns_validate(&result)
        .map_err(|e| APIError::BadRequest {
            error_type: ApiErrorType::OrderValidationFailed,
            message: format!("Failed to decode domain separator: {}", e),
            details: None,
        })?;
    
    Ok(domain_separator)
}
```

**Why fetch dynamically?** Domain separators include chain ID and contract address. Fetching from contract ensures accuracy even if contracts are upgraded or re-deployed.

#### Signature Recovery

```rust:eip712/mod.rs
fn recover_signer(
    message_hash: FixedBytes<32>,
    signature: &Bytes,
) -> Result<AlloyAddress, APIError> {
    if signature.len() != 65 {
        return Err(APIError::BadRequest {
            error_type: ApiErrorType::OrderValidationFailed,
            message: "Invalid signature length".to_string(),
            details: None,
        });
    }
    
    let recovery_id = signature[64];
    let recovery_id = if recovery_id >= 27 {
        recovery_id - 27
    } else {
        recovery_id
    };
    
    let signature_bytes = &signature[0..64];
    
    use secp256k1::{ecdsa::RecoverableSignature, Message, Secp256k1};
    
    let secp = Secp256k1::new();
    let recovery_id = secp256k1::ecdsa::RecoveryId::try_from(recovery_id as i32)?;
    let recoverable_sig = RecoverableSignature::from_compact(signature_bytes, recovery_id)?;
    
    let message = Message::from_digest(*message_hash);
    let public_key = secp.recover_ecdsa(message, &recoverable_sig)?;
    
    // Get address from public key
    let public_key_bytes = public_key.serialize_uncompressed();
    let public_key_hash = keccak256(&public_key_bytes[1..]);
    let address_bytes = &public_key_hash.as_slice()[12..];
    
    Ok(AlloyAddress::from_slice(address_bytes))
}
```

**Algorithm**: Standard ECDSA recovery using secp256k1 curve, then derive Ethereum address via keccak256 of public key.

### TheCompact Implementation (`eip712/compact/mod.rs`)

#### Message Hash Computation

```rust:eip712/compact/mod.rs
pub fn compute_batch_compact_hash(
    order_bytes: &[u8],
    contract_address: AlloyAddress,
) -> Result<FixedBytes<32>, APIError> {
    // Parse order
    let order = OifStandardOrder::abi_decode_validate(order_bytes)?;
    
    // Compute witness hash (mandate with outputs)
    let witness_hash = compute_witness_hash(&order)?;
    
    // Compute lock hash (commitments/inputs)
    let ids_and_amounts = order.inputs.to_vec();
    let lock_hash = compute_lock_hash(&ids_and_amounts)?;
    
    // Compute BatchCompact struct hash
    compute_batch_compact_struct_hash(
        contract_address,
        order.user,
        order.nonce,
        Uint::<256, 4>::from(order.expires),
        lock_hash,
        witness_hash,
    )
}
```

**Structure**: TheCompact uses nested hashing:
```
BatchCompact Hash
├── arbiter (contract address)
├── sponsor (user)
├── nonce
├── expires
├── Lock[] hash
│   └── keccak256(Lock₁ || Lock₂ || ...)
└── Mandate hash
    └── keccak256(fillDeadline || inputOracle || MandateOutput[] hash)
```

#### Signature Extraction

```rust:eip712/compact/mod.rs
pub fn extract_sponsor_signature(signature: &Bytes) -> Bytes {
    // Handle ABI-encoded signatures: abi.encode(sponsorSig, allocatorSig)
    if signature.len() > 65 && signature.len() >= 96 {
        let sponsor_sig_length_offset = 64;
        if signature.len() > sponsor_sig_length_offset + 32 {
            let sponsor_sig_length = u32::from_be_bytes([
                signature[sponsor_sig_length_offset + 28],
                signature[sponsor_sig_length_offset + 29],
                signature[sponsor_sig_length_offset + 30],
                signature[sponsor_sig_length_offset + 31],
            ]) as usize;
            
            let sponsor_sig_start = sponsor_sig_length_offset + 32;
            if signature.len() >= sponsor_sig_start + sponsor_sig_length {
                return Bytes::from(
                    signature[sponsor_sig_start..sponsor_sig_start + sponsor_sig_length].to_vec(),
                );
            }
        }
    }
    
    // If not ABI-encoded or extraction failed, use raw signature
    signature.clone()
}
```

**Why ABI encoding?** TheCompact orders may include both sponsor and allocator signatures. The extraction logic handles both cases.

---

## Factory Registry Pattern

### Design Motivation

**Problem**: The solver needs pluggable implementations (different storage backends, settlement protocols, etc.) without tight coupling.

**Solution**: Factory Registry pattern with lazy initialization and trait-based abstractions.

### Type System

```rust:factory_registry.rs
// Factory function signatures
pub type StorageFactory = fn(&toml::Value) -> Result<Box<dyn StorageInterface>, StorageError>;
pub type AccountFactory = fn(&toml::Value) -> Result<Box<dyn AccountInterface>, AccountError>;
pub type DeliveryFactory = fn(
    &toml::Value,
    &NetworksConfig,
    &SecretString,
    &HashMap<u64, SecretString>,
) -> Result<Box<dyn DeliveryInterface>, DeliveryError>;
// ... similar for all interfaces
```

**Key Characteristics**:
- **Function Pointers**: Stable ABI, easy to register
- **TOML Configuration**: Allows runtime customization
- **Trait Objects**: Dynamic dispatch for polymorphism
- **Error Types**: Domain-specific error handling

### Registration Flow

```
solver-storage::get_all_implementations()
         │
         ▼
Returns HashMap<String, StorageFactory>
         │
         ▼
FactoryRegistry::register_storage(name, factory)
         │
         ▼
Stored in global REGISTRY singleton
         │
         ▼
build_solver_from_config() looks up by name
         │
         ▼
Factory function called with TOML config
         │
         ▼
Returns Box<dyn StorageInterface>
```

### Macro for Reduced Boilerplate

```rust:factory_registry.rs
macro_rules! build_factories {
    ($registry:expr, $config_impls:expr, $registry_field:ident, $type_name:literal) => {{
        let mut factories = HashMap::new();
        for name in $config_impls.keys() {
            if let Some(factory) = $registry.$registry_field.get(name) {
                factories.insert(name.clone(), *factory);
            } else {
                let available: Vec<_> = $registry.$registry_field.keys().cloned().collect();
                return Err(format!(
                    "Unknown {} implementation '{}'. Available: [{}]",
                    $type_name, name, available.join(", ")
                ).into());
            }
        }
        factories
    }};
}
```

**Usage**:
```rust:factory_registry.rs
let storage_factories = build_factories!(
    registry, 
    config.storage.implementations, 
    storage, 
    "storage"
);
```

**Benefits**:
- Reduces repetitive code
- Provides helpful error messages
- Validates all implementations exist before building

### Builder Pattern Integration

```rust:factory_registry.rs
pub async fn build_solver_from_config(
    config: Config,
) -> Result<SolverEngine, Box<dyn std::error::Error>> {
    let registry = get_registry();
    let builder = SolverBuilder::new(config.clone());
    
    // Collect all factory maps
    let factories = SolverFactories {
        storage_factories: build_factories!(...),
        account_factories: build_factories!(...),
        delivery_factories: build_factories!(...),
        discovery_factories: build_factories!(...),
        order_factories: build_factories!(...),
        pricing_factories: build_factories!(...),
        settlement_factories: build_factories!(...),
        strategy_factories: build_factories!(...),
    };
    
    // Delegate to builder
    Ok(builder.build(factories).await?)
}
```

**SolverBuilder** (in solver-core) then:
1. Reads TOML config sections
2. Calls factory functions with parsed config
3. Wires up dependencies
4. Returns fully initialized `SolverEngine`

---

## Security Considerations

### 1. Authentication

**JWT Security**:
- **HS256 Algorithm**: Symmetric signing with shared secret
- **Token Expiry**: Access tokens expire quickly (1 hour)
- **Token Rotation**: Refresh tokens rotate on use
- **Scope Enforcement**: Middleware validates permissions

**Future Improvements**:
- RS256 (asymmetric keys) for distributed systems
- Token revocation list
- Rate limiting on auth endpoints

### 2. Signature Validation

**EIP-712 Security**:
- **Domain Separation**: Prevents cross-chain replay attacks
- **Struct Hashing**: Type-safe message construction
- **ECDSA Recovery**: Cryptographic proof of authorization

**Resource Lock Validation**:
- Fetches domain separator from contract (prevents spoofing)
- Validates against expected user address
- Supports multiple signature formats (sponsor + allocator)

**Escrow Validation**:
- Permit2/EIP-3009 signatures validated by respective protocols
- Pre-validation ensures well-formed messages
- Signature extraction handles ABI-encoded formats

### 3. Input Validation

**Request Validation**:
- InteropAddress format validation (ERC-7930)
- Amount bounds checking (no zero/negative)
- Chain ID verification
- Token support verification

**SQL Injection Prevention**: N/A (no SQL database)

**XSS Prevention**: JSON serialization handles escaping

### 4. CORS

**Current**: Permissive policy (all origins allowed)

**Production Recommendation**:
```rust
CorsLayer::new()
    .allow_origin([
        "https://app.example.com".parse().unwrap(),
    ])
    .allow_methods([Method::GET, Method::POST])
    .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
```

### 5. Rate Limiting

**Current**: Not implemented

**Recommendation**: Add Tower middleware:
```rust
ServiceBuilder::new()
    .layer(GovernorLayer {
        config: Arc::new(
            GovernorConfigBuilder::default()
                .per_second(10)
                .burst_size(20)
                .finish()
                .unwrap()
        ),
    })
```

---

## Configuration

### API Configuration Schema

```toml
[api]
enabled = true
host = "127.0.0.1"
port = 8080
timeout_seconds = 30
max_request_size = 1048576

[api.auth]
enabled = true
jwt_secret = "your-secret-key-here"
access_token_expiry_hours = 1
refresh_token_expiry_hours = 720
issuer = "oif-solver"

[api.quote]
validity_seconds = 300

[api.implementations.discovery]
# Offchain discovery service URL
offchain_eip7683 = "http://discovery-service:8080"
```

### Environment Variables

```bash
# Override log level
RUST_LOG=info,solver_service=debug

# Override config file
solver --config /path/to/config.toml --log-level debug
```

---

## Error Handling

### API Error Types

```rust
pub enum ApiErrorType {
    InvalidRequest,
    OrderValidationFailed,
    QuoteNotFound,
    QuoteConversionFailed,
    MissingSignature,
    SolverAddressError,
}
```

### Error Response Format

```json
{
  "errorType": "OrderValidationFailed",
  "message": "Invalid EIP-712 signature",
  "details": {
    "expected": "0x1234...",
    "received": "0x5678..."
  }
}
```

### HTTP Status Codes

- `200 OK`: Success
- `201 Created`: Resource created (auth registration)
- `400 Bad Request`: Invalid input
- `401 Unauthorized`: Missing/invalid auth token
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `500 Internal Server Error`: System error
- `503 Service Unavailable`: Discovery service unavailable

---

## Performance Considerations

### 1. HTTP Client Pooling

```rust:server.rs
let http_client = reqwest::Client::builder()
    .pool_idle_timeout(Duration::from_secs(90))
    .pool_max_idle_per_host(10)
    .timeout(Duration::from_secs(30))
    .build()?;
```

**Benefits**:
- Connection reuse (avoids TCP handshake overhead)
- Configurable pool size
- Timeout protection

### 2. Parallel Balance Checks

```rust:apis/quote/validation.rs
let balance_checks = outputs.iter().map(|output| async move {
    // RPC call to check balance
});

// Execute all checks in parallel
try_join_all(balance_checks).await?;
```

**Speedup**: O(n) time instead of O(n * latency)

### 3. State Caching

**AppState** holds pre-computed values:
- Discovery URL (formatted once at startup)
- JWT service (initialized once)
- HTTP client (connection pooling)

### 4. Tracing

**Structured Logging**:
```rust
tracing::info!(
    client_id = %claims.sub,
    order_id = %id,
    "Authenticated order retrieval"
);
```

**Benefits**:
- Machine-readable logs
- Correlation IDs
- Performance profiling

---

## Testing Strategy

### Unit Tests

**Coverage**:
- Auth token generation/validation
- Signature extraction
- EIP-712 hash computation
- Quote generation logic
- Validation functions

**Example**:
```rust:auth/mod.rs
#[tokio::test]
async fn test_refresh_token_rotation() {
    let service = JwtService::new(test_config()).unwrap();
    
    let initial_token = service
        .generate_refresh_token("client1", vec![AuthScope::ReadOrders])
        .await
        .unwrap();
    
    let (_, refresh_token1) = service
        .refresh_access_token(&initial_token)
        .await
        .unwrap();
    
    // Verify tokens are different (rotation working)
    assert_ne!(initial_token, refresh_token1);
}
```

### Integration Tests

**Recommended** (not currently implemented):
```rust
#[tokio::test]
async fn test_full_quote_flow() {
    // 1. Start test server
    let server = start_test_server().await;
    
    // 2. POST /api/quotes
    let quote_response = reqwest::Client::new()
        .post(&format!("{}/api/quotes", server.url()))
        .json(&test_quote_request())
        .send()
        .await
        .unwrap();
    
    // 3. Verify quote structure
    assert_eq!(quote_response.status(), 200);
    let quotes: GetQuoteResponse = quote_response.json().await.unwrap();
    assert!(!quotes.quotes.is_empty());
    
    // 4. POST /api/orders with quote acceptance
    let order_response = reqwest::Client::new()
        .post(&format!("{}/api/orders", server.url()))
        .header("Authorization", "Bearer <test-token>")
        .json(&json!({
            "quoteId": quotes.quotes[0].quote_id,
            "signature": "0x..."
        }))
        .send()
        .await
        .unwrap();
    
    // 5. Verify order submission
    assert_eq!(order_response.status(), 200);
}
```

---

## Future Enhancements

### 1. Streaming Responses

**WebSocket Support** for real-time order updates:
```rust
// Future endpoint: /api/orders/{id}/stream
async fn handle_order_stream(
    ws: WebSocketUpgrade,
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, id, state))
}
```

### 2. Batch Quote Requests

**Multi-Quote Optimization**:
```json
{
  "quotes": [
    { "intent": {...}, "user": "0x..." },
    { "intent": {...}, "user": "0x..." }
  ]
}
```

**Benefits**: Reduced HTTP overhead, parallel processing

### 3. Quote Caching

**Redis Integration** for frequently requested routes:
```rust
// Check cache before generating
if let Some(cached_quote) = redis.get(&cache_key).await? {
    return Ok(Json(cached_quote));
}

// Generate and cache
let quote = generate_quote(...).await?;
redis.set_ex(&cache_key, &quote, TTL).await?;
```

### 4. Metrics and Observability

**Prometheus Metrics**:
```rust
// Define metrics
lazy_static! {
    static ref QUOTE_REQUESTS: IntCounter = register_int_counter!(
        "quote_requests_total",
        "Total number of quote requests"
    ).unwrap();
    
    static ref QUOTE_LATENCY: Histogram = register_histogram!(
        "quote_generation_duration_seconds",
        "Time to generate quotes"
    ).unwrap();
}

// Instrument handlers
async fn handle_quote(...) -> Result<Json<GetQuoteResponse>, APIError> {
    QUOTE_REQUESTS.inc();
    let _timer = QUOTE_LATENCY.start_timer();
    
    // ... generate quote
}
```

### 5. GraphQL API

**Alternative to REST** for flexible querying:
```graphql
query {
  quote(input: {
    user: "0x..."
    intent: {
      inputs: [...]
      outputs: [...]
    }
  }) {
    quoteId
    order {
      ... on OifEscrowV0 {
        payload {
          message
        }
      }
    }
    eta
  }
}
```

---

## Conclusion

The `solver-service` crate provides a **production-ready HTTP API** for the OIF solver system with:

### Key Strengths

1. **Clean Architecture**: Clear separation between API layer and business logic
2. **Security**: JWT authentication, EIP-712 validation, CORS support
3. **Flexibility**: Factory registry for pluggable implementations
4. **Standards Compliance**: EIP-7683, EIP-3009, Permit2, TheCompact
5. **Performance**: Connection pooling, parallel processing, efficient state management
6. **Extensibility**: Trait-based abstractions, middleware stack

### Production Readiness

**Ready**:
- Core API endpoints
- Authentication system
- Signature validation
- Quote generation
- Order submission

**Needs Work**:
- Rate limiting
- Comprehensive integration tests
- Observability (metrics, tracing exports)
- Production CORS configuration
- Error recovery mechanisms

### Development Workflow

1. **Add Endpoint**: Create handler in `apis/` module
2. **Register Route**: Add to `server.rs` router
3. **Add Validation**: Extend validators as needed
4. **Test**: Write unit tests for new logic
5. **Document**: Update API docs with examples

---

**End of Documentation**

This documentation provides a **comprehensive technical analysis** of the `solver-service` crate, covering:
- Architecture and design patterns
- Detailed component analysis
- API specifications
- Security considerations
- Performance optimizations
- Testing strategies
- Future enhancements

The crate serves as the **critical bridge** between external clients and the solver's business logic, providing a secure, performant, and extensible HTTP API for cross-chain intent execution.

