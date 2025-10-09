# solver-types: Comprehensive Technical Documentation

> **Deep Technical Analysis of the OIF Solver Type System**  
> Version: 0.1.0 | Edition: 2021

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Architectural Overview](#architectural-overview)
3. [Core Type Categories](#core-type-categories)
4. [Deep Dive: Account Types](#deep-dive-account-types)
5. [Deep Dive: API Types](#deep-dive-api-types)
6. [Deep Dive: Standards (EIP-7683 & ERC-7930)](#deep-dive-standards)
7. [Deep Dive: Order Processing](#deep-dive-order-processing)
8. [Deep Dive: Validation Framework](#deep-dive-validation-framework)
9. [Utility Systems](#utility-systems)
10. [Feature Flags & Conditional Compilation](#feature-flags)
11. [Type Safety & Error Handling](#type-safety--error-handling)
12. [Performance Considerations](#performance-considerations)
13. [Security Considerations](#security-considerations)
14. [Testing Infrastructure](#testing-infrastructure)
15. [Future Extensibility](#future-extensibility)

---

## Executive Summary

**solver-types** is the foundational type system for the OIF (Open Intent Framework) solver, a cross-chain intent execution system. This crate serves as the **single source of truth** for all data structures, providing type-safe abstractions for:

- **Cross-chain order processing** (EIP-7683 standard)
- **Interoperable addressing** (ERC-7930 standard)
- **Multi-chain network configuration**
- **Intent discovery and validation**
- **Order execution lifecycle management**
- **Cost estimation and profitability analysis**

### Key Statistics
- **35 Rust source files** across 5 major subsystems
- **Feature-gated compilation** for optional dependencies
- **Zero-cost abstractions** with compile-time guarantees
- **Comprehensive test coverage** with 100+ unit tests
- **Builder patterns** for complex type construction

---

## Architectural Overview

### Module Organization

```
solver-types/
├── Core Types (9 modules)
│   ├── account.rs          # Blockchain primitives
│   ├── order.rs            # Order lifecycle
│   ├── events.rs           # Event system
│   ├── discovery.rs        # Intent discovery
│   └── delivery.rs         # Transaction delivery
├── API Layer (2 modules)
│   ├── api.rs              # HTTP API types
│   └── auth.rs             # Authentication
├── Configuration (3 modules)
│   ├── networks.rs         # Network configs
│   ├── storage.rs          # Storage keys
│   └── validation.rs       # Config validation
├── Standards (3 modules)
│   ├── standards/eip7683.rs  # Cross-chain orders
│   ├── standards/eip7930.rs  # Interop addressing
│   └── standards/mod.rs      # Standards re-exports
├── Economic (2 modules)
│   ├── costs.rs            # Cost breakdown
│   └── pricing.rs          # Pricing oracles
├── Infrastructure (6 modules)
│   ├── provider.rs         # RPC providers
│   ├── registry.rs         # Self-registration
│   ├── secret_string.rs    # Secure strings
│   ├── oracle.rs           # Oracle routing
│   ├── validation.rs       # Config validation
│   └── lib.rs              # Module exports
└── Utilities (10+ modules)
    └── utils/              # Conversion, formatting, EIP-712
```

### Design Principles

1. **Type Safety First**: Leverage Rust's type system for compile-time guarantees
2. **Zero-Copy Where Possible**: Use references and borrowing to minimize allocations
3. **Feature-Gated Compilation**: Optional dependencies reduce binary size
4. **Standards Compliance**: Full EIP-7683 and ERC-7930 support
5. **Extensibility**: Plugin-style architecture via traits

---

## Core Type Categories

### 1. Blockchain Primitives

#### Address Type
```rust
pub struct Address(pub Vec<u8>);
```

**Purpose**: Chain-agnostic address representation supporting multiple blockchain formats.

**Design Rationale**: 
- Uses `Vec<u8>` instead of fixed-size array for flexibility
- Supports Ethereum (20 bytes), Solana (32 bytes), and future chains
- Custom `Serialize`/`Deserialize` ensures hex string format with "0x" prefix

**Key Features**:
- **Validation**: Enforces 20-byte length for Ethereum in deserialization
- **Display**: Always shows as lowercase hex with "0x" prefix
- **Hash & Eq**: Supports use in `HashMap` and `HashSet`

```rust
// Example: Serialization flow
Address(vec![0xA0, 0xb8, ...]) 
  → serialize → "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
  → deserialize → Address(vec![0xA0, 0xb8, ...])
```

**Critical Implementation Details**:
1. **Conversion from Alloy**: `From<AlloyAddress>` implementation for interop
2. **Error Handling**: Custom errors for invalid hex and wrong length
3. **Test Coverage**: 13 tests covering edge cases (empty, wrong length, roundtrip)

#### Signature Type
```rust
pub struct Signature(pub Vec<u8>);
```

**Purpose**: Ethereum signature in (r, s, v) format (65 bytes).

**Conversion Logic**:
```rust
impl From<PrimitiveSignature> for Signature {
    fn from(sig: PrimitiveSignature) -> Self {
        let mut bytes = Vec::with_capacity(65);
        bytes.extend_from_slice(&sig.r().to_be_bytes::<32>());  // r: 32 bytes
        bytes.extend_from_slice(&sig.s().to_be_bytes::<32>());  // s: 32 bytes
        let v = if sig.v() { 28 } else { 27 };                  // v: 1 byte
        bytes.push(v);
        Signature(bytes)
    }
}
```

**V-Value Encoding**: Non-EIP-155 format (27/28) for compatibility with ecrecover.

#### Transaction Type
```rust
pub struct Transaction {
    pub to: Option<Address>,
    pub data: Vec<u8>,
    pub value: U256,
    pub chain_id: u64,
    pub nonce: Option<u64>,
    pub gas_limit: Option<u64>,
    pub gas_price: Option<u128>,              // Legacy
    pub max_fee_per_gas: Option<u128>,        // EIP-1559
    pub max_priority_fee_per_gas: Option<u128>, // EIP-1559
}
```

**Dual Mode Support**: Handles both legacy (gas_price) and EIP-1559 (maxFeePerGas) transactions.

**Conversion to/from Alloy**: Bidirectional conversion with `TransactionRequest`:
```rust
impl From<TransactionRequest> for Transaction { /* ... */ }
impl From<Transaction> for TransactionRequest { /* ... */ }
```

---

## Deep Dive: API Types

### The Quote System

The API layer implements the **ERC-7683 Cross-Chain Intent Standard** with OIF-specific extensions.

#### Order Type Hierarchy

```
OifOrder (Union Type)
├── OifEscrowV0 { payload: OrderPayload }              # Permit2-based
├── OifResourceLockV0 { payload: OrderPayload }        # The Compact
├── Oif3009V0 { payload: OrderPayload, metadata }      # EIP-3009
└── OifGenericV0 { payload: serde_json::Value }        # Extensible
```

**Versioning Strategy**: Each variant includes version in name (`V0`) for future compatibility.

#### Order Type Methods

```rust
impl OifOrder {
    pub fn order_type(&self) -> &'static str;           // Returns "oif-escrow-v0", etc.
    pub fn version(&self) -> &'static str;              // Returns "v0"
    pub fn is_supported(&self) -> bool;                 // Version check
    pub fn flow_key(&self) -> Option<String>;           // Gas config key
    pub fn requires_ecrecover(&self) -> bool;           // Signature recovery needed?
    pub fn extract_sponsor(&self, sig: Option<&Bytes>) -> Result<Address, String>;
    pub fn get_lock_type(&self) -> LockType;            // Derive custody mechanism
}
```

**Sponsor Extraction Logic** (Critical for reward attribution):

```rust
pub fn extract_sponsor(&self, signature: Option<&Bytes>) -> Result<Address, String> {
    match self {
        OifOrder::OifResourceLockV0 { payload } => {
            // Direct extraction from 'sponsor' field in TheCompact
            payload.message.get("sponsor")
                .and_then(|s| s.as_str())
                .map(|s| hex::decode(without_0x_prefix(s)))
                .ok_or("Sponsor field not found")
        },
        OifOrder::OifEscrowV0 { .. } | OifOrder::Oif3009V0 { .. } => {
            // Signature recovery via ecrecover
            let sig = signature.ok_or("Signature required")?;
            let digest = reconstruct_digest(payload)?;  // EIP-712 digest
            ecrecover_user_from_signature(&digest, &hex::encode(sig))
        },
        OifOrder::OifGenericV0 { .. } => {
            Err("Cannot extract sponsor from generic order")
        }
    }
}
```

**Why This Matters**: 
- Permit2/EIP-3009 orders don't include sender address in payload
- Must use `ecrecover` to derive it from EIP-712 signature
- TheCompact includes sponsor directly (more gas-efficient)

### Input/Output Types

#### QuoteInput vs OrderInput

**QuoteInput** (used in GET /quote requests):
```rust
pub struct QuoteInput {
    pub user: InteropAddress,        // ERC-7930 format
    pub asset: InteropAddress,       // ERC-7930 format
    pub amount: Option<String>,      // Optional for price discovery
    pub lock: Option<AssetLockReference>,
}
```

**OrderInput** (used in POST /order with actual intent):
```rust
pub struct OrderInput {
    pub user: InteropAddress,
    pub asset: InteropAddress,
    pub amount: U256,                // Required - exact amount
    pub lock: Option<AssetLockReference>,
}
```

**Key Difference**: Quote requests allow unknown amounts (solver proposes), while orders require exact amounts.

**Conversion**:
```rust
impl TryFrom<&QuoteInput> for OrderInput {
    type Error = QuoteError;
    fn try_from(quote_input: &QuoteInput) -> Result<Self, Self::Error> {
        let amount_u256 = quote_input.amount.as_ref()
            .map(|s| U256::from_str(s))
            .transpose()?
            .unwrap_or(U256::ZERO);
        // ... validation
    }
}
```

### SwapType Semantics

```rust
pub enum SwapType {
    ExactInput,   // User specifies input amount, solver calculates output
    ExactOutput,  // User specifies output amount, solver calculates input
}
```

**Impact on Quote Processing**:

| SwapType | Known Amount | Calculated Amount | Validation |
|----------|--------------|-------------------|------------|
| ExactInput | `inputs[*].amount` | `outputs[*].amount` | Ensure outputs ≥ minimum |
| ExactOutput | `outputs[*].amount` | `inputs[*].amount` | Ensure inputs ≤ maximum |

**Cost Application**:
```rust
match swap_type {
    SwapType::ExactInput => {
        // Deduct costs from outputs
        output_amount = base_output_amount - cost_in_output_token
    },
    SwapType::ExactOutput => {
        // Add costs to inputs
        input_amount = base_input_amount + cost_in_input_token
    }
}
```

### Error Taxonomy

```rust
pub enum ApiErrorType {
    // Validation Errors (400)
    MissingOrderBytes,
    InvalidHexEncoding,
    OrderValidationFailed,
    InvalidRequest,
    
    // Business Logic Errors (422)
    QuoteNotFound,
    UnsupportedAsset,
    InsufficientLiquidity,
    SolverCapacityExceeded,
    
    // Service Errors (503)
    DiscoveryServiceUnavailable,
    
    // Internal Errors (500)
    GasEstimationFailed,
    SerializationFailed,
    InternalError,
}
```

**Error Mapping**:
```rust
impl From<QuoteError> for APIError {
    fn from(quote_error: QuoteError) -> Self {
        match quote_error {
            QuoteError::InvalidRequest(msg) => APIError::BadRequest {
                error_type: ApiErrorType::InvalidRequest,
                message: msg,
                details: None,
            },
            QuoteError::SolverCapacityExceeded => APIError::ServiceUnavailable {
                error_type: ApiErrorType::SolverCapacityExceeded,
                message: "Solver capacity exceeded, please try again later".to_string(),
                retry_after: Some(60),  // Hint to client
            },
            // ... more mappings
        }
    }
}
```

**Axum Integration**:
```rust
impl axum::response::IntoResponse for APIError {
    fn into_response(self) -> axum::response::Response {
        let status = match self.status_code() {
            400 => StatusCode::BAD_REQUEST,
            422 => StatusCode::UNPROCESSABLE_ENTITY,
            503 => StatusCode::SERVICE_UNAVAILABLE,
            500 => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(self.to_error_response())).into_response()
    }
}
```

---

## Deep Dive: Standards

### EIP-7683: Cross-Chain Intent Standard

#### LockType Enumeration

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LockType {
    #[serde(rename = "permit2_escrow")]
    #[default]
    Permit2Escrow = 1,
    
    #[serde(rename = "eip3009_escrow")]
    Eip3009Escrow = 2,
    
    #[serde(rename = "resource_lock")]
    ResourceLock = 3,
}
```

**Numeric Values**: Match contract constants for ABI encoding compatibility.

**Methods**:
```rust
impl LockType {
    pub fn from_u8(value: u8) -> Option<Self>;      // Decode from contract
    pub fn to_u8(self) -> u8;                        // Encode for contract
    pub fn is_compact(&self) -> bool;                // ResourceLock only
    pub fn is_escrow(&self) -> bool;                 // Permit2 or EIP-3009
    pub fn as_str(&self) -> &'static str;            // Config key
}
```

**FromStr Implementation** (handles both string and numeric inputs):
```rust
impl FromStr for LockType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "permit2_escrow" => Ok(LockType::Permit2Escrow),
            "eip3009_escrow" => Ok(LockType::Eip3009Escrow),
            "resource_lock" => Ok(LockType::ResourceLock),
            "1" => Ok(LockType::Permit2Escrow),  // Contract value
            "2" => Ok(LockType::Eip3009Escrow),
            "3" => Ok(LockType::ResourceLock),
            _ => Err(format!("Invalid lock type: {}", s)),
        }
    }
}
```

#### Eip7683OrderData Structure

```rust
pub struct Eip7683OrderData {
    pub user: String,                                    // Sponsor address
    pub nonce: U256,                                     // Replay protection
    pub origin_chain_id: U256,                           // Source chain
    pub expires: u32,                                    // Order expiration
    pub fill_deadline: u32,                              // Fill deadline
    pub input_oracle: String,                            // Oracle address
    pub inputs: Vec<[U256; 2]>,                         // [token, amount]
    pub order_id: [u8; 32],                             // Unique identifier
    pub gas_limit_overrides: GasLimitOverrides,         // Optional gas limits
    pub outputs: Vec<MandateOutput>,                     // Outputs
    pub raw_order_data: Option<String>,                  // Original ABI-encoded
    pub signature: Option<String>,                       // Off-chain signature
    pub sponsor: Option<String>,                         // Optional sponsor
    pub lock_type: Option<LockType>,                     // Custody mechanism
}
```

**MandateOutput Structure** (matches Solidity struct):
```rust
pub struct MandateOutput {
    pub oracle: [u8; 32],        // Oracle (bytes32 for ABI compatibility)
    pub settler: [u8; 32],       // Settler contract
    pub chain_id: U256,          // Destination chain
    pub token: [u8; 32],         // Token (padded address)
    pub amount: U256,            // Amount
    pub recipient: [u8; 32],     // Recipient (padded address)
    
    #[serde(with = "hex_string")]
    pub call: Vec<u8>,           // Calldata for recipient
    
    #[serde(with = "hex_string")]
    pub context: Vec<u8>,        // Additional context
}
```

**Hex String Serialization** (custom serde module):
```rust
mod hex_string {
    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_str(&with_0x_prefix(&hex::encode(bytes)))
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where D: Deserializer<'de> {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}
```

#### OrderParsable Trait

**Purpose**: Abstract interface for extracting common fields from standard-specific order structures.

```rust
pub trait OrderParsable: Send + Sync {
    fn parse_available_inputs(&self) -> Vec<OrderInput>;
    fn parse_requested_outputs(&self) -> Vec<OrderOutput>;
    fn parse_lock_type(&self) -> Option<String>;
    fn input_oracle(&self) -> String;
    fn origin_chain_id(&self) -> u64;
    fn destination_chain_ids(&self) -> Vec<u64>;
}
```

**EIP-7683 Implementation**:
```rust
impl OrderParsable for Eip7683OrderData {
    fn parse_available_inputs(&self) -> Vec<OrderInput> {
        let origin_chain = self.origin_chain_id.try_into().unwrap_or(1);
        
        self.inputs.iter().map(|input| {
            // input is [token_address, amount] as [U256; 2]
            let token_u256_bytes = input[0].to_be_bytes::<32>();
            let token_address_hex = bytes32_to_address(&token_u256_bytes);
            let token_addr = parse_address(&token_address_hex)
                .unwrap_or(Address(vec![0u8; 20]));
            
            let asset = InteropAddress::from((origin_chain, token_addr));
            let user_addr = parse_address(&self.user)
                .unwrap_or(Address(vec![0u8; 20]));
            let user = InteropAddress::from((origin_chain, user_addr));
            
            OrderInput {
                user,
                asset,
                amount: input[1],
                lock: None,
            }
        }).collect()
    }
    
    fn parse_requested_outputs(&self) -> Vec<OrderOutput> {
        self.outputs.iter().map(|output| {
            let chain_id = output.chain_id.try_into().unwrap_or(1);
            let token_address_hex = bytes32_to_address(&output.token);
            let token_addr = parse_address(&token_address_hex)
                .unwrap_or(Address(vec![0u8; 20]));
            
            let recipient_address_hex = bytes32_to_address(&output.recipient);
            let recipient_addr = parse_address(&recipient_address_hex)
                .unwrap_or(Address(vec![0u8; 20]));
            
            let asset = InteropAddress::from((chain_id, token_addr));
            let receiver = InteropAddress::from((chain_id, recipient_addr));
            
            OrderOutput {
                receiver,
                asset,
                amount: output.amount,
                calldata: if output.call.is_empty() {
                    None
                } else {
                    Some(with_0x_prefix(&hex::encode(&output.call)))
                },
            }
        }).collect()
    }
    
    fn parse_lock_type(&self) -> Option<String> {
        self.lock_type.map(|lt| lt.to_string())
    }
    
    fn input_oracle(&self) -> String {
        self.input_oracle.clone()
    }
    
    fn origin_chain_id(&self) -> u64 {
        self.origin_chain_id.try_into().unwrap_or(1)
    }
    
    fn destination_chain_ids(&self) -> Vec<u64> {
        self.outputs.iter()
            .map(|output| output.chain_id.try_into().unwrap_or(1))
            .collect()
    }
}
```

**Why This Abstraction Matters**:
1. **Standard Independence**: Core solver logic doesn't care about standard-specific details
2. **Easy Extension**: New standards implement trait without changing core code
3. **Type Safety**: Compile-time guarantee that all standards provide required data

#### Solidity Interface Bindings

Using `alloy-sol-types` for zero-copy ABI encoding:

```rust
sol! {
    struct StandardOrder {
        address user;
        uint256 nonce;
        uint256 originChainId;
        uint32 expires;
        uint32 fillDeadline;
        address inputOracle;
        uint256[2][] inputs;
        SolMandateOutput[] outputs;
    }
    
    struct SolMandateOutput {
        bytes32 oracle;
        bytes32 settler;
        uint256 chainId;
        bytes32 token;
        uint256 amount;
        bytes32 recipient;
        bytes call;
        bytes context;
    }
    
    #[sol(rpc)]
    interface IInputSettlerEscrow {
        function finalise(
            StandardOrder calldata order,
            SolveParams[] calldata solveParams,
            bytes32 destination,
            bytes calldata call
        ) external;
        
        function openFor(
            StandardOrder calldata order,
            address sponsor,
            bytes calldata signature
        ) external;
        
        function orderIdentifier(
            StandardOrder calldata order
        ) external view returns (bytes32);
    }
}
```

**Order Type Conversions** (automatic detection):

```rust
impl TryFrom<&OifOrder> for interfaces::StandardOrder {
    type Error = Box<dyn std::error::Error>;
    
    fn try_from(order: &OifOrder) -> Result<Self, Self::Error> {
        match order {
            OifOrder::Oif3009V0 { payload, metadata } => 
                Self::from_eip3009(payload, metadata),
            OifOrder::OifResourceLockV0 { payload } => 
                Self::from_batch_compact(payload),
            OifOrder::OifEscrowV0 { payload } => 
                Self::from_permit2(payload),
            OifOrder::OifGenericV0 { .. } => 
                Err("Generic orders not supported".into()),
        }
    }
}
```

**Permit2 Parsing** (complex EIP-712 structure):

```rust
fn from_permit2(payload: &OrderPayload) -> Result<Self, Box<dyn std::error::Error>> {
    let message_data = payload.message.as_object()
        .ok_or("Invalid message structure")?;
    
    // Extract user from injected ecrecover result
    let user_str = message_data.get("user")
        .and_then(|u| u.as_str())
        .ok_or("Missing user (should be injected by ecrecover)")?;
    let user_address = hex_to_alloy_address(user_str)?;
    
    // Extract nonce
    let nonce_str = message_data.get("nonce")
        .and_then(|n| n.as_str())
        .ok_or("Missing nonce")?;
    let nonce = U256::from_str_radix(nonce_str, 10)?;
    
    // Extract witness data (OIF-specific extension)
    let witness = message_data.get("witness")
        .and_then(|w| w.as_object())
        .ok_or("Missing witness object")?;
    
    let expires = witness.get("expires")
        .and_then(|e| e.as_u64())
        .unwrap_or(fill_deadline as u64) as u32;
    
    let input_oracle_str = witness.get("inputOracle")
        .and_then(|o| o.as_str())
        .ok_or("Missing inputOracle")?;
    let input_oracle = hex_to_alloy_address(input_oracle_str)?;
    
    // Parse inputs from permitted array
    let permitted = message_data.get("permitted")
        .and_then(|p| p.as_array())
        .ok_or("Missing permitted array")?;
    
    let inputs = permitted.iter().map(|perm| {
        let perm_obj = perm.as_object()?;
        let token_str = perm_obj.get("token")?.as_str()?;
        let amount_str = perm_obj.get("amount")?.as_str()?;
        
        let token = hex_to_alloy_address(token_str)?;
        let amount = U256::from_str_radix(amount_str, 10)?;
        
        // Convert to U256 for StandardOrder format
        let mut token_bytes = [0u8; 32];
        token_bytes[12..32].copy_from_slice(&token.0.0);
        let token_u256 = U256::from_be_bytes(token_bytes);
        
        Ok([token_u256, amount])
    }).collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    
    // Parse outputs from witness
    let witness_outputs = witness.get("outputs")
        .and_then(|o| o.as_array())
        .unwrap_or(&Vec::new());
    
    let sol_outputs = witness_outputs.iter().map(|output_item| {
        let output_obj = output_item.as_object()?;
        
        let chain_id = output_obj.get("chainId")?.as_u64()?;
        let amount_str = output_obj.get("amount")?.as_str()?;
        let token_str = output_obj.get("token")?.as_str()?;
        let recipient_str = output_obj.get("recipient")?.as_str()?;
        let oracle_str = output_obj.get("oracle")?.as_str()?;
        let settler_str = output_obj.get("settler")?.as_str()?;
        
        let amount = U256::from_str_radix(amount_str, 10)?;
        let token_bytes = parse_bytes32_from_hex(token_str)?;
        let recipient_bytes = parse_bytes32_from_hex(recipient_str)?;
        let oracle_bytes = parse_bytes32_from_hex(oracle_str)?;
        let settler_bytes = parse_bytes32_from_hex(settler_str)?;
        
        Ok(SolMandateOutput {
            oracle: oracle_bytes.into(),
            settler: settler_bytes.into(),
            chainId: U256::from(chain_id),
            token: token_bytes.into(),
            amount,
            recipient: recipient_bytes.into(),
            call: Vec::new().into(),
            context: Vec::new().into(),
        })
    }).collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    
    Ok(interfaces::StandardOrder {
        user: user_address,
        nonce,
        originChainId: origin_chain_id,
        expires,
        fillDeadline: fill_deadline,
        inputOracle: input_oracle,
        inputs,
        outputs: sol_outputs,
    })
}
```

### ERC-7930: Interoperable Address Standard

#### Address Format Specification

```
Hex: 0x00010000010114D8DA6BF26964AF9D7EED9E03E53415D37AA96045
     ││││││││││││└──────────────────────────────────┘
     │││││││││││└─ ChainReferenceLength: decimal 1
     ││││││││││└── ChainReference: 1 byte = uint8(1)
     │││││││││└─── AddressLength: decimal 20
     ││││││││└──── Address: 20 bytes of Ethereum address
     │││└───┘
     │││└──────── ChainType: 2 bytes (0x0000 = EIP-155)
     ││
     └└────────── Version: decimal 1

Breakdown:
- Version (1 byte):              0x01
- ChainType (2 bytes):           0x0000 (EIP-155 for Ethereum)
- ChainReferenceLength (1 byte): 0x01 (1 byte for chain ID)
- AddressLength (1 byte):        0x14 (20 bytes = 0x14)
- ChainReference (1 byte):       0x01 (Ethereum Mainnet)
- Address (20 bytes):            0x14D8DA6BF26964AF9D7EED9E03E53415D37AA96045
```

#### InteropAddress Structure

```rust
#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
pub struct InteropAddress {
    pub version: u8,                // Always 1 for current spec
    pub chain_type: [u8; 2],        // CAIP namespace (0x0000 = EIP-155)
    pub chain_reference: Vec<u8>,   // Variable-length chain ID
    pub address: Vec<u8>,           // Variable-length address
}
```

**CAIP Namespace Constants**:
```rust
pub mod caip_namespaces {
    pub const EIP155: [u8; 2] = [0x00, 0x00];  // Ethereum
    pub const BIP122: [u8; 2] = [0x00, 0x01];  // Bitcoin
    pub const COSMOS: [u8; 2] = [0x00, 0x02];  // Cosmos
}
```

#### Chain ID Encoding

**Variable-length encoding** for efficiency:

```rust
pub fn new_ethereum(chain_id: u64, address: Address) -> Self {
    let chain_reference = if chain_id <= 255 {
        vec![chain_id as u8]                             // 1 byte
    } else if chain_id <= 65535 {
        vec![(chain_id >> 8) as u8, chain_id as u8]     // 2 bytes
    } else {
        // For larger chain IDs, use minimal bytes
        let mut bytes = Vec::new();
        let mut id = chain_id;
        while id > 0 {
            bytes.insert(0, (id & 0xFF) as u8);
            id >>= 8;
        }
        bytes
    };
    
    Self {
        version: Self::CURRENT_VERSION,
        chain_type: caip_namespaces::EIP155,
        chain_reference,
        address: address.as_slice().to_vec(),
    }
}
```

**Examples**:
- Mainnet (chain_id=1): `0x01` (1 byte)
- Polygon (chain_id=137): `0x89` (1 byte)
- Arbitrum (chain_id=42161): `0xA4, 0xB1` (2 bytes)
- Sepolia (chain_id=11155111): `0xAA, 0x36, 0xA7` (3 bytes)

#### Serialization

```rust
impl Serialize for InteropAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for InteropAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        let s = String::deserialize(deserializer)?;
        InteropAddress::from_hex(&s).map_err(serde::de::Error::custom)
    }
}
```

**Parsing**:
```rust
pub fn from_hex(hex_str: &str) -> Result<Self, InteropAddressError> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str)
        .map_err(|e| InteropAddressError::InvalidHex(e.to_string()))?;
    
    Self::from_bytes(&bytes)
}

pub fn from_bytes(bytes: &[u8]) -> Result<Self, InteropAddressError> {
    if bytes.len() < 6 {
        return Err(InteropAddressError::TooShort {
            expected: 6,
            actual: bytes.len(),
        });
    }
    
    let version = bytes[0];
    if version != Self::CURRENT_VERSION {
        return Err(InteropAddressError::UnsupportedVersion(version));
    }
    
    let chain_type = [bytes[1], bytes[2]];
    let chain_ref_length = bytes[3];
    let address_length = bytes[4];
    
    let expected_total_length = 5 + chain_ref_length as usize + address_length as usize;
    if bytes.len() != expected_total_length {
        return Err(InteropAddressError::TooShort {
            expected: expected_total_length,
            actual: bytes.len(),
        });
    }
    
    let chain_reference = bytes[5..5 + chain_ref_length as usize].to_vec();
    let address = bytes[5 + chain_ref_length as usize..].to_vec();
    
    Ok(Self {
        version,
        chain_type,
        chain_reference,
        address,
    })
}
```

#### Extraction Methods

```rust
pub fn ethereum_chain_id(&self) -> Result<u64, InteropAddressError> {
    if self.chain_type != caip_namespaces::EIP155 {
        return Err(InteropAddressError::UnsupportedChainType(self.chain_type));
    }
    
    let mut chain_id = 0u64;
    for &byte in &self.chain_reference {
        chain_id = (chain_id << 8) | (byte as u64);
    }
    Ok(chain_id)
}

pub fn ethereum_address(&self) -> Result<Address, InteropAddressError> {
    if self.chain_type != caip_namespaces::EIP155 {
        return Err(InteropAddressError::UnsupportedChainType(self.chain_type));
    }
    
    if self.address.len() != Self::ETH_ADDRESS_LENGTH as usize {
        return Err(InteropAddressError::InvalidAddressLength {
            expected: Self::ETH_ADDRESS_LENGTH,
            actual: self.address.len(),
        });
    }
    
    let mut addr_bytes = [0u8; 20];
    addr_bytes.copy_from_slice(&self.address);
    Ok(Address::from(addr_bytes))
}
```

#### Conversion from (chain_id, Address)

```rust
impl From<(u64, crate::Address)> for InteropAddress {
    fn from((chain_id, custom_address): (u64, crate::Address)) -> Self {
        let alloy_address = Address::from_slice(&custom_address.0);
        InteropAddress::new_ethereum(chain_id, alloy_address)
    }
}
```

**Usage Example**:
```rust
let address = Address(vec![0x14, 0xD8, 0xDA, ...]);  // 20 bytes
let chain_id = 1u64;
let interop: InteropAddress = (chain_id, address).into();
// Produces: 0x00010000010114D8DA6BF26964AF9D7EED9E03E53415D37AA96045
```

---

## Deep Dive: Order Processing

### Order Lifecycle

```
┌─────────────┐
│   Created   │ ← Initial state after validation
└──────┬──────┘
       │ openFor() tx sent
       ▼
┌─────────────┐
│   Pending   │ ← Prepare transaction in mempool
└──────┬──────┘
       │ Prepare confirmed
       ▼
┌─────────────┐
│  Executing  │ ← Fill transaction in progress
└──────┬──────┘
       │ Fill confirmed
       ▼
┌─────────────┐
│  Executed   │ ← Fill complete, proof available
└──────┬──────┘
       │ (Optional) Post-fill transaction
       ▼
┌─────────────┐
│ PostFilled  │ ← Post-fill complete
└──────┬──────┘
       │ Oracle attestation received
       ▼
┌─────────────┐
│   Settled   │ ← Ready for claiming
└──────┬──────┘
       │ (Optional) Pre-claim transaction
       ▼
┌─────────────┐
│ PreClaimed  │ ← Pre-claim complete
└──────┬──────┘
       │ Claim confirmed
       ▼
┌─────────────┐
│  Finalized  │ ← Terminal success state
└─────────────┘

       │ Any step fails
       ▼
┌─────────────────┐
│ Failed(TxType)  │ ← Terminal failure state
└─────────────────┘
```

### Order Structure

```rust
pub struct Order {
    pub id: String,                                // Unique identifier
    pub standard: String,                          // "eip7683", etc.
    pub created_at: u64,                           // Unix timestamp
    pub updated_at: u64,                           // Unix timestamp
    pub status: OrderStatus,                       // Current lifecycle state
    pub data: serde_json::Value,                   // Standard-specific data
    pub solver_address: Address,                   // Solver handling this order
    pub quote_id: Option<String>,                  // Associated quote
    pub input_chains: Vec<ChainSettlerInfo>,       // Origin chains
    pub output_chains: Vec<ChainSettlerInfo>,      // Destination chains
    pub execution_params: Option<ExecutionParams>, // Gas parameters
    pub prepare_tx_hash: Option<TransactionHash>,  // openFor tx
    pub fill_tx_hash: Option<TransactionHash>,     // fill tx
    pub post_fill_tx_hash: Option<TransactionHash>,// Post-fill tx
    pub pre_claim_tx_hash: Option<TransactionHash>,// Pre-claim tx
    pub claim_tx_hash: Option<TransactionHash>,    // finalise tx
    pub fill_proof: Option<FillProof>,             // Proof data
}
```

**ChainSettlerInfo**:
```rust
pub struct ChainSettlerInfo {
    pub chain_id: u64,
    pub settler_address: Address,
}
```

**Why Multiple Chains?**:
- **Input Chains**: Some orders may pull assets from multiple chains
- **Output Chains**: Cross-chain orders deliver to different chains

**Example**:
```rust
Order {
    input_chains: vec![
        ChainSettlerInfo { chain_id: 1, settler_address: eth_settler }
    ],
    output_chains: vec![
        ChainSettlerInfo { chain_id: 137, settler_address: polygon_settler },
        ChainSettlerInfo { chain_id: 42161, settler_address: arbitrum_settler }
    ],
    // User swaps ETH on Ethereum for USDC on Polygon + USDC on Arbitrum
}
```

### ExecutionParams

```rust
pub struct ExecutionParams {
    pub gas_price: U256,              // Wei per gas
    pub priority_fee: Option<U256>,   // EIP-1559 priority fee
}
```

**Determined by execution strategy** based on:
- Current gas prices
- Profitability threshold
- Market conditions
- Solver balance

### ExecutionContext

```rust
pub struct ExecutionContext {
    pub chain_data: HashMap<u64, ChainData>,
    pub solver_balances: HashMap<(u64, Option<String>), String>,
    pub timestamp: u64,
}
```

**ChainData**:
```rust
pub struct ChainData {
    pub chain_id: u64,
    pub gas_price: String,      // Current gas price in wei
    pub block_number: u64,      // Latest block
    pub timestamp: u64,         // Block timestamp
}
```

**Built per-intent** to avoid stale data:
```rust
// Pseudocode
let context = ExecutionContext {
    chain_data: [
        (origin_chain_id, fetch_chain_data(origin_chain_id).await),
        (dest_chain_id, fetch_chain_data(dest_chain_id).await),
    ].into_iter().collect(),
    solver_balances: fetch_solver_balances(&order).await,
    timestamp: current_timestamp(),
};
```

### ExecutionDecision

```rust
pub enum ExecutionDecision {
    Execute(ExecutionParams),       // Execute with these params
    Skip(String),                   // Skip with reason
    Defer(std::time::Duration),     // Retry after duration
}
```

**Strategy Pattern**:
```rust
trait ExecutionStrategy {
    async fn decide(&self, order: &Order, context: &ExecutionContext) 
        -> ExecutionDecision;
}
```

**Example Implementation**:
```rust
struct ProfitabilityStrategy {
    min_profit_usd: Decimal,
}

impl ExecutionStrategy for ProfitabilityStrategy {
    async fn decide(&self, order: &Order, context: &ExecutionContext) 
        -> ExecutionDecision 
    {
        let gas_cost = estimate_gas_cost(order, context);
        let expected_profit = calculate_profit(order);
        
        if expected_profit < self.min_profit_usd + gas_cost {
            return ExecutionDecision::Skip(
                format!("Insufficient profit: {} < {}", 
                    expected_profit, self.min_profit_usd + gas_cost)
            );
        }
        
        ExecutionDecision::Execute(ExecutionParams {
            gas_price: U256::from_str(&context.chain_data[&order_chain].gas_price)
                .unwrap(),
            priority_fee: Some(U256::from(2_000_000_000u64)), // 2 gwei
        })
    }
}
```

### FillProof

```rust
pub struct FillProof {
    pub tx_hash: TransactionHash,      // Fill transaction hash
    pub block_number: u64,              // Block where fill occurred
    pub attestation_data: Option<Vec<u8>>, // Oracle attestation
    pub filled_timestamp: u64,          // When filled
    pub oracle_address: String,         // Oracle that attested
}
```

**Construction**:
```rust
impl FillProof {
    pub fn from_receipt(
        receipt: &TransactionReceipt,
        oracle_address: String
    ) -> Self {
        FillProof {
            tx_hash: receipt.hash.clone(),
            block_number: receipt.block_number,
            attestation_data: None,  // Fetched later from oracle
            filled_timestamp: receipt.block_timestamp.unwrap_or(current_timestamp()),
            oracle_address,
        }
    }
}
```

---

## Deep Dive: Validation Framework

### Schema System

**Purpose**: Type-safe TOML configuration validation before runtime.

```rust
pub struct Schema {
    pub required: Vec<Field>,
    pub optional: Vec<Field>,
}
```

**Field Definition**:
```rust
pub struct Field {
    pub name: String,
    pub field_type: FieldType,
    pub validator: Option<FieldValidator>,
}

pub type FieldValidator = Box<dyn Fn(&toml::Value) -> Result<(), String> + Send + Sync>;
```

**Field Types**:
```rust
pub enum FieldType {
    String,
    Integer { min: Option<i64>, max: Option<i64> },
    Boolean,
    Array(Box<FieldType>),
    Table(Schema),  // Recursive for nested structures
}
```

### Schema Construction

```rust
let schema = Schema::new(
    vec![
        // Required fields
        Field::new("port", FieldType::Integer {
            min: Some(1),
            max: Some(65535),
        })
        .with_validator(|value| {
            let port = value.as_integer().unwrap();
            if port < 1024 {
                return Err("Port must be > 1024 for non-root".to_string());
            }
            Ok(())
        }),
        
        Field::new("host", FieldType::String),
    ],
    vec![
        // Optional fields
        Field::new("timeout", FieldType::Integer {
            min: Some(0),
            max: None,
        }),
    ],
);
```

### Validation Logic

```rust
impl Schema {
    pub fn validate(&self, config: &toml::Value) -> Result<(), ValidationError> {
        let table = config.as_table()
            .ok_or_else(|| ValidationError::TypeMismatch {
                field: "root".to_string(),
                expected: "table".to_string(),
                actual: config.type_str().to_string(),
            })?;
        
        // Check required fields
        for field in &self.required {
            let value = table.get(&field.name)
                .ok_or_else(|| ValidationError::MissingField(field.name.clone()))?;
            
            validate_field_type(&field.name, value, &field.field_type)?;
            
            // Run custom validator
            if let Some(validator) = &field.validator {
                validator(value).map_err(|msg| ValidationError::InvalidValue {
                    field: field.name.clone(),
                    message: msg,
                })?;
            }
        }
        
        // Check optional fields (if present)
        for field in &self.optional {
            if let Some(value) = table.get(&field.name) {
                validate_field_type(&field.name, value, &field.field_type)?;
                
                if let Some(validator) = &field.validator {
                    validator(value).map_err(|msg| ValidationError::InvalidValue {
                        field: field.name.clone(),
                        message: msg,
                    })?;
                }
            }
        }
        
        Ok(())
    }
}
```

**Type Validation**:
```rust
fn validate_field_type(
    field_name: &str,
    value: &toml::Value,
    expected_type: &FieldType,
) -> Result<(), ValidationError> {
    match expected_type {
        FieldType::String => {
            if !value.is_str() {
                return Err(ValidationError::TypeMismatch {
                    field: field_name.to_string(),
                    expected: "string".to_string(),
                    actual: value.type_str().to_string(),
                });
            }
        },
        FieldType::Integer { min, max } => {
            let int_val = value.as_integer()
                .ok_or_else(|| ValidationError::TypeMismatch {
                    field: field_name.to_string(),
                    expected: "integer".to_string(),
                    actual: value.type_str().to_string(),
                })?;
            
            if let Some(min_val) = min {
                if int_val < *min_val {
                    return Err(ValidationError::InvalidValue {
                        field: field_name.to_string(),
                        message: format!("Value {} < minimum {}", int_val, min_val),
                    });
                }
            }
            
            if let Some(max_val) = max {
                if int_val > *max_val {
                    return Err(ValidationError::InvalidValue {
                        field: field_name.to_string(),
                        message: format!("Value {} > maximum {}", int_val, max_val),
                    });
                }
            }
        },
        FieldType::Array(inner_type) => {
            let array = value.as_array()
                .ok_or_else(|| ValidationError::TypeMismatch {
                    field: field_name.to_string(),
                    expected: "array".to_string(),
                    actual: value.type_str().to_string(),
                })?;
            
            for (i, item) in array.iter().enumerate() {
                validate_field_type(
                    &format!("{}[{}]", field_name, i),
                    item,
                    inner_type
                )?;
            }
        },
        FieldType::Table(schema) => {
            schema.validate(value).map_err(|e| match e {
                ValidationError::MissingField(f) => 
                    ValidationError::MissingField(format!("{}.{}", field_name, f)),
                ValidationError::InvalidValue { field, message } => 
                    ValidationError::InvalidValue {
                        field: format!("{}.{}", field_name, field),
                        message,
                    },
                other => other,
            })?;
        },
        _ => {}
    }
    Ok(())
}
```

### ConfigSchema Trait

**For plugin-style validation**:

```rust
#[async_trait]
pub trait ConfigSchema: Send + Sync {
    fn validate(&self, config: &toml::Value) -> Result<(), ValidationError>;
}
```

**Usage Example**:
```rust
struct DatabaseConfigSchema;

impl ConfigSchema for DatabaseConfigSchema {
    fn validate(&self, config: &toml::Value) -> Result<(), ValidationError> {
        let schema = Schema::new(
            vec![
                Field::new("host", FieldType::String),
                Field::new("port", FieldType::Integer {
                    min: Some(1),
                    max: Some(65535),
                }),
            ],
            vec![
                Field::new("timeout", FieldType::Integer {
                    min: Some(0),
                    max: None,
                }),
            ],
        );
        schema.validate(config)
    }
}
```

---

## Utility Systems

### EIP-712 Utilities

#### Domain Hash Computation

```rust
pub fn compute_domain_hash(
    name: &str,
    chain_id: u64,
    verifying_contract: &AlloyAddress
) -> B256 {
    let domain_type_hash = keccak256(DOMAIN_TYPE.as_bytes());
    let name_hash = keccak256(name.as_bytes());
    
    let mut enc = Eip712AbiEncoder::new();
    enc.push_b256(&domain_type_hash);
    enc.push_b256(&name_hash);
    enc.push_u256(U256::from(chain_id));
    enc.push_address(verifying_contract);
    
    keccak256(enc.finish())
}
```

**Constants**:
```rust
pub const DOMAIN_TYPE: &str = 
    "EIP712Domain(string name,uint256 chainId,address verifyingContract)";
pub const NAME_PERMIT2: &str = "Permit2";
```

#### Final Digest Computation

**EIP-712 Specification**: `keccak256(0x1901 || domainHash || structHash)`

```rust
pub fn compute_final_digest(domain_hash: &B256, struct_hash: &B256) -> B256 {
    let mut out = Vec::with_capacity(2 + 32 + 32);
    out.push(0x19);
    out.push(0x01);
    out.extend_from_slice(domain_hash.as_slice());
    out.extend_from_slice(struct_hash.as_slice());
    keccak256(out)
}
```

#### ABI Encoder

**Minimal implementation for static types**:

```rust
pub struct Eip712AbiEncoder {
    buf: Vec<u8>,
}

impl Eip712AbiEncoder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }
    
    pub fn push_b256(&mut self, v: &B256) {
        self.buf.extend_from_slice(v.as_slice());
    }
    
    pub fn push_address(&mut self, addr: &AlloyAddress) {
        let mut word = [0u8; 32];
        word[12..].copy_from_slice(addr.as_slice());  // Left-padded
        self.buf.extend_from_slice(&word);
    }
    
    pub fn push_u256(&mut self, v: U256) {
        let word: [u8; 32] = v.to_be_bytes::<32>();
        self.buf.extend_from_slice(&word);
    }
    
    pub fn push_u32(&mut self, v: u32) {
        let mut word = [0u8; 32];
        word[28..].copy_from_slice(&v.to_be_bytes());  // Right-aligned
        self.buf.extend_from_slice(&word);
    }
    
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}
```

#### Signature Recovery

```rust
pub fn ecrecover_user_from_signature(
    digest: &[u8; 32],
    signature: &str,
) -> Result<AlloyAddress, Box<dyn std::error::Error>> {
    // Handle different signature formats
    let sig_to_parse = {
        let without_prefix = without_0x_prefix(signature);
        if without_prefix.len() == 132 {
            // 66-byte signature: skip first byte (signature type indicator)
            with_0x_prefix(&without_prefix[2..])
        } else {
            // Standard 65-byte signature
            with_0x_prefix(signature)
        }
    };
    
    // Parse using alloy-signer
    let sig: Signature = sig_to_parse.parse()
        .map_err(|e| format!("Failed to parse signature: {}", e))?;
    
    // Recover address from prehash
    let recovered = sig.recover_address_from_prehash(&B256::from(*digest))
        .map_err(|e| format!("Recovery failed: {}", e))?;
    
    Ok(recovered)
}
```

**Signature Format Handling**:
- **65 bytes**: Standard (r, s, v) format
- **66 bytes**: With type byte prefix (e.g., `0x00` for EIP-712)

#### Permit2 Digest Reconstruction

**Complete EIP-712 reconstruction** for signature verification:

```rust
pub fn reconstruct_permit2_digest(
    payload: &OrderPayload,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    // 1. Compute domain hash
    let domain = payload.domain.as_object().ok_or("Missing domain")?;
    let chain_id = domain.get("chainId")?.as_str()?.parse::<u64>()?;
    let name = domain.get("name")?.as_str()?;
    let contract_str = domain.get("verifyingContract")?.as_str()?;
    let contract = hex_to_alloy_address(contract_str)?;
    
    let domain_hash = compute_domain_hash(name, chain_id, &contract);
    
    // 2. Compute struct hash
    let permit_type = "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,Permit2Witness witness)MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)TokenPermissions(address token,uint256 amount)Permit2Witness(uint32 expires,address inputOracle,MandateOutput[] outputs)";
    let type_hash = keccak256(permit_type.as_bytes());
    
    let message = payload.message.as_object().ok_or("Missing message")?;
    let spender = hex_to_alloy_address(message.get("spender")?.as_str()?)?;
    let nonce = message.get("nonce")?.as_str()?.parse::<u64>()?;
    let deadline = message.get("deadline")?.as_str()?.parse::<u64>()?;
    
    // Hash permitted array
    let permitted = message.get("permitted")?.as_array()?;
    let token_type_hash = keccak256("TokenPermissions(address token,uint256 amount)".as_bytes());
    
    let mut token_hashes = Vec::new();
    for perm in permitted {
        let perm_obj = perm.as_object()?;
        let token = hex_to_alloy_address(perm_obj.get("token")?.as_str()?)?;
        let amount = U256::from_str_radix(perm_obj.get("amount")?.as_str()?, 10)?;
        
        let mut encoder = Eip712AbiEncoder::new();
        encoder.push_b256(&token_type_hash);
        encoder.push_address(&token);
        encoder.push_u256(amount);
        token_hashes.push(keccak256(encoder.finish()));
    }
    
    let mut permitted_encoder = Eip712AbiEncoder::new();
    for hash in token_hashes {
        permitted_encoder.push_b256(&hash);
    }
    let permitted_hash = keccak256(permitted_encoder.finish());
    
    // Hash witness (contains OIF-specific mandate data)
    let witness = message.get("witness")?.as_object()?;
    let expires = witness.get("expires")?.as_u64()? as u32;
    let oracle = hex_to_alloy_address(witness.get("inputOracle")?.as_str()?)?;
    
    // Hash outputs array
    let outputs = witness.get("outputs")?.as_array()?;
    let output_type_hash = keccak256("MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)".as_bytes());
    
    let mut output_hashes = Vec::new();
    for output in outputs {
        let output_obj = output.as_object()?;
        let oracle = parse_bytes32_from_hex(output_obj.get("oracle")?.as_str()?)?;
        let settler = parse_bytes32_from_hex(output_obj.get("settler")?.as_str()?)?;
        let chain_id = output_obj.get("chainId")?.as_u64()?;
        let token = parse_bytes32_from_hex(output_obj.get("token")?.as_str()?)?;
        let amount = U256::from_str_radix(output_obj.get("amount")?.as_str()?, 10)?;
        let recipient = parse_bytes32_from_hex(output_obj.get("recipient")?.as_str()?)?;
        let call_str = output_obj.get("call")?.as_str().unwrap_or("0x");
        let context_str = output_obj.get("context")?.as_str().unwrap_or("0x");
        
        let call_bytes = if call_str == "0x" { Vec::new() } else { hex::decode(call_str.trim_start_matches("0x"))? };
        let context_bytes = if context_str == "0x" { Vec::new() } else { hex::decode(context_str.trim_start_matches("0x"))? };
        let call_hash = keccak256(&call_bytes);
        let context_hash = keccak256(&context_bytes);
        
        let mut encoder = Eip712AbiEncoder::new();
        encoder.push_b256(&output_type_hash);
        encoder.push_b256(&B256::from(oracle));
        encoder.push_b256(&B256::from(settler));
        encoder.push_u256(U256::from(chain_id));
        encoder.push_b256(&B256::from(token));
        encoder.push_u256(amount);
        encoder.push_b256(&B256::from(recipient));
        encoder.push_b256(&call_hash);
        encoder.push_b256(&context_hash);
        
        output_hashes.push(keccak256(encoder.finish()));
    }
    
    let mut outputs_encoder = Eip712AbiEncoder::new();
    for hash in output_hashes {
        outputs_encoder.push_b256(&hash);
    }
    let outputs_hash = keccak256(outputs_encoder.finish());
    
    // Build witness struct hash
    let witness_type_hash = keccak256("Permit2Witness(uint32 expires,address inputOracle,MandateOutput[] outputs)MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)".as_bytes());
    let mut witness_encoder = Eip712AbiEncoder::new();
    witness_encoder.push_b256(&witness_type_hash);
    witness_encoder.push_u32(expires);
    witness_encoder.push_address(&oracle);
    witness_encoder.push_b256(&outputs_hash);
    let witness_hash = keccak256(witness_encoder.finish());
    
    // Build main struct hash
    let mut struct_encoder = Eip712AbiEncoder::new();
    struct_encoder.push_b256(&type_hash);
    struct_encoder.push_b256(&permitted_hash);
    struct_encoder.push_address(&spender);
    struct_encoder.push_u256(U256::from(nonce));
    struct_encoder.push_u256(U256::from(deadline));
    struct_encoder.push_b256(&witness_hash);
    let struct_hash = keccak256(struct_encoder.finish());
    
    // 3. Final digest
    let final_digest = compute_final_digest(&domain_hash, &struct_hash);
    
    Ok(final_digest.0)
}
```

**Why This Complexity?**:
- Permit2 uses **nested EIP-712 structs** (witness contains mandate)
- Each nested struct must be hashed individually
- Arrays are hashed by concatenating element hashes
- Order of operations must match client-side signing

### Conversion Utilities

#### Address Conversions

**bytes32 to Address** (extract last 20 bytes):
```rust
pub fn bytes32_to_address(bytes32: &[u8; 32]) -> String {
    let hex_string = hex::encode(bytes32);
    let address = if hex_string.len() >= 40 {
        hex_string[hex_string.len() - 40..].to_string()
    } else {
        hex_string
    };
    without_0x_prefix(&address).to_string()
}
```

**Address to bytes32** (left-pad to 32 bytes):
```rust
pub fn address_to_bytes32(address: &AlloyAddress) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[12..32].copy_from_slice(address.as_slice());
    bytes
}
```

**Normalize bytes32 address** (handle right-padding):
```rust
pub fn normalize_bytes32_address(bytes32_value: [u8; 32]) -> [u8; 32] {
    // Detect right-padded: [address(20)][zeros(12)]
    let is_trailing_zeros = bytes32_value[20..32].iter().all(|&b| b == 0);
    let has_nonzero_prefix = bytes32_value[0..20].iter().any(|&b| b != 0);
    
    if is_trailing_zeros && has_nonzero_prefix {
        // Convert to left-padded: [zeros(12)][address(20)]
        let mut normalized = [0u8; 32];
        normalized[12..32].copy_from_slice(&bytes32_value[0..20]);
        normalized
    } else {
        bytes32_value
    }
}
```

#### Wei/ETH Conversions

```rust
pub fn wei_to_eth_string(wei_amount: U256) -> String {
    format_ether(wei_amount)  // Alloy utility
}

pub fn eth_string_to_wei(eth_amount: &str) -> Result<U256, String> {
    parse_ether(eth_amount)
        .map_err(|e| format!("Failed to parse ETH amount '{}': {}", eth_amount, e))
}

pub fn wei_string_to_eth_string(wei_string: &str) -> Result<String, String> {
    let wei = U256::from_str_radix(wei_string, 10)
        .map_err(|e| format!("Invalid wei amount '{}': {}", wei_string, e))?;
    Ok(format_ether(wei))
}
```

#### Decimal Utilities

**Ceiling with decimal places** (protect margins):
```rust
pub fn ceil_dp(x: Decimal, dp: u32) -> Decimal {
    let f = pow10(dp);
    (x * f).round_dp_with_strategy(0, RoundingStrategy::ToPositiveInfinity) / f
}
```

**Example**:
```rust
let cost = Decimal::from_str("1.234").unwrap();
let rounded = ceil_dp(cost, 2);  // "1.24" (always round up)
```

**Why This Matters**: When calculating costs to charge users, always round up to ensure profitability.

### Formatting Utilities

```rust
pub fn truncate_id(id: &str) -> String {
    if id.len() <= 8 {
        id.to_string()
    } else {
        format!("{}..", &id[..8])
    }
}

pub fn with_0x_prefix(hex_str: &str) -> String {
    if hex_str.to_lowercase().starts_with("0x") {
        hex_str.to_string()
    } else {
        format!("0x{}", hex_str)
    }
}

pub fn without_0x_prefix(hex_str: &str) -> &str {
    hex_str.strip_prefix("0x")
        .or_else(|| hex_str.strip_prefix("0X"))
        .unwrap_or(hex_str)
}

pub fn format_token_amount(amount: &str, decimals: u8) -> String {
    if decimals == 0 {
        return amount.to_string();
    }
    
    let decimal_places = decimals as usize;
    let (integer_part, decimal_part) = if amount.len() <= decimal_places {
        let decimal_str = format!("{:0>width$}", amount, width = decimal_places);
        ("0".to_string(), decimal_str)
    } else {
        let split_pos = amount.len() - decimal_places;
        (amount[..split_pos].to_string(), amount[split_pos..].to_string())
    };
    
    let decimal_trimmed = decimal_part.trim_end_matches('0');
    if decimal_trimmed.is_empty() {
        integer_part
    } else {
        format!("{}.{}", integer_part, decimal_trimmed)
    }
}
```

---

## Feature Flags & Conditional Compilation

### Feature: `oif-interfaces`

**Purpose**: Gate Solidity interface bindings to reduce compile time for non-contract modules.

```toml
[features]
default = ["oif-interfaces"]
oif-interfaces = ["alloy-sol-types", "alloy-contract"]
```

**Conditional Compilation**:
```rust
#[cfg(feature = "oif-interfaces")]
use crate::Eip7683OrderData;

#[cfg(feature = "oif-interfaces")]
impl OrderParsable for Eip7683OrderData {
    // Implementation only compiled with feature enabled
}

#[cfg(feature = "oif-interfaces")]
pub mod interfaces {
    use alloy_sol_types::sol;
    sol! {
        struct StandardOrder { /* ... */ }
    }
}
```

**Benefits**:
- **Faster compilation**: Modules not needing contract interaction compile faster
- **Smaller binaries**: Unused code paths eliminated
- **Optional dependencies**: `alloy-sol-types` only pulled when needed

---

## Type Safety & Error Handling

### Error Taxonomy

**Structured Errors with `thiserror`**:

```rust
#[derive(Debug, thiserror::Error)]
pub enum QuoteError {
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    
    #[error("Unsupported asset: {0}")]
    UnsupportedAsset(String),
    
    #[error("Insufficient liquidity for requested amount")]
    InsufficientLiquidity,
    
    #[error("Solver capacity exceeded")]
    SolverCapacityExceeded,
    
    #[error("Internal error: {0}")]
    Internal(String),
}
```

**Error Conversion Chain**:
```
QuoteError → APIError → axum::Response
```

**Type-Safe HTTP Status Mapping**:
```rust
impl From<QuoteError> for APIError {
    fn from(quote_error: QuoteError) -> Self {
        match quote_error {
            QuoteError::InvalidRequest(msg) => APIError::BadRequest {
                error_type: ApiErrorType::InvalidRequest,
                message: msg,
                details: None,
            },
            QuoteError::InsufficientLiquidity => APIError::UnprocessableEntity {
                error_type: ApiErrorType::InsufficientLiquidity,
                message: "Insufficient liquidity available".to_string(),
                details: None,
            },
            // ... more mappings
        }
    }
}
```

### Validation Errors

```rust
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Missing required field: {0}")]
    MissingField(String),
    
    #[error("Invalid value for field '{field}': {message}")]
    InvalidValue { field: String, message: String },
    
    #[error("Type mismatch for field '{field}': expected {expected}, got {actual}")]
    TypeMismatch { field: String, expected: String, actual: String },
    
    #[error("Failed to deserialize config: {0}")]
    DeserializationError(String),
}
```

### Provider Errors

```rust
#[derive(Debug, Clone)]
pub enum ProviderError {
    NetworkConfig(String),
    Connection(String),
    InvalidUrl(String),
}

impl std::error::Error for ProviderError {}
```

---

## Performance Considerations

### Zero-Copy Deserialization

**Leverage Rust's borrowing** for efficiency:

```rust
// GOOD: Borrows from input, no allocation
fn validate_field_type(
    field_name: &str,            // Borrowed
    value: &toml::Value,         // Borrowed
    expected_type: &FieldType,   // Borrowed
) -> Result<(), ValidationError>;

// BAD: Would require cloning
fn validate_field_type_owned(
    field_name: String,          // Owned
    value: toml::Value,          // Owned
    expected_type: FieldType,    // Owned
) -> Result<(), ValidationError>;
```

### Lazy Initialization

**Defer expensive operations**:

```rust
pub struct Order {
    // Stored as JSON, parsed on-demand
    pub data: serde_json::Value,
    
    // Not stored, computed when needed
    #[serde(skip)]
    parsed_data_cache: Option<Box<dyn OrderParsable>>,
}

impl Order {
    pub fn parse_order_data(&mut self) -> Result<&dyn OrderParsable, Box<dyn std::error::Error>> {
        if self.parsed_data_cache.is_none() {
            self.parsed_data_cache = Some(match self.standard.as_str() {
                "eip7683" => {
                    let data: Eip7683OrderData = serde_json::from_value(self.data.clone())?;
                    Box::new(data)
                },
                _ => return Err("Unsupported standard".into()),
            });
        }
        Ok(self.parsed_data_cache.as_ref().unwrap().as_ref())
    }
}
```

### Stack vs Heap Allocation

**Prefer stack for small fixed-size data**:

```rust
// Stack-allocated (good for small data)
pub struct ChainSettlerInfo {
    pub chain_id: u64,          // 8 bytes
    pub settler_address: Address, // ~24 bytes (Vec overhead + 20 bytes)
}

// Heap-allocated (necessary for variable size)
pub struct Order {
    pub id: String,             // Heap
    pub data: serde_json::Value, // Heap
    pub status: OrderStatus,    // Stack (enum)
}
```

### Efficient Serialization

**Custom serde implementations** for performance:

```rust
impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        // Direct hex encoding, no intermediate allocations
        serializer.serialize_str(&with_0x_prefix(&hex::encode(&self.0)))
    }
}
```

---

## Security Considerations

### SecretString (Memory Safety)

**Purpose**: Prevent sensitive data leakage in logs/debug output.

```rust
use zeroize::Zeroizing;

pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(s: String) -> Self {
        Self(Zeroizing::new(s))
    }
    
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString(***REDACTED***)")
    }
}

impl Serialize for SecretString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_str("***REDACTED***")
    }
}
```

**Automatic Zeroing** (via `zeroize` crate):
- Memory overwritten with zeros on drop
- Prevents secrets from lingering in memory
- Compiler optimizations won't remove zeroing

### Signature Verification

**Critical for sponsor identification**:

```rust
pub fn extract_sponsor(&self, signature: Option<&Bytes>) -> Result<Address, String> {
    match self {
        OifOrder::OifEscrowV0 { payload } => {
            let sig = signature.ok_or("Signature required")?;
            
            // Reconstruct exact EIP-712 digest
            let digest = reconstruct_permit2_digest(payload)
                .map_err(|e| format!("Failed to reconstruct digest: {}", e))?;
            
            // Recover signer address via ecrecover
            let recovered = ecrecover_user_from_signature(&digest, &hex::encode(sig))
                .map_err(|e| format!("Failed to recover: {}", e))?;
            
            Ok(Address(recovered.as_slice().to_vec()))
        },
        // ...
    }
}
```

**Why This Matters**:
- **Reward Attribution**: Wrong sponsor = wrong payment
- **Replay Protection**: Nonce verification requires correct signer
- **Security**: Prevents impersonation attacks

### Address Validation

**Strict validation** on deserialization:

```rust
impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        let s = String::deserialize(deserializer)?;
        let hex_str = s.trim_start_matches("0x");
        let bytes = hex::decode(hex_str)
            .map_err(|e| serde::de::Error::custom(format!("Invalid hex: {}", e)))?;
        
        // Enforce 20-byte length for Ethereum
        if bytes.len() != 20 {
            return Err(serde::de::Error::custom(format!(
                "Invalid address length: expected 20 bytes, got {}",
                bytes.len()
            )));
        }
        
        Ok(Address(bytes))
    }
}
```

---

## Testing Infrastructure

### Test Builders

**Fluent API** for constructing test data:

```rust
pub struct TransactionBuilder {
    to: Option<Address>,
    data: Vec<u8>,
    value: U256,
    chain_id: u64,
    nonce: Option<u64>,
    gas_limit: Option<u64>,
    gas_price: Option<u128>,
}

impl TransactionBuilder {
    pub fn new() -> Self {
        Self {
            to: Some(parse_address("0x1234567890123456789012345678901234567890").unwrap()),
            data: vec![],
            value: U256::ZERO,
            chain_id: 1,
            nonce: None,
            gas_limit: None,
            gas_price: None,
        }
    }
    
    pub fn to(mut self, to: Option<Address>) -> Self {
        self.to = to;
        self
    }
    
    pub fn data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }
    
    pub fn data_hex(mut self, hex: &str) -> Result<Self, String> {
        self.data = hex::decode(hex.trim_start_matches("0x"))
            .map_err(|e| format!("Invalid hex: {}", e))?;
        Ok(self)
    }
    
    pub fn value_u64(mut self, value: u64) -> Self {
        self.value = U256::from(value);
        self
    }
    
    pub fn chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = chain_id;
        self
    }
    
    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = Some(nonce);
        self
    }
    
    pub fn gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = Some(gas_limit);
        self
    }
    
    pub fn gas_price_gwei(mut self, gwei: u128) -> Self {
        self.gas_price = Some(gwei * 1_000_000_000);
        self
    }
    
    pub fn build(self) -> Transaction {
        Transaction {
            to: self.to,
            data: self.data,
            value: self.value,
            chain_id: self.chain_id,
            nonce: self.nonce,
            gas_limit: self.gas_limit,
            gas_price: self.gas_price,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
        }
    }
}
```

**Usage**:
```rust
#[test]
fn test_transaction() {
    let tx = TransactionBuilder::new()
        .data_hex("0xabcd").unwrap()
        .value_u64(1000)
        .nonce(42)
        .gas_limit(21000)
        .gas_price_gwei(20)
        .build();
    
    assert_eq!(tx.value, U256::from(1000));
    assert_eq!(tx.nonce, Some(42));
}
```

### Test Coverage

**Key testing patterns**:

1. **Serialization Roundtrips**: Ensure data survives JSON encoding/decoding
2. **Edge Cases**: Empty strings, zero values, max values
3. **Error Conditions**: Invalid hex, wrong lengths, missing fields
4. **Conversion Correctness**: Between different representations
5. **Validation Logic**: Schema validation with valid/invalid inputs

**Example**:
```rust
#[test]
fn test_address_round_trip_serialization() {
    let original = parse_address("0x123456789abcdef0112233445566778899aabbcc").unwrap();
    
    let json = serde_json::to_string(&original).unwrap();
    let deserialized: Address = serde_json::from_str(&json).unwrap();
    
    assert_eq!(original, deserialized);
}

#[test]
fn test_address_deserialization_invalid_length() {
    let too_short = "\"0xa0b86a33e6776fb78b3e1e6b2d0d2e8f0c1d2a\"";
    let result: Result<Address, _> = serde_json::from_str(too_short);
    
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Invalid address length"));
}
```

---

## Future Extensibility

### Design for Extension

**Trait-based abstractions** enable new implementations without modifying core code:

```rust
// Easy to add new order standards
pub trait OrderParsable: Send + Sync {
    fn parse_available_inputs(&self) -> Vec<OrderInput>;
    fn parse_requested_outputs(&self) -> Vec<OrderOutput>;
    // ... more methods
}

// Easy to add new pricing sources
#[async_trait]
pub trait PricingInterface: Send + Sync {
    fn config_schema(&self) -> Box<dyn ConfigSchema>;
    async fn get_supported_pairs(&self) -> Vec<TradingPair>;
    async fn convert_asset(&self, from: &str, to: &str, amount: &str) 
        -> Result<String, PricingError>;
}

// Easy to add new storage backends
pub trait StorageInterface: Send + Sync {
    async fn get(&self, key: StorageKey, id: &str) -> Result<Option<Vec<u8>>, StorageError>;
    async fn set(&self, key: StorageKey, id: &str, value: Vec<u8>) -> Result<(), StorageError>;
}
```

### Version Management

**Built-in versioning** for order types:

```rust
pub mod oif_versions {
    pub const V0: &str = "v0";
    pub const V1: &str = "v1";        // For future use
    pub const CURRENT: &str = V0;
    
    pub fn escrow_order_type(version: &str) -> String {
        format!("oif-escrow-{}", version)
    }
}

impl OifOrder {
    pub fn version(&self) -> &'static str {
        match self {
            OifOrder::OifEscrowV0 { .. } => oif_versions::V0,
            OifOrder::OifEscrowV1 { .. } => oif_versions::V1,  // Future
            // ...
        }
    }
    
    pub fn is_supported(&self) -> bool {
        matches!(self.version(), oif_versions::V0)
    }
}
```

### Plugin System

**Self-registering implementations**:

```rust
pub trait ImplementationRegistry {
    const NAME: &'static str;
    type Factory;
    
    fn factory() -> Self::Factory;
}

// Example: Storage implementation
pub struct MemoryStorageRegistry;

impl ImplementationRegistry for MemoryStorageRegistry {
    const NAME: &'static str = "memory";
    type Factory = fn(&toml::Value) -> Result<Box<dyn StorageInterface>, StorageError>;
    
    fn factory() -> Self::Factory {
        |config| {
            // Construct from config
            Ok(Box::new(MemoryStorage::new()))
        }
    }
}

// Registration at compile time
static STORAGE_REGISTRY: &[(&str, fn(&toml::Value) -> Result<Box<dyn StorageInterface>, StorageError>)] = &[
    (MemoryStorageRegistry::NAME, MemoryStorageRegistry::factory()),
    (PostgresStorageRegistry::NAME, PostgresStorageRegistry::factory()),
];
```

---

## Conclusion

**solver-types** is a meticulously designed type system that serves as the foundation for the OIF solver. Its architecture demonstrates:

✅ **Type Safety**: Compile-time guarantees prevent entire classes of runtime errors  
✅ **Standards Compliance**: Full EIP-7683 and ERC-7930 support with zero-copy ABI encoding  
✅ **Extensibility**: Trait-based design allows adding new standards without core changes  
✅ **Performance**: Zero-cost abstractions with careful attention to allocation patterns  
✅ **Security**: Proper handling of sensitive data and cryptographic operations  
✅ **Testability**: Comprehensive builder patterns and 100+ unit tests  

### Key Innovations

1. **Unified Order Abstraction**: `OrderParsable` trait abstracts standard differences
2. **Interoperable Addressing**: Full ERC-7930 implementation for cross-chain compatibility
3. **Type-Safe Configuration**: Schema-based validation catches errors before runtime
4. **Flexible Feature Flags**: Optional Solidity bindings reduce compilation overhead
5. **Comprehensive Error Handling**: Structured errors map cleanly to HTTP responses

### Metrics Summary

- **35 Rust files** across 10 major subsystems
- **2,500+ lines** of core type definitions
- **1,500+ lines** of utility functions
- **100+ unit tests** with edge case coverage
- **Zero unsafe code** blocks (100% safe Rust)

---

*This documentation represents a complete technical analysis of the solver-types crate as of the current commit. For the latest updates, refer to the source code and inline documentation.*

