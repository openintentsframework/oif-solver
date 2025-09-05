# Project Structure

This document provides a detailed breakdown of the OIF Solver codebase organization, explaining the purpose and contents of each directory and module within the Rust workspace.

## Workspace Overview

The OIF Solver is organized as a Rust workspace with multiple crates, each serving a specific purpose in the cross-chain execution pipeline:

```
oif-solver/
├── Cargo.toml                   # Workspace definition and shared dependencies
├── Cargo.lock                   # Dependency lock file
├── crates/                      # All Rust crates/modules
├── config/                      # Configuration examples and templates
├── api-spec/                    # OpenAPI specifications
├── scripts/                     # Deployment and utility scripts
├── docs/                        # Documentation (you are here!)
├── demo-output/                 # Generated demo files
├── data/                        # Runtime data storage
├── oif-demo                     # Demo CLI tool
├── README.md                    # Project overview
├── OVERVIEW.md                  # Technical overview
├── LICENSE                      # MIT license
└── rust-toolchain.toml          # Rust toolchain specification
```

## Workspace Configuration

### Cargo.toml

The root `Cargo.toml` defines the workspace structure and shared dependencies:

```toml
[workspace]
resolver = "2"
members = [
    "crates/solver-types",
    "crates/solver-core",
    "crates/solver-config",
    "crates/solver-storage",
    "crates/solver-account",
    "crates/solver-delivery",
    "crates/solver-discovery",
    "crates/solver-order",
    "crates/solver-settlement",
    "crates/solver-pricing",
    "crates/solver-service",
]
default-members = ["crates/solver-service"]
```

**Key Sections:**

- `members`: All crates in the workspace
- `default-members`: Primary executable crate
- `[workspace.dependencies]`: Shared dependencies with consistent versions
- `[workspace.package]`: Common package metadata

## Crate Architecture

### Dependency Hierarchy

The crates are organized in layers with clear dependency relationships:

```
solver-service (binary)
    ↓
solver-core (orchestration)
    ↓
solver-discovery, solver-order, solver-delivery, solver-settlement (services)
    ↓
solver-storage, solver-account, solver-config (infrastructure)
    ↓
solver-types (shared types)
```

### Foundation Layer

#### solver-types (`crates/solver-types/`)

**Purpose**: Shared data structures, traits, and type definitions used across all components.

**Key Contents:**

```
src/
├── lib.rs                      # Re-exports and module organization
├── account.rs                  # Account and signing types
├── api.rs                      # API-related types and structures
├── auth.rs                     # Authentication types
├── costs.rs                    # Cost calculation types
├── delivery.rs                 # Delivery service types
├── discovery.rs                # Discovery service types
├── events.rs                   # Event definitions for inter-component communication
├── networks.rs                 # Network and chain definitions
├── oracle.rs                   # Oracle-related types
├── order.rs                    # Order types and state definitions
├── pricing.rs                  # Pricing-related types
├── registry.rs                 # Registry types
├── secret_string.rs            # Secure string handling
├── storage.rs                  # Storage-related types
├── validation.rs               # Validation utilities
├── standards/                  # Protocol-specific types
│   ├── eip7683.rs             # EIP-7683 intent types
│   ├── eip7930.rs             # EIP-7930 interoperable address
│   └── mod.rs
└── utils/                      # Utility modules and helpers
    ├── constants.rs           # Common constants
    ├── conversion.rs          # Type conversion utilities
    ├── eip712.rs              # EIP-712 signing utilities
    ├── formatting.rs          # Formatting utilities
    ├── helpers.rs             # General helper functions
    ├── tests/                 # Test builders and utilities
    └── mod.rs
```

**Dependencies**: Minimal - only serialization, basic utilities, and blockchain types.

**Used By**: All other crates depend on this for shared types.

### Infrastructure Layer

#### solver-config (`crates/solver-config/`)

**Purpose**: Configuration parsing, validation, and management.

**Key Contents:**

```
src/
├── lib.rs                      # Configuration loading and validation
├── loader.rs                   # Configuration file loading utilities
└── builders/                   # Configuration builder patterns
    ├── config.rs               # Configuration builder implementation
    └── mod.rs
```

**Key Features:**

- TOML configuration with file includes
- Validation of network addresses and parameters
- Environment variable substitution
- Modular configuration support

#### solver-storage (`crates/solver-storage/`)

**Purpose**: Persistent storage abstraction with TTL management.

**Key Contents:**

```
src/
├── lib.rs                      # Storage service and main interface
└── implementations/            # Storage backend implementations
    ├── file.rs                # File-based storage backend
    └── memory.rs              # In-memory storage (for testing)
```

**Features:**

- Multiple storage backends (file, memory, future: database)
- Configurable TTL per data type
- Automatic cleanup of expired data
- Atomic operations for critical updates
- Migration support for schema changes

#### solver-account (`crates/solver-account/`)

**Purpose**: Cryptographic key management and transaction signing.

**Key Contents:**

```
src/
├── lib.rs                      # Account service interface
└── implementations/            # Account implementation types
    └── local.rs               # Local private key storage
```

### Service Layer

#### solver-discovery (`crates/solver-discovery/`)

**Purpose**: Multi-source intent discovery and monitoring.

**Key Contents:**

```
src/
├── lib.rs                      # Discovery service orchestration
└── implementations/            # Discovery source implementations
    ├── offchain/               # Off-chain discovery implementations
    │   └── _7683.rs           # EIP-7683 off-chain discovery
    └── onchain/               # On-chain discovery implementations
        └── _7683.rs           # EIP-7683 on-chain event monitoring
```

**Discovery Sources:**

- **On-chain**: Blockchain event monitoring with real-time polling
- **Off-chain**: REST API endpoints for intent submission

#### solver-order (`crates/solver-order/`)

**Purpose**: Intent validation, execution strategies, and transaction generation.

**Key Contents:**

```
src/
├── lib.rs                      # Order service main interface
└── implementations/            # Protocol and strategy implementations
    ├── standards/              # Protocol-specific order handling
    │   └── _7683.rs           # EIP-7683 implementation
    └── strategies/             # Execution strategy implementations
        └── simple.rs          # Basic execution strategy
```

**Strategy Types:**

- **Simple Strategy**: Basic timing and gas price checks

#### solver-delivery (`crates/solver-delivery/`)

**Purpose**: Reliable multi-chain transaction submission and monitoring.

**Key Contents:**

```
src/
├── lib.rs                      # Delivery service coordination
└── implementations/            # Chain-specific delivery methods
    └── evm/                   # EVM-specific implementations
        └── alloy.rs           # EVM chains via Alloy
```

**Features:**

- Multi-chain transaction support
- Configurable confirmation depths
- Gas price optimization
- Transaction status tracking

#### solver-settlement (`crates/solver-settlement/`)

**Purpose**: Post-execution settlement verification and claim processing.

**Key Contents:**

```
src/
├── lib.rs                      # Settlement service interface
├── utils.rs                    # Settlement utility functions
└── implementations/            # Protocol-specific settlement
    └── direct.rs              # Direct settlement logic
```

**Settlement Flow:**

1. Fill transaction validation
2. Fill proof extraction and storage
3. Dispute period monitoring
4. Oracle verification (for cross-chain proofs)
5. Claim transaction generation and submission

#### solver-pricing (`crates/solver-pricing/`)

**Purpose**: Fee calculation and pricing strategies for order execution.

**Key Contents:**

```
src/
├── lib.rs                      # Pricing service interface
└── implementations/            # Pricing strategy implementations
    ├── mock.rs                # Mock pricing for testing
    └── mod.rs                 # Implementation module organization
```

### Orchestration Layer

#### solver-core (`crates/solver-core/`)

**Purpose**: Event-driven orchestration of the entire solver workflow.

**Key Contents:**

```
src/
├── lib.rs                      # Core engine and public interface
├── builder/                    # Solver builder patterns
│   └── mod.rs
├── engine/                     # Core engine components
│   ├── context.rs             # Execution context management
│   ├── event_bus.rs           # Event routing and distribution
│   ├── lifecycle.rs           # Component lifecycle management
│   ├── token_manager.rs       # Token management utilities
│   └── mod.rs
├── handlers/                   # Event handlers for different types
│   ├── intent.rs              # Intent processing handlers
│   ├── order.rs               # Order lifecycle handlers
│   ├── settlement.rs          # Settlement event handlers
│   ├── transaction.rs         # Transaction event handlers
│   └── mod.rs
├── monitoring/                 # Monitoring and observability
│   ├── settlement.rs          # Settlement monitoring
│   ├── transaction.rs         # Transaction monitoring
│   └── mod.rs
├── recovery/                   # Error recovery mechanisms
│   └── mod.rs
└── state/                     # State management
    ├── order.rs               # Order state management
    └── mod.rs
```

**Core Responsibilities:**

- Event-driven workflow orchestration
- Order state machine management
- Component lifecycle coordination
- Error handling and recovery
- Graceful shutdown management

### Binary Layer

#### solver-service (`crates/solver-service/`)

**Purpose**: Main executable that wires up all components and runs the solver.

**Key Contents:**

```
src/
├── main.rs                     # Application entry point
├── factory_registry.rs         # Component factory registry
├── server.rs                  # HTTP API server implementation
├── apis/                      # API endpoint implementations
│   ├── mod.rs                 # API module organization
│   ├── order.rs               # Order API endpoints
│   ├── tokens.rs              # Token information endpoints
│   ├── register.rs            # API registration utilities
│   └── quote/                 # Quote-related endpoints
│       ├── cost/              # Cost calculation for quotes
│       ├── custody.rs         # Asset custody management
│       ├── generation.rs      # Quote generation logic
│       ├── registry.rs        # Quote registry management
│       ├── signing/           # Quote signing utilities
│       ├── validation.rs      # Quote validation
│       └── mod.rs
└── auth/                      # Authentication and authorization
    ├── middleware.rs          # Auth middleware implementation
    └── mod.rs
```

**Features:**

- Command-line argument processing
- Configuration file loading and validation
- Structured logging setup
- Signal handling for graceful shutdown
- Optional REST API server

## Configuration Directory

### config/

Contains configuration examples and templates:

```
config/
├── example.toml                # Complete single-file example
├── demo.toml                  # Main demo configuration with includes
└── demo/                      # Modular demo configuration files
    ├── networks.toml          # Network definitions and tokens
    ├── api.toml               # API server settings
    ├── cli.toml               # CLI-specific configuration
    └── gas.toml               # Gas pricing settings
```

## API Specifications

### api-spec/

OpenAPI 3.0 specifications for the REST API:

```
api-spec/
├── orders-api.yaml            # Orders submission and tracking API
└── tokens-api.yaml            # Supported tokens and networks API
```

## Scripts Directory

### scripts/

Utility scripts for demo and end-to-end testing:

```
scripts/
├── demo/                      # Demo-related scripts and libraries
│   └── lib/                   # Demo utility libraries
│       ├── api.sh             # API interaction utilities
│       ├── blockchain.sh      # Blockchain interaction utilities
│       ├── common.sh          # Common utility functions
│       ├── config.sh          # Configuration utilities
│       ├── deployment.sh      # Contract deployment utilities
│       ├── forge.sh           # Foundry/Forge utilities
│       ├── intents.sh         # Intent handling utilities
│       ├── jwt.sh             # JWT authentication utilities
│       ├── quotes.sh          # Quote handling utilities
│       ├── signature.sh       # Signature utilities
│       └── ui.sh              # User interface utilities
└── e2e/                       # End-to-end testing scripts
    ├── batch_intents.sh       # Batch intent testing
    ├── estimate_gas_compact.sh # Gas estimation for compact orders
    ├── estimate_gas_permit2_escrow.sh # Gas estimation for permit2 escrow
    └── setup_testnet.sh       # Testnet environment setup
```

## Build and Development

### Development Commands

```bash
# Build all crates
cargo build

# Run all tests
cargo test

# Run tests for specific crate
cargo test -p solver-core
```

### Extensibility Points

The structure is designed to accommodate:

- New protocol implementations in `solver-order`
- Additional discovery sources in `solver-discovery`
- New storage backends in `solver-storage`
- Custom execution strategies in order strategies
- Chain-specific optimizations in `solver-delivery`

This modular structure provides a solid foundation for current functionality while enabling future enhancements and extensibility.
