# OIF Solver Overview

The OIF Solver is a high-performance cross-chain order execution system designed for the Open Intents Framework. It discovers (on-chain) or receives (off-chain) intents, validates and executes orders through optimal paths, and manages settlement processes. The solver operates as an autonomous service that monitors blockchain events, makes intelligent execution decisions, and ensures reliable transaction delivery across networks.

## High-Level Project Structure

The OIF Solver uses Rust for its performance-critical requirements in cross-chain transaction execution. Rust provides zero-cost abstractions for the modular architecture, compile-time guarantees for concurrent blockchain monitoring across multiple chains, and predictable latency without garbage collection pauses, essential when competing to execute orders. Additionally, the memory safety guarantees are crucial when handling cryptographic operations simultaneously.

The solver is organized as a Rust workspace with multiple crates, each serving a specific purpose in the cross-chain order execution pipeline. This modular design allows for:

- **Independent Development**: Each crate can be developed and tested in isolation
- **Clear Boundaries**: Well-defined interfaces between components prevent tight coupling
- **Reusability**: Components like `solver-types` and `solver-account` can be used by external projects
- **Scalability**: New execution strategies or chain integrations can be added without modifying core logic
- **Testability**: Each module has its own test suite with mocked dependencies

```
oif-solver/
├── Cargo.toml                   # Workspace definition
├── crates/                      # Modular components
│   ├── solver-account/          # Cryptographic operations
│   ├── solver-config/           # Configuration management
│   ├── solver-core/             # Orchestration engine
│   ├── solver-delivery/         # Transaction submission
│   ├── solver-discovery/        # Intent monitoring
│   ├── solver-order/            # Order processing
│   ├── solver-service/          # Main executable
│   ├── solver-settlement/       # Settlement verification
│   ├── solver-storage/          # State persistence
│   └── solver-types/            # Shared types
├── config/                      # Configuration examples
└── scripts/                     # Deployment and demo scripts
```

## Directory Responsibilities

### Core Infrastructure

- **solver-types**: Common data structures and trait definitions shared across all modules
- **solver-config**: TOML-based configuration parsing and validation
- **solver-storage**: Persistent state management with custom backends
- **solver-account**: Secure key management and transaction signing

### Service Layer

- **solver-discovery**: Multi-chain event monitoring and intent detection
- **solver-order**: Intent validation, strategy evaluation, and transaction generation
- **solver-delivery**: Reliable transaction submission and confirmation monitoring
- **solver-settlement**: Fill validation and oracle verification management

### Orchestration

- **solver-core**: Event-driven orchestration of the entire order lifecycle
- **solver-service**: Binary entry point that wires up all components

## High-Level System Flow

```mermaid
sequenceDiagram
    participant External as External Sources
    participant Discovery as Discovery Service
    participant Core as Core Engine
    participant Storage as Storage Service
    participant Order as Order Service
    participant Delivery as Delivery Service
    participant Settlement as Settlement Service

    Note over External,Settlement: Intent Discovery & Processing
    External->>Discovery: New Intent Event
    Discovery->>Core: Intent Discovered
    Core->>Order: Validate Intent
    Order->>Core: Validated Order
    Core->>Storage: Store Order

    Note over Core,Settlement: Intent Processing
    Core->>Order: Check Execution Strategy
    Order->>Core: Execute Decision
    Core->>Order: Generate Fill Transaction
    Order->>Core: Transaction Ready
    Core->>Delivery: Submit Transaction
    Delivery->>Core: Transaction Submitted

    Note over Core,Settlement: Settlement Processing
    Core->>Delivery: Monitor Transaction
    Delivery->>Core: Transaction Confirmed
    Core->>Settlement: Validate Fill
    Settlement->>Core: Fill Validated
    Core->>Order: Generate Claim
    Core->>Delivery: Submit Claim
    Delivery->>Core: Claim Confirmed
```

## Module Deep Dive

### solver-discovery

Monitors multiple chains simultaneously for new intent events.

```mermaid
sequenceDiagram
    participant Chain as Blockchain
    participant Discovery as DiscoveryService
    participant Core as Core Engine

    loop Event Monitoring
        Discovery->>Chain: Poll for Events
        Chain->>Discovery: Return New Events
        Discovery->>Discovery: Filter & Validate
        Discovery->>Core: Push Valid Intents
    end
```

### solver-order

Processes intents through validation, strategy evaluation, and transaction generation.

```mermaid
sequenceDiagram
    participant Core as Core Engine
    participant Order as OrderService
    participant Strategy as Execution Strategy
    participant Implementation as Order Implementation

    Core->>Order: validate_intent(intent)
    Order->>Implementation: Parse & Validate
    Implementation->>Order: Return Order
    Core->>Order: should_execute(order)
    Order->>Strategy: Evaluate Conditions
    Strategy->>Order: Execution Decision
    Core->>Order: generate_fill_transaction()
    Order->>Implementation: Build Transaction
    Implementation->>Order: Return Transaction
```

### solver-delivery

Handles reliable transaction submission with monitoring and retry logic.

```mermaid
sequenceDiagram
    participant Core as Core Engine
    participant Delivery as DeliveryService
    participant Provider as Chain Provider
    participant Chain as Blockchain

    Core->>Delivery: deliver(transaction)
    Delivery->>Provider: Submit Transaction
    Provider->>Chain: Broadcast
    Chain->>Provider: Return TX Hash
    Provider->>Delivery: Return Hash
    Delivery->>Core: Transaction Submitted

    loop Monitor Confirmation
        Delivery->>Provider: Check Status
        Provider->>Chain: Query Receipt
        Chain->>Provider: Return Status
    end

    Delivery->>Core: Transaction Confirmed
```

### solver-settlement

Validates fills and manages the claim process for completed orders.

```mermaid
sequenceDiagram
    participant Core as Core Engine
    participant Settlement as SettlementService
    participant Chain as Blockchain

    Core->>Settlement: get_attestation(order, tx_hash)
    Settlement->>Chain: Get Transaction Receipt
    Settlement->>Settlement: Extract Fill Proof
    Settlement->>Core: Return Proof

    loop Check Claim Readiness
        Core->>Settlement: can_claim(order, proof)
        Settlement->>Chain: Check Conditions
        Settlement->>Core: Return Status
    end

    Core->>Settlement: Ready to Claim
```

### solver-core

Orchestrates the entire solver workflow through event-driven architecture.

```mermaid
sequenceDiagram
    participant Discovery as Discovery
    participant Core as Core Engine
    participant EventBus as Event Bus
    participant Services as Other Services

    Discovery->>Core: Intent Discovered
    Core->>EventBus: Publish Event
    EventBus->>Services: Broadcast Event
    Services->>EventBus: Publish Response Events
    EventBus->>Core: Deliver Events
    Core->>Core: Process & Coordinate
```

## Conclusion

The event-driven architecture ensures responsive processing of intents, while the clear separation of concerns makes the system easy to understand and extend. Whether used as a complete solver or as individual components, the OIF Solver provides the building blocks for sophisticated cross-chain execution strategies.