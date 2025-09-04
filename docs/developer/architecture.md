# Architecture Guide

This document provides a comprehensive overview of the OIF Solver's architecture, design principles, and how the different components work together to enable cross-chain intent execution.

## Design Principles

### Modular Architecture

The OIF Solver is built as a collection of loosely-coupled, specialized components. Each component has a single responsibility and communicates with others through well-defined interfaces. This approach provides:

- **Maintainability**: Individual components can be developed, tested, and debugged in isolation
- **Extensibility**: New implementations can be added without modifying existing code
- **Testability**: Each component can be unit tested with mocked dependencies

### Event-Driven Design

All components communicate through a centralized event system, enabling:

- **Asynchronous Processing**: Components don't block each other
- **Loose Coupling**: Components only need to know about events, not other components
- **Scalability**: Easy to add new event handlers and processors
- **Observability**: All interactions are captured as events for monitoring

### Multi-Chain Native

Built from the ground up for cross-chain operations:

- **Concurrent Monitoring**: Simultaneously monitor multiple blockchain networks
- **Chain-Specific Optimizations**: Each network can have tailored configurations
- **Unified Interface**: Consistent API regardless of the underlying blockchain
- **Future-Proof**: Easy to add support for new blockchain networks

## High-Level Architecture

```mermaid
graph TB
    subgraph "External Sources"
        OnChain[On-Chain Events]
        OffChain[Off-Chain APIs]
        RestAPI[REST API Clients]
    end

    subgraph "OIF Solver"
        subgraph "Discovery Layer"
            DiscoveryService[Discovery Service]
            OnChainDisc[On-Chain Discovery]
            OffChainDisc[Off-Chain Discovery]
        end

        subgraph "Core Engine"
            CoreEngine[Core Engine]
            EventBus[Event Bus]
            StateMachine[Order State Machine]
        end

        subgraph "Service Layer"
            OrderService[Order Service]
            DeliveryService[Delivery Service]
            SettlementService[Settlement Service]
        end

        subgraph "Infrastructure"
            StorageService[Storage Service]
            AccountService[Account Service]
            ConfigService[Config Service]
        end
    end

    subgraph "Blockchain Networks"
        OriginChain[Origin Chain]
        DestChain[Destination Chain]
        OtherChains[Other Chains...]
    end

    OnChain --> OnChainDisc
    OffChain --> OffChainDisc
    RestAPI --> OffChainDisc

    OnChainDisc --> DiscoveryService
    OffChainDisc --> DiscoveryService
    DiscoveryService --> CoreEngine

    CoreEngine --> EventBus
    EventBus --> OrderService
    EventBus --> DeliveryService
    EventBus --> SettlementService

    OrderService --> StorageService
    DeliveryService --> AccountService
    SettlementService --> StorageService

    DeliveryService --> OriginChain
    DeliveryService --> DestChain
    DeliveryService --> OtherChains

    SettlementService --> OriginChain
    SettlementService --> DestChain
```

## Component Architecture

### Core Engine (solver-core)

The orchestration layer that coordinates all other components.

**Responsibilities:**

- Event-driven workflow orchestration
- Order state management and transitions
- Component lifecycle management
- Error handling and recovery
- Graceful shutdown coordination

**Event Flow:**

1. Receives events from discovery services
2. Routes events to appropriate handlers
3. Manages order state transitions
4. Coordinates multi-step operations

### Discovery Layer (solver-discovery)

Monitors various sources for new cross-chain intents.

**Discovery Sources:**

- **On-Chain Discovery**: Monitors blockchain events for intent submissions
- **Off-Chain Discovery**: Receives intents via REST API endpoints
- **Future Sources**: Extensible to support new discovery mechanisms

### Service Layer

#### Order Service (solver-order)

Handles intent validation, execution strategy evaluation, and transaction generation.

**Order Lifecycle:**

1. **Validation**: Parse and validate intent data
2. **Strategy Evaluation**: Determine optimal execution timing
3. **Transaction Generation**: Create blockchain transactions
4. **State Updates**: Track order progress

#### Delivery Service (solver-delivery)

Manages reliable transaction submission (alloy-implementation) and monitoring across multiple blockchain networks.

**Features:**

- Multi-chain transaction submission
- Confirmation monitoring with configurable depth
- Gas estimation and pricing
- Transaction status tracking

#### Settlement Service (solver-settlement)

Handles post-execution settlement verification and claim processing.

**Settlement Flow:**

1. **Fill Validation**: Verify transaction execution and extract proofs
2. **Dispute Period Monitoring**: Wait for required settlement windows
3. **Claim Generation**: Create claim transactions when ready
4. **Oracle Verification**: Validate cross-chain proofs

### Infrastructure Layer

#### Storage Service (solver-storage)

Provides persistent state management with TTL support.

**Features:**

- Configurable TTL for different data types
- Automatic cleanup of expired data
- Multiple backend implementations (file, future: database)
- Atomic operations for critical data

#### Account Service (solver-account)

Manages cryptographic keys and signing on-chain operations.

**Security Features:**

- Secure key storage and handling
- Multiple account support
- Per-network account mapping

## Data Flow Architecture

### Intent Discovery Flow

```mermaid
sequenceDiagram
    participant External as External Source
    participant Discovery as Discovery Service
    participant Core as Core Engine
    participant Storage as Storage Service

    External->>Discovery: New Intent Event
    Discovery->>Discovery: Validate Intent Format
    Discovery->>Core: IntentDiscovered Event
    Core->>Storage: Store Intent
    Core->>Core: Queue for Processing
```

### Order Processing Flow

```mermaid
sequenceDiagram
    participant Core as Core Engine
    participant Order as Order Service
    participant Delivery as Delivery Service
    participant Settlement as Settlement Service
    participant Storage as Storage Service

    Note over Core,Storage: Intent Processing
    Core->>Order: Validate Intent
    Order->>Core: Validated Order
    Core->>Storage: Store Order

    Note over Core,Storage: Execution Decision
    Core->>Order: Should Execute?
    Order->>Core: Execution Decision
    Core->>Order: Generate Fill Transaction
    Order->>Core: Fill Transaction Ready

    Note over Core,Storage: Transaction Delivery
    Core->>Delivery: Submit Transaction
    Delivery->>Core: Transaction Submitted
    Core->>Storage: Update Order Status

    Note over Core,Storage: Settlement Processing
    Delivery->>Core: Transaction Confirmed
    Core->>Settlement: Validate Fill
    Settlement->>Core: Fill Validated
    Core->>Storage: Store Fill Proof

    Note over Core,Storage: Claim Processing
    Settlement->>Core: Claim Ready
    Core->>Order: Generate Claim Transaction
    Order->>Core: Claim Transaction Ready
    Core->>Delivery: Submit Claim
    Delivery->>Core: Claim Confirmed
    Core->>Storage: Mark Order Complete
```

## State Management

### Order State Machine

Orders progress through defined states with clear transitions:

```mermaid
stateDiagram-v2
    [*] --> Discovered: Intent Discovered
    Discovered --> Validated: Intent Validation
    Validated --> Pending: Strategy Evaluation
    Pending --> Executing: Execution Decision
    Executing --> Executed: Fill Confirmed
    Executed --> PostFilled: Post-Fill Complete
    PostFilled --> PreClaimed: Pre-Claim Complete
    PreClaimed --> Finalized: Claim Confirmed
    Finalized --> [*]

    Validated --> Failed: Validation Error
    Pending --> Failed: Strategy Rejection
    Executing --> Failed: Execution Error
    Failed --> [*]
```

**State Descriptions:**

- **Discovered**: Intent received but not yet processed
- **Validated**: Intent successfully parsed and validated
- **Pending**: Awaiting execution decision from strategy
- **Executing**: Fill transaction in progress
- **Executed**: Fill transaction confirmed
- **PostFilled**: Post-fill processing completed
- **PreClaimed**: Pre-claim transaction completed (if required)
- **Finalized**: Order fully completed with claim
- **Failed**: Order failed at some stage

## Error Handling Strategy

### Layered Error Handling

1. **Component Level**: Each component handles its specific errors
2. **Service Level**: Services aggregate and transform component errors
3. **Core Level**: Core engine handles workflow errors and recovery
4. **Application Level**: Top-level error handling for unrecoverable errors

This architecture provides a solid foundation for reliable, scalable cross-chain intent execution while remaining flexible for future requirements and enhancements.
