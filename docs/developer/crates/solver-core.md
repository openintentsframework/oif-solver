# solver-core

## Purpose & Scope

The `solver-core` crate serves as the orchestration engine for the entire OIF Solver system. It provides event-driven workflow coordination, order state management, and component lifecycle management. This crate acts as the central nervous system that coordinates all other solver components through a unified event bus architecture.

## Internal Architecture

```mermaid
graph TB
    subgraph "solver-core Internal Structure"
        subgraph "Core Engine"
            Engine[engine/mod.rs<br/>Main Engine Coordination]
            Context[engine/context.rs<br/>Execution Context]
            EventBus[engine/event_bus.rs<br/>Event Distribution]
            Lifecycle[engine/lifecycle.rs<br/>Component Management]
            TokenManager[engine/token_manager.rs<br/>Token Utilities]
        end

        subgraph "Event Handlers"
            IntentHandler[handlers/intent.rs<br/>Intent Processing]
            OrderHandler[handlers/order.rs<br/>Order Lifecycle]
            SettlementHandler[handlers/settlement.rs<br/>Settlement Events]
            TransactionHandler[handlers/transaction.rs<br/>Transaction Events]
        end

        subgraph "State Management"
            OrderState[state/order.rs<br/>Order State Machine]
            StateManager[state/mod.rs<br/>State Coordination]
        end

        subgraph "Monitoring"
            SettlementMonitor[monitoring/settlement.rs<br/>Settlement Tracking]
            TransactionMonitor[monitoring/transaction.rs<br/>Transaction Tracking]
        end

        subgraph "Recovery"
            RecoveryMechanism[recovery/mod.rs<br/>Error Recovery Logic]
        end

        subgraph "Configuration Builder"
            SolverBuilder[builder/mod.rs<br/>Solver Configuration]
        end
    end

    Engine --> EventBus
    EventBus --> IntentHandler
    EventBus --> OrderHandler
    EventBus --> SettlementHandler
    EventBus --> TransactionHandler

    IntentHandler --> OrderState
    OrderHandler --> OrderState

    Engine --> Context
    Engine --> Lifecycle
    Engine --> TokenManager

    SettlementMonitor --> EventBus
    TransactionMonitor --> EventBus
```

## Event Flow Architecture

```mermaid
sequenceDiagram
    participant External as External Component
    participant Engine as Solver Engine
    participant EventBus as Event Bus
    participant Handler as Event Handler
    participant State as State Manager
    participant Storage as Storage Service

    External->>Engine: Component Event
    Engine->>EventBus: Route Event
    EventBus->>Handler: Process Event
    Handler->>State: Check State Transition
    State->>Handler: Validate Transition
    Handler->>Storage: Update State
    Handler->>EventBus: Emit Follow-up Events
    EventBus->>Engine: Event Processed
```

## Extension Points

### Adding New Event Handlers

1. Implement the `EventHandler` trait
2. Register with the event bus during engine initialization
3. Handle relevant events and emit follow-up events as needed

### Custom State Machines

1. Implement the `StateMachine` trait for your state/event types
2. Integrate with the existing state management system
3. Ensure proper state persistence and recovery

### Monitoring Components

1. Create monitoring services that subscribe to relevant events
2. Implement health checks and metrics collection
3. Register with the lifecycle manager for proper shutdown handling

The solver-core crate provides the foundation for reliable, event-driven cross-chain intent execution while maintaining clear separation of concerns and extensibility for future requirements.
