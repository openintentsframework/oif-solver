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
            CostProfit[engine/cost_profit.rs<br/>Cost Estimation & Profitability]
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
    IntentHandler --> CostProfit
    OrderHandler --> CostProfit

    Engine --> Context
    Engine --> Lifecycle
    Engine --> TokenManager
    Engine --> CostProfit

    CostProfit --> TokenManager

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

## Cost & Profitability Logic

The `CostProfitService` is a critical component that ensures orders are economically viable before execution. It provides comprehensive cost estimation and profitability validation across multiple blockchain networks.

### Cost Estimation Process

The service calculates execution costs through several components:

**1. Gas Cost Estimation**

- **Open Transaction**: Cost to initiate the order on the origin chain
- **Fill Transaction**: Cost to fulfill the order on the destination chain
- **Claim Transaction**: Cost to claim rewards/settle on the origin chain
- Uses configurable gas units per transaction type with fallback estimates
- Converts gas costs to USD using current gas prices and ETH/USD rates

**2. Operational Cost Calculation**

- Commission fees (configurable basis points)
- Gas buffer (safety margin for gas price volatility)
- Rate buffer (protection against price fluctuations)
- All costs normalized to USD for consistent comparison

### Profitability Validation

The profit margin calculation follows this formula:

**Validation Process:**

1. Parse order data to extract input/output amounts and token addresses
2. Use `TokenManager` to get token metadata (symbol, decimals)
3. Convert all token amounts to USD using `PricingService`
4. Calculate total execution costs from `CostEstimate`
5. Compute profit margin percentage
6. Validate against configurable solver's minimum profitability threshold

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
