# solver-order

## Purpose & Scope

The `solver-order` crate handles the core business logic of intent processing, including validation, execution strategy evaluation, and transaction generation. It transforms raw intents into executable blockchain transactions while applying sophisticated execution strategies to optimize timing, gas costs, and success rates.

## Internal Architecture

```mermaid
graph TB
    subgraph "solver-order Internal Structure"
        subgraph "Main Service"
            OrderService[lib.rs<br/>Order Service Orchestration]
        end

        subgraph "Protocol Standards"
            EIP7683Impl[implementations/standards/_7683.rs<br/>EIP-7683 Implementation]
            FutureProtocols[Future: Other Standards<br/>EIP-XXXX Implementations]
        end

        subgraph "Execution Strategies"
            SimpleStrategy[implementations/strategies/simple.rs<br/>Basic Execution Strategy]
        end

        subgraph "Processing Pipeline"
            Validation[Intent Validation<br/>Format & Business Logic]
            StrategyEval[Strategy Evaluation<br/>Timing & Conditions]
            TxGeneration[Transaction Generation<br/>Fill & Claim Transactions]
            StateUpdates[State Management<br/>Order State Tracking]
        end
    end

    OrderService --> EIP7683Impl
    OrderService --> SimpleStrategy

    EIP7683Impl --> Validation
    Validation --> StrategyEval
    StrategyEval --> TxGeneration
    TxGeneration --> StateUpdates

    FutureProtocols -.-> OrderService
    AdvancedStrategy -.-> OrderService
```

## Processing Pipeline

```mermaid
sequenceDiagram
    participant Core as Core Engine
    participant Order as Order Service
    participant Strategy as Execution Strategy
    participant Validation as Intent Validator
    participant TxGen as Transaction Generator
    participant Storage as Storage Service

    Core->>Order: Process Intent
    Order->>Validation: Validate Intent
    Validation->>Order: Validation Result

    alt Valid Intent
        Order->>Storage: Store Order
        Order->>Strategy: Evaluate Execution
        Strategy->>Strategy: Check Conditions
        Strategy->>Order: Execution Decision

        alt Should Execute
            Order->>TxGen: Generate Fill Transaction
            TxGen->>Order: Transaction Ready
            Order->>Core: Fill Transaction Event
        else Wait
            Order->>Core: Order Pending Event
        end
    else Invalid Intent
        Order->>Core: Intent Rejected Event
    end
```

## Implementation Caveats

### Intent Validation Complexity

- **Multi-Protocol Support**: Different intent standards have varying validation requirements
- **Asset Verification**: Must verify asset existence, decimals, and contract validity across chains
- **Signature Validation**: EIP-712 signature verification requires careful message reconstruction
- **Cross-Chain State**: Validating cross-chain asset balances and allowances is inherently slow

The solver-order crate provides sophisticated intent processing capabilities while maintaining flexibility for different protocols and execution strategies.
