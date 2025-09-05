# solver-delivery

## Purpose & Scope

The `solver-delivery` crate manages reliable transaction submission and monitoring across multiple blockchain networks. It handles gas optimization, confirmation tracking, retry logic, and provides a unified interface for multi-chain transaction delivery regardless of the underlying blockchain implementation.

## Internal Architecture

```mermaid
graph TB
    subgraph "solver-delivery Internal Structure"
        subgraph "Main Service"
            DeliveryService[lib.rs<br/>Multi-Chain Orchestration]
        end

        subgraph "EVM Implementation"
            AlloyImpl[implementations/evm/alloy.rs<br/>Alloy-based EVM Delivery]
        end

        subgraph "Core Components"
            TxSubmission[Transaction Submission<br/>Broadcast & Nonce Management]
            ConfirmationMonitor[Confirmation Monitoring<br/>Block Depth Tracking]
            GasOptimization[Gas Management<br/>Price Estimation & Optimization]
            StateTracking[Status Tracking<br/>Transaction Lifecycle]
        end
    end

    DeliveryService --> AlloyImpl
    AlloyImpl --> TxSubmission
    AlloyImpl --> ConfirmationMonitor
    AlloyImpl --> GasOptimization
    AlloyImpl --> RetryLogic
    AlloyImpl --> StateTracking
```

## Transaction Delivery Flow

```mermaid
sequenceDiagram
    participant Order as Order Service
    participant Delivery as Delivery Service
    participant GasEst as Gas Estimator
    participant Blockchain as Blockchain Network
    participant Monitor as Confirmation Monitor
    participant Core as Core Engine

    Order->>Delivery: Submit Transaction
    Delivery->>GasEst: Estimate Gas & Price
    GasEst->>Delivery: Gas Parameters
    Delivery->>Blockchain: Broadcast Transaction
    Blockchain->>Delivery: Transaction Hash
    Delivery->>Core: Transaction Submitted Event

    loop Confirmation Monitoring
        Monitor->>Blockchain: Check Transaction Status
        Blockchain->>Monitor: Confirmation Status

        alt Insufficient Confirmations
            Monitor->>Monitor: Wait for Next Block
        else Sufficient Confirmations
            Monitor->>Core: Transaction Confirmed Event
        else Transaction Failed
            Monitor->>Delivery: Retry Transaction
            Delivery->>GasEst: Re-estimate Gas
            GasEst->>Delivery: Updated Gas Parameters
            Delivery->>Blockchain: Broadcast Retry
        end
    end
```

## Implementation Caveats

### ⛽ Gas Management Complexity

- **EIP-1559**
- **Network Congestion**: Gas prices can spike rapidly during network congestion
- **Priority Fee Optimization**: Balancing cost vs confirmation speed requires careful tuning
- **Gas Limit Estimation**: Contract interactions may require complex gas limit calculations

### 🔍 Monitoring and Observability

- **Transaction Tracing**: Complete audit trail for all transaction attempts
- **Performance Metrics**: Gas efficiency, confirmation times, and success rates
- **Error Analysis**: Categorizing and analyzing transaction failures
- **Cost Tracking**: Monitoring gas costs across different networks and strategies

## Extension Points

### Adding New Blockchain Networks

1. Create implementation modules for the new blockchain type
2. Implement the `DeliveryService` trait with network-specific logic
3. Add network-specific gas estimation and confirmation logic
4. Handle network-specific transaction formats and requirements

The solver-delivery crate provides robust, multi-chain transaction delivery with sophisticated gas management and retry mechanisms while maintaining flexibility for different blockchain networks and use cases.
