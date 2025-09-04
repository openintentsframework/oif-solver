# solver-settlement

## Purpose & Scope

The `solver-settlement` crate handles post-execution settlement verification, claim processing, and dispute resolution for cross-chain intents. It validates fill transactions, manages dispute periods, coordinates oracle verification for cross-chain proofs, and generates claim transactions when ready.

## Internal Architecture

```mermaid
graph TB
    subgraph "solver-settlement Internal Structure"
        subgraph "Main Service"
            SettlementService[lib.rs<br/>Settlement Orchestration]
            Utils[utils.rs<br/>Settlement Utilities]
        end

        subgraph "Implementation"
            DirectSettlement[implementations/direct.rs<br/>Direct Settlement Logic]
            FutureImpls[Future: Oracle Settlement<br/>Cross-chain Proof Verification]
        end

        subgraph "Core Components"
            FillValidation[Fill Validation<br/>Transaction Verification]
            DisputePeriod[Dispute Period<br/>Timing Management]
            ProofExtraction[Proof Extraction<br/>Settlement Evidence]
            ClaimGeneration[Claim Generation<br/>Transaction Creation]
            OracleVerification[Oracle Verification<br/>Cross-chain Proof Validation]
        end
    end

    SettlementService --> DirectSettlement
    SettlementService --> Utils

    DirectSettlement --> FillValidation
    DirectSettlement --> DisputePeriod
    DirectSettlement --> ProofExtraction
    DirectSettlement --> ClaimGeneration

    FutureImpls -.-> OracleVerification
```

## Settlement Flow

```mermaid
sequenceDiagram
    participant Delivery as Delivery Service
    participant Settlement as Settlement Service
    participant Blockchain as Blockchain Network
    participant Oracle as Cross-chain Oracle
    participant Order as Order Service
    participant Core as Core Engine

    Delivery->>Settlement: Fill Transaction Confirmed
    Settlement->>Blockchain: Validate Fill Transaction
    Blockchain->>Settlement: Fill Details & Proof
    Settlement->>Settlement: Extract Settlement Proof
    Settlement->>Core: Fill Validated Event

    Note over Settlement,Core: Dispute Period Wait
    Settlement->>Settlement: Wait for Dispute Period

    alt Cross-chain Settlement
        Settlement->>Oracle: Submit Proof for Verification
        Oracle->>Settlement: Proof Verification Result
    end

    Settlement->>Order: Generate Claim Transaction
    Order->>Settlement: Claim Transaction Ready
    Settlement->>Core: Claim Ready Event
```

## Implementation Caveats

### ⏰ Timing Complexity

- **Dispute Periods**: Different protocols have varying dispute/challenge periods
- **Block Finality**: Must wait for sufficient finality before extracting proofs
- **Claim Deadlines**: Claims may have expiration deadlines that must be met

The solver-settlement crate provides comprehensive post-execution settlement capabilities while maintaining flexibility for different protocols, oracle systems, and dispute resolution mechanisms.
