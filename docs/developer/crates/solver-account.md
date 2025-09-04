# solver-account

## Purpose & Scope

The `solver-account` crate manages cryptographic key storage, transaction signing, and account management for the OIF Solver. It provides secure key handling, multi-network account mapping, and transaction signing capabilities while maintaining security best practices for private key management.

## Internal Architecture

```mermaid
graph TB
    subgraph "solver-account Internal Structure"
        subgraph "Main Service"
            AccountService[lib.rs<br/>Account Service Interface]
        end

        subgraph "Account Implementations"
            LocalAccount[implementations/local.rs<br/>Local Private Key Storage]
            FutureImpls[Future: Hardware Wallets<br/>HSM, Ledger, etc.]
        end

        subgraph "Core Components"
            KeyManagement[Key Management<br/>Secure Storage & Access]
            TransactionSigning[Transaction Signing<br/>Multi-Chain Support]
            AccountMapping[Account Mapping<br/>Network-Specific Addresses]
            SecurityLayer[Security Layer<br/>Access Control & Validation]
        end
    end

    AccountService --> LocalAccount
    LocalAccount --> KeyManagement
    LocalAccount --> TransactionSigning
    LocalAccount --> AccountMapping
    LocalAccount --> SecurityLayer

    FutureImpls -.-> AccountService
```

## Account Management Flow

```mermaid
sequenceDiagram
    participant Config as Configuration
    participant Account as Account Service
    participant KeyStore as Key Storage
    participant Signer as Transaction Signer
    participant Network as Blockchain Network

    Config->>Account: Load Account Configuration
    Account->>KeyStore: Initialize Key Storage
    KeyStore->>Account: Keys Loaded Successfully

    Note over Account,Network: Transaction Signing Process
    Account->>Signer: Sign Transaction Request
    Signer->>KeyStore: Retrieve Private Key
    KeyStore->>Signer: Private Key (Secure)
    Signer->>Signer: Generate Signature
    Signer->>Account: Signed Transaction
    Account->>Network: Submit Signed Transaction
```

## Implementation Caveats

### 🔒 Security Considerations

- **Private Key Storage**: Keys must be encrypted at rest and never logged

## Extension Points

### Custom Account Implementations

1. Implement the `AccountService` trait for new account types
2. Add support for hardware wallets (Ledger, Trezor, etc.)
3. Integrate with enterprise key management systems
4. Add support for multi-signature accounts

The solver-account crate provides secure, flexible account management with strong cryptographic foundations while supporting multiple blockchain networks and various key storage mechanisms.
