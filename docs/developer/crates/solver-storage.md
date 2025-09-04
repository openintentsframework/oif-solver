# solver-storage

## Purpose & Scope

The `solver-storage` crate provides persistent storage abstraction with TTL (Time-To-Live) management for the OIF Solver system. It handles order state persistence, intent caching, proof storage, and configuration data with automatic cleanup of expired data across multiple storage backends.

## Internal Architecture

```mermaid
graph TB
    subgraph "solver-storage Internal Structure"
        subgraph "Main Service"
            StorageService[lib.rs<br/>Storage Service Interface]
        end

        subgraph "Storage Backends"
            FileStorage[implementations/file.rs<br/>File-based Storage]
            FutureBackends[Future: Database Backends<br/>PostgreSQL, Redis, etc.]
        end

        subgraph "Core Features"
            TTLManager[TTL Management<br/>Automatic Expiration]
            Serialization[Data Serialization<br/>JSON/Binary Formats]
            AtomicOps[Atomic Operations<br/>Consistent Updates]
            Migration[Schema Migration<br/>Version Management]
            Cleanup[Background Cleanup<br/>Expired Data Removal]
        end
    end

    StorageService --> FileStorage
    StorageService --> MemoryStorage
    StorageService --> TTLManager
    StorageService --> Serialization
    StorageService --> AtomicOps

    TTLManager --> Cleanup
    FileStorage --> Migration
    FutureBackends -.-> StorageService
```

## Storage Data Types

```mermaid
graph LR
    subgraph "Stored Data Categories"
        OrderData[Orders<br/>Order Lifecycle & State]
        IntentData[Intents<br/>Cross-chain Intent Data]
        TxHashData[Order by TX Hash<br/>Transaction Hash Mapping]
        QuoteData[Quotes<br/>Generated Price Quotes]
    end

    OrderData --> |Configurable TTL| TTLManager[TTL Manager<br/>File Header Based]
    IntentData --> |Configurable TTL| TTLManager
    TxHashData --> |Configurable TTL| TTLManager
    QuoteData --> |Configurable TTL| TTLManager

    TTLManager --> |Default: No Expiration| Storage[File/Memory Storage]
```

## Configuration Examples

### Storage Backend Configuration

```toml
# Storage configuration with TTL management
[storage]
primary = "file"
cleanup_interval_seconds = 3600

[storage.implementations.file]
storage_path = "./data/storage"
ttl_orders = 0                  # Permanent
ttl_intents = 86400             # 24 hours
ttl_order_by_tx_hash = 86400    # 24 hours
```

## Extension Points

### Custom Storage Backends

1. Implement the `StorageService` trait for new backends
2. Add backend-specific configuration options
3. Handle backend-specific features (e.g., transactions, indexes)

The solver-storage crate provides flexible, persistent storage capabilities with automatic cleanup and multiple backend support while maintaining data consistency and performance across the solver system.
