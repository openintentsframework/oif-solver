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
            MemoryStorage[implementations/memory.rs<br/>In-memory Storage]
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
        OrderData[Order State<br/>Lifecycle Tracking]
        IntentData[Intent Cache<br/>Discovery Results]
        ProofData[Settlement Proofs<br/>Verification Evidence]
        ConfigData[Configuration<br/>Runtime Settings]
        MetricsData[Performance Metrics<br/>Historical Data]
        TempData[Temporary Data<br/>Short-lived Cache]
    end

    OrderData --> |7 days TTL| TTLManager
    IntentData --> |24 hours TTL| TTLManager
    ProofData --> |30 days TTL| TTLManager
    ConfigData --> |No TTL| TTLManager
    MetricsData --> |90 days TTL| TTLManager
    TempData --> |1 hour TTL| TTLManager
```

## Configuration Examples

### Storage Backend Configuration

```toml
[storage]
backend = "file"
data_dir = "/var/lib/solver/data"
default_ttl_seconds = 86400  # 24 hours
cleanup_interval_seconds = 3600  # 1 hour
max_key_size = 256
max_value_size = 1048576  # 1MB

[storage.ttl]
order_state_seconds = 604800      # 7 days
intent_cache_seconds = 86400      # 24 hours
settlement_proof_seconds = 2592000 # 30 days
configuration_seconds = 0         # No expiration
metrics_seconds = 7776000         # 90 days
temporary_seconds = 3600          # 1 hour
```

## Extension Points

### Custom Storage Backends

1. Implement the `StorageService` trait for new backends
2. Add backend-specific configuration options
3. Handle backend-specific features (e.g., transactions, indexes)

The solver-storage crate provides flexible, persistent storage capabilities with automatic cleanup and multiple backend support while maintaining data consistency and performance across the solver system.
