# solver-service

## Purpose & Scope

The `solver-service` crate serves as the main executable that integrates all solver components into a cohesive application. It provides the command-line interface, HTTP API server, component factory registry, and application lifecycle management. This crate acts as the entry point and orchestration layer for the entire OIF Solver system.

## Internal Architecture

```mermaid
graph TB
    subgraph "solver-service Internal Structure"
        subgraph "Application Core"
            Main[main.rs<br/>Application Entry Point]
            Server[server.rs<br/>HTTP API Server]
            Factory[factory_registry.rs<br/>Component Factory]
        end

        subgraph "API Endpoints"
            OrderAPI[apis/order.rs<br/>Order Management API]
            TokensAPI[apis/tokens.rs<br/>Token Information API]
            RegisterAPI[apis/register.rs<br/>Registration Utilities]
        end

        subgraph "Quote Management"
            QuoteGen[apis/quote/generation.rs<br/>Quote Generation]
            QuoteRegistry[apis/quote/registry.rs<br/>Quote Management]
            QuoteValidation[apis/quote/validation.rs<br/>Quote Validation]
            QuoteCustody[apis/quote/custody.rs<br/>Asset Custody]
            QuoteSigning[apis/quote/signing/<br/>Quote Signing Utilities]
            QuoteCost[apis/quote/cost/<br/>Cost Calculation]
        end

        subgraph "Authentication"
            AuthMiddleware[auth/middleware.rs<br/>Authentication Middleware]
            AuthMod[auth/mod.rs<br/>Authentication Module]
        end
    end

    Main --> Server
    Main --> Factory
    Server --> OrderAPI
    Server --> TokensAPI
    Server --> RegisterAPI
    Server --> QuoteGen
    Server --> AuthMiddleware

    QuoteGen --> QuoteRegistry
    QuoteGen --> QuoteValidation
    QuoteGen --> QuoteCustody
    QuoteGen --> QuoteSigning
    QuoteGen --> QuoteCost
```

## Application Lifecycle

```mermaid
sequenceDiagram
    participant CLI as Command Line
    participant Main as Main Application
    participant Config as Configuration
    participant Factory as Component Factory
    participant Core as Solver Core
    participant Server as HTTP Server

    CLI->>Main: Start with CLI Arguments
    Main->>Config: Load Configuration
    Config->>Main: Validated Configuration
    Main->>Factory: Initialize Component Factory
    Factory->>Factory: Register All Components
    Factory->>Core: Build Solver Engine
    Core->>Main: Solver Engine Ready

    opt HTTP API Enabled
        Main->>Server: Start HTTP Server
        Server->>Main: Server Ready
    end

    Main->>Core: Start Solver Engine
    Core->>Main: Engine Started

    Note over Main,Server: Application Running

    CLI->>Main: Shutdown Signal (Ctrl+C)
    Main->>Server: Graceful Shutdown
    Main->>Core: Graceful Shutdown
    Core->>Main: Shutdown Complete
    Main->>CLI: Application Exit
```

## Implementation Caveats

### 🔐 Authentication and Authorization

- **JWT Token Management**: Secure token generation, validation, and refresh
- **Role-Based Access**: Different API endpoints may require different permissions
- **API Key Management**: Support for API key-based authentication
- **Audit Logging**: Log all authenticated operations for security analysis

### 📋 Logging and Observability

- **Structured Logging**: Consistent log format across all components
- **Log Level Management**: Dynamic log level adjustment without restart
- **Performance Metrics**: Application and business metrics collection

## Configuration Examples

### Application Configuration

```toml
# Application-level settings
[app]
name = "OIF Solver Production"
version = "1.0.0"
log_level = "info"
log_format = "json"
shutdown_timeout_seconds = 30

# HTTP API configuration
[api]
enabled = true
bind_address = "0.0.0.0:8080"
max_request_size = 1048576  # 1MB
request_timeout_seconds = 30
enable_cors = true
allowed_origins = ["https://app.example.com"]

# Authentication configuration
[api.auth]
type = "jwt"
jwt_secret = "${JWT_SECRET}"
jwt_expiry_seconds = 3600
require_auth = true

# Rate limiting
[api.rate_limit]
enabled = true
requests_per_minute = 100
burst_size = 20

# Logging configuration
[logging]
level = "info"
format = "json"
output = "stdout"
file_path = "/var/log/solver/application.log"
rotate_size_mb = 100
keep_files = 5

# Metrics and monitoring
[monitoring]
enabled = true
metrics_port = 9090
health_check_interval_seconds = 30
performance_metrics = true
```

### Production Deployment Configuration

```toml
# Production-specific settings
[app]
log_level = "warn"
log_format = "json"
performance_monitoring = true

[api]
bind_address = "0.0.0.0:8080"
max_connections = 1000
keepalive_timeout_seconds = 60
enable_compression = true

[api.security]
enable_https = true
cert_file = "/etc/ssl/certs/solver.crt"
key_file = "/etc/ssl/private/solver.key"
hsts_max_age = 31536000

[resources]
max_memory_mb = 2048
max_file_descriptors = 4096
thread_pool_size = 100

[monitoring]
prometheus_endpoint = "/metrics"
jaeger_endpoint = "http://jaeger:14268/api/traces"
log_sampling_rate = 0.1  # Sample 10% of logs
```

The solver-service crate provides a robust, production-ready application framework that integrates all solver components while maintaining operational excellence through comprehensive monitoring, logging, and configuration management.
