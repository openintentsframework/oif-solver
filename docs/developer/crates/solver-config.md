# solver-config

## Purpose & Scope

The `solver-config` crate provides configuration parsing, validation, and management for the OIF Solver system. It handles TOML configuration files with include support, environment variable substitution, and comprehensive validation of network addresses, parameters, and component settings.

## Internal Architecture

```mermaid
graph TB
    subgraph "solver-config Internal Structure"
        subgraph "Main Module"
            ConfigLib[lib.rs<br/>Configuration Types & Validation]
            Loader[loader.rs<br/>File Loading & Processing]
        end

        subgraph "Configuration Builders"
            ConfigBuilder[builders/config.rs<br/>Fluent Configuration API]
            BuilderMod[builders/mod.rs<br/>Builder Pattern Support]
        end

        subgraph "Core Features"
            FileIncludes[File Includes<br/>Modular Configuration]
            EnvSubstitution[Environment Variables<br/>Runtime Substitution]
            Validation[Configuration Validation<br/>Network & Address Validation]
            Merging[Configuration Merging<br/>Override & Composition]
        end
    end

    ConfigLib --> Loader
    ConfigLib --> ConfigBuilder
    Loader --> FileIncludes
    Loader --> EnvSubstitution
    ConfigBuilder --> Validation
    ConfigBuilder --> Merging
```

## Configuration Structure

```mermaid
graph TB
    subgraph "Configuration Hierarchy"
        RootConfig[Root Configuration<br/>Main Settings]

        subgraph "Component Configs"
            NetworkConfig[Network Configuration<br/>Chain Settings]
            StorageConfig[Storage Configuration<br/>Backend Settings]
            AccountConfig[Account Configuration<br/>Key Management]
            DiscoveryConfig[Discovery Configuration<br/>Source Settings]
            DeliveryConfig[Delivery Configuration<br/>Transaction Settings]
        end

        subgraph "External Files"
            NetworksToml[networks.toml<br/>Chain Definitions]
            AccountsToml[accounts.toml<br/>Key Configuration]
            APIToml[api.toml<br/>Server Settings]
        end
    end

    RootConfig --> NetworkConfig
    RootConfig --> StorageConfig
    RootConfig --> AccountConfig
    RootConfig --> DiscoveryConfig
    RootConfig --> DeliveryConfig

    NetworkConfig -.-> NetworksToml
    AccountConfig -.-> AccountsToml
    DiscoveryConfig -.-> APIToml
```

The solver-config crate provides flexible, powerful configuration management with strong validation and modular organization while supporting complex deployment scenarios and operational requirements.
