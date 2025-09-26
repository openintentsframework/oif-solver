# Developer Documentation

This section provides technical details for developers who want to understand, extend, or contribute to the OIF Solver.

## [Architecture Guide](developer/architecture.md)

High-level system architecture, design principles, and how the different components work together in the cross-chain execution pipeline.

## [Project Structure](developer/project-structure.md)

Detailed breakdown of the codebase organization, workspace structure, and module responsibilities.

## Component Deep Dive

In-depth technical documentation for each solver component:

### Foundation Layer

- **[solver-types](developer/crates/solver-types.md)** - Shared data structures, traits, and type definitions

### Infrastructure Layer

- **[solver-config](developer/crates/solver-config.md)** - Configuration parsing, validation, and management
- **[solver-storage](developer/crates/solver-storage.md)** - Persistent storage abstraction with TTL management
- **[solver-account](developer/crates/solver-account.md)** - Cryptographic key management and transaction signing

### Service Layer

- **[solver-discovery](developer/crates/solver-discovery.md)** - Multi-source intent discovery and monitoring
- **[solver-order](developer/crates/solver-order.md)** - Intent validation, execution strategies, and transaction generation
- **[solver-delivery](developer/crates/solver-delivery.md)** - Reliable multi-chain transaction submission and monitoring
- **[solver-settlement](developer/crates/solver-settlement.md)** - Post-execution settlement verification and claim processing
- **[solver-pricing](developer/crates/solver-pricing.md)** - Fee calculation and pricing strategies

### Orchestration Layer

- **[solver-core](developer/crates/solver-core.md)** - Event-driven orchestration of the entire solver workflow

### Application Layer

- **[solver-service](developer/crates/solver-service.md)** - Main executable that wires up all components

Each crate documentation includes:

- **Purpose & Scope**: What the crate does and its responsibilities
- **Internal Architecture**: Visual diagrams showing component structure
- **Configuration Examples**: TOML configuration snippets
- **Extension Points**: How to add new functionality

## [Contribution Guidelines](developer/contributing.md)

How to contribute to the project, development workflow, coding standards, and pull request process.
