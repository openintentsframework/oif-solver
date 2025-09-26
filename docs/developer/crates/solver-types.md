# solver-types

## Purpose & Scope

The `solver-types` crate serves as the foundational layer for the entire OIF Solver ecosystem, providing shared data structures, traits, and type definitions used across all components. This crate ensures type consistency and enables seamless communication between different solver components.

## Internal Architecture

```mermaid
graph TB
    subgraph "solver-types Internal Structure"
        subgraph "Core Types"
            Account[account.rs<br/>Account & Signing Types]
            API[api.rs<br/>API Structures]
            Auth[auth.rs<br/>Authentication Types]
            Networks[networks.rs<br/>Network Definitions]
            Order[order.rs<br/>Order Types & States]
        end

        subgraph "Domain Types"
            Costs[costs.rs<br/>Cost Calculations]
            Delivery[delivery.rs<br/>Delivery Service Types]
            Discovery[discovery.rs<br/>Discovery Types]
            Events[events.rs<br/>Inter-Component Events]
            Oracle[oracle.rs<br/>Oracle Types]
            Pricing[pricing.rs<br/>Pricing Types]
            Registry[registry.rs<br/>Registry Types]
            Storage[storage.rs<br/>Storage Types]
        end

        subgraph "Standards"
            EIP7683[eip7683.rs<br/>Intent Standard Types]
            EIP7930[eip7930.rs<br/>Interoperable Address]
        end

        subgraph "Utilities"
            Constants[constants.rs<br/>Common Constants]
            Conversion[conversion.rs<br/>Type Conversions]
            EIP712[eip712.rs<br/>Signing Utilities]
            Formatting[formatting.rs<br/>Display & Formatting]
            Helpers[helpers.rs<br/>General Utilities]
            Validation[validation.rs<br/>Input Validation]
            SecretString[secret_string.rs<br/>Secure String Handling]
        end

        subgraph "Testing Support"
            TestBuilders[tests/<br/>Builder Patterns for Testing]
        end
    end
```

## Dependencies

- **No Business Logic**: Pure data types and utilities only
- **Workspace Consistency**: Uses workspace-level dependency versions

This foundational crate ensures type safety and consistency across the entire solver ecosystem while providing comprehensive testing utilities and clear extension points for future protocol support.
