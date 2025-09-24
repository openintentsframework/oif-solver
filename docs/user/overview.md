# Overview

## What is the OIF Solver?

The OIF Solver is a high-performance cross-chain execution system designed for the Open Intents Framework (OIF). It acts as an autonomous service that discovers, validates, and executes cross-chain intents, enabling seamless asset transfers and operations across multiple blockchain networks.

## Key Capabilities

### Cross-Chain Intent Execution

- **Discover Intents**: Monitor multiple blockchain networks simultaneously for new cross-chain intent events
- **Validate Orders**: Parse and validate intent data according to EIP-7683 and other supported protocols
- **Execute Efficiently**: Find optimal execution paths while minimizing costs and maximizing reliability
- **Settle Securely**: Handle the complete settlement process including fill verification and claim processing

### Multi-Protocol Support

- **EIP-7683**: Full support for the Cross-Chain Intents Standard
- **Multiple Order Types**: Support for escrow and compact settlement patterns
- **Flexible Authorization**: Compatible with Permit2 and EIP-3009 authorization methods (The compact with Allocator is another auth mechanism?)

### Production-Ready Features

- **High Performance**: Built in Rust for optimal performance in time-sensitive cross-chain operations
- **Reliable Execution**: Robust error handling and transaction monitoring
- **Comprehensive Monitoring**: Built-in observability with detailed logging and metrics
- **Flexible Configuration**: Modular configuration system supporting multiple networks and customization

## How It Works

The OIF Solver operates through a multi-stage pipeline:

### 1. Intent Discovery

The solver monitors configured blockchain networks for new intent events. It can discover intents through:

- **On-chain monitoring**: Direct blockchain event monitoring
- **Off-chain APIs**: REST API endpoints for intent submission
- **Multiple sources**: Simultaneous monitoring of various discovery channels

### 2. Intent Validation

Once an intent is discovered, the solver:

- Parses the intent data according to the specified protocol
- Validates the intent structure and parameters
- Checks for sufficient liquidity and feasibility
- Converts valid intents into executable orders

### 3. Profitability Analysis

Before accepting any intent, the solver performs a comprehensive profitability analysis to ensure execution will be financially viable:

#### Cost Calculation

The solver calculates all operational costs involved in executing the cross-chain intent:

- **Gas Costs**: Estimates gas fees for all required transactions:
  - **Open transaction**: On the origin chain to initiate the intent
  - **Fill transaction**: On the destination chain to fulfill the user's request
  - **Claim transaction**: On the origin chain to complete settlement
- **Gas Buffer**: Adds a configurable buffer (in basis points) to account for gas price volatility
- **Base Price**: Covers any negative spread when output value exceeds input value
- **Commission**: Optional percentage fee on the total transaction value

#### Profit Margin Calculation

The solver calculates profit margin using this formula:

All token amounts are converted to USD using real-time pricing data to ensure accurate cross-token comparisons.

#### Profitability Validation

Each intent must meet the configured minimum profitability threshold (`min_profitability_pct`) before execution:

- **Threshold Check**: The calculated profit margin must exceed the minimum required percentage
- **Automatic Rejection**: Intents failing profitability validation are automatically skipped
- **Configurable Minimum**: Operators can set their desired minimum profit margin (e.g., 1.0% in demo configurations)

This ensures the solver only executes intents that provide adequate compensation for the operational costs and risks involved.

### 4. Execution Strategy

The solver evaluates when and how to execute orders based on:

- **Market conditions**: Gas prices, liquidity, and timing
- **Execution strategies**: Configurable logic for optimal execution timing
- **Risk assessment**: Safety checks and validation before execution

### 5. Transaction Execution

When ready to execute:

- Generates the necessary blockchain transactions (fill, post-fill, etc.)
- Submits transactions to the appropriate networks
- Monitors transaction confirmation and status
- Handles retries and error recovery

### 6. Settlement Processing

After successful execution:

- Validates fill transactions and extracts proofs
- Monitors dispute periods and settlement conditions
- Generates and submits claim transactions when ready
- Completes the cross-chain settlement process

## Use Cases

### Cross-Chain Asset Transfers

Enable users to seamlessly move assets between different blockchain networks without manual intervention or complex multi-step processes.

### Cross-Chain DeFi Operations

Facilitate complex DeFi operations that span multiple chains, such as borrowing on one chain against collateral on another.

### Automated Market Making

Provide liquidity for cross-chain operations while earning fees from successful intent executions.

### Protocol Integration

Integrate cross-chain functionality into existing DeFi protocols and applications.

## Architecture Highlights

### Modular Design

The solver is built as a collection of specialized components, each handling a specific aspect of the cross-chain execution process. This modularity enables:

- Independent development and testing
- Easy customization and extension
- Clear separation of concerns
- Reliable and maintainable codebase

### Event-Driven Architecture

All components communicate through a centralized event system, ensuring:

- Loose coupling between components
- Asynchronous processing capabilities
- Easy addition of new features and integrations
- Robust error handling and recovery

### Multi-Chain Native

Designed from the ground up to handle multiple blockchain networks simultaneously:

- Concurrent monitoring of multiple chains
- Chain-specific optimizations and configurations
- Unified interface across different networks
- Scalable to new blockchain networks

## Getting Started

Ready to start using the OIF Solver? Check out our [Quickstart Guide](quickstart.md) to get up and running in minutes, or explore the [Configuration Guide](configuration.md) for more advanced setup options.
