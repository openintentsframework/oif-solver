# solver-pricing

## Purpose & Scope

The `solver-pricing` crate handles fee calculation, cost estimation, and pricing strategies for cross-chain intent execution. It provides profit analysis, gas cost estimation, and dynamic pricing mechanisms to ensure economically viable order execution across multiple blockchain networks.

## Internal Architecture (TBD)

```mermaid
graph TB
    subgraph "solver-pricing Internal Structure"
        subgraph "Main Service"
            PricingService[lib.rs<br/>Pricing Service Interface]
        end

        subgraph "Pricing Implementations"
            FuturePricing[Pricing<br/>Real-time Market Data]
        end

        subgraph "Core Components"
            CostCalculation[Cost Calculation<br/>Gas & Fee Estimation]
            ProfitAnalysis[Profit Analysis<br/>Revenue vs Costs]
            MarketData[Market Data<br/>Price Feeds & Rates]
            FeeOptimization[Fee Optimization<br/>Dynamic Pricing Strategy]
        end
    end

    PricingService --> FuturePricing
    FuturePricing --> CostCalculation
    FuturePricing --> ProfitAnalysis

    FuturePricing -.-> MarketData
    FuturePricing -.-> FeeOptimization
```

## Pricing Calculation Flow

```mermaid
sequenceDiagram
    participant Order as Order Service
    participant Pricing as Pricing Service
    participant MarketData as Market Data Provider
    participant GasOracle as Gas Price Oracle
    participant Strategy as Execution Strategy

    Order->>Pricing: Calculate Order Cost
    Pricing->>GasOracle: Get Gas Prices
    GasOracle->>Pricing: Gas Price Data
    Pricing->>MarketData: Get Token Prices
    MarketData->>Pricing: Token Price Data
    Pricing->>Pricing: Calculate Total Cost
    Pricing->>Order: Cost Estimate

    Order->>Pricing: Analyze Profitability
    Pricing->>Pricing: Calculate Revenue
    Pricing->>Pricing: Subtract Costs
    Pricing->>Strategy: Profit Analysis
    Strategy->>Order: Execution Decision
```

## Configuration Examples (TBD)

### Pricing Service Configuration (TBD)

```toml
[pricing]
default_price_source = "coingecko"
price_cache_ttl_seconds = 60
gas_price_cache_ttl_seconds = 30
min_profit_threshold_usd = 5.0
max_slippage_bps = 100  # 1%

[pricing.sources.coingecko]
api_key = "${COINGECKO_API_KEY}"
base_url = "https://api.coingecko.com/api/v3"
rate_limit_per_minute = 50

[pricing.sources.chainlink]
enabled = true
fallback_priority = 2

[pricing.gas_oracles]
[pricing.gas_oracles.ethereum]
source = "ethgasstation"
api_key = "${ETH_GAS_API_KEY}"
fallback_multiplier = 1.2

[pricing.gas_oracles.polygon]
source = "polygonscan"
api_key = "${POLYGON_API_KEY}"
fallback_multiplier = 1.1
```

The solver-pricing crate provides comprehensive pricing and cost analysis capabilities while maintaining flexibility for different market data sources and pricing strategies across multiple blockchain networks.
