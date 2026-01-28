//! Common types module for the OIF solver system.
//!
//! This module defines the core data types and structures used throughout
//! the solver system. It provides a centralized location for shared types
//! to ensure consistency across all solver components.

/// Account-related types for managing solver identities and signatures.
pub mod account;
/// API types for HTTP endpoints and request/response structures.
pub mod api;
/// Authentication and authorization types.
pub mod auth;
/// Transaction delivery types for blockchain interactions.
pub mod delivery;
/// Intent discovery types for finding and processing new orders.
pub mod discovery;
/// Event types for inter-service communication.
pub mod events;
/// Network and token configuration types.
pub mod networks;
/// Oracle-related types for settlement validation and routing.
pub mod oracle;
/// Order processing types including intents, orders, and execution contexts.
pub mod order;
/// Provider utilities for creating and managing Alloy providers.
pub mod provider;
/// Registry trait for self-registering implementations.
pub mod registry;
/// Secure string type for handling sensitive data.
pub mod secret_string;
/// Seed override types for initializing a new solver.
pub mod seed_overrides;
/// Operator configuration types for runtime storage in Redis.
pub mod operator_config;
/// Standard-specific types for different cross-chain protocols.
pub mod standards;
/// Storage types for managing persistent data.
pub mod storage;
/// Utility functions for common type conversions.
pub mod utils;
/// Configuration validation types for ensuring type-safe configurations.
pub mod validation;
/// Versioned wrapper for optimistic locking.
pub mod versioned;

// Cost types
pub mod costs;
/// Pricing oracle types for currency conversion.
pub mod pricing;

// Re-export all types for convenient access
pub use account::*;
pub use api::*;
pub use auth::{AdminConfig, AuthConfig, AuthScope, JwtClaims, RefreshTokenData};
pub use costs::{CostBreakdown, CostContext};
pub use delivery::*;
pub use discovery::*;
pub use events::*;
pub use networks::{NetworkConfig, NetworksConfig, TokenConfig};
pub use order::*;
pub use pricing::*;
pub use provider::{
	create_http_provider, create_http_providers, create_ws_provider, create_ws_providers,
	ProviderError,
};
pub use registry::ImplementationRegistry;
pub use secret_string::SecretString;
pub use seed_overrides::{NetworkOverride, SeedOverrides, Token};
pub use operator_config::{
	OperatorAdminConfig, OperatorConfig, OperatorGasConfig, OperatorGasFlowUnits,
	OperatorHyperlaneConfig, OperatorNetworkConfig, OperatorOracleConfig, OperatorPricingConfig,
	OperatorRpcEndpoint, OperatorSettlementConfig, OperatorSolverConfig, OperatorToken,
};
pub use standards::{
	eip7683::{Eip7683OrderData, MandateOutput as Eip7683Output},
	eip7930::{InteropAddress, InteropAddressError},
};
pub use storage::*;
pub use utils::{
	bytes32_to_address, current_timestamp, format_token_amount, normalize_bytes32_address,
	parse_address, truncate_id, wei_string_to_eth_string, with_0x_prefix, without_0x_prefix,
	DEFAULT_GAS_PRICE_WEI, MOCK_ETH_SOL_PRICE, MOCK_ETH_USD_PRICE, MOCK_SOL_USD_PRICE,
	MOCK_TOKA_USD_PRICE, MOCK_TOKB_USD_PRICE,
};
pub use validation::*;
pub use versioned::Versioned;
