//! Common types module for the OIF solver system.
//!
//! This module defines the core data types and structures used throughout
//! the solver system. It provides a centralized location for shared types
//! to ensure consistency across all solver components.

/// Account-related types for managing solver identities and signatures.
pub mod account;
/// API types for HTTP endpoints and request/response structures.
pub mod api;
/// Transaction delivery types for blockchain interactions.
pub mod delivery;
/// Intent discovery types for finding and processing new orders.
pub mod discovery;
/// Event types for inter-service communication.
pub mod events;
/// Network and token configuration types.
pub mod networks;
/// Order processing types including intents, orders, and execution contexts.
pub mod order;
/// Standard-specific types for different cross-chain protocols.
pub mod standards;
/// Storage types for managing persistent data.
pub mod storage;
/// Utility functions for common type conversions.
pub mod utils;
/// Configuration validation types for ensuring type-safe configurations.
pub mod validation;

// Re-export all types for convenient access
pub use account::*;
pub use api::*;
pub use delivery::*;
pub use discovery::*;
pub use events::*;
pub use networks::{NetworkConfig, NetworksConfig, TokenConfig};
pub use order::*;
pub use standards::{
	eip7683::{Eip7683OrderData, Output as Eip7683Output},
	eip7930::{InteropAddress, InteropAddressError},
};
pub use storage::*;
pub use utils::{
	bytes32_to_address, format_token_amount, truncate_id, with_0x_prefix, without_0x_prefix,
};
pub use validation::*;
