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
/// Order processing types including intents, orders, and execution contexts.
pub mod order;
/// Standard-specific types for different cross-chain protocols.
pub mod standards;
/// Configuration validation types for ensuring type-safe configurations.
pub mod validation;

// Re-export all types for convenient access
pub use account::*;
pub use api::*;
pub use delivery::*;
pub use discovery::*;
pub use events::*;
pub use order::*;
pub use standards::eip7683::{Eip7683OrderData, Output as Eip7683Output};
pub use validation::*;
