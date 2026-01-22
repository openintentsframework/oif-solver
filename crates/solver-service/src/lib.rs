//! OIF Solver Service Library
//!
//! This library provides the core functionality for the OIF solver service,
//! including API handlers, authentication, and server components.

pub mod apis;
pub mod auth;
pub mod config_merge;
pub mod eip712;
pub mod factory_registry;
pub mod seeds;
pub mod server;
pub mod validators;

// Re-export commonly used types and functions
pub use config_merge::merge_config;
pub use factory_registry::build_solver_from_config;
pub use seeds::{SeedPreset, MAINNET_SEED, TESTNET_SEED};
