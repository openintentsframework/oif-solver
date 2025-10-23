//! OIF Solver Service Library
//!
//! This library provides the core functionality for the OIF solver service,
//! including API handlers, authentication, and server components.

pub mod apis;
pub mod auth;
pub mod eip712;
pub mod factory_registry;
pub mod server;
pub mod signature_validator;

// Re-export commonly used types and functions
pub use factory_registry::build_solver_from_config;
