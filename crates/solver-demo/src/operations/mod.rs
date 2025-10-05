//! High-level operation implementations for CLI commands
//!
//! This module contains the business logic implementations for each major
//! CLI operation including environment management, initialization, intent
//! processing, quote generation, and token operations. Each submodule
//! provides a dedicated service for its respective domain.

pub mod env;
pub mod init;
pub mod intent;
pub mod quote;
pub mod token;

// Re-export main types for backward compatibility during migration
pub use env::EnvOps;
pub use init::InitOps;
pub use intent::IntentOps;
pub use quote::QuoteOps;
pub use token::TokenOps;
