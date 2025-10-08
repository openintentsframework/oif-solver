//! Type definitions and data structures for the solver demo
//!
//! This module contains core type definitions including chain identifiers,
//! error types, utility extensions, session management, and data models
//! used throughout the solver demo application.

pub mod chain;
pub mod error;
pub mod extensions;
pub mod hex;
pub mod models;
pub mod session;

pub use chain::ChainId;
pub use error::{Error, Result};
pub use hex::Hex;
pub use models::*;
pub use session::{Environment, Session};
