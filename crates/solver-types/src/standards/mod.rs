//! Standard-specific types for different cross-chain protocols.
//!
//! This module contains data structures and types specific to various
//! cross-chain order standards. Currently supports:
//!
//! - **EIP-7683**: Cross-chain order standard for intent-based bridging
//!
//! Each standard module provides its own type definitions that conform
//! to the respective protocol specifications.

/// EIP-7683 cross-chain order types
pub mod eip7683;

// Re-export commonly used types for convenience
pub use eip7683::{Eip7683OrderData, Output as Eip7683Output};
