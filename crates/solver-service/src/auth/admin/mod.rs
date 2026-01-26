//! Admin authentication module for wallet-based admin operations.
//!
//! This module provides signature verification utilities for admin authentication.
//! It supports both:
//! - EIP-191 personal_sign (for SIWE messages)
//! - EIP-712 typed data signing (for per-action signatures)

pub mod error;
pub mod signature;

pub use error::AdminAuthError;
pub use signature::{recover_personal_sign, verify_admin_signature};
