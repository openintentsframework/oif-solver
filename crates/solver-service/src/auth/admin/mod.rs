//! Admin authentication module for wallet-based admin operations.
//!
//! This module provides EIP-712 typed data signature verification for admin
//! actions. Each admin action (AddToken, Withdraw, etc.) must be individually
//! signed by an authorized admin wallet.
//!
//! # Security Model
//!
//! - Each action is signed with EIP-712 typed data
//! - Signature includes nonce (replay protection) and deadline (expiry)
//! - Signer must be in the admin registry
//! - Nonces are consumed atomically after signature verification

pub mod error;
pub mod signature;
pub mod types;
pub mod verify;

pub use error::AdminAuthError;
pub use signature::{recover_from_hash, recover_personal_sign};
pub use types::{
	admin_domain_separator, AddAdminContents, AddTokenContents, AdminAction, AdminActionHashError,
	ApproveTokensContents, RemoveAdminContents, RemoveTokenContents, SignedAdminRequest,
	UpdateFeeConfigContents, UpdateGasConfigContents, WithdrawContents, ADMIN_DOMAIN_NAME,
	ADMIN_DOMAIN_VERSION,
};
pub use verify::AdminActionVerifier;
