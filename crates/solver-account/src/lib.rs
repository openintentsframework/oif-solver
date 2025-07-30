//! Account management module for the OIF solver system.
//!
//! This module provides abstractions for managing cryptographic accounts and signing operations
//! within the OIF solver ecosystem. It defines interfaces and services for account operations
//! such as address retrieval and transaction signing.

use async_trait::async_trait;
use solver_types::{Address, ConfigSchema, Signature, Transaction};
use thiserror::Error;

/// Re-export implementations
pub mod implementations {
	pub mod local;
}

/// Errors that can occur during account operations.
#[derive(Debug, Error)]
pub enum AccountError {
	/// Error that occurs when signing operations fail.
	#[error("Signing failed: {0}")]
	SigningFailed(String),
	/// Error that occurs when a cryptographic key is invalid or malformed.
	#[error("Invalid key: {0}")]
	InvalidKey(String),
	/// Error that occurs when interacting with the account provider.
	#[error("Provider error: {0}")]
	Provider(String),
}

/// Trait defining the interface for account providers.
///
/// This trait must be implemented by any account provider that wants to integrate
/// with the solver system. It provides methods for retrieving account addresses
/// and signing transactions and messages.
#[async_trait]
pub trait AccountInterface: Send + Sync {
	/// Returns the configuration schema for this account implementation.
	///
	/// This allows each implementation to define its own configuration requirements
	/// with specific validation rules. The schema is used to validate TOML configuration
	/// before initializing the account provider.
	fn config_schema(&self) -> Box<dyn ConfigSchema>;

	/// Retrieves the address associated with this account.
	///
	/// Returns the account's address or an error if the address cannot be retrieved.
	async fn address(&self) -> Result<Address, AccountError>;

	/// Signs a transaction using the account's private key.
	///
	/// Takes a reference to a transaction and returns a signature that can be used
	/// to authorize the transaction execution.
	async fn sign_transaction(&self, tx: &Transaction) -> Result<Signature, AccountError>;

	/// Signs an arbitrary message using the account's private key.
	///
	/// Takes a byte slice representing the message and returns a signature.
	/// This is useful for message authentication and verification purposes.
	async fn sign_message(&self, message: &[u8]) -> Result<Signature, AccountError>;
}

/// Service that manages account operations.
///
/// This struct provides a high-level interface for account management,
/// wrapping an underlying account provider implementation.
pub struct AccountService {
	/// The underlying account provider implementation.
	provider: Box<dyn AccountInterface>,
}

impl AccountService {
	/// Creates a new AccountService with the specified provider.
	///
	/// The provider must implement the AccountInterface trait and will be used
	/// for all account operations performed by this service.
	pub fn new(provider: Box<dyn AccountInterface>) -> Self {
		Self { provider }
	}

	/// Retrieves the address associated with the managed account.
	///
	/// This method delegates to the underlying provider's address method.
	pub async fn get_address(&self) -> Result<Address, AccountError> {
		self.provider.address().await
	}

	/// Signs a transaction using the managed account.
	///
	/// This method delegates to the underlying provider's sign_transaction method.
	pub async fn sign(&self, tx: &Transaction) -> Result<Signature, AccountError> {
		self.provider.sign_transaction(tx).await
	}
}
