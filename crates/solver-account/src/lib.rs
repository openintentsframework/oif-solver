//! Account management module for the OIF solver system.
//!
//! This module provides abstractions for managing cryptographic accounts and signing operations
//! within the OIF solver ecosystem. It defines interfaces and services for account operations
//! such as address retrieval and transaction signing.

use async_trait::async_trait;
use solver_types::{
	Address, ConfigSchema, ImplementationRegistry, SecretString, Signature, Transaction,
};
use std::future::Future;
use std::pin::Pin;
use thiserror::Error;

/// Signer abstraction module
pub mod signer;

/// Re-export AccountSigner for convenience
pub use signer::AccountSigner;

/// Re-export implementations
pub mod implementations {
	pub mod local;

	#[cfg(feature = "kms")]
	pub mod kms;
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
	/// Error that occurs when interacting with the account implementation.
	#[error("Implementation error: {0}")]
	Implementation(String),
}

/// Trait defining the interface for account implementations.
///
/// This trait must be implemented by any account implementation that wants to integrate
/// with the solver system. It provides methods for retrieving account addresses
/// and signing transactions and messages.
#[async_trait]
#[cfg_attr(feature = "testing", mockall::automock)]
pub trait AccountInterface: Send + Sync {
	/// Returns the configuration schema for this account implementation.
	///
	/// This allows each implementation to define its own configuration requirements
	/// with specific validation rules. The schema is used to validate TOML configuration
	/// before initializing the account implementation.
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

	/// Returns a unified signer for use with Alloy's EthereumWallet.
	///
	/// This is the preferred way to get signing capability for the delivery layer.
	fn signer(&self) -> AccountSigner;

	/// Returns the private key as a SecretString with 0x prefix.
	///
	/// # Panics
	/// Panics if called on a KMS signer (use `signer()` instead).
	///
	/// # Deprecated
	/// Use `signer()` instead - this method is not supported for KMS.
	fn get_private_key(&self) -> SecretString {
		panic!("get_private_key() not supported - use signer() instead")
	}
}

/// Async factory function type for account implementations.
///
/// This is the function signature that all account implementations must provide
/// to create instances of their account interface. The factory returns a future
/// that resolves to the account implementation.
///
/// The `for<'a>` higher-ranked trait bound ensures the returned future
/// borrows the config safely for its entire lifetime.
pub type AccountFactory = for<'a> fn(
	&'a toml::Value,
) -> Pin<Box<dyn Future<Output = Result<Box<dyn AccountInterface>, AccountError>> + Send + 'a>>;

/// Registry trait for account implementations.
///
/// This trait extends the base ImplementationRegistry to specify that
/// account implementations must provide an AccountFactory.
pub trait AccountRegistry: ImplementationRegistry<Factory = AccountFactory> {}

/// Get all registered account implementations.
///
/// Returns a vector of (name, factory) tuples for all available account implementations.
/// This is used by the factory registry to automatically register all implementations.
pub fn get_all_implementations() -> Vec<(&'static str, AccountFactory)> {
	use implementations::local;

	#[allow(unused_mut)]
	let mut impls = vec![(local::Registry::NAME, local::Registry::factory())];

	#[cfg(feature = "kms")]
	{
		use implementations::kms;
		impls.push((kms::Registry::NAME, kms::Registry::factory()));
	}

	impls
}

/// Service that manages account operations.
///
/// This struct provides a high-level interface for account management,
/// wrapping an underlying account implementation.
pub struct AccountService {
	/// The underlying account implementation implementation.
	implementation: Box<dyn AccountInterface>,
}

impl AccountService {
	/// Creates a new AccountService with the specified implementation.
	///
	/// The implementation must implement the AccountInterface trait and will be used
	/// for all account operations performed by this service.
	pub fn new(implementation: Box<dyn AccountInterface>) -> Self {
		Self { implementation }
	}

	/// Retrieves the address associated with the managed account.
	///
	/// This method delegates to the underlying implementation's address method.
	pub async fn get_address(&self) -> Result<Address, AccountError> {
		self.implementation.address().await
	}

	/// Signs a transaction using the managed account.
	///
	/// This method delegates to the underlying implementation's sign_transaction method.
	pub async fn sign(&self, tx: &Transaction) -> Result<Signature, AccountError> {
		self.implementation.sign_transaction(tx).await
	}

	/// Returns a unified signer for use with the delivery layer.
	///
	/// This is the preferred way to get signing capability.
	pub fn signer(&self) -> AccountSigner {
		self.implementation.signer()
	}

	/// Returns the private key as a SecretString.
	///
	/// This is used by delivery implementations for transaction signing.
	#[deprecated(note = "Use signer() instead - not supported for KMS")]
	#[allow(deprecated)]
	pub fn get_private_key(&self) -> SecretString {
		self.implementation.get_private_key()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_account_error_display() {
		let err = AccountError::SigningFailed("test error".to_string());
		assert_eq!(format!("{}", err), "Signing failed: test error");

		let err = AccountError::InvalidKey("bad key".to_string());
		assert_eq!(format!("{}", err), "Invalid key: bad key");

		let err = AccountError::Implementation("impl error".to_string());
		assert_eq!(format!("{}", err), "Implementation error: impl error");
	}

	#[test]
	fn test_get_all_implementations_includes_local() {
		let impls = get_all_implementations();
		assert!(!impls.is_empty());
		assert!(impls.iter().any(|(name, _)| *name == "local"));
	}

	#[tokio::test]
	async fn test_account_service_new() {
		use implementations::local::create_account;

		let config: toml::Value = toml::from_str(
			r#"private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80""#,
		)
		.unwrap();
		let account = create_account(&config).await.unwrap();
		let service = AccountService::new(account);
		// Just verify it can be created
		let _ = service.signer();
	}

	#[tokio::test]
	async fn test_account_service_get_address() {
		use implementations::local::create_account;

		let config: toml::Value = toml::from_str(
			r#"private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80""#,
		)
		.unwrap();
		let account = create_account(&config).await.unwrap();
		let service = AccountService::new(account);

		let address = service.get_address().await.unwrap();
		assert!(!address.0.is_empty());
	}

	#[tokio::test]
	async fn test_account_service_sign() {
		use alloy_primitives::U256;
		use implementations::local::create_account;

		let config: toml::Value = toml::from_str(
			r#"private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80""#,
		)
		.unwrap();
		let account = create_account(&config).await.unwrap();
		let service = AccountService::new(account);

		let tx = Transaction {
			to: Some(Address(vec![0u8; 20])),
			value: U256::ZERO,
			data: vec![],
			gas_limit: Some(21000),
			gas_price: Some(1000000000),
			nonce: Some(0),
			chain_id: 1,
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
		};

		let signature = service.sign(&tx).await.unwrap();
		assert!(!signature.0.is_empty());
	}

	#[tokio::test]
	#[allow(deprecated)]
	async fn test_account_service_get_private_key() {
		use implementations::local::create_account;

		let config: toml::Value = toml::from_str(
			r#"private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80""#,
		)
		.unwrap();
		let account = create_account(&config).await.unwrap();
		let service = AccountService::new(account);

		let key = service.get_private_key();
		key.with_exposed(|s| {
			assert!(s.starts_with("0x"));
			assert_eq!(s.len(), 66); // 0x + 64 hex chars
		});
	}

	#[tokio::test]
	async fn test_account_service_signer() {
		use implementations::local::create_account;

		let config: toml::Value = toml::from_str(
			r#"private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80""#,
		)
		.unwrap();
		let account = create_account(&config).await.unwrap();
		let service = AccountService::new(account);

		let signer = service.signer();
		// Verify it returns a valid signer
		let _ = signer.address();
	}
}
