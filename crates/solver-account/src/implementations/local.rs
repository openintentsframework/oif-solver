//! Account provider implementations for the solver service.
//!
//! This module provides concrete implementations of the AccountInterface trait,
//! currently supporting local private key wallets using the Alloy library.

use crate::{AccountError, AccountInterface, AccountSigner};
use alloy_consensus::TxLegacy;
use alloy_network::TxSigner;
use alloy_primitives::{Address as AlloyAddress, Bytes, TxKind};
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use async_trait::async_trait;
use solver_types::{
	with_0x_prefix, Address, ConfigSchema, Field, FieldType, Schema, SecretString, Signature,
	Transaction,
};

/// Local wallet implementation using Alloy's signer.
///
/// This implementation manages a private key locally and uses it to sign
/// transactions and messages. It's suitable for development and testing
/// environments where key management simplicity is preferred.
#[derive(Debug)]
pub struct LocalWallet {
	/// The underlying Alloy signer that handles cryptographic operations.
	signer: PrivateKeySigner,
}

impl LocalWallet {
	/// Creates a new LocalWallet from a hex-encoded private key.
	///
	/// The private key should be provided as a hex string (with or without 0x prefix).
	pub fn new(private_key_hex: &str) -> Result<Self, AccountError> {
		// Parse the private key using Alloy's signer
		let signer = private_key_hex
			.parse::<PrivateKeySigner>()
			.map_err(|e| AccountError::InvalidKey(format!("Invalid private key: {}", e)))?;

		Ok(Self { signer })
	}

	/// Returns the private key as a SecretString with 0x prefix.
	pub fn get_private_key(&self) -> SecretString {
		SecretString::from(&with_0x_prefix(&hex::encode(self.signer.to_bytes())) as &str)
	}
}

/// Configuration schema for LocalWallet.
pub struct LocalWalletSchema;

impl LocalWalletSchema {
	/// Static validation method for use before instance creation
	pub fn validate_config(config: &toml::Value) -> Result<(), solver_types::ValidationError> {
		let instance = Self;
		instance.validate(config)
	}
}

impl ConfigSchema for LocalWalletSchema {
	fn validate(&self, config: &toml::Value) -> Result<(), solver_types::ValidationError> {
		let schema =
			Schema::new(
				// Required fields
				vec![Field::new("private_key", FieldType::String).with_validator(
					|value| match value.as_str() {
						Some(key) => {
							let key_without_prefix = key.strip_prefix("0x").unwrap_or(key);

							if key_without_prefix.len() != 64 {
								return Err(
									"Private key must be 64 hex characters (32 bytes)".to_string()
								);
							}

							if hex::decode(key_without_prefix).is_err() {
								return Err("Private key must be valid hexadecimal".to_string());
							}

							Ok(())
						},
						None => Err("Expected string value for private_key".to_string()),
					},
				)],
				// Optional fields
				vec![],
			);

		schema.validate(config)
	}
}

#[async_trait]
impl AccountInterface for LocalWallet {
	fn config_schema(&self) -> Box<dyn ConfigSchema> {
		Box::new(LocalWalletSchema)
	}

	async fn address(&self) -> Result<Address, AccountError> {
		let alloy_address = self.signer.address();
		Ok(alloy_address.into())
	}

	async fn sign_transaction(&self, tx: &Transaction) -> Result<Signature, AccountError> {
		let to = if let Some(to_addr) = &tx.to {
			if to_addr.0.len() != 20 {
				return Err(AccountError::SigningFailed(
					"Invalid address length".to_string(),
				));
			}
			let mut addr_bytes = [0u8; 20];
			addr_bytes.copy_from_slice(&to_addr.0);
			TxKind::Call(AlloyAddress::from(addr_bytes))
		} else {
			TxKind::Create
		};

		let value = tx.value;

		let mut legacy_tx = TxLegacy {
			chain_id: Some(tx.chain_id),
			nonce: tx.nonce.unwrap_or(0),
			gas_price: tx.gas_price.unwrap_or(0),
			gas_limit: tx.gas_limit.unwrap_or(0),
			to,
			value,
			input: Bytes::from(tx.data.clone()),
		};

		let signature = self
			.signer
			.sign_transaction(&mut legacy_tx)
			.await
			.map_err(|e| {
				AccountError::SigningFailed(format!("Failed to sign transaction: {}", e))
			})?;

		Ok(signature.into())
	}

	async fn sign_message(&self, message: &[u8]) -> Result<Signature, AccountError> {
		// Use Alloy's signer to sign the message (handles EIP-191 internally)
		let signature =
			self.signer.sign_message(message).await.map_err(|e| {
				AccountError::SigningFailed(format!("Failed to sign message: {}", e))
			})?;

		Ok(signature.into())
	}

	fn signer(&self) -> AccountSigner {
		AccountSigner::Local(self.signer.clone())
	}

	fn get_private_key(&self) -> SecretString {
		// Explicit call to inherent method to avoid ambiguity
		LocalWallet::get_private_key(self)
	}
}

/// Factory function to create an account provider from configuration.
///
/// This function reads the account configuration and creates the appropriate
/// AccountInterface implementation. Currently only supports local wallets
/// with a private_key configuration parameter.
///
/// # Errors
///
/// Returns an error if:
/// - `private_key` is not provided in the configuration
/// - The wallet creation fails
pub fn create_account(config: &toml::Value) -> Result<Box<dyn AccountInterface>, AccountError> {
	// Validate configuration first
	LocalWalletSchema::validate_config(config)
		.map_err(|e| AccountError::InvalidKey(format!("Invalid configuration: {}", e)))?;

	let private_key = config
		.get("private_key")
		.and_then(|v| v.as_str())
		.expect("private_key already validated");

	Ok(Box::new(LocalWallet::new(private_key)?))
}

/// Registry for the local account implementation.
pub struct Registry;

impl solver_types::ImplementationRegistry for Registry {
	const NAME: &'static str = "local";
	type Factory = crate::AccountFactory;

	fn factory() -> Self::Factory {
		create_account
	}
}

impl crate::AccountRegistry for Registry {}

#[cfg(test)]
mod tests {
	use super::*;
	use solver_types::{
		utils::tests::builders::TransactionBuilder, Address, ImplementationRegistry, Transaction,
	};
	use std::collections::HashMap;

	// Test private key (FOR TESTING ONLY!)
	const TEST_PRIVATE_KEY: &str =
		"ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
	const TEST_PRIVATE_KEY_WITH_PREFIX: &str =
		"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
	const INVALID_PRIVATE_KEY: &str = "invalid_key";
	const SHORT_PRIVATE_KEY: &str = "1234";

	fn create_test_config(private_key: &str) -> toml::Value {
		let mut config = HashMap::new();
		config.insert(
			"private_key".to_string(),
			toml::Value::String(private_key.to_string()),
		);
		toml::Value::Table(config.into_iter().collect())
	}

	fn create_test_transaction() -> Transaction {
		TransactionBuilder::new().gas_price_gwei(21).build()
	}

	#[test]
	fn test_local_wallet_new_valid_key() {
		let wallet = LocalWallet::new(TEST_PRIVATE_KEY).unwrap();
		assert!(wallet.signer.to_bytes().len() == 32);
	}

	#[test]
	fn test_local_wallet_new_valid_key_with_prefix() {
		let wallet = LocalWallet::new(TEST_PRIVATE_KEY_WITH_PREFIX).unwrap();
		assert!(wallet.signer.to_bytes().len() == 32);
	}

	#[test]
	fn test_local_wallet_new_invalid_key() {
		let result = LocalWallet::new(INVALID_PRIVATE_KEY);
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), AccountError::InvalidKey(_)));
	}

	#[test]
	fn test_local_wallet_get_private_key() {
		let wallet = LocalWallet::new(TEST_PRIVATE_KEY).unwrap();
		let private_key = wallet.get_private_key();
		let private_key_str = private_key.with_exposed(|s| s.to_string());
		assert!(private_key_str.starts_with("0x"));
		assert_eq!(private_key_str.len(), 66); // 0x + 64 hex chars
	}

	#[test]
	fn test_schema_validation_valid_config() {
		let config = create_test_config(TEST_PRIVATE_KEY);
		let result = LocalWalletSchema::validate_config(&config);
		assert!(result.is_ok());
	}

	#[test]
	fn test_schema_validation_valid_config_with_prefix() {
		let config = create_test_config(TEST_PRIVATE_KEY_WITH_PREFIX);
		let result = LocalWalletSchema::validate_config(&config);
		assert!(result.is_ok());
	}

	#[test]
	fn test_schema_validation_invalid_hex() {
		let config = create_test_config(INVALID_PRIVATE_KEY);
		let result = LocalWalletSchema::validate_config(&config);
		assert!(result.is_err());
	}

	#[test]
	fn test_schema_validation_short_key() {
		let config = create_test_config(SHORT_PRIVATE_KEY);
		let result = LocalWalletSchema::validate_config(&config);
		assert!(result.is_err());
	}

	#[test]
	fn test_schema_validation_missing_private_key() {
		let config = toml::Value::Table(HashMap::new().into_iter().collect());
		let result = LocalWalletSchema::validate_config(&config);
		assert!(result.is_err());
	}

	#[tokio::test]
	async fn test_account_interface_address() {
		let wallet = LocalWallet::new(TEST_PRIVATE_KEY).unwrap();
		let address = wallet.address().await.unwrap();
		assert_eq!(address.0.len(), 20);
	}

	#[tokio::test]
	async fn test_account_interface_sign_transaction() {
		let wallet = LocalWallet::new(TEST_PRIVATE_KEY).unwrap();
		let tx = create_test_transaction();
		let signature = wallet.sign_transaction(&tx).await.unwrap();
		assert!(!signature.0.is_empty());
	}

	#[tokio::test]
	async fn test_account_interface_sign_transaction_invalid_address() {
		let wallet = LocalWallet::new(TEST_PRIVATE_KEY).unwrap();
		let mut tx = create_test_transaction();
		tx.to = Some(Address(vec![0u8; 19])); // Invalid address length

		let result = wallet.sign_transaction(&tx).await;
		assert!(result.is_err());
		assert!(matches!(
			result.unwrap_err(),
			AccountError::SigningFailed(_)
		));
	}

	#[tokio::test]
	async fn test_account_interface_sign_transaction_contract_creation() {
		let wallet = LocalWallet::new(TEST_PRIVATE_KEY).unwrap();
		let mut tx = create_test_transaction();
		tx.to = None; // Contract creation

		let signature = wallet.sign_transaction(&tx).await.unwrap();
		assert!(!signature.0.is_empty());
	}

	#[tokio::test]
	async fn test_account_interface_sign_message() {
		let wallet = LocalWallet::new(TEST_PRIVATE_KEY).unwrap();
		let message = b"Hello, World!";
		let signature = wallet.sign_message(message).await.unwrap();
		assert!(!signature.0.is_empty());
	}

	#[test]
	fn test_create_account_valid_config() {
		let config = create_test_config(TEST_PRIVATE_KEY);
		let account = create_account(&config).unwrap();
		assert!(!account.get_private_key().with_exposed(|s| s.is_empty()));
	}

	#[test]
	fn test_create_account_invalid_config() {
		let config = create_test_config(INVALID_PRIVATE_KEY);
		let result = create_account(&config);
		assert!(result.is_err());
	}

	#[test]
	fn test_create_account_missing_private_key() {
		let config = toml::Value::Table(HashMap::new().into_iter().collect());
		let result = create_account(&config);
		assert!(result.is_err());
	}

	#[test]
	fn test_registry_name() {
		assert_eq!(Registry::NAME, "local");
	}

	#[test]
	fn test_registry_factory() {
		let factory = Registry::factory();
		let config = create_test_config(TEST_PRIVATE_KEY);
		let account = factory(&config).unwrap();
		assert!(!account.get_private_key().with_exposed(|s| s.is_empty()));
	}

	#[test]
	fn test_config_schema_interface() {
		let wallet = LocalWallet::new(TEST_PRIVATE_KEY).unwrap();
		let schema = wallet.config_schema();
		let config = create_test_config(TEST_PRIVATE_KEY);
		assert!(schema.validate(&config).is_ok());
	}

	#[test]
	fn test_account_interface_signer() {
		let wallet = LocalWallet::new(TEST_PRIVATE_KEY).unwrap();
		let signer = wallet.signer();

		// Verify the signer is a Local variant and has the correct address
		match signer {
			crate::AccountSigner::Local(s) => {
				// Verify address matches
				let expected_address = alloy_signer::Signer::address(&wallet.signer);
				let actual_address = alloy_signer::Signer::address(&s);
				assert_eq!(expected_address, actual_address);
			},
			#[cfg(feature = "kms")]
			_ => panic!("Expected Local signer"),
		}
	}

	#[test]
	fn test_account_interface_get_private_key_trait() {
		use crate::AccountInterface;
		let wallet = LocalWallet::new(TEST_PRIVATE_KEY).unwrap();
		// Call through the trait to test the trait impl
		let key = AccountInterface::get_private_key(&wallet);
		key.with_exposed(|s| {
			assert!(s.starts_with("0x"));
			assert_eq!(s.len(), 66);
		});
	}
}
