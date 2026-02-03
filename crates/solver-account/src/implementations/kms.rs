//! AWS KMS-backed wallet implementation.
//!
//! This module provides an account implementation that uses AWS KMS for signing
//! operations. The private key never leaves the KMS hardware security module,
//! providing enhanced security for production deployments.
//!
//! This module is only available when the `kms` feature is enabled.

use crate::{AccountError, AccountInterface, AccountSigner};
use alloy_signer_aws::AwsSigner;
use async_trait::async_trait;
use aws_sdk_kms::Client as KmsClient;
use solver_types::{
	Address, ConfigSchema, Field, FieldType, Schema, SecretString, Signature, Transaction,
	ValidationError,
};

/// Configuration schema for KMS wallet.
pub struct KmsWalletSchema;

impl KmsWalletSchema {
	/// Static validation method for use before instance creation.
	pub fn validate_config(config: &toml::Value) -> Result<(), ValidationError> {
		let schema = Self;
		schema.validate(config)
	}
}

impl ConfigSchema for KmsWalletSchema {
	fn validate(&self, config: &toml::Value) -> Result<(), ValidationError> {
		let schema = Schema::new(
			// Required fields
			vec![
				Field::new("key_id", FieldType::String).with_validator(|v| match v.as_str() {
					Some(s) if !s.is_empty() => Ok(()),
					_ => Err("key_id must be a non-empty string".to_string()),
				}),
				Field::new("region", FieldType::String).with_validator(|v| match v.as_str() {
					Some(s) if !s.is_empty() => Ok(()),
					_ => Err("region must be a non-empty string".to_string()),
				}),
			],
			// Optional fields
			vec![
				Field::new("endpoint", FieldType::String), // For LocalStack testing
			],
		);
		schema.validate(config)
	}
}

/// KMS-backed wallet implementation.
///
/// Uses AWS KMS for all signing operations. The private key never leaves
/// the KMS hardware security module. Public key is cached per-instance
/// by the underlying `AwsSigner`.
pub struct KmsWallet {
	/// The underlying AWS KMS signer.
	signer: AwsSigner,
}

impl KmsWallet {
	/// Creates a new KMS wallet with the specified configuration.
	///
	/// # Arguments
	/// * `key_id` - The KMS key ID or ARN
	/// * `region` - AWS region (e.g., "us-east-1")
	/// * `endpoint` - Optional custom endpoint (for LocalStack testing)
	pub async fn new(
		key_id: String,
		region: String,
		endpoint: Option<String>,
	) -> Result<Self, AccountError> {
		let mut config_loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
			.region(aws_config::Region::new(region));

		if let Some(endpoint_url) = endpoint {
			config_loader = config_loader.endpoint_url(endpoint_url);
		}

		let config = config_loader.load().await;
		let client = KmsClient::new(&config);

		let signer = AwsSigner::new(client, key_id, None)
			.await
			.map_err(|e| AccountError::Implementation(format!("KMS initialization failed: {}", e)))?;

		Ok(Self { signer })
	}
}

#[async_trait]
impl AccountInterface for KmsWallet {
	fn config_schema(&self) -> Box<dyn ConfigSchema> {
		Box::new(KmsWalletSchema)
	}

	async fn address(&self) -> Result<Address, AccountError> {
		let addr = alloy_signer::Signer::address(&self.signer);
		Ok(Address(addr.as_slice().to_vec()))
	}

	async fn sign_transaction(&self, _tx: &Transaction) -> Result<Signature, AccountError> {
		// Transaction signing is handled by EthereumWallet using signer()
		// in the delivery layer, not through AccountInterface directly
		Err(AccountError::Implementation(
			"Use signer() with EthereumWallet for transaction signing".into(),
		))
	}

	async fn sign_message(&self, message: &[u8]) -> Result<Signature, AccountError> {
		use alloy_signer::Signer;
		let sig = self
			.signer
			.sign_message(message)
			.await
			.map_err(|e| AccountError::SigningFailed(e.to_string()))?;
		Ok(sig.into()) // Uses From<PrimitiveSignature> impl
	}

	fn signer(&self) -> AccountSigner {
		AccountSigner::Kms(self.signer.clone())
	}

	// Note: get_private_key() uses the default impl which panics
	// KMS signers cannot expose the private key
}

/// Factory function to create a KMS wallet from configuration.
///
/// This function uses sync blocking to initialize the async KMS signer.
/// Safe to call from within a tokio runtime context.
pub fn create_account(config: &toml::Value) -> Result<Box<dyn AccountInterface>, AccountError> {
	KmsWalletSchema::validate_config(config)
		.map_err(|e| AccountError::InvalidKey(format!("Invalid configuration: {}", e)))?;

	let key_id = config
		.get("key_id")
		.and_then(|v| v.as_str())
		.ok_or_else(|| AccountError::InvalidKey("key_id required".into()))?;
	let region = config
		.get("region")
		.and_then(|v| v.as_str())
		.ok_or_else(|| AccountError::InvalidKey("region required".into()))?;
	let endpoint = config
		.get("endpoint")
		.and_then(|v| v.as_str())
		.map(String::from);

	// Block for async initialization with runtime safety
	let wallet = match tokio::runtime::Handle::try_current() {
		Ok(handle) => {
			tokio::task::block_in_place(|| {
				handle.block_on(async {
					KmsWallet::new(key_id.to_string(), region.to_string(), endpoint).await
				})
			})?
		},
		Err(_) => {
			// Fallback for tests without runtime
			let rt = tokio::runtime::Builder::new_current_thread()
				.enable_all()
				.build()
				.map_err(|e| AccountError::Implementation(format!("Runtime error: {}", e)))?;
			rt.block_on(async {
				KmsWallet::new(key_id.to_string(), region.to_string(), endpoint).await
			})?
		},
	};

	Ok(Box::new(wallet))
}

/// Registry for the KMS account implementation.
pub struct Registry;

impl solver_types::ImplementationRegistry for Registry {
	const NAME: &'static str = "kms";
	type Factory = crate::AccountFactory;

	fn factory() -> Self::Factory {
		create_account
	}
}

impl crate::AccountRegistry for Registry {}
