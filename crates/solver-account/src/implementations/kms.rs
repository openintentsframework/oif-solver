//! AWS KMS-backed wallet implementation.
//!
//! This module provides an account implementation that uses AWS KMS for signing
//! operations. The private key never leaves the KMS hardware security module,
//! providing enhanced security for production deployments.
//!
//! This module is only available when the `kms` feature is enabled.

use crate::{AccountError, AccountFactoryFuture, AccountInterface, AccountSigner};
use alloy_consensus::TxLegacy;
use alloy_network::TxSigner;
use alloy_primitives::{Address as AlloyAddress, Bytes, TxKind};
use alloy_signer_aws::AwsSigner;
use async_trait::async_trait;
use aws_sdk_kms::Client as KmsClient;
use serde::Deserialize;
use solver_types::{Address, ConfigSchema, Signature, Transaction, ValidationError};

/// Configuration schema for KMS wallet.
pub struct KmsWalletSchema;

/// Dedicated typed configuration for KMS-backed wallets.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KmsWalletConfig {
	key_id: String,
	region: String,
	endpoint: Option<String>,
}

impl KmsWalletConfig {
	fn from_json(config: &serde_json::Value) -> Result<Self, ValidationError> {
		let parsed: Self = serde_json::from_value(config.clone())
			.map_err(|err| ValidationError::DeserializationError(err.to_string()))?;
		parsed.validate()?;
		Ok(parsed)
	}

	fn validate(&self) -> Result<(), ValidationError> {
		if self.key_id.trim().is_empty() {
			return Err(ValidationError::InvalidValue {
				field: "key_id".to_string(),
				message: "key_id must be a non-empty string".to_string(),
			});
		}
		if self.region.trim().is_empty() {
			return Err(ValidationError::InvalidValue {
				field: "region".to_string(),
				message: "region must be a non-empty string".to_string(),
			});
		}
		Ok(())
	}
}

impl KmsWalletSchema {
	/// Static validation method for use before instance creation.
	pub fn validate_config(config: &serde_json::Value) -> Result<(), ValidationError> {
		KmsWalletConfig::from_json(config).map(|_| ())
	}
}

impl ConfigSchema for KmsWalletSchema {
	fn validate(&self, config: &serde_json::Value) -> Result<(), ValidationError> {
		KmsWalletConfig::from_json(config).map(|_| ())
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
			.map_err(|e| AccountError::Implementation(format!("KMS initialization failed: {e}")))?;

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
			.map_err(|e| AccountError::SigningFailed(format!("Failed to sign transaction: {e}")))?;

		Ok(signature.into())
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
/// Returns an async future that initializes the KMS signer.
pub fn create_account(config: &serde_json::Value) -> AccountFactoryFuture<'_> {
	Box::pin(async move {
		let parsed = KmsWalletConfig::from_json(config)
			.map_err(|e| AccountError::InvalidKey(format!("Invalid configuration: {e}")))?;
		let wallet = KmsWallet::new(parsed.key_id, parsed.region, parsed.endpoint).await?;

		Ok(Box::new(wallet) as Box<dyn AccountInterface>)
	})
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
