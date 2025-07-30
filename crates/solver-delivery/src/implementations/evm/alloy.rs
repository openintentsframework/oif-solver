//! Transaction delivery implementations for the solver service.
//!
//! This module provides concrete implementations of the DeliveryInterface trait,
//! supporting blockchain transaction submission and monitoring using the Alloy library.

use crate::{DeliveryError, DeliveryInterface};
use alloy_network::EthereumWallet;
use alloy_primitives::FixedBytes;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types::TransactionRequest;
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use alloy_transport_http::Http;
use async_trait::async_trait;
use solver_types::{
	ConfigSchema, Field, FieldType, Schema, Signature, Transaction as SolverTransaction,
	TransactionHash, TransactionReceipt,
};
use std::sync::Arc;

/// Utility function to truncate a transaction hash for display.
fn truncate_hash(hash: &TransactionHash) -> String {
	let hash_str = hex::encode(&hash.0);
	if hash_str.len() <= 8 {
		hash_str
	} else {
		format!("{}..", &hash_str[..8])
	}
}

/// Alloy-based EVM delivery implementation.
///
/// This implementation uses the Alloy library to submit and monitor transactions
/// on EVM-compatible blockchains. It handles transaction signing, submission,
/// and confirmation tracking.
pub struct AlloyDelivery {
	/// The Alloy provider for blockchain interaction.
	provider: Arc<dyn Provider<Http<reqwest::Client>> + Send + Sync>,
	/// The chain ID this delivery service is configured for.
	_chain_id: u64,
}

impl AlloyDelivery {
	/// Creates a new AlloyDelivery instance.
	///
	/// Configures an Alloy provider with the specified RPC URL and signer
	/// for transaction submission on the given chain.
	pub async fn new(
		rpc_url: &str,
		chain_id: u64,
		mut signer: PrivateKeySigner,
	) -> Result<Self, DeliveryError> {
		// Create provider with wallet for automatic signing
		let url = rpc_url
			.parse()
			.map_err(|e| DeliveryError::Network(format!("Invalid RPC URL: {}", e)))?;

		// Set the chain ID on the signer
		signer = signer.with_chain_id(Some(chain_id));

		let wallet = EthereumWallet::from(signer);

		let provider = ProviderBuilder::new()
			.with_recommended_fillers()
			.wallet(wallet)
			.on_http(url);

		Ok(Self {
			provider: Arc::new(provider),
			_chain_id: chain_id,
		})
	}
}

/// Configuration schema for Alloy delivery provider.
pub struct AlloyDeliverySchema;

impl ConfigSchema for AlloyDeliverySchema {
	fn validate(&self, config: &toml::Value) -> Result<(), solver_types::ValidationError> {
		let schema = Schema::new(
			// Required fields
			vec![
				Field::new("rpc_url", FieldType::String).with_validator(|value| {
					let url = value.as_str().unwrap();
					if url.starts_with("http://") || url.starts_with("https://") {
						Ok(())
					} else {
						Err("RPC URL must start with http:// or https://".to_string())
					}
				}),
				Field::new("private_key", FieldType::String).with_validator(|value| {
					let key = value.as_str().unwrap();
					let key_without_prefix = key.strip_prefix("0x").unwrap_or(key);

					if key_without_prefix.len() != 64 {
						return Err("Private key must be 64 hex characters (32 bytes)".to_string());
					}

					if hex::decode(key_without_prefix).is_err() {
						return Err("Private key must be valid hexadecimal".to_string());
					}

					Ok(())
				}),
				Field::new(
					"chain_id",
					FieldType::Integer {
						min: Some(1),
						max: None,
					},
				),
			],
			// Optional fields
			vec![],
		);

		schema.validate(config)
	}
}

#[async_trait]
impl DeliveryInterface for AlloyDelivery {
	fn config_schema(&self) -> Box<dyn ConfigSchema> {
		Box::new(AlloyDeliverySchema)
	}

	async fn submit(
		&self,
		tx: SolverTransaction,
		_signature: &Signature,
	) -> Result<TransactionHash, DeliveryError> {
		// Convert solver transaction to alloy transaction request
		let request: TransactionRequest = tx.into();

		// Send transaction - the provider's wallet will handle signing
		let pending_tx =
			self.provider.send_transaction(request).await.map_err(|e| {
				DeliveryError::Network(format!("Failed to send transaction: {}", e))
			})?;

		// Get the transaction hash
		let tx_hash = *pending_tx.tx_hash();
		let hash_str = hex::encode(tx_hash.0);
		let truncated = if hash_str.len() <= 8 {
			hash_str.clone()
		} else {
			format!("{}..", &hash_str[..8])
		};
		tracing::info!(tx_hash = %truncated, "Submitted transaction");

		Ok(TransactionHash(tx_hash.0.to_vec()))
	}

	async fn wait_for_confirmation(
		&self,
		hash: &TransactionHash,
		confirmations: u64,
	) -> Result<TransactionReceipt, DeliveryError> {
		let tx_hash = FixedBytes::<32>::from_slice(&hash.0);

		// Poll interval for checking confirmations
		let poll_interval = tokio::time::Duration::from_secs(10);
		// Allow ~15 seconds per confirmation (typical block time) plus some buffer
		let seconds_per_confirmation = 20;
		let max_timeout = 3600; // Cap at 1 hour
		let timeout_seconds = (confirmations * seconds_per_confirmation)
			.max(seconds_per_confirmation)
			.min(max_timeout);
		let max_wait_time = tokio::time::Duration::from_secs(timeout_seconds);
		let start_time = tokio::time::Instant::now();

		// Log high-level info about what we're doing
		tracing::info!(
			tx_hash = %truncate_hash(hash),
			"Waiting for {} confirmations (timeout: {}s)",
			confirmations,
			timeout_seconds
		);

		loop {
			// Check if we've exceeded max wait time
			if start_time.elapsed() > max_wait_time {
				return Err(DeliveryError::Network(format!(
					"Timeout waiting for {} confirmations after {} seconds",
					confirmations,
					max_wait_time.as_secs()
				)));
			}

			// Get transaction receipt
			let receipt = match self.provider.get_transaction_receipt(tx_hash).await {
				Ok(Some(receipt)) => receipt,
				Ok(None) => {
					// Transaction not yet mined, wait and retry
					tokio::time::sleep(poll_interval).await;
					continue;
				}
				Err(e) => {
					return Err(DeliveryError::Network(format!(
						"Failed to get receipt: {}",
						e
					)));
				}
			};

			// Get current block number
			let current_block = self.provider.get_block_number().await.map_err(|e| {
				DeliveryError::Network(format!("Failed to get block number: {}", e))
			})?;

			let tx_block = receipt.block_number.unwrap_or(0);
			let current_confirmations = current_block.saturating_sub(tx_block);

			// Check if we have enough confirmations
			if current_confirmations >= confirmations {
				return Ok(TransactionReceipt {
					hash: TransactionHash(receipt.transaction_hash.0.to_vec()),
					block_number: tx_block,
					success: receipt.status(),
				});
			}

			tracing::debug!(
				"Waiting for {} more confirmations...",
				confirmations.saturating_sub(current_confirmations)
			);

			// Not enough confirmations yet, wait and retry
			tokio::time::sleep(poll_interval).await;
		}
	}

	async fn get_receipt(
		&self,
		hash: &TransactionHash,
	) -> Result<TransactionReceipt, DeliveryError> {
		let tx_hash = FixedBytes::<32>::from_slice(&hash.0);

		let receipt = self
			.provider
			.get_transaction_receipt(tx_hash)
			.await
			.map_err(|e| DeliveryError::Network(format!("Failed to get receipt: {}", e)))?
			.ok_or_else(|| DeliveryError::Network("Transaction not found".to_string()))?;

		Ok(TransactionReceipt {
			hash: TransactionHash(receipt.transaction_hash.0.to_vec()),
			block_number: receipt.block_number.unwrap_or(0),
			success: receipt.status(),
		})
	}
}

/// Factory function to create an HTTP-based delivery provider from configuration.
///
/// This function reads the delivery configuration and creates an AlloyDelivery
/// instance. Required configuration parameters:
/// - `rpc_url`: The HTTP RPC endpoint URL
/// - `chain_id`: The blockchain network chain ID
/// - `private_key`: The private key for transaction signing
pub fn create_http_delivery(config: &toml::Value) -> Box<dyn DeliveryInterface> {
	let rpc_url = config
		.get("rpc_url")
		.and_then(|v| v.as_str())
		.expect("rpc_url is required");

	let chain_id = config
		.get("chain_id")
		.and_then(|v| v.as_integer())
		.expect("chain_id is required") as u64;

	let private_key = config
		.get("private_key")
		.and_then(|v| v.as_str())
		.expect("private_key is required");

	// Parse the private key
	let signer: PrivateKeySigner = private_key.parse().expect("Invalid private key");

	// Create delivery service synchronously, but the actual connection happens async
	let delivery = tokio::task::block_in_place(|| {
		tokio::runtime::Handle::current()
			.block_on(async { AlloyDelivery::new(rpc_url, chain_id, signer).await })
	});

	Box::new(delivery.expect("Failed to create delivery service"))
}
