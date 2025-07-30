//! Transaction delivery module for the OIF solver system.
//!
//! This module handles the submission and monitoring of blockchain transactions.
//! It provides abstractions for different delivery mechanisms across multiple
//! blockchain networks, managing transaction signing, submission, and confirmation.

use async_trait::async_trait;
use solver_account::AccountService;
use solver_types::{ConfigSchema, Signature, Transaction, TransactionHash, TransactionReceipt};
use std::sync::Arc;
use thiserror::Error;

/// Re-export implementations
pub mod implementations {
	pub mod evm {
		pub mod alloy;
	}
}

/// Errors that can occur during transaction delivery operations.
#[derive(Debug, Error)]
pub enum DeliveryError {
	/// Error that occurs during network communication.
	#[error("Network error: {0}")]
	Network(String),
	/// Error that occurs when a transaction execution fails.
	#[error("Transaction failed: {0}")]
	TransactionFailed(String),
	/// Error that occurs when no suitable provider is available for the operation.
	#[error("No provider available")]
	NoProviderAvailable,
}

/// Trait defining the interface for transaction delivery providers.
///
/// This trait must be implemented by any delivery provider that wants to
/// integrate with the solver system. It provides methods for submitting
/// transactions and monitoring their confirmation status.
#[async_trait]
pub trait DeliveryInterface: Send + Sync {
	/// Returns the configuration schema for this delivery implementation.
	///
	/// This allows each implementation to define its own configuration requirements
	/// with specific validation rules. The schema is used to validate TOML configuration
	/// before initializing the delivery provider.
	fn config_schema(&self) -> Box<dyn ConfigSchema>;

	/// Submits a signed transaction to the blockchain.
	///
	/// Takes a transaction and its signature, submits it to the network,
	/// and returns the transaction hash.
	async fn submit(
		&self,
		tx: Transaction,
		signature: &Signature,
	) -> Result<TransactionHash, DeliveryError>;

	/// Waits for a transaction to be confirmed with the specified number of confirmations.
	///
	/// Blocks until the transaction has received the required number of confirmations
	/// or an error occurs (e.g., transaction reverted or timeout).
	async fn wait_for_confirmation(
		&self,
		hash: &TransactionHash,
		confirmations: u64,
	) -> Result<TransactionReceipt, DeliveryError>;

	/// Retrieves the receipt for a transaction if available.
	///
	/// Returns immediately with the current transaction receipt, or an error
	/// if the transaction is not found or not yet mined.
	async fn get_receipt(
		&self,
		hash: &TransactionHash,
	) -> Result<TransactionReceipt, DeliveryError>;
}

/// Service that manages transaction delivery across multiple blockchain networks.
///
/// The DeliveryService coordinates between different delivery providers based on
/// chain ID, handles transaction signing through the account service, and provides
/// methods for transaction submission and confirmation monitoring.
pub struct DeliveryService {
	/// Map of chain IDs to their corresponding delivery providers.
	providers: std::collections::HashMap<u64, Box<dyn DeliveryInterface>>,
	/// Account service for signing transactions.
	account: Arc<AccountService>,
	/// Default number of confirmations required for transactions.
	min_confirmations: u64,
}

impl DeliveryService {
	/// Creates a new DeliveryService with the specified providers and configuration.
	///
	/// The providers map should contain delivery implementations for each supported
	/// chain ID. The account service is used for transaction signing.
	pub fn new(
		providers: std::collections::HashMap<u64, Box<dyn DeliveryInterface>>,
		account: Arc<AccountService>,
		min_confirmations: u64,
	) -> Self {
		Self {
			providers,
			account,
			min_confirmations,
		}
	}

	/// Delivers a transaction to the appropriate blockchain network.
	///
	/// This method:
	/// 1. Selects the appropriate provider based on the transaction's chain ID
	/// 2. Signs the transaction using the account service
	/// 3. Submits the signed transaction through the provider
	pub async fn deliver(&self, tx: Transaction) -> Result<TransactionHash, DeliveryError> {
		// Get the provider for the transaction's chain ID
		let provider = self
			.providers
			.get(&tx.chain_id)
			.ok_or(DeliveryError::NoProviderAvailable)?;

		// Sign transaction
		let signature = self
			.account
			.sign(&tx)
			.await
			.map_err(|e| DeliveryError::Network(e.to_string()))?;

		// Submit using the chain-specific provider
		provider.submit(tx, &signature).await
	}

	/// Waits for a transaction to be confirmed with the specified number of confirmations.
	///
	/// This method first checks which provider has the transaction, then waits for confirmations
	/// on that specific provider to avoid timeout issues.
	pub async fn confirm(
		&self,
		hash: &TransactionHash,
		confirmations: u64,
	) -> Result<TransactionReceipt, DeliveryError> {
		// First, quickly check which provider has the transaction
		let mut provider_with_tx = None;

		for (chain_id, provider) in self.providers.iter() {
			// Just check if the transaction exists, don't wait for confirmations yet
			match provider.get_receipt(hash).await {
				Ok(_) => {
					provider_with_tx = Some((*chain_id, provider));
					break;
				}
				Err(_) => continue,
			}
		}

		// If we found a provider with the transaction, wait for confirmations
		if let Some((_chain_id, provider)) = provider_with_tx {
			provider.wait_for_confirmation(hash, confirmations).await
		} else {
			Err(DeliveryError::NoProviderAvailable)
		}
	}

	/// Waits for a transaction to be confirmed with the default number of confirmations.
	///
	/// Uses the min_confirmations value configured for this service.
	pub async fn confirm_with_default(
		&self,
		hash: &TransactionHash,
	) -> Result<TransactionReceipt, DeliveryError> {
		// Use configured confirmations
		self.confirm(hash, self.min_confirmations).await
	}

	/// Checks the current status of a transaction.
	///
	/// Returns true if the transaction was successful, false if it failed.
	/// This method tries all providers until one recognizes the transaction.
	pub async fn get_status(&self, hash: &TransactionHash) -> Result<bool, DeliveryError> {
		// Try all providers until one recognizes the transaction
		// TODO: Improve this so it doesn't make redundant requests
		for (chain_id, provider) in self.providers.iter() {
			match provider.get_receipt(hash).await {
				Ok(receipt) => {
					return Ok(receipt.success);
				}
				Err(e) => {
					tracing::trace!(
						"Provider for chain {} cannot find transaction {}: {}",
						chain_id,
						hex::encode(&hash.0),
						e
					);
					continue;
				}
			}
		}

		Err(DeliveryError::NoProviderAvailable)
	}
}
