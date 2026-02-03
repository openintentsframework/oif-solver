//! Transaction delivery module for the OIF solver system.
//!
//! This module handles the submission and monitoring of blockchain transactions.
//! It provides abstractions for different delivery mechanisms across multiple
//! blockchain networks, managing transaction signing, submission, and confirmation.

use alloy_primitives::Bytes;
use async_trait::async_trait;
use solver_types::events::TransactionType;
use solver_types::{
	ChainData, ConfigSchema, ImplementationRegistry, NetworksConfig, Transaction, TransactionHash,
	TransactionReceipt,
};
use std::collections::HashMap;
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
	/// Error that occurs when no suitable implementation is available for the operation.
	#[error("No implementation available")]
	NoImplementationAvailable,
}

/// Callback for transaction monitoring events
pub type TransactionCallback = Box<dyn Fn(TransactionMonitoringEvent) + Send + Sync>;

/// Events emitted during transaction monitoring
#[derive(Debug, Clone)]
pub enum TransactionMonitoringEvent {
	/// Transaction was successfully confirmed
	Confirmed {
		id: String, // order_id in case of intents
		tx_hash: TransactionHash,
		tx_type: TransactionType,
		receipt: TransactionReceipt,
	},
	/// Transaction failed or was reverted
	Failed {
		id: String, // order_id in case of intents
		tx_hash: TransactionHash,
		tx_type: TransactionType,
		error: String,
	},
}

/// Options for tracking transaction confirmation
pub struct TransactionTracking {
	/// Unique identifier for the transaction (e.g. order_id)
	pub id: String,
	/// Type of transaction being submitted
	pub tx_type: TransactionType,
	/// Callback to invoke when transaction state changes
	pub callback: TransactionCallback,
}

impl std::fmt::Debug for TransactionTracking {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("TransactionTracking")
			.field("id", &self.id)
			.field("tx_type", &self.tx_type)
			.finish()
	}
}

/// Extended tracking options with service configuration
#[derive(Debug)]
pub struct TransactionTrackingWithConfig {
	/// Base tracking options
	pub tracking: TransactionTracking,
	/// Minimum confirmations required before considering transaction confirmed
	pub min_confirmations: u64,
	/// Timeout in seconds for monitoring the transaction
	pub monitoring_timeout_seconds: u64,
}

/// Trait defining the interface for transaction delivery implementations.
///
/// This trait must be implemented by any delivery implementation that wants to
/// integrate with the solver system. It provides methods for submitting
/// transactions and monitoring their confirmation status.
#[async_trait]
#[cfg_attr(feature = "testing", mockall::automock)]
pub trait DeliveryInterface: Send + Sync {
	/// Returns the configuration schema for this delivery implementation.
	///
	/// This allows each implementation to define its own configuration requirements
	/// with specific validation rules. The schema is used to validate TOML configuration
	/// before initializing the delivery implementation.
	fn config_schema(&self) -> Box<dyn ConfigSchema>;

	/// Signs and submits a transaction to the blockchain.
	///
	/// Takes a transaction, signs it with the appropriate signer for the chain,
	/// then submits it to the network and returns the transaction hash.
	///
	/// If tracking is provided, monitors the transaction for confirmation/failure
	/// and calls the callback when the transaction state changes.
	async fn submit(
		&self,
		tx: Transaction,
		tracking: Option<TransactionTrackingWithConfig>,
	) -> Result<TransactionHash, DeliveryError>;

	/// Retrieves the receipt for a transaction if available.
	///
	/// Returns immediately with the current transaction receipt, or an error
	/// if the transaction is not found or not yet mined.
	async fn get_receipt(
		&self,
		hash: &TransactionHash,
		chain_id: u64,
	) -> Result<TransactionReceipt, DeliveryError>;

	/// Gets the current gas price for the network.
	///
	/// Returns the recommended gas price in wei as a decimal string.
	async fn get_gas_price(&self, chain_id: u64) -> Result<String, DeliveryError>;

	/// Gets the balance for an address.
	///
	/// For native tokens, pass None for the token parameter.
	/// For ERC-20 tokens, pass the contract address as Some(address).
	/// Returns the balance as a decimal string.
	async fn get_balance(
		&self,
		address: &str,
		token: Option<&str>,
		chain_id: u64,
	) -> Result<String, DeliveryError>;

	/// Gets the ERC-20 token allowance for an owner-spender pair.
	///
	/// Returns the amount of tokens that the spender is allowed to transfer
	/// on behalf of the owner, as a decimal string.
	async fn get_allowance(
		&self,
		owner: &str,
		spender: &str,
		token_address: &str,
		chain_id: u64,
	) -> Result<String, DeliveryError>;

	/// Gets the current nonce for an address.
	///
	/// Returns the next valid nonce for transaction submission.
	async fn get_nonce(&self, address: &str, chain_id: u64) -> Result<u64, DeliveryError>;

	/// Gets the current block number.
	///
	/// Returns the latest block number on the network.
	async fn get_block_number(&self, chain_id: u64) -> Result<u64, DeliveryError>;

	/// Estimates gas units for a transaction without submitting it.
	/// Implementations should call the chain's estimateGas RPC with the provided transaction.
	async fn estimate_gas(&self, tx: Transaction) -> Result<u64, DeliveryError>;

	/// Executes a contract call without sending a transaction.
	///
	/// This performs an eth_call RPC to read data from smart contracts
	/// or simulate transaction execution without submitting to the blockchain.
	async fn eth_call(&self, tx: Transaction) -> Result<Bytes, DeliveryError>;
}

/// Type alias for delivery factory functions.
///
/// This is the function signature that all delivery implementations must provide
/// to create instances of their delivery interface.
pub type DeliveryFactory = fn(
	&toml::Value,
	&NetworksConfig,
	&solver_account::AccountSigner,               // Default/primary signer
	&HashMap<u64, solver_account::AccountSigner>, // Per-network signers
) -> Result<Box<dyn DeliveryInterface>, DeliveryError>;

/// Registry trait for delivery implementations.
///
/// This trait extends the base ImplementationRegistry to specify that
/// delivery implementations must provide a DeliveryFactory.
pub trait DeliveryRegistry: ImplementationRegistry<Factory = DeliveryFactory> {}

/// Get all registered delivery implementations.
///
/// Returns a vector of (name, factory) tuples for all available delivery implementations.
/// This is used by the factory registry to automatically register all implementations.
pub fn get_all_implementations() -> Vec<(&'static str, DeliveryFactory)> {
	use implementations::evm::alloy;

	vec![(alloy::Registry::NAME, alloy::Registry::factory())]
}

/// Service that manages transaction delivery across multiple blockchain networks.
///
/// The DeliveryService coordinates between different delivery implementations based on
/// chain ID and provides methods for transaction submission and confirmation monitoring.
pub struct DeliveryService {
	/// Map of chain IDs to their corresponding delivery implementations.
	implementations: std::collections::HashMap<u64, Arc<dyn DeliveryInterface>>,
	/// Default number of confirmations required for transactions.
	min_confirmations: u64,
	/// Timeout for transaction monitoring in seconds.
	monitoring_timeout_seconds: u64,
}

impl DeliveryService {
	/// Creates a new DeliveryService with the specified implementations and configuration.
	///
	/// The implementations map should contain delivery implementations for each supported
	/// chain ID.
	pub fn new(
		implementations: std::collections::HashMap<u64, Arc<dyn DeliveryInterface>>,
		min_confirmations: u64,
		monitoring_timeout_seconds: u64,
	) -> Self {
		Self {
			implementations,
			min_confirmations,
			monitoring_timeout_seconds,
		}
	}

	/// Delivers a transaction to the appropriate blockchain network.
	///
	/// This method:
	/// 1. Selects the appropriate implementation based on the transaction's chain ID
	/// 2. Submits the transaction through the implementation (which handles signing)
	///
	/// If tracking is provided, monitors the transaction for confirmation/failure.
	pub async fn deliver(
		&self,
		tx: Transaction,
		tracking: Option<TransactionTracking>,
	) -> Result<TransactionHash, DeliveryError> {
		// Get the implementation for the transaction's chain ID
		let implementation = self
			.implementations
			.get(&tx.chain_id)
			.ok_or(DeliveryError::NoImplementationAvailable)?;

		// Submit using the chain-specific implementation (which handles signing)
		// If tracking is provided, add our service configuration
		let enhanced_tracking = tracking.map(|t| TransactionTrackingWithConfig {
			tracking: t,
			min_confirmations: self.min_confirmations,
			monitoring_timeout_seconds: self.monitoring_timeout_seconds,
		});
		implementation.submit(tx, enhanced_tracking).await
	}

	/// Gets the transaction receipt for a given transaction hash.
	///
	/// Returns the full transaction receipt including status, block number, logs, etc.
	pub async fn get_receipt(
		&self,
		hash: &TransactionHash,
		chain_id: u64,
	) -> Result<TransactionReceipt, DeliveryError> {
		let implementation = self
			.implementations
			.get(&chain_id)
			.ok_or(DeliveryError::NoImplementationAvailable)?;

		implementation.get_receipt(hash, chain_id).await
	}

	/// Checks the current status of a transaction on a specific chain.
	///
	/// Returns true if the transaction was successful, false if it failed.
	pub async fn get_status(
		&self,
		hash: &TransactionHash,
		chain_id: u64,
	) -> Result<bool, DeliveryError> {
		let receipt = self.get_receipt(hash, chain_id).await?;
		Ok(receipt.success)
	}

	/// Gets chain-specific data for the given chain ID.
	///
	/// Returns gas price, block number, and other chain state information.
	pub async fn get_chain_data(&self, chain_id: u64) -> Result<ChainData, DeliveryError> {
		let implementation = self
			.implementations
			.get(&chain_id)
			.ok_or(DeliveryError::NoImplementationAvailable)?;

		let gas_price = implementation.get_gas_price(chain_id).await?;
		let block_number = implementation.get_block_number(chain_id).await?;

		Ok(ChainData {
			chain_id,
			gas_price,
			block_number,
			timestamp: std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.unwrap_or_default()
				.as_secs(),
		})
	}

	/// Gets the balance for an address on a specific chain.
	///
	/// Convenience method that routes to the appropriate implementation.
	pub async fn get_balance(
		&self,
		chain_id: u64,
		address: &str,
		token: Option<&str>,
	) -> Result<String, DeliveryError> {
		let implementation = self
			.implementations
			.get(&chain_id)
			.ok_or(DeliveryError::NoImplementationAvailable)?;

		implementation.get_balance(address, token, chain_id).await
	}

	/// Gets the nonce for an address on a specific chain.
	///
	/// Convenience method that routes to the appropriate implementation.
	pub async fn get_nonce(&self, chain_id: u64, address: &str) -> Result<u64, DeliveryError> {
		let implementation = self
			.implementations
			.get(&chain_id)
			.ok_or(DeliveryError::NoImplementationAvailable)?;

		implementation.get_nonce(address, chain_id).await
	}

	/// Gets the ERC-20 token allowance for an owner-spender pair on a specific chain.
	///
	/// Convenience method that routes to the appropriate implementation.
	pub async fn get_allowance(
		&self,
		chain_id: u64,
		owner: &str,
		spender: &str,
		token_address: &str,
	) -> Result<String, DeliveryError> {
		let implementation = self
			.implementations
			.get(&chain_id)
			.ok_or(DeliveryError::NoImplementationAvailable)?;

		implementation
			.get_allowance(owner, spender, token_address, chain_id)
			.await
	}

	/// Gets the current gas price for a specific chain.
	///
	/// Returns the gas price as a string in wei.
	pub async fn get_gas_price(&self, chain_id: u64) -> Result<String, DeliveryError> {
		let implementation = self
			.implementations
			.get(&chain_id)
			.ok_or(DeliveryError::NoImplementationAvailable)?;

		implementation.get_gas_price(chain_id).await
	}

	/// Gets the current block number for a specific chain.
	///
	/// Returns the latest block number.
	pub async fn get_block_number(&self, chain_id: u64) -> Result<u64, DeliveryError> {
		let implementation = self
			.implementations
			.get(&chain_id)
			.ok_or(DeliveryError::NoImplementationAvailable)?;

		implementation.get_block_number(chain_id).await
	}

	/// Estimates gas for a transaction on the specified chain.
	pub async fn estimate_gas(&self, chain_id: u64, tx: Transaction) -> Result<u64, DeliveryError> {
		let implementation = self
			.implementations
			.get(&chain_id)
			.ok_or(DeliveryError::NoImplementationAvailable)?;

		implementation.estimate_gas(tx).await
	}

	/// Executes a contract call (eth_call) without sending a transaction.
	///
	/// This method is used to read data from smart contracts or simulate
	/// transaction execution without actually submitting to the blockchain.
	/// Returns the raw bytes returned by the contract call.
	pub async fn contract_call(
		&self,
		chain_id: u64,
		tx: Transaction,
	) -> Result<alloy_primitives::Bytes, DeliveryError> {
		let implementation = self
			.implementations
			.get(&chain_id)
			.ok_or(DeliveryError::NoImplementationAvailable)?;

		implementation.eth_call(tx).await
	}
}
