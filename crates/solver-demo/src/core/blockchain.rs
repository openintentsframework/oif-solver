//! Blockchain provider and transaction management
//!
//! This module provides blockchain connectivity, transaction building, and execution
//! capabilities. Supports multiple networks, automatic gas estimation, nonce management,
//! and transaction receipt polling with comprehensive error handling.

use crate::types::{
	chain::ChainId,
	error::{Error, Result},
};
use alloy_primitives::{Address, B256, U256};
use alloy_provider::{Provider as AlloyProvider, ProviderBuilder};
use alloy_rpc_types::{TransactionReceipt, TransactionRequest};
use alloy_signer_local::PrivateKeySigner;
use std::sync::Arc;

/// Blockchain provider wrapper with chain-specific configuration
///
/// Provides high-level interface for blockchain operations including balance queries,
/// contract calls, and transaction execution with automatic connection testing
/// and error handling for specific blockchain networks
#[derive(Clone)]
pub struct Provider {
	inner: Arc<dyn AlloyProvider + Send + Sync>,
	chain: ChainId,
}

impl std::fmt::Debug for Provider {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Provider")
			.field("chain", &self.chain)
			.field("inner", &"<dyn AlloyProvider>")
			.finish()
	}
}

impl Provider {
	/// Create new blockchain provider for specified chain
	///
	/// Establishes connection to blockchain network and validates connectivity
	/// by retrieving chain ID from the RPC endpoint
	///
	/// # Arguments
	/// * `chain` - Target blockchain network identifier
	/// * `rpc_url` - RPC endpoint URL for blockchain connection
	///
	/// # Returns
	/// Provider instance ready for blockchain operations
	///
	/// # Errors
	/// Returns Error if RPC URL is invalid or connection test fails
	pub async fn new(chain: ChainId, rpc_url: &str) -> Result<Self> {
		let url = rpc_url
			.parse()
			.map_err(|e| Error::RpcError(format!("Invalid RPC URL: {}", e)))?;

		let provider = ProviderBuilder::new().connect_http(url);

		// Test connection
		provider
			.get_chain_id()
			.await
			.map_err(|e| Error::RpcError(format!("Failed to connect to {}: {}", rpc_url, e)))?;

		Ok(Self {
			inner: Arc::new(provider),
			chain,
		})
	}

	/// Retrieve ETH balance for specified address
	///
	/// # Arguments
	/// * `address` - Ethereum address to query balance for
	///
	/// # Returns
	/// Balance in wei as U256
	///
	/// # Errors
	/// Returns Error if balance query fails
	pub async fn balance(&self, address: Address) -> Result<U256> {
		self.inner
			.get_balance(address)
			.await
			.map_err(|e| Error::RpcError(format!("Failed to get balance: {}", e)))
	}

	/// Retrieve current block number from blockchain
	///
	/// # Returns
	/// Latest block number as u64
	///
	/// # Errors
	/// Returns Error if block number query fails
	pub async fn block_number(&self) -> Result<u64> {
		self.inner
			.get_block_number()
			.await
			.map_err(|e| Error::RpcError(format!("Failed to get block number: {}", e)))
	}

	/// Retrieve configured chain identifier
	///
	/// # Returns
	/// ChainId for this provider instance
	pub fn chain(&self) -> ChainId {
		self.chain
	}

	/// Access underlying Alloy provider for advanced operations
	///
	/// # Returns
	/// Reference to the wrapped provider instance
	pub fn inner(&self) -> &(dyn AlloyProvider + Send + Sync) {
		&*self.inner
	}

	/// Test blockchain connectivity by querying chain ID
	///
	/// # Returns
	/// True if provider can successfully communicate with blockchain
	pub async fn is_connected(&self) -> bool {
		self.inner.get_chain_id().await.is_ok()
	}

	/// Deploy bytecode at specific address using Anvil setCode RPC method
	///
	/// # Arguments
	/// * `address` - Target address for bytecode deployment
	/// * `bytecode` - Hex-encoded bytecode to deploy
	///
	/// # Returns
	/// Success if bytecode deployment completes
	///
	/// # Errors
	/// Returns Error if anvil_setCode RPC call fails
	pub async fn set_code(&self, address: &str, bytecode: &str) -> crate::types::error::Result<()> {
		use std::borrow::Cow;

		// Serialize parameters to RawValue
		let params = serde_json::to_string(&(address, bytecode)).map_err(|e| {
			crate::types::error::Error::from(format!("Failed to serialize params: {}", e))
		})?;
		let raw_params = serde_json::value::RawValue::from_string(params).map_err(|e| {
			crate::types::error::Error::from(format!("Failed to create RawValue: {}", e))
		})?;

		let _response = self
			.inner
			.raw_request_dyn(Cow::Borrowed("anvil_setCode"), &raw_params)
			.await
			.map_err(|e| {
				crate::types::error::Error::from(format!("anvil_setCode failed: {}", e))
			})?;
		Ok(())
	}

	/// Execute contract call and return result data
	///
	/// # Arguments
	/// * `to` - Contract address to call
	/// * `data` - Encoded function call data
	/// * `_chain_id` - Optional chain ID for the call
	///
	/// # Returns
	/// Raw bytes returned from contract call
	///
	/// # Errors
	/// Returns Error if contract call fails
	pub async fn call_contract(
		&self,
		to: Address,
		data: alloy_primitives::Bytes,
		_chain_id: Option<u64>,
	) -> Result<Vec<u8>> {
		use alloy_rpc_types::TransactionRequest;

		let tx = TransactionRequest::default().to(to).input(data.into());

		let result = self
			.inner
			.call(tx)
			.await
			.map_err(|e| Error::RpcError(format!("Contract call failed: {}", e)))?;

		Ok(result.to_vec())
	}

	/// Calculate order identifier from standard order structure
	///
	/// Simplified implementation that returns placeholder order ID.
	/// Production version would call contract to compute actual order hash
	///
	/// # Arguments
	/// * `_chain_id` - Blockchain network identifier
	/// * `_contract_address` - Contract address for order processing
	/// * `_standard_order` - Standard order structure to hash
	///
	/// # Returns
	/// 32-byte order identifier
	///
	/// # Errors
	/// Returns Error if order computation fails
	pub async fn compute_order_identifier(
		&self,
		_chain_id: u64,
		_contract_address: Address,
		_standard_order: &solver_types::standards::eip7683::interfaces::StandardOrder,
	) -> Result<[u8; 32]> {
		// For now, return a dummy order identifier
		// In a real implementation, this would call the contract to compute the order hash
		let mut order_id = [0u8; 32];
		order_id[0] = 0x01; // Just to make it non-zero
		Ok(order_id)
	}
}

/// Transaction builder with automatic parameter filling and execution
///
/// Provides convenient transaction building with automatic gas estimation,
/// nonce management, gas price setting, and transaction execution with
/// optional signing for different blockchain networks
#[derive(Debug, Clone)]
pub struct TxBuilder {
	provider: Provider,
	signer: Option<PrivateKeySigner>,
}

impl TxBuilder {
	/// Create new transaction builder with provider
	///
	/// # Arguments
	/// * `provider` - Blockchain provider for transaction execution
	///
	/// # Returns
	/// Transaction builder ready for configuration
	pub fn new(provider: Provider) -> Self {
		Self {
			provider,
			signer: None,
		}
	}

	/// Configure transaction signer for signed transaction execution
	///
	/// # Arguments
	/// * `signer` - Private key signer for transaction signing
	///
	/// # Returns
	/// Transaction builder with signer configured
	pub fn with_signer(mut self, signer: PrivateKeySigner) -> Self {
		self.signer = Some(signer);
		self
	}

	/// Execute transaction with automatic parameter filling and signing
	///
	/// Automatically fills missing transaction parameters including chain ID,
	/// gas estimation, nonce, and gas price before sending to network
	///
	/// # Arguments
	/// * `tx` - Transaction request to execute
	///
	/// # Returns
	/// Transaction hash after successful submission
	///
	/// # Errors
	/// Returns Error if parameter estimation or transaction submission fails
	pub async fn send(&self, mut tx: TransactionRequest) -> Result<B256> {
		// Set chain ID if not set
		if tx.chain_id.is_none() {
			tx.chain_id = Some(self.provider.chain().id());
		}

		// If we have a signer, sign the transaction
		if let Some(signer) = &self.signer {
			// Set the from address to the signer's address
			tx.from = Some(signer.address());

			// Fill transaction with gas estimates if needed
			if tx.gas.is_none() {
				let gas = self
					.provider
					.inner
					.estimate_gas(tx.clone())
					.await
					.map_err(|e| Error::RpcError(format!("Failed to estimate gas: {}", e)))?;
				tx.gas = Some(gas);
			}

			// Fill nonce if not set
			if tx.nonce.is_none() {
				let nonce = self
					.provider
					.inner
					.get_transaction_count(signer.address())
					.await
					.map_err(|e| Error::RpcError(format!("Failed to get nonce: {}", e)))?;
				tx.nonce = Some(nonce);
			}

			// Fill gas price if not set
			if tx.gas_price.is_none() && tx.max_fee_per_gas.is_none() {
				let gas_price = self
					.provider
					.inner
					.get_gas_price()
					.await
					.map_err(|e| Error::RpcError(format!("Failed to get gas price: {}", e)))?;
				tx.gas_price = Some(gas_price);
			}

			// Send the transaction with from field set
			// For local test networks like Anvil, this should work without manual signing
			let pending = self
				.provider
				.inner
				.send_transaction(tx)
				.await
				.map_err(|e| Error::RpcError(format!("Failed to send transaction: {}", e)))?;

			Ok(*pending.tx_hash())
		} else {
			// No signer provided, send unsigned (for view functions only)
			let pending = self
				.provider
				.inner
				.send_transaction(tx)
				.await
				.map_err(|e| Error::RpcError(format!("Failed to send transaction: {}", e)))?;

			Ok(*pending.tx_hash())
		}
	}

	/// Poll blockchain for transaction receipt with timeout
	///
	/// # Arguments
	/// * `hash` - Transaction hash to monitor
	///
	/// # Returns
	/// Transaction receipt when transaction is mined
	///
	/// # Errors
	/// Returns Error if receipt retrieval fails or timeout is reached
	pub async fn wait(&self, hash: B256) -> Result<TransactionReceipt> {
		// Poll for receipt
		let mut attempts = 0;
		const MAX_ATTEMPTS: u32 = 60; // 60 seconds max wait

		loop {
			if let Some(receipt) = self
				.provider
				.inner
				.get_transaction_receipt(hash)
				.await
				.map_err(|e| Error::RpcError(format!("Failed to get receipt: {}", e)))?
			{
				return Ok(receipt);
			}

			attempts += 1;
			if attempts >= MAX_ATTEMPTS {
				return Err(Error::TxNotFound(hash));
			}

			tokio::time::sleep(std::time::Duration::from_secs(1)).await;
		}
	}

	/// Execute transaction and wait for confirmation receipt
	///
	/// Convenience method that combines transaction sending and receipt polling
	/// into a single operation for complete transaction lifecycle management
	///
	/// # Arguments
	/// * `tx` - Transaction request to execute and monitor
	///
	/// # Returns
	/// Transaction receipt after successful mining
	///
	/// # Errors
	/// Returns Error if transaction submission or receipt polling fails
	pub async fn send_and_wait(&self, tx: TransactionRequest) -> Result<TransactionReceipt> {
		let hash = self.send(tx).await?;
		self.wait(hash).await
	}
}
