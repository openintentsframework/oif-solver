//! Transaction delivery implementations for the solver service.
//!
//! This module provides concrete implementations of the DeliveryInterface trait,
//! supporting blockchain transaction submission and monitoring using the Alloy library.

use crate::{
	DeliveryError, DeliveryInterface, TransactionMonitoringEvent, TransactionTrackingWithConfig,
};
use alloy_network::EthereumWallet;
use alloy_primitives::{Address, Bytes, FixedBytes, U256};
use alloy_provider::{
	fillers::{ChainIdFiller, GasFiller, NonceFiller, SimpleNonceManager},
	DynProvider, Provider, ProviderBuilder,
};
use alloy_rpc_client::RpcClient;
use alloy_rpc_types::TransactionRequest;
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use alloy_transport::layers::{RateLimitRetryPolicy, RetryBackoffLayer};
use alloy_transport::TransportError;
use async_trait::async_trait;
use solver_types::{
	ConfigSchema, Field, FieldType, NetworksConfig, Schema, Transaction as SolverTransaction,
	TransactionHash, TransactionReceipt,
};
use std::collections::HashMap;

/// Alloy-based EVM delivery implementation.
///
/// This implementation uses the Alloy library to submit and monitor transactions
/// on EVM-compatible blockchains. It handles transaction signing, submission,
/// and confirmation tracking. Supports multiple networks with a single instance.
pub struct AlloyDelivery {
	/// Alloy providers for each supported network.
	providers: HashMap<u64, DynProvider>,
}

impl AlloyDelivery {
	/// Creates a new AlloyDelivery instance.
	///
	/// Configures Alloy providers for multiple networks with the specified
	/// RPC URLs and signers for transaction submission. The default_signer is used
	/// for networks that don't have a specific signer configured.
	pub async fn new(
		network_ids: Vec<u64>,
		networks: &NetworksConfig,
		signers: HashMap<u64, PrivateKeySigner>,
		default_signer: PrivateKeySigner,
	) -> Result<Self, DeliveryError> {
		// Validate at least one network
		if network_ids.is_empty() {
			return Err(DeliveryError::Network(
				"At least one network_id must be specified".to_string(),
			));
		}

		let mut providers = HashMap::new();

		for network_id in &network_ids {
			// Get network configuration
			let network = networks.get(network_id).ok_or_else(|| {
				DeliveryError::Network(format!("Network {} not found in configuration", network_id))
			})?;

			// Get HTTP URL from network configuration
			let http_url = network.get_http_url().ok_or_else(|| {
				DeliveryError::Network(format!(
					"No HTTP RPC URL configured for network {}",
					network_id
				))
			})?;

			// Parse RPC URL
			let url = http_url.parse().map_err(|e| {
				DeliveryError::Network(format!("Invalid RPC URL for network {}: {}", network_id, e))
			})?;

			// Get the signer for this network, or use the default
			let signer = signers.get(network_id).unwrap_or(&default_signer);

			// Create signer with chain ID
			let chain_signer = signer.clone().with_chain_id(Some(*network_id));
			let wallet = EthereumWallet::from(chain_signer);

			// Configure retry layer for handling network errors, rate limits, and execution reverts
			// Extend the default rate limit policy to also retry execution reverts during transaction submission
			let retry_policy = RateLimitRetryPolicy::default().or(|error: &TransportError| {
				match error {
					TransportError::ErrorResp(payload) => {
						// Retry execution reverts (error code 3) that may be temporary
						// These often occur during transaction submission due to network congestion or contract state issues
						payload.code == 3 && payload.message.contains("execution reverted")
					},
					_ => false,
				}
			});

			let retry_layer = RetryBackoffLayer::new_with_policy(
				3,    // max_retry: retry up to 3 times for transaction submission (more conservative)
				1500, // backoff: slightly longer initial backoff for transaction retries
				10,   // cups: compute units per second
				retry_policy,
			);

			// Create RPC client with retry capabilities
			let client = RpcClient::builder().layer(retry_layer).http(url);

			// Create provider with simple nonce management and retry capabilities
			let provider = ProviderBuilder::new()
				.filler(NonceFiller::new(SimpleNonceManager::default()))
				.filler(GasFiller)
				.filler(ChainIdFiller::default())
				.wallet(wallet)
				.connect_client(client);

			provider
				.client()
				.set_poll_interval(std::time::Duration::from_secs(7));

			// Use type erasure to simplify the provider type
			let dyn_provider = provider.erased();
			providers.insert(*network_id, dyn_provider);
		}

		Ok(Self { providers })
	}

	/// Gets the provider for a specific chain ID.
	fn get_provider(&self, chain_id: u64) -> Result<&DynProvider, DeliveryError> {
		self.providers.get(&chain_id).ok_or_else(|| {
			DeliveryError::Network(format!("No provider configured for chain ID {}", chain_id))
		})
	}
}

/// Configuration schema for Alloy delivery provider.
///
/// This schema defines the required configuration fields for the Alloy
/// delivery provider, including RPC URL and chain ID validation.
pub struct AlloyDeliverySchema;

impl AlloyDeliverySchema {
	/// Static validation method for use before instance creation
	pub fn validate_config(config: &toml::Value) -> Result<(), solver_types::ValidationError> {
		let instance = Self;
		instance.validate(config)
	}
}

impl ConfigSchema for AlloyDeliverySchema {
	fn validate(&self, config: &toml::Value) -> Result<(), solver_types::ValidationError> {
		let schema = Schema::new(
			// Required fields
			vec![Field::new(
				"network_ids",
				FieldType::Array(Box::new(FieldType::Integer {
					min: Some(1),
					max: None,
				})),
			)
			.with_validator(|value| {
				if let Some(arr) = value.as_array() {
					if arr.is_empty() {
						return Err("network_ids cannot be empty".to_string());
					}
					Ok(())
				} else {
					Err("network_ids must be an array".to_string())
				}
			})],
			// Optional fields
			vec![Field::new(
				"accounts",
				FieldType::Table(Schema::new(
					vec![], // No required fields - network IDs are dynamic
					vec![], // No optional fields - all entries should be account names
				)),
			)
			.with_validator(|value| {
				if let Some(table) = value.as_table() {
					// Validate that keys are valid integers (network IDs)
					// and values are strings (account names)
					for (key, val) in table {
						// Try to parse key as network ID
						if key.parse::<u64>().is_err() {
							return Err(format!("Invalid network ID in accounts: {}", key));
						}
						// Check value is a string
						if !val.is_str() {
							return Err(format!(
								"Account name for network {} must be a string",
								key
							));
						}
					}
					Ok(())
				} else {
					Err("accounts must be a table".to_string())
				}
			})],
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
		tracking: Option<TransactionTrackingWithConfig>,
	) -> Result<TransactionHash, DeliveryError> {
		// Get the chain ID from the transaction
		let chain_id = tx.chain_id;

		// Get the appropriate provider for this chain
		let provider = self.get_provider(chain_id)?;

		// Convert solver transaction to alloy transaction request
		let request: TransactionRequest = tx.clone().into();

		// Log request details for debugging
		if tracking.is_some() {
			tracing::debug!(
				"Sending transaction with monitoring on chain {}: to={:?}, value={:?}, data_len={}, gas_limit={:?}",
				chain_id,
				request.to,
				request.value,
				request.input.input().map(|d| d.len()).unwrap_or(0),
				request.gas
			);
		} else {
			tracing::debug!(
				"Sending transaction on chain {}: to={:?}, value={:?}, data_len={}, gas_limit={:?}",
				chain_id,
				request.to,
				request.value,
				request.input.input().map(|d| d.len()).unwrap_or(0),
				request.gas
			);
		}

		// Send transaction - the provider's wallet will handle signing
		let pending_tx = provider.send_transaction(request).await.map_err(|e| {
			tracing::error!("Transaction submission failed on chain {}: {}", chain_id, e);
			DeliveryError::Network(format!("Failed to send transaction: {}", e))
		})?;

		// Get the transaction hash
		let tx_hash = *pending_tx.tx_hash();
		let tx_hash_obj = TransactionHash(tx_hash.0.to_vec());

		// If tracking is provided, set up monitoring
		if let Some(tracking) = tracking {
			let tx_hash_clone = tx_hash_obj.clone();
			let monitor_chain_id = chain_id;
			tokio::spawn(async move {
				let result = monitor_transaction(
					pending_tx,
					tracking.min_confirmations,
					tracking.monitoring_timeout_seconds,
					monitor_chain_id,
				)
				.await;

				match result {
					Ok(receipt) => {
						(tracking.tracking.callback)(TransactionMonitoringEvent::Confirmed {
							id: tracking.tracking.id,
							tx_hash: tx_hash_clone,
							tx_type: tracking.tracking.tx_type,
							receipt,
						});
					},
					Err(error) => {
						(tracking.tracking.callback)(TransactionMonitoringEvent::Failed {
							id: tracking.tracking.id,
							tx_hash: tx_hash_clone,
							tx_type: tracking.tracking.tx_type,
							error: error.to_string(),
						});
					},
				}
			});
		}

		Ok(tx_hash_obj)
	}

	async fn get_receipt(
		&self,
		hash: &TransactionHash,
		chain_id: u64,
	) -> Result<TransactionReceipt, DeliveryError> {
		let tx_hash = FixedBytes::<32>::from_slice(&hash.0);

		// Get the provider for the specified chain
		let provider = self.get_provider(chain_id)?;

		match provider.get_transaction_receipt(tx_hash).await {
			Ok(Some(receipt)) => {
				// Convert alloy receipt to solver receipt using From implementation
				Ok(TransactionReceipt::from(&receipt))
			},
			Ok(None) => Err(DeliveryError::Network(format!(
				"Transaction not found on chain {}",
				chain_id
			))),
			Err(e) => Err(DeliveryError::Network(format!(
				"Failed to get receipt on chain {}: {}",
				chain_id, e
			))),
		}
	}

	/// Gets the current gas price for the network.
	///
	/// Returns the recommended gas price in wei as a decimal string.
	async fn get_gas_price(&self, chain_id: u64) -> Result<String, DeliveryError> {
		let provider = self.get_provider(chain_id)?;

		let gas_price = provider
			.get_gas_price()
			.await
			.map_err(|e| DeliveryError::Network(format!("Failed to get gas price: {}", e)))?;

		Ok(gas_price.to_string())
	}

	async fn get_balance(
		&self,
		address: &str,
		token: Option<&str>,
		chain_id: u64,
	) -> Result<String, DeliveryError> {
		let address: Address = address
			.parse()
			.map_err(|e| DeliveryError::Network(format!("Invalid address: {}", e)))?;

		let provider = self.get_provider(chain_id)?;

		match token {
			None => {
				// Get native token balance
				let balance = provider
					.get_balance(address)
					.await
					.map_err(|e| DeliveryError::Network(format!("Failed to get balance: {}", e)))?;

				Ok(balance.to_string())
			},
			Some(token_address) => {
				// Get ERC-20 token balance
				let token_addr: Address = token_address
					.parse()
					.map_err(|e| DeliveryError::Network(format!("Invalid token address: {}", e)))?;

				// Create the balanceOf call data
				// balanceOf(address) selector is 0x70a08231
				let selector = [0x70, 0xa0, 0x82, 0x31];
				let mut call_data = Vec::new();
				call_data.extend_from_slice(&selector);
				call_data.extend_from_slice(&[0; 12]); // Pad to 32 bytes
				call_data.extend_from_slice(address.as_slice());

				let call_result = provider
					.call(
						TransactionRequest::default()
							.to(token_addr)
							.input(call_data.into()),
					)
					.await
					.map_err(|e| {
						DeliveryError::Network(format!("Failed to call balanceOf: {}", e))
					})?;

				if call_result.len() < 32 {
					return Err(DeliveryError::Network(
						"Invalid balanceOf response".to_string(),
					));
				}

				let balance = U256::from_be_slice(&call_result[..32]);
				Ok(balance.to_string())
			},
		}
	}

	async fn get_allowance(
		&self,
		owner: &str,
		spender: &str,
		token_address: &str,
		chain_id: u64,
	) -> Result<String, DeliveryError> {
		let owner_addr: Address = owner
			.parse()
			.map_err(|e| DeliveryError::Network(format!("Invalid owner address: {}", e)))?;

		let spender_addr: Address = spender
			.parse()
			.map_err(|e| DeliveryError::Network(format!("Invalid spender address: {}", e)))?;

		let token_addr: Address = token_address
			.parse()
			.map_err(|e| DeliveryError::Network(format!("Invalid token address: {}", e)))?;

		let provider = self.get_provider(chain_id)?;

		// Create the allowance call data
		// allowance(address,address) selector is 0xdd62ed3e
		let selector = [0xdd, 0x62, 0xed, 0x3e];
		let mut call_data = Vec::new();
		call_data.extend_from_slice(&selector);
		call_data.extend_from_slice(&[0; 12]); // Pad owner address to 32 bytes
		call_data.extend_from_slice(owner_addr.as_slice());
		call_data.extend_from_slice(&[0; 12]); // Pad spender address to 32 bytes
		call_data.extend_from_slice(spender_addr.as_slice());

		let call_request = TransactionRequest::default()
			.to(token_addr)
			.input(call_data.into());

		let call_result = provider
			.call(call_request)
			.await
			.map_err(|e| DeliveryError::Network(format!("Failed to call allowance: {}", e)))?;

		if call_result.len() < 32 {
			return Err(DeliveryError::Network(
				"Invalid allowance response".to_string(),
			));
		}

		let allowance = U256::from_be_slice(&call_result[..32]);
		Ok(allowance.to_string())
	}

	async fn get_nonce(&self, address: &str, chain_id: u64) -> Result<u64, DeliveryError> {
		let address: Address = address
			.parse()
			.map_err(|e| DeliveryError::Network(format!("Invalid address: {}", e)))?;

		let provider = self.get_provider(chain_id)?;

		provider
			.get_transaction_count(address)
			.await
			.map_err(|e| DeliveryError::Network(format!("Failed to get nonce: {}", e)))
	}

	async fn get_block_number(&self, chain_id: u64) -> Result<u64, DeliveryError> {
		let provider = self.get_provider(chain_id)?;

		provider
			.get_block_number()
			.await
			.map_err(|e| DeliveryError::Network(format!("Failed to get block number: {}", e)))
	}
	async fn estimate_gas(&self, tx: SolverTransaction) -> Result<u64, DeliveryError> {
		// Get the chain ID from the transaction
		let chain_id = tx.chain_id;

		// Get the appropriate provider for this chain
		let provider = self.get_provider(chain_id)?;

		// Convert to TransactionRequest
		let request: TransactionRequest = tx.into();

		// The provider with wallet will automatically handle setting the `from` field
		// when needed for gas estimation
		let gas = provider
			.estimate_gas(request)
			.await
			.map_err(|e| DeliveryError::Network(format!("Failed to estimate gas: {}", e)))?;
		Ok(gas)
	}

	async fn eth_call(&self, tx: SolverTransaction) -> Result<Bytes, DeliveryError> {
		// Get the chain ID from the transaction
		let chain_id = tx.chain_id;

		// Get the appropriate provider for this chain
		let provider = self.get_provider(chain_id)?;

		// Convert to TransactionRequest
		let request: TransactionRequest = tx.into();

		// Execute the call without submitting a transaction
		let result = provider
			.call(request)
			.await
			.map_err(|e| DeliveryError::Network(format!("Failed to execute eth_call: {}", e)))?;

		Ok(result)
	}
}

/// Monitors a pending transaction for confirmation or timeout.
/// First checks if the receipt already exists (to handle fast-mining transactions),
/// then falls back to alloy's subscription-based monitoring.
async fn monitor_transaction(
	pending_tx: alloy_provider::PendingTransactionBuilder<alloy_network::Ethereum>,
	min_confirmations: u64,
	monitoring_timeout_seconds: u64,
	chain_id: u64,
) -> Result<TransactionReceipt, DeliveryError> {
	use std::time::Duration;

	let tx_hash = *pending_tx.tx_hash();
	let provider = pending_tx.provider().clone();
	let timeout_duration = Duration::from_secs(monitoring_timeout_seconds);

	tracing::info!(
		tx_hash = %tx_hash,
		chain_id = chain_id,
		min_confirmations = min_confirmations,
		timeout_seconds = monitoring_timeout_seconds,
		"Starting transaction monitoring"
	);

	// First, check if the transaction is already mined (handles race condition where
	// tx mines before the subscription is set up)
	if let Ok(Some(receipt)) = provider.get_transaction_receipt(tx_hash).await {
		if receipt.status() {
			// Transaction already mined and successful, check confirmations
			if min_confirmations > 0 {
				if let Some(block_number) = receipt.block_number {
					if let Ok(current_block) = provider.get_block_number().await {
						let confirmations = current_block.saturating_sub(block_number);
						if confirmations >= min_confirmations {
							tracing::info!(
								tx_hash = %tx_hash,
								chain_id = chain_id,
								block_number = ?receipt.block_number,
								"Transaction already confirmed"
							);
							return Ok(TransactionReceipt::from(&receipt));
						}
						// Not enough confirmations yet, fall through to subscription
					}
				}
			} else {
				// No confirmations required
				tracing::info!(
					tx_hash = %tx_hash,
					chain_id = chain_id,
					block_number = ?receipt.block_number,
					"Transaction already confirmed"
				);
				return Ok(TransactionReceipt::from(&receipt));
			}
		} else {
			tracing::error!(
				tx_hash = %tx_hash,
				chain_id = chain_id,
				"Transaction reverted"
			);
			return Err(DeliveryError::TransactionFailed(
				"Transaction reverted".to_string(),
			));
		}
	}

	// Use alloy's subscription-based monitoring for pending transactions
	match pending_tx
		.with_required_confirmations(min_confirmations)
		.with_timeout(Some(timeout_duration))
		.get_receipt()
		.await
	{
		Ok(receipt) => {
			tracing::info!(
				tx_hash = %tx_hash,
				chain_id = chain_id,
				block_number = ?receipt.block_number,
				"Transaction confirmed in monitoring"
			);
			Ok(TransactionReceipt::from(&receipt))
		},
		Err(e) => {
			tracing::error!(
				tx_hash = %tx_hash,
				chain_id = chain_id,
				error = %e,
				"Transaction monitoring failed"
			);
			Err(DeliveryError::TransactionFailed(format!(
				"Transaction monitoring failed: {}",
				e
			)))
		},
	}
}

/// Factory function to create an HTTP-based delivery provider from configuration.
///
/// This function reads the delivery configuration and creates an AlloyDelivery
/// instance.
///
/// # Parameters
/// - `config`: TOML configuration containing:
///   - `network_ids` (required): Array of network IDs to support
///   - `accounts` (optional): Map of network IDs to account names for per-network signing
/// - `networks`: Network configuration containing RPC URLs and contract addresses
/// - `default_private_key`: Default private key for signing transactions
/// - `network_private_keys`: Map of network IDs to private keys for per-network signing
///
/// # Returns
/// A boxed implementation of DeliveryInterface configured for the specified networks
pub fn create_http_delivery(
	config: &toml::Value,
	networks: &NetworksConfig,
	default_private_key: &solver_types::SecretString,
	network_private_keys: &HashMap<u64, solver_types::SecretString>,
) -> Result<Box<dyn DeliveryInterface>, DeliveryError> {
	// Validate configuration first
	AlloyDeliverySchema::validate_config(config)
		.map_err(|e| DeliveryError::Network(format!("Invalid configuration: {}", e)))?;

	// Parse network_ids (required field)
	let network_ids = config
		.get("network_ids")
		.and_then(|v| v.as_array())
		.map(|arr| {
			arr.iter()
				.filter_map(|v| v.as_integer().map(|i| i as u64))
				.collect::<Vec<_>>()
		})
		.ok_or_else(|| DeliveryError::Network("network_ids is required".to_string()))?;

	if network_ids.is_empty() {
		return Err(DeliveryError::Network(
			"network_ids cannot be empty".to_string(),
		));
	}

	// Parse the default signer
	let default_signer: PrivateKeySigner = default_private_key.with_exposed(|key| {
		key.parse()
			.map_err(|_| DeliveryError::Network("Invalid default private key format".to_string()))
	})?;

	// Parse network-specific signers
	let mut network_signers = HashMap::new();
	for (network_id, private_key) in network_private_keys {
		let signer: PrivateKeySigner = private_key.with_exposed(|key| {
			key.parse().map_err(|_| {
				DeliveryError::Network(format!(
					"Invalid private key format for network {}",
					network_id
				))
			})
		})?;
		network_signers.insert(*network_id, signer);
	}

	// Create delivery service synchronously, but the actual connection happens async
	let delivery = tokio::task::block_in_place(|| {
		tokio::runtime::Handle::current().block_on(async {
			AlloyDelivery::new(network_ids, networks, network_signers, default_signer).await
		})
	})?;

	Ok(Box::new(delivery))
}

/// Registry for the HTTP/Alloy delivery implementation.
pub struct Registry;

impl solver_types::ImplementationRegistry for Registry {
	const NAME: &'static str = "evm_alloy";
	type Factory = crate::DeliveryFactory;

	fn factory() -> Self::Factory {
		create_http_delivery
	}
}

impl crate::DeliveryRegistry for Registry {}

#[cfg(test)]
mod tests {
	use super::*;
	use solver_types::{
		utils::tests::builders::{NetworkConfigBuilder, NetworksConfigBuilder},
		SecretString,
	};
	use std::collections::HashMap;

	fn create_test_networks() -> NetworksConfig {
		NetworksConfigBuilder::new()
			.add_network(1, NetworkConfigBuilder::new().build())
			.add_network(137, NetworkConfigBuilder::new().build())
			.build()
	}

	fn create_test_signer() -> PrivateKeySigner {
		"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
			.parse()
			.unwrap()
	}

	#[tokio::test]
	async fn test_alloy_delivery_new_success() {
		let networks = create_test_networks();
		let signer = create_test_signer();

		let result = AlloyDelivery::new(vec![1], &networks, HashMap::new(), signer).await;

		assert!(result.is_ok());
		let delivery = result.unwrap();
		assert!(delivery.providers.contains_key(&1));
	}

	#[tokio::test]
	async fn test_alloy_delivery_new_empty_networks() {
		let networks = NetworksConfigBuilder::new().build();
		let signer = create_test_signer();

		let result = AlloyDelivery::new(vec![], &networks, HashMap::new(), signer).await;

		assert!(matches!(result, Err(DeliveryError::Network(_))));
		if let Err(DeliveryError::Network(msg)) = result {
			assert!(msg.contains("At least one network_id must be specified"));
		}
	}

	#[test]
	fn test_config_schema_validation_valid() {
		let schema = AlloyDeliverySchema;
		let config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			table.insert(
				"network_ids".to_string(),
				toml::Value::Array(vec![toml::Value::Integer(1)]),
			);
			table
		});

		let result = schema.validate(&config);
		assert!(result.is_ok());
	}

	#[test]
	fn test_config_schema_validation_empty_network_ids() {
		let schema = AlloyDeliverySchema;
		let config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			table.insert("network_ids".to_string(), toml::Value::Array(vec![]));
			table
		});

		let result = schema.validate(&config);
		assert!(result.is_err());
		assert!(result
			.unwrap_err()
			.to_string()
			.contains("network_ids cannot be empty"));
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn test_create_http_delivery_success() {
		let config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			table.insert(
				"network_ids".to_string(),
				toml::Value::Array(vec![toml::Value::Integer(1)]),
			);
			table
		});

		let networks = create_test_networks();
		let default_key = SecretString::from(
			"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		);
		let network_keys = HashMap::new();

		let result = create_http_delivery(&config, &networks, &default_key, &network_keys);
		assert!(result.is_ok());
	}

	#[test]
	fn test_registry_name() {
		assert_eq!(
			<Registry as solver_types::ImplementationRegistry>::NAME,
			"evm_alloy"
		);
	}
}
