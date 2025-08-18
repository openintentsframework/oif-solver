//! Direct settlement implementation for testing purposes.
//!
//! This module provides a basic implementation of the SettlementInterface trait
//! intended for testing and development. It handles fill validation and claim
//! readiness checks using simple transaction receipt verification without
//! complex attestation mechanisms.

use crate::{SettlementError, SettlementInterface};
use alloy_primitives::{hex, Address as AlloyAddress, FixedBytes};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types::BlockTransactionsKind;
use alloy_transport_http::Http;
use async_trait::async_trait;
use solver_types::{
	without_0x_prefix, ConfigSchema, Eip7683OrderData, Field, FieldType, FillProof, NetworksConfig,
	Order, Schema, TransactionHash,
};
use std::collections::HashMap;

/// Direct settlement implementation.
///
/// This implementation validates fills by checking transaction receipts
/// and manages dispute periods before allowing claims.
pub struct DirectSettlement {
	/// The order type this implementation handles
	order: String,
	/// Supported network IDs
	network_ids: Vec<u64>,
	/// RPC providers for each supported network.
	providers: HashMap<u64, RootProvider<Http<reqwest::Client>>>,
	/// Oracle addresses for each network (network_id -> oracle_address).
	oracle_addresses: HashMap<u64, String>,
	/// Dispute period duration in seconds.
	dispute_period_seconds: u64,
}

impl DirectSettlement {
	/// Creates a new DirectSettlement instance.
	///
	/// Configures settlement validation with multiple networks, oracle addresses,
	/// and dispute period.
	pub async fn new(
		order: String,
		network_ids: Vec<u64>,
		networks: &NetworksConfig,
		oracle_addresses: HashMap<u64, String>,
		dispute_period_seconds: u64,
	) -> Result<Self, SettlementError> {
		// Create RPC providers for each supported network
		let mut providers = HashMap::new();

		for network_id in &network_ids {
			let network = networks.get(network_id).ok_or_else(|| {
				SettlementError::ValidationFailed(format!(
					"Network {} not found in configuration",
					network_id
				))
			})?;

			let provider = RootProvider::new_http(network.rpc_url.parse().map_err(|e| {
				SettlementError::ValidationFailed(format!(
					"Invalid RPC URL for network {}: {}",
					network_id, e
				))
			})?);

			providers.insert(*network_id, provider);
		}

		// Validate oracle addresses
		let mut validated_oracle_addresses = HashMap::new();
		for (network_id, oracle_address) in oracle_addresses {
			let oracle = oracle_address.parse::<AlloyAddress>().map_err(|e| {
				SettlementError::ValidationFailed(format!(
					"Invalid oracle address for network {}: {}",
					network_id, e
				))
			})?;
			validated_oracle_addresses.insert(network_id, oracle.to_string());
		}

		Ok(Self {
			order,
			network_ids: network_ids.clone(),
			providers,
			oracle_addresses: validated_oracle_addresses,
			dispute_period_seconds,
		})
	}
}

/// Configuration schema for DirectSettlement.
pub struct DirectSettlementSchema;

impl DirectSettlementSchema {
	/// Static validation method for use before instance creation
	pub fn validate_config(config: &toml::Value) -> Result<(), solver_types::ValidationError> {
		let instance = Self;
		instance.validate(config)
	}
}

impl ConfigSchema for DirectSettlementSchema {
	fn validate(&self, config: &toml::Value) -> Result<(), solver_types::ValidationError> {
		let schema = Schema::new(
			// Required fields
			vec![
				Field::new("order", FieldType::String),
				Field::new(
					"network_ids",
					FieldType::Array(Box::new(FieldType::Integer {
						min: Some(1),
						max: None,
					})),
				),
				Field::new(
					"oracle_addresses",
					FieldType::Table(Schema::new(
						vec![], // No required fields - network IDs are dynamic
						vec![], // No optional fields - all entries should be valid addresses
					)),
				)
				.with_validator(|value| {
					// Validate that all values in the table are valid Ethereum addresses
					if let Some(table) = value.as_table() {
						for (network_id, address_value) in table {
							if let Some(addr) = address_value.as_str() {
								if addr.len() != 42 || !addr.starts_with("0x") {
									return Err(format!(
										"oracle_addresses.{} must be a valid Ethereum address",
										network_id
									));
								}
							} else {
								return Err(format!(
									"oracle_addresses.{} must be a string",
									network_id
								));
							}
						}
						Ok(())
					} else {
						Err("oracle_addresses must be a table".to_string())
					}
				}),
			],
			// Optional fields
			vec![Field::new(
				"dispute_period_seconds",
				FieldType::Integer {
					min: Some(0),
					max: Some(86400),
				},
			)],
		);

		schema.validate(config)
	}
}

#[async_trait]
impl SettlementInterface for DirectSettlement {
	fn supported_order(&self) -> &str {
		&self.order
	}

	fn supported_networks(&self) -> &[u64] {
		&self.network_ids
	}

	fn config_schema(&self) -> Box<dyn ConfigSchema> {
		Box::new(DirectSettlementSchema)
	}

	/// Returns the oracle address configured for a specific chain.
	///
	/// This implementation stores oracle addresses per chain in its configuration.
	/// The addresses are stored as hex strings and converted to the Address type on demand.
	///
	/// # Arguments
	/// * `chain_id` - The chain ID to get the oracle address for
	///
	/// # Returns
	/// * `Some(Address)` if an oracle is configured for this chain and the address is valid
	/// * `None` if no oracle is configured or the address format is invalid
	fn get_oracle_address(&self, chain_id: u64) -> Option<solver_types::Address> {
		self.oracle_addresses.get(&chain_id).and_then(|addr_str| {
			let hex_str = without_0x_prefix(addr_str);
			hex::decode(hex_str)
				.ok()
				.filter(|bytes| bytes.len() == 20)
				.map(solver_types::Address)
		})
	}

	/// Gets attestation data for a filled order and generates a fill proof.
	///
	/// Since the transaction is already confirmed by the delivery service,
	/// this method just extracts necessary data for claim generation.
	async fn get_attestation(
		&self,
		order: &Order,
		tx_hash: &TransactionHash,
	) -> Result<FillProof, SettlementError> {
		// Get the destination chain ID from the order
		// Note: For now we assume all outputs are on the same chain
		let destination_chain_id = *order.output_chain_ids.first().ok_or_else(|| {
			SettlementError::ValidationFailed("No output chains in order".to_string())
		})?;

		// Parse order data for other fields we need
		let order_data: Eip7683OrderData =
			serde_json::from_value(order.data.clone()).map_err(|e| {
				SettlementError::ValidationFailed(format!("Failed to parse order data: {}", e))
			})?;

		// Get the appropriate provider for this chain
		let provider = self.providers.get(&destination_chain_id).ok_or_else(|| {
			SettlementError::ValidationFailed(format!(
				"No provider configured for chain {}",
				destination_chain_id
			))
		})?;

		// Get the oracle address for this chain
		let oracle_address = self
			.oracle_addresses
			.get(&destination_chain_id)
			.ok_or_else(|| {
				SettlementError::ValidationFailed(format!(
					"No oracle address configured for chain {}",
					destination_chain_id
				))
			})?;

		// Convert tx hash
		let hash = FixedBytes::<32>::from_slice(&tx_hash.0);

		// Get transaction receipt
		let receipt = provider
			.get_transaction_receipt(hash)
			.await
			.map_err(|e| {
				SettlementError::ValidationFailed(format!("Failed to get receipt: {}", e))
			})?
			.ok_or_else(|| {
				SettlementError::ValidationFailed("Transaction not found".to_string())
			})?;

		// Check if transaction was successful
		if !receipt.status() {
			return Err(SettlementError::ValidationFailed(
				"Transaction failed".to_string(),
			));
		}

		let tx_block = receipt.block_number.unwrap_or(0);

		// Get the block timestamp
		let block = provider
			.get_block_by_number(
				alloy_rpc_types::BlockNumberOrTag::Number(tx_block),
				BlockTransactionsKind::Hashes,
			)
			.await
			.map_err(|e| {
				SettlementError::ValidationFailed(format!("Failed to get block: {}", e))
			})?;

		let block_timestamp = block
			.ok_or_else(|| SettlementError::ValidationFailed("Block not found".to_string()))?
			.header
			.timestamp;

		Ok(FillProof {
			tx_hash: tx_hash.clone(),
			block_number: tx_block,
			oracle_address: oracle_address.clone(),
			attestation_data: Some(order_data.order_id.to_vec()),
			filled_timestamp: block_timestamp,
		})
	}

	/// Checks if an order is ready to be claimed.
	///
	/// Verifies that the dispute period has passed and all claim
	/// requirements are met.
	async fn can_claim(&self, order: &Order, fill_proof: &FillProof) -> bool {
		// Get the destination chain ID from the order
		let destination_chain_id = match order.output_chain_ids.first() {
			Some(&chain_id) => chain_id,
			None => return false,
		};

		// TODO: Parse order data if needed for dispute deadline check
		// let order_data: Eip7683OrderData = match serde_json::from_value(order.data.clone()) {
		//     Ok(data) => data,
		//     Err(_) => return false,
		// };

		// Get the appropriate provider for this chain
		let provider = match self.providers.get(&destination_chain_id) {
			Some(p) => p,
			None => return false,
		};

		// Get current block to check timestamp
		let current_block = match provider.get_block_number().await {
			Ok(block_num) => match provider
				.get_block_by_number(block_num.into(), BlockTransactionsKind::Hashes)
				.await
			{
				Ok(Some(block)) => block,
				Ok(None) => return false,
				Err(_) => return false,
			},
			Err(_) => return false,
		};

		// Check if dispute period has passed using timestamps
		let current_timestamp = current_block.header.timestamp;
		let dispute_end_timestamp = fill_proof.filled_timestamp + self.dispute_period_seconds;

		if current_timestamp < dispute_end_timestamp {
			return false; // Still in dispute period
		}

		// TODO check:
		// 1. Oracle attestation exists
		// 2. No disputes were raised
		// 3. Claim window hasn't expired
		// 4. Rewards haven't been claimed yet

		// For now, return true if dispute period passed
		true
	}
}

/// Factory function to create a settlement provider from configuration.
///
/// Required configuration parameters:
/// - `order`: The order type this implementation handles (e.g., "eip7683")
/// - `network_ids`: Array of network IDs to monitor
/// - `oracle_addresses`: Table mapping network_id -> oracle address
///
/// Optional configuration parameters:
/// - `dispute_period_seconds`: Dispute period duration (default: 300)
pub fn create_settlement(
	config: &toml::Value,
	networks: &NetworksConfig,
) -> Result<Box<dyn SettlementInterface>, SettlementError> {
	// Validate configuration first
	DirectSettlementSchema::validate_config(config)
		.map_err(|e| SettlementError::ValidationFailed(format!("Invalid configuration: {}", e)))?;

	// Get order type
	let order_standard = config
		.get("order")
		.and_then(|v| v.as_str())
		.ok_or_else(|| SettlementError::ValidationFailed("order is required".to_string()))?
		.to_string();

	// Get network IDs
	let network_ids = config
		.get("network_ids")
		.and_then(|v| v.as_array())
		.ok_or_else(|| SettlementError::ValidationFailed("network_ids is required".to_string()))?
		.iter()
		.filter_map(|v| v.as_integer().map(|i| i as u64))
		.collect::<Vec<_>>();

	if network_ids.is_empty() {
		return Err(SettlementError::ValidationFailed(
			"network_ids cannot be empty".to_string(),
		));
	}

	// Get oracle addresses table
	let addresses_table = config
		.get("oracle_addresses")
		.and_then(|v| v.as_table())
		.ok_or_else(|| {
			SettlementError::ValidationFailed("oracle_addresses is required".to_string())
		})?;

	// Build oracle addresses map
	let mut oracle_addresses = HashMap::new();
	for network_id in &network_ids {
		let network_id_str = network_id.to_string();
		let address = addresses_table
			.get(&network_id_str)
			.and_then(|v| v.as_str())
			.ok_or_else(|| {
				SettlementError::ValidationFailed(format!(
					"oracle_addresses missing entry for network {}",
					network_id
				))
			})?;
		oracle_addresses.insert(*network_id, address.to_string());
	}

	let dispute_period_seconds = config
		.get("dispute_period_seconds")
		.and_then(|v| v.as_integer())
		.unwrap_or(300) as u64; // 5 minutes default

	// Create settlement service synchronously
	let settlement = tokio::task::block_in_place(|| {
		tokio::runtime::Handle::current().block_on(async {
			DirectSettlement::new(
				order_standard,
				network_ids,
				networks,
				oracle_addresses,
				dispute_period_seconds,
			)
			.await
		})
	})?;

	Ok(Box::new(settlement))
}

/// Registry for the direct settlement implementation.
pub struct Registry;

impl solver_types::ImplementationRegistry for Registry {
	const NAME: &'static str = "direct";
	type Factory = crate::SettlementFactory;

	fn factory() -> Self::Factory {
		create_settlement
	}
}

impl crate::SettlementRegistry for Registry {}
