//! Direct settlement implementation for testing purposes.
//!
//! This module provides a basic implementation of the SettlementInterface trait
//! intended for testing and development. It handles fill validation and claim
//! readiness checks using simple transaction receipt verification without
//! complex attestation mechanisms.

use crate::{utils::parse_oracle_config, OracleConfig, SettlementError, SettlementInterface};
use alloy_primitives::{hex, FixedBytes};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types::BlockTransactionsKind;
use alloy_transport_http::Http;
use async_trait::async_trait;
use solver_types::{
	with_0x_prefix, ConfigSchema, Eip7683OrderData, Field, FieldType, FillProof, NetworksConfig,
	Order, Schema, TransactionHash,
};
use std::collections::HashMap;

/// Direct settlement implementation.
///
/// This implementation validates fills by checking transaction receipts
/// and manages dispute periods before allowing claims.
pub struct DirectSettlement {
	/// RPC providers for each supported network.
	providers: HashMap<u64, RootProvider<Http<reqwest::Client>>>,
	/// Oracle configuration including addresses and routes
	oracle_config: OracleConfig,
	/// Dispute period duration in seconds.
	dispute_period_seconds: u64,
}

impl DirectSettlement {
	/// Creates a new DirectSettlement instance.
	///
	/// Configures settlement validation with oracle configuration
	/// and dispute period.
	pub async fn new(
		networks: &NetworksConfig,
		oracle_config: OracleConfig,
		dispute_period_seconds: u64,
	) -> Result<Self, SettlementError> {
		// Create RPC providers for each network that has oracles configured
		let mut providers = HashMap::new();

		// Collect unique network IDs from input and output oracles
		let mut all_network_ids: Vec<u64> = oracle_config
			.input_oracles
			.keys()
			.chain(oracle_config.output_oracles.keys())
			.copied()
			.collect();
		all_network_ids.sort_unstable();
		all_network_ids.dedup();

		for network_id in all_network_ids {
			let network = networks.get(&network_id).ok_or_else(|| {
				SettlementError::ValidationFailed(format!(
					"Network {} not found in configuration",
					network_id
				))
			})?;

			let http_url = network.get_http_url().ok_or_else(|| {
				SettlementError::ValidationFailed(format!(
					"No HTTP RPC URL configured for network {}",
					network_id
				))
			})?;
			let provider = RootProvider::new_http(http_url.parse().map_err(|e| {
				SettlementError::ValidationFailed(format!(
					"Invalid RPC URL for network {}: {}",
					network_id, e
				))
			})?);

			providers.insert(network_id, provider);
		}

		Ok(Self {
			providers,
			oracle_config,
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
				Field::new(
					"dispute_period_seconds",
					FieldType::Integer {
						min: Some(0),
						max: Some(86400),
					},
				),
				Field::new(
					"oracles",
					FieldType::Table(Schema::new(
						vec![
							Field::new("input", FieldType::Table(Schema::new(vec![], vec![]))),
							Field::new("output", FieldType::Table(Schema::new(vec![], vec![]))),
						],
						vec![],
					)),
				),
				Field::new("routes", FieldType::Table(Schema::new(vec![], vec![]))),
			],
			// Optional fields
			vec![Field::new("oracle_selection_strategy", FieldType::String)],
		);

		schema.validate(config)
	}
}

#[async_trait]
impl SettlementInterface for DirectSettlement {
	fn oracle_config(&self) -> &OracleConfig {
		&self.oracle_config
	}

	fn config_schema(&self) -> Box<dyn ConfigSchema> {
		Box::new(DirectSettlementSchema)
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
		// Get the origin chain ID from the order
		// Note: For now we assume all inputs are on the same chain
		let origin_chain_id = *order.input_chain_ids.first().ok_or_else(|| {
			SettlementError::ValidationFailed("No input chains in order".to_string())
		})?;
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

		// Get the oracle address for this chain using the selection strategy
		let oracle_addresses = self.get_input_oracles(origin_chain_id);
		if oracle_addresses.is_empty() {
			return Err(SettlementError::ValidationFailed(format!(
				"No input oracle configured for chain {}",
				origin_chain_id
			)));
		}

		// Use selection strategy with order nonce as context for deterministic selection
		let selection_context = order_data.nonce.to::<u64>();
		let oracle_address = self
			.select_oracle(&oracle_addresses, Some(selection_context))
			.ok_or_else(|| {
				SettlementError::ValidationFailed(format!(
					"Failed to select oracle for chain {}",
					origin_chain_id
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
			oracle_address: with_0x_prefix(&hex::encode(&oracle_address.0)),
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

	// Parse oracle configuration using common utilities
	let oracle_config = parse_oracle_config(config)?;

	let dispute_period_seconds = config
		.get("dispute_period_seconds")
		.and_then(|v| v.as_integer())
		.unwrap_or(300) as u64; // 5 minutes default

	// Create settlement service synchronously
	let settlement = tokio::task::block_in_place(|| {
		tokio::runtime::Handle::current().block_on(async {
			DirectSettlement::new(networks, oracle_config, dispute_period_seconds).await
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
