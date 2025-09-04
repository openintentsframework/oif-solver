//! Direct settlement implementation for testing purposes.
//!
//! This module provides a basic implementation of the SettlementInterface trait
//! intended for testing and development. It handles fill validation and claim
//! readiness checks using simple transaction receipt verification without
//! complex attestation mechanisms.

use crate::{utils::parse_oracle_config, OracleConfig, SettlementError, SettlementInterface};
use alloy_primitives::{hex, FixedBytes, U256};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types::BlockTransactionsKind;
use alloy_transport_http::Http;
use async_trait::async_trait;
use solver_types::{
	with_0x_prefix, ConfigSchema, Eip7683OrderData, Field, FieldType, FillProof, NetworksConfig,
	Order, Schema, Transaction, TransactionHash, TransactionReceipt,
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
	/// Retrieves transaction receipt and block data from the destination chain
	/// to construct proof of fill execution.
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

	/// Generates a PostFill transaction for oracle interaction.
	///
	/// Creates a transaction that would interact with the output oracle
	/// on the destination chain after fill execution.
	async fn generate_post_fill_transaction(
		&self,
		order: &Order,
		_fill_receipt: &TransactionReceipt,
	) -> Result<Option<Transaction>, SettlementError> {
		// Get the output oracle for PostFill (happens on destination chain)
		let dest_chain = *order
			.output_chain_ids
			.first()
			.ok_or_else(|| SettlementError::ValidationFailed("No output chains in order".into()))?;

		let oracle_addresses = self.get_output_oracles(dest_chain);
		if oracle_addresses.is_empty() {
			// No oracle configured, no PostFill needed
			return Ok(None);
		}

		// For testing: send to solver's own address (from the order)
		// This simulates a PostFill oracle interaction that modifies state
		// Realistically, this would call a real oracle method
		let data = Vec::new(); // Empty calldata for simple ETH transfer

		Ok(Some(Transaction {
			to: Some(order.solver_address.clone()),
			data,
			value: U256::ZERO,
			chain_id: dest_chain,
			nonce: None,
			gas_limit: Some(21000),
			gas_price: None,
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
		}))
	}

	/// Generates a PreClaim transaction for oracle interaction.
	///
	/// Creates a transaction that would interact with the input oracle
	/// on the origin chain before claiming rewards.
	async fn generate_pre_claim_transaction(
		&self,
		order: &Order,
		_fill_proof: &FillProof,
	) -> Result<Option<Transaction>, SettlementError> {
		// Get the input oracle for PreClaim (happens on origin chain)
		let origin_chain = *order
			.input_chain_ids
			.first()
			.ok_or_else(|| SettlementError::ValidationFailed("No input chains in order".into()))?;

		let oracle_addresses = self.get_input_oracles(origin_chain);
		if oracle_addresses.is_empty() {
			// No oracle configured, no PreClaim needed
			return Ok(None);
		}

		// For testing: send to solver's own address (from the order)
		// This simulates a PreClaim oracle interaction that modifies state
		// Realistically, this would call a real oracle method like submitProof
		let data = Vec::new(); // Empty calldata for simple ETH transfer

		Ok(Some(Transaction {
			to: Some(order.solver_address.clone()),
			data,
			value: U256::ZERO,
			chain_id: origin_chain,
			nonce: None,
			gas_limit: Some(21000),
			gas_price: None,
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
		}))
	}
}

/// Factory function to create a settlement provider from configuration.
///
/// Required configuration parameters:
/// - `oracles`: Table with input and output oracle configurations
/// - `routes`: Table mapping oracle routes for different chains
/// - `dispute_period_seconds`: Dispute period duration (0-86400 seconds)
///
/// Optional configuration parameters:
/// - `oracle_selection_strategy`: Strategy for oracle selection (default: round-robin)
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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{OracleSelectionStrategy, SettlementInterface};
	use solver_types::{
		parse_address,
		utils::tests::builders::{NetworkConfigBuilder, NetworksConfigBuilder},
		ImplementationRegistry,
	};
	use std::collections::HashMap;

	fn create_test_networks() -> NetworksConfig {
		NetworksConfigBuilder::new()
			.add_network(1, NetworkConfigBuilder::new().build())
			.add_network(2, NetworkConfigBuilder::new().build())
			.build()
	}

	// Fix the create_test_oracle_config function
	fn create_test_oracle_config() -> OracleConfig {
		let mut input_oracles = HashMap::new();
		input_oracles.insert(
			1,
			vec![parse_address("0x1111111111111111111111111111111111111111").unwrap()],
		);

		let mut output_oracles = HashMap::new();
		output_oracles.insert(
			2,
			vec![parse_address("0x2222222222222222222222222222222222222222").unwrap()],
		);

		// Fix: routes should map u64 -> Vec<u64>, not (u64, u64) -> Address
		let mut routes = HashMap::new();
		routes.insert(1, vec![2]); // Network 1 can route to network 2

		OracleConfig {
			input_oracles,
			output_oracles,
			routes,
			selection_strategy: OracleSelectionStrategy::RoundRobin,
		}
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn test_direct_settlement_new_success() {
		let networks = create_test_networks();
		let oracle_config = create_test_oracle_config();

		let result = DirectSettlement::new(&networks, oracle_config, 300).await;
		assert!(result.is_ok());

		let settlement = result.unwrap();
		assert_eq!(settlement.dispute_period_seconds, 300);
		assert!(settlement.providers.contains_key(&1));
		assert!(settlement.providers.contains_key(&2));
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn test_direct_settlement_new_missing_network() {
		let mut networks = create_test_networks();
		networks.remove(&1); // Remove network 1
		let oracle_config = create_test_oracle_config();

		let result = DirectSettlement::new(&networks, oracle_config, 300).await;
		assert!(matches!(result, Err(SettlementError::ValidationFailed(_))));
		if let Err(SettlementError::ValidationFailed(msg)) = result {
			assert!(msg.contains("Network 1 not found"));
		}
	}

	#[test]
	fn test_config_schema_validation_valid() {
		let schema = DirectSettlementSchema;
		let config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			table.insert(
				"dispute_period_seconds".to_string(),
				toml::Value::Integer(300),
			);
			table.insert(
				"oracles".to_string(),
				toml::Value::Table({
					let mut oracles = toml::map::Map::new();
					oracles.insert(
						"input".to_string(),
						toml::Value::Table(toml::map::Map::new()),
					);
					oracles.insert(
						"output".to_string(),
						toml::Value::Table(toml::map::Map::new()),
					);
					oracles
				}),
			);
			table.insert(
				"routes".to_string(),
				toml::Value::Table(toml::map::Map::new()),
			);
			table
		});

		let result = schema.validate(&config);
		assert!(result.is_ok());
	}

	#[test]
	fn test_config_schema_validation_missing_required_field() {
		let schema = DirectSettlementSchema;
		let config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			// Missing dispute_period_seconds
			table.insert(
				"oracles".to_string(),
				toml::Value::Table({
					let mut oracles = toml::map::Map::new();
					oracles.insert(
						"input".to_string(),
						toml::Value::Table(toml::map::Map::new()),
					);
					oracles.insert(
						"output".to_string(),
						toml::Value::Table(toml::map::Map::new()),
					);
					oracles
				}),
			);
			table.insert(
				"routes".to_string(),
				toml::Value::Table(toml::map::Map::new()),
			);
			table
		});

		let result = schema.validate(&config);
		assert!(result.is_err());
	}

	#[test]
	fn test_config_schema_validation_invalid_dispute_period() {
		let schema = DirectSettlementSchema;
		let config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			table.insert(
				"dispute_period_seconds".to_string(),
				toml::Value::Integer(100000), // Too large
			);
			table.insert(
				"oracles".to_string(),
				toml::Value::Table({
					let mut oracles = toml::map::Map::new();
					oracles.insert(
						"input".to_string(),
						toml::Value::Table(toml::map::Map::new()),
					);
					oracles.insert(
						"output".to_string(),
						toml::Value::Table(toml::map::Map::new()),
					);
					oracles
				}),
			);
			table.insert(
				"routes".to_string(),
				toml::Value::Table(toml::map::Map::new()),
			);
			table
		});

		let result = schema.validate(&config);
		assert!(result.is_err());
	}

	#[test]
	fn test_static_config_validation() {
		let config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			table.insert(
				"dispute_period_seconds".to_string(),
				toml::Value::Integer(300),
			);
			table.insert(
				"oracles".to_string(),
				toml::Value::Table({
					let mut oracles = toml::map::Map::new();
					oracles.insert(
						"input".to_string(),
						toml::Value::Table(toml::map::Map::new()),
					);
					oracles.insert(
						"output".to_string(),
						toml::Value::Table(toml::map::Map::new()),
					);
					oracles
				}),
			);
			table.insert(
				"routes".to_string(),
				toml::Value::Table(toml::map::Map::new()),
			);
			table
		});

		let result = DirectSettlementSchema::validate_config(&config);
		assert!(result.is_ok());
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn test_create_settlement_success() {
		let config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			table.insert(
				"dispute_period_seconds".to_string(),
				toml::Value::Integer(300),
			);
			table.insert(
				"oracles".to_string(),
				toml::Value::Table({
					let mut oracles = toml::map::Map::new();
					oracles.insert(
						"input".to_string(),
						toml::Value::Table({
							let mut input = toml::map::Map::new();
							input.insert(
								"1".to_string(),
								toml::Value::Array(vec![toml::Value::String(
									"0x1111111111111111111111111111111111111111".to_string(),
								)]),
							);
							input
						}),
					);
					oracles.insert(
						"output".to_string(),
						toml::Value::Table({
							let mut output = toml::map::Map::new();
							output.insert(
								"2".to_string(),
								toml::Value::Array(vec![toml::Value::String(
									"0x2222222222222222222222222222222222222222".to_string(),
								)]),
							);
							output
						}),
					);
					oracles
				}),
			);
			table.insert(
				"routes".to_string(),
				toml::Value::Table({
					let mut routes = toml::map::Map::new();
					// Fix: Use correct routes format - chain_id -> [destination_chain_ids]
					routes.insert(
						"1".to_string(),
						toml::Value::Array(vec![toml::Value::Integer(2)]),
					);
					routes
				}),
			);
			table
		});

		let networks = create_test_networks();
		let result = create_settlement(&config, &networks);
		assert!(result.is_ok());
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn test_create_settlement_invalid_config() {
		let config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			// Missing required fields
			table.insert(
				"dispute_period_seconds".to_string(),
				toml::Value::Integer(300),
			);
			table
		});

		let networks = create_test_networks();
		let result = create_settlement(&config, &networks);
		assert!(matches!(result, Err(SettlementError::ValidationFailed(_))));
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn test_settlement_interface_oracle_config() {
		let networks = create_test_networks();
		let oracle_config = create_test_oracle_config();

		let settlement = DirectSettlement::new(&networks, oracle_config.clone(), 300)
			.await
			.unwrap();

		let returned_config = settlement.oracle_config();
		assert_eq!(
			returned_config.input_oracles.len(),
			oracle_config.input_oracles.len()
		);
		assert_eq!(
			returned_config.output_oracles.len(),
			oracle_config.output_oracles.len()
		);
		assert_eq!(returned_config.routes.len(), oracle_config.routes.len());
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn test_settlement_interface_config_schema() {
		let networks = create_test_networks();
		let oracle_config = create_test_oracle_config();

		let settlement = DirectSettlement::new(&networks, oracle_config, 300)
			.await
			.unwrap();

		let schema = settlement.config_schema();

		// Test valid config
		let valid_config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			table.insert(
				"dispute_period_seconds".to_string(),
				toml::Value::Integer(300),
			);
			table.insert(
				"oracles".to_string(),
				toml::Value::Table({
					let mut oracles = toml::map::Map::new();
					oracles.insert(
						"input".to_string(),
						toml::Value::Table(toml::map::Map::new()),
					);
					oracles.insert(
						"output".to_string(),
						toml::Value::Table(toml::map::Map::new()),
					);
					oracles
				}),
			);
			table.insert(
				"routes".to_string(),
				toml::Value::Table(toml::map::Map::new()),
			);
			table
		});
		assert!(schema.validate(&valid_config).is_ok());
	}

	#[test]
	fn test_registry_name() {
		assert_eq!(
			<Registry as solver_types::ImplementationRegistry>::NAME,
			"direct"
		);
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn test_registry_factory() {
		let factory = Registry::factory();

		// Test that factory function exists and has correct type
		let config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			table.insert(
				"dispute_period_seconds".to_string(),
				toml::Value::Integer(300),
			);
			table.insert(
				"oracles".to_string(),
				toml::Value::Table({
					let mut oracles = toml::map::Map::new();
					oracles.insert(
						"input".to_string(),
						toml::Value::Table({
							let mut input = toml::map::Map::new();
							input.insert(
								"1".to_string(),
								toml::Value::Array(vec![toml::Value::String(
									"0x1111111111111111111111111111111111111111".to_string(),
								)]),
							);
							input
						}),
					);
					oracles.insert(
						"output".to_string(),
						toml::Value::Table({
							let mut output = toml::map::Map::new();
							output.insert(
								"2".to_string(),
								toml::Value::Array(vec![toml::Value::String(
									"0x2222222222222222222222222222222222222222".to_string(),
								)]),
							);
							output
						}),
					);
					oracles
				}),
			);
			table.insert(
				"routes".to_string(),
				toml::Value::Table({
					let mut routes = toml::map::Map::new();
					// Fix: routes expects chain_id -> [destination_chain_ids]
					routes.insert(
						"1".to_string(),
						toml::Value::Array(vec![toml::Value::Integer(2)]),
					);
					routes
				}),
			);
			table
		});

		let networks = create_test_networks();
		let result = factory(&config, &networks);
		assert!(result.is_ok());
	}

	// Integration-style tests for error cases
	#[tokio::test(flavor = "multi_thread")]
	async fn test_direct_settlement_no_http_url() {
		let mut networks = create_test_networks();
		// Remove HTTP URL from network 1
		networks.get_mut(&1).unwrap().rpc_urls.clear();
		let oracle_config = create_test_oracle_config();

		let result = DirectSettlement::new(&networks, oracle_config, 300).await;
		assert!(matches!(result, Err(SettlementError::ValidationFailed(_))));
		if let Err(SettlementError::ValidationFailed(msg)) = result {
			assert!(msg.contains("No HTTP RPC URL configured"));
		}
	}

	#[test]
	fn test_config_with_optional_fields() {
		let schema = DirectSettlementSchema;
		let config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			table.insert(
				"dispute_period_seconds".to_string(),
				toml::Value::Integer(300),
			);
			table.insert(
				"oracles".to_string(),
				toml::Value::Table({
					let mut oracles = toml::map::Map::new();
					oracles.insert(
						"input".to_string(),
						toml::Value::Table(toml::map::Map::new()),
					);
					oracles.insert(
						"output".to_string(),
						toml::Value::Table(toml::map::Map::new()),
					);
					oracles
				}),
			);
			table.insert(
				"routes".to_string(),
				toml::Value::Table(toml::map::Map::new()),
			);
			table.insert(
				"oracle_selection_strategy".to_string(),
				toml::Value::String("round_robin".to_string()),
			);
			table
		});

		let result = schema.validate(&config);
		assert!(result.is_ok());
	}
}
