//! Execution strategy implementations for the solver service.
//!
//! This module provides concrete implementations of the ExecutionStrategy trait

use alloy_primitives::{hex, U256};
use async_trait::async_trait;
use solver_types::{
	with_0x_prefix, ConfigSchema, ExecutionContext, ExecutionDecision, ExecutionParams, Field,
	FieldType, Order, Schema,
};

use crate::{ExecutionStrategy, StrategyError};

/// Simple execution strategy that considers gas price limits.
///
/// This strategy executes orders when gas prices are below a configured
/// maximum, deferring execution when prices are too high.
pub struct SimpleStrategy {
	/// Maximum gas price the solver is willing to pay.
	max_gas_price: U256,
}

impl SimpleStrategy {
	/// Creates a new SimpleStrategy with the specified maximum gas price in gwei.
	pub fn new(max_gas_price_gwei: u64) -> Self {
		Self {
			max_gas_price: U256::from(max_gas_price_gwei) * U256::from(10u64.pow(9)),
		}
	}
}

/// Configuration schema for SimpleStrategy.
///
/// This schema validates the configuration for the simple execution strategy,
/// ensuring the optional maximum gas price parameter is valid if provided.
pub struct SimpleStrategySchema;

impl ConfigSchema for SimpleStrategySchema {
	fn validate(&self, config: &toml::Value) -> Result<(), solver_types::ValidationError> {
		let schema = Schema::new(
			// Required fields
			vec![],
			// Optional fields
			vec![Field::new(
				"max_gas_price_gwei",
				FieldType::Integer {
					min: Some(1),
					max: None,
				},
			)],
		);

		schema.validate(config)
	}
}

#[async_trait]
impl ExecutionStrategy for SimpleStrategy {
	fn config_schema(&self) -> Box<dyn ConfigSchema> {
		Box::new(SimpleStrategySchema)
	}

	async fn should_execute(&self, order: &Order, context: &ExecutionContext) -> ExecutionDecision {
		// Find the maximum gas price across all chains in the context
		let max_gas_price = context
			.chain_data
			.values()
			.map(|chain_data| chain_data.gas_price.parse::<U256>().unwrap_or(U256::ZERO))
			.max()
			.unwrap_or(U256::ZERO);

		// Check if any chain has gas price above our limit
		if max_gas_price > self.max_gas_price {
			return ExecutionDecision::Defer(std::time::Duration::from_secs(60));
		}

		// Parse order using OrderParsable trait for balance checking
		match order.parse_order_data() {
			Ok(parsed_order) => {
				// Get requested outputs for balance checking
				let outputs = parsed_order.parse_requested_outputs();

				// Check each output to ensure we have sufficient balance
				for output in &outputs {
					// Get the asset's InteropAddress directly
					let asset = output.asset.clone();

					// Get chain ID from the asset's InteropAddress
					let chain_id = asset.ethereum_chain_id().unwrap_or_else(|_| {
						tracing::warn!(
							order_id = %order.id,
							"Failed to get chain ID from asset, defaulting to 1"
						);
						1u64
					});

					// Get token address from the asset's InteropAddress
					let token_address = asset
						.ethereum_address()
						.map(|addr| hex::encode(addr.as_slice()))
						.unwrap_or_else(|e| {
							tracing::warn!(
								order_id = %order.id,
								error = %e,
								"Failed to get token address from asset"
							);
							String::new()
						});

					// Build the balance key (chain_id, Some(token_address))
					let balance_key = (chain_id, Some(token_address.clone()));

					// Check if we have the balance for this token
					if let Some(balance_str) = context.solver_balances.get(&balance_key) {
						// Parse balance and required amount
						let balance = balance_str.parse::<U256>().unwrap_or(U256::ZERO);
						let required = output.amount;

						if balance < required {
							tracing::warn!(
								order_id = %order.id,
								chain_id = chain_id,
								token = %with_0x_prefix(&token_address),
								balance = ?balance,
								required = ?required,
								"Insufficient token balance for order"
							);
							return ExecutionDecision::Skip(format!(
								"Insufficient balance on chain {}: have {} need {} of token {}",
								chain_id,
								balance,
								required,
								with_0x_prefix(&token_address)
							));
						}
					} else {
						// No balance info available for this token
						tracing::warn!(
							order_id = %order.id,
							chain_id = chain_id,
							token = %with_0x_prefix(&token_address),
							"No balance information available for token"
						);
						return ExecutionDecision::Skip(format!(
							"No balance information for token {} on chain {}",
							with_0x_prefix(&token_address),
							chain_id
						));
					}
				}
			},
			Err(e) => {
				// Failed to parse order data
				tracing::error!(
					order_id = %order.id,
					error = %e,
					"Failed to parse order data"
				);
				// Continue without balance checks if parsing fails
				tracing::debug!(
					order_id = %order.id,
					"Continuing without balance checks due to parsing failure"
				);
			},
		}

		// Use the maximum gas price for execution (could be made more sophisticated)
		ExecutionDecision::Execute(ExecutionParams {
			gas_price: max_gas_price,
			priority_fee: Some(U256::from(2) * U256::from(10u64.pow(9))), // 2 gwei priority
		})
	}
}

/// Factory function to create an execution strategy from configuration.
///
/// Configuration parameters:
/// - `max_gas_price_gwei`: Maximum gas price in gwei (default: 100)
pub fn create_strategy(config: &toml::Value) -> Result<Box<dyn ExecutionStrategy>, StrategyError> {
	// Validate configuration using the schema
	let schema = SimpleStrategySchema;
	schema
		.validate(config)
		.map_err(|e| StrategyError::InvalidConfig(e.to_string()))?;

	let max_gas_price = config
		.get("max_gas_price_gwei")
		.and_then(|v| v.as_integer())
		.unwrap_or(100) as u64;

	Ok(Box::new(SimpleStrategy::new(max_gas_price)))
}

/// Registry for the simple strategy implementation.
pub struct Registry;

impl solver_types::ImplementationRegistry for Registry {
	const NAME: &'static str = "simple";
	type Factory = crate::StrategyFactory;

	fn factory() -> Self::Factory {
		create_strategy
	}
}

impl crate::StrategyRegistry for Registry {}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::U256;
	use solver_types::{
		standards::eip7683::{Eip7683OrderData, GasLimitOverrides, MandateOutput},
		utils::tests::builders::OrderBuilder,
		ChainData, ExecutionContext, Order,
	};
	use std::collections::HashMap;

	fn create_test_order_data() -> Eip7683OrderData {
		Eip7683OrderData {
			user: "0x1234567890123456789012345678901234567890".to_string(),
			nonce: U256::from(1),
			origin_chain_id: U256::from(1),
			expires: (std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.unwrap()
				.as_secs() + 3600) as u32,
			fill_deadline: (std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.unwrap()
				.as_secs() + 1800) as u32,
			input_oracle: "0x0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A".to_string(),
			inputs: vec![[U256::from(1000), U256::from(100)]],
			order_id: [1u8; 32],
			gas_limit_overrides: GasLimitOverrides::default(),
			outputs: vec![MandateOutput {
				oracle: [0u8; 32],
				settler: [0u8; 32],
				chain_id: U256::from(137),
				token: {
					let mut token = [0u8; 32];
					// Put address in last 20 bytes (0x02 repeated)
					token[12..32].copy_from_slice(&[0x02; 20]);
					token
				},
				amount: U256::from(95),
				recipient: [3u8; 32],
				call: vec![],
				context: vec![],
			}],
			raw_order_data: None,
			signature: None,
			sponsor: None,
			lock_type: None,
		}
	}

	fn create_test_order(order_data: Eip7683OrderData) -> Order {
		OrderBuilder::new()
			.with_data(serde_json::to_value(&order_data).unwrap())
			.with_solver_address(solver_types::Address(vec![99u8; 20]))
			.with_quote_id(Some("test-quote".to_string()))
			.with_input_chain_ids(vec![1])
			.with_output_chain_ids(vec![137])
			.build()
	}

	fn create_test_context(
		gas_prices: Vec<(u64, &str)>,     // (chain_id, gas_price)
		balances: Vec<(u64, &str, &str)>, // (chain_id, token_address, balance)
	) -> ExecutionContext {
		let mut chain_data = HashMap::new();
		let mut solver_balances = HashMap::new();

		// Add chain data with gas prices
		for (chain_id, gas_price) in gas_prices {
			chain_data.insert(
				chain_id,
				ChainData {
					chain_id,
					gas_price: gas_price.to_string(),
					block_number: 1000000,
					timestamp: 1234567890,
				},
			);
		}

		// Add solver balances
		for (chain_id, token_address, balance) in balances {
			solver_balances.insert(
				(chain_id, Some(token_address.to_string())),
				balance.to_string(),
			);
		}

		ExecutionContext {
			chain_data,
			solver_balances,
			timestamp: 1234567890,
		}
	}

	#[test]
	fn test_simple_strategy_new() {
		let strategy = SimpleStrategy::new(50); // 50 gwei
		assert_eq!(
			strategy.max_gas_price,
			U256::from(50) * U256::from(10u64.pow(9))
		);
	}

	#[test]
	fn test_config_schema_validation() {
		let schema = SimpleStrategySchema;

		// Valid empty config
		let valid_config = toml::Value::Table(toml::map::Map::new());
		assert!(schema.validate(&valid_config).is_ok());

		// Valid config with max_gas_price_gwei
		let mut config_map = toml::map::Map::new();
		config_map.insert("max_gas_price_gwei".to_string(), toml::Value::Integer(100));
		let valid_config = toml::Value::Table(config_map);
		assert!(schema.validate(&valid_config).is_ok());

		// Invalid config with zero gas price
		let mut config_map = toml::map::Map::new();
		config_map.insert("max_gas_price_gwei".to_string(), toml::Value::Integer(0));
		let invalid_config = toml::Value::Table(config_map);
		assert!(schema.validate(&invalid_config).is_err());
	}

	#[tokio::test]
	async fn test_should_execute_gas_price_too_high() {
		let strategy = SimpleStrategy::new(50); // 50 gwei max
		let order_data = create_test_order_data();
		let order = create_test_order(order_data);

		// Create context with high gas price (100 gwei > 50 gwei limit)
		let context = create_test_context(
			vec![(1, "100000000000"), (137, "50000000000")], // 100 gwei, 50 gwei
			vec![(
				137,
				"0202020202020202020202020202020202020202020202020202020202020202",
				"1000",
			)],
		);

		let decision = strategy.should_execute(&order, &context).await;

		match decision {
			ExecutionDecision::Defer(duration) => {
				assert_eq!(duration, std::time::Duration::from_secs(60));
			},
			_ => panic!("Expected Defer decision for high gas price"),
		}
	}

	#[tokio::test]
	async fn test_should_execute_insufficient_balance() {
		let strategy = SimpleStrategy::new(100); // 100 gwei max
		let order_data = create_test_order_data();
		let order = create_test_order(order_data);

		// Create context with good gas price but insufficient balance
		let context = create_test_context(
			vec![(1, "50000000000"), (137, "30000000000")], // 50 gwei, 30 gwei
			vec![(
				137,
				"0202020202020202020202020202020202020202", // Use 40 chars (20 bytes)
				"50",
			)], // Only 50, need 95
		);

		let decision = strategy.should_execute(&order, &context).await;

		match decision {
			ExecutionDecision::Skip(reason) => {
				assert!(reason.contains("Insufficient balance"));
				assert!(reason.contains("chain 137"));
				assert!(reason.contains("have 50 need 95"));
			},
			_ => panic!("Expected Skip decision for insufficient balance"),
		}
	}

	#[tokio::test]
	async fn test_should_execute_no_balance_info() {
		let strategy = SimpleStrategy::new(100); // 100 gwei max
		let order_data = create_test_order_data();
		let order = create_test_order(order_data);

		// Create context with good gas price but no balance info
		let context = create_test_context(
			vec![(1, "50000000000"), (137, "30000000000")], // 50 gwei, 30 gwei
			vec![],                                         // No balance information
		);

		let decision = strategy.should_execute(&order, &context).await;

		match decision {
			ExecutionDecision::Skip(reason) => {
				assert!(reason.contains("No balance information"));
				assert!(reason.contains("chain 137"));
			},
			_ => panic!("Expected Skip decision for missing balance info"),
		}
	}

	#[tokio::test]
	async fn test_should_execute_success() {
		let strategy = SimpleStrategy::new(100); // 100 gwei max
		let order_data = create_test_order_data();
		let order = create_test_order(order_data);

		// Create context with good gas price and sufficient balance
		let context = create_test_context(
			vec![(1, "50000000000"), (137, "30000000000")], // 50 gwei, 30 gwei
			vec![(
				137,
				"0202020202020202020202020202020202020202", // Use 40 chars (20 bytes)
				"200",
			)], // 200 > 95 required
		);

		let decision = strategy.should_execute(&order, &context).await;

		match decision {
			ExecutionDecision::Execute(params) => {
				assert_eq!(params.gas_price, U256::from(50000000000u64)); // Max gas price from context
				assert_eq!(params.priority_fee, Some(U256::from(2000000000u64))); // 2 gwei
			},
			ExecutionDecision::Skip(reason) => {
				println!("Skip reason: {}", reason);
				panic!("Expected Execute but got Skip: {}", reason);
			},
			ExecutionDecision::Defer(duration) => {
				println!("Defer duration: {:?}", duration);
				panic!("Expected Execute but got Defer");
			},
		}
	}

	#[tokio::test]
	async fn test_should_execute_unknown_standard() {
		let strategy = SimpleStrategy::new(100); // 100 gwei max
		let mut order = create_test_order(create_test_order_data());
		order.standard = "unknown-standard".to_string();

		// Create context with good conditions
		let context = create_test_context(
			vec![(1, "50000000000")], // 50 gwei
			vec![],                   // No balance info needed for unknown standard
		);

		let decision = strategy.should_execute(&order, &context).await;

		// Should execute without balance checks for unknown standards
		match decision {
			ExecutionDecision::Execute(params) => {
				assert_eq!(params.gas_price, U256::from(50000000000u64));
				assert_eq!(params.priority_fee, Some(U256::from(2000000000u64)));
			},
			_ => panic!("Expected Execute decision for unknown standard"),
		}
	}

	#[tokio::test]
	async fn test_should_execute_multiple_outputs() {
		let strategy = SimpleStrategy::new(100); // 100 gwei max
		let mut order_data = create_test_order_data();

		// Add another output on different chain
		order_data.outputs.push(MandateOutput {
			oracle: [0u8; 32],
			settler: [0u8; 32],
			chain_id: U256::from(42), // Different chain
			token: [4u8; 32],         // Different token
			amount: U256::from(75),
			recipient: [5u8; 32],
			call: vec![],
			context: vec![],
		});

		let order = create_test_order(order_data);

		// Create context with balances for both outputs
		let context = create_test_context(
			vec![
				(1, "50000000000"),
				(137, "30000000000"),
				(42, "40000000000"),
			],
			vec![
				(137, "0202020202020202020202020202020202020202", "200"), // Last 20 bytes as address
				(42, "0404040404040404040404040404040404040404", "100"),  // Last 20 bytes as address
			],
		);

		let decision = strategy.should_execute(&order, &context).await;

		match decision {
			ExecutionDecision::Execute(params) => {
				assert_eq!(params.gas_price, U256::from(50000000000u64)); // Max gas price
			},
			ExecutionDecision::Skip(reason) => {
				println!("Skip reason: {}", reason);
				panic!("Expected Execute but got Skip: {}", reason);
			},
			ExecutionDecision::Defer(duration) => {
				println!("Defer duration: {:?}", duration);
				panic!("Expected Execute but got Defer");
			},
		}
	}

	#[tokio::test]
	async fn test_should_execute_multiple_outputs_one_insufficient() {
		let strategy = SimpleStrategy::new(100); // 100 gwei max
		let mut order_data = create_test_order_data();

		// Add another output on different chain
		order_data.outputs.push(MandateOutput {
			oracle: [0u8; 32],
			settler: [0u8; 32],
			chain_id: U256::from(42),
			token: [4u8; 32],
			amount: U256::from(75),
			recipient: [5u8; 32],
			call: vec![],
			context: vec![],
		});

		let order = create_test_order(order_data);

		// Create context with sufficient balance for first output, insufficient for second
		let context = create_test_context(
			vec![
				(1, "50000000000"),
				(137, "30000000000"),
				(42, "40000000000"),
			],
			vec![
				(137, "0202020202020202020202020202020202020202", "200"), // Sufficient
				(42, "0404040404040404040404040404040404040404", "50"),   // Insufficient (need 75)
			],
		);

		let decision = strategy.should_execute(&order, &context).await;

		match decision {
			ExecutionDecision::Skip(reason) => {
				assert!(reason.contains("Insufficient balance"));
				assert!(reason.contains("chain 42"));
			},
			_ => panic!("Expected Skip decision when one output has insufficient balance"),
		}
	}

	#[test]
	fn test_create_strategy_factory() {
		// Test with default config
		let config = toml::Value::Table(toml::map::Map::new());
		let result = create_strategy(&config);
		assert!(result.is_ok());

		// Test with custom max gas price
		let mut config_map = toml::map::Map::new();
		config_map.insert("max_gas_price_gwei".to_string(), toml::Value::Integer(75));
		let config = toml::Value::Table(config_map);
		let result = create_strategy(&config);
		assert!(result.is_ok());

		// Test with invalid config
		let mut config_map = toml::map::Map::new();
		config_map.insert("max_gas_price_gwei".to_string(), toml::Value::Integer(0));
		let config = toml::Value::Table(config_map);
		let result = create_strategy(&config);
		assert!(result.is_err());
	}
}
