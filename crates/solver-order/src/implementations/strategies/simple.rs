//! Execution strategy implementations for the solver service.
//!
//! This module provides concrete implementations of the ExecutionStrategy trait

use alloy_primitives::U256;
use async_trait::async_trait;
use solver_config::GasConfig;
use solver_types::{
	bytes32_to_address, with_0x_prefix, ConfigSchema, Eip7683OrderData, ExecutionContext,
	ExecutionDecision, ExecutionParams, Field, FieldType, Order, Schema,
};

use crate::{ExecutionStrategy, StrategyError};

/// Simple execution strategy that considers gas price limits and cost estimation.
///
/// This strategy executes orders when gas prices are below a configured
/// maximum and the estimated execution cost is acceptable, deferring execution when prices are too high
/// or costs exceed configured thresholds.
pub struct SimpleStrategy {
	/// Maximum gas price the solver is willing to pay.
	max_gas_price: U256,
	/// Maximum acceptable execution cost in wei (None means no cost limit)
	max_execution_cost: Option<U256>,
	/// Gas configuration for customizable gas estimates
	gas_config: Option<GasConfig>,
}

impl SimpleStrategy {
	/// Creates a new SimpleStrategy with the specified maximum gas price, optional cost limit, and gas config.
	pub fn new(
		max_gas_price_gwei: u64,
		max_execution_cost_gwei: Option<u64>,
		gas_config: Option<GasConfig>,
	) -> Self {
		Self {
			max_gas_price: U256::from(max_gas_price_gwei) * U256::from(10u64.pow(9)),
			max_execution_cost: max_execution_cost_gwei
				.map(|cost| U256::from(cost) * U256::from(10u64.pow(9))),
			gas_config,
		}
	}

	/// Gets gas units for a specific flow from config or returns defaults
	fn get_gas_units_for_flow(&self, flow_key: &str) -> (u64, u64, u64) {
		if let Some(ref gas_config) = self.gas_config {
			if let Some(flow_units) = gas_config.flows.get(flow_key) {
				let open_gas = flow_units.open.unwrap_or(100_000);
				let fill_gas = flow_units.fill.unwrap_or(200_000);
				let claim_gas = flow_units.claim.unwrap_or(150_000);
				return (open_gas, fill_gas, claim_gas);
			}
		}
		// Default values if no config or flow not found
		(100_000, 200_000, 150_000)
	}

	/// Estimates the total execution cost for an order based on execution context
	fn estimate_execution_cost(&self, order: &Order, context: &ExecutionContext) -> Option<U256> {
		// Extract gas estimates from order data if available
		match order.standard.as_str() {
			"eip7683" => {
				if let Ok(order_data) =
					serde_json::from_value::<Eip7683OrderData>(order.data.clone())
				{
					// Get gas prices for origin and destination chains
					let origin_gas_price = context
						.chain_data
						.get(&order_data.origin_chain_id.to::<u64>())
						.and_then(|data| data.gas_price.parse::<U256>().ok())
						.unwrap_or(U256::ZERO);

					let mut total_cost = U256::ZERO;

					// Get gas units from config or use defaults
					let (open_gas, fill_gas, claim_gas) = self.get_gas_units_for_flow("eip7683");

					// Add cost for opening the order (if needed) - origin chain
					total_cost += origin_gas_price * U256::from(open_gas);

					// Add cost for each output (fill operations) - destination chains
					for output in &order_data.outputs {
						let dest_chain_id = output.chain_id.to::<u64>();
						let dest_gas_price = context
							.chain_data
							.get(&dest_chain_id)
							.and_then(|data| data.gas_price.parse::<U256>().ok())
							.unwrap_or(U256::ZERO);

						total_cost += dest_gas_price * U256::from(fill_gas);
					}

					// Add cost for claim transaction - origin chain
					total_cost += origin_gas_price * U256::from(claim_gas);

					return Some(total_cost);
				}
			},
			_ => {
				// For unknown standards, use basic estimation
				let max_gas_price = context
					.chain_data
					.values()
					.map(|chain_data| chain_data.gas_price.parse::<U256>().unwrap_or(U256::ZERO))
					.max()
					.unwrap_or(U256::ZERO);

				// Basic estimate: 500k gas at max gas price
				let estimated_gas = 500_000u64;
				return Some(max_gas_price * U256::from(estimated_gas));
			},
		}

		None
	}
}

/// Configuration schema for SimpleStrategy.
///
/// This schema validates the configuration for the simple execution strategy,
/// ensuring the optional maximum gas price and cost limit parameters are valid if provided.
pub struct SimpleStrategySchema;

impl ConfigSchema for SimpleStrategySchema {
	fn validate(&self, config: &toml::Value) -> Result<(), solver_types::ValidationError> {
		let schema = Schema::new(
			// Required fields
			vec![],
			// Optional fields
			vec![
				Field::new(
					"max_gas_price_gwei",
					FieldType::Integer {
						min: Some(1),
						max: None,
					},
				),
				Field::new(
					"max_execution_cost_gwei",
					FieldType::Integer {
						min: Some(1),
						max: None,
					},
				),
			],
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

		// Estimate execution cost and check against limit if configured
		if let Some(max_cost) = self.max_execution_cost {
			if let Some(estimated_cost) = self.estimate_execution_cost(order, context) {
				if estimated_cost > max_cost {
					tracing::warn!(
						order_id = %order.id,
						estimated_cost = %estimated_cost,
						max_cost = %max_cost,
						"Skipping execution due to cost exceeding configured limit"
					);
					return ExecutionDecision::Skip(format!(
						"Estimated execution cost {} wei exceeds maximum allowed cost {} wei",
						estimated_cost, max_cost
					));
				}
			} else {
				tracing::warn!(
					order_id = %order.id,
					"Could not estimate execution cost, proceeding with caution"
				);
			}
		}

		// Check token balances based on order standard
		match order.standard.as_str() {
			"eip7683" => {
				if let Ok(order_data) =
					serde_json::from_value::<Eip7683OrderData>(order.data.clone())
				{
					// Check each output to ensure we have sufficient balance
					for output in &order_data.outputs {
						let chain_id = output.chain_id.to::<u64>();
						// Convert bytes32 token to address format (without "0x" for balance lookup)
						let token_address = bytes32_to_address(&output.token);

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
				} else {
					tracing::error!(
						order_id = %order.id,
						"Failed to parse EIP-7683 order data"
					);
				}
			},
			_ => {
				// For unknown standards, skip balance checks
				tracing::debug!(
					order_id = %order.id,
					standard = %order.standard,
					"Skipping balance check for unknown order standard"
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
/// - `max_execution_cost_gwei`: Maximum execution cost in gwei (optional, no limit if not provided)
/// - `gas_config`: Gas configuration for customizable gas estimates (can be None for defaults)
pub fn create_strategy(
	config: &toml::Value,
	gas_config: Option<GasConfig>,
) -> Result<Box<dyn ExecutionStrategy>, StrategyError> {
	// Validate configuration using the schema
	let schema = SimpleStrategySchema;
	schema
		.validate(config)
		.map_err(|e| StrategyError::InvalidConfig(e.to_string()))?;

	let max_gas_price = config
		.get("max_gas_price_gwei")
		.and_then(|v| v.as_integer())
		.unwrap_or(100) as u64;

	let max_execution_cost = config
		.get("max_execution_cost_gwei")
		.and_then(|v| v.as_integer())
		.map(|v| v as u64);

	Ok(Box::new(SimpleStrategy::new(
		max_gas_price,
		max_execution_cost,
		gas_config,
	)))
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
	use solver_config::{GasConfig, GasFlowUnits};
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
		let strategy = SimpleStrategy::new(50, None, None); // 50 gwei, no cost limit, no gas config
		assert_eq!(
			strategy.max_gas_price,
			U256::from(50) * U256::from(10u64.pow(9))
		);
		assert_eq!(strategy.max_execution_cost, None);
	}

	#[test]
	fn test_simple_strategy_new_with_cost_limit() {
		let strategy = SimpleStrategy::new(50, Some(1000), None); // 50 gwei max gas, 1000 gwei max cost, no gas config
		assert_eq!(
			strategy.max_gas_price,
			U256::from(50) * U256::from(10u64.pow(9))
		);
		assert_eq!(
			strategy.max_execution_cost,
			Some(U256::from(1000) * U256::from(10u64.pow(9)))
		);

		let strategy_no_cost_limit = SimpleStrategy::new(50, None, None);
		assert_eq!(strategy_no_cost_limit.max_execution_cost, None);
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

		// Valid config with max_execution_cost_gwei
		let mut config_map = toml::map::Map::new();
		config_map.insert(
			"max_execution_cost_gwei".to_string(),
			toml::Value::Integer(500),
		);
		let valid_config = toml::Value::Table(config_map);
		assert!(schema.validate(&valid_config).is_ok());

		// Valid config with both parameters
		let mut config_map = toml::map::Map::new();
		config_map.insert("max_gas_price_gwei".to_string(), toml::Value::Integer(100));
		config_map.insert(
			"max_execution_cost_gwei".to_string(),
			toml::Value::Integer(500),
		);
		let valid_config = toml::Value::Table(config_map);
		assert!(schema.validate(&valid_config).is_ok());

		// Invalid config with zero gas price
		let mut config_map = toml::map::Map::new();
		config_map.insert("max_gas_price_gwei".to_string(), toml::Value::Integer(0));
		let invalid_config = toml::Value::Table(config_map);
		assert!(schema.validate(&invalid_config).is_err());

		// Invalid config with zero execution cost
		let mut config_map = toml::map::Map::new();
		config_map.insert(
			"max_execution_cost_gwei".to_string(),
			toml::Value::Integer(0),
		);
		let invalid_config = toml::Value::Table(config_map);
		assert!(schema.validate(&invalid_config).is_err());
	}

	#[tokio::test]
	async fn test_should_execute_gas_price_too_high() {
		let strategy = SimpleStrategy::new(50, None, None); // 50 gwei max
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
		let strategy = SimpleStrategy::new(100, None, None); // 100 gwei max
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
		let strategy = SimpleStrategy::new(100, None, None); // 100 gwei max
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
		let strategy = SimpleStrategy::new(100, None, None); // 100 gwei max
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
	async fn test_should_execute_cost_too_high() {
		// Set a very low cost limit (1 gwei total) to ensure it gets exceeded
		let strategy = SimpleStrategy::new(100, Some(1), None); // 100 gwei max gas, 1 gwei max cost
		let order_data = create_test_order_data();
		let order = create_test_order(order_data);

		// Create context with good gas price and sufficient balance
		let context = create_test_context(
			vec![(1, "50000000000"), (137, "30000000000")], // 50 gwei, 30 gwei
			vec![(137, "0202020202020202020202020202020202020202", "200")],
		);

		let decision = strategy.should_execute(&order, &context).await;

		match decision {
			ExecutionDecision::Skip(reason) => {
				assert!(reason.contains("Estimated execution cost"));
				assert!(reason.contains("exceeds maximum allowed cost"));
			},
			ExecutionDecision::Execute(_) => {
				panic!("Expected Skip decision for high execution cost");
			},
			ExecutionDecision::Defer(_) => {
				panic!("Expected Skip decision for high execution cost");
			},
		}
	}

	#[tokio::test]
	async fn test_should_execute_cost_within_limit() {
		// Set a very high cost limit to ensure it doesn't get exceeded
		// Our estimated cost is ~18.5e15 wei, so set limit to 20000000000 gwei (20 billion gwei)
		let strategy = SimpleStrategy::new(100, Some(20000000000), None); // 100 gwei max gas, 20B gwei max cost
		let order_data = create_test_order_data();
		let order = create_test_order(order_data);

		// Create context with good gas price and sufficient balance
		let context = create_test_context(
			vec![(1, "50000000000"), (137, "30000000000")], // 50 gwei, 30 gwei
			vec![(137, "0202020202020202020202020202020202020202", "200")],
		);

		let decision = strategy.should_execute(&order, &context).await;

		match decision {
			ExecutionDecision::Execute(params) => {
				assert_eq!(params.gas_price, U256::from(50000000000u64));
				assert_eq!(params.priority_fee, Some(U256::from(2000000000u64)));
			},
			ExecutionDecision::Skip(reason) => {
				panic!("Expected Execute but got Skip: {}", reason);
			},
			ExecutionDecision::Defer(_) => {
				panic!("Expected Execute but got Defer");
			},
		}
	}

	#[test]
	fn test_estimate_execution_cost() {
		let strategy = SimpleStrategy::new(100, Some(500), None);
		let order_data = create_test_order_data();
		let order = create_test_order(order_data);

		let context = create_test_context(
			vec![(1, "50000000000"), (137, "30000000000")], // 50 gwei, 30 gwei
			vec![],
		);

		let estimated_cost = strategy.estimate_execution_cost(&order, &context);
		assert!(estimated_cost.is_some());

		// With our test data (origin chain 1 @ 50 gwei, dest chain 137 @ 30 gwei):
		// - open: 100k gas * 50 gwei = 5e15 wei
		// - fill: 200k gas * 30 gwei = 6e15 wei
		// - claim: 150k gas * 50 gwei = 7.5e15 wei
		// Total: 18.5e15 wei
		let expected_cost = U256::from(50000000000u64) * U256::from(100000u64) + // open
							U256::from(30000000000u64) * U256::from(200000u64) + // fill
							U256::from(50000000000u64) * U256::from(150000u64); // claim
		assert_eq!(estimated_cost.unwrap(), expected_cost);
	}

	#[tokio::test]
	async fn test_should_execute_unknown_standard() {
		let strategy = SimpleStrategy::new(100, None, None); // 100 gwei max
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
		let strategy = SimpleStrategy::new(100, None, None); // 100 gwei max
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
		let strategy = SimpleStrategy::new(100, None, None); // 100 gwei max
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
		let result = create_strategy(&config, None);
		assert!(result.is_ok());

		// Test with custom max gas price
		let mut config_map = toml::map::Map::new();
		config_map.insert("max_gas_price_gwei".to_string(), toml::Value::Integer(75));
		let config = toml::Value::Table(config_map);
		let result = create_strategy(&config, None);
		assert!(result.is_ok());

		// Test with custom execution cost limit
		let mut config_map = toml::map::Map::new();
		config_map.insert(
			"max_execution_cost_gwei".to_string(),
			toml::Value::Integer(500),
		);
		let config = toml::Value::Table(config_map);
		let result = create_strategy(&config, None);
		assert!(result.is_ok());

		// Test with both parameters
		let mut config_map = toml::map::Map::new();
		config_map.insert("max_gas_price_gwei".to_string(), toml::Value::Integer(75));
		config_map.insert(
			"max_execution_cost_gwei".to_string(),
			toml::Value::Integer(500),
		);
		let config = toml::Value::Table(config_map);
		let result = create_strategy(&config, None);
		assert!(result.is_ok());

		// Test with invalid gas price config
		let mut config_map = toml::map::Map::new();
		config_map.insert("max_gas_price_gwei".to_string(), toml::Value::Integer(0));
		let config = toml::Value::Table(config_map);
		let result = create_strategy(&config, None);
		assert!(result.is_err());

		// Test with invalid execution cost config
		let mut config_map = toml::map::Map::new();
		config_map.insert(
			"max_execution_cost_gwei".to_string(),
			toml::Value::Integer(0),
		);
		let config = toml::Value::Table(config_map);
		let result = create_strategy(&config, None);
		assert!(result.is_err());
	}

	#[test]
	fn test_simple_strategy_with_gas_config() {
		// Create a custom gas config
		let mut flows = HashMap::new();
		flows.insert(
			"eip7683".to_string(),
			GasFlowUnits {
				open: Some(80_000),
				fill: Some(250_000),
				claim: Some(120_000),
			},
		);
		let gas_config = GasConfig { flows };

		let strategy = SimpleStrategy::new(100, None, Some(gas_config));

		// Test that the strategy stores the gas config
		assert!(strategy.gas_config.is_some());
	}

	#[test]
	fn test_get_gas_units_for_flow_with_config() {
		// Create a custom gas config
		let mut flows = HashMap::new();
		flows.insert(
			"eip7683".to_string(),
			GasFlowUnits {
				open: Some(80_000),
				fill: Some(250_000),
				claim: Some(120_000),
			},
		);
		flows.insert(
			"partial_config".to_string(),
			GasFlowUnits {
				open: Some(90_000),
				fill: None, // Should use default
				claim: Some(180_000),
			},
		);
		let gas_config = GasConfig { flows };

		let strategy = SimpleStrategy::new(100, None, Some(gas_config));

		// Test custom gas units for eip7683
		let (open, fill, claim) = strategy.get_gas_units_for_flow("eip7683");
		assert_eq!(open, 80_000);
		assert_eq!(fill, 250_000);
		assert_eq!(claim, 120_000);

		// Test partial config (some defaults, some custom)
		let (open, fill, claim) = strategy.get_gas_units_for_flow("partial_config");
		assert_eq!(open, 90_000);
		assert_eq!(fill, 200_000); // Default value
		assert_eq!(claim, 180_000);

		// Test unknown flow (should use defaults)
		let (open, fill, claim) = strategy.get_gas_units_for_flow("unknown_flow");
		assert_eq!(open, 100_000);
		assert_eq!(fill, 200_000);
		assert_eq!(claim, 150_000);
	}

	#[test]
	fn test_get_gas_units_for_flow_without_config() {
		let strategy = SimpleStrategy::new(100, None, None);

		// Should always return defaults when no gas config is provided
		let (open, fill, claim) = strategy.get_gas_units_for_flow("eip7683");
		assert_eq!(open, 100_000);
		assert_eq!(fill, 200_000);
		assert_eq!(claim, 150_000);

		let (open, fill, claim) = strategy.get_gas_units_for_flow("any_flow");
		assert_eq!(open, 100_000);
		assert_eq!(fill, 200_000);
		assert_eq!(claim, 150_000);
	}

	#[test]
	fn test_estimate_execution_cost_with_custom_gas_config() {
		// Create a custom gas config with higher gas estimates
		let mut flows = HashMap::new();
		flows.insert(
			"eip7683".to_string(),
			GasFlowUnits {
				open: Some(200_000),  // Double the default
				fill: Some(400_000),  // Double the default
				claim: Some(300_000), // Double the default
			},
		);
		let gas_config = GasConfig { flows };

		let strategy = SimpleStrategy::new(100, Some(500), Some(gas_config));
		let order_data = create_test_order_data();
		let order = create_test_order(order_data);

		let context = create_test_context(
			vec![(1, "50000000000"), (137, "30000000000")], // 50 gwei, 30 gwei
			vec![],
		);

		let estimated_cost = strategy.estimate_execution_cost(&order, &context);
		assert!(estimated_cost.is_some());

		// With custom gas values (origin chain 1 @ 50 gwei, dest chain 137 @ 30 gwei):
		// - open: 200k gas * 50 gwei = 10e15 wei
		// - fill: 400k gas * 30 gwei = 12e15 wei
		// - claim: 300k gas * 50 gwei = 15e15 wei
		// Total: 37e15 wei (double the original estimate)
		let expected_cost = U256::from(50000000000u64) * U256::from(200000u64) + // open
							U256::from(30000000000u64) * U256::from(400000u64) + // fill
							U256::from(50000000000u64) * U256::from(300000u64); // claim
		assert_eq!(estimated_cost.unwrap(), expected_cost);
	}

	#[test]
	fn test_create_strategy_with_gas_config() {
		// Create a custom gas config
		let mut flows = HashMap::new();
		flows.insert(
			"eip7683".to_string(),
			GasFlowUnits {
				open: Some(150_000),
				fill: Some(300_000),
				claim: Some(200_000),
			},
		);
		let gas_config = GasConfig { flows };

		// Test with both custom strategy config and gas config
		let mut config_map = toml::map::Map::new();
		config_map.insert("max_gas_price_gwei".to_string(), toml::Value::Integer(75));
		config_map.insert(
			"max_execution_cost_gwei".to_string(),
			toml::Value::Integer(500),
		);
		let config = toml::Value::Table(config_map);

		let result = create_strategy(&config, Some(gas_config));
		assert!(result.is_ok());

		// Test with only gas config
		let mut flows2 = HashMap::new();
		flows2.insert(
			"test_flow".to_string(),
			GasFlowUnits {
				open: Some(50_000),
				fill: Some(100_000),
				claim: Some(75_000),
			},
		);
		let gas_config2 = GasConfig { flows: flows2 };

		let empty_config = toml::Value::Table(toml::map::Map::new());
		let result2 = create_strategy(&empty_config, Some(gas_config2));
		assert!(result2.is_ok());

		// Test without gas config (should still work with None)
		let result3 = create_strategy(&empty_config, None);
		assert!(result3.is_ok());
	}

	#[tokio::test]
	async fn test_should_execute_with_custom_gas_affects_cost_limit() {
		// Create a gas config with very high gas estimates to trigger cost limit
		let mut flows = HashMap::new();
		flows.insert(
			"eip7683".to_string(),
			GasFlowUnits {
				open: Some(1_000_000),  // Very high gas
				fill: Some(2_000_000),  // Very high gas
				claim: Some(1_500_000), // Very high gas
			},
		);
		let gas_config = GasConfig { flows };

		// Set a moderate cost limit that should be exceeded with high gas estimates
		let strategy = SimpleStrategy::new(100, Some(100), Some(gas_config)); // 100 gwei max cost
		let order_data = create_test_order_data();
		let order = create_test_order(order_data);

		// Create context with moderate gas prices
		let context = create_test_context(
			vec![(1, "20000000000"), (137, "20000000000")], // 20 gwei each
			vec![(137, "0202020202020202020202020202020202020202", "200")],
		);

		let decision = strategy.should_execute(&order, &context).await;

		// Should skip due to high execution cost from custom gas config
		match decision {
			ExecutionDecision::Skip(reason) => {
				assert!(reason.contains("Estimated execution cost"));
				assert!(reason.contains("exceeds maximum allowed cost"));
			},
			_ => panic!("Expected Skip decision due to high execution cost with custom gas config"),
		}
	}
}
