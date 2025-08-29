//! Execution strategy implementations for the solver service.
//!
//! This module provides concrete implementations of the ExecutionStrategy trait

use alloy_primitives::U256;
use async_trait::async_trait;
use solver_types::{
	bytes32_to_address, with_0x_prefix, ConfigSchema, Eip7683OrderData, ExecutionContext,
	ExecutionDecision, ExecutionParams, Field, FieldType, Order, Schema,
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
