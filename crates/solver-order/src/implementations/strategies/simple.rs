//! Execution strategy implementations for the solver service.
//!
//! This module provides concrete implementations of the ExecutionStrategy trait

use alloy_primitives::U256;
use async_trait::async_trait;
use solver_types::{
	ConfigSchema, ExecutionContext, ExecutionDecision, ExecutionParams, Field, FieldType, Order,
	Schema,
};

use crate::ExecutionStrategy;

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

	async fn should_execute(
		&self,
		_order: &Order,
		context: &ExecutionContext,
	) -> ExecutionDecision {
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
pub fn create_strategy(config: &toml::Value) -> Box<dyn ExecutionStrategy> {
	let max_gas_price = config
		.get("max_gas_price_gwei")
		.and_then(|v| v.as_integer())
		.unwrap_or(100) as u64;

	Box::new(SimpleStrategy::new(max_gas_price))
}
