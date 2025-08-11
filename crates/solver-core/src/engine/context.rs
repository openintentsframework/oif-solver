//! Execution context builder for strategy decisions.
//!
//! Provides utilities to build ExecutionContext with current market conditions
//! such as gas prices, timestamps, and solver balances.

use alloy_primitives::U256;
use solver_types::ExecutionContext;
use std::collections::HashMap;

/// Builder for creating execution context used in strategy decisions.
/// 
/// The ContextBuilder provides methods to construct ExecutionContext instances
/// populated with current market conditions like gas prices, timestamps, and
/// solver balances for use in order execution strategies.
pub struct ContextBuilder;

impl ContextBuilder {
	/// Builds the execution context with current market conditions
	pub async fn build() -> ExecutionContext {
		ExecutionContext {
			gas_price: U256::from(20_000_000_000u64), // 20 gwei
			timestamp: std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.unwrap()
				.as_secs(),
			solver_balance: HashMap::new(),
		}
	}
}
