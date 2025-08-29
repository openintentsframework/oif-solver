//! Order processing module for the OIF solver system.
//!
//! This module handles order validation, execution decisions, and transaction
//! generation for filling and claiming orders. It supports multiple order
//! standards and pluggable execution strategies.

use async_trait::async_trait;
use solver_types::{
	Address, ConfigSchema, ExecutionContext, ExecutionDecision, ExecutionParams, FillProof,
	ImplementationRegistry, Intent, NetworksConfig, Order, Transaction,
};
use std::collections::HashMap;
use thiserror::Error;

/// Re-export implementations
pub mod implementations {
	pub mod standards {
		pub mod _7683;
	}
	pub mod strategies {
		pub mod simple;
	}
}

/// Errors that can occur during order processing operations.
#[derive(Debug, Error)]
pub enum OrderError {
	/// Error that occurs when order validation fails.
	#[error("Validation failed: {0}")]
	ValidationFailed(String),
	/// Error that occurs when the solver has insufficient balance to execute.
	#[error("Insufficient balance")]
	InsufficientBalance,
	/// Error that occurs when the order cannot be satisfied given current conditions.
	#[error("Cannot satisfy order")]
	CannotSatisfyOrder,
	/// Error that occurs when the order configuration is invalid.
	#[error("Invalid order: {0}")]
	InvalidOrder(String),
}

/// Errors that can occur during strategy creation and execution.
#[derive(Debug, Error)]
pub enum StrategyError {
	/// Error that occurs when strategy configuration is invalid.
	#[error("Invalid configuration: {0}")]
	InvalidConfig(String),
	/// Error that occurs when a required parameter is missing.
	#[error("Missing required parameter: {0}")]
	MissingParameter(String),
	/// Error that occurs during strategy initialization.
	#[error("Initialization failed: {0}")]
	InitializationFailed(String),
	/// Error that occurs when strategy implementation is not available.
	#[error("Implementation not available: {0}")]
	ImplementationNotAvailable(String),
}

/// Trait defining the interface for order standard implementations.
///
/// This trait must be implemented for each order standard (e.g., EIP-7683)
/// that the solver supports. It handles standard-specific validation and
/// transaction generation logic.
#[async_trait]
#[cfg_attr(feature = "testing", mockall::automock)]
pub trait OrderInterface: Send + Sync {
	/// Returns the configuration schema for this order implementation.
	///
	/// This allows each implementation to define its own configuration requirements
	/// with specific validation rules. The schema is used to validate TOML configuration
	/// before initializing the order processor.
	fn config_schema(&self) -> Box<dyn ConfigSchema>;

	/// Validates an intent and converts it to a standard order format.
	///
	/// This method performs standard-specific validation to ensure the intent
	/// is well-formed and can be processed by the solver. The solver address
	/// is included in the resulting order for reward attribution.
	///
	/// # Arguments
	///
	/// * `intent` - The intent to validate
	/// * `solver_address` - The solver's address for reward attribution
	async fn validate_intent(
		&self,
		intent: &Intent,
		solver_address: &Address,
	) -> Result<Order, OrderError>;

	/// Generates a transaction to prepare an order for filling (if needed).
	///
	/// For off-chain orders, this might involve calling openFor() to create
	/// the order on-chain. Returns None if no preparation is needed.
	async fn generate_prepare_transaction(
		&self,
		_intent: &Intent,
		_order: &Order,
		_params: &ExecutionParams,
	) -> Result<Option<Transaction>, OrderError> {
		// Default implementation: no preparation needed
		Ok(None)
	}

	/// Generates a transaction to fill the given order.
	///
	/// Creates a blockchain transaction that will execute the order fill
	/// according to the standard's requirements.
	async fn generate_fill_transaction(
		&self,
		order: &Order,
		params: &ExecutionParams,
	) -> Result<Transaction, OrderError>;

	/// Generates a transaction to claim rewards for a filled order.
	///
	/// Creates a blockchain transaction that will claim any rewards or fees
	/// owed to the solver for successfully filling the order.
	async fn generate_claim_transaction(
		&self,
		order: &Order,
		fill_proof: &FillProof,
	) -> Result<Transaction, OrderError>;
}

/// Trait defining the interface for execution strategies.
///
/// Execution strategies determine when and how orders should be executed
/// based on market conditions, profitability, and other factors.
#[async_trait]
#[cfg_attr(feature = "testing", mockall::automock)]
pub trait ExecutionStrategy: Send + Sync {
	/// Returns the configuration schema for this strategy implementation.
	///
	/// This allows each strategy to define its own configuration requirements
	/// with specific validation rules. The schema is used to validate TOML configuration
	/// before initializing the strategy.
	fn config_schema(&self) -> Box<dyn ConfigSchema>;

	/// Determines whether an order should be executed given the current context.
	///
	/// Returns an ExecutionDecision indicating whether to execute now,
	/// skip the order, or defer execution to a later time.
	async fn should_execute(&self, order: &Order, context: &ExecutionContext) -> ExecutionDecision;
}

/// Type alias for order factory functions.
///
/// This is the function signature that all order implementations must provide
/// to create instances of their order interface.
pub type OrderFactory = fn(
	&toml::Value,
	&NetworksConfig,
	&solver_types::oracle::OracleRoutes,
) -> Result<Box<dyn OrderInterface>, OrderError>;

/// Type alias for strategy factory functions.
///
/// This is the function signature that all strategy implementations must provide
/// to create instances of their execution strategy.
pub type StrategyFactory = fn(&toml::Value) -> Result<Box<dyn ExecutionStrategy>, StrategyError>;

/// Registry trait for order implementations.
///
/// This trait extends the base ImplementationRegistry to specify that
/// order implementations must provide an OrderFactory.
pub trait OrderRegistry: ImplementationRegistry<Factory = OrderFactory> {}

/// Registry trait for strategy implementations.
///
/// This trait extends the base ImplementationRegistry to specify that
/// strategy implementations must provide a StrategyFactory.
pub trait StrategyRegistry: ImplementationRegistry<Factory = StrategyFactory> {}

/// Get all registered order implementations.
///
/// Returns a vector of (name, factory) tuples for all available order implementations.
/// This is used by the factory registry to automatically register all implementations.
pub fn get_all_order_implementations() -> Vec<(&'static str, OrderFactory)> {
	use implementations::standards::_7683;

	vec![(_7683::Registry::NAME, _7683::Registry::factory())]
}

/// Get all registered strategy implementations.
///
/// Returns a vector of (name, factory) tuples for all available strategy implementations.
/// This is used by the factory registry to automatically register all implementations.
pub fn get_all_strategy_implementations() -> Vec<(&'static str, StrategyFactory)> {
	use implementations::strategies::simple;

	vec![(simple::Registry::NAME, simple::Registry::factory())]
}

/// Service that manages order processing with multiple implementations and strategies.
///
/// The OrderService coordinates between different order standard implementations
/// and applies the configured execution strategy to make filling decisions.
pub struct OrderService {
	/// Map of standard names to their implementations.
	implementations: HashMap<String, Box<dyn OrderInterface>>,
	/// The execution strategy to use for making filling decisions.
	strategy: Box<dyn ExecutionStrategy>,
}

impl OrderService {
	/// Creates a new OrderService with the specified implementations and strategy.
	pub fn new(
		implementations: HashMap<String, Box<dyn OrderInterface>>,
		strategy: Box<dyn ExecutionStrategy>,
	) -> Self {
		Self {
			implementations,
			strategy,
		}
	}

	/// Validates an intent using the appropriate standard implementation.
	///
	/// Selects the implementation based on the intent's standard field
	/// and delegates validation to that implementation. The solver address
	/// is included in the resulting order for reward attribution.
	///
	/// # Arguments
	///
	/// * `intent` - The intent to validate
	/// * `solver_address` - The solver's address for reward attribution
	pub async fn validate_intent(
		&self,
		intent: &Intent,
		solver_address: &Address,
	) -> Result<Order, OrderError> {
		let implementation = self.implementations.get(&intent.standard).ok_or_else(|| {
			OrderError::ValidationFailed(format!("Unknown standard: {}", intent.standard))
		})?;

		implementation.validate_intent(intent, solver_address).await
	}

	/// Determines whether an order should be executed using the configured strategy.
	pub async fn should_execute(
		&self,
		order: &Order,
		context: &ExecutionContext,
	) -> ExecutionDecision {
		self.strategy.should_execute(order, context).await
	}

	/// Generates a prepare transaction for the given order if needed.
	///
	/// Uses the appropriate standard implementation to create the transaction.
	pub async fn generate_prepare_transaction(
		&self,
		intent: &Intent,
		order: &Order,
		params: &ExecutionParams,
	) -> Result<Option<Transaction>, OrderError> {
		let implementation = self
			.implementations
			.get(&order.standard)
			.ok_or_else(|| OrderError::ValidationFailed("Unknown standard".into()))?;

		implementation
			.generate_prepare_transaction(intent, order, params)
			.await
	}

	/// Generates a fill transaction for the given order.
	///
	/// Uses the appropriate standard implementation to create the transaction.
	pub async fn generate_fill_transaction(
		&self,
		order: &Order,
		params: &ExecutionParams,
	) -> Result<Transaction, OrderError> {
		let implementation = self
			.implementations
			.get(&order.standard)
			.ok_or_else(|| OrderError::ValidationFailed("Unknown standard".into()))?;

		implementation
			.generate_fill_transaction(order, params)
			.await
	}

	/// Generates a claim transaction for a filled order.
	///
	/// Uses the appropriate standard implementation to create the transaction.
	pub async fn generate_claim_transaction(
		&self,
		order: &Order,
		proof: &FillProof,
	) -> Result<Transaction, OrderError> {
		let implementation = self
			.implementations
			.get(&order.standard)
			.ok_or_else(|| OrderError::ValidationFailed("Unknown standard".into()))?;

		implementation
			.generate_claim_transaction(order, proof)
			.await
	}
}
