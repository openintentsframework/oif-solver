//! Settlement module for the OIF solver system.
//!
//! This module handles the validation of filled orders and manages the claiming
//! process for solver rewards. It supports different settlement mechanisms
//! for various order standards.

use async_trait::async_trait;
use solver_types::{
	Address, ConfigSchema, FillProof, ImplementationRegistry, NetworksConfig, Order,
	TransactionHash,
};
use std::collections::HashMap;
use thiserror::Error;

/// Re-export implementations
pub mod implementations {
	pub mod direct;
}

/// Errors that can occur during settlement operations.
#[derive(Debug, Error)]
pub enum SettlementError {
	/// Error that occurs when settlement validation fails.
	#[error("Validation failed: {0}")]
	ValidationFailed(String),
	/// Error that occurs when a fill proof is invalid.
	#[error("Invalid proof")]
	InvalidProof,
	/// Error that occurs when a fill doesn't match order requirements.
	#[error("Fill does not match order requirements")]
	FillMismatch,
}

/// Trait defining the interface for settlement mechanisms.
///
/// This trait must be implemented by each settlement mechanism to handle
/// validation of fills and management of the claim process for different
/// order types. Each implementation must explicitly declare its supported
/// order and networks.
#[async_trait]
pub trait SettlementInterface: Send + Sync {
	/// Returns the order type this implementation handles.
	///
	/// # Returns
	/// A string slice representing the order type (e.g., "eip7683").
	/// This must match the `order` field in Order structs.
	fn supported_order(&self) -> &str;

	/// Returns the network IDs this implementation supports.
	///
	/// # Returns
	/// A slice of network IDs where this settlement can operate.
	/// These must correspond to configured networks in NetworksConfig.
	fn supported_networks(&self) -> &[u64];

	/// Returns the configuration schema for this settlement implementation.
	///
	/// This allows each implementation to define its own configuration requirements
	/// with specific validation rules. The schema is used to validate TOML configuration
	/// before initializing the settlement mechanism.
	fn config_schema(&self) -> Box<dyn ConfigSchema>;

	/// Returns the oracle address for a specific chain.
	///
	/// Each settlement implementation manages its own oracle addresses
	/// which may vary by chain. Returns None if no oracle is configured
	/// for the given chain.
	fn get_oracle_address(&self, chain_id: u64) -> Option<Address>;

	/// Gets attestation data for a filled order by extracting proof data needed for claiming.
	///
	/// This method should:
	/// 1. Fetch the transaction receipt using the tx_hash
	/// 2. Parse logs/events to extract fill details
	/// 3. Verify the fill satisfies the order requirements
	/// 4. Build a FillProof containing all data needed for claiming
	async fn get_attestation(
		&self,
		order: &Order,
		tx_hash: &TransactionHash,
	) -> Result<FillProof, SettlementError>;

	/// Checks if the solver can claim rewards for this fill.
	///
	/// This method should check on-chain conditions such as:
	/// - Time delays or challenge periods
	/// - Oracle attestations if required
	/// - Solver permissions
	/// - Reward availability
	async fn can_claim(&self, order: &Order, fill_proof: &FillProof) -> bool;
}

/// Type alias for settlement factory functions.
///
/// This is the function signature that all settlement implementations must provide
/// to create instances of their settlement interface.
pub type SettlementFactory =
	fn(&toml::Value, &NetworksConfig) -> Result<Box<dyn SettlementInterface>, SettlementError>;

/// Registry trait for settlement implementations.
///
/// This trait extends the base ImplementationRegistry to specify that
/// settlement implementations must provide a SettlementFactory.
pub trait SettlementRegistry: ImplementationRegistry<Factory = SettlementFactory> {}

/// Get all registered settlement implementations.
///
/// Returns a vector of (name, factory) tuples for all available settlement implementations.
/// This is used by the factory registry to automatically register all implementations.
pub fn get_all_implementations() -> Vec<(&'static str, SettlementFactory)> {
	use implementations::direct;

	vec![(direct::Registry::NAME, direct::Registry::factory())]
}

/// Service managing settlement implementations with coverage indexing.
/// Maintains a lookup index for O(1) settlement discovery based on order and network.
pub struct SettlementService {
	/// Map of implementation names to their instances.
	/// Keys are implementation type names (e.g., "direct", "optimistic").
	implementations: HashMap<String, Box<dyn SettlementInterface>>,

	/// Index for fast lookup: (order, network_id) -> implementation_name.
	/// Built at initialization from implementation declarations.
	/// Validated to have no duplicates by config layer.
	coverage_index: HashMap<(String, u64), String>,
}

impl SettlementService {
	/// Creates a new SettlementService with pre-built coverage index.
	///
	/// # Arguments
	/// * `implementations` - Map of implementation name to instance
	///
	/// # Assumptions
	/// * Config validation has already verified no duplicate coverage
	/// * All implementations have valid standard and network declarations
	pub fn new(implementations: HashMap<String, Box<dyn SettlementInterface>>) -> Self {
		let mut coverage_index = HashMap::new();

		// Build coverage index for O(1) runtime lookups
		for (name, implementation) in &implementations {
			let order_standard = implementation.supported_order();
			for &network_id in implementation.supported_networks() {
				let key = (order_standard.to_string(), network_id);
				coverage_index.insert(key, name.clone());
			}
		}

		Self {
			implementations,
			coverage_index,
		}
	}

	/// Gets a specific settlement implementation by name.
	///
	/// Returns None if the implementation doesn't exist.
	pub fn get(&self, name: &str) -> Option<&dyn SettlementInterface> {
		self.implementations.get(name).map(|b| b.as_ref())
	}

	/// Finds the settlement implementation for an order.
	///
	/// # Arguments
	/// * `order` - Order requiring settlement
	///
	/// # Returns
	/// * Reference to the settlement implementation
	///
	/// # Errors
	/// * `SettlementError::ValidationFailed` if no settlement found for order's standard and output chains
	///
	/// # Logic
	/// Iterates through order.output_chain_ids (destination chains) to find first matching settlement.
	/// Settlement occurs on destination chain where tokens are delivered.
	pub fn find_settlement_for_order(
		&self,
		order: &Order,
	) -> Result<&dyn SettlementInterface, SettlementError> {
		// Verify order has output chains
		if order.output_chain_ids.is_empty() {
			return Err(SettlementError::ValidationFailed(
				"Order has no output chains specified".to_string(),
			));
		}

		// Find first output chain with settlement coverage
		for &network_id in &order.output_chain_ids {
			let key = (order.standard.clone(), network_id);
			if let Some(impl_name) = self.coverage_index.get(&key) {
				return Ok(self.implementations[impl_name].as_ref());
			}
		}

		// No settlement found - this should not occur if config validation is correct
		Err(SettlementError::ValidationFailed(format!(
			"No settlement implementation for standard '{}' on output chains {:?}",
			order.standard, order.output_chain_ids
		)))
	}

	/// Finds a settlement implementation by exact standard and network.
	///
	/// # Arguments
	/// * `standard` - Order standard (e.g., "eip7683")
	/// * `network_id` - Network ID where settlement is needed
	///
	/// # Returns
	/// * Reference to the settlement implementation
	///
	/// # Errors
	/// * `SettlementError::ValidationFailed` if no settlement found
	///
	/// # Use Case
	/// Direct lookup when generating quotes for known standard and network.
	pub fn find_settlement_for_standard_and_network(
		&self,
		standard: &str,
		network_id: u64,
	) -> Result<&dyn SettlementInterface, SettlementError> {
		let key = (standard.to_string(), network_id);

		self.coverage_index
			.get(&key)
			.and_then(|impl_name| self.implementations.get(impl_name))
			.map(|implementation| implementation.as_ref())
			.ok_or_else(|| {
				SettlementError::ValidationFailed(format!(
					"No settlement implementation for standard '{}' on network {}",
					standard, network_id
				))
			})
	}

	/// Gets attestation for a filled order using the appropriate settlement implementation.
	///
	/// # Arguments
	/// * `order` - The filled order
	/// * `tx_hash` - Transaction hash of the fill
	///
	/// # Returns
	/// * `FillProof` containing attestation data
	///
	/// # Errors
	/// * Propagates errors from settlement lookup or attestation generation
	pub async fn get_attestation(
		&self,
		order: &Order,
		tx_hash: &TransactionHash,
	) -> Result<FillProof, SettlementError> {
		let implementation = self.find_settlement_for_order(order)?;
		implementation.get_attestation(order, tx_hash).await
	}

	/// Checks if an order can be claimed using the appropriate settlement implementation.
	pub async fn can_claim(&self, order: &Order, fill_proof: &FillProof) -> bool {
		if let Ok(implementation) = self.find_settlement_for_order(order) {
			implementation.can_claim(order, fill_proof).await
		} else {
			false
		}
	}

	/// Gets the oracle address for a specific settlement implementation and chain.
	///
	/// Returns the oracle address if the implementation exists and has one configured
	/// for the specified chain.
	pub fn get_oracle_address(&self, implementation_name: &str, chain_id: u64) -> Option<Address> {
		self.implementations
			.get(implementation_name)
			.and_then(|impl_| impl_.get_oracle_address(chain_id))
	}
}
