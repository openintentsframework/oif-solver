//! Settlement module for the OIF solver system.
//!
//! This module handles the complete settlement lifecycle including validation of
//! filled orders, optional post-fill and pre-claim transactions for oracle interactions,
//! and the final claiming process for solver rewards. It supports different
//! settlement mechanisms for various order standards.

use async_trait::async_trait;
use solver_types::{
	oracle::{OracleInfo, OracleRoutes},
	Address, ConfigSchema, FillProof, ImplementationRegistry, NetworksConfig, Order, Transaction,
	TransactionHash, TransactionReceipt, TransactionType,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;

/// Re-export implementations
pub mod implementations {
	pub mod direct;
	pub mod hyperlane;
}

/// Common utilities for settlement implementations
pub mod utils;

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

/// Strategy for selecting oracles when multiple are available
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OracleSelectionStrategy {
	/// Always use the first available oracle
	First,
	/// Round-robin through available oracles
	RoundRobin,
	/// Random selection from available oracles
	Random,
}

impl Default for OracleSelectionStrategy {
	fn default() -> Self {
		Self::First
	}
}

/// Oracle configuration for a settlement implementation
#[derive(Debug, Clone)]
pub struct OracleConfig {
	/// Input oracle addresses by chain ID (multiple per chain possible)
	pub input_oracles: HashMap<u64, Vec<Address>>,
	/// Output oracle addresses by chain ID (multiple per chain possible)
	pub output_oracles: HashMap<u64, Vec<Address>>,
	/// Valid routes: input_chain -> [output_chains]
	pub routes: HashMap<u64, Vec<u64>>,
	/// Strategy for selecting oracles when multiple are available
	pub selection_strategy: OracleSelectionStrategy,
}

/// Trait defining the interface for settlement mechanisms.
///
/// This trait must be implemented by each settlement mechanism to handle
/// validation of fills and management of the claim process for different
/// order types. Settlements are order-agnostic and only handle oracle mechanics.
#[cfg_attr(feature = "testing", mockall::automock)]
#[async_trait]
pub trait SettlementInterface: Send + Sync {
	/// Get the oracle configuration for this settlement
	fn oracle_config(&self) -> &OracleConfig;

	/// Check if a specific route is supported
	fn is_route_supported(&self, input_chain: u64, output_chain: u64) -> bool {
		self.oracle_config()
			.routes
			.get(&input_chain)
			.is_some_and(|outputs| outputs.contains(&output_chain))
	}

	/// Check if a specific input oracle is supported on a chain
	fn is_input_oracle_supported(&self, chain_id: u64, oracle: &Address) -> bool {
		self.oracle_config()
			.input_oracles
			.get(&chain_id)
			.is_some_and(|oracles| oracles.contains(oracle))
	}

	/// Check if a specific output oracle is supported on a chain
	fn is_output_oracle_supported(&self, chain_id: u64, oracle: &Address) -> bool {
		self.oracle_config()
			.output_oracles
			.get(&chain_id)
			.is_some_and(|oracles| oracles.contains(oracle))
	}

	/// Get all supported input oracles for a chain
	fn get_input_oracles(&self, chain_id: u64) -> Vec<Address> {
		self.oracle_config()
			.input_oracles
			.get(&chain_id)
			.cloned()
			.unwrap_or_default()
	}

	/// Get all supported output oracles for a chain
	fn get_output_oracles(&self, chain_id: u64) -> Vec<Address> {
		self.oracle_config()
			.output_oracles
			.get(&chain_id)
			.cloned()
			.unwrap_or_default()
	}

	/// Select an oracle from available options based on the configured strategy
	/// If selection_context is None, uses an internal counter for round-robin/random
	fn select_oracle(
		&self,
		oracles: &[Address],
		selection_context: Option<u64>,
	) -> Option<Address> {
		if oracles.is_empty() {
			return None;
		}

		match self.oracle_config().selection_strategy {
			OracleSelectionStrategy::First => oracles.first().cloned(),
			OracleSelectionStrategy::RoundRobin => {
				// For round-robin, we need a context value. If none provided,
				// default to 0 (will select first oracle). Callers should provide
				// proper context (e.g., order nonce) for deterministic distribution.
				let context = selection_context.unwrap_or(0);
				let index = (context as usize) % oracles.len();
				oracles.get(index).cloned()
			},
			OracleSelectionStrategy::Random => {
				use std::collections::hash_map::RandomState;
				use std::hash::BuildHasher;

				let context = selection_context.unwrap_or_else(|| {
					std::time::SystemTime::now()
						.duration_since(std::time::UNIX_EPOCH)
						.map(|d| d.as_secs())
						.unwrap_or(0)
				});

				let index = (RandomState::new().hash_one(context) as usize) % oracles.len();
				oracles.get(index).cloned()
			},
		}
	}

	/// Returns the configuration schema for this settlement implementation.
	///
	/// This allows each implementation to define its own configuration requirements
	/// with specific validation rules. The schema is used to validate TOML configuration
	/// before initializing the settlement mechanism.
	fn config_schema(&self) -> Box<dyn ConfigSchema>;

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

	/// Generates a transaction to execute after fill confirmation (optional).
	///
	/// This transaction might:
	/// - Request attestation from an oracle
	/// - Submit proof to a bridge
	/// - Initiate oracle delegation
	/// - Prepare settlement data
	async fn generate_post_fill_transaction(
		&self,
		_order: &Order,
		_fill_receipt: &TransactionReceipt,
	) -> Result<Option<Transaction>, SettlementError> {
		// Default: no post-fill transaction needed
		Ok(None)
	}

	/// Generates a transaction to execute before claiming (optional).
	///
	/// This transaction might:
	/// - Submit oracle signatures
	/// - Finalize attestations
	/// - Prepare claim proofs
	/// - Unlock settlement funds
	async fn generate_pre_claim_transaction(
		&self,
		_order: &Order,
		_fill_proof: &FillProof,
	) -> Result<Option<Transaction>, SettlementError> {
		// Default: no pre-claim transaction needed
		Ok(None)
	}

	/// Called after certain transaction types are confirmed on-chain.
	/// Allows settlements to handle transaction receipts for protocol-specific needs.
	/// For Hyperlane: extracts message IDs from PostFill transaction receipts.
	async fn handle_transaction_confirmed(
		&self,
		_order: &Order,
		_tx_type: TransactionType,
		_receipt: &TransactionReceipt,
	) -> Result<(), SettlementError> {
		Ok(()) // Default: no-op for settlements that don't need this
	}
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
	use implementations::{direct, hyperlane};

	vec![
		(direct::Registry::NAME, direct::Registry::factory()),
		(hyperlane::Registry::NAME, hyperlane::Registry::factory()),
	]
}

/// Service managing settlement implementations.
pub struct SettlementService {
	/// Map of implementation names to their instances.
	/// Keys are implementation type names (e.g., "direct", "optimistic").
	implementations: HashMap<String, Box<dyn SettlementInterface>>,
	/// Track order count for round-robin selection
	selection_counter: Arc<AtomicU64>,
}

impl SettlementService {
	/// Creates a new SettlementService.
	///
	/// # Arguments
	/// * `implementations` - Map of implementation name to instance
	pub fn new(implementations: HashMap<String, Box<dyn SettlementInterface>>) -> Self {
		Self {
			implementations,
			selection_counter: Arc::new(AtomicU64::new(0)),
		}
	}

	/// Gets a specific settlement implementation by name.
	///
	/// Returns None if the implementation doesn't exist.
	pub fn get(&self, name: &str) -> Option<&dyn SettlementInterface> {
		self.implementations.get(name).map(|b| b.as_ref())
	}

	/// Build oracle routes from all settlement implementations.
	pub fn build_oracle_routes(&self) -> OracleRoutes {
		let mut supported_routes = HashMap::new();

		for settlement in self.implementations.values() {
			let config = settlement.oracle_config();

			// For each input oracle
			for (input_chain, input_oracles) in &config.input_oracles {
				for input_oracle in input_oracles {
					let input_info = OracleInfo {
						chain_id: *input_chain,
						oracle: input_oracle.clone(),
					};

					let mut valid_outputs = Vec::new();

					// Add all valid output destinations
					if let Some(dest_chains) = config.routes.get(input_chain) {
						for dest_chain in dest_chains {
							// Add all output oracles on that destination
							if let Some(output_oracles) = config.output_oracles.get(dest_chain) {
								for output_oracle in output_oracles {
									valid_outputs.push(OracleInfo {
										chain_id: *dest_chain,
										oracle: output_oracle.clone(),
									});
								}
							}
						}
					}

					// Only insert if there are valid routes from this input oracle
					if !valid_outputs.is_empty() {
						supported_routes.insert(input_info, valid_outputs);
					}
				}
			}
		}

		OracleRoutes { supported_routes }
	}

	/// Find settlement by oracle address.
	pub fn get_settlement_for_oracle(
		&self,
		chain_id: u64,
		oracle_address: &Address,
		is_input: bool,
	) -> Result<&dyn SettlementInterface, SettlementError> {
		for settlement in self.implementations.values() {
			if is_input {
				if settlement.is_input_oracle_supported(chain_id, oracle_address) {
					return Ok(settlement.as_ref());
				}
			} else if settlement.is_output_oracle_supported(chain_id, oracle_address) {
				return Ok(settlement.as_ref());
			}
		}
		Err(SettlementError::ValidationFailed(format!(
			"No settlement found for {} oracle {} on chain {}",
			if is_input { "input" } else { "output" },
			oracle_address
				.0
				.iter()
				.map(|b| format!("{:02x}", b))
				.collect::<String>(),
			chain_id
		)))
	}

	/// Find settlement for an order based on its oracles.
	pub fn find_settlement_for_order(
		&self,
		order: &Order,
	) -> Result<&dyn SettlementInterface, SettlementError> {
		let order_data = order
			.parse_order_data()
			.map_err(|e| SettlementError::ValidationFailed(e.to_string()))?;
		let input_oracle_str = order_data.input_oracle();
		let input_oracle = solver_types::utils::parse_address(&input_oracle_str)
			.map_err(SettlementError::ValidationFailed)?;
		let origin_chain = order_data.origin_chain_id();

		// Find settlement by input oracle
		self.get_settlement_for_oracle(origin_chain, &input_oracle, true)
	}

	/// Get any settlement that supports a given chain (for quote generation).
	/// Returns both settlement and selected oracle for consistency.
	pub fn get_any_settlement_for_chain(
		&self,
		chain_id: u64,
	) -> Option<(&dyn SettlementInterface, Address)> {
		// Collect all settlements that support this chain with their oracles
		let mut available_settlements = Vec::new();

		for settlement in self.implementations.values() {
			if let Some(oracles) = settlement.oracle_config().input_oracles.get(&chain_id) {
				if !oracles.is_empty() {
					available_settlements.push((settlement.as_ref(), oracles.clone()));
				}
			}
		}

		if available_settlements.is_empty() {
			return None;
		}

		// Get selection context for deterministic oracle selection
		let context = self.selection_counter.fetch_add(1, Ordering::Relaxed);

		// If only one settlement, use it with oracle selection
		if available_settlements.len() == 1 {
			let (settlement, oracles) = &available_settlements[0];
			let selected_oracle = settlement.select_oracle(oracles, Some(context))?;
			return Some((*settlement, selected_oracle));
		}

		// Multiple settlements - use first one but apply oracle selection
		let (settlement, oracles) = &available_settlements[0];
		let selected_oracle = settlement.select_oracle(oracles, Some(context))?;
		Some((*settlement, selected_oracle))
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

	/// Generates a post-fill transaction if needed by the settlement implementation.
	pub async fn generate_post_fill_transaction(
		&self,
		order: &Order,
		fill_receipt: &TransactionReceipt,
	) -> Result<Option<Transaction>, SettlementError> {
		let implementation = self.find_settlement_for_order(order)?;
		implementation
			.generate_post_fill_transaction(order, fill_receipt)
			.await
	}

	/// Generates a pre-claim transaction if needed by the settlement implementation.
	pub async fn generate_pre_claim_transaction(
		&self,
		order: &Order,
		fill_proof: &FillProof,
	) -> Result<Option<Transaction>, SettlementError> {
		let implementation = self.find_settlement_for_order(order)?;
		implementation
			.generate_pre_claim_transaction(order, fill_proof)
			.await
	}
}
