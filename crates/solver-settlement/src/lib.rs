//! Settlement module for the OIF solver system.
//!
//! This module handles the complete settlement lifecycle including validation of
//! filled orders, optional post-fill and pre-claim transactions for oracle interactions,
//! and the final claiming process for solver rewards. It supports different
//! settlement mechanisms for various order standards.

use async_trait::async_trait;
use solver_types::{
	oracle::{OracleInfo, OracleRoutes},
	Address, ConfigSchema, FillProof, ImplementationRegistry, NetworksConfig, Order,
	PusherL2Params, Transaction, TransactionHash, TransactionReceipt, TransactionType,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;

/// Re-export implementations
pub mod implementations {
	pub mod broadcaster;
	pub mod direct;
	pub mod hyperlane;
}

/// Helpers for intent admission heuristics based on settlement configuration.
pub mod admission;

/// Common utilities for settlement implementations
pub mod utils;

/// Block-hash pusher for L1→L2 buffer advancement
pub mod pusher;

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
	/// Failed to generate storage proof data required for broadcaster verification.
	#[error("Proof generation failed for chain {source_chain}: {reason}")]
	ProofGenerationFailed { source_chain: u64, reason: String },
	/// Proof generation attempted before configured finality threshold was met.
	#[error("Finality not reached: required {required_blocks} blocks, current {current_blocks}")]
	FinalityNotReached {
		required_blocks: u64,
		current_blocks: u64,
	},
	/// External prover/proof service is unavailable.
	#[error("Prover unavailable: {0}")]
	ProverUnavailable(String),
	/// Slot derivation mismatch detected between expected and proved slot.
	#[error("Slot derivation mismatch")]
	SlotDerivationMismatch,
}

/// Direction for pushing L1 block hashes into an L2 buffer contract.
///
/// Each direction describes one L1→L2 pair managed by an IPusher contract.
/// A push is triggered order-by-order when the monitor detects the L2 buffer
/// has not yet indexed the L1 block where that order's PostFill broadcast was
/// confirmed (`buffer_newest < required_block`).
///
/// For Arbitrum L2s the deployed pusher always covers the latest `batch_size`
/// L1 blocks (`block.number - batch_size .. block.number`), so a single push
/// is sufficient as long as the required block is within that window.
/// For generic IPusher chains the push starts at `buffer_newest + 1`.
#[derive(Debug, Clone)]
pub struct PusherDirection {
	/// Human-readable label used in logs (e.g., "11155111-to-84532").
	pub label: String,
	/// Chain ID of the L1 chain where the pusher contract is deployed.
	pub l1_chain_id: u64,
	/// Address of the IPusher contract on L1.
	pub pusher_address: Address,
	/// Chain ID of the L2 chain that holds the block-hash buffer.
	pub l2_chain_id: u64,
	/// Address of the IBuffer contract on L2.
	pub buffer_address: Address,
	/// Number of block hashes pushed per call.
	/// For Arbitrum: defines the look-back window (`block.number - batch_size`).
	/// For generic chains: number of sequential blocks pushed from the buffer head.
	pub batch_size: u64,
	/// Minimum seconds between consecutive pushes for this direction.
	pub push_cooldown_seconds: u64,
	/// Chain-specific L2 parameters for building the push transaction.
	pub l2_params: PusherL2Params,
}

#[derive(Debug, Clone)]
pub enum WaitingReason {
	Unknown,
	NoSubmissionState,
	WaitingForProofDelay {
		until: u64,
	},
	WaitingForFinality {
		current_block: u64,
		required_block: u64,
	},
	ProofNotCommittedYet,
	ProofServiceNotReady,
	RpcUnavailable,
	StorageUnavailable,
}

#[derive(Debug, Clone)]
pub enum ActionRequired {
	BufferBehind {
		direction: PusherDirection,
		required_block: u64,
	},
}

#[derive(Debug, Clone)]
pub enum SettlementReadiness {
	Ready,
	Waiting(WaitingReason),
	NeedsAction(ActionRequired),
	PermanentFailure(String),
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
#[async_trait]
#[cfg_attr(feature = "testing", mockall::automock)]
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
				let context = selection_context.unwrap_or_else(|| {
					std::time::SystemTime::now()
						.duration_since(std::time::UNIX_EPOCH)
						.map(|d| d.as_nanos() as u64)
						.unwrap_or(0)
				});

				// Stable FNV-1a hash over the context bytes so the same context
				// always maps to the same oracle across calls and processes.
				let mut hash: u64 = 0xcbf29ce484222325;
				for byte in context.to_le_bytes() {
					hash ^= u64::from(byte);
					hash = hash.wrapping_mul(0x00000100000001b3);
				}
				let index = (hash as usize) % oracles.len();
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

	/// Attempts to recover already-submitted post-fill state when local solver state
	/// is missing or incomplete.
	///
	/// Returns `Ok(true)` when the settlement found and reconstructed existing
	/// post-fill state, `Ok(false)` when nothing was recovered, and `Err(...)` for
	/// settlement-specific recovery failures.
	async fn recover_post_fill_state(&self, _order: &Order) -> Result<bool, SettlementError> {
		Ok(false)
	}

	/// Checks if the solver can claim rewards for this fill.
	///
	/// This method should check on-chain conditions such as:
	/// - Time delays or challenge periods
	/// - Oracle attestations if required
	/// - Solver permissions
	/// - Reward availability
	async fn can_claim(&self, order: &Order, fill_proof: &FillProof) -> bool;

	/// Returns detailed settlement readiness information for this order/fill pair.
	///
	/// The default implementation preserves compatibility for settlements that only
	/// implement `can_claim()`.
	async fn readiness(&self, order: &Order, fill_proof: &FillProof) -> SettlementReadiness {
		if self.can_claim(order, fill_proof).await {
			SettlementReadiness::Ready
		} else {
			SettlementReadiness::Waiting(WaitingReason::Unknown)
		}
	}

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

	/// Check whether the L2 block-hash buffer needs to be advanced for this order.
	///
	/// Returns `Some((direction, required_block))` when the settlement knows which
	/// L1→L2 pusher direction corresponds to this order's fill chain and which L1
	/// block number must be present in the L2 buffer before a storage proof can be
	/// generated. Returns `None` (the default) when no buffer push is required.
	async fn buffer_coverage_check(&self, _order: &Order) -> Option<(PusherDirection, u64)> {
		None
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
///
/// Storage is required for Hyperlane implementation to persist message tracker state
/// across restarts. Other implementations may not require storage.
pub type SettlementFactory = fn(
	&serde_json::Value,
	&NetworksConfig,
	Arc<solver_storage::StorageService>,
) -> Result<Box<dyn SettlementInterface>, SettlementError>;

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
	use implementations::{broadcaster, direct, hyperlane};

	vec![
		(direct::Registry::NAME, direct::Registry::factory()),
		(hyperlane::Registry::NAME, hyperlane::Registry::factory()),
		(
			broadcaster::Registry::NAME,
			broadcaster::Registry::factory(),
		),
	]
}

/// Service managing settlement implementations.
pub struct SettlementService {
	/// Map of implementation names to their instances.
	/// Keys are implementation type names (e.g., "direct", "optimistic").
	implementations: HashMap<String, Box<dyn SettlementInterface>>,
	/// The primary settlement implementation name. All new quotes and unbound orders
	/// use this implementation exclusively.
	primary: String,
	/// Track order count for round-robin selection
	selection_counter: Arc<AtomicU64>,
	/// Poll interval for settlement monitoring in seconds
	poll_interval_seconds: u64,
	/// Per-direction cooldown tracking for block-hash pusher.
	/// Shared across all monitor tasks so cooldowns persist across spawns.
	push_cooldowns: Arc<tokio::sync::Mutex<HashMap<String, Instant>>>,
}

impl SettlementService {
	/// Creates a new SettlementService.
	///
	/// # Arguments
	/// * `implementations` - Map of implementation name to instance
	/// * `primary` - Name of the primary settlement implementation
	/// * `poll_interval_seconds` - Poll interval for settlement monitoring
	pub fn new(
		implementations: HashMap<String, Box<dyn SettlementInterface>>,
		primary: String,
		poll_interval_seconds: u64,
	) -> Self {
		Self {
			implementations,
			primary,
			selection_counter: Arc::new(AtomicU64::new(0)),
			poll_interval_seconds,
			push_cooldowns: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
		}
	}

	/// Gets a specific settlement implementation by name.
	///
	/// Returns None if the implementation doesn't exist.
	pub fn get(&self, name: &str) -> Option<&dyn SettlementInterface> {
		self.implementations.get(name).map(|b| b.as_ref())
	}

	/// Get the primary settlement implementation name.
	pub fn primary(&self) -> &str {
		&self.primary
	}

	/// Get the configured poll interval for settlement monitoring
	pub fn poll_interval_seconds(&self) -> u64 {
		self.poll_interval_seconds
	}

	/// Check whether the L2 block-hash buffer needs to be advanced for an order.
	///
	/// Delegates to the settlement implementation bound to this order.
	/// Returns `None` if the order has no associated settlement or the settlement
	/// does not require a buffer push.
	pub async fn buffer_coverage_check(&self, order: &Order) -> Option<(PusherDirection, u64)> {
		self.find_settlement_for_order(order)
			.ok()?
			.buffer_coverage_check(order)
			.await
	}

	/// Push L1 block hashes into an L2 buffer if the buffer is behind the required block.
	///
	/// Delegates to `pusher::push_if_needed` using the service-level cooldown map,
	/// which persists across settlement monitor spawns.
	pub async fn push_if_needed(
		&self,
		direction: &PusherDirection,
		required_block: u64,
		delivery: &Arc<solver_delivery::DeliveryService>,
		networks: &NetworksConfig,
	) {
		pusher::push_if_needed(
			direction,
			required_block,
			delivery,
			networks,
			&self.push_cooldowns,
		)
		.await;
	}

	/// Attempts to recover already-broadcast post-fill state for an order.
	pub async fn recover_post_fill_state(&self, order: &Order) -> Result<bool, SettlementError> {
		self.find_settlement_for_order(order)?
			.recover_post_fill_state(order)
			.await
	}

	/// Returns typed settlement readiness for an order/fill pair.
	pub async fn readiness(&self, order: &Order, fill_proof: &FillProof) -> SettlementReadiness {
		match self.find_settlement_for_order(order) {
			Ok(implementation) => implementation.readiness(order, fill_proof).await,
			Err(e) => SettlementReadiness::PermanentFailure(e.to_string()),
		}
	}

	/// Build oracle routes from the primary settlement implementation.
	///
	/// Only routes supported by the primary settlement are advertised.
	pub fn build_oracle_routes(&self) -> OracleRoutes {
		let mut supported_routes: HashMap<OracleInfo, Vec<OracleInfo>> = HashMap::new();

		let Some(settlement) = self.implementations.get(&self.primary) else {
			return OracleRoutes { supported_routes };
		};
		let config = settlement.oracle_config();

		for (input_chain, input_oracles) in &config.input_oracles {
			for input_oracle in input_oracles {
				let input_info = OracleInfo {
					chain_id: *input_chain,
					oracle: input_oracle.clone(),
				};

				if let Some(dest_chains) = config.routes.get(input_chain) {
					for dest_chain in dest_chains {
						if let Some(output_oracles) = config.output_oracles.get(dest_chain) {
							for output_oracle in output_oracles {
								let output_info = OracleInfo {
									chain_id: *dest_chain,
									oracle: output_oracle.clone(),
								};
								let outputs =
									supported_routes.entry(input_info.clone()).or_default();
								if !outputs.contains(&output_info) {
									outputs.push(output_info);
								}
							}
						}
					}
				}
			}
		}

		OracleRoutes { supported_routes }
	}

	/// Find settlement by oracle address. Searches all implementations for backward
	/// compatibility with persisted orders. Errors if multiple implementations match.
	pub fn get_settlement_for_oracle(
		&self,
		chain_id: u64,
		oracle_address: &Address,
		is_input: bool,
	) -> Result<&dyn SettlementInterface, SettlementError> {
		let mut matches: Vec<&str> = Vec::new();
		let mut matched_settlement: Option<&dyn SettlementInterface> = None;

		for (name, settlement) in &self.implementations {
			let supported = if is_input {
				settlement.is_input_oracle_supported(chain_id, oracle_address)
			} else {
				settlement.is_output_oracle_supported(chain_id, oracle_address)
			};
			if supported {
				matches.push(name.as_str());
				matched_settlement = Some(settlement.as_ref());
			}
		}

		match matches.len() {
			0 => Err(SettlementError::ValidationFailed(format!(
				"No settlement found for {} oracle {} on chain {}",
				if is_input { "input" } else { "output" },
				oracle_address
					.0
					.iter()
					.map(|b| format!("{b:02x}"))
					.collect::<String>(),
				chain_id
			))),
			1 => Ok(matched_settlement.unwrap()),
			_ => Err(SettlementError::ValidationFailed(format!(
				"Ambiguous: multiple settlements ({}) match {} oracle {} on chain {}",
				matches.join(", "),
				if is_input { "input" } else { "output" },
				oracle_address
					.0
					.iter()
					.map(|b| format!("{b:02x}"))
					.collect::<String>(),
				chain_id
			))),
		}
	}

	/// Find settlement for an order based on its persisted settlement name or primary.
	///
	/// If the order has a persisted `settlement_name`, that binding is used to ensure
	/// consistent settlement handling throughout the order lifecycle, even if runtime
	/// configuration changes. Otherwise, uses the primary settlement.
	pub fn find_settlement_for_order(
		&self,
		order: &Order,
	) -> Result<&dyn SettlementInterface, SettlementError> {
		// Prefer persisted settlement name if available (ensures consistent binding)
		if let Some(ref name) = order.settlement_name {
			if let Some(settlement) = self.implementations.get(name) {
				return Ok(settlement.as_ref());
			}
			// Settlement name was persisted but implementation no longer exists.
			// Do NOT fall back: silently routing through a different settlement
			// could produce a wrong proof or double-settle an order.
			return Err(SettlementError::ValidationFailed(format!(
				"Persisted settlement '{name}' for order {} is no longer available; \
				 cannot route through a different implementation",
				order.id
			)));
		}

		// Use primary settlement for unbound orders
		self.implementations
			.get(&self.primary)
			.map(|s| s.as_ref())
			.ok_or_else(|| {
				SettlementError::ValidationFailed(format!(
					"Primary settlement '{}' not found for unbound order {}",
					self.primary, order.id
				))
			})
	}

	/// Get the primary settlement if it supports a given chain (for quote generation).
	/// Returns settlement implementation name, settlement, input oracle, and output oracle.
	pub fn get_any_settlement_for_chain_with_name(
		&self,
		chain_id: u64,
	) -> Option<(&str, &dyn SettlementInterface, Address, Address)> {
		let context = self.selection_counter.fetch_add(1, Ordering::Relaxed);

		let settlement = self.implementations.get(&self.primary)?.as_ref();
		let input_oracles = settlement.oracle_config().input_oracles.get(&chain_id);
		let output_oracles = settlement.oracle_config().output_oracles.get(&chain_id);

		if (input_oracles.is_none() || input_oracles.is_some_and(|oracles| oracles.is_empty()))
			&& (output_oracles.is_none()
				|| output_oracles.is_some_and(|oracles| oracles.is_empty()))
		{
			return None;
		}

		let input_oracle = if let Some(oracles) = input_oracles {
			if !oracles.is_empty() {
				settlement.select_oracle(oracles, Some(context))?
			} else {
				Address(vec![0u8; 20])
			}
		} else {
			Address(vec![0u8; 20])
		};

		let output_oracle = if let Some(oracles) = output_oracles {
			if !oracles.is_empty() {
				settlement.select_oracle(oracles, Some(context + 1))?
			} else {
				Address(vec![0u8; 20])
			}
		} else {
			Address(vec![0u8; 20])
		};

		Some((
			self.primary.as_str(),
			settlement,
			input_oracle,
			output_oracle,
		))
	}

	/// Get any settlement that supports a given chain (for quote generation).
	/// Returns settlement, input oracle, and output oracle for consistency.
	pub fn get_any_settlement_for_chain(
		&self,
		chain_id: u64,
	) -> Option<(&dyn SettlementInterface, Address, Address)> {
		self.get_any_settlement_for_chain_with_name(chain_id).map(
			|(_, settlement, input_oracle, output_oracle)| {
				(settlement, input_oracle, output_oracle)
			},
		)
	}

	/// Get the primary settlement if it supports both origin and destination chains (for cross-chain quote generation).
	/// Returns settlement implementation name, settlement, input oracle for origin chain, and output oracle for destination chain.
	pub fn get_any_settlement_for_chains_with_name(
		&self,
		origin_chain_id: u64,
		destination_chain_id: u64,
	) -> Option<(&str, &dyn SettlementInterface, Address, Address)> {
		let context = self.selection_counter.fetch_add(1, Ordering::Relaxed);

		let settlement = self.implementations.get(&self.primary)?.as_ref();
		let input_oracles = settlement
			.oracle_config()
			.input_oracles
			.get(&origin_chain_id)?;
		let output_oracles = settlement
			.oracle_config()
			.output_oracles
			.get(&destination_chain_id)?;

		if input_oracles.is_empty() || output_oracles.is_empty() {
			return None;
		}
		if !settlement.is_route_supported(origin_chain_id, destination_chain_id) {
			return None;
		}

		let input_oracle = settlement.select_oracle(input_oracles, Some(context))?;
		let output_oracle = settlement.select_oracle(output_oracles, Some(context + 1))?;

		Some((
			self.primary.as_str(),
			settlement,
			input_oracle,
			output_oracle,
		))
	}

	/// Get any settlement that supports both origin and destination chains (for cross-chain quote generation).
	/// Returns settlement, input oracle for origin chain, and output oracle for destination chain.
	pub fn get_any_settlement_for_chains(
		&self,
		origin_chain_id: u64,
		destination_chain_id: u64,
	) -> Option<(&dyn SettlementInterface, Address, Address)> {
		self.get_any_settlement_for_chains_with_name(origin_chain_id, destination_chain_id)
			.map(|(_, settlement, input_oracle, output_oracle)| {
				(settlement, input_oracle, output_oracle)
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

#[cfg(test)]
mod tests {
	use super::*;
	use async_trait::async_trait;
	use solver_types::utils::tests::builders::OrderBuilder;
	use solver_types::{ConfigSchema, TransactionReceipt};

	struct TestSchema;

	impl ConfigSchema for TestSchema {
		fn validate(
			&self,
			_config: &serde_json::Value,
		) -> Result<(), solver_types::ValidationError> {
			Ok(())
		}
	}

	struct TestSettlement {
		config: OracleConfig,
		can_claim: bool,
		attestation: Option<FillProof>,
		attestation_should_fail: bool,
		recover_post_fill: bool,
		recover_post_fill_should_fail: bool,
		readiness_override: Option<SettlementReadiness>,
		buffer_coverage: Option<(PusherDirection, u64)>,
		post_fill_tx: Option<Transaction>,
		pre_claim_tx: Option<Transaction>,
	}

	#[async_trait]
	impl SettlementInterface for TestSettlement {
		fn oracle_config(&self) -> &OracleConfig {
			&self.config
		}

		fn config_schema(&self) -> Box<dyn ConfigSchema> {
			Box::new(TestSchema)
		}

		async fn get_attestation(
			&self,
			_order: &Order,
			_tx_hash: &TransactionHash,
		) -> Result<FillProof, SettlementError> {
			if self.attestation_should_fail {
				return Err(SettlementError::ValidationFailed(
					"attestation failed".to_string(),
				));
			}

			self.attestation
				.clone()
				.ok_or_else(|| SettlementError::ValidationFailed("attestation missing".to_string()))
		}

		async fn can_claim(&self, _order: &Order, _fill_proof: &FillProof) -> bool {
			self.can_claim
		}

		async fn recover_post_fill_state(&self, _order: &Order) -> Result<bool, SettlementError> {
			if self.recover_post_fill_should_fail {
				return Err(SettlementError::ValidationFailed(
					"recovery failed".to_string(),
				));
			}
			Ok(self.recover_post_fill)
		}

		async fn readiness(&self, order: &Order, fill_proof: &FillProof) -> SettlementReadiness {
			if let Some(readiness) = self.readiness_override.clone() {
				readiness
			} else {
				let _ = (order, fill_proof);
				if self.can_claim {
					SettlementReadiness::Ready
				} else {
					SettlementReadiness::Waiting(WaitingReason::Unknown)
				}
			}
		}

		async fn buffer_coverage_check(&self, _order: &Order) -> Option<(PusherDirection, u64)> {
			self.buffer_coverage.clone()
		}

		async fn generate_post_fill_transaction(
			&self,
			_order: &Order,
			_fill_receipt: &TransactionReceipt,
		) -> Result<Option<Transaction>, SettlementError> {
			Ok(self.post_fill_tx.clone())
		}

		async fn generate_pre_claim_transaction(
			&self,
			_order: &Order,
			_fill_proof: &FillProof,
		) -> Result<Option<Transaction>, SettlementError> {
			Ok(self.pre_claim_tx.clone())
		}
	}

	fn addr(byte: u8) -> Address {
		Address(vec![byte; 20])
	}

	fn sample_fill_proof() -> FillProof {
		FillProof {
			tx_hash: TransactionHash(vec![0xaa; 32]),
			block_number: 1,
			attestation_data: None,
			filled_timestamp: 1,
			oracle_address: "0x1234567890123456789012345678901234567890".into(),
		}
	}

	fn sample_tx(chain_id: u64) -> Transaction {
		Transaction {
			to: Some(addr(0x55)),
			data: vec![0xde, 0xad, 0xbe, 0xef],
			value: alloy_primitives::U256::ZERO,
			chain_id,
			nonce: None,
			gas_limit: None,
			gas_price: None,
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
		}
	}

	fn make_test_settlement(config: OracleConfig) -> TestSettlement {
		TestSettlement {
			config,
			can_claim: false,
			attestation: Some(sample_fill_proof()),
			attestation_should_fail: false,
			recover_post_fill: false,
			recover_post_fill_should_fail: false,
			readiness_override: None,
			buffer_coverage: None,
			post_fill_tx: None,
			pre_claim_tx: None,
		}
	}

	#[test]
	fn test_settlement_service_new_empty() {
		let service = SettlementService::new(HashMap::new(), String::new(), 20);
		assert_eq!(service.poll_interval_seconds(), 20);
		assert!(service.primary().is_empty());
	}

	#[test]
	fn test_random_strategy_same_context_same_oracle() {
		let settlement = make_test_settlement(OracleConfig {
			input_oracles: HashMap::new(),
			output_oracles: HashMap::new(),
			routes: HashMap::new(),
			selection_strategy: OracleSelectionStrategy::Random,
		});
		let oracles = vec![addr(1), addr(2), addr(3)];

		let selected = settlement.select_oracle(&oracles, Some(42)).unwrap();
		for _ in 0..1000 {
			assert_eq!(
				selected,
				settlement.select_oracle(&oracles, Some(42)).unwrap()
			);
		}
	}

	#[test]
	fn test_random_strategy_distributes_across_oracles() {
		let settlement = make_test_settlement(OracleConfig {
			input_oracles: HashMap::new(),
			output_oracles: HashMap::new(),
			routes: HashMap::new(),
			selection_strategy: OracleSelectionStrategy::Random,
		});
		let oracles = vec![addr(1), addr(2), addr(3)];
		let mut seen = [false; 3];

		for context in 0u64..10_000 {
			let selected = settlement.select_oracle(&oracles, Some(context)).unwrap();
			let idx = oracles
				.iter()
				.position(|o| o == &selected)
				.expect("selected oracle must come from candidates");
			seen[idx] = true;
			if seen.iter().all(|v| *v) {
				break;
			}
		}

		assert!(
			seen.iter().all(|v| *v),
			"expected all candidate oracles to be selected across contexts"
		);
	}

	#[test]
	fn test_settlement_selection_rejects_unsupported_route() {
		let mut input_oracles = HashMap::new();
		input_oracles.insert(11155420, vec![addr(1)]);
		input_oracles.insert(84532, vec![addr(2)]);
		let mut output_oracles = HashMap::new();
		output_oracles.insert(11155420, vec![addr(3)]);
		output_oracles.insert(84532, vec![addr(4)]);
		let mut routes = HashMap::new();
		routes.insert(84532, vec![11155420]); // reverse only

		let settlement = make_test_settlement(OracleConfig {
			input_oracles,
			output_oracles,
			routes,
			selection_strategy: OracleSelectionStrategy::First,
		});
		let service = SettlementService::new(
			HashMap::from([(
				"test".to_string(),
				Box::new(settlement) as Box<dyn SettlementInterface>,
			)]),
			"test".to_string(),
			20,
		);

		assert!(
			service
				.get_any_settlement_for_chains_with_name(11155420, 84532)
				.is_none(),
			"unsupported route should not be selected"
		);
	}

	#[test]
	fn test_settlement_selection_accepts_supported_route() {
		let mut input_oracles = HashMap::new();
		input_oracles.insert(11155420, vec![addr(1)]);
		let mut output_oracles = HashMap::new();
		output_oracles.insert(84532, vec![addr(4)]);
		let mut routes = HashMap::new();
		routes.insert(11155420, vec![84532]);

		let settlement = make_test_settlement(OracleConfig {
			input_oracles,
			output_oracles,
			routes,
			selection_strategy: OracleSelectionStrategy::First,
		});
		let service = SettlementService::new(
			HashMap::from([(
				"test".to_string(),
				Box::new(settlement) as Box<dyn SettlementInterface>,
			)]),
			"test".to_string(),
			20,
		);

		assert!(
			service
				.get_any_settlement_for_chains_with_name(11155420, 84532)
				.is_some(),
			"supported route should be selected"
		);
	}

	#[test]
	fn test_support_helpers_cover_route_and_oracle_lookups() {
		let settlement = make_test_settlement(OracleConfig {
			input_oracles: HashMap::from([(1u64, vec![addr(0x11)])]),
			output_oracles: HashMap::from([(10u64, vec![addr(0x22)])]),
			routes: HashMap::from([(1u64, vec![10u64])]),
			selection_strategy: OracleSelectionStrategy::First,
		});

		assert!(settlement.is_route_supported(1, 10));
		assert!(!settlement.is_route_supported(10, 1));
		assert!(settlement.is_input_oracle_supported(1, &addr(0x11)));
		assert!(settlement.is_output_oracle_supported(10, &addr(0x22)));
		assert_eq!(settlement.get_input_oracles(1), vec![addr(0x11)]);
		assert_eq!(settlement.get_output_oracles(10), vec![addr(0x22)]);
		assert!(settlement.select_oracle(&[], Some(0)).is_none());
	}

	#[test]
	fn test_round_robin_selection_uses_context() {
		let settlement = make_test_settlement(OracleConfig {
			input_oracles: HashMap::new(),
			output_oracles: HashMap::new(),
			routes: HashMap::new(),
			selection_strategy: OracleSelectionStrategy::RoundRobin,
		});
		let oracles = vec![addr(1), addr(2), addr(3)];

		assert_eq!(settlement.select_oracle(&oracles, Some(0)), Some(addr(1)));
		assert_eq!(settlement.select_oracle(&oracles, Some(1)), Some(addr(2)));
		assert_eq!(settlement.select_oracle(&oracles, Some(2)), Some(addr(3)));
		assert_eq!(settlement.select_oracle(&oracles, Some(3)), Some(addr(1)));
	}

	#[tokio::test]
	async fn test_default_readiness_returns_ready_when_can_claim_is_true() {
		let mut settlement = make_test_settlement(OracleConfig {
			input_oracles: HashMap::new(),
			output_oracles: HashMap::new(),
			routes: HashMap::new(),
			selection_strategy: OracleSelectionStrategy::First,
		});
		settlement.can_claim = true;
		let order = OrderBuilder::new().build();
		let fill_proof = sample_fill_proof();

		let readiness = settlement.readiness(&order, &fill_proof).await;
		assert!(matches!(readiness, SettlementReadiness::Ready));
	}

	#[tokio::test]
	async fn test_default_readiness_returns_unknown_waiting_when_can_claim_is_false() {
		let settlement = make_test_settlement(OracleConfig {
			input_oracles: HashMap::new(),
			output_oracles: HashMap::new(),
			routes: HashMap::new(),
			selection_strategy: OracleSelectionStrategy::First,
		});
		let order = OrderBuilder::new().build();
		let fill_proof = sample_fill_proof();

		let readiness = settlement.readiness(&order, &fill_proof).await;
		assert!(matches!(
			readiness,
			SettlementReadiness::Waiting(WaitingReason::Unknown)
		));
	}

	#[test]
	fn test_find_settlement_for_order_uses_persisted_settlement_name() {
		let settlement = make_test_settlement(OracleConfig {
			input_oracles: HashMap::new(),
			output_oracles: HashMap::new(),
			routes: HashMap::new(),
			selection_strategy: OracleSelectionStrategy::First,
		});
		let service = SettlementService::new(
			HashMap::from([(
				"bound".to_string(),
				Box::new(settlement) as Box<dyn SettlementInterface>,
			)]),
			"bound".to_string(),
			20,
		);
		let order = OrderBuilder::new()
			.with_settlement_name(Some("bound"))
			.build();

		assert!(service.find_settlement_for_order(&order).is_ok());
	}

	#[test]
	fn test_find_settlement_for_order_missing_persisted_settlement_errors() {
		let service = SettlementService::new(HashMap::new(), String::new(), 20);
		let order = OrderBuilder::new()
			.with_settlement_name(Some("missing"))
			.build();

		let err = match service.find_settlement_for_order(&order) {
			Ok(_) => panic!("missing persisted binding should error"),
			Err(err) => err,
		};
		assert!(
			err.to_string().contains("Persisted settlement 'missing'"),
			"unexpected error: {err}"
		);
	}

	#[test]
	fn test_find_settlement_for_order_uses_primary_for_unbound() {
		let settlement = make_test_settlement(OracleConfig {
			input_oracles: HashMap::new(),
			output_oracles: HashMap::new(),
			routes: HashMap::new(),
			selection_strategy: OracleSelectionStrategy::First,
		});
		let service = SettlementService::new(
			HashMap::from([(
				"primary_impl".to_string(),
				Box::new(settlement) as Box<dyn SettlementInterface>,
			)]),
			"primary_impl".to_string(),
			20,
		);
		// Order without settlement_name should use primary
		let order = OrderBuilder::new().build();

		assert!(service.find_settlement_for_order(&order).is_ok());
	}

	#[test]
	fn test_get_returns_bound_settlement() {
		let settlement = make_test_settlement(OracleConfig {
			input_oracles: HashMap::new(),
			output_oracles: HashMap::new(),
			routes: HashMap::new(),
			selection_strategy: OracleSelectionStrategy::First,
		});
		let service = SettlementService::new(
			HashMap::from([(
				"bound".to_string(),
				Box::new(settlement) as Box<dyn SettlementInterface>,
			)]),
			"bound".to_string(),
			20,
		);

		assert!(service.get("bound").is_some());
		assert!(service.get("missing").is_none());
	}

	#[test]
	fn test_get_any_settlement_for_chains_returns_bound_route_and_oracles() {
		let settlement = make_test_settlement(OracleConfig {
			input_oracles: HashMap::from([(1u64, vec![addr(0x11)])]),
			output_oracles: HashMap::from([(10u64, vec![addr(0x22)])]),
			routes: HashMap::from([(1u64, vec![10u64])]),
			selection_strategy: OracleSelectionStrategy::First,
		});
		let service = SettlementService::new(
			HashMap::from([(
				"bound".to_string(),
				Box::new(settlement) as Box<dyn SettlementInterface>,
			)]),
			"bound".to_string(),
			20,
		);

		let (_settlement, input_oracle, output_oracle) =
			service.get_any_settlement_for_chains(1, 10).unwrap();
		assert_eq!(input_oracle, addr(0x11));
		assert_eq!(output_oracle, addr(0x22));
		assert!(service.get_any_settlement_for_chains(10, 1).is_none());
	}

	#[test]
	fn test_build_oracle_routes_uses_primary_only() {
		let a = make_test_settlement(OracleConfig {
			input_oracles: HashMap::from([(1u64, vec![addr(0x11)])]),
			output_oracles: HashMap::from([(10u64, vec![addr(0x21)])]),
			routes: HashMap::from([(1u64, vec![10u64])]),
			selection_strategy: OracleSelectionStrategy::First,
		});
		let b = make_test_settlement(OracleConfig {
			input_oracles: HashMap::from([(1u64, vec![addr(0x11)])]),
			output_oracles: HashMap::from([(10u64, vec![addr(0x22)])]),
			routes: HashMap::from([(1u64, vec![10u64])]),
			selection_strategy: OracleSelectionStrategy::First,
		});
		let service = SettlementService::new(
			HashMap::from([
				("a".to_string(), Box::new(a) as Box<dyn SettlementInterface>),
				("b".to_string(), Box::new(b) as Box<dyn SettlementInterface>),
			]),
			"a".to_string(),
			20,
		);

		let routes = service.build_oracle_routes();
		let outputs = routes
			.supported_routes
			.get(&solver_types::oracle::OracleInfo {
				chain_id: 1,
				oracle: addr(0x11),
			})
			.unwrap();
		// Only primary ("a") routes are advertised
		assert_eq!(outputs.len(), 1);
		assert!(outputs.iter().any(|out| out.oracle == addr(0x21)));
	}

	#[test]
	fn test_get_settlement_for_oracle_supports_input_and_output_lookup() {
		let settlement = make_test_settlement(OracleConfig {
			input_oracles: HashMap::from([(1u64, vec![addr(0x11)])]),
			output_oracles: HashMap::from([(10u64, vec![addr(0x22)])]),
			routes: HashMap::from([(1u64, vec![10u64])]),
			selection_strategy: OracleSelectionStrategy::First,
		});
		let service = SettlementService::new(
			HashMap::from([(
				"test".to_string(),
				Box::new(settlement) as Box<dyn SettlementInterface>,
			)]),
			"test".to_string(),
			20,
		);

		assert!(service
			.get_settlement_for_oracle(1, &addr(0x11), true)
			.is_ok());
		assert!(service
			.get_settlement_for_oracle(10, &addr(0x22), false)
			.is_ok());
		assert!(service
			.get_settlement_for_oracle(10, &addr(0x99), false)
			.is_err());
	}

	#[test]
	fn test_get_any_settlement_for_chain_with_name_uses_available_side() {
		let settlement = make_test_settlement(OracleConfig {
			input_oracles: HashMap::from([(1u64, vec![addr(0x11)])]),
			output_oracles: HashMap::new(),
			routes: HashMap::from([(1u64, vec![10u64])]),
			selection_strategy: OracleSelectionStrategy::First,
		});
		let service = SettlementService::new(
			HashMap::from([(
				"test".to_string(),
				Box::new(settlement) as Box<dyn SettlementInterface>,
			)]),
			"test".to_string(),
			20,
		);

		let (name, _settlement, input_oracle, output_oracle) =
			service.get_any_settlement_for_chain_with_name(1).unwrap();
		assert_eq!(name, "test");
		assert_eq!(input_oracle, addr(0x11));
		assert_eq!(output_oracle, Address(vec![0u8; 20]));
	}

	#[tokio::test]
	async fn test_buffer_coverage_check_recover_readiness_and_can_claim_delegate() {
		let direction = PusherDirection {
			label: "eth-to-arb".into(),
			l1_chain_id: 11155111,
			pusher_address: addr(0x31),
			l2_chain_id: 421614,
			buffer_address: addr(0x32),
			batch_size: 256,
			push_cooldown_seconds: 60,
			l2_params: PusherL2Params::Raw {
				data: "0x".into(),
				value_wei: None,
			},
		};
		let mut settlement = make_test_settlement(OracleConfig {
			input_oracles: HashMap::new(),
			output_oracles: HashMap::new(),
			routes: HashMap::new(),
			selection_strategy: OracleSelectionStrategy::First,
		});
		settlement.buffer_coverage = Some((direction.clone(), 123));
		settlement.recover_post_fill = true;
		settlement.readiness_override = Some(SettlementReadiness::Waiting(
			WaitingReason::ProofServiceNotReady,
		));
		settlement.can_claim = true;
		let service = SettlementService::new(
			HashMap::from([(
				"bound".to_string(),
				Box::new(settlement) as Box<dyn SettlementInterface>,
			)]),
			"bound".to_string(),
			20,
		);
		let order = OrderBuilder::new()
			.with_settlement_name(Some("bound"))
			.build();
		let fill_proof = sample_fill_proof();

		match service.buffer_coverage_check(&order).await {
			Some((actual_direction, actual_block)) => {
				assert_eq!(actual_direction.label, direction.label);
				assert_eq!(actual_direction.l1_chain_id, direction.l1_chain_id);
				assert_eq!(actual_direction.l2_chain_id, direction.l2_chain_id);
				assert_eq!(actual_block, 123);
			},
			None => panic!("expected buffer coverage result"),
		}
		assert!(service.recover_post_fill_state(&order).await.unwrap());
		assert!(matches!(
			service.readiness(&order, &fill_proof).await,
			SettlementReadiness::Waiting(WaitingReason::ProofServiceNotReady)
		));
		assert!(service.can_claim(&order, &fill_proof).await);
	}

	#[tokio::test]
	async fn test_readiness_and_can_claim_handle_missing_settlement_binding() {
		let service = SettlementService::new(HashMap::new(), String::new(), 20);
		let order = OrderBuilder::new()
			.with_settlement_name(Some("missing"))
			.build();
		let fill_proof = sample_fill_proof();

		assert!(matches!(
			service.readiness(&order, &fill_proof).await,
			SettlementReadiness::PermanentFailure(_)
		));
		assert!(!service.can_claim(&order, &fill_proof).await);
		assert!(service.buffer_coverage_check(&order).await.is_none());
	}

	#[tokio::test]
	async fn test_get_attestation_and_transaction_generation_delegate() {
		let mut settlement = make_test_settlement(OracleConfig {
			input_oracles: HashMap::new(),
			output_oracles: HashMap::new(),
			routes: HashMap::new(),
			selection_strategy: OracleSelectionStrategy::First,
		});
		settlement.post_fill_tx = Some(sample_tx(10));
		settlement.pre_claim_tx = Some(sample_tx(11));
		let service = SettlementService::new(
			HashMap::from([(
				"bound".to_string(),
				Box::new(settlement) as Box<dyn SettlementInterface>,
			)]),
			"bound".to_string(),
			20,
		);
		let order = OrderBuilder::new()
			.with_settlement_name(Some("bound"))
			.build();
		let fill_proof = sample_fill_proof();
		let receipt = TransactionReceipt {
			hash: TransactionHash(vec![0x44; 32]),
			block_number: 123,
			success: true,
			logs: vec![],
			block_timestamp: None,
		};

		assert_eq!(
			service
				.get_attestation(&order, &TransactionHash(vec![0x11; 32]))
				.await
				.unwrap()
				.tx_hash,
			sample_fill_proof().tx_hash
		);
		assert_eq!(
			service
				.generate_post_fill_transaction(&order, &receipt)
				.await
				.unwrap()
				.unwrap()
				.chain_id,
			10
		);
		assert_eq!(
			service
				.generate_pre_claim_transaction(&order, &fill_proof)
				.await
				.unwrap()
				.unwrap()
				.chain_id,
			11
		);
	}
}
