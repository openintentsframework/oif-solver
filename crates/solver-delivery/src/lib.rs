//! Transaction delivery module for the OIF solver system.
//!
//! This module handles the submission and monitoring of blockchain transactions.
//! It provides abstractions for different delivery mechanisms across multiple
//! blockchain networks, managing transaction signing, submission, and confirmation.

use alloy_primitives::Bytes;
use async_trait::async_trait;
use solver_types::events::TransactionType;
use solver_types::{
	Address, ChainData, ConfigSchema, ImplementationRegistry, Log, LogFilter, NetworksConfig,
	Transaction, TransactionAttempt, TransactionAttemptStatus, TransactionHash, TransactionReceipt,
};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

/// Re-export implementations
pub mod implementations {
	pub mod evm {
		pub mod alloy;
		pub mod fees;
		pub mod nonce;
		pub mod op_stack;
	}
}

pub mod compact;
pub use compact::fetch_compact_balance;

pub mod revert_classifier;
pub use revert_classifier::{classify_revert, RevertClassification, StageCompleteReason};

#[cfg(test)]
mod transaction_attempt_recorder_tests {
	use super::*;
	use alloy_primitives::U256;
	use solver_types::{Address, TransactionAttemptStatus, TransactionType};
	use std::sync::Arc;

	fn sample_tx() -> Transaction {
		Transaction {
			to: Some(Address(vec![2; 20])),
			data: vec![1, 2, 3],
			value: U256::ZERO,
			chain_id: 8453,
			nonce: Some(11),
			gas_limit: Some(100000),
			gas_price: None,
			max_fee_per_gas: Some(1000),
			max_priority_fee_per_gas: Some(10),
		}
	}

	#[tokio::test]
	async fn noop_recorder_returns_planned_attempt() {
		let recorder = NoopTransactionAttemptRecorder;
		let attempt = recorder
			.record_planned_attempt(PlannedAttemptInit {
				order_id: "order-1".into(),
				signer: Some(Address(vec![9; 20])),
				tx_type: TransactionType::Fill,
				tx: sample_tx(),
				attempt_id_override: None,
				replacement_of: None,
			})
			.await
			.unwrap();

		assert_eq!(attempt.order_id, "order-1");
		assert_eq!(attempt.signer, Some(Address(vec![9; 20])));
		assert_eq!(attempt.tx_type, TransactionType::Fill);
		assert_eq!(attempt.status, TransactionAttemptStatus::Planned);
	}

	#[tokio::test]
	async fn noop_status_update_is_record_and_forget() {
		let recorder = NoopTransactionAttemptRecorder;

		recorder
			.record_attempt_update(
				"attempt-1",
				TransactionAttemptStatus::SubmitRejected,
				None,
				None,
				Some("nonce too low".to_string()),
			)
			.await
			.unwrap();
	}

	#[tokio::test]
	async fn recorder_trait_is_dyn_safe() {
		let recorder: Arc<dyn TransactionAttemptRecorder> =
			Arc::new(NoopTransactionAttemptRecorder);

		let attempt = recorder
			.record_planned_attempt(PlannedAttemptInit {
				order_id: "order-1".into(),
				signer: Some(Address(vec![9; 20])),
				tx_type: TransactionType::Fill,
				tx: sample_tx(),
				attempt_id_override: None,
				replacement_of: None,
			})
			.await
			.unwrap();

		assert_eq!(attempt.order_id, "order-1");
	}
}

/// Errors that can occur during transaction delivery operations.
#[derive(Debug, Error)]
pub enum DeliveryError {
	/// Error that occurs during network communication.
	#[error("Network error: {0}")]
	Network(String),
	/// Error that occurs when a transaction execution fails.
	#[error("Transaction failed: {0}")]
	TransactionFailed(String),
	/// Submission failed with `nonce too low` after a one-shot resync retry.
	/// Callers (e.g. bridge monitor) should treat this as transient nonce drift,
	/// not a business failure: do not increment failure counters.
	#[error("Nonce too low after resync retry: {0}")]
	NonceTooLow(String),
	/// Signer does not have enough native gas token to cover the transaction's
	/// up-front reservation (`gas_limit * fee_per_gas + value`).
	///
	/// Boxed to keep `DeliveryError` small — the struct has 9 fields and would
	/// otherwise make every `Result<_, DeliveryError>` heavy enough to trip
	/// `clippy::result_large_err`.
	#[error(transparent)]
	InsufficientNativeGas(Box<InsufficientNativeGasInfo>),
	/// Error that occurs when no suitable implementation is available for the operation.
	#[error("No implementation available")]
	NoImplementationAvailable,
	/// The submission was rejected by the node because it does not
	/// sufficiently outbid the existing same-nonce tx in the mempool.
	/// Only emitted when the submission was intentionally a same-nonce
	/// replacement (i.e., `TransactionTracking::replacement_of.is_some()`).
	/// Sweeper escalates the bump on next tick by using the rejected
	/// child's fees as the new highest-fee floor.
	#[error("Replacement underpriced: {hint}")]
	ReplacementUnderpriced { hint: String },
}

/// Detailed payload for `DeliveryError::InsufficientNativeGas`. Stored boxed
/// so the parent enum stays small (see `clippy::result_large_err`).
#[derive(Debug, Error)]
#[error(
	"Insufficient native gas on chain {chain_id} for signer {signer}: balance {balance_wei} wei, required {required_wei} wei, shortfall {shortfall_wei} wei"
)]
pub struct InsufficientNativeGasInfo {
	pub chain_id: u64,
	pub signer: String,
	pub balance_wei: String,
	pub required_wei: String,
	pub shortfall_wei: String,
	pub gas_limit: Option<u64>,
	pub max_fee_per_gas: Option<u128>,
	pub gas_price: Option<u128>,
	pub extra_native_fee_wei: String,
	pub value_wei: String,
}

/// Estimated native fee charged outside execution gas, such as OP Stack L1 data fee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraNativeFeeEstimate {
	pub raw_fee_wei: String,
	pub buffer_wei: String,
	pub total_fee_wei: String,
}

impl Default for ExtraNativeFeeEstimate {
	fn default() -> Self {
		Self {
			raw_fee_wei: "0".to_string(),
			buffer_wei: "0".to_string(),
			total_fee_wei: "0".to_string(),
		}
	}
}

/// Errors that can occur while recording transaction attempt ledger rows.
#[derive(Debug, Error)]
pub enum TransactionAttemptRecorderError {
	/// Storage or persistence failure from the recorder implementation.
	#[error("transaction attempt recorder storage error: {0}")]
	Storage(String),
}

/// Carrier for `record_planned_attempt`. Bundles the fields a new attempt
/// row needs at creation time, including `attempt_id_override` (for the
/// bump sweeper to assign a child id up front) and `replacement_of` (for
/// same-nonce lineage tracking).
#[derive(Debug, Clone)]
pub struct PlannedAttemptInit {
	pub order_id: String,
	pub signer: Option<Address>,
	pub tx_type: TransactionType,
	pub tx: Transaction,
	/// When `Some`, the recorder uses this id verbatim; when `None`,
	/// the recorder generates a fresh id (default behavior).
	pub attempt_id_override: Option<String>,
	/// When `Some`, the new row records this as the parent of the
	/// same-nonce lineage; sweeper-only callers set this.
	pub replacement_of: Option<String>,
}

/// Records transaction delivery attempts independently from order lifecycle state.
#[async_trait]
pub trait TransactionAttemptRecorder: Send + Sync {
	async fn record_planned_attempt(
		&self,
		init: PlannedAttemptInit,
	) -> Result<TransactionAttempt, TransactionAttemptRecorderError>;

	async fn record_attempt_update(
		&self,
		attempt_id: &str,
		status: TransactionAttemptStatus,
		tx_hash: Option<TransactionHash>,
		receipt: Option<TransactionReceipt>,
		error: Option<String>,
	) -> Result<(), TransactionAttemptRecorderError>;
}

#[derive(Debug, Default)]
pub struct NoopTransactionAttemptRecorder;

#[async_trait]
impl TransactionAttemptRecorder for NoopTransactionAttemptRecorder {
	async fn record_planned_attempt(
		&self,
		init: PlannedAttemptInit,
	) -> Result<TransactionAttempt, TransactionAttemptRecorderError> {
		let mut attempt = TransactionAttempt::planned(
			init.attempt_id_override
				.unwrap_or_else(|| "noop-attempt".to_string()),
			init.order_id,
			init.signer,
			init.tx_type,
			init.tx,
		);
		attempt.replacement_of = init.replacement_of;
		Ok(attempt)
	}

	async fn record_attempt_update(
		&self,
		attempt_id: &str,
		status: TransactionAttemptStatus,
		tx_hash: Option<TransactionHash>,
		receipt: Option<TransactionReceipt>,
		error: Option<String>,
	) -> Result<(), TransactionAttemptRecorderError> {
		let _ = (attempt_id, status, tx_hash, receipt, error);
		Ok(())
	}
}

/// Fee model used by a chain at transaction submission time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeModel {
	Legacy,
	Eip1559,
}

/// Speed target for EIP-1559 priority fee selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeSpeed {
	SafeLow,
	Average,
	Fast,
	Fastest,
}

impl FeeSpeed {
	pub fn reward_percentile(self) -> f64 {
		match self {
			FeeSpeed::SafeLow => 30.0,
			FeeSpeed::Average => 50.0,
			FeeSpeed::Fast => 85.0,
			FeeSpeed::Fastest => 99.0,
		}
	}
}

/// Quote-cost policy for EIP-1559 chains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeCostStrategy {
	MaxFee,
	Effective,
	#[serde(rename = "buffered_effective_125")]
	BufferedEffective125,
}

/// Effective fee parameters used for both quote costing and transaction submit.
///
/// For EIP-1559, `max_fee_per_gas` is used for submit and native-gas
/// preflight. `cost_per_gas` is the quote-economics value selected by
/// `FeeCostStrategy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeParams {
	pub chain_id: u64,
	pub model: FeeModel,
	pub gas_price: Option<u128>,
	pub base_fee_per_gas: Option<u128>,
	pub estimated_effective_fee_per_gas: Option<u128>,
	pub max_fee_per_gas: Option<u128>,
	pub max_priority_fee_per_gas: Option<u128>,
	pub cost_per_gas: u128,
}

impl FeeParams {
	pub fn legacy(chain_id: u64, gas_price: u128) -> Self {
		Self {
			chain_id,
			model: FeeModel::Legacy,
			gas_price: Some(gas_price),
			base_fee_per_gas: None,
			estimated_effective_fee_per_gas: None,
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
			cost_per_gas: gas_price,
		}
	}

	/// Build EIP-1559 fee params from estimator output (max_fee + priority)
	/// plus the observed base fee, applying the chosen quote-cost strategy.
	/// This is the single solver-specific constructor used by
	/// `SolverEip1559Estimator` and by callers that already have estimator output.
	pub fn eip1559_with_strategy(
		chain_id: u64,
		max_fee_per_gas: u128,
		max_priority_fee_per_gas: u128,
		base_fee_per_gas: u128,
		cost_strategy: FeeCostStrategy,
	) -> Self {
		let effective = base_fee_per_gas.saturating_add(max_priority_fee_per_gas);
		let buffered_base = base_fee_per_gas.saturating_mul(125) / 100;
		let buffered = buffered_base.saturating_add(max_priority_fee_per_gas);
		let cost_per_gas = match cost_strategy {
			FeeCostStrategy::MaxFee => max_fee_per_gas,
			FeeCostStrategy::Effective => effective,
			FeeCostStrategy::BufferedEffective125 => buffered.min(max_fee_per_gas),
		}
		.max(max_priority_fee_per_gas);

		Self {
			chain_id,
			model: FeeModel::Eip1559,
			gas_price: None,
			base_fee_per_gas: Some(base_fee_per_gas),
			estimated_effective_fee_per_gas: Some(effective.min(max_fee_per_gas)),
			max_fee_per_gas: Some(max_fee_per_gas),
			max_priority_fee_per_gas: Some(max_priority_fee_per_gas),
			cost_per_gas,
		}
	}

	/// Fill missing fee fields on a solver-generated transaction.
	///
	/// Explicit caller-provided fee fields win. This avoids breaking custom
	/// paths that intentionally set their own fees.
	pub fn apply_if_missing(&self, tx: &mut Transaction) {
		match self.model {
			FeeModel::Legacy => {
				if tx.gas_price.is_none() {
					tx.gas_price = self.gas_price;
				}
			},
			FeeModel::Eip1559 => {
				if tx.gas_price.is_none() {
					tx.max_fee_per_gas = tx.max_fee_per_gas.or(self.max_fee_per_gas);
					tx.max_priority_fee_per_gas = tx
						.max_priority_fee_per_gas
						.or(self.max_priority_fee_per_gas);
				}
			},
		}
	}
}

/// Callback for transaction monitoring events
pub type TransactionCallback = Box<dyn Fn(TransactionMonitoringEvent) + Send + Sync>;

/// Events emitted during transaction monitoring
#[derive(Debug, Clone)]
pub enum TransactionMonitoringEvent {
	/// Transaction was successfully confirmed
	Confirmed {
		id: String, // order_id in case of intents
		tx_hash: TransactionHash,
		tx_type: TransactionType,
		receipt: TransactionReceipt,
	},
	/// Transaction failed or was reverted
	Failed {
		id: String, // order_id in case of intents
		tx_hash: TransactionHash,
		tx_type: TransactionType,
		error: String,
		/// Classification of the revert payload. `StageComplete` indicates
		/// the stage may already be done on-chain (caller should defer to
		/// recovery for chain confirmation); `Terminal` and `Unknown` both
		/// indicate stage failure and should terminalize the order through
		/// the existing flow.
		classification: RevertClassification,
	},
	/// Live confirmation watcher gave up before reaching `min_confirmations`.
	/// The transaction's on-chain status is unknown to the monitor — it may
	/// have confirmed after the deadline, or may have been dropped. The order
	/// MUST stay in its current status; startup recovery will reconcile via
	/// direct chain query.
	Indeterminate {
		id: String, // order_id in case of intents
		tx_hash: TransactionHash,
		tx_type: TransactionType,
		reason: String,
	},
	/// Attempt ledger rejected a chain-truth/status write that the delivery
	/// layer attempted after observing a transaction outcome.
	AttemptLedgerConflict {
		id: String,
		attempt_id: String,
		tx_type: TransactionType,
		tx_hash: Option<TransactionHash>,
		attempted_status: TransactionAttemptStatus,
		error: String,
		context: &'static str,
	},
}

/// Options for tracking transaction confirmation
pub struct TransactionTracking {
	/// Unique identifier for the transaction (e.g. order_id)
	pub id: String,
	/// Type of transaction being submitted
	pub tx_type: TransactionType,
	/// Records durable delivery attempts for this tracked transaction.
	pub attempt_recorder: Arc<dyn TransactionAttemptRecorder>,
	/// Callback to invoke when transaction state changes
	pub callback: TransactionCallback,
	/// Pre-allocated attempt id. If `Some`, the recorder uses this id
	/// verbatim via `PlannedAttemptInit::attempt_id_override`. The bump
	/// sweeper sets this so it knows the child id before `deliver()`
	/// returns. Not serialized (struct holds Arc<dyn ...> + closure);
	/// default `None` at normal construction.
	pub attempt_id: Option<String>,
	/// Parent attempt id when this submission is a same-nonce replacement.
	/// Threaded into the new attempt row's `replacement_of` field, AND
	/// gates classification of `DeliveryError::ReplacementUnderpriced`
	/// (only emitted when this is `Some`).
	pub replacement_of: Option<String>,
}

impl std::fmt::Debug for TransactionTracking {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("TransactionTracking")
			.field("id", &self.id)
			.field("tx_type", &self.tx_type)
			.finish()
	}
}

/// Extended tracking options with service configuration
#[derive(Debug)]
pub struct TransactionTrackingWithConfig {
	/// Base tracking options
	pub tracking: TransactionTracking,
	/// Minimum confirmations required before considering transaction confirmed
	pub min_confirmations: u64,
	/// Timeout in seconds for settlement-readiness monitoring (long window).
	pub monitoring_timeout_seconds: u64,
	/// Timeout in seconds for live tx-confirmation polling (short window).
	/// Distinct from `monitoring_timeout_seconds`; see `DeliveryConfig`.
	pub tx_confirmation_timeout_seconds: u64,
}

#[cfg(test)]
mod tracking_config_tests {
	use super::{
		NoopTransactionAttemptRecorder, TransactionMonitoringEvent, TransactionTracking,
		TransactionTrackingWithConfig,
	};
	use solver_types::TransactionType;
	use std::sync::Arc;

	#[test]
	fn tracking_debug_omits_attempt_recorder() {
		let tracking = TransactionTracking {
			id: "test-order-123".to_string(),
			tx_type: TransactionType::Fill,
			attempt_recorder: Arc::new(NoopTransactionAttemptRecorder),
			callback: Box::new(|_: TransactionMonitoringEvent| {}),
			attempt_id: None,
			replacement_of: None,
		};

		let config = TransactionTrackingWithConfig {
			tracking,
			min_confirmations: 3,
			monitoring_timeout_seconds: 300,
			tx_confirmation_timeout_seconds: 600,
		};

		assert_eq!(config.min_confirmations, 3);
		assert_eq!(config.monitoring_timeout_seconds, 300);
		assert_eq!(config.tx_confirmation_timeout_seconds, 600);
		assert_eq!(config.tracking.id, "test-order-123");

		let debug = format!("{:?}", config.tracking);
		assert!(debug.contains("test-order-123"));
		assert!(debug.contains("Fill"));
		assert!(!debug.contains("attempt_recorder"));
	}
}

/// Trait defining the interface for transaction delivery implementations.
///
/// This trait must be implemented by any delivery implementation that wants to
/// integrate with the solver system. It provides methods for submitting
/// transactions and monitoring their confirmation status.
#[async_trait]
#[cfg_attr(feature = "testing", mockall::automock)]
pub trait DeliveryInterface: Send + Sync {
	/// Returns the configuration schema for this delivery implementation.
	///
	/// This allows each implementation to define its own configuration requirements
	/// with specific validation rules. The schema is used to validate TOML configuration
	/// before initializing the delivery implementation.
	fn config_schema(&self) -> Box<dyn ConfigSchema>;

	/// Signs and submits a transaction to the blockchain.
	///
	/// Takes a transaction, signs it with the appropriate signer for the chain,
	/// then submits it to the network and returns the transaction hash.
	///
	/// If tracking is provided, monitors the transaction for confirmation/failure
	/// and calls the callback when the transaction state changes.
	async fn submit(
		&self,
		tx: Transaction,
		tracking: Option<TransactionTrackingWithConfig>,
	) -> Result<TransactionHash, DeliveryError>;

	/// Retrieves the receipt for a transaction if available.
	///
	/// Returns immediately with the current transaction receipt, or an error
	/// if the transaction is not found or not yet mined.
	async fn get_receipt(
		&self,
		hash: &TransactionHash,
		chain_id: u64,
	) -> Result<TransactionReceipt, DeliveryError>;

	/// Gets effective fee parameters for quote costing, rebalance costing, and transaction submission.
	///
	/// This should return the same fee model and per-gas cost the implementation
	/// will use when filling missing fee fields before signing a transaction.
	async fn get_fee_params(&self, chain_id: u64) -> Result<FeeParams, DeliveryError>;

	/// Estimates native fees that are charged outside execution gas for this transaction.
	///
	/// Backends without an extra native fee model return zero by default.
	async fn estimate_extra_native_fee(
		&self,
		_chain_id: u64,
		_tx: &Transaction,
	) -> Result<ExtraNativeFeeEstimate, DeliveryError> {
		Ok(ExtraNativeFeeEstimate::default())
	}

	/// Returns the address this backend would use to sign a transaction
	/// submitted on `chain_id` right now. `None` when the backend has
	/// no configured signer for this chain. Synchronous; no RPC.
	///
	/// Used by the bump sweeper to enforce the same-signer invariant
	/// before dispatching a replacement: replacements from a different
	/// signer don't share a nonce sequence on chain.
	///
	/// Default returns `None` so non-EVM and mock backends don't have
	/// to implement it.
	fn submission_signer(&self, _chain_id: u64) -> Option<Address> {
		None
	}

	/// Gets the balance for an address.
	///
	/// For native tokens, pass None for the token parameter.
	/// For ERC-20 tokens, pass the contract address as Some(address).
	/// Returns the balance as a decimal string.
	async fn get_balance(
		&self,
		address: &str,
		token: Option<&str>,
		chain_id: u64,
	) -> Result<String, DeliveryError>;

	/// Gets the ERC-20 token allowance for an owner-spender pair.
	///
	/// Returns the amount of tokens that the spender is allowed to transfer
	/// on behalf of the owner, as a decimal string.
	async fn get_allowance(
		&self,
		owner: &str,
		spender: &str,
		token_address: &str,
		chain_id: u64,
	) -> Result<String, DeliveryError>;

	/// Gets the current nonce for an address.
	///
	/// Returns the next valid nonce for transaction submission.
	async fn get_nonce(&self, address: &str, chain_id: u64) -> Result<u64, DeliveryError>;

	/// Gets the current block number.
	///
	/// Returns the latest block number on the network.
	async fn get_block_number(&self, chain_id: u64) -> Result<u64, DeliveryError>;

	/// Estimates gas units for a transaction without submitting it.
	/// Implementations should call the chain's estimateGas RPC with the provided transaction.
	async fn estimate_gas(&self, tx: Transaction) -> Result<u64, DeliveryError>;

	/// Estimate gas with a `stateOverride` applied (Alchemy/Geth/Erigon/Reth).
	/// Use to simulate calls that depend on contract state that doesn't
	/// yet exist (e.g. a quote-time post-fill simulation that needs a
	/// fake fill record). No default impl — every backend explicitly
	/// declares whether it supports overrides.
	async fn estimate_gas_with_overrides(
		&self,
		tx: Transaction,
		state_override: alloy_rpc_types::state::StateOverride,
	) -> Result<u64, DeliveryError>;

	/// Executes a contract call without sending a transaction.
	///
	/// This performs an eth_call RPC to read data from smart contracts
	/// or simulate transaction execution without submitting to the blockchain.
	async fn eth_call(&self, tx: Transaction) -> Result<Bytes, DeliveryError>;

	/// Replays the given transaction via `eth_call` at the specified block and
	/// returns the revert payload (4-byte selector + ABI-encoded args) if the
	/// replay reverts. Returns `Ok(None)` if the replay succeeds (unexpected
	/// when the caller already saw `success=false` — can happen after a reorg),
	/// if the backend cannot extract structured revert data, or if this
	/// backend does not support replay.
	///
	/// `from` carries the original signer. It is REQUIRED for OIF settler
	/// reverts because finalise/claim paths perform permission checks against
	/// `msg.sender`; replaying without the matching caller can produce a
	/// different selector. Pass `attempt.signer` from the transaction-attempt
	/// ledger.
	///
	/// Default implementation returns `Ok(None)` so backends that can't replay
	/// (test mocks, recorders, non-EVM backends) compile out-of-the-box.
	/// Callers MUST treat `Ok(None)` as `Unknown` classification (i.e.,
	/// preserve today's `Failed(stage)` behavior).
	async fn get_revert_data(
		&self,
		_chain_id: u64,
		_tx: Transaction,
		_from: Option<Address>,
		_block: u64,
	) -> Result<Option<Vec<u8>>, DeliveryError> {
		Ok(None)
	}

	/// Checks whether a transaction exists in the mempool or on-chain.
	///
	/// Returns `Ok(true)` if the tx is visible (pending or mined), `Ok(false)` if
	/// the node has no record of it (dropped/evicted).
	async fn tx_exists(&self, hash: &TransactionHash, chain_id: u64)
		-> Result<bool, DeliveryError>;

	/// Queries event logs matching the given filter.
	///
	/// Used for scanning chain events (e.g., detecting token arrivals on destination chain).
	async fn get_logs(&self, chain_id: u64, filter: LogFilter) -> Result<Vec<Log>, DeliveryError>;
}

/// Type alias for delivery factory functions.
///
/// This is the function signature that all delivery implementations must provide
/// to create instances of their delivery interface.
pub type DeliveryFactory = fn(
	&serde_json::Value,
	&NetworksConfig,
	&solver_account::AccountSigner, // Default/primary signer
	&HashMap<u64, solver_account::AccountSigner>, // Per-network signers
) -> Result<Box<dyn DeliveryInterface>, DeliveryError>;

/// Registry trait for delivery implementations.
///
/// This trait extends the base ImplementationRegistry to specify that
/// delivery implementations must provide a DeliveryFactory.
pub trait DeliveryRegistry: ImplementationRegistry<Factory = DeliveryFactory> {}

/// Get all registered delivery implementations.
///
/// Returns a vector of (name, factory) tuples for all available delivery implementations.
/// This is used by the factory registry to automatically register all implementations.
pub fn get_all_implementations() -> Vec<(&'static str, DeliveryFactory)> {
	use implementations::evm::alloy;

	vec![(alloy::Registry::NAME, alloy::Registry::factory())]
}

/// Service that manages transaction delivery across multiple blockchain networks.
///
/// The DeliveryService coordinates between different delivery implementations based on
/// chain ID and provides methods for transaction submission and confirmation monitoring.
pub struct DeliveryService {
	/// Map of chain IDs to their corresponding delivery implementations.
	implementations: std::collections::HashMap<u64, Arc<dyn DeliveryInterface>>,
	/// Default number of confirmations required for transactions.
	min_confirmations: u64,
	/// Timeout for settlement-readiness monitoring in seconds (long window).
	monitoring_timeout_seconds: u64,
	/// Timeout for live tx-confirmation polling in seconds (short window).
	tx_confirmation_timeout_seconds: u64,
}

impl DeliveryService {
	/// Creates a new DeliveryService with the specified implementations and configuration.
	///
	/// The implementations map should contain delivery implementations for each supported
	/// chain ID.
	pub fn new(
		implementations: std::collections::HashMap<u64, Arc<dyn DeliveryInterface>>,
		min_confirmations: u64,
		monitoring_timeout_seconds: u64,
		tx_confirmation_timeout_seconds: u64,
	) -> Self {
		Self {
			implementations,
			min_confirmations,
			monitoring_timeout_seconds,
			tx_confirmation_timeout_seconds,
		}
	}

	/// Delivers a transaction to the appropriate blockchain network.
	///
	/// This method:
	/// 1. Selects the appropriate implementation based on the transaction's chain ID
	/// 2. Submits the transaction through the implementation (which handles signing)
	///
	/// If tracking is provided, monitors the transaction for confirmation/failure.
	pub async fn deliver(
		&self,
		tx: Transaction,
		tracking: Option<TransactionTracking>,
	) -> Result<TransactionHash, DeliveryError> {
		// Get the implementation for the transaction's chain ID
		let implementation = self
			.implementations
			.get(&tx.chain_id)
			.ok_or(DeliveryError::NoImplementationAvailable)?;

		// Submit using the chain-specific implementation (which handles signing)
		// If tracking is provided, add our service configuration
		let enhanced_tracking = tracking.map(|t| TransactionTrackingWithConfig {
			tracking: t,
			min_confirmations: self.min_confirmations,
			monitoring_timeout_seconds: self.monitoring_timeout_seconds,
			tx_confirmation_timeout_seconds: self.tx_confirmation_timeout_seconds,
		});
		implementation.submit(tx, enhanced_tracking).await
	}

	/// Gets the transaction receipt for a given transaction hash.
	///
	/// Returns the full transaction receipt including status, block number, logs, etc.
	pub async fn get_receipt(
		&self,
		hash: &TransactionHash,
		chain_id: u64,
	) -> Result<TransactionReceipt, DeliveryError> {
		let implementation = self
			.implementations
			.get(&chain_id)
			.ok_or(DeliveryError::NoImplementationAvailable)?;

		implementation.get_receipt(hash, chain_id).await
	}

	/// Checks the current status of a transaction on a specific chain.
	///
	/// Returns true if the transaction was successful, false if it failed.
	pub async fn get_status(
		&self,
		hash: &TransactionHash,
		chain_id: u64,
	) -> Result<bool, DeliveryError> {
		let receipt = self.get_receipt(hash, chain_id).await?;
		Ok(receipt.success)
	}

	/// Replays a transaction via `eth_call` at the given block and returns the
	/// revert payload bytes on revert. See `DeliveryInterface::get_revert_data`
	/// for the contract: backends without replay support return `Ok(None)`,
	/// which callers must treat as Unknown classification.
	pub async fn get_revert_data(
		&self,
		chain_id: u64,
		tx: Transaction,
		from: Option<Address>,
		block: u64,
	) -> Result<Option<Vec<u8>>, DeliveryError> {
		let implementation = self
			.implementations
			.get(&chain_id)
			.ok_or(DeliveryError::NoImplementationAvailable)?;

		implementation
			.get_revert_data(chain_id, tx, from, block)
			.await
	}

	/// Gets chain-specific data for the given chain ID.
	///
	/// Returns the resolved per-gas quote-cost (sourced from
	/// [`FeeParams::cost_per_gas`]), block number, and other chain state
	/// information. The `gas_price` field is no longer raw `eth_gasPrice`;
	/// it now reflects the same `cost_per_gas` value used to price quote
	/// economics so consumers comparing it against their own gas cap stay
	/// conservative.
	pub async fn get_chain_data(&self, chain_id: u64) -> Result<ChainData, DeliveryError> {
		let implementation = self
			.implementations
			.get(&chain_id)
			.ok_or(DeliveryError::NoImplementationAvailable)?;

		let gas_price = implementation
			.get_fee_params(chain_id)
			.await?
			.cost_per_gas
			.to_string();
		let block_number = implementation.get_block_number(chain_id).await?;

		Ok(ChainData {
			chain_id,
			gas_price,
			block_number,
			timestamp: std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.unwrap_or_default()
				.as_secs(),
		})
	}

	/// Returns the chain's configured submission signer, or `None` if no
	/// backend is registered for `chain_id` OR the backend doesn't expose
	/// a signer.
	pub fn submission_signer(&self, chain_id: u64) -> Option<Address> {
		self.implementations
			.get(&chain_id)
			.and_then(|impl_| impl_.submission_signer(chain_id))
	}

	/// Gets the balance for an address on a specific chain.
	///
	/// Convenience method that routes to the appropriate implementation.
	pub async fn get_balance(
		&self,
		chain_id: u64,
		address: &str,
		token: Option<&str>,
	) -> Result<String, DeliveryError> {
		let implementation = self
			.implementations
			.get(&chain_id)
			.ok_or(DeliveryError::NoImplementationAvailable)?;

		implementation.get_balance(address, token, chain_id).await
	}

	/// Gets the nonce for an address on a specific chain.
	///
	/// Convenience method that routes to the appropriate implementation.
	pub async fn get_nonce(&self, chain_id: u64, address: &str) -> Result<u64, DeliveryError> {
		let implementation = self
			.implementations
			.get(&chain_id)
			.ok_or(DeliveryError::NoImplementationAvailable)?;

		implementation.get_nonce(address, chain_id).await
	}

	/// Gets the ERC-20 token allowance for an owner-spender pair on a specific chain.
	///
	/// Convenience method that routes to the appropriate implementation.
	pub async fn get_allowance(
		&self,
		chain_id: u64,
		owner: &str,
		spender: &str,
		token_address: &str,
	) -> Result<String, DeliveryError> {
		let implementation = self
			.implementations
			.get(&chain_id)
			.ok_or(DeliveryError::NoImplementationAvailable)?;

		implementation
			.get_allowance(owner, spender, token_address, chain_id)
			.await
	}

	/// Gets effective fee parameters for a specific chain.
	///
	/// Returns the same fee params used by the implementation to fill missing
	/// fee fields before signing. Use `cost_per_gas` for quote economics and
	/// `max_fee_per_gas` for native-gas preflight.
	pub async fn get_fee_params(&self, chain_id: u64) -> Result<FeeParams, DeliveryError> {
		let implementation = self
			.implementations
			.get(&chain_id)
			.ok_or(DeliveryError::NoImplementationAvailable)?;

		implementation.get_fee_params(chain_id).await
	}

	/// Estimates native fees that are charged outside execution gas for a transaction.
	pub async fn estimate_extra_native_fee(
		&self,
		chain_id: u64,
		tx: &Transaction,
	) -> Result<ExtraNativeFeeEstimate, DeliveryError> {
		let implementation = self
			.implementations
			.get(&chain_id)
			.ok_or(DeliveryError::NoImplementationAvailable)?;

		implementation.estimate_extra_native_fee(chain_id, tx).await
	}

	/// Gets the current block number for a specific chain.
	///
	/// Returns the latest block number.
	pub async fn get_block_number(&self, chain_id: u64) -> Result<u64, DeliveryError> {
		let implementation = self
			.implementations
			.get(&chain_id)
			.ok_or(DeliveryError::NoImplementationAvailable)?;

		implementation.get_block_number(chain_id).await
	}

	/// Estimates gas for a transaction on the specified chain.
	pub async fn estimate_gas(&self, chain_id: u64, tx: Transaction) -> Result<u64, DeliveryError> {
		let implementation = self
			.implementations
			.get(&chain_id)
			.ok_or(DeliveryError::NoImplementationAvailable)?;

		implementation.estimate_gas(tx).await
	}

	/// Estimates gas for a transaction on the specified chain with a
	/// `stateOverride` applied. Used to simulate calls whose execution
	/// depends on state that doesn't yet exist on chain (e.g. a fake
	/// post-fill record when quoting). The `chain_id` is used only to
	/// pick the backend; the backend itself routes via `tx.chain_id`.
	pub async fn estimate_gas_with_overrides(
		&self,
		chain_id: u64,
		tx: Transaction,
		state_override: alloy_rpc_types::state::StateOverride,
	) -> Result<u64, DeliveryError> {
		let implementation = self
			.implementations
			.get(&chain_id)
			.ok_or(DeliveryError::NoImplementationAvailable)?;

		implementation
			.estimate_gas_with_overrides(tx, state_override)
			.await
	}

	/// Executes a contract call (eth_call) without sending a transaction.
	///
	/// This method is used to read data from smart contracts or simulate
	/// transaction execution without actually submitting to the blockchain.
	/// Returns the raw bytes returned by the contract call.
	pub async fn contract_call(
		&self,
		chain_id: u64,
		tx: Transaction,
	) -> Result<alloy_primitives::Bytes, DeliveryError> {
		let implementation = self
			.implementations
			.get(&chain_id)
			.ok_or(DeliveryError::NoImplementationAvailable)?;

		implementation.eth_call(tx).await
	}

	/// Checks whether a transaction exists in the mempool or on-chain.
	pub async fn tx_exists(
		&self,
		hash: &TransactionHash,
		chain_id: u64,
	) -> Result<bool, DeliveryError> {
		let implementation = self
			.implementations
			.get(&chain_id)
			.ok_or(DeliveryError::NoImplementationAvailable)?;

		implementation.tx_exists(hash, chain_id).await
	}

	/// Queries event logs matching the given filter on a specific chain.
	pub async fn get_logs(
		&self,
		chain_id: u64,
		filter: LogFilter,
	) -> Result<Vec<Log>, DeliveryError> {
		let implementation = self
			.implementations
			.get(&chain_id)
			.ok_or(DeliveryError::NoImplementationAvailable)?;

		implementation.get_logs(chain_id, filter).await
	}
}

#[cfg(test)]
mod fee_param_tests {
	use super::*;
	use alloy_primitives::U256;

	fn empty_tx(chain_id: u64) -> Transaction {
		Transaction {
			to: None,
			data: vec![],
			value: U256::ZERO,
			chain_id,
			nonce: None,
			gas_limit: Some(100_000),
			gas_price: None,
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
		}
	}

	#[test]
	fn apply_if_missing_legacy_fills_gas_price() {
		let params = FeeParams::legacy(137, 5_000_000_000);
		let mut tx = empty_tx(137);
		params.apply_if_missing(&mut tx);
		assert_eq!(tx.gas_price, Some(5_000_000_000));
		assert_eq!(tx.max_fee_per_gas, None);
		assert_eq!(tx.max_priority_fee_per_gas, None);
	}

	#[test]
	fn apply_if_missing_legacy_does_not_override_explicit_gas_price() {
		let params = FeeParams::legacy(137, 5_000_000_000);
		let mut tx = empty_tx(137);
		tx.gas_price = Some(9_999);
		params.apply_if_missing(&mut tx);
		assert_eq!(tx.gas_price, Some(9_999));
	}

	#[test]
	fn apply_if_missing_eip1559_fills_max_and_priority() {
		let params = FeeParams::eip1559_with_strategy(
			1,
			3_000_000_000,
			2_000_000_000,
			500_000_000,
			FeeCostStrategy::BufferedEffective125,
		);
		let mut tx = empty_tx(1);
		params.apply_if_missing(&mut tx);
		assert_eq!(tx.max_fee_per_gas, Some(3_000_000_000));
		assert_eq!(tx.max_priority_fee_per_gas, Some(2_000_000_000));
		assert_eq!(tx.gas_price, None);
	}

	#[test]
	fn apply_if_missing_eip1559_does_not_override_explicit_fees() {
		let params = FeeParams::eip1559_with_strategy(
			1,
			3_000_000_000,
			2_000_000_000,
			500_000_000,
			FeeCostStrategy::BufferedEffective125,
		);
		let mut tx = empty_tx(1);
		tx.max_fee_per_gas = Some(7_777);
		tx.max_priority_fee_per_gas = Some(8_888);
		params.apply_if_missing(&mut tx);
		assert_eq!(tx.max_fee_per_gas, Some(7_777));
		assert_eq!(tx.max_priority_fee_per_gas, Some(8_888));
	}

	#[test]
	fn fee_params_apply_eip1559_to_empty_transaction() {
		let mut tx = Transaction {
			chain_id: 1,
			to: None,
			data: vec![],
			value: U256::ZERO,
			nonce: None,
			gas_limit: Some(21_000),
			gas_price: None,
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
		};

		let params = FeeParams::eip1559_with_strategy(
			1,
			2_500_000_000, // max_fee
			2_000_000_000, // priority
			500_000_000,   // base_fee
			FeeCostStrategy::BufferedEffective125,
		);
		params.apply_if_missing(&mut tx);

		assert_eq!(tx.gas_price, None);
		assert_eq!(tx.max_fee_per_gas, Some(2_500_000_000));
		assert_eq!(tx.max_priority_fee_per_gas, Some(2_000_000_000));
	}

	#[test]
	fn fee_params_do_not_override_explicit_transaction_fees() {
		let mut tx = Transaction {
			chain_id: 1,
			to: None,
			data: vec![],
			value: U256::ZERO,
			nonce: None,
			gas_limit: Some(21_000),
			gas_price: None,
			max_fee_per_gas: Some(9),
			max_priority_fee_per_gas: Some(3),
		};

		let params = FeeParams::eip1559_with_strategy(
			1,
			2_500_000_000, // max_fee
			2_000_000_000, // priority
			500_000_000,   // base_fee
			FeeCostStrategy::BufferedEffective125,
		);
		params.apply_if_missing(&mut tx);

		assert_eq!(tx.max_fee_per_gas, Some(9));
		assert_eq!(tx.max_priority_fee_per_gas, Some(3));
	}

	#[test]
	fn apply_if_missing_eip1559_skipped_when_legacy_gas_price_set() {
		// If a caller has chosen legacy gas_price explicitly, don't backfill 1559 fields.
		let params = FeeParams::eip1559_with_strategy(
			1,
			3_000_000_000,
			2_000_000_000,
			500_000_000,
			FeeCostStrategy::BufferedEffective125,
		);
		let mut tx = empty_tx(1);
		tx.gas_price = Some(123);
		params.apply_if_missing(&mut tx);
		assert_eq!(tx.gas_price, Some(123));
		assert_eq!(tx.max_fee_per_gas, None);
		assert_eq!(tx.max_priority_fee_per_gas, None);
	}

	#[test]
	fn cost_strategy_max_fee_returns_max() {
		let p = FeeParams::eip1559_with_strategy(
			1,
			5_000_000_000,
			2_000_000_000,
			1_000_000_000,
			FeeCostStrategy::MaxFee,
		);
		assert_eq!(p.cost_per_gas, 5_000_000_000);
	}

	#[test]
	fn cost_strategy_effective_returns_base_plus_priority() {
		let p = FeeParams::eip1559_with_strategy(
			1,
			5_000_000_000,
			2_000_000_000,
			1_000_000_000,
			FeeCostStrategy::Effective,
		);
		assert_eq!(p.cost_per_gas, 1_000_000_000 + 2_000_000_000);
	}

	#[test]
	fn cost_strategy_buffered_returns_125_base_plus_priority() {
		let p = FeeParams::eip1559_with_strategy(
			1,
			5_000_000_000,
			2_000_000_000,
			1_000_000_000,
			FeeCostStrategy::BufferedEffective125,
		);
		// 1.25 * 1_000_000_000 + 2_000_000_000 = 3_250_000_000
		assert_eq!(p.cost_per_gas, 3_250_000_000);
	}

	#[test]
	fn cost_strategy_buffered_caps_at_max_fee() {
		// Buffered would exceed max_fee — should be capped.
		let p = FeeParams::eip1559_with_strategy(
			1,
			3_000_000_000,
			2_000_000_000,
			10_000_000_000,
			FeeCostStrategy::BufferedEffective125,
		);
		assert_eq!(p.cost_per_gas, 3_000_000_000);
	}
}

#[cfg(test)]
mod fee_param_proptests {
	use super::*;
	use alloy_primitives::U256;
	use proptest::prelude::*;

	fn arb_bytes(max_len: usize) -> impl Strategy<Value = Vec<u8>> {
		prop::collection::vec(any::<u8>(), 0..=max_len)
	}

	proptest! {
		#[test]
		fn apply_if_missing_preserves_contract_call_fields(
			chain_id in 1u64..10_000_000u64,
			data in arb_bytes(512),
			value in 0u128..1_000_000_000_000_000_000u128,
			gas_limit in prop::option::of(21_000u64..5_000_000u64),
			max_fee in 1u128..1_000_000_000_000u128,
			priority in 0u128..100_000_000_000u128,
		) {
			let priority = priority.min(max_fee);
			let mut tx = Transaction {
				to: None,
				data: data.clone(),
				value: U256::from(value),
				chain_id,
				nonce: None,
				gas_limit,
				gas_price: None,
				max_fee_per_gas: None,
				max_priority_fee_per_gas: None,
			};
			let original = tx.clone();

			FeeParams::eip1559_with_strategy(
				chain_id,
				max_fee,
				priority,
				1_000_000_000,
				FeeCostStrategy::BufferedEffective125,
			)
			.apply_if_missing(&mut tx);

			prop_assert_eq!(tx.to, original.to);
			prop_assert_eq!(tx.data, original.data);
			prop_assert_eq!(tx.value, original.value);
			prop_assert_eq!(tx.chain_id, original.chain_id);
			prop_assert_eq!(tx.gas_limit, original.gas_limit);
		}

		#[test]
		fn apply_if_missing_is_idempotent(
			chain_id in 1u64..10_000_000u64,
			max_fee in 1u128..1_000_000_000_000u128,
			priority in 0u128..100_000_000_000u128,
		) {
			let priority = priority.min(max_fee);
			let params = FeeParams::eip1559_with_strategy(
				chain_id,
				max_fee,
				priority,
				1_000_000_000,
				FeeCostStrategy::BufferedEffective125,
			);
			let mut once = Transaction {
				to: None,
				data: vec![1, 2, 3],
				value: U256::ZERO,
				chain_id,
				nonce: None,
				gas_limit: Some(100_000),
				gas_price: None,
				max_fee_per_gas: None,
				max_priority_fee_per_gas: None,
			};
			let mut twice = once.clone();

			params.apply_if_missing(&mut once);
			params.apply_if_missing(&mut twice);
			params.apply_if_missing(&mut twice);

			prop_assert_eq!(once.gas_price, twice.gas_price);
			prop_assert_eq!(once.max_fee_per_gas, twice.max_fee_per_gas);
			prop_assert_eq!(once.max_priority_fee_per_gas, twice.max_priority_fee_per_gas);
		}
	}
}
