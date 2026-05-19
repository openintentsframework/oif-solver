//! Recovery module for restoring solver state from storage after unexpected exits.
//!
//! This module provides functionality to recover orders from persistent storage,
//! reconcile with blockchain state including all transaction types (prepare, fill,
//! post-fill, pre-claim, claim), and resume processing of active orders.

mod chain_evidence;

use crate::bump::lineage::{lineage_components, lineage_tip};
use crate::engine::event_bus::EventBus;
use crate::state::order::{
	FAILED_STATUS_KIND_INDEX_VALUE, FINALIZED_STATUS_KIND_INDEX_VALUE, STATUS_KIND_INDEX_FIELD,
};
use crate::state::transaction_attempt::TransactionAttemptStore;
use crate::state::OrderStateMachine;
use alloy_primitives::hex;
use solver_delivery::DeliveryService;
use solver_settlement::{SettlementReadiness, SettlementService};
use solver_storage::{QueryFilter, StorageService};
use solver_types::{
	with_0x_prefix, DeliveryEvent, Intent, Order, OrderEvent, OrderStatus, SettlementEvent,
	SolverEvent, StorageKey, TransactionAttempt, TransactionAttemptStatus, TransactionHash,
	TransactionReceipt, TransactionType,
};
use std::sync::Arc;
use thiserror::Error;
use tracing::instrument;

/// Errors that can occur during recovery operations.
#[derive(Debug, Error)]
pub enum RecoveryError {
	#[error("Storage error: {0}")]
	Storage(String),
	#[error("State machine error: {0}")]
	StateMachine(String),
	#[error("Delivery error: {0}")]
	Delivery(String),
	#[error("Settlement error: {0}")]
	Settlement(String),
}

/// Result of reconciling an order with blockchain state.
///
/// This enum represents the different states an order can be in after
/// comparing its stored state with the actual blockchain state during recovery.
#[derive(Debug)]
enum ReconcileResult {
	/// Order needs initial execution (no transactions yet)
	NeedsExecution,
	/// Prepare confirmed, needs fill transaction
	NeedsFill,
	/// Fill confirmed, needs post-fill transaction (if applicable)
	NeedsPostFill,
	/// Post-fill done or not needed, needs monitoring for settlement
	NeedsMonitoring,
	/// Settled, needs pre-claim transaction (if applicable)
	NeedsPreClaim {
		fill_proof: Option<solver_types::FillProof>,
	},
	/// Pre-claim done or not needed, ready for claim
	NeedsClaim {
		fill_proof: Option<solver_types::FillProof>,
	},
	/// Transaction failed (confirmed receipt with status = 0).
	Failed(TransactionType),
	/// Reconciliation could not determine the on-chain state of a tx
	/// (RPC transport error, provider returning a non-deterministic lookup
	/// failure, tx not yet visible). The order's status is left untouched
	/// and no resume event is published — this is *not* a terminal failure.
	///
	/// Recovery currently runs only at engine startup (see
	/// `SolverEngine::initialize_with_recovery`); there is no in-process
	/// periodic re-reconciliation. An order whose reconciliation returns
	/// `Unknown` will be re-reconciled on the next solver restart, when the
	/// RPC may have recovered. This is preferred over `Failed` because the
	/// stranded state is recoverable; `Failed` is terminal.
	Unknown,
	/// Order is finalized
	Finalized,
}

fn choose_recovery_attempt_hash(
	attempts: &[TransactionAttempt],
	tx_type: TransactionType,
) -> Option<TransactionHash> {
	let stage_attempts: Vec<TransactionAttempt> = attempts
		.iter()
		.filter(|attempt| attempt.tx_type == tx_type)
		.cloned()
		.collect();
	let components = lineage_components(&stage_attempts);

	for component in &components {
		if let Some(confirmed) = component
			.iter()
			.find(|attempt| attempt.status == TransactionAttemptStatus::Confirmed)
		{
			if let Some(hash) = confirmed.tx_hash.clone() {
				return Some(hash);
			}
		}
	}

	components
		.iter()
		.filter_map(|component| {
			let tip = lineage_tip(component)?;
			if matches!(
				tip.status,
				TransactionAttemptStatus::Broadcast | TransactionAttemptStatus::Indeterminate
			) {
				tip.tx_hash.clone().map(|hash| (tip.updated_at, hash))
			} else {
				None
			}
		})
		.max_by_key(|(updated_at, _)| *updated_at)
		.map(|(_, hash)| hash)
}

fn order_stage_hash(order: &Order, tx_type: TransactionType) -> Option<TransactionHash> {
	match tx_type {
		TransactionType::Prepare => order.prepare_tx_hash.clone(),
		TransactionType::Fill => order.fill_tx_hash.clone(),
		TransactionType::PostFill => order.post_fill_tx_hash.clone(),
		TransactionType::PreClaim => order.pre_claim_tx_hash.clone(),
		TransactionType::Claim => order.claim_tx_hash.clone(),
	}
}

/// Result of resolving a stage's transaction hash via the three-layer
/// fallback (order field → attempt ledger → chain logs).
///
/// `Terminated` carries no reason payload — the specific cause (refund vs
/// purchase) is logged inside `evidence_to_resolution` at construction time.
enum StageResolution {
	Hash(TransactionHash),
	NotFound,
	Unknown,
	Terminated,
}

fn set_order_stage_hash(order: &mut Order, tx_type: TransactionType, tx_hash: TransactionHash) {
	match tx_type {
		TransactionType::Prepare => order.prepare_tx_hash = Some(tx_hash),
		TransactionType::Fill => order.fill_tx_hash = Some(tx_hash),
		TransactionType::PostFill => order.post_fill_tx_hash = Some(tx_hash),
		TransactionType::PreClaim => order.pre_claim_tx_hash = Some(tx_hash),
		TransactionType::Claim => order.claim_tx_hash = Some(tx_hash),
	}
}

/// Report of the recovery operation.
#[derive(Debug, Default)]
pub struct RecoveryReport {
	/// Total number of orders recovered.
	pub total_orders: usize,
	/// Number of orphaned intents found.
	pub orphaned_intents: usize,
	/// Number of orders reconciled with blockchain.
	pub reconciled_orders: usize,
}

/// Service responsible for recovering solver state from storage.
///
/// The RecoveryService handles the critical task of restoring the solver's
/// operational state after an unexpected shutdown or restart. It reconciles
/// stored order data with actual blockchain state and resumes processing
/// where it left off.
pub struct RecoveryService {
	storage: Arc<StorageService>,
	state_machine: Arc<OrderStateMachine>,
	delivery: Arc<DeliveryService>,
	settlement: Arc<SettlementService>,
	event_bus: EventBus,
	attempt_store: Arc<TransactionAttemptStore>,
	networks_config: Arc<solver_types::NetworksConfig>,
}

impl RecoveryService {
	/// Creates a new RecoveryService instance.
	///
	/// # Arguments
	///
	/// * `storage` - Storage service for accessing persisted state
	/// * `state_machine` - Order state machine for status transitions
	/// * `delivery` - Delivery service for checking transaction status
	/// * `settlement` - Settlement service for claim operations
	/// * `event_bus` - Event bus for publishing recovery events
	/// * `attempt_store` - Transaction attempt store for ledger fallback
	/// * `networks_config` - Network configuration for settler address lookup
	pub fn new(
		storage: Arc<StorageService>,
		state_machine: Arc<OrderStateMachine>,
		delivery: Arc<DeliveryService>,
		settlement: Arc<SettlementService>,
		event_bus: EventBus,
		attempt_store: Arc<TransactionAttemptStore>,
		networks_config: Arc<solver_types::NetworksConfig>,
	) -> Self {
		Self {
			storage,
			state_machine,
			delivery,
			settlement,
			event_bus,
			attempt_store,
			networks_config,
		}
	}

	/// Performs full state recovery from storage with blockchain reconciliation.
	#[instrument(skip_all)]
	pub async fn recover_state(&self) -> Result<(RecoveryReport, Vec<Intent>), RecoveryError> {
		tracing::info!("Starting state recovery from storage");

		let mut report = RecoveryReport::default();

		// Step 1: Load active orders from storage
		let orders = self.load_active_orders().await?;
		report.total_orders = orders.len();

		if orders.is_empty() {
			tracing::info!("No active orders to recover");
			return Ok((report, Vec::new()));
		}

		tracing::info!("Found {} active orders to recover", orders.len());

		// Step 2: Recover orphaned intents
		let orphaned_intents = self.recover_orphaned_intents().await?;
		report.orphaned_intents = orphaned_intents.len();

		// Step 3: Reconcile each order with blockchain and publish recovery events
		for order in orders {
			// Skip reconciliation for orders already in Failed state (terminal state)
			if matches!(order.status, OrderStatus::Failed(_, _)) {
				tracing::info!("Order {} already failed, skipping reconciliation", order.id);
				report.reconciled_orders += 1;
				continue;
			}

			match self.reconcile_with_blockchain(&order).await {
				Ok((reconciled_order, result)) => {
					self.publish_recovery_event(reconciled_order, result).await;
					report.reconciled_orders += 1;
				},
				Err(e) => {
					tracing::warn!("Failed to reconcile order {}: {}", order.id, e);
				},
			}
		}

		tracing::info!(
			"Recovery complete: {} orders recovered, {} orphaned intents, {} reconciled",
			report.total_orders,
			report.orphaned_intents,
			report.reconciled_orders
		);

		Ok((report, orphaned_intents))
	}

	/// Loads active (non-terminal) orders from storage.
	///
	/// This method queries storage for all orders that are not in terminal states
	/// (Finalized or Failed variants). These orders may need to be resumed or
	/// have their state reconciled with the blockchain.
	///
	/// # Returns
	///
	/// A vector of active orders that need recovery processing.
	async fn load_active_orders(&self) -> Result<Vec<Order>, RecoveryError> {
		let terminal_status_kinds = vec![
			serde_json::json!(FINALIZED_STATUS_KIND_INDEX_VALUE),
			serde_json::json!(FAILED_STATUS_KIND_INDEX_VALUE),
		];

		// Query for all non-terminal orders
		let active_orders = self
			.storage
			.query::<Order>(
				StorageKey::Orders.as_str(),
				QueryFilter::NotIn(STATUS_KIND_INDEX_FIELD.to_string(), terminal_status_kinds),
			)
			.await
			.map_err(|e| RecoveryError::Storage(e.to_string()))?;

		// Extract just the orders from the (id, order) tuples
		let orders: Vec<Order> = active_orders.into_iter().map(|(_, order)| order).collect();

		Ok(orders)
	}

	/// Recovers intents that were stored but never converted to orders.
	///
	/// These "orphaned" intents represent work that was in progress when the
	/// solver shut down. They need to be reprocessed to create orders and
	/// continue the normal flow.
	///
	/// # Returns
	///
	/// A vector of orphaned intents that should be reinjected into the
	/// processing pipeline.
	async fn recover_orphaned_intents(&self) -> Result<Vec<Intent>, RecoveryError> {
		// Get all stored intents
		let intents = self
			.storage
			.retrieve_all::<Intent>(StorageKey::Intents.as_str())
			.await
			.map_err(|e| RecoveryError::Storage(e.to_string()))?;

		let mut orphaned = Vec::new();

		for (intent_id, intent) in intents {
			// Check if a corresponding order exists
			let order_exists = self
				.storage
				.exists(StorageKey::Orders.as_str(), &intent_id)
				.await
				.map_err(|e| RecoveryError::Storage(e.to_string()))?;

			if !order_exists {
				tracing::debug!(
					"Found orphaned intent {} without corresponding order",
					intent_id
				);
				orphaned.push(intent);
			} else {
				// Intent has a corresponding order, cleanup the intent
				if let Err(e) = self
					.storage
					.remove(StorageKey::Intents.as_str(), &intent_id)
					.await
				{
					tracing::warn!("Failed to cleanup intent {}: {}", intent_id, e);
				}
			}
		}

		Ok(orphaned)
	}

	async fn attempts_for_recovery(&self, order_id: &str) -> Vec<TransactionAttempt> {
		match self.attempt_store.attempts_for_order(order_id).await {
			Ok(attempts) => attempts,
			Err(error) => {
				tracing::warn!(
					order_id = %order_id,
					error = %error,
					"Failed to load transaction attempts during recovery; falling back to order hashes only"
				);
				Vec::new()
			},
		}
	}

	async fn write_repaired_hash(
		&self,
		order: &mut Order,
		tx_type: TransactionType,
		tx_hash: TransactionHash,
	) {
		set_order_stage_hash(order, tx_type, tx_hash.clone());
		if let Err(error) = self
			.state_machine
			.set_transaction_hash(&order.id, tx_hash, tx_type)
			.await
		{
			tracing::error!(
				order_id = %order.id,
				tx_type = ?tx_type,
				error = %error,
				"Recovered transaction hash but failed to write it back to order"
			);
		}
	}

	async fn mark_recovered_attempt_confirmed(
		&self,
		order_id: &str,
		tx_type: TransactionType,
		tx_hash: &TransactionHash,
		receipt: &TransactionReceipt,
	) {
		match self.attempt_store.attempt_by_hash(tx_hash).await {
			Ok(Some(attempt)) if attempt.order_id == order_id && attempt.tx_type == tx_type => {
				if let Err(error) = self
					.attempt_store
					.mark_attempt_confirmed_from_receipt(
						&attempt.id,
						tx_hash.clone(),
						receipt.clone(),
					)
					.await
				{
					tracing::error!(
						%order_id,
						attempt_id = %attempt.id,
						?tx_type,
						?tx_hash,
						%error,
						"Recovery proved transaction confirmed but attempt ledger update failed"
					);
					self.event_bus
						.publish(SolverEvent::Delivery(
							DeliveryEvent::TransactionAttemptLedgerConflict {
								order_id: order_id.to_string(),
								attempt_id: attempt.id,
								tx_type,
								tx_hash: Some(tx_hash.clone()),
								attempted_status: TransactionAttemptStatus::Confirmed,
								error: error.to_string(),
								context: "recovery mark confirmed".to_string(),
							},
						))
						.ok();
				}
			},
			Ok(Some(attempt)) => {
				tracing::debug!(
					%order_id,
					attempt_id = %attempt.id,
					attempt_order_id = %attempt.order_id,
					attempt_tx_type = ?attempt.tx_type,
					expected_tx_type = ?tx_type,
					?tx_hash,
					"Recovery found attempt by hash but order/stage did not match; not marking confirmed"
				);
			},
			Ok(None) => {
				tracing::debug!(
					%order_id,
					?tx_type,
					?tx_hash,
					"Recovery proved transaction confirmed but no attempt row matched the hash"
				);
			},
			Err(error) => {
				tracing::warn!(
					%order_id,
					?tx_type,
					?tx_hash,
					%error,
					"Recovery could not look up attempt by recovered hash"
				);
			},
		}
	}

	async fn fill_chain_evidence(&self, order: &mut Order) -> StageResolution {
		let chain_id = match order.output_chains.first().map(|c| c.chain_id) {
			Some(id) => id,
			None => {
				tracing::warn!(
					order_id = %order.id,
					"Order has no output_chains; chain probe skipped"
				);
				return StageResolution::Unknown;
			},
		};
		let network = match self.networks_config.get(&chain_id) {
			Some(n) => n,
			None => {
				// Config gap. The chain probe cannot run without a settler
				// address. Fall through to the next reverse-priority stage
				// and surface the misconfiguration via the WARN log so the
				// operator can fix the deployment.
				tracing::warn!(
					chain_id,
					order_id = %order.id,
					"no NetworkConfig for output chain; chain probe skipped, falling through"
				);
				return StageResolution::NotFound;
			},
		};
		let order_id_bytes = match solver_types::order_id_to_bytes32(&order.id) {
			Ok(bytes) => bytes,
			Err(error) => {
				tracing::warn!(
					order_id = %order.id,
					%error,
					"invalid order id for fill chain probe"
				);
				return StageResolution::Unknown;
			},
		};

		let evidence = chain_evidence::chain_evidence_for_fill(
			&self.delivery,
			chain_id,
			&network.output_settler_address,
			&order_id_bytes,
			chain_evidence::DEFAULT_RECOVERY_SCAN_WINDOW_BLOCKS,
		)
		.await;

		self.evidence_to_resolution(order, TransactionType::Fill, evidence)
			.await
	}

	async fn prepare_chain_evidence(&self, order: &mut Order) -> StageResolution {
		let chain_id = match order.input_chains.first().map(|c| c.chain_id) {
			Some(id) => id,
			None => {
				tracing::warn!(
					order_id = %order.id,
					"Order has no input_chains; prepare chain probe skipped"
				);
				return StageResolution::Unknown;
			},
		};
		let network = match self.networks_config.get(&chain_id) {
			Some(n) => n,
			None => {
				tracing::warn!(
					chain_id,
					order_id = %order.id,
					"no NetworkConfig for input chain; prepare chain probe skipped"
				);
				return StageResolution::NotFound;
			},
		};
		let order_id_bytes = match solver_types::order_id_to_bytes32(&order.id) {
			Ok(bytes) => bytes,
			Err(error) => {
				tracing::warn!(
					order_id = %order.id,
					%error,
					"invalid order id for prepare chain probe"
				);
				return StageResolution::Unknown;
			},
		};

		let candidates: Vec<&solver_types::Address> =
			std::iter::once(&network.input_settler_address)
				.chain(network.input_settler_compact_address.iter())
				.collect();

		for settler in candidates {
			let evidence = chain_evidence::chain_evidence_for_prepare_open(
				&self.delivery,
				chain_id,
				settler,
				&order_id_bytes,
				chain_evidence::DEFAULT_RECOVERY_SCAN_WINDOW_BLOCKS,
			)
			.await;

			match evidence {
				chain_evidence::ChainEvidence::Proven { .. }
				| chain_evidence::ChainEvidence::NegativeTerminal { .. }
				| chain_evidence::ChainEvidence::Unknown { .. } => {
					return self
						.evidence_to_resolution(order, TransactionType::Prepare, evidence)
						.await;
				},
				chain_evidence::ChainEvidence::NotFound => continue,
			}
		}

		StageResolution::NotFound
	}

	async fn claim_chain_evidence(
		&self,
		order: &mut Order,
		attempts: &[TransactionAttempt],
	) -> StageResolution {
		let chain_id = match order.input_chains.first().map(|c| c.chain_id) {
			Some(id) => id,
			None => {
				tracing::warn!(
					order_id = %order.id,
					"Order has no input_chains; chain probe skipped"
				);
				return StageResolution::Unknown;
			},
		};
		let network = match self.networks_config.get(&chain_id) {
			Some(n) => n,
			None => {
				// Config gap; see note in fill_chain_evidence above.
				tracing::warn!(
					chain_id,
					order_id = %order.id,
					"no NetworkConfig for input chain; chain probe skipped, falling through"
				);
				return StageResolution::NotFound;
			},
		};
		let order_id_bytes = match solver_types::order_id_to_bytes32(&order.id) {
			Ok(bytes) => bytes,
			Err(error) => {
				tracing::warn!(
					order_id = %order.id,
					%error,
					"invalid order id for claim chain probe"
				);
				return StageResolution::Unknown;
			},
		};
		let anchor_tx = order
			.prepare_tx_hash
			.clone()
			.or_else(|| choose_recovery_attempt_hash(attempts, TransactionType::Prepare));

		let candidates: Vec<&solver_types::Address> =
			std::iter::once(&network.input_settler_address)
				.chain(network.input_settler_compact_address.iter())
				.collect();

		for settler in candidates {
			let evidence = chain_evidence::chain_evidence_for_claim(
				&self.delivery,
				chain_id,
				settler,
				&order_id_bytes,
				anchor_tx.as_ref(),
				chain_evidence::DEFAULT_RECOVERY_SCAN_WINDOW_BLOCKS,
			)
			.await;

			match evidence {
				chain_evidence::ChainEvidence::Proven { .. }
				| chain_evidence::ChainEvidence::NegativeTerminal { .. }
				| chain_evidence::ChainEvidence::Unknown { .. } => {
					return self
						.evidence_to_resolution(order, TransactionType::Claim, evidence)
						.await;
				},
				chain_evidence::ChainEvidence::NotFound => continue,
			}
		}

		StageResolution::NotFound
	}

	/// Handles a confirmed revert: looks up the attempt-ledger row to retrieve
	/// the original `tx` + `signer`, replays via `get_revert_data` against the
	/// failed-tx block, classifies the revert bytes, and dispatches stage
	/// recovery for `StageComplete` classifications.
	///
	/// Preserves today's behavior for `Terminal` and `Unknown`: both terminalize
	/// the stage. Only `StageComplete` defers to chain-evidence confirmation
	/// before deciding whether to advance.
	async fn handle_confirmed_revert(
		&self,
		order: &mut Order,
		tx_type: TransactionType,
		tx_hash: &TransactionHash,
		chain_id: u64,
		receipt_block_number: u64,
		attempts: &[TransactionAttempt],
	) -> ReconcileResult {
		let attempt = match self.attempt_store.attempt_by_hash(tx_hash).await {
			Ok(Some(a)) => a,
			Ok(None) => {
				tracing::warn!(
					order_id = %order.id,
					?tx_type,
					tx_hash = ?tx_hash,
					"Confirmed revert but no attempt ledger row; cannot replay for classification, treating as Failed"
				);
				return ReconcileResult::Failed(tx_type);
			},
			Err(error) => {
				// Transient storage error — DO NOT terminalize. Return Unknown
				// so the next recovery pass retries cleanly. Without this, a
				// single backend hiccup converts a healthy in-flight order
				// into a permanent Failed and may strand funds.
				tracing::warn!(
					order_id = %order.id,
					?tx_type,
					tx_hash = ?tx_hash,
					%error,
					"Confirmed revert but attempt-ledger lookup errored; treating as Unknown for retry"
				);
				return ReconcileResult::Unknown;
			},
		};

		let revert_bytes = match self
			.delivery
			.get_revert_data(
				chain_id,
				attempt.tx.clone(),
				attempt.signer.clone(),
				receipt_block_number,
			)
			.await
		{
			Ok(Some(bytes)) => bytes,
			Ok(None) => {
				tracing::warn!(
					order_id = %order.id,
					?tx_type,
					tx_hash = ?tx_hash,
					"Confirmed revert but replay returned no revert data; treating as Failed"
				);
				return ReconcileResult::Failed(tx_type);
			},
			Err(error) => {
				// Transient RPC error — DO NOT terminalize. See note above.
				tracing::warn!(
					order_id = %order.id,
					?tx_type,
					tx_hash = ?tx_hash,
					%error,
					"Confirmed revert but revert-data replay errored (transport); treating as Unknown for retry"
				);
				return ReconcileResult::Unknown;
			},
		};

		let classification = solver_delivery::classify_revert(&revert_bytes);
		match classification {
			solver_delivery::RevertClassification::StageComplete { reason } => {
				tracing::info!(
					order_id = %order.id,
					?tx_type,
					?reason,
					"Revert classified as stage-complete; running chain probe to confirm"
				);
				self.stage_complete_recovery(order, tx_type, reason, attempts)
					.await
			},
			solver_delivery::RevertClassification::Terminal { selector_hex } => {
				tracing::warn!(
					order_id = %order.id,
					?tx_type,
					%selector_hex,
					"Revert classified as terminal failure"
				);
				ReconcileResult::Failed(tx_type)
			},
			solver_delivery::RevertClassification::Unknown => {
				tracing::warn!(
					order_id = %order.id,
					?tx_type,
					"Revert classification Unknown (selector not catalogued); treating as Failed"
				);
				ReconcileResult::Failed(tx_type)
			},
		}
	}

	/// Stage-specific recovery after a `StageComplete` classification.
	///
	/// Runs PR 04's chain probe for the affected stage and maps the result to
	/// a `ReconcileResult`. Chain agreement is the actual proof — a bare
	/// classification never advances the order on its own.
	async fn stage_complete_recovery(
		&self,
		order: &mut Order,
		tx_type: TransactionType,
		reason: solver_delivery::StageCompleteReason,
		attempts: &[TransactionAttempt],
	) -> ReconcileResult {
		match tx_type {
			TransactionType::Claim => {
				let resolution = self.claim_chain_evidence(order, attempts).await;
				match resolution {
					StageResolution::Hash(_) => ReconcileResult::Finalized,
					StageResolution::Terminated => ReconcileResult::Failed(TransactionType::Claim),
					StageResolution::NotFound | StageResolution::Unknown => {
						tracing::warn!(
							order_id = %order.id,
							?reason,
							"Claim StageComplete classification but chain probe did not confirm; returning Unknown"
						);
						ReconcileResult::Unknown
					},
				}
			},
			TransactionType::PreClaim => {
				// OIF has no "pre-claim done" event. If the claim itself is
				// done on-chain, skipping PreClaim is correct — advance to
				// Finalized directly. Otherwise the StageComplete hint is
				// unconfirmable; fail conservatively.
				let resolution = self.claim_chain_evidence(order, attempts).await;
				match resolution {
					StageResolution::Hash(_) => ReconcileResult::Finalized,
					StageResolution::Terminated => ReconcileResult::Failed(TransactionType::Claim),
					StageResolution::NotFound | StageResolution::Unknown => {
						tracing::warn!(
							order_id = %order.id,
							?reason,
							"PreClaim revert classified StageComplete but chain probe did not confirm claim done; treating as Failed(PreClaim)"
						);
						ReconcileResult::Failed(TransactionType::PreClaim)
					},
				}
			},
			TransactionType::Prepare => {
				let resolution = self.prepare_chain_evidence(order).await;
				match resolution {
					StageResolution::Hash(_) => ReconcileResult::NeedsFill,
					StageResolution::Terminated => {
						ReconcileResult::Failed(TransactionType::Prepare)
					},
					StageResolution::NotFound | StageResolution::Unknown => {
						tracing::warn!(
							order_id = %order.id,
							?reason,
							"Prepare StageComplete classification but Open event was not proven; returning Unknown"
						);
						ReconcileResult::Unknown
					},
				}
			},
			TransactionType::Fill | TransactionType::PostFill => {
				// PR 05 does not promote AlreadyFilled to StageComplete (fill
				// evidence is too weak); and no idempotency errors exist on
				// PostFill in OIF. Defensive fallback.
				tracing::warn!(
					order_id = %order.id,
					?tx_type,
					?reason,
					"StageComplete classification on stage with no chain-probe support; treating as Failed"
				);
				ReconcileResult::Failed(tx_type)
			},
		}
	}

	async fn evidence_to_resolution(
		&self,
		order: &mut Order,
		tx_type: TransactionType,
		evidence: chain_evidence::ChainEvidence,
	) -> StageResolution {
		match evidence {
			chain_evidence::ChainEvidence::Proven {
				tx_hash,
				block_number,
			} => {
				tracing::info!(
					order_id = %order.id,
					?tx_type,
					tx_hash = ?tx_hash,
					block_number,
					"Repairing stage hash from chain log evidence"
				);
				self.write_repaired_hash(order, tx_type, tx_hash.clone())
					.await;
				StageResolution::Hash(tx_hash)
			},
			chain_evidence::ChainEvidence::NegativeTerminal { reason } => {
				tracing::warn!(
					order_id = %order.id,
					?tx_type,
					?reason,
					"Order terminated by chain log (refund or purchase)"
				);
				StageResolution::Terminated
			},
			chain_evidence::ChainEvidence::NotFound => StageResolution::NotFound,
			chain_evidence::ChainEvidence::Unknown { error } => {
				tracing::warn!(
					order_id = %order.id,
					?tx_type,
					%error,
					"Chain log probe failed; treating stage as Unknown"
				);
				StageResolution::Unknown
			},
		}
	}

	async fn resolve_stage(
		&self,
		order: &mut Order,
		attempts: &[TransactionAttempt],
		tx_type: TransactionType,
	) -> StageResolution {
		// Layer 1: order field
		if let Some(tx_hash) = order_stage_hash(order, tx_type) {
			return StageResolution::Hash(tx_hash);
		}

		// Layer 2: attempt ledger fallback
		if let Some(tx_hash) = choose_recovery_attempt_hash(attempts, tx_type) {
			self.write_repaired_hash(order, tx_type, tx_hash.clone())
				.await;
			return StageResolution::Hash(tx_hash);
		}

		// Layer 3: chain log probe
		match tx_type {
			TransactionType::Prepare => self.prepare_chain_evidence(order).await,
			TransactionType::Fill => self.fill_chain_evidence(order).await,
			TransactionType::Claim => self.claim_chain_evidence(order, attempts).await,
			_ => StageResolution::NotFound,
		}
	}

	/// Reconciles an order with blockchain state.
	///
	/// This method checks the actual status of transactions on the blockchain
	/// to determine what action should be taken to resume processing the order.
	/// It checks transactions in reverse order (claim -> pre-claim -> post-fill -> fill -> prepare) to
	/// find the most advanced state.
	///
	/// # Arguments
	///
	/// * `order` - The order to reconcile with blockchain state
	///
	/// # Returns
	///
	/// A `ReconcileResult` indicating what action should be taken next.
	async fn reconcile_with_blockchain(
		&self,
		order: &Order,
	) -> Result<(Order, ReconcileResult), RecoveryError> {
		let attempts = self.attempts_for_recovery(&order.id).await;
		let mut order = order.clone();

		// Check transactions in reverse order (claim -> pre-claim -> post-fill -> fill -> prepare)

		// Check claim transaction
		match self
			.resolve_stage(&mut order, &attempts, TransactionType::Claim)
			.await
		{
			StageResolution::Terminated => {
				// Reason already logged by evidence_to_resolution.
				return Ok((order, ReconcileResult::Failed(TransactionType::Claim)));
			},
			StageResolution::Unknown => return Ok((order, ReconcileResult::Unknown)),
			StageResolution::Hash(claim_tx) => {
				let chain_id = order
					.input_chains
					.first()
					.map(|c| c.chain_id)
					.ok_or_else(|| RecoveryError::Storage("No input chains in order".into()))?;

				match self.delivery.get_receipt(&claim_tx, chain_id).await {
					Ok(receipt) if receipt.success => {
						self.mark_recovered_attempt_confirmed(
							&order.id,
							TransactionType::Claim,
							&claim_tx,
							&receipt,
						)
						.await;
						return Ok((order, ReconcileResult::Finalized));
					},
					Ok(receipt) => {
						tracing::warn!("Claim transaction {:?} reverted", claim_tx);
						let result = self
							.handle_confirmed_revert(
								&mut order,
								TransactionType::Claim,
								&claim_tx,
								chain_id,
								receipt.block_number,
								&attempts,
							)
							.await;
						return Ok((order, result));
					},
					Err(e) => {
						tracing::warn!(
							"Could not get claim transaction receipt; treating as Unknown: {}",
							e
						);
						return Ok((order, ReconcileResult::Unknown));
					},
				}
			},
			StageResolution::NotFound => { /* fall through to pre-claim */ },
		}

		// Check pre-claim transaction
		match self
			.resolve_stage(&mut order, &attempts, TransactionType::PreClaim)
			.await
		{
			StageResolution::Terminated => {
				return Ok((order, ReconcileResult::Failed(TransactionType::Claim)));
			},
			StageResolution::Unknown => return Ok((order, ReconcileResult::Unknown)),
			StageResolution::Hash(pre_claim_tx) => {
				// PreClaim happens on origin chain (same as claim)
				let chain_id = order
					.input_chains
					.first()
					.map(|c| c.chain_id)
					.ok_or_else(|| RecoveryError::Storage("No input chains in order".into()))?;

				match self.delivery.get_receipt(&pre_claim_tx, chain_id).await {
					Ok(receipt) if receipt.success => {
						self.mark_recovered_attempt_confirmed(
							&order.id,
							TransactionType::PreClaim,
							&pre_claim_tx,
							&receipt,
						)
						.await;
						return Ok((
							order.clone(),
							ReconcileResult::NeedsClaim {
								fill_proof: order.fill_proof.clone(),
							},
						));
					},
					Ok(receipt) => {
						let result = self
							.handle_confirmed_revert(
								&mut order,
								TransactionType::PreClaim,
								&pre_claim_tx,
								chain_id,
								receipt.block_number,
								&attempts,
							)
							.await;
						return Ok((order, result));
					},
					Err(e) => {
						tracing::warn!(
							"Could not get pre-claim transaction receipt; treating as Unknown: {}",
							e
						);
						return Ok((order, ReconcileResult::Unknown));
					},
				}
			},
			StageResolution::NotFound => { /* fall through to post-fill */ },
		}

		// Check post-fill transaction
		match self
			.resolve_stage(&mut order, &attempts, TransactionType::PostFill)
			.await
		{
			StageResolution::Terminated => {
				// Negative terminal events only fire on origin chain; PostFill is
				// destination. resolve_stage will never produce Terminated here,
				// but handle defensively.
				return Ok((order, ReconcileResult::Failed(TransactionType::Claim)));
			},
			StageResolution::Unknown => return Ok((order, ReconcileResult::Unknown)),
			StageResolution::Hash(post_fill_tx) => {
				// PostFill happens on destination chain (same as fill)
				let chain_id = order
					.output_chains
					.first()
					.map(|c| c.chain_id)
					.ok_or_else(|| RecoveryError::Storage("No output chains in order".into()))?;

				match self.delivery.get_receipt(&post_fill_tx, chain_id).await {
					Ok(receipt) if receipt.success => {
						self.mark_recovered_attempt_confirmed(
							&order.id,
							TransactionType::PostFill,
							&post_fill_tx,
							&receipt,
						)
						.await;
						if order.fill_proof.is_some() {
							return Ok((
								order.clone(),
								ReconcileResult::NeedsPreClaim {
									fill_proof: order.fill_proof.clone(),
								},
							));
						}
						return Ok((order, ReconcileResult::NeedsMonitoring));
					},
					Ok(receipt) => {
						let result = self
							.handle_confirmed_revert(
								&mut order,
								TransactionType::PostFill,
								&post_fill_tx,
								chain_id,
								receipt.block_number,
								&attempts,
							)
							.await;
						return Ok((order, result));
					},
					Err(e) => {
						tracing::warn!(
							"Could not get post-fill transaction receipt; treating as Unknown: {}",
							e
						);
						return Ok((order, ReconcileResult::Unknown));
					},
				}
			},
			StageResolution::NotFound => { /* fall through to fill */ },
		}

		// Check fill transaction
		match self
			.resolve_stage(&mut order, &attempts, TransactionType::Fill)
			.await
		{
			StageResolution::Terminated => {
				return Ok((order, ReconcileResult::Failed(TransactionType::Claim)));
			},
			StageResolution::Unknown => return Ok((order, ReconcileResult::Unknown)),
			StageResolution::Hash(fill_tx) => {
				let chain_id = order
					.output_chains
					.first()
					.map(|c| c.chain_id)
					.ok_or_else(|| RecoveryError::Storage("No output chains in order".into()))?;

				match self.delivery.get_receipt(&fill_tx, chain_id).await {
					Ok(receipt) if receipt.success => {
						self.mark_recovered_attempt_confirmed(
							&order.id,
							TransactionType::Fill,
							&fill_tx,
							&receipt,
						)
						.await;
						if order.fill_proof.is_some() {
							return Ok((
								order.clone(),
								ReconcileResult::NeedsPreClaim {
									fill_proof: order.fill_proof.clone(),
								},
							));
						} else {
							match self.settlement.recover_post_fill_state(&order).await {
								Ok(true) => return Ok((order, ReconcileResult::NeedsMonitoring)),
								Ok(false) => {
									return Ok((order, ReconcileResult::NeedsPostFill));
								},
								Err(e) => {
									tracing::error!(
										order_id = %order.id,
										error = %e,
										"Failed to recover existing post-fill state during recovery"
									);
									return Err(RecoveryError::Settlement(e.to_string()));
								},
							}
						}
					},
					Ok(receipt) => {
						tracing::warn!(
							"Fill transaction {} reverted",
							with_0x_prefix(&hex::encode(&fill_tx.0))
						);
						let result = self
							.handle_confirmed_revert(
								&mut order,
								TransactionType::Fill,
								&fill_tx,
								chain_id,
								receipt.block_number,
								&attempts,
							)
							.await;
						return Ok((order, result));
					},
					Err(e) => {
						tracing::warn!(
							"Could not get fill transaction receipt; treating as Unknown: {}",
							e
						);
						return Ok((order, ReconcileResult::Unknown));
					},
				}
			},
			StageResolution::NotFound => { /* fall through to prepare */ },
		}

		// Check prepare transaction
		match self
			.resolve_stage(&mut order, &attempts, TransactionType::Prepare)
			.await
		{
			StageResolution::Terminated => {
				return Ok((order, ReconcileResult::Failed(TransactionType::Claim)));
			},
			StageResolution::Unknown => return Ok((order, ReconcileResult::Unknown)),
			StageResolution::Hash(prepare_tx) => {
				let chain_id = order
					.input_chains
					.first()
					.map(|c| c.chain_id)
					.ok_or_else(|| RecoveryError::Storage("No input chains in order".into()))?;

				match self.delivery.get_receipt(&prepare_tx, chain_id).await {
					Ok(receipt) if receipt.success => {
						self.mark_recovered_attempt_confirmed(
							&order.id,
							TransactionType::Prepare,
							&prepare_tx,
							&receipt,
						)
						.await;
						return Ok((order, ReconcileResult::NeedsFill));
					},
					Ok(receipt) => {
						tracing::warn!("Prepare transaction {:?} reverted", prepare_tx);
						let result = self
							.handle_confirmed_revert(
								&mut order,
								TransactionType::Prepare,
								&prepare_tx,
								chain_id,
								receipt.block_number,
								&attempts,
							)
							.await;
						return Ok((order, result));
					},
					Err(e) => {
						tracing::warn!(
							"Could not get prepare transaction receipt; treating as Unknown: {}",
							e
						);
						return Ok((order, ReconcileResult::Unknown));
					},
				}
			},
			StageResolution::NotFound => { /* fall through to NeedsExecution */ },
		}

		// No transactions yet, needs execution
		Ok((order, ReconcileResult::NeedsExecution))
	}

	/// Ensures the order is in the correct state based on reconciliation result.
	///
	/// This method updates the order status in storage to match what we've discovered
	/// from the blockchain, ensuring subsequent operations have valid state transitions.
	///
	/// # Arguments
	///
	/// * `order` - The order to update
	/// * `result` - The reconciliation result that determines the target state
	///
	/// # Returns
	///
	/// The updated order with the correct status, or the original if update fails
	async fn ensure_correct_state(&self, order: Order, result: &ReconcileResult) -> Order {
		let target_status = match result {
			ReconcileResult::NeedsExecution => {
				// No transactions yet, should be in Created or Executing (for on-chain)
				if order.prepare_tx_hash.is_none() && order.execution_params.is_some() {
					// On-chain intent with execution params, should be Executing
					OrderStatus::Executing
				} else {
					// Off-chain intent, should stay in Created
					OrderStatus::Created
				}
			},
			ReconcileResult::NeedsFill => {
				// Prepare confirmed, should be in Executing state
				OrderStatus::Executing
			},
			ReconcileResult::NeedsPostFill => {
				// Fill confirmed, should be Executed
				OrderStatus::Executed
			},
			ReconcileResult::NeedsMonitoring => {
				// Post-fill confirmed (or skipped), should be PostFilled or Executed
				if order.post_fill_tx_hash.is_some() {
					// PostFill transaction exists and is confirmed
					OrderStatus::PostFilled
				} else {
					// No PostFill transaction, but fill is confirmed
					OrderStatus::Executed
				}
			},
			ReconcileResult::NeedsPreClaim { .. } => {
				// Settled, ready for pre-claim
				OrderStatus::Settled
			},
			ReconcileResult::NeedsClaim { .. } => {
				// Pre-claim done or not needed, ready for claim
				if order.pre_claim_tx_hash.is_some() {
					// PreClaim exists and is confirmed
					OrderStatus::PreClaimed
				} else {
					// No PreClaim, but ready to claim
					OrderStatus::Settled
				}
			},
			ReconcileResult::Finalized => {
				// Claim confirmed, should be Finalized
				OrderStatus::Finalized
			},
			ReconcileResult::Failed(tx_type) => {
				// Failed at some stage
				OrderStatus::Failed(*tx_type, "Blockchain reconciliation failed".to_string())
			},
			ReconcileResult::Unknown => {
				// RPC could not determine on-chain state. Don't transition;
				// keep the order's current status. Re-reconciliation happens
				// on the next solver restart's recovery pass.
				order.status.clone()
			},
		};

		// Only update if status differs
		if order.status != target_status {
			tracing::info!(
				"Updating order {} status from {:?} to {:?} based on blockchain state",
				order.id,
				order.status,
				target_status
			);

			match self
				.state_machine
				.transition_order_status(&order.id, target_status.clone())
				.await
			{
				Ok(updated) => updated,
				Err(e) => {
					tracing::error!(
						"Failed to transition order {} to {:?}: {}",
						order.id,
						target_status,
						e
					);
					// Return original order if update fails
					order
				},
			}
		} else {
			order
		}
	}

	/// Publishes appropriate event based on reconciliation result.
	///
	/// This method converts the reconciliation result into the appropriate
	/// event that should be published to resume processing the order from
	/// its current state.
	///
	/// # Arguments
	///
	/// * `order` - The order being recovered
	/// * `result` - The result of blockchain reconciliation
	async fn publish_recovery_event(&self, order: Order, result: ReconcileResult) {
		// First ensure the order is in the correct state
		let order = self.ensure_correct_state(order, &result).await;
		match result {
			ReconcileResult::NeedsExecution => {
				// Order needs initial execution
				if let Some(params) = order.execution_params.clone() {
					tracing::info!("Resuming execution for order {}", order.id);
					self.event_bus
						.publish(SolverEvent::Order(OrderEvent::Executing { order, params }))
						.ok();
				} else {
					tracing::error!("Order {} missing execution params, cannot resume", order.id);
				}
			},

			ReconcileResult::NeedsFill => {
				// Prepare confirmed, need to execute fill transaction
				tracing::info!("Order {} needs fill transaction", order.id);

				// Get execution params to trigger fill
				if let Some(params) = order.execution_params.clone() {
					// Directly publish Executing event to trigger fill
					// (prepare is already confirmed, no need to re-confirm it)
					self.event_bus
						.publish(SolverEvent::Order(OrderEvent::Executing { order, params }))
						.ok();
				} else {
					tracing::error!(
						"Order {} missing execution params, cannot trigger fill",
						order.id
					);
				}
			},

			ReconcileResult::NeedsPostFill => {
				// Fill confirmed, need post-fill processing
				tracing::info!("Order {} needs post-fill processing", order.id);

				// Emit PostFillReady event - handler will fetch receipt and generate transaction
				self.event_bus
					.publish(SolverEvent::Settlement(SettlementEvent::PostFillReady {
						order_id: order.id,
					}))
					.ok();
			},

			ReconcileResult::NeedsMonitoring => {
				// Emit event to spawn settlement monitor
				if let Some(fill_tx_hash) = order.fill_tx_hash.clone() {
					self.event_bus
						.publish(SolverEvent::Settlement(SettlementEvent::StartMonitoring {
							order_id: order.id.clone(),
							fill_tx_hash,
						}))
						.ok();
				}
			},

			ReconcileResult::NeedsPreClaim { fill_proof } => {
				// Settled, check if ready for pre-claim or claim
				tracing::info!("Order {} is settled", order.id);

				if let Some(proof) = fill_proof {
					match self.settlement.readiness(&order, &proof).await {
						SettlementReadiness::Ready => {
							// Ready to claim, emit PreClaimReady event
							// The handler will determine if pre-claim transaction is needed
							self.event_bus
								.publish(SolverEvent::Settlement(SettlementEvent::PreClaimReady {
									order_id: order.id,
								}))
								.ok();
						},
						SettlementReadiness::Waiting(_) | SettlementReadiness::NeedsAction(_) => {
							// Not ready to claim yet, continue monitoring
							if let Some(fill_tx_hash) = order.fill_tx_hash.clone() {
								self.event_bus
									.publish(SolverEvent::Settlement(
										SettlementEvent::StartMonitoring {
											order_id: order.id.clone(),
											fill_tx_hash,
										},
									))
									.ok();
							}
						},
						SettlementReadiness::PermanentFailure(error) => {
							tracing::error!(
								order_id = %order.id,
								error = %error,
								"Permanent settlement failure during recovery"
							);
							if let Err(e) = self
								.state_machine
								.transition_order_status(
									&order.id,
									OrderStatus::Failed(TransactionType::PreClaim, error),
								)
								.await
							{
								tracing::error!(
									"Failed to update order {} status after settlement failure: {}",
									order.id,
									e
								);
							}
						},
					}
				} else {
					// No proof yet, need to get attestation first
					tracing::warn!("Order {} is settled but missing fill proof", order.id);
					// Start monitoring to get the proof
					if let Some(fill_tx_hash) = order.fill_tx_hash.clone() {
						self.event_bus
							.publish(SolverEvent::Settlement(SettlementEvent::StartMonitoring {
								order_id: order.id.clone(),
								fill_tx_hash,
							}))
							.ok();
					}
				}
			},

			ReconcileResult::NeedsClaim { fill_proof } => {
				// Fill confirmed, check if ready to claim
				if let Some(proof) = fill_proof {
					match self.settlement.readiness(&order, &proof).await {
						SettlementReadiness::Ready => {
							tracing::info!("Order {} ready for claiming", order.id);
							self.event_bus
								.publish(SolverEvent::Settlement(SettlementEvent::ClaimReady {
									order_id: order.id,
								}))
								.ok();
						},
						SettlementReadiness::Waiting(_) | SettlementReadiness::NeedsAction(_) => {
							// Not ready to claim yet, emit event to spawn monitor
							if let Some(fill_tx_hash) = order.fill_tx_hash.clone() {
								self.event_bus
									.publish(SolverEvent::Settlement(
										SettlementEvent::StartMonitoring {
											order_id: order.id.clone(),
											fill_tx_hash,
										},
									))
									.ok();
							}
						},
						SettlementReadiness::PermanentFailure(error) => {
							tracing::error!(
								order_id = %order.id,
								error = %error,
								"Permanent settlement failure during claim recovery"
							);
							if let Err(e) = self
								.state_machine
								.transition_order_status(
									&order.id,
									OrderStatus::Failed(TransactionType::Claim, error),
								)
								.await
							{
								tracing::error!(
									"Failed to update order {} status after settlement failure: {}",
									order.id,
									e
								);
							}
						},
					}
				} else {
					// No proof yet, emit event to spawn monitor to get it
					if let Some(fill_tx_hash) = order.fill_tx_hash.clone() {
						self.event_bus
							.publish(SolverEvent::Settlement(SettlementEvent::StartMonitoring {
								order_id: order.id.clone(),
								fill_tx_hash,
							}))
							.ok();
					}
				}
			},

			ReconcileResult::Failed(tx_type) => {
				tracing::warn!("Order {} failed at {:?} stage", order.id, tx_type);
				// Update order status to failed
				if let Err(e) = self
					.state_machine
					.transition_order_status(
						&order.id,
						OrderStatus::Failed(
							tx_type,
							"Blockchain reconciliation failed".to_string(),
						),
					)
					.await
				{
					tracing::error!("Failed to update order {} status: {}", order.id, e);
				}
			},

			ReconcileResult::Unknown => {
				// RPC error or non-deterministic lookup failure during
				// reconciliation. Do not publish any progress event, do not
				// transition status. The order remains in its current state
				// until the next solver restart's recovery pass re-reconciles.
				tracing::warn!(
					"Order {} reconciliation indeterminate; deferring until next solver restart",
					order.id
				);
			},

			ReconcileResult::Finalized => {
				tracing::info!("Order {} already finalized", order.id);
				// Ensure proper state transitions to reach Finalized
				if order.status != OrderStatus::Finalized {
					// Transition through the proper sequence based on current state
					match order.status {
						OrderStatus::Created | OrderStatus::Pending | OrderStatus::Executing => {
							// Need to go: Current -> Executed -> Settled -> Finalized
							if let Err(e) = self
								.transition_through_states(
									&order.id,
									&[
										OrderStatus::Executed,
										OrderStatus::Settled,
										OrderStatus::Finalized,
									],
								)
								.await
							{
								tracing::error!(
									"Failed to transition order {} through states: {}",
									order.id,
									e
								);
							}
						},
						OrderStatus::Executed
						| OrderStatus::PostFilled
						| OrderStatus::PreClaimed => {
							// Need to go through remaining states to Finalized
							if let Err(e) = self
								.transition_through_states(
									&order.id,
									&[OrderStatus::Settled, OrderStatus::Finalized],
								)
								.await
							{
								tracing::error!(
									"Failed to transition order {} through states: {}",
									order.id,
									e
								);
							}
						},
						OrderStatus::Settled => {
							// Just need: Settled -> Finalized
							if let Err(e) = self
								.state_machine
								.transition_order_status(&order.id, OrderStatus::Finalized)
								.await
							{
								tracing::error!(
									"Failed to transition order {} to Finalized: {}",
									order.id,
									e
								);
							}
						},
						OrderStatus::Finalized => {
							// Already finalized, nothing to do
						},
						OrderStatus::Failed(_, _) => {
							// Order is failed, don't transition to finalized
							tracing::warn!("Order {} is in failed state but blockchain shows finalized - data inconsistency", order.id);
						},
					}
				}
			},
		}
	}

	/// Transitions an order through a sequence of states.
	///
	/// This helper method ensures that state transitions happen in the correct order,
	/// as required by the state machine.
	///
	/// # Arguments
	///
	/// * `order_id` - The ID of the order to transition
	/// * `states` - The sequence of states to transition through
	async fn transition_through_states(
		&self,
		order_id: &str,
		states: &[OrderStatus],
	) -> Result<(), RecoveryError> {
		for state in states {
			if let Err(e) = self
				.state_machine
				.transition_order_status(order_id, state.clone())
				.await
			{
				return Err(RecoveryError::StateMachine(format!(
					"Failed to transition order {order_id} to {state:?}: {e}"
				)));
			}
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use mockall::predicate::*;
	use solver_delivery::MockDeliveryInterface;
	use solver_settlement::MockSettlementInterface;
	use solver_storage::{
		implementations::file::{FileStorage, TtlConfig},
		MockStorageInterface,
	};
	use solver_types::{
		utils::tests::builders::{IntentBuilder, OrderBuilder},
		Address, ExecutionParams, FillProof, Transaction, TransactionAttempt,
		TransactionAttemptStatus, TransactionHash,
	};
	use tempfile::TempDir;

	#[test]
	fn chain_event_signatures_compute() {
		use alloy_sol_types::SolEvent;
		use solver_types::standards::eip7683::interfaces::{
			Finalised, OrderPurchased, OutputFilled, Refunded,
		};
		let _ = OutputFilled::SIGNATURE_HASH;
		let _ = Finalised::SIGNATURE_HASH;
		let _ = Refunded::SIGNATURE_HASH;
		let _ = OrderPurchased::SIGNATURE_HASH;
	}

	#[test]
	fn log_filter_for_event_builds_with_settler_and_indexed_order_id() {
		use crate::recovery::chain_evidence::log_filter_for_event;
		use alloy_sol_types::SolEvent;
		use solver_types::standards::eip7683::interfaces::OutputFilled;

		let settler = Address(vec![0xab; 20]);
		let order_id_bytes = [0xcd; 32];
		let filter = log_filter_for_event::<OutputFilled>(
			&settler,
			&order_id_bytes,
			1_000_000,
			Some(1_010_000),
		);

		assert_eq!(filter.address, settler);
		assert_eq!(filter.from_block, 1_000_000);
		assert_eq!(filter.to_block, Some(1_010_000));
		let topics = filter.topics();
		assert_eq!(topics.len(), 2);
		assert_eq!(
			topics[0].as_ref().map(|h| h.0),
			Some(OutputFilled::SIGNATURE_HASH.0)
		);
		assert_eq!(topics[1].as_ref().map(|h| h.0), Some(order_id_bytes));
	}

	#[tokio::test]
	async fn anchor_block_falls_back_to_recent_window_when_anchor_unknown() {
		use crate::recovery::chain_evidence::{
			anchor_block_for_same_chain, DEFAULT_RECOVERY_SCAN_WINDOW_BLOCKS,
		};

		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_get_block_number()
			.with(eq(137u64))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(1_000_000u64) }));

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				137u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
			60,
		));

		let (from_block, to_block) =
			anchor_block_for_same_chain(&delivery, 137, None, DEFAULT_RECOVERY_SCAN_WINDOW_BLOCKS)
				.await
				.unwrap();

		assert_eq!(from_block, 1_000_000 - 10_000);
		assert_eq!(to_block, Some(1_000_000));
	}
	use std::collections::HashMap;

	// Helper functions to create test data
	fn create_test_order_with_status(status: OrderStatus) -> Order {
		OrderBuilder::new()
			.with_status(status)
			.with_execution_params(Some(ExecutionParams {
				gas_price: alloy_primitives::U256::from(1000000000u64),
				priority_fee: Some(alloy_primitives::U256::from(1000000u64)),
			}))
			.build()
	}

	fn create_test_intent() -> Intent {
		IntentBuilder::new().build()
	}

	fn create_test_fill_proof() -> FillProof {
		FillProof {
			tx_hash: TransactionHash(vec![0xbb; 32]),
			block_number: 12345,
			attestation_data: Some(vec![0x01, 0x02, 0x03]),
			filled_timestamp: 1234567890,
			oracle_address: "0x1234567890123456789012345678901234567890".to_string(),
		}
	}

	/// Returns the attempt store paired with its backing `TempDir`. The caller
	/// must bind both halves; if the `TempDir` is dropped, the on-disk directory
	/// is removed and the store points at a path that gets silently re-created
	/// by `FileStorage::set_bytes` on the next write — leaking an orphan dir
	/// the test can no longer clean up.
	fn empty_attempt_store() -> (Arc<TransactionAttemptStore>, TempDir) {
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		(Arc::new(TransactionAttemptStore::new(storage)), temp_dir)
	}

	fn empty_networks_config() -> Arc<solver_types::NetworksConfig> {
		Arc::new(solver_types::NetworksConfig::new())
	}

	fn sample_attempt(
		id: &str,
		tx_type: TransactionType,
		status: TransactionAttemptStatus,
		hash_byte: Option<u8>,
		updated_at: u64,
	) -> TransactionAttempt {
		let mut attempt = TransactionAttempt::planned(
			id.to_string(),
			"test_order_123".to_string(),
			Some(Address(vec![9; 20])),
			tx_type,
			Transaction {
				to: Some(Address(vec![3; 20])),
				data: vec![0xde, 0xad, 0xbe, 0xef],
				value: alloy_primitives::U256::ZERO,
				chain_id: 137,
				nonce: Some(7),
				gas_limit: Some(120000),
				gas_price: None,
				max_fee_per_gas: Some(2000),
				max_priority_fee_per_gas: Some(20),
			},
		);
		attempt.status = status;
		attempt.tx_hash = hash_byte.map(|byte| TransactionHash(vec![byte; 32]));
		attempt.updated_at = updated_at;
		attempt
	}

	#[test]
	fn choose_recovery_attempt_hash_prefers_confirmed_over_newer_broadcast() {
		let attempts = vec![
			sample_attempt(
				"broadcast",
				TransactionType::Fill,
				TransactionAttemptStatus::Broadcast,
				Some(0xbb),
				200,
			),
			sample_attempt(
				"confirmed",
				TransactionType::Fill,
				TransactionAttemptStatus::Confirmed,
				Some(0xcc),
				100,
			),
		];

		let hash = choose_recovery_attempt_hash(&attempts, TransactionType::Fill).unwrap();

		assert_eq!(hash, TransactionHash(vec![0xcc; 32]));
	}

	#[test]
	fn choose_recovery_attempt_hash_uses_newest_indeterminate_when_no_better_attempt_exists() {
		let attempts = vec![
			sample_attempt(
				"old",
				TransactionType::Claim,
				TransactionAttemptStatus::Indeterminate,
				Some(0x11),
				100,
			),
			sample_attempt(
				"new",
				TransactionType::Claim,
				TransactionAttemptStatus::Indeterminate,
				Some(0x22),
				200,
			),
		];

		let hash = choose_recovery_attempt_hash(&attempts, TransactionType::Claim).unwrap();

		assert_eq!(hash, TransactionHash(vec![0x22; 32]));
	}

	#[test]
	fn choose_recovery_attempt_hash_ignores_planned_reverted_and_submit_rejected() {
		let attempts = vec![
			sample_attempt(
				"planned",
				TransactionType::Fill,
				TransactionAttemptStatus::Planned,
				Some(0x01),
				300,
			),
			sample_attempt(
				"reverted",
				TransactionType::Fill,
				TransactionAttemptStatus::Reverted,
				Some(0x02),
				200,
			),
			sample_attempt(
				"rejected",
				TransactionType::Fill,
				TransactionAttemptStatus::SubmitRejected,
				Some(0x03),
				100,
			),
		];

		assert!(choose_recovery_attempt_hash(&attempts, TransactionType::Fill).is_none());
	}

	#[test]
	fn choose_recovery_attempt_hash_ignores_wrong_transaction_type() {
		let attempts = vec![sample_attempt(
			"claim",
			TransactionType::Claim,
			TransactionAttemptStatus::Confirmed,
			Some(0xcc),
			100,
		)];

		assert!(choose_recovery_attempt_hash(&attempts, TransactionType::Fill).is_none());
	}

	#[test]
	fn recovery_picks_confirmed_attempt_when_lineage_present() {
		let a = sample_attempt(
			"A",
			TransactionType::Fill,
			TransactionAttemptStatus::Indeterminate,
			Some(0xaa),
			100,
		);
		let mut b = sample_attempt(
			"B",
			TransactionType::Fill,
			TransactionAttemptStatus::Confirmed,
			Some(0xbb),
			200,
		);
		b.replacement_of = Some("A".to_string());

		let attempts = vec![a, b];
		let hash = choose_recovery_attempt_hash(&attempts, TransactionType::Fill).unwrap();

		assert_eq!(hash, TransactionHash(vec![0xbb; 32]));
	}

	#[test]
	fn recovery_attempt_hash_uses_lineage_tip_when_no_confirmed_member_exists() {
		let mut parent = sample_attempt(
			"parent",
			TransactionType::Fill,
			TransactionAttemptStatus::Indeterminate,
			Some(0xaa),
			300,
		);
		parent.replaced_by = None;
		let mut child = sample_attempt(
			"child",
			TransactionType::Fill,
			TransactionAttemptStatus::Broadcast,
			Some(0xbb),
			200,
		);
		child.replacement_of = Some("parent".to_string());

		let attempts = vec![parent, child];
		let hash = choose_recovery_attempt_hash(&attempts, TransactionType::Fill).unwrap();

		assert_eq!(hash, TransactionHash(vec![0xbb; 32]));
	}

	#[test]
	fn recovery_skips_submit_rejected_and_replaced() {
		let a = sample_attempt(
			"A",
			TransactionType::Fill,
			TransactionAttemptStatus::SubmitRejected,
			None,
			100,
		);
		let mut b = sample_attempt(
			"B",
			TransactionType::Fill,
			TransactionAttemptStatus::Replaced,
			Some(0xbb),
			200,
		);
		b.replacement_of = Some("A".to_string());

		let attempts = vec![a, b];

		assert!(choose_recovery_attempt_hash(&attempts, TransactionType::Fill).is_none());
	}

	#[test]
	fn recovery_attempt_hash_skips_rejected_reverted_replaced_members() {
		let mut replaced = sample_attempt(
			"replaced",
			TransactionType::Fill,
			TransactionAttemptStatus::Replaced,
			Some(0xaa),
			100,
		);
		let mut rejected = sample_attempt(
			"rejected",
			TransactionType::Fill,
			TransactionAttemptStatus::SubmitRejected,
			Some(0xbb),
			200,
		);
		rejected.replacement_of = Some("replaced".to_string());
		let mut reverted = sample_attempt(
			"reverted",
			TransactionType::Fill,
			TransactionAttemptStatus::Reverted,
			Some(0xcc),
			300,
		);
		reverted.replacement_of = Some("rejected".to_string());
		replaced.replaced_by = Some("rejected".to_string());
		rejected.replaced_by = Some("reverted".to_string());

		let attempts = vec![replaced, rejected, reverted];

		assert!(choose_recovery_attempt_hash(&attempts, TransactionType::Fill).is_none());
	}

	fn sample_tx(chain_id: u64) -> Transaction {
		Transaction {
			to: Some(Address(vec![3; 20])),
			data: vec![0xde, 0xad, 0xbe, 0xef],
			value: alloy_primitives::U256::ZERO,
			chain_id,
			nonce: Some(7),
			gas_limit: Some(120000),
			gas_price: None,
			max_fee_per_gas: Some(2000),
			max_priority_fee_per_gas: Some(20),
		}
	}

	#[tokio::test]
	async fn recovery_marks_matching_broadcast_attempt_confirmed_when_fill_receipt_is_proven() {
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));

		let mut order = create_test_order_with_status(OrderStatus::Executed);
		order.fill_tx_hash = None;
		order.post_fill_tx_hash = None;
		order.settlement_name = Some("eip7683".to_string());
		state_machine.store_order(&order).await.unwrap();

		let tx_hash = TransactionHash(vec![0xbb; 32]);
		let attempt = attempt_store
			.create_planned_attempt(
				&order.id,
				Some(Address(vec![9; 20])),
				TransactionType::Fill,
				sample_tx(137),
			)
			.await
			.unwrap();
		attempt_store
			.update_attempt_status(
				&attempt.id,
				TransactionAttemptStatus::Broadcast,
				None,
				|attempt| {
					attempt.tx_hash = Some(tx_hash.clone());
				},
			)
			.await
			.unwrap();

		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_get_receipt()
			.with(eq(tx_hash.clone()), eq(137u64))
			.times(1)
			.returning(move |hash, _| {
				let hash = hash.clone();
				Box::pin(async move {
					Ok(solver_types::TransactionReceipt {
						hash,
						block_number: 12345,
						success: true,
						block_timestamp: None,
						logs: vec![],
					})
				})
			});
		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				137u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
			60,
		));

		let mut mock_settlement = MockSettlementInterface::new();
		mock_settlement
			.expect_recover_post_fill_state()
			.times(1)
			.returning(|_| Box::pin(async move { Ok(false) }));
		let settlement = Arc::new(SettlementService::new(
			HashMap::from([(
				"eip7683".to_string(),
				Box::new(mock_settlement) as Box<dyn solver_settlement::SettlementInterface>,
			)]),
			String::new(),
			20,
		));
		let event_bus = EventBus::new(100);

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine.clone(),
			delivery,
			settlement,
			event_bus,
			attempt_store.clone(),
			empty_networks_config(),
		);

		let (repaired_order, result) = recovery_service
			.reconcile_with_blockchain(&order)
			.await
			.unwrap();

		assert!(matches!(result, ReconcileResult::NeedsPostFill));
		assert_eq!(repaired_order.fill_tx_hash, Some(tx_hash.clone()));
		let stored = state_machine.get_order(&order.id).await.unwrap();
		assert_eq!(stored.fill_tx_hash, Some(tx_hash));
		let attempt = attempt_store.get_attempt(&attempt.id).await.unwrap();
		assert_eq!(attempt.status, TransactionAttemptStatus::Confirmed);
		assert!(attempt.receipt.is_some());
	}

	#[tokio::test]
	async fn recovery_terminal_attempt_conflict_is_operator_visible_not_silent() {
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));

		let tx_hash = TransactionHash(vec![0xcc; 32]);
		let mut order = create_test_order_with_status(OrderStatus::Executing);
		order.fill_tx_hash = Some(tx_hash.clone());
		order.post_fill_tx_hash = None;
		order.settlement_name = Some("eip7683".to_string());
		state_machine.store_order(&order).await.unwrap();

		let attempt = attempt_store
			.create_planned_attempt(
				&order.id,
				Some(Address(vec![9; 20])),
				TransactionType::Fill,
				sample_tx(137),
			)
			.await
			.unwrap();
		attempt_store
			.update_attempt_status(
				&attempt.id,
				TransactionAttemptStatus::Replaced,
				None,
				|attempt| {
					attempt.tx_hash = Some(tx_hash.clone());
				},
			)
			.await
			.unwrap();

		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_get_receipt()
			.with(eq(tx_hash.clone()), eq(137u64))
			.times(1)
			.returning(move |hash, _| {
				let hash = hash.clone();
				Box::pin(async move {
					Ok(solver_types::TransactionReceipt {
						hash,
						block_number: 12345,
						success: true,
						block_timestamp: None,
						logs: vec![],
					})
				})
			});
		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				137u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
			60,
		));

		let mut mock_settlement = MockSettlementInterface::new();
		mock_settlement
			.expect_recover_post_fill_state()
			.times(1)
			.returning(|_| Box::pin(async move { Ok(false) }));
		let settlement = Arc::new(SettlementService::new(
			HashMap::from([(
				"eip7683".to_string(),
				Box::new(mock_settlement) as Box<dyn solver_settlement::SettlementInterface>,
			)]),
			String::new(),
			20,
		));
		let event_bus = EventBus::new(100);
		let mut receiver = event_bus.subscribe();

		let recovery_service = RecoveryService::new(
			storage,
			state_machine,
			delivery,
			settlement,
			event_bus,
			attempt_store,
			empty_networks_config(),
		);

		let (_repaired_order, result) = recovery_service
			.reconcile_with_blockchain(&order)
			.await
			.unwrap();

		assert!(matches!(result, ReconcileResult::NeedsPostFill));
		let event = receiver.try_recv().expect("expected conflict event");
		match event {
			SolverEvent::Delivery(DeliveryEvent::TransactionAttemptLedgerConflict {
				order_id,
				attempt_id,
				tx_type,
				tx_hash: event_tx_hash,
				attempted_status,
				context,
				..
			}) => {
				assert_eq!(order_id, order.id);
				assert_eq!(attempt_id, attempt.id);
				assert_eq!(tx_type, TransactionType::Fill);
				assert_eq!(event_tx_hash, Some(tx_hash));
				assert_eq!(attempted_status, TransactionAttemptStatus::Confirmed);
				assert_eq!(context, "recovery mark confirmed");
			},
			other => panic!("expected TransactionAttemptLedgerConflict, got {other:?}"),
		}
	}

	#[tokio::test]
	async fn recovery_uses_claim_attempt_before_fill_attempt() {
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));

		let mut order = create_test_order_with_status(OrderStatus::Settled);
		order.fill_tx_hash = None;
		order.claim_tx_hash = None;
		state_machine.store_order(&order).await.unwrap();

		let fill_hash = TransactionHash(vec![0xf1; 32]);
		let claim_hash = TransactionHash(vec![0xc1; 32]);

		for (tx_type, tx_hash, chain_id) in [
			(TransactionType::Fill, fill_hash.clone(), 137),
			(TransactionType::Claim, claim_hash.clone(), 1),
		] {
			let attempt = attempt_store
				.create_planned_attempt(
					&order.id,
					Some(Address(vec![9; 20])),
					tx_type,
					sample_tx(chain_id),
				)
				.await
				.unwrap();
			attempt_store
				.update_attempt_status(
					&attempt.id,
					TransactionAttemptStatus::Confirmed,
					None,
					|attempt| {
						attempt.tx_hash = Some(tx_hash);
					},
				)
				.await
				.unwrap();
		}

		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_get_receipt()
			.with(eq(claim_hash.clone()), eq(1u64))
			.times(1)
			.returning(move |hash, _| {
				let hash = hash.clone();
				Box::pin(async move {
					Ok(solver_types::TransactionReceipt {
						hash,
						block_number: 999,
						success: true,
						block_timestamp: None,
						logs: vec![],
					})
				})
			});
		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				1u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
			60,
		));

		let settlement = Arc::new(SettlementService::new(HashMap::new(), String::new(), 20));
		let event_bus = EventBus::new(100);
		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine.clone(),
			delivery,
			settlement,
			event_bus,
			attempt_store,
			empty_networks_config(),
		);

		let (repaired_order, result) = recovery_service
			.reconcile_with_blockchain(&order)
			.await
			.unwrap();

		assert!(matches!(result, ReconcileResult::Finalized));
		assert_eq!(repaired_order.claim_tx_hash, Some(claim_hash.clone()));
		let stored = state_machine.get_order(&order.id).await.unwrap();
		assert_eq!(stored.claim_tx_hash, Some(claim_hash));
	}

	#[tokio::test]
	async fn recovery_continues_with_recovered_hash_when_order_writeback_fails() {
		let mut mock_storage = MockStorageInterface::new();
		mock_storage
			.expect_get_bytes()
			.with(eq("orders:test_order_123"))
			.times(1)
			.returning(|_| {
				Box::pin(async move {
					Err(solver_storage::StorageError::Backend(
						"writeback unavailable".to_string(),
					))
				})
			});

		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20, 60));
		let settlement = Arc::new(SettlementService::new(HashMap::new(), String::new(), 20));
		let event_bus = EventBus::new(100);
		let (attempt_store, _attempts_tmp) = empty_attempt_store();
		let recovery_service = RecoveryService::new(
			storage,
			state_machine,
			delivery,
			settlement,
			event_bus,
			attempt_store,
			empty_networks_config(),
		);

		let mut order = create_test_order_with_status(OrderStatus::Executed);
		order.fill_tx_hash = None;
		let recovered_hash = TransactionHash(vec![0xbb; 32]);
		let attempts = vec![sample_attempt(
			"fill",
			TransactionType::Fill,
			TransactionAttemptStatus::Broadcast,
			Some(0xbb),
			100,
		)];

		let resolution = recovery_service
			.resolve_stage(&mut order, &attempts, TransactionType::Fill)
			.await;

		match resolution {
			StageResolution::Hash(h) => assert_eq!(h, recovered_hash.clone()),
			other => panic!("expected Hash, got {:?}", std::mem::discriminant(&other)),
		}
		assert_eq!(order.fill_tx_hash, Some(recovered_hash));
	}

	#[tokio::test]
	async fn test_recover_state_no_orders() {
		let mut mock_storage = MockStorageInterface::new();

		// Setup expectations for no orders
		mock_storage
			.expect_query()
			.times(1)
			.returning(|_, _| Box::pin(async move { Ok(Vec::new()) }));

		// When query returns empty, get_batch is still called with empty keys
		mock_storage
			.expect_get_batch()
			.times(1)
			.returning(|_| Box::pin(async move { Ok(Vec::new()) }));

		// Create services
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let delivery_impls: HashMap<u64, Arc<dyn solver_delivery::DeliveryInterface>> =
			HashMap::new();
		let delivery = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));
		let settlement_impls: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::new();
		let settlement = Arc::new(SettlementService::new(settlement_impls, String::new(), 20));
		let event_bus = EventBus::new(100);
		let (attempt_store, _attempts_tmp) = empty_attempt_store();

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			attempt_store,
			empty_networks_config(),
		);

		// Test recovery with no orders
		let result = recovery_service.recover_state().await;
		assert!(result.is_ok());

		let (report, orphaned_intents) = result.unwrap();
		assert_eq!(report.total_orders, 0);
		assert_eq!(report.orphaned_intents, 0);
		assert_eq!(report.reconciled_orders, 0);
		assert!(orphaned_intents.is_empty());
	}

	#[tokio::test]
	async fn test_load_active_orders_success() {
		let mut mock_storage = MockStorageInterface::new();
		let order = create_test_order_with_status(OrderStatus::Pending);

		// Serialize order for storage mock
		let order_bytes = serde_json::to_vec(&order).unwrap();
		let order_key = format!("orders:{}", order.id);
		let order_key_clone = order_key.clone();

		mock_storage.expect_query().times(1).returning(move |_, _| {
			let key = order_key_clone.clone();
			Box::pin(async move { Ok(vec![key]) })
		});

		mock_storage
			.expect_get_batch()
			.times(1)
			.returning(move |_| {
				let key = order_key.clone();
				let bytes = order_bytes.clone();
				Box::pin(async move { Ok(vec![(key, bytes)]) })
			});

		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let delivery_impls: HashMap<u64, Arc<dyn solver_delivery::DeliveryInterface>> =
			HashMap::new();
		let delivery = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));
		let settlement_impls: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::new();
		let settlement = Arc::new(SettlementService::new(settlement_impls, String::new(), 20));
		let event_bus = EventBus::new(100);
		let (attempt_store, _attempts_tmp) = empty_attempt_store();

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			attempt_store,
			empty_networks_config(),
		);

		let result = recovery_service.load_active_orders().await;
		assert!(result.is_ok());

		let orders = result.unwrap();
		assert_eq!(orders.len(), 1);
		assert_eq!(orders[0].id, "test_order_123");
		assert_eq!(orders[0].status, OrderStatus::Pending);
	}

	#[tokio::test]
	async fn load_active_orders_queries_canonical_status_kind_index() {
		let mut mock_storage = MockStorageInterface::new();

		mock_storage
			.expect_query()
			.withf(|namespace, filter| {
				if namespace != "orders" {
					return false;
				}

				matches!(
					filter,
					QueryFilter::NotIn(field, values)
						if field == "status_kind"
							&& values
								== &vec![
									serde_json::json!("finalized"),
									serde_json::json!("failed"),
								]
				)
			})
			.times(1)
			.returning(|_, _| Box::pin(async move { Ok(Vec::new()) }));

		mock_storage
			.expect_get_batch()
			.times(1)
			.withf(|keys| keys.is_empty())
			.returning(|_| Box::pin(async move { Ok(Vec::new()) }));

		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let delivery_impls: HashMap<u64, Arc<dyn solver_delivery::DeliveryInterface>> =
			HashMap::new();
		let delivery = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));
		let settlement_impls: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::new();
		let settlement = Arc::new(SettlementService::new(settlement_impls, String::new(), 20));
		let event_bus = EventBus::new(100);
		let (attempt_store, _attempts_tmp) = empty_attempt_store();

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			attempt_store,
			empty_networks_config(),
		);

		let orders = recovery_service.load_active_orders().await.unwrap();
		assert!(orders.is_empty());
	}

	#[tokio::test]
	async fn test_recover_orphaned_intents() {
		let mut mock_storage = MockStorageInterface::new();
		let intent = create_test_intent();

		// Serialize intent for storage mock
		let intent_bytes = serde_json::to_vec(&intent).unwrap();
		let intent_key = format!("intents:{}", intent.id);
		let intent_key_clone = intent_key.clone();

		// Mock retrieve_all for intents
		mock_storage
			.expect_query()
			.with(eq("intents"), always())
			.times(1)
			.returning({
				let intent_key_clone = intent_key_clone.clone();
				move |_, _| {
					let key = intent_key_clone.clone();
					Box::pin(async move { Ok(vec![key]) })
				}
			});

		mock_storage.expect_get_batch().times(1).returning({
			let intent_key = intent_key.clone();
			let intent_bytes = intent_bytes.clone();
			move |_| {
				let key = intent_key.clone();
				let bytes = intent_bytes.clone();
				Box::pin(async move { Ok(vec![(key, bytes)]) })
			}
		});

		// Mock exists check for corresponding order (returns false = orphaned)
		mock_storage
			.expect_exists()
			.with(eq("orders:test_intent_123"))
			.times(1)
			.returning(|_| Box::pin(async { Ok(false) }));

		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let delivery_impls: HashMap<u64, Arc<dyn solver_delivery::DeliveryInterface>> =
			HashMap::new();
		let delivery = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));
		let settlement_impls: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::new();
		let settlement = Arc::new(SettlementService::new(settlement_impls, String::new(), 20));
		let event_bus = EventBus::new(100);
		let (attempt_store, _attempts_tmp) = empty_attempt_store();

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			attempt_store,
			empty_networks_config(),
		);

		let result = recovery_service.recover_orphaned_intents().await;
		assert!(result.is_ok());

		let orphaned = result.unwrap();
		assert_eq!(orphaned.len(), 1);
		assert_eq!(orphaned[0].id, "test_intent_123");
	}

	#[tokio::test]
	async fn test_reconcile_with_blockchain_needs_execution() {
		let order = create_test_order_with_status(OrderStatus::Created);

		let mock_storage = MockStorageInterface::new();
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let delivery_impls: HashMap<u64, Arc<dyn solver_delivery::DeliveryInterface>> =
			HashMap::new();
		let delivery = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));
		let settlement_impls: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::new();
		let settlement = Arc::new(SettlementService::new(settlement_impls, String::new(), 20));
		let event_bus = EventBus::new(100);
		let (attempt_store, _attempts_tmp) = empty_attempt_store();

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			attempt_store,
			empty_networks_config(),
		);

		let result = recovery_service.reconcile_with_blockchain(&order).await;
		assert!(result.is_ok());

		match result.unwrap().1 {
			ReconcileResult::NeedsExecution => {},
			_ => panic!("Expected NeedsExecution"),
		}
	}

	// For tests that need to mock delivery status, create a mock implementation and add it to the DeliveryService
	#[tokio::test]
	async fn test_reconcile_with_blockchain_needs_fill() {
		let mut mock_delivery = MockDeliveryInterface::new();
		let mut order = create_test_order_with_status(OrderStatus::Executed);
		order.prepare_tx_hash = Some(TransactionHash(vec![0xaa; 32]));

		// Mock successful prepare transaction
		mock_delivery
			.expect_get_receipt()
			.with(eq(TransactionHash(vec![0xaa; 32])), eq(1u64))
			.times(1)
			.returning(|_, _| {
				Box::pin(async {
					Ok(solver_types::TransactionReceipt {
						hash: TransactionHash(vec![0xaa; 32]),
						block_number: 12345,
						success: true,
						block_timestamp: None,
						logs: vec![],
					})
				})
			});

		let delivery_impls: HashMap<u64, Arc<dyn solver_delivery::DeliveryInterface>> =
			HashMap::from([(
				1u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]);
		let delivery = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));

		let mock_storage = MockStorageInterface::new();
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let settlement_impls: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::new();
		let settlement = Arc::new(SettlementService::new(settlement_impls, String::new(), 20));
		let event_bus = EventBus::new(100);
		let (attempt_store, _attempts_tmp) = empty_attempt_store();

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			attempt_store,
			empty_networks_config(),
		);

		let result = recovery_service.reconcile_with_blockchain(&order).await;
		assert!(result.is_ok());

		match result.unwrap().1 {
			ReconcileResult::NeedsFill => {},
			_ => panic!("Expected NeedsFill"),
		}
	}

	#[tokio::test]
	async fn test_reconcile_with_blockchain_needs_claim() {
		let mut mock_delivery = MockDeliveryInterface::new();
		let mut order = create_test_order_with_status(OrderStatus::Executed);
		order.fill_tx_hash = Some(TransactionHash(vec![0xbb; 32]));
		order.fill_proof = Some(create_test_fill_proof());
		// Add pre_claim_tx_hash to trigger the NeedsClaim path
		order.pre_claim_tx_hash = Some(TransactionHash(vec![0xcc; 32]));

		// Mock successful pre-claim transaction status - this will trigger NeedsClaim
		mock_delivery
			.expect_get_receipt()
			.with(eq(TransactionHash(vec![0xcc; 32])), eq(1u64)) // input chain
			.times(1)
			.returning(|_, _| {
				Box::pin(async {
					Ok(solver_types::TransactionReceipt {
						hash: TransactionHash(vec![0xcc; 32]),
						block_number: 12344,
						success: true,
						block_timestamp: None,
						logs: vec![],
					})
				})
			});

		let delivery_impls: HashMap<u64, Arc<dyn solver_delivery::DeliveryInterface>> =
			HashMap::from([(
				1u64, // Use chain 1 for pre-claim transaction
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]);
		let delivery = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));

		let mock_storage = MockStorageInterface::new();
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let settlement_impls: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::new();
		let settlement = Arc::new(SettlementService::new(settlement_impls, String::new(), 20));
		let event_bus = EventBus::new(100);
		let (attempt_store, _attempts_tmp) = empty_attempt_store();

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			attempt_store,
			empty_networks_config(),
		);

		let result = recovery_service.reconcile_with_blockchain(&order).await;
		assert!(result.is_ok());

		match result.unwrap().1 {
			ReconcileResult::NeedsClaim { fill_proof } => {
				assert!(fill_proof.is_some());
			},
			_ => panic!("Expected NeedsClaim"),
		}
	}

	#[tokio::test]
	async fn test_reconcile_with_blockchain_recovers_existing_post_fill_state() {
		let mut mock_delivery = MockDeliveryInterface::new();
		let mut mock_settlement = MockSettlementInterface::new();
		let mut order = create_test_order_with_status(OrderStatus::Executed);
		order.fill_tx_hash = Some(TransactionHash(vec![0xbb; 32]));
		order.settlement_name = Some("eip7683".to_string());

		mock_delivery
			.expect_get_receipt()
			.with(eq(TransactionHash(vec![0xbb; 32])), eq(137u64))
			.times(1)
			.returning(|_, _| {
				Box::pin(async {
					Ok(solver_types::TransactionReceipt {
						hash: TransactionHash(vec![0xbb; 32]),
						block_number: 12345,
						success: true,
						block_timestamp: None,
						logs: vec![],
					})
				})
			});

		mock_settlement
			.expect_recover_post_fill_state()
			.times(1)
			.returning(|_| Box::pin(async move { Ok(true) }));

		let delivery_impls: HashMap<u64, Arc<dyn solver_delivery::DeliveryInterface>> =
			HashMap::from([(
				137u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]);
		let delivery = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));

		let mock_storage = MockStorageInterface::new();
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let settlement_impls: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::from([(
				"eip7683".to_string(),
				Box::new(mock_settlement) as Box<dyn solver_settlement::SettlementInterface>,
			)]);
		let settlement = Arc::new(SettlementService::new(settlement_impls, String::new(), 20));
		let event_bus = EventBus::new(100);
		let (attempt_store, _attempts_tmp) = empty_attempt_store();

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			attempt_store,
			empty_networks_config(),
		);

		let result = recovery_service.reconcile_with_blockchain(&order).await;
		assert!(result.is_ok());

		match result.unwrap().1 {
			ReconcileResult::NeedsMonitoring => {},
			other => panic!("Expected NeedsMonitoring, got {other:?}"),
		}
	}

	#[tokio::test]
	async fn post_fill_confirmed_with_fill_proof_needs_pre_claim() {
		let mut mock_delivery = MockDeliveryInterface::new();
		let mut order = create_test_order_with_status(OrderStatus::Settled);
		order.post_fill_tx_hash = Some(TransactionHash(vec![0xdd; 32]));
		order.fill_proof = Some(create_test_fill_proof());

		mock_delivery
			.expect_get_receipt()
			.with(eq(TransactionHash(vec![0xdd; 32])), eq(137u64))
			.times(1)
			.returning(|_, _| {
				Box::pin(async {
					Ok(solver_types::TransactionReceipt {
						hash: TransactionHash(vec![0xdd; 32]),
						block_number: 12345,
						success: true,
						block_timestamp: None,
						logs: vec![],
					})
				})
			});

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				137u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
			60,
		));

		let storage = Arc::new(StorageService::new(Box::new(MockStorageInterface::new())));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let settlement = Arc::new(SettlementService::new(HashMap::new(), String::new(), 20));
		let (attempt_store, _attempts_tmp) = empty_attempt_store();
		let recovery_service = RecoveryService::new(
			storage,
			state_machine,
			delivery,
			settlement,
			EventBus::new(100),
			attempt_store,
			empty_networks_config(),
		);

		let (_, result) = recovery_service
			.reconcile_with_blockchain(&order)
			.await
			.unwrap();

		assert!(matches!(
			result,
			ReconcileResult::NeedsPreClaim {
				fill_proof: Some(_)
			}
		));
	}

	#[tokio::test]
	async fn test_reconcile_with_blockchain_post_fill_recovery_miss_needs_post_fill() {
		let mut mock_delivery = MockDeliveryInterface::new();
		let mut mock_settlement = MockSettlementInterface::new();
		let mut order = create_test_order_with_status(OrderStatus::Executed);
		order.fill_tx_hash = Some(TransactionHash(vec![0xbb; 32]));
		order.settlement_name = Some("eip7683".to_string());

		mock_delivery
			.expect_get_receipt()
			.with(eq(TransactionHash(vec![0xbb; 32])), eq(137u64))
			.times(1)
			.returning(|_, _| {
				Box::pin(async {
					Ok(solver_types::TransactionReceipt {
						hash: TransactionHash(vec![0xbb; 32]),
						block_number: 12345,
						success: true,
						block_timestamp: None,
						logs: vec![],
					})
				})
			});

		mock_settlement
			.expect_recover_post_fill_state()
			.times(1)
			.returning(|_| Box::pin(async move { Ok(false) }));

		let delivery_impls: HashMap<u64, Arc<dyn solver_delivery::DeliveryInterface>> =
			HashMap::from([(
				137u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]);
		let delivery = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));

		let mock_storage = MockStorageInterface::new();
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let settlement_impls: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::from([(
				"eip7683".to_string(),
				Box::new(mock_settlement) as Box<dyn solver_settlement::SettlementInterface>,
			)]);
		let settlement = Arc::new(SettlementService::new(settlement_impls, String::new(), 20));
		let event_bus = EventBus::new(100);
		let (attempt_store, _attempts_tmp) = empty_attempt_store();

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			attempt_store,
			empty_networks_config(),
		);

		let result = recovery_service.reconcile_with_blockchain(&order).await;
		assert!(result.is_ok());
		assert!(matches!(result.unwrap().1, ReconcileResult::NeedsPostFill));
	}

	#[tokio::test]
	async fn test_reconcile_with_blockchain_post_fill_recovery_error_propagates() {
		let mut mock_delivery = MockDeliveryInterface::new();
		let mut mock_settlement = MockSettlementInterface::new();
		let mut order = create_test_order_with_status(OrderStatus::Executed);
		order.fill_tx_hash = Some(TransactionHash(vec![0xbb; 32]));
		order.settlement_name = Some("eip7683".to_string());

		mock_delivery
			.expect_get_receipt()
			.with(eq(TransactionHash(vec![0xbb; 32])), eq(137u64))
			.times(1)
			.returning(|_, _| {
				Box::pin(async {
					Ok(solver_types::TransactionReceipt {
						hash: TransactionHash(vec![0xbb; 32]),
						block_number: 12345,
						success: true,
						block_timestamp: None,
						logs: vec![],
					})
				})
			});

		mock_settlement
			.expect_recover_post_fill_state()
			.times(1)
			.returning(|_| {
				Box::pin(async move {
					Err(solver_settlement::SettlementError::ValidationFailed(
						"recovery window exhausted".to_string(),
					))
				})
			});

		let delivery_impls: HashMap<u64, Arc<dyn solver_delivery::DeliveryInterface>> =
			HashMap::from([(
				137u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]);
		let delivery = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));

		let mock_storage = MockStorageInterface::new();
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let settlement_impls: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::from([(
				"eip7683".to_string(),
				Box::new(mock_settlement) as Box<dyn solver_settlement::SettlementInterface>,
			)]);
		let settlement = Arc::new(SettlementService::new(settlement_impls, String::new(), 20));
		let event_bus = EventBus::new(100);
		let (attempt_store, _attempts_tmp) = empty_attempt_store();

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			attempt_store,
			empty_networks_config(),
		);

		let result = recovery_service.reconcile_with_blockchain(&order).await;
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), RecoveryError::Settlement(_)));
	}

	#[tokio::test]
	async fn test_reconcile_with_blockchain_finalized() {
		let mut mock_delivery = MockDeliveryInterface::new();
		let mut order = create_test_order_with_status(OrderStatus::Settled);
		order.claim_tx_hash = Some(TransactionHash(vec![0xcc; 32]));

		// Mock successful claim transaction
		mock_delivery
			.expect_get_receipt()
			.with(eq(TransactionHash(vec![0xcc; 32])), eq(1u64))
			.times(1)
			.returning(|_, _| {
				Box::pin(async {
					Ok(solver_types::TransactionReceipt {
						hash: TransactionHash(vec![0xcc; 32]),
						block_number: 12345,
						success: true,
						block_timestamp: None,
						logs: vec![],
					})
				})
			});

		let delivery_impls: HashMap<u64, Arc<dyn solver_delivery::DeliveryInterface>> =
			HashMap::from([(
				1u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]);
		let delivery = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));

		let mock_storage = MockStorageInterface::new();
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let settlement_impls: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::new();
		let settlement = Arc::new(SettlementService::new(settlement_impls, String::new(), 20));
		let event_bus = EventBus::new(100);
		let (attempt_store, _attempts_tmp) = empty_attempt_store();

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			attempt_store,
			empty_networks_config(),
		);

		let result = recovery_service.reconcile_with_blockchain(&order).await;
		assert!(result.is_ok());

		match result.unwrap().1 {
			ReconcileResult::Finalized => {},
			_ => panic!("Expected Finalized"),
		}
	}

	#[tokio::test]
	async fn test_reconcile_with_blockchain_failed_transaction() {
		let mut mock_delivery = MockDeliveryInterface::new();
		let mut order = create_test_order_with_status(OrderStatus::Executed);
		order.prepare_tx_hash = Some(TransactionHash(vec![0xaa; 32]));

		// Mock failed prepare transaction
		mock_delivery
			.expect_get_receipt()
			.with(eq(TransactionHash(vec![0xaa; 32])), eq(1u64))
			.times(1)
			.returning(|_, _| {
				Box::pin(async {
					Ok(solver_types::TransactionReceipt {
						hash: TransactionHash(vec![0xaa; 32]),
						block_number: 12345,
						success: false,
						block_timestamp: None,
						logs: vec![],
					})
				})
			});

		let delivery_impls: HashMap<u64, Arc<dyn solver_delivery::DeliveryInterface>> =
			HashMap::from([(
				1u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]);
		let delivery = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));

		let mock_storage = MockStorageInterface::new();
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let settlement_impls: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::new();
		let settlement = Arc::new(SettlementService::new(settlement_impls, String::new(), 20));
		let event_bus = EventBus::new(100);
		let (attempt_store, _attempts_tmp) = empty_attempt_store();

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			attempt_store,
			empty_networks_config(),
		);

		let result = recovery_service.reconcile_with_blockchain(&order).await;
		assert!(result.is_ok());

		match result.unwrap().1 {
			ReconcileResult::Failed(TransactionType::Prepare) => {},
			_ => panic!("Expected Failed(Prepare)"),
		}
	}

	#[tokio::test]
	async fn test_reconcile_with_blockchain_rpc_error_returns_unknown_not_failed() {
		// A transient RPC error or tx-not-found must NOT terminally fail the
		// order. Recovery should return Unknown so the caller leaves the order
		// in its current status; the next solver restart's recovery pass will
		// re-reconcile. Without this, RPC blips during recovery convert healthy
		// in-flight orders into terminal Failed orders.
		let mut mock_delivery = MockDeliveryInterface::new();
		let mut order = create_test_order_with_status(OrderStatus::Executed);
		order.prepare_tx_hash = Some(TransactionHash(vec![0xaa; 32]));

		// Simulate a transport-level RPC error.
		mock_delivery
			.expect_get_receipt()
			.with(eq(TransactionHash(vec![0xaa; 32])), eq(1u64))
			.times(1)
			.returning(|_, _| {
				Box::pin(async {
					Err(solver_delivery::DeliveryError::Network(
						"connection reset by peer".to_string(),
					))
				})
			});

		let delivery_impls: HashMap<u64, Arc<dyn solver_delivery::DeliveryInterface>> =
			HashMap::from([(
				1u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]);
		let delivery = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));

		let mock_storage = MockStorageInterface::new();
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let settlement_impls: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::new();
		let settlement = Arc::new(SettlementService::new(settlement_impls, String::new(), 20));
		let event_bus = EventBus::new(100);
		let (attempt_store, _attempts_tmp) = empty_attempt_store();

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			attempt_store,
			empty_networks_config(),
		);

		let result = recovery_service.reconcile_with_blockchain(&order).await;
		assert!(result.is_ok());

		match result.unwrap().1 {
			ReconcileResult::Unknown => {},
			other => panic!("Expected Unknown for RPC error, got {other:?}"),
		}
	}

	#[tokio::test]
	async fn test_publish_recovery_event_needs_claim_ready() {
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let order = create_test_order_with_status(OrderStatus::Settled);
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		state_machine.store_order(&order).await.unwrap();
		let delivery_impls: HashMap<u64, Arc<dyn solver_delivery::DeliveryInterface>> =
			HashMap::new();
		let delivery = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));

		// Create empty settlement service - this will cause can_claim to return false,
		// which should trigger spawn_settlement_monitor instead of publishing ClaimReady
		let settlement_impls: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::new();
		let settlement = Arc::new(SettlementService::new(settlement_impls, String::new(), 20));
		let event_bus = EventBus::new(100);

		// Subscribe to events
		let mut receiver = event_bus.subscribe();
		let (attempt_store, _attempts_tmp) = empty_attempt_store();

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			attempt_store,
			empty_networks_config(),
		);

		recovery_service
			.publish_recovery_event(
				order.clone(),
				ReconcileResult::NeedsClaim {
					fill_proof: Some(create_test_fill_proof()),
				},
			)
			.await;

		// Since can_claim will return false (no settlement impl found),
		// no ClaimReady event should be published, so receiver should be empty
		assert!(
			receiver.try_recv().is_err(),
			"Expected no event to be published when can_claim returns false"
		);
	}

	#[tokio::test]
	async fn test_publish_recovery_event_needs_execution() {
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let order = create_test_order_with_status(OrderStatus::Created);
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		state_machine.store_order(&order).await.unwrap();
		let delivery_impls: HashMap<u64, Arc<dyn solver_delivery::DeliveryInterface>> =
			HashMap::new();
		let delivery = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));
		let settlement_impls: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::new();
		let settlement = Arc::new(SettlementService::new(settlement_impls, String::new(), 20));
		let event_bus = EventBus::new(100);

		// Subscribe to events
		let mut receiver = event_bus.subscribe();
		let (attempt_store, _attempts_tmp) = empty_attempt_store();

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			attempt_store,
			empty_networks_config(),
		);

		recovery_service
			.publish_recovery_event(order.clone(), ReconcileResult::NeedsExecution)
			.await;

		// Check that the correct event was published
		let event = receiver.try_recv().unwrap();
		match event {
			SolverEvent::Order(OrderEvent::Executing {
				order: event_order,
				params: _,
			}) => {
				assert_eq!(event_order.id, order.id);
			},
			_ => panic!("Expected Order::Executing event"),
		}
	}

	#[tokio::test]
	async fn test_publish_recovery_event_needs_pre_claim_waiting_starts_monitoring() {
		let mut mock_settlement = MockSettlementInterface::new();
		let mut order = create_test_order_with_status(OrderStatus::Executed);
		order.settlement_name = Some("eip7683".to_string());
		order.fill_tx_hash = Some(TransactionHash(vec![0xbb; 32]));

		mock_settlement
			.expect_readiness()
			.times(1)
			.returning(|_, _| {
				Box::pin(async move {
					SettlementReadiness::Waiting(
						solver_settlement::WaitingReason::ProofServiceNotReady,
					)
				})
			});

		let storage = Arc::new(StorageService::new(Box::new(
			solver_storage::implementations::memory::MemoryStorage::new(),
		)));
		storage
			.store(StorageKey::Orders.as_str(), &order.id, &order, None)
			.await
			.unwrap();
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20, 60));
		let settlement_impls: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::from([(
				"eip7683".to_string(),
				Box::new(mock_settlement) as Box<dyn solver_settlement::SettlementInterface>,
			)]);
		let settlement = Arc::new(SettlementService::new(settlement_impls, String::new(), 20));
		let event_bus = EventBus::new(100);
		let mut receiver = event_bus.subscribe();
		let (attempt_store, _attempts_tmp) = empty_attempt_store();

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			attempt_store,
			empty_networks_config(),
		);

		recovery_service
			.publish_recovery_event(
				order,
				ReconcileResult::NeedsPreClaim {
					fill_proof: Some(create_test_fill_proof()),
				},
			)
			.await;

		match receiver.try_recv().unwrap() {
			SolverEvent::Settlement(SettlementEvent::StartMonitoring {
				order_id,
				fill_tx_hash,
			}) => {
				assert_eq!(order_id, "test_order_123");
				assert_eq!(fill_tx_hash, TransactionHash(vec![0xbb; 32]));
			},
			other => panic!("Expected StartMonitoring event, got {other:?}"),
		}
	}

	#[tokio::test]
	async fn test_publish_recovery_event_needs_claim_permanent_failure_marks_order_failed() {
		let mut mock_settlement = MockSettlementInterface::new();
		let mut order = create_test_order_with_status(OrderStatus::Settled);
		order.settlement_name = Some("eip7683".to_string());
		order.fill_tx_hash = Some(TransactionHash(vec![0xbb; 32]));
		order.pre_claim_tx_hash = Some(TransactionHash(vec![0xcc; 32]));

		mock_settlement
			.expect_readiness()
			.times(1)
			.returning(|_, _| {
				Box::pin(async move {
					SettlementReadiness::PermanentFailure("proof permanently invalid".into())
				})
			});

		let storage = Arc::new(StorageService::new(Box::new(
			solver_storage::implementations::memory::MemoryStorage::new(),
		)));
		storage
			.store(StorageKey::Orders.as_str(), &order.id, &order, None)
			.await
			.unwrap();
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20, 60));
		let settlement_impls: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::from([(
				"eip7683".to_string(),
				Box::new(mock_settlement) as Box<dyn solver_settlement::SettlementInterface>,
			)]);
		let settlement = Arc::new(SettlementService::new(settlement_impls, String::new(), 20));
		let event_bus = EventBus::new(100);
		let mut receiver = event_bus.subscribe();
		let (attempt_store, _attempts_tmp) = empty_attempt_store();

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			attempt_store,
			empty_networks_config(),
		);

		recovery_service
			.publish_recovery_event(
				order.clone(),
				ReconcileResult::NeedsClaim {
					fill_proof: Some(create_test_fill_proof()),
				},
			)
			.await;

		assert!(
			receiver.try_recv().is_err(),
			"Permanent failure should not emit follow-up events"
		);

		let updated: Order = storage
			.retrieve(StorageKey::Orders.as_str(), &order.id)
			.await
			.unwrap();
		assert!(matches!(
			updated.status,
			OrderStatus::Failed(TransactionType::Claim, _)
		));
	}

	#[tokio::test]
	async fn test_recovery_report_structure() {
		let report = RecoveryReport {
			total_orders: 5,
			orphaned_intents: 2,
			reconciled_orders: 4,
		};

		assert_eq!(report.total_orders, 5);
		assert_eq!(report.orphaned_intents, 2);
		assert_eq!(report.reconciled_orders, 4);

		// Test default
		let default_report = RecoveryReport::default();
		assert_eq!(default_report.total_orders, 0);
		assert_eq!(default_report.orphaned_intents, 0);
		assert_eq!(default_report.reconciled_orders, 0);
	}

	#[tokio::test]
	async fn test_recovery_error_types() {
		let storage_error = RecoveryError::Storage("test storage error".to_string());
		assert!(storage_error.to_string().contains("Storage error"));

		let state_error = RecoveryError::StateMachine("test state error".to_string());
		assert!(state_error.to_string().contains("State machine error"));

		let delivery_error = RecoveryError::Delivery("test delivery error".to_string());
		assert!(delivery_error.to_string().contains("Delivery error"));

		let settlement_error = RecoveryError::Settlement("test settlement error".to_string());
		assert!(settlement_error.to_string().contains("Settlement error"));
	}

	// ========================================================================
	// Chain-aware recovery tests
	// ========================================================================

	use solver_types::standards::eip7683::interfaces::{
		Finalised, Open, OrderPurchased, OutputFilled, Refunded,
	};

	/// Match `filter.topics()[0]` against the expected event's signature hash.
	/// Without this, mocks accept calls for the wrong event signature.
	fn matches_event<E: alloy_sol_types::SolEvent>(filter: &solver_types::LogFilter) -> bool {
		filter
			.topics()
			.first()
			.and_then(|t| t.as_ref())
			.map(|h| h.0 == E::SIGNATURE_HASH.0)
			.unwrap_or(false)
	}

	fn networks_with(
		chain_id: u64,
		network: solver_types::NetworkConfig,
	) -> Arc<solver_types::NetworksConfig> {
		let mut map = solver_types::NetworksConfig::new();
		map.insert(chain_id, network);
		Arc::new(map)
	}

	fn test_network_config(
		input_settler: Address,
		output_settler: Address,
	) -> solver_types::NetworkConfig {
		solver_types::NetworkConfig {
			name: None,
			network_type: solver_types::NetworkType::New,
			rpc_urls: vec![],
			input_settler_address: input_settler,
			output_settler_address: output_settler,
			tokens: vec![],
			input_settler_compact_address: None,
			the_compact_address: None,
			allocator_address: None,
		}
	}

	#[tokio::test]
	async fn prepare_stage_complete_with_open_event_recovers_to_needs_fill() {
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));
		let input_settler = Address(vec![0xcc; 20]);
		let prepare_hash = TransactionHash(vec![0xab; 32]);
		let networks = networks_with(
			1,
			test_network_config(input_settler.clone(), Address(vec![0xaa; 20])),
		);

		let mut order = OrderBuilder::new()
			.with_id(format!("0x{}", "11".repeat(32)))
			.with_status(OrderStatus::Pending)
			.with_execution_params(Some(ExecutionParams {
				gas_price: alloy_primitives::U256::from(1000000000u64),
				priority_fee: Some(alloy_primitives::U256::from(1000000u64)),
			}))
			.build();
		state_machine.store_order(&order).await.unwrap();

		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_get_block_number()
			.with(eq(1u64))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(1_000_000u64) }));
		let prepare_hash_for_logs = prepare_hash.clone();
		mock_delivery
			.expect_get_logs()
			.withf(|chain_id, filter| *chain_id == 1 && matches_event::<Open>(filter))
			.times(1)
			.returning(move |_, _| {
				let tx_hash = prepare_hash_for_logs.clone();
				Box::pin(async move {
					Ok(vec![solver_types::Log {
						address: Address(vec![0xcc; 20]),
						topics: vec![],
						data: vec![],
						transaction_hash: Some(tx_hash),
						block_number: Some(995_000),
					}])
				})
			});
		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				1u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
			60,
		));
		let settlement = Arc::new(SettlementService::new(HashMap::new(), String::new(), 20));
		let recovery_service = RecoveryService::new(
			storage,
			state_machine,
			delivery,
			settlement,
			EventBus::new(100),
			attempt_store,
			networks,
		);

		let result = recovery_service
			.stage_complete_recovery(
				&mut order,
				TransactionType::Prepare,
				solver_delivery::StageCompleteReason::EscrowInvalidOrderStatus,
				&[],
			)
			.await;

		assert!(matches!(result, ReconcileResult::NeedsFill));
		assert_eq!(order.prepare_tx_hash, Some(prepare_hash));
	}

	#[tokio::test]
	async fn prepare_stage_complete_without_open_evidence_does_not_advance() {
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));
		let input_settler = Address(vec![0xcc; 20]);
		let networks = networks_with(
			1,
			test_network_config(input_settler.clone(), Address(vec![0xaa; 20])),
		);

		let mut order = OrderBuilder::new()
			.with_id(format!("0x{}", "22".repeat(32)))
			.with_status(OrderStatus::Pending)
			.build();
		state_machine.store_order(&order).await.unwrap();

		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_get_block_number()
			.with(eq(1u64))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(1_000_000u64) }));
		mock_delivery
			.expect_get_logs()
			.withf(|chain_id, filter| *chain_id == 1 && matches_event::<Open>(filter))
			.times(1)
			.returning(|_, _| Box::pin(async move { Ok(vec![]) }));
		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				1u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
			60,
		));
		let settlement = Arc::new(SettlementService::new(HashMap::new(), String::new(), 20));
		let recovery_service = RecoveryService::new(
			storage,
			state_machine,
			delivery,
			settlement,
			EventBus::new(100),
			attempt_store,
			networks,
		);

		let result = recovery_service
			.stage_complete_recovery(
				&mut order,
				TransactionType::Prepare,
				solver_delivery::StageCompleteReason::EscrowInvalidOrderStatus,
				&[],
			)
			.await;

		assert!(matches!(result, ReconcileResult::Unknown));
		assert!(order.prepare_tx_hash.is_none());
	}

	#[tokio::test]
	async fn recovery_repairs_fill_hash_from_chain_log_when_order_and_ledger_empty() {
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));

		let mut order = create_test_order_with_status(OrderStatus::Executed);
		order.fill_tx_hash = None;
		order.post_fill_tx_hash = None;
		order.settlement_name = Some("eip7683".to_string());
		state_machine.store_order(&order).await.unwrap();

		let output_settler = Address(vec![0xaa; 20]);
		let fill_hash = TransactionHash(vec![0xbb; 32]);

		let networks = networks_with(
			137,
			test_network_config(Address(vec![0xcc; 20]), output_settler.clone()),
		);

		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_get_block_number()
			.with(eq(137u64))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(1_000_000u64) }));

		let fill_hash_for_logs = fill_hash.clone();
		mock_delivery
			.expect_get_logs()
			.withf(|chain_id, filter| *chain_id == 137 && matches_event::<OutputFilled>(filter))
			.times(1)
			.returning(move |_, _| {
				let fh = fill_hash_for_logs.clone();
				Box::pin(async move {
					Ok(vec![solver_types::Log {
						address: Address(vec![0xaa; 20]),
						topics: vec![],
						data: vec![],
						transaction_hash: Some(fh),
						block_number: Some(995_000),
					}])
				})
			});

		mock_delivery
			.expect_get_receipt()
			.with(eq(fill_hash.clone()), eq(137u64))
			.times(1)
			.returning(|hash, _| {
				let hash = hash.clone();
				Box::pin(async move {
					Ok(solver_types::TransactionReceipt {
						hash,
						block_number: 995_000,
						success: true,
						block_timestamp: None,
						logs: vec![],
					})
				})
			});

		let mut mock_settlement = MockSettlementInterface::new();
		mock_settlement
			.expect_recover_post_fill_state()
			.times(1)
			.returning(|_| Box::pin(async move { Ok(false) }));

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				137u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
			60,
		));
		let settlement = Arc::new(SettlementService::new(
			HashMap::from([(
				"eip7683".to_string(),
				Box::new(mock_settlement) as Box<dyn solver_settlement::SettlementInterface>,
			)]),
			String::new(),
			20,
		));

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine.clone(),
			delivery,
			settlement,
			EventBus::new(100),
			attempt_store,
			networks,
		);

		let (repaired, result) = recovery_service
			.reconcile_with_blockchain(&order)
			.await
			.unwrap();
		assert!(matches!(result, ReconcileResult::NeedsPostFill));
		assert_eq!(repaired.fill_tx_hash, Some(fill_hash.clone()));
		assert_eq!(
			state_machine
				.get_order(&order.id)
				.await
				.unwrap()
				.fill_tx_hash,
			Some(fill_hash)
		);
	}

	#[tokio::test]
	async fn recovery_repairs_claim_hash_from_chain_log() {
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));

		let mut order = create_test_order_with_status(OrderStatus::Settled);
		order.fill_tx_hash = None;
		order.claim_tx_hash = None;
		state_machine.store_order(&order).await.unwrap();

		let input_settler = Address(vec![0xcc; 20]);
		let claim_hash = TransactionHash(vec![0xc1; 32]);

		let networks = networks_with(
			1,
			test_network_config(input_settler.clone(), Address(vec![0xaa; 20])),
		);

		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_get_block_number()
			.with(eq(1u64))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(20_000_000u64) }));

		let claim_hash_for_logs = claim_hash.clone();
		mock_delivery
			.expect_get_logs()
			.withf(|chain_id, filter| *chain_id == 1 && matches_event::<Finalised>(filter))
			.times(1)
			.returning(move |_, _| {
				let h = claim_hash_for_logs.clone();
				Box::pin(async move {
					Ok(vec![solver_types::Log {
						address: Address(vec![0xcc; 20]),
						topics: vec![],
						data: vec![],
						transaction_hash: Some(h),
						block_number: Some(19_995_000),
					}])
				})
			});

		mock_delivery
			.expect_get_receipt()
			.with(eq(claim_hash.clone()), eq(1u64))
			.times(1)
			.returning(|hash, _| {
				let hash = hash.clone();
				Box::pin(async move {
					Ok(solver_types::TransactionReceipt {
						hash,
						block_number: 19_995_000,
						success: true,
						block_timestamp: None,
						logs: vec![],
					})
				})
			});

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				1u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
			60,
		));
		let settlement = Arc::new(SettlementService::new(HashMap::new(), String::new(), 20));

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine.clone(),
			delivery,
			settlement,
			EventBus::new(100),
			attempt_store,
			networks,
		);

		let (repaired, result) = recovery_service
			.reconcile_with_blockchain(&order)
			.await
			.unwrap();
		assert!(matches!(result, ReconcileResult::Finalized));
		assert_eq!(repaired.claim_tx_hash, Some(claim_hash.clone()));
	}

	#[tokio::test]
	async fn claim_chain_probe_uses_prepare_hash_from_attempt_ledger_as_anchor() {
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));

		let mut order = create_test_order_with_status(OrderStatus::Settled);
		order.prepare_tx_hash = None;
		order.claim_tx_hash = None;
		state_machine.store_order(&order).await.unwrap();

		let prepare_hash = TransactionHash(vec![0xaa; 32]);
		let claim_hash = TransactionHash(vec![0xc1; 32]);
		let prepare_attempt = attempt_store
			.create_planned_attempt(
				&order.id,
				Some(Address(vec![9; 20])),
				TransactionType::Prepare,
				sample_tx(1),
			)
			.await
			.unwrap();
		attempt_store
			.update_attempt_status(
				&prepare_attempt.id,
				TransactionAttemptStatus::Broadcast,
				None,
				|attempt| {
					attempt.tx_hash = Some(prepare_hash.clone());
				},
			)
			.await
			.unwrap();

		let input_settler = Address(vec![0xcc; 20]);
		let networks = networks_with(
			1,
			test_network_config(input_settler.clone(), Address(vec![0xaa; 20])),
		);

		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_get_block_number()
			.with(eq(1u64))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(20_000_000u64) }));
		mock_delivery
			.expect_get_receipt()
			.with(eq(prepare_hash.clone()), eq(1u64))
			.times(1)
			.returning(|hash, _| {
				let hash = hash.clone();
				Box::pin(async move {
					Ok(solver_types::TransactionReceipt {
						hash,
						block_number: 19_990_000,
						success: true,
						block_timestamp: None,
						logs: vec![],
					})
				})
			});

		let claim_hash_for_logs = claim_hash.clone();
		mock_delivery
			.expect_get_logs()
			.withf(|chain_id, filter| *chain_id == 1 && matches_event::<Finalised>(filter))
			.times(1)
			.returning(move |_, _| {
				let h = claim_hash_for_logs.clone();
				Box::pin(async move {
					Ok(vec![solver_types::Log {
						address: Address(vec![0xcc; 20]),
						topics: vec![],
						data: vec![],
						transaction_hash: Some(h),
						block_number: Some(19_995_000),
					}])
				})
			});
		mock_delivery
			.expect_get_receipt()
			.with(eq(claim_hash.clone()), eq(1u64))
			.times(1)
			.returning(|hash, _| {
				let hash = hash.clone();
				Box::pin(async move {
					Ok(solver_types::TransactionReceipt {
						hash,
						block_number: 19_995_000,
						success: true,
						block_timestamp: None,
						logs: vec![],
					})
				})
			});

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				1u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
			60,
		));
		let settlement = Arc::new(SettlementService::new(HashMap::new(), String::new(), 20));

		let recovery_service = RecoveryService::new(
			storage,
			state_machine,
			delivery,
			settlement,
			EventBus::new(100),
			attempt_store,
			networks,
		);

		let (repaired, result) = recovery_service
			.reconcile_with_blockchain(&order)
			.await
			.unwrap();

		assert!(matches!(result, ReconcileResult::Finalized));
		assert_eq!(repaired.claim_tx_hash, Some(claim_hash));
	}

	#[tokio::test]
	async fn recovery_terminates_order_when_refunded_event_found() {
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));

		let mut order = create_test_order_with_status(OrderStatus::Settled);
		order.fill_tx_hash = None;
		order.claim_tx_hash = None;
		state_machine.store_order(&order).await.unwrap();

		let networks = networks_with(
			1,
			test_network_config(Address(vec![0xcc; 20]), Address(vec![0xaa; 20])),
		);

		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_get_block_number()
			.with(eq(1u64))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(20_000_000u64) }));

		// Finalised: empty
		mock_delivery
			.expect_get_logs()
			.withf(|chain_id, filter| *chain_id == 1 && matches_event::<Finalised>(filter))
			.times(1)
			.returning(|_, _| Box::pin(async move { Ok(vec![]) }));

		// Refunded: matches
		mock_delivery
			.expect_get_logs()
			.withf(|chain_id, filter| *chain_id == 1 && matches_event::<Refunded>(filter))
			.times(1)
			.returning(|_, _| {
				Box::pin(async move {
					Ok(vec![solver_types::Log {
						transaction_hash: Some(TransactionHash(vec![0xee; 32])),
						block_number: Some(19_995_000),
						..Default::default()
					}])
				})
			});

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				1u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
			60,
		));
		let settlement = Arc::new(SettlementService::new(HashMap::new(), String::new(), 20));

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			EventBus::new(100),
			attempt_store,
			networks,
		);

		let (repaired, result) = recovery_service
			.reconcile_with_blockchain(&order)
			.await
			.unwrap();
		assert!(matches!(
			result,
			ReconcileResult::Failed(TransactionType::Claim)
		));
		assert_eq!(repaired.claim_tx_hash, None);
	}

	#[tokio::test]
	async fn recovery_terminates_order_when_purchased_event_found() {
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));

		let mut order = create_test_order_with_status(OrderStatus::Settled);
		order.fill_tx_hash = None;
		order.claim_tx_hash = None;
		state_machine.store_order(&order).await.unwrap();

		let networks = networks_with(
			1,
			test_network_config(Address(vec![0xcc; 20]), Address(vec![0xaa; 20])),
		);

		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_get_block_number()
			.with(eq(1u64))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(20_000_000u64) }));

		// Finalised: empty
		mock_delivery
			.expect_get_logs()
			.withf(|chain_id, filter| *chain_id == 1 && matches_event::<Finalised>(filter))
			.times(1)
			.returning(|_, _| Box::pin(async move { Ok(vec![]) }));

		// Refunded: empty
		mock_delivery
			.expect_get_logs()
			.withf(|chain_id, filter| *chain_id == 1 && matches_event::<Refunded>(filter))
			.times(1)
			.returning(|_, _| Box::pin(async move { Ok(vec![]) }));

		// OrderPurchased: matches
		mock_delivery
			.expect_get_logs()
			.withf(|chain_id, filter| *chain_id == 1 && matches_event::<OrderPurchased>(filter))
			.times(1)
			.returning(|_, _| {
				Box::pin(async move {
					Ok(vec![solver_types::Log {
						transaction_hash: Some(TransactionHash(vec![0xee; 32])),
						block_number: Some(19_995_000),
						..Default::default()
					}])
				})
			});

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				1u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
			60,
		));
		let settlement = Arc::new(SettlementService::new(HashMap::new(), String::new(), 20));

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			EventBus::new(100),
			attempt_store,
			networks,
		);

		let (_repaired, result) = recovery_service
			.reconcile_with_blockchain(&order)
			.await
			.unwrap();
		assert!(matches!(
			result,
			ReconcileResult::Failed(TransactionType::Claim)
		));
	}

	#[tokio::test]
	async fn recovery_returns_unknown_when_chain_probe_fails() {
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));

		let mut order = create_test_order_with_status(OrderStatus::Settled);
		order.fill_tx_hash = None;
		order.claim_tx_hash = None;
		state_machine.store_order(&order).await.unwrap();

		let networks = networks_with(
			1,
			test_network_config(Address(vec![0xcc; 20]), Address(vec![0xaa; 20])),
		);

		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_get_block_number()
			.with(eq(1u64))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(20_000_000u64) }));

		// Finalised: RPC error → Unknown short-circuits
		mock_delivery
			.expect_get_logs()
			.withf(|chain_id, filter| *chain_id == 1 && matches_event::<Finalised>(filter))
			.times(1)
			.returning(|_, _| {
				Box::pin(async move {
					Err(solver_delivery::DeliveryError::Network(
						"provider down".into(),
					))
				})
			});

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				1u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
			60,
		));
		let settlement = Arc::new(SettlementService::new(HashMap::new(), String::new(), 20));

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			EventBus::new(100),
			attempt_store,
			networks,
		);

		let (repaired, result) = recovery_service
			.reconcile_with_blockchain(&order)
			.await
			.unwrap();
		assert!(matches!(result, ReconcileResult::Unknown));
		assert_eq!(repaired.claim_tx_hash, None);
	}

	#[tokio::test]
	async fn recovery_returns_not_found_when_chain_scan_yields_nothing() {
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));

		let mut order = create_test_order_with_status(OrderStatus::Created);
		order.fill_tx_hash = None;
		order.claim_tx_hash = None;
		order.pre_claim_tx_hash = None;
		order.post_fill_tx_hash = None;
		order.prepare_tx_hash = None;
		state_machine.store_order(&order).await.unwrap();

		// Configure BOTH chains so probe runs for both Claim (origin=1) and Fill (dest=137).
		let mut networks_map = solver_types::NetworksConfig::new();
		networks_map.insert(
			1,
			test_network_config(Address(vec![0xcc; 20]), Address(vec![0xaa; 20])),
		);
		networks_map.insert(
			137,
			test_network_config(Address(vec![0xcc; 20]), Address(vec![0xaa; 20])),
		);
		let networks = Arc::new(networks_map);

		let mut mock_delivery_1 = MockDeliveryInterface::new();
		mock_delivery_1
			.expect_get_block_number()
			.with(eq(1u64))
			.times(2)
			.returning(|_| Box::pin(async move { Ok(20_000_000u64) }));
		// Claim queries (Finalised, Refunded, OrderPurchased) and Prepare Open return empty.
		mock_delivery_1
			.expect_get_logs()
			.times(4)
			.returning(|_, _| Box::pin(async move { Ok(vec![]) }));

		let mut mock_delivery_137 = MockDeliveryInterface::new();
		mock_delivery_137
			.expect_get_block_number()
			.with(eq(137u64))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(1_000_000u64) }));
		mock_delivery_137
			.expect_get_logs()
			.times(1)
			.returning(|_, _| Box::pin(async move { Ok(vec![]) }));

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([
				(
					1u64,
					Arc::new(mock_delivery_1) as Arc<dyn solver_delivery::DeliveryInterface>,
				),
				(
					137u64,
					Arc::new(mock_delivery_137) as Arc<dyn solver_delivery::DeliveryInterface>,
				),
			]),
			1,
			20,
			60,
		));
		let settlement = Arc::new(SettlementService::new(HashMap::new(), String::new(), 20));

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			EventBus::new(100),
			attempt_store,
			networks,
		);

		let (_repaired, result) = recovery_service
			.reconcile_with_blockchain(&order)
			.await
			.unwrap();
		// All chain probes returned empty, fall through all stages → NeedsExecution.
		assert!(matches!(result, ReconcileResult::NeedsExecution));
	}

	#[tokio::test]
	async fn recovery_falls_through_when_output_chain_config_missing() {
		// Order references chain 137 (output) but NetworksConfig is empty
		// for chain 137. The fill probe must skip with a WARN log and the
		// stage resolution must be NotFound (fall through), letting the
		// next reverse-priority stage check run.
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));

		// Populate ONLY chain 1 (so claim probe runs and returns NotFound).
		// Chain 137 is intentionally missing.
		let mut networks_map = solver_types::NetworksConfig::new();
		networks_map.insert(
			1,
			solver_types::NetworkConfig {
				name: None,
				network_type: solver_types::NetworkType::New,
				rpc_urls: vec![],
				input_settler_address: Address(vec![0xcc; 20]),
				output_settler_address: Address(vec![0xaa; 20]),
				tokens: vec![],
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);
		let networks = Arc::new(networks_map);

		let mut order = create_test_order_with_status(OrderStatus::Created);
		order.prepare_tx_hash = None;
		order.fill_tx_hash = None;
		order.post_fill_tx_hash = None;
		order.pre_claim_tx_hash = None;
		order.claim_tx_hash = None;
		state_machine.store_order(&order).await.unwrap();

		// Claim and Prepare probes on chain 1 run (configured); both return empty.
		let mut mock_delivery_1 = MockDeliveryInterface::new();
		mock_delivery_1
			.expect_get_block_number()
			.with(eq(1u64))
			.times(2)
			.returning(|_| Box::pin(async move { Ok(20_000_000u64) }));
		mock_delivery_1
			.expect_get_logs()
			.times(4)
			.returning(|_, _| Box::pin(async move { Ok(vec![]) }));

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				1u64,
				Arc::new(mock_delivery_1) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
			60,
		));
		let settlement = Arc::new(SettlementService::new(HashMap::new(), String::new(), 20));

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			EventBus::new(100),
			attempt_store,
			networks,
		);

		let (_repaired, result) = recovery_service
			.reconcile_with_blockchain(&order)
			.await
			.unwrap();
		// Claim probe returns NotFound (empty logs). Fill probe is skipped
		// because chain 137 is not configured (NotFound + WARN log).
		// All stages fall through to NeedsExecution.
		assert!(matches!(result, ReconcileResult::NeedsExecution));
	}

	#[tokio::test]
	async fn recovery_falls_through_when_input_chain_config_missing() {
		// Mirror of the above: chain 1 (input) is missing from config,
		// chain 137 (output) is populated. Claim probe is skipped with
		// WARN, fill probe runs and returns empty, reconciliation falls
		// through to NeedsExecution.
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));

		let mut networks_map = solver_types::NetworksConfig::new();
		networks_map.insert(
			137,
			solver_types::NetworkConfig {
				name: None,
				network_type: solver_types::NetworkType::New,
				rpc_urls: vec![],
				input_settler_address: Address(vec![0xcc; 20]),
				output_settler_address: Address(vec![0xaa; 20]),
				tokens: vec![],
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);
		let networks = Arc::new(networks_map);

		let mut order = create_test_order_with_status(OrderStatus::Created);
		order.prepare_tx_hash = None;
		order.fill_tx_hash = None;
		order.post_fill_tx_hash = None;
		order.pre_claim_tx_hash = None;
		order.claim_tx_hash = None;
		state_machine.store_order(&order).await.unwrap();

		let mut mock_delivery_137 = MockDeliveryInterface::new();
		mock_delivery_137
			.expect_get_block_number()
			.with(eq(137u64))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(1_000_000u64) }));
		mock_delivery_137
			.expect_get_logs()
			.times(1)
			.returning(|_, _| Box::pin(async move { Ok(vec![]) }));

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				137u64,
				Arc::new(mock_delivery_137) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
			60,
		));
		let settlement = Arc::new(SettlementService::new(HashMap::new(), String::new(), 20));

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			EventBus::new(100),
			attempt_store,
			networks,
		);

		let (_repaired, result) = recovery_service
			.reconcile_with_blockchain(&order)
			.await
			.unwrap();
		assert!(matches!(result, ReconcileResult::NeedsExecution));
	}

	#[tokio::test]
	async fn recovery_returns_unknown_when_fill_log_matched_but_metadata_missing() {
		// A matched OutputFilled log without tx_hash / block_number cannot
		// be used to repair the order. The probe surfaces Unknown so the
		// order is not silently advanced from incomplete chain evidence.
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));

		let mut order = create_test_order_with_status(OrderStatus::Created);
		order.fill_tx_hash = None;
		order.claim_tx_hash = None;
		order.pre_claim_tx_hash = None;
		order.post_fill_tx_hash = None;
		order.prepare_tx_hash = None;
		state_machine.store_order(&order).await.unwrap();

		let networks = networks_with(
			137,
			test_network_config(Address(vec![0xcc; 20]), Address(vec![0xaa; 20])),
		);

		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_get_block_number()
			.with(eq(137u64))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(1_000_000u64) }));
		// OutputFilled returns a log with both transaction_hash and
		// block_number = None.
		mock_delivery
			.expect_get_logs()
			.withf(|chain_id, filter| *chain_id == 137 && matches_event::<OutputFilled>(filter))
			.times(1)
			.returning(|_, _| {
				Box::pin(async move {
					Ok(vec![solver_types::Log {
						transaction_hash: None,
						block_number: None,
						..Default::default()
					}])
				})
			});

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				137u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
			60,
		));
		let settlement = Arc::new(SettlementService::new(HashMap::new(), String::new(), 20));

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			EventBus::new(100),
			attempt_store,
			networks,
		);

		let (repaired, result) = recovery_service
			.reconcile_with_blockchain(&order)
			.await
			.unwrap();
		// Claim probe gets NotFound (chain 1 unconfigured). Fill probe gets
		// MatchedButUnusable → ChainEvidence::Unknown → StageResolution::Unknown
		// → ReconcileResult::Unknown.
		assert!(matches!(result, ReconcileResult::Unknown));
		assert_eq!(repaired.fill_tx_hash, None);
	}

	#[tokio::test]
	async fn recovery_returns_unknown_when_finalised_log_matched_but_metadata_missing() {
		// Same shape as the fill case but for the origin-chain Finalised event.
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));

		let mut order = create_test_order_with_status(OrderStatus::Settled);
		order.fill_tx_hash = None;
		order.claim_tx_hash = None;
		state_machine.store_order(&order).await.unwrap();

		let networks = networks_with(
			1,
			test_network_config(Address(vec![0xcc; 20]), Address(vec![0xaa; 20])),
		);

		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_get_block_number()
			.with(eq(1u64))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(20_000_000u64) }));
		mock_delivery
			.expect_get_logs()
			.withf(|chain_id, filter| *chain_id == 1 && matches_event::<Finalised>(filter))
			.times(1)
			.returning(|_, _| {
				Box::pin(async move {
					Ok(vec![solver_types::Log {
						transaction_hash: None,
						block_number: None,
						..Default::default()
					}])
				})
			});

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				1u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
			60,
		));
		let settlement = Arc::new(SettlementService::new(HashMap::new(), String::new(), 20));

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			EventBus::new(100),
			attempt_store,
			networks,
		);

		let (repaired, result) = recovery_service
			.reconcile_with_blockchain(&order)
			.await
			.unwrap();
		assert!(matches!(result, ReconcileResult::Unknown));
		assert_eq!(repaired.claim_tx_hash, None);
	}

	// ========================================================================
	// PR 05: Idempotent-revert classification tests
	// ========================================================================

	/// AlreadyClaimed selector — claim revert classified as StageComplete, chain
	/// probe finds a matching Finalised event → order advances to Finalized.
	#[tokio::test]
	async fn recovery_advances_claim_when_already_claimed_revert_and_chain_proves_finalised() {
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));

		let mut order = create_test_order_with_status(OrderStatus::Settled);
		let claim_hash = TransactionHash(vec![0xc1; 32]);
		let onchain_claim_hash = TransactionHash(vec![0xee; 32]);
		order.claim_tx_hash = Some(claim_hash.clone());
		state_machine.store_order(&order).await.unwrap();

		// Seed attempt-ledger: claim attempt with tx + signer captured.
		let claim_attempt = attempt_store
			.create_planned_attempt(
				&order.id,
				Some(Address(vec![0xab; 20])),
				TransactionType::Claim,
				sample_tx(1),
			)
			.await
			.unwrap();
		attempt_store
			.update_attempt_status(
				&claim_attempt.id,
				TransactionAttemptStatus::Broadcast,
				None,
				|attempt| {
					attempt.tx_hash = Some(claim_hash.clone());
				},
			)
			.await
			.unwrap();

		let input_settler = Address(vec![0xcc; 20]);
		let networks = networks_with(
			1,
			test_network_config(input_settler.clone(), Address(vec![0xaa; 20])),
		);

		let mut mock_delivery = MockDeliveryInterface::new();
		// Confirmed-revert receipt for the claim tx.
		mock_delivery
			.expect_get_receipt()
			.with(eq(claim_hash.clone()), eq(1u64))
			.times(1)
			.returning(|hash, _| {
				let hash = hash.clone();
				Box::pin(async move {
					Ok(solver_types::TransactionReceipt {
						hash,
						block_number: 19_995_000,
						success: false,
						block_timestamp: None,
						logs: vec![],
					})
				})
			});
		// AlreadyClaimed revert bytes (selector 0x646cf558).
		mock_delivery
			.expect_get_revert_data()
			.times(1)
			.returning(|_, _, _, _| Box::pin(async { Ok(Some(hex::decode("646cf558").unwrap())) }));
		// Chain probe: anchor block number + Finalised log on chain.
		mock_delivery
			.expect_get_block_number()
			.with(eq(1u64))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(20_000_000u64) }));
		let onchain_claim_hash_for_logs = onchain_claim_hash.clone();
		mock_delivery
			.expect_get_logs()
			.withf(|chain_id, filter| *chain_id == 1 && matches_event::<Finalised>(filter))
			.times(1)
			.returning(move |_, _| {
				let h = onchain_claim_hash_for_logs.clone();
				Box::pin(async move {
					Ok(vec![solver_types::Log {
						address: Address(vec![0xcc; 20]),
						topics: vec![],
						data: vec![],
						transaction_hash: Some(h),
						block_number: Some(19_995_000),
					}])
				})
			});

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				1u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
			60,
		));
		let settlement = Arc::new(SettlementService::new(HashMap::new(), String::new(), 20));

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			EventBus::new(100),
			attempt_store,
			networks,
		);

		let (repaired, result) = recovery_service
			.reconcile_with_blockchain(&order)
			.await
			.unwrap();
		assert!(
			matches!(result, ReconcileResult::Finalized),
			"expected Finalized, got {result:?}"
		);
		assert_eq!(repaired.claim_tx_hash, Some(onchain_claim_hash));
	}

	/// InvalidOrderStatus + chain probe finds Refunded → Failed(Claim).
	#[tokio::test]
	async fn recovery_terminates_on_invalid_order_status_when_chain_proves_refunded() {
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));

		let mut order = create_test_order_with_status(OrderStatus::Settled);
		let claim_hash = TransactionHash(vec![0xc1; 32]);
		order.claim_tx_hash = Some(claim_hash.clone());
		state_machine.store_order(&order).await.unwrap();

		let claim_attempt = attempt_store
			.create_planned_attempt(
				&order.id,
				Some(Address(vec![0xab; 20])),
				TransactionType::Claim,
				sample_tx(1),
			)
			.await
			.unwrap();
		attempt_store
			.update_attempt_status(
				&claim_attempt.id,
				TransactionAttemptStatus::Broadcast,
				None,
				|attempt| {
					attempt.tx_hash = Some(claim_hash.clone());
				},
			)
			.await
			.unwrap();

		let networks = networks_with(
			1,
			test_network_config(Address(vec![0xcc; 20]), Address(vec![0xaa; 20])),
		);

		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_get_receipt()
			.with(eq(claim_hash.clone()), eq(1u64))
			.times(1)
			.returning(|hash, _| {
				let hash = hash.clone();
				Box::pin(async move {
					Ok(solver_types::TransactionReceipt {
						hash,
						block_number: 19_995_000,
						success: false,
						block_timestamp: None,
						logs: vec![],
					})
				})
			});
		// InvalidOrderStatus (0x2916ae33) → StageComplete.
		mock_delivery
			.expect_get_revert_data()
			.times(1)
			.returning(|_, _, _, _| Box::pin(async { Ok(Some(hex::decode("2916ae33").unwrap())) }));
		mock_delivery
			.expect_get_block_number()
			.with(eq(1u64))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(20_000_000u64) }));
		// Finalised probe runs first; return empty so we move on to Refunded.
		mock_delivery
			.expect_get_logs()
			.withf(|chain_id, filter| *chain_id == 1 && matches_event::<Finalised>(filter))
			.times(1)
			.returning(|_, _| Box::pin(async move { Ok(vec![]) }));
		// Refunded event found → NegativeTerminal → Failed(Claim).
		mock_delivery
			.expect_get_logs()
			.withf(|chain_id, filter| *chain_id == 1 && matches_event::<Refunded>(filter))
			.times(1)
			.returning(|_, _| {
				Box::pin(async move {
					Ok(vec![solver_types::Log {
						address: Address(vec![0xcc; 20]),
						topics: vec![],
						data: vec![],
						transaction_hash: Some(TransactionHash(vec![0xff; 32])),
						block_number: Some(19_995_000),
					}])
				})
			});

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				1u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
			60,
		));
		let settlement = Arc::new(SettlementService::new(HashMap::new(), String::new(), 20));

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			EventBus::new(100),
			attempt_store,
			networks,
		);

		let (_repaired, result) = recovery_service
			.reconcile_with_blockchain(&order)
			.await
			.unwrap();
		assert!(
			matches!(result, ReconcileResult::Failed(TransactionType::Claim)),
			"expected Failed(Claim), got {result:?}"
		);
	}

	/// StageComplete claim revert + chain probe NotFound → Unknown (retry next pass).
	#[tokio::test]
	async fn recovery_returns_unknown_when_claim_stage_complete_but_chain_disagrees() {
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));

		let mut order = create_test_order_with_status(OrderStatus::Settled);
		let claim_hash = TransactionHash(vec![0xc1; 32]);
		order.claim_tx_hash = Some(claim_hash.clone());
		state_machine.store_order(&order).await.unwrap();

		let claim_attempt = attempt_store
			.create_planned_attempt(
				&order.id,
				Some(Address(vec![0xab; 20])),
				TransactionType::Claim,
				sample_tx(1),
			)
			.await
			.unwrap();
		attempt_store
			.update_attempt_status(
				&claim_attempt.id,
				TransactionAttemptStatus::Broadcast,
				None,
				|attempt| {
					attempt.tx_hash = Some(claim_hash.clone());
				},
			)
			.await
			.unwrap();

		let networks = networks_with(
			1,
			test_network_config(Address(vec![0xcc; 20]), Address(vec![0xaa; 20])),
		);

		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_get_receipt()
			.with(eq(claim_hash.clone()), eq(1u64))
			.times(1)
			.returning(|hash, _| {
				let hash = hash.clone();
				Box::pin(async move {
					Ok(solver_types::TransactionReceipt {
						hash,
						block_number: 19_995_000,
						success: false,
						block_timestamp: None,
						logs: vec![],
					})
				})
			});
		mock_delivery
			.expect_get_revert_data()
			.times(1)
			.returning(|_, _, _, _| Box::pin(async { Ok(Some(hex::decode("646cf558").unwrap())) }));
		mock_delivery
			.expect_get_block_number()
			.with(eq(1u64))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(20_000_000u64) }));
		// Empty logs for ALL event filters — chain probe finds nothing.
		mock_delivery
			.expect_get_logs()
			.returning(|_, _| Box::pin(async move { Ok(vec![]) }));

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				1u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
			60,
		));
		let settlement = Arc::new(SettlementService::new(HashMap::new(), String::new(), 20));

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			EventBus::new(100),
			attempt_store,
			networks,
		);

		let (_, result) = recovery_service
			.reconcile_with_blockchain(&order)
			.await
			.unwrap();
		assert!(
			matches!(result, ReconcileResult::Unknown),
			"expected Unknown, got {result:?}"
		);
	}

	/// Terminal revert (FillDeadline) → Failed(Claim); chain probe is NOT called.
	#[tokio::test]
	async fn recovery_terminates_on_terminal_revert_without_chain_probe() {
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));

		let mut order = create_test_order_with_status(OrderStatus::Settled);
		let claim_hash = TransactionHash(vec![0xc1; 32]);
		order.claim_tx_hash = Some(claim_hash.clone());
		state_machine.store_order(&order).await.unwrap();

		let claim_attempt = attempt_store
			.create_planned_attempt(
				&order.id,
				Some(Address(vec![0xab; 20])),
				TransactionType::Claim,
				sample_tx(1),
			)
			.await
			.unwrap();
		attempt_store
			.update_attempt_status(
				&claim_attempt.id,
				TransactionAttemptStatus::Broadcast,
				None,
				|attempt| {
					attempt.tx_hash = Some(claim_hash.clone());
				},
			)
			.await
			.unwrap();

		let networks = networks_with(
			1,
			test_network_config(Address(vec![0xcc; 20]), Address(vec![0xaa; 20])),
		);

		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_get_receipt()
			.with(eq(claim_hash.clone()), eq(1u64))
			.times(1)
			.returning(|hash, _| {
				let hash = hash.clone();
				Box::pin(async move {
					Ok(solver_types::TransactionReceipt {
						hash,
						block_number: 19_995_000,
						success: false,
						block_timestamp: None,
						logs: vec![],
					})
				})
			});
		// FillDeadline (0x9f3ddb90) → Terminal.
		mock_delivery
			.expect_get_revert_data()
			.times(1)
			.returning(|_, _, _, _| Box::pin(async { Ok(Some(hex::decode("9f3ddb90").unwrap())) }));
		// Chain probe is NOT called — these expectations explicitly disallow it.
		mock_delivery.expect_get_block_number().times(0);
		mock_delivery.expect_get_logs().times(0);

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				1u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
			60,
		));
		let settlement = Arc::new(SettlementService::new(HashMap::new(), String::new(), 20));

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			EventBus::new(100),
			attempt_store,
			networks,
		);

		let (_, result) = recovery_service
			.reconcile_with_blockchain(&order)
			.await
			.unwrap();
		assert!(
			matches!(result, ReconcileResult::Failed(TransactionType::Claim)),
			"expected Failed(Claim), got {result:?}"
		);
	}

	/// Confirmed revert with no attempt-ledger row → Failed(stage); replay skipped.
	#[tokio::test]
	async fn recovery_terminates_when_attempt_ledger_has_no_row() {
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		// Empty attempt store — no row for the claim hash.
		let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));

		let mut order = create_test_order_with_status(OrderStatus::Settled);
		let claim_hash = TransactionHash(vec![0xc1; 32]);
		order.claim_tx_hash = Some(claim_hash.clone());
		state_machine.store_order(&order).await.unwrap();

		let networks = networks_with(
			1,
			test_network_config(Address(vec![0xcc; 20]), Address(vec![0xaa; 20])),
		);

		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_get_receipt()
			.with(eq(claim_hash.clone()), eq(1u64))
			.times(1)
			.returning(|hash, _| {
				let hash = hash.clone();
				Box::pin(async move {
					Ok(solver_types::TransactionReceipt {
						hash,
						block_number: 19_995_000,
						success: false,
						block_timestamp: None,
						logs: vec![],
					})
				})
			});
		// get_revert_data must NOT be called when attempt-ledger lookup misses.
		mock_delivery.expect_get_revert_data().times(0);

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				1u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
			60,
		));
		let settlement = Arc::new(SettlementService::new(HashMap::new(), String::new(), 20));

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			EventBus::new(100),
			attempt_store,
			networks,
		);

		let (_, result) = recovery_service
			.reconcile_with_blockchain(&order)
			.await
			.unwrap();
		assert!(
			matches!(result, ReconcileResult::Failed(TransactionType::Claim)),
			"expected Failed(Claim), got {result:?}"
		);
	}

	/// PreClaim revert classified StageComplete but chain probe finds no claim
	/// → Failed(PreClaim). Conservative behavior — we don't advance PreClaim
	/// without on-chain confirmation that the claim actually happened.
	#[tokio::test]
	async fn recovery_preclaim_stage_complete_returns_failed_preclaim_when_chain_disagrees() {
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));

		let mut order = create_test_order_with_status(OrderStatus::Settled);
		let preclaim_hash = TransactionHash(vec![0xd1; 32]);
		// No claim_tx_hash; PreClaim is the active stage. Layer 1 of
		// resolve_stage(Claim) yields nothing → chain probe runs and finds
		// nothing → falls through to PreClaim.
		order.claim_tx_hash = None;
		order.pre_claim_tx_hash = Some(preclaim_hash.clone());
		state_machine.store_order(&order).await.unwrap();

		let preclaim_attempt = attempt_store
			.create_planned_attempt(
				&order.id,
				Some(Address(vec![0xab; 20])),
				TransactionType::PreClaim,
				sample_tx(1),
			)
			.await
			.unwrap();
		attempt_store
			.update_attempt_status(
				&preclaim_attempt.id,
				TransactionAttemptStatus::Broadcast,
				None,
				|attempt| {
					attempt.tx_hash = Some(preclaim_hash.clone());
				},
			)
			.await
			.unwrap();

		let networks = networks_with(
			1,
			test_network_config(Address(vec![0xcc; 20]), Address(vec![0xaa; 20])),
		);

		let mut mock_delivery = MockDeliveryInterface::new();
		// Anchor block: called by EACH claim_chain_evidence invocation. There
		// are two — the initial resolve_stage(Claim) probe AND the
		// stage_complete_recovery probe after PreClaim reverts.
		mock_delivery
			.expect_get_block_number()
			.with(eq(1u64))
			.times(2)
			.returning(|_| Box::pin(async move { Ok(20_000_000u64) }));
		// Both Finalised/Refunded/Purchased probes return empty across both
		// claim_chain_evidence invocations; uncatch-all match.
		mock_delivery
			.expect_get_logs()
			.returning(|_, _| Box::pin(async move { Ok(vec![]) }));
		// PreClaim receipt: confirmed-revert.
		mock_delivery
			.expect_get_receipt()
			.with(eq(preclaim_hash.clone()), eq(1u64))
			.times(1)
			.returning(|hash, _| {
				let hash = hash.clone();
				Box::pin(async move {
					Ok(solver_types::TransactionReceipt {
						hash,
						block_number: 19_995_000,
						success: false,
						block_timestamp: None,
						logs: vec![],
					})
				})
			});
		// AlreadyClaimed → StageComplete.
		mock_delivery
			.expect_get_revert_data()
			.times(1)
			.returning(|_, _, _, _| Box::pin(async { Ok(Some(hex::decode("646cf558").unwrap())) }));

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				1u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
			60,
		));
		let settlement = Arc::new(SettlementService::new(HashMap::new(), String::new(), 20));

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			EventBus::new(100),
			attempt_store,
			networks,
		);

		let (_, result) = recovery_service
			.reconcile_with_blockchain(&order)
			.await
			.unwrap();
		assert!(
			matches!(result, ReconcileResult::Failed(TransactionType::PreClaim)),
			"expected Failed(PreClaim), got {result:?}"
		);
	}

	/// Regression: a transient RPC error during `get_revert_data` must NOT
	/// terminalize the order. Without the Err→Unknown split, a single Alchemy
	/// blip during startup recovery converts an in-flight order into permanent
	/// Failed — exactly the stranded-funds case PR 05 is designed to prevent.
	#[tokio::test]
	async fn recovery_returns_unknown_when_get_revert_data_errors_transiently() {
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));

		let mut order = create_test_order_with_status(OrderStatus::Settled);
		let claim_hash = TransactionHash(vec![0xc1; 32]);
		order.claim_tx_hash = Some(claim_hash.clone());
		state_machine.store_order(&order).await.unwrap();

		// Attempt ledger row present so we get past the first guard and reach
		// the get_revert_data call.
		let claim_attempt = attempt_store
			.create_planned_attempt(
				&order.id,
				Some(Address(vec![0xab; 20])),
				TransactionType::Claim,
				sample_tx(1),
			)
			.await
			.unwrap();
		attempt_store
			.update_attempt_status(
				&claim_attempt.id,
				TransactionAttemptStatus::Broadcast,
				None,
				|attempt| {
					attempt.tx_hash = Some(claim_hash.clone());
				},
			)
			.await
			.unwrap();

		let networks = networks_with(
			1,
			test_network_config(Address(vec![0xcc; 20]), Address(vec![0xaa; 20])),
		);

		let mut mock_delivery = MockDeliveryInterface::new();
		// Confirmed-revert receipt for the claim tx.
		mock_delivery
			.expect_get_receipt()
			.with(eq(claim_hash.clone()), eq(1u64))
			.times(1)
			.returning(|hash, _| {
				let hash = hash.clone();
				Box::pin(async move {
					Ok(solver_types::TransactionReceipt {
						hash,
						block_number: 19_995_000,
						success: false,
						block_timestamp: None,
						logs: vec![],
					})
				})
			});
		// Replay fails with a transport error.
		mock_delivery
			.expect_get_revert_data()
			.times(1)
			.returning(|_, _, _, _| {
				Box::pin(async {
					Err(solver_delivery::DeliveryError::Network(
						"connection reset by peer".to_string(),
					))
				})
			});
		// Chain probe must NOT be called: we never reached classification.
		mock_delivery.expect_get_block_number().times(0);
		mock_delivery.expect_get_logs().times(0);

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				1u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
			60,
		));
		let settlement = Arc::new(SettlementService::new(HashMap::new(), String::new(), 20));

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			EventBus::new(100),
			attempt_store,
			networks,
		);

		let (_, result) = recovery_service
			.reconcile_with_blockchain(&order)
			.await
			.unwrap();
		assert!(
			matches!(result, ReconcileResult::Unknown),
			"transient RPC error must yield Unknown for retry, got {result:?}"
		);
	}

	/// Regression: the chain-evidence scan must search BEFORE the anchor block,
	/// not start at it. A competitor solver's `Finalised` at block N-200 is
	/// frequently the cause of our claim tx reverting at block N — if we scan
	/// only [N, latest], we miss the proof and incorrectly return NotFound.
	///
	/// With the fix (`from_block = receipt.block_number - window_blocks`), the
	/// scan covers [N-window, latest] and the earlier event is found.
	#[tokio::test]
	async fn chain_probe_scans_before_anchor_block_to_catch_earlier_events() {
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));

		// Order without claim_tx_hash; resolve_stage(Claim) will fall through
		// to chain probe. anchor_tx comes from prepare_tx_hash.
		let mut order = create_test_order_with_status(OrderStatus::Settled);
		let prepare_hash = TransactionHash(vec![0xaa; 32]);
		let onchain_claim_hash = TransactionHash(vec![0xee; 32]);
		order.fill_tx_hash = None;
		order.claim_tx_hash = None;
		order.prepare_tx_hash = Some(prepare_hash.clone());
		state_machine.store_order(&order).await.unwrap();

		let networks = networks_with(
			1,
			test_network_config(Address(vec![0xcc; 20]), Address(vec![0xaa; 20])),
		);

		let prepare_block: u64 = 19_995_000;
		let earlier_proof_block: u64 = prepare_block - 200;

		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_get_block_number()
			.with(eq(1u64))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(20_000_000u64) }));
		// Anchor receipt: prepare_tx mined at prepare_block.
		mock_delivery
			.expect_get_receipt()
			.with(eq(prepare_hash.clone()), eq(1u64))
			.times(1)
			.returning(move |hash, _| {
				let hash = hash.clone();
				Box::pin(async move {
					Ok(solver_types::TransactionReceipt {
						hash,
						block_number: prepare_block,
						success: true,
						block_timestamp: None,
						logs: vec![],
					})
				})
			});
		// Finalised event lives BEFORE the anchor. The pre-fix `from_block`
		// was `prepare_block`, which would skip this. The fixed `from_block`
		// is `prepare_block - DEFAULT_RECOVERY_SCAN_WINDOW_BLOCKS (10_000)`,
		// which covers `earlier_proof_block` (200 blocks earlier).
		let proof_hash_for_logs = onchain_claim_hash.clone();
		mock_delivery
			.expect_get_logs()
			.withf(|chain_id, filter| *chain_id == 1 && matches_event::<Finalised>(filter))
			.times(1)
			.returning(move |_, _| {
				let h = proof_hash_for_logs.clone();
				Box::pin(async move {
					Ok(vec![solver_types::Log {
						address: Address(vec![0xcc; 20]),
						topics: vec![],
						data: vec![],
						transaction_hash: Some(h),
						block_number: Some(earlier_proof_block),
					}])
				})
			});
		// After write-back, recovery fetches the on-chain claim's receipt to
		// finish the Finalized branch.
		mock_delivery
			.expect_get_receipt()
			.with(eq(onchain_claim_hash.clone()), eq(1u64))
			.times(1)
			.returning(move |hash, _| {
				let hash = hash.clone();
				Box::pin(async move {
					Ok(solver_types::TransactionReceipt {
						hash,
						block_number: earlier_proof_block,
						success: true,
						block_timestamp: None,
						logs: vec![],
					})
				})
			});

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				1u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
			60,
		));
		let settlement = Arc::new(SettlementService::new(HashMap::new(), String::new(), 20));

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			EventBus::new(100),
			attempt_store,
			networks,
		);

		let (repaired, result) = recovery_service
			.reconcile_with_blockchain(&order)
			.await
			.unwrap();
		assert!(
			matches!(result, ReconcileResult::Finalized),
			"chain probe must find earlier proof event, got {result:?}"
		);
		assert_eq!(repaired.claim_tx_hash, Some(onchain_claim_hash));
	}
}
