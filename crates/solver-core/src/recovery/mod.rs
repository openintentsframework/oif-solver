//! Recovery module for restoring solver state from storage after unexpected exits.
//!
//! This module provides functionality to recover orders from persistent storage,
//! reconcile with blockchain state including all transaction types (prepare, fill,
//! post-fill, pre-claim, claim), and resume processing of active orders.

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
	with_0x_prefix, Intent, Order, OrderEvent, OrderStatus, SettlementEvent, SolverEvent,
	StorageKey, TransactionAttempt, TransactionAttemptStatus, TransactionHash, TransactionType,
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

fn recovery_status_rank(status: TransactionAttemptStatus) -> Option<u8> {
	match status {
		TransactionAttemptStatus::Confirmed => Some(3),
		TransactionAttemptStatus::Broadcast => Some(2),
		TransactionAttemptStatus::Indeterminate => Some(1),
		TransactionAttemptStatus::Planned
		| TransactionAttemptStatus::SubmitRejected
		| TransactionAttemptStatus::Reverted => None,
	}
}

fn choose_recovery_attempt_hash(
	attempts: &[TransactionAttempt],
	tx_type: TransactionType,
) -> Option<TransactionHash> {
	attempts
		.iter()
		.filter(|attempt| attempt.tx_type == tx_type)
		.filter_map(|attempt| {
			let rank = recovery_status_rank(attempt.status)?;
			let tx_hash = attempt.tx_hash.clone()?;
			Some((rank, attempt.updated_at, tx_hash))
		})
		.max_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)))
		.map(|(_, _, tx_hash)| tx_hash)
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
	pub fn new(
		storage: Arc<StorageService>,
		state_machine: Arc<OrderStateMachine>,
		delivery: Arc<DeliveryService>,
		settlement: Arc<SettlementService>,
		event_bus: EventBus,
		attempt_store: Arc<TransactionAttemptStore>,
	) -> Self {
		Self {
			storage,
			state_machine,
			delivery,
			settlement,
			event_bus,
			attempt_store,
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

	async fn resolve_and_repair_stage_hash(
		&self,
		order: &mut Order,
		attempts: &[TransactionAttempt],
		tx_type: TransactionType,
	) -> Option<TransactionHash> {
		if let Some(tx_hash) = order_stage_hash(order, tx_type) {
			return Some(tx_hash);
		}

		let tx_hash = choose_recovery_attempt_hash(attempts, tx_type)?;
		set_order_stage_hash(order, tx_type, tx_hash.clone());

		if let Err(error) = self
			.state_machine
			.set_transaction_hash(&order.id, tx_hash.clone(), tx_type)
			.await
		{
			tracing::error!(
				order_id = %order.id,
				tx_type = ?tx_type,
				error = %error,
				"Recovered transaction hash from attempt ledger but failed to write it back to order"
			);
		}

		Some(tx_hash)
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
		if let Some(claim_tx) = self
			.resolve_and_repair_stage_hash(&mut order, &attempts, TransactionType::Claim)
			.await
		{
			let chain_id = order
				.input_chains
				.first()
				.map(|c| c.chain_id)
				.ok_or_else(|| RecoveryError::Storage("No input chains in order".into()))?;

			match self.delivery.get_status(&claim_tx, chain_id).await {
				Ok(true) => {
					// Transaction succeeded
					return Ok((order, ReconcileResult::Finalized));
				},
				Ok(false) => {
					// Transaction failed/reverted
					tracing::warn!("Claim transaction {:?} failed/reverted", claim_tx);
					return Ok((order, ReconcileResult::Failed(TransactionType::Claim)));
				},
				Err(e) => {
					// Could not determine on-chain state. Surface as Unknown so the
					// order is not terminally failed on a transient RPC blip; see
					// the `ReconcileResult::Unknown` doc for retry semantics.
					tracing::warn!(
						"Could not get claim transaction status; treating as Unknown: {}",
						e
					);
					return Ok((order, ReconcileResult::Unknown));
				},
			}
		}

		// Check pre-claim transaction
		if let Some(pre_claim_tx) = self
			.resolve_and_repair_stage_hash(&mut order, &attempts, TransactionType::PreClaim)
			.await
		{
			// PreClaim happens on origin chain (same as claim)
			let chain_id = order
				.input_chains
				.first()
				.map(|c| c.chain_id)
				.ok_or_else(|| RecoveryError::Storage("No input chains in order".into()))?;

			match self.delivery.get_status(&pre_claim_tx, chain_id).await {
				Ok(true) => {
					// Pre-claim confirmed, ready for claim
					return Ok((
						order.clone(),
						ReconcileResult::NeedsClaim {
							fill_proof: order.fill_proof.clone(),
						},
					));
				},
				Ok(false) => {
					return Ok((order, ReconcileResult::Failed(TransactionType::PreClaim)));
				},
				Err(e) => {
					tracing::warn!(
						"Could not get pre-claim transaction status; treating as Unknown: {}",
						e
					);
					return Ok((order, ReconcileResult::Unknown));
				},
			}
		}

		// Check post-fill transaction
		if let Some(post_fill_tx) = self
			.resolve_and_repair_stage_hash(&mut order, &attempts, TransactionType::PostFill)
			.await
		{
			// PostFill happens on destination chain (same as fill)
			let chain_id = order
				.output_chains
				.first()
				.map(|c| c.chain_id)
				.ok_or_else(|| RecoveryError::Storage("No output chains in order".into()))?;

			match self.delivery.get_status(&post_fill_tx, chain_id).await {
				Ok(true) => {
					// Post-fill confirmed, needs monitoring for settlement
					return Ok((order, ReconcileResult::NeedsMonitoring));
				},
				Ok(false) => {
					return Ok((order, ReconcileResult::Failed(TransactionType::PostFill)));
				},
				Err(e) => {
					tracing::warn!(
						"Could not get post-fill transaction status; treating as Unknown: {}",
						e
					);
					return Ok((order, ReconcileResult::Unknown));
				},
			}
		}

		// Check fill transaction
		if let Some(fill_tx) = self
			.resolve_and_repair_stage_hash(&mut order, &attempts, TransactionType::Fill)
			.await
		{
			let chain_id = order
				.output_chains
				.first()
				.map(|c| c.chain_id)
				.ok_or_else(|| RecoveryError::Storage("No output chains in order".into()))?;

			match self.delivery.get_status(&fill_tx, chain_id).await {
				Ok(true) => {
					// Fill confirmed, check what's needed next
					if order.fill_proof.is_some() {
						// Already have attestation, settled and may need pre-claim
						return Ok((
							order.clone(),
							ReconcileResult::NeedsPreClaim {
								fill_proof: order.fill_proof.clone(),
							},
						));
					} else {
						// Fill is confirmed but local post-fill state may be missing due to a
						// crash after submission. Recover it before deciding to resubmit.
						match self.settlement.recover_post_fill_state(&order).await {
							Ok(true) => return Ok((order, ReconcileResult::NeedsMonitoring)),
							Ok(false) => {
								// Need to process post-fill and get attestation
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
				Ok(false) => {
					// Transaction failed/reverted
					tracing::warn!(
						"Fill transaction {} failed/reverted",
						with_0x_prefix(&hex::encode(&fill_tx.0))
					);
					return Ok((order, ReconcileResult::Failed(TransactionType::Fill)));
				},
				Err(e) => {
					// Could not determine on-chain state. Surface as Unknown so the
					// order is not terminally failed; see `ReconcileResult::Unknown`.
					tracing::warn!(
						"Could not get fill transaction status; treating as Unknown: {}",
						e
					);
					return Ok((order, ReconcileResult::Unknown));
				},
			}
		}

		// Check prepare transaction
		if let Some(prepare_tx) = self
			.resolve_and_repair_stage_hash(&mut order, &attempts, TransactionType::Prepare)
			.await
		{
			let chain_id = order
				.input_chains
				.first()
				.map(|c| c.chain_id)
				.ok_or_else(|| RecoveryError::Storage("No input chains in order".into()))?;

			match self.delivery.get_status(&prepare_tx, chain_id).await {
				Ok(true) => {
					// Transaction succeeded, prepare confirmed
					return Ok((order, ReconcileResult::NeedsFill));
				},
				Ok(false) => {
					// Transaction failed/reverted
					tracing::warn!("Prepare transaction {:?} failed/reverted", prepare_tx);
					return Ok((order, ReconcileResult::Failed(TransactionType::Prepare)));
				},
				Err(e) => {
					// Could not determine on-chain state. Surface as Unknown so the
					// order is not terminally failed; see `ReconcileResult::Unknown`.
					tracing::warn!(
						"Could not get prepare transaction status; treating as Unknown: {}",
						e
					);
					return Ok((order, ReconcileResult::Unknown));
				},
			}
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

	fn empty_attempt_store() -> Arc<TransactionAttemptStore> {
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		Arc::new(TransactionAttemptStore::new(storage))
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
	async fn recovery_repairs_missing_fill_hash_from_broadcast_attempt() {
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
			attempt_store,
		);

		let (repaired_order, result) = recovery_service
			.reconcile_with_blockchain(&order)
			.await
			.unwrap();

		assert!(matches!(result, ReconcileResult::NeedsPostFill));
		assert_eq!(repaired_order.fill_tx_hash, Some(tx_hash.clone()));
		let stored = state_machine.get_order(&order.id).await.unwrap();
		assert_eq!(stored.fill_tx_hash, Some(tx_hash));
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
		let recovery_service = RecoveryService::new(
			storage,
			state_machine,
			delivery,
			settlement,
			event_bus,
			empty_attempt_store(),
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

		let hash = recovery_service
			.resolve_and_repair_stage_hash(&mut order, &attempts, TransactionType::Fill)
			.await;

		assert_eq!(hash, Some(recovered_hash.clone()));
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

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			empty_attempt_store(),
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

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			empty_attempt_store(),
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

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			empty_attempt_store(),
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

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			empty_attempt_store(),
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

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			empty_attempt_store(),
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

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			empty_attempt_store(),
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

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			empty_attempt_store(),
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

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			empty_attempt_store(),
		);

		let result = recovery_service.reconcile_with_blockchain(&order).await;
		assert!(result.is_ok());

		match result.unwrap().1 {
			ReconcileResult::NeedsMonitoring => {},
			other => panic!("Expected NeedsMonitoring, got {other:?}"),
		}
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

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			empty_attempt_store(),
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

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			empty_attempt_store(),
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

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			empty_attempt_store(),
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

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			empty_attempt_store(),
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

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			empty_attempt_store(),
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
		let mut mock_storage = MockStorageInterface::new();

		// Mock the exists call first
		mock_storage
			.expect_exists()
			.with(eq("orders:test_order_123"))
			.returning(|_| Box::pin(async { Ok(true) }));

		// Mock the get_bytes call that happens when retrieving the order
		let order = create_test_order_with_status(OrderStatus::Executed);
		let order_bytes = serde_json::to_vec(&order).unwrap();
		mock_storage
			.expect_get_bytes()
			.with(eq("orders:test_order_123"))
			.returning(move |_| {
				let order_bytes = order_bytes.clone();
				Box::pin(async move { Ok(order_bytes) })
			});

		// Mock the set_bytes call that happens when updating the order
		mock_storage
			.expect_set_bytes()
			.returning(|_, _, _, _| Box::pin(async { Ok(()) }));

		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
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

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			empty_attempt_store(),
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
		let mut mock_storage = MockStorageInterface::new();

		// Mock the exists call first
		mock_storage
			.expect_exists()
			.with(eq("orders:test_order_123"))
			.returning(|_| Box::pin(async { Ok(true) }));

		// Mock the get_bytes call that happens when retrieving the order
		let order = create_test_order_with_status(OrderStatus::Created);
		let order_bytes = serde_json::to_vec(&order).unwrap();
		mock_storage
			.expect_get_bytes()
			.with(eq("orders:test_order_123"))
			.returning(move |_| {
				let order_bytes = order_bytes.clone();
				Box::pin(async move { Ok(order_bytes) })
			});

		// Mock the set_bytes call that happens when updating the order
		mock_storage
			.expect_set_bytes()
			.returning(|_, _, _, _| Box::pin(async { Ok(()) }));

		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let delivery_impls: HashMap<u64, Arc<dyn solver_delivery::DeliveryInterface>> =
			HashMap::new();
		let delivery = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));
		let settlement_impls: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::new();
		let settlement = Arc::new(SettlementService::new(settlement_impls, String::new(), 20));
		let event_bus = EventBus::new(100);

		// Subscribe to events
		let mut receiver = event_bus.subscribe();

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			empty_attempt_store(),
		);

		let order = create_test_order_with_status(OrderStatus::Created);
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

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			empty_attempt_store(),
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

		let recovery_service = RecoveryService::new(
			storage.clone(),
			state_machine,
			delivery,
			settlement,
			event_bus,
			empty_attempt_store(),
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
}
