//! Recovery module for restoring solver state from storage after unexpected exits.
//!
//! This module provides functionality to recover orders from persistent storage,
//! reconcile with blockchain state including all transaction types (prepare, fill,
//! post-fill, pre-claim, claim), and resume processing of active orders.

use crate::engine::event_bus::EventBus;
use crate::state::OrderStateMachine;
use solver_delivery::DeliveryService;
use solver_settlement::SettlementService;
use solver_storage::{QueryFilter, StorageService};
use solver_types::{
	Intent, Order, OrderEvent, OrderStatus, SettlementEvent, SolverEvent, StorageKey,
	TransactionType,
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
	/// Transaction failed
	Failed(TransactionType),
	/// Order is finalized
	Finalized,
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
	) -> Self {
		Self {
			storage,
			state_machine,
			delivery,
			settlement,
			event_bus,
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
			match self.reconcile_with_blockchain(&order).await {
				Ok(result) => {
					self.publish_recovery_event(order, result).await;
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
		// Define all terminal status values to exclude using proper serialization
		let non_terminal_statuses = vec![
			serde_json::to_value(OrderStatus::Finalized)
				.expect("OrderStatus::Finalized serialization should not fail"),
			serde_json::to_value(OrderStatus::Failed(TransactionType::Prepare))
				.expect("OrderStatus::Failed(Prepare) serialization should not fail"),
			serde_json::to_value(OrderStatus::Failed(TransactionType::Fill))
				.expect("OrderStatus::Failed(Fill) serialization should not fail"),
			serde_json::to_value(OrderStatus::Failed(TransactionType::Claim))
				.expect("OrderStatus::Failed(Claim) serialization should not fail"),
			serde_json::to_value(OrderStatus::Failed(TransactionType::PostFill))
				.expect("OrderStatus::Failed(PostFill) serialization should not fail"),
			serde_json::to_value(OrderStatus::Failed(TransactionType::PreClaim))
				.expect("OrderStatus::Failed(PreClaim) serialization should not fail"),
		];

		// Query for all non-terminal orders
		let active_orders = self
			.storage
			.query::<Order>(
				StorageKey::Orders.as_str(),
				QueryFilter::NotIn("status".to_string(), non_terminal_statuses),
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
	) -> Result<ReconcileResult, RecoveryError> {
		// Check transactions in reverse order (claim -> fill -> prepare)

		// Check claim transaction
		if let Some(ref claim_tx) = order.claim_tx_hash {
			let chain_id = *order
				.input_chain_ids
				.first()
				.ok_or_else(|| RecoveryError::Storage("No input chains in order".into()))?;

			match self.delivery.get_status(claim_tx, chain_id).await {
				Ok(true) => {
					// Transaction succeeded
					return Ok(ReconcileResult::Finalized);
				},
				Ok(false) => {
					// Transaction failed/reverted
					tracing::warn!("Claim transaction {:?} failed/reverted", claim_tx);
					return Ok(ReconcileResult::Failed(TransactionType::Claim));
				},
				Err(e) => {
					// Could not get status - network issue, node problem, etc.
					// Fail the transaction since we can't determine its state
					tracing::error!(
						"Could not get claim transaction status, marking as failed: {}",
						e
					);
					return Ok(ReconcileResult::Failed(TransactionType::Claim));
				},
			}
		}

		// Check pre-claim transaction
		if let Some(ref pre_claim_tx) = order.pre_claim_tx_hash {
			// PreClaim happens on origin chain (same as claim)
			let chain_id = *order
				.input_chain_ids
				.first()
				.ok_or_else(|| RecoveryError::Storage("No input chains in order".into()))?;
			match self.delivery.get_status(pre_claim_tx, chain_id).await {
				Ok(true) => {
					// Pre-claim confirmed, ready for claim
					return Ok(ReconcileResult::NeedsClaim {
						fill_proof: order.fill_proof.clone(),
					});
				},
				Ok(false) => return Ok(ReconcileResult::Failed(TransactionType::PreClaim)),
				Err(_) => return Ok(ReconcileResult::Failed(TransactionType::PreClaim)),
			}
		}

		// Check post-fill transaction
		if let Some(ref post_fill_tx) = order.post_fill_tx_hash {
			// PostFill happens on destination chain (same as fill)
			let chain_id = *order
				.output_chain_ids
				.first()
				.ok_or_else(|| RecoveryError::Storage("No output chains in order".into()))?;
			match self.delivery.get_status(post_fill_tx, chain_id).await {
				Ok(true) => {
					// Post-fill confirmed, needs monitoring for settlement
					return Ok(ReconcileResult::NeedsMonitoring);
				},
				Ok(false) => return Ok(ReconcileResult::Failed(TransactionType::PostFill)),
				Err(_) => return Ok(ReconcileResult::Failed(TransactionType::PostFill)),
			}
		}

		// Check fill transaction
		if let Some(ref fill_tx) = order.fill_tx_hash {
			let chain_id = *order
				.output_chain_ids
				.first()
				.ok_or_else(|| RecoveryError::Storage("No output chains in order".into()))?;

			match self.delivery.get_status(fill_tx, chain_id).await {
				Ok(true) => {
					// Fill confirmed, check what's needed next
					if order.fill_proof.is_some() {
						// Already have attestation, settled and may need pre-claim
						return Ok(ReconcileResult::NeedsPreClaim {
							fill_proof: order.fill_proof.clone(),
						});
					} else {
						// Need to process post-fill and get attestation
						return Ok(ReconcileResult::NeedsPostFill);
					}
				},
				Ok(false) => {
					// Transaction failed/reverted
					tracing::warn!("Fill transaction {:?} failed/reverted", fill_tx);
					return Ok(ReconcileResult::Failed(TransactionType::Fill));
				},
				Err(e) => {
					// Could not get status - network issue, node problem, etc.
					// Fail the transaction since we can't determine its state
					tracing::error!(
						"Could not get fill transaction status, marking as failed: {}",
						e
					);
					return Ok(ReconcileResult::Failed(TransactionType::Fill));
				},
			}
		}

		// Check prepare transaction
		if let Some(ref prepare_tx) = order.prepare_tx_hash {
			let chain_id = *order
				.input_chain_ids
				.first()
				.ok_or_else(|| RecoveryError::Storage("No input chains in order".into()))?;

			match self.delivery.get_status(prepare_tx, chain_id).await {
				Ok(true) => {
					// Transaction succeeded, prepare confirmed
					return Ok(ReconcileResult::NeedsFill);
				},
				Ok(false) => {
					// Transaction failed/reverted
					tracing::warn!("Prepare transaction {:?} failed/reverted", prepare_tx);
					return Ok(ReconcileResult::Failed(TransactionType::Prepare));
				},
				Err(e) => {
					// Could not get status - network issue, node problem, etc.
					// Fail the transaction since we can't determine its state
					tracing::error!(
						"Could not get prepare transaction status, marking as failed: {}",
						e
					);
					return Ok(ReconcileResult::Failed(TransactionType::Prepare));
				},
			}
		}

		// No transactions yet, needs execution
		Ok(ReconcileResult::NeedsExecution)
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
				OrderStatus::Failed(*tx_type)
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
					// We have the proof, check if we can claim
					if self.settlement.can_claim(&order, &proof).await {
						// Ready to claim, emit PreClaimReady event
						// The handler will determine if pre-claim transaction is needed
						self.event_bus
							.publish(SolverEvent::Settlement(SettlementEvent::PreClaimReady {
								order_id: order.id,
							}))
							.ok();
					} else {
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
					// We have the proof, check if we can claim
					if self.settlement.can_claim(&order, &proof).await {
						tracing::info!("Order {} ready for claiming", order.id);
						self.event_bus
							.publish(SolverEvent::Settlement(SettlementEvent::ClaimReady {
								order_id: order.id,
							}))
							.ok();
					} else {
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
					.transition_order_status(&order.id, OrderStatus::Failed(tx_type))
					.await
				{
					tracing::error!("Failed to update order {} status: {}", order.id, e);
				}
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
						OrderStatus::Failed(_) => {
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
					"Failed to transition order {} to {:?}: {}",
					order_id, state, e
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
	use solver_storage::MockStorageInterface;
	use solver_types::{
		utils::builders::{IntentBuilder, OrderBuilder},
		ExecutionParams, FillProof, TransactionHash,
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
		// TODO: use builder!
		FillProof {
			tx_hash: TransactionHash(vec![0xbb; 32]),
			block_number: 12345,
			attestation_data: Some(vec![0x01, 0x02, 0x03]),
			filled_timestamp: 1234567890,
			oracle_address: "0x1234567890123456789012345678901234567890".to_string(),
		}
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
		let delivery = Arc::new(DeliveryService::new(delivery_impls, 1));
		let settlement_impls: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::new();
		let settlement = Arc::new(SettlementService::new(settlement_impls));
		let event_bus = EventBus::new(100);

		let recovery_service =
			RecoveryService::new(storage, state_machine, delivery, settlement, event_bus);

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
		let delivery = Arc::new(DeliveryService::new(delivery_impls, 1));
		let settlement_impls: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::new();
		let settlement = Arc::new(SettlementService::new(settlement_impls));
		let event_bus = EventBus::new(100);

		let recovery_service =
			RecoveryService::new(storage, state_machine, delivery, settlement, event_bus);

		let result = recovery_service.load_active_orders().await;
		assert!(result.is_ok());

		let orders = result.unwrap();
		assert_eq!(orders.len(), 1);
		assert_eq!(orders[0].id, "test_order_123");
		assert_eq!(orders[0].status, OrderStatus::Pending);
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
		let delivery = Arc::new(DeliveryService::new(delivery_impls, 1));
		let settlement_impls: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::new();
		let settlement = Arc::new(SettlementService::new(settlement_impls));
		let event_bus = EventBus::new(100);

		let recovery_service =
			RecoveryService::new(storage, state_machine, delivery, settlement, event_bus);

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
		let delivery = Arc::new(DeliveryService::new(delivery_impls, 1));
		let settlement_impls: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::new();
		let settlement = Arc::new(SettlementService::new(settlement_impls));
		let event_bus = EventBus::new(100);

		let recovery_service =
			RecoveryService::new(storage, state_machine, delivery, settlement, event_bus);

		let result = recovery_service.reconcile_with_blockchain(&order).await;
		assert!(result.is_ok());

		match result.unwrap() {
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
					})
				})
			});

		let delivery_impls: HashMap<u64, Arc<dyn solver_delivery::DeliveryInterface>> =
			HashMap::from([(
				1u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]);
		let delivery = Arc::new(DeliveryService::new(delivery_impls, 1));

		let mock_storage = MockStorageInterface::new();
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let settlement_impls: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::new();
		let settlement = Arc::new(SettlementService::new(settlement_impls));
		let event_bus = EventBus::new(100);

		let recovery_service =
			RecoveryService::new(storage, state_machine, delivery, settlement, event_bus);

		let result = recovery_service.reconcile_with_blockchain(&order).await;
		assert!(result.is_ok());

		match result.unwrap() {
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
					})
				})
			});

		let delivery_impls: HashMap<u64, Arc<dyn solver_delivery::DeliveryInterface>> =
			HashMap::from([(
				1u64, // Use chain 1 for pre-claim transaction
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]);
		let delivery = Arc::new(DeliveryService::new(delivery_impls, 1));

		let mock_storage = MockStorageInterface::new();
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let settlement_impls: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::new();
		let settlement = Arc::new(SettlementService::new(settlement_impls));
		let event_bus = EventBus::new(100);

		let recovery_service =
			RecoveryService::new(storage, state_machine, delivery, settlement, event_bus);

		let result = recovery_service.reconcile_with_blockchain(&order).await;
		assert!(result.is_ok());

		match result.unwrap() {
			ReconcileResult::NeedsClaim { fill_proof } => {
				assert!(fill_proof.is_some());
			},
			_ => panic!("Expected NeedsClaim"),
		}
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
					})
				})
			});

		let delivery_impls: HashMap<u64, Arc<dyn solver_delivery::DeliveryInterface>> =
			HashMap::from([(
				1u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]);
		let delivery = Arc::new(DeliveryService::new(delivery_impls, 1));

		let mock_storage = MockStorageInterface::new();
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let settlement_impls: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::new();
		let settlement = Arc::new(SettlementService::new(settlement_impls));
		let event_bus = EventBus::new(100);

		let recovery_service =
			RecoveryService::new(storage, state_machine, delivery, settlement, event_bus);

		let result = recovery_service.reconcile_with_blockchain(&order).await;
		assert!(result.is_ok());

		match result.unwrap() {
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
					})
				})
			});

		let delivery_impls: HashMap<u64, Arc<dyn solver_delivery::DeliveryInterface>> =
			HashMap::from([(
				1u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]);
		let delivery = Arc::new(DeliveryService::new(delivery_impls, 1));

		let mock_storage = MockStorageInterface::new();
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let settlement_impls: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::new();
		let settlement = Arc::new(SettlementService::new(settlement_impls));
		let event_bus = EventBus::new(100);

		let recovery_service =
			RecoveryService::new(storage, state_machine, delivery, settlement, event_bus);

		let result = recovery_service.reconcile_with_blockchain(&order).await;
		assert!(result.is_ok());

		match result.unwrap() {
			ReconcileResult::Failed(TransactionType::Prepare) => {},
			_ => panic!("Expected Failed(Prepare)"),
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
		let delivery = Arc::new(DeliveryService::new(delivery_impls, 1));

		// Create empty settlement service - this will cause can_claim to return false,
		// which should trigger spawn_settlement_monitor instead of publishing ClaimReady
		let settlement_impls: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::new();
		let settlement = Arc::new(SettlementService::new(settlement_impls));
		let event_bus = EventBus::new(100);

		// Subscribe to events
		let mut receiver = event_bus.subscribe();

		let recovery_service =
			RecoveryService::new(storage, state_machine, delivery, settlement, event_bus);

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
		let delivery = Arc::new(DeliveryService::new(delivery_impls, 1));
		let settlement_impls: HashMap<String, Box<dyn solver_settlement::SettlementInterface>> =
			HashMap::new();
		let settlement = Arc::new(SettlementService::new(settlement_impls));
		let event_bus = EventBus::new(100);

		// Subscribe to events
		let mut receiver = event_bus.subscribe();

		let recovery_service =
			RecoveryService::new(storage, state_machine, delivery, settlement, event_bus);

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
