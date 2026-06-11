//! Transaction handler for managing blockchain transaction lifecycle.
//!
//! Handles transaction confirmations, failures, and state transitions based on
//! transaction type (prepare, fill, post-fill, pre-claim, claim). Spawns monitoring
//! tasks for pending transactions and emits events for settlement processing.

use crate::engine::event_bus::EventBus;
use crate::state::OrderStateMachine;
use alloy_primitives::hex;
use solver_settlement::SettlementService;
use solver_storage::StorageService;
use solver_types::{
	truncate_id, DeliveryEvent, Order, OrderEvent, OrderStatus, SettlementEvent, SolverEvent,
	StorageKey, TransactionHash, TransactionReceipt, TransactionType,
};
use std::sync::Arc;
use thiserror::Error;
use tracing::instrument;

/// Errors that can occur during transaction processing.
///
/// These errors represent failures in storage operations,
/// state transitions, or service operations during transaction handling.
#[derive(Debug, Error)]
pub enum TransactionError {
	#[error("Storage error: {0}")]
	Storage(String),
	#[error("State error: {0}")]
	State(String),
	#[error("Settlement callback failed for {stage:?}: {source}")]
	SettlementCallback {
		stage: TransactionType,
		#[source]
		source: solver_settlement::SettlementError,
	},
	#[error("Service error: {0}")]
	Service(String),
}

fn stage_hash(order: &Order, tx_type: TransactionType) -> Option<&TransactionHash> {
	match tx_type {
		TransactionType::Prepare => order.prepare_tx_hash.as_ref(),
		TransactionType::Fill => order.fill_tx_hash.as_ref(),
		TransactionType::PostFill => order.post_fill_tx_hash.as_ref(),
		TransactionType::PreClaim => order.pre_claim_tx_hash.as_ref(),
		TransactionType::Claim => order.claim_tx_hash.as_ref(),
	}
}

fn set_stage_hash(order: &mut Order, tx_type: TransactionType, tx_hash: TransactionHash) {
	match tx_type {
		TransactionType::Prepare => order.prepare_tx_hash = Some(tx_hash),
		TransactionType::Fill => order.fill_tx_hash = Some(tx_hash),
		TransactionType::PostFill => order.post_fill_tx_hash = Some(tx_hash),
		TransactionType::PreClaim => order.pre_claim_tx_hash = Some(tx_hash),
		TransactionType::Claim => order.claim_tx_hash = Some(tx_hash),
	}
}

/// Handler for managing blockchain transaction lifecycle.
///
/// The TransactionHandler manages transaction confirmations, failures,
/// and state transitions based on transaction type. It emits appropriate events
/// to trigger subsequent processing by other handlers (e.g., settlement handler
/// for post-fill and pre-claim transactions).
pub struct TransactionHandler {
	storage: Arc<StorageService>,
	state_machine: Arc<OrderStateMachine>,
	settlement: Arc<SettlementService>,
	event_bus: EventBus,
}

impl TransactionHandler {
	pub fn new(
		storage: Arc<StorageService>,
		state_machine: Arc<OrderStateMachine>,
		settlement: Arc<SettlementService>,
		event_bus: EventBus,
	) -> Self {
		Self {
			storage,
			state_machine,
			settlement,
			event_bus,
		}
	}

	async fn reconcile_already_applied_stage_hash(
		&self,
		order_id: &str,
		tx_type: TransactionType,
		observed_hash: &TransactionHash,
		order: &Order,
	) -> Result<(), TransactionError> {
		match stage_hash(order, tx_type) {
			Some(stored_hash) if stored_hash == observed_hash => Ok(()),
			Some(stored_hash) => {
				self.event_bus
					.publish(SolverEvent::Delivery(
						DeliveryEvent::TransactionCanonicalHashConflict {
							order_id: order_id.to_string(),
							tx_type,
							stored_hash: stored_hash.clone(),
							observed_hash: observed_hash.clone(),
						},
					))
					.ok();
				Ok(())
			},
			None => {
				let repair_hash = observed_hash.clone();
				let updated = self
					.state_machine
					.update_order_with(order_id, |order| {
						if stage_hash(order, tx_type).is_none() {
							set_stage_hash(order, tx_type, repair_hash.clone());
						}
					})
					.await
					.map_err(|e| TransactionError::State(e.to_string()))?;

				if let Some(stored_hash) = stage_hash(&updated, tx_type) {
					if stored_hash != observed_hash {
						self.event_bus
							.publish(SolverEvent::Delivery(
								DeliveryEvent::TransactionCanonicalHashConflict {
									order_id: order_id.to_string(),
									tx_type,
									stored_hash: stored_hash.clone(),
									observed_hash: observed_hash.clone(),
								},
							))
							.ok();
					}
				}
				Ok(())
			},
		}
	}

	/// Handles confirmed transactions based on their type.
	///
	/// Routes to the appropriate handler based on transaction type:
	/// - Prepare: Updates status to Executing and emits OrderEvent::Executing
	/// - Fill: Updates status to Executed and emits SettlementEvent::PostFillReady
	/// - PostFill: Updates status to PostFilled and emits SettlementEvent::StartMonitoring
	/// - PreClaim: Updates status to PreClaimed and emits SettlementEvent::ClaimReady
	/// - Claim: Updates status to Finalized and emits SettlementEvent::Completed
	#[instrument(skip_all, fields(order_id = %truncate_id(&order_id), tx_type = ?tx_type))]
	pub async fn handle_confirmed(
		&self,
		order_id: String,
		tx_hash: TransactionHash,
		tx_type: TransactionType,
		receipt: TransactionReceipt,
	) -> Result<(), TransactionError> {
		// Defensive check
		if !receipt.success {
			self.event_bus
				.publish(SolverEvent::Delivery(DeliveryEvent::TransactionFailed {
					order_id,
					tx_hash,
					tx_type,
					error: "Transaction reverted".to_string(),
				}))
				.ok();
			return Ok(());
		}

		// Retrieve the order for confirmation handling.
		let order: Order = self
			.storage
			.retrieve(StorageKey::Orders.as_str(), &order_id)
			.await
			.map_err(|e| TransactionError::Storage(e.to_string()))?;
		let settlement_callback_order = matches!(
			tx_type,
			TransactionType::PostFill | TransactionType::PreClaim
		)
		.then(|| order.clone());

		// Handle based on transaction type
		match tx_type {
			TransactionType::Prepare => {
				self.handle_prepare_confirmed(tx_hash, order).await?;
			},
			TransactionType::Fill => {
				self.handle_fill_confirmed(tx_hash, order).await?;
			},
			TransactionType::PostFill => {
				self.handle_post_fill_confirmed(tx_hash, order).await?;
			},
			TransactionType::PreClaim => {
				self.handle_pre_claim_confirmed(tx_hash, order).await?;
			},
			TransactionType::Claim => {
				self.handle_claim_confirmed(tx_hash, order).await?;
			},
		}

		// For PostFill and PreClaim, run settlement-specific receipt post-processing
		// after persisting the chain-confirmed stage. A transient callback failure
		// must not erase the fact that the transaction succeeded on-chain.
		if let Some(order) = settlement_callback_order {
			self.settlement
				.handle_transaction_confirmed(&order, tx_type, &receipt)
				.await
				.map_err(|source| TransactionError::SettlementCallback {
					stage: tx_type,
					source,
				})?;
		}

		Ok(())
	}

	/// Handles failed transactions.
	#[instrument(skip_all, fields(order_id = %truncate_id(&order_id), tx_hash = %truncate_id(&hex::encode(&tx_hash.0)), tx_type = ?tx_type))]
	pub async fn handle_failed(
		&self,
		order_id: String,
		tx_hash: TransactionHash,
		tx_type: TransactionType,
		error: String,
	) -> Result<(), TransactionError> {
		tracing::error!("Transaction failed: {}", error);

		// Update order status with specific failure type and error message
		self.state_machine
			.transition_order_status(&order_id, OrderStatus::Failed(tx_type, error))
			.await
			.map_err(|e| TransactionError::State(e.to_string()))?;

		Ok(())
	}

	/// Handles prepare transaction confirmation.
	///
	/// Updates status to Executing and persists the canonical `prepare_tx_hash`
	/// in one atomic write. Publishes `OrderEvent::Executing` only when the
	/// transition was actually applied; duplicate or out-of-order `Confirmed`
	/// callbacks from monitor replay, recovery/live races, or chain reorg
	/// reconciliation fall into the `AlreadyApplied` branch, where the handler
	/// repairs a missing stage hash or emits a canonical-hash conflict without
	/// re-triggering the fill.
	async fn handle_prepare_confirmed(
		&self,
		tx_hash: TransactionHash,
		order: Order,
	) -> Result<(), TransactionError> {
		// Extract execution params — precondition for publishing Executing.
		// Checked before the transition so a missing-params order does not
		// silently advance state without ever emitting the downstream event.
		let params = order.execution_params.clone().ok_or_else(|| {
			TransactionError::Service("Order missing execution params".to_string())
		})?;

		let order_id = order.id.clone();
		let tx_hash_for_update = tx_hash.clone();

		// Atomic transition + prepare_tx_hash write.
		let outcome = self
			.state_machine
			.try_transition_order_status(&order_id, OrderStatus::Executing, move |o| {
				o.prepare_tx_hash = Some(tx_hash_for_update.clone());
			})
			.await
			.map_err(|e| TransactionError::State(e.to_string()))?;

		if outcome.applied() {
			let updated_order = outcome.order().clone();
			self.event_bus
				.publish(SolverEvent::Order(OrderEvent::Executing {
					order: updated_order,
					params,
				}))
				.ok();
		} else {
			self.reconcile_already_applied_stage_hash(
				&order_id,
				TransactionType::Prepare,
				&tx_hash,
				outcome.order(),
			)
			.await?;
			tracing::debug!(
				order_id = %truncate_id(&order_id),
				"prepare confirmation: order already at/past Executing; skipping OrderEvent::Executing"
			);
		}

		Ok(())
	}

	/// Handles confirmed fill transactions.
	///
	/// Updates status to Executed and emits PostFillReady event to trigger
	/// post-fill transaction generation if needed. The downstream event is
	/// gated on `outcome.applied()` so a duplicate `Confirmed` callback from
	/// a same-nonce lineage does not double-publish PostFillReady.
	async fn handle_fill_confirmed(
		&self,
		tx_hash: TransactionHash,
		order: Order,
	) -> Result<(), TransactionError> {
		let order_id = order.id;

		// Update status from Executing to Executed (fill completed).
		let tx_hash_for_update = tx_hash.clone();
		let outcome = self
			.state_machine
			.try_transition_order_status(&order_id, OrderStatus::Executed, move |o| {
				o.fill_tx_hash = Some(tx_hash_for_update.clone());
			})
			.await
			.map_err(|e| TransactionError::State(e.to_string()))?;

		if outcome.applied() {
			// Emit PostFillReady event - handler will determine if transaction needed
			self.event_bus
				.publish(SolverEvent::Settlement(SettlementEvent::PostFillReady {
					order_id,
				}))
				.ok();
		} else {
			self.reconcile_already_applied_stage_hash(
				&order_id,
				TransactionType::Fill,
				&tx_hash,
				outcome.order(),
			)
			.await?;
			tracing::debug!(
				order_id = %truncate_id(&order_id),
				"fill confirmation: order already at/past Executed; skipping PostFillReady"
			);
		}

		Ok(())
	}

	/// Handles confirmed post-fill transactions.
	///
	/// Updates status to PostFilled and emits StartMonitoring event to begin
	/// monitoring for settlement readiness. The downstream event is gated on
	/// `outcome.applied()` so a duplicate `Confirmed` from a same-nonce
	/// lineage does not double-publish StartMonitoring.
	async fn handle_post_fill_confirmed(
		&self,
		tx_hash: TransactionHash,
		order: Order,
	) -> Result<(), TransactionError> {
		let order_id = order.id;

		// Update status to PostFilled.
		let tx_hash_for_update = tx_hash.clone();
		let outcome = self
			.state_machine
			.try_transition_order_status(&order_id, OrderStatus::PostFilled, move |o| {
				o.post_fill_tx_hash = Some(tx_hash_for_update.clone());
			})
			.await
			.map_err(|e| TransactionError::State(e.to_string()))?;

		if outcome.applied() {
			// Get fill transaction hash for monitoring
			let fill_tx_hash = order
				.fill_tx_hash
				.clone()
				.ok_or_else(|| TransactionError::Service("Missing fill transaction hash: required for post-fill transaction processing and settlement monitoring".into()))?;

			self.event_bus
				.publish(SolverEvent::Settlement(SettlementEvent::StartMonitoring {
					order_id,
					fill_tx_hash,
				}))
				.ok();
		} else {
			self.reconcile_already_applied_stage_hash(
				&order_id,
				TransactionType::PostFill,
				&tx_hash,
				outcome.order(),
			)
			.await?;
			tracing::debug!(
				order_id = %truncate_id(&order_id),
				"post-fill confirmation: order already at/past PostFilled; skipping StartMonitoring"
			);
		}

		Ok(())
	}

	/// Handles confirmed pre-claim transactions.
	///
	/// Updates status to PreClaimed and emits ClaimReady event to trigger
	/// the final claim transaction. The downstream event is gated on
	/// `outcome.applied()` so a duplicate `Confirmed` from a same-nonce
	/// lineage does not double-publish ClaimReady.
	async fn handle_pre_claim_confirmed(
		&self,
		tx_hash: TransactionHash,
		order: Order,
	) -> Result<(), TransactionError> {
		let order_id = order.id;
		// Update status from Settled to PreClaimed.
		let tx_hash_for_update = tx_hash.clone();
		let outcome = self
			.state_machine
			.try_transition_order_status(&order_id, OrderStatus::PreClaimed, move |o| {
				o.pre_claim_tx_hash = Some(tx_hash_for_update.clone());
			})
			.await
			.map_err(|e| TransactionError::State(e.to_string()))?;

		if outcome.applied() {
			// PreClaim confirmed, emit ClaimReady
			self.event_bus
				.publish(SolverEvent::Settlement(SettlementEvent::ClaimReady {
					order_id,
				}))
				.ok();
		} else {
			self.reconcile_already_applied_stage_hash(
				&order_id,
				TransactionType::PreClaim,
				&tx_hash,
				outcome.order(),
			)
			.await?;
			tracing::debug!(
				order_id = %truncate_id(&order_id),
				"pre-claim confirmation: order already at/past PreClaimed; skipping ClaimReady"
			);
		}

		Ok(())
	}

	/// Handles confirmed claim transactions.
	///
	/// Updates status to Finalized, records `claim_tx_hash`, and emits the
	/// Completed event. The downstream event is gated on `outcome.applied()`
	/// so a duplicate `Confirmed` from a same-nonce lineage does not
	/// double-publish Completed.
	async fn handle_claim_confirmed(
		&self,
		tx_hash: TransactionHash,
		order: Order,
	) -> Result<(), TransactionError> {
		let order_id = order.id;

		// Transition to Finalized first; the outcome tells us whether this
		// confirmation actually advanced the order's status. We do the
		// claim_tx_hash write only when the transition fires so duplicate
		// confirmations from same-nonce lineages don't overwrite the
		// canonical claim hash recorded on the first Confirmed.
		let tx_hash_for_update = tx_hash.clone();
		let outcome = self
			.state_machine
			.try_transition_order_status(&order_id, OrderStatus::Finalized, move |o| {
				o.claim_tx_hash = Some(tx_hash_for_update.clone());
			})
			.await
			.map_err(|e| TransactionError::State(e.to_string()))?;

		if outcome.applied() {
			// Publish completed event
			self.event_bus
				.publish(SolverEvent::Settlement(
					solver_types::SettlementEvent::Completed { order_id },
				))
				.ok();
		} else {
			self.reconcile_already_applied_stage_hash(
				&order_id,
				TransactionType::Claim,
				&tx_hash,
				outcome.order(),
			)
			.await?;
			tracing::debug!(
				order_id = %truncate_id(&order_id),
				"claim confirmation: order already at/past Finalized; skipping Completed"
			);
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::engine::event_bus::EventBus;
	use crate::state::OrderStateMachine;
	use alloy_primitives::U256;
	use mockall::predicate::*;
	use solver_settlement::{MockSettlementInterface, SettlementError, SettlementService};
	use solver_storage::{MockStorageInterface, StorageService};
	use solver_types::utils::tests::builders::{OrderBuilder, TransactionReceiptBuilder};
	use solver_types::{
		ExecutionParams, Order, OrderStatus, SolverEvent, TransactionHash, TransactionReceipt,
		TransactionType,
	};
	use std::collections::HashMap;
	use std::sync::Arc;
	use tokio::sync::broadcast;

	fn create_test_order(with_execution_params: bool) -> Order {
		OrderBuilder::new()
			.with_status(OrderStatus::Created)
			.with_execution_params(match with_execution_params {
				true => Some(ExecutionParams {
					gas_price: U256::from(20_000_000_000u64),
					priority_fee: Some(U256::from(1_000_000_000u64)),
				}),
				false => None,
			})
			.with_fill_tx_hash(Some(TransactionHash(vec![0xab; 32])))
			.build()
	}

	fn create_test_tx_hash() -> TransactionHash {
		TransactionHash(vec![0xcd; 32])
	}

	fn create_test_receipt(success: bool) -> TransactionReceipt {
		TransactionReceiptBuilder::new()
			.with_success(success)
			.build()
	}

	async fn create_test_handler_with_mocks<F1>(
		setup_storage: F1,
	) -> (TransactionHandler, broadcast::Receiver<SolverEvent>)
	where
		F1: FnOnce(&mut MockStorageInterface),
	{
		let mut mock_storage = MockStorageInterface::new();

		// Set up expectations using the provided closure
		setup_storage(&mut mock_storage);

		// Create services with configured mocks
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));

		// Use the SAME storage for state machine instead of separate memory storage
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));

		// Create event bus
		let event_bus = EventBus::new(100);
		let receiver = event_bus.subscribe();

		let handler = TransactionHandler::new(
			storage,
			state_machine,
			Arc::new(SettlementService::new(HashMap::new(), String::new(), 20)),
			event_bus,
		);

		(handler, receiver)
	}

	async fn create_memory_handler_with_order(
		order: Order,
	) -> (
		TransactionHandler,
		broadcast::Receiver<SolverEvent>,
		Arc<OrderStateMachine>,
	) {
		let storage_impl = solver_storage::implementations::memory::MemoryStorage::new();
		let storage = Arc::new(StorageService::new(Box::new(storage_impl)));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let event_bus = EventBus::new(100);
		let receiver = event_bus.subscribe();

		state_machine.store_order(&order).await.unwrap();

		let handler = TransactionHandler::new(
			storage,
			state_machine.clone(),
			Arc::new(SettlementService::new(HashMap::new(), String::new(), 20)),
			event_bus,
		);

		(handler, receiver, state_machine)
	}

	async fn create_memory_handler_with_order_and_settlement(
		order: Order,
		mock_settlement: MockSettlementInterface,
	) -> (
		TransactionHandler,
		broadcast::Receiver<SolverEvent>,
		Arc<OrderStateMachine>,
	) {
		let storage_impl = solver_storage::implementations::memory::MemoryStorage::new();
		let storage = Arc::new(StorageService::new(Box::new(storage_impl)));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let event_bus = EventBus::new(100);
		let receiver = event_bus.subscribe();

		state_machine.store_order(&order).await.unwrap();

		let settlement = Arc::new(SettlementService::new(
			HashMap::from([(
				"eip7683".to_string(),
				Box::new(mock_settlement) as Box<dyn solver_settlement::SettlementInterface>,
			)]),
			"eip7683".to_string(),
			20,
		));
		let handler =
			TransactionHandler::new(storage, state_machine.clone(), settlement, event_bus);

		(handler, receiver, state_machine)
	}

	#[tokio::test]
	async fn test_handle_confirmed_with_failed_receipt() {
		// No storage mock needed since failed receipts return early
		let (handler, mut receiver) = create_test_handler_with_mocks(|_storage| {
			// No expectations needed for failed receipt case
		})
		.await;

		let failed_receipt = create_test_receipt(false);

		let result = handler
			.handle_confirmed(
				"test_order".to_string(),
				create_test_tx_hash(),
				TransactionType::Fill,
				failed_receipt,
			)
			.await;

		assert!(result.is_ok());

		// Should emit TransactionFailed event
		let event = receiver.recv().await.unwrap();
		match event {
			SolverEvent::Delivery(DeliveryEvent::TransactionFailed {
				order_id,
				tx_type,
				error,
				..
			}) => {
				assert_eq!(order_id, "test_order");
				assert_eq!(tx_type, TransactionType::Fill);
				assert_eq!(error, "Transaction reverted");
			},
			_ => panic!("Expected TransactionFailed event"),
		}
	}

	#[tokio::test]
	async fn test_handle_prepare_confirmed() {
		let order_for_state = create_test_order(true);
		let (handler, mut receiver, state_machine) =
			create_memory_handler_with_order(order_for_state.clone()).await;

		let receipt = create_test_receipt(true);
		let tx_hash = create_test_tx_hash();

		let result = handler
			.handle_confirmed(
				"test_order_123".to_string(),
				tx_hash.clone(),
				TransactionType::Prepare,
				receipt,
			)
			.await;

		assert!(result.is_ok());

		// Should emit Executing event with the post-transition order carrying
		// the canonical prepare_tx_hash.
		let event = receiver.recv().await.unwrap();
		match event {
			SolverEvent::Order(OrderEvent::Executing { order, params }) => {
				assert_eq!(order.id, "test_order_123");
				assert_eq!(order.status, OrderStatus::Executing);
				assert_eq!(order.prepare_tx_hash, Some(tx_hash.clone()));
				assert_eq!(params.gas_price, U256::from(20_000_000_000u64));
			},
			_ => panic!("Expected Executing event, got: {event:?}"),
		}

		// Verify order status was updated to Executing and prepare_tx_hash
		// was persisted atomically with the transition.
		let updated_order = state_machine.get_order(&order_for_state.id).await.unwrap();
		assert_eq!(updated_order.status, OrderStatus::Executing);
		assert_eq!(updated_order.prepare_tx_hash, Some(tx_hash));
	}

	#[tokio::test]
	async fn test_handle_prepare_confirmed_missing_execution_params() {
		let order = create_test_order(false);

		let (handler, _) = create_test_handler_with_mocks(|storage| {
			// Mock the retrieve call for getting the order
			let order_bytes = serde_json::to_vec(&order).unwrap();
			storage
				.expect_get_bytes()
				.with(eq("orders:test_order_1".to_string()))
				.times(1)
				.returning(move |_| {
					let bytes = order_bytes.clone();
					Box::pin(async move { Ok(bytes) })
				});
		})
		.await;

		let receipt = create_test_receipt(true);

		let result = handler
			.handle_confirmed(
				"test_order_1".to_string(),
				create_test_tx_hash(),
				TransactionType::Prepare,
				receipt,
			)
			.await;

		assert!(result.is_err());
		match result.unwrap_err() {
			TransactionError::Service(msg) => {
				assert_eq!(msg, "Order missing execution params");
			},
			_ => panic!("Expected Service error"),
		}
	}

	#[tokio::test]
	async fn test_handle_fill_confirmed() {
		let order = OrderBuilder::new()
			.with_status(OrderStatus::Executing)
			.with_execution_params(Some(ExecutionParams {
				gas_price: U256::from(20_000_000_000u64),
				priority_fee: Some(U256::from(1_000_000_000u64)),
			}))
			.with_fill_tx_hash(Some(TransactionHash(vec![0xab; 32])))
			.build();
		let tx_hash = create_test_receipt(true).hash;
		let receipt = create_test_receipt(true);
		let (handler, mut receiver, state_machine) =
			create_memory_handler_with_order(order.clone()).await;

		let result = handler
			.handle_confirmed(
				"test_order_123".to_string(),
				tx_hash.clone(),
				TransactionType::Fill,
				receipt,
			)
			.await;

		assert!(result.is_ok());

		// Should emit PostFillReady event
		let event = receiver.recv().await.unwrap();
		match event {
			SolverEvent::Settlement(SettlementEvent::PostFillReady { order_id }) => {
				assert_eq!(order_id, "test_order_123");
			},
			_ => panic!("Expected PostFillReady event, got: {event:?}"),
		}

		let updated_order = state_machine.get_order(&order.id).await.unwrap();
		assert_eq!(updated_order.status, OrderStatus::Executed);
		assert_eq!(updated_order.fill_tx_hash, Some(tx_hash));
	}

	#[tokio::test]
	async fn fill_confirmed_writes_status_and_hash_in_one_persisted_order() {
		let order = OrderBuilder::new()
			.with_status(OrderStatus::Executing)
			.with_execution_params(Some(ExecutionParams {
				gas_price: U256::from(20_000_000_000u64),
				priority_fee: Some(U256::from(1_000_000_000u64)),
			}))
			.build();
		let tx_hash = TransactionHash(vec![0x33; 32]);
		let (handler, mut receiver, state_machine) =
			create_memory_handler_with_order(order.clone()).await;

		handler
			.handle_confirmed(
				order.id.clone(),
				tx_hash.clone(),
				TransactionType::Fill,
				create_test_receipt(true),
			)
			.await
			.unwrap();

		let updated_order = state_machine.get_order(&order.id).await.unwrap();
		assert_eq!(updated_order.status, OrderStatus::Executed);
		assert_eq!(updated_order.fill_tx_hash, Some(tx_hash));
		let events = drain_events(&mut receiver);
		assert_eq!(
			events
				.iter()
				.filter(|event| matches!(
					event,
					SolverEvent::Settlement(SettlementEvent::PostFillReady { .. })
				))
				.count(),
			1
		);
		assert_eq!(
			events
				.iter()
				.filter(|event| matches!(
					event,
					SolverEvent::Delivery(DeliveryEvent::TransactionCanonicalHashConflict { .. })
				))
				.count(),
			0
		);
	}

	#[tokio::test]
	async fn fill_confirmed_replaces_parent_hash_without_conflict_event() {
		let parent_hash = TransactionHash(vec![0x11; 32]);
		let child_hash = TransactionHash(vec![0x33; 32]);
		let order = OrderBuilder::new()
			.with_status(OrderStatus::Executing)
			.with_fill_tx_hash(Some(parent_hash))
			.with_execution_params(Some(ExecutionParams {
				gas_price: U256::from(20_000_000_000u64),
				priority_fee: Some(U256::from(1_000_000_000u64)),
			}))
			.build();
		let (handler, mut receiver, state_machine) =
			create_memory_handler_with_order(order.clone()).await;

		handler
			.handle_confirmed(
				order.id.clone(),
				child_hash.clone(),
				TransactionType::Fill,
				create_test_receipt(true),
			)
			.await
			.unwrap();

		let updated_order = state_machine.get_order(&order.id).await.unwrap();
		assert_eq!(updated_order.status, OrderStatus::Executed);
		assert_eq!(updated_order.fill_tx_hash, Some(child_hash));
		let events = drain_events(&mut receiver);
		assert_eq!(
			events
				.iter()
				.filter(|event| matches!(
					event,
					SolverEvent::Settlement(SettlementEvent::PostFillReady { .. })
				))
				.count(),
			1
		);
		assert_eq!(
			events
				.iter()
				.filter(|event| matches!(
					event,
					SolverEvent::Delivery(DeliveryEvent::TransactionCanonicalHashConflict { .. })
				))
				.count(),
			0
		);
	}

	#[tokio::test]
	async fn duplicate_fill_confirmed_repairs_missing_hash_without_republishing() {
		let tx_hash = TransactionHash(vec![0x33; 32]);
		let order = OrderBuilder::new()
			.with_status(OrderStatus::Executed)
			.with_fill_tx_hash(None)
			.build();
		let (handler, mut receiver, state_machine) =
			create_memory_handler_with_order(order.clone()).await;

		handler
			.handle_confirmed(
				order.id.clone(),
				tx_hash.clone(),
				TransactionType::Fill,
				create_test_receipt(true),
			)
			.await
			.unwrap();

		let updated_order = state_machine.get_order(&order.id).await.unwrap();
		assert_eq!(updated_order.status, OrderStatus::Executed);
		assert_eq!(updated_order.fill_tx_hash, Some(tx_hash));
		let events = drain_events(&mut receiver);
		assert_eq!(
			events
				.iter()
				.filter(|event| matches!(
					event,
					SolverEvent::Settlement(SettlementEvent::PostFillReady { .. })
				))
				.count(),
			0
		);
	}

	#[tokio::test]
	async fn duplicate_fill_confirmed_with_different_hash_emits_canonical_hash_conflict() {
		let stored_hash = TransactionHash(vec![0x33; 32]);
		let observed_hash = TransactionHash(vec![0x44; 32]);
		let order = OrderBuilder::new()
			.with_status(OrderStatus::Executed)
			.with_fill_tx_hash(Some(stored_hash.clone()))
			.build();
		let (handler, mut receiver, state_machine) =
			create_memory_handler_with_order(order.clone()).await;

		handler
			.handle_confirmed(
				order.id.clone(),
				observed_hash.clone(),
				TransactionType::Fill,
				create_test_receipt(true),
			)
			.await
			.unwrap();

		let updated_order = state_machine.get_order(&order.id).await.unwrap();
		assert_eq!(updated_order.fill_tx_hash, Some(stored_hash.clone()));
		let events = drain_events(&mut receiver);
		assert_eq!(
			events
				.iter()
				.filter(|event| matches!(
					event,
					SolverEvent::Settlement(SettlementEvent::PostFillReady { .. })
				))
				.count(),
			0
		);
		let conflicts = events
			.iter()
			.filter(|event| {
				matches!(
					event,
					SolverEvent::Delivery(DeliveryEvent::TransactionCanonicalHashConflict { .. })
				)
			})
			.collect::<Vec<_>>();
		assert_eq!(conflicts.len(), 1);
		match conflicts[0] {
			SolverEvent::Delivery(DeliveryEvent::TransactionCanonicalHashConflict {
				order_id,
				tx_type,
				stored_hash: event_stored_hash,
				observed_hash: event_observed_hash,
			}) => {
				assert_eq!(order_id, &order.id);
				assert_eq!(*tx_type, TransactionType::Fill);
				assert_eq!(event_stored_hash, &stored_hash);
				assert_eq!(event_observed_hash, &observed_hash);
			},
			other => panic!("expected TransactionCanonicalHashConflict, got {other:?}"),
		}
	}

	#[tokio::test]
	async fn test_handle_post_fill_confirmed() {
		let mut order = create_test_order(true);
		order.status = OrderStatus::Executed;
		let tx_hash = create_test_tx_hash();
		let (handler, mut receiver, state_machine) =
			create_memory_handler_with_order(order.clone()).await;

		let receipt = create_test_receipt(true);

		let result = handler
			.handle_confirmed(
				"test_order_123".to_string(),
				tx_hash.clone(),
				TransactionType::PostFill,
				receipt,
			)
			.await;

		assert!(result.is_ok());

		// Should emit StartMonitoring event
		let event = receiver.recv().await.unwrap();
		match event {
			SolverEvent::Settlement(SettlementEvent::StartMonitoring {
				order_id,
				fill_tx_hash,
			}) => {
				assert_eq!(order_id, "test_order_123");
				assert_eq!(fill_tx_hash, TransactionHash(vec![0xab; 32]));
			},
			_ => panic!("Expected StartMonitoring event, got: {event:?}"),
		}

		// Verify order status was updated to PostFilled
		let updated_order = state_machine.get_order(&order.id).await.unwrap();
		assert_eq!(updated_order.status, OrderStatus::PostFilled);
		assert_eq!(updated_order.post_fill_tx_hash, Some(tx_hash));
	}

	#[tokio::test]
	async fn post_fill_confirmed_transient_callback_error_persists_confirmation_first() {
		let mut order = create_test_order(true);
		order.status = OrderStatus::Executed;
		order.settlement_name = Some("eip7683".to_string());
		let tx_hash = create_test_tx_hash();
		let receipt = create_test_receipt(true);

		let mut mock_settlement = MockSettlementInterface::new();
		mock_settlement
			.expect_handle_transaction_confirmed()
			.withf(|_, tx_type, _| *tx_type == TransactionType::PostFill)
			.times(1)
			.returning(|_, _, _| {
				Box::pin(
					async move { Err(SettlementError::ProverUnavailable("rpc timeout".into())) },
				)
			});
		let (handler, _receiver, state_machine) =
			create_memory_handler_with_order_and_settlement(order.clone(), mock_settlement).await;

		let result = handler
			.handle_confirmed(
				order.id.clone(),
				tx_hash.clone(),
				TransactionType::PostFill,
				receipt,
			)
			.await;

		assert!(matches!(
			result,
			Err(TransactionError::SettlementCallback {
				stage: TransactionType::PostFill,
				..
			})
		));
		let updated_order = state_machine.get_order(&order.id).await.unwrap();
		assert_eq!(updated_order.status, OrderStatus::PostFilled);
		assert_eq!(updated_order.post_fill_tx_hash, Some(tx_hash));
	}

	#[tokio::test]
	async fn test_handle_post_fill_confirmed_missing_fill_tx_hash() {
		let mut order = create_test_order(true);
		order.fill_tx_hash = None; // Remove fill tx hash
		order.status = OrderStatus::Executed;
		let tx_hash = create_test_tx_hash();
		let (handler, _, _state_machine) = create_memory_handler_with_order(order).await;

		let receipt = create_test_receipt(true);

		let result = handler
			.handle_confirmed(
				"test_order_123".to_string(),
				tx_hash,
				TransactionType::PostFill,
				receipt,
			)
			.await;

		assert!(result.is_err());
		match result.unwrap_err() {
			TransactionError::Service(msg) => {
				assert!(msg.contains("Missing fill transaction hash"));
			},
			other => panic!("Expected Service error, got: {other:?}"),
		}
	}

	#[tokio::test]
	async fn test_handle_pre_claim_confirmed() {
		let tx_hash = create_test_tx_hash();
		let mut order_for_state = create_test_order(true);
		order_for_state.status = OrderStatus::Settled;
		let (handler, mut receiver, state_machine) =
			create_memory_handler_with_order(order_for_state.clone()).await;

		let receipt = create_test_receipt(true);

		let result = handler
			.handle_confirmed(
				"test_order_123".to_string(),
				tx_hash.clone(),
				TransactionType::PreClaim,
				receipt,
			)
			.await;

		assert!(result.is_ok());

		// Should emit ClaimReady event
		let event = receiver.recv().await.unwrap();
		match event {
			SolverEvent::Settlement(SettlementEvent::ClaimReady { order_id }) => {
				assert_eq!(order_id, order_for_state.id);
			},
			_ => panic!("Expected ClaimReady event, got: {event:?}"),
		}

		// Verify order status was updated to PreClaimed
		let updated_order = state_machine.get_order(&order_for_state.id).await.unwrap();
		assert_eq!(updated_order.status, OrderStatus::PreClaimed);
		assert_eq!(updated_order.pre_claim_tx_hash, Some(tx_hash));
	}

	#[tokio::test]
	async fn pre_claim_confirmed_transient_callback_error_persists_confirmation_first() {
		let tx_hash = create_test_tx_hash();
		let mut order = create_test_order(true);
		order.status = OrderStatus::Settled;
		order.settlement_name = Some("eip7683".to_string());
		let receipt = create_test_receipt(true);

		let mut mock_settlement = MockSettlementInterface::new();
		mock_settlement
			.expect_handle_transaction_confirmed()
			.withf(|_, tx_type, _| *tx_type == TransactionType::PreClaim)
			.times(1)
			.returning(|_, _, _| {
				Box::pin(
					async move { Err(SettlementError::ProverUnavailable("rpc timeout".into())) },
				)
			});
		let (handler, _receiver, state_machine) =
			create_memory_handler_with_order_and_settlement(order.clone(), mock_settlement).await;

		let result = handler
			.handle_confirmed(
				order.id.clone(),
				tx_hash.clone(),
				TransactionType::PreClaim,
				receipt,
			)
			.await;

		assert!(matches!(
			result,
			Err(TransactionError::SettlementCallback {
				stage: TransactionType::PreClaim,
				..
			})
		));
		let updated_order = state_machine.get_order(&order.id).await.unwrap();
		assert_eq!(updated_order.status, OrderStatus::PreClaimed);
		assert_eq!(updated_order.pre_claim_tx_hash, Some(tx_hash));
	}

	#[tokio::test]
	async fn test_handle_claim_confirmed() {
		let tx_hash = create_test_tx_hash();
		let mut order_for_state = create_test_order(true);
		order_for_state.status = OrderStatus::PreClaimed;
		let (handler, mut receiver, state_machine) =
			create_memory_handler_with_order(order_for_state.clone()).await;

		let receipt = create_test_receipt(true);

		let result = handler
			.handle_confirmed(
				"test_order_123".to_string(),
				tx_hash.clone(),
				TransactionType::Claim,
				receipt,
			)
			.await;

		assert!(result.is_ok());

		// Should emit Completed event
		let event = receiver.recv().await.unwrap();
		match event {
			SolverEvent::Settlement(SettlementEvent::Completed { order_id }) => {
				assert_eq!(order_id, "test_order_123");
			},
			_ => panic!("Expected Completed event, got: {event:?}"),
		}

		// Verify order status was updated to Finalized and claim_tx_hash was set
		let updated_order = state_machine.get_order("test_order_123").await.unwrap();
		assert_eq!(updated_order.status, OrderStatus::Finalized);
		assert_eq!(updated_order.claim_tx_hash, Some(tx_hash));
	}

	#[tokio::test]
	async fn test_handle_failed_transaction() {
		let order_for_state = create_test_order(true);
		let (handler, _, state_machine) =
			create_memory_handler_with_order(order_for_state.clone()).await;

		let result = handler
			.handle_failed(
				order_for_state.id.clone(),
				create_test_tx_hash(),
				TransactionType::Fill,
				"Gas limit exceeded".to_string(),
			)
			.await;

		assert!(result.is_ok());

		// Verify order status was updated to Failed
		let updated_order = state_machine.get_order(&order_for_state.id).await.unwrap();
		assert_eq!(
			updated_order.status,
			OrderStatus::Failed(TransactionType::Fill, "Gas limit exceeded".to_string())
		);
	}

	#[tokio::test]
	async fn test_handle_confirmed_storage_error() {
		let (handler, _) = create_test_handler_with_mocks(|storage| {
			// Simulate storage error for order retrieval
			storage
				.expect_get_bytes()
				.with(eq("orders:test_order_1".to_string()))
				.times(1)
				.returning(|_| {
					Box::pin(async {
						Err(solver_storage::StorageError::NotFound(
							"test_order_1".to_string(),
						))
					})
				});
		})
		.await;

		let receipt = create_test_receipt(true);

		let result = handler
			.handle_confirmed(
				"test_order_1".to_string(),
				create_test_tx_hash(),
				TransactionType::Prepare,
				receipt,
			)
			.await;

		assert!(result.is_err());
		match result.unwrap_err() {
			TransactionError::Storage(_) => {}, // Expected
			_ => panic!("Expected Storage error"),
		}
	}

	/// Drains the given broadcast subscriber non-blockingly and counts events
	/// matching the predicate. Used by idempotency-gating tests.
	fn drain_count<F>(sub: &mut tokio::sync::broadcast::Receiver<SolverEvent>, pred: F) -> usize
	where
		F: Fn(&SolverEvent) -> bool,
	{
		let mut count = 0;
		while let Ok(ev) = sub.try_recv() {
			if pred(&ev) {
				count += 1;
			}
		}
		count
	}

	fn drain_events(sub: &mut tokio::sync::broadcast::Receiver<SolverEvent>) -> Vec<SolverEvent> {
		let mut events = Vec::new();
		while let Ok(ev) = sub.try_recv() {
			events.push(ev);
		}
		events
	}

	/// Regression test: a duplicate `Confirmed` callback arriving from a
	/// same-nonce lineage (e.g., gas-bumped replacement) must NOT re-publish
	/// the downstream Settlement event. Without the
	/// `try_transition_order_status` + `outcome.applied()` gate this test
	/// fails because the second handler call re-publishes PostFillReady.
	#[tokio::test]
	async fn handle_fill_confirmed_publishes_post_fill_ready_only_once() {
		// Build an order at Executing — the precondition for handle_fill_confirmed.
		let order_at_executing = OrderBuilder::new()
			.with_id("test_order_dup_fill")
			.with_status(OrderStatus::Executing)
			.with_execution_params(Some(ExecutionParams {
				gas_price: U256::from(20_000_000_000u64),
				priority_fee: Some(U256::from(1_000_000_000u64)),
			}))
			.with_fill_tx_hash(Some(TransactionHash(vec![0xab; 32])))
			.build();

		// Use a real in-memory storage so both handler calls observe the
		// status update produced by the first call. The mock-based pattern
		// used elsewhere in this file isn't well suited to multi-call
		// idempotency tests because the mocked retrieve doesn't naturally
		// reflect intermediate writes across two `transition` calls.
		let storage_impl = solver_storage::implementations::memory::MemoryStorage::new();
		let storage = Arc::new(StorageService::new(Box::new(storage_impl)));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let event_bus = EventBus::new(100);
		let mut subscriber = event_bus.subscribe();

		let handler = TransactionHandler::new(
			storage.clone(),
			state_machine.clone(),
			Arc::new(SettlementService::new(HashMap::new(), String::new(), 20)),
			event_bus,
		);

		// Seed the order in storage at Executing.
		state_machine
			.store_order(&order_at_executing)
			.await
			.unwrap();

		// First confirmation: Executing → Executed. Should publish PostFillReady.
		handler
			.handle_fill_confirmed(TransactionHash(vec![0xaa; 32]), order_at_executing.clone())
			.await
			.unwrap();
		let first = drain_count(&mut subscriber, |e| {
			matches!(
				e,
				SolverEvent::Settlement(SettlementEvent::PostFillReady { .. })
			)
		});
		assert_eq!(first, 1, "first confirmation must publish PostFillReady");

		// Duplicate confirmation arrives (e.g., bumped tx's receipt fires
		// after the canonical tx already landed). Order is now at Executed.
		let mut order_at_executed = order_at_executing.clone();
		order_at_executed.status = OrderStatus::Executed;
		handler
			.handle_fill_confirmed(TransactionHash(vec![0xbb; 32]), order_at_executed)
			.await
			.unwrap();
		let second = drain_count(&mut subscriber, |e| {
			matches!(
				e,
				SolverEvent::Settlement(SettlementEvent::PostFillReady { .. })
			)
		});
		assert_eq!(
			second, 0,
			"duplicate Confirmed must not double-publish PostFillReady"
		);
	}

	/// Regression for the Prepare counterpart of the Fill idempotency test.
	/// A duplicate `Confirmed` callback for the Prepare stage (e.g., a
	/// same-nonce gas-bumped replacement landing after the parent already
	/// advanced the order) must NOT re-publish `OrderEvent::Executing` — that
	/// would re-trigger the fill submission.
	#[tokio::test]
	async fn handle_prepare_confirmed_publishes_executing_only_once() {
		let order_at_created = OrderBuilder::new()
			.with_id("test_order_dup_prepare")
			.with_status(OrderStatus::Created)
			.with_execution_params(Some(ExecutionParams {
				gas_price: U256::from(20_000_000_000u64),
				priority_fee: Some(U256::from(1_000_000_000u64)),
			}))
			.build();

		let storage_impl = solver_storage::implementations::memory::MemoryStorage::new();
		let storage = Arc::new(StorageService::new(Box::new(storage_impl)));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let event_bus = EventBus::new(100);
		let mut subscriber = event_bus.subscribe();

		let handler = TransactionHandler::new(
			storage.clone(),
			state_machine.clone(),
			Arc::new(SettlementService::new(HashMap::new(), String::new(), 20)),
			event_bus,
		);

		state_machine.store_order(&order_at_created).await.unwrap();

		// First confirmation: Created → Executing. Should publish Executing.
		handler
			.handle_prepare_confirmed(TransactionHash(vec![0xaa; 32]), order_at_created.clone())
			.await
			.unwrap();
		let first = drain_count(&mut subscriber, |e| {
			matches!(e, SolverEvent::Order(OrderEvent::Executing { .. }))
		});
		assert_eq!(first, 1, "first confirmation must publish Executing");

		// Duplicate confirmation (e.g., bumped-tx receipt arrives after the
		// parent already advanced the order). Order is now at Executing.
		let mut order_at_executing = order_at_created.clone();
		order_at_executing.status = OrderStatus::Executing;
		handler
			.handle_prepare_confirmed(TransactionHash(vec![0xbb; 32]), order_at_executing)
			.await
			.unwrap();
		let second = drain_count(&mut subscriber, |e| {
			matches!(e, SolverEvent::Order(OrderEvent::Executing { .. }))
		});
		assert_eq!(
			second, 0,
			"duplicate Confirmed must not re-publish OrderEvent::Executing"
		);
	}

	/// Regression for the AlreadyApplied-conflict branch on the Prepare stage.
	/// An order already past Prepare with a stored `prepare_tx_hash` receives
	/// a duplicate Prepare confirmation carrying a different hash. The
	/// handler must emit `TransactionCanonicalHashConflict`, leave the stored
	/// hash unchanged, and NOT re-publish `OrderEvent::Executing`.
	#[tokio::test]
	async fn duplicate_prepare_confirmed_with_different_hash_emits_canonical_hash_conflict() {
		let stored_hash = TransactionHash(vec![0x33; 32]);
		let observed_hash = TransactionHash(vec![0x44; 32]);
		let order = OrderBuilder::new()
			.with_status(OrderStatus::Executing)
			.with_prepare_tx_hash(Some(stored_hash.clone()))
			.with_execution_params(Some(ExecutionParams {
				gas_price: U256::from(20_000_000_000u64),
				priority_fee: Some(U256::from(1_000_000_000u64)),
			}))
			.build();
		let (handler, mut receiver, state_machine) =
			create_memory_handler_with_order(order.clone()).await;

		handler
			.handle_confirmed(
				order.id.clone(),
				observed_hash.clone(),
				TransactionType::Prepare,
				create_test_receipt(true),
			)
			.await
			.unwrap();

		let updated_order = state_machine.get_order(&order.id).await.unwrap();
		assert_eq!(updated_order.prepare_tx_hash, Some(stored_hash.clone()));
		let events = drain_events(&mut receiver);
		assert_eq!(
			events
				.iter()
				.filter(|event| matches!(event, SolverEvent::Order(OrderEvent::Executing { .. })))
				.count(),
			0,
			"AlreadyApplied with different hash must not republish Executing"
		);
		let conflicts = events
			.iter()
			.filter(|event| {
				matches!(
					event,
					SolverEvent::Delivery(DeliveryEvent::TransactionCanonicalHashConflict { .. })
				)
			})
			.collect::<Vec<_>>();
		assert_eq!(conflicts.len(), 1);
		match conflicts[0] {
			SolverEvent::Delivery(DeliveryEvent::TransactionCanonicalHashConflict {
				order_id,
				tx_type,
				stored_hash: event_stored_hash,
				observed_hash: event_observed_hash,
			}) => {
				assert_eq!(order_id, &order.id);
				assert_eq!(*tx_type, TransactionType::Prepare);
				assert_eq!(event_stored_hash, &stored_hash);
				assert_eq!(event_observed_hash, &observed_hash);
			},
			other => panic!("expected TransactionCanonicalHashConflict, got {other:?}"),
		}
	}

	#[tokio::test]
	async fn test_handle_failed_state_error() {
		let (handler, _) = create_test_handler_with_mocks(|storage| {
			// Mock get_bytes to return NotFound error for nonexistent order
			storage
				.expect_get_bytes()
				.with(eq("orders:nonexistent_order"))
				.times(1)
				.returning(|key| {
					let key = key.to_string();
					Box::pin(async move { Err(solver_storage::StorageError::NotFound(key)) })
				});
		})
		.await;

		// Don't store the order to cause a state error

		let result = handler
			.handle_failed(
				"nonexistent_order".to_string(),
				create_test_tx_hash(),
				TransactionType::Fill,
				"Test error".to_string(),
			)
			.await;

		assert!(result.is_err());
		match result.unwrap_err() {
			TransactionError::State(_) => {}, // Expected
			_ => panic!("Expected State error"),
		}
	}
}
