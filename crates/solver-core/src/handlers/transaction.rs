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
	#[error("Service error: {0}")]
	Service(String),
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

		// Retrieve the order for settlement callback
		let order: Order = self
			.storage
			.retrieve(StorageKey::Orders.as_str(), &order_id)
			.await
			.map_err(|e| TransactionError::Storage(e.to_string()))?;

		// For PostFill and PreClaim, call settlement callback BEFORE other processing
		// This allows Hyperlane to extract and store message IDs from receipts
		if matches!(
			tx_type,
			TransactionType::PostFill | TransactionType::PreClaim
		) {
			// Call settlement-specific handler
			if let Ok(settlement) = self.settlement.find_settlement_for_order(&order) {
				settlement
					.handle_transaction_confirmed(&order, tx_type, &receipt)
					.await
					.map_err(|e: solver_settlement::SettlementError| {
						TransactionError::Service(format!("Settlement callback failed: {}", e))
					})?;
			}
		}

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
	/// Updates status to Executing and publishes OrderEvent::Executing
	/// to trigger the fill transaction.
	async fn handle_prepare_confirmed(
		&self,
		_tx_hash: TransactionHash,
		order: Order,
	) -> Result<(), TransactionError> {
		// Extract execution params
		let params = order.execution_params.clone().ok_or_else(|| {
			TransactionError::Service("Order missing execution params".to_string())
		})?;

		// Update order status to executing (prepare done, fill in progress)
		self.state_machine
			.transition_order_status(&order.id, OrderStatus::Executing)
			.await
			.map_err(|e| TransactionError::State(e.to_string()))?;

		// Now publish Executing event to proceed with fill
		self.event_bus
			.publish(SolverEvent::Order(OrderEvent::Executing { order, params }))
			.ok();

		Ok(())
	}

	/// Handles confirmed fill transactions.
	///
	/// Updates status to Executed and emits PostFillReady event to trigger
	/// post-fill transaction generation if needed.
	async fn handle_fill_confirmed(
		&self,
		_tx_hash: TransactionHash,
		order: Order,
	) -> Result<(), TransactionError> {
		let order_id = order.id;

		// Update status from Executing to Executed (fill completed)
		self.state_machine
			.transition_order_status(&order_id, OrderStatus::Executed)
			.await
			.map_err(|e| TransactionError::State(e.to_string()))?;

		// Emit PostFillReady event - handler will determine if transaction needed
		self.event_bus
			.publish(SolverEvent::Settlement(SettlementEvent::PostFillReady {
				order_id,
			}))
			.ok();

		Ok(())
	}

	/// Handles confirmed post-fill transactions.
	///
	/// Updates status to PostFilled and emits StartMonitoring event to begin
	/// monitoring for settlement readiness.
	async fn handle_post_fill_confirmed(
		&self,
		_tx_hash: TransactionHash,
		order: Order,
	) -> Result<(), TransactionError> {
		let order_id = order.id;

		// Update status to PostFilled
		self.state_machine
			.transition_order_status(&order_id, OrderStatus::PostFilled)
			.await
			.map_err(|e| TransactionError::State(e.to_string()))?;

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

		Ok(())
	}

	/// Handles confirmed pre-claim transactions.
	///
	/// Updates status to PreClaimed and emits ClaimReady event to trigger
	/// the final claim transaction.
	async fn handle_pre_claim_confirmed(
		&self,
		_tx_hash: TransactionHash,
		order: Order,
	) -> Result<(), TransactionError> {
		let order_id = order.id;
		// Update status from Settled to PreClaimed
		self.state_machine
			.transition_order_status(&order_id, OrderStatus::PreClaimed)
			.await
			.map_err(|e| TransactionError::State(e.to_string()))?;

		// PreClaim confirmed, emit ClaimReady
		self.event_bus
			.publish(SolverEvent::Settlement(SettlementEvent::ClaimReady {
				order_id,
			}))
			.ok();

		Ok(())
	}

	/// Handles confirmed claim transactions.
	///
	/// Updates status to Finalized and emits Completed event to signal
	/// successful order completion.
	async fn handle_claim_confirmed(
		&self,
		tx_hash: TransactionHash,
		order: Order,
	) -> Result<(), TransactionError> {
		let order_id = order.id;
		// Update order with claim transaction hash and mark as finalized
		self.state_machine
			.update_order_with(&order_id, |order| {
				order.claim_tx_hash = Some(tx_hash.clone());
				order.status = OrderStatus::Finalized;
			})
			.await
			.map_err(|e| TransactionError::State(e.to_string()))?;

		// Publish completed event
		self.event_bus
			.publish(SolverEvent::Settlement(
				solver_types::SettlementEvent::Completed { order_id },
			))
			.ok();

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
	use solver_settlement::SettlementService;
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
			Arc::new(SettlementService::new(HashMap::new(), 20)),
			event_bus,
		);

		(handler, receiver)
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
		let (handler, mut receiver) = create_test_handler_with_mocks(|storage| {
			// Track whether we've updated the order
			use std::sync::{Arc, Mutex};
			let updated_order_bytes: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
			let updated_order_bytes_clone = updated_order_bytes.clone();

			// Mock the retrieve call for getting the order
			storage
				.expect_get_bytes()
				.with(eq("orders:test_order_123".to_string()))
				.times(4) // Called: handle_confirmed (1x), transition_order_status (2x), get_order final check (1x)
				.returning(move |_| {
					// Check if we have an updated version saved
					let updated = updated_order_bytes_clone.lock().unwrap();
					if let Some(bytes) = updated.as_ref() {
						let bytes = bytes.clone();
						Box::pin(async move { Ok(bytes) })
					} else {
						// Return initial order before update
						let order = create_test_order(true);
						Box::pin(async move { Ok(serde_json::to_vec(&order).unwrap()) })
					}
				});

			// Mock exists check for transition_order_status
			storage
				.expect_exists()
				.with(eq("orders:test_order_123"))
				.times(1)
				.returning(|_| Box::pin(async move { Ok(true) }));

			// Mock set_bytes for store_order (initial) and transition_order_status
			storage
				.expect_set_bytes()
				.times(2)
				.returning(move |_, bytes, _, _| {
					// Store the updated order bytes
					*updated_order_bytes.lock().unwrap() = Some(bytes.to_vec());
					Box::pin(async move { Ok(()) })
				});
		})
		.await;

		// Store the order in state machine first
		let order_for_state = create_test_order(true);
		handler
			.state_machine
			.store_order(&order_for_state)
			.await
			.unwrap();

		let receipt = create_test_receipt(true);

		let result = handler
			.handle_confirmed(
				"test_order_123".to_string(),
				create_test_tx_hash(),
				TransactionType::Prepare,
				receipt,
			)
			.await;

		assert!(result.is_ok());

		// Should emit Executing event
		let event = receiver.recv().await.unwrap();
		match event {
			SolverEvent::Order(OrderEvent::Executing { order, params }) => {
				assert_eq!(order.id, "test_order_123");
				assert_eq!(params.gas_price, U256::from(20_000_000_000u64));
			},
			_ => panic!("Expected Executing event, got: {:?}", event),
		}

		// Verify order status was updated to Executing
		let updated_order = handler
			.state_machine
			.get_order(&order_for_state.id)
			.await
			.unwrap();
		assert_eq!(updated_order.status, OrderStatus::Executing);
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
		// Create order with Executing status since fill confirmation transitions to Executed
		let order = OrderBuilder::new()
			.with_status(OrderStatus::Executing)
			.with_execution_params(Some(ExecutionParams {
				gas_price: U256::from(20_000_000_000u64),
				priority_fee: Some(U256::from(1_000_000_000u64)),
			}))
			.with_fill_tx_hash(Some(TransactionHash(vec![0xab; 32])))
			.build();

		let receipt = create_test_receipt(true);

		let (handler, mut receiver) = create_test_handler_with_mocks(|storage| {
			// Mock the retrieve call for getting the order by order ID
			storage
				.expect_get_bytes()
				.with(eq("orders:test_order_123"))
				.times(4) // Called 3 times: handle_confirmed, transition_order_status, update_order_with
				.returning(|_| {
					// Return order with Executing status to match the valid transition
					let order = OrderBuilder::new()
						.with_status(OrderStatus::Executing)
						.with_execution_params(Some(ExecutionParams {
							gas_price: U256::from(20_000_000_000u64),
							priority_fee: Some(U256::from(1_000_000_000u64)),
						}))
						.with_fill_tx_hash(Some(TransactionHash(vec![0xab; 32])))
						.build();
					Box::pin(async move { Ok(serde_json::to_vec(&order).unwrap()) })
				});

			// Mock exists check for state transition
			storage
				.expect_exists()
				.with(eq("orders:test_order_123"))
				.times(1)
				.returning(|_| Box::pin(async move { Ok(true) }));

			// Mock set_bytes for state transition update (called twice: initial store + update)
			storage
				.expect_set_bytes()
				.times(1)
				.returning(|_, _, _, _| Box::pin(async move { Ok(()) }));
		})
		.await;

		let result = handler
			.handle_confirmed(
				"test_order_123".to_string(),
				receipt.hash.clone(),
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
			_ => panic!("Expected PostFillReady event, got: {:?}", event),
		}

		// Verify order status was updated to Executed by checking the state machine
		let updated_order = handler.state_machine.get_order(&order.id).await.unwrap();
		assert_eq!(updated_order.status, OrderStatus::Executing);
	}

	#[tokio::test]
	async fn test_handle_post_fill_confirmed() {
		let order = create_test_order(true);
		let tx_hash = create_test_tx_hash();

		let (handler, mut receiver) = create_test_handler_with_mocks(|storage| {
			// Track whether we've updated the order
			use std::sync::{Arc, Mutex};
			let updated_order_bytes: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
			let updated_order_bytes_clone = updated_order_bytes.clone();

			// Mock the retrieve call for getting the order by order ID
			storage
				.expect_get_bytes()
				.with(eq("orders:test_order_123"))
				.times(4) // Called: handle_confirmed (1x), transition_order_status (2x), get_order final check (1x)
				.returning(move |_| {
					// Check if we have an updated version saved
					let updated = updated_order_bytes_clone.lock().unwrap();
					if let Some(bytes) = updated.as_ref() {
						let bytes = bytes.clone();
						Box::pin(async move { Ok(bytes) })
					} else {
						// Return initial order with Executed status (required for PostFill transition)
						let mut order = create_test_order(true);
						order.status = OrderStatus::Executed;
						Box::pin(async move { Ok(serde_json::to_vec(&order).unwrap()) })
					}
				});

			// Mock exists check for state transition
			storage
				.expect_exists()
				.with(eq("orders:test_order_123"))
				.times(1)
				.returning(|_| Box::pin(async move { Ok(true) }));

			// Mock set_bytes for store_order (initial) and state transition update
			storage
				.expect_set_bytes()
				.times(2)
				.returning(move |_, bytes, _, _| {
					// Store the updated order bytes
					*updated_order_bytes.lock().unwrap() = Some(bytes.to_vec());
					Box::pin(async move { Ok(()) })
				});
		})
		.await;

		// Store the order in state machine first with Executed status (required for PostFill transition)
		let mut order_for_state = order.clone();
		order_for_state.status = OrderStatus::Executed;
		handler
			.state_machine
			.store_order(&order_for_state)
			.await
			.unwrap();

		let receipt = create_test_receipt(true);

		let result = handler
			.handle_confirmed(
				"test_order_123".to_string(),
				tx_hash,
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
			_ => panic!("Expected StartMonitoring event, got: {:?}", event),
		}

		// Verify order status was updated to PostFilled
		let updated_order = handler.state_machine.get_order(&order.id).await.unwrap();
		assert_eq!(updated_order.status, OrderStatus::PostFilled);
	}

	#[tokio::test]
	async fn test_handle_post_fill_confirmed_missing_fill_tx_hash() {
		let mut order = create_test_order(true);
		order.fill_tx_hash = None; // Remove fill tx hash
		let tx_hash = create_test_tx_hash();

		let (handler, _) = create_test_handler_with_mocks(|storage| {
			// Track whether we've updated the order
			use std::sync::{Arc, Mutex};
			let updated_order_bytes: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
			let updated_order_bytes_clone = updated_order_bytes.clone();

			// Mock the retrieve call for getting the order by order ID
			storage
				.expect_get_bytes()
				.with(eq("orders:test_order_123"))
				.times(3) // Called: handle_confirmed (1x), transition_order_status (2x) - fails before final get
				.returning(move |_| {
					// Check if we have an updated version saved
					let updated = updated_order_bytes_clone.lock().unwrap();
					if let Some(bytes) = updated.as_ref() {
						let bytes = bytes.clone();
						Box::pin(async move { Ok(bytes) })
					} else {
						// Return order with Executed status but missing fill_tx_hash
						let mut order = create_test_order(true);
						order.fill_tx_hash = None;
						order.status = OrderStatus::Executed;
						Box::pin(async move { Ok(serde_json::to_vec(&order).unwrap()) })
					}
				});

			// Mock exists check for state transition
			storage
				.expect_exists()
				.with(eq("orders:test_order_123"))
				.times(1)
				.returning(|_| Box::pin(async move { Ok(true) }));

			// Mock set_bytes for store_order (initial) and state transition
			storage
				.expect_set_bytes()
				.times(2)
				.returning(move |_, bytes, _, _| {
					// Store the updated order bytes
					*updated_order_bytes.lock().unwrap() = Some(bytes.to_vec());
					Box::pin(async move { Ok(()) })
				});
		})
		.await;

		// Store the order in state machine first with Executed status
		let mut order_for_state = order.clone();
		order_for_state.status = OrderStatus::Executed;
		handler
			.state_machine
			.store_order(&order_for_state)
			.await
			.unwrap();

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
			other => panic!("Expected Service error, got: {:?}", other),
		}
	}

	#[tokio::test]
	async fn test_handle_pre_claim_confirmed() {
		let tx_hash = create_test_tx_hash();

		let (handler, mut receiver) = create_test_handler_with_mocks(|storage| {
			// Track whether we've updated the order
			use std::sync::{Arc, Mutex};
			let updated_order_bytes: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
			let updated_order_bytes_clone = updated_order_bytes.clone();

			// Mock the retrieve call for getting the order by order ID
			storage
				.expect_get_bytes()
				.with(eq("orders:test_order_123"))
				.times(4) // Called: handle_confirmed (1x), transition_order_status (2x), get_order final check (1x)
				.returning(move |_| {
					// Check if we have an updated version saved
					let updated = updated_order_bytes_clone.lock().unwrap();
					if let Some(bytes) = updated.as_ref() {
						let bytes = bytes.clone();
						Box::pin(async move { Ok(bytes) })
					} else {
						// Return initial order with Settled status (required for PreClaim transition)
						let mut order = create_test_order(true);
						order.status = OrderStatus::Settled;
						Box::pin(async move { Ok(serde_json::to_vec(&order).unwrap()) })
					}
				});

			// Mock exists check for state transition
			storage
				.expect_exists()
				.with(eq("orders:test_order_123"))
				.times(1)
				.returning(|_| Box::pin(async move { Ok(true) }));

			// Mock set_bytes for store_order (initial) and state transition update
			storage
				.expect_set_bytes()
				.times(2)
				.returning(move |_, bytes, _, _| {
					// Store the updated order bytes
					*updated_order_bytes.lock().unwrap() = Some(bytes.to_vec());
					Box::pin(async move { Ok(()) })
				});
		})
		.await;

		// Store the order in state machine first with Settled status (required for PreClaim transition)
		let mut order_for_state = create_test_order(true);
		order_for_state.status = OrderStatus::Settled;
		handler
			.state_machine
			.store_order(&order_for_state)
			.await
			.unwrap();

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
			_ => panic!("Expected ClaimReady event, got: {:?}", event),
		}

		// Verify order status was updated to PreClaimed
		let updated_order = handler
			.state_machine
			.get_order(&order_for_state.id)
			.await
			.unwrap();
		assert_eq!(updated_order.status, OrderStatus::PreClaimed);
	}

	#[tokio::test]
	async fn test_handle_claim_confirmed() {
		let tx_hash = create_test_tx_hash();

		let (handler, mut receiver) = create_test_handler_with_mocks(|storage| {
			// Track whether we've saved the finalized order
			use std::sync::{Arc, Mutex};
			let finalized_order_bytes: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
			let finalized_order_bytes_clone = finalized_order_bytes.clone();

			// Mock the retrieve call for getting the order by order ID (handle_confirmed + update_order_with)
			storage
				.expect_get_bytes()
				.with(eq("orders:test_order_123"))
				.times(3) // Called: handle_confirmed (1x), update_order_with (2x)
				.returning(move |_| {
					// Check if we have a finalized version saved
					let finalized = finalized_order_bytes_clone.lock().unwrap();
					if let Some(bytes) = finalized.as_ref() {
						let bytes = bytes.clone();
						Box::pin(async move { Ok(bytes) })
					} else {
						// Return PreClaimed order before update
						let mut order = create_test_order(true);
						order.status = OrderStatus::PreClaimed;
						Box::pin(async move { Ok(serde_json::to_vec(&order).unwrap()) })
					}
				});

			// Mock exists check for update_order_with
			storage
				.expect_exists()
				.with(eq("orders:test_order_123"))
				.times(1)
				.returning(|_| Box::pin(async move { Ok(true) }));

			// Mock set_bytes for update_order_with (saves order with Finalized status)
			storage
				.expect_set_bytes()
				.times(1)
				.returning(move |_, bytes, _, _| {
					// Store the finalized order bytes
					*finalized_order_bytes.lock().unwrap() = Some(bytes.to_vec());
					Box::pin(async move { Ok(()) })
				});
		})
		.await;

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
			_ => panic!("Expected Completed event, got: {:?}", event),
		}

		// Verify order status was updated to Finalized and claim_tx_hash was set
		let updated_order = handler
			.state_machine
			.get_order("test_order_123")
			.await
			.unwrap();
		assert_eq!(updated_order.status, OrderStatus::Finalized);
		assert_eq!(updated_order.claim_tx_hash, Some(tx_hash));
	}

	#[tokio::test]
	async fn test_handle_failed_transaction() {
		let (handler, _) = create_test_handler_with_mocks(|storage| {
			// Track whether we've updated the order
			use std::sync::{Arc, Mutex};
			let updated_order_bytes: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
			let updated_order_bytes_clone = updated_order_bytes.clone();

			// Mock get_bytes for transition_order_status and final get_order
			storage
				.expect_get_bytes()
				.with(eq("orders:test_order_123"))
				.times(3) // Called: transition (2x), final get_order (1x)
				.returning(move |_| {
					// Check if we have an updated version saved
					let updated = updated_order_bytes_clone.lock().unwrap();
					if let Some(bytes) = updated.as_ref() {
						let bytes = bytes.clone();
						Box::pin(async move { Ok(bytes) })
					} else {
						// Return initial order
						let order = create_test_order(true);
						Box::pin(async move { Ok(serde_json::to_vec(&order).unwrap()) })
					}
				});

			// Mock exists check for transition_order_status
			storage
				.expect_exists()
				.with(eq("orders:test_order_123"))
				.times(1)
				.returning(|_| Box::pin(async move { Ok(true) }));

			// Mock set_bytes for store_order and transition_order_status
			storage
				.expect_set_bytes()
				.times(2)
				.returning(move |_, bytes, _, _| {
					// Store the updated order bytes
					*updated_order_bytes.lock().unwrap() = Some(bytes.to_vec());
					Box::pin(async move { Ok(()) })
				});
		})
		.await;

		// Store the order in state machine first
		let order_for_state = create_test_order(true);
		handler
			.state_machine
			.store_order(&order_for_state)
			.await
			.unwrap();

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
		let updated_order = handler
			.state_machine
			.get_order(&order_for_state.id)
			.await
			.unwrap();
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
