//! Settlement handler for processing settlement operations.
//!
//! Manages post-fill, pre-claim, and claim transaction generation and submission.
//! Handles the complete settlement lifecycle including optional oracle interactions
//! and proof generation through the settlement service.

use crate::engine::event_bus::EventBus;
use crate::monitoring::SettlementMonitor;
use crate::state::OrderStateMachine;
use alloy_primitives::hex;
use solver_delivery::{DeliveryService, TransactionMonitoringEvent, TransactionTracking};
use solver_order::OrderService;
use solver_settlement::SettlementService;
use solver_storage::StorageService;
use solver_types::{
	truncate_id, DeliveryEvent, Order, SettlementEvent, SolverEvent, StorageKey, TransactionHash,
	TransactionType,
};
use std::sync::Arc;
use thiserror::Error;
use tracing::instrument;

/// Errors that can occur during settlement processing.
///
/// These errors represent failures in storage operations,
/// service operations, or state transitions during settlement handling.
#[derive(Debug, Error)]
pub enum SettlementError {
	#[error("Storage error: {0}")]
	Storage(String),
	#[error("Service error: {0}")]
	Service(String),
	#[error("State error: {0}")]
	State(String),
}

/// Handler for processing settlement operations.
///
/// The SettlementHandler manages the complete settlement lifecycle including:
/// - Post-fill transaction generation and submission (e.g., oracle attestation requests)
/// - Pre-claim transaction generation and submission (e.g., oracle signature submission)
/// - Claim transaction batch processing for reward collection
/// - Settlement monitoring coordination
pub struct SettlementHandler {
	settlement: Arc<SettlementService>,
	order_service: Arc<OrderService>,
	delivery: Arc<DeliveryService>,
	storage: Arc<StorageService>,
	state_machine: Arc<OrderStateMachine>,
	event_bus: EventBus,
	monitoring_timeout_minutes: u64,
}

impl SettlementHandler {
	pub fn new(
		settlement: Arc<SettlementService>,
		order_service: Arc<OrderService>,
		delivery: Arc<DeliveryService>,
		storage: Arc<StorageService>,
		state_machine: Arc<OrderStateMachine>,
		event_bus: EventBus,
		monitoring_timeout_minutes: u64,
	) -> Self {
		Self {
			settlement,
			order_service,
			delivery,
			storage,
			state_machine,
			event_bus,
			monitoring_timeout_minutes,
		}
	}

	/// Helper method to spawn settlement monitoring task.
	pub fn spawn_settlement_monitor(&self, order: Order, fill_tx_hash: TransactionHash) {
		let monitor = SettlementMonitor::new(
			self.settlement.clone(),
			self.state_machine.clone(),
			self.event_bus.clone(),
			self.monitoring_timeout_minutes,
		);

		tokio::spawn(async move {
			monitor.monitor_claim_readiness(order, fill_tx_hash).await;
		});
	}

	/// Handles PostFillReady event by generating and submitting PostFill transaction if needed.
	#[instrument(skip_all, fields(order_id = %truncate_id(&order_id)))]
	pub async fn handle_post_fill_ready(&self, order_id: String) -> Result<(), SettlementError> {
		// Retrieve the order
		let order: Order = self
			.storage
			.retrieve(StorageKey::Orders.as_str(), &order_id)
			.await
			.map_err(|e| SettlementError::Storage(e.to_string()))?;

		// Get the fill transaction hash
		let fill_tx_hash = order.fill_tx_hash.clone().ok_or_else(|| {
			SettlementError::Service("Order missing fill transaction hash".to_string())
		})?;

		// Get the destination chain for the fill
		let chain_id = order
			.output_chains
			.first()
			.map(|c| c.chain_id)
			.ok_or_else(|| SettlementError::Service("No output chains in order".to_string()))?;

		// Get the fill receipt
		let receipt = self
			.delivery
			.get_receipt(&fill_tx_hash, chain_id)
			.await
			.map_err(|e| SettlementError::Service(format!("Failed to get fill receipt: {e}")))?;

		// Generate post-fill transaction
		let post_fill_tx = self
			.settlement
			.generate_post_fill_transaction(&order, &receipt)
			.await
			.map_err(|e| SettlementError::Service(e.to_string()))?;

		match post_fill_tx {
			Some(post_fill_tx) => {
				// Create callback for monitoring
				let event_bus = self.event_bus.clone();
				let callback = Box::new(move |event: TransactionMonitoringEvent| match event {
					TransactionMonitoringEvent::Confirmed {
						id,
						tx_hash,
						tx_type,
						receipt,
					} => {
						event_bus
							.publish(SolverEvent::Delivery(DeliveryEvent::TransactionConfirmed {
								order_id: id,
								tx_hash,
								tx_type,
								receipt,
							}))
							.ok();
					},
					TransactionMonitoringEvent::Failed {
						id,
						tx_hash,
						tx_type,
						error,
					} => {
						event_bus
							.publish(SolverEvent::Delivery(DeliveryEvent::TransactionFailed {
								order_id: id,
								tx_hash,
								tx_type,
								error,
							}))
							.ok();
					},
				});

				let tracking = TransactionTracking {
					id: order_id.clone(),
					tx_type: TransactionType::PostFill,
					callback,
				};

				let tx_hash = self
					.delivery
					.deliver(post_fill_tx.clone(), Some(tracking))
					.await
					.map_err(|e| SettlementError::Service(e.to_string()))?;

				// Store tx hash
				self.state_machine
					.set_transaction_hash(&order_id, tx_hash.clone(), TransactionType::PostFill)
					.await
					.map_err(|e| SettlementError::State(e.to_string()))?;

				// Store reverse mapping
				self.storage
					.store(
						StorageKey::OrderByTxHash.as_str(),
						&hex::encode(&tx_hash.0),
						&order_id,
						None,
					)
					.await
					.map_err(|e| SettlementError::Storage(e.to_string()))?;

				// Publish pending event
				self.event_bus
					.publish(SolverEvent::Delivery(DeliveryEvent::TransactionPending {
						order_id,
						tx_hash,
						tx_type: TransactionType::PostFill,
						tx_chain_id: post_fill_tx.chain_id,
					}))
					.ok();
			},
			None => {
				// No PostFill needed, start monitoring immediately
				tracing::info!(
					order_id = %truncate_id(&order_id),
					"No PostFill transaction needed, proceeding to settlement monitoring"
				);

				// Retrieve order
				let order: Order = self
					.storage
					.retrieve(StorageKey::Orders.as_str(), &order_id)
					.await
					.map_err(|e| SettlementError::Storage(e.to_string()))?;

				let fill_tx_hash = order.fill_tx_hash.clone().ok_or_else(|| {
					SettlementError::Service(
						"Missing fill transaction hash: required for settlement monitoring".into(),
					)
				})?;

				self.event_bus
					.publish(SolverEvent::Settlement(SettlementEvent::StartMonitoring {
						order_id,
						fill_tx_hash,
					}))
					.ok();
			},
		}
		Ok(())
	}

	/// Handles PreClaimReady event by generating and submitting PreClaim transaction if needed.
	#[instrument(skip_all, fields(order_id = %truncate_id(&order_id)))]
	pub async fn handle_pre_claim_ready(&self, order_id: String) -> Result<(), SettlementError> {
		// Retrieve the order
		let order: Order = self
			.storage
			.retrieve(StorageKey::Orders.as_str(), &order_id)
			.await
			.map_err(|e| SettlementError::Storage(e.to_string()))?;

		// Get the fill proof
		let fill_proof = order
			.fill_proof
			.clone()
			.ok_or_else(|| SettlementError::Service("Order missing fill proof".to_string()))?;

		// Generate pre-claim transaction
		let pre_claim_tx = self
			.settlement
			.generate_pre_claim_transaction(&order, &fill_proof)
			.await
			.map_err(|e| SettlementError::Service(e.to_string()))?;

		match pre_claim_tx {
			Some(pre_claim_tx) => {
				// Create callback for monitoring
				let event_bus = self.event_bus.clone();
				let callback = Box::new(move |event: TransactionMonitoringEvent| match event {
					TransactionMonitoringEvent::Confirmed {
						id,
						tx_hash,
						tx_type,
						receipt,
					} => {
						event_bus
							.publish(SolverEvent::Delivery(DeliveryEvent::TransactionConfirmed {
								order_id: id,
								tx_hash,
								tx_type,
								receipt,
							}))
							.ok();
					},
					TransactionMonitoringEvent::Failed {
						id,
						tx_hash,
						tx_type,
						error,
					} => {
						event_bus
							.publish(SolverEvent::Delivery(DeliveryEvent::TransactionFailed {
								order_id: id,
								tx_hash,
								tx_type,
								error,
							}))
							.ok();
					},
				});

				let tracking = TransactionTracking {
					id: order_id.clone(),
					tx_type: TransactionType::PreClaim,
					callback,
				};

				let tx_hash = self
					.delivery
					.deliver(pre_claim_tx.clone(), Some(tracking))
					.await
					.map_err(|e| SettlementError::Service(e.to_string()))?;

				// Store tx hash
				self.state_machine
					.set_transaction_hash(&order_id, tx_hash.clone(), TransactionType::PreClaim)
					.await
					.map_err(|e| SettlementError::State(e.to_string()))?;

				// Store reverse mapping
				self.storage
					.store(
						StorageKey::OrderByTxHash.as_str(),
						&hex::encode(&tx_hash.0),
						&order_id,
						None,
					)
					.await
					.map_err(|e| SettlementError::Storage(e.to_string()))?;

				// Publish pending event
				self.event_bus
					.publish(SolverEvent::Delivery(DeliveryEvent::TransactionPending {
						order_id,
						tx_hash,
						tx_type: TransactionType::PreClaim,
						tx_chain_id: pre_claim_tx.chain_id,
					}))
					.ok();
			},
			None => {
				// No PreClaim needed, emit ClaimReady
				tracing::info!(
					order_id = %truncate_id(&order_id),
					"No PreClaim transaction needed, proceeding to claim"
				);

				self.event_bus
					.publish(SolverEvent::Settlement(SettlementEvent::ClaimReady {
						order_id,
					}))
					.ok();
			},
		}
		Ok(())
	}

	/// Processes a batch of orders ready for claiming.
	#[instrument(skip_all)]
	pub async fn process_claim_batch(
		&self,
		batch: &mut Vec<String>,
	) -> Result<(), SettlementError> {
		for order_id in batch.drain(..) {
			// Retrieve order
			let order: Order = self
				.storage
				.retrieve(StorageKey::Orders.as_str(), &order_id)
				.await
				.map_err(|e| SettlementError::Storage(e.to_string()))?;

			// Retrieve fill proof (already validated when ClaimReady was emitted)
			let fill_proof = order
				.fill_proof
				.clone()
				.ok_or_else(|| SettlementError::Service("Order missing fill proof".to_string()))?;

			// Generate claim transaction
			let claim_tx = self
				.order_service
				.generate_claim_transaction(&order, &fill_proof)
				.await
				.map_err(|e| SettlementError::Service(e.to_string()))?;

			// Submit claim transaction through delivery service with monitoring
			let event_bus = self.event_bus.clone();
			let callback = Box::new(move |event: TransactionMonitoringEvent| match event {
				TransactionMonitoringEvent::Confirmed {
					id,
					tx_hash,
					tx_type,
					receipt,
				} => {
					event_bus
						.publish(SolverEvent::Delivery(DeliveryEvent::TransactionConfirmed {
							order_id: id,
							tx_hash,
							tx_type,
							receipt,
						}))
						.ok();
				},
				TransactionMonitoringEvent::Failed {
					id,
					tx_hash,
					tx_type,
					error,
				} => {
					event_bus
						.publish(SolverEvent::Delivery(DeliveryEvent::TransactionFailed {
							order_id: id,
							tx_hash,
							tx_type,
							error,
						}))
						.ok();
				},
			});

			let tracking = TransactionTracking {
				id: order.id.clone(),
				tx_type: TransactionType::Claim,
				callback,
			};

			let claim_tx_hash = self
				.delivery
				.deliver(claim_tx.clone(), Some(tracking))
				.await
				.map_err(|e| SettlementError::Service(e.to_string()))?;

			self.event_bus
				.publish(SolverEvent::Delivery(DeliveryEvent::TransactionPending {
					order_id: order.id.clone(),
					tx_hash: claim_tx_hash.clone(),
					tx_type: TransactionType::Claim,
					tx_chain_id: claim_tx.chain_id,
				}))
				.ok();

			// Update order with claim transaction hash
			self.state_machine
				.set_transaction_hash(&order.id, claim_tx_hash.clone(), TransactionType::Claim)
				.await
				.map_err(|e| SettlementError::State(e.to_string()))?;

			// Store reverse mapping: tx_hash -> order_id
			self.storage
				.store(
					StorageKey::OrderByTxHash.as_str(),
					&hex::encode(&claim_tx_hash.0),
					&order.id,
					None,
				)
				.await
				.map_err(|e| SettlementError::Storage(e.to_string()))?;
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use mockall::predicate::*;
	use solver_delivery::{DeliveryService, MockDeliveryInterface};
	use solver_order::{MockOrderInterface, OrderService};
	use solver_settlement::{MockSettlementInterface, SettlementService};
	use solver_storage::{MockStorageInterface, StorageError, StorageService};
	use solver_types::utils::tests::builders::{
		OrderBuilder, TransactionBuilder, TransactionReceiptBuilder,
	};
	use solver_types::{Address, Order, Transaction, TransactionHash, TransactionReceipt};
	use std::collections::HashMap;
	use std::sync::Arc;
	use tokio::sync::broadcast;

	fn create_test_order() -> Order {
		OrderBuilder::new().build()
	}

	fn create_test_receipt() -> TransactionReceipt {
		TransactionReceiptBuilder::new().build()
	}

	fn create_test_transaction() -> Transaction {
		TransactionBuilder::new()
			.chain_id(137)
			.gas_limit(21000)
			.gas_price_gwei(20)
			.build()
	}

	fn default_order_oracle_address() -> Address {
		solver_types::utils::parse_address("0x1234567890123456789012345678901234567890")
			.expect("Valid oracle address")
	}

	async fn create_test_handler_with_mocks<F1, F2, F3, F4>(
		setup_storage: F1,
		setup_settlement: F2,
		setup_delivery: F3,
		setup_order: F4,
	) -> (SettlementHandler, broadcast::Receiver<SolverEvent>)
	where
		F1: FnOnce(&mut MockStorageInterface),
		F2: FnOnce(&mut MockSettlementInterface),
		F3: FnOnce(&mut MockDeliveryInterface),
		F4: FnOnce(&mut MockOrderInterface),
	{
		let mut mock_storage = MockStorageInterface::new();
		let mut mock_settlement = MockSettlementInterface::new();
		let mut mock_delivery = MockDeliveryInterface::new();
		let mut mock_order = MockOrderInterface::new();

		// Set up expectations using the provided closures
		setup_storage(&mut mock_storage);
		setup_settlement(&mut mock_settlement);
		setup_delivery(&mut mock_delivery);
		setup_order(&mut mock_order);

		// Create services with configured mocks
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let settlement = Arc::new(SettlementService::new(
			HashMap::from([(
				"eip7683".to_string(),
				Box::new(mock_settlement) as Box<dyn solver_settlement::SettlementInterface>,
			)]),
			20,
		));
		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				137u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
		));
		let order_service = Arc::new(OrderService::new(
			HashMap::from([(
				"eip7683".to_string(),
				Box::new(mock_order) as Box<dyn solver_order::OrderInterface>,
			)]),
			Box::new(solver_order::MockExecutionStrategy::new()),
		));

		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let event_bus = EventBus::new(100);
		let event_rx = event_bus.subscribe(); // Get receiver from event bus

		let handler = SettlementHandler::new(
			settlement,
			order_service,
			delivery,
			storage,
			state_machine,
			event_bus,
			30,
		);

		(handler, event_rx)
	}

	#[tokio::test]
	async fn test_handle_post_fill_ready_storage_error() {
		let (handler, _) = create_test_handler_with_mocks(
			|mock_storage| {
				mock_storage.expect_get_bytes().returning(|_| {
					Box::pin(
						async move { Err(StorageError::NotFound("test_order_123".to_string())) },
					)
				});
			},
			|_| {}, // No settlement expectations
			|_| {}, // No delivery expectations
			|_| {}, // No order expectations
		)
		.await;

		let result = handler
			.handle_post_fill_ready("test_order_123".to_string())
			.await;
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), SettlementError::Storage(_)));
	}

	#[tokio::test]
	async fn test_handle_pre_claim_ready_missing_fill_proof() {
		let (handler, _) = create_test_handler_with_mocks(
			|mock_storage| {
				mock_storage.expect_get_bytes().returning(|_| {
					Box::pin(
						async move { Err(StorageError::NotFound("test_order_123".to_string())) },
					)
				});
			},
			|_| {},
			|_| {},
			|_| {},
		)
		.await;

		let result = handler
			.handle_pre_claim_ready("test_order_123".to_string())
			.await;
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), SettlementError::Storage(_)));
	}

	#[tokio::test]
	async fn test_process_claim_batch_storage_error() {
		let (handler, _) = create_test_handler_with_mocks(
			|mock_storage| {
				mock_storage
					.expect_get_bytes()
					.with(eq("orders:nonexistent_order"))
					.times(1)
					.returning(|_| {
						Box::pin(async move {
							Err(StorageError::NotFound("nonexistent_order".to_string()))
						})
					});
			},
			|_| {}, // No settlement expectations
			|_| {}, // No delivery expectations
			|_| {}, // No order expectations
		)
		.await;

		let mut batch = vec!["nonexistent_order".to_string()];
		let result = handler.process_claim_batch(&mut batch).await;
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), SettlementError::Storage(_)));
	}

	#[tokio::test]
	async fn test_handle_post_fill_ready_with_transaction() {
		let (handler, _) = create_test_handler_with_mocks(
			|mock_storage| {
				// Mock order retrieval - called twice: once by handler, once by settlement service
				mock_storage
					.expect_get_bytes()
					.with(eq("orders:test_order_123"))
					.times(2) // Called twice: initial retrieval + settlement service oracle lookup
					.returning(|_| {
						let order = OrderBuilder::new()
							.with_standard("eip7683")
							.with_fill_tx_hash(Some(TransactionHash(vec![0x11; 32])))
							.build();
						Box::pin(async move { Ok(serde_json::to_vec(&order).unwrap()) })
					});
				// Mock exists check for update operation
				mock_storage
					.expect_exists()
					.with(eq("orders:test_order_123"))
					.times(1)
					.returning(|_| Box::pin(async move { Ok(true) }));
				// Mock storage for transaction hash mapping
				mock_storage
					.expect_set_bytes()
					.times(2)
					.returning(|_, _, _, _| Box::pin(async move { Ok(()) }));
			},
			|mock_settlement| {
				// Add expectation for is_input_oracle_supported
				mock_settlement
					.expect_is_input_oracle_supported()
					.with(eq(1u64), eq(default_order_oracle_address()))
					.times(1)
					.returning(|_, _| true);

				// Mock settlement service methods
				mock_settlement
					.expect_generate_post_fill_transaction()
					.times(1)
					.returning(|_, _| {
						let tx = create_test_transaction();
						Box::pin(async move { Ok(Some(tx)) })
					});
			},
			|mock_delivery| {
				mock_delivery
					.expect_get_receipt()
					.with(eq(TransactionHash(vec![0x11; 32])), eq(137u64))
					.times(1)
					.returning(|_, _| {
						let receipt = create_test_receipt();
						Box::pin(async move { Ok(receipt) })
					});
				mock_delivery.expect_submit().times(1).returning(|_, _| {
					let hash = TransactionHash(vec![0x33; 32]);
					Box::pin(async move { Ok(hash) })
				});
			},
			|_| {}, // No order expectations
		)
		.await;

		let result = handler
			.handle_post_fill_ready("test_order_123".to_string())
			.await;

		assert!(result.is_ok());
	}

	#[tokio::test]
	async fn test_handle_post_fill_ready_no_transaction_needed() {
		let (handler, _) = create_test_handler_with_mocks(
			|mock_storage| {
				// Called twice: initial retrieval + when no PostFill needed
				mock_storage
					.expect_get_bytes()
					.with(eq("orders:test_order_123"))
					.times(2)
					.returning(|_| {
						let order = OrderBuilder::new()
							.with_standard("eip7683")
							.with_fill_tx_hash(Some(TransactionHash(vec![0x11; 32])))
							.build();
						Box::pin(async move { Ok(serde_json::to_vec(&order).unwrap()) })
					});
			},
			|mock_settlement| {
				// Add expectation for is_input_oracle_supported with the correct oracle address
				mock_settlement
					.expect_is_input_oracle_supported()
					.with(eq(1u64), eq(default_order_oracle_address()))
					.times(1)
					.returning(|_, _| true);

				mock_settlement
					.expect_generate_post_fill_transaction()
					.times(1)
					// Return None to indicate no transaction needed
					.returning(|_, _| Box::pin(async move { Ok(None) }));
			},
			|mock_delivery| {
				mock_delivery
					.expect_get_receipt()
					.with(eq(TransactionHash(vec![0x11; 32])), eq(137u64))
					.times(1)
					.returning(|_, _| {
						let receipt = create_test_receipt();
						Box::pin(async move { Ok(receipt) })
					});
			},
			|_| {}, // No order expectations
		)
		.await;

		let result = handler
			.handle_post_fill_ready("test_order_123".to_string())
			.await;

		assert!(result.is_ok());
	}

	#[tokio::test]
	async fn test_handle_post_fill_ready_missing_fill_tx_hash() {
		let (handler, _) = create_test_handler_with_mocks(
			|mock_storage| {
				mock_storage
					.expect_get_bytes()
					.with(eq("orders:test_order_123"))
					.times(1)
					.returning(|_| {
						let mut order = create_test_order();
						order.fill_tx_hash = None; // Missing fill tx hash
						Box::pin(async move { Ok(serde_json::to_vec(&order).unwrap()) })
					});
			},
			|_| {},
			|_| {},
			|_| {}, // No other expectations needed
		)
		.await;

		let result = handler
			.handle_post_fill_ready("test_order_123".to_string())
			.await;
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), SettlementError::Service(_)));
	}

	#[tokio::test]
	async fn test_handle_post_fill_ready_no_output_chains() {
		let (handler, _) = create_test_handler_with_mocks(
			|mock_storage| {
				mock_storage
					.expect_get_bytes()
					.with(eq("orders:test_order_123"))
					.times(1)
					.returning(|_| {
						let mut order = create_test_order();
						order.output_chains = vec![]; // No output chains
						Box::pin(async move { Ok(serde_json::to_vec(&order).unwrap()) })
					});
			},
			|_| {},
			|_| {},
			|_| {}, // No other expectations needed
		)
		.await;

		let result = handler
			.handle_post_fill_ready("test_order_123".to_string())
			.await;
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), SettlementError::Service(_)));
	}
}
