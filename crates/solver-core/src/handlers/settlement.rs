//! Settlement handler for processing settlement operations.
//!
//! Manages post-fill, pre-claim, and claim transaction generation and submission.
//! Handles the complete settlement lifecycle including optional oracle interactions
//! and proof generation through the settlement service.

use crate::engine::event_bus::EventBus;
use crate::monitoring::SettlementMonitor;
use crate::state::transaction_attempt::TransactionAttemptStore;
use crate::state::OrderStateMachine;
use alloy_primitives::hex;
use solver_delivery::{
	DeliveryService, RevertClassification, TransactionAttemptRecorder, TransactionMonitoringEvent,
	TransactionTracking,
};
use solver_order::OrderService;
use solver_settlement::SettlementService;
use solver_storage::StorageService;
use solver_types::{
	truncate_id, DeliveryEvent, NetworksConfig, Order, SettlementEvent, SolverEvent, StorageKey,
	TransactionHash, TransactionType,
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
	#[error("Delivery error: {0}")]
	Delivery(#[from] solver_delivery::DeliveryError),
	#[error("Settlement service error: {0}")]
	SettlementService(#[from] solver_settlement::SettlementError),
	#[error("State error: {0}")]
	State(String),
	/// Transient delivery failure caused by the signer being short on
	/// native gas at submission time. Distinguished from `Service` so
	/// callers (e.g. the engine's PostFillReady handler) can route this
	/// to a retry-on-recovery path instead of marking the order Failed.
	/// The underlying `DeliveryError::InsufficientNativeGas` payload is
	/// preserved for diagnostics.
	#[error("Insufficient native gas: {0}")]
	InsufficientNativeGas(Box<solver_delivery::InsufficientNativeGasInfo>),
}

fn map_delivery_error(error: solver_delivery::DeliveryError) -> SettlementError {
	match error {
		solver_delivery::DeliveryError::InsufficientNativeGas(info) => {
			SettlementError::InsufficientNativeGas(info)
		},
		other => SettlementError::Delivery(other),
	}
}

fn map_settlement_service_error(error: solver_settlement::SettlementError) -> SettlementError {
	SettlementError::SettlementService(error)
}

#[derive(Debug, Error)]
#[error("Claim batch failed for order {order_id}: {error}")]
pub struct ClaimBatchError {
	pub order_id: String,
	pub error: SettlementError,
}

impl ClaimBatchError {
	fn new(order_id: &str, error: SettlementError) -> Self {
		Self {
			order_id: order_id.to_string(),
			error,
		}
	}
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
	networks: NetworksConfig,
}

impl SettlementHandler {
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		settlement: Arc<SettlementService>,
		order_service: Arc<OrderService>,
		delivery: Arc<DeliveryService>,
		storage: Arc<StorageService>,
		state_machine: Arc<OrderStateMachine>,
		event_bus: EventBus,
		monitoring_timeout_minutes: u64,
		networks: NetworksConfig,
	) -> Self {
		Self {
			settlement,
			order_service,
			delivery,
			storage,
			state_machine,
			event_bus,
			monitoring_timeout_minutes,
			networks,
		}
	}

	fn transaction_attempt_recorder(&self) -> Arc<dyn TransactionAttemptRecorder> {
		Arc::new(TransactionAttemptStore::new(self.storage.clone()))
	}

	/// Helper method to spawn settlement monitoring task.
	pub fn spawn_settlement_monitor(&self, order: Order, fill_tx_hash: TransactionHash) {
		let monitor = SettlementMonitor::new(
			self.settlement.clone(),
			self.state_machine.clone(),
			self.event_bus.clone(),
			self.monitoring_timeout_minutes,
			self.delivery.clone(),
			self.networks.clone(),
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

		// If the post-fill was already submitted before a crash, recover the persisted
		// broadcaster state and continue with monitoring instead of resubmitting.
		let recovered = self
			.settlement
			.recover_post_fill_state(&order)
			.await
			.map_err(map_settlement_service_error)?;
		if recovered {
			tracing::info!(
				order_id = %truncate_id(&order_id),
				"Recovered existing post-fill state, proceeding to settlement monitoring"
			);
			self.event_bus
				.publish(SolverEvent::Settlement(SettlementEvent::StartMonitoring {
					order_id,
					fill_tx_hash,
				}))
				.ok();
			return Ok(());
		}

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
			.map_err(map_delivery_error)?;

		// Generate post-fill transaction
		let post_fill_tx = self
			.settlement
			.generate_post_fill_transaction(&order, &receipt)
			.await
			.map_err(map_settlement_service_error)?;

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
						classification,
					} => match classification {
						RevertClassification::StageComplete { reason } => {
							tracing::info!(
								order_id = %id,
								?tx_type,
								?reason,
								?tx_hash,
								"Revert classified as stage-complete; deferring to recovery for chain confirmation"
							);
						},
						RevertClassification::Terminal { .. } | RevertClassification::Unknown => {
							event_bus
								.publish(SolverEvent::Delivery(DeliveryEvent::TransactionFailed {
									order_id: id,
									tx_hash,
									tx_type,
									error,
								}))
								.ok();
						},
					},
					TransactionMonitoringEvent::Indeterminate {
						id: order_id_inner,
						tx_hash,
						tx_type,
						reason,
					} => {
						tracing::warn!(
							%order_id_inner,
							?tx_hash,
							?tx_type,
							%reason,
							"Live tx monitor indeterminate; order left in current status"
						);
					},
					TransactionMonitoringEvent::AttemptLedgerConflict {
						id,
						attempt_id,
						tx_type,
						tx_hash,
						attempted_status,
						error,
						context,
					} => {
						event_bus
							.publish(SolverEvent::Delivery(
								DeliveryEvent::TransactionAttemptLedgerConflict {
									order_id: id,
									attempt_id,
									tx_type,
									tx_hash,
									attempted_status,
									error,
									context: context.to_string(),
								},
							))
							.ok();
					},
				});

				let tracking = TransactionTracking {
					id: order_id.clone(),
					tx_type: TransactionType::PostFill,
					attempt_recorder: self.transaction_attempt_recorder(),
					callback,
					attempt_id: None,
					replacement_of: None,
				};

				let tx_hash = self
					.delivery
					.deliver(post_fill_tx.clone(), Some(tracking))
					.await
					.map_err(map_delivery_error)?;

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
			.map_err(map_settlement_service_error)?;

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
						classification,
					} => match classification {
						RevertClassification::StageComplete { reason } => {
							tracing::info!(
								order_id = %id,
								?tx_type,
								?reason,
								?tx_hash,
								"Revert classified as stage-complete; deferring to recovery for chain confirmation"
							);
						},
						RevertClassification::Terminal { .. } | RevertClassification::Unknown => {
							event_bus
								.publish(SolverEvent::Delivery(DeliveryEvent::TransactionFailed {
									order_id: id,
									tx_hash,
									tx_type,
									error,
								}))
								.ok();
						},
					},
					TransactionMonitoringEvent::Indeterminate {
						id: order_id_inner,
						tx_hash,
						tx_type,
						reason,
					} => {
						tracing::warn!(
							%order_id_inner,
							?tx_hash,
							?tx_type,
							%reason,
							"Live tx monitor indeterminate; order left in current status"
						);
					},
					TransactionMonitoringEvent::AttemptLedgerConflict {
						id,
						attempt_id,
						tx_type,
						tx_hash,
						attempted_status,
						error,
						context,
					} => {
						event_bus
							.publish(SolverEvent::Delivery(
								DeliveryEvent::TransactionAttemptLedgerConflict {
									order_id: id,
									attempt_id,
									tx_type,
									tx_hash,
									attempted_status,
									error,
									context: context.to_string(),
								},
							))
							.ok();
					},
				});

				let tracking = TransactionTracking {
					id: order_id.clone(),
					tx_type: TransactionType::PreClaim,
					attempt_recorder: self.transaction_attempt_recorder(),
					callback,
					attempt_id: None,
					replacement_of: None,
				};

				let tx_hash = self
					.delivery
					.deliver(pre_claim_tx.clone(), Some(tracking))
					.await
					.map_err(map_delivery_error)?;

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
	) -> Result<(), ClaimBatchError> {
		let order_ids = std::mem::take(batch);
		for order_id in order_ids {
			// Retrieve order
			let order: Order = self
				.storage
				.retrieve(StorageKey::Orders.as_str(), &order_id)
				.await
				.map_err(|e| {
					ClaimBatchError::new(&order_id, SettlementError::Storage(e.to_string()))
				})?;

			// Retrieve fill proof (already validated when ClaimReady was emitted)
			let fill_proof = order.fill_proof.clone().ok_or_else(|| {
				ClaimBatchError::new(
					&order_id,
					SettlementError::Service("Order missing fill proof".to_string()),
				)
			})?;

			// Generate claim transaction
			let claim_tx = self
				.order_service
				.generate_claim_transaction(&order, &fill_proof)
				.await
				.map_err(|e| {
					ClaimBatchError::new(&order_id, SettlementError::Service(e.to_string()))
				})?;

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
					classification,
				} => match classification {
					RevertClassification::StageComplete { reason } => {
						tracing::info!(
							order_id = %id,
							?tx_type,
							?reason,
							?tx_hash,
							"Revert classified as stage-complete; deferring to recovery for chain confirmation"
						);
					},
					RevertClassification::Terminal { .. } | RevertClassification::Unknown => {
						event_bus
							.publish(SolverEvent::Delivery(DeliveryEvent::TransactionFailed {
								order_id: id,
								tx_hash,
								tx_type,
								error,
							}))
							.ok();
					},
				},
				TransactionMonitoringEvent::Indeterminate {
					id: order_id_inner,
					tx_hash,
					tx_type,
					reason,
				} => {
					tracing::warn!(
						%order_id_inner,
						?tx_hash,
						?tx_type,
						%reason,
						"Live tx monitor indeterminate; order left in current status"
					);
				},
				TransactionMonitoringEvent::AttemptLedgerConflict {
					id,
					attempt_id,
					tx_type,
					tx_hash,
					attempted_status,
					error,
					context,
				} => {
					event_bus
						.publish(SolverEvent::Delivery(
							DeliveryEvent::TransactionAttemptLedgerConflict {
								order_id: id,
								attempt_id,
								tx_type,
								tx_hash,
								attempted_status,
								error,
								context: context.to_string(),
							},
						))
						.ok();
				},
			});

			let tracking = TransactionTracking {
				id: order.id.clone(),
				tx_type: TransactionType::Claim,
				attempt_recorder: self.transaction_attempt_recorder(),
				callback,
				attempt_id: None,
				replacement_of: None,
			};

			let claim_tx_hash = self
				.delivery
				.deliver(claim_tx.clone(), Some(tracking))
				.await
				.map_err(|e| ClaimBatchError::new(&order_id, map_delivery_error(e)))?;

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
				.map_err(|e| {
					ClaimBatchError::new(&order_id, SettlementError::State(e.to_string()))
				})?;

			// Store reverse mapping: tx_hash -> order_id
			self.storage
				.store(
					StorageKey::OrderByTxHash.as_str(),
					&hex::encode(&claim_tx_hash.0),
					&order.id,
					None,
				)
				.await
				.map_err(|e| {
					ClaimBatchError::new(&order_id, SettlementError::Storage(e.to_string()))
				})?;
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use mockall::predicate::*;
	use solver_delivery::{DeliveryError, DeliveryService, MockDeliveryInterface};
	use solver_order::{MockOrderInterface, OrderService};
	use solver_settlement::{MockSettlementInterface, SettlementService};
	use solver_storage::{MockStorageInterface, StorageError, StorageService};
	use solver_types::utils::tests::builders::{
		OrderBuilder, TransactionBuilder, TransactionReceiptBuilder,
	};
	use solver_types::{FillProof, Order, Transaction, TransactionHash, TransactionReceipt};
	use std::collections::HashMap;
	use std::sync::Arc;
	use tokio::sync::broadcast;

	fn create_test_order() -> Order {
		OrderBuilder::new().build()
	}

	fn create_test_receipt() -> TransactionReceipt {
		TransactionReceiptBuilder::new().build()
	}

	fn create_test_fill_proof() -> FillProof {
		FillProof {
			tx_hash: TransactionHash(vec![0x11; 32]),
			block_number: 100,
			attestation_data: Some(vec![0x42]),
			filled_timestamp: 1_700_000_000,
			oracle_address: "0x1234567890123456789012345678901234567890".to_string(),
		}
	}

	fn create_test_transaction() -> Transaction {
		TransactionBuilder::new()
			.chain_id(137)
			.gas_limit(21000)
			.gas_price_gwei(20)
			.build()
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
			"eip7683".to_string(),
			20,
		));
		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				137u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
			60,
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
			HashMap::new(), // networks — empty for handler unit tests
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
		let error = result.unwrap_err();
		assert_eq!(error.order_id, "nonexistent_order");
		assert!(matches!(error.error, SettlementError::Storage(_)));
	}

	#[tokio::test]
	async fn pre_claim_ready_preserves_insufficient_native_gas_as_transient() {
		let (handler, _) = create_test_handler_with_mocks(
			|mock_storage| {
				mock_storage
					.expect_get_bytes()
					.with(eq("orders:test_order_123"))
					.times(1)
					.returning(|_| {
						let order = OrderBuilder::new()
							.with_standard("eip7683")
							.with_fill_proof(Some(create_test_fill_proof()))
							.build();
						Box::pin(async move { Ok(serde_json::to_vec(&order).unwrap()) })
					});
			},
			|mock_settlement| {
				mock_settlement
					.expect_generate_pre_claim_transaction()
					.times(1)
					.returning(|_, _| Box::pin(async move { Ok(Some(create_test_transaction())) }));
			},
			|mock_delivery| {
				mock_delivery.expect_submit().times(1).returning(|_, _| {
					Box::pin(async move {
						Err(DeliveryError::InsufficientNativeGas(Box::new(
							solver_delivery::InsufficientNativeGasInfo {
								chain_id: 137,
								signer: "0x0000000000000000000000000000000000000001".to_string(),
								balance_wei: "0".to_string(),
								required_wei: "1".to_string(),
								shortfall_wei: "1".to_string(),
								gas_limit: Some(21_000),
								max_fee_per_gas: Some(1),
								gas_price: None,
								extra_native_fee_wei: "0".to_string(),
								value_wei: "0".to_string(),
							},
						)))
					})
				});
			},
			|_| {},
		)
		.await;

		let result = handler
			.handle_pre_claim_ready("test_order_123".to_string())
			.await;

		assert!(matches!(
			result.unwrap_err(),
			SettlementError::InsufficientNativeGas(_)
		));
	}

	#[tokio::test]
	async fn post_fill_ready_preserves_receipt_network_error_as_delivery_error() {
		let (handler, _) = create_test_handler_with_mocks(
			|mock_storage| {
				mock_storage
					.expect_get_bytes()
					.with(eq("orders:test_order_123"))
					.times(1)
					.returning(|_| {
						let order = OrderBuilder::new()
							.with_standard("eip7683")
							.with_fill_tx_hash(Some(TransactionHash(vec![0x11; 32])))
							.build();
						Box::pin(async move { Ok(serde_json::to_vec(&order).unwrap()) })
					});
			},
			|mock_settlement| {
				mock_settlement
					.expect_recover_post_fill_state()
					.times(1)
					.returning(|_| Box::pin(async move { Ok(false) }));
			},
			|mock_delivery| {
				mock_delivery
					.expect_get_receipt()
					.with(eq(TransactionHash(vec![0x11; 32])), eq(137u64))
					.times(1)
					.returning(|_, _| {
						Box::pin(async move { Err(DeliveryError::Network("rpc down".into())) })
					});
			},
			|_| {},
		)
		.await;

		let result = handler
			.handle_post_fill_ready("test_order_123".to_string())
			.await;

		assert!(matches!(
			result.unwrap_err(),
			SettlementError::Delivery(DeliveryError::Network(_))
		));
	}

	#[tokio::test]
	async fn pre_claim_ready_preserves_settlement_service_error() {
		let (handler, _) = create_test_handler_with_mocks(
			|mock_storage| {
				mock_storage
					.expect_get_bytes()
					.with(eq("orders:test_order_123"))
					.times(1)
					.returning(|_| {
						let order = OrderBuilder::new()
							.with_standard("eip7683")
							.with_fill_proof(Some(create_test_fill_proof()))
							.build();
						Box::pin(async move { Ok(serde_json::to_vec(&order).unwrap()) })
					});
			},
			|mock_settlement| {
				mock_settlement
					.expect_generate_pre_claim_transaction()
					.times(1)
					.returning(|_, _| {
						Box::pin(async move {
							Err(solver_settlement::SettlementError::ProverUnavailable(
								"prover down".to_string(),
							))
						})
					});
			},
			|_| {},
			|_| {},
		)
		.await;

		let result = handler
			.handle_pre_claim_ready("test_order_123".to_string())
			.await;

		assert!(matches!(
			result.unwrap_err(),
			SettlementError::SettlementService(
				solver_settlement::SettlementError::ProverUnavailable(_)
			)
		));
	}

	#[tokio::test]
	async fn test_handle_post_fill_ready_with_transaction() {
		let (handler, _) = create_test_handler_with_mocks(
			|mock_storage| {
				// Mock order retrieval - called twice: once by handler, once by state update
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
				// Mock exists check for update operation
				mock_storage
					.expect_exists()
					.with(eq("orders:test_order_123"))
					.returning(|_| Box::pin(async move { Ok(true) }));
				// Mock storage for transaction hash mapping
				mock_storage
					.expect_set_bytes()
					.times(1)
					.returning(|_, _, _, _| Box::pin(async move { Ok(()) }));
				mock_storage
					.expect_compare_and_swap_with_indexes()
					.times(1)
					.returning(|_, _, _, _, _| Box::pin(async move { Ok(true) }));
			},
			|mock_settlement| {
				mock_settlement
					.expect_recover_post_fill_state()
					.times(1)
					.returning(|_| Box::pin(async move { Ok(false) }));

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
				mock_settlement
					.expect_recover_post_fill_state()
					.times(1)
					.returning(|_| Box::pin(async move { Ok(false) }));

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
	async fn test_handle_post_fill_ready_recovered_submission_skips_resubmit() {
		let (handler, mut receiver) = create_test_handler_with_mocks(
			|mock_storage| {
				mock_storage
					.expect_get_bytes()
					.with(eq("orders:test_order_123"))
					.times(1)
					.returning(|_| {
						let order = OrderBuilder::new()
							.with_standard("eip7683")
							.with_fill_tx_hash(Some(TransactionHash(vec![0x11; 32])))
							.build();
						Box::pin(async move { Ok(serde_json::to_vec(&order).unwrap()) })
					});
			},
			|mock_settlement| {
				mock_settlement
					.expect_recover_post_fill_state()
					.times(1)
					.returning(|_| Box::pin(async move { Ok(true) }));
			},
			|_mock_delivery| {},
			|_mock_order| {},
		)
		.await;

		let result = handler
			.handle_post_fill_ready("test_order_123".to_string())
			.await;

		assert!(result.is_ok());
		match receiver.try_recv() {
			Ok(SolverEvent::Settlement(SettlementEvent::StartMonitoring {
				order_id,
				fill_tx_hash,
			})) => {
				assert_eq!(order_id, "test_order_123");
				assert_eq!(fill_tx_hash, TransactionHash(vec![0x11; 32]));
			},
			Ok(other) => panic!("Expected StartMonitoring event, got: {other:?}"),
			Err(e) => panic!("Expected StartMonitoring event but got error: {e:?}"),
		}
	}

	#[tokio::test]
	async fn test_handle_post_fill_ready_recovery_error_propagates() {
		let (handler, _) = create_test_handler_with_mocks(
			|mock_storage| {
				mock_storage
					.expect_get_bytes()
					.with(eq("orders:test_order_123"))
					.times(1)
					.returning(|_| {
						let order = OrderBuilder::new()
							.with_standard("eip7683")
							.with_fill_tx_hash(Some(TransactionHash(vec![0x11; 32])))
							.build();
						Box::pin(async move { Ok(serde_json::to_vec(&order).unwrap()) })
					});
			},
			|mock_settlement| {
				mock_settlement
					.expect_recover_post_fill_state()
					.times(1)
					.returning(|_| {
						Box::pin(async move {
							Err(solver_settlement::SettlementError::ValidationFailed(
								"tracker recovery failed".to_string(),
							))
						})
					});
			},
			|_mock_delivery| {},
			|_mock_order| {},
		)
		.await;

		let result = handler
			.handle_post_fill_ready("test_order_123".to_string())
			.await;

		assert!(result.is_err());
		assert!(matches!(
			result.unwrap_err(),
			SettlementError::SettlementService(_)
		));
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
