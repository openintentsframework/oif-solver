//! Order handler for processing order preparation and execution.
//!
//! Manages the generation and submission of prepare transactions (for off-chain orders)
//! and fill transactions, updating order state and publishing appropriate events.

use crate::engine::event_bus::EventBus;
use crate::state::OrderStateMachine;
use alloy_primitives::hex;
use solver_delivery::{DeliveryService, TransactionMonitoringEvent, TransactionTracking};
use solver_order::OrderService;
use solver_storage::StorageService;
use solver_types::{
	truncate_id, DeliveryEvent, ExecutionParams, Order, OrderEvent, OrderStatus, SolverEvent,
	StorageKey, TransactionType,
};
use std::sync::Arc;
use thiserror::Error;
use tracing::instrument;

/// Errors that can occur during order processing.
///
/// These errors represent failures in service operations,
/// storage operations, or state transitions during order handling.
#[derive(Debug, Error)]
pub enum OrderError {
	#[error("Service error: {0}")]
	Service(String),
	#[error("Storage error: {0}")]
	Storage(String),
	#[error("State error: {0}")]
	State(String),
}

/// Handler for processing order preparation and execution.
///
/// The OrderHandler manages the generation and submission of prepare
/// transactions for off-chain orders and fill transactions for all orders,
/// while updating order state and publishing relevant events.
pub struct OrderHandler {
	order_service: Arc<OrderService>,
	delivery: Arc<DeliveryService>,
	storage: Arc<StorageService>,
	state_machine: Arc<OrderStateMachine>,
	event_bus: EventBus,
}

impl OrderHandler {
	pub fn new(
		order_service: Arc<OrderService>,
		delivery: Arc<DeliveryService>,
		storage: Arc<StorageService>,
		state_machine: Arc<OrderStateMachine>,
		event_bus: EventBus,
	) -> Self {
		Self {
			order_service,
			delivery,
			storage,
			state_machine,
			event_bus,
		}
	}

	/// Handles order preparation for off-chain orders.
	#[instrument(skip_all, fields(order_id = %truncate_id(&order.id)))]
	pub async fn handle_preparation(
		&self,
		source: String,
		order: Order,
		params: ExecutionParams,
	) -> Result<(), OrderError> {
		// Generate prepare transaction
		if let Some(prepare_tx) = self
			.order_service
			.generate_prepare_transaction(&source, &order, &params)
			.await
			.map_err(|e| OrderError::Service(e.to_string()))?
		{
			// Submit prepare transaction with monitoring
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
				tx_type: TransactionType::Prepare,
				callback,
			};

			let prepare_tx_hash = self
				.delivery
				.deliver(prepare_tx.clone(), Some(tracking))
				.await
				.map_err(|e| OrderError::Service(e.to_string()))?;

			self.event_bus
				.publish(SolverEvent::Delivery(DeliveryEvent::TransactionPending {
					order_id: order.id.clone(),
					tx_hash: prepare_tx_hash.clone(),
					tx_type: TransactionType::Prepare,
					tx_chain_id: prepare_tx.chain_id,
				}))
				.ok();

			// Store tx_hash -> order_id mapping
			self.storage
				.store(
					StorageKey::OrderByTxHash.as_str(),
					&hex::encode(&prepare_tx_hash.0),
					&order.id,
					None,
				)
				.await
				.map_err(|e| OrderError::Storage(e.to_string()))?;

			// Update order with execution params and prepare tx hash
			self.state_machine
				.update_order_with(&order.id, |o| {
					o.execution_params = Some(params.clone());
					o.status = OrderStatus::Pending;
					o.prepare_tx_hash = Some(prepare_tx_hash);
				})
				.await
				.map_err(|e| OrderError::State(e.to_string()))?;
		} else {
			// No preparation needed (on-chain intent), go directly to Executing
			self.state_machine
				.update_order_with(&order.id, |o| {
					o.execution_params = Some(params.clone());
					o.status = OrderStatus::Executing;
				})
				.await
				.map_err(|e| OrderError::State(e.to_string()))?;

			self.event_bus
				.publish(SolverEvent::Order(OrderEvent::Executing {
					order: order.clone(),
					params,
				}))
				.ok();
		}

		Ok(())
	}

	/// Handles order execution by generating and submitting a fill transaction.
	#[instrument(skip_all, fields(order_id = %truncate_id(&order.id)))]
	pub async fn handle_execution(
		&self,
		order: Order,
		params: ExecutionParams,
	) -> Result<(), OrderError> {
		// Generate fill transaction
		let tx = self
			.order_service
			.generate_fill_transaction(&order, &params)
			.await
			.map_err(|e| OrderError::Service(e.to_string()))?;

		// Submit transaction with monitoring
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
			tx_type: TransactionType::Fill,
			callback,
		};

		let tx_hash = self
			.delivery
			.deliver(tx.clone(), Some(tracking))
			.await
			.map_err(|e| OrderError::Service(e.to_string()))?;

		self.event_bus
			.publish(SolverEvent::Delivery(DeliveryEvent::TransactionPending {
				order_id: order.id.clone(),
				tx_hash: tx_hash.clone(),
				tx_type: TransactionType::Fill,
				tx_chain_id: tx.chain_id,
			}))
			.ok();

		// Store fill transaction
		self.state_machine
			.set_transaction_hash(&order.id, tx_hash.clone(), TransactionType::Fill)
			.await
			.map_err(|e| OrderError::State(e.to_string()))?;

		// Store reverse mapping: tx_hash -> order_id
		self.storage
			.store(
				StorageKey::OrderByTxHash.as_str(),
				&hex::encode(&tx_hash.0),
				&order.id,
				None,
			)
			.await
			.map_err(|e| OrderError::Storage(e.to_string()))?;

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::engine::event_bus::EventBus;
	use crate::state::OrderStateMachine;
	use alloy_primitives::U256;
	use solver_delivery::{DeliveryService, MockDeliveryInterface};
	use solver_order::{MockOrderInterface, OrderService};
	use solver_storage::{MockStorageInterface, StorageService};
	use solver_types::utils::tests::builders::{OrderBuilder, TransactionBuilder};
	use solver_types::{
		ExecutionParams, Order, SolverEvent, Transaction, TransactionHash, TransactionType,
	};
	use std::collections::HashMap;
	use std::sync::Arc;
	use tokio::sync::broadcast;

	fn create_test_order() -> Order {
		OrderBuilder::new().build()
	}

	fn create_test_execution_params() -> ExecutionParams {
		ExecutionParams {
			gas_price: U256::from(20_000_000_000u64),         // 20 gwei
			priority_fee: Some(U256::from(1_000_000_000u64)), // 1 gwei
		}
	}

	fn create_test_transaction() -> Transaction {
		TransactionBuilder::new()
			.chain_id(137)
			.gas_limit(21000)
			.gas_price(20_000_000_000u128) // Add gas price (20 gwei)
			.build()
	}

	fn create_test_tx_hash() -> TransactionHash {
		TransactionHash(vec![0xab; 32])
	}

	async fn create_test_handler_with_mocks<F1, F2, F3>(
		setup_order: F1,
		setup_delivery: F2,
		setup_storage: F3,
	) -> (OrderHandler, broadcast::Receiver<SolverEvent>)
	where
		F1: FnOnce(&mut MockOrderInterface),
		F2: FnOnce(&mut MockDeliveryInterface),
		F3: FnOnce(&mut MockStorageInterface),
	{
		let mut mock_order = MockOrderInterface::new();
		let mut mock_delivery = MockDeliveryInterface::new();
		let mut mock_storage = MockStorageInterface::new();

		// Set up expectations using the provided closures
		setup_order(&mut mock_order);
		setup_delivery(&mut mock_delivery);
		setup_storage(&mut mock_storage);

		// Create services with configured mocks
		let order_service = Arc::new(OrderService::new(
			HashMap::from([(
				"eip7683".to_string(),
				Box::new(mock_order) as Box<dyn solver_order::OrderInterface>,
			)]),
			Box::new(solver_order::MockExecutionStrategy::new()),
		));

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				137u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
		));

		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let event_bus = EventBus::new(100);
		let event_rx = event_bus.subscribe();

		let handler = OrderHandler::new(order_service, delivery, storage, state_machine, event_bus);

		(handler, event_rx)
	}

	#[tokio::test]
	async fn test_handle_preparation_with_prepare_transaction_success() {
		let order = create_test_order();
		let params = create_test_execution_params();
		let prepare_tx = create_test_transaction();
		let prepare_tx_hash = create_test_tx_hash();

		// Clone variables for use in closures and assertions
		let prepare_tx_clone = prepare_tx.clone();
		let prepare_tx_hash_clone = prepare_tx_hash.clone();
		let order_clone = order.clone();

		let (handler, mut event_rx) = create_test_handler_with_mocks(
			|mock_order| {
				let prepare_tx_clone = prepare_tx_clone.clone();
				mock_order
					.expect_generate_prepare_transaction()
					.times(1)
					.returning(move |_, _, _| {
						let tx = prepare_tx_clone.clone();
						Box::pin(async move { Ok(Some(tx)) })
					});
			},
			|mock_delivery| {
				let hash_clone = prepare_tx_hash_clone.clone();
				mock_delivery.expect_submit().times(1).returning(move |_| {
					let hash = hash_clone.clone();
					Box::pin(async move { Ok(hash) })
				});
			},
			|mock_storage| {
				let order_clone = order_clone.clone();
				mock_storage
					.expect_set_bytes()
					.times(1)
					.returning(|_, _, _, _| Box::pin(async { Ok(()) }));

				// Mock for state machine storage operations
				mock_storage
					.expect_exists()
					.returning(|_| Box::pin(async { Ok(true) }));

				mock_storage.expect_get_bytes().returning(move |_| {
					let order = order_clone.clone();
					Box::pin(async move { Ok(serde_json::to_vec(&order).unwrap()) })
				});

				mock_storage
					.expect_set_bytes()
					.returning(|_, _, _, _| Box::pin(async { Ok(()) }));
			},
		)
		.await;

		let result = handler
			.handle_preparation("test_source".to_string(), order.clone(), params.clone())
			.await;

		assert!(result.is_ok());

		// Verify event was published
		let event = tokio::time::timeout(std::time::Duration::from_millis(100), event_rx.recv())
			.await
			.expect("Should receive event")
			.expect("Event should be valid");

		match event {
			SolverEvent::Delivery(DeliveryEvent::TransactionPending {
				order_id,
				tx_hash,
				tx_type,
				tx_chain_id,
			}) => {
				assert_eq!(order_id, order.id);
				assert_eq!(tx_hash, prepare_tx_hash);
				assert_eq!(tx_type, TransactionType::Prepare);
				assert_eq!(tx_chain_id, prepare_tx.chain_id);
			},
			_ => panic!("Expected TransactionPending event"),
		}
	}

	#[tokio::test]
	async fn test_handle_preparation_without_prepare_transaction() {
		let order = create_test_order();
		let params = create_test_execution_params();

		// Clone for closure
		let order_clone = order.clone();

		let (handler, mut event_rx) = create_test_handler_with_mocks(
			|mock_order| {
				mock_order
					.expect_generate_prepare_transaction()
					.times(1)
					.returning(|_, _, _| Box::pin(async { Ok(None) }));
			},
			|_mock_delivery| {
				// No delivery expectations since no prepare transaction
			},
			|mock_storage| {
				let order_clone = order_clone.clone();
				// Mock for state machine storage operations
				mock_storage
					.expect_exists()
					.returning(|_| Box::pin(async { Ok(true) }));

				mock_storage.expect_get_bytes().returning(move |_| {
					let order = order_clone.clone();
					Box::pin(async move { Ok(serde_json::to_vec(&order).unwrap()) })
				});

				mock_storage
					.expect_set_bytes()
					.returning(|_, _, _, _| Box::pin(async { Ok(()) }));
			},
		)
		.await;

		let result = handler
			.handle_preparation("test_source".to_string(), order.clone(), params.clone())
			.await;

		assert!(result.is_ok());

		// Verify OrderEvent::Executing was published
		let event = tokio::time::timeout(std::time::Duration::from_millis(100), event_rx.recv())
			.await
			.expect("Should receive event")
			.expect("Event should be valid");

		match event {
			SolverEvent::Order(OrderEvent::Executing {
				order: event_order,
				params: _,
			}) => {
				assert_eq!(event_order.id, order.id);
			},
			_ => panic!("Expected OrderEvent::Executing event"),
		}
	}

	#[tokio::test]
	async fn test_handle_preparation_order_service_error() {
		let order = create_test_order();
		let params = create_test_execution_params();

		let (handler, _event_rx) = create_test_handler_with_mocks(
			|mock_order| {
				mock_order
					.expect_generate_prepare_transaction()
					.times(1)
					.returning(|_, _, _| {
						Box::pin(async {
							Err(solver_order::OrderError::ValidationFailed(
								"Test error".to_string(),
							))
						})
					});
			},
			|_mock_delivery| {},
			|_mock_storage| {},
		)
		.await;

		let result = handler
			.handle_preparation("test_source".to_string(), order, params)
			.await;

		assert!(result.is_err());
		match result.unwrap_err() {
			OrderError::Service(msg) => assert!(msg.contains("Test error")),
			_ => panic!("Expected Service error"),
		}
	}

	#[tokio::test]
	async fn test_handle_preparation_delivery_error() {
		let order = create_test_order();
		let params = create_test_execution_params();
		let prepare_tx = create_test_transaction();

		let (handler, _event_rx) = create_test_handler_with_mocks(
			|mock_order| {
				mock_order
					.expect_generate_prepare_transaction()
					.times(1)
					.returning(move |_, _, _| {
						let tx = prepare_tx.clone();
						Box::pin(async move { Ok(Some(tx)) })
					});
			},
			|mock_delivery| {
				mock_delivery.expect_submit().times(1).returning(|_| {
					Box::pin(async {
						Err(solver_delivery::DeliveryError::Network(
							"Delivery failed".to_string(),
						))
					})
				});
			},
			|_mock_storage| {},
		)
		.await;

		let result = handler
			.handle_preparation("test_source".to_string(), order, params)
			.await;

		assert!(result.is_err());
		match result.unwrap_err() {
			OrderError::Service(msg) => assert!(msg.contains("Delivery failed")),
			_ => panic!("Expected Service error"),
		}
	}

	#[tokio::test]
	async fn test_handle_preparation_storage_error() {
		let order = create_test_order();
		let params = create_test_execution_params();
		let prepare_tx = create_test_transaction();
		let prepare_tx_hash = create_test_tx_hash();

		let (handler, _event_rx) = create_test_handler_with_mocks(
			|mock_order| {
				mock_order
					.expect_generate_prepare_transaction()
					.times(1)
					.returning(move |_, _, _| {
						let tx = prepare_tx.clone();
						Box::pin(async move { Ok(Some(tx)) })
					});
			},
			|mock_delivery| {
				mock_delivery.expect_submit().times(1).returning(move |_| {
					let hash = prepare_tx_hash.clone();
					Box::pin(async move { Ok(hash) })
				});
			},
			|mock_storage| {
				mock_storage
					.expect_set_bytes()
					.times(1)
					.returning(|_, _, _, _| {
						Box::pin(async {
							Err(solver_storage::StorageError::Backend(
								"Storage failed".to_string(),
							))
						})
					});
			},
		)
		.await;

		let result = handler
			.handle_preparation("test_source".to_string(), order, params)
			.await;

		assert!(result.is_err());
		match result.unwrap_err() {
			OrderError::Storage(msg) => assert!(msg.contains("Storage failed")),
			_ => panic!("Expected Storage error"),
		}
	}

	#[tokio::test]
	async fn test_handle_execution_success() {
		let order = create_test_order();
		let params = create_test_execution_params();
		let fill_tx = create_test_transaction();
		let fill_tx_hash = create_test_tx_hash();

		// Clone for closure
		let order_clone = order.clone();
		let fill_tx_clone = fill_tx.clone();
		let fill_tx_hash_clone = fill_tx_hash.clone();

		let (handler, mut event_rx) = create_test_handler_with_mocks(
			|mock_order| {
				let fill_tx_clone = fill_tx_clone.clone();
				mock_order
					.expect_generate_fill_transaction()
					.times(1)
					.returning(move |_, _| {
						let tx = fill_tx_clone.clone();
						Box::pin(async move { Ok(tx) })
					});
			},
			|mock_delivery| {
				let fill_tx_hash_clone = fill_tx_hash_clone.clone();
				mock_delivery.expect_submit().times(1).returning(move |_| {
					let hash = fill_tx_hash_clone.clone();
					Box::pin(async move { Ok(hash) })
				});
			},
			|mock_storage| {
				let order_clone = order_clone.clone();
				// Mock for state machine storage operations
				mock_storage
					.expect_exists()
					.returning(|_| Box::pin(async { Ok(true) }));

				mock_storage.expect_get_bytes().returning(move |_| {
					let order = order_clone.clone();
					Box::pin(async move { Ok(serde_json::to_vec(&order).unwrap()) })
				});

				mock_storage
					.expect_set_bytes()
					.returning(|_, _, _, _| Box::pin(async { Ok(()) }));
			},
		)
		.await;

		let result = handler.handle_execution(order.clone(), params).await;

		assert!(result.is_ok());

		// Verify event was published
		let event = tokio::time::timeout(std::time::Duration::from_millis(100), event_rx.recv())
			.await
			.expect("Should receive event")
			.expect("Event should be valid");

		match event {
			SolverEvent::Delivery(DeliveryEvent::TransactionPending {
				order_id,
				tx_hash,
				tx_type,
				tx_chain_id,
			}) => {
				assert_eq!(order_id, order.id);
				assert_eq!(tx_hash, fill_tx_hash);
				assert_eq!(tx_type, TransactionType::Fill);
				assert_eq!(tx_chain_id, fill_tx.chain_id);
			},
			_ => panic!("Expected TransactionPending event"),
		}
	}

	#[tokio::test]
	async fn test_handle_execution_order_service_error() {
		let order = create_test_order();
		let params = create_test_execution_params();

		let (handler, _event_rx) = create_test_handler_with_mocks(
			|mock_order| {
				mock_order
					.expect_generate_fill_transaction()
					.times(1)
					.returning(|_, _| {
						Box::pin(async {
							Err(solver_order::OrderError::ValidationFailed(
								"Fill error".to_string(),
							))
						})
					});
			},
			|_mock_delivery| {},
			|_mock_storage| {},
		)
		.await;

		let result = handler.handle_execution(order, params).await;

		assert!(result.is_err());
		match result.unwrap_err() {
			OrderError::Service(msg) => assert!(msg.contains("Fill error")),
			_ => panic!("Expected Service error"),
		}
	}

	#[tokio::test]
	async fn test_handle_execution_delivery_error() {
		let order = create_test_order();
		let params = create_test_execution_params();
		let fill_tx = create_test_transaction();

		let (handler, _event_rx) = create_test_handler_with_mocks(
			|mock_order| {
				mock_order
					.expect_generate_fill_transaction()
					.times(1)
					.returning(move |_, _| {
						let tx = fill_tx.clone();
						Box::pin(async move { Ok(tx) })
					});
			},
			|mock_delivery| {
				mock_delivery.expect_submit().times(1).returning(|_| {
					Box::pin(async {
						Err(solver_delivery::DeliveryError::Network(
							"Execution delivery failed".to_string(),
						))
					})
				});
			},
			|_mock_storage| {},
		)
		.await;

		let result = handler.handle_execution(order, params).await;

		assert!(result.is_err());
		match result.unwrap_err() {
			OrderError::Service(msg) => assert!(msg.contains("Execution delivery failed")),
			_ => panic!("Expected Service error"),
		}
	}

	#[tokio::test]
	async fn test_handle_execution_state_machine_error() {
		let order = create_test_order();
		let params = create_test_execution_params();
		let fill_tx = create_test_transaction();
		let fill_tx_hash = create_test_tx_hash();

		let (handler, _event_rx) = create_test_handler_with_mocks(
			|mock_order| {
				mock_order
					.expect_generate_fill_transaction()
					.times(1)
					.returning(move |_, _| {
						let tx = fill_tx.clone();
						Box::pin(async move { Ok(tx) })
					});
			},
			|mock_delivery| {
				let fill_tx_hash_clone = fill_tx_hash.clone();
				mock_delivery.expect_submit().times(1).returning(move |_| {
					let hash = fill_tx_hash_clone.clone();
					Box::pin(async move { Ok(hash) })
				});
			},
			|mock_storage| {
				// Mock for state machine storage operations - simulate error
				mock_storage.expect_get_bytes().returning(|_| {
					Box::pin(async {
						Err(solver_storage::StorageError::Backend(
							"State machine error".to_string(),
						))
					})
				});
			},
		)
		.await;

		let result = handler.handle_execution(order, params).await;

		assert!(result.is_err());
		match result.unwrap_err() {
			OrderError::State(msg) => assert!(msg.contains("State machine error")),
			_ => panic!("Expected State error"),
		}
	}
}
