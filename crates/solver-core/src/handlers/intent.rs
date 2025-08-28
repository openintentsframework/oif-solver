//! Intent handler for processing discovered intents.
//!
//! Responsible for validating intents, creating orders, storing them,
//! and determining execution strategy through the order service.

use crate::engine::{context::ContextBuilder, event_bus::EventBus, token_manager::TokenManager};
use crate::state::OrderStateMachine;
use solver_config::Config;
use solver_delivery::DeliveryService;
use solver_order::OrderService;
use solver_storage::StorageService;
use solver_types::{
	truncate_id, Address, DiscoveryEvent, ExecutionDecision, Intent, OrderEvent, SolverEvent,
	StorageKey,
};
use std::sync::Arc;
use thiserror::Error;
use tracing::instrument;

/// Errors that can occur during intent processing.
///
/// These errors represent failures in validating intents,
/// storing them, or communicating with required services.
#[derive(Debug, Error)]
pub enum IntentError {
	#[error("Validation error: {0}")]
	Validation(String),
	#[error("Storage error: {0}")]
	Storage(String),
	#[error("Service error: {0}")]
	Service(String),
}

/// Handler for processing discovered intents into executable orders.
///
/// The IntentHandler validates incoming intents, creates orders from them,
/// stores them in the persistence layer, and determines execution strategy
/// through the order service.
pub struct IntentHandler {
	order_service: Arc<OrderService>,
	storage: Arc<StorageService>,
	state_machine: Arc<OrderStateMachine>,
	event_bus: EventBus,
	delivery: Arc<DeliveryService>,
	solver_address: Address,
	token_manager: Arc<TokenManager>,
	config: Config,
}

impl IntentHandler {
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		order_service: Arc<OrderService>,
		storage: Arc<StorageService>,
		state_machine: Arc<OrderStateMachine>,
		event_bus: EventBus,
		delivery: Arc<DeliveryService>,
		solver_address: Address,
		token_manager: Arc<TokenManager>,
		config: Config,
	) -> Self {
		Self {
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			solver_address,
			token_manager,
			config,
		}
	}

	/// Handles a newly discovered intent.
	#[instrument(skip_all, fields(order_id = %truncate_id(&intent.id)))]
	pub async fn handle(&self, intent: Intent) -> Result<(), IntentError> {
		// Prevent duplicate order processing when multiple discovery modules for the same standard are active.
		//
		// When an off-chain 7683 order is submitted via the API, it triggers an `openFor` transaction
		// which emits an `Open` event identical to regular on-chain orders. This causes both
		// the off-chain module (which initiated it) and the on-chain module (monitoring events)
		// to attempt processing the same order.
		//
		// By checking if the intent already exists in storage, we ensure each order is only
		// processed once, regardless of which discovery module receives it first.
		let exists = self
			.storage
			.exists(StorageKey::Intents.as_str(), &intent.id)
			.await
			.map_err(|e| {
				IntentError::Storage(format!("Failed to check intent existence: {}", e))
			})?;
		if exists {
			tracing::debug!(
				"Intent ({}) already exists, skipping duplicate processing",
				truncate_id(&intent.id)
			);
			return Ok(());
		}

		tracing::info!("Discovered intent");

		// Validate intent
		match self
			.order_service
			.validate_intent(&intent, &self.solver_address)
			.await
		{
			Ok(order) => {
				self.event_bus
					.publish(SolverEvent::Discovery(DiscoveryEvent::IntentValidated {
						intent_id: intent.id.clone(),
						order: order.clone(),
					}))
					.ok();

				// Store intent for deduplication
				self.storage
					.store(StorageKey::Intents.as_str(), &order.id, &intent, None)
					.await
					.map_err(|e| IntentError::Storage(e.to_string()))?;

				// Store order
				self.state_machine
					.store_order(&order)
					.await
					.map_err(|e| IntentError::Storage(e.to_string()))?;

				// Check execution strategy
				let builder = ContextBuilder::new(
					self.delivery.clone(),
					self.solver_address.clone(),
					self.token_manager.clone(),
					self.config.clone(),
				);
				let context = builder
					.build_execution_context(&intent)
					.await
					.map_err(|e| IntentError::Service(e.to_string()))?;
				match self.order_service.should_execute(&order, &context).await {
					ExecutionDecision::Execute(params) => {
						self.event_bus
							.publish(SolverEvent::Order(OrderEvent::Preparing {
								intent: intent.clone(),
								order,
								params,
							}))
							.ok();
					},
					ExecutionDecision::Skip(reason) => {
						self.event_bus
							.publish(SolverEvent::Order(OrderEvent::Skipped {
								order_id: order.id,
								reason,
							}))
							.ok();
					},
					ExecutionDecision::Defer(duration) => {
						self.event_bus
							.publish(SolverEvent::Order(OrderEvent::Deferred {
								order_id: order.id,
								retry_after: duration,
							}))
							.ok();
					},
				}
			},
			Err(e) => {
				tracing::warn!(
					reason = %e,
					"Intent rejected during validation"
				);
				self.event_bus
					.publish(SolverEvent::Discovery(DiscoveryEvent::IntentRejected {
						intent_id: intent.id,
						reason: e.to_string(),
					}))
					.ok();
			},
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::engine::token_manager::TokenManager;
	use alloy_primitives::U256;
	use mockall::predicate::*;
	use solver_account::MockAccountInterface;
	use solver_config::ConfigBuilder;
	use solver_delivery::DeliveryService;
	use solver_order::{MockExecutionStrategy, MockOrderInterface};
	use solver_storage::{MockStorageInterface, StorageError};
	use solver_types::{Address, ExecutionParams, Intent, Order, OrderStatus, SolverEvent};
	use std::collections::HashMap;
	use std::sync::Arc;
	use std::time::Duration;

	fn create_test_intent() -> Intent {
		Intent {
			id: "test_intent_123".to_string(),
			standard: "eip7683".to_string(),
			data: serde_json::json!({
				"origin_chain_id": 1,
				"outputs": [
					{
						"chain_id": 137,
						"token": "0x0000000000000000000000000000000000000000",
						"amount": "950000000000000000"
					}
				]
			}),
			source: "test".to_string(),
			metadata: solver_types::IntentMetadata {
				requires_auction: false,
				exclusive_until: None,
				discovered_at: 1234567890,
			},
			quote_id: None,
		}
	}

	fn create_test_order() -> Order {
		Order {
			id: "test_order_123".to_string(),
			standard: "7683".to_string(),
			status: OrderStatus::Created,
			solver_address: Address(vec![0x12; 20]),
			created_at: 1234567890,
			updated_at: 1234567890,
			post_fill_tx_hash: None,
			pre_claim_tx_hash: None,
			prepare_tx_hash: None,
			fill_tx_hash: None,
			claim_tx_hash: None,
			execution_params: None,
			fill_proof: None,
			data: serde_json::json!({"test": "order_data"}),
			quote_id: None,
			input_chain_ids: vec![1],
			output_chain_ids: vec![137],
		}
	}

	fn create_test_address() -> Address {
		Address(vec![0xab; 20])
	}

	fn create_test_config() -> Config {
		ConfigBuilder::new().build()
	}

	#[tokio::test]
	async fn test_handle_intent_success_execute() {
		let mut mock_storage = MockStorageInterface::new();
		let mut mock_order_interface = MockOrderInterface::new();
		let mut mock_strategy = MockExecutionStrategy::new();

		let intent = create_test_intent();
		let solver_address = create_test_address();

		// Setup expectations
		mock_storage
			.expect_exists()
			.with(eq("intents:test_intent_123"))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(false) }));

		mock_storage
			.expect_set_bytes()
			.times(2) // Once for intent, once for order
			.returning(|_, _, _, _| Box::pin(async move { Ok(()) }));

		mock_order_interface
			.expect_validate_intent()
			.with(eq(intent.clone()), eq(solver_address.clone()))
			.times(1)
			.returning(move |_, _| Box::pin(async move { Ok(create_test_order()) }));

		mock_strategy
			.expect_should_execute()
			.times(1)
			.returning(|_, _| {
				Box::pin(async move {
					ExecutionDecision::Execute(ExecutionParams {
						gas_price: U256::from(20000000000u64),
						priority_fee: Some(U256::from(1000u64)),
					})
				})
			});

		// Create services
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let order_service = Arc::new(OrderService::new(
			HashMap::from([(
				"eip7683".to_string(),
				Box::new(mock_order_interface) as Box<dyn solver_order::OrderInterface>,
			)]),
			Box::new(mock_strategy),
		));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let event_bus = EventBus::new(100);

		// Create mock delivery service and token manager
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1));
		let token_manager = Arc::new(TokenManager::new(
			Default::default(), // empty networks config
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let config = create_test_config();

		let handler = IntentHandler::new(
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			solver_address.clone(),
			token_manager,
			config,
		);

		let result = handler.handle(intent).await;
		assert!(result.is_ok());
	}

	#[tokio::test]
	async fn test_handle_intent_duplicate_skipped() {
		let mut mock_storage = MockStorageInterface::new();

		let intent = create_test_intent();
		let solver_address = create_test_address();

		// Setup expectations - intent already exists
		mock_storage
			.expect_exists()
			.with(eq("intents:test_intent_123"))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(true) }));

		// Should not call any other methods since we skip duplicate
		mock_storage.expect_set_bytes().times(0);

		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let order_service = Arc::new(OrderService::new(
			HashMap::new(),
			Box::new(MockExecutionStrategy::new()),
		));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let event_bus = EventBus::new(100);
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1));
		let token_manager = Arc::new(TokenManager::new(
			Default::default(),
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let config = create_test_config();

		let handler = IntentHandler::new(
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			solver_address,
			token_manager,
			config,
		);

		let result = handler.handle(intent).await;
		assert!(result.is_ok());
	}

	#[tokio::test]
	async fn test_handle_intent_validation_failure() {
		let mut mock_storage = MockStorageInterface::new();
		let mut mock_order_interface = MockOrderInterface::new();

		let intent = create_test_intent();
		let solver_address = create_test_address();

		// Setup expectations
		mock_storage
			.expect_exists()
			.with(eq("intents:test_intent_123"))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(false) }));

		mock_order_interface
			.expect_validate_intent()
			.with(eq(intent.clone()), eq(solver_address.clone()))
			.times(1)
			.returning(|_, _| {
				Box::pin(async move {
					Err(solver_order::OrderError::ValidationFailed(
						"Invalid intent".to_string(),
					))
				})
			});

		// Should not store anything since validation failed
		mock_storage.expect_set_bytes().times(0);

		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let order_service = Arc::new(OrderService::new(
			HashMap::from([(
				"eip7683".to_string(),
				Box::new(mock_order_interface) as Box<dyn solver_order::OrderInterface>,
			)]),
			Box::new(MockExecutionStrategy::new()),
		));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let event_bus = EventBus::new(100);
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1));
		let token_manager = Arc::new(TokenManager::new(
			Default::default(),
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let config = create_test_config();

		let handler = IntentHandler::new(
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			solver_address,
			token_manager,
			config,
		);

		let result = handler.handle(intent).await;
		assert!(result.is_ok()); // Handler doesn't fail on validation errors
	}

	#[tokio::test]
	async fn test_handle_intent_skip_execution() {
		let mut mock_storage = MockStorageInterface::new();
		let mut mock_order_interface = MockOrderInterface::new();
		let mut mock_strategy = MockExecutionStrategy::new();

		let intent = create_test_intent();
		let solver_address = create_test_address();

		// Setup expectations
		mock_storage
			.expect_exists()
			.with(eq("intents:test_intent_123"))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(false) }));

		mock_storage
			.expect_set_bytes()
			.times(2) // Once for intent, once for order
			.returning(|_, _, _, _| Box::pin(async move { Ok(()) }));

		mock_order_interface
			.expect_validate_intent()
			.with(eq(intent.clone()), eq(solver_address.clone()))
			.times(1)
			.returning(move |_, _| Box::pin(async move { Ok(create_test_order()) }));

		mock_strategy
			.expect_should_execute()
			.times(1)
			.returning(|_, _| {
				Box::pin(async move { ExecutionDecision::Skip("Insufficient balance".to_string()) })
			});

		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let order_service = Arc::new(OrderService::new(
			HashMap::from([(
				"eip7683".to_string(),
				Box::new(mock_order_interface) as Box<dyn solver_order::OrderInterface>,
			)]),
			Box::new(mock_strategy),
		));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let event_bus = EventBus::new(100);
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1));
		let token_manager = Arc::new(TokenManager::new(
			Default::default(),
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let config = create_test_config();

		let handler = IntentHandler::new(
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			solver_address,
			token_manager,
			config,
		);

		let result = handler.handle(intent).await;
		assert!(result.is_ok());
	}

	#[tokio::test]
	async fn test_handle_intent_defer_execution() {
		let mut mock_storage = MockStorageInterface::new();
		let mut mock_order_interface = MockOrderInterface::new();
		let mut mock_strategy = MockExecutionStrategy::new();

		let intent = create_test_intent();
		let solver_address = create_test_address();

		// Setup expectations
		mock_storage
			.expect_exists()
			.with(eq("intents:test_intent_123"))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(false) }));

		mock_storage
			.expect_set_bytes()
			.times(2)
			.returning(|_, _, _, _| Box::pin(async move { Ok(()) }));

		mock_order_interface
			.expect_validate_intent()
			.times(1)
			.returning(move |_, _| Box::pin(async move { Ok(create_test_order()) }));

		mock_strategy
			.expect_should_execute()
			.times(1)
			.returning(|_, _| {
				Box::pin(async move { ExecutionDecision::Defer(Duration::from_secs(60)) })
			});

		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let order_service = Arc::new(OrderService::new(
			HashMap::from([(
				"eip7683".to_string(),
				Box::new(mock_order_interface) as Box<dyn solver_order::OrderInterface>,
			)]),
			Box::new(mock_strategy),
		));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let event_bus = EventBus::new(100);
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1));
		let token_manager = Arc::new(TokenManager::new(
			Default::default(),
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let config = create_test_config();

		let handler = IntentHandler::new(
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			solver_address,
			token_manager,
			config,
		);

		let result = handler.handle(intent).await;
		assert!(result.is_ok());
	}

	#[tokio::test]
	async fn test_handle_intent_storage_error() {
		let mut mock_storage = MockStorageInterface::new();

		let intent = create_test_intent();
		let solver_address = create_test_address();

		// Setup expectations - storage fails
		mock_storage
			.expect_exists()
			.with(eq("intents:test_intent_123"))
			.times(1)
			.returning(|_| {
				Box::pin(async move { Err(StorageError::Backend("Database down".to_string())) })
			});

		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let order_service = Arc::new(OrderService::new(
			HashMap::new(),
			Box::new(MockExecutionStrategy::new()),
		));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let event_bus = EventBus::new(100);
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1));
		let token_manager = Arc::new(TokenManager::new(
			Default::default(),
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let config = create_test_config();

		let handler = IntentHandler::new(
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			solver_address,
			token_manager,
			config,
		);

		let result = handler.handle(intent).await;
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), IntentError::Storage(_)));
	}

	#[tokio::test]
	async fn test_event_publishing() {
		let mut mock_storage = MockStorageInterface::new();
		let mut mock_order_interface = MockOrderInterface::new();
		let mut mock_strategy = MockExecutionStrategy::new();

		let intent = create_test_intent();
		let solver_address = create_test_address();

		// Setup expectations
		mock_storage
			.expect_exists()
			.returning(|_| Box::pin(async move { Ok(false) }));
		mock_storage
			.expect_set_bytes()
			.returning(|_, _, _, _| Box::pin(async move { Ok(()) }));
		mock_order_interface
			.expect_validate_intent()
			.returning(move |_, _| Box::pin(async move { Ok(create_test_order()) }));
		mock_strategy.expect_should_execute().returning(|_, _| {
			Box::pin(async move {
				ExecutionDecision::Execute(ExecutionParams {
					gas_price: U256::from(20000000000u64),
					priority_fee: Some(U256::from(1000u64)),
				})
			})
		});

		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let order_service = Arc::new(OrderService::new(
			HashMap::from([(
				"eip7683".to_string(),
				Box::new(mock_order_interface) as Box<dyn solver_order::OrderInterface>,
			)]),
			Box::new(mock_strategy),
		));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let event_bus = EventBus::new(100);
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1));
		let token_manager = Arc::new(TokenManager::new(
			Default::default(),
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let config = create_test_config();

		// Subscribe to events before creating handler
		let mut receiver = event_bus.subscribe();

		let handler = IntentHandler::new(
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			solver_address,
			token_manager,
			config,
		);

		// Handle intent and check events
		let result = handler.handle(intent.clone()).await;
		assert!(result.is_ok());

		// Should receive IntentValidated and Preparing events
		let event1 = receiver.recv().await.unwrap();
		match event1 {
			SolverEvent::Discovery(solver_types::DiscoveryEvent::IntentValidated {
				intent_id,
				..
			}) => {
				assert_eq!(intent_id, intent.id);
			},
			_ => panic!("Expected IntentValidated event"),
		}

		let event2 = receiver.recv().await.unwrap();
		match event2 {
			SolverEvent::Order(solver_types::OrderEvent::Preparing { .. }) => {
				// Success
			},
			_ => panic!("Expected Preparing event"),
		}
	}
}
