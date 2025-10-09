//! Core solver engine that orchestrates the order execution lifecycle.
//!
//! This module contains the main SolverEngine struct which coordinates between
//! all services (discovery, order processing, delivery, settlement) and manages
//! the main event loop for processing intents and orders.

pub mod context;
pub mod cost_profit;
pub mod event_bus;
pub mod lifecycle;
pub mod token_manager;

use self::{cost_profit::CostProfitService, token_manager::TokenManager};
use crate::handlers::{IntentHandler, OrderHandler, SettlementHandler, TransactionHandler};
use crate::recovery::RecoveryService;
use crate::state::OrderStateMachine;
use alloy_primitives::hex;
use solver_account::AccountService;
use solver_config::Config;
use solver_delivery::DeliveryService;
use solver_discovery::DiscoveryService;
use solver_order::OrderService;
use solver_pricing::PricingService;
use solver_settlement::SettlementService;
use solver_storage::StorageService;
use solver_types::{
	truncate_id, Address, DeliveryEvent, Intent, Order, OrderEvent, SettlementEvent, SolverEvent,
	StorageKey,
};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{mpsc, Semaphore};
use tracing::instrument;

/// Errors that can occur during engine operations.
///
/// These errors represent various failure modes that can occur while
/// the solver engine is running, including configuration issues,
/// service failures, and handler errors.
#[derive(Debug, Error)]
pub enum EngineError {
	#[error("Configuration error: {0}")]
	Config(String),
	#[error("Service error: {0}")]
	Service(String),
	#[error("Handler error: {0}")]
	Handler(String),
}

/// Main solver engine that orchestrates the order execution lifecycle.
#[derive(Clone)]
pub struct SolverEngine {
	/// Solver configuration.
	pub(crate) config: Config,
	/// Storage service for persisting state.
	pub(crate) storage: Arc<StorageService>,
	/// Account service for address and signing operations.
	#[allow(dead_code)]
	pub(crate) account: Arc<AccountService>,
	/// Delivery service for blockchain transactions.
	#[allow(dead_code)]
	pub(crate) delivery: Arc<DeliveryService>,
	/// Discovery service for finding new orders.
	pub(crate) discovery: Arc<DiscoveryService>,
	/// Order service for validation and execution.
	#[allow(dead_code)]
	pub(crate) order: Arc<OrderService>,
	/// Settlement service for monitoring and claiming.
	#[allow(dead_code)]
	pub(crate) settlement: Arc<SettlementService>,
	/// Pricing service for asset price conversion.
	#[allow(dead_code)]
	pub(crate) pricing: Arc<PricingService>,
	/// Token manager for token approvals and validation.
	#[allow(dead_code)]
	pub(crate) token_manager: Arc<TokenManager>,
	/// Event bus for inter-service communication.
	pub(crate) event_bus: event_bus::EventBus,
	/// Order state machine
	#[allow(dead_code)]
	pub(crate) state_machine: Arc<OrderStateMachine>,
	/// Intent handler
	pub(crate) intent_handler: Arc<IntentHandler>,
	/// Order handler
	pub(crate) order_handler: Arc<OrderHandler>,
	/// Transaction handler
	pub(crate) transaction_handler: Arc<TransactionHandler>,
	/// Settlement handler
	pub(crate) settlement_handler: Arc<SettlementHandler>,
}

/// Number of orders to batch together for claim operations.
///
/// This constant defines how many orders are batched together when
/// submitting claim transactions to reduce gas costs.
static CLAIM_BATCH: usize = 1;

impl SolverEngine {
	/// Creates a new solver engine with the given services.
	///
	/// This constructor initializes all internal components including handlers
	/// and the state machine, establishing the complete event-driven architecture
	/// for order processing.
	///
	/// # Arguments
	///
	/// * `config` - Solver configuration settings
	/// * `storage` - Storage service for persisting state
	/// * `account` - Account service for address and signing operations
	/// * `solver_address` - The solver's Ethereum address
	/// * `delivery` - Service for submitting blockchain transactions
	/// * `discovery` - Service for discovering new intents
	/// * `order` - Service for order validation and execution
	/// * `settlement` - Service for monitoring and claiming settlements
	/// * `pricing` - Service for asset price conversion
	/// * `event_bus` - Event bus for inter-service communication
	/// * `token_manager` - Manager for token approvals and validation
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		config: Config,
		storage: Arc<StorageService>,
		account: Arc<AccountService>,
		solver_address: Address,
		delivery: Arc<DeliveryService>,
		discovery: Arc<DiscoveryService>,
		order: Arc<OrderService>,
		settlement: Arc<SettlementService>,
		pricing: Arc<PricingService>,
		event_bus: event_bus::EventBus,
		token_manager: Arc<TokenManager>,
	) -> Self {
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));

		// Create CostProfitService for cost estimation and profitability validation
		let cost_profit_service = Arc::new(CostProfitService::new(
			pricing.clone(),
			delivery.clone(),
			token_manager.clone(),
			storage.clone(),
		));

		let intent_handler = Arc::new(IntentHandler::new(
			order.clone(),
			storage.clone(),
			state_machine.clone(),
			event_bus.clone(),
			delivery.clone(),
			solver_address,
			token_manager.clone(),
			cost_profit_service,
			config.clone(),
		));

		let order_handler = Arc::new(OrderHandler::new(
			order.clone(),
			delivery.clone(),
			storage.clone(),
			state_machine.clone(),
			event_bus.clone(),
		));

		let transaction_handler = Arc::new(TransactionHandler::new(
			storage.clone(),
			state_machine.clone(),
			settlement.clone(),
			event_bus.clone(),
		));

		let settlement_handler = Arc::new(SettlementHandler::new(
			settlement.clone(),
			order.clone(),
			delivery.clone(),
			storage.clone(),
			state_machine.clone(),
			event_bus.clone(),
			config.solver.monitoring_timeout_seconds / 60, // Convert seconds to minutes
		));

		Self {
			config,
			storage,
			account,
			delivery,
			discovery,
			order,
			settlement,
			pricing,
			token_manager,
			event_bus,
			state_machine,
			intent_handler,
			order_handler,
			transaction_handler,
			settlement_handler,
		}
	}

	/// Initializes the engine with state recovery from storage.
	///
	/// This method performs a complete state recovery by:
	/// 1. Loading active orders from persistent storage
	/// 2. Reconciling order states with blockchain state
	/// 3. Recovering orphaned intents that weren't processed
	/// 4. Publishing appropriate events to resume processing
	///
	/// # Returns
	///
	/// A vector of orphaned intents that need to be reprocessed, or an error
	/// if recovery fails critically.
	pub async fn initialize_with_recovery(&self) -> Result<Vec<Intent>, EngineError> {
		tracing::info!("Initializing solver engine with state recovery");

		// Create recovery service with required dependencies
		let recovery_service = RecoveryService::new(
			self.storage.clone(),
			self.state_machine.clone(),
			self.delivery.clone(),
			self.settlement.clone(),
			self.event_bus.clone(),
		);

		// Perform recovery
		match recovery_service.recover_state().await {
			Ok((report, orphaned_intents)) => {
				tracing::info!(
					"State recovery successful: {} orders recovered, {} orphaned intents, {} reconciled",
					report.total_orders,
					report.orphaned_intents,
					report.reconciled_orders
				);

				// Events have already been published by the recovery service
				Ok(orphaned_intents)
			},
			Err(e) => {
				tracing::error!("State recovery failed: {}", e);
				// TODO: Decide whether to continue or fail based on configuration
				Ok(Vec::new())
			},
		}
	}

	/// Main execution loop for the solver engine.
	///
	/// This method runs the core event-driven processing loop that:
	/// 1. Performs initial state recovery
	/// 2. Starts discovery services to find new intents
	/// 3. Processes incoming intents and converts them to orders
	/// 4. Handles order lifecycle events (prepare, execute, settle)
	/// 5. Manages transaction monitoring and error handling
	/// 6. Batches settlement claims for efficiency
	/// 7. Runs storage cleanup tasks
	///
	/// The loop uses semaphores to control concurrency - transaction events
	/// are serialized to avoid nonce conflicts, while other events can run
	/// concurrently.
	///
	/// # Returns
	///
	/// Returns `Ok(())` when the engine shuts down gracefully, or an error
	/// if a critical failure occurs that prevents continued operation.
	#[instrument(skip_all)]
	pub async fn run(&self) -> Result<(), EngineError> {
		// Subscribe to events before recovery so we don't miss recovery events
		let mut event_receiver = self.event_bus.subscribe();

		// Perform recovery and get orphaned intents
		let orphaned_intents = self.initialize_with_recovery().await?;

		// Start discovery monitoring
		let (intent_tx, mut intent_rx) = mpsc::unbounded_channel();

		// Re-inject orphaned intents if any
		for intent in orphaned_intents {
			if let Err(e) = intent_tx.send(intent) {
				tracing::warn!("Failed to re-inject orphaned intent: {}", e);
			}
		}

		self.discovery
			.start_all(intent_tx)
			.await
			.map_err(|e| EngineError::Service(e.to_string()))?;

		// Batch claim processing
		let mut claim_batch = Vec::new();

		// Start storage cleanup task
		let storage = self.storage.clone();
		let cleanup_interval_seconds = self.config.storage.cleanup_interval_seconds;
		let cleanup_interval = tokio::time::interval(Duration::from_secs(cleanup_interval_seconds));
		tracing::info!(
			"Starting storage cleanup service, will run every {} seconds",
			cleanup_interval_seconds
		);
		let cleanup_handle = tokio::spawn(async move {
			let mut interval = cleanup_interval;
			loop {
				interval.tick().await;
				match storage.cleanup_expired().await {
					Ok(0) => {
						tracing::debug!("Storage cleanup: no expired entries found");
					},
					Ok(count) => {
						tracing::info!("Storage cleanup: removed {} expired entries", count);
					},
					Err(e) => {
						tracing::warn!("Storage cleanup failed: {}", e);
					},
				}
			}
		});

		// Create separate semaphores for different event types
		// Transaction events need to be serialized to avoid nonce conflicts
		let transaction_semaphore = Arc::new(Semaphore::new(1)); // Serialize transaction submissions
		let general_semaphore = Arc::new(Semaphore::new(100)); // Allow concurrent non-tx operations

		loop {
			tokio::select! {
				// Handle discovered intents
				Some(intent) = intent_rx.recv() => {
					self.spawn_handler(&general_semaphore, move |engine| async move {
						if let Err(e) = engine.intent_handler.handle(intent).await {
							return Err(EngineError::Service(format!("Failed to handle intent: {}", e)));
						}
						Ok(())
					})
					.await;
				}

				// Handle events
				Ok(event) = event_receiver.recv() => {
					match event {
						SolverEvent::Order(OrderEvent::Preparing { intent, order, params }) => {
							// Preparing sends a prepare transaction - use transaction semaphore
							self.spawn_handler(&transaction_semaphore, move |engine| async move {
								if let Err(e) = engine.order_handler.handle_preparation(intent.source, order, params).await {
									return Err(EngineError::Service(format!("Failed to handle order preparation: {}", e)));
								}
								Ok(())
							})
							.await;
						}
						SolverEvent::Order(OrderEvent::Executing { order, params }) => {
							// Executing sends a fill transaction - use transaction semaphore
							self.spawn_handler(&transaction_semaphore, move |engine| async move {
								if let Err(e) = engine.order_handler.handle_execution(order, params).await {
									return Err(EngineError::Service(format!("Failed to handle order execution: {}", e)));
								}
								Ok(())
							})
							.await;
						}

						SolverEvent::Delivery(DeliveryEvent::TransactionPending { order_id, tx_hash, tx_type, tx_chain_id: _ }) => {
							tracing::info!(
								order_id = %truncate_id(&order_id),
								tx_hash = %truncate_id(&hex::encode(&tx_hash.0)),
								tx_type = ?tx_type,
								"Submitted transaction"
							);
						}

						SolverEvent::Delivery(DeliveryEvent::TransactionConfirmed { order_id, tx_hash, tx_type, receipt }) => {
							tracing::info!(
								order_id = %truncate_id(&order_id),
								tx_hash = %truncate_id(&hex::encode(&tx_hash.0)),
								tx_type = ?tx_type,
								"Confirmed"
							);
							// Confirmation handling doesn't directly send transactions - use general semaphore
							// Note: This may trigger OrderEvent::Executing which will be serialized separately
							self.spawn_handler(&general_semaphore, move |engine| async move {
								if let Err(e) = engine.transaction_handler.handle_confirmed(order_id, tx_hash, tx_type, receipt).await {
									return Err(EngineError::Service(format!("Failed to handle transaction confirmation: {}", e)));
								}
								Ok(())
							})
							.await;
						}

						SolverEvent::Delivery(DeliveryEvent::TransactionFailed { order_id, tx_hash, tx_type, error }) => {
							tracing::error!(
								order_id = %truncate_id(&order_id),
								tx_hash = %truncate_id(&hex::encode(&tx_hash.0)),
								tx_type = ?tx_type,
								error = %error,
								"Transaction failed"
							);
							// Failure handling doesn't send transactions - use general semaphore
							self.spawn_handler(&general_semaphore, move |engine| async move {
								if let Err(e) = engine.transaction_handler.handle_failed(order_id, tx_hash, tx_type, error).await {
									return Err(EngineError::Service(format!("Failed to handle transaction failure: {}", e)));
								}
								Ok(())
							})
							.await;
						}

						// Handle PostFillReady - use settlement handler
						SolverEvent::Settlement(SettlementEvent::PostFillReady { order_id }) => {
							self.spawn_handler(&transaction_semaphore, move |engine| async move {
								if let Err(e) = engine.settlement_handler.handle_post_fill_ready(order_id).await {
									return Err(EngineError::Service(format!("Failed to handle PostFillReady: {}", e)));
								}
								Ok(())
							})
							.await;
						}

						// Handle PreClaimReady - use settlement handler
						SolverEvent::Settlement(SettlementEvent::PreClaimReady { order_id }) => {
							self.spawn_handler(&transaction_semaphore, move |engine| async move {
								if let Err(e) = engine.settlement_handler.handle_pre_claim_ready(order_id).await {
									return Err(EngineError::Service(format!("Failed to handle PreClaimReady: {}", e)));
								}
								Ok(())
							})
							.await;
						}

						// Handle StartMonitoring - spawn settlement monitor
						SolverEvent::Settlement(SettlementEvent::StartMonitoring { order_id, fill_tx_hash }) => {
							// Retrieve order
							let order: Order = match self.storage
								.retrieve(StorageKey::Orders.as_str(), &order_id)
								.await
							{
								Ok(order) => order,
								Err(e) => {
									tracing::error!("Failed to retrieve order {}: {}", order_id, e);
									EngineError::Service(format!("Failed to retrieve order {}: {}", order_id, e));
									continue;
								}
							};

							// Spawn monitor directly (it handles its own tokio::spawn internally)
							self.settlement_handler.spawn_settlement_monitor(order, fill_tx_hash);
						}

						SolverEvent::Settlement(SettlementEvent::ClaimReady { order_id }) => {
							claim_batch.push(order_id);
							if claim_batch.len() >= CLAIM_BATCH {
								let mut batch = std::mem::take(&mut claim_batch);
								claim_batch.clear();
								// Claim sends a transaction - use transaction semaphore
								self.spawn_handler(&transaction_semaphore, move |engine| async move {
									if let Err(e) = engine.settlement_handler.process_claim_batch(&mut batch).await {
										return Err(EngineError::Service(format!("Failed to process claim batch: {}", e)));
									}
									Ok(())
								})
								.await;
							}
						}

						_ => {}
					}
				}

				// Shutdown signal
				_ = tokio::signal::ctrl_c() => {
					break;
				}
			}
		}

		// Cleanup
		cleanup_handle.abort(); // Stop the cleanup task

		self.discovery
			.stop_all()
			.await
			.map_err(|e| EngineError::Service(e.to_string()))?;

		Ok(())
	}

	/// Returns a reference to the event bus.
	///
	/// The event bus is used for inter-service communication and allows
	/// external components to subscribe to solver events.
	pub fn event_bus(&self) -> &event_bus::EventBus {
		&self.event_bus
	}

	/// Returns a reference to the solver configuration.
	///
	/// Provides access to all configuration settings including network
	/// parameters, timeouts, and service-specific settings.
	pub fn config(&self) -> &Config {
		&self.config
	}

	/// Returns a reference to the storage service.
	///
	/// Provides access to the persistent storage layer for orders,
	/// intents, and other solver state.
	pub fn storage(&self) -> &Arc<StorageService> {
		&self.storage
	}

	/// Returns a reference to the token manager.
	///
	/// Provides access to token approval management and validation
	/// functionality for cross-chain operations.
	pub fn token_manager(&self) -> &Arc<TokenManager> {
		&self.token_manager
	}

	/// Returns a reference to the settlement service.
	pub fn settlement(&self) -> &Arc<SettlementService> {
		&self.settlement
	}

	/// Returns a reference to the discovery service.
	pub fn discovery(&self) -> &Arc<DiscoveryService> {
		&self.discovery
	}

	/// Returns a reference to the delivery service.
	pub fn delivery(&self) -> &Arc<DeliveryService> {
		&self.delivery
	}

	/// Returns a reference to the account service.
	pub fn account(&self) -> &Arc<AccountService> {
		&self.account
	}

	/// Returns a reference to the order service.
	pub fn order(&self) -> &Arc<OrderService> {
		&self.order
	}

	/// Returns a reference to the pricing service.
	pub fn pricing(&self) -> &Arc<PricingService> {
		&self.pricing
	}

	/// Helper method to spawn handler tasks with semaphore-based concurrency control.
	///
	/// This method:
	/// 1. Acquires a permit from the semaphore to limit concurrent tasks
	/// 2. Clones the engine and spawns the handler in a new task
	/// 3. Handles errors by logging them appropriately
	async fn spawn_handler<F, Fut>(&self, semaphore: &Arc<Semaphore>, handler: F)
	where
		F: FnOnce(SolverEngine) -> Fut + Send + 'static,
		Fut: Future<Output = Result<(), EngineError>> + Send,
	{
		let engine = self.clone();
		match semaphore.clone().acquire_owned().await {
			Ok(permit) => {
				tokio::spawn(async move {
					let _permit = permit; // Keep permit alive for duration of task
					if let Err(e) = handler(engine).await {
						tracing::error!("Handler error: {}", e);
					}
				});
			},
			Err(e) => {
				tracing::error!("Failed to acquire semaphore permit: {}", e);
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::engine::event_bus::EventBus;
	use solver_account::AccountService;
	use solver_config::Config;
	use solver_delivery::DeliveryService;
	use solver_discovery::DiscoveryService;
	use solver_order::OrderService;
	use solver_settlement::SettlementService;
	use solver_storage::StorageService;
	use solver_types::Address;
	use std::sync::Arc;
	use tokio::sync::Semaphore;

	// Helper function to create mock services for testing
	fn create_mock_services() -> (
		Config,
		Arc<StorageService>,
		Arc<AccountService>,
		Address,
		Arc<DeliveryService>,
		Arc<DiscoveryService>,
		Arc<OrderService>,
		Arc<SettlementService>,
		Arc<PricingService>,
		EventBus,
		Arc<TokenManager>,
	) {
		// Create minimal config for testing
		let config_toml = r#"
			[solver]
			id = "test-solver"
			monitoring_timeout_seconds = 30
			min_profitability_pct = 1.0
			
			[storage]
			primary = "memory"
			cleanup_interval_seconds = 3600
			[storage.implementations.memory]
			
			[delivery]
			min_confirmations = 1
			[delivery.implementations]
			
			[account]
			primary = "local"
			[account.implementations.local]
			private_key = "0x1234567890123456789012345678901234567890123456789012345678901234"
			
			[discovery]
			[discovery.implementations]
			
			[order]
			[order.implementations]
			[order.strategy]
			primary = "simple"
			[order.strategy.implementations.simple]
			
			[settlement]
			[settlement.implementations]
			
			[networks.1]
			chain_id = 1
			input_settler_address = "0x1111111111111111111111111111111111111111"
			output_settler_address = "0x2222222222222222222222222222222222222222"
			[[networks.1.rpc_urls]]
			http = "http://localhost:8545"
			[[networks.1.tokens]]
			symbol = "TEST"
			address = "0x3333333333333333333333333333333333333333"
			decimals = 18
			
			[networks.2]
			chain_id = 2
			input_settler_address = "0x4444444444444444444444444444444444444444"
			output_settler_address = "0x5555555555555555555555555555555555555555"
			[[networks.2.rpc_urls]]
			http = "http://localhost:8546"
			[[networks.2.tokens]]
			symbol = "TEST2"
			address = "0x6666666666666666666666666666666666666666"
			decimals = 18
		"#;
		let config: Config = toml::from_str(config_toml).expect("Failed to parse test config");

		// Create mock services using proper constructors
		let storage = Arc::new(StorageService::new(Box::new(
			solver_storage::implementations::memory::MemoryStorage::new(),
		)));

		// Create account service with local wallet
		let account_config = toml::from_str(
			r#"private_key = "0x1234567890123456789012345678901234567890123456789012345678901234""#,
		)
		.expect("Failed to parse account config");
		let account = Arc::new(AccountService::new(
			solver_account::implementations::local::create_account(&account_config)
				.expect("Failed to create account"),
		));

		// Create address from bytes
		let solver_address = Address(vec![1u8; 20]);

		// Create delivery service - using empty implementations map for testing
		let delivery = Arc::new(DeliveryService::new(
			std::collections::HashMap::new(),
			1,
			20,
		));

		// Create discovery service - using empty implementations map for testing
		let discovery = Arc::new(DiscoveryService::new(std::collections::HashMap::new()));

		// Create order service - needs implementations and strategy
		let strategy_config = toml::Value::Table(toml::value::Table::new());
		let strategy =
			solver_order::implementations::strategies::simple::create_strategy(&strategy_config)
				.expect("Failed to create strategy");
		let order = Arc::new(OrderService::new(
			std::collections::HashMap::new(),
			strategy,
		));

		// Create settlement service - using empty implementations map for testing
		let settlement = Arc::new(SettlementService::new(std::collections::HashMap::new(), 20));

		// Create pricing service with mock implementation
		let pricing_config = toml::Value::Table(toml::value::Table::new());
		let pricing_impl =
			solver_pricing::implementations::mock::create_mock_pricing(&pricing_config)
				.expect("Failed to create mock pricing");
		let pricing = Arc::new(solver_pricing::PricingService::new(pricing_impl));

		let event_bus = EventBus::new(100);

		// Create token manager with empty networks config
		let networks = std::collections::HashMap::new();
		let token_manager = Arc::new(TokenManager::new(
			networks,
			delivery.clone(),
			account.clone(),
		));

		(
			config,
			storage,
			account,
			solver_address,
			delivery,
			discovery,
			order,
			settlement,
			pricing,
			event_bus,
			token_manager,
		)
	}

	#[test]
	fn test_solver_engine_new() {
		let (
			config,
			storage,
			account,
			solver_address,
			delivery,
			discovery,
			order,
			settlement,
			pricing,
			event_bus,
			token_manager,
		) = create_mock_services();

		let engine = SolverEngine::new(
			config.clone(),
			storage.clone(),
			account.clone(),
			solver_address,
			delivery.clone(),
			discovery.clone(),
			order.clone(),
			settlement.clone(),
			pricing.clone(),
			event_bus.clone(),
			token_manager.clone(),
		);

		// Verify the engine was constructed properly by testing its accessors
		assert_eq!(
			engine.config().solver.monitoring_timeout_seconds,
			config.solver.monitoring_timeout_seconds
		);
		assert!(Arc::ptr_eq(engine.storage(), &storage));
		assert!(Arc::ptr_eq(engine.token_manager(), &token_manager));
		assert!(Arc::ptr_eq(engine.settlement(), &settlement));
		assert!(Arc::ptr_eq(engine.discovery(), &discovery));

		// Verify event bus is accessible
		let _event_bus_ref = engine.event_bus();
	}

	#[tokio::test]
	async fn test_initialize_with_recovery_success() {
		let (
			config,
			storage,
			account,
			solver_address,
			delivery,
			discovery,
			order,
			settlement,
			pricing,
			event_bus,
			token_manager,
		) = create_mock_services();

		let engine = SolverEngine::new(
			config,
			storage,
			account,
			solver_address,
			delivery,
			discovery,
			order,
			settlement,
			pricing,
			event_bus,
			token_manager,
		);

		// This test assumes the RecoveryService will return empty results for memory storage
		let result = engine.initialize_with_recovery().await;
		assert!(result.is_ok());
		let orphaned_intents = result.unwrap();
		assert!(orphaned_intents.is_empty()); // Memory storage should have no existing state
	}

	#[tokio::test]
	async fn test_initialize_with_recovery_handles_errors_gracefully() {
		let (
			config,
			storage,
			account,
			solver_address,
			delivery,
			discovery,
			order,
			settlement,
			pricing,
			event_bus,
			token_manager,
		) = create_mock_services();

		let engine = SolverEngine::new(
			config,
			storage,
			account,
			solver_address,
			delivery,
			discovery,
			order,
			settlement,
			pricing,
			event_bus,
			token_manager,
		);

		// Even if recovery fails internally, the method should return Ok with empty Vec
		// as per the implementation's error handling strategy
		let result = engine.initialize_with_recovery().await;
		assert!(result.is_ok());
	}

	#[tokio::test]
	async fn test_spawn_handler_with_handler_error() {
		let (
			config,
			storage,
			account,
			solver_address,
			delivery,
			discovery,
			order,
			settlement,
			pricing,
			event_bus,
			token_manager,
		) = create_mock_services();

		let engine = SolverEngine::new(
			config,
			storage,
			account,
			solver_address,
			delivery,
			discovery,
			order,
			settlement,
			pricing,
			event_bus,
			token_manager,
		);

		let semaphore = Arc::new(Semaphore::new(1));

		// Test handler that returns an error - should be logged but not panic
		engine
			.spawn_handler(&semaphore, move |_engine| async move {
				Err(EngineError::Service("Test error".to_string()))
			})
			.await;
	}

	#[test]
	fn test_engine_error_display() {
		let config_error = EngineError::Config("test config error".to_string());
		assert_eq!(
			config_error.to_string(),
			"Configuration error: test config error"
		);

		let service_error = EngineError::Service("test service error".to_string());
		assert_eq!(
			service_error.to_string(),
			"Service error: test service error"
		);

		let handler_error = EngineError::Handler("test handler error".to_string());
		assert_eq!(
			handler_error.to_string(),
			"Handler error: test handler error"
		);
	}
}
