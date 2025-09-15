//! Core solver engine that orchestrates the order execution lifecycle.
//!
//! This module contains the main SolverEngine struct which coordinates between
//! all services (discovery, order processing, delivery, settlement) and manages
//! the main event loop for processing intents and orders.

pub mod context;
pub mod event_bus;
pub mod lifecycle;
pub mod token_manager;

use self::token_manager::TokenManager;
use crate::handlers::{IntentHandler, OrderHandler, SettlementHandler, TransactionHandler};
use crate::recovery::RecoveryService;
use crate::state::OrderStateMachine;
use solver_account::AccountService;
use solver_config::Config;
use solver_delivery::DeliveryService;
use solver_discovery::DiscoveryService;
use solver_order::OrderService;
use solver_pricing::PricingService;
use solver_settlement::SettlementService;
use solver_storage::StorageService;
use solver_types::{
	Address, DeliveryEvent, Intent, Order, OrderEvent, SettlementEvent, SolverEvent, StorageKey,
};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{mpsc, Semaphore};

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

		let intent_handler = Arc::new(IntentHandler::new(
			order.clone(),
			storage.clone(),
			state_machine.clone(),
			event_bus.clone(),
			delivery.clone(),
			solver_address,
			token_manager.clone(),
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
			delivery.clone(),
			storage.clone(),
			state_machine.clone(),
			event_bus.clone(),
			config.solver.monitoring_timeout_minutes,
		));

		let settlement_handler = Arc::new(SettlementHandler::new(
			settlement.clone(),
			order.clone(),
			delivery.clone(),
			storage.clone(),
			state_machine.clone(),
			event_bus.clone(),
			config.solver.monitoring_timeout_minutes,
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
								if let Err(e) = engine.order_handler.handle_preparation(intent, order, params).await {
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

						SolverEvent::Delivery(DeliveryEvent::TransactionPending { order_id, tx_hash, tx_type, tx_chain_id }) => {
							// Monitoring doesn't send transactions - use general semaphore
							self.spawn_handler(&general_semaphore, move |engine| async move {
								engine.transaction_handler.monitor_transaction(order_id, tx_hash, tx_type, tx_chain_id).await;
								Ok(())
							})
							.await;
						}

						SolverEvent::Delivery(DeliveryEvent::TransactionConfirmed { order_id, tx_hash, tx_type, receipt }) => {
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
