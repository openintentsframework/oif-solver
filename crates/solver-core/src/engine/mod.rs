//! Core solver engine that orchestrates the order execution lifecycle.
//!
//! This module contains the main SolverEngine struct which coordinates between
//! all services (discovery, order processing, delivery, settlement) and manages
//! the main event loop for processing intents and orders.

pub mod context;
pub mod event_bus;
pub mod lifecycle;

use crate::handlers::{IntentHandler, OrderHandler, SettlementHandler, TransactionHandler};
use crate::state::OrderStateMachine;
use solver_account::AccountService;
use solver_config::Config;
use solver_delivery::DeliveryService;
use solver_discovery::DiscoveryService;
use solver_order::OrderService;
use solver_settlement::SettlementService;
use solver_storage::StorageService;
use solver_types::{Address, DeliveryEvent, OrderEvent, SettlementEvent, SolverEvent};
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
	/// Creates a new solver engine with the given services
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
		event_bus: event_bus::EventBus,
	) -> Self {
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));

		let intent_handler = Arc::new(IntentHandler::new(
			order.clone(),
			storage.clone(),
			state_machine.clone(),
			event_bus.clone(),
			delivery.clone(),
			solver_address,
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
			settlement.clone(),
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
		));

		Self {
			config,
			storage,
			account,
			delivery,
			discovery,
			order,
			settlement,
			event_bus,
			state_machine,
			intent_handler,
			order_handler,
			transaction_handler,
			settlement_handler,
		}
	}

	/// Main execution loop for the solver engine.
	pub async fn run(&self) -> Result<(), EngineError> {
		// Start discovery monitoring
		let (intent_tx, mut intent_rx) = mpsc::unbounded_channel();
		self.discovery
			.start_all(intent_tx)
			.await
			.map_err(|e| EngineError::Service(e.to_string()))?;

		// Subscribe to events
		let mut event_receiver = self.event_bus.subscribe();

		// Batch claim processing
		let mut claim_batch = Vec::new();

		// Start storage cleanup task
		let storage = self.storage.clone();
		let cleanup_interval = tokio::time::interval(Duration::from_secs(
			self.config.storage.cleanup_interval_seconds,
		));
		let cleanup_handle = tokio::spawn(async move {
			let mut interval = cleanup_interval;
			loop {
				interval.tick().await;
				match storage.cleanup_expired().await {
					Ok(count) if count > 0 => {
						tracing::debug!("Storage cleanup: removed {} expired entries", count);
					}
					Err(e) => {
						tracing::warn!("Storage cleanup failed: {}", e);
					}
					_ => {} // No expired entries
				}
			}
		});

		// TODO: Make this configurable?
		let semaphore = Arc::new(Semaphore::new(100)); // Limit to 100 concurrent tasks

		loop {
			tokio::select! {
				// Handle discovered intents
				Some(intent) = intent_rx.recv() => {
					self.spawn_handler(&semaphore, move |engine| async move {
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
							self.spawn_handler(&semaphore, move |engine| async move {
								if let Err(e) = engine.order_handler.handle_preparation(intent, order, params).await {
									return Err(EngineError::Service(format!("Failed to handle order preparation: {}", e)));
								}
								Ok(())
							})
							.await;
						}
						SolverEvent::Order(OrderEvent::Executing { order, params }) => {
							self.spawn_handler(&semaphore, move |engine| async move {
								if let Err(e) = engine.order_handler.handle_execution(order, params).await {
									return Err(EngineError::Service(format!("Failed to handle order execution: {}", e)));
								}
								Ok(())
							})
							.await;
						}

						SolverEvent::Delivery(DeliveryEvent::TransactionPending { order_id, tx_hash, tx_type }) => {
							self.spawn_handler(&semaphore, move |engine| async move {
								engine.transaction_handler.monitor_transaction(order_id, tx_hash, tx_type).await;
								Ok(())
							})
							.await;
						}

						SolverEvent::Delivery(DeliveryEvent::TransactionConfirmed { order_id, tx_hash, tx_type, receipt }) => {
							self.spawn_handler(&semaphore, move |engine| async move {
								if let Err(e) = engine.transaction_handler.handle_confirmed(order_id, tx_hash, tx_type, receipt).await {
									return Err(EngineError::Service(format!("Failed to handle transaction confirmation: {}", e)));
								}
								Ok(())
							})
							.await;
						}

						SolverEvent::Delivery(DeliveryEvent::TransactionFailed { order_id, tx_hash, tx_type, error }) => {
							self.spawn_handler(&semaphore, move |engine| async move {
								if let Err(e) = engine.transaction_handler.handle_failed(order_id, tx_hash, tx_type, error).await {
									return Err(EngineError::Service(format!("Failed to handle transaction failure: {}", e)));
								}
								Ok(())
							})
							.await;
						}

						SolverEvent::Settlement(SettlementEvent::ClaimReady { order_id }) => {
							claim_batch.push(order_id);
							if claim_batch.len() >= CLAIM_BATCH {
								let mut batch = std::mem::take(&mut claim_batch);
								claim_batch.clear();
								self.spawn_handler(&semaphore, move |engine| async move {
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
	pub fn event_bus(&self) -> &event_bus::EventBus {
		&self.event_bus
	}

	/// Returns a reference to the configuration.
	pub fn config(&self) -> &Config {
		&self.config
	}

	/// Returns a reference to the storage service.
	pub fn storage(&self) -> &Arc<StorageService> {
		&self.storage
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
			}
			Err(e) => {
				tracing::error!("Failed to acquire semaphore permit: {}", e);
			}
		}
	}
}
