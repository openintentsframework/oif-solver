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
use solver_config::Config;
use solver_delivery::DeliveryService;
use solver_discovery::DiscoveryService;
use solver_order::OrderService;
use solver_settlement::SettlementService;
use solver_storage::StorageService;
use solver_types::{DeliveryEvent, OrderEvent, SettlementEvent, SolverEvent};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::mpsc;

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
pub struct SolverEngine {
	/// Solver configuration.
	pub(crate) config: Config,
	/// Storage service for persisting state.
	pub(crate) storage: Arc<StorageService>,
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
static CLAIM_BATCH: usize = 1;

impl SolverEngine {
	/// Creates a new solver engine with the given services
	pub fn new(
		config: Config,
		storage: Arc<StorageService>,
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

		loop {
			tokio::select! {
				// Handle discovered intents
				Some(intent) = intent_rx.recv() => {
					if let Err(e) = self.intent_handler.handle(intent).await {
						tracing::error!("Failed to handle intent: {}", e);
					}
				}

				// Handle events
				Ok(event) = event_receiver.recv() => {
					match event {
						SolverEvent::Order(OrderEvent::Preparing { intent, order, params }) => {
							if let Err(e) = self.order_handler.handle_preparation(intent, order, params).await {
								tracing::error!("Failed to handle order preparation: {}", e);
							}
						}
						SolverEvent::Order(OrderEvent::Executing { order, params }) => {
							if let Err(e) = self.order_handler.handle_execution(order, params).await {
								tracing::error!("Failed to handle order execution: {}", e);
							}
						}

						SolverEvent::Delivery(DeliveryEvent::TransactionPending { order_id, tx_hash, tx_type }) => {
							self.transaction_handler.monitor_transaction(order_id, tx_hash, tx_type).await;
						}

						SolverEvent::Delivery(DeliveryEvent::TransactionConfirmed { order_id, tx_hash, tx_type, receipt }) => {
							if let Err(e) = self.transaction_handler.handle_confirmed(order_id, tx_hash, tx_type, receipt).await {
								tracing::error!("Failed to handle transaction confirmation: {}", e);
							}
						}

						SolverEvent::Delivery(DeliveryEvent::TransactionFailed { order_id, tx_hash, tx_type, error }) => {
							if let Err(e) = self.transaction_handler.handle_failed(order_id, tx_hash, tx_type, error).await {
								tracing::error!("Failed to handle transaction failure: {}", e);
							}
						}

						SolverEvent::Settlement(SettlementEvent::ClaimReady { order_id }) => {
							claim_batch.push(order_id);
							if claim_batch.len() >= CLAIM_BATCH {
								if let Err(e) = self.settlement_handler.process_claim_batch(&mut claim_batch).await {
									tracing::error!("Failed to process claim batch: {}", e);
								}
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
}
