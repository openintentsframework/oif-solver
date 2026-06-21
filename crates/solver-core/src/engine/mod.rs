//! Core solver engine that orchestrates the order execution lifecycle.
//!
//! This module contains the main SolverEngine struct which coordinates between
//! all services (discovery, order processing, delivery, settlement) and manages
//! the main event loop for processing intents and orders.

pub mod context;
pub mod cost_profit;
pub mod event_bus;
pub mod lifecycle;
pub mod live_estimate;
pub mod post_fill_overrides;
pub mod startup_readiness;
pub mod token_manager;

use self::{
	cost_profit::CostProfitService,
	startup_readiness::{SharedStartupReadiness, StartupReadiness},
	token_manager::TokenManager,
};
use crate::handlers::{IntentHandler, OrderHandler, SettlementHandler, TransactionHandler};
use crate::recovery::RecoveryService;
use crate::state::transaction_attempt::TransactionAttemptStore;
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
	StorageKey, TransactionType,
};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{mpsc, RwLock, Semaphore};
use tracing::instrument;

const INTENT_QUEUE_CAPACITY: usize = 1024;

/// Upper bound on handler tasks that have been spawned but not yet completed.
///
/// `spawn_handler` acquires one of these permits BEFORE `tokio::spawn` and the
/// spawned task holds it for its whole lifetime. This caps the number of
/// in-flight (including parked) handler tasks, so a bounded intake — the H-09
/// intent queue / event bus — cannot be drained into unlimited parked
/// semaphore-waiter tasks (unbounded memory growth).
///
/// Sized to match `INTENT_QUEUE_CAPACITY`: the queue can hold at most that many
/// pending items, so allowing the same number of concurrent handlers means the
/// common path never blocks on this bound — backpressure only engages at true
/// saturation. It is far above the single-permit `transaction_semaphore`, so a
/// merely contended transaction permit never blocks dispatch (preserving the
/// M-13 property that a held transaction permit cannot stall the event loop).
const MAX_INFLIGHT_HANDLERS: usize = INTENT_QUEUE_CAPACITY;

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
	/// Dynamic configuration that supports hot reload via admin API.
	pub(crate) dynamic_config: Arc<RwLock<Config>>,
	/// Static configuration snapshot taken at startup (services don't see hot reload changes).
	pub(crate) static_config: Config,
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
	/// Shared cost/profit service, including quote-time live estimate limits.
	pub(crate) cost_profit_service: Arc<CostProfitService>,
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
	/// Bridge service for cross-chain rebalancing
	pub(crate) bridge_service: Option<Arc<solver_bridge::BridgeService>>,
	pub(crate) rebalance_monitor_status:
		Arc<tokio::sync::RwLock<solver_bridge::monitor::RebalanceMonitorStatus>>,
	/// The solver's Ethereum address.
	pub(crate) solver_address: solver_types::Address,
	/// Public-facing startup readiness state. Defaults to `ready()`. The
	/// builder writes a non-ready value here when startup approvals are
	/// blocked on native gas; the retry loop flips it back when the next
	/// approval pass succeeds.
	pub(crate) startup_readiness: SharedStartupReadiness,
}

/// Number of orders to batch together for claim operations.
///
/// This constant defines how many orders are batched together when
/// submitting claim transactions to reduce gas costs.
static CLAIM_BATCH: usize = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SettlementFailurePolicy {
	RetryLater,
	FailOrder,
}

/// Classifies settlement-stage failures without relying on formatted strings.
///
/// A retryable result means the order should stay in its current non-terminal
/// state so startup recovery can re-drive the stage. Permanent failures are
/// the only errors that should transition already-filled orders to `Failed`.
fn settlement_failure_policy(
	_stage: TransactionType,
	error: &crate::handlers::settlement::SettlementError,
) -> SettlementFailurePolicy {
	use crate::handlers::settlement::SettlementError;
	use solver_delivery::DeliveryError;
	use solver_settlement::SettlementError as SettlementServiceError;

	match error {
		SettlementError::InsufficientNativeGas(_) => SettlementFailurePolicy::RetryLater,
		SettlementError::Delivery(delivery_error) => match delivery_error {
			DeliveryError::Network(_) => SettlementFailurePolicy::RetryLater,
			DeliveryError::TransactionFailed(_) => SettlementFailurePolicy::FailOrder,
			DeliveryError::NonceTooLow(_) => SettlementFailurePolicy::RetryLater,
			DeliveryError::InsufficientNativeGas(_) => SettlementFailurePolicy::RetryLater,
			DeliveryError::NoImplementationAvailable => SettlementFailurePolicy::RetryLater,
			DeliveryError::ReplacementUnderpriced { .. } => SettlementFailurePolicy::RetryLater,
		},
		SettlementError::SettlementService(settlement_error) => match settlement_error {
			SettlementServiceError::ValidationFailed(_) => SettlementFailurePolicy::FailOrder,
			SettlementServiceError::InvalidProof => SettlementFailurePolicy::FailOrder,
			SettlementServiceError::FillMismatch => SettlementFailurePolicy::FailOrder,
			SettlementServiceError::ProofGenerationFailed { .. } => {
				SettlementFailurePolicy::RetryLater
			},
			SettlementServiceError::FinalityNotReached { .. } => {
				SettlementFailurePolicy::RetryLater
			},
			SettlementServiceError::ProverUnavailable(_) => SettlementFailurePolicy::RetryLater,
			SettlementServiceError::SlotDerivationMismatch => SettlementFailurePolicy::FailOrder,
		},
		SettlementError::Storage(_) | SettlementError::Service(_) | SettlementError::State(_) => {
			SettlementFailurePolicy::FailOrder
		},
	}
}

impl SolverEngine {
	/// Creates a new solver engine with the given services.
	///
	/// This constructor initializes all internal components including handlers
	/// and the state machine, establishing the complete event-driven architecture
	/// for order processing.
	///
	/// # Arguments
	///
	/// * `dynamic_config` - Dynamic configuration that supports hot reload via admin API
	/// * `static_config` - Static configuration snapshot taken at startup (services don't see hot reload changes)
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
	/// * `bridge_service` - Optional bridge service for cross-chain rebalancing
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		dynamic_config: Arc<RwLock<Config>>,
		static_config: Config,
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
		bridge_service: Option<Arc<solver_bridge::BridgeService>>,
	) -> Self {
		let solver_address_stored = solver_address.clone();

		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));

		// Create CostProfitService for cost estimation and profitability validation
		let cost_profit_service = Arc::new(CostProfitService::new(
			pricing.clone(),
			delivery.clone(),
			token_manager.clone(),
			storage.clone(),
			settlement.clone(),
		));

		let intent_handler = Arc::new(IntentHandler::new(
			order.clone(),
			storage.clone(),
			state_machine.clone(),
			event_bus.clone(),
			delivery.clone(),
			solver_address,
			token_manager.clone(),
			cost_profit_service.clone(),
			dynamic_config.clone(), // Pass dynamic config for hot-reload support
			&static_config,         // Pass static config for deny list loading
		));

		let order_handler = Arc::new(OrderHandler::new(
			order.clone(),
			delivery.clone(),
			storage.clone(),
			state_machine.clone(),
			event_bus.clone(),
			dynamic_config.clone(),
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
			static_config.solver.monitoring_timeout_seconds / 60, // Convert seconds to minutes
			static_config.networks.clone(),
		));

		Self {
			dynamic_config,
			static_config,
			storage,
			account,
			delivery,
			discovery,
			order,
			settlement,
			pricing,
			token_manager,
			cost_profit_service,
			event_bus,
			state_machine,
			intent_handler,
			order_handler,
			transaction_handler,
			settlement_handler,
			bridge_service,
			solver_address: solver_address_stored,
			rebalance_monitor_status: Arc::new(tokio::sync::RwLock::new(
				solver_bridge::monitor::RebalanceMonitorStatus::default(),
			)),
			startup_readiness: Arc::new(RwLock::new(StartupReadiness::ready())),
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

		let transaction_attempt_store =
			Arc::new(TransactionAttemptStore::new(self.storage.clone()));

		// Create recovery service with required dependencies
		let recovery_service = RecoveryService::new(
			self.storage.clone(),
			self.state_machine.clone(),
			self.delivery.clone(),
			self.settlement.clone(),
			self.event_bus.clone(),
			transaction_attempt_store,
			Arc::new(self.static_config.networks.clone()),
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

		// Start discovery monitoring with bounded intake so external discovery
		// sources cannot accumulate unbounded in-memory intent backlog.
		let intent_queue_capacity = INTENT_QUEUE_CAPACITY.max(orphaned_intents.len());
		let (intent_tx, mut intent_rx) = mpsc::channel(intent_queue_capacity);

		// Re-inject orphaned intents if any
		for intent in orphaned_intents {
			if let Err(e) = intent_tx.try_send(intent) {
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
		let cleanup_interval_seconds = self.static_config.storage.cleanup_interval_seconds;
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

		// Bounds the number of spawned-but-not-yet-completed handler tasks. Each
		// `spawn_handler` call acquires a permit before spawning and holds it for
		// the task's lifetime, so a bounded intake cannot fan out into unlimited
		// parked semaphore-waiter tasks. See `MAX_INFLIGHT_HANDLERS`.
		let dispatch_semaphore = Arc::new(Semaphore::new(MAX_INFLIGHT_HANDLERS));

		let rebalance_handle = if let Some(bridge_service) = &self.bridge_service {
			// Rebalance preflight: cross-check operator-declared route data
			// against on-chain state before starting the monitor. Catches wrong
			// composer/wrapper/OFT addresses, peer-wiring drift, and
			// `approval_required` mismatches at startup rather than at first
			// rebalance attempt. Pairs without `bridge_route` (legacy
			// chain-keyed path) skip preflight.
			{
				let runtime_config = self.dynamic_config.read().await;
				if let Some(rebalance) = runtime_config.rebalance.as_ref() {
					if rebalance.enabled && !rebalance.pairs.is_empty() {
						let impl_name = rebalance.implementation.clone();
						// Convert runtime RebalancePairConfig (string addresses) into
						// OperatorRebalancePairConfig (parsed addresses) for preflight.
						let mut converted: Vec<solver_types::OperatorRebalancePairConfig> =
							Vec::with_capacity(rebalance.pairs.len());
						let mut convert_err: Option<String> = None;
						for p in &rebalance.pairs {
							let parse = |hex_str: &str,
							             field: &str|
							 -> Result<alloy_primitives::Address, String> {
								let s = hex_str.strip_prefix("0x").unwrap_or(hex_str);
								let bytes = hex::decode(s).map_err(|e| {
									format!("pair '{}' {} not hex: {e}", p.pair_id, field)
								})?;
								if bytes.len() != 20 {
									return Err(format!(
										"pair '{}' {} not 20 bytes",
										p.pair_id, field
									));
								}
								let mut arr = [0u8; 20];
								arr.copy_from_slice(&bytes);
								Ok(alloy_primitives::Address::from(arr))
							};
							let chain_a = match (
								parse(&p.chain_a.token_address, "chain_a.token_address"),
								parse(&p.chain_a.oft_address, "chain_a.oft_address"),
							) {
								(Ok(t), Ok(o)) => solver_types::RebalancePairSide {
									chain_id: p.chain_a.chain_id,
									token_address: t,
									oft_address: o,
								},
								(Err(e), _) | (_, Err(e)) => {
									convert_err = Some(e);
									break;
								},
							};
							let chain_b = match (
								parse(&p.chain_b.token_address, "chain_b.token_address"),
								parse(&p.chain_b.oft_address, "chain_b.oft_address"),
							) {
								(Ok(t), Ok(o)) => solver_types::RebalancePairSide {
									chain_id: p.chain_b.chain_id,
									token_address: t,
									oft_address: o,
								},
								(Err(e), _) | (_, Err(e)) => {
									convert_err = Some(e);
									break;
								},
							};
							converted.push(solver_types::OperatorRebalancePairConfig {
								pair_id: p.pair_id.clone(),
								chain_a,
								chain_b,
								target_balance_a: p.target_balance_a.clone(),
								target_balance_b: p.target_balance_b.clone(),
								deviation_band_bps: p.deviation_band_bps,
								max_bridge_amount: p.max_bridge_amount.clone(),
								bridge_route: p.bridge_route.clone(),
							});
						}
						drop(runtime_config);
						if let Some(e) = convert_err {
							return Err(EngineError::Service(format!(
								"rebalance preflight: pair conversion failed: {e}"
							)));
						}
						match bridge_service.get_implementation(&impl_name) {
							Ok(bridge_impl) => {
								if let Err(e) = bridge_impl.preflight(&converted).await {
									tracing::error!(
										implementation = %impl_name,
										error = %e,
										"Rebalance preflight FAILED — bridge config mismatch with on-chain state; the rebalance monitor will not start"
									);
									return Err(EngineError::Service(format!(
										"rebalance preflight failed: {e}"
									)));
								}
								tracing::info!(
									implementation = %impl_name,
									pairs = converted.len(),
									"Rebalance preflight passed"
								);
							},
							Err(e) => {
								tracing::error!(
									implementation = %impl_name,
									error = %e,
									"Rebalance bridge implementation not registered; refusing to start rebalance monitor"
								);
								return Err(EngineError::Service(format!(
									"rebalance bridge implementation '{impl_name}' is not registered: {e}"
								)));
							},
						}
					}
				}
			}

			let solver_addr_hex = format!("0x{}", hex::encode(&self.solver_address.0));
			let monitor = solver_bridge::monitor::RebalanceMonitor::new(
				bridge_service.clone(),
				self.delivery.clone(),
				self.dynamic_config.clone(),
				self.storage.clone(),
				transaction_semaphore.clone(),
				solver_addr_hex,
				self.rebalance_monitor_status.clone(),
			);
			let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
			let handle = tokio::spawn(async move { monitor.run(shutdown_rx).await });
			tracing::info!("Rebalance monitor started");
			Some((handle, shutdown_tx))
		} else {
			None
		};

		let bump_handle = if self.static_config.tx_bump.enabled {
			let attempt_store = Arc::new(
				crate::state::transaction_attempt::TransactionAttemptStore::new(
					self.storage.clone(),
				),
			);
			let attempt_recorder: Arc<dyn solver_delivery::TransactionAttemptRecorder> =
				attempt_store.clone();
			let bump = crate::bump::TransactionBumpService::new(
				self.static_config.tx_bump.clone(),
				self.storage.clone(),
				attempt_store,
				self.delivery.clone(),
				self.event_bus.clone(),
				attempt_recorder,
				self.pricing.clone(),
			);
			let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
			let handle = tokio::spawn(async move { bump.run(shutdown_rx).await });
			tracing::info!("tx_bump sweeper spawned");
			Some((handle, shutdown_tx))
		} else {
			None
		};

		loop {
			tokio::select! {
				// Handle discovered intents
				Some(intent) = intent_rx.recv() => {
					self.spawn_handler(&dispatch_semaphore, &general_semaphore, move |engine| async move {
						if let Err(e) = engine.intent_handler.handle(intent).await {
							return Err(EngineError::Service(format!("Failed to handle intent: {e}")));
						}
						Ok(())
					}).await;
				}

				// Handle events
				Ok(event) = event_receiver.recv() => {
					match event {
						SolverEvent::Order(OrderEvent::Preparing { intent, order, params }) => {
							// Preparing sends a prepare transaction - use transaction semaphore
							self.spawn_handler(&dispatch_semaphore, &transaction_semaphore, move |engine| async move {
								let order_id = order.id.clone();
								if let Err(e) = engine.order_handler.handle_preparation(intent.source, order, params).await {
									let error_msg = format!("Failed to handle order preparation: {e}");
									// Attempt to mark order as failed
									if let Err(state_err) = engine.state_machine
										.transition_order_status(&order_id, solver_types::OrderStatus::Failed(solver_types::TransactionType::Prepare, error_msg.clone()))
										.await
									{
										tracing::error!("Failed to mark order as failed: {}", state_err);
									}
									return Err(EngineError::Service(error_msg));
								}
								Ok(())
							}).await;
						}
						SolverEvent::Order(OrderEvent::Executing { order, params }) => {
							tracing::info!(
								event = "OrderExecuting",
								order_id = %order.id,
								"Handling order execution event"
							);
							// Executing sends a fill transaction - use transaction semaphore
							self.spawn_handler(&dispatch_semaphore, &transaction_semaphore, move |engine| async move {
								let order_id = order.id.clone();
								if let Err(e) = engine.order_handler.handle_execution(order, params).await {
									let error_msg = format!("Failed to handle order execution: {e}");
									// Attempt to mark order as failed
									if let Err(state_err) = engine.state_machine
										.transition_order_status(&order_id, solver_types::OrderStatus::Failed(solver_types::TransactionType::Fill, error_msg.clone()))
										.await
									{
										tracing::error!("Failed to mark order as failed: {}", state_err);
									}
									return Err(EngineError::Service(error_msg));
								}
								Ok(())
							}).await;
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
							self.spawn_handler(&dispatch_semaphore, &general_semaphore, move |engine| async move {
								let order_id_clone = order_id.clone();
								match engine.transaction_handler.handle_confirmed(order_id, tx_hash, tx_type, receipt).await {
									Ok(()) => Ok(()),
									Err(crate::handlers::transaction::TransactionError::SettlementCallback { stage, source }) => {
										engine.handle_settlement_stage_error(
											&order_id_clone,
											stage,
											"TransactionConfirmed",
											crate::handlers::settlement::SettlementError::SettlementService(source),
										).await
									},
									Err(e) => {
										let error_msg = format!("Failed to handle transaction confirmation: {e}");
										// Attempt to mark order as failed with the transaction type from the event
										if let Err(state_err) = engine.state_machine
											.transition_order_status(&order_id_clone, solver_types::OrderStatus::Failed(tx_type, error_msg.clone()))
											.await
										{
											tracing::error!("Failed to mark order as failed: {}", state_err);
										}
										Err(EngineError::Service(error_msg))
									}
								}
							}).await;
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
							self.spawn_handler(&dispatch_semaphore, &general_semaphore, move |engine| async move {
								if let Err(e) = engine.transaction_handler.handle_failed(order_id, tx_hash, tx_type, error).await {
									return Err(EngineError::Service(format!("Failed to handle transaction failure: {e}")));
								}
								Ok(())
							}).await;
						}

						// Handle PostFillReady - use settlement handler
						SolverEvent::Settlement(SettlementEvent::PostFillReady { order_id }) => {
							tracing::info!(
								event = "PostFillReady",
								order_id = %order_id,
								"Handling post-fill readiness event"
							);
							self.spawn_handler(&dispatch_semaphore, &transaction_semaphore, move |engine| async move {
								let order_id_clone = order_id.clone();
								if let Err(e) = engine.settlement_handler.handle_post_fill_ready(order_id).await {
									return engine.handle_settlement_stage_error(
										&order_id_clone,
										TransactionType::PostFill,
										"PostFillReady",
										e,
									).await;
								}
								Ok(())
							}).await;
						}

						// Handle PreClaimReady - use settlement handler
						SolverEvent::Settlement(SettlementEvent::PreClaimReady { order_id }) => {
							self.spawn_handler(&dispatch_semaphore, &transaction_semaphore, move |engine| async move {
								let order_id_clone = order_id.clone();
								if let Err(e) = engine.settlement_handler.handle_pre_claim_ready(order_id).await {
									return engine.handle_settlement_stage_error(
										&order_id_clone,
										TransactionType::PreClaim,
										"PreClaimReady",
										e,
									).await;
								}
								Ok(())
							}).await;
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
									EngineError::Service(format!("Failed to retrieve order {order_id}: {e}"));
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
								self.spawn_handler(&dispatch_semaphore, &transaction_semaphore, move |engine| async move {
									if let Err(e) = engine.settlement_handler.process_claim_batch(&mut batch).await {
										return engine.handle_settlement_stage_error(
											&e.order_id,
											TransactionType::Claim,
											"ClaimReady",
											e.error,
										).await;
									}
									Ok(())
								}).await;
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
		cleanup_handle.abort();

		if let Some((handle, shutdown_tx)) = rebalance_handle {
			let _ = shutdown_tx.send(true);
			handle.abort();
			tracing::info!("Rebalance monitor stopped");
		}

		if let Some((handle, shutdown_tx)) = bump_handle {
			let _ = shutdown_tx.send(true);
			handle.abort();
			tracing::info!("tx_bump sweeper stopped");
		}

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

	/// Returns a reference to the static config (snapshot taken at startup).
	///
	/// Note: This returns the static snapshot, not the hot-reloadable config.
	/// For hot-reloaded config values, use `dynamic_config()`.
	pub fn config(&self) -> &Config {
		&self.static_config
	}

	/// Returns the dynamic config for hot reload support.
	///
	/// Use this when you need access to config values that may have been
	/// updated via the admin API.
	pub fn dynamic_config(&self) -> &Arc<RwLock<Config>> {
		&self.dynamic_config
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

	/// Returns the shared cost/profit service.
	pub fn cost_profit_service(&self) -> &Arc<CostProfitService> {
		&self.cost_profit_service
	}

	/// Returns a reference to the bridge service, if configured.
	pub fn bridge_service(&self) -> Option<&Arc<solver_bridge::BridgeService>> {
		self.bridge_service.as_ref()
	}

	/// Returns the shared rebalance monitor status for the admin API.
	pub fn rebalance_monitor_status(
		&self,
	) -> &Arc<tokio::sync::RwLock<solver_bridge::monitor::RebalanceMonitorStatus>> {
		&self.rebalance_monitor_status
	}

	/// Returns the solver address as a hex string with 0x prefix.
	pub fn solver_address_hex(&self) -> String {
		format!("0x{}", hex::encode(&self.solver_address.0))
	}

	/// Returns a reference to the solver's primary account address.
	pub fn solver_address(&self) -> &solver_types::Address {
		&self.solver_address
	}

	/// Returns a snapshot of the current startup readiness state. Cheap —
	/// takes a read lock, clones, and releases. Safe to call from hot
	/// paths like the health endpoint.
	pub async fn startup_readiness(&self) -> StartupReadiness {
		self.startup_readiness.read().await.clone()
	}

	/// Returns the shared handle for the startup readiness state. Used by
	/// the builder to seed the initial value and hand a clone to the
	/// background approval retry loop.
	pub fn startup_readiness_handle(&self) -> SharedStartupReadiness {
		Arc::clone(&self.startup_readiness)
	}

	async fn handle_settlement_stage_error(
		&self,
		order_id: &str,
		tx_type: TransactionType,
		context: &str,
		error: crate::handlers::settlement::SettlementError,
	) -> Result<(), EngineError> {
		let error_msg = format!("Failed to handle {context}: {error}");
		match settlement_failure_policy(tx_type, &error) {
			SettlementFailurePolicy::RetryLater => {
				tracing::warn!(
					order_id = %order_id,
					tx_type = ?tx_type,
					error = %error_msg,
					"Settlement stage failed with a transient error; leaving order retryable"
				);
			},
			SettlementFailurePolicy::FailOrder => {
				if let Err(state_err) = self
					.state_machine
					.transition_order_status(
						order_id,
						solver_types::OrderStatus::Failed(tx_type, error_msg.clone()),
					)
					.await
				{
					tracing::error!("Failed to mark order as failed: {}", state_err);
				}
			},
		}
		Err(EngineError::Service(error_msg))
	}

	/// Helper method to spawn handler tasks with semaphore-based concurrency control.
	///
	/// Two semaphores cooperate here, with distinct responsibilities:
	///
	/// * `dispatch` (capacity `MAX_INFLIGHT_HANDLERS`) — acquired BEFORE
	///   `tokio::spawn` and held for the spawned task's whole lifetime. This
	///   bounds the number of spawned-but-not-yet-completed handler tasks, so a
	///   bounded intake (the H-09 intent queue / event bus) cannot be drained
	///   into unlimited parked waiter tasks (unbounded memory growth, M-13
	///   regression). Sized well above the single transaction permit, so the
	///   common path finds a permit immediately and this `.await` does not park
	///   the event loop; the loop only blocks here at TRUE saturation.
	/// * `semaphore` (the per-event-type `transaction_semaphore` /
	///   `general_semaphore`) — acquired INSIDE the spawned task, so a merely
	///   contended transaction permit can no longer park the `select!` event loop
	///   (the original M-13 fix). This serializes nonce allocation on the
	///   single-permit `transaction_semaphore` via mutual exclusion; ordering
	///   among already-spawned waiters becomes tokio's fair acquisition queue
	///   rather than event-arrival order, which is acceptable because nonce
	///   allocation only requires mutual exclusion, not a specific order.
	///
	/// Net effect: bounded in-flight memory WITHOUT reintroducing the per-event
	/// stall — backpressure engages only when `MAX_INFLIGHT_HANDLERS` tasks are
	/// already in flight, not on every contended single transaction permit.
	/// Handler errors are logged.
	async fn spawn_handler<F, Fut>(
		&self,
		dispatch: &Arc<Semaphore>,
		semaphore: &Arc<Semaphore>,
		handler: F,
	) where
		F: FnOnce(SolverEngine) -> Fut + Send + 'static,
		Fut: Future<Output = Result<(), EngineError>> + Send,
	{
		let engine = self.clone();
		let semaphore = semaphore.clone();

		// Acquire the dispatch permit BEFORE spawning. This bounds the number of
		// spawned-but-not-yet-completed handler tasks to the dispatch capacity
		// (`MAX_INFLIGHT_HANDLERS`), so a bounded intake cannot be drained into
		// unlimited parked semaphore-waiter tasks (the H-09 memory-exhaustion
		// concern). Under normal load a permit is immediately available, so this
		// `.await` completes synchronously and does NOT park the event loop;
		// crucially, a merely contended single transaction permit never consumes
		// a dispatch permit at acquisition time, so it cannot stall dispatch
		// (preserving the M-13 property). The loop only blocks here at TRUE
		// saturation — `MAX_INFLIGHT_HANDLERS` tasks already in flight — which is
		// correct, bounded backpressure rather than the original per-event stall.
		let dispatch_permit = match dispatch.clone().acquire_owned().await {
			Ok(permit) => permit,
			Err(e) => {
				tracing::error!("Failed to acquire dispatch permit: {}", e);
				return;
			},
		};

		tokio::spawn(async move {
			// Hold the dispatch permit for the whole task lifetime; it is
			// released on completion, freeing a slot for the next dispatch.
			let _dispatch_permit = dispatch_permit;
			match semaphore.acquire_owned().await {
				Ok(permit) => {
					let _permit = permit; // Keep permit alive for duration of task
					if let Err(e) = handler(engine).await {
						tracing::error!("Handler error: {}", e);
					}
				},
				Err(e) => {
					tracing::error!("Failed to acquire semaphore permit: {}", e);
				},
			}
		});
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::engine::event_bus::EventBus;
	use solver_account::AccountService;
	use solver_config::{Config, ConfigBuilder};
	use solver_delivery::{DeliveryError, DeliveryService, InsufficientNativeGasInfo};
	use solver_discovery::DiscoveryService;
	use solver_order::OrderService;
	use solver_settlement::SettlementService;
	use solver_storage::StorageService;
	use solver_types::utils::tests::builders::OrderBuilder;
	use solver_types::{Address, OrderStatus, TransactionType};
	use std::sync::Arc;
	use tokio::sync::Semaphore;

	// Helper function to create mock services for testing
	#[allow(clippy::type_complexity)]
	async fn create_mock_services() -> (
		Arc<RwLock<Config>>,
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
		let config: Config = ConfigBuilder::new().build();

		// Create mock services using proper constructors
		let storage = Arc::new(StorageService::new(Box::new(
			solver_storage::implementations::memory::MemoryStorage::new(),
		)));

		// Create account service with local wallet
		let account_config = serde_json::json!({
			"private_key": "0x1234567890123456789012345678901234567890123456789012345678901234"
		});
		let account = Arc::new(AccountService::new(
			solver_account::implementations::local::create_account(&account_config)
				.await
				.expect("Failed to create account"),
		));

		// Create address from bytes
		let solver_address = Address(vec![1u8; 20]);

		// Create delivery service - using empty implementations map for testing
		let delivery = Arc::new(DeliveryService::new(
			std::collections::HashMap::new(),
			1,
			20,
			60,
		));

		// Create discovery service - using empty implementations map for testing
		let discovery = Arc::new(DiscoveryService::new(std::collections::HashMap::new()));

		// Create order service - needs implementations and strategy
		let strategy_config = serde_json::Value::Object(serde_json::Map::new());
		let strategy =
			solver_order::implementations::strategies::simple::create_strategy(&strategy_config)
				.expect("Failed to create strategy");
		let order = Arc::new(OrderService::new(
			std::collections::HashMap::new(),
			strategy,
		));

		// Create settlement service - using empty implementations map for testing
		let settlement = Arc::new(SettlementService::new(
			std::collections::HashMap::new(),
			String::new(),
			20,
		));

		// Create pricing service with mock implementation
		let pricing_config = serde_json::Value::Object(serde_json::Map::new());
		let pricing_impl =
			solver_pricing::implementations::mock::create_mock_pricing(&pricing_config)
				.expect("Failed to create mock pricing");
		let pricing = Arc::new(solver_pricing::PricingService::new(
			pricing_impl,
			Vec::new(),
		));

		let event_bus = EventBus::new(100);

		// Create token manager with empty networks config
		let networks = std::collections::HashMap::new();
		let token_manager = Arc::new(TokenManager::new(
			networks,
			delivery.clone(),
			account.clone(),
		));

		let dynamic_config = Arc::new(RwLock::new(config.clone()));

		(
			dynamic_config,
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

	#[tokio::test]
	async fn test_solver_engine_new() {
		let (
			dynamic_config,
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
		) = create_mock_services().await;

		let engine = SolverEngine::new(
			dynamic_config,
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
			None,
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
			dynamic_config,
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
		) = create_mock_services().await;

		let engine = SolverEngine::new(
			dynamic_config,
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
			None,
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
			dynamic_config,
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
		) = create_mock_services().await;

		let engine = SolverEngine::new(
			dynamic_config,
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
			None,
		);

		// Even if recovery fails internally, the method should return Ok with empty Vec
		// as per the implementation's error handling strategy
		let result = engine.initialize_with_recovery().await;
		assert!(result.is_ok());
	}

	#[tokio::test]
	async fn test_spawn_handler_with_handler_error() {
		let (
			dynamic_config,
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
		) = create_mock_services().await;

		let engine = SolverEngine::new(
			dynamic_config,
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
			None,
		);

		let semaphore = Arc::new(Semaphore::new(1));
		let dispatch = Arc::new(Semaphore::new(64));

		// Test handler that returns an error - should be logged but not panic
		engine
			.spawn_handler(&dispatch, &semaphore, move |_engine| async move {
				Err(EngineError::Service("Test error".to_string()))
			})
			.await;
	}

	/// M-13: dispatching a second handler must not block the event loop while a
	/// contended permit is held. The `transaction_semaphore` is `Semaphore::new(1)`
	/// to serialize nonce allocation; if the permit is acquired INLINE (before the
	/// spawn) then a second tx event parks the whole `select!` loop until the
	/// in-flight handler releases the permit. Permit acquisition must therefore
	/// happen INSIDE the spawned task, so `spawn_handler` returns immediately.
	#[tokio::test]
	async fn spawn_handler_does_not_block_when_permit_contended() {
		let engine = create_test_engine().await;

		// Single-permit semaphore mirrors the transaction_semaphore.
		let semaphore = Arc::new(Semaphore::new(1));
		// Ample dispatch capacity so the M-13 dispatch path under test never
		// parks on dispatch backpressure — we are isolating the transaction
		// permit contention, not the saturation bound.
		let dispatch = Arc::new(Semaphore::new(64));

		// Hold the only permit for the duration of the dispatch under test.
		let held = semaphore.clone().acquire_owned().await.unwrap();

		// Signals when the spawned handler actually begins executing.
		let (ran_tx, mut ran_rx) = tokio::sync::oneshot::channel::<()>();

		// Dispatching a handler must return promptly even though no transaction
		// permit is available — the spawned task waits for the permit, the caller
		// does not. If transaction-permit acquisition happened INLINE (pre-fix),
		// this call would block the caller until `held` is released, so the
		// timeout below would elapse.
		tokio::time::timeout(std::time::Duration::from_secs(2), async {
			engine
				.spawn_handler(&dispatch, &semaphore, move |_engine| async move {
					let _ = ran_tx.send(());
					Ok(())
				})
				.await;
		})
		.await
		.expect("spawn_handler must dispatch without blocking on a contended permit");

		// While the permit is held the spawned handler must NOT have run — it is
		// parked on the semaphore inside its own task, not in the caller.
		assert!(
			matches!(
				ran_rx.try_recv(),
				Err(tokio::sync::oneshot::error::TryRecvError::Empty)
			),
			"handler must not run while the permit is held",
		);

		// Releasing the permit lets the queued task acquire it and run, proving
		// serialization is preserved (mutual exclusion via the semaphore).
		drop(held);
		tokio::time::timeout(std::time::Duration::from_secs(2), ran_rx)
			.await
			.expect("handler must run once the permit is released")
			.expect("handler completion signal");
	}

	/// M-13 regression: the number of spawned-but-not-yet-completed handler
	/// tasks must be bounded by the dispatch semaphore capacity, even when a
	/// held transaction permit keeps every handler parked.
	///
	/// Without a bound, a bounded intake (the H-09 intent queue / event bus) can
	/// be drained into UNLIMITED parked semaphore-waiter tasks → unbounded
	/// memory growth. With a dispatch permit acquired BEFORE `tokio::spawn`, the
	/// `(cap + 1)`th dispatch must block until an earlier in-flight task
	/// completes — so no more than `cap` tasks are ever live at once.
	#[tokio::test]
	async fn spawn_handler_bounds_inflight_tasks() {
		use std::sync::atomic::{AtomicUsize, Ordering};

		let engine = create_test_engine().await;

		// Tiny dispatch capacity so we can saturate it cheaply.
		const CAP: usize = 2;
		let dispatch = Arc::new(Semaphore::new(CAP));

		// Single-permit transaction semaphore, held for the whole test so every
		// spawned handler parks on it and therefore never releases its dispatch
		// permit. This is the worst case for memory: maximal parked waiters.
		let tx_semaphore = Arc::new(Semaphore::new(1));
		let held = tx_semaphore.clone().acquire_owned().await.unwrap();

		// Counts handler tasks that have actually been spawned (dispatched).
		let dispatched = Arc::new(AtomicUsize::new(0));

		// Drive far more dispatches than the cap from a background task. Each
		// `spawn_handler` call acquires a dispatch permit before spawning; once
		// CAP permits are held by parked tasks, further calls must block here.
		let n = CAP * 8;
		let driver = {
			let engine = engine.clone();
			let dispatch = dispatch.clone();
			let tx_semaphore = tx_semaphore.clone();
			let dispatched = dispatched.clone();
			tokio::spawn(async move {
				for _ in 0..n {
					let dispatched = dispatched.clone();
					engine
						.spawn_handler(&dispatch, &tx_semaphore, move |_engine| async move {
							dispatched.fetch_add(1, Ordering::SeqCst);
							Ok(())
						})
						.await;
				}
			})
		};

		// Give the driver ample time to run as far as it can. Pre-fix (no bound)
		// it dispatches all `n` tasks. Post-fix it stalls after `CAP`.
		tokio::time::sleep(std::time::Duration::from_millis(200)).await;

		let live = dispatched.load(Ordering::SeqCst);
		assert!(
			live <= CAP,
			"in-flight handler tasks must be bounded by the dispatch capacity: \
			 expected <= {CAP}, observed {live}",
		);
		assert!(
			!driver.is_finished(),
			"driver must be blocked on the dispatch semaphore, not have dispatched all {n} tasks",
		);

		// Releasing the transaction permit lets parked tasks complete, freeing
		// dispatch permits so the driver can finish all `n` dispatches.
		drop(held);
		tokio::time::timeout(std::time::Duration::from_secs(5), driver)
			.await
			.expect("driver must finish once parked tasks complete")
			.expect("driver task must not panic");
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

	fn insufficient_native_gas_error() -> crate::handlers::settlement::SettlementError {
		crate::handlers::settlement::SettlementError::InsufficientNativeGas(Box::new(
			InsufficientNativeGasInfo {
				chain_id: 1,
				signer: "0x0000000000000000000000000000000000000001".to_string(),
				balance_wei: "0".to_string(),
				required_wei: "1".to_string(),
				shortfall_wei: "1".to_string(),
				gas_limit: Some(21_000),
				max_fee_per_gas: Some(1),
				gas_price: None,
				value_wei: "0".to_string(),
			},
		))
	}

	async fn create_test_engine() -> SolverEngine {
		let (
			dynamic_config,
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
		) = create_mock_services().await;

		SolverEngine::new(
			dynamic_config,
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
			None,
		)
	}

	#[test]
	fn settlement_policy_retries_transient_delivery_errors() {
		let errors = vec![
			crate::handlers::settlement::SettlementError::Delivery(DeliveryError::Network(
				"rpc down".to_string(),
			)),
			crate::handlers::settlement::SettlementError::Delivery(DeliveryError::NonceTooLow(
				"nonce drift".to_string(),
			)),
			crate::handlers::settlement::SettlementError::Delivery(
				DeliveryError::ReplacementUnderpriced {
					hint: "raise fee".to_string(),
				},
			),
			crate::handlers::settlement::SettlementError::Delivery(
				DeliveryError::NoImplementationAvailable,
			),
			insufficient_native_gas_error(),
			crate::handlers::settlement::SettlementError::SettlementService(
				solver_settlement::SettlementError::FinalityNotReached {
					required_blocks: 10,
					current_blocks: 3,
				},
			),
			crate::handlers::settlement::SettlementError::SettlementService(
				solver_settlement::SettlementError::ProverUnavailable("down".to_string()),
			),
			crate::handlers::settlement::SettlementError::SettlementService(
				solver_settlement::SettlementError::ProofGenerationFailed {
					source_chain: 1,
					reason: "rpc down".to_string(),
				},
			),
		];

		for error in errors {
			for stage in [
				TransactionType::PostFill,
				TransactionType::PreClaim,
				TransactionType::Claim,
			] {
				assert_eq!(
					settlement_failure_policy(stage, &error),
					SettlementFailurePolicy::RetryLater,
					"expected {error:?} at {stage:?} to be retryable"
				);
			}
		}
	}

	#[test]
	fn settlement_policy_fails_permanent_settlement_errors() {
		let errors = vec![
			crate::handlers::settlement::SettlementError::SettlementService(
				solver_settlement::SettlementError::ValidationFailed("bad config".to_string()),
			),
			crate::handlers::settlement::SettlementError::SettlementService(
				solver_settlement::SettlementError::InvalidProof,
			),
			crate::handlers::settlement::SettlementError::SettlementService(
				solver_settlement::SettlementError::FillMismatch,
			),
			crate::handlers::settlement::SettlementError::SettlementService(
				solver_settlement::SettlementError::SlotDerivationMismatch,
			),
			crate::handlers::settlement::SettlementError::Delivery(
				DeliveryError::TransactionFailed("reverted".to_string()),
			),
			crate::handlers::settlement::SettlementError::Storage("storage down".to_string()),
			crate::handlers::settlement::SettlementError::State("cas failed".to_string()),
			crate::handlers::settlement::SettlementError::Service("missing proof".to_string()),
		];

		for error in errors {
			assert_eq!(
				settlement_failure_policy(TransactionType::PreClaim, &error),
				SettlementFailurePolicy::FailOrder,
				"expected {error:?} to be permanent"
			);
		}
	}

	#[tokio::test]
	async fn post_fill_ready_transient_error_leaves_order_executed() {
		let engine = create_test_engine().await;
		let order = OrderBuilder::new()
			.with_id("post-fill-transient-order".to_string())
			.with_status(OrderStatus::Executed)
			.build();
		engine.state_machine.store_order(&order).await.unwrap();

		let result = engine
			.handle_settlement_stage_error(
				&order.id,
				TransactionType::PostFill,
				"PostFillReady",
				crate::handlers::settlement::SettlementError::Delivery(DeliveryError::Network(
					"rpc down".to_string(),
				)),
			)
			.await;

		assert!(result.is_err());
		let stored = engine.state_machine.get_order(&order.id).await.unwrap();
		assert_eq!(stored.status, OrderStatus::Executed);
	}

	#[tokio::test]
	async fn pre_claim_ready_transient_error_leaves_order_settled() {
		let engine = create_test_engine().await;
		let order = OrderBuilder::new()
			.with_id("pre-claim-transient-order".to_string())
			.with_status(OrderStatus::Settled)
			.build();
		engine.state_machine.store_order(&order).await.unwrap();

		let result = engine
			.handle_settlement_stage_error(
				&order.id,
				TransactionType::PreClaim,
				"PreClaimReady",
				insufficient_native_gas_error(),
			)
			.await;

		assert!(result.is_err());
		let stored = engine.state_machine.get_order(&order.id).await.unwrap();
		assert_eq!(stored.status, OrderStatus::Settled);
	}

	#[tokio::test]
	async fn claim_ready_transient_error_leaves_order_retryable() {
		let engine = create_test_engine().await;
		let order = OrderBuilder::new()
			.with_id("claim-transient-order".to_string())
			.with_status(OrderStatus::PreClaimed)
			.build();
		engine.state_machine.store_order(&order).await.unwrap();

		let result = engine
			.handle_settlement_stage_error(
				&order.id,
				TransactionType::Claim,
				"ClaimReady",
				crate::handlers::settlement::SettlementError::Delivery(
					DeliveryError::NoImplementationAvailable,
				),
			)
			.await;

		assert!(result.is_err());
		let stored = engine.state_machine.get_order(&order.id).await.unwrap();
		assert_eq!(stored.status, OrderStatus::PreClaimed);
	}

	#[tokio::test]
	async fn claim_ready_permanent_error_fails_only_affected_order() {
		let engine = create_test_engine().await;
		let affected = OrderBuilder::new()
			.with_id("claim-permanent-order".to_string())
			.with_status(OrderStatus::PreClaimed)
			.build();
		let unaffected = OrderBuilder::new()
			.with_id("claim-unaffected-order".to_string())
			.with_status(OrderStatus::PreClaimed)
			.build();
		engine.state_machine.store_order(&affected).await.unwrap();
		engine.state_machine.store_order(&unaffected).await.unwrap();

		let result = engine
			.handle_settlement_stage_error(
				&affected.id,
				TransactionType::Claim,
				"ClaimReady",
				crate::handlers::settlement::SettlementError::SettlementService(
					solver_settlement::SettlementError::InvalidProof,
				),
			)
			.await;

		assert!(result.is_err());
		let affected = engine.state_machine.get_order(&affected.id).await.unwrap();
		assert!(matches!(
			affected.status,
			OrderStatus::Failed(TransactionType::Claim, _)
		));
		let unaffected = engine
			.state_machine
			.get_order(&unaffected.id)
			.await
			.unwrap();
		assert_eq!(unaffected.status, OrderStatus::PreClaimed);
	}

	#[tokio::test]
	async fn engine_startup_readiness_defaults_to_ready() {
		let (
			dynamic_config,
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
		) = create_mock_services().await;

		let engine = SolverEngine::new(
			dynamic_config,
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
			None,
		);

		let snapshot = engine.startup_readiness().await;

		assert!(snapshot.approvals_ready);
		assert!(snapshot.reason.is_none());
		assert!(snapshot.blocked_signers.is_empty());
	}

	#[tokio::test]
	async fn engine_startup_readiness_handle_propagates_writes_to_getter() {
		use crate::engine::startup_readiness::{BlockedSigner, StartupReadiness};

		let (
			dynamic_config,
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
		) = create_mock_services().await;

		let engine = SolverEngine::new(
			dynamic_config,
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
			None,
		);

		let handle = engine.startup_readiness_handle();
		*handle.write().await = StartupReadiness::waiting_for_native_gas(vec![BlockedSigner {
			chain_id: 1,
			signer: "0xabc".to_string(),
			balance_wei: "0".to_string(),
		}]);

		let snapshot = engine.startup_readiness().await;
		assert!(!snapshot.approvals_ready);
		assert_eq!(snapshot.reason.as_deref(), Some("waiting_for_native_gas"));
		assert_eq!(snapshot.blocked_signers.len(), 1);
		assert_eq!(snapshot.blocked_signers[0].chain_id, 1);
	}
}
