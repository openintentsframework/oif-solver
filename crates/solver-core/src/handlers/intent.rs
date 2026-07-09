//! Intent handler for processing discovered intents.
//!
//! Responsible for validating intents, creating orders, storing them,
//! and determining execution strategy through the order service.

use crate::engine::{
	context::ContextBuilder,
	cost_profit::{estimate_quote_gas_units_from_flow_keys, CostProfitService},
	event_bus::EventBus,
	token_manager::TokenManager,
};
use crate::state::OrderStateMachine;
use lru::LruCache;
use solver_config::{source_finality_expected_delay_seconds, Config};
use solver_delivery::DeliveryService;
use solver_order::OrderService;
use solver_settlement::admission::estimate_required_expiry_window_seconds;
use solver_storage::{
	compact_reservations::{CompactReservationStore, ReservationError},
	StorageService,
};
use solver_types::{
	current_timestamp, standards::eip7683::LockType, truncate_id, with_0x_prefix, Address,
	DiscoveryEvent, Eip7683OrderData, ExecutionDecision, ExecutionParams, Intent, Order,
	OrderEvent, SolverEvent, StorageKey,
};
use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
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
	cost_profit_service: Arc<CostProfitService>,
	/// Dynamic config for hot-reload support.
	/// Config changes via Admin API are immediately visible.
	dynamic_config: Arc<RwLock<Config>>,
	/// In-memory LRU cache for fast intent deduplication to prevent race conditions
	/// Automatically evicts oldest entries when capacity is exceeded
	processed_intents: Arc<RwLock<LruCache<String, ()>>>,
	/// Denied Ethereum addresses (lowercase hex with 0x prefix).
	/// Loaded once at startup from `config.solver.deny_list` if set.
	denied_addresses: HashSet<String>,
	/// Shared in-flight Compact-deposit reservation accounting.
	///
	/// Cloned from the `OrderStateMachine` passed to `new`, so intake
	/// reservation here and terminal-state release in the state machine go
	/// through the SAME `CompactReservationStore` instance. The store holds
	/// per-lock-id mutex guards that only serialize concurrent admissions when
	/// one instance is reused; a fresh `::new()` per reservation would defeat
	/// the file-backend create-race fix.
	compact_reservations: Arc<CompactReservationStore>,
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
		cost_profit_service: Arc<CostProfitService>,
		dynamic_config: Arc<RwLock<Config>>,
		static_config: &Config,
	) -> Self {
		let deny_list_configured = static_config.solver.deny_list.is_some();
		let denied_addresses = match Self::load_deny_list(static_config.solver.deny_list.as_deref())
		{
			Ok(set) => {
				if set.is_empty() && !deny_list_configured {
					tracing::warn!("No deny list configured. Enforcement is disabled.");
				}
				set
			},
			Err(e) => {
				// Fail closed: a configured deny list that can't be loaded is a hard error.
				panic!("Deny list is configured but could not be loaded (fail-closed): {e}");
			},
		};
		// Share the SAME reservation store the state machine releases through,
		// so intake reserve and terminal release serialize against one set of
		// per-lock-id guards (Fix 2: a per-call `::new()` defeated this).
		let compact_reservations = state_machine.compact_reservations();
		Self {
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			solver_address,
			token_manager,
			cost_profit_service,
			dynamic_config,
			processed_intents: Arc::new(RwLock::new(LruCache::new(
				NonZeroUsize::new(10000).unwrap(),
			))),
			denied_addresses,
			compact_reservations,
		}
	}

	/// Load denied addresses from a JSON file.
	///
	/// - If no path is configured, returns `Ok(empty set)` (feature not in use).
	/// - If a path is configured but the file is missing or malformed, returns `Err`
	///   so the caller can fail closed.
	///   All addresses are stored in lowercase.
	fn load_deny_list(path: Option<&str>) -> Result<HashSet<String>, String> {
		let path = match path {
			Some(p) if !p.is_empty() => p,
			_ => return Ok(HashSet::new()),
		};
		let content = std::fs::read_to_string(path)
			.map_err(|e| format!("Failed to read deny list at '{path}': {e}"))?;
		let addrs: Vec<String> = serde_json::from_str(&content)
			.map_err(|e| format!("Failed to parse deny list at '{path}': {e}"))?;
		let set: HashSet<String> = addrs.into_iter().map(|a| a.to_lowercase()).collect();
		tracing::info!(
			path = %path,
			count = %set.len(),
			"Deny list loaded"
		);
		Ok(set)
	}

	/// Handles a newly discovered intent.
	#[instrument(skip_all, fields(order_id = %truncate_id(&intent.id)))]
	pub async fn handle(&self, intent: Intent) -> Result<(), IntentError> {
		// Clone config early to release lock before any async calls.
		// This enables hot-reload: config changes via Admin API are picked up on next intent.
		let config = self.dynamic_config.read().await.clone();

		// Backstop for intake-disabled mode on discovery paths. HTTP quote/order
		// intake is rejected earlier in solver-service; this catches anything that
		// reaches the engine via discovery (on-chain events, etc.).
		if config.solver.is_intake_disabled() {
			tracing::warn!(
				intent_id = %intent.id,
				"Intent rejected because solver intake is disabled"
			);
			self.event_bus
				.publish(SolverEvent::Discovery(DiscoveryEvent::IntentRejected {
					intent_id: intent.id,
					reason: "Solver intake is disabled".to_string(),
				}))
				.ok();
			return Ok(());
		}

		if intent.lock_type == LockType::ResourceLock.as_str()
			&& !config.solver.is_resource_lock_enabled()
		{
			tracing::warn!(
				intent_id = %intent.id,
				"Intent rejected because ResourceLock orders are disabled"
			);
			self.event_bus
				.publish(SolverEvent::Discovery(DiscoveryEvent::IntentRejected {
					intent_id: intent.id,
					reason: "ResourceLock orders are disabled by this solver configuration"
						.to_string(),
				}))
				.ok();
			return Ok(());
		}

		// Normalize the intent id at the lookup boundary so that in-memory dedupe,
		// the storage existence check, and the storage write all use the same key.
		// Discovery sources may emit ids with or without the `0x` prefix; without
		// this normalization the cross-restart `exists` check could miss an intent
		// that `store` had written under the prefixed form, allowing a duplicate
		// `store_order` to overwrite an active order's tx hashes.
		let dedup_id = with_0x_prefix(&intent.id);

		// Prevent duplicate order processing when multiple discovery modules for the same standard are active.
		//
		// When an off-chain 7683 order is submitted via the API, it triggers an `openFor` transaction
		// which emits an `Open` event identical to regular on-chain orders. This causes both
		// the off-chain module (which initiated it) and the on-chain module (monitoring events)
		// to attempt processing the same order.
		//
		// By checking if the intent already exists in storage, we ensure each order is only
		// processed once, regardless of which discovery module receives it first.
		// This is for fast in-memory deduplication to prevent race conditions
		// This provides atomic check-and-insert for intent IDs
		{
			let mut processed = self.processed_intents.write().await;
			if processed.contains(&dedup_id) {
				tracing::debug!(
					"Duplicate intent detected in memory cache, already being processed"
				);
				return Ok(());
			}
			// Atomically claim this intent ID (LRU will auto-evict oldest if at capacity)
			processed.put(dedup_id.clone(), ());
		}

		// Fallback check against persistent storage for cross-restart deduplication
		// This handles cases where the service was restarted between intent discovery
		let exists = self
			.storage
			.exists(StorageKey::Intents.as_str(), &dedup_id)
			.await
			.map_err(|e| IntentError::Storage(format!("Failed to check intent existence: {e}")))?;
		if exists {
			tracing::debug!("Duplicate intent detected in persistent storage, already processed");
			return Ok(());
		}

		// Deny list check — runs before storing to avoid polluting the dedup cache
		// with addresses that will always be rejected.
		if !self.denied_addresses.is_empty() {
			if let Ok(order_data) = serde_json::from_value::<Eip7683OrderData>(intent.data.clone())
			{
				// Check the order sender (user field).
				let user_addr = order_data.user.to_lowercase();
				if self.denied_addresses.contains(&user_addr) {
					tracing::warn!(
						intent_id = %intent.id,
						address = %user_addr,
						"Intent rejected: sender is on deny list"
					);
					self.event_bus
						.publish(SolverEvent::Discovery(DiscoveryEvent::IntentRejected {
							intent_id: intent.id,
							reason: "Sender address is on deny list".to_string(),
						}))
						.ok();
					return Ok(());
				}
				// Check every output recipient.
				for output in &order_data.outputs {
					// recipient is bytes32; the Ethereum address occupies the last 20 bytes.
					let addr_bytes = &output.recipient[12..];
					let hex_str: String = addr_bytes.iter().map(|b| format!("{b:02x}")).collect();
					let recipient_addr = format!("0x{hex_str}");
					if self.denied_addresses.contains(&recipient_addr) {
						tracing::warn!(
							intent_id = %intent.id,
							address = %recipient_addr,
							"Intent rejected: recipient is on deny list"
						);
						self.event_bus
							.publish(SolverEvent::Discovery(DiscoveryEvent::IntentRejected {
								intent_id: intent.id,
								reason: "Recipient address is on deny list".to_string(),
							}))
							.ok();
						return Ok(());
					}
				}
			}
		}

		// Store intent immediately to prevent race conditions with duplicate discovery.
		// This claims the intent ID slot before we start the potentially slow validation process.
		// `dedup_id` is the same canonicalized key the existence check used above.
		self.storage
			.store(StorageKey::Intents.as_str(), &dedup_id, &intent, None)
			.await
			.map_err(|e| {
				IntentError::Storage(format!("Failed to store intent for deduplication: {e}"))
			})?;

		tracing::info!("Discovered intent");

		// Use the order_bytes field directly from the intent
		let order_bytes = &intent.order_bytes;

		// For on-chain discovered intents, we use a simple callback that returns the intent ID
		// since the order ID was already computed during discovery.
		//
		// Normalize the id before handing it to `hex::decode`. Discovery sources may emit
		// ids with or without the `0x` prefix; without normalization a prefixed intent
		// passes the dedupe step above (which canonicalizes via `with_0x_prefix`) but
		// then fails order creation here, since `alloy_primitives::hex::decode` rejects
		// `0x...`-prefixed inputs.
		let intent_id = solver_types::without_0x_prefix(&intent.id).to_string();
		let order_id_callback: solver_types::OrderIdCallback =
			Box::new(move |_chain_id, _tx_data| {
				let id = intent_id.clone();
				Box::pin(async move {
					alloy_primitives::hex::decode(&id)
						.map_err(|e| format!("Failed to decode intent ID: {e}"))
				})
			});

		// Validate and create order using the unified method.
		// For quote-derived intents, enrich intent data with the persisted quote settlement binding.
		let mut intent_data_value = intent.data.clone();
		if let Some(quote_id) = intent.quote_id.as_deref() {
			match self
				.storage
				.retrieve::<solver_types::StoredQuote>(StorageKey::Quotes.as_str(), quote_id)
				.await
			{
				Ok(quote_with_context) => {
					if let Some(settlement_name) = quote_with_context.settlement_name {
						if let Some(intent_obj) = intent_data_value.as_object_mut() {
							// Preserve both key styles for compatibility with current parsers.
							intent_obj.insert(
								"settlement_name".to_string(),
								serde_json::Value::String(settlement_name.clone()),
							);
							intent_obj.insert(
								"settlementName".to_string(),
								serde_json::Value::String(settlement_name),
							);
						}
					}
				},
				Err(solver_storage::StorageError::NotFound(_)) => {
					tracing::debug!(%quote_id, "No stored quote context found for intent");
				},
				Err(error) => {
					tracing::warn!(
						%quote_id,
						%error,
						"Failed to retrieve quote context for intent settlement binding"
					);
				},
			}
		}
		let intent_data = Some(intent_data_value);
		match self
			.order_service
			.validate_and_create_order(
				&intent.standard,
				order_bytes,
				&intent_data,
				&intent.lock_type,
				order_id_callback,
				&self.solver_address,
				intent.quote_id.clone(),
			)
			.await
		{
			Ok(mut order) => {
				apply_prepare_gas_limit_from_config(&mut order, &intent.source, &config);

				// Settlement-aware acceptance gate:
				// Skip orders that do not leave enough time to reach claim/finalize safely.
				if let Ok(order_data) =
					serde_json::from_value::<Eip7683OrderData>(order.data.clone())
				{
					let now = current_timestamp() as u32;
					if intent.source == "off-chain" {
						if let Err(reason) =
							validate_source_finality_window(&order_data, &config, now)
						{
							tracing::warn!(order_id = %order.id, %reason, "Skipping order");
							self.event_bus
								.publish(SolverEvent::Order(OrderEvent::Skipped {
									order_id: order.id.clone(),
									reason,
								}))
								.ok();
							return Ok(());
						}
					}

					let expires_remaining = order_data.expires.saturating_sub(now) as u64;
					if let Some((required_window, breakdown)) =
						estimate_required_expiry_window_seconds(
							&order_data,
							&config.settlement.implementations,
							config.settlement.settlement_poll_interval_seconds,
							order.settlement_name.as_deref(),
						) {
						let settlement_remaining =
							order_data.expires.saturating_sub(order_data.fill_deadline) as u64;
						if expires_remaining < required_window
							|| settlement_remaining < required_window
						{
							let reason = format!(
								"Insufficient settlement window: expires_in={expires_remaining}s settlement_after_fill={settlement_remaining}s required={required_window}s ({breakdown})"
							);
							tracing::warn!(order_id = %order.id, %reason, "Skipping order");
							self.event_bus
								.publish(SolverEvent::Order(OrderEvent::Skipped {
									order_id: order.id.clone(),
									reason,
								}))
								.ok();
							return Ok(());
						}
					}
				}

				if let Err(e) = self
					.cost_profit_service
					.validate_before_fill_simulation(&order, &config)
					.await
				{
					tracing::warn!("Order failed pre-simulation validation: {}", e);
					self.event_bus
						.publish(SolverEvent::Order(OrderEvent::Skipped {
							order_id: order.id.clone(),
							reason: format!("Pre-simulation validation failed: {e}"),
						}))
						.ok();
					return Ok(());
				}

				// Step 1: Generate fill transaction and simulate to get accurate gas estimate
				// This also validates callbacks won't revert
				let default_params = ExecutionParams {
					gas_price: alloy_primitives::U256::ZERO,
					priority_fee: None,
				};

				let fill_tx = match self
					.order_service
					.generate_fill_transaction(&order, &default_params)
					.await
				{
					Ok(fill_tx) => fill_tx,
					Err(e) => {
						// If fill transaction generation fails, skip the order
						tracing::warn!("Failed to generate fill transaction for simulation: {}", e);
						self.event_bus
							.publish(SolverEvent::Order(OrderEvent::Skipped {
								order_id: order.id.clone(),
								reason: format!("Fill transaction generation failed: {e}"),
							}))
							.ok();
						return Ok(());
					},
				};

				// Simulate the fill transaction to validate callbacks and get gas estimate.
				let simulated_fill_gas = match self
					.cost_profit_service
					.simulate_callback_and_estimate_gas(&order, &fill_tx, &config)
					.await
				{
					Ok(simulation_result) => {
						if simulation_result.has_callback {
							tracing::info!(
								"✅ Callback simulation passed for order {} - estimated gas: {} units on chain {}",
								order.id,
								simulation_result.estimated_gas_units,
								simulation_result.chain_id
							);
						}
						// Use simulated gas if available, otherwise None (will use config default).
						if simulation_result.estimated_gas_units > 0 {
							Some(simulation_result.estimated_gas_units)
						} else {
							None
						}
					},
					Err(e) => {
						tracing::warn!("Order failed callback simulation: {}", e);
						self.event_bus
							.publish(SolverEvent::Order(OrderEvent::Skipped {
								order_id: order.id.clone(),
								reason: format!("Callback simulation failed: {e}"),
							}))
							.ok();
						return Ok(());
					},
				};

				// Step 2: Calculate cost estimation using simulated gas
				let cost_estimate = match self
					.cost_profit_service
					.estimate_cost_for_order_with_gas(
						&order,
						&config,
						simulated_fill_gas,
						Some(&fill_tx),
					)
					.await
				{
					Ok(estimate) => estimate,
					Err(e) => {
						tracing::warn!("Failed to calculate cost estimate: {}", e);
						return Err(IntentError::Service(format!("Cost estimation failed: {e}")));
					},
				};

				// Step 3: Validate profitability with accurate gas costs
				match self
					.cost_profit_service
					.validate_profitability(
						&order,
						&cost_estimate,
						config.solver.min_profitability_pct,
						intent.quote_id.as_deref(),
						&intent.source,
					)
					.await
				{
					Ok(_actual_profit_margin) => {
						// Profitability details already logged in validate_profitability function
					},
					Err(e) => {
						tracing::warn!("Order failed profitability validation: {}", e);
						self.event_bus
							.publish(SolverEvent::Order(OrderEvent::Skipped {
								order_id: order.id.clone(),
								reason: format!("Insufficient profitability: {e}"),
							}))
							.ok();
						return Ok(());
					},
				}

				// Update order's gas_limit_overrides with simulated gas before storing
				// This ensures the actual fill transaction uses the simulated gas limit
				if let Some(simulated_gas) = simulated_fill_gas {
					if let Ok(mut order_data) =
						serde_json::from_value::<Eip7683OrderData>(order.data.clone())
					{
						order_data.gas_limit_overrides.fill_gas_limit = Some(simulated_gas);
						if let Ok(updated_data) = serde_json::to_value(&order_data) {
							order.data = updated_data;
							tracing::debug!(
								"Updated order gas_limit_overrides.fill_gas_limit to {} units",
								simulated_gas
							);
						}
					}
				}

				self.event_bus
					.publish(SolverEvent::Discovery(DiscoveryEvent::IntentValidated {
						intent_id: intent.id.clone(),
						order: order.clone(),
					}))
					.ok();

				// Run the execution decision BEFORE persisting the order. On Execute,
				// we attach `execution_params` to the order so it lands in storage
				// already resumable from `NeedsExecution`; on Skip, we don't store
				// the order at all (no terminal Skipped status exists, and recovery
				// would otherwise classify it as NeedsExecution + missing params and
				// strand it). Defer keeps its prior behavior — stored without params —
				// pending a separate fix for the Defer recovery path.
				let builder = ContextBuilder::new(
					self.delivery.clone(),
					self.solver_address.clone(),
					self.token_manager.clone(),
					config.clone(),
				);
				let context = builder
					.build_execution_context(&intent)
					.await
					.map_err(|e| IntentError::Service(e.to_string()))?;

				// Reserve the order's Compact deposits at the engine acceptance
				// boundary, before the order is stored/executed or deferred.
				// This is the single authoritative reservation point: it covers
				// every intake path (HTTP /orders, discovery /intent, on-chain
				// events), unlike a service-side reservation which only the
				// /orders path would hit. A compact deposit's on-chain balance is
				// not reduced until the origin claim lands, so without this two
				// orders could draw on the same deposit. The reservation is keyed
				// by the engine order id, expires at the order's `expires`, and is
				// released on terminal states (see
				// `OrderStateMachine::release_compact_reservations`).
				if intent.lock_type == LockType::ResourceLock.as_str() {
					match self.reserve_compact_deposits(&order).await {
						Ok(true) => {},
						Ok(false) => {
							// No deposits to reserve (e.g. all-zero inputs); nothing held.
						},
						Err(reason) => {
							tracing::warn!(
								order_id = %order.id,
								%reason,
								"Intent rejected: compact deposit reservation failed"
							);
							self.event_bus
								.publish(SolverEvent::Discovery(DiscoveryEvent::IntentRejected {
									intent_id: intent.id,
									reason,
								}))
								.ok();
							return Ok(());
						},
					}
				}

				match self.order_service.should_execute(&order, &context).await {
					ExecutionDecision::Execute(params) => {
						order.execution_params = Some(params.clone());
						if let Err(e) = self.state_machine.store_order(&order).await {
							// Release the reservation we just took so the deposit
							// is not stranded until expiry on a failed store.
							self.release_compact_deposits(&order).await;
							return Err(IntentError::Storage(e.to_string()));
						}
						self.event_bus
							.publish(SolverEvent::Order(OrderEvent::Preparing {
								intent: intent.clone(),
								order,
								params,
							}))
							.ok();
					},
					ExecutionDecision::Skip(reason) => {
						// The order will never be stored, so its reservation would
						// otherwise linger until `expires`. Release it now.
						self.release_compact_deposits(&order).await;
						self.event_bus
							.publish(SolverEvent::Order(OrderEvent::Skipped {
								order_id: order.id,
								reason,
							}))
							.ok();
					},
					ExecutionDecision::Defer(duration) => {
						if let Err(e) = self.state_machine.store_order(&order).await {
							self.release_compact_deposits(&order).await;
							return Err(IntentError::Storage(e.to_string()));
						}
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

	/// Reserves the resource-lock order's Compact deposits.
	///
	/// Returns `Ok(true)` when at least one deposit was reserved, `Ok(false)`
	/// when the order has nothing to reserve (no non-zero deposit inputs), and
	/// `Err(reason)` when the deposit could not be derived (chain/config/RPC
	/// failure) or the deposit is oversubscribed by other in-flight orders. The
	/// caller maps `Err` to an `IntentRejected` rejection.
	async fn reserve_compact_deposits(&self, order: &Order) -> Result<bool, String> {
		let order_data: Eip7683OrderData = serde_json::from_value(order.data.clone())
			.map_err(|e| format!("Failed to parse order data for compact reservation: {e}"))?;

		let config = self.dynamic_config.read().await.clone();
		let deposits = crate::handlers::compact_reservation::derive_compact_deposit_reservations(
			&self.delivery,
			&config,
			&order_data,
		)
		.await?;

		if deposits.is_empty() {
			return Ok(false);
		}

		self.compact_reservations
			.reserve_order(&order.id, u64::from(order_data.expires), &deposits)
			.await
			.map_err(|e| match e {
				ReservationError::Oversubscribed { .. } => {
					format!("Compact deposit oversubscribed by in-flight orders: {e}")
				},
				ReservationError::Storage(msg) => {
					format!("Failed to reserve compact deposit: {msg}")
				},
			})?;
		Ok(true)
	}

	/// Best-effort release of an order's Compact reservations.
	///
	/// Used on the engine-side intake paths that abandon an order after it was
	/// reserved (Skip decision, or a storage failure when persisting). Delegates
	/// to the shared
	/// [`crate::handlers::compact_reservation::release_compact_reservations`];
	/// failures only delay reuse of the deposit until the reservation lapses at
	/// the order's `expires`, so they are logged, not propagated.
	async fn release_compact_deposits(&self, order: &Order) {
		crate::handlers::compact_reservation::release_compact_reservations(
			&self.compact_reservations,
			order,
			"intake abandon",
		)
		.await;
	}
}

fn prepare_gas_cap(open_units: u64) -> u64 {
	// Quote economics use the tight configured open units; execution needs bounded headroom for
	// Permit2 cold nonce-bitmap writes and the configured input/output order caps.
	open_units.saturating_mul(125).saturating_add(99) / 100
}

fn validate_source_finality_window(
	order_data: &Eip7683OrderData,
	config: &Config,
	now: u32,
) -> Result<(), String> {
	if !matches!(order_data.lock_type, Some(lock_type) if lock_type.is_escrow()) {
		return Ok(());
	}
	let origin_chain_id = u64::try_from(order_data.origin_chain_id).map_err(|_| {
		format!(
			"Invalid origin chain id for source finality validation: {}",
			order_data.origin_chain_id
		)
	})?;
	let Some(required_delay) = source_finality_expected_delay_seconds(config, origin_chain_id)
	else {
		return Ok(());
	};
	let required_delay = required_delay.saturating_add(config.source_finality.retry_grace_seconds);
	let fill_remaining = order_data.fill_deadline.saturating_sub(now) as u64;
	if fill_remaining < required_delay {
		return Err(format!(
			"Insufficient source finality window: fill_deadline_in={fill_remaining}s required={required_delay}s origin_chain_id={origin_chain_id}"
		));
	}
	Ok(())
}

fn apply_prepare_gas_limit_from_config(order: &mut Order, source: &str, config: &Config) {
	if source != "off-chain" {
		return;
	}

	let Ok(mut order_data) = serde_json::from_value::<Eip7683OrderData>(order.data.clone()) else {
		return;
	};
	let Some(lock_type) = order_data.lock_type else {
		return;
	};
	if matches!(lock_type, LockType::ResourceLock) {
		return;
	}

	let flow_keys = vec![lock_type.as_str().to_string()];
	let gas_units = estimate_quote_gas_units_from_flow_keys(&flow_keys, config);
	order_data.gas_limit_overrides.prepare_gas_limit = Some(prepare_gas_cap(gas_units.open_units));
	if let Ok(updated_data) = serde_json::to_value(&order_data) {
		order.data = updated_data;
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::engine::token_manager::TokenManager;
	use alloy_primitives::U256;
	use mockall::predicate::*;
	use serde_json::json;
	use solver_account::MockAccountInterface;
	use solver_config::ConfigBuilder;
	use solver_delivery::{DeliveryService, FeeParams};
	use solver_order::{MockExecutionStrategy, MockOrderInterface};
	use solver_pricing::{MockPricingInterface, PricingService};
	use solver_storage::{MockStorageInterface, StorageError};
	use solver_types::standards::eip7683::{GasLimitOverrides, LockType};
	use solver_types::utils::tests::builders::{
		Eip7683OrderDataBuilder, IntentBuilder, MandateOutputBuilder, OrderBuilder,
	};
	use solver_types::{Address, DiscoveryEvent, ExecutionParams, Intent, Order, SolverEvent};
	use std::collections::HashMap;
	use std::sync::Arc;
	use std::time::Duration;

	fn create_test_intent() -> Intent {
		IntentBuilder::new().build()
	}

	fn create_test_order() -> Order {
		let order_data = Eip7683OrderDataBuilder::new().build();
		OrderBuilder::new()
			.with_id("test_intent_123".to_string())
			.with_data(serde_json::to_value(&order_data).unwrap())
			.build()
	}

	fn create_test_order_with_expires_in(expires_in_seconds: u32) -> Order {
		let mut order_data = Eip7683OrderDataBuilder::new().build();
		let now = current_timestamp() as u32;
		order_data.expires = now.saturating_add(expires_in_seconds);
		order_data.fill_deadline = now.saturating_add(expires_in_seconds.saturating_sub(1));

		OrderBuilder::new()
			.with_id("test_intent_123".to_string())
			.with_data(serde_json::to_value(&order_data).unwrap())
			.build()
	}

	fn create_test_order_with_short_source_finality_deadline() -> Order {
		let now = current_timestamp() as u32;
		let mut order_data = Eip7683OrderDataBuilder::new().build();
		order_data.lock_type = Some(LockType::Permit2Escrow);
		order_data.origin_chain_id = U256::from(1);
		order_data.fill_deadline = now.saturating_add(60);
		order_data.expires = now.saturating_add(1_800);
		create_test_order_from_data(order_data)
	}

	fn create_test_order_from_data(order_data: Eip7683OrderData) -> Order {
		OrderBuilder::new()
			.with_id("test_intent_123".to_string())
			.with_data(serde_json::to_value(&order_data).unwrap())
			.build()
	}

	fn address20_to_bytes32(address: [u8; 20]) -> [u8; 32] {
		let mut bytes = [0u8; 32];
		bytes[12..].copy_from_slice(&address);
		bytes
	}

	fn create_test_order_with_unsupported_output_token() -> Order {
		let mut order_data = Eip7683OrderDataBuilder::new().build();
		order_data.outputs[0].token = address20_to_bytes32([0x44; 20]);
		create_test_order_from_data(order_data)
	}

	fn create_test_order_with_oversized_callback_data() -> Order {
		let output = MandateOutputBuilder::new()
			.chain_id(U256::from(137))
			.token([0u8; 32])
			.amount(U256::from(95u64))
			.recipient([0u8; 32])
			.call(vec![0xab; u16::MAX as usize + 1])
			.build();
		let order_data = Eip7683OrderDataBuilder::new().outputs(vec![output]).build();
		create_test_order_from_data(order_data)
	}

	fn create_test_address() -> Address {
		Address(vec![0xab; 20])
	}

	fn create_test_config() -> (Arc<RwLock<Config>>, Config) {
		let config = ConfigBuilder::new().build();
		(Arc::new(RwLock::new(config.clone())), config)
	}

	#[test]
	fn validate_source_finality_window_rejects_default_conservative_short_deadline() {
		let config = ConfigBuilder::new().build();
		let now = 1_000;
		let mut order_data = Eip7683OrderDataBuilder::new().build();
		order_data.lock_type = Some(LockType::Permit2Escrow);
		order_data.origin_chain_id = U256::from(1);
		order_data.fill_deadline = now + 300;
		order_data.expires = now + 1_800;

		let err = validate_source_finality_window(&order_data, &config, now)
			.expect_err("default conservative source finality should reject 5 minute deadline");

		assert!(err.contains("Insufficient source finality window"));
		assert!(err.contains("fill_deadline_in=300s"));
		assert!(err.contains("required=1200s"));
		assert!(err.contains("origin_chain_id=1"));
	}

	#[test]
	fn validate_source_finality_window_requires_full_remaining_delay() {
		let config = ConfigBuilder::new().build();
		let now = 1_000;
		let mut order_data = Eip7683OrderDataBuilder::new().build();
		order_data.lock_type = Some(LockType::Permit2Escrow);
		order_data.origin_chain_id = U256::from(1);
		order_data.fill_deadline = now + 1_170;
		order_data.expires = now + 2_400;

		let err = validate_source_finality_window(&order_data, &config, now)
			.expect_err("direct intake must require the full source finality delay");

		assert!(err.contains("Insufficient source finality window"));
		assert!(err.contains("fill_deadline_in=1170s"));
		assert!(err.contains("required=1200s"));
	}

	#[test]
	fn validate_source_finality_window_allows_full_remaining_delay() {
		let config = ConfigBuilder::new().build();
		let now = 1_000;
		let mut order_data = Eip7683OrderDataBuilder::new().build();
		order_data.lock_type = Some(LockType::Permit2Escrow);
		order_data.origin_chain_id = U256::from(1);
		order_data.fill_deadline = now + 1_200;
		order_data.expires = now + 2_400;

		validate_source_finality_window(&order_data, &config, now)
			.expect("full source finality window should be accepted");
	}

	#[test]
	fn validate_source_finality_window_rejects_unrepresentable_origin_chain_id() {
		let config = ConfigBuilder::new().build();
		let now = 1_000;
		let mut order_data = Eip7683OrderDataBuilder::new().build();
		order_data.lock_type = Some(LockType::Permit2Escrow);
		order_data.origin_chain_id = U256::MAX;
		order_data.fill_deadline = now + 1_800;
		order_data.expires = now + 2_400;

		let err = validate_source_finality_window(&order_data, &config, now)
			.expect_err("unrepresentable chain id must not fall back to chain 0");

		assert!(err.contains("Invalid origin chain id"));
		assert!(err.contains(&U256::MAX.to_string()));
	}

	#[test]
	fn validate_source_finality_window_skips_resource_lock_orders() {
		let config = ConfigBuilder::new().build();
		let now = 1_000;
		let mut order_data = Eip7683OrderDataBuilder::new().build();
		order_data.lock_type = Some(LockType::ResourceLock);
		order_data.origin_chain_id = U256::MAX;
		order_data.fill_deadline = now + 300;
		order_data.expires = now + 1_800;

		validate_source_finality_window(&order_data, &config, now)
			.expect("source finality applies only to escrow orders");
	}

	fn create_test_config_with_gas_open(flow_key: &str, open: u64) -> Config {
		let mut config = ConfigBuilder::new().build();
		let mut gas = solver_config::GasConfig {
			flows: HashMap::new(),
			live_fill_estimate_enabled: true,
			live_post_fill_estimate_chain_ids: HashSet::new(),
			max_concurrent_live_fill_estimates_per_chain:
				solver_config::DEFAULT_MAX_CONCURRENT_LIVE_FILL_ESTIMATES_PER_CHAIN,
		};
		gas.flows.insert(
			flow_key.to_string(),
			solver_config::GasFlowUnits {
				open: Some(open),
				fill: Some(150_000),
				post_fill: Some(300_000),
				pre_claim: Some(0),
				claim: Some(150_000),
			},
		);
		config.gas = Some(gas);
		config
	}

	fn create_test_order_with_lock_type(lock_type: LockType) -> Order {
		let mut order_data = Eip7683OrderDataBuilder::new().build();
		order_data.lock_type = Some(lock_type);
		order_data.gas_limit_overrides = GasLimitOverrides::default();
		create_test_order_from_data(order_data)
	}

	#[test]
	fn prepare_gas_cap_adds_execution_headroom() {
		assert_eq!(prepare_gas_cap(146_306), 182_883);
		assert_eq!(prepare_gas_cap(130_254), 162_818);
	}

	#[test]
	fn apply_prepare_gas_limit_sets_permit2_open_units_for_offchain_order() {
		let config = create_test_config_with_gas_open("permit2_escrow", 146_306);
		let mut order = create_test_order_with_lock_type(LockType::Permit2Escrow);

		apply_prepare_gas_limit_from_config(&mut order, "off-chain", &config);

		let order_data: Eip7683OrderData = serde_json::from_value(order.data).unwrap();
		assert_eq!(
			order_data.gas_limit_overrides.prepare_gas_limit,
			Some(182_883)
		);
	}

	#[test]
	fn apply_prepare_gas_limit_sets_eip3009_open_units_for_offchain_order() {
		let config = create_test_config_with_gas_open("eip3009_escrow", 130_254);
		let mut order = create_test_order_with_lock_type(LockType::Eip3009Escrow);

		apply_prepare_gas_limit_from_config(&mut order, "off-chain", &config);

		let order_data: Eip7683OrderData = serde_json::from_value(order.data).unwrap();
		assert_eq!(
			order_data.gas_limit_overrides.prepare_gas_limit,
			Some(162_818)
		);
	}

	#[test]
	fn prepare_gas_limit_uses_quote_open_units_source() {
		let config = create_test_config_with_gas_open("permit2_escrow", 146_306);
		let flow_keys = vec!["permit2_escrow".to_string()];
		let quote_open_units =
			estimate_quote_gas_units_from_flow_keys(&flow_keys, &config).open_units;
		let mut order = create_test_order_with_lock_type(LockType::Permit2Escrow);

		apply_prepare_gas_limit_from_config(&mut order, "off-chain", &config);

		let order_data: Eip7683OrderData = serde_json::from_value(order.data).unwrap();
		assert_eq!(
			order_data.gas_limit_overrides.prepare_gas_limit,
			Some(prepare_gas_cap(quote_open_units))
		);
	}

	#[test]
	fn apply_prepare_gas_limit_ignores_onchain_orders() {
		let config = create_test_config_with_gas_open("permit2_escrow", 146_306);
		let mut order = create_test_order_with_lock_type(LockType::Permit2Escrow);

		apply_prepare_gas_limit_from_config(&mut order, "on-chain", &config);

		let order_data: Eip7683OrderData = serde_json::from_value(order.data).unwrap();
		assert_eq!(order_data.gas_limit_overrides.prepare_gas_limit, None);
	}

	#[test]
	fn apply_prepare_gas_limit_skips_resource_lock() {
		let config = create_test_config_with_gas_open("resource_lock", 123_456);
		let mut order = create_test_order_with_lock_type(LockType::ResourceLock);

		apply_prepare_gas_limit_from_config(&mut order, "off-chain", &config);

		let order_data: Eip7683OrderData = serde_json::from_value(order.data).unwrap();
		assert_eq!(order_data.gas_limit_overrides.prepare_gas_limit, None);
	}

	async fn assert_handle_stores_prepare_gas_limit_for_quote_id(quote_id: Option<String>) {
		let mut mock_storage = MockStorageInterface::new();
		let mut mock_order_interface = MockOrderInterface::new();
		let mut mock_strategy = MockExecutionStrategy::new();

		let intent = IntentBuilder::new()
			.with_source("off-chain")
			.with_quote_id(quote_id.clone())
			.build();
		let solver_address = create_test_address();

		mock_storage
			.expect_exists()
			.with(eq("intents:0xtest_intent_123"))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(false) }));

		if let Some(ref quote_id) = quote_id {
			let quote_key = format!("quotes:{quote_id}");
			mock_storage
				.expect_get_bytes()
				.times(1)
				.returning(move |key| {
					assert_eq!(key, quote_key);
					let key = key.to_string();
					Box::pin(async move { Err(StorageError::NotFound(key)) })
				});
		}

		mock_storage
			.expect_set_bytes()
			.withf(|key: &str, _: &Vec<u8>, _, _| key.starts_with("intents:"))
			.times(1)
			.returning(|_, _, _, _| Box::pin(async move { Ok(()) }));

		mock_storage
			.expect_set_bytes()
			.withf(|key: &str, bytes: &Vec<u8>, _, _| {
				if !key.starts_with("orders:") {
					return false;
				}
				let Ok(order) = serde_json::from_slice::<Order>(bytes) else {
					return false;
				};
				if order.execution_params.is_none() {
					return false;
				}
				let Ok(order_data) = serde_json::from_value::<Eip7683OrderData>(order.data.clone())
				else {
					return false;
				};
				order_data.gas_limit_overrides.prepare_gas_limit == Some(182_883)
			})
			.times(1)
			.returning(|_, _, _, _| Box::pin(async move { Ok(()) }));

		mock_order_interface
			.expect_validate_and_create_order()
			.times(1)
			.returning(move |_, _, _, _, _, _| {
				Box::pin(
					async move { Ok(create_test_order_with_lock_type(LockType::Permit2Escrow)) },
				)
			});
		mock_order_interface
			.expect_generate_fill_transaction()
			.times(1)
			.returning(|_, _| {
				Box::pin(async move {
					Ok(solver_types::Transaction {
						to: Some(solver_types::Address(vec![0u8; 20])),
						data: vec![],
						value: U256::ZERO,
						chain_id: 137,
						nonce: None,
						gas_limit: Some(200000),
						gas_price: None,
						max_fee_per_gas: None,
						max_priority_fee_per_gas: None,
					})
				})
			});

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
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20, 60));
		let token_manager = Arc::new(TokenManager::new(
			Default::default(),
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let cost_profit_service = if quote_id.is_some() {
			let mut mock_quote_storage = MockStorageInterface::new();
			mock_quote_storage.expect_get_bytes().returning(|key| {
				let key = key.to_string();
				Box::pin(async move { Err(StorageError::NotFound(key)) })
			});
			create_mock_cost_profit_service_with_storage(mock_quote_storage)
		} else {
			create_mock_cost_profit_service()
		};
		let static_config = create_test_config_with_gas_open("permit2_escrow", 146_306);
		let config = Arc::new(RwLock::new(static_config.clone()));

		let handler = IntentHandler::new(
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			solver_address,
			token_manager,
			cost_profit_service,
			config,
			&static_config,
		);

		let result = handler.handle(intent).await;
		assert!(result.is_ok());
	}

	#[tokio::test]
	async fn handle_direct_offchain_intent_stores_prepare_gas_limit() {
		assert_handle_stores_prepare_gas_limit_for_quote_id(None).await;
	}

	#[tokio::test]
	async fn handle_quote_offchain_intent_stores_prepare_gas_limit() {
		assert_handle_stores_prepare_gas_limit_for_quote_id(Some("quote-123".to_string())).await;
	}

	fn create_test_config_with_broadcaster() -> Arc<RwLock<Config>> {
		let mut config = ConfigBuilder::new().build();
		let broadcaster = json!({
			"oracles": {
				"input": {
					"1": ["0x0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A"]
				},
				"output": {
					"137": ["0x1111111111111111111111111111111111111111"]
				}
			},
			"routes": {
				"1": [137]
			},
			"proof_wait_time_seconds": 30,
			"storage_proof_timeout_seconds": 30,
			"default_finality_blocks": 20
		});
		config
			.settlement
			.implementations
			.insert("broadcaster".to_string(), broadcaster);
		Arc::new(RwLock::new(config))
	}

	fn create_test_config_with_hyperlane_min_window(
		min_window_seconds: u64,
	) -> Arc<RwLock<Config>> {
		let mut config = ConfigBuilder::new().build();
		let hyperlane = json!({
			"oracles": {
				"input": {
					"1": ["0x0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A"]
				},
				"output": {
					"137": ["0x1111111111111111111111111111111111111111"]
				}
			},
			"routes": {
				"1": [137]
			},
			"intent_min_expiry_seconds": min_window_seconds
		});

		config
			.settlement
			.implementations
			.insert("hyperlane".to_string(), hyperlane);
		Arc::new(RwLock::new(config))
	}

	fn create_test_config_with_broadcaster_and_hyperlane_min_window(
		hyperlane_min_window_seconds: u64,
	) -> Config {
		let mut config = ConfigBuilder::new().build();

		let broadcaster = json!({
			"oracles": {
				"input": {
					"1": ["0x0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A"]
				},
				"output": {
					"137": ["0x1111111111111111111111111111111111111111"]
				}
			},
			"routes": {
				"1": [137]
			},
			"proof_wait_time_seconds": 30,
			"storage_proof_timeout_seconds": 30,
			"default_finality_blocks": 20
		});
		let hyperlane = json!({
			"oracles": {
				"input": {
					"1": ["0x0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A"]
				},
				"output": {
					"137": ["0x1111111111111111111111111111111111111111"]
				}
			},
			"routes": {
				"1": [137]
			},
			"intent_min_expiry_seconds": hyperlane_min_window_seconds
		});

		config
			.settlement
			.implementations
			.insert("broadcaster".to_string(), broadcaster);
		config
			.settlement
			.implementations
			.insert("hyperlane".to_string(), hyperlane);

		config
	}

	#[test]
	fn test_estimate_required_expiry_window_respects_pinned_settlement() {
		let config = create_test_config_with_broadcaster_and_hyperlane_min_window(500);

		let order_data = Eip7683OrderDataBuilder::new().build();

		let pinned_broadcaster = estimate_required_expiry_window_seconds(
			&order_data,
			&config.settlement.implementations,
			config.settlement.settlement_poll_interval_seconds,
			Some("broadcaster"),
		)
		.expect("expected broadcaster estimate");
		let unpinned = estimate_required_expiry_window_seconds(
			&order_data,
			&config.settlement.implementations,
			config.settlement.settlement_poll_interval_seconds,
			None,
		)
		.expect("expected unpinned estimate");

		assert!(
			pinned_broadcaster.1.contains("broadcaster"),
			"expected broadcaster breakdown when pinned, got {}",
			pinned_broadcaster.1
		);
		assert!(
			!pinned_broadcaster.1.contains("hyperlane"),
			"pinned estimate should not use hyperlane window: {}",
			pinned_broadcaster.1
		);
		assert!(
			unpinned.0 >= 500,
			"unpinned estimate should include hyperlane explicit min window, got {}",
			unpinned.0
		);
		assert!(
			pinned_broadcaster.0 < unpinned.0,
			"pinned broadcaster estimate should be below unpinned max window: pinned={}, unpinned={}",
			pinned_broadcaster.0,
			unpinned.0
		);
	}

	fn create_mock_cost_profit_service() -> Arc<CostProfitService> {
		create_mock_cost_profit_service_with_storage(MockStorageInterface::new())
	}

	fn create_mock_cost_profit_service_with_storage(
		mock_storage: MockStorageInterface,
	) -> Arc<CostProfitService> {
		// Create mock pricing service with expected method responses
		let mut mock_pricing = MockPricingInterface::new();

		mock_pricing
			.expect_wei_to_currency()
			.returning(|_, _| Box::pin(async move { Ok("0.01".to_string()) }));

		// Mock convert_asset calls - return different prices for input vs output tokens
		mock_pricing
			.expect_convert_asset()
			.returning(|token_symbol, _, amount| {
				let token_symbol = token_symbol.to_string();
				let amount_str = amount.to_string();
				Box::pin(async move {
					// Parse the amount and multiply by token price
					let amount_decimal = amount_str.parse::<f64>().unwrap_or(0.0);
					let price_per_token = match token_symbol.as_str() {
						"INPUT" => 1.0,  // $1 per INPUT token
						"OUTPUT" => 1.0, // $1 per OUTPUT token
						_ => 1.0,
					};
					let total_usd = amount_decimal * price_per_token;
					Ok(total_usd.to_string())
				})
			});

		// Mock get_supported_pairs - return the token pairs we support
		mock_pricing.expect_get_supported_pairs().returning(|| {
			Box::pin(async move {
				vec![
					solver_types::TradingPair {
						base: "INPUT".to_string(),
						quote: "USD".to_string(),
					},
					solver_types::TradingPair {
						base: "OUTPUT".to_string(),
						quote: "USD".to_string(),
					},
				]
			})
		});

		let pricing_service = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));

		// Create mock delivery service with chain implementations
		let mut delivery_impls = HashMap::new();

		let mut mock_delivery_1 = solver_delivery::MockDeliveryInterface::new();
		mock_delivery_1
			.expect_get_fee_params()
			.returning(|chain_id| {
				Box::pin(async move { Ok(FeeParams::legacy(chain_id, 20_000u128)) })
			});
		mock_delivery_1
			.expect_get_block_number()
			.returning(|_| Box::pin(async move { Ok(1000000u64) }));
		mock_delivery_1
			.expect_estimate_gas()
			.returning(|_| Box::pin(async move { Ok(200000u64) }));

		let mut mock_delivery_137 = solver_delivery::MockDeliveryInterface::new();
		mock_delivery_137
			.expect_get_fee_params()
			.returning(|chain_id| {
				Box::pin(async move { Ok(FeeParams::legacy(chain_id, 20_000u128)) })
			});
		mock_delivery_137
			.expect_get_block_number()
			.returning(|_| Box::pin(async move { Ok(1000000u64) }));
		mock_delivery_137
			.expect_estimate_gas()
			.returning(|_| Box::pin(async move { Ok(200000u64) }));

		delivery_impls.insert(
			1u64,
			Arc::new(mock_delivery_1) as Arc<dyn solver_delivery::DeliveryInterface>,
		);
		delivery_impls.insert(
			137u64,
			Arc::new(mock_delivery_137) as Arc<dyn solver_delivery::DeliveryInterface>,
		);

		let delivery_service = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));

		// Create tokens that match the test order data exactly
		let input_token = solver_types::utils::tests::builders::TokenConfigBuilder::new()
			.address({
				// Convert U256::from(1000) to Address - token 1000 = 0x3e8
				let mut addr_bytes = [0u8; 20];
				addr_bytes[18] = 0x03; // 0x03e8 = 1000
				addr_bytes[19] = 0xe8;
				solver_types::Address(addr_bytes.to_vec())
			})
			.symbol("INPUT".to_string())
			.decimals(18)
			.build();

		let native_token = solver_types::utils::tests::builders::TokenConfigBuilder::new()
			.address(solver_types::Address(vec![0u8; 20]))
			.symbol("ETH".to_string())
			.decimals(18)
			.build();

		let output_token = solver_types::utils::tests::builders::TokenConfigBuilder::new()
			.address(solver_types::Address(vec![0u8; 20])) // Zero address for output
			.symbol("OUTPUT".to_string())
			.decimals(18)
			.build();

		// Create networks config with matching token addresses
		let networks_config = solver_types::utils::tests::builders::NetworksConfigBuilder::new()
			.add_network(
				1,
				solver_types::utils::tests::builders::NetworkConfigBuilder::new()
					.tokens(vec![native_token, input_token])
					.build(),
			)
			.add_network(
				137,
				solver_types::utils::tests::builders::NetworkConfigBuilder::new()
					.tokens(vec![output_token])
					.build(),
			)
			.build();

		let token_manager = Arc::new(TokenManager::new(
			networks_config,
			delivery_service.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let mut mock_settlement = solver_settlement::MockSettlementInterface::new();
		mock_settlement
			.expect_quote_post_fill_fee()
			.returning(|_| Box::pin(async { Ok(None) }));
		let settlement_service = Arc::new(solver_settlement::SettlementService::new(
			HashMap::from([(
				"mock".to_string(),
				Box::new(mock_settlement) as Box<dyn solver_settlement::SettlementInterface>,
			)]),
			"mock".to_string(),
			1,
		));

		Arc::new(CostProfitService::new(
			pricing_service,
			delivery_service,
			token_manager,
			Arc::new(StorageService::new(Box::new(mock_storage))),
			settlement_service,
		))
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
			.with(eq("intents:0xtest_intent_123"))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(false) }));

		mock_storage
			.expect_set_bytes()
			.times(2) // Once for intent, once for order
			.returning(|_, _, _, _| Box::pin(async move { Ok(()) }));

		mock_order_interface
			.expect_validate_and_create_order()
			.times(1)
			.returning(move |_, _, _, _, _, _| Box::pin(async move { Ok(create_test_order()) }));

		// Add expectation for generate_fill_transaction (used for callback simulation)
		mock_order_interface
			.expect_generate_fill_transaction()
			.times(1)
			.returning(|_, _| {
				Box::pin(async move {
					Ok(solver_types::Transaction {
						to: Some(solver_types::Address(vec![0u8; 20])),
						data: vec![],
						value: U256::ZERO,
						chain_id: 137,
						nonce: None,
						gas_limit: Some(200000),
						gas_price: None,
						max_fee_per_gas: None,
						max_priority_fee_per_gas: None,
					})
				})
			});

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
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20, 60));
		let token_manager = Arc::new(TokenManager::new(
			Default::default(), // empty networks config
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let cost_profit_service = create_mock_cost_profit_service();
		let (config, static_config) = create_test_config();

		let handler = IntentHandler::new(
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			solver_address.clone(),
			token_manager,
			cost_profit_service,
			config,
			&static_config,
		);

		let result = handler.handle(intent).await;
		assert!(result.is_ok());
	}

	#[tokio::test]
	async fn test_handle_intent_rejects_unsupported_output_token_before_fill_simulation() {
		let mut mock_storage = MockStorageInterface::new();
		let mut mock_order_interface = MockOrderInterface::new();
		let mut mock_strategy = MockExecutionStrategy::new();

		let intent = IntentBuilder::new().with_source("off-chain").build();
		let solver_address = create_test_address();

		mock_storage
			.expect_exists()
			.with(eq("intents:0xtest_intent_123"))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(false) }));
		mock_storage
			.expect_set_bytes()
			.times(1)
			.returning(|_, _, _, _| Box::pin(async move { Ok(()) }));

		mock_order_interface
			.expect_validate_and_create_order()
			.times(1)
			.returning(move |_, _, _, _, _, _| {
				Box::pin(async move { Ok(create_test_order_with_unsupported_output_token()) })
			});
		mock_order_interface
			.expect_generate_fill_transaction()
			.times(0);
		mock_strategy.expect_should_execute().times(0);

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
		let mut receiver = event_bus.subscribe();
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20, 60));
		let token_manager = Arc::new(TokenManager::new(
			Default::default(),
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let cost_profit_service = create_mock_cost_profit_service();
		let (config, static_config) = create_test_config();

		let handler = IntentHandler::new(
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			solver_address,
			token_manager,
			cost_profit_service,
			config,
			&static_config,
		);

		handler
			.handle(intent)
			.await
			.expect("handler should skip unsupported token intent without error");

		match receiver.recv().await.unwrap() {
			SolverEvent::Order(OrderEvent::Skipped { reason, .. }) => {
				assert!(reason.contains("Token not supported"));
			},
			other => panic!("Expected OrderEvent::Skipped, got {other:?}"),
		}
	}

	#[tokio::test]
	async fn test_handle_intent_skips_short_source_finality_deadline() {
		let mut mock_storage = MockStorageInterface::new();
		let mut mock_order_interface = MockOrderInterface::new();
		let mut mock_strategy = MockExecutionStrategy::new();

		let intent = IntentBuilder::new().with_source("off-chain").build();
		let solver_address = create_test_address();

		mock_storage
			.expect_exists()
			.with(eq("intents:0xtest_intent_123"))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(false) }));
		mock_storage
			.expect_set_bytes()
			.times(1)
			.returning(|_, _, _, _| Box::pin(async move { Ok(()) }));

		mock_order_interface
			.expect_validate_and_create_order()
			.times(1)
			.returning(move |_, _, _, _, _, _| {
				Box::pin(async move { Ok(create_test_order_with_short_source_finality_deadline()) })
			});
		mock_order_interface
			.expect_generate_fill_transaction()
			.times(0);
		mock_strategy.expect_should_execute().times(0);

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
		let mut receiver = event_bus.subscribe();
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20, 60));
		let token_manager = Arc::new(TokenManager::new(
			Default::default(),
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let cost_profit_service = create_mock_cost_profit_service();
		let (config, static_config) = create_test_config();

		let handler = IntentHandler::new(
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			solver_address,
			token_manager,
			cost_profit_service,
			config,
			&static_config,
		);

		handler
			.handle(intent)
			.await
			.expect("handler should skip source-finality-impossible intent without error");

		match receiver.recv().await.unwrap() {
			SolverEvent::Order(OrderEvent::Skipped { reason, .. }) => {
				assert!(reason.contains("Insufficient source finality window"));
			},
			other => panic!("Expected OrderEvent::Skipped, got {other:?}"),
		}
	}

	#[tokio::test]
	async fn test_handle_intent_rejects_oversized_callback_before_fill_simulation() {
		let mut mock_storage = MockStorageInterface::new();
		let mut mock_order_interface = MockOrderInterface::new();
		let mut mock_strategy = MockExecutionStrategy::new();

		let intent = create_test_intent();
		let solver_address = create_test_address();

		mock_storage
			.expect_exists()
			.with(eq("intents:0xtest_intent_123"))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(false) }));
		mock_storage
			.expect_set_bytes()
			.times(1)
			.returning(|_, _, _, _| Box::pin(async move { Ok(()) }));

		mock_order_interface
			.expect_validate_and_create_order()
			.times(1)
			.returning(move |_, _, _, _, _, _| {
				Box::pin(async move { Ok(create_test_order_with_oversized_callback_data()) })
			});
		mock_order_interface
			.expect_generate_fill_transaction()
			.times(0);
		mock_strategy.expect_should_execute().times(0);

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
		let mut receiver = event_bus.subscribe();
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20, 60));
		let token_manager = Arc::new(TokenManager::new(
			Default::default(),
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let cost_profit_service = create_mock_cost_profit_service();
		let (config, static_config) = create_test_config();

		let handler = IntentHandler::new(
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			solver_address,
			token_manager,
			cost_profit_service,
			config,
			&static_config,
		);

		handler
			.handle(intent)
			.await
			.expect("handler should skip oversized callback intent without error");

		match receiver.recv().await.unwrap() {
			SolverEvent::Order(OrderEvent::Skipped { reason, .. }) => {
				assert!(reason.contains("callbackData is too large"));
			},
			other => panic!("Expected OrderEvent::Skipped, got {other:?}"),
		}
	}

	#[tokio::test]
	async fn test_handle_intent_duplicate_skipped() {
		let mut mock_storage = MockStorageInterface::new();

		let intent = create_test_intent();
		let solver_address = create_test_address();

		// Setup expectations - intent already exists
		mock_storage
			.expect_exists()
			.with(eq("intents:0xtest_intent_123"))
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
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20, 60));
		let token_manager = Arc::new(TokenManager::new(
			Default::default(),
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let cost_profit_service = create_mock_cost_profit_service();
		let (config, static_config) = create_test_config();

		let handler = IntentHandler::new(
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			solver_address,
			token_manager,
			cost_profit_service,
			config,
			&static_config,
		);

		let result = handler.handle(intent).await;
		assert!(result.is_ok());
	}

	#[tokio::test]
	async fn test_handle_intent_dedupes_with_prefixed_storage_key_for_unprefixed_input() {
		// Cross-restart dedupe must be tolerant of `0x` prefix variance from
		// discovery sources. The handler normalizes intent.id at lookup time so
		// that the storage `exists` check uses the same key that `store` writes
		// under. Without normalization, an intent stored under "0xabc..." would
		// not be found when the next discovery emits "abc..." and the handler
		// would proceed to overwrite the existing order.
		let mut mock_storage = MockStorageInterface::new();
		let intent = create_test_intent(); // id = "test_intent_123" (no 0x prefix)
		let solver_address = create_test_address();

		// `exists` MUST be called with the prefixed key, matching how `store` writes it.
		mock_storage
			.expect_exists()
			.with(eq("intents:0xtest_intent_123"))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(true) }));

		// Dedupe path: handler returns early; no further storage writes.
		mock_storage.expect_set_bytes().times(0);

		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let order_service = Arc::new(OrderService::new(
			HashMap::new(),
			Box::new(MockExecutionStrategy::new()),
		));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let event_bus = EventBus::new(100);
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20, 60));
		let token_manager = Arc::new(TokenManager::new(
			Default::default(),
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let cost_profit_service = create_mock_cost_profit_service();
		let (config, static_config) = create_test_config();

		let handler = IntentHandler::new(
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			solver_address,
			token_manager,
			cost_profit_service,
			config,
			&static_config,
		);

		let result = handler.handle(intent).await;
		assert!(result.is_ok());
	}

	#[tokio::test]
	async fn test_handle_intent_dedupes_when_input_id_already_has_0x_prefix() {
		// Symmetric case: an incoming intent whose id is *already* prefixed must
		// look up under the same canonical key as the unprefixed form. This proves
		// the normalization is idempotent.
		let mut mock_storage = MockStorageInterface::new();
		let intent = IntentBuilder::new()
			.with_id("0xtest_intent_123".to_string())
			.build();
		let solver_address = create_test_address();

		mock_storage
			.expect_exists()
			.with(eq("intents:0xtest_intent_123"))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(true) }));
		mock_storage.expect_set_bytes().times(0);

		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let order_service = Arc::new(OrderService::new(
			HashMap::new(),
			Box::new(MockExecutionStrategy::new()),
		));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let event_bus = EventBus::new(100);
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20, 60));
		let token_manager = Arc::new(TokenManager::new(
			Default::default(),
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let cost_profit_service = create_mock_cost_profit_service();
		let (config, static_config) = create_test_config();

		let handler = IntentHandler::new(
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			solver_address,
			token_manager,
			cost_profit_service,
			config,
			&static_config,
		);

		let result = handler.handle(intent).await;
		assert!(result.is_ok());
	}

	#[tokio::test]
	async fn test_handle_intent_execute_stores_order_with_execution_params_attached() {
		// When should_execute returns Execute(params), the order MUST be persisted
		// with execution_params already attached. Otherwise a crash between
		// store_order and the prepare handler's params write strands the order on
		// recovery (NeedsExecution + missing params, no resumption path).
		let mut mock_storage = MockStorageInterface::new();
		let mut mock_order_interface = MockOrderInterface::new();
		let mut mock_strategy = MockExecutionStrategy::new();

		let intent = create_test_intent();
		let solver_address = create_test_address();

		mock_storage
			.expect_exists()
			.with(eq("intents:0xtest_intent_123"))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(false) }));

		// Intent write: any bytes, must happen once.
		mock_storage
			.expect_set_bytes()
			.withf(|key: &str, _: &Vec<u8>, _, _| key.starts_with("intents:"))
			.times(1)
			.returning(|_, _, _, _| Box::pin(async move { Ok(()) }));

		// Order write: MUST contain execution_params. Otherwise no expectation
		// matches and mockall panics.
		mock_storage
			.expect_set_bytes()
			.withf(|key: &str, bytes: &Vec<u8>, _, _| {
				if !key.starts_with("orders:") {
					return false;
				}
				matches!(
					serde_json::from_slice::<Order>(bytes),
					Ok(o) if o.execution_params.is_some()
				)
			})
			.times(1)
			.returning(|_, _, _, _| Box::pin(async move { Ok(()) }));

		mock_order_interface
			.expect_validate_and_create_order()
			.times(1)
			.returning(move |_, _, _, _, _, _| Box::pin(async move { Ok(create_test_order()) }));
		mock_order_interface
			.expect_generate_fill_transaction()
			.times(1)
			.returning(|_, _| {
				Box::pin(async move {
					Ok(solver_types::Transaction {
						to: Some(solver_types::Address(vec![0u8; 20])),
						data: vec![],
						value: U256::ZERO,
						chain_id: 137,
						nonce: None,
						gas_limit: Some(200000),
						gas_price: None,
						max_fee_per_gas: None,
						max_priority_fee_per_gas: None,
					})
				})
			});

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
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20, 60));
		let token_manager = Arc::new(TokenManager::new(
			Default::default(),
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let cost_profit_service = create_mock_cost_profit_service();
		let (config, static_config) = create_test_config();

		let handler = IntentHandler::new(
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			solver_address,
			token_manager,
			cost_profit_service,
			config,
			&static_config,
		);

		let result = handler.handle(intent).await;
		assert!(result.is_ok());
	}

	#[tokio::test]
	async fn test_handle_intent_skip_does_not_store_order() {
		// The Skip path does not write to the Orders namespace. A stored skipped
		// order would sit in Created with no execution_params and trip the
		// recovery NeedsExecution + missing-params strand path the same way a
		// crashed Execute path used to.
		let mut mock_storage = MockStorageInterface::new();
		let mut mock_order_interface = MockOrderInterface::new();
		let mut mock_strategy = MockExecutionStrategy::new();

		let intent = create_test_intent();
		let solver_address = create_test_address();

		mock_storage
			.expect_exists()
			.with(eq("intents:0xtest_intent_123"))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(false) }));

		// Only the intent should be persisted; no Orders write.
		mock_storage
			.expect_set_bytes()
			.withf(|key: &str, _: &Vec<u8>, _, _| key.starts_with("intents:"))
			.times(1)
			.returning(|_, _, _, _| Box::pin(async move { Ok(()) }));

		// Any write to "orders:" is a regression — fail-match so mockall panics.
		mock_storage
			.expect_set_bytes()
			.withf(|key: &str, _: &Vec<u8>, _, _| key.starts_with("orders:"))
			.times(0);

		mock_order_interface
			.expect_validate_and_create_order()
			.times(1)
			.returning(move |_, _, _, _, _, _| Box::pin(async move { Ok(create_test_order()) }));
		mock_order_interface
			.expect_generate_fill_transaction()
			.times(1)
			.returning(|_, _| {
				Box::pin(async move {
					Ok(solver_types::Transaction {
						to: Some(solver_types::Address(vec![0u8; 20])),
						data: vec![],
						value: U256::ZERO,
						chain_id: 137,
						nonce: None,
						gas_limit: Some(200000),
						gas_price: None,
						max_fee_per_gas: None,
						max_priority_fee_per_gas: None,
					})
				})
			});

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
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20, 60));
		let token_manager = Arc::new(TokenManager::new(
			Default::default(),
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let cost_profit_service = create_mock_cost_profit_service();
		let (config, static_config) = create_test_config();

		let handler = IntentHandler::new(
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			solver_address,
			token_manager,
			cost_profit_service,
			config,
			&static_config,
		);

		let result = handler.handle(intent).await;
		assert!(result.is_ok());
	}

	#[tokio::test]
	async fn test_handle_intent_rejects_before_storage_when_intake_disabled() {
		let mut mock_storage = MockStorageInterface::new();
		mock_storage.expect_exists().times(0);
		mock_storage.expect_set_bytes().times(0);

		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let order_service = Arc::new(OrderService::new(
			HashMap::new(),
			Box::new(MockExecutionStrategy::new()),
		));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let event_bus = EventBus::new(100);
		let mut event_receiver = event_bus.subscribe();
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20, 60));
		let token_manager = Arc::new(TokenManager::new(
			Default::default(),
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let cost_profit_service = create_mock_cost_profit_service();
		let (config, static_config) = create_test_config();
		config.write().await.solver.ingress_mode = solver_config::SolverIngressMode::IntakeDisabled;
		let intent = create_test_intent();
		let intent_id = intent.id.clone();

		let handler = IntentHandler::new(
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			create_test_address(),
			token_manager,
			cost_profit_service,
			config,
			&static_config,
		);

		handler
			.handle(intent)
			.await
			.expect("handler should not error");

		let event = tokio::time::timeout(Duration::from_millis(100), event_receiver.recv())
			.await
			.expect("expected rejection event")
			.expect("event bus should return event");

		assert!(matches!(
			event,
			SolverEvent::Discovery(DiscoveryEvent::IntentRejected { intent_id: id, reason })
				if id == intent_id && reason.contains("intake")
		));
	}

	#[tokio::test]
	async fn test_handle_intent_rejects_resource_lock_before_storage_when_disabled() {
		let mut mock_storage = MockStorageInterface::new();
		mock_storage.expect_exists().times(0);
		mock_storage.expect_set_bytes().times(0);

		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let order_service = Arc::new(OrderService::new(
			HashMap::new(),
			Box::new(MockExecutionStrategy::new()),
		));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let event_bus = EventBus::new(100);
		let mut event_receiver = event_bus.subscribe();
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20, 60));
		let token_manager = Arc::new(TokenManager::new(
			Default::default(),
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let cost_profit_service = create_mock_cost_profit_service();
		let (config, static_config) = create_test_config();
		let intent = IntentBuilder::new()
			.with_lock_type(LockType::ResourceLock.to_string())
			.build();
		let intent_id = intent.id.clone();

		let handler = IntentHandler::new(
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			create_test_address(),
			token_manager,
			cost_profit_service,
			config,
			&static_config,
		);

		handler
			.handle(intent)
			.await
			.expect("handler should not error");

		let event = tokio::time::timeout(Duration::from_millis(100), event_receiver.recv())
			.await
			.expect("expected rejection event")
			.expect("event bus should return event");

		assert!(matches!(
			event,
			SolverEvent::Discovery(DiscoveryEvent::IntentRejected { intent_id: id, reason })
				if id == intent_id && reason.contains("ResourceLock orders are disabled")
		));
	}

	#[tokio::test]
	async fn test_handle_intent_allows_resource_lock_when_enabled() {
		let mut mock_storage = MockStorageInterface::new();
		let mut mock_order_interface = MockOrderInterface::new();

		let intent = IntentBuilder::new()
			.with_lock_type(LockType::ResourceLock.to_string())
			.build();
		let intent_id = intent.id.clone();
		let solver_address = create_test_address();

		mock_storage
			.expect_exists()
			.with(eq("intents:0xtest_intent_123"))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(false) }));

		mock_storage
			.expect_set_bytes()
			.times(1)
			.returning(|_, _, _, _| Box::pin(async move { Ok(()) }));

		mock_order_interface
			.expect_validate_and_create_order()
			.times(1)
			.withf(|_, _, lock_type, _, _, _| lock_type == LockType::ResourceLock.as_str())
			.returning(|_, _, _, _, _, _| {
				Box::pin(async move {
					Err(solver_order::OrderError::ValidationFailed(
						"resource lock reached validation".to_string(),
					))
				})
			});

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
		let mut event_receiver = event_bus.subscribe();
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20, 60));
		let token_manager = Arc::new(TokenManager::new(
			Default::default(),
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let cost_profit_service = create_mock_cost_profit_service();
		let (config, static_config) = create_test_config();
		config.write().await.solver.resource_lock_enabled = true;

		let handler = IntentHandler::new(
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			solver_address,
			token_manager,
			cost_profit_service,
			config,
			&static_config,
		);

		handler
			.handle(intent)
			.await
			.expect("handler should not error");

		let event = tokio::time::timeout(Duration::from_millis(100), event_receiver.recv())
			.await
			.expect("expected validation failure event")
			.expect("event bus should return event");

		assert!(matches!(
			event,
			SolverEvent::Discovery(DiscoveryEvent::IntentRejected { intent_id: id, reason })
				if id == intent_id && reason.contains("resource lock reached validation")
		));
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
			.with(eq("intents:0xtest_intent_123"))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(false) }));

		mock_order_interface
			.expect_validate_and_create_order()
			.times(1)
			.returning(|_, _, _, _, _, _| {
				Box::pin(async move {
					Err(solver_order::OrderError::ValidationFailed(
						"Invalid intent".to_string(),
					))
				})
			});

		// Intent is always stored first for deduplication, even if validation fails later
		mock_storage
			.expect_set_bytes()
			.times(1)
			.returning(|_, _, _, _| Box::pin(async move { Ok(()) }));

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
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20, 60));
		let token_manager = Arc::new(TokenManager::new(
			Default::default(),
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let (config, static_config) = create_test_config();

		let cost_profit_service = create_mock_cost_profit_service();

		let handler = IntentHandler::new(
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			solver_address,
			token_manager,
			cost_profit_service,
			config,
			&static_config,
		);

		let result = handler.handle(intent).await;
		assert!(result.is_ok()); // Handler doesn't fail on validation errors
	}

	#[tokio::test]
	async fn test_handle_intent_skip_due_to_broadcaster_expiry_budget() {
		let mut mock_storage = MockStorageInterface::new();
		let mut mock_order_interface = MockOrderInterface::new();
		let mut mock_strategy = MockExecutionStrategy::new();

		let intent = create_test_intent();
		let solver_address = create_test_address();

		mock_storage
			.expect_exists()
			.with(eq("intents:0xtest_intent_123"))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(false) }));

		// Only the intent should be stored (order is skipped before order storage).
		mock_storage
			.expect_set_bytes()
			.times(1)
			.returning(|_, _, _, _| Box::pin(async move { Ok(()) }));

		mock_order_interface
			.expect_validate_and_create_order()
			.times(1)
			.returning(move |_, _, _, _, _, _| {
				Box::pin(async move { Ok(create_test_order_with_expires_in(60)) })
			});

		// Skip happens before simulation + strategy execution.
		mock_order_interface
			.expect_generate_fill_transaction()
			.times(0);
		mock_strategy.expect_should_execute().times(0);

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
		let mut receiver = event_bus.subscribe();

		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20, 60));
		let token_manager = Arc::new(TokenManager::new(
			Default::default(),
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let config = create_test_config_with_broadcaster();
		let static_config = config.read().await.clone();
		let cost_profit_service = create_mock_cost_profit_service();

		let handler = IntentHandler::new(
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			solver_address,
			token_manager,
			cost_profit_service,
			config,
			&static_config,
		);

		let result = handler.handle(intent).await;
		assert!(result.is_ok());

		match receiver.recv().await.unwrap() {
			SolverEvent::Order(OrderEvent::Skipped { reason, .. }) => {
				assert!(reason.contains("Insufficient settlement window"));
				assert!(reason.contains("broadcaster:"));
			},
			other => panic!("Expected OrderEvent::Skipped, got {other:?}"),
		}
	}

	#[tokio::test]
	async fn test_handle_intent_skip_due_to_explicit_settlement_min_window() {
		let mut mock_storage = MockStorageInterface::new();
		let mut mock_order_interface = MockOrderInterface::new();
		let mut mock_strategy = MockExecutionStrategy::new();

		let intent = create_test_intent();
		let solver_address = create_test_address();

		mock_storage
			.expect_exists()
			.with(eq("intents:0xtest_intent_123"))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(false) }));
		mock_storage
			.expect_set_bytes()
			.times(1)
			.returning(|_, _, _, _| Box::pin(async move { Ok(()) }));

		mock_order_interface
			.expect_validate_and_create_order()
			.times(1)
			.returning(move |_, _, _, _, _, _| {
				Box::pin(async move { Ok(create_test_order_with_expires_in(100)) })
			});
		mock_order_interface
			.expect_generate_fill_transaction()
			.times(0);
		mock_strategy.expect_should_execute().times(0);

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
		let mut receiver = event_bus.subscribe();
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20, 60));
		let token_manager = Arc::new(TokenManager::new(
			Default::default(),
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let config = create_test_config_with_hyperlane_min_window(500);
		let static_config = config.read().await.clone();
		let cost_profit_service = create_mock_cost_profit_service();

		let handler = IntentHandler::new(
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			solver_address,
			token_manager,
			cost_profit_service,
			config,
			&static_config,
		);

		let result = handler.handle(intent).await;
		assert!(result.is_ok());

		match receiver.recv().await.unwrap() {
			SolverEvent::Order(OrderEvent::Skipped { reason, .. }) => {
				assert!(reason.contains("Insufficient settlement window"));
				assert!(reason.contains("hyperlane: explicit intent_min_expiry_seconds=500s"));
			},
			other => panic!("Expected OrderEvent::Skipped, got {other:?}"),
		}
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
			.with(eq("intents:0xtest_intent_123"))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(false) }));

		// Skip path stores only the intent (no order write).
		// See test_handle_intent_skip_does_not_store_order for the strict per-call assertion.
		mock_storage
			.expect_set_bytes()
			.times(1)
			.returning(|_, _, _, _| Box::pin(async move { Ok(()) }));

		mock_order_interface
			.expect_validate_and_create_order()
			.times(1)
			.returning(move |_, _, _, _, _, _| Box::pin(async move { Ok(create_test_order()) }));

		// Add expectation for generate_fill_transaction (used for callback simulation)
		mock_order_interface
			.expect_generate_fill_transaction()
			.times(1)
			.returning(|_, _| {
				Box::pin(async move {
					Ok(solver_types::Transaction {
						to: Some(solver_types::Address(vec![0u8; 20])),
						data: vec![],
						value: U256::ZERO,
						chain_id: 137,
						nonce: None,
						gas_limit: Some(200000),
						gas_price: None,
						max_fee_per_gas: None,
						max_priority_fee_per_gas: None,
					})
				})
			});

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
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20, 60));
		let token_manager = Arc::new(TokenManager::new(
			Default::default(),
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let (config, static_config) = create_test_config();

		let cost_profit_service = create_mock_cost_profit_service();

		let handler = IntentHandler::new(
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			solver_address,
			token_manager,
			cost_profit_service,
			config,
			&static_config,
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
			.with(eq("intents:0xtest_intent_123"))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(false) }));

		mock_storage
			.expect_set_bytes()
			.times(2)
			.returning(|_, _, _, _| Box::pin(async move { Ok(()) }));

		mock_order_interface
			.expect_validate_and_create_order()
			.times(1)
			.returning(move |_, _, _, _, _, _| Box::pin(async move { Ok(create_test_order()) }));

		// Add expectation for generate_fill_transaction (used for callback simulation)
		mock_order_interface
			.expect_generate_fill_transaction()
			.times(1)
			.returning(|_, _| {
				Box::pin(async move {
					Ok(solver_types::Transaction {
						to: Some(solver_types::Address(vec![0u8; 20])),
						data: vec![],
						value: U256::ZERO,
						chain_id: 137,
						nonce: None,
						gas_limit: Some(200000),
						gas_price: None,
						max_fee_per_gas: None,
						max_priority_fee_per_gas: None,
					})
				})
			});

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
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20, 60));
		let token_manager = Arc::new(TokenManager::new(
			Default::default(),
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let (config, static_config) = create_test_config();

		let cost_profit_service = create_mock_cost_profit_service();

		let handler = IntentHandler::new(
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			solver_address,
			token_manager,
			cost_profit_service,
			config,
			&static_config,
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
			.with(eq("intents:0xtest_intent_123"))
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
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20, 60));
		let token_manager = Arc::new(TokenManager::new(
			Default::default(),
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let (config, static_config) = create_test_config();

		let cost_profit_service = create_mock_cost_profit_service();

		let handler = IntentHandler::new(
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			solver_address,
			token_manager,
			cost_profit_service,
			config,
			&static_config,
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
			.expect_validate_and_create_order()
			.times(1)
			.returning(move |_, _, _, _, _, _| Box::pin(async move { Ok(create_test_order()) }));

		// Add expectation for generate_fill_transaction (used for callback simulation)
		mock_order_interface
			.expect_generate_fill_transaction()
			.times(1)
			.returning(|_, _| {
				Box::pin(async move {
					Ok(solver_types::Transaction {
						to: Some(solver_types::Address(vec![0u8; 20])),
						data: vec![],
						value: U256::ZERO,
						chain_id: 137,
						nonce: None,
						gas_limit: Some(200000),
						gas_price: None,
						max_fee_per_gas: None,
						max_priority_fee_per_gas: None,
					})
				})
			});

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
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20, 60));
		let token_manager = Arc::new(TokenManager::new(
			Default::default(),
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let (config, static_config) = create_test_config();

		// Subscribe to events before creating handler
		let mut receiver = event_bus.subscribe();

		let cost_profit_service = create_mock_cost_profit_service();

		let handler = IntentHandler::new(
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			solver_address,
			token_manager,
			cost_profit_service,
			config,
			&static_config,
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

	// ── Deny-list unit tests ────────────────────────────────────────────

	#[test]
	fn test_load_deny_list_no_path_returns_empty() {
		let result = IntentHandler::load_deny_list(None);
		assert!(result.is_ok());
		assert!(result.unwrap().is_empty());
	}

	#[test]
	fn test_load_deny_list_empty_path_returns_empty() {
		let result = IntentHandler::load_deny_list(Some(""));
		assert!(result.is_ok());
		assert!(result.unwrap().is_empty());
	}

	#[test]
	fn test_load_deny_list_valid_file() {
		let dir = tempfile::tempdir().unwrap();
		let file_path = dir.path().join("deny.json");
		std::fs::write(
			&file_path,
			r#"["0xABC123def456789012345678901234567890abcd","0x1111111111111111111111111111111111111111"]"#,
		)
		.unwrap();

		let result = IntentHandler::load_deny_list(Some(file_path.to_str().unwrap()));
		assert!(result.is_ok());
		let set = result.unwrap();
		assert_eq!(set.len(), 2);
		// All addresses should be lowercased
		assert!(set.contains("0xabc123def456789012345678901234567890abcd"));
		assert!(set.contains("0x1111111111111111111111111111111111111111"));
	}

	#[test]
	fn test_load_deny_list_missing_file_returns_error() {
		let result = IntentHandler::load_deny_list(Some("/nonexistent/path/deny.json"));
		assert!(result.is_err());
		assert!(result.unwrap_err().contains("Failed to read deny list"));
	}

	#[test]
	fn test_load_deny_list_malformed_json_returns_error() {
		let dir = tempfile::tempdir().unwrap();
		let file_path = dir.path().join("bad.json");
		std::fs::write(&file_path, "not valid json").unwrap();

		let result = IntentHandler::load_deny_list(Some(file_path.to_str().unwrap()));
		assert!(result.is_err());
		assert!(result.unwrap_err().contains("Failed to parse deny list"));
	}

	#[test]
	fn test_denied_addresses_sender_hit() {
		// Verify that a sender address present in the deny list is detected.
		let dir = tempfile::tempdir().unwrap();
		let file_path = dir.path().join("deny.json");
		let denied_addr = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
		std::fs::write(&file_path, format!(r#"["{denied_addr}"]"#)).unwrap();

		let set = IntentHandler::load_deny_list(Some(file_path.to_str().unwrap())).unwrap();
		assert!(set.contains(denied_addr));
	}

	#[test]
	fn test_denied_addresses_recipient_hit() {
		// Simulate recipient extraction: bytes32 where the last 20 bytes are the address.
		let dir = tempfile::tempdir().unwrap();
		let file_path = dir.path().join("deny.json");
		let denied_addr = "0x1234567890abcdef1234567890abcdef12345678";
		std::fs::write(&file_path, format!(r#"["{denied_addr}"]"#)).unwrap();

		let set = IntentHandler::load_deny_list(Some(file_path.to_str().unwrap())).unwrap();

		// Construct a bytes32 recipient with the address in the last 20 bytes
		let mut recipient = [0u8; 32];
		let addr_bytes = hex::decode("1234567890abcdef1234567890abcdef12345678").unwrap();
		recipient[12..].copy_from_slice(&addr_bytes);

		// Extract using the same logic as the handler
		let addr_bytes = &recipient[12..];
		let hex_str: String = addr_bytes.iter().map(|b| format!("{b:02x}")).collect();
		let recipient_addr = format!("0x{hex_str}");

		assert!(set.contains(&recipient_addr));
	}

	// ===================== Fix A: engine-side compact reservations =====================

	const RL_USER: &str = "0x1234567890123456789012345678901234567890";
	const RL_COMPACT: &str = "0x3333333333333333333333333333333333333333";
	const RL_CHAIN: u64 = 1;

	/// Delivery stub whose `eth_call` returns a fixed `balanceOf` result. Used
	/// to drive `derive_compact_deposit_reservations` in reservation tests.
	struct BalanceDelivery {
		balance: U256,
	}

	#[async_trait::async_trait]
	impl solver_delivery::DeliveryInterface for BalanceDelivery {
		fn config_schema(&self) -> Box<dyn solver_types::validation::ConfigSchema> {
			unimplemented!()
		}
		async fn submit(
			&self,
			_: solver_types::Transaction,
			_: Option<solver_delivery::TransactionTrackingWithConfig>,
		) -> Result<solver_types::TransactionHash, solver_delivery::DeliveryError> {
			unimplemented!()
		}
		async fn get_receipt(
			&self,
			_: &solver_types::TransactionHash,
			_: u64,
		) -> Result<solver_types::TransactionReceipt, solver_delivery::DeliveryError> {
			unimplemented!()
		}
		async fn get_fee_params(
			&self,
			chain_id: u64,
		) -> Result<solver_delivery::FeeParams, solver_delivery::DeliveryError> {
			Ok(solver_delivery::FeeParams::legacy(chain_id, 1))
		}
		async fn get_balance(
			&self,
			_: &str,
			_: Option<&str>,
			_: u64,
		) -> Result<String, solver_delivery::DeliveryError> {
			unimplemented!()
		}
		async fn get_allowance(
			&self,
			_: &str,
			_: &str,
			_: &str,
			_: u64,
		) -> Result<String, solver_delivery::DeliveryError> {
			unimplemented!()
		}
		async fn get_nonce(&self, _: &str, _: u64) -> Result<u64, solver_delivery::DeliveryError> {
			unimplemented!()
		}
		async fn get_block_number(&self, _: u64) -> Result<u64, solver_delivery::DeliveryError> {
			unimplemented!()
		}
		async fn estimate_gas(
			&self,
			_: solver_types::Transaction,
		) -> Result<u64, solver_delivery::DeliveryError> {
			unimplemented!()
		}
		async fn estimate_gas_with_overrides(
			&self,
			_: solver_types::Transaction,
			_: alloy_rpc_types::state::StateOverride,
		) -> Result<u64, solver_delivery::DeliveryError> {
			unimplemented!()
		}
		async fn eth_call(
			&self,
			_: solver_types::Transaction,
		) -> Result<alloy_primitives::Bytes, solver_delivery::DeliveryError> {
			Ok(alloy_primitives::Bytes::from(
				self.balance.to_be_bytes::<32>().to_vec(),
			))
		}
		async fn tx_exists(
			&self,
			_: &solver_types::TransactionHash,
			_: u64,
		) -> Result<bool, solver_delivery::DeliveryError> {
			Ok(false)
		}
		async fn get_logs(
			&self,
			_: u64,
			_: solver_types::LogFilter,
		) -> Result<Vec<solver_types::Log>, solver_delivery::DeliveryError> {
			Ok(vec![])
		}
	}

	fn rl_config(balance: U256) -> (Config, Arc<DeliveryService>) {
		let network = solver_types::utils::tests::builders::NetworkConfigBuilder::new()
			.the_compact_address_hex(RL_COMPACT)
			.unwrap()
			.build();
		let networks = solver_types::utils::tests::builders::NetworksConfigBuilder::new()
			.add_network(RL_CHAIN, network)
			.build();
		let config = ConfigBuilder::new().networks(networks).build();

		let mut delivery_impls: HashMap<u64, Arc<dyn solver_delivery::DeliveryInterface>> =
			HashMap::new();
		delivery_impls.insert(RL_CHAIN, Arc::new(BalanceDelivery { balance }));
		let delivery = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));
		(config, delivery)
	}

	fn rl_handler(
		storage: Arc<StorageService>,
		delivery: Arc<DeliveryService>,
		config: Config,
	) -> IntentHandler {
		let order_service = Arc::new(OrderService::new(
			HashMap::new(),
			Box::new(MockExecutionStrategy::new()),
		));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let event_bus = EventBus::new(100);
		let token_manager = Arc::new(TokenManager::new(
			Default::default(),
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let cost_profit_service = create_mock_cost_profit_service();
		let dynamic_config = Arc::new(RwLock::new(config.clone()));
		IntentHandler::new(
			order_service,
			storage,
			state_machine,
			event_bus,
			delivery,
			create_test_address(),
			token_manager,
			cost_profit_service,
			dynamic_config,
			&config,
		)
	}

	fn rl_order(order_id: &str, token_id: U256, amount: U256) -> Order {
		use solver_types::standards::eip7683::GasLimitOverrides;
		let expires = (current_timestamp() as u32).saturating_add(3600);
		let order_data = Eip7683OrderData {
			user: RL_USER.to_string(),
			nonce: U256::from(1u64),
			origin_chain_id: U256::from(RL_CHAIN),
			expires,
			fill_deadline: expires,
			input_oracle: RL_USER.to_string(),
			inputs: vec![[token_id, amount]],
			order_id: [0u8; 32],
			gas_limit_overrides: GasLimitOverrides::default(),
			outputs: vec![],
			raw_order_data: None,
			signature: None,
			sponsor: None,
			lock_type: Some(LockType::ResourceLock),
		};
		OrderBuilder::new()
			.with_id(order_id.to_string())
			.with_data(serde_json::to_value(&order_data).unwrap())
			.build()
	}

	#[tokio::test]
	async fn reserve_compact_deposits_records_reservation() {
		// (a) An admitted resource-lock order holds a reservation against its
		// Compact deposit.
		use solver_storage::compact_reservations::{CompactReservationStore, DepositReservation};

		let storage = Arc::new(StorageService::new(Box::new(
			solver_storage::implementations::memory::MemoryStorage::new(),
		)));
		let token_id = U256::from(7u64);
		let amount = U256::from(500u64);
		let (config, delivery) = rl_config(amount);
		let handler = rl_handler(storage.clone(), delivery, config);

		let order = rl_order("rl-a", token_id, amount);
		let reserved = handler.reserve_compact_deposits(&order).await.unwrap();
		assert!(reserved, "expected a deposit to be reserved");

		// The deposit is now fully subscribed: a direct second reservation
		// against the same lock must be rejected.
		let store = CompactReservationStore::new(storage);
		let expires = current_timestamp().saturating_add(3600);
		let err = store
			.reserve_order(
				"rl-other",
				expires,
				&[DepositReservation {
					chain_id: RL_CHAIN,
					owner: RL_USER.to_string(),
					token_id,
					amount,
					available_balance: amount,
				}],
			)
			.await
			.unwrap_err();
		assert!(matches!(
			err,
			solver_storage::compact_reservations::ReservationError::Oversubscribed { .. }
		));
	}

	#[tokio::test]
	async fn reserve_compact_deposits_rejects_oversubscription() {
		// (b) A second order drawing on the same deposit is rejected once the
		// deposit is fully subscribed.
		let storage = Arc::new(StorageService::new(Box::new(
			solver_storage::implementations::memory::MemoryStorage::new(),
		)));
		let token_id = U256::from(7u64);
		let amount = U256::from(500u64);
		let (config, delivery) = rl_config(amount);
		let handler = rl_handler(storage, delivery, config);

		handler
			.reserve_compact_deposits(&rl_order("rl-a", token_id, amount))
			.await
			.unwrap();

		let err = handler
			.reserve_compact_deposits(&rl_order("rl-b", token_id, amount))
			.await
			.unwrap_err();
		assert!(
			err.contains("oversubscribed"),
			"expected oversubscription rejection, got: {err}"
		);
	}

	#[tokio::test]
	async fn release_compact_deposits_frees_capacity() {
		// (c) Releasing a reservation (the Skip / error path) frees the deposit
		// for the next order.
		let storage = Arc::new(StorageService::new(Box::new(
			solver_storage::implementations::memory::MemoryStorage::new(),
		)));
		let token_id = U256::from(7u64);
		let amount = U256::from(500u64);
		let (config, delivery) = rl_config(amount);
		let handler = rl_handler(storage, delivery, config);

		let order = rl_order("rl-a", token_id, amount);
		handler.reserve_compact_deposits(&order).await.unwrap();

		// Before release a competing order is rejected...
		assert!(handler
			.reserve_compact_deposits(&rl_order("rl-b", token_id, amount))
			.await
			.is_err());

		// ...releasing rl-a frees the capacity.
		handler.release_compact_deposits(&order).await;

		handler
			.reserve_compact_deposits(&rl_order("rl-b", token_id, amount))
			.await
			.unwrap();
	}

	#[tokio::test]
	async fn reserve_compact_deposits_rejects_when_deposit_insufficient() {
		// A deposit smaller than the order amount is rejected at reservation
		// time (oversubscribed against a balance that cannot cover it).
		let storage = Arc::new(StorageService::new(Box::new(
			solver_storage::implementations::memory::MemoryStorage::new(),
		)));
		let token_id = U256::from(7u64);
		let amount = U256::from(500u64);
		let (config, delivery) = rl_config(U256::from(100u64)); // balance < amount
		let handler = rl_handler(storage, delivery, config);

		let err = handler
			.reserve_compact_deposits(&rl_order("rl-a", token_id, amount))
			.await
			.unwrap_err();
		assert!(
			err.contains("oversubscribed"),
			"expected oversubscription rejection, got: {err}"
		);
	}

	#[tokio::test]
	async fn concurrent_reservations_through_shared_handler_never_oversubscribe_file_backend() {
		// Fix 2 (C-06 round 2): the per-lock-id mutex guards in
		// `CompactReservationStore` only serialize concurrent admissions when one
		// store instance is reused. Production wires a single store into both the
		// `IntentHandler` (reserve) and `OrderStateMachine` (release); a per-call
		// `::new()` would give each admission a fresh guard map and reopen the
		// non-atomic `set_nx` create race on the file backend.
		//
		// This drives concurrent `reserve_compact_deposits` through ONE handler
		// (the production pattern) over the file backend. With sharing, exactly
		// `balance / amount` admissions win; without it, the create race could
		// admit more and oversubscribe.
		use solver_storage::implementations::file::{FileStorage, TtlConfig};

		let temp = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let token_id = U256::from(7u64);
		let amount = U256::from(100u64);
		let balance = U256::from(500u64);
		let (config, delivery) = rl_config(balance);
		// One handler == one shared reservation store, as in production.
		let handler = Arc::new(rl_handler(storage, delivery, config));

		let mut handles = Vec::new();
		for i in 0..10 {
			let handler = Arc::clone(&handler);
			handles.push(tokio::spawn(async move {
				handler
					.reserve_compact_deposits(&rl_order(&format!("rl-{i}"), token_id, amount))
					.await
					.unwrap_or(false)
			}));
		}

		let mut admitted = 0;
		for handle in handles {
			if handle.await.unwrap() {
				admitted += 1;
			}
		}
		// 500 / 100 = exactly 5 orders fit.
		assert_eq!(
			admitted, 5,
			"shared store must serialize concurrent admissions; got {admitted} admitted"
		);
	}

	#[tokio::test]
	async fn handler_reserve_and_state_machine_release_share_one_store() {
		// Fix 2: the reserve path (IntentHandler) and the terminal-state release
		// path (OrderStateMachine) must operate on the SAME store. Build a state
		// machine, derive a handler from it (as production does), reserve through
		// the handler, then release through the state machine and confirm the
		// capacity is freed — which only works if both share one instance over a
		// CAS-backed store.
		use solver_types::OrderStatus;

		let storage = Arc::new(StorageService::new(Box::new(
			solver_storage::implementations::memory::MemoryStorage::new(),
		)));
		let token_id = U256::from(7u64);
		let amount = U256::from(500u64);
		let (config, delivery) = rl_config(amount);

		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let order_service = Arc::new(OrderService::new(
			HashMap::new(),
			Box::new(MockExecutionStrategy::new()),
		));
		let token_manager = Arc::new(TokenManager::new(
			Default::default(),
			delivery.clone(),
			Arc::new(solver_account::AccountService::new(Box::new(
				MockAccountInterface::new(),
			))),
		));
		let handler = IntentHandler::new(
			order_service,
			storage,
			state_machine.clone(),
			EventBus::new(100),
			delivery,
			create_test_address(),
			token_manager,
			create_mock_cost_profit_service(),
			Arc::new(RwLock::new(config.clone())),
			&config,
		);

		// Reserve through the handler; the deposit is now fully subscribed.
		let order = rl_order("rl-a", token_id, amount);
		handler.reserve_compact_deposits(&order).await.unwrap();
		assert!(handler
			.reserve_compact_deposits(&rl_order("rl-b", token_id, amount))
			.await
			.is_err());

		// Release through the state machine's terminal-status path (Finalized).
		state_machine.store_order(&order).await.unwrap();
		// Walk the order to Finalized so the release fires on the terminal hop.
		for status in [
			OrderStatus::Executing,
			OrderStatus::Executed,
			OrderStatus::Settled,
			OrderStatus::Finalized,
		] {
			state_machine
				.transition_order_status(&order.id, status)
				.await
				.unwrap();
		}

		// The deposit is free again because reserve and release shared one store.
		handler
			.reserve_compact_deposits(&rl_order("rl-b", token_id, amount))
			.await
			.unwrap();
	}
}
