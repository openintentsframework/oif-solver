//! Intent handler for processing discovered intents.
//!
//! Responsible for validating intents, creating orders, storing them,
//! and determining execution strategy through the order service.

use crate::engine::{
	context::ContextBuilder, cost_profit::CostProfitService, event_bus::EventBus,
	token_manager::TokenManager,
};
use crate::state::OrderStateMachine;
use lru::LruCache;
use solver_config::Config;
use solver_delivery::DeliveryService;
use solver_order::OrderService;
use solver_settlement::admission::estimate_required_expiry_window_seconds;
use solver_storage::StorageService;
use solver_types::{
	current_timestamp, truncate_id, with_0x_prefix, Address, DiscoveryEvent, Eip7683OrderData,
	ExecutionDecision, ExecutionParams, Intent, OrderEvent, SolverEvent, StorageKey,
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
			if processed.contains(&intent.id) {
				tracing::debug!(
					"Duplicate intent detected in memory cache, already being processed"
				);
				return Ok(());
			}
			// Atomically claim this intent ID (LRU will auto-evict oldest if at capacity)
			processed.put(intent.id.clone(), ());
		}

		// Fallback check against persistent storage for cross-restart deduplication
		// This handles cases where the service was restarted between intent discovery
		let exists = self
			.storage
			.exists(StorageKey::Intents.as_str(), &intent.id)
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

		// Store intent immediately to prevent race conditions with duplicate discovery
		// This claims the intent ID slot before we start the potentially slow validation process
		self.storage
			.store(
				StorageKey::Intents.as_str(),
				&with_0x_prefix(&intent.id),
				&intent,
				None,
			)
			.await
			.map_err(|e| {
				IntentError::Storage(format!("Failed to store intent for deduplication: {e}"))
			})?;

		tracing::info!("Discovered intent");

		// Use the order_bytes field directly from the intent
		let order_bytes = &intent.order_bytes;

		// For on-chain discovered intents, we use a simple callback that returns the intent ID
		// since the order ID was already computed during discovery
		let intent_id = intent.id.clone();
		let order_id_callback: solver_types::OrderIdCallback =
			Box::new(move |_chain_id, _tx_data| {
				let id = intent_id.clone();
				Box::pin(async move {
					// Return the intent ID as bytes (it's already a hex string)
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
			Ok(order) => {
				// Settlement-aware acceptance gate:
				// Skip orders that do not leave enough time to reach claim/finalize safely.
				if let Ok(order_data) =
					serde_json::from_value::<Eip7683OrderData>(order.data.clone())
				{
					let now = current_timestamp() as u32;
					let expires_remaining = order_data.expires.saturating_sub(now) as u64;
					if let Some((required_window, breakdown)) =
						estimate_required_expiry_window_seconds(
							&order_data,
							&config.settlement.implementations,
							config.settlement.settlement_poll_interval_seconds,
							order.settlement_name.as_deref(),
						) {
						if expires_remaining < required_window {
							let reason = format!(
								"Insufficient settlement window: expires_in={expires_remaining}s required={required_window}s ({breakdown})"
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

				// Step 1: Generate fill transaction and simulate to get accurate gas estimate
				// This also validates callbacks won't revert
				let default_params = ExecutionParams {
					gas_price: alloy_primitives::U256::ZERO,
					priority_fee: None,
				};

				let simulated_fill_gas = match self
					.order_service
					.generate_fill_transaction(&order, &default_params)
					.await
				{
					Ok(fill_tx) => {
						// Simulate the fill transaction to validate callbacks and get gas estimate
						match self
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
								// Use simulated gas if available, otherwise None (will use config default)
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
						}
					},
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

				// Step 2: Calculate cost estimation using simulated gas
				let cost_estimate = match self
					.cost_profit_service
					.estimate_cost_for_order_with_gas(&order, &config, simulated_fill_gas)
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
				let mut order = order;
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
					config.clone(),
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
	use serde_json::json;
	use solver_account::MockAccountInterface;
	use solver_config::ConfigBuilder;
	use solver_delivery::DeliveryService;
	use solver_order::{MockExecutionStrategy, MockOrderInterface};
	use solver_pricing::{MockPricingInterface, PricingService};
	use solver_storage::{MockStorageInterface, StorageError};
	use solver_types::utils::tests::builders::{
		Eip7683OrderDataBuilder, IntentBuilder, OrderBuilder,
	};
	use solver_types::{Address, ExecutionParams, Intent, Order, SolverEvent};
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

	fn create_test_address() -> Address {
		Address(vec![0xab; 20])
	}

	fn create_test_config() -> (Arc<RwLock<Config>>, Config) {
		let config = ConfigBuilder::new().build();
		(Arc::new(RwLock::new(config.clone())), config)
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
			.expect_get_gas_price()
			.returning(|_| Box::pin(async move { Ok("20000".to_string()) }));
		mock_delivery_1
			.expect_get_block_number()
			.returning(|_| Box::pin(async move { Ok(1000000u64) }));
		mock_delivery_1
			.expect_estimate_gas()
			.returning(|_| Box::pin(async move { Ok(200000u64) }));

		let mut mock_delivery_137 = solver_delivery::MockDeliveryInterface::new();
		mock_delivery_137
			.expect_get_gas_price()
			.returning(|_| Box::pin(async move { Ok("20000".to_string()) }));
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

		let delivery_service = Arc::new(DeliveryService::new(delivery_impls, 1, 20));

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
					.tokens(vec![input_token])
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

		Arc::new(CostProfitService::new(
			pricing_service,
			delivery_service,
			token_manager,
			Arc::new(StorageService::new(Box::new(MockStorageInterface::new()))),
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
			.with(eq("intents:test_intent_123"))
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
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20));
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
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20));
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
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20));
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
			.with(eq("intents:test_intent_123"))
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

		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20));
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
			.with(eq("intents:test_intent_123"))
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
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20));
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
			.with(eq("intents:test_intent_123"))
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
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20));
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
			.with(eq("intents:test_intent_123"))
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
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20));
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
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20));
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
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20));
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
}
