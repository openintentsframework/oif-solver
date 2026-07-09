//! Quote processing pipeline for cross-chain intent execution.
//!
//! This module implements the complete quote generation system for the OIF solver.
//! It processes user requests for cross-chain token transfers and generates executable
//! quotes with appropriate signatures, settlement mechanisms, and execution guarantees.
//!
//! ## Architecture
//!
//! The quote module is organized into specialized submodules:
//!
//! - **Validation**: Request validation and capability checking
//! - **Custody**: Token custody decision engine
//! - **Generation**: Quote assembly and optimization
//! - **Signing**: Signature payload generation
//!
//! ## Quote Lifecycle
//!
//! 1. **Request Reception**: User submits transfer intent with inputs/outputs
//! 2. **Validation**: Verify request format, supported chains, and token availability
//! 3. **Capability Check**: Ensure solver can execute on specified chains
//! 4. **Balance Verification**: Confirm solver has sufficient output tokens
//! 5. **Quote Generation**: Create multiple quote options with different mechanisms
//! 6. **Storage**: Persist quotes for later retrieval and execution
//!
//! ## Key Features
//!
//! ### Multi-Protocol Support
//! - Permit2 for universal token approvals
//! - EIP-3009 for native gasless transfers
//! - TheCompact for resource lock allocations
//!
//! ### Optimization Strategies
//! - Speed optimization for fastest execution
//! - Cost optimization for lowest fees
//! - Trust minimization for maximum security
//! - Input prioritization for token preferences
//!
//! ### Security Guarantees
//! - Cryptographic binding via EIP-712 signatures
//! - Oracle verification for settlement
//! - Expiry times to prevent stale quotes
//! - Nonce management for replay protection
//!
//! ## API Integration
//!
//! The module exposes three main functions:
//! - `process_quote_request`: Main entry point for quote generation
//! - `get_quote_by_id`: Retrieve stored quotes
//! - `quote_exists`: Check quote validity
//!
//! ## Storage Model
//!
//! Quotes are stored with:
//! - TTL-based expiry (default 5 minutes)
//! - Unique IDs for retrieval
//! - Complete execution details
//!
//! ## Error Handling
//!
//! The module provides detailed error types:
//! - `InvalidRequest`: Malformed or unsupported requests
//! - `InsufficientLiquidity`: Solver lacks required tokens
//! - `UnsupportedChain`: Chain not configured
//! - `Internal`: System errors
pub mod custody;
pub mod generation;
pub mod registry;
pub mod signing;
pub(crate) mod timing;
pub mod validation;

use self::generation::QuoteGenerator;

// Re-export quote helpers
pub use signing::payloads::permit2;
pub use validation::QuoteValidator;

use solver_config::Config;
use solver_core::engine::cost_profit::CostProfitService;
use solver_core::SolverEngine;
use solver_types::{
	CostContext, GetQuoteRequest, GetQuoteResponse, Quote, QuoteError, StorageKey, StoredQuote,
};

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tracing::info;

/// Process-wide ceiling on retained `StoredQuote` records (audit finding H-13).
///
/// The public `/quotes` endpoint persists a `StoredQuote` per accepted request.
/// Even with the per-IP rate limit and the quote concurrency cap, a flood from
/// many distinct source IPs can otherwise grow persistent storage without bound
/// (each entry only disappears on its validity TTL). This limiter tracks stored
/// quote ids in FIFO insertion order and, once the configured capacity is
/// exceeded, reports the oldest ids for eviction so storage stays bounded. The
/// evicted quotes would expire on their TTL regardless; the cap just enforces
/// the ceiling early under load.
///
/// Scope note: the limiter is per process (a multi-replica deployment bounds
/// each replica independently) and its capacity is fixed on first use.
#[derive(Debug)]
struct QuoteRetentionLimiter {
	capacity: usize,
	ids: Mutex<VecDeque<String>>,
}

impl QuoteRetentionLimiter {
	fn new(capacity: usize) -> Self {
		Self {
			// A zero cap would evict every quote immediately, breaking the
			// retrieve-by-id flow; clamp to at least 1.
			capacity: capacity.max(1),
			ids: Mutex::new(VecDeque::new()),
		}
	}

	/// Record newly stored quote ids and return the ids that must be evicted to
	/// stay within `capacity` (oldest first).
	fn register<I: IntoIterator<Item = String>>(&self, new_ids: I) -> Vec<String> {
		let mut ids = self.ids.lock().expect("quote retention mutex poisoned");
		let mut evicted = Vec::new();
		for id in new_ids {
			ids.push_back(id);
			while ids.len() > self.capacity {
				if let Some(old) = ids.pop_front() {
					evicted.push(old);
				}
			}
		}
		evicted
	}
}

/// Returns the process-wide quote retention limiter, initializing it with
/// `capacity` on first use.
fn quote_retention_limiter(capacity: usize) -> &'static QuoteRetentionLimiter {
	static LIMITER: OnceLock<QuoteRetentionLimiter> = OnceLock::new();
	LIMITER.get_or_init(|| QuoteRetentionLimiter::new(capacity))
}

/// Processes a quote request and returns available quote options.
///
/// This is the main HTTP API entry point that orchestrates the quote processing
/// pipeline by delegating to specialized modules.
pub async fn process_quote_request(
	request: GetQuoteRequest,
	solver: &SolverEngine,
	config: &Config,
) -> Result<GetQuoteResponse, QuoteError> {
	// Reject early when intake is disabled — cheaper than starting a timer
	// or any other work.
	crate::validators::intake::ensure_intake_enabled::<QuoteError>(config)?;

	let quote_started_at = Instant::now();
	let mut stage_started_at = quote_started_at;
	let mut log_stage = |stage: &'static str| {
		let now = Instant::now();
		info!(
			stage,
			stage_elapsed_ms = now.duration_since(stage_started_at).as_millis(),
			total_elapsed_ms = now.duration_since(quote_started_at).as_millis(),
			"Quote processing stage completed"
		);
		stage_started_at = now;
	};

	info!(
		"Processing quote request with {} inputs",
		request.intent.inputs.len()
	);

	// Use the new validation architecture to get ValidatedQuoteContext
	let validated_context = QuoteValidator::validate_quote_request(&request, solver)?;

	// Validate callback whitelist early for fail-fast behavior
	// This prevents users from getting quotes they can't execute due to callback restrictions
	QuoteValidator::validate_callback_whitelist(&request, config)?;

	// Check solver capabilities: networks only (token support is enforced during collection below)
	QuoteValidator::validate_supported_networks(&request, &config.networks)?;
	log_stage("validation");

	let settlement_service = solver.settlement();
	let delivery_service = solver.delivery();
	let quote_generator = QuoteGenerator::new(settlement_service.clone(), delivery_service.clone());
	let resolved_request = quote_generator.resolve_quote_request(&request).await?;
	let resolved_flow_keys = vec![resolved_request.flow_key.clone()];
	log_stage("resolve_quote_request");

	let cost_profit_service = quote_cost_profit_service(solver);

	let solver_address = solver.solver_address().clone();
	let cost_context = cost_profit_service
		.calculate_cost_context_for_flow_keys(
			&request,
			&validated_context,
			config,
			&resolved_flow_keys,
			&solver_address,
		)
		.await
		.map_err(|e| QuoteError::Internal(format!("Failed to calculate cost context: {e}")))?;
	log_stage("cost_context");

	// Validate and collect assets with cost-adjusted amounts
	let _supported_inputs = QuoteValidator::validate_and_collect_inputs_with_costs(
		&request,
		&config.networks,
		&cost_context,
	)?;

	let supported_outputs = QuoteValidator::validate_and_collect_outputs_with_costs(
		&request,
		&config.networks,
		&cost_context,
	)?;
	log_stage("collect_assets");

	// Check destination balances for cost-adjusted output amounts
	QuoteValidator::ensure_destination_balances_with_costs(
		solver,
		&supported_outputs,
		&validated_context,
		&cost_context,
	)
	.await?;
	log_stage("destination_balance_check");

	let quote_pairs = quote_generator
		.generate_quotes_with_costs_resolved(
			&request,
			&validated_context,
			&cost_context,
			config,
			&resolved_request,
		)
		.await?;
	log_stage("generate_quotes");

	// Persist quotes and cost contexts (including settlement_name internally),
	// bounded by the configured retention ceiling (H-13).
	let max_stored_quotes = config
		.api
		.as_ref()
		.and_then(|api| api.quote.as_ref())
		.map(|q| q.max_stored_quotes)
		.unwrap_or(solver_config::DEFAULT_QUOTE_MAX_STORED_QUOTES);
	store_quotes(solver, &quote_pairs, &cost_context, max_stored_quotes).await;
	log_stage("store_quotes");

	let quotes: Vec<Quote> = quote_pairs.into_iter().map(|(q, _)| q).collect();
	info!(
		quote_count = quotes.len(),
		total_elapsed_ms = quote_started_at.elapsed().as_millis(),
		"Generated and stored quote options"
	);

	Ok(GetQuoteResponse { quotes })
}

fn quote_cost_profit_service(solver: &SolverEngine) -> Arc<CostProfitService> {
	solver.cost_profit_service().clone()
}

/// Stores generated quotes with their cost contexts.
///
/// Each quote is stored together with its cost context as a StoredQuote record.
/// Storage errors are logged but do not fail the request.
/// Compute the H-07 economic binding for a generated quote, derived from the order
/// it priced. The profitability gate recomputes this from the submitted order and
/// honors the stored cost context only on a match.
///
/// Returns `None` when the quote's order cannot be projected to a canonical
/// `StandardOrder` (e.g. generic orders); the gate then judges such an order on the
/// freshly recomputed breakdown rather than the stored one.
fn binding_for_quote(quote: &Quote) -> Option<alloy_primitives::B256> {
	use solver_types::order::OrderParsable;
	use solver_types::standards::eip7683::{interfaces::StandardOrder, Eip7683OrderData};

	let standard = StandardOrder::try_from(&quote.order).ok()?;
	let order_data = Eip7683OrderData::from(standard);
	Some(solver_types::quote_order_binding(
		order_data.origin_chain_id(),
		// Flow key derived explicitly from the quote's order variant (not via the
		// lossy `From<StandardOrder>`, which drops the lock type). `OifOrder::flow_key`
		// and the gate's `parse_lock_type` produce identical strings by construction.
		quote.order.flow_key().as_deref(),
		&order_data.parse_available_inputs(),
		&order_data.parse_requested_outputs(),
	))
}

async fn store_quotes(
	solver: &SolverEngine,
	quotes: &[(Quote, Option<String>)],
	cost_context: &CostContext,
	max_stored_quotes: usize,
) {
	let storage = solver.storage();
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs();

	let mut stored_ids: Vec<String> = Vec::with_capacity(quotes.len());
	for (quote, settlement_name) in quotes {
		// Calculate TTL from valid_until timestamp
		let ttl = if quote.valid_until > now {
			Duration::from_secs(quote.valid_until - now)
		} else {
			// Quote is already expired, store with minimal TTL
			Duration::from_secs(1)
		};

		// Create combined structure with quote and cost context. The economic
		// binding (H-07) pins this quote's stored cost to the order it priced, so
		// the profitability gate cannot be tricked into applying it to a different,
		// loss-making order that merely presents this quote's id.
		let quote_with_context = StoredQuote {
			quote: quote.clone(),
			cost_context: cost_context.clone(),
			settlement_name: settlement_name.clone(),
			binding: binding_for_quote(quote),
		};

		// Store the combined structure in a single I/O operation
		if let Err(e) = storage
			.store_with_ttl(
				StorageKey::Quotes.as_str(),
				&quote.quote_id,
				&quote_with_context,
				None, // No indexes needed
				Some(ttl),
			)
			.await
		{
			tracing::warn!(
				"Failed to store quote with context {}: {}",
				quote.quote_id,
				e
			);
		} else {
			tracing::debug!(
				"Stored quote {} with cost context, TTL {:?} (valid_until: {})",
				quote.quote_id,
				ttl,
				quote.valid_until
			);
			stored_ids.push(quote.quote_id.clone());
		}
	}

	// Enforce the process-wide retention ceiling (H-13): evict the oldest
	// quotes once the cap is exceeded so a quote flood cannot grow storage
	// without bound. Eviction failures are non-fatal (the TTL still applies).
	let evicted = quote_retention_limiter(max_stored_quotes).register(stored_ids);
	for id in &evicted {
		if let Err(e) = storage.remove(StorageKey::Quotes.as_str(), id).await {
			tracing::debug!("Failed to evict over-capacity quote {}: {}", id, e);
		}
	}
	if !evicted.is_empty() {
		tracing::debug!(
			evicted = evicted.len(),
			cap = max_stored_quotes,
			"Evicted oldest quotes to respect retention cap"
		);
	}
}

#[allow(dead_code)]
/// Retrieves a stored quote by its ID.
///
/// This function looks up a previously generated quote in storage.
/// Quotes are automatically expired based on their TTL.
pub async fn get_quote_by_id(quote_id: &str, solver: &SolverEngine) -> Result<Quote, QuoteError> {
	let storage = solver.storage();

	match storage
		.retrieve::<StoredQuote>(StorageKey::Quotes.as_str(), quote_id)
		.await
	{
		Ok(quote_with_context) => {
			tracing::debug!("Retrieved quote {} from storage", quote_id);
			Ok(quote_with_context.quote)
		},
		Err(e) => {
			tracing::warn!("Failed to retrieve quote {}: {}", quote_id, e);
			Err(QuoteError::InvalidRequest(format!(
				"Quote not found: {quote_id}"
			)))
		},
	}
}

#[allow(dead_code)]
/// Checks if a quote exists in storage.
///
/// This is useful for validating quote IDs before processing intents.
pub async fn quote_exists(quote_id: &str, solver: &SolverEngine) -> Result<bool, QuoteError> {
	let storage = solver.storage();

	match storage.exists(StorageKey::Quotes.as_str(), quote_id).await {
		Ok(exists) => {
			tracing::debug!("Quote {} exists: {}", quote_id, exists);
			Ok(exists)
		},
		Err(e) => {
			tracing::warn!("Failed to check quote existence {}: {}", quote_id, e);
			Err(QuoteError::Internal(format!("Storage error: {e}")))
		},
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn retention_limiter_evicts_oldest_beyond_capacity() {
		let limiter = QuoteRetentionLimiter::new(3);
		// First three fit under the cap → nothing evicted.
		assert!(limiter
			.register(["a", "b", "c"].iter().map(|s| s.to_string()))
			.is_empty());
		// Two more exceed the cap of 3 → the two oldest are evicted, oldest first.
		let evicted = limiter.register(["d", "e"].iter().map(|s| s.to_string()));
		assert_eq!(evicted, vec!["a".to_string(), "b".to_string()]);
	}

	#[test]
	fn retention_limiter_capacity_one_evicts_each_previous() {
		let limiter = QuoteRetentionLimiter::new(1);
		assert!(limiter
			.register(std::iter::once("a".to_string()))
			.is_empty());
		assert_eq!(
			limiter.register(std::iter::once("b".to_string())),
			vec!["a".to_string()]
		);
		assert_eq!(
			limiter.register(std::iter::once("c".to_string())),
			vec!["b".to_string()]
		);
	}

	#[test]
	fn retention_limiter_clamps_zero_capacity_to_one() {
		// A zero cap must not evict the only quote it just stored (that would
		// break retrieve-by-id immediately); capacity is clamped to >= 1.
		let limiter = QuoteRetentionLimiter::new(0);
		assert!(limiter
			.register(std::iter::once("a".to_string()))
			.is_empty());
		assert_eq!(
			limiter.register(std::iter::once("b".to_string())),
			vec!["a".to_string()]
		);
	}

	use alloy_primitives::Address as AlloyAddress;
	use solver_account::AccountService;
	use solver_config::{ApiConfig, ConfigBuilder, QuoteConfig, SettlementConfig};
	use solver_core::engine::event_bus::EventBus;
	use solver_core::engine::token_manager::TokenManager;
	use solver_core::SolverEngine;
	use solver_delivery::{DeliveryInterface, DeliveryService, MockDeliveryInterface};
	use solver_discovery::DiscoveryService;
	use solver_order::OrderService;
	use solver_pricing::PricingService;
	use solver_settlement::{MockSettlementInterface, SettlementInterface, SettlementService};
	use solver_storage::{implementations::memory::MemoryStorage, StorageService};
	use solver_types::order::OrderParsable;
	use solver_types::standards::eip7683::{interfaces::StandardOrder, Eip7683OrderData, LockType};
	use solver_types::{
		current_timestamp, oif_versions, parse_address, Address, AuthScheme, CostBreakdown,
		CostContext, FailureHandlingMode, GetQuoteRequest, IntentRequest, IntentType,
		InteropAddress, OifOrder, OrderPayload, OriginMode, OriginSubmission, Quote, QuoteError,
		QuoteInput, QuoteOutput, QuotePreference, QuotePreview, SignatureType, StorageKey,
		StoredQuote, SwapType,
	};
	use std::collections::HashMap;
	use std::sync::Arc;
	use tokio;

	// Test constants
	const TEST_QUOTE_ID: &str = "test_quote_123";

	/// Creates a simple storage service for testing
	fn create_test_storage() -> Arc<StorageService> {
		Arc::new(StorageService::new(Box::new(MemoryStorage::new())))
	}

	/// Creates a minimal SolverEngine for testing
	fn create_test_solver_engine() -> SolverEngine {
		let config: solver_config::Config = serde_json::from_value(serde_json::json!({
			"solver": {
				"id": "test-solver",
				"monitoring_timeout_seconds": 30,
				"min_profitability_pct": 1.0
			},
			"storage": {
				"primary": "memory",
				"cleanup_interval_seconds": 3600,
				"implementations": {
					"memory": {}
				}
			},
			"delivery": {
				"min_confirmations": 1,
				"implementations": {}
			},
			"account": {
				"primary": "local",
				"implementations": {
					"local": {
						"private_key": "0x1234567890123456789012345678901234567890123456789012345678901234"
					}
				}
			},
			"discovery": {
				"implementations": {}
			},
			"order": {
				"implementations": {},
				"strategy": {
					"primary": "simple",
					"implementations": {
						"simple": {}
					}
				}
			},
			"settlement": {
				"implementations": {}
			},
			"networks": {
				"1": {
					"chain_id": 1,
					"input_settler_address": "0x1111111111111111111111111111111111111111",
					"output_settler_address": "0x2222222222222222222222222222222222222222",
					"rpc_urls": [
						{ "http": "http://localhost:8545" }
					],
					"tokens": [
						{
							"symbol": "TEST",
							"address": "0x3333333333333333333333333333333333333333",
							"decimals": 18
						}
					]
				},
				"137": {
					"chain_id": 137,
					"input_settler_address": "0x1111111111111111111111111111111111111111",
					"output_settler_address": "0x2222222222222222222222222222222222222222",
					"rpc_urls": [
						{ "http": "http://localhost:8545" }
					],
					"tokens": [
						{
							"symbol": "TEST",
							"address": "0x3333333333333333333333333333333333333333",
							"decimals": 18
						}
					]
				}
			}
		}))
		.expect("Failed to parse test config");

		// Create mock services
		let storage = create_test_storage();
		let account = Arc::new(AccountService::new(Box::new(
			solver_account::implementations::local::LocalWallet::new(
				"0x1234567890123456789012345678901234567890123456789012345678901234",
			)
			.unwrap(),
		)));
		let solver_address = Address([0xAB; 20].to_vec());
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20, 60));
		let discovery = Arc::new(DiscoveryService::new(HashMap::new()));
		let strategy = solver_order::implementations::strategies::simple::create_strategy(
			&serde_json::Value::Object(serde_json::Map::new()),
		)
		.unwrap();
		let order = Arc::new(OrderService::new(HashMap::new(), strategy));
		let settlement = Arc::new(SettlementService::new(HashMap::new(), String::new(), 3));
		let pricing_impl = solver_pricing::implementations::mock::create_mock_pricing(
			&serde_json::Value::Object(serde_json::Map::new()),
		)
		.unwrap();
		let pricing = Arc::new(PricingService::new(pricing_impl, Vec::new()));
		let event_bus = EventBus::new(64);
		let networks: solver_types::NetworksConfig = HashMap::new();
		let token_manager = Arc::new(TokenManager::new(
			networks,
			delivery.clone(),
			account.clone(),
		));

		let dynamic_config = Arc::new(tokio::sync::RwLock::new(config.clone()));
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
	fn quote_cost_profit_service_is_shared_for_solver() {
		let solver = create_test_solver_engine();

		let first = quote_cost_profit_service(&solver);
		let second = quote_cost_profit_service(&solver);

		assert!(Arc::ptr_eq(&first, &second));
	}

	/// Creates a valid test quote request
	fn create_test_quote_request() -> GetQuoteRequest {
		let user_addr = AlloyAddress::from([0x11; 20]);
		let input_token_addr = AlloyAddress::from([0xA0; 20]);
		let receiver_addr = AlloyAddress::from([0x22; 20]);
		let output_token_addr = AlloyAddress::from([0xB0; 20]);

		GetQuoteRequest {
			user: InteropAddress::new_ethereum(1, user_addr),
			intent: IntentRequest {
				intent_type: IntentType::OifSwap,
				inputs: vec![QuoteInput {
					user: InteropAddress::new_ethereum(1, user_addr),
					asset: InteropAddress::new_ethereum(1, input_token_addr),
					amount: Some("1000000000000000000".to_string()), // 1 ETH
					lock: None,
				}],
				outputs: vec![QuoteOutput {
					receiver: InteropAddress::new_ethereum(137, receiver_addr),
					asset: InteropAddress::new_ethereum(137, output_token_addr),
					amount: Some("950000000000000000".to_string()), // 0.95 ETH equivalent
					calldata: None,
				}],
				swap_type: Some(SwapType::ExactInput),
				min_valid_until: None,
				preference: Some(QuotePreference::Speed),
				origin_submission: None,
				failure_handling: None,
				partial_fill: None,
				metadata: None,
			},
			supported_types: vec![oif_versions::escrow_order_type("v0")],
		}
	}

	fn create_quote_processing_request() -> GetQuoteRequest {
		let user_addr = AlloyAddress::from([0x11; 20]);
		let receiver_addr = AlloyAddress::from([0x22; 20]);

		GetQuoteRequest {
			user: InteropAddress::new_ethereum(1, user_addr),
			intent: IntentRequest {
				intent_type: IntentType::OifSwap,
				inputs: vec![QuoteInput {
					user: InteropAddress::new_ethereum(1, user_addr),
					asset: InteropAddress::new_ethereum(
						1,
						AlloyAddress::from_slice(
							&parse_address("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
								.unwrap()
								.0,
						),
					),
					amount: Some("1000000000".to_string()), // 1,000 USDC
					lock: None,
				}],
				outputs: vec![QuoteOutput {
					receiver: InteropAddress::new_ethereum(137, receiver_addr),
					asset: InteropAddress::new_ethereum(
						137,
						AlloyAddress::from_slice(
							&parse_address("0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174")
								.unwrap()
								.0,
						),
					),
					amount: None,
					calldata: None,
				}],
				swap_type: Some(SwapType::ExactInput),
				min_valid_until: None,
				preference: Some(QuotePreference::Speed),
				origin_submission: Some(OriginSubmission {
					mode: OriginMode::User,
					schemes: Some(vec![AuthScheme::Permit2]),
				}),
				failure_handling: None,
				partial_fill: Some(false),
				metadata: None,
			},
			supported_types: vec![oif_versions::escrow_order_type("v0")],
		}
	}

	fn create_quote_processing_config() -> solver_config::Config {
		let api_config = ApiConfig {
			enabled: true,
			host: "127.0.0.1".to_string(),
			port: 8080,
			timeout_seconds: 30,
			max_request_size: 1_048_576,
			implementations: Default::default(),
			rate_limiting: None,
			cors: None,
			auth: None,
			quote: Some(QuoteConfig {
				validity_seconds: 60,
				fill_deadline_seconds: 300,
				expires_seconds: 600,
				max_concurrent_requests: solver_config::DEFAULT_QUOTE_MAX_CONCURRENT_REQUESTS,
				max_stored_quotes: solver_config::DEFAULT_QUOTE_MAX_STORED_QUOTES,
			}),
		};

		let settlement_config = SettlementConfig {
			implementations: HashMap::new(),
			primary: "test".to_string(),
			settlement_poll_interval_seconds: 3,
		};

		let mut networks = solver_types::NetworksConfig::new();
		networks.insert(
			1,
			solver_types::NetworkConfig {
				name: Some("ethereum".to_string()),
				network_type: solver_types::networks::NetworkType::Parent,
				rpc_urls: vec![],
				input_settler_address: parse_address("0x1111111111111111111111111111111111111111")
					.unwrap(),
				output_settler_address: parse_address("0x2222222222222222222222222222222222222222")
					.unwrap(),
				tokens: vec![
					solver_types::TokenConfig {
						address: Address(vec![0u8; 20]),
						symbol: "ETH".to_string(),
						name: Some("Ether".to_string()),
						decimals: 18,
					},
					solver_types::TokenConfig {
						address: parse_address("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
							.unwrap(),
						symbol: "USDC".to_string(),
						name: Some("USD Coin".to_string()),
						decimals: 6,
					},
				],
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);
		networks.insert(
			137,
			solver_types::NetworkConfig {
				name: Some("polygon".to_string()),
				network_type: solver_types::networks::NetworkType::Hub,
				rpc_urls: vec![],
				input_settler_address: parse_address("0x3333333333333333333333333333333333333333")
					.unwrap(),
				output_settler_address: parse_address("0x4444444444444444444444444444444444444444")
					.unwrap(),
				tokens: vec![
					solver_types::TokenConfig {
						address: Address(vec![0u8; 20]),
						symbol: "POL".to_string(),
						name: Some("Polygon Ecosystem Token".to_string()),
						decimals: 18,
					},
					solver_types::TokenConfig {
						address: parse_address("0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174")
							.unwrap(),
						symbol: "USDC".to_string(),
						name: Some("USD Coin".to_string()),
						decimals: 6,
					},
				],
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);

		ConfigBuilder::new()
			.api(Some(api_config))
			.settlement(settlement_config)
			.networks(networks)
			.build()
	}

	fn add_broadcaster_min_expiry_to_quote_processing_config(
		config: &mut solver_config::Config,
		min_expiry_seconds: u64,
	) {
		config.settlement.implementations.insert(
			"test".to_string(),
			serde_json::json!({
				"oracles": {
					"input": {
						"1": ["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
					},
					"output": {
						"137": ["0xdddddddddddddddddddddddddddddddddddddddd"]
					}
				},
				"routes": {
					"1": [137]
				},
				"intent_min_expiry_seconds": min_expiry_seconds
			}),
		);
	}

	fn create_quote_processing_settlement_service() -> Arc<SettlementService> {
		let mut input_oracles = HashMap::new();
		let mut output_oracles = HashMap::new();
		let mut routes = HashMap::new();

		input_oracles.insert(1, vec![Address(vec![0xaa; 20])]);
		input_oracles.insert(137, vec![Address(vec![0xcc; 20])]);
		output_oracles.insert(1, vec![Address(vec![0xbb; 20])]);
		output_oracles.insert(137, vec![Address(vec![0xdd; 20])]);
		routes.insert(1, vec![137]);
		routes.insert(137, vec![1]);

		let mut mock_settlement = MockSettlementInterface::new();
		let route_support = routes.clone();
		mock_settlement
			.expect_oracle_config()
			.return_const(solver_settlement::OracleConfig {
				input_oracles,
				output_oracles,
				routes,
				selection_strategy: solver_settlement::OracleSelectionStrategy::First,
			});
		mock_settlement
			.expect_is_route_supported()
			.returning(move |input_chain, output_chain| {
				route_support
					.get(&input_chain)
					.is_some_and(|outputs| outputs.contains(&output_chain))
			});
		mock_settlement
			.expect_select_oracle()
			.returning(|oracles, _context| oracles.first().cloned());
		mock_settlement
			.expect_quote_post_fill_fee()
			.returning(|_| Box::pin(async { Ok(None) }));

		let mut implementations: HashMap<String, Box<dyn SettlementInterface>> = HashMap::new();
		implementations.insert("test".to_string(), Box::new(mock_settlement));

		Arc::new(SettlementService::new(
			implementations,
			"test".to_string(),
			3,
		))
	}

	fn create_quote_processing_solver_engine() -> SolverEngine {
		let config = create_quote_processing_config();

		let mut delivery_implementations: HashMap<u64, Arc<dyn DeliveryInterface>> = HashMap::new();

		let mut mock_delivery_1 = MockDeliveryInterface::new();
		mock_delivery_1
			.expect_get_fee_params()
			.returning(|chain_id| {
				Box::pin(
					async move { Ok(solver_delivery::FeeParams::legacy(chain_id, 1_000_000_000)) },
				)
			});
		mock_delivery_1
			.expect_get_balance()
			.returning(|_, _, _| Box::pin(async move { Ok("5000000000".to_string()) }));
		delivery_implementations.insert(1, Arc::new(mock_delivery_1) as Arc<dyn DeliveryInterface>);

		let mut mock_delivery_137 = MockDeliveryInterface::new();
		mock_delivery_137
			.expect_get_fee_params()
			.returning(|chain_id| {
				Box::pin(
					async move { Ok(solver_delivery::FeeParams::legacy(chain_id, 1_000_000_000)) },
				)
			});
		mock_delivery_137
			.expect_get_balance()
			.returning(|_, _, _| Box::pin(async move { Ok("5000000000".to_string()) }));
		// Quote-time live fill estimation: return an error so the cost path
		// silently falls back to the static `flows.<key>.fill` default. This
		// preserves the test's pre-live-estimate behavior.
		mock_delivery_137.expect_estimate_gas().returning(|_| {
			Box::pin(async move {
				Err(solver_delivery::DeliveryError::Network(
					"test mock: live estimate unavailable".into(),
				))
			})
		});
		delivery_implementations.insert(
			137,
			Arc::new(mock_delivery_137) as Arc<dyn DeliveryInterface>,
		);

		let storage = create_test_storage();
		let account = Arc::new(AccountService::new(Box::new(
			solver_account::implementations::local::LocalWallet::new(
				"0x1234567890123456789012345678901234567890123456789012345678901234",
			)
			.unwrap(),
		)));
		let solver_address = Address([0xAB; 20].to_vec());
		let delivery = Arc::new(DeliveryService::new(delivery_implementations, 1, 20, 60));
		let discovery = Arc::new(DiscoveryService::new(HashMap::new()));
		let strategy = solver_order::implementations::strategies::simple::create_strategy(
			&serde_json::Value::Object(serde_json::Map::new()),
		)
		.unwrap();
		let order = Arc::new(OrderService::new(HashMap::new(), strategy));
		let settlement = create_quote_processing_settlement_service();
		let pricing_impl =
			solver_pricing::implementations::mock::create_mock_pricing(&serde_json::json!({
				"pair_prices": {
					"ETH/USD": "2000.0",
					"POL/USD": "0.5",
					"USDC/USD": "1.0"
				}
			}))
			.unwrap();
		let pricing = Arc::new(PricingService::new(pricing_impl, Vec::new()));
		let event_bus = EventBus::new(64);
		let token_manager = Arc::new(TokenManager::new(
			config.networks.clone(),
			delivery.clone(),
			account.clone(),
		));

		let dynamic_config = Arc::new(tokio::sync::RwLock::new(config.clone()));
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

	/// Creates a test quote
	fn create_test_quote() -> Quote {
		let _input_token_addr = AlloyAddress::from([0xA0; 20]);
		let _output_token_addr = AlloyAddress::from([0xB0; 20]);

		Quote {
			order: OifOrder::OifEscrowV0 {
				payload: OrderPayload {
					signature_type: SignatureType::Eip712,
					domain: serde_json::json!({}),
					primary_type: "Order".to_string(),
					message: serde_json::json!({}),
					types: Some(serde_json::json!({})),
				},
			},
			failure_handling: FailureHandlingMode::RefundAutomatic,
			partial_fill: false,
			valid_until: current_timestamp() + 300, // 5 minutes from now
			eta: Some(60),
			quote_id: TEST_QUOTE_ID.to_string(),
			provider: Some("test_solver".to_string()),
			preview: QuotePreview {
				inputs: vec![],
				outputs: vec![],
			},
		}
	}

	fn quote_with_order(order: OifOrder) -> Quote {
		Quote {
			order,
			failure_handling: FailureHandlingMode::RefundAutomatic,
			partial_fill: false,
			valid_until: current_timestamp() + 300,
			eta: Some(60),
			quote_id: TEST_QUOTE_ID.to_string(),
			provider: Some("test_solver".to_string()),
			preview: QuotePreview {
				inputs: vec![],
				outputs: vec![],
			},
		}
	}

	fn valid_permit2_quote() -> Quote {
		quote_with_order(OifOrder::OifEscrowV0 {
			payload: OrderPayload {
				signature_type: SignatureType::Eip712,
				domain: serde_json::json!({
					"name": "Permit2",
					"chainId": 1,
					"verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3"
				}),
				primary_type: "PermitBatchWitnessTransferFrom".to_string(),
				message: serde_json::json!({
					"permitted": [{
						"token": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
						"amount": "1000"
					}],
					"nonce": "1",
					"deadline": "2",
					"witness": {
						"user": "0x1111111111111111111111111111111111111111",
						"expires": 3,
						"inputOracle": "0x2222222222222222222222222222222222222222",
						"outputs": [{
							"oracle": "0x0000000000000000000000003333333333333333333333333333333333333333",
							"settler": "0x0000000000000000000000004444444444444444444444444444444444444444",
							"chainId": 137,
							"token": "0x000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
							"amount": "900",
							"recipient": "0x0000000000000000000000005555555555555555555555555555555555555555",
							"callbackData": "0x",
							"context": "0x"
						}]
					}
				}),
				types: None,
			},
		})
	}

	fn valid_eip3009_quote() -> Quote {
		let user = InteropAddress::new_ethereum(1, AlloyAddress::from([0x11; 20])).to_string();
		let input_asset =
			InteropAddress::new_ethereum(1, AlloyAddress::from([0xA0; 20])).to_string();
		let output_asset =
			InteropAddress::new_ethereum(137, AlloyAddress::from([0xB0; 20])).to_string();
		let receiver =
			InteropAddress::new_ethereum(137, AlloyAddress::from([0x55; 20])).to_string();

		quote_with_order(OifOrder::Oif3009V0 {
			payload: OrderPayload {
				signature_type: SignatureType::Eip712,
				domain: serde_json::json!({
					"name": "USDC",
					"version": "2",
					"chainId": 1,
					"verifyingContract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
				}),
				primary_type: "ReceiveWithAuthorization".to_string(),
				message: serde_json::json!({
					"from": "0x1111111111111111111111111111111111111111",
					"to": "0x2222222222222222222222222222222222222222",
					"value": "1000",
					"validAfter": 0,
					"validBefore": 2,
					"nonce": "0x1111111111111111111111111111111111111111111111111111111111111111"
				}),
				types: None,
			},
			metadata: serde_json::json!({
				"domain_separator": "0x1111111111111111111111111111111111111111111111111111111111111111",
				"user": user,
				"nonce": 1,
				"originChainId": 1,
				"expires": 3,
				"fillDeadline": 2,
				"inputOracle": "0x2222222222222222222222222222222222222222",
				"inputs": [{
					"chainId": 1,
					"asset": input_asset,
					"amount": "1000",
					"user": user
				}],
				"outputs": [{
					"chainId": 137,
					"asset": output_asset,
					"amount": "900",
					"receiver": receiver,
					"oracle": "0x3333333333333333333333333333333333333333",
					"settler": "0x4444444444444444444444444444444444444444"
				}]
			}),
		})
	}

	fn valid_resource_lock_quote() -> Quote {
		quote_with_order(OifOrder::OifResourceLockV0 {
			payload: OrderPayload {
				signature_type: SignatureType::Eip712,
				domain: serde_json::json!({
					"name": "The Compact",
					"version": "1",
					"chainId": 1,
					"verifyingContract": "0x6666666666666666666666666666666666666666"
				}),
				primary_type: "BatchCompact".to_string(),
				message: serde_json::json!({
					"sponsor": "0x1111111111111111111111111111111111111111",
					"nonce": "1",
					"expires": "3",
					"commitments": [{
						"lockTag": "0x0102030405060708090a0b0c",
						"token": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
						"amount": "1000"
					}],
					"mandate": {
						"fillDeadline": "2",
						"inputOracle": "0x2222222222222222222222222222222222222222",
						"outputs": [{
							"oracle": "0x0000000000000000000000003333333333333333333333333333333333333333",
							"settler": "0x0000000000000000000000004444444444444444444444444444444444444444",
							"chainId": 137,
							"token": "0x000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
							"amount": "900",
							"recipient": "0x0000000000000000000000005555555555555555555555555555555555555555",
							"callbackData": "0x",
							"context": "0x"
						}]
					}
				}),
				types: None,
			},
		})
	}

	fn gate_binding_for_quote_order(quote: &Quote, lock_type: LockType) -> alloy_primitives::B256 {
		let standard = StandardOrder::try_from(&quote.order).expect("valid StandardOrder");
		let mut order_data = Eip7683OrderData::from(standard);
		order_data.lock_type = Some(lock_type);
		let parsed_lock_type = order_data.parse_lock_type();
		let inputs = order_data.parse_available_inputs();
		let outputs = order_data.parse_requested_outputs();

		assert!(
			!inputs.is_empty(),
			"gate-side derivation must parse non-empty inputs for {lock_type:?}"
		);
		assert!(
			!outputs.is_empty(),
			"gate-side derivation must parse non-empty outputs for {lock_type:?}"
		);

		solver_types::quote_order_binding(
			order_data.origin_chain_id(),
			parsed_lock_type.as_deref(),
			&inputs,
			&outputs,
		)
	}

	/// H-07 store↔gate agreement: the binding's flow key is derived on the **store**
	/// side via `OifOrder::flow_key()` (`binding_for_quote`) but on the **gate** side
	/// via `Eip7683OrderData::parse_lock_type()`, i.e. `LockType`'s `Display`
	/// (`Display` delegates to `as_str`). These two independent derivations must
	/// produce identical strings for every concrete order variant, or a legitimate
	/// quote redemption false-rejects at the profitability gate (a fail-closed
	/// outage). The gate's own tests build the stored binding with the gate-side
	/// derivation, so they cannot catch a store↔gate divergence; this pins it.
	#[test]
	fn flow_key_agrees_with_gate_lock_type_for_all_variants() {
		use solver_types::standards::eip7683::LockType;

		fn empty_payload() -> OrderPayload {
			OrderPayload {
				signature_type: SignatureType::Eip712,
				domain: serde_json::json!({}),
				primary_type: "Order".to_string(),
				message: serde_json::json!({}),
				types: Some(serde_json::json!({})),
			}
		}

		// (order variant, the LockType the gate derives via `parse_lock_type`)
		let cases = [
			(
				OifOrder::OifEscrowV0 {
					payload: empty_payload(),
				},
				LockType::Permit2Escrow,
			),
			(
				OifOrder::Oif3009V0 {
					payload: empty_payload(),
					metadata: serde_json::json!({}),
				},
				LockType::Eip3009Escrow,
			),
			(
				OifOrder::OifResourceLockV0 {
					payload: empty_payload(),
				},
				LockType::ResourceLock,
			),
		];

		for (order, gate_lock_type) in cases {
			// Gate side computes `parse_lock_type()` == `lock_type.to_string()`.
			// Store side computes `flow_key()`. They MUST match.
			assert_eq!(
				order.flow_key().as_deref(),
				Some(gate_lock_type.to_string().as_str()),
				"store-side flow_key() must equal gate-side parse_lock_type() for \
				 {gate_lock_type:?}; a divergence false-rejects every redemption of \
				 this variant",
			);
		}

		// Generic orders intentionally carry no flow key and no economic binding;
		// the gate falls back to the fresh breakdown on a `None` binding.
		assert_eq!(
			OifOrder::OifGenericV0 {
				payload: serde_json::json!({})
			}
			.flow_key(),
			None,
		);
	}

	#[test]
	fn binding_for_quote_matches_gate_derivation_for_all_concrete_flows() {
		let cases = [
			(valid_permit2_quote(), LockType::Permit2Escrow),
			(valid_eip3009_quote(), LockType::Eip3009Escrow),
			(valid_resource_lock_quote(), LockType::ResourceLock),
		];

		for (quote, lock_type) in cases {
			let stored_binding = binding_for_quote(&quote).expect("quote binding");
			let gate_binding = gate_binding_for_quote_order(&quote, lock_type);

			assert_eq!(
				stored_binding, gate_binding,
				"store-side binding_for_quote() must match gate-side parse_lock_type() \
					 derivation for {lock_type:?}",
			);
		}
	}

	#[test]
	fn binding_for_quote_returns_none_for_generic_orders() {
		let quote = quote_with_order(OifOrder::OifGenericV0 {
			payload: serde_json::json!({}),
		});

		assert_eq!(binding_for_quote(&quote), None);
	}

	/// Creates a test cost context
	fn create_test_cost_context() -> CostContext {
		CostContext {
			cost_breakdown: CostBreakdown {
				gas_open: rust_decimal::Decimal::new(1, 2), // 0.01
				gas_fill: rust_decimal::Decimal::new(2, 2), // 0.02
				gas_post_fill: rust_decimal::Decimal::ZERO,
				gas_pre_claim: rust_decimal::Decimal::ZERO,
				gas_claim: rust_decimal::Decimal::new(1, 2),  // 0.01
				gas_buffer: rust_decimal::Decimal::new(4, 3), // 0.004
				settlement_fee: rust_decimal::Decimal::ZERO,
				settlement_fee_buffer: rust_decimal::Decimal::ZERO,
				l1_data_fee: rust_decimal::Decimal::ZERO,
				l1_data_fee_buffer: rust_decimal::Decimal::ZERO,
				rate_buffer: rust_decimal::Decimal::ZERO,
				base_price: rust_decimal::Decimal::ZERO,
				min_profit: rust_decimal::Decimal::new(5, 0), // 5.0
				operational_cost: rust_decimal::Decimal::new(44, 3), // 0.044
				subtotal: rust_decimal::Decimal::new(44, 3),  // 0.044
				total: rust_decimal::Decimal::new(44, 3),     // 0.044
				currency: "USD".to_string(),
			},
			execution_costs_by_chain: HashMap::new(),
			liquidity_cost_adjustment: rust_decimal::Decimal::ZERO,
			protocol_fees: HashMap::new(),
			swap_type: SwapType::ExactInput,
			cost_amounts_in_tokens: HashMap::new(),
			swap_amounts: HashMap::new(),
			adjusted_amounts: HashMap::new(),
		}
	}

	/// Creates a test stored quote record.
	fn create_test_stored_quote() -> StoredQuote {
		StoredQuote {
			quote: create_test_quote(),
			cost_context: create_test_cost_context(),
			settlement_name: None,
			binding: None,
		}
	}

	#[tokio::test]
	async fn test_store_quotes_success() {
		let solver = create_test_solver_engine();
		let quotes = vec![(create_test_quote(), None)];
		let cost_context = create_test_cost_context();

		// Test the actual store_quotes function (large cap → no eviction)
		store_quotes(&solver, &quotes, &cost_context, usize::MAX).await;

		// Verify the quote was stored by trying to retrieve it using the public API
		let result = get_quote_by_id(TEST_QUOTE_ID, &solver).await;
		assert!(result.is_ok());
		assert_eq!(result.unwrap().quote_id, TEST_QUOTE_ID);
	}

	#[tokio::test]
	async fn test_store_quotes_with_expired_quote() {
		let solver = create_test_solver_engine();

		let mut quote = create_test_quote();
		// Set quote to be already expired
		quote.valid_until = current_timestamp() - 100;
		let quotes = vec![(quote, None)];
		let cost_context = create_test_cost_context();

		// Test the actual store_quotes function with expired quote
		store_quotes(&solver, &quotes, &cost_context, usize::MAX).await;

		// Verify the quote was still stored (memory storage ignores TTL)
		// Use the public API to retrieve it
		let result = get_quote_by_id(TEST_QUOTE_ID, &solver).await;
		assert!(result.is_ok());
		assert_eq!(result.unwrap().quote_id, TEST_QUOTE_ID);
	}

	#[tokio::test]
	async fn test_get_quote_by_id_success() {
		let solver = create_test_solver_engine();
		let stored_quote = create_test_stored_quote();

		// Store the quote first using direct storage access (setup)
		solver
			.storage()
			.store(
				StorageKey::Quotes.as_str(),
				TEST_QUOTE_ID,
				&stored_quote,
				None,
			)
			.await
			.unwrap();

		// Test the actual get_quote_by_id function
		let result = get_quote_by_id(TEST_QUOTE_ID, &solver).await;
		assert!(result.is_ok());
		assert_eq!(result.unwrap().quote_id, TEST_QUOTE_ID);
	}

	#[tokio::test]
	async fn test_get_quote_by_id_not_found() {
		let solver = create_test_solver_engine();

		// Test the actual get_quote_by_id function with nonexistent quote
		let result = get_quote_by_id("nonexistent_quote", &solver).await;
		assert!(result.is_err());
		match result.unwrap_err() {
			QuoteError::InvalidRequest(msg) => assert!(msg.contains("Quote not found")),
			_ => panic!("Expected InvalidRequest error"),
		}
	}

	#[tokio::test]
	async fn test_quote_exists_true() {
		let solver = create_test_solver_engine();
		let stored_quote = create_test_stored_quote();

		// Store the quote first using direct storage access (setup)
		solver
			.storage()
			.store(
				StorageKey::Quotes.as_str(),
				TEST_QUOTE_ID,
				&stored_quote,
				None,
			)
			.await
			.unwrap();

		// Test the actual quote_exists function
		let result = quote_exists(TEST_QUOTE_ID, &solver).await;
		assert!(result.is_ok());
		assert!(result.unwrap());
	}

	#[tokio::test]
	async fn test_quote_exists_false() {
		let solver = create_test_solver_engine();

		// Test the actual quote_exists function with nonexistent quote
		let result = quote_exists("nonexistent_quote", &solver).await;
		assert!(result.is_ok());
		assert!(!result.unwrap());
	}

	#[test]
	fn test_stored_quote_serialization() {
		let stored_quote = create_test_stored_quote();

		// Test that the structure can be serialized/deserialized
		let serialized = serde_json::to_string(&stored_quote).expect("Should serialize");
		let deserialized: StoredQuote =
			serde_json::from_str(&serialized).expect("Should deserialize");

		assert_eq!(deserialized.quote.quote_id, TEST_QUOTE_ID);
		assert_eq!(deserialized.cost_context.swap_type, SwapType::ExactInput);
	}

	#[test]
	fn test_storage_key_quotes() {
		assert_eq!(StorageKey::Quotes.as_str(), "quotes");
	}

	// Helper function tests
	#[test]
	fn test_create_test_quote_has_valid_structure() {
		let quote = create_test_quote();
		assert_eq!(quote.quote_id, TEST_QUOTE_ID);
		assert!(quote.valid_until > current_timestamp());
		assert_eq!(quote.failure_handling, FailureHandlingMode::RefundAutomatic);
		assert!(!quote.partial_fill);
		assert_eq!(quote.eta, Some(60));
		assert_eq!(quote.provider, Some("test_solver".to_string()));
	}

	#[test]
	fn test_create_test_cost_context_has_valid_structure() {
		let cost_context = create_test_cost_context();
		assert_eq!(cost_context.swap_type, SwapType::ExactInput);
		assert_eq!(cost_context.cost_breakdown.currency, "USD");
		assert!(cost_context.cost_breakdown.total > rust_decimal::Decimal::ZERO);
	}

	#[test]
	fn test_create_test_quote_request_has_valid_structure() {
		let request = create_test_quote_request();
		assert_eq!(request.intent.intent_type, IntentType::OifSwap);
		assert_eq!(request.intent.inputs.len(), 1);
		assert_eq!(request.intent.outputs.len(), 1);
		assert_eq!(request.intent.swap_type, Some(SwapType::ExactInput));
		assert_eq!(request.intent.preference, Some(QuotePreference::Speed));
		assert_eq!(request.supported_types.len(), 1);
	}

	#[tokio::test]
	async fn test_process_quote_request_rejects_multi_input_shape() {
		let solver = create_test_solver_engine();
		let mut request = create_test_quote_request();
		let user_addr = AlloyAddress::from([0x11; 20]);
		let second_input_token_addr = AlloyAddress::from([0xC0; 20]);
		let output_token_addr = AlloyAddress::from([0xB0; 20]);

		request.intent.inputs.push(QuoteInput {
			user: InteropAddress::new_ethereum(1, user_addr),
			asset: InteropAddress::new_ethereum(1, second_input_token_addr),
			amount: Some("500000000000000000".to_string()),
			lock: None,
		});
		request.intent.outputs[0] = QuoteOutput {
			receiver: InteropAddress::new_ethereum(137, AlloyAddress::from([0x22; 20])),
			asset: InteropAddress::new_ethereum(137, output_token_addr),
			amount: Some("950000000000000000".to_string()),
			calldata: None,
		};

		let config_guard = solver.dynamic_config().read().await;
		let result = process_quote_request(request, &solver, &config_guard).await;
		drop(config_guard);

		assert!(
			matches!(result, Err(QuoteError::UnsupportedQuoteShape(msg)) if msg.contains("multi-input"))
		);
	}

	#[tokio::test]
	async fn test_process_quote_request_rejects_when_intake_disabled() {
		let solver = create_test_solver_engine();
		let request = create_test_quote_request();
		let mut config = solver.dynamic_config().read().await.clone();
		config.solver.ingress_mode = solver_config::SolverIngressMode::IntakeDisabled;

		let result = process_quote_request(request, &solver, &config).await;

		assert!(matches!(result, Err(QuoteError::SolverIntakeDisabled)));
	}

	#[tokio::test]
	async fn test_process_quote_request_single_input_success() {
		let solver = create_quote_processing_solver_engine();
		let request = create_quote_processing_request();

		let config_guard = solver.dynamic_config().read().await;
		let result = process_quote_request(request, &solver, &config_guard).await;
		drop(config_guard);

		assert!(
			result.is_ok(),
			"expected quote generation to succeed: {result:?}"
		);

		let response = result.unwrap();
		assert_eq!(response.quotes.len(), 1);
		assert_eq!(response.quotes[0].provider.as_deref(), Some("oif-solver"));
		assert_eq!(response.quotes[0].eta, Some(96));
		assert!(!response.quotes[0].quote_id.is_empty());
	}

	#[tokio::test]
	async fn test_process_quote_request_clamps_permit2_expiry_to_broadcaster_window() {
		let solver = create_quote_processing_solver_engine();
		let request = create_quote_processing_request();
		let mut config = solver.dynamic_config().read().await.clone();
		add_broadcaster_min_expiry_to_quote_processing_config(&mut config, 3_600);

		let before = current_timestamp();
		let result = process_quote_request(request, &solver, &config).await;

		assert!(
			result.is_ok(),
			"expected quote generation to succeed: {result:?}"
		);

		let response = result.unwrap();
		let quote = &response.quotes[0];
		match &quote.order {
			OifOrder::OifEscrowV0 { payload } => {
				let expires = payload.message["witness"]["expires"]
					.as_u64()
					.expect("Permit2 witness expires should be numeric");
				assert!(
					expires >= before + 3_900,
					"expires={expires} should cover fill_deadline_seconds + broadcaster minimum"
				);
			},
			other => panic!("expected Permit2 escrow quote, got {other:?}"),
		}
	}
}
