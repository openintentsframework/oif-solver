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
pub mod validation;

use self::generation::QuoteGenerator;

// Re-export quote helpers
pub use signing::payloads::permit2;
pub use validation::QuoteValidator;

use solver_config::Config;
use solver_core::SolverEngine;
use solver_types::{
	CostContext, GetQuoteRequest, GetQuoteResponse, Quote, QuoteError, StorageKey, StoredQuote,
};

use std::time::Duration;
use tracing::info;

/// Processes a quote request and returns available quote options.
///
/// This is the main HTTP API entry point that orchestrates the quote processing
/// pipeline by delegating to specialized modules.
pub async fn process_quote_request(
	request: GetQuoteRequest,
	solver: &SolverEngine,
	config: &Config,
) -> Result<GetQuoteResponse, QuoteError> {
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

	let settlement_service = solver.settlement();
	let delivery_service = solver.delivery();
	let quote_generator = QuoteGenerator::new(settlement_service.clone(), delivery_service.clone());
	let resolved_request = quote_generator.resolve_quote_request(&request).await?;
	let resolved_flow_keys = vec![resolved_request.flow_key.clone()];

	let cost_profit_service = solver_core::engine::cost_profit::CostProfitService::new(
		solver.pricing().clone(),
		solver.delivery().clone(),
		solver.token_manager().clone(),
		solver.storage().clone(),
	);

	let cost_context = cost_profit_service
		.calculate_cost_context_for_flow_keys(
			&request,
			&validated_context,
			config,
			&resolved_flow_keys,
		)
		.await
		.map_err(|e| QuoteError::Internal(format!("Failed to calculate cost context: {e}")))?;

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

	// Check destination balances for cost-adjusted output amounts
	QuoteValidator::ensure_destination_balances_with_costs(
		solver,
		&supported_outputs,
		&validated_context,
		&cost_context,
	)
	.await?;

	let quote_pairs = quote_generator
		.generate_quotes_with_costs_resolved(
			&request,
			&validated_context,
			&cost_context,
			config,
			&resolved_request,
		)
		.await?;

	// Persist quotes and cost contexts (including settlement_name internally)
	store_quotes(solver, &quote_pairs, &cost_context).await;

	let quotes: Vec<Quote> = quote_pairs.into_iter().map(|(q, _)| q).collect();
	info!("Generated and stored {} quote options", quotes.len());

	Ok(GetQuoteResponse { quotes })
}

/// Stores generated quotes with their cost contexts.
///
/// Each quote is stored together with its cost context as a StoredQuote record.
/// Storage errors are logged but do not fail the request.
async fn store_quotes(
	solver: &SolverEngine,
	quotes: &[(Quote, Option<String>)],
	cost_context: &CostContext,
) {
	let storage = solver.storage();
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs();

	for (quote, settlement_name) in quotes {
		// Calculate TTL from valid_until timestamp
		let ttl = if quote.valid_until > now {
			Duration::from_secs(quote.valid_until - now)
		} else {
			// Quote is already expired, store with minimal TTL
			Duration::from_secs(1)
		};

		// Create combined structure with quote and cost context
		let quote_with_context = StoredQuote {
			quote: quote.clone(),
			cost_context: cost_context.clone(),
			settlement_name: settlement_name.clone(),
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
		}
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
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20));
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
				tokens: vec![solver_types::TokenConfig {
					address: parse_address("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap(),
					symbol: "USDC".to_string(),
					name: Some("USD Coin".to_string()),
					decimals: 6,
				}],
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
				tokens: vec![solver_types::TokenConfig {
					address: parse_address("0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174").unwrap(),
					symbol: "USDC".to_string(),
					name: Some("USD Coin".to_string()),
					decimals: 6,
				}],
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
			.expect_get_gas_price()
			.returning(|_| Box::pin(async move { Ok("1000000000".to_string()) }));
		mock_delivery_1
			.expect_get_balance()
			.returning(|_, _, _| Box::pin(async move { Ok("5000000000".to_string()) }));
		delivery_implementations.insert(1, Arc::new(mock_delivery_1) as Arc<dyn DeliveryInterface>);

		let mut mock_delivery_137 = MockDeliveryInterface::new();
		mock_delivery_137
			.expect_get_gas_price()
			.returning(|_| Box::pin(async move { Ok("1000000000".to_string()) }));
		mock_delivery_137
			.expect_get_balance()
			.returning(|_, _, _| Box::pin(async move { Ok("5000000000".to_string()) }));
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
		let delivery = Arc::new(DeliveryService::new(delivery_implementations, 1, 20));
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

	/// Creates a test cost context
	fn create_test_cost_context() -> CostContext {
		CostContext {
			cost_breakdown: CostBreakdown {
				gas_open: rust_decimal::Decimal::new(1, 2),   // 0.01
				gas_fill: rust_decimal::Decimal::new(2, 2),   // 0.02
				gas_claim: rust_decimal::Decimal::new(1, 2),  // 0.01
				gas_buffer: rust_decimal::Decimal::new(4, 3), // 0.004
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
		}
	}

	#[tokio::test]
	async fn test_store_quotes_success() {
		let solver = create_test_solver_engine();
		let quotes = vec![(create_test_quote(), None)];
		let cost_context = create_test_cost_context();

		// Test the actual store_quotes function
		store_quotes(&solver, &quotes, &cost_context).await;

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
		store_quotes(&solver, &quotes, &cost_context).await;

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
			receiver: InteropAddress::new_ethereum(1, AlloyAddress::from([0x22; 20])),
			asset: InteropAddress::new_ethereum(1, output_token_addr),
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
}
