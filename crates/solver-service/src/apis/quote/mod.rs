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

// Re-export main functionality
pub use generation::QuoteGenerator;
pub use signing::payloads::permit2;
pub use validation::QuoteValidator;

use solver_config::Config;
use solver_core::SolverEngine;
use solver_types::{
	CostContext, GetQuoteRequest, GetQuoteResponse, Quote, QuoteError, QuoteWithCostContext,
	StorageKey,
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

	let cost_profit_service = solver_core::engine::cost_profit::CostProfitService::new(
		solver.pricing().clone(),
		solver.delivery().clone(),
		solver.token_manager().clone(),
		solver.storage().clone(),
	);

	let cost_context = cost_profit_service
		.calculate_cost_context(&request, &validated_context, config)
		.await
		.map_err(|e| QuoteError::Internal(format!("Failed to calculate cost context: {}", e)))?;

	// Check solver capabilities: networks only (token support is enforced during collection below)
	QuoteValidator::validate_supported_networks(&request, solver)?;

	// Validate and collect assets with cost-adjusted amounts
	let _supported_inputs =
		QuoteValidator::validate_and_collect_inputs_with_costs(&request, solver, &cost_context)?;

	let supported_outputs =
		QuoteValidator::validate_and_collect_outputs_with_costs(&request, solver, &cost_context)?;

	// Check destination balances for cost-adjusted output amounts
	QuoteValidator::ensure_destination_balances_with_costs(
		solver,
		&supported_outputs,
		&validated_context,
		&cost_context,
	)
	.await?;

	// Generate quotes using the business logic layer with embedded costs
	let settlement_service = solver.settlement();
	let delivery_service = solver.delivery();
	let quote_generator = QuoteGenerator::new(settlement_service.clone(), delivery_service.clone());

	let quotes = quote_generator
		.generate_quotes_with_costs(&request, &validated_context, &cost_context, config)
		.await?;

	// Persist quotes and cost contexts
	store_quotes(solver, &quotes, &cost_context).await;

	info!("Generated and stored {} quote options", quotes.len());

	Ok(GetQuoteResponse { quotes })
}

/// Stores generated quotes with their cost contexts.
///
/// Each quote is stored together with its cost context as a QuoteWithCostContext structure.
/// Storage errors are logged but do not fail the request.
async fn store_quotes(solver: &SolverEngine, quotes: &[Quote], cost_context: &CostContext) {
	let storage = solver.storage();
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs();

	for quote in quotes {
		// Calculate TTL from valid_until timestamp
		let ttl = if quote.valid_until > now {
			Duration::from_secs(quote.valid_until - now)
		} else {
			// Quote is already expired, store with minimal TTL
			Duration::from_secs(1)
		};

		// Create combined structure with quote and cost context
		let quote_with_context = QuoteWithCostContext {
			quote: quote.clone(),
			cost_context: cost_context.clone(),
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
		.retrieve::<QuoteWithCostContext>(StorageKey::Quotes.as_str(), quote_id)
		.await
	{
		Ok(quote_with_context) => {
			tracing::debug!("Retrieved quote {} from storage", quote_id);
			Ok(quote_with_context.quote)
		},
		Err(e) => {
			tracing::warn!("Failed to retrieve quote {}: {}", quote_id, e);
			Err(QuoteError::InvalidRequest(format!(
				"Quote not found: {}",
				quote_id
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
			Err(QuoteError::Internal(format!("Storage error: {}", e)))
		},
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::Address as AlloyAddress;
	use solver_storage::{implementations::memory::MemoryStorage, StorageService};
	use solver_types::{
		current_timestamp, oif_versions, CostBreakdown, CostContext, FailureHandlingMode,
		GetQuoteRequest, IntentRequest, IntentType, InteropAddress, OifOrder, OrderPayload, Quote,
		QuoteError, QuoteInput, QuoteOutput, QuotePreference, QuotePreview, QuoteWithCostContext,
		SignatureType, StorageKey, SwapType,
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

	/// Creates a mock SolverEngine for testing that only implements the storage interface
	struct MockSolverEngine {
		storage: Arc<StorageService>,
	}

	impl MockSolverEngine {
		fn new(storage: Arc<StorageService>) -> Self {
			Self { storage }
		}

		fn storage(&self) -> &Arc<StorageService> {
			&self.storage
		}
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

	/// Creates a test quote with cost context
	fn create_test_quote_with_context() -> QuoteWithCostContext {
		QuoteWithCostContext {
			quote: create_test_quote(),
			cost_context: create_test_cost_context(),
		}
	}

	#[tokio::test]
	async fn test_store_quotes_success() {
		let storage = create_test_storage();
		let mock_solver = MockSolverEngine::new(storage);
		let quotes = vec![create_test_quote()];
		let cost_context = create_test_cost_context();

		// Test store_quotes by directly calling the storage operations
		let storage = mock_solver.storage();
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs();

		for quote in &quotes {
			let ttl = if quote.valid_until > now {
				Duration::from_secs(quote.valid_until - now)
			} else {
				Duration::from_secs(1)
			};

			let quote_with_context = QuoteWithCostContext {
				quote: quote.clone(),
				cost_context: cost_context.clone(),
			};

			storage
				.store_with_ttl(
					StorageKey::Quotes.as_str(),
					&quote.quote_id,
					&quote_with_context,
					None,
					Some(ttl),
				)
				.await
				.expect("Should store quote successfully");
		}

		// Verify the quote was stored by trying to retrieve it
		let stored_quote: Result<QuoteWithCostContext, _> = mock_solver
			.storage()
			.retrieve(StorageKey::Quotes.as_str(), TEST_QUOTE_ID)
			.await;
		assert!(stored_quote.is_ok());
		assert_eq!(stored_quote.unwrap().quote.quote_id, TEST_QUOTE_ID);
	}

	#[tokio::test]
	async fn test_store_quotes_with_expired_quote() {
		let storage = create_test_storage();
		let mock_solver = MockSolverEngine::new(storage);

		let mut quote = create_test_quote();
		// Set quote to be already expired
		quote.valid_until = current_timestamp() - 100;
		let quotes = vec![quote];
		let cost_context = create_test_cost_context();

		// Test store_quotes with expired quote
		let storage = mock_solver.storage();
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs();

		for quote in &quotes {
			let ttl = if quote.valid_until > now {
				Duration::from_secs(quote.valid_until - now)
			} else {
				Duration::from_secs(1) // Minimal TTL for expired quotes
			};

			let quote_with_context = QuoteWithCostContext {
				quote: quote.clone(),
				cost_context: cost_context.clone(),
			};

			storage
				.store_with_ttl(
					StorageKey::Quotes.as_str(),
					&quote.quote_id,
					&quote_with_context,
					None,
					Some(ttl),
				)
				.await
				.expect("Should store expired quote successfully");
		}

		// Verify the quote was still stored (memory storage ignores TTL)
		let stored_quote: Result<QuoteWithCostContext, _> = mock_solver
			.storage()
			.retrieve(StorageKey::Quotes.as_str(), TEST_QUOTE_ID)
			.await;
		assert!(stored_quote.is_ok());
	}

	#[tokio::test]
	async fn test_get_quote_by_id_success() {
		let storage = create_test_storage();
		let mock_solver = MockSolverEngine::new(storage);
		let quote_with_context = create_test_quote_with_context();

		// Store the quote first
		mock_solver
			.storage()
			.store(
				StorageKey::Quotes.as_str(),
				TEST_QUOTE_ID,
				&quote_with_context,
				None,
			)
			.await
			.unwrap();

		// Test retrieval using storage directly
		let stored_quote: Result<QuoteWithCostContext, _> = mock_solver
			.storage()
			.retrieve(StorageKey::Quotes.as_str(), TEST_QUOTE_ID)
			.await;
		let result = stored_quote
			.map(|qwc| qwc.quote)
			.map_err(|_| QuoteError::InvalidRequest(format!("Quote not found: {}", TEST_QUOTE_ID)));
		assert!(result.is_ok());
		assert_eq!(result.unwrap().quote_id, TEST_QUOTE_ID);
	}

	#[tokio::test]
	async fn test_get_quote_by_id_not_found() {
		let storage = create_test_storage();
		let mock_solver = MockSolverEngine::new(storage);

		// Test retrieval of nonexistent quote using storage directly
		let stored_quote: Result<QuoteWithCostContext, _> = mock_solver
			.storage()
			.retrieve(StorageKey::Quotes.as_str(), "nonexistent_quote")
			.await;
		let result = stored_quote.map(|qwc| qwc.quote).map_err(|_| {
			QuoteError::InvalidRequest("Quote not found: nonexistent_quote".to_string())
		});
		assert!(result.is_err());
		match result.unwrap_err() {
			QuoteError::InvalidRequest(msg) => assert!(msg.contains("Quote not found")),
			_ => panic!("Expected InvalidRequest error"),
		}
	}

	#[tokio::test]
	async fn test_quote_exists_true() {
		let storage = create_test_storage();
		let mock_solver = MockSolverEngine::new(storage);
		let quote_with_context = create_test_quote_with_context();

		// Store the quote first
		mock_solver
			.storage()
			.store(
				StorageKey::Quotes.as_str(),
				TEST_QUOTE_ID,
				&quote_with_context,
				None,
			)
			.await
			.unwrap();

		// Test quote existence using storage directly
		let result = mock_solver
			.storage()
			.exists(StorageKey::Quotes.as_str(), TEST_QUOTE_ID)
			.await
			.map_err(|e| QuoteError::Internal(format!("Storage error: {}", e)));
		assert!(result.is_ok());
		assert!(result.unwrap());
	}

	#[tokio::test]
	async fn test_quote_exists_false() {
		let storage = create_test_storage();
		let mock_solver = MockSolverEngine::new(storage);

		// Test nonexistent quote using storage directly
		let result = mock_solver
			.storage()
			.exists(StorageKey::Quotes.as_str(), "nonexistent_quote")
			.await
			.map_err(|e| QuoteError::Internal(format!("Storage error: {}", e)));
		assert!(result.is_ok());
		assert!(!result.unwrap());
	}

	#[test]
	fn test_quote_with_cost_context_serialization() {
		let quote_with_context = create_test_quote_with_context();

		// Test that the structure can be serialized/deserialized
		let serialized = serde_json::to_string(&quote_with_context).expect("Should serialize");
		let deserialized: QuoteWithCostContext =
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
}
