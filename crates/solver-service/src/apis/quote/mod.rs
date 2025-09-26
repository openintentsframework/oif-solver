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
use solver_types::{GetQuoteRequest, GetQuoteResponse, Quote, QuoteError, StorageKey};

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

	// Persist quotes
	store_quotes(solver, &quotes).await;

	info!("Generated and stored {} quote options", quotes.len());

	Ok(GetQuoteResponse { quotes })
}

/// Stores generated quotes with TTL based on their valid_until timestamp.
///
/// Storage errors are logged but do not fail the request.
async fn store_quotes(solver: &SolverEngine, quotes: &[Quote]) {
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

		if let Err(e) = storage
			.store_with_ttl(
				StorageKey::Quotes.as_str(),
				&quote.quote_id,
				quote,
				None, // No indexes needed for quotes
				Some(ttl),
			)
			.await
		{
			tracing::warn!("Failed to store quote {}: {}", quote.quote_id, e);
		} else {
			tracing::debug!(
				"Stored quote {} with TTL {:?} (valid_until: {})",
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
		.retrieve::<Quote>(StorageKey::Quotes.as_str(), quote_id)
		.await
	{
		Ok(quote) => {
			tracing::debug!("Retrieved quote {} from storage", quote_id);
			Ok(quote)
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
