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
//! - ERC-3009 for native gasless transfers
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

use solver_config::{Config, QuoteConfig};
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
		request.available_inputs.len()
	);

	// Validate the request
	QuoteValidator::validate_request(&request)?;

	// Check solver capabilities: networks only (token support is enforced during collection below)
	QuoteValidator::validate_supported_networks(&request, solver)?;

	// Collect supported assets for this request (for later use: balances/custody/pricing)
	let (_supported_inputs, supported_outputs) = (
		QuoteValidator::collect_supported_available_inputs(&request, solver)?,
		QuoteValidator::validate_and_collect_requested_outputs(&request, solver)?,
	);

	// Check destination balances for required outputs
	QuoteValidator::ensure_destination_balances(solver, &supported_outputs).await?;

	// Generate quotes using the business logic layer
	let settlement_service = solver.settlement();
	let quote_generator = QuoteGenerator::new(settlement_service.clone());
	let mut quotes = quote_generator.generate_quotes(&request, config).await?;

	// Enrich quotes with a preliminary cost breakdown using CostProfitService
	let cost_profit_service = solver_core::engine::cost_profit::CostProfitService::new(
		solver.pricing().clone(),
		solver.delivery().clone(),
		solver.token_manager().clone(),
	);

	for quote in &mut quotes {
		match cost_profit_service
			.estimate_cost_for_quote(quote, config)
			.await
		{
			Ok(cost) => {
				quote.cost = Some(cost);
			},
			Err(e) => {
				tracing::warn!("Failed to estimate cost for quote {}: {}", quote.quote_id, e);
			},
		}
	}

	// Persist quotes
	let validity_seconds = config
		.api
		.as_ref()
		.and_then(|api| api.quote.as_ref())
		.map(|quote| quote.validity_seconds)
		.unwrap_or_else(|| QuoteConfig::default().validity_seconds);
	let quote_ttl = Duration::from_secs(validity_seconds);
	store_quotes(solver, &quotes, quote_ttl).await;

	info!("Generated and stored {} quote options", quotes.len());

	Ok(GetQuoteResponse { quotes })
}

/// Stores generated quotes with a given TTL.
///
/// Storage errors are logged but do not fail the request.
async fn store_quotes(solver: &SolverEngine, quotes: &[Quote], ttl: Duration) {
	let storage = solver.storage();

	for quote in quotes {
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
			tracing::debug!("Stored quote {} with TTL {:?}", quote.quote_id, ttl);
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
