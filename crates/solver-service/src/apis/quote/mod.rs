//! Quote Business Logic Module
//!
//! This module contains the core business logic for quote processing,
//! separated from the HTTP API layer for better maintainability and testing.

pub mod custody;
pub mod generation;
pub mod validation;

// Re-export main functionality
pub use generation::QuoteGenerator;
pub use validation::QuoteValidator;

// Main API function
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
		request.available_inputs.len()
	);

	// 1. Validate the request
	QuoteValidator::validate_request(&request)?;

	// 2. Check solver capabilities
	// TODO: Implement solver capability checking

	// 3. Generate quotes using the business logic layer
	let quote_generator = QuoteGenerator::new();
	let quotes = quote_generator.generate_quotes(&request, config).await?;

	// 4. Persist quotes
	let quote_ttl = Duration::from_secs(300);
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
		}
		Err(e) => {
			tracing::warn!("Failed to retrieve quote {}: {}", quote_id, e);
			Err(QuoteError::InvalidRequest(format!(
				"Quote not found: {}",
				quote_id
			)))
		}
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
		}
		Err(e) => {
			tracing::warn!("Failed to check quote existence {}: {}", quote_id, e);
			Err(QuoteError::Internal(format!("Storage error: {}", e)))
		}
	}
}
