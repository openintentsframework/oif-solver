//! Quote operations module
//!
//! Provides functionality for requesting, processing, and signing quotes for
//! cross-chain intents. Handles quote retrieval from solver APIs, signature
//! generation, and order creation with comprehensive testing capabilities.

use crate::{
	core::logging,
	types::{
		chain::ChainId,
		error::{Error, Result},
	},
	Context, GetQuoteRequest, GetQuoteResponse, PostOrderRequest,
};
use alloy_primitives::U256;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::instrument;

/// Quote operations handler
///
/// Provides methods for managing quote lifecycle including request generation,
/// API communication, signature creation, and order submission. Supports both
/// file-based and programmatic quote operations with integrated testing capabilities.
pub struct QuoteOps {
	ctx: Arc<Context>,
}

impl QuoteOps {
	/// Creates a new quote operations handler
	///
	/// # Arguments
	/// * `ctx` - Shared application context containing configuration and services
	///
	/// # Returns
	/// New quote operations instance
	pub fn new(ctx: Arc<Context>) -> Self {
		Self { ctx }
	}

	/// Retrieves a quote from the solver API using a request file
	///
	/// # Arguments
	/// * `input_file` - Path to JSON file containing quote request parameters
	///
	/// # Returns
	/// Quote response containing available quotes and pricing information
	///
	/// # Errors
	/// Returns error if request file missing, API call fails, or response invalid
	#[instrument(skip(self))]
	pub async fn get(&self, input_file: &std::path::Path) -> Result<GetQuoteResponse> {
		use crate::core::logging;

		logging::verbose_operation(
			"Processing quote request",
			&input_file.display().to_string(),
		);

		if !input_file.exists() {
			return Err(Error::Other(anyhow::anyhow!(
				"Request file not found: {}. Please run 'intent build' first.",
				input_file.display()
			)));
		}

		let content = std::fs::read_to_string(input_file)?;
		let quote_request: GetQuoteRequest = serde_json::from_str(&content)?;

		let api = self.ctx.api_client().await?;
		let response = api.get_quote(quote_request).await?;

		if let Some(parent_dir) = input_file.parent() {
			let output_file = parent_dir.join("get_quote.res.json");
			let content = serde_json::to_string_pretty(&response)?;
			std::fs::write(&output_file, content)?;
			logging::verbose_tech("Quote response saved", &output_file.display().to_string());
		}

		logging::verbose_success(
			"Quote request completed",
			&format!("{} quotes received", response.quotes.len()),
		);

		Ok(response)
	}

	/// Signs a quote and creates an order request for submission
	///
	/// # Arguments
	/// * `quote_response` - Quote response containing available quotes
	///
	/// # Returns
	/// Post order request with signed quote ready for submission
	///
	/// # Errors
	/// Returns error if no quotes available, signing fails, or signature invalid
	#[instrument(skip(self, quote_response))]
	pub async fn sign(&self, quote_response: GetQuoteResponse) -> Result<PostOrderRequest> {
		use crate::core::logging;

		logging::verbose_operation("Starting quote signing", "processing signature");

		let quote = quote_response
			.quotes
			.first()
			.ok_or_else(|| Error::Other(anyhow::anyhow!("No quotes available")))?;

		let signer = self.get_signer()?;
		let signature_hex = self.create_signature(quote, signer).await?;

		let signature_bytes = hex::decode(signature_hex.trim_start_matches("0x"))
			.map_err(|e| Error::Other(anyhow::anyhow!("Failed to decode signature: {}", e)))?;

		let order_request = PostOrderRequest {
			order: quote.order.clone(),
			signature: alloy_primitives::Bytes::from(signature_bytes),
			quote_id: Some(quote.quote_id.clone()),
			origin_submission: None,
		};

		logging::verbose_success("Quote signed", &format!("quote ID: {}", quote.quote_id));

		Ok(order_request)
	}

	#[instrument(skip(self))]
	pub async fn test(&self, params: TestQuoteParams) -> Result<TestQuoteResults> {
		use crate::core::logging;
		logging::verbose_tech(
			"Starting quote testing",
			&format!(
				"from {}:{} to {}:{}, count: {}",
				params.from_chain,
				params.from_token,
				params.to_chain,
				params.to_token,
				params.count
			),
		);

		let mut results = TestQuoteResults {
			total: params.count,
			successful: 0,
			failed: 0,
			average_time_ms: 0,
			best_rate: None,
			worst_rate: None,
		};

		let mut total_time = Duration::ZERO;

		for i in 0..params.count {
			logging::verbose_operation(
				&format!("Running quote test {} of {}", i + 1, params.count),
				"",
			);

			let amount = params.base_amount * U256::from(i + 1);

			let quote_params = QuoteParams {
				from_chain: params.from_chain,
				to_chain: params.to_chain,
				from_token: params.from_token.clone(),
				to_token: params.to_token.clone(),
				amount,
				min_amount: None,
			};

			let start = Instant::now();

			// For testing, we'll need to create a temporary request file
			// This is a simplified approach - in practice, we'd want to build proper requests
			match self.build_temp_request_and_get_quote(quote_params).await {
				Ok(_response) => {
					let duration = start.elapsed();
					total_time += duration;
					results.successful += 1;

					// Calculate rate from response (placeholder for now)
					let rate = 1.0;

					// Update best/worst rates
					if results.best_rate.is_none() || rate > results.best_rate.unwrap() {
						results.best_rate = Some(rate);
					}
					if results.worst_rate.is_none() || rate < results.worst_rate.unwrap() {
						results.worst_rate = Some(rate);
					}

					logging::verbose_success(
						&format!("Quote test {} successful", i + 1),
						&format!("{}ms, rate: {}", duration.as_millis(), rate),
					);
				},
				Err(e) => {
					results.failed += 1;
					logging::warning(&format!("Quote test {} failed: {}", i + 1, e));
				},
			}
		}

		// Calculate average time
		if results.successful > 0 {
			results.average_time_ms = (total_time.as_millis() / results.successful as u128) as u64;
		}

		self.display_test_summary(&results);

		Ok(results)
	}

	/// Helper method for testing - builds a temporary request and gets quote
	async fn build_temp_request_and_get_quote(
		&self,
		_params: QuoteParams,
	) -> Result<GetQuoteResponse> {
		// For now, just use the existing request file
		// In a full implementation, we'd build the request from params
		let input_file = std::path::Path::new("./.oif-demo/requests/get_quote.req.json");
		self.get(input_file).await
	}

	fn get_signer(&self) -> Result<alloy_signer_local::PrivateKeySigner> {
		let private_key = self
			.ctx
			.config
			.accounts()
			.user
			.private_key
			.as_ref()
			.ok_or_else(|| Error::InvalidPrivateKey)?;

		use crate::types::hex::Hex;
		Hex::to_private_key(private_key.expose_secret())
	}

	async fn create_signature(
		&self,
		quote: &solver_types::api::Quote,
		signer: alloy_signer_local::PrivateKeySigner,
	) -> Result<String> {
		// Get the private key from the signer
		let private_key = format!("0x{}", hex::encode(signer.to_bytes()));

		let chain_id = quote.order.origin_chain_id();
		let provider = self.ctx.provider(ChainId::Custom { id: chain_id }).await?;

		// Use the SigningService to create the signature
		let signature = self
			.ctx
			.signing
			.sign_quote(quote, &private_key, provider)
			.await?;

		Ok(signature)
	}

	fn display_test_summary(&self, results: &TestQuoteResults) {
		logging::success(&format!(
			"Quote test summary: {}/{} successful ({:.1}%), avg {}ms",
			results.successful,
			results.total,
			(results.successful as f64 / results.total as f64) * 100.0,
			results.average_time_ms
		));
	}

	/// Get quote and sign it - pure business logic without file I/O
	pub async fn get_and_sign_quote(
		&self,
		quote_request: GetQuoteRequest,
	) -> Result<PostOrderRequest> {
		// Get quote from API
		let api = self.ctx.api_client().await?;
		let response = api.get_quote(quote_request).await?;

		if response.quotes.is_empty() {
			return Err(Error::Other(anyhow::anyhow!("No quotes received")));
		}

		// Sign the quote
		let post_order_request = self.sign(response).await?;

		Ok(post_order_request)
	}
}

/// Quote request parameters
#[derive(Debug, Clone)]
pub struct QuoteParams {
	pub from_chain: ChainId,
	pub to_chain: ChainId,
	pub from_token: String,
	pub to_token: String,
	pub amount: U256,
	pub min_amount: Option<U256>,
}

/// Sign result
#[derive(Debug, Clone)]
pub struct SignResult {
	pub order_id: String,
	pub status: solver_types::api::PostOrderResponseStatus,
}

/// Test quote parameters
#[derive(Debug, Clone)]
pub struct TestQuoteParams {
	pub count: usize,
	pub from_chain: ChainId,
	pub to_chain: ChainId,
	pub from_token: String,
	pub to_token: String,
	pub base_amount: U256,
}

/// Test quote results
#[derive(Debug, Clone)]
pub struct TestQuoteResults {
	pub total: usize,
	pub successful: usize,
	pub failed: usize,
	pub average_time_ms: u64,
	pub best_rate: Option<f64>,
	pub worst_rate: Option<f64>,
}
