use anyhow::{anyhow, Result};
use chrono::Utc;
use serde_json;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::fs;
use tracing::{debug, info, warn};

use solver_types::{
	api::{GetQuoteRequest, GetQuoteResponse},
	OriginSubmission,
};

use crate::{
	core::SessionManager,
	models::{BatchTestResults, BatchTestStatistics, QuoteTestResult, QuoteTestStatus},
	services::{ApiClient, SigningService},
};

/// Service for handling quote operations including API calls and persistence
pub struct QuoteService {
	session_manager: Arc<SessionManager>,
	api_client: Arc<ApiClient>,
	signing_service: Arc<SigningService>,
}

impl QuoteService {
	/// Create a new quote service
	pub async fn new(
		session_manager: Arc<SessionManager>,
		api_client: Arc<ApiClient>,
		signing_service: Arc<SigningService>,
	) -> Result<Self> {
		Ok(Self {
			session_manager,
			api_client,
			signing_service,
		})
	}

	/// Get session manager
	pub fn session_manager(&self) -> &Arc<SessionManager> {
		&self.session_manager
	}

	/// Get quotes for a given request and save both request and response
	pub async fn get_quote(
		&self,
		request: GetQuoteRequest,
		output_file: Option<PathBuf>,
	) -> Result<GetQuoteResponse> {
		info!("Getting quote for intent request");

		// Determine file paths - always override
		let requests_dir = self.session_manager.requests_dir();
		let response_file = output_file.unwrap_or_else(|| requests_dir.join("get_quote.res.json"));

		// Make API call using ApiClient
		let quote_response = self
			.api_client
			.request_quote(request.clone())
			.await
			.map_err(|e| anyhow!("Failed to get quote: {}", e))?;

		info!("Received {} quotes", quote_response.quotes.len());

		// Save the quote response
		if let Some(parent) = response_file.parent() {
			fs::create_dir_all(parent).await?;
		}
		let json = serde_json::to_string_pretty(&quote_response)?;
		fs::write(&response_file, json).await?;
		debug!("Saved quote response to: {:?}", response_file);

		Ok(quote_response)
	}

	/// Sign a quote and create PostOrderRequest without submitting
	pub async fn sign_quote(
		&self,
		quote_file: PathBuf,
		signature: Option<String>,
		output_file: Option<PathBuf>,
		quote_index: Option<usize>,
	) -> Result<(serde_json::Value, PathBuf, usize)> {
		info!("Signing quote from file: {:?}", quote_file);

		// Load the quote response
		let response: GetQuoteResponse = self.load_response(&quote_file).await?;

		if response.quotes.is_empty() {
			return Err(anyhow!("No quotes found in the response file"));
		}

		// Determine which quote to sign
		let selected_index = if let Some(idx) = quote_index {
			if idx >= response.quotes.len() {
				return Err(anyhow!(
					"Invalid quote index {}. File contains {} quotes",
					idx,
					response.quotes.len()
				));
			}
			idx
		} else if response.quotes.len() == 1 {
			0
		} else {
			return Err(anyhow!(
				"Multiple quotes available ({}). Please specify which quote to sign.",
				response.quotes.len()
			));
		};

		let quote = &response.quotes[selected_index];
		info!("Signing quote with ID: {}", quote.quote_id);

		// Sign the quote if no signature provided
		let final_signature = match signature {
			Some(sig) => {
				info!("Using provided signature");
				sig
			},
			None => {
				info!("Signing quote with EIP-712 using user's private key");
				// Get user's private key for signing permits
				let user_account = self.session_manager.get_user_account().await;
				let user_private_key = user_account
					.private_key
					.ok_or_else(|| anyhow!("User private key not available for signing"))?;

				self.signing_service
					.sign_quote(quote, &user_private_key)
					.await
					.map_err(|e| anyhow!("Failed to sign quote: {}", e))?
			},
		};

		// Create the post_order request file - always override
		let requests_dir = self.session_manager.requests_dir();
		let order_request_file =
			output_file.unwrap_or_else(|| requests_dir.join("post_order.req.json"));
		let origin_submission: Option<OriginSubmission> = (&quote.order).into();
		let clean_signature = final_signature.trim_start_matches("0x");
		let post_order_json = serde_json::json!({
			"order": quote.order,  // Structured OifOrder with EIP-712 payload
			"signature": format!("0x{}", clean_signature),  // EIP-712 signature as single value with 0x prefix
			"quoteId": quote.quote_id,  // Optional quote identifier
			"originSubmission": origin_submission,  // Optional origin submission preference
		});

		if let Some(parent) = order_request_file.parent() {
			fs::create_dir_all(parent).await?;
		}
		let request_json = serde_json::to_string_pretty(&post_order_json)?;
		fs::write(&order_request_file, request_json).await?;
		debug!("Created PostOrderRequest at: {:?}", order_request_file);

		Ok((post_order_json, order_request_file, selected_index))
	}

	/// Test multiple intents from a batch file
	pub async fn test_batch(
		&self,
		batch_file: PathBuf,
		_output_file: Option<PathBuf>,
	) -> Result<BatchTestResults> {
		info!("Running batch test from file: {:?}", batch_file);

		// Load batch intents
		let batch_content = fs::read_to_string(&batch_file)
			.await
			.map_err(|e| anyhow!("Failed to read batch file: {}", e))?;

		let requests: Vec<GetQuoteRequest> = serde_json::from_str(&batch_content).map_err(|e| {
			// Check if user might be using the wrong file type
			if batch_content.contains("\"intents\"") && batch_content.contains("\"enabled\"") {
				anyhow!(
					"Failed to parse '{}' as array of GetQuoteRequest.\n\n\
						This file appears to be a batch intent specification (batch_intents.json).\n\n\
						Use this workflow:\n\
						1. oif-demo intent build-batch {}  # Creates get_quotes.req.json\n\
						2. oif-demo quote test get_quotes.req.json         # Tests quotes and signs them\n\
						3. oif-demo intent test post_orders.req.json       # Submits signed orders\n\n\
						Original error: {}",
					batch_file.display(),
					batch_file.display(),
					e
				)
			} else {
				anyhow!(
					"Failed to parse batch file as array of GetQuoteRequest: {}",
					e
				)
			}
		})?;

		info!("Testing {} quote requests", requests.len());

		let start_time = Instant::now();
		let mut results = Vec::new();
		let mut successful = 0;
		let mut failed = 0;
		let mut total_response_time = 0u64;

		// Process each request
		for (i, request) in requests.iter().enumerate() {
			info!("Processing request {}/{}", i + 1, requests.len());

			let request_start = Instant::now();
			let result = self.test_single_request(request.clone()).await;
			let duration = request_start.elapsed().as_millis() as u64;

			total_response_time += duration;

			let test_result = match result {
				Ok(response) => {
					successful += 1;
					QuoteTestResult {
						request: request.clone(),
						response: Some(response),
						error: None,
						duration_ms: duration,
						status: QuoteTestStatus::Success,
					}
				},
				Err(e) => {
					failed += 1;
					warn!("Request {} failed: {}", i + 1, e);
					QuoteTestResult {
						request: request.clone(),
						response: None,
						error: Some(e.to_string()),
						duration_ms: duration,
						status: QuoteTestStatus::Failed,
					}
				},
			};

			results.push(test_result);
		}

		let total_duration = start_time.elapsed().as_millis() as u64;
		let total = results.len();

		let statistics = BatchTestStatistics {
			total,
			successful,
			failed,
			avg_response_time_ms: if total > 0 {
				total_response_time as f64 / total as f64
			} else {
				0.0
			},
			total_duration_ms: total_duration,
		};

		let batch_results = BatchTestResults {
			results,
			tested_at: Utc::now(),
			file_path: std::path::PathBuf::new(), // Not saving to file
			statistics,
		};

		// Create post_orders.req.json from successful quotes
		self.create_post_orders_from_batch(&batch_results).await?;

		info!(
			"Batch test completed: {}/{} successful, avg response time: {:.2}ms",
			successful, total, batch_results.statistics.avg_response_time_ms
		);

		Ok(batch_results)
	}

	/// Test a single quote request
	async fn test_single_request(&self, request: GetQuoteRequest) -> Result<GetQuoteResponse> {
		self.api_client.request_quote(request).await
	}

	/// Load a quote response from disk
	async fn load_response(&self, file_path: &PathBuf) -> Result<GetQuoteResponse> {
		let content = fs::read_to_string(file_path)
			.await
			.map_err(|e| anyhow!("Failed to read file {:?}: {}", file_path, e))?;

		let response: GetQuoteResponse = serde_json::from_str(&content)
			.map_err(|e| anyhow!("Failed to parse quote response: {}", e))?;

		Ok(response)
	}

	/// Create post_orders.req.json from successful quotes in batch results
	async fn create_post_orders_from_batch(&self, batch_results: &BatchTestResults) -> Result<()> {
		use solver_types::api::PostOrderRequest;

		// Collect all successful quotes
		let mut post_orders = Vec::new();

		for result in &batch_results.results {
			if let (QuoteTestStatus::Success, Some(response)) = (&result.status, &result.response) {
				// Process each quote in the response
				for quote in &response.quotes {
					// Get user's private key for signing permits
					let user_account = self.session_manager.get_user_account().await;
					let user_private_key = user_account
						.private_key
						.clone()
						.ok_or_else(|| anyhow!("User private key not available for signing"))?;

					// Sign the quote using user's private key
					let sign_result = self
						.signing_service
						.sign_quote(quote, &user_private_key)
						.await;

					match sign_result {
						Ok(signature) => {
							// Create origin submission from the quote
							let origin_submission: Option<OriginSubmission> = (&quote.order).into();

							// Create PostOrderRequest
							let post_order = PostOrderRequest {
								order: quote.order.clone(),
								signature: alloy_primitives::Bytes::from(
									hex::decode(signature.trim_start_matches("0x"))
										.map_err(|e| anyhow!("Invalid signature hex: {}", e))?,
								),
								quote_id: Some(quote.quote_id.clone()),
								origin_submission,
							};

							post_orders.push(post_order);
						},
						Err(e) => {
							warn!("Failed to sign quote {}: {}", quote.quote_id, e);
						},
					}
				}
			}
		}

		if post_orders.is_empty() {
			info!("No successful quotes to sign - post_orders.req.json not created");
			return Ok(());
		}

		// Save to post_orders.req.json
		let post_orders_file = self
			.session_manager
			.requests_dir()
			.join("post_orders.req.json");

		// Ensure directory exists
		if let Some(parent) = post_orders_file.parent() {
			fs::create_dir_all(parent).await?;
		}

		let json = serde_json::to_string_pretty(&post_orders)?;
		fs::write(&post_orders_file, json).await?;

		info!(
			"Created post_orders.req.json with {} signed orders",
			post_orders.len()
		);
		debug!("Saved to: {:?}", post_orders_file);

		Ok(())
	}
}
