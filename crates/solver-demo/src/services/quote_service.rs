use anyhow::{anyhow, Result};
use chrono::Utc;
use serde_json;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::fs;
use tracing::{debug, info, warn};

use solver_types::api::{GetQuoteRequest, GetQuoteResponse};

use crate::{
	core::SessionManager,
	models::{BatchTestResults, BatchTestStatistics, QuoteTestResult, QuoteTestStatus},
	services::{ApiClient, FileIndexer, SigningService},
};

/// Service for handling quote operations including API calls and persistence
pub struct QuoteService {
	session_manager: Arc<SessionManager>,
	api_client: Arc<ApiClient>,
	signing_service: Arc<SigningService>,
	file_indexer: Arc<FileIndexer>,
}

impl QuoteService {
	/// Create a new quote service
	pub async fn new(
		session_manager: Arc<SessionManager>,
		api_client: Arc<ApiClient>,
		signing_service: Arc<SigningService>,
	) -> Result<Self> {
		let file_indexer = Arc::new(FileIndexer::new(session_manager.requests_dir().as_path()).await?);
		
		Ok(Self {
			session_manager,
			api_client,
			signing_service,
			file_indexer,
		})
	}

	/// Get quotes for a given request and save both request and response
	pub async fn get_quote(
		&self,
		request: GetQuoteRequest,
		output_file: Option<PathBuf>,
	) -> Result<GetQuoteResponse> {
		info!("Getting quote for intent request");

		// Use current intent index since intent build already created the files
		let current_index = self.file_indexer.current_index("intent").await;
		
		// Determine file paths
		let requests_dir = self.session_manager.requests_dir();
		let response_file = output_file.unwrap_or_else(|| {
			requests_dir.join(format!("{}.get_quote.res.json", current_index))
		});

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
				info!("Signing quote with EIP-712");
				self.signing_service
					.sign_quote(quote)
					.await
					.map_err(|e| anyhow!("Failed to sign quote: {}", e))?
			},
		};

		// Get a new index for post_order request
		let order_index = self.file_indexer.next_index("post_order").await?;
		
		// Create the post_order request file
		let requests_dir = self.session_manager.requests_dir();
		let order_request_file = output_file.unwrap_or_else(|| {
			requests_dir.join(format!("{}.post_order.req.json", order_index))
		});
		
		// Create a PostOrderRequest with structured Order data (EIP-712 typed data)
		// Convert the Quote to a StandardOrder structure
		use solver_types::standards::eip7683::interfaces::StandardOrder;
		let standard_order = StandardOrder::try_from(quote)
			.map_err(|e| anyhow!("Failed to convert quote to StandardOrder: {}", e))?;
		
		// Create the PostOrderRequest with structured data
		let post_order_json = serde_json::json!({
			"order": standard_order,  // EIP-712 typed data structure
			"signature": final_signature,  // EIP-712 signature
			"quoteId": quote.quote_id,  // Optional quote identifier
			"originSubmission": quote.origin_submission,  // Optional origin submission preference
		});
		
		if let Some(parent) = order_request_file.parent() {
			fs::create_dir_all(parent).await?;
		}
		let request_json = serde_json::to_string_pretty(&post_order_json)?;
		fs::write(&order_request_file, request_json).await?;
		debug!("Created PostOrderRequest at: {:?}", order_request_file);

		Ok((post_order_json, order_request_file, selected_index))
	}

	/// Accept a quote by loading from file and submitting order to API
	pub async fn accept_quote(
		&self,
		quote_file: PathBuf,
		signature: Option<String>,
		output_file: Option<PathBuf>,
		quote_index: Option<usize>,
	) -> Result<(serde_json::Value, PathBuf, usize)> {
		info!("Accepting quote from file: {:?}", quote_file);

		// Load the quote response
		let response: GetQuoteResponse = self.load_response(&quote_file).await?;

		if response.quotes.is_empty() {
			return Err(anyhow!("No quotes found in the response file"));
		}

		// Determine which quote to accept
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
			// Only one quote, accept it automatically
			0
		} else {
			// Multiple quotes but no index specified - caller should handle selection
			return Err(anyhow!(
				"Multiple quotes available ({}). Please specify which quote to accept.",
				response.quotes.len()
			));
		};

		let quote = &response.quotes[selected_index];
		info!("Accepting quote with ID: {}", quote.quote_id);

		// Sign the quote if no signature provided
		let final_signature = match signature {
			Some(sig) => {
				info!("Using provided signature");
				sig
			},
			None => {
				info!("Signing quote with EIP-712");
				self.signing_service
					.sign_quote(quote)
					.await
					.map_err(|e| anyhow!("Failed to sign quote: {}", e))?
			},
		};

		// Get a new index for post_order
		let order_index = self.file_indexer.next_index("post_order").await?;
		
		// Create the post_order request file with the signature
		let requests_dir = self.session_manager.requests_dir();
		let order_request_file = requests_dir.join(format!("{}.post_order.req.json", order_index));
		
		// Update request with actual signature
		let order_request = serde_json::json!({
			"quote_id": quote.quote_id,
			"signature": final_signature,
			"quote_index": selected_index,
		});
		
		if let Some(parent) = order_request_file.parent() {
			fs::create_dir_all(parent).await?;
		}
		let request_json = serde_json::to_string_pretty(&order_request)?;
		fs::write(&order_request_file, request_json).await?;
		debug!("Updated order request with signature at: {:?}", order_request_file);
		
		// Submit order to API
		info!("Submitting order to API");
		let api_response = self
			.api_client
			.submit_order(quote, final_signature.clone())
			.await
			.map_err(|e| anyhow!("Failed to submit order to API: {}", e))?;

		info!("Order submitted successfully");

		// Save API response
		let response_file = output_file.unwrap_or_else(|| {
			requests_dir.join(format!("{}.post_order.res.json", order_index))
		});

		// Save raw API response
		if let Some(parent) = response_file.parent() {
			fs::create_dir_all(parent).await?;
		}
		let json = serde_json::to_string_pretty(&api_response)?;
		fs::write(&response_file, json).await?;
		debug!("Saved order response to: {:?}", response_file);

		Ok((api_response, response_file, selected_index))
	}

	/// Test multiple intents from a batch file
	pub async fn test_batch(
		&self,
		batch_file: PathBuf,
		output_file: Option<PathBuf>,
	) -> Result<BatchTestResults> {
		info!("Running batch test from file: {:?}", batch_file);

		// Load batch intents
		let batch_content = fs::read_to_string(&batch_file)
			.await
			.map_err(|e| anyhow!("Failed to read batch file: {}", e))?;

		let requests: Vec<GetQuoteRequest> = serde_json::from_str(&batch_content)
			.map_err(|e| anyhow!("Failed to parse batch file: {}", e))?;

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

		let results_file = output_file.unwrap_or_else(|| {
			self.session_manager
				.requests_dir()
				.join(format!("batch_test_{}.json", Utc::now().timestamp()))
		});

		let batch_results = BatchTestResults {
			results,
			tested_at: Utc::now(),
			file_path: results_file,
			statistics,
		};

		// Save results
		self.save_batch_results(&batch_results).await?;

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

	/// Save batch test results to disk
	async fn save_batch_results(&self, results: &BatchTestResults) -> Result<()> {
		// Ensure quotes directory exists
		if let Some(parent) = results.file_path.parent() {
			fs::create_dir_all(parent).await?;
		}

		let json = serde_json::to_string_pretty(results)?;
		fs::write(&results.file_path, json).await?;

		debug!("Saved batch test results to: {:?}", results.file_path);
		Ok(())
	}
}
