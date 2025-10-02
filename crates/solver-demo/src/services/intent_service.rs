use anyhow::{anyhow, Result};
use chrono::Utc;
use serde_json;
use solver_types::api::PostOrderRequest;
use std::{path::PathBuf, sync::Arc, time::Instant};
use tokio::fs;
use tracing::{debug, warn};

use crate::{
	core::{ContractManager, SessionManager},
	models::{BatchIntentTestResults, BatchTestStatistics, IntentTestResult, IntentTestStatus},
	services::{ApiClient, TokenService},
};

/// Service for handling intent operations
pub struct IntentService {
	pub session_manager: Arc<SessionManager>,
	pub contract_manager: Arc<ContractManager>,
	#[allow(dead_code)]
	token_service: Arc<TokenService>,
	pub api_client: Arc<ApiClient>,
}

impl IntentService {
	pub fn new(
		session_manager: Arc<SessionManager>,
		contract_manager: Arc<ContractManager>,
		token_service: Arc<TokenService>,
		api_client: Arc<ApiClient>,
	) -> Self {
		Self {
			session_manager,
			contract_manager,
			token_service,
			api_client,
		}
	}

	/// Test batch submission of multiple intents
	pub async fn test_batch(
		&self,
		input_file: PathBuf,
		output_file: Option<PathBuf>,
	) -> Result<BatchIntentTestResults> {
		debug!("Starting batch intent test from file: {:?}", input_file);

		// Read input file
		let content = fs::read_to_string(&input_file)
			.await
			.map_err(|e| anyhow!("Failed to read input file: {}", e))?;

		// Parse as array of PostOrderRequest
		let requests: Vec<PostOrderRequest> = serde_json::from_str(&content).map_err(|e| {
			anyhow!(
				"Failed to parse input file as array of PostOrderRequest: {}",
				e
			)
		})?;

		if requests.is_empty() {
			return Err(anyhow!("No requests found in input file"));
		}

		debug!("Found {} intent requests to test", requests.len());

		let mut results = Vec::new();
		let batch_start = Instant::now();

		// Process each request
		for (index, request) in requests.into_iter().enumerate() {
			debug!(
				"Processing intent request {}/{}",
				index + 1,
				results.len() + 1
			);

			let start_time = Instant::now();
			let result = match self.submit_single_intent(request.clone()).await {
				Ok(response) => IntentTestResult {
					request,
					response: Some(response),
					error: None,
					duration_ms: start_time.elapsed().as_millis() as u64,
					status: IntentTestStatus::Success,
				},
				Err(e) => {
					let error_str = e.to_string();
					warn!("Intent submission failed: {}", error_str);

					let status = if error_str.contains("timeout") {
						IntentTestStatus::Timeout
					} else if error_str.contains("invalid") || error_str.contains("parse") {
						IntentTestStatus::InvalidRequest
					} else {
						IntentTestStatus::Failed
					};

					IntentTestResult {
						request,
						response: None,
						error: Some(error_str),
						duration_ms: start_time.elapsed().as_millis() as u64,
						status,
					}
				},
			};

			results.push(result);
		}

		// Calculate statistics
		let total = results.len();
		let successful = results
			.iter()
			.filter(|r| matches!(r.status, IntentTestStatus::Success))
			.count();
		let failed = total - successful;

		let total_response_time: u64 = results.iter().map(|r| r.duration_ms).sum();
		let avg_response_time_ms = if total > 0 {
			total_response_time as f64 / total as f64
		} else {
			0.0
		};

		let statistics = BatchTestStatistics {
			total,
			successful,
			failed,
			avg_response_time_ms,
			total_duration_ms: batch_start.elapsed().as_millis() as u64,
		};

		// Determine output file path
		let requests_dir = self.session_manager.requests_dir();
		let output_path = output_file.unwrap_or_else(|| requests_dir.join("post_orders.res.json"));

		// Ensure directory exists
		if let Some(parent) = output_path.parent() {
			fs::create_dir_all(parent).await?;
		}

		// Create results object
		let batch_results = BatchIntentTestResults {
			results,
			tested_at: Utc::now(),
			file_path: output_path.clone(),
			statistics,
		};

		// Save results to file
		let json = serde_json::to_string_pretty(&batch_results)?;
		fs::write(&output_path, json).await?;

		debug!(
			"Batch intent test completed, results saved to: {:?}",
			output_path
		);

		Ok(batch_results)
	}

	/// Submit a single intent and return the response
	async fn submit_single_intent(
		&self,
		request: PostOrderRequest,
	) -> Result<solver_types::api::PostOrderResponse> {
		self.api_client.post_intent(request).await
	}
}
