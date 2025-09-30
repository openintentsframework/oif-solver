use anyhow::{anyhow, Result};
use clap::Subcommand;
use serde_json;
use solver_types::api::GetQuoteRequest;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tracing::info;

use crate::core::{DisplayUtils, TreeItem};
use crate::services::QuoteService;

#[derive(Debug, Subcommand)]
pub enum QuoteCommands {
	/// Get a quote for an intent file
	Get {
		/// Intent JSON file containing GetQuoteRequest (get_quote.req.json from 'intent build')
		input: PathBuf,

		/// Optional output file for the response (defaults to get_quote.res.json)
		#[arg(short, long)]
		output: Option<PathBuf>,
	},

	/// Sign a quote to create a PostOrderRequest for submission
	Sign {
		/// Quote response JSON file (get_quote.res.json)
		input: PathBuf,

		/// Optional signature (will auto-sign if not provided)
		#[arg(short, long)]
		signature: Option<String>,

		/// Optional output file for the PostOrderRequest (defaults to post_order.req.json)
		#[arg(short, long)]
		output: Option<PathBuf>,

		/// Quote index to sign (0-based, for multiple quotes)
		#[arg(short = 'q', long)]
		quote_index: Option<usize>,
	},

	/// Test quotes for multiple intents
	Test {
		/// JSON file containing array of GetQuoteRequest objects
		input: PathBuf,

		/// Optional output file for test results
		#[arg(short, long)]
		output: Option<PathBuf>,
	},
}

pub struct QuoteHandler {
	quote_service: Arc<QuoteService>,
	display: Arc<DisplayUtils>,
}

impl QuoteHandler {
	pub fn new(quote_service: Arc<QuoteService>) -> Self {
		Self {
			quote_service,
			display: Arc::new(DisplayUtils::new()),
		}
	}

	pub async fn handle(&self, command: QuoteCommands) -> Result<()> {
		match command {
			QuoteCommands::Get { input, output } => self.handle_get(input, output).await,
			QuoteCommands::Sign {
				input,
				signature,
				output,
				quote_index,
			} => {
				self.handle_sign(input, signature, output, quote_index)
					.await
			},
			QuoteCommands::Test { input, output } => self.handle_test(input, output).await,
		}
	}

	async fn handle_get(&self, input_file: PathBuf, output_file: Option<PathBuf>) -> Result<()> {
		info!("Getting quote from request file: {:?}", input_file);

		// Load the request
		let content = fs::read_to_string(&input_file)
			.await
			.map_err(|e| anyhow!("Failed to read input file: {}", e))?;

		let request: GetQuoteRequest = serde_json::from_str(&content)
			.map_err(|e| anyhow!("Failed to parse GetQuoteRequest: {}", e))?;

		// Get quote
		let response = self
			.quote_service
			.get_quote(request, output_file.clone())
			.await?;

		// Display results
		self.display.header("Quote Request Results");

		let quote_count = response.quotes.len();
		self.display
			.success(&format!("Received {} quotes", quote_count));

		// Display quote details
		for (i, quote) in response.quotes.iter().enumerate() {
			self.display.tree(
				&format!("Quote {}", i + 1),
				vec![
					TreeItem::KeyValue("Quote ID".to_string(), quote.quote_id.clone()),
					TreeItem::KeyValue("Valid Until".to_string(), quote.valid_until.to_string()),
					TreeItem::KeyValue("Partial Fill".to_string(), quote.partial_fill.to_string()),
					TreeItem::KeyValue(
						"Failure Handling".to_string(),
						format!("{:?}", quote.failure_handling),
					),
					TreeItem::KeyValue(
						"ETA".to_string(),
						quote.eta.map_or("N/A".to_string(), |e| e.to_string()),
					),
					TreeItem::KeyValue(
						"Provider".to_string(),
						quote.provider.clone().unwrap_or("N/A".to_string()),
					),
				],
			);
		}

		// Determine where the response was saved
		// With the new always-override approach, response is saved as get_quote.res.json
		let response_file = if let Some(ref out) = output_file {
			out.clone()
		} else {
			// Use the standard response file name in the same directory as input
			input_file
				.parent()
				.map(|p| p.join("get_quote.res.json"))
				.unwrap_or_else(|| PathBuf::from("get_quote.res.json"))
		};

		self.display
			.success(&format!("Response saved to: {:?}", response_file));

		// Add next steps
		if quote_count > 0 {
			if quote_count > 1 {
				self.display.next_steps(vec![&format!(
					"Sign a specific quote: oif-demo quote sign {:?} --quote-index 0",
					response_file
				)]);
			} else {
				self.display.next_steps(vec![&format!(
					"Sign the quote: oif-demo quote sign {:?}",
					response_file
				)]);
			}
		}

		Ok(())
	}

	async fn handle_sign(
		&self,
		input_file: PathBuf,
		signature: Option<String>,
		output_file: Option<PathBuf>,
		quote_index: Option<usize>,
	) -> Result<()> {
		info!("Signing quote from file: {:?}", input_file);

		// Load and check the quotes
		let content = fs::read_to_string(&input_file)
			.await
			.map_err(|e| anyhow!("Failed to read input file: {}", e))?;

		let response: solver_types::api::GetQuoteResponse = serde_json::from_str(&content)
			.map_err(|e| anyhow!("Failed to parse GetQuoteResponse: {}", e))?;

		// Handle multiple quotes scenario
		let final_index = if response.quotes.is_empty() {
			return Err(anyhow!("No quotes found in the response file"));
		} else if response.quotes.len() > 1 && quote_index.is_none() {
			// Multiple quotes available - show them and ask user to select
			self.display.header("Multiple Quotes Available");
			self.display.info(&format!(
				"Found {} quotes. Please select one:",
				response.quotes.len()
			));

			for (i, quote) in response.quotes.iter().enumerate() {
				self.display.tree(
					&format!("Quote {} (Index: {})", i + 1, i),
					vec![
						TreeItem::KeyValue("Quote ID".to_string(), quote.quote_id.clone()),
						TreeItem::KeyValue(
							"Valid Until".to_string(),
							quote.valid_until.to_string(),
						),
						TreeItem::KeyValue(
							"Provider".to_string(),
							quote.provider.clone().unwrap_or("N/A".to_string()),
						),
					],
				);
			}

			self.display.notes(vec![
				"To sign a specific quote, run the command again with --quote-index <index>",
				"For example: oif-demo quote sign -i quote.json --quote-index 0",
			]);

			return Err(anyhow!(
				"Please specify --quote-index to select which quote to sign"
			));
		} else {
			quote_index
		};

		// Sign the quote and create PostOrderRequest without submitting
		let (_post_order_request, request_file, selected_index) = self
			.quote_service
			.sign_quote(input_file.clone(), signature, output_file, final_index)
			.await?;

		// Get the quote that was signed
		let quote = &response.quotes[selected_index];

		// Display results
		self.display.header("Quote Signed");

		if response.quotes.len() > 1 {
			self.display.success(&format!(
				"Successfully signed quote {} of {}: {}",
				selected_index + 1,
				response.quotes.len(),
				quote.quote_id
			));
		} else {
			self.display
				.success(&format!("Successfully signed quote: {}", quote.quote_id));
		}

		self.display
			.info(&format!("PostOrderRequest saved to: {:?}", request_file));

		self.display.next_steps(vec![
			&format!(
				"Submit the order: oif-demo intent submit {:?}",
				request_file
			),
			&format!(
				"Or submit directly on-chain: oif-demo intent submit {:?} --onchain",
				request_file
			),
		]);

		Ok(())
	}

	async fn handle_test(&self, input_file: PathBuf, output_file: Option<PathBuf>) -> Result<()> {
		info!("Testing batch quotes from file: {:?}", input_file);

		// Run batch test
		let results = self
			.quote_service
			.test_batch(input_file, output_file)
			.await?;

		// Display results
		self.display.header("Batch Quote Test Results");

		let stats = &results.statistics;
		self.display.tree(
			"Statistics",
			vec![
				TreeItem::KeyValue("Total Tests".to_string(), stats.total.to_string()),
				TreeItem::KeyValue("Successful".to_string(), stats.successful.to_string()),
				TreeItem::KeyValue("Failed".to_string(), stats.failed.to_string()),
				TreeItem::KeyValue(
					"Success Rate".to_string(),
					format!(
						"{:.1}%",
						(stats.successful as f64 / stats.total as f64) * 100.0
					),
				),
				TreeItem::KeyValue(
					"Avg Response Time".to_string(),
					format!("{:.2}ms", stats.avg_response_time_ms),
				),
				TreeItem::KeyValue(
					"Total Duration".to_string(),
					format!("{}ms", stats.total_duration_ms),
				),
			],
		);

		// Display failed requests if any
		let failed_results: Vec<_> = results
			.results
			.iter()
			.enumerate()
			.filter(|(_, r)| matches!(r.status, crate::models::QuoteTestStatus::Failed))
			.collect();

		if !failed_results.is_empty() {
			self.display.tree(
				"Failed Requests",
				failed_results
					.iter()
					.map(|(i, result)| {
						TreeItem::KeyValue(
							format!("Request {}", i + 1),
							result
								.error
								.as_ref()
								.unwrap_or(&"Unknown error".to_string())
								.clone(),
						)
					})
					.collect(),
			);
		}

		self.display
			.info(&format!("Results saved to: {:?}", results.file_path));

		Ok(())
	}
}
