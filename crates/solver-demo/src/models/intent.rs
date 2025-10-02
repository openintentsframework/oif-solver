use alloy_primitives::{Address, U256};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use solver_types::api::{PostOrderRequest, PostOrderResponse};
use std::path::PathBuf;

use crate::models::BatchTestStatistics;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Intent {
	pub from_chain: u64,
	pub to_chain: u64,
	pub from_token: Address,
	pub to_token: Address,
	pub amount: U256,
	pub recipient: Address,
	pub swap_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentResult {
	pub order_id: String,
	pub quote: Quote,
	pub intent: Intent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quote {
	pub id: String,
	pub price: String,
	pub amount_out: U256,
	pub expires_at: u64,
}

/// Individual intent test result for batch testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentTestResult {
	/// The PostOrderRequest that was tested
	pub request: PostOrderRequest,
	/// Response if successful
	pub response: Option<PostOrderResponse>,
	/// Error message if failed
	pub error: Option<String>,
	/// Time taken for the request
	pub duration_ms: u64,
	/// Test status
	pub status: IntentTestStatus,
}

/// Status of an intent test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntentTestStatus {
	Success,
	Failed,
	Timeout,
	InvalidRequest,
}

/// Batch test results for multiple intents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchIntentTestResults {
	/// Test results for each intent
	pub results: Vec<IntentTestResult>,
	/// When the batch test was run
	pub tested_at: DateTime<Utc>,
	/// File path where results were saved
	pub file_path: PathBuf,
	/// Overall statistics
	pub statistics: BatchTestStatistics,
}

/// Batch intent specification file format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchIntentSpec {
	/// Array of intent specifications
	pub intents: Vec<IntentSpec>,
}

/// Individual intent specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentSpec {
	/// Description of the intent
	pub description: Option<String>,
	/// Whether this intent is enabled for testing
	#[serde(default = "default_true")]
	pub enabled: bool,
	/// Origin chain ID
	pub origin_chain_id: u64,
	/// Destination chain ID
	pub dest_chain_id: u64,
	/// Origin token details
	pub origin_token: TokenSpec,
	/// Destination token details
	pub dest_token: TokenSpec,
	/// Amount specifications
	pub amounts: AmountSpec,
	/// Optional recipient (defaults to user)
	pub recipient: Option<String>,
	/// Optional settlement type (defaults to "escrow")
	pub settlement: Option<String>,
	/// Optional auth mechanism (defaults to "permit2")
	pub auth: Option<String>,
}

/// Token specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSpec {
	/// Token address
	pub address: String,
	/// Token symbol
	pub symbol: String,
	/// Token decimals
	pub decimals: u8,
}

/// Amount specification - supports both exact input and exact output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmountSpec {
	/// Input amount (for exact input swaps)
	pub input: Option<String>,
	/// Output amount (for exact output swaps)
	pub output: Option<String>,
}

fn default_true() -> bool {
	true
}
