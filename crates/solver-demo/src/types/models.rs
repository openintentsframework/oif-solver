//! Data models for intent specifications and batch processing
//!
//! This module defines the data structures used for representing cross-chain
//! intent specifications, including batch intent files, individual intents,
//! token specifications, and amount configurations.

use serde::{Deserialize, Serialize};

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

/// Default value function for enabled field
///
/// # Returns
/// Always returns true as the default value for intent enabled status
fn default_true() -> bool {
	true
}
