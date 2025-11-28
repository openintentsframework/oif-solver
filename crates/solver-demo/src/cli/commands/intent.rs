//! Intent operations command definitions and argument structures
//!
//! This module defines the CLI arguments for intent-related operations
//! including intent building, batch processing, order submission,
//! and status monitoring for cross-chain OIF intent execution.

use clap::{Args, Subcommand};
use std::path::PathBuf;

/// Intent operations command with comprehensive cross-chain intent management
///
/// Provides access to intent lifecycle operations including building,
/// batch processing, submission, and monitoring for OIF cross-chain swaps
#[derive(Args, Debug)]
pub struct IntentCommand {
	#[command(subcommand)]
	pub command: IntentSubcommand,
}

/// Available intent operation subcommands
///
/// Provides comprehensive intent management including building,
/// batch processing, submission, and status monitoring capabilities
#[derive(Subcommand, Debug)]
pub enum IntentSubcommand {
	/// Build single cross-chain intent specification with detailed parameters
	Build {
		/// Source blockchain network identifier
		#[arg(long)]
		from_chain: u64,

		/// Destination blockchain network identifier
		#[arg(long)]
		to_chain: u64,

		/// Source token symbol or contract address
		#[arg(long)]
		from_token: String,

		/// Destination token symbol or contract address
		#[arg(long)]
		to_token: String,

		/// Token amount to swap (in token units)
		#[arg(long)]
		amount: String,

		/// Swap direction type (exact-input or exact-output)
		#[arg(long, default_value = "exact-input")]
		swap_type: String,

		/// Settlement mechanism type (escrow or compact)
		#[arg(long, default_value = "escrow")]
		settlement: String,

		/// Authorization scheme (permit2 or eip3009) required for escrow settlements
		#[arg(long)]
		auth: Option<String>,

		/// Optional callback data (hex string like 0xabcd1234)
		#[arg(long)]
		callback_data: Option<String>,

		/// Optional callback recipient address (overrides default recipient)
		#[arg(long)]
		callback_recipient: Option<String>,

		/// Optional output file path for generated intent
		#[arg(short, long)]
		output: Option<PathBuf>,
	},

	/// Build multiple intents from batch specification file
	BuildBatch {
		/// Path to batch input specification file with multiple intent definitions
		input: PathBuf,

		/// Optional output file path for generated batch intents
		#[arg(short, long)]
		output: Option<PathBuf>,
	},

	/// Submit signed order request to execution infrastructure
	Submit {
		/// Path to PostOrderRequest JSON file with signed order
		input: PathBuf,

		/// Submit directly on-chain instead of through API service
		#[arg(long)]
		onchain: bool,

		/// Target blockchain network ID for on-chain submission
		#[arg(long)]
		chain: Option<u64>,
	},

	/// Execute comprehensive testing for multiple intent specifications
	Test {
		/// Path to batch input specification file for testing
		input: PathBuf,

		/// Enable on-chain submission during testing
		#[arg(long)]
		onchain: bool,

		/// Optional output directory for comprehensive test results
		#[arg(short, long)]
		output: Option<PathBuf>,
	},

	/// Check execution status of submitted order
	Status {
		/// Order identifier for status lookup
		order_id: String,
	},
}
