//! Quote operations command definitions and argument structures
//!
//! This module defines the CLI arguments for quote-related operations
//! including quote generation, signature creation, and batch testing
//! capabilities for OIF intent processing and order management.

use clap::{Args, Subcommand};
use std::path::PathBuf;

/// Quote operations command with comprehensive quote management capabilities
///
/// Provides access to quote generation, signature creation, and testing
/// operations for OIF intent processing and order lifecycle management
#[derive(Args, Debug)]
pub struct QuoteCommand {
	#[command(subcommand)]
	pub command: QuoteSubcommand,
}

/// Available quote operation subcommands
///
/// Provides comprehensive quote management including generation,
/// signing, and batch testing capabilities for intent processing
#[derive(Subcommand, Debug)]
pub enum QuoteSubcommand {
	/// Generate quote response from intent specification
	Get {
		/// Path to GetQuoteRequest JSON specification file
		input: PathBuf,

		/// Optional output file path for quote response
		#[arg(short, long)]
		output: Option<PathBuf>,
	},

	/// Sign quote to create PostOrderRequest with cryptographic signature
	Sign {
		/// Path to GetQuoteResponse JSON file containing quotes
		input: PathBuf,

		/// Quote index to sign when multiple quotes are available
		#[arg(short = 'q', long, default_value = "0")]
		quote_index: usize,

		/// Pre-computed signature string (generates new signature if not provided)
		#[arg(short, long)]
		signature: Option<String>,

		/// Optional output file path for signed order request
		#[arg(short, long)]
		output: Option<PathBuf>,
	},

	/// Execute batch quote testing for multiple intent specifications
	Test {
		/// Path to batch input specification file with multiple intents
		input: PathBuf,

		/// Optional output directory for batch test results
		#[arg(short, long)]
		output: Option<PathBuf>,
	},
}
