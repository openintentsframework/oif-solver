//! Configuration display command definitions and argument structures
//!
//! This module defines the CLI arguments for configuration display operations
//! including basic and detailed configuration viewing with optional verbose
//! output for comprehensive system state inspection.

use clap::Args;

/// Configuration display command with optional detailed output
///
/// Provides access to current application configuration with support
/// for both basic summary and comprehensive detailed configuration views
#[derive(Args, Debug)]
pub struct ConfigCommand {
	/// Enable detailed configuration output with comprehensive system state
	#[arg(long)]
	pub detailed: bool,
}
