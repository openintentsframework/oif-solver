//! Initialization command definitions and argument structures
//!
//! This module defines the CLI arguments for the init command which handles
//! configuration file generation and loading for the solver demo application.

use clap::{Args, Subcommand};
use std::path::PathBuf;

/// Command arguments for configuration initialization operations
///
/// Provides subcommands for generating new configurations and loading
/// existing configuration files into the solver demo session.
#[derive(Args, Debug)]
pub struct InitCommand {
	#[command(subcommand)]
	pub command: InitSubcommand,
}

/// Available initialization subcommands for configuration management
///
/// Supports creating new configurations from templates and loading
/// existing configurations for use in the current session.
#[derive(Subcommand, Debug)]
pub enum InitSubcommand {
	/// Generate new configuration
	New {
		/// Configuration file path
		path: PathBuf,

		/// Chain IDs to configure (comma-separated)
		#[arg(long, value_delimiter = ',', default_value = "31337,31338")]
		chains: Vec<u64>,

		/// Force overwrite existing configuration
		#[arg(long)]
		force: bool,
	},

	/// Load existing configuration
	Load {
		/// Configuration file path
		path: PathBuf,

		/// Initialize for local environment
		#[arg(long)]
		local: bool,
	},

	/// Load configuration from storage backend (Redis/file/memory)
	LoadStorage {
		/// Solver ID to load (defaults to SOLVER_ID env var)
		#[arg(long)]
		solver_id: Option<String>,

		/// Initialize for local environment
		#[arg(long)]
		local: bool,
	},
}
