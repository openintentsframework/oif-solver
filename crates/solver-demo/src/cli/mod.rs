//! Command-line interface definitions and parsing
//!
//! This module defines the CLI structure using clap, including the main
//! command parser, subcommand definitions, and output formatting utilities.
//! Provides the entry point for all CLI operations.

pub mod commands;
pub mod output;

use clap::{Parser, Subcommand};

/// Main CLI application structure for the OIF Solver Demo
///
/// Defines the top-level command-line interface with all available
/// subcommands for testing and demonstrating cross-chain intent resolution.
#[derive(Parser, Debug)]
#[command(name = "solver-demo")]
#[command(about = "OIF Solver Demo - Test and demonstrate cross-chain intent resolution")]
#[command(version)]
pub struct Cli {
	#[command(subcommand)]
	pub command: Commands,
}

/// Available CLI subcommands for different operations
///
/// Each variant represents a major functional area including initialization,
/// configuration management, environment setup, token operations, account
/// management, intent handling, and quote generation.
#[derive(Subcommand, Debug)]
pub enum Commands {
	/// Initialize configuration
	Init(commands::InitCommand),

	/// Show current configuration
	Config,

	/// Environment management (local mode only)
	Env(commands::EnvCommand),

	/// Token operations
	Token(commands::TokenCommand),

	/// Account management
	Account(commands::AccountCommand),

	/// Intent operations
	Intent(commands::IntentCommand),

	/// Quote operations
	Quote(commands::QuoteCommand),
}
