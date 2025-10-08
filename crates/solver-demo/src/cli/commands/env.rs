//! Environment management command definitions and argument structures
//!
//! This module defines the CLI arguments for environment management operations
//! including local network startup, contract deployment, environment setup,
//! and status monitoring for development and testing environments.

use clap::{Args, Subcommand};

/// Environment management command with comprehensive subcommand support
///
/// Provides access to environment lifecycle operations including local network
/// management, contract deployment, and environment setup for testing
#[derive(Args, Debug)]
pub struct EnvCommand {
	#[command(subcommand)]
	pub command: EnvSubcommand,
}

/// Available environment management subcommands
///
/// Provides comprehensive environment lifecycle management including
/// network control, deployment operations, and setup automation
#[derive(Subcommand, Debug)]
pub enum EnvSubcommand {
	/// Start local development environment with Anvil blockchain networks
	Start,

	/// Stop running local development environment and cleanup resources
	Stop,

	/// Display current environment status and configuration details
	Status,

	/// Deploy smart contracts to blockchain networks with flexible targeting
	Deploy {
		/// Specific contract name to deploy (e.g., InputSettlerEscrow, AlwaysOKAllocator)
		#[arg(short = 'n', long)]
		contract: Option<String>,

		/// Deploy complete set of standard protocol contracts
		#[arg(long)]
		all: bool,

		/// Target blockchain network ID (deploys to all configured chains if unspecified)
		#[arg(short, long)]
		chain: Option<u64>,

		/// Force contract redeployment even if contracts already exist
		#[arg(long)]
		force: bool,

		/// Display list of available contracts for deployment
		#[arg(long)]
		list: bool,

		/// Path to compiled contract artifacts directory
		#[arg(short, long, default_value = "oif-contracts/out")]
		path: String,
	},

	/// Setup complete testing environment with token minting and permissions
	Setup {
		/// Target blockchain network ID (setup all configured chains if unspecified)
		#[arg(short, long)]
		chain: Option<u64>,

		/// Amount of tokens to mint for testing (specified in whole token units)
		#[arg(short, long, default_value = "1000")]
		amount: u64,
	},
}
