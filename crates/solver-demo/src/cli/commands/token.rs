//! Token operations command definitions and argument structures
//!
//! This module defines the CLI arguments for token-related operations
//! including token listing, minting, balance checking, and approval
//! management for ERC20 tokens across multiple blockchain networks.

use clap::{Args, Subcommand};

/// Token operations command with comprehensive ERC20 token management
///
/// Provides access to token lifecycle operations including listing,
/// minting, balance monitoring, and approval management across networks
#[derive(Args, Debug)]
pub struct TokenCommand {
	#[command(subcommand)]
	pub command: TokenSubcommand,
}

/// Available token operation subcommands
///
/// Provides comprehensive ERC20 token management including
/// discovery, minting, balance monitoring, and permission management
#[derive(Subcommand, Debug)]
pub enum TokenSubcommand {
	/// Display list of available tokens with filtering options
	List {
		/// Filter results by specific blockchain network IDs
		#[arg(long, value_delimiter = ',')]
		chains: Option<Vec<u64>>,
	},

	/// Mint test tokens for local development environments
	Mint {
		/// Target blockchain network identifier
		#[arg(long)]
		chain: u64,

		/// Token symbol identifier or contract address
		#[arg(long)]
		token: String,

		/// Amount of tokens to mint (in token units)
		#[arg(long)]
		amount: String,

		/// Recipient address for minted tokens (defaults to configured user)
		#[arg(long)]
		to: Option<String>,
	},

	/// Check token balances with monitoring and filtering capabilities
	Balance {
		/// Account type or address to check (user/solver/recipient/all or specific address)
		#[arg(long, default_value = "all")]
		account: String,

		/// Enable follow mode with refresh interval in seconds
		#[arg(long)]
		follow: Option<u64>,

		/// Filter results by specific blockchain network IDs
		#[arg(long, value_delimiter = ',')]
		chains: Option<Vec<u64>>,
	},

	/// Approve token spending allowance for specific spender
	Approve {
		/// Target blockchain network identifier
		#[arg(long)]
		chain: u64,

		/// Token symbol identifier or contract address
		#[arg(long)]
		token: String,

		/// Address authorized to spend tokens
		#[arg(long)]
		spender: String,

		/// Maximum amount of tokens to approve for spending
		#[arg(long)]
		amount: String,
	},
}
