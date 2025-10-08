//! Account management command definitions and argument structures
//!
//! This module defines the CLI arguments for account management operations
//! including listing configured accounts and displaying detailed account
//! information for user, solver, and recipient accounts.

use clap::{Args, Subcommand};

/// Account management command with subcommand routing
///
/// Provides access to account-related operations including account listing
/// and detailed information display for configured application accounts
#[derive(Args, Debug)]
pub struct AccountCommand {
	#[command(subcommand)]
	pub command: AccountSubcommand,
}

/// Available account management subcommands
///
/// Provides operations for viewing and inspecting configured accounts
/// including comprehensive listing and detailed account information
#[derive(Subcommand, Debug)]
pub enum AccountSubcommand {
	/// Display list of all configured accounts with basic information
	List,

	/// Show detailed information for specific account type
	Info {
		/// Account type identifier (user, solver, or recipient)
		account: String,
	},
}
