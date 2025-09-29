pub mod accounts;
pub mod config_generator;
pub mod environment;
pub mod intent;
pub mod quote;
pub mod token;

use clap::Subcommand;
use std::path::PathBuf;

#[derive(Debug, Subcommand)]
pub enum Commands {
	/// Initialize demo configuration
	#[command(subcommand)]
	Init(InitCommand),

	/// Show current configuration
	Config,

	/// Manage local environment (Anvil chains)
	#[command(subcommand)]
	Env(environment::EnvironmentCommands),

	/// Token operations (mint, balance, approve)
	#[command(subcommand)]
	Token(token::TokenCommands),

	/// Account management
	#[command(subcommand)]
	Accounts(accounts::AccountCommands),

	/// Intent operations (build, submit, test, status, list)
	#[command(subcommand)]
	Intent(intent::IntentCommands),

	/// Quote operations (get, accept, test)
	#[command(subcommand)]
	Quote(quote::QuoteCommands),
}

#[derive(Debug, Subcommand)]
pub enum InitCommand {
	/// Generate a new configuration file with placeholder values
	New {
		/// Output path for the config file (e.g., config/demo.toml)
		path: PathBuf,

		/// Chain IDs to include
		#[arg(long, value_delimiter = ',', default_value = "31337,31338")]
		chains: Vec<u64>,
	},

	/// Load an existing configuration file
	Load {
		/// Config file path
		path: PathBuf,

		/// Initialize for local development
		#[arg(long)]
		local: bool,
	},
}
