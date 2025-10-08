//! Configuration management and environment setup
//!
//! This module provides configuration loading, account management, and environment
//! variable handling for the solver demo application. Supports environment-based
//! configuration overrides and automatic reloading of configuration files.

use crate::{
	constants::{anvil_accounts, env_vars},
	types::{
		chain::ChainId,
		error::{Error, Result},
	},
};
use serde::{Deserialize, Serialize};
use solver_config::Config as SolverFullConfig;
use solver_types::networks::NetworkConfig;
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};

/// Central configuration manager for solver demo application
///
/// Combines solver configuration, network settings, and account information
/// with support for environment variable overrides and automatic loading
/// from configuration files with include directives
#[derive(Debug, Clone)]
pub struct Config {
	pub path: PathBuf,
	pub solver: SolverFullConfig,
	networks: HashMap<ChainId, NetworkConfig>,
	accounts: Accounts,
}

impl Config {
	/// Load configuration from file path with environment variable support
	///
	/// Loads environment variables from .env file if present, then reads and
	/// parses the configuration file including any referenced include files
	///
	/// # Arguments
	/// * `path` - Path to the main configuration file
	///
	/// # Returns
	/// Fully loaded Config instance with all networks and accounts configured
	///
	/// # Errors
	/// Returns Error if configuration file is missing, invalid, or includes cannot be resolved
	pub async fn load(path: &Path) -> Result<Self> {
		// Load .env file if it exists (ignore errors if not found)
		let _ = dotenvy::dotenv();

		if !path.exists() {
			return Err(Error::ConfigNotFound(path.to_path_buf()));
		}

		// Use SolverFullConfig::from_file to properly handle includes
		let full_config = SolverFullConfig::from_file(path.to_str().unwrap()).await?;

		// Extract networks from the full config
		let mut networks = HashMap::new();
		for (chain_id, network) in &full_config.networks {
			let chain_id_obj = ChainId::from_u64(*chain_id);
			networks.insert(chain_id_obj, network.clone());
		}

		// Extract accounts from the full config (with env var support)
		let accounts = Accounts::from_full_config(&full_config)?;

		Ok(Self {
			path: path.to_path_buf(),
			solver: full_config,
			networks,
			accounts,
		})
	}

	/// Reload configuration from disk and update current instance
	///
	/// Reloads the configuration file from the same path used during initial
	/// load, updating all settings and accounts with current values
	///
	/// # Returns
	/// Success if configuration is reloaded successfully
	///
	/// # Errors
	/// Returns Error if configuration file cannot be read or parsed
	pub async fn reload(&mut self) -> Result<()> {
		*self = Self::load(&self.path).await?;
		Ok(())
	}

	/// Retrieve network configuration for a specific blockchain chain
	///
	/// # Arguments
	/// * `chain` - Target blockchain network identifier
	///
	/// # Returns
	/// Optional reference to NetworkConfig if chain is configured
	pub fn network(&self, chain: ChainId) -> Option<&NetworkConfig> {
		self.networks.get(&chain)
	}

	/// Retrieve list of all configured blockchain networks
	///
	/// # Returns
	/// Vector of ChainId instances for all networks defined in configuration
	pub fn chains(&self) -> Vec<ChainId> {
		self.networks.keys().copied().collect()
	}

	/// Retrieve the data directory path for application storage
	///
	/// Returns the project-relative path used for storing session data,
	/// temporary files, and other application state
	///
	/// # Returns
	/// PathBuf pointing to the .oif-demo directory in project root
	pub fn data_dir(&self) -> PathBuf {
		// Always use project root for data directory
		Path::new(".").join(".oif-demo")
	}

	/// Retrieve account configuration for all application accounts
	///
	/// # Returns
	/// Reference to Accounts containing user, solver, and recipient account information
	pub fn accounts(&self) -> &Accounts {
		&self.accounts
	}
}

/// Account configuration container for application accounts
///
/// Contains user, solver, and recipient account information with support
/// for environment variable overrides and private key management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Accounts {
	pub user: Account,
	pub solver: Account,
	pub recipient: Account,
}

impl Accounts {
	fn from_full_config(_config: &SolverFullConfig) -> Result<Self> {
		// Read from environment variables with defaults
		let user = Account {
			address: env::var(env_vars::USER_ADDRESS)
				.unwrap_or_else(|_| anvil_accounts::USER_ADDRESS.to_string()),
			private_key: env::var(env_vars::USER_PRIVATE_KEY)
				.ok()
				.or_else(|| Some(anvil_accounts::USER_PRIVATE_KEY.to_string()))
				.map(|s| solver_types::SecretString::from(s.as_str())),
		};

		// Solver account - read from env or use defaults
		let solver = Account {
			address: env::var(env_vars::SOLVER_ADDRESS)
				.unwrap_or_else(|_| anvil_accounts::SOLVER_ADDRESS.to_string()),
			private_key: env::var(env_vars::SOLVER_PRIVATE_KEY)
				.ok()
				.or_else(|| Some(anvil_accounts::SOLVER_PRIVATE_KEY.to_string()))
				.map(|s| solver_types::SecretString::from(s.as_str())),
		};

		// Recipient account - usually no private key needed
		let recipient = Account {
			address: env::var(env_vars::RECIPIENT_ADDRESS)
				.unwrap_or_else(|_| anvil_accounts::RECIPIENT_ADDRESS.to_string()),
			private_key: None,
		};

		Ok(Self {
			user,
			solver,
			recipient,
		})
	}
}

/// Individual account information with optional private key
///
/// Represents a blockchain account with address and optional private key
/// for transaction signing operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
	pub address: String,
	pub private_key: Option<solver_types::SecretString>,
}

impl Account {
	/// Check if account has a private key available for signing
	///
	/// # Returns
	/// True if private key is present, false otherwise
	pub fn has_private_key(&self) -> bool {
		self.private_key.is_some()
	}

	/// Convert account address to EIP-55 checksum format
	///
	/// Converts the account address string to proper checksummed format
	/// for display and validation purposes
	///
	/// # Returns
	/// Checksummed address string
	///
	/// # Errors
	/// Returns Error if address format is invalid
	pub fn address_checksum(&self) -> Result<String> {
		use crate::types::hex::Hex;
		let addr = Hex::to_address(&self.address)?;
		Ok(addr.to_checksum(None))
	}
}
