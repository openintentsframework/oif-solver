//! CLI tool for demonstrating OIF Solver cross-chain intent execution
//!
//! This crate provides a command-line interface for testing and demonstrating
//! the Open Intent Framework (OIF) Solver's capabilities for executing cross-chain
//! intents. It includes functionality for environment setup, token management,
//! quote generation, and intent execution across multiple blockchain networks.

pub mod cli;
pub mod constants;
pub mod core;
pub mod operations;
pub mod types;

// Re-export key types from solver-types for convenience
pub use solver_types::{
	api::{
		AssetAmount, AuthScheme, GetQuoteRequest, GetQuoteResponse, IntentRequest, OifOrder,
		PostOrderRequest, PostOrderResponse, Quote, SwapType,
	},
	networks::{NetworkConfig, TokenConfig},
};

// Re-export Address type from alloy for convenience
pub use alloy_primitives::Address;

// Re-export Alloy Bytes type for signatures
pub use alloy_primitives::Bytes;

// Re-export utility functions from solver-types
pub use solver_types::utils::{
	conversion::{parse_address, parse_bytes32_from_hex},
	formatting::{format_token_amount, with_0x_prefix, without_0x_prefix},
};

// Re-export our custom types
pub use types::{
	chain::ChainId,
	error::{Error, Result},
	session::{Environment, Session},
};

// Re-export core components
pub use core::{
	api::ApiClient,
	blockchain::{Provider, TxBuilder},
	config::Config,
	contracts::Contracts,
	jwt::JwtService,
	session::SessionStore,
	signing::SigningService,
	storage::Storage,
	tokens::TokenRegistry,
};

// Main application context
use std::path::Path;
use std::sync::RwLock;

use crate::core::{contracts::ContractAddresses, logging};

/// Main application context holding all shared state
pub struct Context {
	pub config: Config,
	pub storage: Storage,
	pub session: SessionStore,
	pub tokens: TokenRegistry,
	pub contracts: RwLock<Contracts>,
	pub signing: SigningService,
	pub jwt: JwtService,
}

impl Context {
	/// Initialize a new context from configuration path
	///
	/// # Arguments
	/// * `config_path` - Path to the configuration file
	/// * `is_local` - Whether to run in local development mode
	///
	/// # Returns
	/// A new Context instance with all components initialized
	///
	/// # Errors
	/// Returns Error if configuration loading, storage initialization, or component setup fails
	pub async fn init(config_path: &Path, is_local: bool) -> Result<Self> {
		let config = Config::load(config_path).await?;
		let storage = Storage::new(&config.data_dir())?;
		let session = SessionStore::new(
			storage.clone(),
			config_path.to_path_buf(),
			if is_local {
				Environment::Local
			} else {
				Environment::Production
			},
		)?;
		let tokens = TokenRegistry::from_config(&config)?;
		let mut contracts = Contracts::new();

		// Load ABIs (pass a dummy path since we use embedded ABIs)
		contracts.load_abis(std::path::Path::new("."))?;

		// Load deployed contracts from session into contracts struct
		for chain in config.chains() {
			if let Some(deployed) = session.contracts(chain) {
				use crate::core::logging;
				logging::verbose_tech(
					"Loading contracts for chain",
					&format!(
						"chain {}, allocator: {:?}, compact: {:?}",
						chain.id(),
						deployed.allocator,
						deployed.compact
					),
				);

				// Convert session contracts to contracts struct format using helper
				match ContractAddresses::from_session_contract_set(deployed) {
					Ok(contract_addresses) => {
						contracts.set_addresses(chain, contract_addresses);
						logging::verbose_success(
							"Contracts loaded successfully for chain",
							&chain.id().to_string(),
						);
					},
					Err(e) => {
						logging::warning(&format!(
							"Failed to load contracts for chain {}: {}",
							chain.id(),
							e
						));
					},
				}
			}
		}

		// Populate session with chains from config
		session.set_chains(config.chains())?;

		// Save the session to persist the config path and chains
		session.save()?;

		// Create signing service
		let signing = SigningService::new();

		// Create JWT service with API URL
		let api_url = if let Some(api_config) = &config.solver.api {
			format!("http://{}:{}", api_config.host, api_config.port)
		} else {
			"http://localhost:3000".to_string()
		};
		let jwt = JwtService::new(api_url);

		Ok(Self {
			config,
			storage,
			session,
			tokens,
			contracts: RwLock::new(contracts),
			signing,
			jwt,
		})
	}

	/// Create a blockchain provider for the specified chain
	///
	/// # Arguments
	/// * `chain` - The chain ID to create a provider for
	///
	/// # Returns
	/// A Provider instance configured for the specified chain
	///
	/// # Errors
	/// Returns Error if the chain is not found in configuration or RPC URL is invalid
	pub async fn provider(&self, chain: ChainId) -> Result<Provider> {
		let network = self
			.config
			.network(chain)
			.ok_or_else(|| Error::ChainNotFound(chain))?;

		// Use first RPC URL from the list
		let rpc_endpoint = network
			.rpc_urls
			.first()
			.ok_or_else(|| Error::InvalidConfig("No RPC URLs configured".to_string()))?;

		// Extract HTTP URL from RpcEndpoint
		let rpc_url = rpc_endpoint
			.http
			.as_ref()
			.ok_or_else(|| Error::InvalidConfig("No HTTP RPC URL configured".to_string()))?;

		Provider::new(chain, rpc_url).await
	}

	/// Create an authenticated API client for solver service communication
	///
	/// # Returns
	/// An ApiClient instance configured with JWT authentication if enabled
	///
	/// # Errors
	/// Returns Error if JWT token retrieval fails (when auth is enabled) or API client creation fails
	pub async fn api_client(&self) -> Result<ApiClient> {
		// Get API URL from config if available, otherwise use default
		let api_url = if let Some(api_config) = &self.config.solver.api {
			format!("http://{}:{}", api_config.host, api_config.port)
		} else {
			"http://localhost:3000".to_string()
		};

		// Check if auth is enabled
		let auth_enabled = self.config.solver.api
			.as_ref()
			.and_then(|api| api.auth.as_ref())
			.map(|auth| auth.enabled)
			.unwrap_or(false);

		// Create API client with or without JWT authentication
		if auth_enabled {
			// Get valid JWT token
			let token = self.jwt.get_valid_token(&self.session).await?;
			ApiClient::new(&api_url).map(|client| client.with_jwt(token))
		} else {
			// Create API client without authentication
			ApiClient::new(&api_url)
		}
	}
}

impl Context {
	/// Load existing context from previously stored session data
	///
	/// # Returns
	/// A Context instance restored from saved session and configuration
	///
	/// # Errors
	/// Returns Error if no session exists, config path is invalid, or initialization fails
	pub async fn load_existing() -> Result<Self> {
		// Check if there's a session with a stored config path
		let data_dir = std::path::Path::new(".oif-demo");
		if !data_dir.exists() {
			return Err(Error::InvalidConfig(
				"No configuration loaded. Run 'cargo run -p solver-demo -- init load <path>' first"
					.to_string(),
			));
		}

		let storage = Storage::new(data_dir)?;
		if !storage.exists("session") {
			return Err(Error::InvalidConfig(
				"No session found. Run 'cargo run -p solver-demo init load <path>' first"
					.to_string(),
			));
		}

		// Load existing session store
		let session_store = SessionStore::load(storage.clone())?;
		let config_path = session_store.config_path().ok_or_else(|| {
			Error::InvalidConfig(
				"No config path stored. Run 'cargo run -p solver-demo init load <path>' first"
					.to_string(),
			)
		})?;

		if config_path.as_os_str().is_empty() {
			return Err(Error::InvalidConfig(
				"No config path stored. Run 'cargo run -p solver-demo init load <path>' first"
					.to_string(),
			));
		}

		if !config_path.exists() {
			return Err(Error::InvalidConfig(format!(
				"Config file not found: {}. Run 'cargo run -p solver-demo init load <path>' again",
				config_path.display()
			)));
		}

		// Load the config
		let config = Config::load(&config_path).await?;
		let tokens = TokenRegistry::from_config(&config)?;
		let mut contracts = Contracts::new();

		// Load ABIs (pass a dummy path since we use embedded ABIs)
		contracts.load_abis(std::path::Path::new("."))?;

		// Load deployed contracts from session into contracts struct
		for chain in config.chains() {
			if let Some(deployed) = session_store.contracts(chain) {
				// Convert session contracts to contracts struct format using helper
				match ContractAddresses::from_session_contract_set(deployed) {
					Ok(contract_addresses) => {
						contracts.set_addresses(chain, contract_addresses);
					},
					Err(e) => {
						logging::warning(&format!(
							"Failed to load contracts for chain {} from session: {}",
							chain.id(),
							e
						));
					},
				}
			}
		}

		// Create signing service
		let signing = SigningService::new();

		// Create JWT service with API URL
		let api_url = if let Some(api_config) = &config.solver.api {
			format!("http://{}:{}", api_config.host, api_config.port)
		} else {
			"http://localhost:3000".to_string()
		};
		let jwt = JwtService::new(api_url);

		Ok(Self {
			config,
			storage,
			session: session_store,
			tokens,
			contracts: RwLock::new(contracts),
			signing,
			jwt,
		})
	}

	/// Get the default chain ID from configuration
	///
	/// # Returns
	/// The first configured chain ID, or chain 31337 if no chains are configured
	pub fn default_chain(&self) -> ChainId {
		self.config
			.chains()
			.first()
			.copied()
			.unwrap_or(ChainId::Custom { id: 31337 })
	}

	/// Check if the context is running in local development mode
	///
	/// # Returns
	/// True if environment is set to Local, false otherwise
	pub fn is_local(&self) -> bool {
		matches!(self.session.environment(), Environment::Local)
	}

	/// Resolve an address from either a hex string or predefined account name
	///
	/// # Arguments
	/// * `address_or_name` - Either a hex address string or account name (user, solver, recipient)
	///
	/// # Returns
	/// The resolved Address
	///
	/// # Errors
	/// Returns Error if the input is neither a valid hex address nor a known account name
	pub fn resolve_address(&self, address_or_name: &str) -> Result<Address> {
		match address_or_name.to_lowercase().as_str() {
			"user" => {
				use crate::types::hex::Hex;
				Hex::to_address(&self.config.accounts().user.address).map_err(|_| {
					Error::InvalidAddress(format!(
						"Invalid user address: {}",
						&self.config.accounts().user.address
					))
				})
			},
			"solver" => {
				use crate::types::hex::Hex;
				Hex::to_address(&self.config.accounts().solver.address).map_err(|_| {
					Error::InvalidAddress(format!(
						"Invalid solver address: {}",
						&self.config.accounts().solver.address
					))
				})
			},
			"recipient" => {
				use crate::types::hex::Hex;
				Hex::to_address(&self.config.accounts().recipient.address).map_err(|_| {
					Error::InvalidAddress(format!(
						"Invalid recipient address: {}",
						&self.config.accounts().recipient.address
					))
				})
			},
			_ => {
				// Try to parse as hex address
				use crate::types::hex::Hex;
				Hex::to_address(address_or_name).map_err(|_| {
					Error::InvalidAddress(format!(
						"Invalid address or unknown account name: {}",
						address_or_name
					))
				})
			},
		}
	}

	/// Get a human-readable display name for an address
	///
	/// # Arguments
	/// * `address` - The address to generate a display name for
	///
	/// # Returns
	/// A string containing the address with account label if it matches a known account
	pub fn address_display_name(&self, address: Address) -> String {
		use crate::types::hex::Hex;

		// Check if it matches any of our known accounts
		if let Ok(user_addr) = Hex::to_address(&self.config.accounts().user.address) {
			if address == user_addr {
				return format!("{} (user)", address);
			}
		}

		if let Ok(solver_addr) = Hex::to_address(&self.config.accounts().solver.address) {
			if address == solver_addr {
				return format!("{} (solver)", address);
			}
		}

		if let Ok(recipient_addr) = Hex::to_address(&self.config.accounts().recipient.address) {
			if address == recipient_addr {
				return format!("{} (recipient)", address);
			}
		}

		// Just return the address
		format!("{}", address)
	}

	/// Get all available predefined account names
	///
	/// # Returns
	/// A slice containing all valid account name strings
	pub fn available_account_names() -> &'static [&'static str] {
		&["user", "solver", "recipient"]
	}

	/// Check if a string matches a predefined account name
	///
	/// # Arguments
	/// * `name` - The string to check
	///
	/// # Returns
	/// True if the name matches a valid account name (case-insensitive)
	pub fn is_account_name(name: &str) -> bool {
		Self::available_account_names().contains(&name.to_lowercase().as_str())
	}

	/// Resolve multiple addresses from a comma-separated string
	///
	/// # Arguments
	/// * `addresses_str` - Comma-separated string of addresses or account names
	///
	/// # Returns
	/// A vector of resolved Address instances
	///
	/// # Errors
	/// Returns Error if any address in the string cannot be resolved
	pub fn resolve_addresses(&self, addresses_str: &str) -> Result<Vec<Address>> {
		addresses_str
			.split(',')
			.map(|addr| self.resolve_address(addr.trim()))
			.collect()
	}
}
