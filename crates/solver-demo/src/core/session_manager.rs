//! Session management module for the OIF Solver demonstration system.
//!
//! This module provides comprehensive session management capabilities for tracking and persisting
//! state throughout the lifecycle of solver operations. It handles configuration loading,
//! network settings management, account information tracking, and contract address persistence.
//! The SessionManager serves as the central state repository for all solver operations,
//! ensuring consistency across different components and enabling seamless recovery from
//! interruptions or failures.

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::utils::address::bytes_to_checksum_address;

use crate::models::{
	AccountInfo, ContractAddresses, Environment, JwtTokenEntry, NetworkConfig, SessionConfig,
	TokenInfo,
};

/// Primary session management structure for the OIF Solver.
///
/// The SessionManager maintains all runtime configuration and state for solver operations.
/// It provides thread-safe access to configuration data through Arc and RwLock primitives,
/// enabling concurrent access from multiple components while maintaining data integrity.
/// The manager handles persistence of state to disk, ensuring that sessions can be
/// resumed after interruptions and that configuration changes are properly preserved.
pub struct SessionManager {
	/// Thread-safe session configuration containing runtime state.
	///
	/// Protected by RwLock to allow concurrent reads and exclusive writes,
	/// ensuring data consistency across multiple accessing components.
	config: Arc<RwLock<SessionConfig>>,

	/// Immutable solver configuration loaded from TOML files.
	///
	/// Contains network settings, account configurations, API endpoints,
	/// and other solver-specific parameters that remain constant during execution.
	solver_config: Arc<solver_config::Config>,

	/// Root directory for all session-related data storage.
	///
	/// Typically located at `.oif-demo` in the current working directory,
	/// this directory contains contracts, process IDs, outputs, and cache data.
	data_dir: PathBuf,

	/// Path to the JSON file storing persistent session configuration.
	///
	/// Located at `data_dir/config.json`, this file maintains session state
	/// across program executions and enables session recovery.
	config_file: PathBuf,
}

impl SessionManager {
	/// Initializes a new session with the specified configuration file.
	///
	/// Creates a new SessionManager instance by loading configuration from the specified
	/// TOML file and setting up the necessary directory structure. This method performs
	/// comprehensive initialization including parsing network configurations, extracting
	/// contract addresses, setting up RPC endpoints, and configuring account information.
	///
	/// The initialization process handles both local development and production environments,
	/// adjusting behavior accordingly based on the is_local parameter.
	pub async fn init(config_path: &Path, is_local: bool) -> Result<Self> {
		info!("Initializing session with config: {:?}", config_path);

		let data_dir = Self::get_data_directory()?;
		let config_file = data_dir.join("config.json");

		Self::ensure_directories(&data_dir)?;

		let mut config = SessionConfig::default();
		config.session.active_config = Some(config_path.to_path_buf());
		config.session.environment_type = if is_local {
			Environment::Local
		} else {
			Environment::Production
		};
		config.session.last_updated = chrono::Utc::now();

		if !config_path.exists() {
			return Err(anyhow!("Configuration file not found at {:?}", config_path));
		}

		debug!("Loading TOML configuration from {:?}", config_path);

		let parsed_config = solver_config::Config::from_file(
			config_path
				.to_str()
				.ok_or_else(|| anyhow!("Invalid config path"))?,
		)
		.await?;

		let includes = Self::parse_includes_from_config(config_path).await?;
		config.session.includes = includes;

		// Build network configurations using the extracted helper
		let (chain_ids, rpc_urls, network_configs) = Self::build_network_configs(&parsed_config);

		config.session.chain_ids = chain_ids;
		config.session.rpc_urls = rpc_urls;
		config.networks_config = network_configs.clone();

		for (chain_id, net_config) in &network_configs {
			config
				.session
				.contract_addresses
				.insert(*chain_id, net_config.contracts.clone());
		}

		if let Ok(primary) = Self::get_solver_address(&parsed_config).await {
			config.accounts.solver.address = primary;
		}

		debug!(
			"Loaded {} chains from configuration",
			config.session.chain_ids.len()
		);

		let manager = Self {
			config: Arc::new(RwLock::new(config)),
			solver_config: Arc::new(parsed_config),
			data_dir,
			config_file: config_file.clone(),
		};

		manager.save().await?;

		Ok(manager)
	}

	/// Loads an existing session from persistent storage.
	///
	/// Attempts to restore a previously saved session by reading the configuration
	/// from the JSON file in the data directory. This enables resumption of
	/// interrupted operations and maintains continuity across program executions.
	/// The method validates the stored configuration and ensures all required
	/// components are properly initialized before returning the session manager.
	pub async fn load() -> Result<Self> {
		let data_dir = Self::get_data_directory()?;
		let config_file = data_dir.join("config.json");

		Self::ensure_directories(&data_dir)?;

		if !config_file.exists() {
			return Err(anyhow!(
				"No session found. Please run 'oif-demo init <config>' first."
			));
		}

		let contents = tokio::fs::read_to_string(&config_file).await?;
		let mut config: SessionConfig = serde_json::from_str(&contents)?;

		debug!("Loaded session config: {:#?}", config);

		if config.networks_config.is_empty() && !config.session.contract_addresses.is_empty() {
			debug!("Populating networks_config from contract_addresses");
			for (chain_id, contracts) in &config.session.contract_addresses {
				let network_config = NetworkConfig {
					chain_id: *chain_id,
					name: format!("Chain {}", chain_id),
					rpc_url: config
						.session
						.rpc_urls
						.get(chain_id)
						.cloned()
						.unwrap_or_default(),
					explorer_url: None,
					contracts: contracts.clone(),
				};
				config.networks_config.insert(*chain_id, network_config);
			}
			debug!(
				"Populated networks_config with {} entries",
				config.networks_config.len()
			);
		}

		let solver_config = if let Some(ref config_path) = config.session.active_config {
			solver_config::Config::from_file(
				config_path
					.to_str()
					.ok_or_else(|| anyhow!("Invalid config path"))?,
			)
			.await?
		} else {
			return Err(anyhow!("No active configuration path stored in session"));
		};

		Ok(Self {
			config: Arc::new(RwLock::new(config)),
			solver_config: Arc::new(solver_config),
			data_dir,
			config_file,
		})
	}

	/// Parses include file references from the TOML configuration.
	///
	/// Analyzes the configuration file to identify and resolve all included
	/// configuration files. This supports modular configuration where settings
	/// can be split across multiple files for better organization. The method
	/// handles both relative and absolute paths, resolving them appropriately
	/// based on the base configuration directory.
	async fn parse_includes_from_config(config_path: &Path) -> Result<crate::models::IncludeFiles> {
		use tokio::fs;

		let mut includes = crate::models::IncludeFiles::default();
		let content = fs::read_to_string(config_path).await?;
		let parsed: toml::Value = toml::from_str(&content)?;
		let base_dir = config_path.parent().unwrap_or(Path::new("."));

		if let Some(table) = parsed.as_table() {
			for key in table.keys() {
				if key != "include" {
					includes
						.section_sources
						.insert(key.clone(), config_path.to_path_buf());
				}
			}
		}

		if let Some(include_value) = parsed.get("include") {
			if let Some(include_array) = include_value.as_array() {
				for item in include_array {
					if let Some(path_str) = item.as_str() {
						let path = PathBuf::from(path_str);

						let resolved_path = if path.is_relative() {
							base_dir.join(&path)
						} else {
							path.clone()
						};

						if let Some(file_stem) = path.file_stem() {
							if let Some(key) = file_stem.to_str() {
								includes
									.files
									.insert(key.to_string(), resolved_path.clone());
							}
						}

						if resolved_path.exists() {
							if let Ok(include_content) = fs::read_to_string(&resolved_path).await {
								if let Ok(include_parsed) =
									toml::from_str::<toml::Value>(&include_content)
								{
									if let Some(include_table) = include_parsed.as_table() {
										for section_key in include_table.keys() {
											if !includes.section_sources.contains_key(section_key) {
												includes.section_sources.insert(
													section_key.clone(),
													resolved_path.clone(),
												);
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}

		debug!("Parsed includes: {:?}", includes.files);
		debug!("Section sources: {:?}", includes.section_sources);

		Ok(includes)
	}

	/// Returns the path to the session data directory.
	///
	/// Provides access to the root directory where all session-related
	/// data is stored, including contracts, process IDs, outputs, and cache.
	pub fn data_dir(&self) -> &Path {
		&self.data_dir
	}

	/// Returns the path to the contracts directory.
	///
	/// Determines the appropriate location for contract artifacts, preferring
	/// the local oif-contracts/out directory if it exists, otherwise falling
	/// back to the contracts subdirectory within the data directory.
	pub fn contracts_dir(&self) -> PathBuf {
		let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
		let contracts_path = current_dir.join("oif-contracts").join("out");

		if contracts_path.exists() {
			contracts_path
		} else {
			self.data_dir.join("contracts")
		}
	}

	/// Returns the path to the process IDs directory.
	///
	/// Provides the location where process IDs for background services
	/// and chain instances are stored for tracking and management.
	pub fn pids_dir(&self) -> PathBuf {
		self.data_dir.join("pids")
	}

	/// Returns the path to the requests directory.
	///
	/// Provides the location for storing all API requests and responses,
	/// including quotes, intents, and orders.
	pub fn requests_dir(&self) -> PathBuf {
		self.data_dir.join("requests")
	}

	/// Retrieves the list of configured blockchain chain IDs.
	///
	/// Returns all chain IDs that have been configured in the session,
	/// representing the networks that the solver can interact with.
	pub async fn get_chain_ids(&self) -> Vec<u64> {
		let config = self.config.read().await;
		config.session.chain_ids.clone()
	}

	/// Retrieves the RPC URL for a specific blockchain network.
	///
	/// Returns the configured RPC endpoint URL for the specified chain ID,
	/// or None if the chain is not configured in the session.
	pub async fn get_rpc_url(&self, chain_id: u64) -> Option<String> {
		let config = self.config.read().await;
		config.session.rpc_urls.get(&chain_id).cloned()
	}

	/// Retrieves the base URL for the solver API service.
	///
	/// Returns the configured API endpoint URL, constructing it from the
	/// host and port settings in the configuration. Falls back to a default
	/// localhost address if no API configuration is present.
	pub async fn get_api_base_url(&self) -> String {
		if let Some(ref api_config) = self.solver_config.api {
			let host = api_config.host.clone();
			let port = api_config.port;
			format!("http://{}:{}", host, port)
		} else {
			"http://127.0.0.1:3000".to_string()
		}
	}

	/// Retrieves the complete network configuration for a specific chain.
	///
	/// Returns the full NetworkConfig structure containing RPC URLs, contract
	/// addresses, token information, and other network-specific settings for
	/// the specified chain ID.
	pub async fn get_network_config(&self, chain_id: u64) -> Option<NetworkConfig> {
		let config = self.config.read().await;
		config.networks_config.get(&chain_id).cloned()
	}

	/// Retrieves the current environment type.
	///
	/// Returns whether the session is configured for local development
	/// or production deployment, affecting various operational behaviors.
	pub async fn get_environment(&self) -> Environment {
		let config = self.config.read().await;
		config.session.environment_type.clone()
	}

	/// Checks if the session is configured for local development.
	///
	/// Returns true if the environment is set to Local, indicating that
	/// the solver is operating in development mode with local chains.
	pub async fn is_local(&self) -> bool {
		let config = self.config.read().await;
		matches!(config.session.environment_type, Environment::Local)
	}

	/// Retrieves the parsed include file information.
	///
	/// Returns the structure containing all included configuration files
	/// and their relationships, enabling modular configuration management.
	pub async fn get_includes(&self) -> crate::models::IncludeFiles {
		let config = self.config.read().await;
		config.session.includes.clone()
	}

	/// Retrieves the path to the active configuration file.
	///
	/// Returns the file path of the currently active TOML configuration,
	/// or None if no configuration is currently active.
	pub fn get_config_path(&self) -> Option<String> {
		self.config.try_read().ok().and_then(|config| {
			config
				.session
				.active_config
				.as_ref()
				.map(|p| p.display().to_string())
		})
	}

	/// Retrieves the user account information.
	///
	/// Returns the AccountInfo structure containing the address and
	/// optional private key for the user account used in demonstrations.
	pub async fn get_user_account(&self) -> AccountInfo {
		let config = self.config.read().await;
		AccountInfo {
			address: config.accounts.user.address,
			private_key: config.accounts.user.private_key.clone(),
			label: "User".to_string(),
		}
	}

	/// Retrieves the solver account information.
	///
	/// Returns the AccountInfo structure for the solver account, including
	/// the address and attempting to retrieve the private key from the
	/// configured account implementation.
	pub async fn get_solver_account(&self) -> AccountInfo {
		let config = self.config.read().await;

		let private_key = self.get_solver_private_key().await.ok();

		AccountInfo {
			address: config.accounts.solver.address,
			private_key,
			label: "Solver".to_string(),
		}
	}

	/// Retrieves the recipient account information.
	///
	/// Returns the AccountInfo structure for the recipient account used
	/// in transfer demonstrations and testing scenarios.
	pub async fn get_recipient_account(&self) -> AccountInfo {
		let config = self.config.read().await;
		AccountInfo {
			address: config.accounts.recipient.address,
			private_key: config.accounts.recipient.private_key.clone(),
			label: "Recipient".to_string(),
		}
	}

	/// Retrieves a stored JWT token by key.
	///
	/// Returns the JWT token entry associated with the specified key,
	/// or None if no token is stored for that key.
	pub async fn get_jwt_token(&self, key: &str) -> Option<JwtTokenEntry> {
		let config = self.config.read().await;
		config.tokens.get(key).cloned()
	}

	/// Stores a JWT token with the specified key.
	///
	/// Saves the JWT token entry under the given key and persists the
	/// updated configuration to disk for future use.
	pub async fn set_jwt_token(&self, key: String, token: JwtTokenEntry) -> Result<()> {
		let mut config = self.config.write().await;
		config.tokens.insert(key, token);
		drop(config);
		self.save().await
	}

	/// Retrieves all contract addresses for a specific chain.
	///
	/// Returns the ContractAddresses structure containing all deployed
	/// contract addresses for the specified chain ID.
	pub async fn get_contract_addresses(&self, chain_id: u64) -> Option<ContractAddresses> {
		let config = self.config.read().await;
		config.session.contract_addresses.get(&chain_id).cloned()
	}

	/// Retrieves information for a specific token on a chain.
	///
	/// Returns the TokenInfo structure containing the address and decimals
	/// for the specified token symbol on the given chain.
	pub async fn get_token_info(&self, chain_id: u64, token: &str) -> Result<TokenInfo> {
		let config = self.config.read().await;
		config
			.session
			.contract_addresses
			.get(&chain_id)
			.and_then(|addresses| addresses.tokens.get(token).cloned())
			.ok_or_else(|| anyhow!("Token {} not found on chain {}", token, chain_id))
	}

	/// Retrieves the contract address for a specific token.
	///
	/// Returns the Ethereum address of the specified token contract
	/// on the given chain.
	pub async fn get_token_address(&self, chain_id: u64, token: &str) -> Result<String> {
		self.get_token_info(chain_id, token)
			.await
			.map(|info| info.address)
	}

	/// Retrieves the decimal places for a specific token.
	///
	/// Returns the number of decimal places used by the specified token
	/// on the given chain for proper amount calculations.
	pub async fn get_token_decimals(&self, chain_id: u64, token: &str) -> Result<u8> {
		self.get_token_info(chain_id, token)
			.await
			.map(|info| info.decimals)
	}

	/// Builds network configurations from a parsed solver config.
	///
	/// Converts the networks from solver_types::NetworkConfig to the session's
	/// NetworkConfig format, handling RPC URL selection, address formatting,
	/// and oracle configuration. Returns chain IDs, RPC URLs, and network configs.
	fn build_network_configs(
		parsed_config: &solver_config::Config,
	) -> (Vec<u64>, HashMap<u64, String>, HashMap<u64, NetworkConfig>) {
		let mut chain_ids = Vec::new();
		let mut rpc_urls = HashMap::new();
		let mut network_configs = HashMap::new();

		for (chain_id, network) in parsed_config.networks.iter() {
			chain_ids.push(*chain_id);
			if let Some(rpc_url) = network.rpc_urls.first() {
				let url = if let Some(http_url) = &rpc_url.http {
					http_url.clone()
				} else if let Some(ws_url) = &rpc_url.ws {
					ws_url.clone()
				} else {
					continue;
				};

				rpc_urls.insert(*chain_id, url.clone());
				let oracle_address =
					Self::get_oracle_for_chain(&parsed_config.settlement, *chain_id);

				let net_config = NetworkConfig {
					chain_id: *chain_id,
					name: format!("Chain {}", chain_id),
					rpc_url: url,
					explorer_url: None,
					contracts: ContractAddresses {
						input_settler: Some(bytes_to_checksum_address(
							&network.input_settler_address.0,
							Some(*chain_id),
						)),
						output_settler: Some(bytes_to_checksum_address(
							&network.output_settler_address.0,
							Some(*chain_id),
						)),
						permit2: Some(
							crate::utils::constants::PERMIT2_CANONICAL_ADDRESS.to_string(),
						),
						tokens: network
							.tokens
							.iter()
							.map(|token| {
								(
									token.symbol.clone(),
									TokenInfo {
										address: bytes_to_checksum_address(
											&token.address.0,
											Some(*chain_id),
										),
										decimals: token.decimals,
									},
								)
							})
							.collect(),
						compact: network
							.the_compact_address
							.as_ref()
							.map(|a| bytes_to_checksum_address(&a.0, Some(*chain_id))),
						input_settler_compact: network
							.input_settler_compact_address
							.as_ref()
							.map(|a| bytes_to_checksum_address(&a.0, Some(*chain_id))),
						allocator: network
							.allocator_address
							.as_ref()
							.map(|a| bytes_to_checksum_address(&a.0, Some(*chain_id))),
						oracle: oracle_address,
					},
				};

				network_configs.insert(*chain_id, net_config);
			}
		}

		(chain_ids, rpc_urls, network_configs)
	}

	/// Reloads the configuration from disk to pick up any file changes.
	///
	/// This method refreshes the in-memory configuration by re-reading the
	/// TOML files from disk. This is useful after configuration files have
	/// been updated (e.g., with new contract addresses) and the in-memory
	/// state needs to be synchronized with the file system.
	pub async fn reload_config(&self) -> Result<()> {
		// Get the original config file path from the session
		let config = self.config.read().await;
		let config_path = config
			.session
			.active_config
			.as_ref()
			.ok_or_else(|| anyhow!("No active config path found"))?
			.clone();
		drop(config);

		// Parse the config file using the same method as init
		let parsed_config = solver_config::Config::from_file(
			config_path
				.to_str()
				.ok_or_else(|| anyhow!("Invalid config path"))?,
		)
		.await?;

		// Build networks config using the extracted helper
		let (_, _, network_configs) = Self::build_network_configs(&parsed_config);

		// Update the networks configuration in memory
		let mut config = self.config.write().await;
		config.networks_config = network_configs;

		info!("Configuration reloaded from {}", config_path.display());
		Ok(())
	}

	/// Updates the contract addresses for a specific chain.
	///
	/// Stores the new contract addresses for the specified chain and persists
	/// the changes to disk. In local mode, also updates the TOML configuration
	/// files with the new addresses for consistency.
	pub async fn update_contract_addresses(
		&self,
		chain_id: u64,
		addresses: ContractAddresses,
	) -> Result<()> {
		let mut config = self.config.write().await;
		config
			.session
			.contract_addresses
			.insert(chain_id, addresses.clone());
		config.session.last_updated = chrono::Utc::now();
		drop(config);
		self.save().await?;

		if self.is_local().await {
			self.update_toml_config(chain_id, &addresses).await?;
		}

		Ok(())
	}

	/// Updates the network configuration for a specific chain.
	///
	/// Stores the new network configuration including RPC URLs and contract
	/// addresses, then persists the changes to maintain consistency.
	pub async fn update_network_config(&self, chain_id: u64, network: NetworkConfig) -> Result<()> {
		let mut config = self.config.write().await;
		config.networks_config.insert(chain_id, network);
		config.session.last_updated = chrono::Utc::now();
		drop(config);
		self.save().await
	}

	/// Adds a new token to the configuration for a specific chain.
	///
	/// Registers a new token with its contract address and decimal places
	/// for the specified chain, enabling the solver to interact with it.
	pub async fn add_token(
		&self,
		chain_id: u64,
		symbol: String,
		address: String,
		decimals: u8,
	) -> Result<()> {
		let mut config = self.config.write().await;
		let addresses = config
			.session
			.contract_addresses
			.entry(chain_id)
			.or_insert_with(ContractAddresses::default);
		addresses
			.tokens
			.insert(symbol, TokenInfo { address, decimals });
		config.session.last_updated = chrono::Utc::now();
		drop(config);
		self.save().await
	}

	/// Extracts the port number from a chain's RPC URL.
	///
	/// Attempts to parse the port number from the RPC URL configured for
	/// the specified chain, useful for local chain management.
	pub async fn get_chain_port(&self, chain_id: u64) -> Result<u16> {
		let rpc_url = self
			.get_rpc_url(chain_id)
			.await
			.ok_or_else(|| anyhow!("No RPC URL for chain {}", chain_id))?;

		Self::extract_port_from_url(&rpc_url)
			.ok_or_else(|| anyhow!("Cannot extract port from URL: {}", rpc_url))
	}

	/// Validates that the session is ready for deployment operations.
	///
	/// Checks that all necessary configuration elements are present,
	/// including chain IDs and RPC URLs, before allowing deployment.
	pub async fn is_deployment_ready(&self) -> Result<()> {
		let config = self.config.read().await;

		if config.session.chain_ids.is_empty() {
			return Err(anyhow!(
				"No chains found in session. Please run 'oif-demo init <config>' first."
			));
		}

		for chain_id in &config.session.chain_ids {
			if !config.session.rpc_urls.contains_key(chain_id) {
				return Err(anyhow!(
					"No RPC URL found for chain {} in session",
					chain_id
				));
			}
		}

		Ok(())
	}

	/// Persists the current session configuration to disk.
	///
	/// Serializes the session configuration to JSON and writes it to
	/// the config file, ensuring state persistence across executions.
	pub async fn save(&self) -> Result<()> {
		let config = self.config.read().await;
		let contents = serde_json::to_string_pretty(&*config)?;
		tokio::fs::write(&self.config_file, contents).await?;
		Ok(())
	}

	/// Clears the persisted session configuration.
	///
	/// Removes the configuration file from disk, effectively resetting
	/// the session state for a fresh start.
	pub async fn clear(&self) -> Result<()> {
		if self.config_file.exists() {
			tokio::fs::remove_file(&self.config_file).await?;
		}
		Ok(())
	}

	/// Determines the appropriate data directory for session storage.
	///
	/// Constructs the path to the .oif-demo directory in the current
	/// working directory for storing all session-related data.
	fn get_data_directory() -> Result<PathBuf> {
		let current_dir = std::env::current_dir()?;
		let data_dir = current_dir.join(".oif-demo");
		debug!("Using data directory: {}", data_dir.display());
		Ok(data_dir)
	}

	/// Ensures all required directories exist.
	///
	/// Creates the data directory and all necessary subdirectories
	/// if they don't already exist, providing the required structure
	/// for session operations.
	fn ensure_directories(data_dir: &Path) -> Result<()> {
		std::fs::create_dir_all(data_dir)?;
		std::fs::create_dir_all(data_dir.join("pids"))?;
		std::fs::create_dir_all(data_dir.join("requests"))?;
		Ok(())
	}

	/// Extracts the port number from a URL string.
	///
	/// Parses localhost URLs to extract the port number, returning None
	/// for non-localhost URLs or if parsing fails.
	fn extract_port_from_url(url: &str) -> Option<u16> {
		if url.contains("127.0.0.1:") || url.contains("localhost:") {
			url.split(':')
				.next_back()?
				.trim_end_matches('/')
				.parse()
				.ok()
		} else {
			None
		}
	}

	/// Updates TOML configuration files with deployed contract addresses.
	///
	/// In local development mode, replaces placeholder addresses in the TOML
	/// configuration files with actual deployed contract addresses. This ensures
	/// that the configuration files remain synchronized with the deployed state
	/// and can be used for subsequent operations.
	async fn update_toml_config(&self, chain_id: u64, addresses: &ContractAddresses) -> Result<()> {
		use crate::utils::placeholders::*;

		let config = self.config.read().await;
		let config_path = config
			.session
			.active_config
			.as_ref()
			.ok_or_else(|| anyhow!("No active config path in session"))?
			.clone();
		drop(config);

		let includes = self.get_includes().await;

		let networks_file = includes
			.networks()
			.ok_or_else(|| anyhow!("No networks configuration file found"))?
			.clone();

		let main_config_file = config_path.clone();

		if !networks_file.exists() {
			return Ok(());
		}

		let mut content = tokio::fs::read_to_string(&networks_file).await?;
		let original_content = content.clone();

		let format_addr = |addr: &str| -> String {
			// Parse the address and convert to checksum format
			let parsed_addr = addr
				.parse::<alloy_primitives::Address>()
				.unwrap_or_else(|_| panic!("Invalid address format: {}", addr));
			parsed_addr.to_checksum(Some(chain_id))
		};

		let mut all_chain_ids = self.get_chain_ids().await;
		all_chain_ids.sort_unstable();
		let placeholders = generate_placeholder_map(&all_chain_ids);

		if let Some(input_settler) = &addresses.input_settler {
			if let Some(placeholder) =
				placeholders.get(&format!("{}{}", PLACEHOLDER_INPUT_SETTLER_PREFIX, chain_id))
			{
				content = content.replace(placeholder, &format_addr(input_settler));
			}
		}

		if let Some(output_settler) = &addresses.output_settler {
			if let Some(placeholder) = placeholders.get(&format!(
				"{}{}",
				PLACEHOLDER_OUTPUT_SETTLER_PREFIX, chain_id
			)) {
				content = content.replace(placeholder, &format_addr(output_settler));
			}
		}

		if let Some(compact) = &addresses.compact {
			if let Some(placeholder) =
				placeholders.get(&format!("{}{}", PLACEHOLDER_COMPACT_PREFIX, chain_id))
			{
				content = content.replace(placeholder, &format_addr(compact));
			}
		}

		if let Some(input_settler_compact) = &addresses.input_settler_compact {
			if let Some(placeholder) = placeholders.get(&format!(
				"{}{}",
				PLACEHOLDER_INPUT_SETTLER_COMPACT_PREFIX, chain_id
			)) {
				content = content.replace(placeholder, &format_addr(input_settler_compact));
			}
		}

		if let Some(allocator) = &addresses.allocator {
			if let Some(placeholder) =
				placeholders.get(&format!("{}{}", PLACEHOLDER_ALLOCATOR_PREFIX, chain_id))
			{
				content = content.replace(placeholder, &format_addr(allocator));
			}
		}

		if let Some(toka_info) = addresses.tokens.get("TOKA") {
			if let Some(placeholder) =
				placeholders.get(&format!("{}{}", PLACEHOLDER_TOKEN_A_PREFIX, chain_id))
			{
				content = content.replace(placeholder, &format_addr(&toka_info.address));
			}
		}

		if let Some(tokb_info) = addresses.tokens.get("TOKB") {
			if let Some(placeholder) =
				placeholders.get(&format!("{}{}", PLACEHOLDER_TOKEN_B_PREFIX, chain_id))
			{
				content = content.replace(placeholder, &format_addr(&tokb_info.address));
			}
		}

		if let Some(oracle) = &addresses.oracle {
			if let Some(placeholder) =
				placeholders.get(&format!("{}{}", ORACLE_PLACEHOLDER_INPUT_PREFIX, chain_id))
			{
				content = content.replace(placeholder, &format_addr(oracle));
			}
			if let Some(placeholder) =
				placeholders.get(&format!("{}{}", ORACLE_PLACEHOLDER_OUTPUT_PREFIX, chain_id))
			{
				content = content.replace(placeholder, &format_addr(oracle));
			}
		}

		if content != original_content {
			tokio::fs::write(&networks_file, content).await?;
			info!(
				"Updated {} with deployed addresses for chain {}",
				networks_file.display(),
				chain_id
			);
		}

		if main_config_file.exists() {
			let mut main_content = tokio::fs::read_to_string(&main_config_file).await?;
			let original_main = main_content.clone();

			if let Some(oracle) = &addresses.oracle {
				if let Some(placeholder) =
					placeholders.get(&format!("{}{}", ORACLE_PLACEHOLDER_INPUT_PREFIX, chain_id))
				{
					main_content = main_content.replace(placeholder, &format_addr(oracle));
				}
				if let Some(placeholder) =
					placeholders.get(&format!("{}{}", ORACLE_PLACEHOLDER_OUTPUT_PREFIX, chain_id))
				{
					main_content = main_content.replace(placeholder, &format_addr(oracle));
				}
			}

			if chain_id == all_chain_ids[0] {
				if let Some(input_settler) = &addresses.input_settler {
					if let Some(placeholder) = placeholders.get(PLACEHOLDER_SETTLEMENT_DOMAIN) {
						main_content =
							main_content.replace(placeholder, &format_addr(input_settler));
					}
				}
			}

			if main_content != original_main {
				tokio::fs::write(&main_config_file, main_content).await?;
				info!(
					"Updated {} with oracle addresses for chain {}",
					main_config_file
						.file_name()
						.and_then(|n| n.to_str())
						.unwrap_or("config"),
					chain_id
				);
			}
		}

		Ok(())
	}

	/// Derives the solver account address from configuration.
	///
	/// Uses the configured account implementation to derive the solver's
	/// Ethereum address, supporting various account types including
	/// local wallets and hardware security modules.
	async fn get_solver_address(
		solver_config: &solver_config::Config,
	) -> Result<alloy_primitives::Address> {
		use solver_account::get_all_implementations;

		let primary = &solver_config.account.primary;

		let account_config = solver_config
			.account
			.implementations
			.get(primary)
			.ok_or_else(|| anyhow!("Account implementation '{}' not found", primary))?;

		let implementations = get_all_implementations();
		let (_, factory) = implementations
			.iter()
			.find(|(name, _)| name == primary)
			.ok_or_else(|| anyhow!("Unknown account implementation: {}", primary))?;

		let account =
			factory(account_config).map_err(|e| anyhow!("Failed to create account: {}", e))?;

		let solver_address = account
			.address()
			.await
			.map_err(|e| anyhow!("Failed to get solver address: {}", e))?;

		let address_hex = bytes_to_checksum_address(&solver_address.0, None);
		let address = address_hex
			.parse::<alloy_primitives::Address>()
			.map_err(|e| anyhow!("Failed to parse address: {}", e))?;

		Ok(address)
	}

	/// Retrieves the solver account's private key.
	///
	/// Extracts the private key from the configured account implementation
	/// when available, typically used for local development and testing.
	/// Returns an error if the account type doesn't support key extraction.
	pub async fn get_solver_private_key(&self) -> Result<String> {
		use solver_account::get_all_implementations;

		let solver_config = &self.solver_config;

		let primary = &solver_config.account.primary;

		let account_config = solver_config
			.account
			.implementations
			.get(primary)
			.ok_or_else(|| anyhow!("Account implementation '{}' not found", primary))?;

		let implementations = get_all_implementations();
		let (_, factory) = implementations
			.iter()
			.find(|(name, _)| name == primary)
			.ok_or_else(|| anyhow!("Unknown account implementation: {}", primary))?;

		let account =
			factory(account_config).map_err(|e| anyhow!("Failed to create account: {}", e))?;

		let secret_string = account.get_private_key();

		Ok(secret_string.expose_secret().to_string())
	}

	/// Retrieves oracle addresses for a specific cross-chain route.
	///
	/// Analyzes the settlement configuration to find oracle addresses
	/// that support the specified route from one chain to another.
	/// Returns a tuple of (input_oracle, output_oracle) addresses.
	pub fn get_oracle_addresses_for_route(
		&self,
		from_chain: u64,
		to_chain: u64,
	) -> Result<(Option<String>, Option<String>)> {
		for impl_config in self.solver_config.settlement.implementations.values() {
			if let Some(routes_value) = impl_config.get("routes") {
				if let Some(routes_table) = routes_value.as_table() {
					if let Some(destinations_value) = routes_table.get(&from_chain.to_string()) {
						if let Some(destinations) = destinations_value.as_array() {
							let supports_route = destinations.iter().any(|dest| {
								dest.as_integer().is_some_and(|d| d as u64 == to_chain)
							});

							if supports_route {
								return self.extract_oracle_addresses_from_impl(
									impl_config,
									from_chain,
									to_chain,
								);
							}
						}
					}
				}
			}
		}

		Ok((None, None))
	}

	/// Extracts oracle addresses from a settlement implementation configuration.
	///
	/// Parses the implementation configuration to find oracle addresses
	/// configured for the input and output chains in a cross-chain route.
	fn extract_oracle_addresses_from_impl(
		&self,
		impl_config: &toml::Value,
		from_chain: u64,
		to_chain: u64,
	) -> Result<(Option<String>, Option<String>)> {
		let mut input_oracle = None;
		let mut output_oracle = None;

		if let Some(oracles_value) = impl_config.get("oracles") {
			if let Some(oracles_table) = oracles_value.as_table() {
				if let Some(input_value) = oracles_table.get("input") {
					if let Some(input_table) = input_value.as_table() {
						if let Some(oracles_array) = input_table.get(&from_chain.to_string()) {
							if let Some(array) = oracles_array.as_array() {
								if let Some(first_oracle) = array.first() {
									if let Some(oracle_str) = first_oracle.as_str() {
										input_oracle = Some(oracle_str.to_string());
									}
								}
							}
						}
					}
				}

				if let Some(output_value) = oracles_table.get("output") {
					if let Some(output_table) = output_value.as_table() {
						if let Some(oracles_array) = output_table.get(&to_chain.to_string()) {
							if let Some(array) = oracles_array.as_array() {
								if let Some(first_oracle) = array.first() {
									if let Some(oracle_str) = first_oracle.as_str() {
										output_oracle = Some(oracle_str.to_string());
									}
								}
							}
						}
					}
				}
			}
		}

		Ok((input_oracle, output_oracle))
	}

	/// Retrieves the oracle address for a specific chain.
	///
	/// Searches the settlement configuration to find an oracle address
	/// configured for the specified chain ID.
	pub fn get_oracle_addresses_for_chain(&self, chain_id: u64) -> Option<String> {
		Self::get_oracle_for_chain(&self.solver_config.settlement, chain_id)
	}

	/// Searches for an oracle address in the settlement configuration.
	///
	/// Iterates through all settlement implementations to find an oracle
	/// address configured for the specified chain ID, checking both input
	/// and output oracle configurations.
	fn get_oracle_for_chain(
		settlement_config: &solver_config::SettlementConfig,
		chain_id: u64,
	) -> Option<String> {
		for impl_config in settlement_config.implementations.values() {
			if let Some(network_ids_value) = impl_config.get("network_ids") {
				if let Some(network_ids) = network_ids_value.as_array() {
					let has_chain = network_ids
						.iter()
						.any(|id| id.as_integer().is_some_and(|i| i as u64 == chain_id));

					if has_chain {
						if let Some(oracles_value) = impl_config.get("oracles") {
							if let Some(oracles_table) = oracles_value.as_table() {
								if let Some(input_value) = oracles_table.get("input") {
									if let Some(input_table) = input_value.as_table() {
										if let Some(oracles_array) =
											input_table.get(&chain_id.to_string())
										{
											if let Some(array) = oracles_array.as_array() {
												if let Some(first_oracle) = array.first() {
													if let Some(oracle_str) = first_oracle.as_str()
													{
														return Some(oracle_str.to_string());
													}
												}
											}
										}
									}
								}

								if let Some(output_value) = oracles_table.get("output") {
									if let Some(output_table) = output_value.as_table() {
										if let Some(oracles_array) =
											output_table.get(&chain_id.to_string())
										{
											if let Some(array) = oracles_array.as_array() {
												if let Some(first_oracle) = array.first() {
													if let Some(oracle_str) = first_oracle.as_str()
													{
														return Some(oracle_str.to_string());
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}

		None
	}
}
