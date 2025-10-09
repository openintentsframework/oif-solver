//! Session state management and persistent storage
//!
//! This module provides the SessionStore for maintaining application state
//! across CLI invocations. It handles configuration mapping, contract addresses,
//! JWT tokens, and other session data with thread-safe access and persistence.

use crate::{
	constants::DEFAULT_TOKEN_DECIMALS,
	types::{
		chain::ChainId,
		error::{Error, Result},
		session::{ContractSet, Environment, JwtToken, Session, SessionTokenInfo},
	},
};
use alloy_primitives::Address;

// Re-export for module convenience
pub use crate::types::session::ContractAddresses;
use std::sync::{Arc, RwLock};
use std::{
	collections::HashMap,
	path::{Path, PathBuf},
};

use super::storage::Storage;

/// Thread-safe session state manager with persistent storage
///
/// Provides concurrent access to session data including configuration paths,
/// deployed contracts, JWT tokens, and application environment settings.
/// All operations are thread-safe and automatically persisted to storage.
#[derive(Debug, Clone)]
pub struct SessionStore {
	session: Arc<RwLock<Session>>,
	storage: Storage,
}

/// Build configuration sections mapping by parsing config includes
///
/// # Arguments
/// * `config_path` - Path to the main configuration file
///
/// # Returns
/// HashMap mapping section names to their corresponding file paths
fn build_config_sections_mapping(config_path: &Path) -> HashMap<String, PathBuf> {
	let mut sections = HashMap::new();

	// Always map "main" to the main config file
	sections.insert("main".to_string(), config_path.to_path_buf());

	// Try to read and parse the main config file
	if let Ok(content) = std::fs::read_to_string(config_path) {
		if let Ok(main_config) = toml::from_str::<toml::Value>(&content) {
			// Check for includes array
			if let Some(includes) = main_config.get("include").and_then(|v| v.as_array()) {
				let config_dir = config_path.parent().unwrap_or(Path::new("."));

				for include_value in includes {
					if let Some(include_path_str) = include_value.as_str() {
						let include_path = config_dir.join(include_path_str);

						// Read the included file and determine what sections it contains
						if let Ok(include_content) = std::fs::read_to_string(&include_path) {
							if let Ok(include_config) =
								toml::from_str::<toml::Value>(&include_content)
							{
								// Map each top-level section in the included file
								if let Some(table) = include_config.as_table() {
									for section_name in table.keys() {
										sections.insert(section_name.clone(), include_path.clone());
									}
								}
							}
						}
					}
				}
			}

			// Also map sections that are directly in the main config file
			if let Some(table) = main_config.as_table() {
				for section_name in table.keys() {
					// Don't override if already mapped to an include file
					if !sections.contains_key(section_name) && section_name != "include" {
						sections.insert(section_name.clone(), config_path.to_path_buf());
					}
				}
			}
		}
	}

	sections
}

impl SessionStore {
	/// Create a new session store with fresh session state
	///
	/// # Arguments
	/// * `storage` - Storage instance for persistence
	/// * `config_path` - Path to the configuration file
	/// * `environment` - Runtime environment (Local or Production)
	///
	/// # Returns
	/// New SessionStore instance with initialized session state
	///
	/// # Errors
	/// Returns Error if session initialization fails
	pub fn new(storage: Storage, config_path: PathBuf, environment: Environment) -> Result<Self> {
		// Always create a fresh session to ensure it reflects the current TOML configuration
		// This ensures that any changes to the config files are properly reflected

		// Build config sections mapping based on standard structure
		let config_sections = build_config_sections_mapping(&config_path);

		// For now, start with empty placeholder map - this will be populated when config is generated
		let placeholder_map = HashMap::new();

		let session = Session::new(config_path, config_sections, placeholder_map, environment);

		Ok(Self {
			session: Arc::new(RwLock::new(session)),
			storage,
		})
	}

	/// Load an existing session store from persistent storage
	///
	/// # Arguments
	/// * `storage` - Storage instance containing saved session data
	///
	/// # Returns
	/// SessionStore instance restored from saved session state
	///
	/// # Errors
	/// Returns Error if no session exists in storage or loading fails
	pub fn load(storage: Storage) -> Result<Self> {
		if !storage.exists("session") {
			return Err(Error::InvalidConfig("No session found".to_string()));
		}

		let session: Session = storage.load("session")?;

		Ok(Self {
			session: Arc::new(RwLock::new(session)),
			storage,
		})
	}

	/// Save current session state to persistent storage
	///
	/// # Returns
	/// Success if session is saved successfully
	///
	/// # Errors
	/// Returns Error if acquiring read lock fails or storage operation fails
	pub fn save(&self) -> Result<()> {
		let session = self
			.session
			.read()
			.map_err(|e| Error::StorageError(format!("Failed to acquire read lock: {}", e)))?;
		self.storage.save("session", &*session)
	}

	/// Get the current runtime environment setting
	///
	/// # Returns
	/// Environment enum indicating Local or Production mode
	pub fn environment(&self) -> Environment {
		self.session
			.read()
			.map(|s| s.environment)
			.unwrap_or(Environment::Local)
	}

	/// Set the runtime environment setting
	///
	/// # Arguments
	/// * `env` - Environment to set (Local or Production)
	///
	/// # Returns
	/// Success if environment is updated and saved
	///
	/// # Errors
	/// Returns Error if acquiring write lock fails or save operation fails
	pub fn set_environment(&self, env: Environment) -> Result<()> {
		let mut session = self
			.session
			.write()
			.map_err(|e| Error::StorageError(format!("Failed to acquire write lock: {}", e)))?;
		session.environment = env;
		drop(session);
		self.save()
	}

	/// Get the list of configured blockchain chains
	///
	/// # Returns
	/// Vector of ChainId instances for all configured chains
	pub fn chains(&self) -> Vec<ChainId> {
		self.session
			.read()
			.map(|s| s.chains.clone())
			.unwrap_or_default()
	}

	/// Set the list of configured blockchain chains
	///
	/// # Arguments
	/// * `chains` - Vector of ChainId instances to configure
	///
	/// # Returns
	/// Success if chains are updated and saved
	///
	/// # Errors
	/// Returns Error if acquiring write lock fails or save operation fails
	pub fn set_chains(&self, chains: Vec<ChainId>) -> Result<()> {
		let mut session = self
			.session
			.write()
			.map_err(|e| Error::StorageError(format!("Failed to acquire write lock: {}", e)))?;
		session.chains = chains;
		drop(session);
		self.save()
	}

	/// Set the configuration file path
	///
	/// # Arguments
	/// * `path` - Path to the configuration file
	///
	/// # Returns
	/// Success if path is updated and saved
	///
	/// # Errors
	/// Returns Error if acquiring write lock fails or save operation fails
	pub fn set_config_path(&self, path: PathBuf) -> Result<()> {
		let mut session = self
			.session
			.write()
			.map_err(|e| Error::StorageError(format!("Failed to acquire write lock: {}", e)))?;
		session.config_path = path;
		drop(session);
		self.save()
	}

	/// Get config path
	pub fn config_path(&self) -> Option<PathBuf> {
		self.session.read().ok().map(|s| s.config_path.clone())
	}

	/// Get config sections mapping
	pub fn config_sections(&self) -> HashMap<String, PathBuf> {
		self.session
			.read()
			.ok()
			.map(|s| s.config_sections.clone())
			.unwrap_or_default()
	}

	/// Set placeholder mapping
	pub fn set_placeholder_map(&self, placeholder_map: HashMap<String, String>) -> Result<()> {
		let mut session = self
			.session
			.write()
			.map_err(|e| Error::StorageError(format!("Failed to acquire write lock: {}", e)))?;
		session.placeholder_map = placeholder_map;
		drop(session);
		self.save()
	}

	/// Get placeholder mapping
	pub fn placeholder_map(&self) -> HashMap<String, String> {
		self.session
			.read()
			.ok()
			.map(|s| s.placeholder_map.clone())
			.unwrap_or_default()
	}

	/// Find placeholder address for a given placeholder key
	pub fn get_placeholder_address(&self, placeholder_key: &str) -> Option<String> {
		self.session
			.read()
			.ok()?
			.placeholder_map
			.get(placeholder_key)
			.cloned()
	}

	/// Get or create JWT token
	pub fn get_jwt_token(&self, key: &str) -> Option<String> {
		let session = self.session.read().ok()?;
		session
			.jwt_tokens
			.get(key)
			.filter(|t| !t.is_expired())
			.map(|t| t.token.clone())
	}

	/// Store JWT token
	pub fn set_jwt_token(&self, key: String, token: String, expires_at: i64) -> Result<()> {
		let mut session = self
			.session
			.write()
			.map_err(|e| Error::StorageError(format!("Failed to acquire write lock: {}", e)))?;
		session
			.jwt_tokens
			.insert(key, JwtToken::new(token, expires_at));
		drop(session);
		self.save()
	}

	/// Get deployed contracts for a chain
	pub fn contracts(&self, chain: ChainId) -> Option<ContractSet> {
		let session = self.session.read().ok()?;
		session
			.deployed_contracts
			.get(&chain.id().to_string())
			.cloned()
	}

	/// Check if contracts are deployed for a chain
	pub fn has_contracts(&self, chain: ChainId) -> bool {
		if let Some(contracts) = self.contracts(chain) {
			// Check if any contract address is NOT a placeholder
			let session = self.session.read().unwrap();
			let placeholder_values: std::collections::HashSet<String> =
				session.placeholder_map.values().cloned().collect();

			// Check if any contract address is NOT in the placeholder map (meaning it's a real deployed contract)
			let has_real_contracts = contracts
				.all_addresses()
				.iter()
				.any(|addr| !placeholder_values.contains(&addr.to_lowercase()));

			has_real_contracts
		} else {
			false
		}
	}

	/// Set deployed contracts for a chain
	pub fn set_contracts(&self, chain: ChainId, contracts: ContractSet) -> Result<()> {
		let mut session = self
			.session
			.write()
			.map_err(|e| Error::StorageError(format!("Failed to acquire write lock: {}", e)))?;
		session
			.deployed_contracts
			.insert(chain.id().to_string(), contracts);
		drop(session);
		self.save()
	}

	/// Set contract addresses for a chain
	pub fn set_contract_addresses(
		&self,
		chain: ChainId,
		addresses: ContractAddresses,
	) -> Result<()> {
		{
			let mut session = self
				.session
				.write()
				.map_err(|e| Error::StorageError(format!("Failed to acquire write lock: {}", e)))?;

			// Convert ContractAddresses to ContractSet
			let contract_set = ContractSet {
				input_settler: addresses.input_settler.map(|a| format!("{:?}", a)),
				input_settler_compact: addresses.input_settler_compact.map(|a| format!("{:?}", a)),
				output_settler: addresses.output_settler.map(|a| format!("{:?}", a)),
				permit2: addresses.permit2.map(|a| format!("{:?}", a)),
				compact: addresses.the_compact.map(|a| format!("{:?}", a)),
				allocator: addresses.allocator.map(|a| format!("{:?}", a)),
				input_oracle: addresses.input_oracle.map(|a| format!("{:?}", a)),
				output_oracle: addresses.output_oracle.map(|a| format!("{:?}", a)),
				tokens: addresses
					.tokens
					.into_iter()
					.map(|(symbol, (address, decimals))| {
						(
							symbol,
							SessionTokenInfo {
								address: address.to_checksum(Some(chain.id())),
								decimals,
							},
						)
					})
					.collect(),
			};

			session
				.deployed_contracts
				.insert(chain.id().to_string(), contract_set);
		} // Write lock is dropped here

		// Now safe to call save() which needs a read lock
		self.save()?;
		Ok(())
	}

	/// Store individual contract address for specific chain and contract type
	///
	/// Updates contract address mapping for the specified chain with automatic
	/// contract type detection based on contract name
	///
	/// # Arguments
	/// * `chain` - Target blockchain network identifier
	/// * `contract_name` - Contract type name for address mapping
	/// * `address` - Contract address to store
	///
	/// # Returns
	/// Success if contract address is stored and session is saved
	///
	/// # Errors
	/// Returns Error if unknown contract name, lock acquisition fails, or save fails
	pub fn set_single_contract(
		&self,
		chain: ChainId,
		contract_name: &str,
		address: Address,
	) -> Result<()> {
		let mut session = self
			.session
			.write()
			.map_err(|e| Error::StorageError(format!("Failed to acquire write lock: {}", e)))?;

		// Get or create contract set for this chain
		let chain_key = chain.id().to_string();
		let mut contract_set = session
			.deployed_contracts
			.get(&chain_key)
			.cloned()
			.unwrap_or_default();

		// Update the specific contract based on name
		let address_str = format!("{:?}", address);
		match contract_name {
			"InputSettlerEscrow" => contract_set.input_settler = Some(address_str),
			"InputSettlerCompact" => contract_set.input_settler_compact = Some(address_str),
			"OutputSettler" => contract_set.output_settler = Some(address_str),
			"Permit2" => contract_set.permit2 = Some(address_str),
			"TheCompact" => contract_set.compact = Some(address_str),
			"AlwaysOKAllocator" => contract_set.allocator = Some(address_str),
			"InputOracle" => contract_set.input_oracle = Some(address_str),
			"OutputOracle" => contract_set.output_oracle = Some(address_str),
			name if name.starts_with("MockERC20") || name.contains("Token") => {
				// TODO: For tokens, we'll use the contract name as the key for now
				// The caller should use set_token_contract() to set the proper symbol
				contract_set.tokens.insert(
					name.to_string(),
					SessionTokenInfo {
						address: address_str,
						decimals: DEFAULT_TOKEN_DECIMALS,
					},
				);
			},
			_ => {
				return Err(Error::InvalidConfig(format!(
					"Unknown contract name: {}",
					contract_name
				)));
			},
		}

		session.deployed_contracts.insert(chain_key, contract_set);
		drop(session);
		self.save()
	}

	/// Store token contract address with automatic symbol retrieval
	///
	/// Queries the token contract to retrieve its symbol and stores the
	/// token information in the session with the proper symbol identifier
	///
	/// # Arguments
	/// * `chain` - Target blockchain network identifier
	/// * `address` - Token contract address
	/// * `ctx` - Application context for contract interaction
	///
	/// # Returns
	/// Success if token symbol is retrieved and stored successfully
	///
	/// # Errors
	/// Returns Error if symbol retrieval fails, lock acquisition fails, or save fails
	pub async fn set_token_contract(
		&self,
		chain: ChainId,
		address: Address,
		ctx: &crate::Context,
	) -> Result<()> {
		// Get the symbol from the contract
		let symbol = self.get_token_symbol(chain, address, ctx).await?;

		let mut session = self
			.session
			.write()
			.map_err(|e| Error::StorageError(format!("Failed to acquire write lock: {}", e)))?;

		// Get or create contract set for this chain
		let chain_key = chain.id().to_string();
		let mut contract_set = session
			.deployed_contracts
			.get(&chain_key)
			.cloned()
			.unwrap_or_default();

		// Store with the actual symbol
		let address_str = format!("{:?}", address);
		contract_set.tokens.insert(symbol, {
			SessionTokenInfo {
				address: address_str,
				decimals: DEFAULT_TOKEN_DECIMALS,
			}
		});

		session.deployed_contracts.insert(chain_key, contract_set);
		drop(session);
		self.save()
	}

	/// Retrieve token symbol from contract using ERC20 symbol method
	///
	/// # Arguments
	/// * `chain` - Target blockchain network identifier
	/// * `address` - Token contract address to query
	/// * `ctx` - Application context for provider and contract access
	///
	/// # Returns
	/// Token symbol string from contract
	///
	/// # Errors
	/// Returns Error if provider access fails or symbol call fails
	async fn get_token_symbol(
		&self,
		chain: ChainId,
		address: Address,
		ctx: &crate::Context,
	) -> Result<String> {
		let provider = ctx.provider(chain).await?;

		// Clone the contracts to avoid holding lock across await
		let contracts = {
			let contracts_guard = ctx.contracts.read().unwrap();
			contracts_guard.clone()
		};

		// Use the contracts helper to get token symbol
		contracts.erc20_symbol(&provider, address).await
	}

	/// Check if session is configured for local development environment
	///
	/// # Returns
	/// True if environment is set to Local mode
	pub fn is_local(&self) -> bool {
		self.environment().is_local()
	}

	/// Reset session to fresh state while preserving configuration path and environment
	///
	/// Clears all stored data including contracts, tokens, JWT tokens, and placeholder
	/// mappings while maintaining the original configuration structure
	///
	/// # Returns
	/// Success if session is cleared and saved successfully
	///
	/// # Errors
	/// Returns Error if write lock acquisition fails or save operation fails
	pub fn clear(&self) -> Result<()> {
		let mut session = self
			.session
			.write()
			.map_err(|e| Error::StorageError(format!("Failed to acquire write lock: {}", e)))?;
		let config_path = session.config_path.clone();
		let config_sections = build_config_sections_mapping(&config_path);
		let placeholder_map = HashMap::new(); // Clear the placeholder map
		*session = Session::new(
			config_path,
			config_sections,
			placeholder_map,
			session.environment,
		);
		drop(session);
		self.save()
	}

	/// Execute atomic session update using provided closure function
	///
	/// Provides safe access to session data for complex updates with automatic
	/// lock management and persistence after successful closure execution
	///
	/// # Arguments
	/// * `f` - Closure function for session modification
	///
	/// # Returns
	/// Result from closure execution if successful
	///
	/// # Errors
	/// Returns Error if write lock acquisition fails, closure fails, or save fails
	pub fn update<F, R>(&self, f: F) -> Result<R>
	where
		F: FnOnce(&mut Session) -> Result<R>,
	{
		let mut session = self
			.session
			.write()
			.map_err(|e| Error::StorageError(format!("Failed to acquire write lock: {}", e)))?;
		let result = f(&mut session)?;
		drop(session);
		self.save()?;
		Ok(result)
	}
}
