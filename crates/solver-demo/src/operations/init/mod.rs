//! Configuration initialization operations and utilities
//!
//! This module provides operations for creating new solver configurations
//! and loading existing configurations into the application session.
//! Handles placeholder generation, environment setup, and configuration
//! file management for both local and production environments.

use crate::{
	constants::{anvil_accounts, env_vars, DEFAULT_TOKEN_DECIMALS, PERMIT2_ADDRESS},
	core::{config::Config, session::SessionStore, storage::Storage},
	types::{
		chain::ChainId,
		error::{Error, Result},
		session::{ContractAddresses, Environment},
	},
	Context,
};
use alloy_primitives::Address;
use solver_config::SettlementConfig;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::instrument;

// Import placeholder constants from the constants module
use crate::constants::placeholders::*;

/// Service for configuration initialization and management operations
///
/// Provides methods for creating new configurations with placeholder values
/// and loading existing configurations into the application session.
/// Supports both contextual and context-free operations.
pub struct InitOps {
	_ctx: Option<Arc<Context>>,
}

impl InitOps {
	/// Create an initialization service with application context
	///
	/// # Arguments
	/// * `ctx` - Application context for accessing configuration and session state
	///
	/// # Returns
	/// InitOps instance configured with context for load operations
	pub fn with_context(ctx: Arc<Context>) -> Self {
		Self { _ctx: Some(ctx) }
	}

	/// Create an initialization service without application context
	///
	/// # Returns
	/// InitOps instance for configuration creation operations that do not require existing context
	pub fn without_context() -> Self {
		Self { _ctx: None }
	}

	/// Create a new configuration file with placeholder contract addresses
	///
	/// # Arguments
	/// * `path` - Path where the configuration file will be created
	/// * `chains` - List of chain IDs to include in the configuration
	/// * `force` - Whether to overwrite existing configuration files
	///
	/// # Returns
	/// Success if configuration is created successfully
	///
	/// # Errors
	/// Returns Error if file creation fails or configuration already exists without force flag
	#[instrument(skip(self))]
	pub async fn create(&self, path: PathBuf, chains: Vec<u64>, force: bool) -> Result<()> {
		// Delegate to the existing generate_new_config function
		generate_new_config(&path, chains, force).await
	}

	/// Load an existing configuration file and initialize session state
	///
	/// # Arguments
	/// * `path` - Path to the configuration file to load
	/// * `is_local` - Whether to initialize for local development environment
	///
	/// # Returns
	/// Success if configuration is loaded and session is initialized
	///
	/// # Errors
	/// Returns Error if configuration file cannot be loaded or session initialization fails
	#[instrument(skip(self))]
	pub async fn load(&self, path: PathBuf, is_local: bool) -> Result<()> {
		// Delegate to the existing load_config function
		load_config(&path, is_local).await
	}
}

/// Generate placeholder contract addresses for configuration templates
///
/// # Arguments
/// * `chain_ids` - List of chain IDs to generate placeholders for
///
/// # Returns
/// HashMap mapping placeholder keys to generated placeholder addresses
fn generate_placeholder_map(chain_ids: &[u64]) -> HashMap<String, String> {
	let mut map = HashMap::new();
	let mut counter = PLACEHOLDER_START_COUNTER;

	// Generate placeholders for each chain
	for chain_id in chain_ids {
		// Input settler
		map.insert(
			format!("{PLACEHOLDER_INPUT_SETTLER_PREFIX}{chain_id}"),
			format!("0x{counter:040x}"),
		);
		counter += 1;

		// Output settler
		map.insert(
			format!("{PLACEHOLDER_OUTPUT_SETTLER_PREFIX}{chain_id}"),
			format!("0x{counter:040x}"),
		);
		counter += 1;

		// Compact
		map.insert(
			format!("{PLACEHOLDER_COMPACT_PREFIX}{chain_id}"),
			format!("0x{counter:040x}"),
		);
		counter += 1;

		// InputSettlerCompact
		map.insert(
			format!("{PLACEHOLDER_INPUT_SETTLER_COMPACT_PREFIX}{chain_id}"),
			format!("0x{counter:040x}"),
		);
		counter += 1;

		// Allocator
		map.insert(
			format!("{PLACEHOLDER_ALLOCATOR_PREFIX}{chain_id}"),
			format!("0x{counter:040x}"),
		);
		counter += 1;

		// Tokens
		map.insert(
			format!("{PLACEHOLDER_TOKEN_A_PREFIX}{chain_id}"),
			format!("0x{counter:040x}"),
		);
		counter += 1;

		map.insert(
			format!("{PLACEHOLDER_TOKEN_B_PREFIX}{chain_id}"),
			format!("0x{counter:040x}"),
		);
		counter += 1;

		// Oracles
		map.insert(
			format!("{ORACLE_PLACEHOLDER_INPUT_PREFIX}{chain_id}"),
			format!("0x{counter:040x}"),
		);
		counter += 1;

		map.insert(
			format!("{ORACLE_PLACEHOLDER_OUTPUT_PREFIX}{chain_id}"),
			format!("0x{counter:040x}"),
		);
		counter += 1;
	}

	map
}

/// Generate a new configuration file with placeholder addresses
pub async fn generate_new_config(path: &Path, chains: Vec<u64>, force: bool) -> Result<()> {
	// Check if config already exists
	if path.exists() && !force {
		return Err(Error::ConfigExists(path.to_path_buf()));
	}

	// Ensure parent directory exists
	if let Some(parent) = path.parent() {
		std::fs::create_dir_all(parent)?;
	}

	// Get config name from file stem
	let config_name = path.file_stem().and_then(|s| s.to_str()).unwrap_or("demo");

	// Generate placeholder map
	let placeholders = generate_placeholder_map(&chains);

	// Generate configuration content using same format as original
	let config_content = generate_demo_config(&chains, config_name, &placeholders)?;

	// Write main config file
	std::fs::write(path, config_content)?;

	// Create includes directory
	if let Some(parent) = path.parent() {
		let include_dir = parent.join(config_name);
		std::fs::create_dir_all(&include_dir)?;

		// Write networks.toml
		let networks_path = include_dir.join("networks.toml");
		std::fs::write(
			networks_path,
			generate_networks_config(&chains, &placeholders)?,
		)?;

		// Write gas.toml
		let gas_path = include_dir.join("gas.toml");
		std::fs::write(gas_path, generate_gas_config()?)?;

		// Write api.toml
		let api_path = include_dir.join("api.toml");
		std::fs::write(api_path, generate_api_config()?)?;
	}

	Ok(())
}

/// Load an existing configuration and initialize session
pub async fn load_config(path: &Path, is_local: bool) -> Result<()> {
	// Load configuration
	let config = Config::load(path).await?;

	// Create storage directory
	let storage = Storage::new(&config.data_dir())?;

	// Initialize session
	let environment = if is_local {
		Environment::Local
	} else {
		Environment::Production
	};

	let session = SessionStore::new(storage.clone(), path.to_path_buf(), environment)?;

	// Set configured chains
	let chains: Vec<ChainId> = config.chains();
	session.set_chains(chains.clone())?;

	// Generate and store placeholder map for this configuration
	let chain_ids: Vec<u64> = chains.iter().map(|c| c.id()).collect();
	let placeholder_map = generate_placeholder_map(&chain_ids);
	session.set_placeholder_map(placeholder_map)?;

	// Load contract addresses from configuration for each chain
	use crate::core::logging;
	logging::verbose_operation("Processing chains", &format!("{} chains", chains.len()));

	for chain in &chains {
		logging::verbose_operation("Processing chain", &chain.to_string());
		if let Some(network) = config.network(*chain) {
			logging::verbose_success("Found network configuration", &chain.to_string());
			let mut tokens = HashMap::new();

			// Extract token addresses
			for token in &network.tokens {
				let addr: Address =
					token.address.to_string().parse().map_err(|e| {
						Error::InvalidConfig(format!("Invalid token address: {e}"))
					})?;
				tokens.insert(token.symbol.clone(), (addr, token.decimals));
			}
			logging::verbose_tech(
				"Processed tokens",
				&format!("{} tokens for chain {}", tokens.len(), chain),
			);

			// Helper function to convert solver_types::Address to alloy_primitives::Address
			let parse_address = |addr: &solver_types::Address| -> Result<Address> {
				addr.to_string()
					.parse()
					.map_err(|e| Error::InvalidConfig(format!("Invalid address: {e}")))
			};

			// Canonical permit2 address (same on all networks)
			let permit2_addr: Address = PERMIT2_ADDRESS
				.parse()
				.map_err(|e| Error::InvalidConfig(format!("Invalid permit2 address: {e}")))?;

			// Extract oracle addresses from settlement config
			let input_oracle_addr =
				get_input_oracle_for_chain(&config.solver.settlement, chain.id())
					.and_then(|addr_str| addr_str.parse::<Address>().ok());
			let output_oracle_addr =
				get_output_oracle_for_chain(&config.solver.settlement, chain.id())
					.and_then(|addr_str| addr_str.parse::<Address>().ok());

			// Create ContractAddresses struct
			let contract_addresses = ContractAddresses {
				chain: *chain,
				permit2: Some(permit2_addr),
				input_settler: Some(parse_address(&network.input_settler_address)?),
				input_settler_compact: network
					.input_settler_compact_address
					.as_ref()
					.map(parse_address)
					.transpose()?,
				output_settler: Some(parse_address(&network.output_settler_address)?),
				the_compact: network
					.the_compact_address
					.as_ref()
					.map(parse_address)
					.transpose()?,
				allocator: network
					.allocator_address
					.as_ref()
					.map(parse_address)
					.transpose()?,
				input_oracle: input_oracle_addr,
				output_oracle: output_oracle_addr,
				tokens,
			};

			// Set contract addresses in session
			logging::verbose_operation("Setting contract addresses", &chain.to_string());
			session.set_contract_addresses(*chain, contract_addresses)?;
			logging::verbose_success("Contract addresses set", &chain.to_string());
		}
	}

	// Save initial session
	session.save()?;

	// Verbose details about what was loaded
	logging::verbose_tech("Environment", if is_local { "Local" } else { "Production" });
	logging::verbose_tech("Chains", &format!("{chains:?}"));
	logging::verbose_tech("Data directory", &config.data_dir().display().to_string());

	Ok(())
}

/// Gets input oracle address for the specified chain
fn get_input_oracle_for_chain(
	settlement_config: &SettlementConfig,
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
												if let Some(oracle_str) = first_oracle.as_str() {
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

/// Gets output oracle address for the specified chain
fn get_output_oracle_for_chain(
	settlement_config: &SettlementConfig,
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
							if let Some(output_value) = oracles_table.get("output") {
								if let Some(output_table) = output_value.as_table() {
									if let Some(oracles_array) =
										output_table.get(&chain_id.to_string())
									{
										if let Some(array) = oracles_array.as_array() {
											if let Some(first_oracle) = array.first() {
												if let Some(oracle_str) = first_oracle.as_str() {
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

/// Generate the main configuration file
fn generate_demo_config(
	chain_ids: &[u64],
	config_name: &str,
	placeholders: &HashMap<String, String>,
) -> Result<String> {
	let mut config = String::new();

	// Header
	config.push_str("# OIF Solver Configuration - Generated File\n");
	config.push_str("# Generated with placeholder values for easy regex replacement\n\n");

	// Include files
	config.push_str(&format!(
		"include = [\"{config_name}/networks.toml\", \"{config_name}/api.toml\", \"{config_name}/gas.toml\"]\n\n"
	));

	// Solver configuration
	config.push_str("[solver]\n");
	config.push_str("id = \"oif-solver-demo\"\n");
	config.push_str("min_profitability_pct = 1.0\n");
	config.push_str("monitoring_timeout_seconds = 28800\n\n");

	// Storage configuration
	add_storage_config(&mut config);

	// Account configuration
	add_account_config(&mut config);

	// Delivery configuration
	add_delivery_config(&mut config, chain_ids);

	// Discovery configuration
	add_discovery_config(&mut config, chain_ids);

	// Order configuration
	add_order_config(&mut config);

	// Pricing configuration
	add_pricing_config(&mut config);

	// Settlement configuration
	add_settlement_config(&mut config, chain_ids, placeholders)?;

	Ok(config)
}

fn add_storage_config(config: &mut String) {
	config.push_str(
		"# ============================================================================\n",
	);
	config.push_str("# STORAGE\n");
	config.push_str(
		"# ============================================================================\n",
	);
	config.push_str("[storage]\n");
	config.push_str("primary = \"file\"\n");
	config.push_str("cleanup_interval_seconds = 60\n\n");

	config.push_str("[storage.implementations.memory]\n");
	config.push_str("# Memory storage has no configuration\n\n");

	config.push_str("[storage.implementations.file]\n");
	config.push_str("storage_path = \"./data/storage\"\n");
	config.push_str("ttl_orders = 300                # 5 minutes\n");
	config.push_str("ttl_intents = 120               # 2 minutes\n");
	config.push_str("ttl_order_by_tx_hash = 300      # 5 minutes\n\n");
}

fn add_account_config(config: &mut String) {
	// Load environment variables
	let _ = dotenvy::dotenv();

	config.push_str(
		"# ============================================================================\n",
	);
	config.push_str("# ACCOUNT\n");
	config.push_str(
		"# ============================================================================\n",
	);
	config.push_str("[account]\n");
	config.push_str("primary = \"local\"\n\n");

	config.push_str("[account.implementations.local]\n");

	// Use SOLVER_PRIVATE_KEY from env or default Anvil key
	let solver_key = std::env::var(env_vars::SOLVER_PRIVATE_KEY)
		.unwrap_or_else(|_| anvil_accounts::SOLVER_PRIVATE_KEY.to_string());
	config.push_str(&format!("private_key = \"{solver_key}\"\n\n"));
}

fn add_delivery_config(config: &mut String, chain_ids: &[u64]) {
	config.push_str(
		"# ============================================================================\n",
	);
	config.push_str("# DELIVERY\n");
	config.push_str(
		"# ============================================================================\n",
	);
	config.push_str("[delivery]\n");
	config.push_str("min_confirmations = 1\n\n");

	config.push_str("[delivery.implementations.evm_alloy]\n");
	config.push_str(&format!("network_ids = {chain_ids:?}\n\n"));
}

fn add_discovery_config(config: &mut String, chain_ids: &[u64]) {
	config.push_str(
		"# ============================================================================\n",
	);
	config.push_str("# DISCOVERY\n");
	config.push_str(
		"# ============================================================================\n",
	);
	config.push_str("[discovery]\n\n");

	config.push_str("[discovery.implementations.onchain_eip7683]\n");
	config.push_str(&format!("network_ids = {chain_ids:?}\n"));
	config.push_str(
		"polling_interval_secs = 0    # Use WebSocket subscriptions instead of polling\n\n",
	);

	config.push_str("[discovery.implementations.offchain_eip7683]\n");
	config.push_str("api_host = \"127.0.0.1\"\n");
	config.push_str("api_port = 8081\n");
	config.push_str(&format!(
		"network_ids = [{}]\n\n",
		chain_ids.first().unwrap_or(&31337)
	));
}

fn add_order_config(config: &mut String) {
	config.push_str(
		"# ============================================================================\n",
	);
	config.push_str("# ORDER\n");
	config.push_str(
		"# ============================================================================\n",
	);
	config.push_str("[order]\n\n");

	config.push_str("[order.implementations.eip7683]\n\n");

	config.push_str("[order.strategy]\n");
	config.push_str("primary = \"simple\"\n\n");

	config.push_str("[order.strategy.implementations.simple]\n");
	config.push_str("max_gas_price_gwei = 100\n\n");
}

fn add_pricing_config(config: &mut String) {
	config.push_str(
		"# ============================================================================\n",
	);
	config.push_str("# PRICING\n");
	config.push_str(
		"# ============================================================================\n",
	);
	config.push_str("[pricing]\n");
	config.push_str("primary = \"mock\"\n\n");

	config.push_str("[pricing.implementations.mock]\n");
	config.push_str("# Uses default ETH/USD price of 4615.16\n\n");

	config.push_str("[pricing.implementations.coingecko]\n");
	config.push_str("# Free tier configuration (no API key required)\n");
	config.push_str("# api_key = \"CG-YOUR-API-KEY-HERE\"\n");
	config.push_str("cache_duration_seconds = 60\n");
	config.push_str("rate_limit_delay_ms = 1200\n\n");

	config.push_str("# Custom prices for demo/test tokens (in USD)\n");
	config.push_str("[pricing.implementations.coingecko.custom_prices]\n");
	config.push_str("TOKA = \"200.00\"\n");
	config.push_str("TOKB = \"195.00\"\n\n");
}

fn add_settlement_config(
	config: &mut String,
	chain_ids: &[u64],
	placeholders: &HashMap<String, String>,
) -> Result<()> {
	config.push_str(
		"# ============================================================================\n",
	);
	config.push_str("# SETTLEMENT\n");
	config.push_str(
		"# ============================================================================\n",
	);
	config.push_str("[settlement]\n");
	config.push_str("settlement_poll_interval_seconds = 3\n\n");

	config.push_str("[settlement.implementations.direct]\n");
	config.push_str("order = \"eip7683\"\n");
	config.push_str(&format!("network_ids = {chain_ids:?}\n"));
	config.push_str("dispute_period_seconds = 1\n");
	config.push_str("# Oracle selection strategy when multiple oracles are available (First, RoundRobin, Random)\n");
	config.push_str("oracle_selection_strategy = \"First\"\n\n");

	// Oracle configuration
	config.push_str("# Oracle configuration with multiple oracle support\n");
	config.push_str("[settlement.implementations.direct.oracles]\n");

	// Input oracles
	config.push_str("# Input oracles (on origin chains)\n");
	config.push_str("input = { ");
	for (i, chain_id) in chain_ids.iter().enumerate() {
		if i > 0 {
			config.push_str(", ");
		}
		let oracle_addr = placeholders
			.get(&format!("ORACLE_PLACEHOLDER_INPUT_{chain_id}"))
			.ok_or_else(|| {
				Error::InvalidConfig(format!("Missing ORACLE_PLACEHOLDER_INPUT_{chain_id}"))
			})?;
		config.push_str(&format!("{chain_id} = [\n    \"{oracle_addr}\",\n]"));
	}
	config.push_str(" }\n");

	// Output oracles
	config.push_str("# Output oracles (on destination chains)\n");
	config.push_str("output = { ");
	for (i, chain_id) in chain_ids.iter().enumerate() {
		if i > 0 {
			config.push_str(", ");
		}
		let oracle_addr = placeholders
			.get(&format!("ORACLE_PLACEHOLDER_OUTPUT_{chain_id}"))
			.ok_or_else(|| {
				Error::InvalidConfig(format!("Missing ORACLE_PLACEHOLDER_OUTPUT_{chain_id}"))
			})?;
		config.push_str(&format!("{chain_id} = [\n    \"{oracle_addr}\",\n]"));
	}
	config.push_str(" }\n\n");

	// Valid routes
	config.push_str("# Valid routes: from origin chain -> to destination chains\n");
	config.push_str("[settlement.implementations.direct.routes]\n");

	for from_chain in chain_ids {
		let to_chains: Vec<u64> = chain_ids
			.iter()
			.filter(|&c| c != from_chain)
			.cloned()
			.collect();
		if !to_chains.is_empty() {
			config.push_str(&format!("{from_chain} = {to_chains:?}\n"));
		}
	}

	Ok(())
}

/// Generate networks.toml configuration
fn generate_networks_config(
	chain_ids: &[u64],
	placeholders: &HashMap<String, String>,
) -> Result<String> {
	let mut config = String::new();

	// Header
	config.push_str("# Network Configuration - Generated with Placeholders\n");
	config.push_str("# Defines all supported blockchain networks and their tokens\n\n");

	// Generate configuration for each chain
	for (idx, chain_id) in chain_ids.iter().enumerate() {
		config.push_str(&format!("[networks.{chain_id}]\n"));

		// Contract addresses
		let input_settler = placeholders
			.get(&format!("PLACEHOLDER_INPUT_SETTLER_{chain_id}"))
			.ok_or_else(|| {
				Error::InvalidConfig(format!("Missing PLACEHOLDER_INPUT_SETTLER_{chain_id}"))
			})?;
		config.push_str(&format!("input_settler_address = \"{input_settler}\"\n"));

		// InputSettlerCompact address
		let input_settler_compact = placeholders
			.get(&format!("PLACEHOLDER_INPUT_SETTLER_COMPACT_{chain_id}"))
			.ok_or_else(|| {
				Error::InvalidConfig(format!(
					"Missing PLACEHOLDER_INPUT_SETTLER_COMPACT_{chain_id}"
				))
			})?;
		config.push_str(&format!(
			"input_settler_compact_address = \"{input_settler_compact}\"\n"
		));

		// TheCompact contract address
		let compact = placeholders
			.get(&format!("PLACEHOLDER_COMPACT_{chain_id}"))
			.ok_or_else(|| {
				Error::InvalidConfig(format!("Missing PLACEHOLDER_COMPACT_{chain_id}"))
			})?;
		config.push_str(&format!("the_compact_address = \"{compact}\"\n"));

		let allocator = placeholders
			.get(&format!("PLACEHOLDER_ALLOCATOR_{chain_id}"))
			.ok_or_else(|| {
				Error::InvalidConfig(format!("Missing PLACEHOLDER_ALLOCATOR_{chain_id}"))
			})?;
		config.push_str(&format!("allocator_address = \"{allocator}\"\n"));

		let output_settler = placeholders
			.get(&format!("PLACEHOLDER_OUTPUT_SETTLER_{chain_id}"))
			.ok_or_else(|| {
				Error::InvalidConfig(format!("Missing PLACEHOLDER_OUTPUT_SETTLER_{chain_id}"))
			})?;
		config.push_str(&format!(
			"output_settler_address = \"{output_settler}\"\n\n"
		));

		// RPC endpoints
		config.push_str("# RPC endpoints with both HTTP and WebSocket URLs for each network\n");
		config.push_str(&format!("[[networks.{chain_id}.rpc_urls]]\n"));

		let port = 8545 + idx;
		config.push_str(&format!("http = \"http://localhost:{port}\"\n"));
		config.push_str(&format!("ws = \"ws://localhost:{port}\"\n\n"));

		// Token configurations
		config.push_str(&format!("[[networks.{chain_id}.tokens]]\n"));
		let token_a = placeholders
			.get(&format!("PLACEHOLDER_TOKEN_A_{chain_id}"))
			.ok_or_else(|| {
				Error::InvalidConfig(format!("Missing PLACEHOLDER_TOKEN_A_{chain_id}"))
			})?;
		config.push_str(&format!("address = \"{token_a}\"\n"));
		config.push_str("symbol = \"TOKA\"\n");
		config.push_str(&format!("decimals = {DEFAULT_TOKEN_DECIMALS}\n\n"));

		config.push_str(&format!("[[networks.{chain_id}.tokens]]\n"));
		let token_b = placeholders
			.get(&format!("PLACEHOLDER_TOKEN_B_{chain_id}"))
			.ok_or_else(|| {
				Error::InvalidConfig(format!("Missing PLACEHOLDER_TOKEN_B_{chain_id}"))
			})?;
		config.push_str(&format!("address = \"{token_b}\"\n"));
		config.push_str("symbol = \"TOKB\"\n");
		config.push_str(&format!("decimals = {DEFAULT_TOKEN_DECIMALS}\n\n"));
	}

	Ok(config)
}

/// Generate gas.toml configuration
fn generate_gas_config() -> Result<String> {
	let mut config = String::new();

	config.push_str("[gas]\n\n");

	config.push_str("[gas.flows.resource_lock]\n");
	config.push_str("# Gas units captured by scripts/e2e/estimate_gas.sh on local anvil\n");
	config.push_str("open = 0\n");
	config.push_str("fill = 77298\n");
	config.push_str("claim = 122793\n\n");

	config.push_str("[gas.flows.permit2_escrow]\n");
	config.push_str("# Gas units captured by scripts/e2e/estimate_gas.sh on local anvil\n");
	config.push_str("open = 146306\n");
	config.push_str("fill = 77298\n");
	config.push_str("claim = 60084\n\n");

	config.push_str("[gas.flows.eip3009_escrow]\n");
	config.push_str("# Gas units captured by scripts/e2e/estimate_gas.sh on local anvil\n");
	config.push_str("open = 130254\n");
	config.push_str("fill = 77298\n");
	config.push_str("claim = 60084\n");

	Ok(config)
}

/// Generate api.toml configuration
fn generate_api_config() -> Result<String> {
	let mut config = String::new();

	config.push_str("# API Server Configuration\n");
	config.push_str("# Configures the HTTP API for receiving off-chain intents\n\n");

	config.push_str("[api]\n");
	config.push_str("enabled = true\n");
	config.push_str("host = \"127.0.0.1\"\n");
	config.push_str("port = 3000\n");
	config.push_str("timeout_seconds = 30\n");
	config.push_str("max_request_size = 1048576  # 1MB\n\n");

	config.push_str("[api.implementations]\n");
	config.push_str("discovery = \"offchain_eip7683\"\n\n");

	config.push_str("# JWT Authentication Configuration\n");
	config.push_str("[api.auth]\n");
	config.push_str("enabled = true\n");
	config.push_str("jwt_secret = \"${JWT_SECRET:-MySuperDuperSecureSecret123!}\"\n");
	config.push_str("access_token_expiry_hours = 1\n");
	config.push_str("refresh_token_expiry_hours = 720  # 30 days\n");
	config.push_str("issuer = \"oif-solver-demo\"\n\n");

	config.push_str("# Quote Configuration\n");
	config.push_str("[api.quote]\n");
	config.push_str("# Quote validity duration in seconds\n");
	config.push_str("# Default is 20 seconds. Customize as needed:\n");
	config.push_str("validity_seconds = 60  # 1 minute validity\n");

	Ok(config)
}
