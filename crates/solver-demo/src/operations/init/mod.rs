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

	// Write single JSON config file
	std::fs::write(path, config_content)?;

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
				let addr: Address = token
					.address
					.to_string()
					.parse()
					.map_err(|e| Error::InvalidConfig(format!("Invalid token address: {e}")))?;
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
					.any(|id| id.as_i64().is_some_and(|i| i as u64 == chain_id));

				if has_chain {
					if let Some(oracles_value) = impl_config.get("oracles") {
						if let Some(oracles_table) = oracles_value.as_object() {
							if let Some(input_value) = oracles_table.get("input") {
								if let Some(input_table) = input_value.as_object() {
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
					.any(|id| id.as_i64().is_some_and(|i| i as u64 == chain_id));

				if has_chain {
					if let Some(oracles_value) = impl_config.get("oracles") {
						if let Some(oracles_table) = oracles_value.as_object() {
							if let Some(output_value) = oracles_table.get("output") {
								if let Some(output_table) = output_value.as_object() {
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
	_config_name: &str,
	placeholders: &HashMap<String, String>,
) -> Result<String> {
	let solver_key = std::env::var(env_vars::SOLVER_PRIVATE_KEY)
		.unwrap_or_else(|_| anvil_accounts::SOLVER_PRIVATE_KEY.to_string());

	let mut networks = serde_json::Map::new();
	for (idx, chain_id) in chain_ids.iter().enumerate() {
		let input_settler = placeholders
			.get(&format!("PLACEHOLDER_INPUT_SETTLER_{chain_id}"))
			.ok_or_else(|| {
				Error::InvalidConfig(format!("Missing PLACEHOLDER_INPUT_SETTLER_{chain_id}"))
			})?;
		let output_settler = placeholders
			.get(&format!("PLACEHOLDER_OUTPUT_SETTLER_{chain_id}"))
			.ok_or_else(|| {
				Error::InvalidConfig(format!("Missing PLACEHOLDER_OUTPUT_SETTLER_{chain_id}"))
			})?;
		let input_settler_compact = placeholders
			.get(&format!("PLACEHOLDER_INPUT_SETTLER_COMPACT_{chain_id}"))
			.ok_or_else(|| {
				Error::InvalidConfig(format!(
					"Missing PLACEHOLDER_INPUT_SETTLER_COMPACT_{chain_id}"
				))
			})?;
		let compact = placeholders
			.get(&format!("PLACEHOLDER_COMPACT_{chain_id}"))
			.ok_or_else(|| {
				Error::InvalidConfig(format!("Missing PLACEHOLDER_COMPACT_{chain_id}"))
			})?;
		let allocator = placeholders
			.get(&format!("PLACEHOLDER_ALLOCATOR_{chain_id}"))
			.ok_or_else(|| {
				Error::InvalidConfig(format!("Missing PLACEHOLDER_ALLOCATOR_{chain_id}"))
			})?;
		let token_a = placeholders
			.get(&format!("PLACEHOLDER_TOKEN_A_{chain_id}"))
			.ok_or_else(|| {
				Error::InvalidConfig(format!("Missing PLACEHOLDER_TOKEN_A_{chain_id}"))
			})?;
		let token_b = placeholders
			.get(&format!("PLACEHOLDER_TOKEN_B_{chain_id}"))
			.ok_or_else(|| {
				Error::InvalidConfig(format!("Missing PLACEHOLDER_TOKEN_B_{chain_id}"))
			})?;

		let port = 8545 + idx;
		networks.insert(
			chain_id.to_string(),
			serde_json::json!({
				"input_settler_address": input_settler,
				"output_settler_address": output_settler,
				"input_settler_compact_address": input_settler_compact,
				"the_compact_address": compact,
				"allocator_address": allocator,
				"rpc_urls": [{
					"http": format!("http://localhost:{port}"),
					"ws": format!("ws://localhost:{port}")
				}],
				"tokens": [
					{
						"address": token_a,
						"symbol": "TOKA",
						"decimals": DEFAULT_TOKEN_DECIMALS
					},
					{
						"address": token_b,
						"symbol": "TOKB",
						"decimals": DEFAULT_TOKEN_DECIMALS
					}
				]
			}),
		);
	}

	let routes = chain_ids
		.iter()
		.map(|from| {
			let to: Vec<u64> = chain_ids.iter().copied().filter(|c| c != from).collect();
			(from.to_string(), serde_json::json!(to))
		})
		.collect::<serde_json::Map<String, serde_json::Value>>();

	let input_oracles = chain_ids
		.iter()
		.map(|chain_id| {
			let addr = placeholders
				.get(&format!("ORACLE_PLACEHOLDER_INPUT_{chain_id}"))
				.cloned()
				.unwrap_or_else(|| "0x0000000000000000000000000000000000000000".to_string());
			(chain_id.to_string(), serde_json::json!([addr]))
		})
		.collect::<serde_json::Map<String, serde_json::Value>>();

	let output_oracles = chain_ids
		.iter()
		.map(|chain_id| {
			let addr = placeholders
				.get(&format!("ORACLE_PLACEHOLDER_OUTPUT_{chain_id}"))
				.cloned()
				.unwrap_or_else(|| "0x0000000000000000000000000000000000000000".to_string());
			(chain_id.to_string(), serde_json::json!([addr]))
		})
		.collect::<serde_json::Map<String, serde_json::Value>>();

	let first_chain = *chain_ids.first().unwrap_or(&31337);
	let config = serde_json::json!({
		"solver": {
			"id": "oif-solver-demo",
			"min_profitability_pct": "1.0",
			"monitoring_timeout_seconds": 28800
		},
		"networks": serde_json::Value::Object(networks),
		"storage": {
			"primary": "file",
			"cleanup_interval_seconds": 60,
			"implementations": {
				"memory": {},
				"file": {
					"storage_path": "./data/storage",
					"ttl_orders": 300,
					"ttl_intents": 120,
					"ttl_order_by_tx_hash": 300
				}
			}
		},
		"account": {
			"primary": "local",
			"implementations": {
				"local": { "private_key": solver_key }
			}
		},
		"delivery": {
			"min_confirmations": 1,
			"implementations": {
				"evm_alloy": { "network_ids": chain_ids }
			}
		},
		"discovery": {
			"implementations": {
				"onchain_eip7683": {
					"network_ids": chain_ids,
					"polling_interval_secs": 0
				},
				"offchain_eip7683": {
					"api_host": "127.0.0.1",
					"api_port": 8081,
					"network_ids": [first_chain]
				}
			}
		},
		"order": {
			"implementations": {
				"eip7683": {}
			},
			"strategy": {
				"primary": "simple",
				"implementations": {
					"simple": {
						"max_gas_price_gwei": 100
					}
				}
			}
		},
		"pricing": {
			"primary": "mock",
			"implementations": {
				"mock": {},
				"coingecko": {
					"cache_duration_seconds": 60,
					"rate_limit_delay_ms": 1200,
					"custom_prices": {
						"TOKA": "200.00",
						"TOKB": "195.00"
					}
				}
			}
		},
		"settlement": {
			"settlement_poll_interval_seconds": 3,
			"implementations": {
				"direct": {
					"order": "eip7683",
					"network_ids": chain_ids,
					"dispute_period_seconds": 1,
					"oracle_selection_strategy": "First",
					"oracles": {
						"input": serde_json::Value::Object(input_oracles),
						"output": serde_json::Value::Object(output_oracles)
					},
					"routes": serde_json::Value::Object(routes)
				}
			}
		},
		"api": {
			"enabled": true,
			"host": "127.0.0.1",
			"port": 3000,
			"timeout_seconds": 30,
			"max_request_size": 1048576,
			"implementations": {
				"discovery": "offchain_eip7683"
			},
			"auth": {
				"enabled": true,
				"jwt_secret": "${JWT_SECRET:-MySuperDuperSecureSecret123!}",
				"access_token_expiry_hours": 1,
				"refresh_token_expiry_hours": 720,
				"issuer": "oif-solver-demo"
			},
			"quote": {
				"validity_seconds": 60
			}
		},
		"gas": {
			"flows": {
				"resource_lock": { "open": 0, "fill": 77298, "claim": 122793 },
				"permit2_escrow": { "open": 146306, "fill": 77298, "claim": 60084 },
				"eip3009_escrow": { "open": 130254, "fill": 77298, "claim": 60084 }
			}
		}
	});

	serde_json::to_string_pretty(&config).map_err(Error::from)
}
