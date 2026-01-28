//! Configuration merge logic for combining seed overrides with seed data.
//!
//! This module provides the logic to merge user-provided `SeedOverrides`
//! with hardcoded `SeedConfig` to produce a complete `solver_config::Config`.
//!
//! # Architecture
//!
//! The merge process:
//! 1. Validates that all requested chain IDs exist in the seed
//! 2. Builds NetworksConfig from user tokens + seed contract addresses
//! 3. Builds Hyperlane settlement config dynamically based on selected chains
//! 4. Sets all standard implementations (storage, delivery, discovery, etc.)
//! 5. Auto-generates a unique solver ID (or uses the provided one)
//!
//! # Example
//!
//! ```rust,ignore
//! use solver_service::config_merge::merge_config;
//! use solver_service::seeds::TESTNET_SEED;
//! use solver_types::SeedOverrides;
//!
//! let overrides: SeedOverrides = serde_json::from_str(json)?;
//! let config = merge_config(overrides, &TESTNET_SEED)?;
//! ```

use crate::seeds::types::{NetworkSeed, SeedConfig, SeedDefaults};
use solver_config::{
	AccountConfig, ApiConfig, ApiImplementations, Config, DeliveryConfig, DiscoveryConfig,
	GasConfig, GasFlowUnits, OrderConfig, PricingConfig, SettlementConfig, SolverConfig,
	StorageConfig, StrategyConfig,
};
use solver_types::{
	networks::RpcEndpoint, NetworkConfig, NetworkOverride, NetworksConfig, SeedOverrides,
	TokenConfig,
};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

/// Errors that can occur during configuration merge.
#[derive(Debug, Error)]
pub enum MergeError {
	/// A requested chain ID is not supported by the seed.
	#[error("Unknown chain ID: {0}. Supported chains: {1:?}")]
	UnknownChainId(u64, Vec<u64>),

	/// No tokens were specified for a network.
	#[error("No tokens specified for chain {0}")]
	NoTokens(u64),

	/// Duplicate chain ID in network configuration.
	#[error("Duplicate chain ID: {0}")]
	DuplicateChainId(u64),

	/// At least 2 networks are required.
	#[error("At least 2 networks are required for cross-chain operations")]
	InsufficientNetworks,

	/// Validation error after merge.
	#[error("Configuration validation failed: {0}")]
	Validation(String),
}

/// Merges seed overrides with a seed config to produce a complete Config.
///
/// # Arguments
///
/// * `overrides` - User-provided seed overrides with chain IDs and tokens
/// * `seed` - Hardcoded seed configuration with contract addresses and defaults
///
/// # Returns
///
/// A complete `Config` ready for use by the solver.
///
/// # Errors
///
/// Returns a `MergeError` if:
/// - A requested chain ID is not supported by the seed
/// - No tokens are specified for a network
/// - Fewer than 2 networks are requested
pub fn merge_config(overrides: SeedOverrides, seed: &SeedConfig) -> Result<Config, MergeError> {
	// Check for duplicate chain IDs first (before the 2-network check)
	// to prevent duplicates from collapsing in HashMap and bypassing validation
	let mut seen_chain_ids = std::collections::HashSet::new();
	for network in &overrides.networks {
		if !seen_chain_ids.insert(network.chain_id) {
			return Err(MergeError::DuplicateChainId(network.chain_id));
		}
	}

	// Validate we have at least 2 unique networks
	if seen_chain_ids.len() < 2 {
		return Err(MergeError::InsufficientNetworks);
	}

	// Validate all chain IDs exist in seed and have tokens
	let chain_ids: Vec<u64> = overrides.networks.iter().map(|n| n.chain_id).collect();
	for network in &overrides.networks {
		if !seed.supports_chain(network.chain_id) {
			return Err(MergeError::UnknownChainId(
				network.chain_id,
				seed.supported_chain_ids(),
			));
		}
		if network.tokens.is_empty() {
			return Err(MergeError::NoTokens(network.chain_id));
		}
	}

	// Use provided solver_id or generate a new one
	let solver_id = overrides
		.solver_id
		.clone()
		.unwrap_or_else(|| format!("solver-{}", Uuid::new_v4()));

	// Build networks config
	let networks = build_networks_config(&overrides.networks, seed)?;

	// Build the full config
	let config = Config {
		solver: build_solver_config(&solver_id, &seed.defaults),
		networks,
		storage: build_storage_config(&seed.defaults),
		delivery: build_delivery_config(&chain_ids, &seed.defaults),
		account: build_account_config(&seed.defaults),
		discovery: build_discovery_config(&chain_ids, &seed.defaults),
		order: build_order_config(&seed.defaults),
		settlement: build_settlement_config(&chain_ids, seed),
		pricing: Some(build_pricing_config(&seed.defaults)),
		api: Some(build_api_config(overrides.admin.as_ref())),
		gas: Some(build_gas_config(&seed.defaults)),
	};

	Ok(config)
}

/// Builds the NetworksConfig from seed overrides and seed data.
fn build_networks_config(
	overrides: &[NetworkOverride],
	seed: &SeedConfig,
) -> Result<NetworksConfig, MergeError> {
	let mut networks = HashMap::new();

	for override_ in overrides {
		let network_seed = seed.get_network(override_.chain_id).ok_or_else(|| {
			MergeError::UnknownChainId(override_.chain_id, seed.supported_chain_ids())
		})?;

		let network_config = build_network_config(network_seed, override_);
		networks.insert(override_.chain_id, network_config);
	}

	Ok(networks)
}

/// Builds a single NetworkConfig from seed data and user overrides.
fn build_network_config(seed: &NetworkSeed, override_: &NetworkOverride) -> NetworkConfig {
	// Build RPC endpoints - use override if provided, otherwise use seed defaults
	let rpc_urls = match &override_.rpc_urls {
		Some(urls) if !urls.is_empty() => urls
			.iter()
			.map(|url| RpcEndpoint::http_only(url.clone()))
			.collect(),
		_ => seed
			.default_rpc_urls
			.iter()
			.map(|url| RpcEndpoint::http_only(url.to_string()))
			.collect(),
	};

	// Convert user tokens to TokenConfig
	let tokens = override_
		.tokens
		.iter()
		.map(|t| TokenConfig {
			address: solver_types::Address(t.address.as_slice().to_vec()),
			symbol: t.symbol.clone(),
			decimals: t.decimals,
		})
		.collect();

	NetworkConfig {
		rpc_urls,
		input_settler_address: solver_types::Address(seed.input_settler.as_slice().to_vec()),
		output_settler_address: solver_types::Address(seed.output_settler.as_slice().to_vec()),
		tokens,
		input_settler_compact_address: Some(solver_types::Address(
			seed.input_settler_compact.as_slice().to_vec(),
		)),
		the_compact_address: Some(solver_types::Address(seed.the_compact.as_slice().to_vec())),
		allocator_address: Some(solver_types::Address(seed.allocator.as_slice().to_vec())),
	}
}

/// Builds the SolverConfig section.
fn build_solver_config(solver_id: &str, defaults: &SeedDefaults) -> SolverConfig {
	SolverConfig {
		id: solver_id.to_string(),
		min_profitability_pct: defaults.min_profitability_pct,
		monitoring_timeout_seconds: defaults.monitoring_timeout_seconds,
	}
}

/// Helper to create a toml::Value::Table from key-value pairs
fn toml_table(pairs: Vec<(&str, toml::Value)>) -> toml::Value {
	let mut table = toml::map::Map::new();
	for (key, value) in pairs {
		table.insert(key.to_string(), value);
	}
	toml::Value::Table(table)
}

/// Builds the StorageConfig section.
fn build_storage_config(defaults: &SeedDefaults) -> StorageConfig {
	let mut implementations = HashMap::new();

	// Read Redis URL from environment variable with default fallback
	let redis_url =
		std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

	// Redis implementation config
	let redis_config = toml_table(vec![
		("redis_url", toml::Value::String(redis_url)),
		("key_prefix", toml::Value::String("oif-solver".to_string())),
		("connection_timeout_ms", toml::Value::Integer(5000)),
		("ttl_orders", toml::Value::Integer(0)),
		("ttl_intents", toml::Value::Integer(86400)),
		("ttl_order_by_tx_hash", toml::Value::Integer(86400)),
	]);
	implementations.insert("redis".to_string(), redis_config);

	// Memory implementation (fallback for testing)
	implementations.insert(
		"memory".to_string(),
		toml::Value::Table(toml::map::Map::new()),
	);

	StorageConfig {
		primary: defaults.storage_primary.to_string(),
		implementations,
		cleanup_interval_seconds: defaults.cleanup_interval_seconds,
	}
}

/// Builds the DeliveryConfig section.
fn build_delivery_config(chain_ids: &[u64], defaults: &SeedDefaults) -> DeliveryConfig {
	let mut implementations = HashMap::new();

	let network_ids_array = toml::Value::Array(
		chain_ids
			.iter()
			.map(|id| toml::Value::Integer(*id as i64))
			.collect(),
	);

	let evm_alloy_config = toml_table(vec![("network_ids", network_ids_array)]);
	implementations.insert("evm_alloy".to_string(), evm_alloy_config);

	DeliveryConfig {
		implementations,
		min_confirmations: defaults.min_confirmations,
	}
}

/// Builds the AccountConfig section.
fn build_account_config(defaults: &SeedDefaults) -> AccountConfig {
	let mut implementations = HashMap::new();

	// Read private key from environment variable and trim whitespace
	let private_key = std::env::var("SOLVER_PRIVATE_KEY")
		.map(|k| k.trim().to_string())
		.unwrap_or_else(|_| "${SOLVER_PRIVATE_KEY}".to_string());

	let local_config = toml_table(vec![("private_key", toml::Value::String(private_key))]);
	implementations.insert("local".to_string(), local_config);

	AccountConfig {
		primary: defaults.account_primary.to_string(),
		implementations,
	}
}

/// Builds the DiscoveryConfig section.
fn build_discovery_config(chain_ids: &[u64], defaults: &SeedDefaults) -> DiscoveryConfig {
	let mut implementations = HashMap::new();

	let network_ids_array = toml::Value::Array(
		chain_ids
			.iter()
			.map(|id| toml::Value::Integer(*id as i64))
			.collect(),
	);

	// Onchain discovery - polls chain for new orders
	let onchain_config = toml_table(vec![
		("network_ids", network_ids_array.clone()),
		(
			"polling_interval_secs",
			toml::Value::Integer(defaults.polling_interval_secs as i64),
		),
	]);
	implementations.insert("onchain_eip7683".to_string(), onchain_config);

	// Offchain discovery - receives orders via HTTP API from aggregators
	let offchain_config = toml_table(vec![
		("api_host", toml::Value::String("127.0.0.1".to_string())),
		("api_port", toml::Value::Integer(8081)),
		("network_ids", network_ids_array),
	]);
	implementations.insert("offchain_eip7683".to_string(), offchain_config);

	DiscoveryConfig { implementations }
}

/// Builds the OrderConfig section.
fn build_order_config(defaults: &SeedDefaults) -> OrderConfig {
	let mut implementations = HashMap::new();

	// EIP-7683 order implementation
	implementations.insert(
		"eip7683".to_string(),
		toml::Value::Table(toml::map::Map::new()),
	);

	// Strategy implementations
	let mut strategy_implementations = HashMap::new();
	let simple_strategy_config = toml_table(vec![(
		"max_gas_price_gwei",
		toml::Value::Integer(defaults.max_gas_price_gwei as i64),
	)]);
	strategy_implementations.insert("simple".to_string(), simple_strategy_config);

	OrderConfig {
		implementations,
		strategy: StrategyConfig {
			primary: defaults.order_strategy_primary.to_string(),
			implementations: strategy_implementations,
		},
		callback_whitelist: Vec::new(),
		simulate_callbacks: defaults.simulate_callbacks,
	}
}

/// Builds the SettlementConfig section including Hyperlane configuration.
fn build_settlement_config(chain_ids: &[u64], seed: &SeedConfig) -> SettlementConfig {
	let mut implementations = HashMap::new();

	// Build Hyperlane settlement config
	let hyperlane_config = build_hyperlane_config(chain_ids, seed);
	implementations.insert("hyperlane".to_string(), hyperlane_config);

	SettlementConfig {
		implementations,
		settlement_poll_interval_seconds: seed.defaults.settlement_poll_interval_seconds,
	}
}

/// Builds the Hyperlane settlement configuration dynamically.
fn build_hyperlane_config(chain_ids: &[u64], seed: &SeedConfig) -> toml::Value {
	let mut table = toml::map::Map::new();

	// Basic settings
	table.insert(
		"order".to_string(),
		toml::Value::String("eip7683".to_string()),
	);
	table.insert(
		"network_ids".to_string(),
		toml::Value::Array(
			chain_ids
				.iter()
				.map(|id| toml::Value::Integer(*id as i64))
				.collect(),
		),
	);
	table.insert(
		"default_gas_limit".to_string(),
		toml::Value::Integer(seed.defaults.hyperlane_default_gas_limit as i64),
	);
	table.insert(
		"message_timeout_seconds".to_string(),
		toml::Value::Integer(seed.defaults.hyperlane_message_timeout_seconds as i64),
	);
	table.insert(
		"finalization_required".to_string(),
		toml::Value::Boolean(seed.defaults.hyperlane_finalization_required),
	);

	// Build oracles map
	let mut input_oracles = toml::map::Map::new();
	let mut output_oracles = toml::map::Map::new();

	for chain_id in chain_ids {
		if let Some(network) = seed.get_network(*chain_id) {
			let oracle_addr = format!("0x{}", hex::encode(network.hyperlane_oracle));
			let oracle_array = toml::Value::Array(vec![toml::Value::String(oracle_addr.clone())]);

			input_oracles.insert(chain_id.to_string(), oracle_array.clone());
			output_oracles.insert(chain_id.to_string(), oracle_array);
		}
	}

	let mut oracles = toml::map::Map::new();
	oracles.insert("input".to_string(), toml::Value::Table(input_oracles));
	oracles.insert("output".to_string(), toml::Value::Table(output_oracles));
	table.insert("oracles".to_string(), toml::Value::Table(oracles));

	// Build routes - each chain can send to all other chains
	let mut routes = toml::map::Map::new();
	for chain_id in chain_ids {
		let other_chains: Vec<toml::Value> = chain_ids
			.iter()
			.filter(|c| *c != chain_id)
			.map(|c| toml::Value::Integer(*c as i64))
			.collect();
		routes.insert(chain_id.to_string(), toml::Value::Array(other_chains));
	}
	table.insert("routes".to_string(), toml::Value::Table(routes));

	// Build mailboxes map
	let mut mailboxes = toml::map::Map::new();
	for chain_id in chain_ids {
		if let Some(network) = seed.get_network(*chain_id) {
			let mailbox_addr = format!("0x{}", hex::encode(network.hyperlane_mailbox));
			mailboxes.insert(chain_id.to_string(), toml::Value::String(mailbox_addr));
		}
	}
	table.insert("mailboxes".to_string(), toml::Value::Table(mailboxes));

	// Build IGP addresses map
	let mut igp_addresses = toml::map::Map::new();
	for chain_id in chain_ids {
		if let Some(network) = seed.get_network(*chain_id) {
			let igp_addr = format!("0x{}", hex::encode(network.hyperlane_igp));
			igp_addresses.insert(chain_id.to_string(), toml::Value::String(igp_addr));
		}
	}
	table.insert(
		"igp_addresses".to_string(),
		toml::Value::Table(igp_addresses),
	);

	toml::Value::Table(table)
}

/// Builds the PricingConfig section.
fn build_pricing_config(defaults: &SeedDefaults) -> PricingConfig {
	let mut implementations = HashMap::new();

	// CoinGecko implementation
	let coingecko_config = toml_table(vec![
		(
			"cache_duration_seconds",
			toml::Value::Integer(defaults.cache_duration_seconds as i64),
		),
		("rate_limit_delay_ms", toml::Value::Integer(1200)),
	]);
	implementations.insert("coingecko".to_string(), coingecko_config);

	// DefiLlama implementation
	let defillama_config = toml_table(vec![(
		"cache_duration_seconds",
		toml::Value::Integer(defaults.cache_duration_seconds as i64),
	)]);
	implementations.insert("defillama".to_string(), defillama_config);

	PricingConfig {
		primary: defaults.pricing_primary.to_string(),
		fallbacks: defaults
			.pricing_fallbacks
			.iter()
			.map(|s| s.to_string())
			.collect(),
		implementations,
	}
}

/// Builds the GasConfig section with flow-specific gas units.
fn build_gas_config(defaults: &SeedDefaults) -> GasConfig {
	let mut flows = HashMap::new();

	flows.insert(
		"resource_lock".to_string(),
		GasFlowUnits {
			open: Some(defaults.gas_resource_lock.open),
			fill: Some(defaults.gas_resource_lock.fill),
			claim: Some(defaults.gas_resource_lock.claim),
		},
	);

	flows.insert(
		"permit2_escrow".to_string(),
		GasFlowUnits {
			open: Some(defaults.gas_permit2_escrow.open),
			fill: Some(defaults.gas_permit2_escrow.fill),
			claim: Some(defaults.gas_permit2_escrow.claim),
		},
	);

	flows.insert(
		"eip3009_escrow".to_string(),
		GasFlowUnits {
			open: Some(defaults.gas_eip3009_escrow.open),
			fill: Some(defaults.gas_eip3009_escrow.fill),
			claim: Some(defaults.gas_eip3009_escrow.claim),
		},
	);

	GasConfig { flows }
}

/// Builds the ApiConfig section with default values for HTTP API server.
fn build_api_config(
	admin_override: Option<&solver_types::seed_overrides::AdminOverride>,
) -> ApiConfig {
	// Build auth config if admin is configured
	// Note: `auth.enabled` controls JWT requirement for /orders endpoint
	// Admin auth (wallet signatures for /admin/*) is controlled separately by `auth.admin.enabled`
	let auth = admin_override.map(|admin| {
		use solver_types::{AdminConfig, AuthConfig, SecretString};

		AuthConfig {
			enabled: false, // Don't require JWT for /orders - admin auth is separate
			jwt_secret: SecretString::new(uuid::Uuid::new_v4().to_string()),
			access_token_expiry_hours: 1,
			refresh_token_expiry_hours: 720, // 30 days
			issuer: "oif-solver".to_string(),
			admin: Some(AdminConfig {
				enabled: admin.enabled,
				domain: admin.domain.clone(),
				nonce_ttl_seconds: admin.nonce_ttl_seconds.unwrap_or(300),
				admin_addresses: admin.admin_addresses.clone(),
			}),
		}
	});

	ApiConfig {
		enabled: true,
		host: "127.0.0.1".to_string(),
		port: 3000,
		timeout_seconds: 30,
		max_request_size: 1024 * 1024, // 1MB
		implementations: ApiImplementations {
			discovery: Some("offchain_eip7683".to_string()),
		},
		rate_limiting: None,
		cors: None,
		auth,
		quote: None,
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::seeds::TESTNET_SEED;
	use alloy_primitives::address;

	fn test_seed_overrides() -> SeedOverrides {
		SeedOverrides {
			solver_id: None,
			networks: vec![
				NetworkOverride {
					chain_id: 11155420, // Optimism Sepolia
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "USDC".to_string(),
						address: address!("191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6"),
						decimals: 6,
					}],
					rpc_urls: None,
				},
				NetworkOverride {
					chain_id: 84532, // Base Sepolia
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "USDC".to_string(),
						address: address!("73c83DAcc74bB8a704717AC09703b959E74b9705"),
						decimals: 6,
					}],
					rpc_urls: Some(vec!["https://custom-rpc.example.com".to_string()]),
				},
			],
			admin: None,
		}
	}

	#[test]
	fn test_merge_config_success() {
		let overrides = test_seed_overrides();
		let result = merge_config(overrides, &TESTNET_SEED);

		assert!(result.is_ok());
		let config = result.unwrap();

		// Check solver ID is auto-generated
		assert!(config.solver.id.starts_with("solver-"));

		// Check networks
		assert_eq!(config.networks.len(), 2);
		assert!(config.networks.contains_key(&11155420));
		assert!(config.networks.contains_key(&84532));
	}

	#[test]
	fn test_merge_config_unknown_chain() {
		let overrides = SeedOverrides {
			solver_id: None,
			networks: vec![
				NetworkOverride {
					chain_id: 999999, // Unknown chain
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "TEST".to_string(),
						address: address!("1111111111111111111111111111111111111111"),
						decimals: 18,
					}],
					rpc_urls: None,
				},
				NetworkOverride {
					chain_id: 11155420,
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "USDC".to_string(),
						address: address!("191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6"),
						decimals: 6,
					}],
					rpc_urls: None,
				},
			],
			admin: None,
		};

		let result = merge_config(overrides, &TESTNET_SEED);
		assert!(result.is_err());
		assert!(matches!(
			result.unwrap_err(),
			MergeError::UnknownChainId(999999, _)
		));
	}

	#[test]
	fn test_merge_config_no_tokens() {
		let overrides = SeedOverrides {
			solver_id: None,
			networks: vec![
				NetworkOverride {
					chain_id: 11155420,
					tokens: vec![], // No tokens
					rpc_urls: None,
				},
				NetworkOverride {
					chain_id: 84532,
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "USDC".to_string(),
						address: address!("73c83DAcc74bB8a704717AC09703b959E74b9705"),
						decimals: 6,
					}],
					rpc_urls: None,
				},
			],
			admin: None,
		};

		let result = merge_config(overrides, &TESTNET_SEED);
		assert!(result.is_err());
		assert!(matches!(
			result.unwrap_err(),
			MergeError::NoTokens(11155420)
		));
	}

	#[test]
	fn test_merge_config_insufficient_networks() {
		let overrides = SeedOverrides {
			solver_id: None,
			networks: vec![NetworkOverride {
				chain_id: 11155420,
				tokens: vec![solver_types::seed_overrides::Token {
					symbol: "USDC".to_string(),
					address: address!("191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6"),
					decimals: 6,
				}],
				rpc_urls: None,
			}],
			admin: None,
		};

		let result = merge_config(overrides, &TESTNET_SEED);
		assert!(result.is_err());
		assert!(matches!(
			result.unwrap_err(),
			MergeError::InsufficientNetworks
		));
	}

	#[test]
	fn test_network_config_uses_seed_defaults() {
		let overrides = test_seed_overrides();
		let config = merge_config(overrides, &TESTNET_SEED).unwrap();

		// Check Optimism Sepolia uses seed default RPC (no override provided)
		let opt_network = config.networks.get(&11155420).unwrap();
		let rpc_url = opt_network.get_http_url().unwrap();
		assert!(rpc_url.contains("sepolia.optimism.io"));
	}

	#[test]
	fn test_network_config_uses_custom_rpc() {
		let overrides = test_seed_overrides();
		let config = merge_config(overrides, &TESTNET_SEED).unwrap();

		// Check Base Sepolia uses custom RPC (override provided)
		let base_network = config.networks.get(&84532).unwrap();
		let rpc_url = base_network.get_http_url().unwrap();
		assert_eq!(rpc_url, "https://custom-rpc.example.com");
	}

	#[test]
	fn test_settlement_config_has_hyperlane() {
		let overrides = test_seed_overrides();
		let config = merge_config(overrides, &TESTNET_SEED).unwrap();

		assert!(config.settlement.implementations.contains_key("hyperlane"));

		let hyperlane = config.settlement.implementations.get("hyperlane").unwrap();
		assert!(hyperlane.get("network_ids").is_some());
		assert!(hyperlane.get("oracles").is_some());
		assert!(hyperlane.get("routes").is_some());
		assert!(hyperlane.get("mailboxes").is_some());
		assert!(hyperlane.get("igp_addresses").is_some());
	}

	#[test]
	fn test_hyperlane_routes_bidirectional() {
		let overrides = test_seed_overrides();
		let config = merge_config(overrides, &TESTNET_SEED).unwrap();

		let hyperlane = config.settlement.implementations.get("hyperlane").unwrap();
		let routes = hyperlane.get("routes").unwrap().as_table().unwrap();

		// Check Optimism Sepolia can send to Base Sepolia
		let opt_routes = routes.get("11155420").unwrap().as_array().unwrap();
		assert!(opt_routes.contains(&toml::Value::Integer(84532)));

		// Check Base Sepolia can send to Optimism Sepolia
		let base_routes = routes.get("84532").unwrap().as_array().unwrap();
		assert!(base_routes.contains(&toml::Value::Integer(11155420)));
	}

	#[test]
	fn test_storage_config() {
		let overrides = test_seed_overrides();
		let config = merge_config(overrides, &TESTNET_SEED).unwrap();

		assert_eq!(config.storage.primary, "redis");
		assert!(config.storage.implementations.contains_key("redis"));
		assert!(config.storage.implementations.contains_key("memory"));
	}

	#[test]
	fn test_pricing_config() {
		let overrides = test_seed_overrides();
		let config = merge_config(overrides, &TESTNET_SEED).unwrap();

		let pricing = config.pricing.as_ref().unwrap();
		assert_eq!(pricing.primary, "coingecko");
		assert!(pricing.fallbacks.contains(&"defillama".to_string()));
		assert!(pricing.implementations.contains_key("coingecko"));
		assert!(pricing.implementations.contains_key("defillama"));
	}

	#[test]
	fn test_gas_config() {
		let overrides = test_seed_overrides();
		let config = merge_config(overrides, &TESTNET_SEED).unwrap();

		let gas = config.gas.as_ref().unwrap();
		assert!(gas.flows.contains_key("resource_lock"));
		assert!(gas.flows.contains_key("permit2_escrow"));
		assert!(gas.flows.contains_key("eip3009_escrow"));

		let resource_lock = gas.flows.get("resource_lock").unwrap();
		assert_eq!(resource_lock.open, Some(0));
		assert_eq!(resource_lock.fill, Some(77298));
		assert_eq!(resource_lock.claim, Some(122793));
	}

	#[test]
	fn test_merge_error_display() {
		// Test all error variants have proper Display implementations
		let unknown_chain = MergeError::UnknownChainId(999, vec![1, 2, 3]);
		assert!(unknown_chain.to_string().contains("Unknown chain ID"));
		assert!(unknown_chain.to_string().contains("999"));

		let no_tokens = MergeError::NoTokens(42);
		assert!(no_tokens.to_string().contains("No tokens"));
		assert!(no_tokens.to_string().contains("42"));

		let duplicate = MergeError::DuplicateChainId(123);
		assert!(duplicate.to_string().contains("Duplicate chain ID"));
		assert!(duplicate.to_string().contains("123"));

		let insufficient = MergeError::InsufficientNetworks;
		assert!(insufficient.to_string().contains("At least 2 networks"));

		let validation = MergeError::Validation("test error".to_string());
		assert!(validation
			.to_string()
			.contains("Configuration validation failed"));
		assert!(validation.to_string().contains("test error"));
	}

	#[test]
	fn test_merge_config_duplicate_chain_ids() {
		let overrides = SeedOverrides {
			solver_id: None,
			networks: vec![
				NetworkOverride {
					chain_id: 11155420,
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "USDC".to_string(),
						address: address!("191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6"),
						decimals: 6,
					}],
					rpc_urls: None,
				},
				NetworkOverride {
					chain_id: 11155420, // Duplicate!
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "DAI".to_string(),
						address: address!("191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6"),
						decimals: 18,
					}],
					rpc_urls: None,
				},
			],
			admin: None,
		};

		let result = merge_config(overrides, &TESTNET_SEED);
		assert!(result.is_err());
		assert!(matches!(
			result.unwrap_err(),
			MergeError::DuplicateChainId(11155420)
		));
	}

	#[test]
	fn test_custom_solver_id() {
		let overrides = SeedOverrides {
			solver_id: Some("my-custom-solver".to_string()),
			networks: vec![
				NetworkOverride {
					chain_id: 11155420,
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "USDC".to_string(),
						address: address!("191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6"),
						decimals: 6,
					}],
					rpc_urls: None,
				},
				NetworkOverride {
					chain_id: 84532,
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "USDC".to_string(),
						address: address!("73c83DAcc74bB8a704717AC09703b959E74b9705"),
						decimals: 6,
					}],
					rpc_urls: None,
				},
			],
			admin: None,
		};

		let config = merge_config(overrides, &TESTNET_SEED).unwrap();
		assert_eq!(config.solver.id, "my-custom-solver");
	}
}
