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

use crate::seeds::types::{NetworkSeed, SeedConfig, SeedDefaults, COMMON_DEFAULTS};
use rust_decimal::Decimal;
use solver_config::{
	AccountConfig, ApiConfig, ApiImplementations, Config, DeliveryConfig, DiscoveryConfig,
	GasConfig, GasFlowUnits, OrderConfig, PricingConfig, SettlementConfig, SolverConfig,
	StorageConfig, StrategyConfig,
};
use solver_types::seed_overrides::OracleSelectionStrategyOverride;
use solver_types::{
	networks::{NetworkType, RpcEndpoint},
	AccountOverride, DirectSettlementOverride, HyperlaneSettlementOverride, NetworkConfig,
	NetworkOverride, NetworksConfig, OperatorAccountConfig, OperatorAdminConfig, OperatorConfig,
	OperatorDirectConfig, OperatorGasConfig, OperatorGasFlowUnits, OperatorHyperlaneConfig,
	OperatorNetworkConfig, OperatorOracleConfig, OperatorOracleSelectionStrategy,
	OperatorPricingConfig, OperatorRpcEndpoint, OperatorSettlementConfig, OperatorSettlementType,
	OperatorSolverConfig, OperatorToken, OperatorWithdrawalsConfig, SeedOverrides,
	SettlementTypeOverride, TokenConfig,
};
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use uuid::Uuid;

/// Errors that can occur during configuration merge.
#[derive(Debug, Error)]
pub enum MergeError {
	/// A requested chain ID is not supported by the seed.
	#[error("Unknown chain ID: {0}. Supported chains: {1:?}")]
	UnknownChainId(u64, Vec<u64>),

	/// No tokens were specified for a network.
	///
	/// Kept for backward compatibility with existing error handling/tests.
	/// Empty token arrays are now allowed during boot.
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

fn validate_network_for_seeding(
	network: &NetworkOverride,
	seed: &SeedConfig,
) -> Result<(), MergeError> {
	// Seed-backed chain: always valid for network-level requirements.
	if seed.supports_chain(network.chain_id) {
		return Ok(());
	}

	// Non-seeded chain requires an explicit contract and RPC bundle.
	let missing_fields = collect_missing_non_seeded_network_fields(network);

	if missing_fields.is_empty() {
		return Ok(());
	}

	Err(MergeError::Validation(format!(
		"Non-seeded chain {} is missing required fields: {}",
		network.chain_id,
		missing_fields.join(", ")
	)))
}

fn collect_missing_non_seeded_network_fields(network: &NetworkOverride) -> Vec<&'static str> {
	let mut missing_fields = Vec::new();

	if network.name.as_ref().is_none_or(|n| n.trim().is_empty()) {
		missing_fields.push("name");
	}
	if network.network_type.is_none() {
		missing_fields.push("type");
	}
	if network.input_settler_address.is_none() {
		missing_fields.push("input_settler_address");
	}
	if network.output_settler_address.is_none() {
		missing_fields.push("output_settler_address");
	}
	if network.rpc_urls.as_ref().is_none_or(|urls| urls.is_empty()) {
		missing_fields.push("rpc_urls");
	}

	missing_fields
}

fn validate_network_for_seedless_mode(network: &NetworkOverride) -> Result<(), MergeError> {
	let missing_fields = collect_missing_non_seeded_network_fields(network);

	if missing_fields.is_empty() {
		return Ok(());
	}

	Err(MergeError::Validation(format!(
		"seedless mode requires explicit fields for chain {}: {}",
		network.chain_id,
		missing_fields.join(", ")
	)))
}

fn validate_seedless_settlement_requirements(
	initializer: &SeedOverrides,
	chain_ids: &[u64],
) -> Result<(), MergeError> {
	match initializer.settlement_type() {
		SettlementTypeOverride::Hyperlane => {
			let hyperlane = initializer
				.settlement
				.as_ref()
				.and_then(|s| s.hyperlane.as_ref())
				.ok_or_else(|| {
					MergeError::Validation(
						"seedless mode requires explicit settlement.hyperlane configuration"
							.to_string(),
					)
				})?;

			for chain_id in chain_ids {
				if !hyperlane.mailboxes.contains_key(chain_id) {
					return Err(MergeError::Validation(format!(
						"seedless mode requires settlement.hyperlane.mailboxes for chain {}",
						chain_id
					)));
				}
				if !hyperlane.igp_addresses.contains_key(chain_id) {
					return Err(MergeError::Validation(format!(
						"seedless mode requires settlement.hyperlane.igp_addresses for chain {}",
						chain_id
					)));
				}

				match hyperlane.oracles.input.get(chain_id) {
					Some(oracles) if !oracles.is_empty() => {},
					Some(_) => {
						return Err(MergeError::Validation(format!(
							"seedless mode requires non-empty settlement.hyperlane.oracles.input for chain {}",
							chain_id
						)))
					},
					None => {
						return Err(MergeError::Validation(format!(
							"seedless mode requires settlement.hyperlane.oracles.input for chain {}",
							chain_id
						)))
					},
				}

				match hyperlane.oracles.output.get(chain_id) {
					Some(oracles) if !oracles.is_empty() => {},
					Some(_) => {
						return Err(MergeError::Validation(format!(
							"seedless mode requires non-empty settlement.hyperlane.oracles.output for chain {}",
							chain_id
						)))
					},
					None => {
						return Err(MergeError::Validation(format!(
							"seedless mode requires settlement.hyperlane.oracles.output for chain {}",
							chain_id
						)))
					},
				}
			}
		},
		SettlementTypeOverride::Direct => {
			let direct = initializer
				.settlement
				.as_ref()
				.and_then(|s| s.direct.as_ref())
				.ok_or_else(|| {
					MergeError::Validation(
						"seedless mode requires settlement.direct when settlement.type is 'direct'"
							.to_string(),
					)
				})?;

			for chain_id in chain_ids {
				match direct.oracles.input.get(chain_id) {
					Some(oracles) if !oracles.is_empty() => {},
					Some(_) => {
						return Err(MergeError::Validation(format!(
							"seedless mode requires non-empty settlement.direct.oracles.input for chain {}",
							chain_id
						)))
					},
					None => {
						return Err(MergeError::Validation(format!(
							"seedless mode requires settlement.direct.oracles.input for chain {}",
							chain_id
						)))
					},
				}
				match direct.oracles.output.get(chain_id) {
					Some(oracles) if !oracles.is_empty() => {},
					Some(_) => {
						return Err(MergeError::Validation(format!(
							"seedless mode requires non-empty settlement.direct.oracles.output for chain {}",
							chain_id
						)))
					},
					None => {
						return Err(MergeError::Validation(format!(
							"seedless mode requires settlement.direct.oracles.output for chain {}",
							chain_id
						)))
					},
				}
			}
		},
	}

	Ok(())
}

fn parse_bool_env_var(name: &str, default: bool) -> Result<bool, MergeError> {
	match std::env::var(name) {
		Ok(raw) => raw.trim().to_ascii_lowercase().parse().map_err(|_| {
			MergeError::Validation(format!(
				"Invalid boolean value for {name}: {raw} (expected 'true' or 'false')"
			))
		}),
		Err(std::env::VarError::NotPresent) => Ok(default),
		Err(std::env::VarError::NotUnicode(_)) => Err(MergeError::Validation(format!(
			"Invalid unicode value for {name}"
		))),
	}
}

fn load_public_register_enabled(auth_enabled: bool) -> Result<bool, MergeError> {
	if !auth_enabled {
		return Ok(false);
	}

	parse_bool_env_var("AUTH_PUBLIC_REGISTER_ENABLED", false)
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
/// - Fewer than 2 networks are requested
pub fn merge_config(overrides: SeedOverrides, seed: &SeedConfig) -> Result<Config, MergeError> {
	let operator_config = merge_to_operator_config(overrides, seed)?;
	build_runtime_config(&operator_config)
}

/// Merges Seeds (Rust defaults) + Initializer (JSON) into a full OperatorConfig.
///
/// Called ONLY on first boot. The result is stored in Redis and becomes the
/// source of truth for all subsequent boots.
///
/// # Arguments
///
/// * `initializer` - User-provided seed overrides with chain IDs and tokens
/// * `seed` - Hardcoded seed configuration with contract addresses and defaults
///
/// # Returns
///
/// A complete `OperatorConfig` ready to be stored in Redis.
pub fn merge_to_operator_config(
	initializer: SeedOverrides,
	seed: &SeedConfig,
) -> Result<OperatorConfig, MergeError> {
	// Check for duplicate chain IDs
	let mut seen_chain_ids = std::collections::HashSet::new();
	for network in &initializer.networks {
		if !seen_chain_ids.insert(network.chain_id) {
			return Err(MergeError::DuplicateChainId(network.chain_id));
		}
	}

	// Validate we have at least 2 unique networks
	if seen_chain_ids.len() < 2 {
		return Err(MergeError::InsufficientNetworks);
	}

	// Validate requested chains (seed-backed OR valid non-seeded bundle)
	for network in &initializer.networks {
		validate_network_for_seeding(network, seed)?;
	}

	// Use provided solver_id or generate a new one
	let solver_id = initializer
		.solver_id
		.clone()
		.unwrap_or_else(|| format!("solver-{}", Uuid::new_v4()));

	// Build operator networks config
	let networks = build_operator_networks_config(&initializer.networks, seed)?;

	// Get chain IDs for hyperlane config
	let chain_ids: Vec<u64> = initializer.networks.iter().map(|n| n.chain_id).collect();

	// Build settlement config (hyperlane by default, direct optional)
	let settlement = build_operator_settlement_config(&initializer, seed, &chain_ids)?;

	// Build admin config from initializer
	let admin = match &initializer.admin {
		Some(admin_override) => OperatorAdminConfig {
			enabled: admin_override.enabled,
			domain: admin_override.domain.clone(),
			chain_id: admin_override.chain_id.unwrap_or(chain_ids[0]),
			nonce_ttl_seconds: admin_override.nonce_ttl_seconds.unwrap_or(300),
			admin_addresses: admin_override.admin_addresses.clone(),
			withdrawals: OperatorWithdrawalsConfig {
				enabled: admin_override.withdrawals.enabled,
			},
		},
		None => OperatorAdminConfig::default(),
	};

	// Extract fee config overrides (flattened in SeedOverrides)
	let min_profitability_pct = initializer
		.min_profitability_pct
		.unwrap_or(seed.defaults.min_profitability_pct);

	let gas_buffer_bps = initializer.gas_buffer_bps.unwrap_or(1000);
	let commission_bps = initializer
		.commission_bps
		.unwrap_or(seed.defaults.commission_bps);
	let rate_buffer_bps = initializer
		.rate_buffer_bps
		.unwrap_or(seed.defaults.rate_buffer_bps);

	Ok(OperatorConfig {
		solver_id: solver_id.clone(),
		solver_name: Some(initializer.solver_name.clone().unwrap_or(solver_id)),
		networks,
		settlement,
		gas: OperatorGasConfig {
			resource_lock: OperatorGasFlowUnits {
				open: seed.defaults.gas_resource_lock.open,
				fill: seed.defaults.gas_resource_lock.fill,
				claim: seed.defaults.gas_resource_lock.claim,
			},
			permit2_escrow: OperatorGasFlowUnits {
				open: seed.defaults.gas_permit2_escrow.open,
				fill: seed.defaults.gas_permit2_escrow.fill,
				claim: seed.defaults.gas_permit2_escrow.claim,
			},
			eip3009_escrow: OperatorGasFlowUnits {
				open: seed.defaults.gas_eip3009_escrow.open,
				fill: seed.defaults.gas_eip3009_escrow.fill,
				claim: seed.defaults.gas_eip3009_escrow.claim,
			},
		},
		pricing: OperatorPricingConfig {
			primary: seed.defaults.pricing_primary.to_string(),
			fallbacks: seed
				.defaults
				.pricing_fallbacks
				.iter()
				.map(|s| s.to_string())
				.collect(),
			cache_duration_seconds: seed.defaults.cache_duration_seconds,
			custom_prices: HashMap::new(),
		},
		solver: OperatorSolverConfig {
			min_profitability_pct,
			gas_buffer_bps,
			commission_bps,
			rate_buffer_bps,
			monitoring_timeout_seconds: seed.defaults.monitoring_timeout_seconds,
		},
		admin,
		auth_enabled: initializer.auth_enabled.unwrap_or(false),
		account: initializer.account.as_ref().map(|a| OperatorAccountConfig {
			primary: a.primary.clone(),
			implementations: a.implementations.clone(),
		}),
	})
}

/// Merges initializer JSON into a full OperatorConfig without using a seed preset.
///
/// Seedless mode uses `COMMON_DEFAULTS` and requires explicit network + settlement
/// contract data in the JSON payload.
pub fn merge_to_operator_config_seedless(
	initializer: SeedOverrides,
) -> Result<OperatorConfig, MergeError> {
	for network in &initializer.networks {
		validate_network_for_seedless_mode(network)?;
	}

	let chain_ids: Vec<u64> = initializer.networks.iter().map(|n| n.chain_id).collect();
	validate_seedless_settlement_requirements(&initializer, &chain_ids)?;

	let seedless_seed = SeedConfig {
		networks: &[],
		defaults: COMMON_DEFAULTS.clone(),
	};

	merge_to_operator_config(initializer, &seedless_seed)
}

/// Builds OperatorNetworkConfig HashMap from seed overrides and seed data.
fn build_operator_networks_config(
	overrides: &[NetworkOverride],
	seed: &SeedConfig,
) -> Result<HashMap<u64, OperatorNetworkConfig>, MergeError> {
	let mut networks = HashMap::new();

	for override_ in overrides {
		let network_seed = seed.get_network(override_.chain_id);
		let network_config = build_operator_network_config(network_seed, override_)?;
		networks.insert(override_.chain_id, network_config);
	}

	Ok(networks)
}

/// Builds a single OperatorNetworkConfig from seed data and user overrides.
fn build_operator_network_config(
	seed: Option<&NetworkSeed>,
	override_: &NetworkOverride,
) -> Result<OperatorNetworkConfig, MergeError> {
	// Build RPC endpoints - use override if provided, otherwise use seed defaults
	let rpc_urls: Vec<OperatorRpcEndpoint> = match &override_.rpc_urls {
		Some(urls) if !urls.is_empty() => urls
			.iter()
			.map(|url| OperatorRpcEndpoint::http_only(url.clone()))
			.collect(),
		_ => {
			if let Some(seed) = seed {
				seed.default_rpc_urls
					.iter()
					.map(|url| OperatorRpcEndpoint::http_only(url.to_string()))
					.collect()
			} else {
				return Err(MergeError::Validation(format!(
					"Non-seeded chain {} requires rpc_urls",
					override_.chain_id
				)));
			}
		},
	};

	// Convert user tokens to OperatorToken
	let tokens = override_
		.tokens
		.iter()
		.map(|t| OperatorToken {
			symbol: t.symbol.clone(),
			name: Some(t.name.clone().unwrap_or_else(|| t.symbol.clone())),
			address: t.address,
			decimals: t.decimals,
		})
		.collect();

	let name = override_
		.name
		.clone()
		.filter(|n| !n.trim().is_empty())
		.or_else(|| seed.map(|s| s.name.to_string()))
		.ok_or_else(|| {
			MergeError::Validation(format!(
				"Non-seeded chain {} requires name",
				override_.chain_id
			))
		})?;

	let input_settler_address = override_
		.input_settler_address
		.or_else(|| seed.map(|s| s.input_settler))
		.ok_or_else(|| {
			MergeError::Validation(format!(
				"Non-seeded chain {} requires input_settler_address",
				override_.chain_id
			))
		})?;

	let output_settler_address = override_
		.output_settler_address
		.or_else(|| seed.map(|s| s.output_settler))
		.ok_or_else(|| {
			MergeError::Validation(format!(
				"Non-seeded chain {} requires output_settler_address",
				override_.chain_id
			))
		})?;

	Ok(OperatorNetworkConfig {
		chain_id: override_.chain_id,
		name,
		network_type: override_.network_type.unwrap_or(NetworkType::New),
		tokens,
		rpc_urls,
		input_settler_address,
		output_settler_address,
		input_settler_compact_address: override_
			.input_settler_compact_address
			.or_else(|| seed.map(|s| s.input_settler_compact)),
		the_compact_address: override_
			.the_compact_address
			.or_else(|| seed.map(|s| s.the_compact)),
		allocator_address: override_
			.allocator_address
			.or_else(|| seed.map(|s| s.allocator)),
	})
}

/// Builds settlement configuration for OperatorConfig.
fn build_operator_settlement_config(
	initializer: &SeedOverrides,
	seed: &SeedConfig,
	chain_ids: &[u64],
) -> Result<OperatorSettlementConfig, MergeError> {
	let settlement_type = initializer.settlement_type();

	match settlement_type {
		SettlementTypeOverride::Hyperlane => {
			let hyperlane = build_operator_hyperlane_config(initializer, seed, chain_ids)?;
			Ok(OperatorSettlementConfig {
				settlement_poll_interval_seconds: seed.defaults.settlement_poll_interval_seconds,
				settlement_type: OperatorSettlementType::Hyperlane,
				hyperlane: Some(hyperlane),
				direct: None,
			})
		},
		SettlementTypeOverride::Direct => {
			let direct_override = initializer
				.settlement
				.as_ref()
				.and_then(|s| s.direct.as_ref())
				.ok_or_else(|| {
					MergeError::Validation(
						"settlement.type is 'direct' but settlement.direct is missing".to_string(),
					)
				})?;

			let direct = build_operator_direct_config_from_override(direct_override, chain_ids)?;
			Ok(OperatorSettlementConfig {
				settlement_poll_interval_seconds: seed.defaults.settlement_poll_interval_seconds,
				settlement_type: OperatorSettlementType::Direct,
				hyperlane: None,
				direct: Some(direct),
			})
		},
	}
}

/// Builds the Hyperlane configuration for OperatorConfig.
fn build_operator_hyperlane_config(
	initializer: &SeedOverrides,
	seed: &SeedConfig,
	chain_ids: &[u64],
) -> Result<OperatorHyperlaneConfig, MergeError> {
	let hyperlane_override = initializer
		.settlement
		.as_ref()
		.and_then(|s| s.hyperlane.as_ref());

	if let Some(override_cfg) = hyperlane_override {
		return build_operator_hyperlane_config_from_override(override_cfg, seed, chain_ids);
	}

	build_operator_hyperlane_config_from_seed(seed, chain_ids)
}

/// Builds the Hyperlane configuration from seed defaults.
fn build_operator_hyperlane_config_from_seed(
	seed: &SeedConfig,
	chain_ids: &[u64],
) -> Result<OperatorHyperlaneConfig, MergeError> {
	// Build mailboxes map
	let mut mailboxes = HashMap::new();
	for chain_id in chain_ids {
		let network = seed.get_network(*chain_id).ok_or_else(|| {
			MergeError::Validation(format!(
				"Chain {} is not in seed; provide settlement.hyperlane override",
				chain_id
			))
		})?;
		mailboxes.insert(*chain_id, network.hyperlane_mailbox);
	}

	// Build IGP addresses map
	let mut igp_addresses = HashMap::new();
	for chain_id in chain_ids {
		let network = seed.get_network(*chain_id).ok_or_else(|| {
			MergeError::Validation(format!(
				"Chain {} is not in seed; provide settlement.hyperlane override",
				chain_id
			))
		})?;
		igp_addresses.insert(*chain_id, network.hyperlane_igp);
	}

	// Build oracles map
	let mut input_oracles = HashMap::new();
	let mut output_oracles = HashMap::new();
	for chain_id in chain_ids {
		let network = seed.get_network(*chain_id).ok_or_else(|| {
			MergeError::Validation(format!(
				"Chain {} is not in seed; provide settlement.hyperlane override",
				chain_id
			))
		})?;
		input_oracles.insert(*chain_id, vec![network.hyperlane_oracle]);
		output_oracles.insert(*chain_id, vec![network.hyperlane_oracle]);
	}

	// Build routes - each chain can send to all other chains
	let mut routes = HashMap::new();
	for chain_id in chain_ids {
		let other_chains: Vec<u64> = chain_ids
			.iter()
			.filter(|c| *c != chain_id)
			.copied()
			.collect();
		routes.insert(*chain_id, other_chains);
	}

	Ok(OperatorHyperlaneConfig {
		default_gas_limit: seed.defaults.hyperlane_default_gas_limit,
		message_timeout_seconds: seed.defaults.hyperlane_message_timeout_seconds,
		finalization_required: seed.defaults.hyperlane_finalization_required,
		mailboxes,
		igp_addresses,
		oracles: OperatorOracleConfig {
			input: input_oracles,
			output: output_oracles,
		},
		routes,
	})
}

fn ensure_oracle_chain_entries(
	oracles: &HashMap<u64, Vec<alloy_primitives::Address>>,
	path: &str,
	chain_id: u64,
) -> Result<(), MergeError> {
	match oracles.get(&chain_id) {
		Some(entries) if !entries.is_empty() => Ok(()),
		Some(_) => Err(MergeError::Validation(format!(
			"{path} is empty for chain {chain_id}"
		))),
		None => Err(MergeError::Validation(format!(
			"{path} is missing chain {chain_id}"
		))),
	}
}

fn build_full_mesh_routes(chain_ids: &[u64]) -> HashMap<u64, Vec<u64>> {
	let mut routes = HashMap::new();
	for chain_id in chain_ids {
		let other_chains: Vec<u64> = chain_ids
			.iter()
			.filter(|c| *c != chain_id)
			.copied()
			.collect();
		routes.insert(*chain_id, other_chains);
	}
	routes
}

fn validate_routes(
	routes: &HashMap<u64, Vec<u64>>,
	chain_ids: &[u64],
	path: &str,
) -> Result<(), MergeError> {
	let configured_chain_ids: HashSet<u64> = chain_ids.iter().copied().collect();

	for (source_chain, destination_chains) in routes {
		if !configured_chain_ids.contains(source_chain) {
			return Err(MergeError::Validation(format!(
				"{path} has source chain {source_chain} which is not in configured networks"
			)));
		}

		for destination_chain in destination_chains {
			if !configured_chain_ids.contains(destination_chain) {
				return Err(MergeError::Validation(format!(
					"{path} has destination chain {destination_chain} which is not in configured networks"
				)));
			}
		}
	}

	Ok(())
}

/// Builds the Hyperlane configuration from initializer override.
fn build_operator_hyperlane_config_from_override(
	override_cfg: &HyperlaneSettlementOverride,
	seed: &SeedConfig,
	chain_ids: &[u64],
) -> Result<OperatorHyperlaneConfig, MergeError> {
	for chain_id in chain_ids {
		if !override_cfg.mailboxes.contains_key(chain_id) {
			return Err(MergeError::Validation(format!(
				"settlement.hyperlane.mailboxes is missing chain {}",
				chain_id
			)));
		}
		if !override_cfg.igp_addresses.contains_key(chain_id) {
			return Err(MergeError::Validation(format!(
				"settlement.hyperlane.igp_addresses is missing chain {}",
				chain_id
			)));
		}
		ensure_oracle_chain_entries(
			&override_cfg.oracles.input,
			"settlement.hyperlane.oracles.input",
			*chain_id,
		)?;
		ensure_oracle_chain_entries(
			&override_cfg.oracles.output,
			"settlement.hyperlane.oracles.output",
			*chain_id,
		)?;
	}

	let routes = if override_cfg.routes.is_empty() {
		build_full_mesh_routes(chain_ids)
	} else {
		validate_routes(
			&override_cfg.routes,
			chain_ids,
			"settlement.hyperlane.routes",
		)?;
		override_cfg.routes.clone()
	};

	Ok(OperatorHyperlaneConfig {
		default_gas_limit: override_cfg
			.default_gas_limit
			.unwrap_or(seed.defaults.hyperlane_default_gas_limit),
		message_timeout_seconds: override_cfg
			.message_timeout_seconds
			.unwrap_or(seed.defaults.hyperlane_message_timeout_seconds),
		finalization_required: override_cfg
			.finalization_required
			.unwrap_or(seed.defaults.hyperlane_finalization_required),
		mailboxes: override_cfg.mailboxes.clone(),
		igp_addresses: override_cfg.igp_addresses.clone(),
		oracles: OperatorOracleConfig {
			input: override_cfg.oracles.input.clone(),
			output: override_cfg.oracles.output.clone(),
		},
		routes,
	})
}

fn build_operator_direct_config_from_override(
	override_cfg: &DirectSettlementOverride,
	chain_ids: &[u64],
) -> Result<OperatorDirectConfig, MergeError> {
	for chain_id in chain_ids {
		ensure_oracle_chain_entries(
			&override_cfg.oracles.input,
			"settlement.direct.oracles.input",
			*chain_id,
		)?;
		ensure_oracle_chain_entries(
			&override_cfg.oracles.output,
			"settlement.direct.oracles.output",
			*chain_id,
		)?;
	}

	let routes = if override_cfg.routes.is_empty() {
		build_full_mesh_routes(chain_ids)
	} else {
		validate_routes(&override_cfg.routes, chain_ids, "settlement.direct.routes")?;
		override_cfg.routes.clone()
	};

	let selection_strategy = match override_cfg.oracle_selection_strategy {
		Some(OracleSelectionStrategyOverride::RoundRobin) => {
			OperatorOracleSelectionStrategy::RoundRobin
		},
		Some(OracleSelectionStrategyOverride::Random) => OperatorOracleSelectionStrategy::Random,
		_ => OperatorOracleSelectionStrategy::First,
	};

	Ok(OperatorDirectConfig {
		dispute_period_seconds: override_cfg.dispute_period_seconds.unwrap_or(300),
		oracles: OperatorOracleConfig {
			input: override_cfg.oracles.input.clone(),
			output: override_cfg.oracles.output.clone(),
		},
		routes,
		oracle_selection_strategy: selection_strategy,
	})
}

/// Builds runtime Config from OperatorConfig.
///
/// Called on every boot (after first boot) and on hot reload.
/// Transforms the persisted OperatorConfig into the runtime Config used by the solver.
///
/// # Arguments
///
/// * `operator_config` - The OperatorConfig loaded from Redis
///
/// # Returns
///
/// A complete `Config` ready for use by the solver.
pub fn build_runtime_config(operator_config: &OperatorConfig) -> Result<Config, MergeError> {
	let chain_ids: Vec<u64> = operator_config.networks.keys().copied().collect();

	// Validate we have at least 2 networks
	if chain_ids.len() < 2 {
		return Err(MergeError::InsufficientNetworks);
	}

	// Build networks config from OperatorConfig
	let networks = build_networks_from_operator_config(operator_config);

	// Build the full config
	let config = Config {
		solver: SolverConfig {
			id: operator_config.solver_id.clone(),
			min_profitability_pct: operator_config.solver.min_profitability_pct,
			gas_buffer_bps: operator_config.solver.gas_buffer_bps,
			commission_bps: operator_config.solver.commission_bps,
			rate_buffer_bps: operator_config.solver.rate_buffer_bps,
			monitoring_timeout_seconds: operator_config.solver.monitoring_timeout_seconds,
		},
		networks,
		storage: build_storage_config_from_operator(&operator_config.solver_id),
		delivery: build_delivery_config_from_operator(&chain_ids),
		account: build_account_config_from_operator(operator_config.account.as_ref()),
		discovery: build_discovery_config_from_operator(&chain_ids),
		order: build_order_config_from_operator(),
		settlement: build_settlement_config_from_operator(operator_config, &chain_ids)?,
		pricing: Some(build_pricing_config_from_operator(&operator_config.pricing)),
		api: Some(build_api_config_from_operator(
			&operator_config.admin,
			operator_config.auth_enabled,
		)?),
		gas: Some(build_gas_config_from_operator(&operator_config.gas)),
	};

	Ok(config)
}

/// Builds NetworksConfig from OperatorConfig.
fn build_networks_from_operator_config(operator_config: &OperatorConfig) -> NetworksConfig {
	let mut networks = HashMap::new();

	for (chain_id, op_network) in &operator_config.networks {
		// Build RPC endpoints
		let rpc_urls = op_network
			.rpc_urls
			.iter()
			.map(|r| RpcEndpoint {
				http: Some(r.http.clone()),
				ws: r.ws.clone(),
			})
			.collect();

		// Convert tokens
		let tokens = op_network
			.tokens
			.iter()
			.map(|t| TokenConfig {
				address: solver_types::Address(t.address.as_slice().to_vec()),
				symbol: t.symbol.clone(),
				name: t.name.clone(),
				decimals: t.decimals,
			})
			.collect();

		let network_config = NetworkConfig {
			name: Some(op_network.name.clone()),
			network_type: op_network.network_type,
			rpc_urls,
			input_settler_address: solver_types::Address(
				op_network.input_settler_address.as_slice().to_vec(),
			),
			output_settler_address: solver_types::Address(
				op_network.output_settler_address.as_slice().to_vec(),
			),
			tokens,
			input_settler_compact_address: op_network
				.input_settler_compact_address
				.map(|a| solver_types::Address(a.as_slice().to_vec())),
			the_compact_address: op_network
				.the_compact_address
				.map(|a| solver_types::Address(a.as_slice().to_vec())),
			allocator_address: op_network
				.allocator_address
				.map(|a| solver_types::Address(a.as_slice().to_vec())),
		};

		networks.insert(*chain_id, network_config);
	}

	networks
}

/// Builds StorageConfig from operator defaults.
///
/// Uses `solver_id` as the Redis key prefix to isolate storage per solver instance.
fn build_storage_config_from_operator(solver_id: &str) -> StorageConfig {
	let mut implementations = HashMap::new();

	// Read Redis URL from environment variable with default fallback
	let redis_url =
		std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

	// Redis implementation config
	// Use solver_id as key_prefix to isolate storage per solver instance
	let redis_config = toml_table(vec![
		("redis_url", toml::Value::String(redis_url)),
		("key_prefix", toml::Value::String(solver_id.to_string())),
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
		primary: "redis".to_string(),
		implementations,
		cleanup_interval_seconds: 3600,
	}
}

/// Builds DeliveryConfig from operator config.
fn build_delivery_config_from_operator(chain_ids: &[u64]) -> DeliveryConfig {
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
		min_confirmations: 3,
	}
}

/// Builds AccountConfig from operator config.
///
/// If the operator config has an account configuration, uses that.
/// Otherwise, defaults to local wallet with SOLVER_PRIVATE_KEY.
fn build_account_config_from_operator(
	account_config: Option<&OperatorAccountConfig>,
) -> AccountConfig {
	// If operator has account config, use it
	if let Some(config) = account_config {
		tracing::info!(
			primary = %config.primary,
			implementations = ?config.implementations.keys().collect::<Vec<_>>(),
			"Using operator account config"
		);
		let mut implementations = HashMap::new();

		for (name, json_value) in &config.implementations {
			let toml_value = json_to_toml(json_value);
			implementations.insert(name.clone(), toml_value);
		}

		return AccountConfig {
			primary: config.primary.clone(),
			implementations,
		};
	}

	tracing::info!("No operator account config found, using default local wallet");
	// Default: local wallet with private key from environment
	let mut implementations = HashMap::new();

	// Read private key from environment variable and trim whitespace
	let private_key = std::env::var("SOLVER_PRIVATE_KEY")
		.map(|k| k.trim().to_string())
		.unwrap_or_else(|_| "${SOLVER_PRIVATE_KEY}".to_string());

	let local_config = toml_table(vec![("private_key", toml::Value::String(private_key))]);
	implementations.insert("local".to_string(), local_config);

	AccountConfig {
		primary: "local".to_string(),
		implementations,
	}
}

/// Builds DiscoveryConfig from operator config.
fn build_discovery_config_from_operator(chain_ids: &[u64]) -> DiscoveryConfig {
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
		("polling_interval_secs", toml::Value::Integer(5)),
	]);
	implementations.insert("onchain_eip7683".to_string(), onchain_config);

	// Offchain discovery - receives orders via HTTP API from aggregators
	let offchain_config = toml_table(vec![
		("api_host", toml::Value::String("0.0.0.0".to_string())),
		("api_port", toml::Value::Integer(8081)),
		("network_ids", network_ids_array),
	]);
	implementations.insert("offchain_eip7683".to_string(), offchain_config);

	DiscoveryConfig { implementations }
}

/// Builds OrderConfig from operator defaults.
fn build_order_config_from_operator() -> OrderConfig {
	let mut implementations = HashMap::new();

	// EIP-7683 order implementation
	implementations.insert(
		"eip7683".to_string(),
		toml::Value::Table(toml::map::Map::new()),
	);

	// Strategy implementations
	let mut strategy_implementations = HashMap::new();
	let simple_strategy_config =
		toml_table(vec![("max_gas_price_gwei", toml::Value::Integer(100))]);
	strategy_implementations.insert("simple".to_string(), simple_strategy_config);

	OrderConfig {
		implementations,
		strategy: StrategyConfig {
			primary: "simple".to_string(),
			implementations: strategy_implementations,
		},
		callback_whitelist: Vec::new(),
		simulate_callbacks: true,
	}
}

/// Builds SettlementConfig from OperatorConfig.
fn build_settlement_config_from_operator(
	operator_config: &OperatorConfig,
	chain_ids: &[u64],
) -> Result<SettlementConfig, MergeError> {
	let mut implementations = HashMap::new();

	match operator_config.settlement.settlement_type {
		OperatorSettlementType::Hyperlane => {
			let hyperlane = operator_config
				.settlement
				.hyperlane
				.as_ref()
				.ok_or_else(|| {
					MergeError::Validation(
						"settlement_type is hyperlane but settlement.hyperlane is missing"
							.to_string(),
					)
				})?;
			let hyperlane_config = build_hyperlane_toml_from_operator(hyperlane, chain_ids);
			implementations.insert("hyperlane".to_string(), hyperlane_config);
		},
		OperatorSettlementType::Direct => {
			let direct = operator_config.settlement.direct.as_ref().ok_or_else(|| {
				MergeError::Validation(
					"settlement_type is direct but settlement.direct is missing".to_string(),
				)
			})?;
			let direct_config = build_direct_toml_from_operator(direct, chain_ids);
			implementations.insert("direct".to_string(), direct_config);
		},
	}

	Ok(SettlementConfig {
		implementations,
		settlement_poll_interval_seconds: operator_config
			.settlement
			.settlement_poll_interval_seconds,
	})
}

/// Builds Hyperlane toml config from OperatorHyperlaneConfig.
fn build_hyperlane_toml_from_operator(
	hyperlane: &OperatorHyperlaneConfig,
	chain_ids: &[u64],
) -> toml::Value {
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
		toml::Value::Integer(hyperlane.default_gas_limit as i64),
	);
	table.insert(
		"message_timeout_seconds".to_string(),
		toml::Value::Integer(hyperlane.message_timeout_seconds as i64),
	);
	table.insert(
		"finalization_required".to_string(),
		toml::Value::Boolean(hyperlane.finalization_required),
	);

	// Build oracles map
	let mut input_oracles = toml::map::Map::new();
	let mut output_oracles = toml::map::Map::new();

	for (chain_id, oracles) in &hyperlane.oracles.input {
		let oracle_array = toml::Value::Array(
			oracles
				.iter()
				.map(|addr| toml::Value::String(format!("0x{}", hex::encode(addr))))
				.collect(),
		);
		input_oracles.insert(chain_id.to_string(), oracle_array);
	}

	for (chain_id, oracles) in &hyperlane.oracles.output {
		let oracle_array = toml::Value::Array(
			oracles
				.iter()
				.map(|addr| toml::Value::String(format!("0x{}", hex::encode(addr))))
				.collect(),
		);
		output_oracles.insert(chain_id.to_string(), oracle_array);
	}

	let mut oracles = toml::map::Map::new();
	oracles.insert("input".to_string(), toml::Value::Table(input_oracles));
	oracles.insert("output".to_string(), toml::Value::Table(output_oracles));
	table.insert("oracles".to_string(), toml::Value::Table(oracles));

	// Build routes
	let mut routes = toml::map::Map::new();
	for (chain_id, destinations) in &hyperlane.routes {
		let dest_array = toml::Value::Array(
			destinations
				.iter()
				.map(|c| toml::Value::Integer(*c as i64))
				.collect(),
		);
		routes.insert(chain_id.to_string(), dest_array);
	}
	table.insert("routes".to_string(), toml::Value::Table(routes));

	// Build mailboxes map
	let mut mailboxes = toml::map::Map::new();
	for (chain_id, addr) in &hyperlane.mailboxes {
		mailboxes.insert(
			chain_id.to_string(),
			toml::Value::String(format!("0x{}", hex::encode(addr))),
		);
	}
	table.insert("mailboxes".to_string(), toml::Value::Table(mailboxes));

	// Build IGP addresses map
	let mut igp_addresses = toml::map::Map::new();
	for (chain_id, addr) in &hyperlane.igp_addresses {
		igp_addresses.insert(
			chain_id.to_string(),
			toml::Value::String(format!("0x{}", hex::encode(addr))),
		);
	}
	table.insert(
		"igp_addresses".to_string(),
		toml::Value::Table(igp_addresses),
	);

	toml::Value::Table(table)
}

/// Builds direct settlement toml config from OperatorDirectConfig.
fn build_direct_toml_from_operator(
	direct: &OperatorDirectConfig,
	chain_ids: &[u64],
) -> toml::Value {
	let mut table = toml::map::Map::new();

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
		"dispute_period_seconds".to_string(),
		toml::Value::Integer(direct.dispute_period_seconds as i64),
	);
	table.insert(
		"oracle_selection_strategy".to_string(),
		toml::Value::String(match direct.oracle_selection_strategy {
			OperatorOracleSelectionStrategy::First => "First".to_string(),
			OperatorOracleSelectionStrategy::RoundRobin => "RoundRobin".to_string(),
			OperatorOracleSelectionStrategy::Random => "Random".to_string(),
		}),
	);

	let mut input_oracles = toml::map::Map::new();
	for (chain_id, oracles) in &direct.oracles.input {
		let oracle_array = toml::Value::Array(
			oracles
				.iter()
				.map(|addr| toml::Value::String(format!("0x{}", hex::encode(addr))))
				.collect(),
		);
		input_oracles.insert(chain_id.to_string(), oracle_array);
	}

	let mut output_oracles = toml::map::Map::new();
	for (chain_id, oracles) in &direct.oracles.output {
		let oracle_array = toml::Value::Array(
			oracles
				.iter()
				.map(|addr| toml::Value::String(format!("0x{}", hex::encode(addr))))
				.collect(),
		);
		output_oracles.insert(chain_id.to_string(), oracle_array);
	}

	let mut oracles = toml::map::Map::new();
	oracles.insert("input".to_string(), toml::Value::Table(input_oracles));
	oracles.insert("output".to_string(), toml::Value::Table(output_oracles));
	table.insert("oracles".to_string(), toml::Value::Table(oracles));

	let mut routes = toml::map::Map::new();
	for (chain_id, destinations) in &direct.routes {
		let dest_array = toml::Value::Array(
			destinations
				.iter()
				.map(|c| toml::Value::Integer(*c as i64))
				.collect(),
		);
		routes.insert(chain_id.to_string(), dest_array);
	}
	table.insert("routes".to_string(), toml::Value::Table(routes));

	toml::Value::Table(table)
}

/// Builds PricingConfig from OperatorPricingConfig.
fn build_pricing_config_from_operator(pricing: &OperatorPricingConfig) -> PricingConfig {
	let mut implementations = HashMap::new();

	// CoinGecko implementation
	let coingecko_config = toml_table(vec![
		(
			"cache_duration_seconds",
			toml::Value::Integer(pricing.cache_duration_seconds as i64),
		),
		("rate_limit_delay_ms", toml::Value::Integer(1200)),
	]);
	implementations.insert("coingecko".to_string(), coingecko_config);

	// DefiLlama implementation
	let defillama_config = toml_table(vec![(
		"cache_duration_seconds",
		toml::Value::Integer(pricing.cache_duration_seconds as i64),
	)]);
	implementations.insert("defillama".to_string(), defillama_config);

	PricingConfig {
		primary: pricing.primary.clone(),
		fallbacks: pricing.fallbacks.clone(),
		implementations,
	}
}

/// Builds GasConfig from OperatorGasConfig.
fn build_gas_config_from_operator(gas: &OperatorGasConfig) -> GasConfig {
	let mut flows = HashMap::new();

	flows.insert(
		"resource_lock".to_string(),
		GasFlowUnits {
			open: Some(gas.resource_lock.open),
			fill: Some(gas.resource_lock.fill),
			claim: Some(gas.resource_lock.claim),
		},
	);

	flows.insert(
		"permit2_escrow".to_string(),
		GasFlowUnits {
			open: Some(gas.permit2_escrow.open),
			fill: Some(gas.permit2_escrow.fill),
			claim: Some(gas.permit2_escrow.claim),
		},
	);

	flows.insert(
		"eip3009_escrow".to_string(),
		GasFlowUnits {
			open: Some(gas.eip3009_escrow.open),
			fill: Some(gas.eip3009_escrow.fill),
			claim: Some(gas.eip3009_escrow.claim),
		},
	);

	GasConfig { flows }
}

/// Builds ApiConfig from OperatorAdminConfig.
fn build_api_config_from_operator(
	admin: &OperatorAdminConfig,
	auth_enabled: bool,
) -> Result<ApiConfig, MergeError> {
	let auth = if admin.enabled || auth_enabled {
		// Read JWT secret from environment variable
		let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| {
			tracing::warn!(
				"JWT_SECRET not set - using random secret. Tokens will be invalid after restart!"
			);
			uuid::Uuid::new_v4().to_string()
		});
		let public_register_enabled = load_public_register_enabled(auth_enabled)?;

		let admin_config = if admin.enabled {
			Some(solver_types::AdminConfig {
				enabled: admin.enabled,
				domain: admin.domain.clone(),
				chain_id: Some(admin.chain_id),
				nonce_ttl_seconds: admin.nonce_ttl_seconds,
				admin_addresses: admin.admin_addresses.clone(),
			})
		} else {
			None
		};

		Some(solver_types::AuthConfig {
			enabled: auth_enabled,
			jwt_secret: solver_types::SecretString::new(jwt_secret),
			access_token_expiry_hours: 1,
			refresh_token_expiry_hours: 720, // 30 days
			issuer: "oif-solver".to_string(),
			public_register_enabled,
			admin: admin_config,
		})
	} else {
		None
	};

	Ok(ApiConfig {
		enabled: true,
		host: "0.0.0.0".to_string(),
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
	})
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
			name: Some(t.name.clone().unwrap_or_else(|| t.symbol.clone())),
			decimals: t.decimals,
		})
		.collect();

	NetworkConfig {
		name: Some(
			override_
				.name
				.clone()
				.filter(|n| !n.trim().is_empty())
				.unwrap_or_else(|| seed.name.to_string()),
		),
		network_type: override_.network_type.unwrap_or(NetworkType::New),
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
fn build_solver_config(
	solver_id: &str,
	defaults: &SeedDefaults,
	min_profitability_override: Option<Decimal>,
	gas_buffer_bps_override: Option<u32>,
	commission_bps_override: Option<u32>,
	rate_buffer_bps_override: Option<u32>,
) -> SolverConfig {
	SolverConfig {
		id: solver_id.to_string(),
		min_profitability_pct: min_profitability_override.unwrap_or(defaults.min_profitability_pct),
		gas_buffer_bps: gas_buffer_bps_override.unwrap_or(1000),
		commission_bps: commission_bps_override.unwrap_or(defaults.commission_bps),
		rate_buffer_bps: rate_buffer_bps_override.unwrap_or(defaults.rate_buffer_bps),
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
///
/// Uses `solver_id` as the Redis key prefix to isolate storage per solver instance.
fn build_storage_config(defaults: &SeedDefaults, solver_id: &str) -> StorageConfig {
	let mut implementations = HashMap::new();

	// Read Redis URL from environment variable with default fallback
	let redis_url =
		std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

	// Redis implementation config
	// Use solver_id as key_prefix to isolate storage per solver instance
	let redis_config = toml_table(vec![
		("redis_url", toml::Value::String(redis_url)),
		("key_prefix", toml::Value::String(solver_id.to_string())),
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
///
/// If account_override is provided, only the specified implementations are included.
/// Otherwise, defaults to local wallet with SOLVER_PRIVATE_KEY.
fn build_account_config(
	defaults: &SeedDefaults,
	account_override: Option<&AccountOverride>,
) -> AccountConfig {
	// If account override is provided, use it instead of defaults
	if let Some(override_config) = account_override {
		let mut implementations = HashMap::new();

		for (name, config) in &override_config.implementations {
			// Convert serde_json::Value to toml::Value
			let toml_value = json_to_toml(config);
			implementations.insert(name.clone(), toml_value);
		}

		return AccountConfig {
			primary: override_config.primary.clone(),
			implementations,
		};
	}

	// Default: local wallet with private key from environment
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

/// Converts a serde_json::Value to a toml::Value.
fn json_to_toml(json: &serde_json::Value) -> toml::Value {
	match json {
		serde_json::Value::Null => toml::Value::String("".to_string()),
		serde_json::Value::Bool(b) => toml::Value::Boolean(*b),
		serde_json::Value::Number(n) => {
			if let Some(i) = n.as_i64() {
				toml::Value::Integer(i)
			} else if let Some(f) = n.as_f64() {
				toml::Value::Float(f)
			} else {
				toml::Value::String(n.to_string())
			}
		},
		serde_json::Value::String(s) => toml::Value::String(s.clone()),
		serde_json::Value::Array(arr) => toml::Value::Array(arr.iter().map(json_to_toml).collect()),
		serde_json::Value::Object(obj) => {
			let mut table = toml::map::Map::new();
			for (k, v) in obj {
				table.insert(k.clone(), json_to_toml(v));
			}
			toml::Value::Table(table)
		},
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
		("api_host", toml::Value::String("0.0.0.0".to_string())),
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
	auth_enabled: Option<bool>,
) -> Result<ApiConfig, MergeError> {
	// Build auth config if admin is configured or auth is enabled
	// Note: `auth.enabled` controls JWT requirement for /orders endpoint
	// Admin auth (wallet signatures for /admin/*) is controlled separately by `auth.admin.enabled`
	let auth = if admin_override.is_some() || auth_enabled.unwrap_or(false) {
		use solver_types::{AdminConfig, AuthConfig, SecretString};

		// Read JWT secret from environment variable
		let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| {
			tracing::warn!(
				"JWT_SECRET not set - using random secret. Tokens will be invalid after restart!"
			);
			uuid::Uuid::new_v4().to_string()
		});
		let public_register_enabled = load_public_register_enabled(auth_enabled.unwrap_or(false))?;

		let admin_config = admin_override.map(|admin| AdminConfig {
			enabled: admin.enabled,
			domain: admin.domain.clone(),
			chain_id: admin.chain_id,
			nonce_ttl_seconds: admin.nonce_ttl_seconds.unwrap_or(300),
			admin_addresses: admin.admin_addresses.clone(),
		});

		Some(AuthConfig {
			enabled: auth_enabled.unwrap_or(false),
			jwt_secret: SecretString::new(jwt_secret),
			access_token_expiry_hours: 1,
			refresh_token_expiry_hours: 720, // 30 days
			issuer: "oif-solver".to_string(),
			public_register_enabled,
			admin: admin_config,
		})
	} else {
		None
	};

	Ok(ApiConfig {
		enabled: true,
		host: "0.0.0.0".to_string(),
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
	})
}

/// Converts an existing Config to OperatorConfig.
///
/// This is a backward-compatibility helper that extracts the modifiable
/// configuration from an existing Config struct. Used when the solver
/// already has a Config loaded from Redis but needs to convert it to
/// OperatorConfig for admin API persistence.
///
/// Note: Some information (like Hyperlane addresses) may be incomplete
/// as Config stores them in toml format. The function does best-effort
/// extraction.
pub fn config_to_operator_config(config: &Config) -> Result<OperatorConfig, MergeError> {
	use alloy_primitives::Address;

	let chain_ids: Vec<u64> = config.networks.keys().copied().collect();

	// Build operator networks from Config networks
	let mut networks = HashMap::new();
	for (chain_id, network_config) in &config.networks {
		let tokens = network_config
			.tokens
			.iter()
			.map(|t| {
				let addr_bytes: [u8; 20] = t.address.0.as_slice().try_into().unwrap_or([0u8; 20]);
				OperatorToken {
					symbol: t.symbol.clone(),
					name: t.name.clone(),
					address: Address::from(addr_bytes),
					decimals: t.decimals,
				}
			})
			.collect();

		let rpc_urls = network_config
			.rpc_urls
			.iter()
			.filter_map(|r| {
				r.http.as_ref().map(|http| OperatorRpcEndpoint {
					http: http.clone(),
					ws: r.ws.clone(),
				})
			})
			.collect();

		let input_settler_bytes: [u8; 20] = network_config
			.input_settler_address
			.0
			.as_slice()
			.try_into()
			.unwrap_or([0u8; 20]);
		let output_settler_bytes: [u8; 20] = network_config
			.output_settler_address
			.0
			.as_slice()
			.try_into()
			.unwrap_or([0u8; 20]);

		let input_settler_compact_address = network_config
			.input_settler_compact_address
			.as_ref()
			.and_then(|a| {
				let bytes: [u8; 20] = a.0.as_slice().try_into().ok()?;
				Some(Address::from(bytes))
			});
		let the_compact_address = network_config.the_compact_address.as_ref().and_then(|a| {
			let bytes: [u8; 20] = a.0.as_slice().try_into().ok()?;
			Some(Address::from(bytes))
		});
		let allocator_address = network_config.allocator_address.as_ref().and_then(|a| {
			let bytes: [u8; 20] = a.0.as_slice().try_into().ok()?;
			Some(Address::from(bytes))
		});

		let op_network = OperatorNetworkConfig {
			chain_id: *chain_id,
			name: network_config
				.name
				.clone()
				.filter(|n| !n.trim().is_empty())
				.unwrap_or_else(|| format!("chain-{chain_id}")),
			network_type: network_config.network_type,
			tokens,
			rpc_urls,
			input_settler_address: Address::from(input_settler_bytes),
			output_settler_address: Address::from(output_settler_bytes),
			input_settler_compact_address,
			the_compact_address,
			allocator_address,
		};

		networks.insert(*chain_id, op_network);
	}

	// Extract selected settlement implementation from runtime config.
	let (settlement_type, hyperlane, direct) =
		if config.settlement.implementations.contains_key("direct") {
			(
				OperatorSettlementType::Direct,
				None,
				Some(extract_direct_config(&config.settlement, &chain_ids)),
			)
		} else {
			(
				OperatorSettlementType::Hyperlane,
				Some(extract_hyperlane_config(&config.settlement, &chain_ids)),
				None,
			)
		};

	// Extract gas config
	let gas = config
		.gas
		.as_ref()
		.map(|g| OperatorGasConfig {
			resource_lock: g
				.flows
				.get("resource_lock")
				.map(|f| OperatorGasFlowUnits {
					open: f.open.unwrap_or(0),
					fill: f.fill.unwrap_or(0),
					claim: f.claim.unwrap_or(0),
				})
				.unwrap_or_default(),
			permit2_escrow: g
				.flows
				.get("permit2_escrow")
				.map(|f| OperatorGasFlowUnits {
					open: f.open.unwrap_or(0),
					fill: f.fill.unwrap_or(0),
					claim: f.claim.unwrap_or(0),
				})
				.unwrap_or_default(),
			eip3009_escrow: g
				.flows
				.get("eip3009_escrow")
				.map(|f| OperatorGasFlowUnits {
					open: f.open.unwrap_or(0),
					fill: f.fill.unwrap_or(0),
					claim: f.claim.unwrap_or(0),
				})
				.unwrap_or_default(),
		})
		.unwrap_or(OperatorGasConfig {
			resource_lock: OperatorGasFlowUnits::default(),
			permit2_escrow: OperatorGasFlowUnits::default(),
			eip3009_escrow: OperatorGasFlowUnits::default(),
		});

	// Extract pricing config
	let pricing = config
		.pricing
		.as_ref()
		.map(|p| OperatorPricingConfig {
			primary: p.primary.clone(),
			fallbacks: p.fallbacks.clone(),
			cache_duration_seconds: 60, // Default
			custom_prices: HashMap::new(),
		})
		.unwrap_or(OperatorPricingConfig {
			primary: "coingecko".to_string(),
			fallbacks: vec!["defillama".to_string()],
			cache_duration_seconds: 60,
			custom_prices: HashMap::new(),
		});

	// Extract admin config
	let admin = config
		.api
		.as_ref()
		.and_then(|api| api.auth.as_ref())
		.and_then(|auth| auth.admin.as_ref())
		.map(|a| OperatorAdminConfig {
			enabled: a.enabled,
			domain: a.domain.clone(),
			chain_id: a
				.chain_id
				.unwrap_or(chain_ids.first().copied().unwrap_or(1)),
			nonce_ttl_seconds: a.nonce_ttl_seconds,
			admin_addresses: a.admin_addresses.clone(),
			withdrawals: OperatorWithdrawalsConfig::default(),
		})
		.unwrap_or_default();

	let auth_enabled = config
		.api
		.as_ref()
		.and_then(|api| api.auth.as_ref())
		.map(|auth| auth.enabled)
		.unwrap_or(false);

	// Extract account config - only set if not using default local wallet
	let account = extract_account_config(&config.account);

	Ok(OperatorConfig {
		solver_id: config.solver.id.clone(),
		solver_name: Some(config.solver.id.clone()),
		networks,
		settlement: OperatorSettlementConfig {
			settlement_poll_interval_seconds: config.settlement.settlement_poll_interval_seconds,
			settlement_type,
			hyperlane,
			direct,
		},
		gas,
		pricing,
		solver: OperatorSolverConfig {
			min_profitability_pct: config.solver.min_profitability_pct,
			gas_buffer_bps: config.solver.gas_buffer_bps,
			commission_bps: config.solver.commission_bps,
			rate_buffer_bps: config.solver.rate_buffer_bps,
			monitoring_timeout_seconds: config.solver.monitoring_timeout_seconds,
		},
		admin,
		auth_enabled,
		account,
	})
}

/// Extracts account config from AccountConfig.
/// Returns None if using default local wallet, Some(...) for other implementations.
fn extract_account_config(account: &AccountConfig) -> Option<OperatorAccountConfig> {
	// If primary is "local", return None to use default behavior
	if account.primary == "local" {
		return None;
	}

	// Convert toml implementations to JSON
	let implementations = account
		.implementations
		.iter()
		.map(|(name, toml_value)| {
			let json_value = toml_to_json(toml_value);
			(name.clone(), json_value)
		})
		.collect();

	Some(OperatorAccountConfig {
		primary: account.primary.clone(),
		implementations,
	})
}

/// Converts a toml::Value to a serde_json::Value.
fn toml_to_json(toml: &toml::Value) -> serde_json::Value {
	match toml {
		toml::Value::String(s) => serde_json::Value::String(s.clone()),
		toml::Value::Integer(i) => serde_json::Value::Number((*i).into()),
		toml::Value::Float(f) => serde_json::Number::from_f64(*f)
			.map(serde_json::Value::Number)
			.unwrap_or(serde_json::Value::Null),
		toml::Value::Boolean(b) => serde_json::Value::Bool(*b),
		toml::Value::Datetime(dt) => serde_json::Value::String(dt.to_string()),
		toml::Value::Array(arr) => serde_json::Value::Array(arr.iter().map(toml_to_json).collect()),
		toml::Value::Table(table) => {
			let map: serde_json::Map<String, serde_json::Value> = table
				.iter()
				.map(|(k, v)| (k.clone(), toml_to_json(v)))
				.collect();
			serde_json::Value::Object(map)
		},
	}
}

/// Extracts Hyperlane config from settlement toml config.
fn extract_hyperlane_config(
	settlement: &SettlementConfig,
	chain_ids: &[u64],
) -> OperatorHyperlaneConfig {
	use alloy_primitives::Address;

	let hyperlane_toml = settlement.implementations.get("hyperlane");

	// Helper to parse address from hex string
	let parse_addr = |s: &str| -> Option<Address> {
		let s = s.strip_prefix("0x").unwrap_or(s);
		hex::decode(s).ok().and_then(|bytes| {
			let arr: [u8; 20] = bytes.as_slice().try_into().ok()?;
			Some(Address::from(arr))
		})
	};

	let default_gas_limit = hyperlane_toml
		.and_then(|h| h.get("default_gas_limit"))
		.and_then(|v| v.as_integer())
		.unwrap_or(300_000) as u64;

	let message_timeout_seconds = hyperlane_toml
		.and_then(|h| h.get("message_timeout_seconds"))
		.and_then(|v| v.as_integer())
		.unwrap_or(600) as u64;

	let finalization_required = hyperlane_toml
		.and_then(|h| h.get("finalization_required"))
		.and_then(|v| v.as_bool())
		.unwrap_or(true);

	// Extract mailboxes
	let mut mailboxes = HashMap::new();
	if let Some(toml_mailboxes) = hyperlane_toml
		.and_then(|h| h.get("mailboxes"))
		.and_then(|v| v.as_table())
	{
		for (chain_id_str, addr_val) in toml_mailboxes {
			if let (Ok(chain_id), Some(addr_str)) = (chain_id_str.parse::<u64>(), addr_val.as_str())
			{
				if let Some(addr) = parse_addr(addr_str) {
					mailboxes.insert(chain_id, addr);
				}
			}
		}
	}

	// Extract IGP addresses
	let mut igp_addresses = HashMap::new();
	if let Some(toml_igp) = hyperlane_toml
		.and_then(|h| h.get("igp_addresses"))
		.and_then(|v| v.as_table())
	{
		for (chain_id_str, addr_val) in toml_igp {
			if let (Ok(chain_id), Some(addr_str)) = (chain_id_str.parse::<u64>(), addr_val.as_str())
			{
				if let Some(addr) = parse_addr(addr_str) {
					igp_addresses.insert(chain_id, addr);
				}
			}
		}
	}

	// Extract oracles
	let mut input_oracles = HashMap::new();
	let mut output_oracles = HashMap::new();
	if let Some(toml_oracles) = hyperlane_toml
		.and_then(|h| h.get("oracles"))
		.and_then(|v| v.as_table())
	{
		if let Some(input_table) = toml_oracles.get("input").and_then(|v| v.as_table()) {
			for (chain_id_str, addrs_val) in input_table {
				if let (Ok(chain_id), Some(addrs_array)) =
					(chain_id_str.parse::<u64>(), addrs_val.as_array())
				{
					let addrs: Vec<Address> = addrs_array
						.iter()
						.filter_map(|v| v.as_str().and_then(parse_addr))
						.collect();
					if !addrs.is_empty() {
						input_oracles.insert(chain_id, addrs);
					}
				}
			}
		}
		if let Some(output_table) = toml_oracles.get("output").and_then(|v| v.as_table()) {
			for (chain_id_str, addrs_val) in output_table {
				if let (Ok(chain_id), Some(addrs_array)) =
					(chain_id_str.parse::<u64>(), addrs_val.as_array())
				{
					let addrs: Vec<Address> = addrs_array
						.iter()
						.filter_map(|v| v.as_str().and_then(parse_addr))
						.collect();
					if !addrs.is_empty() {
						output_oracles.insert(chain_id, addrs);
					}
				}
			}
		}
	}

	// Extract routes
	let mut routes = HashMap::new();
	if let Some(toml_routes) = hyperlane_toml
		.and_then(|h| h.get("routes"))
		.and_then(|v| v.as_table())
	{
		for (chain_id_str, dests_val) in toml_routes {
			if let (Ok(chain_id), Some(dests_array)) =
				(chain_id_str.parse::<u64>(), dests_val.as_array())
			{
				let dests: Vec<u64> = dests_array
					.iter()
					.filter_map(|v| v.as_integer().map(|i| i as u64))
					.collect();
				routes.insert(chain_id, dests);
			}
		}
	}

	// If routes is empty, build default routes (each chain to all others)
	if routes.is_empty() {
		for chain_id in chain_ids {
			let other_chains: Vec<u64> = chain_ids
				.iter()
				.filter(|c| *c != chain_id)
				.copied()
				.collect();
			routes.insert(*chain_id, other_chains);
		}
	}

	OperatorHyperlaneConfig {
		default_gas_limit,
		message_timeout_seconds,
		finalization_required,
		mailboxes,
		igp_addresses,
		oracles: OperatorOracleConfig {
			input: input_oracles,
			output: output_oracles,
		},
		routes,
	}
}

/// Extracts direct settlement config from settlement toml config.
fn extract_direct_config(settlement: &SettlementConfig, chain_ids: &[u64]) -> OperatorDirectConfig {
	use alloy_primitives::Address;

	let direct_toml = settlement.implementations.get("direct");

	// Helper to parse address from hex string
	let parse_addr = |s: &str| -> Option<Address> {
		let s = s.strip_prefix("0x").unwrap_or(s);
		hex::decode(s).ok().and_then(|bytes| {
			let arr: [u8; 20] = bytes.as_slice().try_into().ok()?;
			Some(Address::from(arr))
		})
	};

	let dispute_period_seconds = direct_toml
		.and_then(|d| d.get("dispute_period_seconds"))
		.and_then(|v| v.as_integer())
		.unwrap_or(300) as u64;

	let oracle_selection_strategy = direct_toml
		.and_then(|d| d.get("oracle_selection_strategy"))
		.and_then(|v| v.as_str())
		.map(|s| match s {
			"RoundRobin" => OperatorOracleSelectionStrategy::RoundRobin,
			"Random" => OperatorOracleSelectionStrategy::Random,
			_ => OperatorOracleSelectionStrategy::First,
		})
		.unwrap_or(OperatorOracleSelectionStrategy::First);

	let mut input_oracles = HashMap::new();
	let mut output_oracles = HashMap::new();
	if let Some(toml_oracles) = direct_toml
		.and_then(|d| d.get("oracles"))
		.and_then(|v| v.as_table())
	{
		if let Some(input_table) = toml_oracles.get("input").and_then(|v| v.as_table()) {
			for (chain_id_str, addrs_val) in input_table {
				if let (Ok(chain_id), Some(addrs_array)) =
					(chain_id_str.parse::<u64>(), addrs_val.as_array())
				{
					let addrs: Vec<Address> = addrs_array
						.iter()
						.filter_map(|v| v.as_str().and_then(parse_addr))
						.collect();
					if !addrs.is_empty() {
						input_oracles.insert(chain_id, addrs);
					}
				}
			}
		}

		if let Some(output_table) = toml_oracles.get("output").and_then(|v| v.as_table()) {
			for (chain_id_str, addrs_val) in output_table {
				if let (Ok(chain_id), Some(addrs_array)) =
					(chain_id_str.parse::<u64>(), addrs_val.as_array())
				{
					let addrs: Vec<Address> = addrs_array
						.iter()
						.filter_map(|v| v.as_str().and_then(parse_addr))
						.collect();
					if !addrs.is_empty() {
						output_oracles.insert(chain_id, addrs);
					}
				}
			}
		}
	}

	let mut routes = HashMap::new();
	if let Some(toml_routes) = direct_toml
		.and_then(|d| d.get("routes"))
		.and_then(|v| v.as_table())
	{
		for (chain_id_str, dests_val) in toml_routes {
			if let (Ok(chain_id), Some(dests_array)) =
				(chain_id_str.parse::<u64>(), dests_val.as_array())
			{
				let dests: Vec<u64> = dests_array
					.iter()
					.filter_map(|v| v.as_integer().map(|i| i as u64))
					.collect();
				routes.insert(chain_id, dests);
			}
		}
	}

	if routes.is_empty() {
		for chain_id in chain_ids {
			let other_chains: Vec<u64> = chain_ids
				.iter()
				.filter(|c| *c != chain_id)
				.copied()
				.collect();
			routes.insert(*chain_id, other_chains);
		}
	}

	OperatorDirectConfig {
		dispute_period_seconds,
		oracles: OperatorOracleConfig {
			input: input_oracles,
			output: output_oracles,
		},
		routes,
		oracle_selection_strategy,
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::seeds::TESTNET_SEED;
	use alloy_primitives::address;
	use rust_decimal::Decimal;
	use serial_test::serial;
	use solver_types::seed_overrides::AdminOverride;
	use std::str::FromStr;

	fn test_seed_overrides() -> SeedOverrides {
		SeedOverrides {
			solver_id: None,
			solver_name: None,
			networks: vec![
				NetworkOverride {
					chain_id: 11155420, // Optimism Sepolia
					name: None,
					network_type: None,
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "USDC".to_string(),
						name: None,
						address: address!("191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6"),
						decimals: 6,
					}],
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
				NetworkOverride {
					chain_id: 84532, // Base Sepolia
					name: None,
					network_type: None,
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "USDC".to_string(),
						name: None,
						address: address!("73c83DAcc74bB8a704717AC09703b959E74b9705"),
						decimals: 6,
					}],
					rpc_urls: Some(vec!["https://custom-rpc.example.com".to_string()]),
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
			],
			account: None,
			admin: None,
			auth_enabled: None,
			min_profitability_pct: None,
			gas_buffer_bps: None,
			commission_bps: None,
			rate_buffer_bps: None,
			settlement: None,
			routing_defaults: None,
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
			solver_name: None,
			networks: vec![
				NetworkOverride {
					chain_id: 999999, // Unknown chain
					name: None,
					network_type: None,
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "TEST".to_string(),
						name: None,
						address: address!("1111111111111111111111111111111111111111"),
						decimals: 18,
					}],
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
				NetworkOverride {
					chain_id: 11155420,
					name: None,
					network_type: None,
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "USDC".to_string(),
						name: None,
						address: address!("191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6"),
						decimals: 6,
					}],
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
			],
			account: None,
			admin: None,
			auth_enabled: None,
			min_profitability_pct: None,
			gas_buffer_bps: None,
			commission_bps: None,
			rate_buffer_bps: None,
			settlement: None,
			routing_defaults: None,
		};

		let result = merge_config(overrides, &TESTNET_SEED);
		assert!(result.is_err());
		assert!(
			matches!(result.unwrap_err(), MergeError::Validation(msg) if msg.contains("Non-seeded chain 999999 is missing required fields"))
		);
	}

	#[test]
	fn test_merge_config_empty_tokens() {
		let overrides = SeedOverrides {
			solver_id: None,
			solver_name: None,
			networks: vec![
				NetworkOverride {
					chain_id: 11155420,
					name: None,
					network_type: None,
					tokens: vec![], // No tokens
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
				NetworkOverride {
					chain_id: 84532,
					name: None,
					network_type: None,
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "USDC".to_string(),
						name: None,
						address: address!("73c83DAcc74bB8a704717AC09703b959E74b9705"),
						decimals: 6,
					}],
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
			],
			account: None,
			admin: None,
			auth_enabled: None,
			min_profitability_pct: None,
			gas_buffer_bps: None,
			commission_bps: None,
			rate_buffer_bps: None,
			settlement: None,
			routing_defaults: None,
		};

		let result = merge_config(overrides, &TESTNET_SEED).unwrap();
		assert_eq!(result.networks.len(), 2);
		assert_eq!(result.networks.get(&11155420).unwrap().tokens.len(), 0);
		assert_eq!(result.networks.get(&84532).unwrap().tokens.len(), 1);
	}

	#[test]
	fn test_merge_config_all_networks_empty_tokens() {
		let overrides = SeedOverrides {
			solver_id: None,
			solver_name: None,
			networks: vec![
				NetworkOverride {
					chain_id: 11155420,
					name: None,
					network_type: None,
					tokens: vec![],
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
				NetworkOverride {
					chain_id: 84532,
					name: None,
					network_type: None,
					tokens: vec![],
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
			],
			account: None,
			admin: None,
			auth_enabled: None,
			min_profitability_pct: None,
			gas_buffer_bps: None,
			commission_bps: None,
			rate_buffer_bps: None,
			settlement: None,
			routing_defaults: None,
		};

		let result = merge_config(overrides, &TESTNET_SEED).unwrap();
		assert_eq!(result.networks.len(), 2);
		assert_eq!(result.networks.get(&11155420).unwrap().tokens.len(), 0);
		assert_eq!(result.networks.get(&84532).unwrap().tokens.len(), 0);
	}

	#[test]
	fn test_merge_config_insufficient_networks() {
		let overrides = SeedOverrides {
			solver_id: None,
			solver_name: None,
			networks: vec![NetworkOverride {
				chain_id: 11155420,
				name: None,
				network_type: None,
				tokens: vec![solver_types::seed_overrides::Token {
					symbol: "USDC".to_string(),
					name: None,
					address: address!("191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6"),
					decimals: 6,
				}],
				rpc_urls: None,
				input_settler_address: None,
				output_settler_address: None,
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			}],
			account: None,
			admin: None,
			auth_enabled: None,
			min_profitability_pct: None,
			gas_buffer_bps: None,
			commission_bps: None,
			rate_buffer_bps: None,
			settlement: None,
			routing_defaults: None,
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
	fn test_merge_config_applies_fee_overrides() {
		use std::str::FromStr;

		// Create overrides with fee configuration
		let overrides = SeedOverrides {
			solver_id: Some("fee-test-solver".to_string()),
			solver_name: None,
			networks: vec![
				NetworkOverride {
					chain_id: 11155420,
					name: None,
					network_type: None,
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "USDC".to_string(),
						name: None,
						address: address!("191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6"),
						decimals: 6,
					}],
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
				NetworkOverride {
					chain_id: 84532,
					name: None,
					network_type: None,
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "USDC".to_string(),
						name: None,
						address: address!("73c83DAcc74bB8a704717AC09703b959E74b9705"),
						decimals: 6,
					}],
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
			],
			account: None,
			admin: None,
			auth_enabled: None,
			min_profitability_pct: Some(Decimal::from_str("2.5").unwrap()), // Override: 2.5%
			gas_buffer_bps: Some(1500),                                     // Override: 15%
			commission_bps: Some(25),                                       // Override: 0.25%
			rate_buffer_bps: Some(30),                                      // Override: 0.30%
			settlement: None,
			routing_defaults: None,
		};

		let config = merge_config(overrides, &TESTNET_SEED).unwrap();

		// Verify min_profitability_pct is applied
		assert_eq!(
			config.solver.min_profitability_pct,
			Decimal::from_str("2.5").unwrap()
		);

		// Verify gas_buffer_bps is applied
		assert_eq!(config.solver.gas_buffer_bps, 1500);

		// Verify commission_bps is applied
		assert_eq!(config.solver.commission_bps, 25);

		// Verify rate_buffer_bps is applied
		assert_eq!(config.solver.rate_buffer_bps, 30);
	}

	#[test]
	fn test_merge_config_uses_defaults_when_no_fee_overrides() {
		// Test seed overrides without fee configuration uses seed defaults
		let overrides = test_seed_overrides();
		let config = merge_config(overrides, &TESTNET_SEED).unwrap();

		// Should use seed default min_profitability_pct
		assert_eq!(
			config.solver.min_profitability_pct,
			TESTNET_SEED.defaults.min_profitability_pct
		);

		// Should use default gas_buffer_bps (1000 = 10%)
		assert_eq!(config.solver.gas_buffer_bps, 1000);

		// Should use seed default commission_bps
		assert_eq!(
			config.solver.commission_bps,
			TESTNET_SEED.defaults.commission_bps
		);

		// Should use seed default rate_buffer_bps
		assert_eq!(
			config.solver.rate_buffer_bps,
			TESTNET_SEED.defaults.rate_buffer_bps
		);
	}

	#[test]
	fn test_settlement_config_has_hyperlane() {
		let overrides = test_seed_overrides();
		let config = merge_config(overrides, &TESTNET_SEED).unwrap();

		assert!(config.settlement.implementations.contains_key("hyperlane"));
		assert!(!config.settlement.implementations.contains_key("direct"));

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
			solver_name: None,
			networks: vec![
				NetworkOverride {
					chain_id: 11155420,
					name: None,
					network_type: None,
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "USDC".to_string(),
						name: None,
						address: address!("191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6"),
						decimals: 6,
					}],
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
				NetworkOverride {
					chain_id: 11155420, // Duplicate!
					name: None,
					network_type: None,
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "DAI".to_string(),
						name: None,
						address: address!("191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6"),
						decimals: 18,
					}],
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
			],
			account: None,
			admin: None,
			auth_enabled: None,
			min_profitability_pct: None,
			gas_buffer_bps: None,
			commission_bps: None,
			rate_buffer_bps: None,
			settlement: None,
			routing_defaults: None,
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
			solver_name: None,
			networks: vec![
				NetworkOverride {
					chain_id: 11155420,
					name: None,
					network_type: None,
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "USDC".to_string(),
						name: None,
						address: address!("191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6"),
						decimals: 6,
					}],
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
				NetworkOverride {
					chain_id: 84532,
					name: None,
					network_type: None,
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "USDC".to_string(),
						name: None,
						address: address!("73c83DAcc74bB8a704717AC09703b959E74b9705"),
						decimals: 6,
					}],
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
			],
			account: None,
			admin: None,
			auth_enabled: None,
			min_profitability_pct: None,
			gas_buffer_bps: None,
			commission_bps: None,
			rate_buffer_bps: None,
			settlement: None,
			routing_defaults: None,
		};

		let config = merge_config(overrides, &TESTNET_SEED).unwrap();
		assert_eq!(config.solver.id, "my-custom-solver");
	}

	// ===== Tests for merge_to_operator_config =====

	#[test]
	fn test_merge_to_operator_config_success() {
		let overrides = test_seed_overrides();
		let result = merge_to_operator_config(overrides, &TESTNET_SEED);

		assert!(result.is_ok());
		let op_config = result.unwrap();

		// Check solver ID is auto-generated
		assert!(op_config.solver_id.starts_with("solver-"));
		assert_eq!(op_config.solver_name, Some(op_config.solver_id.clone()));

		// Check networks
		assert_eq!(op_config.networks.len(), 2);
		assert!(op_config.networks.contains_key(&11155420));
		assert!(op_config.networks.contains_key(&84532));

		// Check network details
		let opt_network = op_config.networks.get(&11155420).unwrap();
		assert_eq!(opt_network.chain_id, 11155420);
		assert_eq!(opt_network.name, "optimism-sepolia");
		assert_eq!(opt_network.network_type, NetworkType::New);
		assert_eq!(opt_network.tokens.len(), 1);
		assert_eq!(opt_network.tokens[0].symbol, "USDC");
		assert_eq!(opt_network.tokens[0].name, Some("USDC".to_string()));
	}

	#[test]
	fn test_merge_to_operator_config_with_custom_solver_id() {
		let overrides = SeedOverrides {
			solver_id: Some("my-operator-solver".to_string()),
			solver_name: None,
			networks: vec![
				NetworkOverride {
					chain_id: 11155420,
					name: None,
					network_type: None,
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "USDC".to_string(),
						name: None,
						address: address!("191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6"),
						decimals: 6,
					}],
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
				NetworkOverride {
					chain_id: 84532,
					name: None,
					network_type: None,
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "USDC".to_string(),
						name: None,
						address: address!("73c83DAcc74bB8a704717AC09703b959E74b9705"),
						decimals: 6,
					}],
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
			],
			account: None,
			admin: None,
			auth_enabled: None,
			min_profitability_pct: None,
			gas_buffer_bps: None,
			commission_bps: None,
			rate_buffer_bps: None,
			settlement: None,
			routing_defaults: None,
		};

		let op_config = merge_to_operator_config(overrides, &TESTNET_SEED).unwrap();
		assert_eq!(op_config.solver_id, "my-operator-solver");
		assert_eq!(
			op_config.solver_name,
			Some("my-operator-solver".to_string())
		);
	}

	#[test]
	fn test_merge_to_operator_config_preserves_names_and_network_type() {
		let overrides = SeedOverrides {
			solver_id: Some("my-operator-solver".to_string()),
			solver_name: Some("Operator Alpha".to_string()),
			networks: vec![
				NetworkOverride {
					chain_id: 11155420,
					name: Some("Optimism Sepolia Parent".to_string()),
					network_type: Some(NetworkType::Parent),
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "USDC".to_string(),
						name: Some("USD Coin".to_string()),
						address: address!("191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6"),
						decimals: 6,
					}],
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
				NetworkOverride {
					chain_id: 84532,
					name: Some("Base Sepolia Hub".to_string()),
					network_type: Some(NetworkType::Hub),
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "USDC".to_string(),
						name: Some("USD Coin".to_string()),
						address: address!("73c83DAcc74bB8a704717AC09703b959E74b9705"),
						decimals: 6,
					}],
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
			],
			account: None,
			admin: None,
			auth_enabled: None,
			min_profitability_pct: None,
			gas_buffer_bps: None,
			commission_bps: None,
			rate_buffer_bps: None,
			settlement: None,
			routing_defaults: None,
		};

		let op_config = merge_to_operator_config(overrides, &TESTNET_SEED).unwrap();
		assert_eq!(op_config.solver_name, Some("Operator Alpha".to_string()));

		let origin = op_config.networks.get(&11155420).unwrap();
		assert_eq!(origin.name, "Optimism Sepolia Parent");
		assert_eq!(origin.network_type, NetworkType::Parent);
		assert_eq!(origin.tokens[0].name, Some("USD Coin".to_string()));

		let destination = op_config.networks.get(&84532).unwrap();
		assert_eq!(destination.name, "Base Sepolia Hub");
		assert_eq!(destination.network_type, NetworkType::Hub);
		assert_eq!(destination.tokens[0].name, Some("USD Coin".to_string()));
	}

	#[test]
	fn test_merge_to_operator_config_unknown_chain() {
		let overrides = SeedOverrides {
			solver_id: None,
			solver_name: None,
			networks: vec![
				NetworkOverride {
					chain_id: 999999,
					name: None,
					network_type: None,
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "TEST".to_string(),
						name: None,
						address: address!("1111111111111111111111111111111111111111"),
						decimals: 18,
					}],
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
				NetworkOverride {
					chain_id: 11155420,
					name: None,
					network_type: None,
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "USDC".to_string(),
						name: None,
						address: address!("191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6"),
						decimals: 6,
					}],
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
			],
			account: None,
			admin: None,
			auth_enabled: None,
			min_profitability_pct: None,
			gas_buffer_bps: None,
			commission_bps: None,
			rate_buffer_bps: None,
			settlement: None,
			routing_defaults: None,
		};

		let result = merge_to_operator_config(overrides, &TESTNET_SEED);
		assert!(result.is_err());
		assert!(
			matches!(result.unwrap_err(), MergeError::Validation(msg) if msg.contains("Non-seeded chain 999999 is missing required fields"))
		);
	}

	#[test]
	fn test_merge_to_operator_config_non_seeded_chain_with_hyperlane_override() {
		let non_seed_chain_id = 123456u64;
		let overrides = SeedOverrides {
			solver_id: None,
			solver_name: None,
			networks: vec![
				NetworkOverride {
					chain_id: 11155420,
					name: None,
					network_type: None,
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "USDC".to_string(),
						name: None,
						address: address!("191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6"),
						decimals: 6,
					}],
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
				NetworkOverride {
					chain_id: non_seed_chain_id,
					name: Some("custom-l2".to_string()),
					network_type: Some(NetworkType::New),
					tokens: vec![],
					rpc_urls: Some(vec!["https://rpc.custom-l2.example".to_string()]),
					input_settler_address: Some(address!(
						"1000000000000000000000000000000000000001"
					)),
					output_settler_address: Some(address!(
						"2000000000000000000000000000000000000002"
					)),
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
			],
			settlement: Some(solver_types::SettlementOverride {
				settlement_type: SettlementTypeOverride::Hyperlane,
				hyperlane: Some(HyperlaneSettlementOverride {
					mailboxes: HashMap::from([
						(
							11155420,
							address!("3000000000000000000000000000000000000003"),
						),
						(
							non_seed_chain_id,
							address!("4000000000000000000000000000000000000004"),
						),
					]),
					igp_addresses: HashMap::from([
						(
							11155420,
							address!("5000000000000000000000000000000000000005"),
						),
						(
							non_seed_chain_id,
							address!("6000000000000000000000000000000000000006"),
						),
					]),
					oracles: solver_types::OracleOverrides {
						input: HashMap::from([
							(
								11155420,
								vec![address!("7000000000000000000000000000000000000007")],
							),
							(
								non_seed_chain_id,
								vec![address!("8000000000000000000000000000000000000008")],
							),
						]),
						output: HashMap::from([
							(
								11155420,
								vec![address!("7000000000000000000000000000000000000007")],
							),
							(
								non_seed_chain_id,
								vec![address!("8000000000000000000000000000000000000008")],
							),
						]),
					},
					routes: HashMap::from([
						(11155420, vec![non_seed_chain_id]),
						(non_seed_chain_id, vec![11155420]),
					]),
					default_gas_limit: None,
					message_timeout_seconds: None,
					finalization_required: None,
				}),
				direct: None,
			}),
			routing_defaults: None,
			account: None,
			admin: None,
			auth_enabled: None,
			min_profitability_pct: None,
			gas_buffer_bps: None,
			commission_bps: None,
			rate_buffer_bps: None,
		};

		let op_config = merge_to_operator_config(overrides, &TESTNET_SEED).unwrap();
		let non_seeded = op_config.networks.get(&non_seed_chain_id).unwrap();
		assert_eq!(non_seeded.name, "custom-l2");
		assert_eq!(
			non_seeded.input_settler_address,
			address!("1000000000000000000000000000000000000001")
		);
		assert_eq!(
			op_config.settlement.settlement_type,
			OperatorSettlementType::Hyperlane
		);
		assert!(op_config
			.settlement
			.hyperlane
			.as_ref()
			.unwrap()
			.mailboxes
			.contains_key(&non_seed_chain_id));
	}

	#[test]
	fn test_merge_to_operator_config_seedless_hyperlane_success() {
		let chain_a = 500001u64;
		let chain_b = 500002u64;
		let overrides = SeedOverrides {
			solver_id: None,
			solver_name: None,
			networks: vec![
				NetworkOverride {
					chain_id: chain_a,
					name: Some("seedless-a".to_string()),
					network_type: Some(NetworkType::Parent),
					tokens: vec![],
					rpc_urls: Some(vec!["https://rpc.seedless-a.example".to_string()]),
					input_settler_address: Some(address!(
						"1111111111111111111111111111111111111111"
					)),
					output_settler_address: Some(address!(
						"2222222222222222222222222222222222222222"
					)),
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
				NetworkOverride {
					chain_id: chain_b,
					name: Some("seedless-b".to_string()),
					network_type: Some(NetworkType::Hub),
					tokens: vec![],
					rpc_urls: Some(vec!["https://rpc.seedless-b.example".to_string()]),
					input_settler_address: Some(address!(
						"3333333333333333333333333333333333333333"
					)),
					output_settler_address: Some(address!(
						"4444444444444444444444444444444444444444"
					)),
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
			],
			settlement: Some(solver_types::SettlementOverride {
				settlement_type: SettlementTypeOverride::Hyperlane,
				hyperlane: Some(HyperlaneSettlementOverride {
					mailboxes: HashMap::from([
						(
							chain_a,
							address!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
						),
						(
							chain_b,
							address!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
						),
					]),
					igp_addresses: HashMap::from([
						(
							chain_a,
							address!("cccccccccccccccccccccccccccccccccccccccc"),
						),
						(
							chain_b,
							address!("dddddddddddddddddddddddddddddddddddddddd"),
						),
					]),
					oracles: solver_types::OracleOverrides {
						input: HashMap::from([
							(
								chain_a,
								vec![address!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")],
							),
							(
								chain_b,
								vec![address!("ffffffffffffffffffffffffffffffffffffffff")],
							),
						]),
						output: HashMap::from([
							(
								chain_a,
								vec![address!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")],
							),
							(
								chain_b,
								vec![address!("ffffffffffffffffffffffffffffffffffffffff")],
							),
						]),
					},
					routes: HashMap::new(),
					default_gas_limit: None,
					message_timeout_seconds: None,
					finalization_required: None,
				}),
				direct: None,
			}),
			routing_defaults: None,
			account: None,
			admin: None,
			auth_enabled: None,
			min_profitability_pct: None,
			gas_buffer_bps: None,
			commission_bps: None,
			rate_buffer_bps: None,
		};

		let op_config = merge_to_operator_config_seedless(overrides).unwrap();
		assert!(op_config.solver_id.starts_with("solver-"));
		assert_eq!(
			op_config.settlement.settlement_type,
			OperatorSettlementType::Hyperlane
		);

		let hyperlane = op_config.settlement.hyperlane.unwrap();
		assert_eq!(hyperlane.routes.get(&chain_a), Some(&vec![chain_b]));
		assert_eq!(hyperlane.routes.get(&chain_b), Some(&vec![chain_a]));
		assert_eq!(
			op_config.gas.resource_lock.fill,
			COMMON_DEFAULTS.gas_resource_lock.fill
		);
	}

	#[test]
	fn test_merge_to_operator_config_seedless_missing_required_network_field() {
		let overrides = SeedOverrides {
			solver_id: None,
			solver_name: None,
			networks: vec![
				NetworkOverride {
					chain_id: 600001,
					name: Some("seedless-a".to_string()),
					network_type: Some(NetworkType::Parent),
					tokens: vec![],
					rpc_urls: Some(vec!["https://rpc.seedless-a.example".to_string()]),
					input_settler_address: None,
					output_settler_address: Some(address!(
						"2222222222222222222222222222222222222222"
					)),
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
				NetworkOverride {
					chain_id: 600002,
					name: Some("seedless-b".to_string()),
					network_type: Some(NetworkType::Hub),
					tokens: vec![],
					rpc_urls: Some(vec!["https://rpc.seedless-b.example".to_string()]),
					input_settler_address: Some(address!(
						"3333333333333333333333333333333333333333"
					)),
					output_settler_address: Some(address!(
						"4444444444444444444444444444444444444444"
					)),
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
			],
			settlement: None,
			routing_defaults: None,
			account: None,
			admin: None,
			auth_enabled: None,
			min_profitability_pct: None,
			gas_buffer_bps: None,
			commission_bps: None,
			rate_buffer_bps: None,
		};

		let result = merge_to_operator_config_seedless(overrides);
		assert!(matches!(
			result.unwrap_err(),
			MergeError::Validation(msg)
				if msg.contains("seedless mode requires explicit fields for chain 600001: input_settler_address")
		));
	}

	#[test]
	fn test_merge_to_operator_config_seedless_missing_hyperlane_payload() {
		let overrides = SeedOverrides {
			solver_id: None,
			solver_name: None,
			networks: vec![
				NetworkOverride {
					chain_id: 700001,
					name: Some("seedless-a".to_string()),
					network_type: Some(NetworkType::Parent),
					tokens: vec![],
					rpc_urls: Some(vec!["https://rpc.seedless-a.example".to_string()]),
					input_settler_address: Some(address!(
						"1111111111111111111111111111111111111111"
					)),
					output_settler_address: Some(address!(
						"2222222222222222222222222222222222222222"
					)),
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
				NetworkOverride {
					chain_id: 700002,
					name: Some("seedless-b".to_string()),
					network_type: Some(NetworkType::Hub),
					tokens: vec![],
					rpc_urls: Some(vec!["https://rpc.seedless-b.example".to_string()]),
					input_settler_address: Some(address!(
						"3333333333333333333333333333333333333333"
					)),
					output_settler_address: Some(address!(
						"4444444444444444444444444444444444444444"
					)),
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
			],
			settlement: None,
			routing_defaults: None,
			account: None,
			admin: None,
			auth_enabled: None,
			min_profitability_pct: None,
			gas_buffer_bps: None,
			commission_bps: None,
			rate_buffer_bps: None,
		};

		let result = merge_to_operator_config_seedless(overrides);
		assert!(matches!(
			result.unwrap_err(),
			MergeError::Validation(msg)
				if msg.contains("seedless mode requires explicit settlement.hyperlane configuration")
		));
	}

	#[test]
	fn test_merge_to_operator_config_seedless_direct_success() {
		let chain_a = 800001u64;
		let chain_b = 800002u64;
		let overrides = SeedOverrides {
			solver_id: Some("seedless-direct-test".to_string()),
			solver_name: None,
			networks: vec![
				NetworkOverride {
					chain_id: chain_a,
					name: Some("seedless-a".to_string()),
					network_type: Some(NetworkType::Parent),
					tokens: vec![],
					rpc_urls: Some(vec!["https://rpc.seedless-a.example".to_string()]),
					input_settler_address: Some(address!(
						"1111111111111111111111111111111111111111"
					)),
					output_settler_address: Some(address!(
						"2222222222222222222222222222222222222222"
					)),
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
				NetworkOverride {
					chain_id: chain_b,
					name: Some("seedless-b".to_string()),
					network_type: Some(NetworkType::Hub),
					tokens: vec![],
					rpc_urls: Some(vec!["https://rpc.seedless-b.example".to_string()]),
					input_settler_address: Some(address!(
						"3333333333333333333333333333333333333333"
					)),
					output_settler_address: Some(address!(
						"4444444444444444444444444444444444444444"
					)),
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
			],
			settlement: Some(solver_types::SettlementOverride {
				settlement_type: SettlementTypeOverride::Direct,
				hyperlane: None,
				direct: Some(DirectSettlementOverride {
					oracles: solver_types::OracleOverrides {
						input: HashMap::from([
							(
								chain_a,
								vec![address!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")],
							),
							(
								chain_b,
								vec![address!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")],
							),
						]),
						output: HashMap::from([
							(
								chain_a,
								vec![address!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")],
							),
							(
								chain_b,
								vec![address!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")],
							),
						]),
					},
					routes: HashMap::new(),
					dispute_period_seconds: Some(600),
					oracle_selection_strategy: Some(OracleSelectionStrategyOverride::First),
				}),
			}),
			routing_defaults: None,
			account: None,
			admin: None,
			auth_enabled: None,
			min_profitability_pct: None,
			gas_buffer_bps: None,
			commission_bps: None,
			rate_buffer_bps: None,
		};

		let op_config = merge_to_operator_config_seedless(overrides).unwrap();
		assert_eq!(
			op_config.settlement.settlement_type,
			OperatorSettlementType::Direct
		);
		let runtime = build_runtime_config(&op_config).unwrap();
		assert!(runtime.settlement.implementations.contains_key("direct"));
		assert!(!runtime.settlement.implementations.contains_key("hyperlane"));
	}

	#[test]
	fn test_merge_to_operator_config_seedless_rejects_invalid_hyperlane_routes() {
		let chain_a = 900001u64;
		let chain_b = 900002u64;
		let overrides = SeedOverrides {
			solver_id: None,
			solver_name: None,
			networks: vec![
				NetworkOverride {
					chain_id: chain_a,
					name: Some("seedless-a".to_string()),
					network_type: Some(NetworkType::Parent),
					tokens: vec![],
					rpc_urls: Some(vec!["https://rpc.seedless-a.example".to_string()]),
					input_settler_address: Some(address!(
						"1111111111111111111111111111111111111111"
					)),
					output_settler_address: Some(address!(
						"2222222222222222222222222222222222222222"
					)),
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
				NetworkOverride {
					chain_id: chain_b,
					name: Some("seedless-b".to_string()),
					network_type: Some(NetworkType::Hub),
					tokens: vec![],
					rpc_urls: Some(vec!["https://rpc.seedless-b.example".to_string()]),
					input_settler_address: Some(address!(
						"3333333333333333333333333333333333333333"
					)),
					output_settler_address: Some(address!(
						"4444444444444444444444444444444444444444"
					)),
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
			],
			settlement: Some(solver_types::SettlementOverride {
				settlement_type: SettlementTypeOverride::Hyperlane,
				hyperlane: Some(HyperlaneSettlementOverride {
					mailboxes: HashMap::from([
						(
							chain_a,
							address!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
						),
						(
							chain_b,
							address!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
						),
					]),
					igp_addresses: HashMap::from([
						(
							chain_a,
							address!("cccccccccccccccccccccccccccccccccccccccc"),
						),
						(
							chain_b,
							address!("dddddddddddddddddddddddddddddddddddddddd"),
						),
					]),
					oracles: solver_types::OracleOverrides {
						input: HashMap::from([
							(
								chain_a,
								vec![address!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")],
							),
							(
								chain_b,
								vec![address!("ffffffffffffffffffffffffffffffffffffffff")],
							),
						]),
						output: HashMap::from([
							(
								chain_a,
								vec![address!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")],
							),
							(
								chain_b,
								vec![address!("ffffffffffffffffffffffffffffffffffffffff")],
							),
						]),
					},
					routes: HashMap::from([
						(chain_a, vec![chain_b, 999999]),
						(chain_b, vec![chain_a]),
					]),
					default_gas_limit: None,
					message_timeout_seconds: None,
					finalization_required: None,
				}),
				direct: None,
			}),
			routing_defaults: None,
			account: None,
			admin: None,
			auth_enabled: None,
			min_profitability_pct: None,
			gas_buffer_bps: None,
			commission_bps: None,
			rate_buffer_bps: None,
		};

		let result = merge_to_operator_config_seedless(overrides);
		assert!(matches!(
			result.unwrap_err(),
			MergeError::Validation(msg)
				if msg.contains("settlement.hyperlane.routes has destination chain 999999")
		));
	}

	#[test]
	fn test_merge_to_operator_config_direct_missing_payload_fails() {
		let mut overrides = test_seed_overrides();
		overrides.settlement = Some(solver_types::SettlementOverride {
			settlement_type: SettlementTypeOverride::Direct,
			hyperlane: None,
			direct: None,
		});

		let result = merge_to_operator_config(overrides, &TESTNET_SEED);
		assert!(
			matches!(result.unwrap_err(), MergeError::Validation(msg) if msg.contains("settlement.direct is missing"))
		);
	}

	#[test]
	fn test_merge_to_operator_config_direct_and_runtime_only_direct() {
		let mut overrides = test_seed_overrides();
		overrides.settlement = Some(solver_types::SettlementOverride {
			settlement_type: SettlementTypeOverride::Direct,
			hyperlane: None,
			direct: Some(DirectSettlementOverride {
				oracles: solver_types::OracleOverrides {
					input: HashMap::from([
						(
							11155420,
							vec![address!("7100000000000000000000000000000000000007")],
						),
						(
							84532,
							vec![address!("8200000000000000000000000000000000000008")],
						),
					]),
					output: HashMap::from([
						(
							11155420,
							vec![address!("7100000000000000000000000000000000000007")],
						),
						(
							84532,
							vec![address!("8200000000000000000000000000000000000008")],
						),
					]),
				},
				routes: HashMap::new(),
				dispute_period_seconds: Some(900),
				oracle_selection_strategy: Some(OracleSelectionStrategyOverride::RoundRobin),
			}),
		});

		let op_config = merge_to_operator_config(overrides, &TESTNET_SEED).unwrap();
		assert_eq!(
			op_config.settlement.settlement_type,
			OperatorSettlementType::Direct
		);
		assert!(op_config.settlement.hyperlane.is_none());
		assert_eq!(
			op_config
				.settlement
				.direct
				.as_ref()
				.unwrap()
				.oracle_selection_strategy,
			OperatorOracleSelectionStrategy::RoundRobin
		);

		let runtime_config = build_runtime_config(&op_config).unwrap();
		assert!(runtime_config
			.settlement
			.implementations
			.contains_key("direct"));
		assert!(!runtime_config
			.settlement
			.implementations
			.contains_key("hyperlane"));

		let roundtrip = config_to_operator_config(&runtime_config).unwrap();
		assert_eq!(
			roundtrip.settlement.settlement_type,
			OperatorSettlementType::Direct
		);
		assert!(roundtrip.settlement.direct.is_some());
		assert!(roundtrip.settlement.hyperlane.is_none());
	}

	#[test]
	fn test_merge_to_operator_config_duplicate_chain() {
		let overrides = SeedOverrides {
			solver_id: None,
			solver_name: None,
			networks: vec![
				NetworkOverride {
					chain_id: 11155420,
					name: None,
					network_type: None,
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "USDC".to_string(),
						name: None,
						address: address!("191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6"),
						decimals: 6,
					}],
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
				NetworkOverride {
					chain_id: 11155420, // Duplicate
					name: None,
					network_type: None,
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "DAI".to_string(),
						name: None,
						address: address!("1111111111111111111111111111111111111111"),
						decimals: 18,
					}],
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
			],
			account: None,
			admin: None,
			auth_enabled: None,
			min_profitability_pct: None,
			gas_buffer_bps: None,
			commission_bps: None,
			rate_buffer_bps: None,
			settlement: None,
			routing_defaults: None,
		};

		let result = merge_to_operator_config(overrides, &TESTNET_SEED);
		assert!(result.is_err());
		assert!(matches!(
			result.unwrap_err(),
			MergeError::DuplicateChainId(11155420)
		));
	}

	#[test]
	fn test_merge_to_operator_config_insufficient_networks() {
		let overrides = SeedOverrides {
			solver_id: None,
			solver_name: None,
			networks: vec![NetworkOverride {
				chain_id: 11155420,
				name: None,
				network_type: None,
				tokens: vec![solver_types::seed_overrides::Token {
					symbol: "USDC".to_string(),
					name: None,
					address: address!("191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6"),
					decimals: 6,
				}],
				rpc_urls: None,
				input_settler_address: None,
				output_settler_address: None,
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			}],
			account: None,
			admin: None,
			auth_enabled: None,
			min_profitability_pct: None,
			gas_buffer_bps: None,
			commission_bps: None,
			rate_buffer_bps: None,
			settlement: None,
			routing_defaults: None,
		};

		let result = merge_to_operator_config(overrides, &TESTNET_SEED);
		assert!(result.is_err());
		assert!(matches!(
			result.unwrap_err(),
			MergeError::InsufficientNetworks
		));
	}

	#[test]
	fn test_merge_to_operator_config_empty_tokens() {
		let overrides = SeedOverrides {
			solver_id: None,
			solver_name: None,
			networks: vec![
				NetworkOverride {
					chain_id: 11155420,
					name: None,
					network_type: None,
					tokens: vec![], // No tokens
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
				NetworkOverride {
					chain_id: 84532,
					name: None,
					network_type: None,
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "USDC".to_string(),
						name: None,
						address: address!("73c83DAcc74bB8a704717AC09703b959E74b9705"),
						decimals: 6,
					}],
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
			],
			account: None,
			admin: None,
			auth_enabled: None,
			min_profitability_pct: None,
			gas_buffer_bps: None,
			commission_bps: None,
			rate_buffer_bps: None,
			settlement: None,
			routing_defaults: None,
		};

		let result = merge_to_operator_config(overrides, &TESTNET_SEED).unwrap();
		assert_eq!(result.networks.len(), 2);
		assert_eq!(result.networks.get(&11155420).unwrap().tokens.len(), 0);
		assert_eq!(result.networks.get(&84532).unwrap().tokens.len(), 1);
	}

	#[test]
	fn test_merge_to_operator_config_all_networks_empty_tokens() {
		let overrides = SeedOverrides {
			solver_id: None,
			solver_name: None,
			networks: vec![
				NetworkOverride {
					chain_id: 11155420,
					name: None,
					network_type: None,
					tokens: vec![],
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
				NetworkOverride {
					chain_id: 84532,
					name: None,
					network_type: None,
					tokens: vec![],
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
			],
			account: None,
			admin: None,
			auth_enabled: None,
			min_profitability_pct: None,
			gas_buffer_bps: None,
			commission_bps: None,
			rate_buffer_bps: None,
			settlement: None,
			routing_defaults: None,
		};

		let result = merge_to_operator_config(overrides, &TESTNET_SEED).unwrap();
		assert_eq!(result.networks.len(), 2);
		assert_eq!(result.networks.get(&11155420).unwrap().tokens.len(), 0);
		assert_eq!(result.networks.get(&84532).unwrap().tokens.len(), 0);
	}

	#[test]
	fn test_merge_to_operator_config_with_admin() {
		let overrides = SeedOverrides {
			solver_id: Some("admin-test-solver".to_string()),
			solver_name: None,
			networks: vec![
				NetworkOverride {
					chain_id: 11155420,
					name: None,
					network_type: None,
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "USDC".to_string(),
						name: None,
						address: address!("191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6"),
						decimals: 6,
					}],
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
				NetworkOverride {
					chain_id: 84532,
					name: None,
					network_type: None,
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "USDC".to_string(),
						name: None,
						address: address!("73c83DAcc74bB8a704717AC09703b959E74b9705"),
						decimals: 6,
					}],
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
			],
			account: None,
			admin: Some(AdminOverride {
				enabled: true,
				domain: "test.solver.com".to_string(),
				chain_id: Some(1),
				nonce_ttl_seconds: Some(600),
				admin_addresses: vec![address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266")],
				withdrawals: solver_types::seed_overrides::WithdrawalsOverride::default(),
			}),
			auth_enabled: None,
			min_profitability_pct: None,
			gas_buffer_bps: None,
			commission_bps: None,
			rate_buffer_bps: None,
			settlement: None,
			routing_defaults: None,
		};

		let op_config = merge_to_operator_config(overrides, &TESTNET_SEED).unwrap();

		assert!(op_config.admin.enabled);
		assert_eq!(op_config.admin.domain, "test.solver.com");
		assert_eq!(op_config.admin.chain_id, 1);
		assert_eq!(op_config.admin.nonce_ttl_seconds, 600);
		assert_eq!(op_config.admin.admin_addresses.len(), 1);
	}

	#[test]
	fn test_merge_to_operator_config_hyperlane() {
		let overrides = test_seed_overrides();
		let op_config = merge_to_operator_config(overrides, &TESTNET_SEED).unwrap();

		assert_eq!(
			op_config.settlement.settlement_type,
			OperatorSettlementType::Hyperlane
		);
		assert!(op_config.settlement.direct.is_none());
		let hyperlane = op_config.settlement.hyperlane.as_ref().unwrap();

		// Check mailboxes exist for both chains
		assert!(hyperlane.mailboxes.contains_key(&11155420));
		assert!(hyperlane.mailboxes.contains_key(&84532));

		// Check IGP addresses exist
		assert!(hyperlane.igp_addresses.contains_key(&11155420));
		assert!(hyperlane.igp_addresses.contains_key(&84532));

		// Check routes are bidirectional
		let opt_routes = hyperlane.routes.get(&11155420).unwrap();
		assert!(opt_routes.contains(&84532));

		let base_routes = hyperlane.routes.get(&84532).unwrap();
		assert!(base_routes.contains(&11155420));
	}

	#[test]
	fn test_merge_to_operator_config_gas() {
		let overrides = test_seed_overrides();
		let op_config = merge_to_operator_config(overrides, &TESTNET_SEED).unwrap();

		// Gas config should be populated from seed defaults
		assert!(op_config.gas.resource_lock.fill > 0);
		assert!(op_config.gas.permit2_escrow.fill > 0);
		assert!(op_config.gas.eip3009_escrow.fill > 0);
	}

	// ===== Tests for build_runtime_config =====

	#[test]
	fn test_build_runtime_config_success() {
		let overrides = test_seed_overrides();
		let op_config = merge_to_operator_config(overrides, &TESTNET_SEED).unwrap();
		let result = build_runtime_config(&op_config);

		assert!(result.is_ok());
		let config = result.unwrap();

		// Check solver config
		assert_eq!(config.solver.id, op_config.solver_id);
		assert_eq!(
			config.solver.min_profitability_pct,
			op_config.solver.min_profitability_pct
		);

		// Check networks
		assert_eq!(config.networks.len(), 2);
		assert!(config.networks.contains_key(&11155420));
		assert!(config.networks.contains_key(&84532));
	}

	#[test]
	fn test_build_runtime_config_insufficient_networks() {
		// Create an OperatorConfig with only 1 network (invalid)
		let mut op_config = OperatorConfig {
			solver_id: "test-solver".to_string(),
			solver_name: Some("test-solver".to_string()),
			networks: HashMap::new(),
			settlement: OperatorSettlementConfig {
				settlement_poll_interval_seconds: 60,
				settlement_type: OperatorSettlementType::Hyperlane,
				hyperlane: Some(OperatorHyperlaneConfig {
					default_gas_limit: 300000,
					message_timeout_seconds: 600,
					finalization_required: true,
					mailboxes: HashMap::new(),
					igp_addresses: HashMap::new(),
					oracles: OperatorOracleConfig {
						input: HashMap::new(),
						output: HashMap::new(),
					},
					routes: HashMap::new(),
				}),
				direct: None,
			},
			gas: OperatorGasConfig {
				resource_lock: OperatorGasFlowUnits::default(),
				permit2_escrow: OperatorGasFlowUnits::default(),
				eip3009_escrow: OperatorGasFlowUnits::default(),
			},
			pricing: OperatorPricingConfig {
				primary: "coingecko".to_string(),
				fallbacks: vec![],
				cache_duration_seconds: 60,
				custom_prices: HashMap::new(),
			},
			solver: OperatorSolverConfig {
				min_profitability_pct: Decimal::from_str("0.0").unwrap(),
				gas_buffer_bps: 1000,
				commission_bps: 20,
				rate_buffer_bps: 14,
				monitoring_timeout_seconds: 30,
			},
			admin: OperatorAdminConfig::default(),
			auth_enabled: false,
			account: None,
		};

		// Add only one network
		op_config.networks.insert(
			1,
			OperatorNetworkConfig {
				chain_id: 1,
				name: "test".to_string(),
				network_type: NetworkType::New,
				tokens: vec![],
				rpc_urls: vec![],
				input_settler_address: address!("0000000000000000000000000000000000000001"),
				output_settler_address: address!("0000000000000000000000000000000000000002"),
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);

		let result = build_runtime_config(&op_config);
		assert!(result.is_err());
		assert!(matches!(
			result.unwrap_err(),
			MergeError::InsufficientNetworks
		));
	}

	#[test]
	fn test_build_runtime_config_preserves_gas_config() {
		let overrides = test_seed_overrides();
		let op_config = merge_to_operator_config(overrides, &TESTNET_SEED).unwrap();
		let config = build_runtime_config(&op_config).unwrap();

		let gas = config.gas.as_ref().unwrap();
		let resource_lock = gas.flows.get("resource_lock").unwrap();

		// Check that gas values are preserved
		assert_eq!(
			resource_lock.fill.unwrap(),
			op_config.gas.resource_lock.fill
		);
		assert_eq!(
			resource_lock.claim.unwrap(),
			op_config.gas.resource_lock.claim
		);
	}

	#[test]
	fn test_build_runtime_config_preserves_pricing_config() {
		let overrides = test_seed_overrides();
		let op_config = merge_to_operator_config(overrides, &TESTNET_SEED).unwrap();
		let config = build_runtime_config(&op_config).unwrap();

		let pricing = config.pricing.as_ref().unwrap();
		assert_eq!(pricing.primary, op_config.pricing.primary);
		assert_eq!(pricing.fallbacks, op_config.pricing.fallbacks);
	}

	// ===== Tests for config_to_operator_config =====

	#[test]
	fn test_config_to_operator_config_roundtrip() {
		// Create a config via merge
		let overrides = test_seed_overrides();
		let config = merge_config(overrides, &TESTNET_SEED).unwrap();

		// Convert to operator config
		let result = config_to_operator_config(&config);
		assert!(result.is_ok());

		let op_config = result.unwrap();

		// Check basic fields are preserved
		assert_eq!(op_config.solver_id, config.solver.id);
		assert_eq!(
			op_config.solver.min_profitability_pct,
			config.solver.min_profitability_pct
		);
		assert_eq!(
			op_config.solver.gas_buffer_bps,
			config.solver.gas_buffer_bps
		);
		assert_eq!(
			op_config.solver.commission_bps,
			config.solver.commission_bps
		);
		assert_eq!(
			op_config.solver.rate_buffer_bps,
			config.solver.rate_buffer_bps
		);
		assert_eq!(
			op_config.solver.monitoring_timeout_seconds,
			config.solver.monitoring_timeout_seconds
		);

		// Check networks are preserved
		assert_eq!(op_config.networks.len(), config.networks.len());
		for chain_id in config.networks.keys() {
			assert!(op_config.networks.contains_key(chain_id));
		}
	}

	#[test]
	fn test_config_to_operator_config_preserves_tokens() {
		let overrides = test_seed_overrides();
		let config = merge_config(overrides, &TESTNET_SEED).unwrap();
		let op_config = config_to_operator_config(&config).unwrap();

		// Check tokens are preserved
		let orig_network = config.networks.get(&11155420).unwrap();
		let op_network = op_config.networks.get(&11155420).unwrap();

		assert_eq!(op_network.tokens.len(), orig_network.tokens.len());
		assert_eq!(op_network.tokens[0].symbol, orig_network.tokens[0].symbol);
		assert_eq!(
			op_network.tokens[0].decimals,
			orig_network.tokens[0].decimals
		);
	}

	#[test]
	fn test_config_to_operator_config_extracts_gas() {
		let overrides = test_seed_overrides();
		let config = merge_config(overrides, &TESTNET_SEED).unwrap();
		let op_config = config_to_operator_config(&config).unwrap();

		// Gas config should be extracted
		let orig_gas = config.gas.as_ref().unwrap();
		let orig_resource_lock = orig_gas.flows.get("resource_lock").unwrap();

		assert_eq!(
			op_config.gas.resource_lock.fill,
			orig_resource_lock.fill.unwrap()
		);
		assert_eq!(
			op_config.gas.resource_lock.claim,
			orig_resource_lock.claim.unwrap()
		);
	}

	#[test]
	fn test_config_to_operator_config_extracts_hyperlane() {
		let overrides = test_seed_overrides();
		let config = merge_config(overrides, &TESTNET_SEED).unwrap();
		let op_config = config_to_operator_config(&config).unwrap();

		let hyperlane = op_config.settlement.hyperlane.as_ref().unwrap();

		// Hyperlane config should be extracted
		assert!(!hyperlane.mailboxes.is_empty());
		assert!(!hyperlane.routes.is_empty());

		// Check routes exist for both chains
		assert!(hyperlane.routes.contains_key(&11155420));
		assert!(hyperlane.routes.contains_key(&84532));
	}

	// ===== Tests for helper functions =====

	#[test]
	fn test_toml_table_helper() {
		let table = toml_table(vec![
			("key1", toml::Value::String("value1".to_string())),
			("key2", toml::Value::Integer(42)),
			("key3", toml::Value::Boolean(true)),
		]);

		assert!(table.is_table());
		let t = table.as_table().unwrap();
		assert_eq!(t.get("key1").unwrap().as_str().unwrap(), "value1");
		assert_eq!(t.get("key2").unwrap().as_integer().unwrap(), 42);
		assert!(t.get("key3").unwrap().as_bool().unwrap());
	}

	#[test]
	fn test_build_delivery_config_from_operator() {
		let chain_ids = vec![1, 10, 137];
		let delivery = build_delivery_config_from_operator(&chain_ids);

		assert!(delivery.implementations.contains_key("evm_alloy"));
		let evm_config = delivery.implementations.get("evm_alloy").unwrap();
		let network_ids = evm_config.get("network_ids").unwrap().as_array().unwrap();
		assert_eq!(network_ids.len(), 3);
	}

	#[test]
	fn test_build_discovery_config_from_operator() {
		let chain_ids = vec![1, 10];
		let discovery = build_discovery_config_from_operator(&chain_ids);

		assert!(discovery.implementations.contains_key("onchain_eip7683"));
		assert!(discovery.implementations.contains_key("offchain_eip7683"));

		let onchain = discovery.implementations.get("onchain_eip7683").unwrap();
		assert!(onchain.get("polling_interval_secs").is_some());
	}

	#[test]
	fn test_build_order_config_from_operator() {
		let order = build_order_config_from_operator();

		assert!(order.implementations.contains_key("eip7683"));
		assert_eq!(order.strategy.primary, "simple");
		assert!(order.strategy.implementations.contains_key("simple"));
	}

	#[test]
	fn test_build_storage_config_from_operator() {
		let storage = build_storage_config_from_operator("test-solver");

		assert_eq!(storage.primary, "redis");
		assert!(storage.implementations.contains_key("redis"));
		assert!(storage.implementations.contains_key("memory"));

		// Verify key_prefix is set to solver_id
		let redis_config = storage.implementations.get("redis").unwrap();
		let key_prefix = redis_config.get("key_prefix").unwrap().as_str().unwrap();
		assert_eq!(key_prefix, "test-solver");
	}

	#[test]
	fn test_build_gas_config_from_operator() {
		let op_gas = OperatorGasConfig {
			resource_lock: OperatorGasFlowUnits {
				open: 100,
				fill: 200,
				claim: 300,
			},
			permit2_escrow: OperatorGasFlowUnits {
				open: 400,
				fill: 500,
				claim: 600,
			},
			eip3009_escrow: OperatorGasFlowUnits {
				open: 700,
				fill: 800,
				claim: 900,
			},
		};

		let gas = build_gas_config_from_operator(&op_gas);

		let resource_lock = gas.flows.get("resource_lock").unwrap();
		assert_eq!(resource_lock.open, Some(100));
		assert_eq!(resource_lock.fill, Some(200));
		assert_eq!(resource_lock.claim, Some(300));

		let permit2 = gas.flows.get("permit2_escrow").unwrap();
		assert_eq!(permit2.fill, Some(500));

		let eip3009 = gas.flows.get("eip3009_escrow").unwrap();
		assert_eq!(eip3009.claim, Some(900));
	}

	#[test]
	fn test_build_pricing_config_from_operator() {
		let op_pricing = OperatorPricingConfig {
			primary: "coingecko".to_string(),
			fallbacks: vec!["defillama".to_string()],
			cache_duration_seconds: 120,
			custom_prices: HashMap::new(),
		};

		let pricing = build_pricing_config_from_operator(&op_pricing);

		assert_eq!(pricing.primary, "coingecko");
		assert_eq!(pricing.fallbacks, vec!["defillama".to_string()]);
		assert!(pricing.implementations.contains_key("coingecko"));
		assert!(pricing.implementations.contains_key("defillama"));
	}

	#[test]
	#[serial]
	fn test_build_api_config_from_operator_admin_enabled() {
		use std::env;

		let original_public_register = env::var("AUTH_PUBLIC_REGISTER_ENABLED").ok();
		env::set_var("AUTH_PUBLIC_REGISTER_ENABLED", "true");

		let admin = OperatorAdminConfig {
			enabled: true,
			domain: "solver.example.com".to_string(),
			chain_id: 1,
			nonce_ttl_seconds: 300,
			admin_addresses: vec![address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266")],
			withdrawals: OperatorWithdrawalsConfig::default(),
		};

		let api = build_api_config_from_operator(&admin, true).unwrap();

		assert!(api.enabled);
		let auth = api.auth.as_ref().unwrap();
		assert!(auth.enabled);
		assert!(auth.public_register_enabled);
		let admin_config = auth.admin.as_ref().unwrap();
		assert!(admin_config.enabled);
		assert_eq!(admin_config.domain, "solver.example.com");
		assert_eq!(admin_config.chain_id, Some(1));

		env::remove_var("AUTH_PUBLIC_REGISTER_ENABLED");
		if let Some(val) = original_public_register {
			env::set_var("AUTH_PUBLIC_REGISTER_ENABLED", val);
		}
	}

	#[test]
	fn test_build_api_config_from_operator_admin_disabled() {
		let admin = OperatorAdminConfig {
			enabled: false,
			domain: "".to_string(),
			chain_id: 0,
			nonce_ttl_seconds: 0,
			admin_addresses: vec![],
			withdrawals: OperatorWithdrawalsConfig::default(),
		};

		let api = build_api_config_from_operator(&admin, false).unwrap();

		assert!(api.enabled); // API is always enabled
		assert!(api.auth.is_none()); // But auth is None when admin disabled
	}

	#[test]
	#[serial]
	fn test_parse_bool_env_var_uses_default_when_missing() {
		let key = "TEST_PARSE_BOOL_MISSING";
		std::env::remove_var(key);
		let parsed = parse_bool_env_var(key, true).unwrap();
		assert!(parsed);
	}

	#[test]
	#[serial]
	fn test_parse_bool_env_var_parses_case_insensitive_values() {
		let key = "TEST_PARSE_BOOL_CASE";
		std::env::set_var(key, "TrUe");
		let parsed = parse_bool_env_var(key, false).unwrap();
		assert!(parsed);
		std::env::remove_var(key);
	}

	#[test]
	#[serial]
	fn test_parse_bool_env_var_rejects_invalid_value() {
		let key = "TEST_PARSE_BOOL_INVALID";
		std::env::set_var(key, "yes");
		let err = parse_bool_env_var(key, false).unwrap_err();
		std::env::remove_var(key);

		assert!(matches!(err, MergeError::Validation(_)));
		assert!(err.to_string().contains("Invalid boolean value"));
	}

	#[test]
	fn test_build_operator_network_config_falls_back_to_seed_name_and_rpc() {
		let network_seed = TESTNET_SEED
			.get_network(11155420)
			.expect("expected optimism sepolia in seed");
		let override_ = NetworkOverride {
			chain_id: 11155420,
			name: Some("   ".to_string()),
			network_type: None,
			tokens: vec![solver_types::seed_overrides::Token {
				symbol: "USDC".to_string(),
				name: None,
				address: address!("191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6"),
				decimals: 6,
			}],
			rpc_urls: Some(vec![]),
			input_settler_address: None,
			output_settler_address: None,
			input_settler_compact_address: None,
			the_compact_address: None,
			allocator_address: None,
		};

		let network = build_operator_network_config(Some(network_seed), &override_).unwrap();
		assert_eq!(network.name, network_seed.name);
		assert_eq!(network.network_type, NetworkType::New);
		assert_eq!(network.tokens[0].name, Some("USDC".to_string()));
		assert_eq!(network.rpc_urls.len(), network_seed.default_rpc_urls.len());
	}

	#[test]
	fn test_build_operator_hyperlane_config_from_seed() {
		let hyperlane =
			build_operator_hyperlane_config_from_seed(&TESTNET_SEED, &[11155420, 84532]).unwrap();
		assert!(hyperlane.mailboxes.contains_key(&11155420));
		assert!(hyperlane.mailboxes.contains_key(&84532));
		assert!(hyperlane.igp_addresses.contains_key(&11155420));
		assert!(hyperlane.igp_addresses.contains_key(&84532));
		assert_eq!(hyperlane.routes.get(&11155420), Some(&vec![84532]));
		assert_eq!(hyperlane.routes.get(&84532), Some(&vec![11155420]));
	}

	#[test]
	#[serial]
	fn test_jwt_secret_from_env_var() {
		use std::env;

		// Save original value
		let original_jwt = env::var("JWT_SECRET").ok();

		// Test: Set JWT_SECRET and verify it's used
		env::set_var("JWT_SECRET", "test-jwt-secret-from-env-var-32ch");
		let admin = OperatorAdminConfig {
			enabled: true,
			domain: "test.com".to_string(),
			chain_id: 1,
			nonce_ttl_seconds: 300,
			admin_addresses: vec![address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266")],
			withdrawals: OperatorWithdrawalsConfig::default(),
		};
		let api = build_api_config_from_operator(&admin, false).unwrap();
		let auth = api.auth.as_ref().unwrap();
		assert_eq!(
			auth.jwt_secret.expose_secret(),
			"test-jwt-secret-from-env-var-32ch"
		);

		// Restore original env var
		env::remove_var("JWT_SECRET");
		if let Some(val) = original_jwt {
			env::set_var("JWT_SECRET", val);
		}
	}

	#[test]
	#[serial]
	fn test_auth_enabled_defaults_public_register_disabled() {
		use std::env;

		let original = env::var("AUTH_PUBLIC_REGISTER_ENABLED").ok();
		env::remove_var("AUTH_PUBLIC_REGISTER_ENABLED");

		let admin = OperatorAdminConfig::default();
		let api = build_api_config_from_operator(&admin, true).unwrap();
		let auth = api.auth.as_ref().unwrap();
		assert!(!auth.public_register_enabled);

		if let Some(val) = original {
			env::set_var("AUTH_PUBLIC_REGISTER_ENABLED", val);
		}
	}

	#[test]
	#[serial]
	fn test_auth_disabled_ignores_public_register_env() {
		use std::env;

		let original = env::var("AUTH_PUBLIC_REGISTER_ENABLED").ok();
		env::set_var("AUTH_PUBLIC_REGISTER_ENABLED", "true");

		let enabled = load_public_register_enabled(false).unwrap();
		assert!(!enabled);

		env::remove_var("AUTH_PUBLIC_REGISTER_ENABLED");
		if let Some(val) = original {
			env::set_var("AUTH_PUBLIC_REGISTER_ENABLED", val);
		}
	}

	#[test]
	fn test_kms_account_override_full_flow() {
		use solver_types::AccountOverride;

		// Create overrides with KMS account configuration
		let overrides = SeedOverrides {
			solver_id: Some("kms-test-solver".to_string()),
			solver_name: None,
			networks: vec![
				NetworkOverride {
					chain_id: 11155420,
					name: None,
					network_type: None,
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "USDC".to_string(),
						name: None,
						address: address!("191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6"),
						decimals: 6,
					}],
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
				NetworkOverride {
					chain_id: 84532,
					name: None,
					network_type: None,
					tokens: vec![solver_types::seed_overrides::Token {
						symbol: "USDC".to_string(),
						name: None,
						address: address!("73c83DAcc74bB8a704717AC09703b959E74b9705"),
						decimals: 6,
					}],
					rpc_urls: None,
					input_settler_address: None,
					output_settler_address: None,
					input_settler_compact_address: None,
					the_compact_address: None,
					allocator_address: None,
				},
			],
			account: Some(AccountOverride {
				primary: "kms".to_string(),
				implementations: {
					let mut map = std::collections::HashMap::new();
					map.insert(
						"kms".to_string(),
						serde_json::json!({
							"key_id": "test-key-id",
							"region": "us-east-1"
						}),
					);
					map
				},
			}),
			admin: None,
			auth_enabled: None,
			min_profitability_pct: None,
			gas_buffer_bps: None,
			commission_bps: None,
			rate_buffer_bps: None,
			settlement: None,
			routing_defaults: None,
		};

		// Step 1: merge_config should create Config with KMS account
		let config = merge_config(overrides.clone(), &TESTNET_SEED).unwrap();

		// Verify Config has KMS as primary (not local)
		assert_eq!(
			config.account.primary, "kms",
			"Config primary should be 'kms'"
		);
		assert!(
			config.account.implementations.contains_key("kms"),
			"Config should have 'kms' implementation"
		);
		assert!(
			!config.account.implementations.contains_key("local"),
			"Config should NOT have 'local' implementation when using KMS"
		);

		// Step 2: config_to_operator_config should preserve account config
		let op_config = config_to_operator_config(&config).unwrap();

		// Verify OperatorConfig has account set (not None)
		assert!(
			op_config.account.is_some(),
			"OperatorConfig.account should be Some for KMS"
		);
		let op_account = op_config.account.as_ref().unwrap();
		assert_eq!(
			op_account.primary, "kms",
			"OperatorConfig account primary should be 'kms'"
		);
		assert!(
			op_account.implementations.contains_key("kms"),
			"OperatorConfig should have 'kms' implementation"
		);

		// Step 3: build_runtime_config should restore KMS account config
		let runtime_config = build_runtime_config(&op_config).unwrap();

		// Verify runtime Config has KMS (not local)
		assert_eq!(
			runtime_config.account.primary, "kms",
			"Runtime config primary should be 'kms'"
		);
		assert!(
			runtime_config.account.implementations.contains_key("kms"),
			"Runtime config should have 'kms' implementation"
		);
		assert!(
			!runtime_config.account.implementations.contains_key("local"),
			"Runtime config should NOT have 'local' implementation"
		);
	}
}
