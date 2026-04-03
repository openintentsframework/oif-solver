//! Configuration module for the OIF solver system.
//!
//! This module provides structures and utilities for managing solver configuration.
//! It supports loading configuration from JSON files and provides validation to ensure
//! all required configuration values are properly set.

pub mod builders;

pub use builders::config::ConfigBuilder;

use regex::Regex;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use solver_types::{networks::deserialize_networks, NetworksConfig};
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use thiserror::Error;

/// Errors that can occur during configuration operations.
#[derive(Debug, Error)]
pub enum ConfigError {
	/// Error that occurs during file I/O operations.
	#[error("IO error: {0}")]
	Io(#[from] std::io::Error),
	/// Error that occurs when parsing JSON configuration.
	#[error("Configuration error: {0}")]
	Parse(String),
	/// Error that occurs when configuration validation fails.
	#[error("Validation error: {0}")]
	Validation(String),
}

impl From<serde_json::Error> for ConfigError {
	fn from(err: serde_json::Error) -> Self {
		ConfigError::Parse(err.to_string())
	}
}

/// Main configuration structure for the OIF solver.
///
/// This structure contains all configuration sections required for the solver
/// to operate, including solver identity, storage, delivery, accounts, discovery,
/// order processing, settlement configurations, and API server.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
	/// Configuration specific to the solver instance.
	pub solver: SolverConfig,
	/// Network and token configurations.
	#[serde(deserialize_with = "deserialize_networks")]
	pub networks: NetworksConfig,
	/// Configuration for the storage backend.
	pub storage: StorageConfig,
	/// Configuration for delivery mechanisms.
	pub delivery: DeliveryConfig,
	/// Configuration for account management.
	pub account: AccountConfig,
	/// Configuration for order discovery.
	pub discovery: DiscoveryConfig,
	/// Configuration for order processing.
	pub order: OrderConfig,
	/// Configuration for settlement operations.
	pub settlement: SettlementConfig,
	/// Configuration for pricing services.
	#[serde(default)]
	pub pricing: Option<PricingConfig>,
	/// Configuration for the HTTP API server.
	pub api: Option<ApiConfig>,
	/// Optional gas configuration for precomputed/overridden gas units by flow.
	#[serde(default)]
	pub gas: Option<GasConfig>,
	/// Optional cross-chain rebalancing configuration.
	#[serde(default)]
	pub rebalance: Option<RebalanceConfig>,
}

/// Configuration specific to the solver instance.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SolverConfig {
	/// Unique identifier for this solver instance.
	pub id: String,
	/// Minimum profitability percentage required to execute orders.
	pub min_profitability_pct: Decimal,
	/// Gas buffer in basis points (e.g., 1000 = 10%).
	/// Applied as safety margin on gas cost estimates.
	#[serde(default = "default_gas_buffer_bps")]
	pub gas_buffer_bps: u32,
	/// Commission in basis points (e.g., 20 = 0.20%).
	/// Added to solver profit requirement.
	#[serde(default = "default_commission_bps")]
	pub commission_bps: u32,
	/// Rate buffer in basis points (e.g., 14 = 0.14%).
	/// Applied to exchange rate to protect against price volatility.
	#[serde(default = "default_rate_buffer_bps")]
	pub rate_buffer_bps: u32,
	/// Timeout in seconds for monitoring transactions.
	/// Defaults to 28800 seconds (8 hours) if not specified.
	#[serde(default = "default_monitoring_timeout_seconds")]
	pub monitoring_timeout_seconds: u64,
	/// Optional path to a JSON file containing denied Ethereum addresses.
	/// The file must contain a JSON array of lowercase hex strings (e.g. ["0xabc...", ...]).
	/// When set, any intent whose sender or recipient appears in the list is silently dropped.
	#[serde(default)]
	pub deny_list: Option<String>,
}

/// Configuration for the storage backend.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StorageConfig {
	/// Which implementation to use as primary.
	pub primary: String,
	/// Map of storage implementation names to their configurations.
	pub implementations: HashMap<String, serde_json::Value>,
	/// Interval in seconds for cleaning up expired storage entries.
	pub cleanup_interval_seconds: u64,
}

/// Configuration for delivery mechanisms.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeliveryConfig {
	/// Map of delivery implementation names to their configurations.
	/// Each implementation has its own configuration format stored as raw JSON values.
	pub implementations: HashMap<String, serde_json::Value>,
	/// Minimum number of confirmations required for transactions.
	/// Defaults to 3 confirmations if not specified.
	#[serde(default = "default_confirmations")]
	pub min_confirmations: u64,
}

/// Returns the default number of confirmations required.
///
/// This provides a default value of 3 confirmations for transaction finality
/// when no explicit confirmation count is configured.
fn default_confirmations() -> u64 {
	3 // Default to 3 confirmations
}

/// Returns the default monitoring timeout in seconds.
fn default_monitoring_timeout_seconds() -> u64 {
	28800 // Default to 8 hours (480 minutes * 60 seconds)
}

/// Returns the default value for boolean flags (true).
fn default_true() -> bool {
	true
}

/// Configuration for account management.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AccountConfig {
	/// Which implementation to use as primary.
	pub primary: String,
	/// Map of account implementation names to their configurations.
	pub implementations: HashMap<String, serde_json::Value>,
}

/// Configuration for order discovery.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DiscoveryConfig {
	/// Map of discovery implementation names to their configurations.
	/// Each implementation has its own configuration format stored as raw JSON values.
	pub implementations: HashMap<String, serde_json::Value>,
}

/// Configuration for order processing.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OrderConfig {
	/// Map of order implementation names to their configurations.
	/// Each implementation handles specific order types.
	pub implementations: HashMap<String, serde_json::Value>,
	/// Strategy configuration for order execution.
	pub strategy: StrategyConfig,
	/// Whitelisted callback contract addresses in EIP-7930 InteropAddress format.
	/// Format: EIP-7930 hex string e.g. "0x0001000002210514154c8bb598df835e9617c2cdcb8c84838bd329c6"
	/// The format encodes: Version (2 bytes) | ChainType (2 bytes) | ChainRefLen (1 byte) | ChainRef | AddrLen (1 byte) | Address
	#[serde(default)]
	pub callback_whitelist: Vec<String>,
	/// Enable gas simulation for callbacks before filling.
	#[serde(default = "default_true")]
	pub simulate_callbacks: bool,
}

/// Configuration for execution strategies.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StrategyConfig {
	/// Which strategy implementation to use as primary.
	pub primary: String,
	/// Map of strategy implementation names to their configurations.
	pub implementations: HashMap<String, serde_json::Value>,
}

/// Configuration for settlement operations.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SettlementConfig {
	/// Map of settlement implementation names to their configurations.
	/// Each implementation handles specific settlement mechanisms.
	pub implementations: HashMap<String, serde_json::Value>,
	/// The primary settlement implementation name. Must exist in `implementations`.
	/// All new quotes and unbound orders use this implementation exclusively.
	#[serde(default)]
	pub primary: String,
	/// Poll interval in seconds for settlement readiness monitoring.
	/// Defaults to 3 seconds if not specified.
	#[serde(default = "default_settlement_poll_interval_seconds")]
	pub settlement_poll_interval_seconds: u64,
}

/// Returns the default settlement poll interval in seconds.
fn default_settlement_poll_interval_seconds() -> u64 {
	3 // Default to 3 seconds
}

/// Implementation references for API functionality.
///
/// Specifies which implementations to use for various API features.
/// These must match the names of configured implementations in their respective sections.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ApiImplementations {
	/// Discovery implementation to use for order forwarding.
	/// Must match one of the configured implementations in [discovery.implementations].
	/// Used by the /orders endpoint to forward intent submissions to the discovery service.
	/// If not specified, order forwarding will be disabled.
	pub discovery: Option<String>,
}

/// Configuration for the HTTP API server.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiConfig {
	/// Whether the API server is enabled.
	#[serde(default)]
	pub enabled: bool,
	/// Host address to bind the server to.
	#[serde(default = "default_api_host")]
	pub host: String,
	/// Port to bind the server to.
	#[serde(default = "default_api_port")]
	pub port: u16,
	/// Request timeout in seconds.
	#[serde(default = "default_api_timeout")]
	pub timeout_seconds: u64,
	/// Maximum request size in bytes.
	#[serde(default = "default_max_request_size")]
	pub max_request_size: usize,
	/// Implementation references for API functionality.
	#[serde(default)]
	pub implementations: ApiImplementations,
	/// Rate limiting configuration.
	pub rate_limiting: Option<RateLimitConfig>,
	/// CORS configuration.
	pub cors: Option<CorsConfig>,
	/// Authentication configuration.
	pub auth: Option<solver_types::AuthConfig>,
	/// Quote generation configuration.
	pub quote: Option<QuoteConfig>,
}

/// Rate limiting configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitConfig {
	/// Maximum requests per minute per IP.
	pub requests_per_minute: u32,
	/// Burst allowance for requests.
	pub burst_size: u32,
}

/// CORS configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CorsConfig {
	/// Allowed origins for CORS.
	pub allowed_origins: Vec<String>,
	/// Allowed headers for CORS.
	pub allowed_headers: Vec<String>,
	/// Allowed methods for CORS.
	pub allowed_methods: Vec<String>,
}

/// Gas unit overrides for a specific flow.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GasFlowUnits {
	/// Optional override for open/prepare step gas units
	pub open: Option<u64>,
	/// Optional override for fill step gas units
	pub fill: Option<u64>,
	/// Optional override for claim/finalize step gas units
	#[serde(alias = "finalize")] // allow "finalize" as an alias in config
	pub claim: Option<u64>,
}

/// Configuration for pricing services.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PricingConfig {
	/// Which implementation to use as primary.
	pub primary: String,
	/// Fallback implementations to try if primary fails (in order).
	#[serde(default)]
	pub fallbacks: Vec<String>,
	/// Map of pricing implementation names to their configurations.
	pub implementations: HashMap<String, serde_json::Value>,
}

fn default_gas_buffer_bps() -> u32 {
	1000 // 10%
}

fn default_commission_bps() -> u32 {
	0 // Disabled by default for backward compatibility
}

fn default_rate_buffer_bps() -> u32 {
	14 // 0.14%
}

/// Gas configuration mapping flow identifiers to gas unit overrides.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GasConfig {
	/// Map of flow key -> GasFlowUnits
	/// Example keys: "permit2_escrow", "resource_lock"
	pub flows: HashMap<String, GasFlowUnits>,
}

/// Runtime rebalancing configuration.
///
/// Built from `OperatorRebalanceConfig` during `build_runtime_config()`.
/// Policy fields are hot-reloadable; transport fields are static at startup.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RebalanceConfig {
	/// Whether auto-rebalancing is enabled.
	pub enabled: bool,
	/// Bridge implementation name (e.g., "layerzero_vaultbridge").
	pub implementation: String,
	/// Monitor polling interval in seconds.
	pub monitor_interval_seconds: u64,
	/// Cooldown between auto-rebalances for the same pair (seconds).
	pub cooldown_seconds: u64,
	/// Maximum concurrent bridge transfers.
	pub max_pending_transfers: u32,
	/// Minimum native gas per chain (keyed by chain ID, decimal string in wei).
	#[serde(default)]
	pub min_native_gas_reserve: HashMap<u64, String>,
	/// Maximum bridge fee in bps relative to transfer amount.
	#[serde(default)]
	pub max_fee_bps: Option<u32>,
	/// Rebalance pairs (cross-chain asset pairs).
	#[serde(default)]
	pub pairs: Vec<RebalancePairConfig>,
	/// Implementation-specific transport config (opaque JSON).
	#[serde(default)]
	pub bridge_config: Option<serde_json::Value>,
}

/// Runtime pair configuration (mirror of OperatorRebalancePairConfig).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RebalancePairConfig {
	/// Unique, operator-chosen identifier for this pair (e.g., "usdc-eth-katana").
	pub pair_id: String,
	/// Chain A side of the pair.
	pub chain_a: RebalancePairSideConfig,
	/// Chain B side of the pair.
	pub chain_b: RebalancePairSideConfig,
	/// Target balance for chain A (decimal string in base units).
	pub target_balance_a: String,
	/// Target balance for chain B (decimal string in base units).
	pub target_balance_b: String,
	/// Acceptable deviation in basis points (e.g., 2000 = +/-20%).
	pub deviation_band_bps: u32,
	/// Maximum amount per bridge operation (decimal string).
	pub max_bridge_amount: String,
}

/// One side of a runtime rebalance pair.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RebalancePairSideConfig {
	/// Chain ID.
	pub chain_id: u64,
	/// Token contract address on this chain (hex string with 0x prefix).
	pub token_address: String,
	/// OFT contract address on this chain (hex string with 0x prefix).
	pub oft_address: String,
}

/// Configuration for quote generation parameters.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QuoteConfig {
	/// Quote validity duration in seconds.
	/// Defaults to 60 seconds (1 minute) if not specified.
	#[serde(default = "default_quote_validity_seconds")]
	pub validity_seconds: u64,
	/// Fill deadline duration in seconds (time to fill outputs on destination chains).
	/// Defaults to 300 seconds (5 minutes) if not specified.
	#[serde(default = "default_fill_deadline_seconds")]
	pub fill_deadline_seconds: u64,
	/// Expiry duration in seconds (time to finalize/claim on origin chain).
	/// Defaults to 600 seconds (10 minutes) if not specified.
	#[serde(default = "default_expires_seconds")]
	pub expires_seconds: u64,
}

impl Default for QuoteConfig {
	fn default() -> Self {
		Self {
			validity_seconds: default_quote_validity_seconds(),
			fill_deadline_seconds: default_fill_deadline_seconds(),
			expires_seconds: default_expires_seconds(),
		}
	}
}

/// Returns the default quote validity duration in seconds.
///
/// This provides a default value of 60 seconds (1 minute) for quote validity
/// when no explicit duration is configured.
fn default_quote_validity_seconds() -> u64 {
	60 // Default to 60 seconds (1 minute)
}

/// Returns the default fill deadline duration in seconds.
///
/// This provides a default value of 300 seconds (5 minutes) for fill deadline
/// when no explicit duration is configured.
fn default_fill_deadline_seconds() -> u64 {
	300 // Default to 300 seconds (5 minutes)
}

/// Returns the default expires duration in seconds.
///
/// This provides a default value of 600 seconds (10 minutes) for expires
/// when no explicit duration is configured.
fn default_expires_seconds() -> u64 {
	600 // Default to 600 seconds (10 minutes)
}

/// Returns the default API host.
///
/// This provides a default host address of 127.0.0.1 (localhost) for the API server
/// when no explicit host is configured.
fn default_api_host() -> String {
	"127.0.0.1".to_string()
}

/// Returns the default API port.
///
/// This provides a default port of 3000 for the API server
/// when no explicit port is configured.
fn default_api_port() -> u16 {
	3000
}

/// Returns the default API timeout in seconds.
///
/// This provides a default timeout of 30 seconds for API requests
/// when no explicit timeout is configured.
fn default_api_timeout() -> u64 {
	30
}

/// Returns the default maximum request size in bytes.
///
/// This provides a default maximum request size of 1MB (1024 * 1024 bytes)
/// when no explicit limit is configured.
fn default_max_request_size() -> usize {
	1024 * 1024 // 1MB
}

/// Resolves environment variables in a string.
///
/// Replaces ${VAR_NAME} with the value of the environment variable VAR_NAME.
/// Supports default values with ${VAR_NAME:-default_value}.
///
/// Input strings are limited to 1MB to prevent ReDoS attacks.
pub(crate) fn resolve_env_vars(input: &str) -> Result<String, ConfigError> {
	// Limit input size to prevent ReDoS attacks
	const MAX_INPUT_SIZE: usize = 1024 * 1024; // 1MB
	if input.len() > MAX_INPUT_SIZE {
		return Err(ConfigError::Validation(format!(
			"Configuration file too large: {} bytes (max: {} bytes)",
			input.len(),
			MAX_INPUT_SIZE
		)));
	}

	let re = Regex::new(r"\$\{([A-Z_][A-Z0-9_]{0,127})(?::-([^}]{0,256}))?\}")
		.map_err(|e| ConfigError::Parse(format!("Regex error: {e}")))?;

	let mut result = input.to_string();
	let mut replacements = Vec::new();

	for cap in re.captures_iter(input) {
		let full_match = cap.get(0).unwrap();
		let var_name = cap.get(1).unwrap().as_str();
		let default_value = cap.get(2).map(|m| m.as_str());

		let value = match std::env::var(var_name) {
			Ok(v) => v,
			Err(_) => {
				if let Some(default) = default_value {
					default.to_string()
				} else {
					return Err(ConfigError::Validation(format!(
						"Environment variable '{var_name}' not found"
					)));
				}
			},
		};

		replacements.push((full_match.start(), full_match.end(), value));
	}

	// Apply replacements in reverse order to maintain positions
	for (start, end, value) in replacements.iter().rev() {
		result.replace_range(start..end, value);
	}

	Ok(result)
}

impl Config {
	/// Loads configuration from a file with async environment variable resolution.
	pub async fn from_file(path: &str) -> Result<Self, ConfigError> {
		let content = tokio::fs::read_to_string(Path::new(path)).await?;
		let resolved = resolve_env_vars(&content)?;
		let config: Config = serde_json::from_str(&resolved)?;
		config.validate()?;
		Ok(config)
	}

	/// Validates the configuration to ensure all required fields are properly set.
	///
	/// This method performs comprehensive validation across all configuration sections:
	/// - Ensures solver ID is not empty
	/// - Validates storage backend is specified
	/// - Checks that at least one delivery provider is configured
	/// - Verifies account provider is set
	/// - Ensures at least one discovery source exists
	/// - Validates order implementations and strategy are configured
	/// - Checks that settlement implementations are present
	/// - Validates networks configuration
	fn validate(&self) -> Result<(), ConfigError> {
		// Validate solver config
		if self.solver.id.is_empty() {
			return Err(ConfigError::Validation("Solver ID cannot be empty".into()));
		}

		// Validate networks config
		if self.networks.is_empty() {
			return Err(ConfigError::Validation(
				"Networks configuration cannot be empty".into(),
			));
		}
		if self.networks.len() < 2 {
			return Err(ConfigError::Validation(
				"At least 2 different networks must be configured".into(),
			));
		}
		for (chain_id, network) in &self.networks {
			if network.input_settler_address.0.is_empty() {
				return Err(ConfigError::Validation(format!(
					"Network {chain_id} must have input_settler_address"
				)));
			}
			if network.output_settler_address.0.is_empty() {
				return Err(ConfigError::Validation(format!(
					"Network {chain_id} must have output_settler_address"
				)));
			}
		}

		// Validate storage config
		if self.storage.implementations.is_empty() {
			return Err(ConfigError::Validation(
				"At least one storage implementation must be configured".into(),
			));
		}
		if self.storage.primary.is_empty() {
			return Err(ConfigError::Validation(
				"Storage primary implementation cannot be empty".into(),
			));
		}
		if !self
			.storage
			.implementations
			.contains_key(&self.storage.primary)
		{
			return Err(ConfigError::Validation(format!(
				"Primary storage '{}' not found in implementations",
				self.storage.primary
			)));
		}
		if self.storage.cleanup_interval_seconds == 0 {
			return Err(ConfigError::Validation(
				"Storage cleanup_interval_seconds must be greater than 0".into(),
			));
		}
		if self.storage.cleanup_interval_seconds > 86400 {
			return Err(ConfigError::Validation(
				"Storage cleanup_interval_seconds cannot exceed 86400 (24 hours)".into(),
			));
		}

		// Validate delivery config
		if self.delivery.implementations.is_empty() {
			return Err(ConfigError::Validation(
				"At least one delivery implementation required".into(),
			));
		}

		// Validate min_confirmations is within reasonable bounds
		if self.delivery.min_confirmations == 0 {
			return Err(ConfigError::Validation(
				"min_confirmations must be at least 1".into(),
			));
		}
		if self.delivery.min_confirmations > 100 {
			return Err(ConfigError::Validation(
				"min_confirmations cannot exceed 100".into(),
			));
		}

		// Validate monitoring timeout is reasonable (between 30 seconds and 14 days).
		// Optimistic-rollup broadcaster routes (e.g. Arbitrum L2→L1) require the
		// solver to monitor for claim readiness across the full challenge period
		// (~7 days), so the upper bound must accommodate week-scale timeouts.
		if self.solver.monitoring_timeout_seconds < 30
			|| self.solver.monitoring_timeout_seconds > 1_209_600
		{
			return Err(ConfigError::Validation(
				"monitoring_timeout_seconds must be between 30 and 1209600 seconds (14 days)"
					.into(),
			));
		}

		// Validate account config
		if self.account.implementations.is_empty() {
			return Err(ConfigError::Validation(
				"Account implementation cannot be empty".into(),
			));
		}

		// Validate discovery config
		if self.discovery.implementations.is_empty() {
			return Err(ConfigError::Validation(
				"At least one discovery implementation required".into(),
			));
		}

		// Validate order config
		if self.order.implementations.is_empty() {
			return Err(ConfigError::Validation(
				"At least one order implementation required".into(),
			));
		}
		if self.order.strategy.primary.is_empty() {
			return Err(ConfigError::Validation(
				"Order strategy primary cannot be empty".into(),
			));
		}
		if self.order.strategy.implementations.is_empty() {
			return Err(ConfigError::Validation(
				"At least one strategy implementation required".into(),
			));
		}

		// Validate settlement config
		if self.settlement.implementations.is_empty() {
			return Err(ConfigError::Validation(
				"At least one settlement implementation required".into(),
			));
		}
		if self.settlement.primary.is_empty() {
			return Err(ConfigError::Validation(
				"settlement.primary must be set".into(),
			));
		}
		if !self
			.settlement
			.implementations
			.contains_key(&self.settlement.primary)
		{
			return Err(ConfigError::Validation(format!(
				"settlement.primary '{}' not found in settlement.implementations",
				self.settlement.primary
			)));
		}

		// Validate settlement poll interval (1-monitoring_timeout_seconds)
		// Settlement can be slower, especially for cross-chain
		if self.settlement.settlement_poll_interval_seconds < 1
			|| self.settlement.settlement_poll_interval_seconds
				> self.solver.monitoring_timeout_seconds
		{
			return Err(ConfigError::Validation(format!(
				"settlement_poll_interval_seconds must be between 1 and {}",
				self.solver.monitoring_timeout_seconds
			)));
		}

		// Validate API config if enabled
		if let Some(ref api) = self.api {
			if api.enabled {
				// Validate discovery implementation exists if specified
				if let Some(ref discovery) = api.implementations.discovery {
					if !self.discovery.implementations.contains_key(discovery) {
						return Err(ConfigError::Validation(format!(
							"API discovery implementation '{discovery}' not found in discovery.implementations"
						)));
					}
				}
			}
		}

		// Validate settlement configurations and coverage
		self.validate_settlement_coverage()?;

		// Validate rebalance config if present
		if let Some(ref rebalance) = self.rebalance {
			if rebalance.enabled {
				if rebalance.implementation.is_empty() {
					return Err(ConfigError::Validation(
						"Rebalance implementation cannot be empty when enabled".into(),
					));
				}
				if rebalance.monitor_interval_seconds == 0 {
					return Err(ConfigError::Validation(
						"Rebalance monitor_interval_seconds must be > 0".into(),
					));
				}
				if rebalance.cooldown_seconds == 0 {
					return Err(ConfigError::Validation(
						"Rebalance cooldown_seconds must be > 0".into(),
					));
				}
				if rebalance.max_pending_transfers == 0 {
					return Err(ConfigError::Validation(
						"Rebalance max_pending_transfers must be > 0 when enabled".into(),
					));
				}
				if rebalance.bridge_config.is_none() {
					return Err(ConfigError::Validation(
						"Rebalance bridge_config must be present when rebalance is enabled".into(),
					));
				}
				if rebalance.pairs.is_empty() {
					return Err(ConfigError::Validation(
						"Rebalance must have at least one pair when enabled".into(),
					));
				}
				let mut seen_ids = std::collections::HashSet::new();
				for pair in &rebalance.pairs {
					if pair.pair_id.is_empty() {
						return Err(ConfigError::Validation(
							"Rebalance pair_id cannot be empty".into(),
						));
					}
					if !seen_ids.insert(&pair.pair_id) {
						return Err(ConfigError::Validation(format!(
							"Duplicate rebalance pair_id: '{}'",
							pair.pair_id
						)));
					}
				}
			}
		}

		Ok(())
	}

	/// Validates settlement implementation coverage.
	///
	/// # Returns
	/// * `Ok(())` if coverage is valid and complete
	/// * `Err(ConfigError::Validation)` with specific error
	///
	/// # Validation Rules
	/// 1. Each settlement must declare 'standard' and 'network_ids'
	/// 2. No two settlements may cover same standard+network
	/// 3. Every order standard must have at least one settlement
	/// 4. All network_ids must exist in networks configuration
	fn validate_settlement_coverage(&self) -> Result<(), ConfigError> {
		// Track coverage: (standard, network_id) -> implementation_name
		let mut coverage: HashMap<(String, u64), String> = HashMap::new();

		// Parse and validate each settlement implementation
		for (impl_name, impl_config) in &self.settlement.implementations {
			// Extract standard field
			let order_standard = impl_config
				.get("order")
				.and_then(|v| v.as_str())
				.ok_or_else(|| {
					ConfigError::Validation(format!(
						"Settlement implementation '{impl_name}' missing 'order' field"
					))
				})?;

			// Extract network_ids
			let network_ids = impl_config
				.get("network_ids")
				.and_then(|v| v.as_array())
				.ok_or_else(|| {
					ConfigError::Validation(format!(
						"Settlement implementation '{impl_name}' missing 'network_ids' field"
					))
				})?;

			// Check for duplicate coverage
			for network_value in network_ids {
				let network_id = network_value.as_i64().ok_or_else(|| {
					ConfigError::Validation(format!(
						"Invalid network_id in settlement '{impl_name}'"
					))
				})? as u64;

				let key = (order_standard.to_string(), network_id);

				if let Some(existing) = coverage.insert(key.clone(), impl_name.clone()) {
					return Err(ConfigError::Validation(format!(
						"Duplicate settlement coverage for order '{order_standard}' on network {network_id}: '{existing}' and '{impl_name}'"
					)));
				}

				// Validate network exists in networks config
				if !self.networks.contains_key(&network_id) {
					return Err(ConfigError::Validation(format!(
						"Settlement '{impl_name}' references network {network_id} which doesn't exist in networks config"
					)));
				}
			}
		}

		// Validate all order implementations have settlement coverage
		for order_standard in self.order.implementations.keys() {
			// Orders might not specify networks directly, but we need to ensure
			// the standard is covered somewhere
			let has_coverage = coverage.keys().any(|(std, _)| std == order_standard);

			if !has_coverage {
				return Err(ConfigError::Validation(format!(
					"Order standard '{order_standard}' has no settlement implementations"
				)));
			}
		}

		Ok(())
	}
}

/// Implementation of FromStr trait for Config to enable parsing from string.
///
/// This allows configuration to be parsed from JSON strings using the standard
/// string parsing interface. Environment variables are resolved and the
/// configuration is automatically validated after parsing.
impl FromStr for Config {
	type Err = ConfigError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let resolved = resolve_env_vars(s)?;
		let config: Config = serde_json::from_str(&resolved)?;
		config.validate()?;
		Ok(config)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::json;

	fn parse_json_fixture(value: serde_json::Value) -> Result<Config, ConfigError> {
		let json_string =
			serde_json::to_string(&value).map_err(|err| ConfigError::Parse(err.to_string()))?;
		Config::from_str(&json_string)
	}

	fn test_network(chain_id: u32, rpc_url: &str) -> serde_json::Value {
		json!({
			"chain_id": chain_id,
			"input_settler_address": "0x1234567890123456789012345678901234567890",
			"output_settler_address": "0x0987654321098765432109876543210987654321",
			"rpc_urls": [{ "http": rpc_url }],
			"tokens": [{
				"address": "0xabcdef1234567890abcdef1234567890abcdef12",
				"symbol": "TEST",
				"decimals": 18
			}]
		})
	}

	fn base_config_json(
		networks: serde_json::Value,
		order_implementations: serde_json::Value,
		settlement_implementations: serde_json::Value,
	) -> serde_json::Value {
		let settlement_primary = settlement_implementations
			.as_object()
			.and_then(|implementations| implementations.keys().next().cloned())
			.unwrap_or_default();

		json!({
			"solver": {
				"id": "test",
				"monitoring_timeout_seconds": 300,
				"min_profitability_pct": 5.0
			},
			"networks": networks,
			"storage": {
				"primary": "memory",
				"cleanup_interval_seconds": 3600,
				"implementations": {
					"memory": {}
				}
			},
			"delivery": {
				"implementations": {
					"test": {}
				}
			},
			"account": {
				"primary": "local",
				"implementations": {
					"local": {
						"private_key": "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
					}
				}
			},
			"discovery": {
				"implementations": {
					"test": {}
				}
			},
			"order": {
				"implementations": order_implementations,
				"strategy": {
					"primary": "simple",
					"implementations": {
						"simple": {}
					}
				}
			},
			"settlement": {
				"implementations": settlement_implementations,
				"primary": settlement_primary
			}
		})
	}

	#[test]
	fn test_env_var_resolution() {
		// Set up test environment variables
		std::env::set_var("TEST_HOST", "localhost");
		std::env::set_var("TEST_PORT", "5432");

		let input = r#"{"host":"${TEST_HOST}:${TEST_PORT}"}"#;
		let result = resolve_env_vars(input).unwrap();
		assert_eq!(result, r#"{"host":"localhost:5432"}"#);

		// Clean up
		std::env::remove_var("TEST_HOST");
		std::env::remove_var("TEST_PORT");
	}

	#[test]
	fn test_env_var_with_default() {
		let input = r#"{"value":"${MISSING_VAR:-default_value}"}"#;
		let result = resolve_env_vars(input).unwrap();
		assert_eq!(result, r#"{"value":"default_value"}"#);
	}

	#[test]
	fn test_missing_env_var_error() {
		let input = r#"{"value":"${MISSING_VAR}"}"#;
		let result = resolve_env_vars(input);
		assert!(result.is_err());
		assert!(result.unwrap_err().to_string().contains("MISSING_VAR"));
	}

	#[test]
	fn test_config_with_env_vars() {
		// Set environment variable
		std::env::set_var("TEST_SOLVER_ID", "test-solver");
		let config = parse_json_fixture(json!({
			"solver": {
				"id": "${TEST_SOLVER_ID}",
				"monitoring_timeout_seconds": 300,
				"min_profitability_pct": 1.0
			},
			"networks": {
				"1": test_network(1, "http://localhost:8545"),
				"2": test_network(2, "http://localhost:8546")
			},
			"storage": {
				"primary": "memory",
				"cleanup_interval_seconds": 3600,
				"implementations": {
					"memory": {}
				}
			},
			"delivery": {
				"implementations": {
					"test": {}
				}
			},
			"account": {
				"primary": "local",
				"implementations": {
					"local": {
						"private_key": "${TEST_PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
					}
				}
			},
			"discovery": {
				"implementations": {
					"test": {}
				}
			},
			"order": {
				"implementations": {
					"test": {}
				},
				"strategy": {
					"primary": "simple",
					"implementations": {
						"simple": {}
					}
				}
				},
				"settlement": {
					"primary": "test",
					"implementations": {
						"test": {
							"order": "test",
							"network_ids": [1, 2]
						}
					}
				}
			}))
			.unwrap();
		assert_eq!(config.solver.id, "test-solver");
		assert_eq!(
			config.solver.min_profitability_pct,
			Decimal::from_str("1.0").unwrap()
		);

		// Clean up
		std::env::remove_var("TEST_SOLVER_ID");
	}

	#[test]
	fn test_config_allows_empty_network_tokens() {
		fn empty_token_network(rpc_url: &str) -> serde_json::Value {
			json!({
				"input_settler_address": "0x1234567890123456789012345678901234567890",
				"output_settler_address": "0x0987654321098765432109876543210987654321",
				"rpc_urls": [{ "http": rpc_url }],
				"tokens": []
			})
		}

		let config = parse_json_fixture(base_config_json(
			json!({
				"1": empty_token_network("http://localhost:8545"),
				"2": empty_token_network("http://localhost:8546")
			}),
			json!({
				"test": {}
			}),
			json!({
			"test": {
				"order": "test",
				"network_ids": [1, 2]
			}
			}),
		))
		.expect("Config should parse");
		assert_eq!(config.networks.get(&1).unwrap().tokens.len(), 0);
		assert_eq!(config.networks.get(&2).unwrap().tokens.len(), 0);
	}

	#[test]
	fn test_duplicate_settlement_coverage_rejected() {
		let result = parse_json_fixture(base_config_json(
			json!({
				"1": test_network(1, "http://localhost:8545"),
				"2": test_network(2, "http://localhost:8546"),
				"3": test_network(3, "http://localhost:8547")
			}),
			json!({
				"eip7683": {}
			}),
			json!({
			"impl1": {
				"order": "eip7683",
				"network_ids": [1, 2]
			},
			"impl2": {
				"order": "eip7683",
				"network_ids": [2, 3]
				}
			}),
		));
		assert!(result.is_err());
		let err = result.unwrap_err();
		// The test should fail because network 2 is covered by both impl1 and impl2
		// Check for the key parts of the error message
		let error_msg = err.to_string();
		assert!(
			error_msg.contains("network 2")
				&& error_msg.contains("impl1")
				&& error_msg.contains("impl2"),
			"Expected duplicate coverage error for network 2, got: {err}"
		);
	}

	#[test]
	fn test_missing_settlement_standard_rejected() {
		let result = parse_json_fixture(base_config_json(
			json!({
				"1": test_network(1, "http://localhost:8545"),
				"2": test_network(2, "http://localhost:8546")
			}),
			json!({
				"eip7683": {}
			}),
			json!({
			"impl1": {
				"network_ids": [1, 2]
				}
			}),
		));
		assert!(result.is_err());
		let err = result.unwrap_err();
		assert!(err.to_string().contains("missing 'order' field"));
	}

	#[test]
	fn test_settlement_references_invalid_network() {
		let result = parse_json_fixture(base_config_json(
			json!({
				"1": test_network(1, "http://localhost:8545"),
				"2": test_network(2, "http://localhost:8546")
			}),
			json!({
				"eip7683": {}
			}),
			json!({
			"impl1": {
				"order": "eip7683",
				"network_ids": [1, 2, 999]
				}
			}),
		));
		assert!(result.is_err());
		let err = result.unwrap_err();
		assert!(err
			.to_string()
			.contains("references network 999 which doesn't exist"));
	}

	#[test]
	fn test_order_standard_without_settlement() {
		let result = parse_json_fixture(base_config_json(
			json!({
				"1": test_network(1, "http://localhost:8545"),
				"2": test_network(2, "http://localhost:8546")
			}),
			json!({
				"eip7683": {},
				"eip9999": {}
			}),
			json!({
			"impl1": {
				"order": "eip7683",
				"network_ids": [1, 2]
				}
			}),
		));
		assert!(result.is_err());
		let err = result.unwrap_err();
		assert!(err
			.to_string()
			.contains("Order standard 'eip9999' has no settlement implementations"));
	}

	#[test]
	fn test_monitoring_timeout_accepts_lower_and_upper_bounds() {
		let networks = json!({
			"1": test_network(1, "http://localhost:8545"),
			"2": test_network(2, "http://localhost:8546")
		});
		let order_implementations = json!({
			"test": {}
		});
		let settlement_implementations = json!({
			"test": {
				"order": "test",
				"network_ids": [1, 2]
			}
		});

		let mut lower_bound = base_config_json(
			networks.clone(),
			order_implementations.clone(),
			settlement_implementations.clone(),
		);
		lower_bound["solver"]["monitoring_timeout_seconds"] = json!(30);
		assert!(parse_json_fixture(lower_bound).is_ok());

		let mut upper_bound =
			base_config_json(networks, order_implementations, settlement_implementations);
		upper_bound["solver"]["monitoring_timeout_seconds"] = json!(1_209_600);
		assert!(parse_json_fixture(upper_bound).is_ok());
	}

	#[test]
	fn test_monitoring_timeout_rejects_values_outside_extended_range() {
		let networks = json!({
			"1": test_network(1, "http://localhost:8545"),
			"2": test_network(2, "http://localhost:8546")
		});
		let order_implementations = json!({
			"test": {}
		});
		let settlement_implementations = json!({
			"test": {
				"order": "test",
				"network_ids": [1, 2]
			}
		});

		let mut too_small = base_config_json(
			networks.clone(),
			order_implementations.clone(),
			settlement_implementations.clone(),
		);
		too_small["solver"]["monitoring_timeout_seconds"] = json!(29);
		assert!(matches!(
			parse_json_fixture(too_small),
			Err(ConfigError::Validation(message))
				if message.contains("monitoring_timeout_seconds")
		));

		let mut too_large =
			base_config_json(networks, order_implementations, settlement_implementations);
		too_large["solver"]["monitoring_timeout_seconds"] = json!(1_209_601);
		assert!(matches!(
			parse_json_fixture(too_large),
			Err(ConfigError::Validation(message))
				if message.contains("monitoring_timeout_seconds")
		));
	}

	#[test]
	fn test_pair_id_is_explicit_config_field() {
		let pair = RebalancePairConfig {
			pair_id: "usdc-eth-katana".to_string(),
			chain_a: RebalancePairSideConfig {
				chain_id: 1,
				token_address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
				oft_address: "0x0000000000000000000000000000000000000001".to_string(),
			},
			chain_b: RebalancePairSideConfig {
				chain_id: 747474,
				token_address: "0x0000000000000000000000000000000000000002".to_string(),
				oft_address: "0x0000000000000000000000000000000000000003".to_string(),
			},
			target_balance_a: "1000000".to_string(),
			target_balance_b: "1000000".to_string(),
			deviation_band_bps: 2000,
			max_bridge_amount: "500000".to_string(),
		};

		// pair_id is the value set by the operator, not derived
		assert_eq!(pair.pair_id, "usdc-eth-katana");
	}

	#[test]
	fn test_same_symbol_different_tokens_can_coexist_with_distinct_pair_ids() {
		// Two USDC variants on the same chain pair (e.g., native USDC vs bridged eUSDC)
		// can coexist as long as the operator gives them different pair_ids.
		let native_usdc = RebalancePairConfig {
			pair_id: "usdc-native-eth-arb".to_string(),
			chain_a: RebalancePairSideConfig {
				chain_id: 1,
				token_address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
				oft_address: "0x0000000000000000000000000000000000000001".to_string(),
			},
			chain_b: RebalancePairSideConfig {
				chain_id: 42161,
				token_address: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831".to_string(),
				oft_address: "0x0000000000000000000000000000000000000002".to_string(),
			},
			target_balance_a: "1000000".to_string(),
			target_balance_b: "1000000".to_string(),
			deviation_band_bps: 2000,
			max_bridge_amount: "500000".to_string(),
		};

		let bridged_usdc = RebalancePairConfig {
			pair_id: "usdc-bridged-eth-arb".to_string(),
			chain_a: RebalancePairSideConfig {
				chain_id: 1,
				token_address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
				oft_address: "0x0000000000000000000000000000000000000003".to_string(),
			},
			chain_b: RebalancePairSideConfig {
				chain_id: 42161,
				// Different token address — bridged variant
				token_address: "0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8".to_string(),
				oft_address: "0x0000000000000000000000000000000000000004".to_string(),
			},
			target_balance_a: "1000000".to_string(),
			target_balance_b: "1000000".to_string(),
			deviation_band_bps: 2000,
			max_bridge_amount: "500000".to_string(),
		};

		// Distinct pair_ids — no collision
		assert_ne!(native_usdc.pair_id, bridged_usdc.pair_id);
	}

	fn base_rebalance_config_json() -> serde_json::Value {
		let mut config = base_config_json(
			json!({
				"1": test_network(1, "http://localhost:8545"),
				"747474": test_network(747474, "http://localhost:9545")
			}),
			json!({ "test": {} }),
			json!({
				"test": {
					"order": "test",
					"network_ids": [1, 747474]
				}
			}),
		);

		config["rebalance"] = json!({
			"enabled": true,
			"implementation": "layerzero",
			"monitor_interval_seconds": 15,
			"cooldown_seconds": 60,
			"max_pending_transfers": 3,
			"bridge_config": {
				"composer_addresses": {},
				"vault_addresses": { "1": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
			},
			"pairs": [{
				"pair_id": "eth-katana",
				"chain_a": {
					"chain_id": 1,
					"token_address": "0x1111111111111111111111111111111111111111",
					"oft_address": "0x2222222222222222222222222222222222222222"
				},
				"chain_b": {
					"chain_id": 747474,
					"token_address": "0x3333333333333333333333333333333333333333",
					"oft_address": "0x4444444444444444444444444444444444444444"
				},
				"target_balance_a": "1000000",
				"target_balance_b": "1000000",
				"deviation_band_bps": 2000,
				"max_bridge_amount": "500000"
			}]
		});
		config
	}

	#[test]
	fn test_rebalance_enabled_requires_non_empty_implementation() {
		let mut config = base_rebalance_config_json();
		config["rebalance"]["implementation"] = json!("");

		let result = parse_json_fixture(config);
		assert!(matches!(
			result,
			Err(ConfigError::Validation(message))
				if message.contains("Rebalance implementation cannot be empty when enabled")
		));
	}

	#[test]
	fn test_rebalance_requires_non_zero_intervals_and_pending_limit() {
		let mut zero_monitor = base_rebalance_config_json();
		zero_monitor["rebalance"]["monitor_interval_seconds"] = json!(0);
		assert!(matches!(
			parse_json_fixture(zero_monitor),
			Err(ConfigError::Validation(message))
				if message.contains("monitor_interval_seconds")
		));

		let mut zero_cooldown = base_rebalance_config_json();
		zero_cooldown["rebalance"]["cooldown_seconds"] = json!(0);
		assert!(matches!(
			parse_json_fixture(zero_cooldown),
			Err(ConfigError::Validation(message))
				if message.contains("cooldown_seconds")
		));

		let mut zero_pending = base_rebalance_config_json();
		zero_pending["rebalance"]["max_pending_transfers"] = json!(0);
		assert!(matches!(
			parse_json_fixture(zero_pending),
			Err(ConfigError::Validation(message))
				if message.contains("max_pending_transfers")
		));
	}

	#[test]
	fn test_rebalance_enabled_requires_bridge_config() {
		let mut config = base_rebalance_config_json();
		config["rebalance"]["bridge_config"] = serde_json::Value::Null;

		let result = parse_json_fixture(config);
		assert!(matches!(
			result,
			Err(ConfigError::Validation(message))
				if message.contains("bridge_config must be present when rebalance is enabled")
		));
	}

	#[test]
	fn test_rebalance_rejects_empty_pair_id() {
		let mut config = base_rebalance_config_json();
		config["rebalance"]["pairs"][0]["pair_id"] = json!("");

		let result = parse_json_fixture(config);
		assert!(matches!(
			result,
			Err(ConfigError::Validation(message))
				if message.contains("pair_id cannot be empty")
		));
	}

	#[test]
	fn test_rebalance_rejects_duplicate_pair_ids() {
		let mut config = base_rebalance_config_json();
		let duplicate = config["rebalance"]["pairs"][0].clone();
		config["rebalance"]["pairs"]
			.as_array_mut()
			.unwrap()
			.push(duplicate);

		let result = parse_json_fixture(config);
		assert!(matches!(
			result,
			Err(ConfigError::Validation(message))
				if message.contains("Duplicate rebalance pair_id")
		));
	}
}
