//! Configuration module for the OIF solver system.
//!
//! This module provides structures and utilities for managing solver configuration.
//! It supports loading configuration from TOML files and provides validation to ensure
//! all required configuration values are properly set.
//!
//! ## Modular Configuration Support
//!
//! Configurations can be split into multiple files for better organization:
//! - Use `include = ["file1.toml", "file2.toml"]` to include other config files
//! - Each top-level section must be unique across all files (no duplicates allowed)

pub mod builders;
mod loader;

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
	/// Error that occurs when parsing TOML configuration.
	#[error("Configuration error: {0}")]
	Parse(String),
	/// Error that occurs when configuration validation fails.
	#[error("Validation error: {0}")]
	Validation(String),
}

impl From<toml::de::Error> for ConfigError {
	fn from(err: toml::de::Error) -> Self {
		// Extract just the message without the huge input dump
		let message = err.message().to_string();
		ConfigError::Parse(message)
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
}

/// Configuration specific to the solver instance.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SolverConfig {
	/// Unique identifier for this solver instance.
	pub id: String,
	/// Timeout duration in minutes for monitoring operations.
	/// Defaults to 480 minutes (8 hours) if not specified.
	#[serde(default = "default_monitoring_timeout_minutes")]
	pub monitoring_timeout_minutes: u64,
	/// Minimum profitability percentage required to execute orders.
	pub min_profitability_pct: Decimal,
}

/// Returns the default monitoring timeout in minutes.
///
/// This provides a default value of 480 minutes (8 hours) for monitoring operations
/// when no explicit timeout is configured.
fn default_monitoring_timeout_minutes() -> u64 {
	480 // Default to 8 hours
}

/// Configuration for the storage backend.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StorageConfig {
	/// Which implementation to use as primary.
	pub primary: String,
	/// Map of storage implementation names to their configurations.
	pub implementations: HashMap<String, toml::Value>,
	/// Interval in seconds for cleaning up expired storage entries.
	pub cleanup_interval_seconds: u64,
}

/// Configuration for delivery mechanisms.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeliveryConfig {
	/// Map of delivery implementation names to their configurations.
	/// Each implementation has its own configuration format stored as raw TOML values.
	pub implementations: HashMap<String, toml::Value>,
	/// Minimum number of confirmations required for transactions.
	/// Defaults to 12 confirmations if not specified.
	#[serde(default = "default_confirmations")]
	pub min_confirmations: u64,
}

/// Returns the default number of confirmations required.
///
/// This provides a default value of 12 confirmations for transaction finality
/// when no explicit confirmation count is configured.
fn default_confirmations() -> u64 {
	12 // Default to 12 confirmations
}

/// Configuration for account management.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AccountConfig {
	/// Which implementation to use as primary.
	pub primary: String,
	/// Map of account implementation names to their configurations.
	pub implementations: HashMap<String, toml::Value>,
}

/// Configuration for order discovery.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DiscoveryConfig {
	/// Map of discovery implementation names to their configurations.
	/// Each implementation has its own configuration format stored as raw TOML values.
	pub implementations: HashMap<String, toml::Value>,
}

/// Configuration for order processing.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OrderConfig {
	/// Map of order implementation names to their configurations.
	/// Each implementation handles specific order types.
	pub implementations: HashMap<String, toml::Value>,
	/// Strategy configuration for order execution.
	pub strategy: StrategyConfig,
}

/// Configuration for execution strategies.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StrategyConfig {
	/// Which strategy implementation to use as primary.
	pub primary: String,
	/// Map of strategy implementation names to their configurations.
	pub implementations: HashMap<String, toml::Value>,
}

/// Configuration for settlement operations.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SettlementConfig {
	/// Map of settlement implementation names to their configurations.
	/// Each implementation handles specific settlement mechanisms.
	pub implementations: HashMap<String, toml::Value>,
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
	/// Map of pricing implementation names to their configurations.
	pub implementations: HashMap<String, toml::Value>,
}

/// Gas configuration mapping flow identifiers to gas unit overrides.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GasConfig {
	/// Map of flow key -> GasFlowUnits
	/// Example keys: "permit2_escrow", "resource_lock"
	pub flows: HashMap<String, GasFlowUnits>,
}

/// Configuration for quote generation parameters.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QuoteConfig {
	/// Quote validity duration in seconds.
	/// Defaults to 20 seconds if not specified.
	#[serde(default = "default_quote_validity_seconds")]
	pub validity_seconds: u64,
}

impl Default for QuoteConfig {
	fn default() -> Self {
		Self {
			validity_seconds: default_quote_validity_seconds(),
		}
	}
}

/// Returns the default quote validity duration in seconds.
///
/// This provides a default value of 20 seconds for quote validity
/// when no explicit duration is configured.
fn default_quote_validity_seconds() -> u64 {
	20 // Default to 20 seconds
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
		.map_err(|e| ConfigError::Parse(format!("Regex error: {}", e)))?;

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
						"Environment variable '{}' not found",
						var_name
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
	///
	/// This method supports modular configuration through include directives:
	/// - `include = ["file1.toml", "file2.toml"]` - Include specific files
	///
	/// Each top-level section must be unique across all configuration files.
	///
	/// Environment variables are loaded from .env files in the current working directory.
	pub async fn from_file(path: &str) -> Result<Self, ConfigError> {
		let path_buf = Path::new(path);
		let base_dir = path_buf.parent().unwrap_or_else(|| Path::new("."));

		// Create loader with config file's base directory for includes
		let mut loader = loader::ConfigLoader::new(base_dir);

		let file_name = path_buf
			.file_name()
			.ok_or_else(|| ConfigError::Validation(format!("Invalid path: {}", path)))?;
		loader.load_config(file_name).await
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
					"Network {} must have input_settler_address",
					chain_id
				)));
			}
			if network.output_settler_address.0.is_empty() {
				return Err(ConfigError::Validation(format!(
					"Network {} must have output_settler_address",
					chain_id
				)));
			}
			if network.tokens.is_empty() {
				return Err(ConfigError::Validation(format!(
					"Network {} must have at least 1 token configured",
					chain_id
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

		let monitoring_timeout_in_seconds = self.solver.monitoring_timeout_minutes * 60;

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

		// Validate settlement poll interval (1-monitoring_timeout_in_seconds)
		// Settlement can be slower, especially for cross-chain
		if self.settlement.settlement_poll_interval_seconds < 1
			|| self.settlement.settlement_poll_interval_seconds > monitoring_timeout_in_seconds
		{
			return Err(ConfigError::Validation(format!(
				"settlement_poll_interval_seconds must be between 1 and {}",
				monitoring_timeout_in_seconds
			)));
		}

		// Validate API config if enabled
		if let Some(ref api) = self.api {
			if api.enabled {
				// Validate discovery implementation exists if specified
				if let Some(ref discovery) = api.implementations.discovery {
					if !self.discovery.implementations.contains_key(discovery) {
						return Err(ConfigError::Validation(format!(
							"API discovery implementation '{}' not found in discovery.implementations",
							discovery
						)));
					}
				}
			}
		}

		// Validate settlement configurations and coverage
		self.validate_settlement_coverage()?;

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
						"Settlement implementation '{}' missing 'order' field",
						impl_name
					))
				})?;

			// Extract network_ids
			let network_ids = impl_config
				.get("network_ids")
				.and_then(|v| v.as_array())
				.ok_or_else(|| {
					ConfigError::Validation(format!(
						"Settlement implementation '{}' missing 'network_ids' field",
						impl_name
					))
				})?;

			// Check for duplicate coverage
			for network_value in network_ids {
				let network_id = network_value.as_integer().ok_or_else(|| {
					ConfigError::Validation(format!(
						"Invalid network_id in settlement '{}'",
						impl_name
					))
				})? as u64;

				let key = (order_standard.to_string(), network_id);

				if let Some(existing) = coverage.insert(key.clone(), impl_name.clone()) {
					return Err(ConfigError::Validation(format!(
						"Duplicate settlement coverage for order '{}' on network {}: '{}' and '{}'",
						order_standard, network_id, existing, impl_name
					)));
				}

				// Validate network exists in networks config
				if !self.networks.contains_key(&network_id) {
					return Err(ConfigError::Validation(format!(
						"Settlement '{}' references network {} which doesn't exist in networks config",
						impl_name, network_id
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
					"Order standard '{}' has no settlement implementations",
					order_standard
				)));
			}
		}

		Ok(())
	}
}

/// Implementation of FromStr trait for Config to enable parsing from string.
///
/// This allows configuration to be parsed from TOML strings using the standard
/// string parsing interface. Environment variables are resolved and the
/// configuration is automatically validated after parsing.
impl FromStr for Config {
	type Err = ConfigError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let resolved = resolve_env_vars(s)?;
		let config: Config = toml::from_str(&resolved)?;
		config.validate()?;
		Ok(config)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_env_var_resolution() {
		// Set up test environment variables
		std::env::set_var("TEST_HOST", "localhost");
		std::env::set_var("TEST_PORT", "5432");

		let input = "host = \"${TEST_HOST}:${TEST_PORT}\"";
		let result = resolve_env_vars(input).unwrap();
		assert_eq!(result, "host = \"localhost:5432\"");

		// Clean up
		std::env::remove_var("TEST_HOST");
		std::env::remove_var("TEST_PORT");
	}

	#[test]
	fn test_env_var_with_default() {
		let input = "value = \"${MISSING_VAR:-default_value}\"";
		let result = resolve_env_vars(input).unwrap();
		assert_eq!(result, "value = \"default_value\"");
	}

	#[test]
	fn test_missing_env_var_error() {
		let input = "value = \"${MISSING_VAR}\"";
		let result = resolve_env_vars(input);
		assert!(result.is_err());
		assert!(result.unwrap_err().to_string().contains("MISSING_VAR"));
	}

	#[test]
	fn test_config_with_env_vars() {
		// Set environment variable
		std::env::set_var("TEST_SOLVER_ID", "test-solver");

		let config_str = r#"
[solver]
id = "${TEST_SOLVER_ID}"
monitoring_timeout_minutes = 5
min_profitability_pct = 1.0

[networks.1]
input_settler_address = "0x1234567890123456789012345678901234567890"
output_settler_address = "0x0987654321098765432109876543210987654321"
[[networks.1.rpc_urls]]
http = "http://localhost:8545"
[[networks.1.tokens]]
address = "0xabcdef1234567890abcdef1234567890abcdef12"
symbol = "TEST"
decimals = 18

[networks.2]
input_settler_address = "0x1234567890123456789012345678901234567890"
output_settler_address = "0x0987654321098765432109876543210987654321"
[[networks.2.rpc_urls]]
http = "http://localhost:8546"
[[networks.2.tokens]]
address = "0xabcdef1234567890abcdef1234567890abcdef12"
symbol = "TEST"
decimals = 18

[storage]
primary = "memory"
cleanup_interval_seconds = 3600
[storage.implementations.memory]

[delivery]
[delivery.implementations.test]

[account]
primary = "local"
[account.implementations.local]
private_key = "${TEST_PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

[discovery]
[discovery.implementations.test]

[order]
[order.implementations.test]
[order.strategy]
primary = "simple"
[order.strategy.implementations.simple]

[settlement]
[settlement.implementations.test]
order = "test"
network_ids = [1, 2]
"#;

		let config: Config = config_str.parse().unwrap();
		assert_eq!(config.solver.id, "test-solver");
		assert_eq!(
			config.solver.min_profitability_pct,
			Decimal::from_str("1.0").unwrap()
		);

		// Clean up
		std::env::remove_var("TEST_SOLVER_ID");
	}

	#[test]
	fn test_duplicate_settlement_coverage_rejected() {
		let config_str = r#"
[solver]
id = "test"
monitoring_timeout_minutes = 5
min_profitability_pct = 5.0  # Minimum profitability percentage required to execute orders

[networks.1]
input_settler_address = "0x1234567890123456789012345678901234567890"
output_settler_address = "0x0987654321098765432109876543210987654321"
[[networks.1.rpc_urls]]
http = "http://localhost:8545"
[[networks.1.tokens]]
address = "0xabcdef1234567890abcdef1234567890abcdef12"
symbol = "TEST"
decimals = 18

[networks.2]
input_settler_address = "0x1234567890123456789012345678901234567890"
output_settler_address = "0x0987654321098765432109876543210987654321"
[[networks.2.rpc_urls]]
http = "http://localhost:8546"
[[networks.2.tokens]]
address = "0xabcdef1234567890abcdef1234567890abcdef12"
symbol = "TEST"
decimals = 18

[networks.3]
input_settler_address = "0x1234567890123456789012345678901234567890"
output_settler_address = "0x0987654321098765432109876543210987654321"
[[networks.3.rpc_urls]]
http = "http://localhost:8547"
[[networks.3.tokens]]
address = "0xabcdef1234567890abcdef1234567890abcdef12"
symbol = "TEST"
decimals = 18

[storage]
primary = "memory"
cleanup_interval_seconds = 3600
[storage.implementations.memory]

[delivery]
[delivery.implementations.test]

[account]
primary = "local"
[account.implementations.local]
private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

[discovery]
[discovery.implementations.test]

[order]
[order.implementations.eip7683]
[order.strategy]
primary = "simple"
[order.strategy.implementations.simple]

[settlement.implementations.impl1]
order = "eip7683"
network_ids = [1, 2]

[settlement.implementations.impl2]
order = "eip7683"
network_ids = [2, 3]  # Network 2 overlaps with impl1
"#;

		let result = Config::from_str(config_str);
		assert!(result.is_err());
		let err = result.unwrap_err();
		// The test should fail because network 2 is covered by both impl1 and impl2
		// Check for the key parts of the error message
		let error_msg = err.to_string();
		assert!(
			error_msg.contains("network 2")
				&& error_msg.contains("impl1")
				&& error_msg.contains("impl2"),
			"Expected duplicate coverage error for network 2, got: {}",
			err
		);
	}

	#[test]
	fn test_missing_settlement_standard_rejected() {
		let config_str = r#"
[solver]
id = "test"
monitoring_timeout_minutes = 5
min_profitability_pct = 5.0  # Minimum profitability percentage required to execute orders

[networks.1]
input_settler_address = "0x1234567890123456789012345678901234567890"
output_settler_address = "0x0987654321098765432109876543210987654321"
[[networks.1.rpc_urls]]
http = "http://localhost:8545"
[[networks.1.tokens]]
address = "0xabcdef1234567890abcdef1234567890abcdef12"
symbol = "TEST"
decimals = 18

[networks.2]
input_settler_address = "0x1234567890123456789012345678901234567890"
output_settler_address = "0x0987654321098765432109876543210987654321"
[[networks.2.rpc_urls]]
http = "http://localhost:8546"
[[networks.2.tokens]]
address = "0xabcdef1234567890abcdef1234567890abcdef12"
symbol = "TEST"
decimals = 18

[storage]
primary = "memory"
cleanup_interval_seconds = 3600
[storage.implementations.memory]

[delivery]
[delivery.implementations.test]

[account]
primary = "local"
[account.implementations.local]
private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

[discovery]
[discovery.implementations.test]

[order]
[order.implementations.eip7683]
[order.strategy]
primary = "simple"
[order.strategy.implementations.simple]

[settlement.implementations.impl1]
# Missing 'standard' field
network_ids = [1, 2]
"#;

		let result = Config::from_str(config_str);
		assert!(result.is_err());
		let err = result.unwrap_err();
		assert!(err.to_string().contains("missing 'order' field"));
	}

	#[test]
	fn test_settlement_references_invalid_network() {
		let config_str = r#"
[solver]
id = "test"
monitoring_timeout_minutes = 5
min_profitability_pct = 5.0  # Minimum profitability percentage required to execute orders

[networks.1]
input_settler_address = "0x1234567890123456789012345678901234567890"
output_settler_address = "0x0987654321098765432109876543210987654321"
[[networks.1.rpc_urls]]
http = "http://localhost:8545"
[[networks.1.tokens]]
address = "0xabcdef1234567890abcdef1234567890abcdef12"
symbol = "TEST"
decimals = 18

[networks.2]
input_settler_address = "0x1234567890123456789012345678901234567890"
output_settler_address = "0x0987654321098765432109876543210987654321"
[[networks.2.rpc_urls]]
http = "http://localhost:8546"
[[networks.2.tokens]]
address = "0xabcdef1234567890abcdef1234567890abcdef12"
symbol = "TEST"
decimals = 18

[storage]
primary = "memory"
cleanup_interval_seconds = 3600
[storage.implementations.memory]

[delivery]
[delivery.implementations.test]

[account]
primary = "local"
[account.implementations.local]
private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

[discovery]
[discovery.implementations.test]

[order]
[order.implementations.eip7683]
[order.strategy]
primary = "simple"
[order.strategy.implementations.simple]

[settlement.implementations.impl1]
order = "eip7683"
network_ids = [1, 2, 999]  # Network 999 doesn't exist
"#;

		let result = Config::from_str(config_str);
		assert!(result.is_err());
		let err = result.unwrap_err();
		assert!(err
			.to_string()
			.contains("references network 999 which doesn't exist"));
	}

	#[test]
	fn test_order_standard_without_settlement() {
		let config_str = r#"
[solver]
id = "test"
monitoring_timeout_minutes = 5
min_profitability_pct = 5.0  # Minimum profitability percentage required to execute orders

[networks.1]
input_settler_address = "0x1234567890123456789012345678901234567890"
output_settler_address = "0x0987654321098765432109876543210987654321"
[[networks.1.rpc_urls]]
http = "http://localhost:8545"
[[networks.1.tokens]]
address = "0xabcdef1234567890abcdef1234567890abcdef12"
symbol = "TEST"
decimals = 18

[networks.2]
input_settler_address = "0x1234567890123456789012345678901234567890"
output_settler_address = "0x0987654321098765432109876543210987654321"
[[networks.2.rpc_urls]]
http = "http://localhost:8546"
[[networks.2.tokens]]
address = "0xabcdef1234567890abcdef1234567890abcdef12"
symbol = "TEST"
decimals = 18

[storage]
primary = "memory"
cleanup_interval_seconds = 3600
[storage.implementations.memory]

[delivery]
[delivery.implementations.test]

[account]
primary = "local"
[account.implementations.local]
private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

[discovery]
[discovery.implementations.test]

[order]
[order.implementations.eip7683]
[order.implementations.eip9999]  # Order standard with no settlement
[order.strategy]
primary = "simple"
[order.strategy.implementations.simple]

[settlement.implementations.impl1]
order = "eip7683"  # Only covers eip7683, not eip9999
network_ids = [1, 2]
"#;

		let result = Config::from_str(config_str);
		assert!(result.is_err());
		let err = result.unwrap_err();
		assert!(err
			.to_string()
			.contains("Order standard 'eip9999' has no settlement implementations"));
	}
}
