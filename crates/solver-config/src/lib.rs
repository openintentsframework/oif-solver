//! Configuration module for the OIF solver system.
//!
//! This module provides structures and utilities for managing solver configuration.
//! It supports loading configuration from TOML files and provides validation to ensure
//! all required configuration values are properly set.

use regex::Regex;
use serde::{Deserialize, Serialize};
use solver_types::{networks::deserialize_networks, NetworksConfig};
use std::collections::HashMap;
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
	/// Configuration for the HTTP API server.
	pub api: Option<ApiConfig>,
}

/// Domain configuration for EIP-712 signatures in quotes.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DomainConfig {
	/// Chain ID where the settlement contract is deployed.
	pub chain_id: u64,
	/// Settlement contract address.
	pub address: String,
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
	/// Map of delivery provider names to their configurations.
	/// Each provider has its own configuration format stored as raw TOML values.
	pub providers: HashMap<String, toml::Value>,
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
	/// The type of account provider to use (e.g., "local", "aws-kms", "hardware").
	pub provider: String,
	/// Provider-specific configuration parameters as raw TOML values.
	pub config: toml::Value,
}

/// Configuration for order discovery.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DiscoveryConfig {
	/// Map of discovery source names to their configurations.
	/// Each source has its own configuration format stored as raw TOML values.
	pub sources: HashMap<String, toml::Value>,
}

/// Configuration for order processing.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OrderConfig {
	/// Map of order implementation names to their configurations.
	/// Each implementation handles specific order types.
	pub implementations: HashMap<String, toml::Value>,
	/// Strategy configuration for order execution.
	pub execution_strategy: StrategyConfig,
}

/// Configuration for execution strategies.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StrategyConfig {
	/// The type of strategy to use (e.g., "fifo", "priority", "custom").
	pub strategy_type: String,
	/// Strategy-specific configuration parameters as raw TOML values.
	pub config: toml::Value,
}

/// Configuration for settlement operations.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SettlementConfig {
	/// Map of settlement implementation names to their configurations.
	/// Each implementation handles specific settlement mechanisms.
	pub implementations: HashMap<String, toml::Value>,
	/// Domain configuration for EIP-712 signatures in quotes.
	pub domain: Option<DomainConfig>,
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
	/// Rate limiting configuration.
	pub rate_limiting: Option<RateLimitConfig>,
	/// CORS configuration.
	pub cors: Option<CorsConfig>,
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
fn resolve_env_vars(input: &str) -> Result<String, ConfigError> {
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
			}
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
	/// Loads configuration from a file at the specified path.
	///
	/// This method reads the file content, resolves environment variables,
	/// and parses it as TOML configuration. The configuration is validated
	/// before being returned.
	///
	/// Environment variables can be referenced using:
	/// - `${VAR_NAME}` - Required environment variable
	/// - `${VAR_NAME:-default}` - With default value if not set
	pub fn from_file(path: &str) -> Result<Self, ConfigError> {
		let content = std::fs::read_to_string(path)?;
		let resolved = resolve_env_vars(&content)?;
		resolved.parse()
	}

	/// Loads configuration from a file with async environment variable resolution.
	///
	/// This method is async-ready for future extensions that might need
	/// async secret resolution (e.g., from Vault, AWS KMS, etc).
	pub async fn from_file_async(path: &str) -> Result<Self, ConfigError> {
		// For now, just calls the sync version
		// In the future, this could use async resolvers
		Self::from_file(path)
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
		if self.delivery.providers.is_empty() {
			return Err(ConfigError::Validation(
				"At least one delivery provider required".into(),
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

		// Validate account config
		if self.account.provider.is_empty() {
			return Err(ConfigError::Validation(
				"Account provider cannot be empty".into(),
			));
		}

		// Validate discovery config
		if self.discovery.sources.is_empty() {
			return Err(ConfigError::Validation(
				"At least one discovery source required".into(),
			));
		}

		// Validate order config
		if self.order.implementations.is_empty() {
			return Err(ConfigError::Validation(
				"At least one order implementation required".into(),
			));
		}
		if self.order.execution_strategy.strategy_type.is_empty() {
			return Err(ConfigError::Validation(
				"Execution strategy type cannot be empty".into(),
			));
		}

		// Validate settlement config
		if self.settlement.implementations.is_empty() {
			return Err(ConfigError::Validation(
				"At least one settlement implementation required".into(),
			));
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

[networks.1]
rpc_url = "http://localhost:8545"
input_settler_address = "0x1234567890123456789012345678901234567890"
output_settler_address = "0x0987654321098765432109876543210987654321"
[[networks.1.tokens]]
address = "0xabcdef1234567890abcdef1234567890abcdef12"
symbol = "TEST"
decimals = 18

[networks.2]
rpc_url = "http://localhost:8546"
input_settler_address = "0x1234567890123456789012345678901234567890"
output_settler_address = "0x0987654321098765432109876543210987654321"
[[networks.2.tokens]]
address = "0xabcdef1234567890abcdef1234567890abcdef12"
symbol = "TEST"
decimals = 18

[storage]
primary = "memory"
cleanup_interval_seconds = 3600
[storage.implementations.memory]

[delivery]
[delivery.providers.test]

[account]
provider = "local"
[account.config]
private_key = "${TEST_PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

[discovery]
[discovery.sources.test]

[order]
[order.implementations.test]
[order.execution_strategy]
strategy_type = "simple"
[order.execution_strategy.config]

[settlement]
[settlement.implementations.test]
"#;

		let config: Config = config_str.parse().unwrap();
		assert_eq!(config.solver.id, "test-solver");

		// Clean up
		std::env::remove_var("TEST_SOLVER_ID");
	}
}
