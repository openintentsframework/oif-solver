//! Configuration module for the OIF solver system.
//!
//! This module provides structures and utilities for managing solver configuration.
//! It supports loading configuration from TOML files and provides validation to ensure
//! all required configuration values are properly set.

use serde::{Deserialize, Serialize};
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
	#[error("Parse error: {0}")]
	Parse(#[from] toml::de::Error),
	/// Error that occurs when configuration validation fails.
	#[error("Validation error: {0}")]
	Validation(String),
}

/// Main configuration structure for the OIF solver.
///
/// This structure contains all configuration sections required for the solver
/// to operate, including solver identity, storage, delivery, accounts, discovery,
/// order processing, and settlement configurations.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
	/// Configuration specific to the solver instance.
	pub solver: SolverConfig,
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
fn default_monitoring_timeout_minutes() -> u64 {
	480 // Default to 8 hours
}

/// Configuration for the storage backend.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StorageConfig {
	/// The type of storage backend to use (e.g., "memory", "redis", "postgres").
	pub backend: String,
	/// Backend-specific configuration parameters as raw TOML values.
	pub config: toml::Value,
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
}

impl Config {
	/// Loads configuration from a file at the specified path.
	///
	/// This method reads the file content and parses it as TOML configuration.
	/// The configuration is validated before being returned.
	pub fn from_file(path: &str) -> Result<Self, ConfigError> {
		let content = std::fs::read_to_string(path)?;
		content.parse()
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
	fn validate(&self) -> Result<(), ConfigError> {
		// Validate solver config
		if self.solver.id.is_empty() {
			return Err(ConfigError::Validation("Solver ID cannot be empty".into()));
		}

		// Validate storage config
		if self.storage.backend.is_empty() {
			return Err(ConfigError::Validation(
				"Storage backend cannot be empty".into(),
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
/// string parsing interface. The configuration is automatically validated after parsing.
impl FromStr for Config {
	type Err = ConfigError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let config: Config = toml::from_str(s)?;
		config.validate()?;
		Ok(config)
	}
}
