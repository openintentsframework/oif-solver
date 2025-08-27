//! Configuration builder for creating test and development configurations.
//!
//! This module provides utilities for constructing Config instances with
//! sensible defaults, particularly useful for testing scenarios.

use crate::{
	AccountConfig, ApiConfig, Config, DeliveryConfig, DiscoveryConfig, GasConfig, OrderConfig,
	SettlementConfig, SolverConfig, StorageConfig, StrategyConfig,
};
use std::collections::HashMap;

/// Builder for creating `Config` instances with a fluent API.
///
/// Provides an easy way to create test configurations with sensible defaults.
#[derive(Debug, Clone)]
pub struct ConfigBuilder {
	solver_id: String,
	monitoring_timeout_minutes: u64,
	storage_primary: String,
	storage_cleanup_interval_seconds: u64,
	min_confirmations: u64,
	account_primary: String,
	strategy_primary: String,
	api: Option<ApiConfig>,
}

impl Default for ConfigBuilder {
	fn default() -> Self {
		Self::new()
	}
}

impl ConfigBuilder {
	/// Creates a new `ConfigBuilder` with default values suitable for testing.
	pub fn new() -> Self {
		Self {
			solver_id: "test-solver".to_string(),
			monitoring_timeout_minutes: 1,
			storage_primary: "memory".to_string(),
			storage_cleanup_interval_seconds: 60,
			min_confirmations: 1,
			account_primary: "local".to_string(),
			strategy_primary: "simple".to_string(),
			api: None,
		}
	}

	/// Sets the solver ID.
	pub fn solver_id(mut self, id: String) -> Self {
		self.solver_id = id;
		self
	}

	/// Sets the monitoring timeout in minutes.
	pub fn monitoring_timeout_minutes(mut self, timeout: u64) -> Self {
		self.monitoring_timeout_minutes = timeout;
		self
	}

	/// Sets the primary storage implementation.
	pub fn storage_primary(mut self, primary: String) -> Self {
		self.storage_primary = primary;
		self
	}

	/// Sets the storage cleanup interval in seconds.
	pub fn storage_cleanup_interval_seconds(mut self, interval: u64) -> Self {
		self.storage_cleanup_interval_seconds = interval;
		self
	}

	/// Sets the minimum confirmations for delivery.
	pub fn min_confirmations(mut self, confirmations: u64) -> Self {
		self.min_confirmations = confirmations;
		self
	}

	/// Sets the primary account implementation.
	pub fn account_primary(mut self, primary: String) -> Self {
		self.account_primary = primary;
		self
	}

	/// Sets the primary strategy implementation.
	pub fn strategy_primary(mut self, primary: String) -> Self {
		self.strategy_primary = primary;
		self
	}

	/// Sets the API configuration.
	pub fn api(mut self, api: Option<ApiConfig>) -> Self {
		self.api = api;
		self
	}

	/// Builds the `Config` with the configured values.
	pub fn build(self) -> Config {
		Config {
			solver: SolverConfig {
				id: self.solver_id,
				monitoring_timeout_minutes: self.monitoring_timeout_minutes,
			},
			networks: HashMap::new(),
			storage: StorageConfig {
				primary: self.storage_primary,
				implementations: HashMap::new(),
				cleanup_interval_seconds: self.storage_cleanup_interval_seconds,
			},
			delivery: DeliveryConfig {
				implementations: HashMap::new(),
				min_confirmations: self.min_confirmations,
			},
			account: AccountConfig {
				primary: self.account_primary,
				implementations: HashMap::new(),
			},
			discovery: DiscoveryConfig {
				implementations: HashMap::new(),
			},
			order: OrderConfig {
				implementations: HashMap::new(),
				strategy: StrategyConfig {
					primary: self.strategy_primary,
					implementations: HashMap::new(),
				},
			},
			settlement: SettlementConfig {
				implementations: HashMap::new(),
				domain: None,
			},
			api: self.api,
			gas: Some(GasConfig {
				flows: HashMap::new(),
			}),
		}
	}
}
