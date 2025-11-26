//! Configuration builder for creating test and development configurations.
//!
//! This module provides utilities for constructing Config instances with
//! sensible defaults, particularly useful for testing scenarios.

use rust_decimal::Decimal;

use crate::{
	AccountConfig, ApiConfig, Config, DeliveryConfig, DiscoveryConfig, GasConfig, NetworksConfig,
	OrderConfig, SettlementConfig, SolverConfig, StorageConfig, StrategyConfig,
};
use std::collections::HashMap;

/// Builder for creating `Config` instances with a fluent API.
///
/// Provides an easy way to create test configurations with sensible defaults.
#[derive(Debug, Clone)]
pub struct ConfigBuilder {
	solver_id: String,
	monitoring_timeout_seconds: u64,
	min_profitability_pct: Decimal,
	storage_primary: String,
	storage_cleanup_interval_seconds: u64,
	min_confirmations: u64,
	account_primary: String,
	strategy_primary: String,
	api: Option<ApiConfig>,
	settlement: Option<SettlementConfig>,
	networks: Option<NetworksConfig>,
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
			monitoring_timeout_seconds: 60,
			min_profitability_pct: Decimal::ZERO,
			storage_primary: "memory".to_string(),
			storage_cleanup_interval_seconds: 60,
			min_confirmations: 1,
			account_primary: "local".to_string(),
			strategy_primary: "simple".to_string(),
			api: None,
			settlement: None,
			networks: None,
		}
	}

	/// Sets the solver ID.
	pub fn solver_id(mut self, id: String) -> Self {
		self.solver_id = id;
		self
	}

	/// Sets the monitoring timeout in seconds.
	pub fn monitoring_timeout_seconds(mut self, timeout: u64) -> Self {
		self.monitoring_timeout_seconds = timeout;
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

	/// Sets the settlement configuration.
	pub fn settlement(mut self, settlement: SettlementConfig) -> Self {
		self.settlement = Some(settlement);
		self
	}

	/// Sets the networks configuration.
	pub fn networks(mut self, networks: NetworksConfig) -> Self {
		self.networks = Some(networks);
		self
	}

	/// Sets the minimum profitability percentage.
	pub fn with_min_profitability_pct(mut self, min_profitability_pct: Decimal) -> Self {
		self.min_profitability_pct = min_profitability_pct;
		self
	}

	/// Builds the `Config` with the configured values.
	pub fn build(self) -> Config {
		Config {
			solver: SolverConfig {
				id: self.solver_id,
				min_profitability_pct: self.min_profitability_pct,
				monitoring_timeout_seconds: self.monitoring_timeout_seconds,
			},
			networks: self.networks.unwrap_or_default(),
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
			callback_whitelist: Vec::new(),
			simulate_callbacks: true,
		},
			settlement: self.settlement.unwrap_or_else(|| SettlementConfig {
				implementations: HashMap::new(),
				settlement_poll_interval_seconds: 3,
			}),
			pricing: None,
			api: self.api,
			gas: Some(GasConfig {
				flows: HashMap::new(),
			}),
		}
	}
}
