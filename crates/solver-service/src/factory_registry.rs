//! Dynamic factory registry for solver implementations.
//!
//! This module provides a centralized registry for all factory functions,
//! allowing dynamic instantiation of implementations based on configuration.

use solver_account::{AccountError, AccountInterface};
use solver_config::Config;
use solver_core::{SolverBuilder, SolverEngine, SolverFactories};
use solver_delivery::{DeliveryError, DeliveryInterface};
use solver_discovery::{DiscoveryError, DiscoveryInterface};
use solver_order::{ExecutionStrategy, OrderError, OrderInterface, StrategyError};

use solver_pricing::PricingInterface;
use solver_settlement::{SettlementError, SettlementInterface};
use solver_storage::StorageFactory;
use solver_types::{NetworksConfig, PricingError};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use tokio::sync::RwLock;

// Type aliases for factory functions
pub type AccountFactory = fn(&toml::Value) -> Result<Box<dyn AccountInterface>, AccountError>;
pub type DeliveryFactory = fn(
	&toml::Value,
	&NetworksConfig,
	&solver_types::SecretString,
	&std::collections::HashMap<u64, solver_types::SecretString>,
) -> Result<Box<dyn DeliveryInterface>, DeliveryError>;
pub type DiscoveryFactory =
	fn(&toml::Value, &NetworksConfig) -> Result<Box<dyn DiscoveryInterface>, DiscoveryError>;
pub type OrderFactory = fn(
	&toml::Value,
	&NetworksConfig,
	&solver_types::oracle::OracleRoutes,
) -> Result<Box<dyn OrderInterface>, OrderError>;
pub type PricingFactory = fn(&toml::Value) -> Result<Box<dyn PricingInterface>, PricingError>;
pub type SettlementFactory = fn(
	&toml::Value,
	&NetworksConfig,
	std::sync::Arc<solver_storage::StorageService>,
) -> Result<Box<dyn SettlementInterface>, SettlementError>;
pub type StrategyFactory = fn(&toml::Value) -> Result<Box<dyn ExecutionStrategy>, StrategyError>;

/// Global registry for all implementation factories
#[derive(Default)]
pub struct FactoryRegistry {
	pub storage: HashMap<String, StorageFactory>,
	pub account: HashMap<String, AccountFactory>,
	pub delivery: HashMap<String, DeliveryFactory>,
	pub discovery: HashMap<String, DiscoveryFactory>,
	pub order: HashMap<String, OrderFactory>,
	pub pricing: HashMap<String, PricingFactory>,
	pub settlement: HashMap<String, SettlementFactory>,
	pub strategy: HashMap<String, StrategyFactory>,
}

impl FactoryRegistry {
	/// Create a new empty registry
	pub fn new() -> Self {
		Self {
			storage: HashMap::new(),
			account: HashMap::new(),
			delivery: HashMap::new(),
			discovery: HashMap::new(),
			order: HashMap::new(),
			pricing: HashMap::new(),
			settlement: HashMap::new(),
			strategy: HashMap::new(),
		}
	}

	/// Register a storage implementation
	pub fn register_storage(&mut self, name: impl Into<String>, factory: StorageFactory) {
		self.storage.insert(name.into(), factory);
	}

	/// Register an account implementation
	pub fn register_account(&mut self, name: impl Into<String>, factory: AccountFactory) {
		self.account.insert(name.into(), factory);
	}

	/// Register a delivery implementation
	pub fn register_delivery(&mut self, name: impl Into<String>, factory: DeliveryFactory) {
		self.delivery.insert(name.into(), factory);
	}

	/// Register a discovery implementation
	pub fn register_discovery(&mut self, name: impl Into<String>, factory: DiscoveryFactory) {
		self.discovery.insert(name.into(), factory);
	}

	/// Register an order implementation
	pub fn register_order(&mut self, name: impl Into<String>, factory: OrderFactory) {
		self.order.insert(name.into(), factory);
	}

	/// Register a settlement implementation
	pub fn register_settlement(&mut self, name: impl Into<String>, factory: SettlementFactory) {
		self.settlement.insert(name.into(), factory);
	}

	/// Register a pricing implementation
	pub fn register_pricing(&mut self, name: impl Into<String>, factory: PricingFactory) {
		self.pricing.insert(name.into(), factory);
	}

	/// Register a strategy implementation
	pub fn register_strategy(&mut self, name: impl Into<String>, factory: StrategyFactory) {
		self.strategy.insert(name.into(), factory);
	}
}

// Global registry instance
static REGISTRY: OnceLock<FactoryRegistry> = OnceLock::new();

/// Initialize the global registry with all available implementations
pub fn initialize_registry() -> &'static FactoryRegistry {
	REGISTRY.get_or_init(|| {
		let mut registry = FactoryRegistry::new();

		// Auto-register all storage implementations
		for (name, factory) in solver_storage::get_all_implementations() {
			tracing::debug!("Registering storage implementation: {}", name);
			registry.register_storage(name, factory);
		}

		// Auto-register all account implementations
		for (name, factory) in solver_account::get_all_implementations() {
			tracing::debug!("Registering account implementation: {}", name);
			registry.register_account(name, factory);
		}

		// Auto-register all delivery implementations
		for (name, factory) in solver_delivery::get_all_implementations() {
			tracing::debug!("Registering delivery implementation: {}", name);
			registry.register_delivery(name, factory);
		}

		// Auto-register all discovery implementations
		for (name, factory) in solver_discovery::get_all_implementations() {
			tracing::debug!("Registering discovery implementation: {}", name);
			registry.register_discovery(name, factory);
		}

		// Auto-register all order implementations
		for (name, factory) in solver_order::get_all_order_implementations() {
			tracing::debug!("Registering order implementation: {}", name);
			registry.register_order(name, factory);
		}

		// Auto-register all pricing implementations
		for (name, factory) in solver_pricing::get_all_implementations() {
			tracing::debug!("Registering pricing implementation: {}", name);
			registry.register_pricing(name, factory);
		}

		// Auto-register all settlement implementations
		for (name, factory) in solver_settlement::get_all_implementations() {
			tracing::debug!("Registering settlement implementation: {}", name);
			registry.register_settlement(name, factory);
		}

		// Auto-register all strategy implementations
		for (name, factory) in solver_order::get_all_strategy_implementations() {
			tracing::debug!("Registering strategy implementation: {}", name);
			registry.register_strategy(name, factory);
		}

		registry
	})
}

/// Get the global factory registry
pub fn get_registry() -> &'static FactoryRegistry {
	initialize_registry()
}

/// Macro to build factories from config implementations
macro_rules! build_factories {
	($registry:expr, $config_impls:expr, $registry_field:ident, $type_name:literal) => {{
		let mut factories = HashMap::new();
		for name in $config_impls.keys() {
			if let Some(factory) = $registry.$registry_field.get(name) {
				factories.insert(name.clone(), *factory);
			} else {
				let available: Vec<_> = $registry.$registry_field.keys().cloned().collect();
				let available_str = available.join(", ");
				return Err(format!(
					"Unknown {} implementation '{}'. Available: [{}]",
					$type_name, name, available_str
				)
				.into());
			}
		}
		factories
	}};
}

/// Build solver using registry and dynamic config.
///
/// Note: Services created during build use a static snapshot of the config and will NOT
/// see hot-reload changes. Only SolverEngine's `dynamic_config()` accessor provides
/// access to hot-reloaded values.
pub async fn build_solver_from_config(
	dynamic_config: Arc<RwLock<Config>>,
) -> Result<SolverEngine, Box<dyn std::error::Error>> {
	let registry = get_registry();
	// Take a static snapshot for building services (they stay stale after hot reload)
	let static_config = dynamic_config.read().await.clone();
	let builder = SolverBuilder::new(dynamic_config, static_config.clone());

	// Build factories for each component type using the macro
	let storage_factories = build_factories!(
		registry,
		static_config.storage.implementations,
		storage,
		"storage"
	);
	let delivery_factories = build_factories!(
		registry,
		static_config.delivery.implementations,
		delivery,
		"delivery"
	);
	let discovery_factories = build_factories!(
		registry,
		static_config.discovery.implementations,
		discovery,
		"discovery"
	);
	let order_factories = build_factories!(
		registry,
		static_config.order.implementations,
		order,
		"order"
	);
	let pricing_factories = if let Some(pricing_config) = &static_config.pricing {
		build_factories!(registry, pricing_config.implementations, pricing, "pricing")
	} else {
		HashMap::new()
	};
	let settlement_factories = build_factories!(
		registry,
		static_config.settlement.implementations,
		settlement,
		"settlement"
	);
	let account_factories = build_factories!(
		registry,
		static_config.account.implementations,
		account,
		"account"
	);
	let strategy_factories = build_factories!(
		registry,
		static_config.order.strategy.implementations,
		strategy,
		"strategy"
	);

	let factories = SolverFactories {
		storage_factories,
		account_factories,
		delivery_factories,
		discovery_factories,
		order_factories,
		pricing_factories,
		settlement_factories,
		strategy_factories,
	};

	Ok(builder.build(factories).await?)
}

#[cfg(test)]
mod tests {
	use super::*;
	use solver_config::Config;

	#[test]
	fn initialize_registry_is_idempotent() {
		let first = initialize_registry() as *const FactoryRegistry;
		let second = initialize_registry() as *const FactoryRegistry;
		assert_eq!(first, second);
	}

	#[tokio::test]
	async fn build_solver_from_config_errors_on_unknown_delivery_impl() {
		let config_toml = r#"
			[solver]
			id = "test-solver"
			monitoring_timeout_seconds = 30
			min_profitability_pct = 1.0

			[storage]
			primary = "memory"
			cleanup_interval_seconds = 60
			[storage.implementations.memory]

			[delivery]
			min_confirmations = 1
			primary = "unknown"
			[delivery.implementations]
			unknown = {}

			[account]
			primary = "local"
			[account.implementations.local]
			private_key = "0x1234567890123456789012345678901234567890123456789012345678901234"

			[discovery]
			[discovery.implementations]

			[order]
			[order.implementations]
			[order.strategy]
			primary = "simple"
			[order.strategy.implementations.simple]

			[settlement]
			[settlement.implementations]

			[networks.1]
			chain_id = 1
			input_settler_address = "0x0000000000000000000000000000000000000001"
			output_settler_address = "0x0000000000000000000000000000000000000002"
			[[networks.1.rpc_urls]]
			http = "http://localhost:8545"
			[[networks.1.tokens]]
			symbol = "TEST"
			address = "0x0000000000000000000000000000000000000003"
			decimals = 18
		"#;

		let config: Config = toml::from_str(config_toml).expect("config parses");
		let dynamic_config = Arc::new(RwLock::new(config));
		let message = match build_solver_from_config(dynamic_config).await {
			Ok(_) => panic!("expected failure"),
			Err(error) => error.to_string(),
		};
		assert!(message.contains("Unknown delivery implementation 'unknown'"));
	}
}
