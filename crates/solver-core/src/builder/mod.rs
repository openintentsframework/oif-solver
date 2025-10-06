//! Builder pattern for constructing solver engines.
//!
//! Provides a flexible way to compose a SolverEngine from various service
//! implementations using factory functions. Supports pluggable storage,
//! account, delivery, discovery, order implementations and
//! settlement and execution strategies.

use crate::engine::{event_bus::EventBus, SolverEngine};
use solver_account::{AccountError, AccountInterface, AccountService};
use solver_config::Config;
use solver_delivery::{DeliveryError, DeliveryInterface, DeliveryService};
use solver_discovery::{DiscoveryError, DiscoveryInterface, DiscoveryService};
use solver_order::{ExecutionStrategy, OrderError, OrderInterface, OrderService, StrategyError};
use solver_pricing::PricingService;
use solver_settlement::{SettlementError, SettlementInterface, SettlementService};
use solver_storage::{StorageError, StorageInterface, StorageService};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

/// Errors that can occur during solver engine construction.
///
/// These errors indicate problems with configuration or missing required components
/// when building a solver engine instance.
#[derive(Debug, Error)]
pub enum BuilderError {
	#[error("Configuration error: {0}")]
	Config(String),
	#[error("Missing required component: {0}")]
	MissingComponent(String),
}

/// Container for all factory functions needed to build a SolverEngine.
///
/// This struct holds factory functions for creating implementations of each
/// service type required by the solver engine. Each factory function takes
/// a TOML configuration value and returns the corresponding service implementation.
pub struct SolverFactories<SF, AF, DF, DIF, OF, PF, SEF, STF> {
	pub storage_factories: HashMap<String, SF>,
	pub account_factories: HashMap<String, AF>,
	pub delivery_factories: HashMap<String, DF>,
	pub discovery_factories: HashMap<String, DIF>,
	pub order_factories: HashMap<String, OF>,
	pub pricing_factories: HashMap<String, PF>,
	pub settlement_factories: HashMap<String, SEF>,
	pub strategy_factories: HashMap<String, STF>,
}

/// Builder for constructing a SolverEngine with pluggable implementations.
pub struct SolverBuilder {
	config: Config,
}

impl SolverBuilder {
	/// Creates a new SolverBuilder with the given configuration.
	pub fn new(config: Config) -> Self {
		Self { config }
	}

	/// Builds the SolverEngine using factories for each component type.
	pub async fn build<SF, AF, DF, DIF, OF, PF, SEF, STF>(
		self,
		factories: SolverFactories<SF, AF, DF, DIF, OF, PF, SEF, STF>,
	) -> Result<SolverEngine, BuilderError>
	where
		SF: Fn(&toml::Value) -> Result<Box<dyn StorageInterface>, StorageError>,
		AF: Fn(&toml::Value) -> Result<Box<dyn AccountInterface>, AccountError>,
		DF: Fn(
			&toml::Value,
			&solver_types::NetworksConfig,
			&solver_types::SecretString,
			&std::collections::HashMap<u64, solver_types::SecretString>,
		) -> Result<Box<dyn DeliveryInterface>, DeliveryError>,
		DIF: Fn(
			&toml::Value,
			&solver_types::NetworksConfig,
		) -> Result<Box<dyn DiscoveryInterface>, DiscoveryError>,
		OF: Fn(
			&toml::Value,
			&solver_types::NetworksConfig,
			&solver_types::oracle::OracleRoutes,
		) -> Result<Box<dyn OrderInterface>, OrderError>,
		PF: Fn(
			&toml::Value,
		) -> Result<Box<dyn solver_types::PricingInterface>, solver_types::PricingError>,
		SEF: Fn(
			&toml::Value,
			&solver_types::NetworksConfig,
			Arc<StorageService>,
		) -> Result<Box<dyn SettlementInterface>, SettlementError>,
		STF: Fn(&toml::Value) -> Result<Box<dyn ExecutionStrategy>, StrategyError>,
	{
		// Create storage implementations
		let mut storage_impls = HashMap::new();
		for (name, config) in &self.config.storage.implementations {
			if let Some(factory) = factories.storage_factories.get(name) {
				match factory(config) {
					Ok(implementation) => {
						// Validation already happened in the factory
						storage_impls.insert(name.clone(), implementation);
						let is_primary = &self.config.storage.primary == name;
						tracing::info!(component = "storage", implementation = %name, enabled = %is_primary, "Loaded");
					},
					Err(e) => {
						tracing::error!(
							component = "storage",
							implementation = %name,
							error = %e,
							"Failed to create storage implementation"
						);
						return Err(BuilderError::Config(format!(
							"Failed to create storage implementation '{}': {}",
							name, e
						)));
					},
				}
			}
		}

		if storage_impls.is_empty() {
			return Err(BuilderError::Config(
				"No valid storage implementations available".into(),
			));
		}

		// Get the primary storage implementation
		let primary_storage = &self.config.storage.primary;
		let storage_backend = storage_impls.remove(primary_storage).ok_or_else(|| {
			BuilderError::Config(format!(
				"Primary storage '{}' failed to load or has invalid configuration",
				primary_storage
			))
		})?;

		let storage = Arc::new(StorageService::new(storage_backend));

		// Create account implementations
		let mut account_impls = HashMap::new();
		for (name, config) in &self.config.account.implementations {
			if let Some(factory) = factories.account_factories.get(name) {
				match factory(config) {
					Ok(implementation) => {
						account_impls.insert(name.clone(), implementation);
						let is_primary = &self.config.account.primary == name;
						tracing::info!(component = "account", implementation = %name, enabled = %is_primary, "Loaded");
					},
					Err(e) => {
						tracing::error!(
							component = "account",
							implementation = %name,
							error = %e,
							"Failed to create account implementation"
						);
						return Err(BuilderError::Config(format!(
							"Failed to create account implementation '{}': {}",
							name, e
						)));
					},
				}
			}
		}

		if account_impls.is_empty() {
			return Err(BuilderError::Config(
				"No account implementations available".to_string(),
			));
		}

		// Create AccountService for each account implementation
		let mut account_services = HashMap::new();
		for (name, implementation) in account_impls {
			account_services.insert(name.clone(), Arc::new(AccountService::new(implementation)));
		}

		// Get the primary account service
		let primary_account = self.config.account.primary.as_str();
		let account = account_services
			.get(primary_account)
			.ok_or_else(|| {
				BuilderError::Config(format!(
					"Primary account '{}' not found in loaded accounts",
					primary_account
				))
			})?
			.clone();

		// Fetch the solver address once during initialization
		let solver_address = match account.get_address().await {
			Ok(address) => address,
			Err(e) => {
				tracing::error!(
					component = "account",
					error = %e,
					"Failed to get solver address"
				);
				return Err(BuilderError::Config(format!(
					"Failed to get solver address: {}",
					e
				)));
			},
		};

		// Create delivery implementations
		let mut delivery_implementations = std::collections::HashMap::new();

		// Get the default private key from the primary account
		let default_private_key = account.get_private_key();

		for (name, config) in &self.config.delivery.implementations {
			if let Some(factory) = factories.delivery_factories.get(name) {
				// Parse per-network account mappings from config
				let mut network_private_keys = HashMap::new();
				if let Some(accounts_table) = config.get("accounts").and_then(|v| v.as_table()) {
					for (network_id_str, account_name_value) in accounts_table {
						if let Ok(network_id) = network_id_str.parse::<u64>() {
							if let Some(account_name) = account_name_value.as_str() {
								if let Some(account_service) = account_services.get(account_name) {
									let private_key = account_service.get_private_key();
									network_private_keys.insert(network_id, private_key);
								} else {
									tracing::warn!(
										"Account '{}' not found, skipping",
										account_name
									);
								}
							}
						}
					}
				}

				match factory(
					config,
					&self.config.networks,
					&default_private_key,
					&network_private_keys,
				) {
					Ok(implementation) => {
						// Extract network_ids from config to create the mapping
						if let Some(network_ids) =
							config.get("network_ids").and_then(|v| v.as_array())
						{
							let implementation_arc: Arc<dyn DeliveryInterface> =
								implementation.into();
							for network_id_value in network_ids {
								if let Some(network_id) = network_id_value.as_integer() {
									let network_id = network_id as u64;
									delivery_implementations
										.insert(network_id, implementation_arc.clone());
									tracing::info!(component = "delivery", implementation = %name, network_id = %network_id, "Loaded");
								}
							}
						} else {
							tracing::error!(
								component = "delivery",
								implementation = %name,
								"Missing network_ids configuration"
							);
							return Err(BuilderError::Config(format!(
								"Delivery implementation '{}' missing network_ids configuration",
								name
							)));
						}
					},
					Err(e) => {
						tracing::error!(
							component = "delivery",
							implementation = %name,
							error = %e,
							"Failed to create delivery implementation"
						);
						return Err(BuilderError::Config(format!(
							"Failed to create delivery implementation '{}': {}",
							name, e
						)));
					},
				}
			}
		}

		if delivery_implementations.is_empty() {
			tracing::warn!("No delivery implementations available - solver will not be able to submit any transactions");
		}

		let delivery = Arc::new(DeliveryService::new(
			delivery_implementations,
			self.config.delivery.min_confirmations,
		));

		// Create discovery implementations
		let mut discovery_implementations = HashMap::new();
		for (name, config) in &self.config.discovery.implementations {
			if let Some(factory) = factories.discovery_factories.get(name) {
				match factory(config, &self.config.networks) {
					Ok(implementation) => {
						// Validation already happened in the factory
						discovery_implementations.insert(name.clone(), implementation);
						tracing::info!(component = "discovery", implementation = %name, "Loaded");
					},
					Err(e) => {
						tracing::error!(
							component = "discovery",
							implementation = %name,
							error = %e,
							"Failed to create discovery implementation"
						);
						return Err(BuilderError::Config(format!(
							"Failed to create discovery implementation '{}': {}",
							name, e
						)));
					},
				}
			}
		}

		if discovery_implementations.is_empty() {
			tracing::warn!(
				"No discovery implementations available - solver will not discover any new orders"
			);
		}

		let discovery = Arc::new(DiscoveryService::new(discovery_implementations));

		// Create settlement implementations first (needed for oracle routes)
		let mut settlement_impls = HashMap::new();
		for (name, config) in &self.config.settlement.implementations {
			if let Some(factory) = factories.settlement_factories.get(name) {
				match factory(config, &self.config.networks, storage.clone()) {
					Ok(implementation) => {
						// Validation already happened in the factory
						settlement_impls.insert(name.clone(), implementation);
						tracing::info!(component = "settlement", implementation = %name, "Loaded");
					},
					Err(e) => {
						tracing::error!(
							component = "settlement",
							implementation = %name,
							error = %e,
							"Failed to create settlement implementation"
						);
						return Err(BuilderError::Config(format!(
							"Failed to create settlement implementation '{}': {}",
							name, e
						)));
					},
				}
			}
		}

		if settlement_impls.is_empty() {
			tracing::warn!("No settlement implementations available - solver will not be able to monitor and claim settlements");
		}

		let settlement = Arc::new(SettlementService::new(
			settlement_impls,
			self.config.settlement.settlement_poll_interval_seconds,
		));

		// Create pricing service
		let pricing_config =
			self.config.pricing.as_ref().ok_or_else(|| {
				BuilderError::Config("Pricing configuration is required".to_string())
			})?;

		let mut pricing_impls = HashMap::new();
		for (name, config) in &pricing_config.implementations {
			if let Some(factory) = factories.pricing_factories.get(name) {
				match factory(config) {
					Ok(implementation) => {
						pricing_impls.insert(name.clone(), implementation);
						let is_primary = &pricing_config.primary == name;
						tracing::info!(component = "pricing", implementation = %name, enabled = %is_primary, "Loaded");
					},
					Err(e) => {
						tracing::error!(
							component = "pricing",
							implementation = %name,
							error = %e,
							"Failed to create pricing implementation"
						);
						return Err(BuilderError::Config(format!(
							"Failed to create pricing implementation '{}': {}",
							name, e
						)));
					},
				}
			}
		}

		// Use the primary pricing implementation
		let primary_pricing = pricing_config.primary.as_str();
		let pricing_impl = pricing_impls.remove(primary_pricing).ok_or_else(|| {
			BuilderError::Config(format!(
				"Primary pricing '{}' failed to load or has invalid configuration",
				primary_pricing
			))
		})?;
		let pricing = Arc::new(PricingService::new(pricing_impl));

		// Build oracle routes from settlement implementations
		let oracle_routes = settlement.build_oracle_routes();
		tracing::info!(
			oracle_routes = %oracle_routes.supported_routes.len(),
			"Built oracle routes from settlement implementations"
		);

		// Create order implementations (now with oracle routes)
		let mut order_impls = HashMap::new();
		for (name, config) in &self.config.order.implementations {
			if let Some(factory) = factories.order_factories.get(name) {
				match factory(config, &self.config.networks, &oracle_routes) {
					Ok(implementation) => {
						// Validation already happened in the factory
						order_impls.insert(name.clone(), implementation);
						tracing::info!(component = "order", implementation = %name, "Loaded");
					},
					Err(e) => {
						tracing::error!(
							component = "order",
							implementation = %name,
							error = %e,
							"Failed to create order implementation"
						);
						return Err(BuilderError::Config(format!(
							"Failed to create order implementation '{}': {}",
							name, e
						)));
					},
				}
			}
		}

		if order_impls.is_empty() {
			tracing::warn!("No order implementations available - solver will not be able to process any orders");
		}

		// Create strategy implementations
		let mut strategy_impls = HashMap::new();
		for (name, config) in &self.config.order.strategy.implementations {
			if let Some(factory) = factories.strategy_factories.get(name) {
				match factory(config) {
					Ok(implementation) => {
						strategy_impls.insert(name.clone(), implementation);
						let is_primary = &self.config.order.strategy.primary == name;
						tracing::info!(component = "strategy", implementation = %name, enabled = %is_primary, "Loaded");
					},
					Err(e) => {
						tracing::error!(
							component = "strategy",
							implementation = %name,
							error = %e,
							"Failed to create strategy implementation"
						);
						return Err(BuilderError::Config(format!(
							"Failed to create strategy implementation '{}': {}",
							name, e
						)));
					},
				}
			}
		}

		if strategy_impls.is_empty() {
			return Err(BuilderError::Config(
				"No strategy implementations available".to_string(),
			));
		}

		// Use the primary strategy implementation
		let primary_strategy = self.config.order.strategy.primary.as_str();
		let strategy = strategy_impls.remove(primary_strategy).ok_or_else(|| {
			BuilderError::Config(format!(
				"Primary strategy '{}' failed to load or has invalid configuration",
				primary_strategy
			))
		})?;

		let order = Arc::new(OrderService::new(order_impls, strategy));

		// Create and initialize the TokenManager
		let token_manager = Arc::new(crate::engine::token_manager::TokenManager::new(
			self.config.networks.clone(),
			delivery.clone(),
			account.clone(),
		));

		// Ensure all token approvals are set
		match token_manager.ensure_approvals().await {
			Ok(()) => {
				tracing::info!(
					component = "token_manager",
					networks = self.config.networks.len(),
					"Token manager initialized with approvals"
				);
			},
			Err(e) => {
				tracing::error!(
					component = "token_manager",
					error = %e,
					"Failed to ensure token approvals"
				);
				return Err(BuilderError::Config(format!(
					"Failed to ensure token approvals: {}",
					e
				)));
			},
		}

		// Log initial balances for monitoring
		match token_manager.check_balances().await {
			Ok(balances) => {
				for ((chain_id, token), balance) in &balances {
					let formatted_balance = format!(
						"{} {}",
						solver_types::format_token_amount(balance, token.decimals),
						token.symbol
					);

					tracing::info!(
						chain_id = chain_id,
						token = %token.symbol,
						balance = %formatted_balance,
						"Initial solver balance"
					);
				}
			},
			Err(e) => {
				tracing::warn!(
					error = %e,
					"Failed to check initial balances"
				);
			},
		}

		Ok(SolverEngine::new(
			self.config,
			storage,
			account,
			solver_address,
			delivery,
			discovery,
			order,
			settlement,
			pricing,
			EventBus::new(1000),
			token_manager,
		))
	}
}
