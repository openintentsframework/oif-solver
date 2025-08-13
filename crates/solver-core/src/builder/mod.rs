//! Builder pattern for constructing solver engines.
//!
//! Provides a flexible way to compose a SolverEngine from various service
//! implementations using factory functions. Supports pluggable storage backends,
//! account providers, delivery mechanisms, discovery sources, order implementations,
//! settlement strategies, and execution strategies.

use crate::engine::{event_bus::EventBus, SolverEngine};
use solver_account::{AccountError, AccountInterface, AccountService};
use solver_config::Config;
use solver_delivery::{DeliveryError, DeliveryInterface, DeliveryService};
use solver_discovery::{DiscoveryError, DiscoveryInterface, DiscoveryService};
use solver_order::{ExecutionStrategy, OrderError, OrderInterface, OrderService};
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
pub struct SolverFactories<SF, AF, DF, DIF, OF, SEF, STF> {
	pub storage_factories: HashMap<String, SF>,
	pub account_factory: AF,
	pub delivery_factories: HashMap<String, DF>,
	pub discovery_factories: HashMap<String, DIF>,
	pub order_factories: HashMap<String, OF>,
	pub settlement_factories: HashMap<String, SEF>,
	pub strategy_factory: STF,
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
	pub async fn build<SF, AF, DF, DIF, OF, SEF, STF>(
		self,
		factories: SolverFactories<SF, AF, DF, DIF, OF, SEF, STF>,
	) -> Result<SolverEngine, BuilderError>
	where
		SF: Fn(&toml::Value) -> Result<Box<dyn StorageInterface>, StorageError>,
		AF: FnOnce(&toml::Value) -> Result<Box<dyn AccountInterface>, AccountError>,
		DF: Fn(
			&toml::Value,
			&solver_types::NetworksConfig,
			Option<&solver_types::SecretString>,
		) -> Result<Box<dyn DeliveryInterface>, DeliveryError>,
		DIF: Fn(
			&toml::Value,
			&solver_types::NetworksConfig,
		) -> Result<Box<dyn DiscoveryInterface>, DiscoveryError>,
		OF: Fn(
			&toml::Value,
			&solver_types::NetworksConfig,
		) -> Result<Box<dyn OrderInterface>, OrderError>,
		SEF: Fn(
			&toml::Value,
			&solver_types::NetworksConfig,
		) -> Result<Box<dyn SettlementInterface>, SettlementError>,
		STF: FnOnce(&toml::Value) -> Box<dyn ExecutionStrategy>,
	{
		// Create storage implementations
		let mut storage_impls = HashMap::new();
		for (name, config) in &self.config.storage.implementations {
			if let Some(factory) = factories.storage_factories.get(name) {
				match factory(config) {
					Ok(implementation) => {
						// Validation already happened in the factory
						storage_impls.insert(name.clone(), implementation);
						let impl_name = if name == &self.config.storage.primary {
							format!("{} (primary)", name)
						} else {
							name.to_string()
						};
						tracing::info!(component = "storage", implementation = %impl_name, "Loaded");
					}
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
					}
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

		// Create account provider
		let account_provider = match (factories.account_factory)(&self.config.account.config) {
			Ok(provider) => provider,
			Err(e) => {
				tracing::error!(
					component = "account",
					implementation = %self.config.account.provider,
					error = %e,
					"Failed to create account provider"
				);
				return Err(BuilderError::Config(format!(
					"Failed to create account provider '{}': {}",
					self.config.account.provider, e
				)));
			}
		};

		let account = Arc::new(AccountService::new(account_provider));

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
			}
		};

		tracing::info!(
			component = "account",
			implementation = %self.config.account.provider,
			address = %solver_address,
			"Loaded"
		);

		// Create delivery providers
		let mut delivery_providers = HashMap::new();
		let default_private_key = account.get_private_key();

		for (name, config) in &self.config.delivery.providers {
			if let Some(factory) = factories.delivery_factories.get(name) {
				match factory(config, &self.config.networks, default_private_key.as_ref()) {
					Ok(provider) => {
						// Validation already happened in the factory, extract chain_id for the map key
						let chain_id = config
							.get("network_id")
							.and_then(|v| v.as_integer())
							.expect("network_id validated by factory") as u64;

						delivery_providers.insert(chain_id, provider);
						tracing::info!(component = "delivery", implementation = %name, chain_id = %chain_id, "Loaded");
					}
					Err(e) => {
						tracing::error!(
							component = "delivery",
							implementation = %name,
							error = %e,
							"Failed to create delivery provider"
						);
						return Err(BuilderError::Config(format!(
							"Failed to create delivery provider '{}': {}",
							name, e
						)));
					}
				}
			}
		}

		if delivery_providers.is_empty() {
			tracing::warn!("No delivery providers available - solver will not be able to submit any transactions");
		}

		let delivery = Arc::new(DeliveryService::new(
			delivery_providers,
			account.clone(),
			self.config.delivery.min_confirmations,
		));

		// Create discovery sources
		let mut discovery_sources = Vec::new();
		for (name, config) in &self.config.discovery.sources {
			if let Some(factory) = factories.discovery_factories.get(name) {
				match factory(config, &self.config.networks) {
					Ok(source) => {
						// Validation already happened in the factory
						discovery_sources.push(source);
						tracing::info!(component = "discovery", implementation = %name, "Loaded");
					}
					Err(e) => {
						tracing::error!(
							component = "discovery",
							implementation = %name,
							error = %e,
							"Failed to create discovery source"
						);
						return Err(BuilderError::Config(format!(
							"Failed to create discovery source '{}': {}",
							name, e
						)));
					}
				}
			}
		}

		if discovery_sources.is_empty() {
			tracing::warn!(
				"No discovery sources available - solver will not discover any new orders"
			);
		}

		let discovery = Arc::new(DiscoveryService::new(discovery_sources));

		// Create order implementations
		let mut order_impls = HashMap::new();
		for (name, config) in &self.config.order.implementations {
			if let Some(factory) = factories.order_factories.get(name) {
				match factory(config, &self.config.networks) {
					Ok(implementation) => {
						// Validation already happened in the factory
						order_impls.insert(name.clone(), implementation);
						tracing::info!(component = "order", implementation = %name, "Loaded");
					}
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
					}
				}
			}
		}

		if order_impls.is_empty() {
			tracing::warn!("No order implementations available - solver will not be able to process any orders");
		}

		// Create execution strategy
		let strategy = (factories.strategy_factory)(&self.config.order.execution_strategy.config);
		tracing::info!(component = "strategy", implementation = %self.config.order.execution_strategy.strategy_type, "Loaded");

		let order = Arc::new(OrderService::new(order_impls, strategy));

		// Create settlement implementations
		let mut settlement_impls = HashMap::new();
		for (name, config) in &self.config.settlement.implementations {
			if let Some(factory) = factories.settlement_factories.get(name) {
				match factory(config, &self.config.networks) {
					Ok(implementation) => {
						// Validation already happened in the factory
						settlement_impls.insert(name.clone(), implementation);
						tracing::info!(component = "settlement", implementation = %name, "Loaded");
					}
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
					}
				}
			}
		}

		if settlement_impls.is_empty() {
			tracing::warn!("No settlement implementations available - solver will not be able to monitor and claim settlements");
		}

		let settlement = Arc::new(SettlementService::new(settlement_impls));

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
			}
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
			}
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
			}
			Err(e) => {
				tracing::warn!(
					error = %e,
					"Failed to check initial balances"
				);
			}
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
			EventBus::new(1000),
			token_manager,
		))
	}
}
