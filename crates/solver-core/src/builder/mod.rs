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

#[derive(Debug, Error)]
pub enum BuilderError {
	#[error("Configuration error: {0}")]
	Config(String),
	#[error("Missing required component: {0}")]
	MissingComponent(String),
}

/// Container for all factory functions needed to build a SolverEngine
pub struct SolverFactories<SF, AF, DF, DIF, OF, SEF, STF> {
	pub storage_factory: SF,
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
	pub fn build<SF, AF, DF, DIF, OF, SEF, STF>(
		self,
		factories: SolverFactories<SF, AF, DF, DIF, OF, SEF, STF>,
	) -> Result<SolverEngine, BuilderError>
	where
		SF: FnOnce(&toml::Value) -> Result<Box<dyn StorageInterface>, StorageError>,
		AF: FnOnce(&toml::Value) -> Result<Box<dyn AccountInterface>, AccountError>,
		DF: Fn(&toml::Value) -> Result<Box<dyn DeliveryInterface>, DeliveryError>,
		DIF: Fn(&toml::Value) -> Result<Box<dyn DiscoveryInterface>, DiscoveryError>,
		OF: Fn(&toml::Value) -> Result<Box<dyn OrderInterface>, OrderError>,
		SEF: Fn(&toml::Value) -> Result<Box<dyn SettlementInterface>, SettlementError>,
		STF: FnOnce(&toml::Value) -> Box<dyn ExecutionStrategy>,
	{
		// Create storage backend
		let storage_backend =
			(factories.storage_factory)(&self.config.storage.config).map_err(|e| {
				tracing::error!(
					component = "storage",
					implementation = %self.config.storage.backend,
					error = %e,
					"Failed to create storage backend"
				);
				BuilderError::Config(format!(
					"Failed to create storage backend '{}': {}",
					self.config.storage.backend, e
				))
			})?;
		let storage = Arc::new(StorageService::new(storage_backend));
		tracing::info!(component = "storage", implementation = %self.config.storage.backend, "Loaded");

		// Create account provider
		let account_provider =
			(factories.account_factory)(&self.config.account.config).map_err(|e| {
				tracing::error!(
					component = "account",
					implementation = %self.config.account.provider,
					error = %e,
					"Failed to create account provider"
				);
				BuilderError::Config(format!(
					"Failed to create account provider '{}': {}",
					self.config.account.provider, e
				))
			})?;
		let account = Arc::new(AccountService::new(account_provider));
		tracing::info!(component = "account", implementation = %self.config.account.provider, "Loaded");

		// Create delivery providers
		let mut delivery_providers = HashMap::new();
		for (name, config) in &self.config.delivery.providers {
			if let Some(factory) = factories.delivery_factories.get(name) {
				// Extract chain_id from the config
				let chain_id = match config.get("chain_id").and_then(|v| v.as_integer()) {
					Some(id) => id as u64,
					None => {
						tracing::error!(
							component = "delivery",
							implementation = %name,
							"chain_id missing for delivery provider, skipping"
						);
						continue;
					}
				};

				match factory(config) {
					Ok(provider) => {
						// Validate the configuration using the provider's schema
						match provider.config_schema().validate(config) {
							Ok(_) => {
								delivery_providers.insert(chain_id, provider);
								tracing::info!(component = "delivery", implementation = %name, chain_id = %chain_id, "Loaded");
							}
							Err(e) => {
								tracing::error!(
									component = "delivery",
									implementation = %name,
									chain_id = %chain_id,
									error = %e,
									"Invalid configuration for delivery provider, skipping"
								);
							}
						}
					}
					Err(e) => {
						tracing::error!(
							component = "delivery",
							implementation = %name,
							chain_id = %chain_id,
							error = %e,
							"Failed to create delivery provider, skipping"
						);
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
				match factory(config) {
					Ok(source) => {
						// Validate the configuration using the source's schema
						match source.config_schema().validate(config) {
							Ok(_) => {
								discovery_sources.push(source);
								tracing::info!(component = "discovery", implementation = %name, "Loaded");
							}
							Err(e) => {
								tracing::error!(
									component = "discovery",
									implementation = %name,
									error = %e,
									"Invalid configuration for discovery source, skipping"
								);
							}
						}
					}
					Err(e) => {
						tracing::error!(
							component = "discovery",
							implementation = %name,
							error = %e,
							"Failed to create discovery source, skipping"
						);
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
				match factory(config) {
					Ok(implementation) => {
						// Validate the configuration using the implementation's schema
						match implementation.config_schema().validate(config) {
							Ok(_) => {
								order_impls.insert(name.clone(), implementation);
								tracing::info!(component = "order", implementation = %name, "Loaded");
							}
							Err(e) => {
								tracing::error!(
									component = "order",
									implementation = %name,
									error = %e,
									"Invalid configuration for order implementation, skipping"
								);
							}
						}
					}
					Err(e) => {
						tracing::error!(
							component = "order",
							implementation = %name,
							error = %e,
							"Failed to create order implementation, skipping"
						);
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
				match factory(config) {
					Ok(implementation) => {
						// Validate the configuration using the implementation's schema
						match implementation.config_schema().validate(config) {
							Ok(_) => {
								settlement_impls.insert(name.clone(), implementation);
								tracing::info!(component = "settlement", implementation = %name, "Loaded");
							}
							Err(e) => {
								tracing::error!(
									component = "settlement",
									implementation = %name,
									error = %e,
									"Invalid configuration for settlement implementation, skipping"
								);
							}
						}
					}
					Err(e) => {
						tracing::error!(
							component = "settlement",
							implementation = %name,
							error = %e,
							"Failed to create settlement implementation, skipping"
						);
					}
				}
			}
		}

		if settlement_impls.is_empty() {
			tracing::warn!("No settlement implementations available - solver will not be able to monitor and claim settlements");
		}

		let settlement = Arc::new(SettlementService::new(settlement_impls));

		Ok(SolverEngine::new(
			self.config,
			storage,
			delivery,
			discovery,
			order,
			settlement,
			EventBus::new(1000),
		))
	}
}
