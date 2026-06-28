//! Builder pattern for constructing solver engines.
//!
//! Provides a flexible way to compose a SolverEngine from various service
//! implementations using factory functions. Supports pluggable storage,
//! account, delivery, discovery, order implementations and
//! settlement and execution strategies.

use crate::engine::{event_bus::EventBus, SolverEngine};
use alloy_primitives::U256;
use solver_account::{AccountError, AccountInterface, AccountService};
use solver_config::Config;
use solver_delivery::{DeliveryError, DeliveryInterface, DeliveryService};
use solver_discovery::{DiscoveryError, DiscoveryInterface, DiscoveryService};
use solver_order::{ExecutionStrategy, OrderError, OrderInterface, OrderService, StrategyError};
use solver_pricing::PricingService;
use solver_settlement::{SettlementError, SettlementInterface, SettlementService};
use solver_storage::{StorageError, StorageInterface, StorageService};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

fn native_gas_reserve_shortfall(balance: U256, configured_reserve: U256) -> Option<U256> {
	(balance < configured_reserve).then(|| configured_reserve.saturating_sub(balance))
}

/// Returns true when a token manager error was caused by the signer lacking
/// native gas to submit an approval transaction.
fn is_insufficient_native_gas(error: &crate::engine::token_manager::TokenManagerError) -> bool {
	matches!(
		error,
		crate::engine::token_manager::TokenManagerError::DeliveryError(
			DeliveryError::InsufficientNativeGas(_)
		)
	)
}

/// Pulls the chain id, signer address, and current balance out of a token
/// manager error caused by insufficient native gas. Returns `None` for any
/// other error variant.
fn blocked_signer_from_error(
	error: &crate::engine::token_manager::TokenManagerError,
) -> Option<crate::engine::startup_readiness::BlockedSigner> {
	match error {
		crate::engine::token_manager::TokenManagerError::DeliveryError(
			DeliveryError::InsufficientNativeGas(info),
		) => Some(crate::engine::startup_readiness::BlockedSigner {
			chain_id: info.chain_id,
			signer: info.signer.clone(),
			balance_wei: info.balance_wei.clone(),
		}),
		_ => None,
	}
}

/// Merges a known authoritative blocker (from the failing approval call)
/// with the result of a per-chain native-balance scan. Any chain showing a
/// strictly-zero balance is added; the primary blocker takes precedence
/// for its own chain so a non-zero but insufficient balance is still
/// reported correctly.
fn merge_blocked_signers(
	primary: Option<crate::engine::startup_readiness::BlockedSigner>,
	solver_address: &str,
	chain_balances: Vec<(u64, String)>,
) -> Vec<crate::engine::startup_readiness::BlockedSigner> {
	use crate::engine::startup_readiness::BlockedSigner;
	use std::collections::HashSet;

	let mut result: Vec<BlockedSigner> = Vec::new();
	let mut seen: HashSet<u64> = HashSet::new();

	if let Some(primary) = primary {
		seen.insert(primary.chain_id);
		result.push(primary);
	}

	for (chain_id, balance_wei) in chain_balances {
		if seen.contains(&chain_id) {
			continue;
		}
		if balance_wei == "0" {
			result.push(BlockedSigner {
				chain_id,
				signer: solver_address.to_string(),
				balance_wei,
			});
			seen.insert(chain_id);
		}
	}

	result
}

/// Reads native balances on every configured chain for `solver_address`
/// and merges with `primary` (the chain whose approval call actually
/// errored, if known) to produce the full set of blocked signers for the
/// frontend. Per-chain RPC failures are logged and skipped, never
/// propagated — a degraded RPC must not turn into a startup crash.
async fn discover_blocked_signers(
	delivery: &Arc<solver_delivery::DeliveryService>,
	networks: &solver_types::NetworksConfig,
	solver_address: &str,
	primary: Option<crate::engine::startup_readiness::BlockedSigner>,
) -> Vec<crate::engine::startup_readiness::BlockedSigner> {
	let mut chain_balances: Vec<(u64, String)> = Vec::with_capacity(networks.len());
	for chain_id in networks.keys() {
		match delivery.get_balance(*chain_id, solver_address, None).await {
			Ok(balance) => chain_balances.push((*chain_id, balance)),
			Err(error) => {
				tracing::debug!(
					chain_id = chain_id,
					error = %error,
					"Could not read native balance during blocked-signer scan; skipping chain"
				);
			},
		}
	}
	merge_blocked_signers(primary, solver_address, chain_balances)
}

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
	/// Dynamic configuration that supports hot reload via admin API.
	dynamic_config: Arc<RwLock<Config>>,
	/// Static configuration snapshot (services don't see hot reload changes).
	static_config: Config,
}

impl SolverBuilder {
	/// Creates a new SolverBuilder with the given configuration.
	///
	/// The builder takes a static snapshot of the config for building services.
	/// Services created from this snapshot will NOT see hot-reload changes.
	/// Hot-reload is handled at the API layer (e.g., quote validation reads
	/// networks directly from the dynamic config passed to handlers).
	pub fn new(dynamic_config: Arc<RwLock<Config>>, static_config: Config) -> Self {
		Self {
			dynamic_config,
			static_config,
		}
	}

	/// Builds the SolverEngine using factories for each component type.
	pub async fn build<SF, AF, DF, DIF, OF, PF, SEF, STF>(
		self,
		factories: SolverFactories<SF, AF, DF, DIF, OF, PF, SEF, STF>,
	) -> Result<SolverEngine, BuilderError>
	where
		SF: Fn(&serde_json::Value) -> Result<Box<dyn StorageInterface>, StorageError>,
		for<'a> AF: Fn(
			&'a serde_json::Value,
		) -> Pin<
			Box<dyn Future<Output = Result<Box<dyn AccountInterface>, AccountError>> + Send + 'a>,
		>,
		DF: Fn(
			&serde_json::Value,
			&solver_types::NetworksConfig,
			&solver_account::AccountSigner,
			&std::collections::HashMap<u64, solver_account::AccountSigner>,
		) -> Result<Box<dyn DeliveryInterface>, DeliveryError>,
		DIF: Fn(
			&serde_json::Value,
			&solver_types::NetworksConfig,
		) -> Result<Box<dyn DiscoveryInterface>, DiscoveryError>,
		OF: Fn(
			&serde_json::Value,
			&solver_types::NetworksConfig,
			&solver_types::oracle::OracleRoutes,
		) -> Result<Box<dyn OrderInterface>, OrderError>,
		PF: Fn(
			&serde_json::Value,
		) -> Result<Box<dyn solver_pricing::PricingInterface>, solver_types::PricingError>,
		SEF: Fn(
			&serde_json::Value,
			&solver_types::NetworksConfig,
			Arc<StorageService>,
		) -> Result<Box<dyn SettlementInterface>, SettlementError>,
		STF: Fn(&serde_json::Value) -> Result<Box<dyn ExecutionStrategy>, StrategyError>,
	{
		// Create storage implementations
		let mut storage_impls = HashMap::new();
		for (name, config) in &self.static_config.storage.implementations {
			if let Some(factory) = factories.storage_factories.get(name) {
				match factory(config) {
					Ok(implementation) => {
						// Validation already happened in the factory
						storage_impls.insert(name.clone(), implementation);
						let is_primary = &self.static_config.storage.primary == name;
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
							"Failed to create storage implementation '{name}': {e}"
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
		let primary_storage = &self.static_config.storage.primary;
		let storage_backend = storage_impls.remove(primary_storage).ok_or_else(|| {
			BuilderError::Config(format!(
				"Primary storage '{primary_storage}' failed to load or has invalid configuration"
			))
		})?;

		let storage = Arc::new(StorageService::new(storage_backend));
		let transaction_attempt_recorder: Arc<dyn solver_delivery::TransactionAttemptRecorder> =
			Arc::new(
				crate::state::transaction_attempt::TransactionAttemptStore::new(storage.clone()),
			);

		// Create account implementations
		let mut account_impls = HashMap::new();
		for (name, config) in &self.static_config.account.implementations {
			if let Some(factory) = factories.account_factories.get(name) {
				match factory(config).await {
					Ok(implementation) => {
						account_impls.insert(name.clone(), implementation);
						let is_primary = &self.static_config.account.primary == name;
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
							"Failed to create account implementation '{name}': {e}"
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
		let primary_account = self.static_config.account.primary.as_str();
		let account = account_services
			.get(primary_account)
			.ok_or_else(|| {
				BuilderError::Config(format!(
					"Primary account '{primary_account}' not found in loaded accounts"
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
					"Failed to get solver address: {e}"
				)));
			},
		};

		// Log the solver address for operational visibility
		tracing::info!(
			component = "account",
			address = %solver_address,
			"Solver address initialized"
		);

		// Create delivery implementations
		let mut delivery_implementations = std::collections::HashMap::new();

		// Get the default signer from the primary account
		let default_signer = account.signer();

		for (name, config) in &self.static_config.delivery.implementations {
			if let Some(factory) = factories.delivery_factories.get(name) {
				// Parse per-network account mappings from config
				let mut network_signers = HashMap::new();
				if let Some(accounts_table) = config.get("accounts").and_then(|v| v.as_object()) {
					for (network_id_str, account_name_value) in accounts_table {
						if let Ok(network_id) = network_id_str.parse::<u64>() {
							if let Some(account_name) = account_name_value.as_str() {
								if let Some(account_service) = account_services.get(account_name) {
									let signer = account_service.signer();
									network_signers.insert(network_id, signer);
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
					&self.static_config.networks,
					&default_signer,
					&network_signers,
				) {
					Ok(implementation) => {
						// Extract network_ids from config to create the mapping
						if let Some(network_ids) =
							config.get("network_ids").and_then(|v| v.as_array())
						{
							let implementation_arc: Arc<dyn DeliveryInterface> =
								implementation.into();
							for network_id_value in network_ids {
								if let Some(network_id) = network_id_value.as_i64() {
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
								"Delivery implementation '{name}' missing network_ids configuration"
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
							"Failed to create delivery implementation '{name}': {e}"
						)));
					},
				}
			}
		}

		if delivery_implementations.is_empty() {
			tracing::warn!(
				"No delivery implementations available - solver will not be able to submit any transactions"
			);
		}

		let delivery = Arc::new(
			DeliveryService::new(
				delivery_implementations,
				self.static_config.delivery.min_confirmations,
				self.static_config.solver.monitoring_timeout_seconds,
				self.static_config.delivery.tx_confirmation_timeout_seconds,
			)
			.with_attempt_recorder(transaction_attempt_recorder.clone()),
		);

		// Create discovery implementations
		let mut discovery_implementations = HashMap::new();
		for (name, config) in &self.static_config.discovery.implementations {
			if let Some(factory) = factories.discovery_factories.get(name) {
				match factory(config, &self.static_config.networks) {
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
							"Failed to create discovery implementation '{name}': {e}"
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

		// Create settlement implementations (needed for oracle routes)
		let mut settlement_impls = HashMap::new();
		let primary = self.static_config.settlement.primary.clone();

		for (name, config) in &self.static_config.settlement.implementations {
			if let Some(factory) = factories.settlement_factories.get(name) {
				match factory(config, &self.static_config.networks, storage.clone()) {
					Ok(implementation) => {
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
							"Failed to create settlement implementation '{name}': {e}"
						)));
					},
				}
			}
		}

		if settlement_impls.is_empty() {
			tracing::warn!(
				"No settlement implementations available - solver will not be able to monitor and claim settlements"
			);
		} else if !primary.is_empty() && !settlement_impls.contains_key(&primary) {
			return Err(BuilderError::Config(format!(
				"Settlement primary '{primary}' not found in loaded implementations"
			)));
		}

		let settlement = Arc::new(SettlementService::new(
			settlement_impls,
			primary,
			self.static_config
				.settlement
				.settlement_poll_interval_seconds,
		));

		// Create pricing service
		let pricing_config =
			self.static_config.pricing.as_ref().ok_or_else(|| {
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
							"Failed to create pricing implementation '{name}': {e}"
						)));
					},
				}
			}
		}

		// Use the primary pricing implementation
		let primary_pricing = pricing_config.primary.as_str();
		let pricing_impl = pricing_impls.remove(primary_pricing).ok_or_else(|| {
			BuilderError::Config(format!(
				"Primary pricing '{primary_pricing}' failed to load or has invalid configuration"
			))
		})?;

		// Collect fallback implementations in order
		let mut fallback_impls = Vec::new();
		for fallback_name in &pricing_config.fallbacks {
			if let Some(fallback_impl) = pricing_impls.remove(fallback_name) {
				tracing::info!(
					component = "pricing",
					implementation = %fallback_name,
					"Registered as fallback"
				);
				fallback_impls.push(fallback_impl);
			} else {
				tracing::warn!(
					component = "pricing",
					implementation = %fallback_name,
					"Fallback pricing implementation not found or not configured"
				);
			}
		}

		if !fallback_impls.is_empty() {
			tracing::info!(
				component = "pricing",
				primary = %primary_pricing,
				fallback_count = %fallback_impls.len(),
				"Pricing service initialized with fallbacks"
			);
		}
		let pricing = Arc::new(PricingService::new(pricing_impl, fallback_impls));

		// Build oracle routes from settlement implementations
		let oracle_routes = settlement.build_oracle_routes();
		tracing::info!(
			oracle_routes = %oracle_routes.supported_routes.len(),
			"Built oracle routes from settlement implementations"
		);

		// Create order implementations (now with oracle routes)
		let mut order_impls = HashMap::new();
		for (name, config) in &self.static_config.order.implementations {
			if let Some(factory) = factories.order_factories.get(name) {
				match factory(config, &self.static_config.networks, &oracle_routes) {
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
							"Failed to create order implementation '{name}': {e}"
						)));
					},
				}
			}
		}

		if order_impls.is_empty() {
			tracing::warn!(
				"No order implementations available - solver will not be able to process any orders"
			);
		}

		// Create strategy implementations
		let mut strategy_impls = HashMap::new();
		for (name, config) in &self.static_config.order.strategy.implementations {
			if let Some(factory) = factories.strategy_factories.get(name) {
				match factory(config) {
					Ok(implementation) => {
						strategy_impls.insert(name.clone(), implementation);
						let is_primary = &self.static_config.order.strategy.primary == name;
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
							"Failed to create strategy implementation '{name}': {e}"
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
		let primary_strategy = self.static_config.order.strategy.primary.as_str();
		let strategy = strategy_impls.remove(primary_strategy).ok_or_else(|| {
			BuilderError::Config(format!(
				"Primary strategy '{primary_strategy}' failed to load or has invalid configuration"
			))
		})?;

		let order = Arc::new(OrderService::new(order_impls, strategy));

		// Create and initialize the TokenManager
		let token_manager = Arc::new(
			crate::engine::token_manager::TokenManager::new(
				self.static_config.networks.clone(),
				delivery.clone(),
				account.clone(),
			)
			.with_attempt_recorder(transaction_attempt_recorder),
		);

		let empty_token_networks: Vec<u64> = self
			.static_config
			.networks
			.iter()
			.filter_map(|(chain_id, network)| network.tokens.is_empty().then_some(*chain_id))
			.collect();
		if !empty_token_networks.is_empty() {
			if empty_token_networks.len() == self.static_config.networks.len() {
				tracing::warn!(
					chains = ?empty_token_networks,
					"All configured networks have zero tokens; solver started, but quotes and fills remain unavailable until tokens are added"
				);
			} else {
				tracing::warn!(
					chains = ?empty_token_networks,
					"Some configured networks have zero tokens; quote support is limited for those chains until tokens are added"
				);
			}
		}

		// Ensure all token approvals are set. If the signer has no native gas,
		// don't crash startup — log a warning and retry in the background so the
		// API stays up while an operator funds the signer. The deferred state is
		// surfaced through the engine's startup readiness handle (see below).
		let solver_address_str = solver_address.to_string();
		let mut deferred_blocked_signers: Vec<crate::engine::startup_readiness::BlockedSigner> =
			Vec::new();
		match token_manager.ensure_approvals().await {
			Ok(()) => {
				tracing::info!(
					component = "token_manager",
					networks = self.static_config.networks.len(),
					"Token manager initialized with approvals"
				);
			},
			Err(e) if is_insufficient_native_gas(&e) => {
				tracing::warn!(
					component = "token_manager",
					error = %e,
					"Startup token approvals deferred: signer lacks native gas. \
					 Retrying every 30s in the background."
				);
				deferred_blocked_signers = discover_blocked_signers(
					&delivery,
					&self.static_config.networks,
					&solver_address_str,
					blocked_signer_from_error(&e),
				)
				.await;
			},
			Err(e) => {
				tracing::error!(
					component = "token_manager",
					error = %e,
					"Failed to ensure token approvals"
				);
				return Err(BuilderError::Config(format!(
					"Failed to ensure token approvals: {e}"
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

		if let Some(ref rebalance) = self.static_config.rebalance {
			if rebalance.enabled {
				let solver_address_str = solver_address.to_string();
				for (chain_id, reserve_wei) in &rebalance.min_native_gas_reserve {
					let configured_reserve = match U256::from_str_radix(reserve_wei, 10) {
						Ok(value) => value,
						Err(e) => {
							tracing::warn!(
								chain_id,
								configured_min_native_gas_reserve_wei = %reserve_wei,
								error = %e,
								"Invalid min_native_gas_reserve value; skipping low native gas warning"
							);
							continue;
						},
					};

					match delivery
						.get_balance(*chain_id, &solver_address_str, None)
						.await
					{
						Ok(balance_wei) => match U256::from_str_radix(&balance_wei, 10) {
							Ok(balance) => {
								if let Some(shortfall) =
									native_gas_reserve_shortfall(balance, configured_reserve)
								{
									tracing::warn!(
										chain_id,
										signer = %solver_address_str,
										balance_wei = %balance,
										configured_min_native_gas_reserve_wei = %configured_reserve,
										shortfall_wei = %shortfall,
										"Low native gas balance for rebalance signer"
									);
								}
							},
							Err(e) => {
								tracing::warn!(
									chain_id,
									balance_wei = %balance_wei,
									error = %e,
									"Could not parse native balance for rebalance gas reserve warning"
								);
							},
						},
						Err(e) => {
							tracing::warn!(
								chain_id,
								signer = %solver_address_str,
								error = %e,
								"Could not read native balance for rebalance gas reserve warning"
							);
						},
					}
				}
			}
		}

		// Construct BridgeService if rebalance is configured and enabled
		let bridge_service = if let Some(ref rebalance) = self.static_config.rebalance {
			if rebalance.enabled {
				let alloy_addr = alloy_primitives::Address::from_slice(&solver_address.0);

				let bridge_config = rebalance.bridge_config.as_ref().ok_or_else(|| {
					BuilderError::Config("Rebalance enabled but bridge_config is missing".into())
				})?;

				let registered = solver_bridge::get_all_implementations().map_err(|e| {
					BuilderError::Config(format!("Failed to read bridge registry: {e}"))
				})?;
				let target = &rebalance.implementation;
				let (_, factory) = registered
					.iter()
					.find(|(name, _)| *name == target.as_str())
					.ok_or_else(|| {
						BuilderError::Config(format!(
							"Rebalance implementation '{target}' not registered. Available: {:?}",
							registered.iter().map(|(n, _)| n).collect::<Vec<_>>()
						))
					})?;

				let impl_ = factory(bridge_config, delivery.clone(), alloy_addr).map_err(|e| {
					BuilderError::Config(format!(
						"Failed to create bridge implementation '{target}': {e}"
					))
				})?;

				let mut impls = std::collections::HashMap::new();
				impls.insert(target.clone(), std::sync::Arc::from(impl_));

				tracing::info!(
					implementation = target,
					"Bridge service initialized for rebalancing"
				);

				Some(std::sync::Arc::new(solver_bridge::BridgeService::new(
					impls,
					storage.clone(),
					self.static_config.solver.id.clone(),
				)))
			} else {
				None
			}
		} else {
			None
		};

		let retry_token_manager = Arc::clone(&token_manager);
		let retry_delivery = Arc::clone(&delivery);
		let retry_networks = self.static_config.networks.clone();
		let retry_solver_address_str = solver_address_str.clone();

		let engine = SolverEngine::new(
			self.dynamic_config,
			self.static_config,
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
			bridge_service,
		);

		// If startup approvals were deferred for native gas, publish the
		// blocked-signer state on the engine's readiness handle and spawn the
		// retry loop. Using the engine's shared handle means /health reflects
		// updates without any extra plumbing. Each retry tick re-scans every
		// configured chain so the frontend sees signers drop off the list as
		// the operator funds them, not just one at a time.
		if !deferred_blocked_signers.is_empty() {
			let handle = engine.startup_readiness_handle();
			*handle.write().await =
				crate::engine::startup_readiness::StartupReadiness::waiting_for_native_gas(
					deferred_blocked_signers,
				);
			let retry_handle = Arc::clone(&handle);
			tokio::spawn(async move {
				loop {
					tokio::time::sleep(std::time::Duration::from_secs(30)).await;
					match retry_token_manager.ensure_approvals().await {
						Ok(()) => {
							tracing::info!(
								component = "token_manager",
								"Startup token approvals completed after native gas became available"
							);
							*retry_handle.write().await =
								crate::engine::startup_readiness::StartupReadiness::ready();
							return;
						},
						Err(retry_err) if is_insufficient_native_gas(&retry_err) => {
							tracing::debug!(
								component = "token_manager",
								error = %retry_err,
								"Still waiting for native gas to complete startup approvals"
							);
							let blocked = discover_blocked_signers(
								&retry_delivery,
								&retry_networks,
								&retry_solver_address_str,
								blocked_signer_from_error(&retry_err),
							)
							.await;
							if !blocked.is_empty() {
								*retry_handle.write().await =
									crate::engine::startup_readiness::StartupReadiness::waiting_for_native_gas(
										blocked,
									);
							}
						},
						Err(retry_err) => {
							tracing::error!(
								component = "token_manager",
								error = %retry_err,
								"Startup approval retry failed with non-gas error"
							);
						},
					}
				}
			});
		}

		Ok(engine)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn native_gas_reserve_shortfall_warns_when_balance_is_below_configured_reserve() {
		let shortfall = native_gas_reserve_shortfall(U256::from(10u64), U256::from(30u64));

		assert_eq!(shortfall, Some(U256::from(20u64)));
	}

	#[test]
	fn native_gas_reserve_shortfall_is_none_when_balance_meets_configured_reserve() {
		assert_eq!(
			native_gas_reserve_shortfall(U256::from(30u64), U256::from(30u64)),
			None
		);
		assert_eq!(
			native_gas_reserve_shortfall(U256::from(31u64), U256::from(30u64)),
			None
		);
	}

	#[test]
	fn is_insufficient_native_gas_matches_delivery_native_gas_error() {
		use crate::engine::token_manager::TokenManagerError;
		use solver_delivery::{DeliveryError, InsufficientNativeGasInfo};

		let err = TokenManagerError::DeliveryError(DeliveryError::InsufficientNativeGas(Box::new(
			InsufficientNativeGasInfo {
				chain_id: 8453,
				signer: "0xsolver".to_string(),
				balance_wei: "0".to_string(),
				required_wei: "1000".to_string(),
				shortfall_wei: "1000".to_string(),
				gas_limit: None,
				max_fee_per_gas: None,
				gas_price: None,
				value_wei: "0".to_string(),
			},
		)));

		assert!(is_insufficient_native_gas(&err));
	}

	#[test]
	fn is_insufficient_native_gas_rejects_unrelated_errors() {
		use crate::engine::token_manager::TokenManagerError;

		let err = TokenManagerError::ParseError("nope".to_string());

		assert!(!is_insufficient_native_gas(&err));
	}

	#[test]
	fn blocked_signer_from_native_gas_error_uses_chain_signer_balance() {
		use crate::engine::startup_readiness::BlockedSigner;
		use crate::engine::token_manager::TokenManagerError;
		use solver_delivery::{DeliveryError, InsufficientNativeGasInfo};

		let err = TokenManagerError::DeliveryError(DeliveryError::InsufficientNativeGas(Box::new(
			InsufficientNativeGasInfo {
				chain_id: 8453,
				signer: "0xsolver".to_string(),
				balance_wei: "1000000000000".to_string(),
				required_wei: "5000000000000".to_string(),
				shortfall_wei: "4000000000000".to_string(),
				gas_limit: None,
				max_fee_per_gas: None,
				gas_price: None,
				value_wei: "0".to_string(),
			},
		)));

		let signer =
			blocked_signer_from_error(&err).expect("native gas error yields blocked signer");

		assert_eq!(
			signer,
			BlockedSigner {
				chain_id: 8453,
				signer: "0xsolver".to_string(),
				balance_wei: "1000000000000".to_string(),
			}
		);
	}

	#[test]
	fn blocked_signer_from_unrelated_error_is_none() {
		use crate::engine::token_manager::TokenManagerError;

		let err = TokenManagerError::ParseError("nope".to_string());

		assert!(blocked_signer_from_error(&err).is_none());
	}

	#[test]
	fn merge_blocked_signers_lists_every_zero_balance_chain() {
		let merged = merge_blocked_signers(
			None,
			"0xsolver",
			vec![(1, "0".to_string()), (10, "0".to_string())],
		);

		assert_eq!(merged.len(), 2);
		assert!(merged
			.iter()
			.any(|s| s.chain_id == 1 && s.balance_wei == "0"));
		assert!(merged
			.iter()
			.any(|s| s.chain_id == 10 && s.balance_wei == "0"));
	}

	#[test]
	fn merge_blocked_signers_preserves_primary_authoritative_balance() {
		use crate::engine::startup_readiness::BlockedSigner;

		// Primary error reports a non-zero but insufficient balance on chain 1.
		// The naive scan also sees that balance as non-zero, so it would skip
		// chain 1 — we must keep the primary's record.
		let primary = Some(BlockedSigner {
			chain_id: 1,
			signer: "0xsolver".to_string(),
			balance_wei: "500".to_string(),
		});

		let merged = merge_blocked_signers(
			primary,
			"0xsolver",
			vec![(1, "500".to_string()), (10, "0".to_string())],
		);

		assert_eq!(merged.len(), 2);
		let chain1 = merged.iter().find(|s| s.chain_id == 1).unwrap();
		assert_eq!(chain1.balance_wei, "500"); // primary's value preserved, not duplicated
		assert!(merged
			.iter()
			.any(|s| s.chain_id == 10 && s.balance_wei == "0"));
	}

	#[test]
	fn merge_blocked_signers_omits_funded_chains() {
		let merged = merge_blocked_signers(
			None,
			"0xsolver",
			vec![
				(1, "1000000000000000000".to_string()), // 1 ETH — funded
				(10, "0".to_string()),
			],
		);

		assert_eq!(merged.len(), 1);
		assert_eq!(merged[0].chain_id, 10);
	}

	#[test]
	fn merge_blocked_signers_empty_when_everything_funded_and_no_primary() {
		let merged = merge_blocked_signers(
			None,
			"0xsolver",
			vec![(1, "1000".to_string()), (10, "1".to_string())],
		);

		assert!(merged.is_empty());
	}
}
