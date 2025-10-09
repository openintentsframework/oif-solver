//! Pricing oracle implementations for the OIF solver system.
//!
//! This module provides pricing oracle implementations for converting between
//! wei amounts and fiat currencies. Currently supports mock pricing for development.

use async_trait::async_trait;
use solver_types::{ConfigSchema, ImplementationRegistry, PricingError, TradingPair};

/// Trait defining the interface for pricing oracle implementations.
///
/// This trait must be implemented by any pricing implementation that wants to
/// integrate with the solver system. It provides methods for fetching asset prices
/// and converting between wei amounts and fiat currencies.
#[async_trait]
#[cfg_attr(feature = "testing", mockall::automock)]
pub trait PricingInterface: Send + Sync {
	/// Returns the configuration schema for this pricing implementation.
	fn config_schema(&self) -> Box<dyn ConfigSchema>;

	/// Gets all supported trading pairs by this implementation.
	async fn get_supported_pairs(&self) -> Vec<TradingPair>;

	/// Converts between two assets using available pricing data.
	/// This may involve multiple hops (e.g., ETH -> USD -> SOL).
	async fn convert_asset(
		&self,
		from_asset: &str,
		to_asset: &str,
		amount: &str,
	) -> Result<String, PricingError>;

	/// Converts a wei amount to the specified currency using current ETH price.
	///
	/// Takes wei amount as a string and returns the equivalent value in the target currency.
	async fn wei_to_currency(
		&self,
		wei_amount: &str,
		currency: &str,
	) -> Result<String, PricingError>;

	/// Converts a currency amount to wei using current ETH price.
	///
	/// Takes currency amount as a string and returns the equivalent value in wei.
	async fn currency_to_wei(
		&self,
		currency_amount: &str,
		currency: &str,
	) -> Result<String, PricingError>;
}

/// Type alias for pricing factory functions.
pub type PricingFactory = fn(&toml::Value) -> Result<Box<dyn PricingInterface>, PricingError>;

/// Registry trait for pricing implementations.
pub trait PricingRegistry: ImplementationRegistry<Factory = PricingFactory> {}

/// Re-export implementations
pub mod implementations {
	pub mod coingecko;
	pub mod mock;
}

/// Get all registered pricing implementations.
pub fn get_all_implementations() -> Vec<(&'static str, PricingFactory)> {
	use implementations::{coingecko, mock};
	vec![
		(
			mock::MockPricingRegistry::NAME,
			mock::MockPricingRegistry::factory(),
		),
		(
			coingecko::CoinGeckoPricingRegistry::NAME,
			coingecko::CoinGeckoPricingRegistry::factory(),
		),
	]
}

/// Configuration for pricing operations.
#[derive(Debug, Clone)]
pub struct PricingConfig {
	/// Target currency for price display.
	pub currency: String,
	/// Commission in basis points.
	pub commission_bps: u32,
	/// Gas buffer in basis points.
	pub gas_buffer_bps: u32,
	/// Rate buffer in basis points.
	pub rate_buffer_bps: u32,
	/// Whether to use live gas estimation.
	pub enable_live_gas_estimate: bool,
}

impl PricingConfig {
	pub fn default_values() -> Self {
		Self {
			currency: "USD".to_string(),
			commission_bps: 20,
			gas_buffer_bps: 1000,
			rate_buffer_bps: 14,
			enable_live_gas_estimate: false,
		}
	}

	/// Builds pricing config from a TOML table (e.g. strategy implementation table)
	pub fn from_table(table: &toml::Value) -> Self {
		let defaults = Self::default_values();
		Self {
			currency: table
				.get("pricing_currency")
				.and_then(|v| v.as_str())
				.unwrap_or(&defaults.currency)
				.to_string(),
			commission_bps: table
				.get("commission_bps")
				.and_then(|v| v.as_integer())
				.unwrap_or(defaults.commission_bps as i64) as u32,
			gas_buffer_bps: table
				.get("gas_buffer_bps")
				.and_then(|v| v.as_integer())
				.unwrap_or(defaults.gas_buffer_bps as i64) as u32,
			rate_buffer_bps: table
				.get("rate_buffer_bps")
				.and_then(|v| v.as_integer())
				.unwrap_or(defaults.rate_buffer_bps as i64) as u32,
			enable_live_gas_estimate: table
				.get("enable_live_gas_estimate")
				.and_then(|v| v.as_bool())
				.unwrap_or(defaults.enable_live_gas_estimate),
		}
	}
}

/// Service that manages asset pricing across the solver system.
pub struct PricingService {
	/// The primary pricing implementation.
	implementation: Box<dyn PricingInterface>,
	/// Pricing configuration.
	config: PricingConfig,
}

impl PricingService {
	/// Creates a new PricingService with the specified implementation and default config.
	pub fn new(implementation: Box<dyn PricingInterface>) -> Self {
		Self {
			implementation,
			config: PricingConfig::default_values(),
		}
	}

	/// Creates a new PricingService with the specified implementation and config.
	pub fn new_with_config(
		implementation: Box<dyn PricingInterface>,
		config: PricingConfig,
	) -> Self {
		Self {
			implementation,
			config,
		}
	}

	/// Gets the current pricing configuration.
	pub fn config(&self) -> &PricingConfig {
		&self.config
	}
	/// Gets all supported trading pairs.
	pub async fn get_supported_pairs(&self) -> Vec<TradingPair> {
		self.implementation.get_supported_pairs().await
	}

	/// Converts between two assets using available pricing data.
	pub async fn convert_asset(
		&self,
		from_asset: &str,
		to_asset: &str,
		amount: &str,
	) -> Result<String, PricingError> {
		self.implementation
			.convert_asset(from_asset, to_asset, amount)
			.await
	}

	/// Converts a wei amount to the specified currency using current ETH price.
	pub async fn wei_to_currency(
		&self,
		wei_amount: &str,
		currency: &str,
	) -> Result<String, PricingError> {
		self.implementation
			.wei_to_currency(wei_amount, currency)
			.await
	}

	/// Converts a currency amount to wei using current ETH price.
	pub async fn currency_to_wei(
		&self,
		currency_amount: &str,
		currency: &str,
	) -> Result<String, PricingError> {
		self.implementation
			.currency_to_wei(currency_amount, currency)
			.await
	}
}
