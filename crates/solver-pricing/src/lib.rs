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
	pub mod defillama;
	pub mod mock;
}

/// Get all registered pricing implementations.
pub fn get_all_implementations() -> Vec<(&'static str, PricingFactory)> {
	use implementations::{coingecko, defillama, mock};
	vec![
		(
			mock::MockPricingRegistry::NAME,
			mock::MockPricingRegistry::factory(),
		),
		(
			coingecko::CoinGeckoPricingRegistry::NAME,
			coingecko::CoinGeckoPricingRegistry::factory(),
		),
		(
			defillama::DefiLlamaPricingRegistry::NAME,
			defillama::DefiLlamaPricingRegistry::factory(),
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
/// Supports primary implementation with optional fallbacks.
pub struct PricingService {
	/// The primary pricing implementation.
	implementation: Box<dyn PricingInterface>,
	/// Fallback pricing implementations (tried in order if primary fails).
	fallbacks: Vec<Box<dyn PricingInterface>>,
	/// Pricing configuration.
	config: PricingConfig,
}

impl PricingService {
	/// Creates a new PricingService with the specified implementation and default config.
	pub fn new(implementation: Box<dyn PricingInterface>) -> Self {
		Self {
			implementation,
			fallbacks: Vec::new(),
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
			fallbacks: Vec::new(),
			config,
		}
	}

	/// Creates a new PricingService with fallback implementations.
	pub fn new_with_fallbacks(
		implementation: Box<dyn PricingInterface>,
		fallbacks: Vec<Box<dyn PricingInterface>>,
	) -> Self {
		Self {
			implementation,
			fallbacks,
			config: PricingConfig::default_values(),
		}
	}

	/// Creates a new PricingService with fallback implementations and config.
	pub fn new_with_fallbacks_and_config(
		implementation: Box<dyn PricingInterface>,
		fallbacks: Vec<Box<dyn PricingInterface>>,
		config: PricingConfig,
	) -> Self {
		Self {
			implementation,
			fallbacks,
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
	/// Falls back to alternative providers if primary fails.
	pub async fn convert_asset(
		&self,
		from_asset: &str,
		to_asset: &str,
		amount: &str,
	) -> Result<String, PricingError> {
		// Try primary implementation
		match self
			.implementation
			.convert_asset(from_asset, to_asset, amount)
			.await
		{
			Ok(result) => return Ok(result),
			Err(e) => {
				if self.fallbacks.is_empty() {
					return Err(e);
				}
				tracing::warn!(
					"Primary pricing provider failed for convert_asset: {}, trying fallbacks",
					e
				);
			}
		}

		// Try fallbacks in order
		for (idx, fallback) in self.fallbacks.iter().enumerate() {
			match fallback.convert_asset(from_asset, to_asset, amount).await {
				Ok(result) => {
					tracing::info!("Fallback provider {} succeeded for convert_asset", idx + 1);
					return Ok(result);
				}
				Err(e) => {
					tracing::warn!("Fallback provider {} failed for convert_asset: {}", idx + 1, e);
				}
			}
		}

		Err(PricingError::Network(
			"All pricing providers failed for convert_asset".to_string(),
		))
	}

	/// Converts a wei amount to the specified currency using current ETH price.
	/// Falls back to alternative providers if primary fails.
	pub async fn wei_to_currency(
		&self,
		wei_amount: &str,
		currency: &str,
	) -> Result<String, PricingError> {
		// Try primary implementation
		match self
			.implementation
			.wei_to_currency(wei_amount, currency)
			.await
		{
			Ok(result) => return Ok(result),
			Err(e) => {
				if self.fallbacks.is_empty() {
					return Err(e);
				}
				tracing::warn!(
					"Primary pricing provider failed for wei_to_currency: {}, trying fallbacks",
					e
				);
			}
		}

		// Try fallbacks in order
		for (idx, fallback) in self.fallbacks.iter().enumerate() {
			match fallback.wei_to_currency(wei_amount, currency).await {
				Ok(result) => {
					tracing::info!("Fallback provider {} succeeded for wei_to_currency", idx + 1);
					return Ok(result);
				}
				Err(e) => {
					tracing::warn!(
						"Fallback provider {} failed for wei_to_currency: {}",
						idx + 1,
						e
					);
				}
			}
		}

		Err(PricingError::Network(
			"All pricing providers failed for wei_to_currency".to_string(),
		))
	}

	/// Converts a currency amount to wei using current ETH price.
	/// Falls back to alternative providers if primary fails.
	pub async fn currency_to_wei(
		&self,
		currency_amount: &str,
		currency: &str,
	) -> Result<String, PricingError> {
		// Try primary implementation
		match self
			.implementation
			.currency_to_wei(currency_amount, currency)
			.await
		{
			Ok(result) => return Ok(result),
			Err(e) => {
				if self.fallbacks.is_empty() {
					return Err(e);
				}
				tracing::warn!(
					"Primary pricing provider failed for currency_to_wei: {}, trying fallbacks",
					e
				);
			}
		}

		// Try fallbacks in order
		for (idx, fallback) in self.fallbacks.iter().enumerate() {
			match fallback.currency_to_wei(currency_amount, currency).await {
				Ok(result) => {
					tracing::info!("Fallback provider {} succeeded for currency_to_wei", idx + 1);
					return Ok(result);
				}
				Err(e) => {
					tracing::warn!(
						"Fallback provider {} failed for currency_to_wei: {}",
						idx + 1,
						e
					);
				}
			}
		}

		Err(PricingError::Network(
			"All pricing providers failed for currency_to_wei".to_string(),
		))
	}
}
