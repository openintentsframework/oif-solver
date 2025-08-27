//! Pricing oracle types for converting between wei and fiat currencies.
//!
//! This module defines the core pricing interface and types used by the solver
//! to convert gas costs from wei to display currencies like USD.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use toml;

use crate::{ConfigSchema, ImplementationRegistry};

/// Errors that can occur during pricing operations.
#[derive(Debug, Error)]
pub enum PricingError {
	/// Error when a requested asset price is not available.
	#[error("Price not available for asset: {0}")]
	PriceNotAvailable(String),
	/// Error during network communication with price sources.
	#[error("Network error: {0}")]
	Network(String),
	/// Error when price data is invalid or corrupted.
	#[error("Invalid price data: {0}")]
	InvalidData(String),
}

/// Represents a price quote for an asset in a specific currency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetPrice {
	/// The asset symbol or identifier (e.g., "ETH", "BTC").
	pub asset: String,
	/// The price in the target currency (e.g., USD).
	pub price: String,
	/// The currency this price is denominated in (e.g., "USD").
	pub currency: String,
}

/// Trait defining the interface for pricing oracle implementations.
///
/// This trait must be implemented by any pricing implementation that wants to
/// integrate with the solver system. It provides methods for fetching asset prices
/// and converting between wei amounts and fiat currencies.
#[async_trait]
pub trait PricingInterface: Send + Sync {
	/// Returns the configuration schema for this pricing implementation.
	fn config_schema(&self) -> Box<dyn ConfigSchema>;

	/// Gets the current price for an asset in the specified currency.
	///
	/// Returns the price as a decimal string to avoid precision loss.
	async fn get_asset_price(
		&self,
		asset: &str,
		currency: &str,
	) -> Result<AssetPrice, PricingError>;

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
