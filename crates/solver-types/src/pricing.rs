//! Pricing oracle types for converting between wei and fiat currencies.
//!
//! This module defines the core pricing interface and types used by the solver
//! to convert gas costs from wei to display currencies like USD.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
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
	/// Error when parsing a trading pair from string format.
	#[error("Invalid pair format: {0}")]
	InvalidPairFormat(String),
}

/// Represents a trading pair for price queries.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TradingPair {
	/// The base asset (e.g., "ETH", "SOL").
	pub base: String,
	/// The quote asset (e.g., "USD", "SOL").
	pub quote: String,
}

impl TradingPair {
	/// Creates a new trading pair.
	pub fn new(base: &str, quote: &str) -> Self {
		Self {
			base: base.to_uppercase(),
			quote: quote.to_uppercase(),
		}
	}
}

impl fmt::Display for TradingPair {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}/{}", self.base, self.quote)
	}
}

impl FromStr for TradingPair {
	type Err = PricingError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let parts: Vec<&str> = s.split('/').collect();
		if parts.len() != 2 {
			return Err(PricingError::InvalidPairFormat(s.to_string()));
		}
		Ok(Self::new(parts[0], parts[1]))
	}
}

/// Represents a price quote for an asset in a specific currency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetPrice {
	/// The trading pair this price represents.
	pub pair: TradingPair,
	/// The price of the base asset in terms of the quote asset.
	pub price: String,
	/// Timestamp when this price was retrieved (Unix timestamp).
	pub timestamp: u64,
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
