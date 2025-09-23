//! Pricing oracle types for converting between wei and fiat currencies.
//!
//! This module defines the core pricing interface and types used by the solver
//! to convert gas costs from wei to display currencies like USD.

use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use thiserror::Error;

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

