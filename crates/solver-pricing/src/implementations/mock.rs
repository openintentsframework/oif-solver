//! Mock pricing implementation for development and testing.
//!
//! This implementation provides fixed asset prices for development purposes.
//! Supports ETH/USD, ETH/SOL, SOL/USD pairs as requested.

use crate::{PricingFactory, PricingInterface, PricingRegistry};
use alloy_primitives::utils::parse_ether;
use async_trait::async_trait;
use solver_types::utils::wei_string_to_eth_string;
use solver_types::{
	ConfigSchema, ImplementationRegistry, PricingError, TradingPair, ValidationError,
	MOCK_ETH_SOL_PRICE, MOCK_ETH_USD_PRICE, MOCK_SOL_USD_PRICE, MOCK_TOKA_USD_PRICE,
	MOCK_TOKB_USD_PRICE,
};
use std::collections::HashMap;
use toml;

/// Mock pricing implementation with fixed asset prices.
pub struct MockPricing {
	/// Map of trading pairs to their prices.
	pair_prices: HashMap<String, String>,
}

impl MockPricing {
	/// Creates a new MockPricing instance with configuration.
	pub fn new(config: &toml::Value) -> Result<Self, PricingError> {
		let mut pair_prices = HashMap::new();

		// Default prices
		pair_prices.insert("ETH/USD".to_string(), MOCK_ETH_USD_PRICE.to_string());
		pair_prices.insert("SOL/USD".to_string(), MOCK_SOL_USD_PRICE.to_string());
		pair_prices.insert("ETH/SOL".to_string(), MOCK_ETH_SOL_PRICE.to_string()); // ETH price / SOL price

		// Demo token prices
		pair_prices.insert("TOKA/USD".to_string(), MOCK_TOKA_USD_PRICE.to_string());
		pair_prices.insert("TOKB/USD".to_string(), MOCK_TOKB_USD_PRICE.to_string());

		// Allow configuration overrides
		if let Some(prices) = config.get("pair_prices").and_then(|v| v.as_table()) {
			for (pair, price) in prices {
				if let Some(price_str) = price.as_str() {
					pair_prices.insert(pair.to_uppercase(), price_str.to_string());
				}
			}
		}

		// Legacy support for eth_price_usd
		if let Some(eth_price) = config.get("eth_price_usd").and_then(|v| v.as_str()) {
			pair_prices.insert("ETH/USD".to_string(), eth_price.to_string());
		}

		Ok(Self { pair_prices })
	}

	/// Helper to get price for a pair, trying both directions.
	fn get_pair_price_internal(&self, pair: &TradingPair) -> Option<(String, bool)> {
		let forward_key = format!("{}/{}", pair.base, pair.quote);
		let reverse_key = format!("{}/{}", pair.quote, pair.base);

		if let Some(price) = self.pair_prices.get(&forward_key) {
			Some((price.clone(), false))
		} else if let Some(reverse_price) = self.pair_prices.get(&reverse_key) {
			// Calculate inverse price
			if let Ok(price_f64) = reverse_price.parse::<f64>() {
				if price_f64 != 0.0 {
					let inverse = 1.0 / price_f64;
					Some((format!("{inverse:.8}"), true))
				} else {
					None
				}
			} else {
				None
			}
		} else {
			None
		}
	}
}

#[async_trait]
impl PricingInterface for MockPricing {
	fn config_schema(&self) -> Box<dyn ConfigSchema> {
		Box::new(MockPricingSchema)
	}

	async fn get_supported_pairs(&self) -> Vec<TradingPair> {
		let mut pairs = Vec::new();
		for pair_str in self.pair_prices.keys() {
			if let Ok(pair) = pair_str.parse::<TradingPair>() {
				pairs.push(pair);
			}
		}
		pairs
	}

	async fn convert_asset(
		&self,
		from_asset: &str,
		to_asset: &str,
		amount: &str,
	) -> Result<String, PricingError> {
		let from_upper = from_asset.to_uppercase();
		let to_upper = to_asset.to_uppercase();

		if from_upper == to_upper {
			return Ok(amount.to_string());
		}

		let amount_f64 = amount
			.parse::<f64>()
			.map_err(|e| PricingError::InvalidData(format!("Invalid amount: {e}")))?;

		// Direct conversion
		let direct_pair = TradingPair::new(&from_upper, &to_upper);
		if let Some((price, _)) = self.get_pair_price_internal(&direct_pair) {
			let price_f64 = price
				.parse::<f64>()
				.map_err(|e| PricingError::InvalidData(format!("Invalid price: {e}")))?;
			return Ok((amount_f64 * price_f64).to_string());
		}

		// Try conversion through USD
		let from_usd_pair = TradingPair::new(&from_upper, "USD");
		let to_usd_pair = TradingPair::new(&to_upper, "USD");

		if let (Some((from_usd_price, _)), Some((to_usd_price, _))) = (
			self.get_pair_price_internal(&from_usd_pair),
			self.get_pair_price_internal(&to_usd_pair),
		) {
			let from_price_f64 = from_usd_price
				.parse::<f64>()
				.map_err(|e| PricingError::InvalidData(format!("Invalid from price: {e}")))?;
			let to_price_f64 = to_usd_price
				.parse::<f64>()
				.map_err(|e| PricingError::InvalidData(format!("Invalid to price: {e}")))?;

			if to_price_f64 != 0.0 {
				let conversion_rate = from_price_f64 / to_price_f64;
				return Ok((amount_f64 * conversion_rate).to_string());
			}
		}

		Err(PricingError::PriceNotAvailable(format!(
			"No conversion path from {from_asset} to {to_asset}"
		)))
	}

	async fn wei_to_currency(
		&self,
		wei_amount: &str,
		currency: &str,
	) -> Result<String, PricingError> {
		// Convert wei to ETH using utility function
		let eth_amount_str =
			wei_string_to_eth_string(wei_amount).map_err(PricingError::InvalidData)?;

		let eth_amount_f64 = eth_amount_str
			.parse::<f64>()
			.map_err(|e| PricingError::InvalidData(format!("Invalid ETH amount: {e}")))?;

		// Convert ETH to target currency
		let eth_pair = TradingPair::new("ETH", currency);
		if let Some((price, _)) = self.get_pair_price_internal(&eth_pair) {
			let price_f64 = price
				.parse::<f64>()
				.map_err(|e| PricingError::InvalidData(format!("Invalid price: {e}")))?;
			let result = eth_amount_f64 * price_f64;
			// Use 8 decimal places to preserve precision for small gas costs
			Ok(format!("{result:.8}"))
		} else {
			Err(PricingError::PriceNotAvailable(format!("ETH/{currency}")))
		}
	}

	async fn currency_to_wei(
		&self,
		currency_amount: &str,
		currency: &str,
	) -> Result<String, PricingError> {
		let currency_amount_f64 = currency_amount
			.parse::<f64>()
			.map_err(|e| PricingError::InvalidData(format!("Invalid currency amount: {e}")))?;

		// Get ETH price in the given currency
		let eth_pair = TradingPair::new("ETH", currency);
		if let Some((price, _)) = self.get_pair_price_internal(&eth_pair) {
			let eth_price_f64 = price
				.parse::<f64>()
				.map_err(|e| PricingError::InvalidData(format!("Invalid ETH price: {e}")))?;

			if eth_price_f64 == 0.0 {
				return Err(PricingError::InvalidData(
					"ETH price cannot be zero".to_string(),
				));
			}

			// Convert currency to ETH, then to wei using Alloy's parse_ether helper
			let eth_amount = currency_amount_f64 / eth_price_f64;
			let eth_amount_str = format!("{eth_amount:.18}"); // Use high precision for ETH
			let wei_amount = parse_ether(&eth_amount_str).map_err(|e| {
				PricingError::InvalidData(format!("Failed to convert ETH to wei: {e}"))
			})?;

			Ok(wei_amount.to_string())
		} else {
			Err(PricingError::PriceNotAvailable(format!("ETH/{currency}")))
		}
	}
}

/// Configuration schema for mock pricing implementation.
pub struct MockPricingSchema;

impl ConfigSchema for MockPricingSchema {
	fn validate(&self, config: &toml::Value) -> Result<(), ValidationError> {
		// Optional pair_prices validation
		if let Some(pair_prices) = config.get("pair_prices") {
			if let Some(table) = pair_prices.as_table() {
				for (pair, price) in table {
					// Validate pair format
					if !pair.contains('/') {
						return Err(ValidationError::InvalidValue {
							field: format!("pair_prices.{pair}"),
							message: "Pair must be in format 'BASE/QUOTE'".to_string(),
						});
					}

					// Validate price is string
					if price.as_str().is_none() {
						return Err(ValidationError::TypeMismatch {
							field: format!("pair_prices.{pair}"),
							expected: "string".to_string(),
							actual: format!("{price:?}"),
						});
					}
				}
			} else {
				return Err(ValidationError::TypeMismatch {
					field: "pair_prices".to_string(),
					expected: "table".to_string(),
					actual: format!("{pair_prices:?}"),
				});
			}
		}

		Ok(())
	}
}

/// Registry for mock pricing implementation.
pub struct MockPricingRegistry;

impl ImplementationRegistry for MockPricingRegistry {
	const NAME: &'static str = "mock";
	type Factory = PricingFactory;

	fn factory() -> Self::Factory {
		create_mock_pricing
	}
}

impl PricingRegistry for MockPricingRegistry {}

/// Factory function for creating MockPricing instances.
pub fn create_mock_pricing(
	config: &toml::Value,
) -> Result<Box<dyn PricingInterface>, PricingError> {
	Ok(Box::new(MockPricing::new(config)?))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn create_default_config() -> toml::Value {
		toml::Value::Table(toml::map::Map::new())
	}

	#[tokio::test]
	async fn test_wei_to_currency_precision() {
		// Test that small gas costs are preserved with 8 decimal precision
		let config = create_default_config();
		let pricing = MockPricing::new(&config).unwrap();

		// 167885103876 wei at ETH price of $4615.16 (MOCK_ETH_USD_PRICE)
		// = 0.000000167885103876 ETH * 4615.16 = very small USD amount
		let result = pricing
			.wei_to_currency("167885103876", "USD")
			.await
			.unwrap();

		// Should have 8 decimal places of precision, not rounded to $0.00
		let value: f64 = result.parse().unwrap();
		assert!(value > 0.0, "Small gas cost should not be zero");
		assert!(value < 0.01, "Value should be less than 1 cent");

		// Verify we have more than 2 decimal places of precision
		assert!(
			result.contains('.'),
			"Result should have decimal point: {result}"
		);
		let decimal_places = result.split('.').nth(1).map(|s| s.len()).unwrap_or(0);
		assert!(
			decimal_places >= 4,
			"Should have at least 4 decimal places for precision, got {decimal_places}: {result}"
		);
	}

	#[tokio::test]
	async fn test_wei_to_currency_larger_amounts() {
		let config = create_default_config();
		let pricing = MockPricing::new(&config).unwrap();

		// 1 ETH in wei
		let result = pricing
			.wei_to_currency("1000000000000000000", "USD")
			.await
			.unwrap();

		let value: f64 = result.parse().unwrap();
		// Should be approximately $4615.16 (MOCK_ETH_USD_PRICE)
		assert!(
			value > 4000.0 && value < 5000.0,
			"1 ETH should be between $4000-$5000, got {value}"
		);
	}

	#[tokio::test]
	async fn test_convert_asset_same_currency() {
		let config = create_default_config();
		let pricing = MockPricing::new(&config).unwrap();

		// Same currency should return the same amount
		let result = pricing.convert_asset("ETH", "ETH", "1.5").await.unwrap();
		assert_eq!(result, "1.5");
	}

	#[tokio::test]
	async fn test_convert_asset_through_usd() {
		let config = create_default_config();
		let pricing = MockPricing::new(&config).unwrap();

		// ETH -> SOL conversion through USD
		// ETH = $4615.16, SOL = $240.50, so 1 ETH ≈ 19.2 SOL
		let result = pricing.convert_asset("ETH", "SOL", "1").await.unwrap();
		let value: f64 = result.parse().unwrap();

		assert!(
			value > 15.0 && value < 25.0,
			"1 ETH should be between 15-25 SOL, got {value}"
		);
	}

	#[tokio::test]
	async fn test_currency_to_wei() {
		let config = create_default_config();
		let pricing = MockPricing::new(&config).unwrap();

		// Get the mock ETH price first
		let eth_price: f64 = MOCK_ETH_USD_PRICE.parse().unwrap();

		// Convert that USD amount to wei - should be approximately 1 ETH
		let result = pricing
			.currency_to_wei(&eth_price.to_string(), "USD")
			.await
			.unwrap();
		let wei: u128 = result.parse().unwrap();

		// Should be close to 1e18 (1 ETH)
		let one_eth: u128 = 1_000_000_000_000_000_000;
		let diff = wei.abs_diff(one_eth);
		// Allow 1% tolerance
		assert!(
			diff < one_eth / 100,
			"${eth_price} should be ~1 ETH (1e18 wei), got {wei} wei"
		);
	}
}
