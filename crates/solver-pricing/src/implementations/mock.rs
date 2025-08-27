//! Mock pricing implementation for development and testing.
//!
//! This implementation provides fixed asset prices for development purposes.
//! ETH is set to $4,615.16 as requested.

use alloy_primitives::U256;
use async_trait::async_trait;
use solver_types::{
	AssetPrice, ConfigSchema, ImplementationRegistry, PricingError, PricingFactory,
	PricingInterface, PricingRegistry, ValidationError,
};
use toml;

/// Mock pricing implementation with fixed asset prices.
pub struct MockPricing {
	/// Fixed ETH price in USD.
	eth_price_usd: String,
}

impl MockPricing {
	/// Creates a new MockPricing instance with configuration.
	pub fn new(config: &toml::Value) -> Result<Self, PricingError> {
		let eth_price_usd = config
			.get("eth_price_usd")
			.and_then(|v| v.as_str())
			.unwrap_or("4615.16")
			.to_string();

		Ok(Self { eth_price_usd })
	}
}

#[async_trait]
impl PricingInterface for MockPricing {
	fn config_schema(&self) -> Box<dyn ConfigSchema> {
		Box::new(MockPricingSchema)
	}

	async fn get_asset_price(
		&self,
		asset: &str,
		currency: &str,
	) -> Result<AssetPrice, PricingError> {
		match (
			asset.to_uppercase().as_str(),
			currency.to_uppercase().as_str(),
		) {
			("ETH", "USD") => Ok(AssetPrice {
				asset: "ETH".to_string(),
				price: self.eth_price_usd.clone(),
				currency: "USD".to_string(),
			}),
			_ => Err(PricingError::PriceNotAvailable(format!(
				"{}/{}",
				asset, currency
			))),
		}
	}

	async fn wei_to_currency(
		&self,
		wei_amount: &str,
		currency: &str,
	) -> Result<String, PricingError> {
		if currency.to_uppercase() != "USD" {
			return Err(PricingError::PriceNotAvailable(currency.to_string()));
		}

		let wei = U256::from_str_radix(wei_amount, 10)
			.map_err(|e| PricingError::InvalidData(format!("Invalid wei amount: {}", e)))?;

		// Convert wei to ETH (1 ETH = 10^18 wei)
		let eth_decimals = U256::from(10_u64.pow(18));
		let eth_price = U256::from_str_radix(&self.eth_price_usd.replace(".", ""), 10)
			.map_err(|e| PricingError::InvalidData(format!("Invalid ETH price: {}", e)))?;

		// Calculate USD value: (wei * eth_price) / (10^18 * 100)
		// We multiply by 100 since our price has 2 decimal places
		let divisor = eth_decimals.saturating_mul(U256::from(100u64));
		let usd_value_scaled = wei
			.saturating_mul(eth_price)
			.checked_div(divisor)
			.unwrap_or(U256::ZERO);

		// Convert back to decimal string with 2 decimal places
		let dollars = usd_value_scaled
			.checked_div(U256::from(100u64))
			.unwrap_or(U256::ZERO);
		let cents = usd_value_scaled % U256::from(100u64);

		Ok(format!("{}.{:02}", dollars, cents))
	}

	async fn currency_to_wei(
		&self,
		currency_amount: &str,
		currency: &str,
	) -> Result<String, PricingError> {
		if currency.to_uppercase() != "USD" {
			return Err(PricingError::PriceNotAvailable(currency.to_string()));
		}

		let usd_amount = currency_amount
			.parse::<f64>()
			.map_err(|e| PricingError::InvalidData(format!("Invalid currency amount: {}", e)))?;

		let eth_price = self
			.eth_price_usd
			.parse::<f64>()
			.map_err(|e| PricingError::InvalidData(format!("Invalid ETH price: {}", e)))?;

		// Convert USD to ETH, then to wei
		let eth_amount = usd_amount / eth_price;
		let wei_amount = eth_amount * 10_f64.powi(18);

		Ok(format!("{:.0}", wei_amount))
	}
}

/// Configuration schema for mock pricing implementation.
pub struct MockPricingSchema;

impl ConfigSchema for MockPricingSchema {
	fn validate(&self, config: &toml::Value) -> Result<(), ValidationError> {
		// Optional eth_price_usd field validation
		if let Some(price_value) = config.get("eth_price_usd") {
			if price_value.as_str().is_none() {
				return Err(ValidationError::TypeMismatch {
					field: "eth_price_usd".to_string(),
					expected: "string".to_string(),
					actual: format!("{:?}", price_value),
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
