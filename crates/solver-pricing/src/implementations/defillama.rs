//! DeFiLlama pricing implementation for production use.
//!
//! This implementation provides real-time asset prices from DeFiLlama API.
//! DeFiLlama is a free, open-source API with no rate limits for basic usage.

use crate::{PricingFactory, PricingInterface, PricingRegistry};
use alloy_primitives::utils::parse_ether;
use async_trait::async_trait;
use reqwest::{
	header::{HeaderMap, HeaderValue, ACCEPT},
	Client,
};
use rust_decimal::Decimal;
use serde::Deserialize;
use solver_types::utils::wei_string_to_eth_string;
use solver_types::{
	ConfigSchema, ImplementationRegistry, PricingError, TradingPair, ValidationError,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::debug;

/// Cache entry for price data
#[derive(Debug, Clone)]
struct PriceCacheEntry {
	price: String,
	timestamp: u64,
}

/// DeFiLlama pricing implementation with caching.
pub struct DefiLlamaPricing {
	/// HTTP client for API requests
	client: Client,
	/// Base URL for the API
	base_url: String,
	/// Cache for price data
	price_cache: Arc<RwLock<HashMap<String, PriceCacheEntry>>>,
	/// Cache duration in seconds
	cache_duration: u64,
	/// Map of token symbols (e.g., "ETH") to DeFiLlama coin IDs (e.g., "coingecko:ethereum")
	token_id_map: HashMap<String, String>,
	/// Custom fixed prices for tokens (useful for testing/demo)
	custom_prices: HashMap<String, String>,
}

/// DeFiLlama API response for current prices endpoint
#[derive(Debug, Deserialize)]
struct DefiLlamaPriceResponse {
	coins: HashMap<String, CoinPrice>,
}

#[derive(Debug, Deserialize)]
struct CoinPrice {
	price: f64,
	#[allow(dead_code)]
	symbol: Option<String>,
	#[allow(dead_code)]
	timestamp: Option<u64>,
	#[allow(dead_code)]
	confidence: Option<f64>,
}

impl DefiLlamaPricing {
	/// Creates a new DefiLlamaPricing instance with configuration.
	pub fn new(config: &toml::Value) -> Result<Self, PricingError> {
		// Validate configuration first
		let schema = DefiLlamaConfigSchema;
		schema.validate(config).map_err(|e| {
			PricingError::InvalidData(format!("Configuration validation failed: {e}"))
		})?;

		let base_url = config
			.get("base_url")
			.and_then(|v| v.as_str())
			.unwrap_or("https://coins.llama.fi")
			.to_string();

		let cache_duration = config
			.get("cache_duration_seconds")
			.and_then(|v| v.as_integer())
			.unwrap_or(60) as u64;

		// Build token ID map from shared defaults, adding "coingecko:" prefix for DeFiLlama API
		let mut token_id_map: HashMap<String, String> = crate::DEFAULT_TOKEN_MAPPINGS
			.iter()
			.map(|(symbol, id)| (symbol.to_string(), format!("coingecko:{id}")))
			.collect();

		// Allow custom token mappings
		if let Some(custom_tokens) = config.get("token_id_map").and_then(|v| v.as_table()) {
			for (symbol, id) in custom_tokens {
				if let Some(id_str) = id.as_str() {
					token_id_map.insert(symbol.to_uppercase(), id_str.to_string());
				}
			}
		}

		// Parse custom prices for tokens (useful for testing/demo)
		let mut custom_prices = HashMap::new();
		if let Some(prices_config) = config.get("custom_prices").and_then(|v| v.as_table()) {
			for (symbol, price) in prices_config {
				let price_decimal = if let Some(price_str) = price.as_str() {
					price_str.parse::<Decimal>().map_err(|e| {
						PricingError::InvalidData(format!(
							"Invalid custom price for {symbol}: {e}"
						))
					})?
				} else if let Some(price_num) = price.as_float() {
					Decimal::try_from(price_num).map_err(|e| {
						PricingError::InvalidData(format!(
							"Invalid custom price for {symbol}: {e}"
						))
					})?
				} else if let Some(price_int) = price.as_integer() {
					Decimal::from(price_int)
				} else {
					return Err(PricingError::InvalidData(format!(
						"Custom price for {symbol} must be a number or numeric string"
					)));
				};

				custom_prices.insert(symbol.to_uppercase(), price_decimal.to_string());
				debug!(
					"Added custom price for {}: ${}",
					symbol.to_uppercase(),
					price_decimal
				);
			}
		}

		// Create HTTP client with headers
		let mut headers = HeaderMap::new();
		headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

		let client = Client::builder()
			.default_headers(headers)
			.user_agent("oif-solver/0.1.0 (https://github.com/openzeppelin/oif-solver)")
			.timeout(Duration::from_secs(30))
			.build()
			.map_err(|e| PricingError::Network(format!("Failed to create HTTP client: {e}")))?;

		debug!(
			"DeFiLlama pricing initialized - Base URL: {}, Cache: {}s",
			base_url, cache_duration
		);
		debug!(
			"DeFiLlama token mappings: {} tokens configured",
			token_id_map.len()
		);

		Ok(Self {
			client,
			base_url,
			price_cache: Arc::new(RwLock::new(HashMap::new())),
			cache_duration,
			token_id_map,
			custom_prices,
		})
	}

	/// Get DeFiLlama coin ID for a token symbol
	fn get_defillama_id(&self, symbol: &str) -> Option<String> {
		self.token_id_map.get(&symbol.to_uppercase()).cloned()
	}

	/// Check if currency is USD (the only supported vs_currency)
	fn is_usd(&self, currency: &str) -> bool {
		currency.to_uppercase() == "USD"
	}

	/// Fetch prices from DeFiLlama API
	async fn fetch_prices(&self, ids: Vec<String>) -> Result<DefiLlamaPriceResponse, PricingError> {
		let ids_param = ids.join(",");

		// DeFiLlama endpoint: /prices/current/{coins}
		let url = format!("{}/prices/current/{}", self.base_url, ids_param);

		debug!("Fetching prices from DeFiLlama API: {}", url);

		let response = self
			.client
			.get(&url)
			.send()
			.await
			.map_err(|e| PricingError::Network(format!("API request failed: {e}")))?;

		if !response.status().is_success() {
			let status = response.status();
			let body = response.text().await.unwrap_or_default();
			return Err(PricingError::Network(format!(
				"API returned error status {status}: {body}"
			)));
		}

		response
			.json::<DefiLlamaPriceResponse>()
			.await
			.map_err(|e| PricingError::InvalidData(format!("Failed to parse response: {e}")))
	}

	/// Get cached price or fetch from API
	async fn get_price(&self, token: &str, vs_currency: &str) -> Result<String, PricingError> {
		let cache_key = format!("{}/{}", token.to_uppercase(), vs_currency.to_uppercase());

		// Check cache first
		{
			let cache = self.price_cache.read().await;
			if let Some(entry) = cache.get(&cache_key) {
				let now = SystemTime::now()
					.duration_since(UNIX_EPOCH)
					.unwrap()
					.as_secs();

				if now - entry.timestamp < self.cache_duration {
					debug!("Using cached price for {}: ${}", cache_key, entry.price);
					return Ok(entry.price.clone());
				}
			}
		}

		// Always fetch in USD
		if !self.is_usd(vs_currency) {
			return Err(PricingError::PriceNotAvailable(format!(
				"Only USD is supported, got {vs_currency}"
			)));
		}

		// Check if token has a custom price
		let token_upper = token.to_uppercase();
		if let Some(custom_price) = self.custom_prices.get(&token_upper) {
			debug!(
				"Returning custom price for {}: ${}",
				token_upper, custom_price
			);
			// Update cache
			{
				let mut cache = self.price_cache.write().await;
				cache.insert(
					cache_key.clone(),
					PriceCacheEntry {
						price: custom_price.clone(),
						timestamp: SystemTime::now()
							.duration_since(UNIX_EPOCH)
							.unwrap()
							.as_secs(),
					},
				);
			}
			return Ok(custom_price.clone());
		}

		// Fetch from API
		let defillama_id = self
			.get_defillama_id(token)
			.ok_or_else(|| PricingError::PriceNotAvailable(format!("Unknown token: {token}")))?;

		let response = self.fetch_prices(vec![defillama_id.clone()]).await?;

		let price = response
			.coins
			.get(&defillama_id)
			.ok_or_else(|| PricingError::PriceNotAvailable(format!("{token}/USD")))?;

		let price_decimal = Decimal::try_from(price.price)
			.map_err(|e| PricingError::InvalidData(format!("Invalid price value: {e}")))?;
		let price_str = price_decimal.to_string();

		// Update cache
		{
			let mut cache = self.price_cache.write().await;
			cache.insert(
				cache_key.clone(),
				PriceCacheEntry {
					price: price_str.clone(),
					timestamp: SystemTime::now()
						.duration_since(UNIX_EPOCH)
						.unwrap()
						.as_secs(),
				},
			);
		}

		debug!("Fetched and cached price for {}: ${}", cache_key, price_str);
		Ok(price_str)
	}

	/// Get price for a trading pair
	async fn get_pair_price(&self, pair: &TradingPair) -> Result<String, PricingError> {
		let base = &pair.base;
		let quote = &pair.quote;

		// If both are the same, price is 1
		if base.eq_ignore_ascii_case(quote) {
			return Ok("1.0".to_string());
		}

		// If quote is USD, get direct price
		if self.is_usd(quote) {
			return self.get_price(base, "USD").await;
		}

		// If base is USD but quote isn't, get inverse
		if self.is_usd(base) {
			let crypto_price = self.get_price(quote, "USD").await?;
			let price: Decimal = crypto_price
				.parse()
				.map_err(|e| PricingError::InvalidData(format!("Invalid price: {e}")))?;

			if price.is_zero() {
				return Err(PricingError::InvalidData("Price is zero".to_string()));
			}

			let one = Decimal::ONE;
			return Ok((one / price).to_string());
		}

		// For non-USD pairs, not supported
		Err(PricingError::PriceNotAvailable(format!(
			"Only USD pairs are supported, got {base}/{quote}"
		)))
	}
}

#[async_trait]
impl PricingInterface for DefiLlamaPricing {
	fn config_schema(&self) -> Box<dyn ConfigSchema> {
		Box::new(DefiLlamaConfigSchema)
	}

	async fn get_supported_pairs(&self) -> Vec<TradingPair> {
		// Generate pairs for all known tokens against USD only
		self.token_id_map
			.keys()
			.map(|token| TradingPair::new(token, "USD"))
			.collect()
	}

	async fn convert_asset(
		&self,
		from_asset: &str,
		to_asset: &str,
		amount: &str,
	) -> Result<String, PricingError> {
		if from_asset.eq_ignore_ascii_case(to_asset) {
			return Ok(amount.to_string());
		}

		let from_upper = from_asset.to_uppercase();
		let to_upper = to_asset.to_uppercase();

		let amount_decimal: Decimal = amount
			.parse()
			.map_err(|e| PricingError::InvalidData(format!("Invalid amount: {e}")))?;

		let pair = TradingPair::new(&from_upper, &to_upper);
		let rate = self.get_pair_price(&pair).await?;
		let rate_decimal: Decimal = rate
			.parse()
			.map_err(|e| PricingError::InvalidData(format!("Invalid rate: {e}")))?;

		let result = amount_decimal * rate_decimal;
		Ok(result.to_string())
	}

	async fn wei_to_currency(
		&self,
		wei_amount: &str,
		currency: &str,
	) -> Result<String, PricingError> {
		// Only USD is supported
		if !self.is_usd(currency) {
			return Err(PricingError::PriceNotAvailable(format!(
				"Only USD is supported, got {currency}"
			)));
		}

		// Convert wei to ETH using utility function
		let eth_amount_str =
			wei_string_to_eth_string(wei_amount).map_err(PricingError::InvalidData)?;

		let eth_amount: Decimal = eth_amount_str
			.parse()
			.map_err(|e| PricingError::InvalidData(format!("Invalid ETH amount: {e}")))?;

		// Get ETH price in USD
		let eth_price = self.get_price("ETH", "USD").await?;
		let price_decimal: Decimal = eth_price
			.parse()
			.map_err(|e| PricingError::InvalidData(format!("Invalid price: {e}")))?;

		let result = eth_amount * price_decimal;
		debug!(
			"Converted gas cost: {} wei = {} ETH = ${} USD (ETH price: ${})",
			wei_amount,
			eth_amount_str,
			result.round_dp(8),
			eth_price
		);
		// Use 8 decimal places to preserve precision for small gas costs
		Ok(result.round_dp(8).to_string())
	}

	async fn currency_to_wei(
		&self,
		currency_amount: &str,
		currency: &str,
	) -> Result<String, PricingError> {
		// Only USD is supported
		if !self.is_usd(currency) {
			return Err(PricingError::PriceNotAvailable(format!(
				"Only USD is supported, got {currency}"
			)));
		}

		let currency_amount_decimal: Decimal = currency_amount
			.parse()
			.map_err(|e| PricingError::InvalidData(format!("Invalid currency amount: {e}")))?;

		// Get ETH price in USD
		let eth_price = self.get_price("ETH", "USD").await?;
		let eth_price_decimal: Decimal = eth_price
			.parse()
			.map_err(|e| PricingError::InvalidData(format!("Invalid ETH price: {e}")))?;

		if eth_price_decimal.is_zero() {
			return Err(PricingError::InvalidData(
				"ETH price cannot be zero".to_string(),
			));
		}

		// Convert currency to ETH, then to wei
		// Round to 18 decimal places as parse_ether only accepts at most 18 fractional digits
		let eth_amount = currency_amount_decimal / eth_price_decimal;
		let eth_amount_str = format!("{eth_amount:.18}");
		let wei_amount = parse_ether(&eth_amount_str).map_err(|e| {
			PricingError::InvalidData(format!("Failed to convert ETH to wei: {e}"))
		})?;

		Ok(wei_amount.to_string())
	}
}

/// Configuration schema for DeFiLlama pricing implementation.
pub struct DefiLlamaConfigSchema;

impl ConfigSchema for DefiLlamaConfigSchema {
	fn validate(&self, config: &toml::Value) -> Result<(), ValidationError> {
		// Optional base URL
		if let Some(base_url) = config.get("base_url") {
			if base_url.as_str().is_none() {
				return Err(ValidationError::TypeMismatch {
					field: "base_url".to_string(),
					expected: "string".to_string(),
					actual: format!("{base_url:?}"),
				});
			}
		}

		// Optional cache duration
		if let Some(cache_duration) = config.get("cache_duration_seconds") {
			if cache_duration.as_integer().is_none() {
				return Err(ValidationError::TypeMismatch {
					field: "cache_duration_seconds".to_string(),
					expected: "integer".to_string(),
					actual: format!("{cache_duration:?}"),
				});
			}
		}

		// Optional token_id_map
		if let Some(token_map) = config.get("token_id_map") {
			if let Some(table) = token_map.as_table() {
				for (symbol, id) in table {
					if id.as_str().is_none() {
						return Err(ValidationError::TypeMismatch {
							field: format!("token_id_map.{symbol}"),
							expected: "string".to_string(),
							actual: format!("{id:?}"),
						});
					}
				}
			} else {
				return Err(ValidationError::TypeMismatch {
					field: "token_id_map".to_string(),
					expected: "table".to_string(),
					actual: format!("{token_map:?}"),
				});
			}
		}

		// Optional custom_prices
		if let Some(custom_prices) = config.get("custom_prices") {
			if let Some(table) = custom_prices.as_table() {
				for (symbol, price) in table {
					let is_valid = if let Some(price_str) = price.as_str() {
						price_str.parse::<Decimal>().is_ok()
					} else if let Some(price_num) = price.as_float() {
						Decimal::try_from(price_num).is_ok()
					} else {
						price.as_integer().is_some()
					};

					if !is_valid {
						return Err(ValidationError::TypeMismatch {
							field: format!("custom_prices.{symbol}"),
							expected: "valid decimal string, float, or integer".to_string(),
							actual: format!("{price:?}"),
						});
					}
				}
			} else {
				return Err(ValidationError::TypeMismatch {
					field: "custom_prices".to_string(),
					expected: "table".to_string(),
					actual: format!("{custom_prices:?}"),
				});
			}
		}

		Ok(())
	}
}

/// Registry for DeFiLlama pricing implementation.
pub struct DefiLlamaPricingRegistry;

impl ImplementationRegistry for DefiLlamaPricingRegistry {
	const NAME: &'static str = "defillama";
	type Factory = PricingFactory;

	fn factory() -> Self::Factory {
		create_defillama_pricing
	}
}

impl PricingRegistry for DefiLlamaPricingRegistry {}

/// Factory function for creating DefiLlamaPricing instances.
pub fn create_defillama_pricing(
	config: &toml::Value,
) -> Result<Box<dyn PricingInterface>, PricingError> {
	Ok(Box::new(DefiLlamaPricing::new(config)?))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn minimal_config() -> toml::Value {
		toml::Value::Table(toml::map::Map::new())
	}

	fn config_with_custom_prices() -> toml::Value {
		toml::from_str(
			r#"
            cache_duration_seconds = 10
            [custom_prices]
            ETH = "3000.50"
            BTC = "65000"
        "#,
		)
		.unwrap()
	}

	fn config_with_custom_base_url() -> toml::Value {
		toml::from_str(
			r#"
            base_url = "https://custom.llama.fi"
            cache_duration_seconds = 120
        "#,
		)
		.unwrap()
	}

	fn config_with_custom_token_map() -> toml::Value {
		toml::from_str(
			r#"
            [token_id_map]
            MYTOKEN = "coingecko:my-custom-token"
            CUSTOM = "coingecko:custom-coin"
        "#,
		)
		.unwrap()
	}

	fn config_with_float_custom_prices() -> toml::Value {
		toml::from_str(
			r#"
            [custom_prices]
            ETH = 3000.123
            SOL = 150
        "#,
		)
		.unwrap()
	}

	#[test]
	fn test_new_default_config() {
		let pricing = DefiLlamaPricing::new(&minimal_config()).unwrap();
		assert_eq!(pricing.base_url, "https://coins.llama.fi");
		assert_eq!(pricing.cache_duration, 60);
	}

	#[test]
	fn test_get_defillama_id() {
		let pricing = DefiLlamaPricing::new(&minimal_config()).unwrap();
		assert_eq!(
			pricing.get_defillama_id("ETH"),
			Some("coingecko:ethereum".to_string())
		);
		assert_eq!(
			pricing.get_defillama_id("btc"),
			Some("coingecko:bitcoin".to_string())
		);
		assert_eq!(
			pricing.get_defillama_id("WETH"),
			Some("coingecko:ethereum".to_string())
		);
		assert_eq!(pricing.get_defillama_id("UNKNOWN"), None);
	}

	#[test]
	fn test_is_usd() {
		let pricing = DefiLlamaPricing::new(&minimal_config()).unwrap();
		assert!(pricing.is_usd("USD"));
		assert!(pricing.is_usd("usd"));
		assert!(pricing.is_usd("Usd"));
		assert!(!pricing.is_usd("EUR"));
		assert!(!pricing.is_usd("ETH"));
	}

	#[tokio::test]
	async fn test_get_pair_price_same_asset() {
		let pricing = DefiLlamaPricing::new(&minimal_config()).unwrap();
		let pair = TradingPair::new("ETH", "ETH");
		let result = pricing.get_pair_price(&pair).await.unwrap();
		assert_eq!(result, "1.0");
	}

	#[tokio::test]
	async fn test_get_pair_price_unsupported() {
		let pricing = DefiLlamaPricing::new(&minimal_config()).unwrap();
		let pair = TradingPair::new("ETH", "BTC");
		let result = pricing.get_pair_price(&pair).await;
		assert!(result.is_err());
	}

	#[tokio::test]
	async fn test_custom_price_retrieval() {
		let pricing = DefiLlamaPricing::new(&config_with_custom_prices()).unwrap();
		let result = pricing.get_price("ETH", "USD").await.unwrap();
		assert_eq!(result, "3000.50");
	}

	#[tokio::test]
	async fn test_get_price_non_usd_fails() {
		let pricing = DefiLlamaPricing::new(&minimal_config()).unwrap();
		let result = pricing.get_price("ETH", "EUR").await;
		assert!(matches!(result, Err(PricingError::PriceNotAvailable(_))));
	}

	#[tokio::test]
	async fn test_get_price_unknown_token() {
		let pricing = DefiLlamaPricing::new(&minimal_config()).unwrap();
		let result = pricing.get_price("FAKECOIN", "USD").await;
		assert!(matches!(result, Err(PricingError::PriceNotAvailable(_))));
	}

	#[tokio::test]
	async fn test_convert_asset_same() {
		let pricing = DefiLlamaPricing::new(&minimal_config()).unwrap();
		let result = pricing.convert_asset("ETH", "eth", "5.5").await.unwrap();
		assert_eq!(result, "5.5");
	}

	#[tokio::test]
	async fn test_convert_asset_invalid_amount() {
		let pricing = DefiLlamaPricing::new(&minimal_config()).unwrap();
		let result = pricing.convert_asset("ETH", "USD", "not_a_number").await;
		assert!(matches!(result, Err(PricingError::InvalidData(_))));
	}

	#[tokio::test]
	async fn test_wei_to_currency_non_usd() {
		let pricing = DefiLlamaPricing::new(&minimal_config()).unwrap();
		let result = pricing.wei_to_currency("1000000000000000000", "EUR").await;
		assert!(matches!(result, Err(PricingError::PriceNotAvailable(_))));
	}

	#[tokio::test]
	async fn test_currency_to_wei_invalid() {
		let pricing = DefiLlamaPricing::new(&minimal_config()).unwrap();
		let result = pricing.currency_to_wei("invalid", "USD").await;
		assert!(matches!(result, Err(PricingError::InvalidData(_))));
	}

	#[tokio::test]
	async fn test_get_supported_pairs() {
		let pricing = DefiLlamaPricing::new(&minimal_config()).unwrap();
		let pairs = pricing.get_supported_pairs().await;
		assert!(!pairs.is_empty());
		// All should be against USD
		assert!(pairs.iter().all(|p| p.quote == "USD"));
	}

	#[test]
	fn test_config_schema_valid() {
		let schema = DefiLlamaConfigSchema;
		assert!(schema.validate(&minimal_config()).is_ok());
		assert!(schema.validate(&config_with_custom_prices()).is_ok());
	}

	#[test]
	fn test_config_schema_invalid_custom_price() {
		let schema = DefiLlamaConfigSchema;
		let bad_config = toml::from_str(
			r#"
            [custom_prices]
            ETH = "not_a_price"
        "#,
		)
		.unwrap();
		assert!(schema.validate(&bad_config).is_err());
	}

	#[test]
	fn test_new_with_custom_base_url() {
		let pricing = DefiLlamaPricing::new(&config_with_custom_base_url()).unwrap();
		assert_eq!(pricing.base_url, "https://custom.llama.fi");
		assert_eq!(pricing.cache_duration, 120);
	}

	#[test]
	fn test_custom_token_mapping() {
		let pricing = DefiLlamaPricing::new(&config_with_custom_token_map()).unwrap();
		assert_eq!(
			pricing.get_defillama_id("MYTOKEN"),
			Some("coingecko:my-custom-token".to_string())
		);
		assert_eq!(
			pricing.get_defillama_id("CUSTOM"),
			Some("coingecko:custom-coin".to_string())
		);
		// Should still have defaults
		assert_eq!(
			pricing.get_defillama_id("ETH"),
			Some("coingecko:ethereum".to_string())
		);
	}

	#[tokio::test]
	async fn test_custom_price_float_format() {
		let pricing = DefiLlamaPricing::new(&config_with_float_custom_prices()).unwrap();
		let result = pricing.get_price("ETH", "USD").await.unwrap();
		assert_eq!(result, "3000.123");
	}

	#[tokio::test]
	async fn test_custom_price_integer_format() {
		let pricing = DefiLlamaPricing::new(&config_with_float_custom_prices()).unwrap();
		let result = pricing.get_price("SOL", "USD").await.unwrap();
		assert_eq!(result, "150");
	}

	#[tokio::test]
	async fn test_convert_asset_with_custom_prices() {
		let pricing = DefiLlamaPricing::new(&config_with_custom_prices()).unwrap();
		// Convert 2 ETH to USD at $3000.50 each = $6001.00
		let result = pricing.convert_asset("ETH", "USD", "2").await.unwrap();
		assert_eq!(result, "6001.00");
	}

	#[tokio::test]
	async fn test_convert_asset_usd_to_crypto() {
		let pricing = DefiLlamaPricing::new(&config_with_custom_prices()).unwrap();
		// Convert $6001 USD to ETH at $3000.50 per ETH
		let result = pricing.convert_asset("USD", "ETH", "6001").await.unwrap();
		// $6001 / $3000.50 = ~1.9996667...
		let result_decimal: Decimal = result.parse().unwrap();
		assert!(result_decimal > Decimal::from(1));
		assert!(result_decimal < Decimal::from(3));
	}

	#[tokio::test]
	async fn test_wei_to_currency_with_custom_eth_price() {
		let pricing = DefiLlamaPricing::new(&config_with_custom_prices()).unwrap();
		// 1 ETH in wei = 1000000000000000000
		let result = pricing
			.wei_to_currency("1000000000000000000", "USD")
			.await
			.unwrap();
		// Should be $3000.50 (with 8 decimal places)
		assert_eq!(result, "3000.50000000");
	}

	#[tokio::test]
	async fn test_currency_to_wei_non_usd() {
		let pricing = DefiLlamaPricing::new(&minimal_config()).unwrap();
		let result = pricing.currency_to_wei("100", "EUR").await;
		assert!(matches!(result, Err(PricingError::PriceNotAvailable(_))));
	}

	#[tokio::test]
	async fn test_currency_to_wei_with_custom_price() {
		let pricing = DefiLlamaPricing::new(&config_with_custom_prices()).unwrap();
		// $3000.50 USD = 1 ETH = 1000000000000000000 wei
		let result = pricing.currency_to_wei("3000.50", "USD").await.unwrap();
		// Should be approximately 1 ETH in wei
		let wei: u128 = result.parse().unwrap();
		let one_eth_wei: u128 = 1_000_000_000_000_000_000;
		// Allow small precision difference
		assert!(wei > one_eth_wei - 1_000_000_000_000_000);
		assert!(wei < one_eth_wei + 1_000_000_000_000_000);
	}

	#[test]
	fn test_config_schema_invalid_base_url_type() {
		let schema = DefiLlamaConfigSchema;
		let bad_config = toml::from_str(
			r#"
            base_url = 123
        "#,
		)
		.unwrap();
		assert!(schema.validate(&bad_config).is_err());
	}

	#[test]
	fn test_config_schema_invalid_cache_duration_type() {
		let schema = DefiLlamaConfigSchema;
		let bad_config = toml::from_str(
			r#"
            cache_duration_seconds = "not_a_number"
        "#,
		)
		.unwrap();
		assert!(schema.validate(&bad_config).is_err());
	}

	#[test]
	fn test_config_schema_invalid_token_map_not_table() {
		let schema = DefiLlamaConfigSchema;
		let bad_config = toml::from_str(
			r#"
            token_id_map = "invalid"
        "#,
		)
		.unwrap();
		assert!(schema.validate(&bad_config).is_err());
	}

	#[test]
	fn test_config_schema_invalid_token_map_value() {
		let schema = DefiLlamaConfigSchema;
		let bad_config = toml::from_str(
			r#"
            [token_id_map]
            MYTOKEN = 123
        "#,
		)
		.unwrap();
		assert!(schema.validate(&bad_config).is_err());
	}

	#[test]
	fn test_config_schema_invalid_custom_prices_not_table() {
		let schema = DefiLlamaConfigSchema;
		let bad_config = toml::from_str(
			r#"
            custom_prices = "invalid"
        "#,
		)
		.unwrap();
		assert!(schema.validate(&bad_config).is_err());
	}

	#[test]
	fn test_config_schema_valid_float_prices() {
		let schema = DefiLlamaConfigSchema;
		assert!(schema.validate(&config_with_float_custom_prices()).is_ok());
	}

	#[test]
	fn test_registry_name() {
		assert_eq!(DefiLlamaPricingRegistry::NAME, "defillama");
	}

	#[test]
	fn test_factory_function() {
		let config = minimal_config();
		let result = create_defillama_pricing(&config);
		assert!(result.is_ok());
	}

	#[test]
	fn test_config_schema_method() {
		let pricing = DefiLlamaPricing::new(&minimal_config()).unwrap();
		let schema = pricing.config_schema();
		assert!(schema.validate(&minimal_config()).is_ok());
	}

	#[tokio::test]
	async fn test_cache_hit() {
		let pricing = DefiLlamaPricing::new(&config_with_custom_prices()).unwrap();
		// First call should populate cache
		let result1 = pricing.get_price("ETH", "USD").await.unwrap();
		// Second call should hit cache
		let result2 = pricing.get_price("ETH", "USD").await.unwrap();
		assert_eq!(result1, result2);
		assert_eq!(result1, "3000.50");
	}

	#[tokio::test]
	async fn test_get_pair_price_with_usd_base() {
		let pricing = DefiLlamaPricing::new(&config_with_custom_prices()).unwrap();
		// USD/ETH should give inverse of ETH/USD
		let pair = TradingPair::new("USD", "ETH");
		let result = pricing.get_pair_price(&pair).await.unwrap();
		let result_decimal: Decimal = result.parse().unwrap();
		// 1/3000.50 ≈ 0.000333...
		assert!(result_decimal > Decimal::ZERO);
		assert!(result_decimal < Decimal::ONE);
	}

	#[tokio::test]
	async fn test_convert_asset_crypto_to_crypto_fails() {
		let pricing = DefiLlamaPricing::new(&config_with_custom_prices()).unwrap();
		// ETH to BTC should fail (non-USD pair)
		let result = pricing.convert_asset("ETH", "BTC", "1").await;
		assert!(result.is_err());
	}

	#[test]
	fn test_default_token_mappings() {
		let pricing = DefiLlamaPricing::new(&minimal_config()).unwrap();
		// Check various default mappings
		assert_eq!(
			pricing.get_defillama_id("ETHEREUM"),
			Some("coingecko:ethereum".to_string())
		);
		assert_eq!(
			pricing.get_defillama_id("SOLANA"),
			Some("coingecko:solana".to_string())
		);
		assert_eq!(
			pricing.get_defillama_id("BITCOIN"),
			Some("coingecko:bitcoin".to_string())
		);
		assert_eq!(
			pricing.get_defillama_id("USDC"),
			Some("coingecko:usd-coin".to_string())
		);
		assert_eq!(
			pricing.get_defillama_id("USDT"),
			Some("coingecko:tether".to_string())
		);
		assert_eq!(
			pricing.get_defillama_id("DAI"),
			Some("coingecko:dai".to_string())
		);
		assert_eq!(
			pricing.get_defillama_id("WBTC"),
			Some("coingecko:wrapped-bitcoin".to_string())
		);
		assert_eq!(
			pricing.get_defillama_id("MATIC"),
			Some("coingecko:matic-network".to_string())
		);
		assert_eq!(
			pricing.get_defillama_id("ARB"),
			Some("coingecko:arbitrum".to_string())
		);
		assert_eq!(
			pricing.get_defillama_id("OP"),
			Some("coingecko:optimism".to_string())
		);
	}

	#[test]
	fn test_get_defillama_id_case_insensitive() {
		let pricing = DefiLlamaPricing::new(&minimal_config()).unwrap();
		assert_eq!(
			pricing.get_defillama_id("eth"),
			Some("coingecko:ethereum".to_string())
		);
		assert_eq!(
			pricing.get_defillama_id("Eth"),
			Some("coingecko:ethereum".to_string())
		);
		assert_eq!(
			pricing.get_defillama_id("ETH"),
			Some("coingecko:ethereum".to_string())
		);
	}
}
