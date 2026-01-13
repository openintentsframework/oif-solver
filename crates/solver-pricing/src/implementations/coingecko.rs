//! CoinGecko pricing implementation for production use.
//!
//! This implementation provides real-time asset prices from CoinGecko API.
//! Supports ETH and other major cryptocurrencies against USD.

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

/// CoinGecko pricing implementation with caching and rate limiting.
pub struct CoinGeckoPricing {
	/// HTTP client for API requests
	client: Client,
	/// API key for authentication (optional for free tier)
	#[allow(dead_code)]
	api_key: Option<String>,
	/// Base URL for the API
	base_url: String,
	/// Cache for price data
	price_cache: Arc<RwLock<HashMap<String, PriceCacheEntry>>>,
	/// Cache duration in seconds
	cache_duration: u64,
	/// Map of token symbols to CoinGecko IDs
	token_id_map: HashMap<String, String>,
	/// Custom fixed prices for tokens (useful for testing/demo)
	custom_prices: HashMap<String, String>,
	/// Rate limit delay in milliseconds
	rate_limit_delay_ms: u64,
	/// Last API call timestamp
	last_api_call: Arc<RwLock<Option<u64>>>,
}

/// CoinGecko API response for simple price endpoint
#[derive(Debug, Deserialize)]
struct SimplePriceResponse {
	#[serde(flatten)]
	prices: HashMap<String, HashMap<String, Decimal>>,
}

impl CoinGeckoPricing {
	/// Creates a new CoinGeckoPricing instance with configuration.
	pub fn new(config: &toml::Value) -> Result<Self, PricingError> {
		// Validate configuration first
		let schema = CoinGeckoConfigSchema;
		schema.validate(config).map_err(|e| {
			PricingError::InvalidData(format!("Configuration validation failed: {}", e))
		})?;

		// Extract configuration
		let api_key = config
			.get("api_key")
			.and_then(|v| v.as_str())
			.map(|s| s.to_string());

		let base_url = config
			.get("base_url")
			.and_then(|v| v.as_str())
			.unwrap_or(if api_key.is_some() {
				"https://pro-api.coingecko.com/api/v3"
			} else {
				"https://api.coingecko.com/api/v3"
			})
			.to_string();

		let cache_duration = config
			.get("cache_duration_seconds")
			.and_then(|v| v.as_integer())
			.unwrap_or(60) as u64; // Default 60 seconds cache

		let rate_limit_delay_ms = config
			.get("rate_limit_delay_ms")
			.and_then(|v| v.as_integer())
			.unwrap_or(if api_key.is_some() { 100 } else { 1200 }) as u64; // Pro: 100ms, Free: 1.2s

		// Build token ID map
		let mut token_id_map = HashMap::new();

		// Default mappings
		token_id_map.insert("ETH".to_string(), "ethereum".to_string());
		token_id_map.insert("ETHEREUM".to_string(), "ethereum".to_string());
		token_id_map.insert("SOL".to_string(), "solana".to_string());
		token_id_map.insert("SOLANA".to_string(), "solana".to_string());
		token_id_map.insert("BTC".to_string(), "bitcoin".to_string());
		token_id_map.insert("BITCOIN".to_string(), "bitcoin".to_string());
		token_id_map.insert("USDC".to_string(), "usd-coin".to_string());
		token_id_map.insert("USDT".to_string(), "tether".to_string());
		token_id_map.insert("DAI".to_string(), "dai".to_string());
		token_id_map.insert("WETH".to_string(), "ethereum".to_string());
		token_id_map.insert("WBTC".to_string(), "wrapped-bitcoin".to_string());
		token_id_map.insert("MATIC".to_string(), "matic-network".to_string());
		token_id_map.insert("ARB".to_string(), "arbitrum".to_string());
		token_id_map.insert("OP".to_string(), "optimism".to_string());

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
							"Invalid custom price for {}: {}",
							symbol, e
						))
					})?
				} else if let Some(price_num) = price.as_float() {
					Decimal::try_from(price_num).map_err(|e| {
						PricingError::InvalidData(format!(
							"Invalid custom price for {}: {}",
							symbol, e
						))
					})?
				} else if let Some(price_int) = price.as_integer() {
					Decimal::from(price_int)
				} else {
					return Err(PricingError::InvalidData(format!(
						"Custom price for {} must be a number or numeric string",
						symbol
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
		if let Some(ref key) = api_key {
			headers.insert(
				"x-cg-pro-api-key",
				HeaderValue::from_str(key).map_err(|e| {
					PricingError::InvalidData(format!("Invalid API key format: {}", e))
				})?,
			);
		}
		headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

		let client = Client::builder()
			.default_headers(headers)
			.user_agent("oif-solver/0.1.0 (https://github.com/openintentsframework/oif-solver)")
			.timeout(Duration::from_secs(30))
			.build()
			.map_err(|e| PricingError::Network(format!("Failed to create HTTP client: {}", e)))?;

		debug!(
			"CoinGecko pricing initialized - Base URL: {}, Cache: {}s, Rate limit: {}ms",
			base_url, cache_duration, rate_limit_delay_ms
		);
		debug!(
			"CoinGecko token mappings: {} tokens configured",
			token_id_map.len()
		);

		Ok(Self {
			client,
			api_key,
			base_url,
			price_cache: Arc::new(RwLock::new(HashMap::new())),
			cache_duration,
			token_id_map,
			custom_prices,
			rate_limit_delay_ms,
			last_api_call: Arc::new(RwLock::new(None)),
		})
	}

	/// Apply rate limiting
	async fn apply_rate_limit(&self) {
		let mut last_call = self.last_api_call.write().await;

		if let Some(last_timestamp) = *last_call {
			let now = SystemTime::now()
				.duration_since(UNIX_EPOCH)
				.unwrap()
				.as_millis() as u64;

			let elapsed = now - last_timestamp;
			if elapsed < self.rate_limit_delay_ms {
				let delay = self.rate_limit_delay_ms - elapsed;
				tokio::time::sleep(Duration::from_millis(delay)).await;
			}
		}

		*last_call = Some(
			SystemTime::now()
				.duration_since(UNIX_EPOCH)
				.unwrap()
				.as_millis() as u64,
		);
	}

	/// Get CoinGecko ID for a token symbol
	fn get_coingecko_id(&self, symbol: &str) -> Option<String> {
		self.token_id_map.get(&symbol.to_uppercase()).cloned()
	}

	/// Check if currency is USD (the only supported vs_currency)
	fn is_usd(&self, currency: &str) -> bool {
		currency.to_uppercase() == "USD"
	}

	/// Fetch prices from CoinGecko API
	async fn fetch_prices(
		&self,
		ids: Vec<String>,
		vs_currencies: Vec<String>,
	) -> Result<SimplePriceResponse, PricingError> {
		self.apply_rate_limit().await;

		let ids_param = ids.join(",");
		let vs_currencies_param = vs_currencies.join(",");

		let url = format!(
			"{}/simple/price?ids={}&vs_currencies={}",
			self.base_url, ids_param, vs_currencies_param
		);

		debug!("Fetching prices from CoinGecko API: {}", url);

		let response = self
			.client
			.get(&url)
			.send()
			.await
			.map_err(|e| PricingError::Network(format!("API request failed: {}", e)))?;

		if !response.status().is_success() {
			let status = response.status();
			let body = response.text().await.unwrap_or_default();
			return Err(PricingError::Network(format!(
				"API returned error status {}: {}",
				status, body
			)));
		}

		response
			.json::<SimplePriceResponse>()
			.await
			.map_err(|e| PricingError::InvalidData(format!("Failed to parse response: {}", e)))
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
				"Only USD is supported, got {}",
				vs_currency
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
		let coingecko_id = self
			.get_coingecko_id(token)
			.ok_or_else(|| PricingError::PriceNotAvailable(format!("Unknown token: {}", token)))?;

		let response = self
			.fetch_prices(vec![coingecko_id.clone()], vec!["usd".to_string()])
			.await?;

		let price = response
			.prices
			.get(&coingecko_id)
			.and_then(|prices| prices.get("usd"))
			.ok_or_else(|| PricingError::PriceNotAvailable(format!("{}/USD", token)))?;

		let price_str = price.to_string();

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
				.map_err(|e| PricingError::InvalidData(format!("Invalid price: {}", e)))?;

			if price.is_zero() {
				return Err(PricingError::InvalidData("Price is zero".to_string()));
			}

			let one = Decimal::ONE;
			return Ok((one / price).to_string());
		}

		// For non-USD pairs, we could support crypto-to-crypto through USD
		// but there's no current use case in the solver
		Err(PricingError::PriceNotAvailable(format!(
			"Only USD pairs are supported, got {}/{}",
			base, quote
		)))
	}
}

#[async_trait]
impl PricingInterface for CoinGeckoPricing {
	fn config_schema(&self) -> Box<dyn ConfigSchema> {
		Box::new(CoinGeckoConfigSchema)
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
			.map_err(|e| PricingError::InvalidData(format!("Invalid amount: {}", e)))?;

		let pair = TradingPair::new(&from_upper, &to_upper);
		let rate = self.get_pair_price(&pair).await?;
		let rate_decimal: Decimal = rate
			.parse()
			.map_err(|e| PricingError::InvalidData(format!("Invalid rate: {}", e)))?;

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
				"Only USD is supported, got {}",
				currency
			)));
		}

		// Convert wei to ETH using utility function
		let eth_amount_str =
			wei_string_to_eth_string(wei_amount).map_err(PricingError::InvalidData)?;

		let eth_amount: Decimal = eth_amount_str
			.parse()
			.map_err(|e| PricingError::InvalidData(format!("Invalid ETH amount: {}", e)))?;

		// Get ETH price in USD
		let eth_price = self.get_price("ETH", "USD").await?;
		let price_decimal: Decimal = eth_price
			.parse()
			.map_err(|e| PricingError::InvalidData(format!("Invalid price: {}", e)))?;

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
				"Only USD is supported, got {}",
				currency
			)));
		}

		let currency_amount_decimal: Decimal = currency_amount
			.parse()
			.map_err(|e| PricingError::InvalidData(format!("Invalid currency amount: {}", e)))?;

		// Get ETH price in USD
		let eth_price = self.get_price("ETH", "USD").await?;
		let eth_price_decimal: Decimal = eth_price
			.parse()
			.map_err(|e| PricingError::InvalidData(format!("Invalid ETH price: {}", e)))?;

		if eth_price_decimal.is_zero() {
			return Err(PricingError::InvalidData(
				"ETH price cannot be zero".to_string(),
			));
		}

		// Convert currency to ETH, then to wei
		let eth_amount = currency_amount_decimal / eth_price_decimal;
		let eth_amount_str = eth_amount.to_string();
		let wei_amount = parse_ether(&eth_amount_str).map_err(|e| {
			PricingError::InvalidData(format!("Failed to convert ETH to wei: {}", e))
		})?;

		Ok(wei_amount.to_string())
	}
}

/// Configuration schema for CoinGecko pricing implementation.
pub struct CoinGeckoConfigSchema;

impl ConfigSchema for CoinGeckoConfigSchema {
	fn validate(&self, config: &toml::Value) -> Result<(), ValidationError> {
		// Optional API key
		if let Some(api_key) = config.get("api_key") {
			if api_key.as_str().is_none() {
				return Err(ValidationError::TypeMismatch {
					field: "api_key".to_string(),
					expected: "string".to_string(),
					actual: format!("{:?}", api_key),
				});
			}
		}

		// Optional base URL
		if let Some(base_url) = config.get("base_url") {
			if base_url.as_str().is_none() {
				return Err(ValidationError::TypeMismatch {
					field: "base_url".to_string(),
					expected: "string".to_string(),
					actual: format!("{:?}", base_url),
				});
			}
		}

		// Optional cache duration
		if let Some(cache_duration) = config.get("cache_duration_seconds") {
			if cache_duration.as_integer().is_none() {
				return Err(ValidationError::TypeMismatch {
					field: "cache_duration_seconds".to_string(),
					expected: "integer".to_string(),
					actual: format!("{:?}", cache_duration),
				});
			}
		}

		// Optional rate limit delay
		if let Some(delay) = config.get("rate_limit_delay_ms") {
			if delay.as_integer().is_none() {
				return Err(ValidationError::TypeMismatch {
					field: "rate_limit_delay_ms".to_string(),
					expected: "integer".to_string(),
					actual: format!("{:?}", delay),
				});
			}
		}

		// Optional token_id_map
		if let Some(token_map) = config.get("token_id_map") {
			if let Some(table) = token_map.as_table() {
				for (symbol, id) in table {
					if id.as_str().is_none() {
						return Err(ValidationError::TypeMismatch {
							field: format!("token_id_map.{}", symbol),
							expected: "string".to_string(),
							actual: format!("{:?}", id),
						});
					}
				}
			} else {
				return Err(ValidationError::TypeMismatch {
					field: "token_id_map".to_string(),
					expected: "table".to_string(),
					actual: format!("{:?}", token_map),
				});
			}
		}

		// Optional custom_prices
		if let Some(custom_prices) = config.get("custom_prices") {
			if let Some(table) = custom_prices.as_table() {
				for (symbol, price) in table {
					// Price can be string (parseable as Decimal), float, or integer
					let is_valid = if let Some(price_str) = price.as_str() {
						price_str.parse::<Decimal>().is_ok()
					} else if let Some(price_num) = price.as_float() {
						Decimal::try_from(price_num).is_ok()
					} else {
						price.as_integer().is_some()
					};

					if !is_valid {
						return Err(ValidationError::TypeMismatch {
							field: format!("custom_prices.{}", symbol),
							expected: "valid decimal string, float, or integer".to_string(),
							actual: format!("{:?}", price),
						});
					}
				}
			} else {
				return Err(ValidationError::TypeMismatch {
					field: "custom_prices".to_string(),
					expected: "table".to_string(),
					actual: format!("{:?}", custom_prices),
				});
			}
		}

		Ok(())
	}
}

/// Registry for CoinGecko pricing implementation.
pub struct CoinGeckoPricingRegistry;

impl ImplementationRegistry for CoinGeckoPricingRegistry {
	const NAME: &'static str = "coingecko";
	type Factory = PricingFactory;

	fn factory() -> Self::Factory {
		create_coingecko_pricing
	}
}

impl PricingRegistry for CoinGeckoPricingRegistry {}

/// Factory function for creating CoinGeckoPricing instances.
pub fn create_coingecko_pricing(
	config: &toml::Value,
) -> Result<Box<dyn PricingInterface>, PricingError> {
	Ok(Box::new(CoinGeckoPricing::new(config)?))
}

#[cfg(test)]
mod tests {
	use super::*;
	use tokio;

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

	#[test]
	fn test_new_default_config() {
		let pricing = CoinGeckoPricing::new(&minimal_config()).unwrap();
		assert_eq!(pricing.base_url, "https://api.coingecko.com/api/v3");
		assert_eq!(pricing.cache_duration, 60);
		assert_eq!(pricing.rate_limit_delay_ms, 1200);
	}

	#[test]
	fn test_new_with_api_key() {
		let config = toml::from_str(r#"api_key = "pro_key_123""#).unwrap();
		let pricing = CoinGeckoPricing::new(&config).unwrap();
		assert_eq!(pricing.base_url, "https://pro-api.coingecko.com/api/v3");
		assert_eq!(pricing.rate_limit_delay_ms, 100);
	}

	#[test]
	fn test_get_coingecko_id() {
		let pricing = CoinGeckoPricing::new(&minimal_config()).unwrap();
		assert_eq!(
			pricing.get_coingecko_id("ETH"),
			Some("ethereum".to_string())
		);
		assert_eq!(pricing.get_coingecko_id("btc"), Some("bitcoin".to_string()));
		assert_eq!(
			pricing.get_coingecko_id("WETH"),
			Some("ethereum".to_string())
		);
		assert_eq!(pricing.get_coingecko_id("UNKNOWN"), None);
	}

	#[test]
	fn test_is_usd() {
		let pricing = CoinGeckoPricing::new(&minimal_config()).unwrap();
		assert!(pricing.is_usd("USD"));
		assert!(pricing.is_usd("usd"));
		assert!(pricing.is_usd("Usd"));
		assert!(!pricing.is_usd("EUR"));
		assert!(!pricing.is_usd("ETH"));
	}

	#[tokio::test]
	async fn test_get_pair_price_same_asset() {
		let pricing = CoinGeckoPricing::new(&minimal_config()).unwrap();
		let pair = TradingPair::new("ETH", "ETH");
		let result = pricing.get_pair_price(&pair).await.unwrap();
		assert_eq!(result, "1.0");
	}

	#[tokio::test]
	async fn test_get_pair_price_unsupported() {
		let pricing = CoinGeckoPricing::new(&minimal_config()).unwrap();
		let pair = TradingPair::new("ETH", "BTC");
		let result = pricing.get_pair_price(&pair).await;
		assert!(result.is_err());
	}

	#[tokio::test]
	async fn test_custom_price_retrieval() {
		let pricing = CoinGeckoPricing::new(&config_with_custom_prices()).unwrap();
		let result = pricing.get_price("ETH", "USD").await.unwrap();
		assert_eq!(result, "3000.50");
	}

	#[tokio::test]
	async fn test_get_price_non_usd_fails() {
		let pricing = CoinGeckoPricing::new(&minimal_config()).unwrap();
		let result = pricing.get_price("ETH", "EUR").await;
		assert!(matches!(result, Err(PricingError::PriceNotAvailable(_))));
	}

	#[tokio::test]
	async fn test_get_price_unknown_token() {
		let pricing = CoinGeckoPricing::new(&minimal_config()).unwrap();
		let result = pricing.get_price("FAKECOIN", "USD").await;
		assert!(matches!(result, Err(PricingError::PriceNotAvailable(_))));
	}

	#[tokio::test]
	async fn test_convert_asset_same() {
		let pricing = CoinGeckoPricing::new(&minimal_config()).unwrap();
		let result = pricing.convert_asset("ETH", "eth", "5.5").await.unwrap();
		assert_eq!(result, "5.5");
	}

	#[tokio::test]
	async fn test_convert_asset_invalid_amount() {
		let pricing = CoinGeckoPricing::new(&minimal_config()).unwrap();
		let result = pricing.convert_asset("ETH", "USD", "not_a_number").await;
		assert!(matches!(result, Err(PricingError::InvalidData(_))));
	}

	#[tokio::test]
	async fn test_wei_to_currency_non_usd() {
		let pricing = CoinGeckoPricing::new(&minimal_config()).unwrap();
		let result = pricing.wei_to_currency("1000000000000000000", "EUR").await;
		assert!(matches!(result, Err(PricingError::PriceNotAvailable(_))));
	}

	#[tokio::test]
	async fn test_currency_to_wei_invalid() {
		let pricing = CoinGeckoPricing::new(&minimal_config()).unwrap();
		let result = pricing.currency_to_wei("invalid", "USD").await;
		assert!(matches!(result, Err(PricingError::InvalidData(_))));
	}

	#[tokio::test]
	async fn test_get_supported_pairs() {
		let pricing = CoinGeckoPricing::new(&minimal_config()).unwrap();
		let pairs = pricing.get_supported_pairs().await;
		assert!(!pairs.is_empty());
		// All should be against USD
		assert!(pairs.iter().all(|p| p.quote == "USD"));
	}

	#[test]
	fn test_config_schema_valid() {
		let schema = CoinGeckoConfigSchema;
		assert!(schema.validate(&minimal_config()).is_ok());
		assert!(schema.validate(&config_with_custom_prices()).is_ok());
	}

	#[test]
	fn test_config_schema_invalid_api_key() {
		let schema = CoinGeckoConfigSchema;
		let bad_config = toml::from_str(r#"api_key = 123"#).unwrap();
		assert!(schema.validate(&bad_config).is_err());
	}

	#[test]
	fn test_config_schema_invalid_custom_price() {
		let schema = CoinGeckoConfigSchema;
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
	fn test_price_cache_entry() {
		let entry = PriceCacheEntry {
			price: "2500.0".to_string(),
			timestamp: 1234567890,
		};
		let cloned = entry.clone();
		assert_eq!(entry.price, cloned.price);
		assert_eq!(entry.timestamp, cloned.timestamp);
	}
}
