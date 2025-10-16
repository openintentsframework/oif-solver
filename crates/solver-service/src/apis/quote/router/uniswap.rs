//! Uniswap Routing API integration.
//!
//! This module provides integration with Uniswap's Routing API to fetch
//! optimal swap routes and generate calldata for the Universal Router.

use alloy_primitives::U256;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Uniswap Routing API client for fetching swap routes.
#[derive(Clone, Debug)]
pub struct UniswapRouter {
	/// HTTP client for API requests
	client: Client,
	/// Optional API key for authenticated requests
	api_key: Option<String>,
	/// Base URL for Uniswap Routing API
	base_url: String,
}

/// Configuration for Uniswap routing
#[derive(Clone, Debug)]
pub struct UniswapConfig {
	/// Optional API key (X-API-KEY header)
	pub api_key: Option<String>,
	/// Slippage tolerance in basis points (e.g., 50 = 0.5%)
	pub slippage_bps: u16,
	/// Whether routing is enabled
	#[allow(dead_code)]
	pub enabled: bool,
	/// Universal Router addresses per chain ID
	pub router_addresses: HashMap<u64, String>,
}

impl Default for UniswapConfig {
	fn default() -> Self {
		Self {
			api_key: None,
			slippage_bps: 50, // 0.5% default
			enabled: false,
			router_addresses: Self::default_router_addresses(),
		}
	}
}

impl UniswapConfig {
	/// Returns default Universal Router addresses for supported chains
	pub fn default_router_addresses() -> HashMap<u64, String> {
		let mut addresses = HashMap::new();
		// Universal Router v1.2 canonical addresses
		addresses.insert(1, "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD".to_string()); // Mainnet
		addresses.insert(10, "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD".to_string()); // Optimism
		addresses.insert(137, "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD".to_string()); // Polygon
		addresses.insert(8453, "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD".to_string()); // Base
		addresses.insert(42161, "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD".to_string()); // Arbitrum
		addresses
	}

	/// Get Universal Router address for a specific chain
	pub fn get_router_address(&self, chain_id: u64) -> Option<&String> {
		self.router_addresses.get(&chain_id)
	}
}

/// Result from Uniswap Routing API quote request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniswapRoute {
	/// Universal Router contract address
	pub to: String,
	/// Encoded calldata for Universal Router
	pub calldata: String,
	/// Expected output amount (in token's smallest unit)
	pub amount_out: String,
	/// Gas estimate for the transaction
	#[serde(skip_serializing_if = "Option::is_none")]
	pub gas_estimate: Option<String>,
}

/// Response from Uniswap Routing API
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UniswapApiResponse {
	/// Routing information
	quote: String,
	/// Quote for the output amount after fees
	quote_gas_adjusted: Option<String>,
	/// Gas estimate
	gas_use_estimate: Option<String>,
	/// Method parameters for execution
	method_parameters: MethodParameters,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MethodParameters {
	/// Calldata for the Universal Router
	calldata: String,
	/// Value to send (ETH) - should be 0 for ERC20-to-ERC20
	value: String,
	/// Universal Router address
	to: String,
}

/// Error type for Uniswap routing operations
#[derive(Debug, thiserror::Error)]
pub enum UniswapError {
	#[error("HTTP request failed: {0}")]
	HttpError(#[from] reqwest::Error),
	#[error("Invalid response: {0}")]
	InvalidResponse(String),
	#[error("No route found: {0}")]
	NoRoute(String),
}

impl UniswapRouter {
	/// Create a new Uniswap router client
	pub fn new(api_key: Option<String>) -> Self {
		Self {
			client: Client::new(),
			api_key,
			base_url: "https://api.uniswap.org/v2/quote".to_string(),
		}
	}

	/// Fetch a swap route from Uniswap Routing API
	///
	/// # Arguments
	/// * `chain_id` - Chain ID (e.g., 1 for Ethereum mainnet)
	/// * `token_in` - Input token address (0x-prefixed)
	/// * `token_out` - Output token address (0x-prefixed)
	/// * `amount_in` - Input amount in token's smallest unit
	/// * `recipient` - Address to receive output tokens
	/// * `slippage_bps` - Slippage tolerance in basis points
	pub async fn get_route(
		&self,
		chain_id: u64,
		token_in: &str,
		token_out: &str,
		amount_in: &U256,
		recipient: &str,
		slippage_bps: u16,
	) -> Result<UniswapRoute, UniswapError> {
		// Build query parameters
		let params = vec![
			("tokenInAddress", token_in.to_string()),
			("tokenInChainId", chain_id.to_string()),
			("tokenOutAddress", token_out.to_string()),
			("tokenOutChainId", chain_id.to_string()),
			("amount", amount_in.to_string()),
			("type", "EXACT_INPUT".to_string()),
			("recipient", recipient.to_string()),
			("slippageTolerance", format!("{}", slippage_bps as f64 / 10000.0)),
			("enableUniversalRouter", "true".to_string()),
		];

		// Build request
		let mut request = self.client.get(&self.base_url).query(&params);

		// Add API key if provided
		if let Some(ref key) = self.api_key {
			request = request.header("X-API-KEY", key);
		}

		// Execute request
		tracing::debug!(
			"Fetching Uniswap route: chain={}, token_in={}, token_out={}, amount={}",
			chain_id,
			token_in,
			token_out,
			amount_in
		);

		let response = request.send().await?;

		if !response.status().is_success() {
			let status = response.status();
			let body = response.text().await.unwrap_or_default();
			return Err(UniswapError::NoRoute(format!(
				"API returned status {}: {}",
				status, body
			)));
		}

		let api_response: UniswapApiResponse = response.json().await.map_err(|e| {
			UniswapError::InvalidResponse(format!("Failed to parse response: {}", e))
		})?;

		// Validate that value is 0 (ERC20 only for now)
		if api_response.method_parameters.value != "0" {
			return Err(UniswapError::InvalidResponse(
				"ETH value transfers not supported".to_string(),
			));
		}

		Ok(UniswapRoute {
			to: api_response.method_parameters.to,
			calldata: api_response.method_parameters.calldata,
			amount_out: api_response
				.quote_gas_adjusted
				.unwrap_or(api_response.quote),
			gas_estimate: api_response.gas_use_estimate,
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_uniswap_config_default() {
		let config = UniswapConfig::default();
		assert_eq!(config.slippage_bps, 50);
		assert!(!config.enabled);
		assert!(config.api_key.is_none());

		// Check default router addresses
		assert_eq!(
			config.get_router_address(1),
			Some(&"0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD".to_string())
		);
		assert_eq!(
			config.get_router_address(137),
			Some(&"0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD".to_string())
		);
	}

	#[test]
	fn test_uniswap_router_new() {
		let router = UniswapRouter::new(Some("test-key".to_string()));
		assert_eq!(router.api_key, Some("test-key".to_string()));
		assert_eq!(router.base_url, "https://api.uniswap.org/v2/quote");
	}

	#[test]
	fn test_get_router_address_unsupported_chain() {
		let config = UniswapConfig::default();
		assert!(config.get_router_address(999999).is_none());
	}
}

