//! Network configuration types for multi-chain solver operations.
//!
//! This module defines the configuration structures for managing network-specific
//! settings, including RPC URLs, settler addresses, and supported tokens across
//! different blockchain networks.

use crate::Address;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;

/// Configuration for RPC endpoints supporting both HTTP and WebSocket protocols.
///
/// Each RPC endpoint can provide HTTP and/or WebSocket URLs for different
/// types of operations. HTTP is typically used for request/response operations
/// while WebSocket enables push-based subscriptions.
///
/// # Fields
///
/// * `http` - Optional HTTP(S) RPC endpoint URL
/// * `ws` - Optional WebSocket (ws:// or wss://) RPC endpoint URL
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RpcEndpoint {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub http: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub ws: Option<String>,
}

impl RpcEndpoint {
	/// Creates a new RPC endpoint with HTTP URL only.
	pub fn http_only(url: String) -> Self {
		Self {
			http: Some(url),
			ws: None,
		}
	}

	/// Creates a new RPC endpoint with WebSocket URL only.
	pub fn ws_only(url: String) -> Self {
		Self {
			http: None,
			ws: Some(url),
		}
	}

	/// Creates a new RPC endpoint with both HTTP and WebSocket URLs.
	pub fn both(http: String, ws: String) -> Self {
		Self {
			http: Some(http),
			ws: Some(ws),
		}
	}
}

/// Configuration for a token on a specific network.
///
/// Defines the essential properties of a token that the solver needs
/// to interact with on a blockchain.
///
/// # Fields
///
/// * `address` - The on-chain address of the token contract
/// * `symbol` - The token symbol (e.g., "USDC", "ETH")
/// * `decimals` - The number of decimal places for the token
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct TokenConfig {
	pub address: Address,
	pub symbol: String,
	pub decimals: u8,
}

/// Configuration for a single blockchain network.
///
/// Contains all the network-specific settings required for the solver
/// to interact with a particular blockchain.
///
/// # Fields
///
/// * `rpc_urls` - Array of RPC endpoints with HTTP and/or WebSocket URLs for fallback
/// * `input_settler_address` - Address of the input settler contract (for origin chains)
/// * `output_settler_address` - Address of the output settler contract (for destination chains)
/// * `tokens` - List of supported tokens on this network
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkConfig {
	pub rpc_urls: Vec<RpcEndpoint>,
	pub input_settler_address: Address,
	pub output_settler_address: Address,
	pub tokens: Vec<TokenConfig>,
}

impl NetworkConfig {
	/// Get the first available HTTP URL from the RPC endpoints.
	pub fn get_http_url(&self) -> Option<&str> {
		self.rpc_urls
			.iter()
			.find_map(|endpoint| endpoint.http.as_deref())
	}

	/// Get the first available WebSocket URL from the RPC endpoints.
	pub fn get_ws_url(&self) -> Option<&str> {
		self.rpc_urls
			.iter()
			.find_map(|endpoint| endpoint.ws.as_deref())
	}

	/// Get all HTTP URLs for fallback purposes.
	pub fn get_all_http_urls(&self) -> Vec<&str> {
		self.rpc_urls
			.iter()
			.filter_map(|endpoint| endpoint.http.as_deref())
			.collect()
	}

	/// Get all WebSocket URLs for fallback purposes.
	pub fn get_all_ws_urls(&self) -> Vec<&str> {
		self.rpc_urls
			.iter()
			.filter_map(|endpoint| endpoint.ws.as_deref())
			.collect()
	}
}

/// Networks configuration mapping chain IDs to their configurations.
///
/// This is a type alias for a HashMap that maps chain IDs (as u64) to
/// their corresponding network configurations. The configuration supports
/// custom deserialization from TOML where chain IDs can be provided as
/// string keys.
pub type NetworksConfig = HashMap<u64, NetworkConfig>;

/// Helper function to deserialize network configurations from TOML.
///
/// This function handles the deserialization of network configurations where
/// chain IDs are provided as string keys in TOML (since TOML doesn't support
/// numeric keys in tables) and converts them to u64 keys for internal use.
///
/// # Errors
///
/// Returns a deserialization error if:
/// - A chain ID key cannot be parsed as a u64
/// - The underlying network configuration is invalid
pub fn deserialize_networks<'de, D>(deserializer: D) -> Result<NetworksConfig, D::Error>
where
	D: Deserializer<'de>,
{
	let string_map: HashMap<String, NetworkConfig> = HashMap::deserialize(deserializer)?;
	let mut result = HashMap::new();

	for (key, value) in string_map {
		let chain_id = key
			.parse::<u64>()
			.map_err(|e| serde::de::Error::custom(format!("Invalid chain_id '{}': {}", key, e)))?;
		result.insert(chain_id, value);
	}

	Ok(result)
}
