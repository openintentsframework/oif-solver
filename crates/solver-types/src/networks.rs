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
	/// Optional Compact/Resource Lock input settler address
	#[serde(default)]
	pub input_settler_compact_address: Option<Address>,
	/// Optional TheCompact contract address (for demos/tools)
	#[serde(default)]
	pub the_compact_address: Option<Address>,
	/// Optional allocator address for TheCompact resource locks
	#[serde(default)]
	pub allocator_address: Option<Address>,
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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::utils::tests::builders::{NetworkConfigBuilder, TokenConfigBuilder};
	use crate::Address;
	use serde_json;

	// Helper function to create Address from hex string
	fn addr(hex: &str) -> Address {
		let hex_str = hex::decode(hex.trim_start_matches("0x")).unwrap();
		Address(hex_str)
	}

	#[test]
	fn test_rpc_endpoint_creation() {
		// Test HTTP only using static method
		let http_endpoint = RpcEndpoint::http_only("https://eth.llamarpc.com".to_string());
		assert_eq!(
			http_endpoint.http,
			Some("https://eth.llamarpc.com".to_string())
		);
		assert_eq!(http_endpoint.ws, None);

		// Test WebSocket only using static method
		let ws_endpoint = RpcEndpoint::ws_only("wss://eth.llamarpc.com".to_string());
		assert_eq!(ws_endpoint.http, None);
		assert_eq!(ws_endpoint.ws, Some("wss://eth.llamarpc.com".to_string()));

		// Test both HTTP and WebSocket using static method
		let both_endpoint = RpcEndpoint::both(
			"https://eth.llamarpc.com".to_string(),
			"wss://eth.llamarpc.com".to_string(),
		);
		assert_eq!(
			both_endpoint.http,
			Some("https://eth.llamarpc.com".to_string())
		);
		assert_eq!(both_endpoint.ws, Some("wss://eth.llamarpc.com".to_string()));
	}

	#[test]
	fn test_rpc_endpoint_serialization() {
		let endpoint = RpcEndpoint::both(
			"https://eth.llamarpc.com".to_string(),
			"wss://eth.llamarpc.com".to_string(),
		);

		let json = serde_json::to_string(&endpoint).unwrap();
		assert!(json.contains("\"http\":\"https://eth.llamarpc.com\""));
		assert!(json.contains("\"ws\":\"wss://eth.llamarpc.com\""));

		let deserialized: RpcEndpoint = serde_json::from_str(&json).unwrap();
		assert_eq!(deserialized.http, endpoint.http);
		assert_eq!(deserialized.ws, endpoint.ws);
	}

	#[test]
	fn test_rpc_endpoint_optional_fields() {
		// Test with only HTTP
		let http_only = RpcEndpoint::http_only("https://eth.llamarpc.com".to_string());

		let json = serde_json::to_string(&http_only).unwrap();
		assert!(json.contains("\"http\""));
		assert!(!json.contains("\"ws\""));

		// Test with only WebSocket
		let ws_only = RpcEndpoint::ws_only("wss://eth.llamarpc.com".to_string());

		let json = serde_json::to_string(&ws_only).unwrap();
		assert!(!json.contains("\"http\""));
		assert!(json.contains("\"ws\""));
	}

	#[test]
	fn test_token_config_creation() {
		let token = TokenConfigBuilder::new().build();

		assert_eq!(
			token.address,
			addr("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48") // Real USDC address
		);
		assert_eq!(token.symbol, "USDC");
		assert_eq!(token.decimals, 6);
	}

	#[test]
	fn test_token_config_serialization() {
		let token = TokenConfigBuilder::new()
			.address_hex("6B175474E89094C44Da98b954EedeAC495271d0F")
			.unwrap()
			.symbol("DAI")
			.decimals(18)
			.build();

		let json = serde_json::to_string(&token).unwrap();
		assert!(json.contains("\"symbol\":\"DAI\""));
		assert!(json.contains("\"decimals\":18"));

		let deserialized: TokenConfig = serde_json::from_str(&json).unwrap();
		assert_eq!(deserialized.address, token.address);
		assert_eq!(deserialized.symbol, token.symbol);
		assert_eq!(deserialized.decimals, token.decimals);
	}

	#[test]
	fn test_token_config_equality() {
		let token1 = TokenConfigBuilder::new().build();

		let token2 = TokenConfigBuilder::new().build();

		let token3 = TokenConfigBuilder::new()
			.address_hex("6B175474E89094C44Da98b954EedeAC495271d0F")
			.unwrap()
			.symbol("DAI")
			.decimals(18)
			.build();

		assert_eq!(token1, token2);
		assert_ne!(token1, token3);
	}

	#[test]
	fn test_network_config_url_methods() {
		let network = NetworkConfigBuilder::new()
			.add_rpc_endpoint(RpcEndpoint::both(
				"https://mainnet.infura.io".to_string(),
				"wss://mainnet.infura.io".to_string(),
			))
			.build();

		// Test get_http_url (should return first available)
		assert_eq!(network.get_http_url(), Some("https://eth.llamarpc.com"));

		// Test get_ws_url (should return first available)
		assert_eq!(network.get_ws_url(), Some("wss://eth.llamarpc.com"));

		// Test get_all_http_urls
		let all_http = network.get_all_http_urls();
		assert_eq!(all_http.len(), 2);
		assert!(all_http.contains(&"https://mainnet.infura.io"));
		assert!(all_http.contains(&"https://eth.llamarpc.com"));

		// Test get_all_ws_urls
		let all_ws = network.get_all_ws_urls();
		assert_eq!(all_ws.len(), 2);
		assert!(all_ws.contains(&"wss://mainnet.infura.io"));
		assert!(all_ws.contains(&"wss://eth.llamarpc.com"));
	}

	#[test]
	fn test_deserialize_networks_success() {
		use serde_json::json;

		let networks_json = json!({
			"1": {
				"rpc_urls": [
					{"http": "https://mainnet.infura.io"}
				],
				"input_settler_address": "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9",
				"output_settler_address": "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
				"tokens": []
			},
			"137": {
				"rpc_urls": [
					{"http": "https://polygon-rpc.com"}
				],
				"input_settler_address": "0xA0b86a33E6776Fb78B3e1E6B2D0d2E8F0C1D2A3B",
				"output_settler_address": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
				"tokens": []
			}
		});

		let result: Result<NetworksConfig, _> = serde_json::from_value(networks_json);

		assert!(result.is_ok());
		let networks = result.unwrap();
		assert_eq!(networks.len(), 2);
		assert!(networks.contains_key(&1));
		assert!(networks.contains_key(&137));

		let eth_network = &networks[&1];
		assert_eq!(
			eth_network.get_http_url(),
			Some("https://mainnet.infura.io")
		);
	}

	#[test]
	fn test_deserialize_networks_invalid_chain_id() {
		use serde_json::json;

		let networks_json = json!({
			"invalid_chain_id": {
				"rpc_urls": [
					{"http": "https://mainnet.infura.io"}
				],
				"input_settler_address": "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9",
				"output_settler_address": "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
				"tokens": []
			}
		});

		let result: Result<NetworksConfig, _> = serde_json::from_value(networks_json);

		assert!(result.is_err());
		let error_msg = result.unwrap_err().to_string();

		assert!(error_msg.contains("invalid value"));
		assert!(error_msg.contains("expected key to be a number in quotes"));
	}

	#[test]
	fn test_network_config_serialization() {
		let network = NetworkConfigBuilder::new().build();

		let json = serde_json::to_string(&network).unwrap();
		let deserialized: NetworkConfig = serde_json::from_str(&json).unwrap();

		assert_eq!(deserialized.rpc_urls.len(), 1);
		assert_eq!(deserialized.tokens.len(), 1);
		assert_eq!(deserialized.tokens[0].symbol, "USDC");
		assert_eq!(
			deserialized.input_settler_address,
			network.input_settler_address
		);
		assert_eq!(
			deserialized.output_settler_address,
			network.output_settler_address
		);
	}

	#[test]
	fn test_debug_implementations() {
		let endpoint = RpcEndpoint::both(
			"https://eth.llamarpc.com".to_string(),
			"wss://eth.llamarpc.com".to_string(),
		);
		let debug_str = format!("{:?}", endpoint);
		assert!(debug_str.contains("RpcEndpoint"));
		assert!(debug_str.contains("https://eth.llamarpc.com"));

		let token = TokenConfigBuilder::new()
			.address_hex("A0b86a33E6776Fb78B3e1E6B2D0d2E8F0C1D2A3B")
			.unwrap()
			.symbol("TEST")
			.decimals(18)
			.build();
		let debug_str = format!("{:?}", token);
		assert!(debug_str.contains("TokenConfig"));
		assert!(debug_str.contains("TEST"));
		assert!(debug_str.contains("18"));

		let network = NetworkConfigBuilder::new().build();
		let debug_str = format!("{:?}", network);
		assert!(debug_str.contains("NetworkConfig"));
	}

	#[test]
	fn test_clone_implementations() {
		let endpoint = RpcEndpoint::both(
			"https://eth.llamarpc.com".to_string(),
			"wss://eth.llamarpc.com".to_string(),
		);
		let cloned = endpoint.clone();
		assert_eq!(cloned.http, endpoint.http);
		assert_eq!(cloned.ws, endpoint.ws);

		let token = TokenConfigBuilder::new()
			.address_hex("A0b86a33E6776Fb78B3e1E6B2D0d2E8F0C1D2A3B")
			.unwrap()
			.symbol("TEST")
			.decimals(18)
			.build();
		let cloned = token.clone();
		assert_eq!(cloned, token);

		let network = NetworkConfigBuilder::new().build();
		let cloned = network.clone();
		assert_eq!(cloned.rpc_urls.len(), network.rpc_urls.len());
		assert_eq!(cloned.tokens.len(), network.tokens.len());
	}
}
