//! Network configuration types for multi-chain solver operations.
//!
//! This module defines the configuration structures for managing network-specific
//! settings, including RPC URLs, settler addresses, and supported tokens across
//! different blockchain networks.

use crate::Address;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;

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
/// * `rpc_url` - The HTTP(S) RPC endpoint for blockchain interaction
/// * `input_settler_address` - Address of the input settler contract (for origin chains)
/// * `output_settler_address` - Address of the output settler contract (for destination chains)
/// * `tokens` - List of supported tokens on this network
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkConfig {
	pub rpc_url: String,
	pub input_settler_address: Address,
	pub output_settler_address: Address,
	pub tokens: Vec<TokenConfig>,
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
