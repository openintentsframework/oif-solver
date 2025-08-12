use crate::Address;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct TokenConfig {
	pub address: Address,
	pub symbol: String,
	pub decimals: u8,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkConfig {
	pub input_settler_address: Address,
	pub output_settler_address: Address,
	pub tokens: Vec<TokenConfig>,
}

/// Networks configuration with custom deserialization to handle string keys
pub type NetworksConfig = HashMap<u64, NetworkConfig>;

/// Helper function to deserialize a HashMap with string keys as u64 keys
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
