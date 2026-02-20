//! Common utilities for settlement implementations.
//!
//! This module provides shared utilities for parsing oracle configurations
//! from TOML config files, used by all settlement implementations.

use crate::{OracleConfig, OracleSelectionStrategy, SettlementError};
use alloy_primitives::{FixedBytes, B256, U256};
use alloy_provider::{DynProvider, Provider};
use alloy_sol_types::{sol, SolCall};
use serde::{de::DeserializeOwned, Serialize};
use solver_storage::StorageService;
use solver_types::{
	create_http_provider, utils::parse_address, Address, NetworksConfig, ProviderError, StorageKey,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

sol! {
	interface IBaseInputOracle {
		function isProven(
			uint256 remoteChainId,
			bytes32 remoteOracle,
			bytes32 application,
			bytes32 dataHash
		) external view returns (bool);
	}
}

/// Parse an oracle table from TOML configuration.
///
/// Parses a table mapping chain IDs to arrays of oracle addresses.
/// Expected format:
/// ```toml
/// 31337 = ["0x1111...", "0x2222..."]
/// 31338 = ["0x3333..."]
/// ```
pub fn parse_oracle_table(
	table: &toml::Value,
) -> Result<HashMap<u64, Vec<Address>>, SettlementError> {
	let mut result = HashMap::new();

	if let Some(table) = table.as_table() {
		for (chain_id_str, oracles_value) in table {
			let chain_id = chain_id_str.parse::<u64>().map_err(|e| {
				SettlementError::ValidationFailed(format!("Invalid chain ID '{chain_id_str}': {e}"))
			})?;

			let oracles = if let Some(array) = oracles_value.as_array() {
				array
					.iter()
					.map(|v| {
						v.as_str()
							.ok_or_else(|| {
								SettlementError::ValidationFailed(format!(
									"Oracle address must be string for chain {chain_id}"
								))
							})
							.and_then(|s| {
								parse_address(s).map_err(|e| {
									SettlementError::ValidationFailed(format!(
										"Invalid oracle address for chain {chain_id}: {e}"
									))
								})
							})
					})
					.collect::<Result<Vec<_>, _>>()?
			} else {
				return Err(SettlementError::ValidationFailed(format!(
					"Oracles for chain {chain_id} must be an array"
				)));
			};

			if oracles.is_empty() {
				return Err(SettlementError::ValidationFailed(format!(
					"At least one oracle address required for chain {chain_id}"
				)));
			}

			result.insert(chain_id, oracles);
		}
	}

	Ok(result)
}

/// Parse a routes table from TOML configuration.
///
/// Parses a table mapping source chain IDs to arrays of destination chain IDs.
/// Expected format:
/// ```toml
/// 31337 = [31338, 31339]
/// 31338 = [31337]
/// ```
pub fn parse_routes_table(table: &toml::Value) -> Result<HashMap<u64, Vec<u64>>, SettlementError> {
	let mut result = HashMap::new();

	if let Some(table) = table.as_table() {
		for (chain_id_str, destinations_value) in table {
			let chain_id = chain_id_str.parse::<u64>().map_err(|e| {
				SettlementError::ValidationFailed(format!("Invalid chain ID '{chain_id_str}': {e}"))
			})?;

			let destinations = if let Some(array) = destinations_value.as_array() {
				array
					.iter()
					.map(|v| {
						v.as_integer().map(|i| i as u64).ok_or_else(|| {
							SettlementError::ValidationFailed(format!(
								"Destination chain ID must be integer for route from chain {chain_id}"
							))
						})
					})
					.collect::<Result<Vec<_>, _>>()?
			} else {
				return Err(SettlementError::ValidationFailed(format!(
					"Destinations for chain {chain_id} must be an array"
				)));
			};

			if destinations.is_empty() {
				return Err(SettlementError::ValidationFailed(format!(
					"At least one destination required for route from chain {chain_id}"
				)));
			}

			result.insert(chain_id, destinations);
		}
	}

	Ok(result)
}

/// Parse an oracle selection strategy from configuration.
///
/// Converts a string value to an OracleSelectionStrategy enum.
/// Defaults to "First" if not specified or invalid.
pub fn parse_selection_strategy(value: Option<&str>) -> OracleSelectionStrategy {
	match value {
		Some("First") => OracleSelectionStrategy::First,
		Some("RoundRobin") => OracleSelectionStrategy::RoundRobin,
		Some("Random") => OracleSelectionStrategy::Random,
		_ => OracleSelectionStrategy::default(),
	}
}

/// Parse a complete oracle configuration from TOML.
///
/// Expects a config structure like:
/// ```toml
/// [oracles]
/// input = { 31337 = ["0x..."], 31338 = ["0x..."] }
/// output = { 31337 = ["0x..."], 31338 = ["0x..."] }
///
/// [routes]
/// 31337 = [31338]
/// 31338 = [31337]
///
/// oracle_selection_strategy = "RoundRobin"  # Optional
/// ```
pub fn parse_oracle_config(config: &toml::Value) -> Result<OracleConfig, SettlementError> {
	// Parse oracles section
	let oracles_table = config.get("oracles").ok_or_else(|| {
		SettlementError::ValidationFailed("Missing 'oracles' section".to_string())
	})?;

	let input_oracles = parse_oracle_table(oracles_table.get("input").ok_or_else(|| {
		SettlementError::ValidationFailed("Missing 'oracles.input'".to_string())
	})?)?;

	let output_oracles = parse_oracle_table(oracles_table.get("output").ok_or_else(|| {
		SettlementError::ValidationFailed("Missing 'oracles.output'".to_string())
	})?)?;

	// Parse routes section
	let routes = parse_routes_table(config.get("routes").ok_or_else(|| {
		SettlementError::ValidationFailed("Missing 'routes' section".to_string())
	})?)?;

	// Validate that routes reference valid chains
	validate_routes(&input_oracles, &output_oracles, &routes)?;

	// Parse optional selection strategy
	let selection_strategy = parse_selection_strategy(
		config
			.get("oracle_selection_strategy")
			.and_then(|v| v.as_str()),
	);

	Ok(OracleConfig {
		input_oracles,
		output_oracles,
		routes,
		selection_strategy,
	})
}

/// Parse a table mapping chain IDs to single addresses.
pub fn parse_address_table(table: &toml::Value) -> Result<HashMap<u64, Address>, SettlementError> {
	let mut result = HashMap::new();

	if let Some(table) = table.as_table() {
		for (chain_id_str, address_value) in table {
			let chain_id = chain_id_str.parse::<u64>().map_err(|e| {
				SettlementError::ValidationFailed(format!("Invalid chain ID '{chain_id_str}': {e}"))
			})?;

			let address_str = address_value.as_str().ok_or_else(|| {
				SettlementError::ValidationFailed(format!(
					"Address must be string for chain {chain_id}"
				))
			})?;

			let address = parse_address(address_str).map_err(|e| {
				SettlementError::ValidationFailed(format!(
					"Invalid address for chain {chain_id}: {e}"
				))
			})?;

			result.insert(chain_id, address);
		}
	}

	Ok(result)
}

/// Parse a table mapping chain IDs to bytes32 values.
pub fn parse_b256_table(table: &toml::Value) -> Result<HashMap<u64, B256>, SettlementError> {
	let mut result = HashMap::new();

	if let Some(table) = table.as_table() {
		for (chain_id_str, value) in table {
			let chain_id = chain_id_str.parse::<u64>().map_err(|e| {
				SettlementError::ValidationFailed(format!("Invalid chain ID '{chain_id_str}': {e}"))
			})?;

			let value_str = value.as_str().ok_or_else(|| {
				SettlementError::ValidationFailed(format!(
					"Value must be string for chain {chain_id}"
				))
			})?;

			let parsed = value_str.parse::<B256>().map_err(|e| {
				SettlementError::ValidationFailed(format!(
					"Invalid bytes32 value for chain {chain_id}: {e}"
				))
			})?;

			result.insert(chain_id, parsed);
		}
	}

	Ok(result)
}

/// Create strict HTTP providers for all given chains.
pub fn create_providers_for_chains(
	chain_ids: &[u64],
	networks: &NetworksConfig,
) -> Result<HashMap<u64, DynProvider>, SettlementError> {
	let mut unique_chain_ids = chain_ids.to_vec();
	unique_chain_ids.sort_unstable();
	unique_chain_ids.dedup();

	let mut providers = HashMap::new();
	for chain_id in unique_chain_ids {
		let provider = create_http_provider(chain_id, networks).map_err(|e| match e {
			ProviderError::NetworkConfig(msg) => SettlementError::ValidationFailed(msg),
			ProviderError::Connection(msg) => SettlementError::ValidationFailed(msg),
			ProviderError::InvalidUrl(msg) => SettlementError::ValidationFailed(msg),
		})?;
		providers.insert(chain_id, provider);
	}

	Ok(providers)
}

/// Convert a 20-byte solver address to a right-aligned bytes32 value.
pub fn address_to_bytes32(address: &Address) -> [u8; 32] {
	let mut out = [0u8; 32];
	if address.0.len() == 20 {
		out[12..32].copy_from_slice(&address.0);
	}
	out
}

/// Generic helper to call BaseInputOracle.isProven().
pub async fn check_is_proven(
	provider: &DynProvider,
	oracle_address: &Address,
	remote_chain_id: u64,
	remote_oracle: [u8; 32],
	application: [u8; 32],
	data_hash: [u8; 32],
) -> Result<bool, SettlementError> {
	let call_data = IBaseInputOracle::isProvenCall {
		remoteChainId: U256::from(remote_chain_id),
		remoteOracle: FixedBytes::<32>::from(remote_oracle),
		application: FixedBytes::<32>::from(application),
		dataHash: FixedBytes::<32>::from(data_hash),
	};

	let request = alloy_rpc_types::eth::transaction::TransactionRequest {
		to: Some(alloy_primitives::TxKind::Call(
			alloy_primitives::Address::from_slice(&oracle_address.0),
		)),
		input: call_data.abi_encode().into(),
		..Default::default()
	};

	let result = provider
		.call(request)
		.await
		.map_err(|e| SettlementError::ValidationFailed(format!("Failed to call isProven: {e}")))?;

	Ok(result.len() >= 32 && result[31] != 0)
}

/// Generic storage-backed settlement message tracker.
#[derive(Clone)]
pub struct SettlementMessageTracker<S>
where
	S: Clone + Serialize + DeserializeOwned + Send + Sync + 'static,
{
	storage: Arc<StorageService>,
	namespace: &'static str,
	cache: Arc<RwLock<HashMap<String, S>>>,
}

impl<S> SettlementMessageTracker<S>
where
	S: Clone + Serialize + DeserializeOwned + Send + Sync + 'static,
{
	pub fn new(storage: Arc<StorageService>, namespace: &'static str) -> Self {
		Self {
			storage,
			namespace,
			cache: Arc::new(RwLock::new(HashMap::new())),
		}
	}

	fn storage_key(&self, order_id: &str) -> String {
		format!("{}:{order_id}", self.namespace)
	}

	pub async fn load(&self, order_id: &str) -> Option<S> {
		{
			let cache = self.cache.read().await;
			if let Some(state) = cache.get(order_id) {
				return Some(state.clone());
			}
		}

		let key = self.storage_key(order_id);
		match self
			.storage
			.retrieve::<S>(StorageKey::SettlementMessages.as_str(), &key)
			.await
		{
			Ok(state) => {
				let mut cache = self.cache.write().await;
				cache.insert(order_id.to_string(), state.clone());
				Some(state)
			},
			Err(_) => None,
		}
	}

	pub async fn save(
		&self,
		order_id: &str,
		state: &S,
		ttl: Option<Duration>,
	) -> Result<(), SettlementError> {
		let key = self.storage_key(order_id);

		self.storage
			.store_with_ttl(
				StorageKey::SettlementMessages.as_str(),
				&key,
				state,
				None,
				ttl,
			)
			.await
			.map_err(|e| {
				SettlementError::ValidationFailed(format!("Failed to persist message state: {e}"))
			})?;

		let mut cache = self.cache.write().await;
		cache.insert(order_id.to_string(), state.clone());
		Ok(())
	}
}

/// Validate that all routes reference chains with configured oracles.
fn validate_routes(
	input_oracles: &HashMap<u64, Vec<Address>>,
	output_oracles: &HashMap<u64, Vec<Address>>,
	routes: &HashMap<u64, Vec<u64>>,
) -> Result<(), SettlementError> {
	for (from_chain, to_chains) in routes {
		// Source chain must have input oracle
		if !input_oracles.contains_key(from_chain) {
			return Err(SettlementError::ValidationFailed(format!(
				"Route from chain {from_chain} has no input oracle configured"
			)));
		}

		// All destination chains must have output oracles
		for to_chain in to_chains {
			if !output_oracles.contains_key(to_chain) {
				return Err(SettlementError::ValidationFailed(format!(
					"Route from chain {from_chain} to chain {to_chain} has no output oracle configured"
				)));
			}
		}
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_parse_selection_strategy() {
		assert_eq!(
			parse_selection_strategy(Some("First")),
			OracleSelectionStrategy::First
		);
		assert_eq!(
			parse_selection_strategy(Some("RoundRobin")),
			OracleSelectionStrategy::RoundRobin
		);
		assert_eq!(
			parse_selection_strategy(Some("Random")),
			OracleSelectionStrategy::Random
		);
		assert_eq!(
			parse_selection_strategy(Some("Invalid")),
			OracleSelectionStrategy::First
		);
		assert_eq!(
			parse_selection_strategy(None),
			OracleSelectionStrategy::First
		);
	}

	#[test]
	fn test_parse_oracle_table_success() {
		let config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			table.insert(
				"1".to_string(),
				toml::Value::Array(vec![
					toml::Value::String("0x1111111111111111111111111111111111111111".to_string()),
					toml::Value::String("0x2222222222222222222222222222222222222222".to_string()),
				]),
			);
			table.insert(
				"2".to_string(),
				toml::Value::Array(vec![toml::Value::String(
					"0x3333333333333333333333333333333333333333".to_string(),
				)]),
			);
			table
		});

		let result = parse_oracle_table(&config).unwrap();
		assert_eq!(result.len(), 2);
		assert!(result.contains_key(&1));
		assert!(result.contains_key(&2));
		assert_eq!(result[&1].len(), 2);
		assert_eq!(result[&2].len(), 1);
		assert_eq!(
			result[&1][0],
			parse_address("0x1111111111111111111111111111111111111111").unwrap()
		);
		assert_eq!(
			result[&2][0],
			parse_address("0x3333333333333333333333333333333333333333").unwrap()
		);
	}

	#[test]
	fn test_parse_oracle_table_invalid_chain_id() {
		let config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			table.insert(
				"invalid".to_string(),
				toml::Value::Array(vec![toml::Value::String(
					"0x1111111111111111111111111111111111111111".to_string(),
				)]),
			);
			table
		});

		let result = parse_oracle_table(&config);
		assert!(matches!(result, Err(SettlementError::ValidationFailed(_))));
		if let Err(SettlementError::ValidationFailed(msg)) = result {
			assert!(msg.contains("Invalid chain ID 'invalid'"));
		}
	}

	#[test]
	fn test_parse_oracle_table_not_array() {
		let config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			table.insert(
				"1".to_string(),
				toml::Value::String("not_array".to_string()),
			);
			table
		});

		let result = parse_oracle_table(&config);
		assert!(matches!(result, Err(SettlementError::ValidationFailed(_))));
		if let Err(SettlementError::ValidationFailed(msg)) = result {
			assert!(msg.contains("Oracles for chain 1 must be an array"));
		}
	}

	#[test]
	fn test_parse_oracle_table_empty_array() {
		let config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			table.insert("1".to_string(), toml::Value::Array(vec![]));
			table
		});

		let result = parse_oracle_table(&config);
		assert!(matches!(result, Err(SettlementError::ValidationFailed(_))));
		if let Err(SettlementError::ValidationFailed(msg)) = result {
			assert!(msg.contains("At least one oracle address required for chain 1"));
		}
	}

	#[test]
	fn test_parse_oracle_table_non_string_address() {
		let config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			table.insert(
				"1".to_string(),
				toml::Value::Array(vec![toml::Value::Integer(123)]),
			);
			table
		});

		let result = parse_oracle_table(&config);
		assert!(matches!(result, Err(SettlementError::ValidationFailed(_))));
		if let Err(SettlementError::ValidationFailed(msg)) = result {
			assert!(msg.contains("Oracle address must be string for chain 1"));
		}
	}

	#[test]
	fn test_parse_oracle_table_invalid_address() {
		let config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			table.insert(
				"1".to_string(),
				toml::Value::Array(vec![toml::Value::String("invalid_address".to_string())]),
			);
			table
		});

		let result = parse_oracle_table(&config);
		assert!(matches!(result, Err(SettlementError::ValidationFailed(_))));
		if let Err(SettlementError::ValidationFailed(msg)) = result {
			assert!(msg.contains("Invalid oracle address for chain 1"));
		}
	}

	#[test]
	fn test_parse_routes_table_success() {
		let config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			table.insert(
				"1".to_string(),
				toml::Value::Array(vec![toml::Value::Integer(2), toml::Value::Integer(3)]),
			);
			table.insert(
				"2".to_string(),
				toml::Value::Array(vec![toml::Value::Integer(1)]),
			);
			table
		});

		let result = parse_routes_table(&config).unwrap();
		assert_eq!(result.len(), 2);
		assert!(result.contains_key(&1));
		assert!(result.contains_key(&2));
		assert_eq!(result[&1], vec![2, 3]);
		assert_eq!(result[&2], vec![1]);
	}

	#[test]
	fn test_parse_routes_table_invalid_chain_id() {
		let config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			table.insert(
				"invalid".to_string(),
				toml::Value::Array(vec![toml::Value::Integer(2)]),
			);
			table
		});

		let result = parse_routes_table(&config);
		assert!(matches!(result, Err(SettlementError::ValidationFailed(_))));
		if let Err(SettlementError::ValidationFailed(msg)) = result {
			assert!(msg.contains("Invalid chain ID 'invalid'"));
		}
	}

	#[test]
	fn test_parse_routes_table_not_array() {
		let config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			table.insert("1".to_string(), toml::Value::Integer(2));
			table
		});

		let result = parse_routes_table(&config);
		assert!(matches!(result, Err(SettlementError::ValidationFailed(_))));
		if let Err(SettlementError::ValidationFailed(msg)) = result {
			assert!(msg.contains("Destinations for chain 1 must be an array"));
		}
	}

	#[test]
	fn test_parse_routes_table_empty_array() {
		let config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			table.insert("1".to_string(), toml::Value::Array(vec![]));
			table
		});

		let result = parse_routes_table(&config);
		assert!(matches!(result, Err(SettlementError::ValidationFailed(_))));
		if let Err(SettlementError::ValidationFailed(msg)) = result {
			assert!(msg.contains("At least one destination required for route from chain 1"));
		}
	}

	#[test]
	fn test_parse_routes_table_non_integer_destination() {
		let config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			table.insert(
				"1".to_string(),
				toml::Value::Array(vec![toml::Value::String("invalid".to_string())]),
			);
			table
		});

		let result = parse_routes_table(&config);
		assert!(matches!(result, Err(SettlementError::ValidationFailed(_))));
		if let Err(SettlementError::ValidationFailed(msg)) = result {
			assert!(msg.contains("Destination chain ID must be integer for route from chain 1"));
		}
	}

	#[test]
	fn test_validate_routes_success() {
		let mut input_oracles = HashMap::new();
		input_oracles.insert(
			1,
			vec![parse_address("0x1111111111111111111111111111111111111111").unwrap()],
		);

		let mut output_oracles = HashMap::new();
		output_oracles.insert(
			2,
			vec![parse_address("0x2222222222222222222222222222222222222222").unwrap()],
		);
		output_oracles.insert(
			3,
			vec![parse_address("0x3333333333333333333333333333333333333333").unwrap()],
		);

		let mut routes = HashMap::new();
		routes.insert(1, vec![2, 3]);

		let result = validate_routes(&input_oracles, &output_oracles, &routes);
		assert!(result.is_ok());
	}

	#[test]
	fn test_validate_routes_missing_input_oracle() {
		let input_oracles = HashMap::new(); // Empty - no input oracle for chain 1

		let mut output_oracles = HashMap::new();
		output_oracles.insert(
			2,
			vec![parse_address("0x2222222222222222222222222222222222222222").unwrap()],
		);

		let mut routes = HashMap::new();
		routes.insert(1, vec![2]);

		let result = validate_routes(&input_oracles, &output_oracles, &routes);
		assert!(matches!(result, Err(SettlementError::ValidationFailed(_))));
		if let Err(SettlementError::ValidationFailed(msg)) = result {
			assert!(msg.contains("Route from chain 1 has no input oracle configured"));
		}
	}

	#[test]
	fn test_validate_routes_missing_output_oracle() {
		let mut input_oracles = HashMap::new();
		input_oracles.insert(
			1,
			vec![parse_address("0x1111111111111111111111111111111111111111").unwrap()],
		);

		let output_oracles = HashMap::new(); // Empty - no output oracle for chain 2

		let mut routes = HashMap::new();
		routes.insert(1, vec![2]);

		let result = validate_routes(&input_oracles, &output_oracles, &routes);
		assert!(matches!(result, Err(SettlementError::ValidationFailed(_))));
		if let Err(SettlementError::ValidationFailed(msg)) = result {
			assert!(msg.contains("Route from chain 1 to chain 2 has no output oracle configured"));
		}
	}

	#[test]
	fn test_parse_oracle_config_success() {
		let config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			table.insert(
				"oracles".to_string(),
				toml::Value::Table({
					let mut oracles = toml::map::Map::new();
					oracles.insert(
						"input".to_string(),
						toml::Value::Table({
							let mut input = toml::map::Map::new();
							input.insert(
								"1".to_string(),
								toml::Value::Array(vec![toml::Value::String(
									"0x1111111111111111111111111111111111111111".to_string(),
								)]),
							);
							input
						}),
					);
					oracles.insert(
						"output".to_string(),
						toml::Value::Table({
							let mut output = toml::map::Map::new();
							output.insert(
								"2".to_string(),
								toml::Value::Array(vec![toml::Value::String(
									"0x2222222222222222222222222222222222222222".to_string(),
								)]),
							);
							output
						}),
					);
					oracles
				}),
			);
			table.insert(
				"routes".to_string(),
				toml::Value::Table({
					let mut routes = toml::map::Map::new();
					routes.insert(
						"1".to_string(),
						toml::Value::Array(vec![toml::Value::Integer(2)]),
					);
					routes
				}),
			);
			table.insert(
				"oracle_selection_strategy".to_string(),
				toml::Value::String("RoundRobin".to_string()),
			);
			table
		});

		let result = parse_oracle_config(&config).unwrap();
		assert_eq!(result.input_oracles.len(), 1);
		assert_eq!(result.output_oracles.len(), 1);
		assert_eq!(result.routes.len(), 1);
		assert!(matches!(
			result.selection_strategy,
			OracleSelectionStrategy::RoundRobin
		));
	}

	#[test]
	fn test_parse_oracle_config_missing_oracles_section() {
		let config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			table.insert(
				"routes".to_string(),
				toml::Value::Table(toml::map::Map::new()),
			);
			table
		});

		let result = parse_oracle_config(&config);
		assert!(matches!(result, Err(SettlementError::ValidationFailed(_))));
		if let Err(SettlementError::ValidationFailed(msg)) = result {
			assert!(msg.contains("Missing 'oracles' section"));
		}
	}

	#[test]
	fn test_parse_oracle_config_missing_input_oracles() {
		let config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			table.insert(
				"oracles".to_string(),
				toml::Value::Table({
					let mut oracles = toml::map::Map::new();
					oracles.insert(
						"output".to_string(),
						toml::Value::Table(toml::map::Map::new()),
					);
					oracles
				}),
			);
			table.insert(
				"routes".to_string(),
				toml::Value::Table(toml::map::Map::new()),
			);
			table
		});

		let result = parse_oracle_config(&config);
		assert!(matches!(result, Err(SettlementError::ValidationFailed(_))));
		if let Err(SettlementError::ValidationFailed(msg)) = result {
			assert!(msg.contains("Missing 'oracles.input'"));
		}
	}

	#[test]
	fn test_parse_oracle_config_missing_output_oracles() {
		let config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			table.insert(
				"oracles".to_string(),
				toml::Value::Table({
					let mut oracles = toml::map::Map::new();
					oracles.insert(
						"input".to_string(),
						toml::Value::Table(toml::map::Map::new()),
					);
					oracles
				}),
			);
			table.insert(
				"routes".to_string(),
				toml::Value::Table(toml::map::Map::new()),
			);
			table
		});

		let result = parse_oracle_config(&config);
		assert!(matches!(result, Err(SettlementError::ValidationFailed(_))));
		if let Err(SettlementError::ValidationFailed(msg)) = result {
			assert!(msg.contains("Missing 'oracles.output'"));
		}
	}

	#[test]
	fn test_parse_oracle_config_missing_routes() {
		let config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			table.insert(
				"oracles".to_string(),
				toml::Value::Table({
					let mut oracles = toml::map::Map::new();
					oracles.insert(
						"input".to_string(),
						toml::Value::Table(toml::map::Map::new()),
					);
					oracles.insert(
						"output".to_string(),
						toml::Value::Table(toml::map::Map::new()),
					);
					oracles
				}),
			);
			table
		});

		let result = parse_oracle_config(&config);
		assert!(matches!(result, Err(SettlementError::ValidationFailed(_))));
		if let Err(SettlementError::ValidationFailed(msg)) = result {
			assert!(msg.contains("Missing 'routes' section"));
		}
	}

	#[test]
	fn test_parse_oracle_config_default_strategy() {
		let config = toml::Value::Table({
			let mut table = toml::map::Map::new();
			table.insert(
				"oracles".to_string(),
				toml::Value::Table({
					let mut oracles = toml::map::Map::new();
					oracles.insert(
						"input".to_string(),
						toml::Value::Table({
							let mut input = toml::map::Map::new();
							input.insert(
								"1".to_string(),
								toml::Value::Array(vec![toml::Value::String(
									"0x1111111111111111111111111111111111111111".to_string(),
								)]),
							);
							input
						}),
					);
					oracles.insert(
						"output".to_string(),
						toml::Value::Table({
							let mut output = toml::map::Map::new();
							output.insert(
								"2".to_string(),
								toml::Value::Array(vec![toml::Value::String(
									"0x2222222222222222222222222222222222222222".to_string(),
								)]),
							);
							output
						}),
					);
					oracles
				}),
			);
			table.insert(
				"routes".to_string(),
				toml::Value::Table({
					let mut routes = toml::map::Map::new();
					routes.insert(
						"1".to_string(),
						toml::Value::Array(vec![toml::Value::Integer(2)]),
					);
					routes
				}),
			);
			// No oracle_selection_strategy - should default to First
			table
		});

		let result = parse_oracle_config(&config).unwrap();
		assert!(matches!(
			result.selection_strategy,
			OracleSelectionStrategy::First
		));
	}
}
