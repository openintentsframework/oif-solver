//! Common utilities for settlement implementations.
//!
//! This module provides shared utilities for parsing oracle configurations
//! from TOML config files, used by all settlement implementations.

use crate::{OracleConfig, OracleSelectionStrategy, SettlementError};
use solver_types::{utils::parse_address, Address};
use std::collections::HashMap;

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
				SettlementError::ValidationFailed(format!(
					"Invalid chain ID '{}': {}",
					chain_id_str, e
				))
			})?;

			let oracles = if let Some(array) = oracles_value.as_array() {
				array
					.iter()
					.map(|v| {
						v.as_str()
							.ok_or_else(|| {
								SettlementError::ValidationFailed(format!(
									"Oracle address must be string for chain {}",
									chain_id
								))
							})
							.and_then(|s| {
								parse_address(s).map_err(|e| {
									SettlementError::ValidationFailed(format!(
										"Invalid oracle address for chain {}: {}",
										chain_id, e
									))
								})
							})
					})
					.collect::<Result<Vec<_>, _>>()?
			} else {
				return Err(SettlementError::ValidationFailed(format!(
					"Oracles for chain {} must be an array",
					chain_id
				)));
			};

			if oracles.is_empty() {
				return Err(SettlementError::ValidationFailed(format!(
					"At least one oracle address required for chain {}",
					chain_id
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
				SettlementError::ValidationFailed(format!(
					"Invalid chain ID '{}': {}",
					chain_id_str, e
				))
			})?;

			let destinations = if let Some(array) = destinations_value.as_array() {
				array
					.iter()
					.map(|v| {
						v.as_integer().map(|i| i as u64).ok_or_else(|| {
							SettlementError::ValidationFailed(format!(
								"Destination chain ID must be integer for route from chain {}",
								chain_id
							))
						})
					})
					.collect::<Result<Vec<_>, _>>()?
			} else {
				return Err(SettlementError::ValidationFailed(format!(
					"Destinations for chain {} must be an array",
					chain_id
				)));
			};

			if destinations.is_empty() {
				return Err(SettlementError::ValidationFailed(format!(
					"At least one destination required for route from chain {}",
					chain_id
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
				"Route from chain {} has no input oracle configured",
				from_chain
			)));
		}

		// All destination chains must have output oracles
		for to_chain in to_chains {
			if !output_oracles.contains_key(to_chain) {
				return Err(SettlementError::ValidationFailed(format!(
					"Route from chain {} to chain {} has no output oracle configured",
					from_chain, to_chain
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
}
