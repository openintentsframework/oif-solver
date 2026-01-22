//! Seed override types for initializing a new solver.
//!
//! This module defines the configuration structures that are received from
//! the UI or CLI when deploying a new solver instance. These types specify
//! which networks and tokens the solver should support, overriding or
//! extending the defaults from the seed preset.
//!
//! # Example JSON
//!
//! ```json
//! {
//!   "solver_id": "my-solver-instance",
//!   "networks": [
//!     {
//!       "chain_id": 10,
//!       "tokens": [
//!         {"symbol": "USDC", "address": "0x...", "decimals": 6}
//!       ],
//!       "rpc_urls": ["https://user-rpc.com"]
//!     }
//!   ]
//! }
//! ```

use alloy_primitives::Address;
use serde::{Deserialize, Serialize};

/// Seed overrides received from UI/CLI for deploying a new solver.
///
/// This is the top-level structure that specifies which networks
/// the solver should operate on and what tokens to support.
/// These values override/extend the seed preset defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedOverrides {
	/// Optional solver ID. If provided, this ID will be used for the solver.
	/// If not provided, a new UUID-based ID will be generated.
	/// Providing a consistent solver_id enables idempotent seeding.
	#[serde(default)]
	pub solver_id: Option<String>,

	/// List of networks the solver should support.
	/// Each network must exist in the seed configuration.
	pub networks: Vec<NetworkOverride>,
}

/// Per-network configuration provided by the user.
///
/// Contains the chain ID and tokens to support, with optional
/// RPC URL overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkOverride {
	/// Chain ID of the network (e.g., 10 for Optimism, 8453 for Base).
	/// Must exist in the seed configuration.
	pub chain_id: u64,

	/// Tokens this solver will support on this network.
	/// Required - different solvers support different tokens.
	pub tokens: Vec<Token>,

	/// Optional custom RPC URLs.
	/// If not provided, defaults from the seed will be used.
	#[serde(default)]
	pub rpc_urls: Option<Vec<String>>,
}

/// Token configuration for a specific network.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Token {
	/// Token symbol (e.g., "USDC", "WETH").
	pub symbol: String,

	/// Token contract address on this network.
	pub address: Address,

	/// Number of decimals for this token (e.g., 6 for USDC, 18 for ETH).
	pub decimals: u8,
}

impl SeedOverrides {
	/// Get the chain IDs from all networks.
	pub fn chain_ids(&self) -> Vec<u64> {
		self.networks.iter().map(|n| n.chain_id).collect()
	}

	/// Check if a specific chain is included.
	pub fn has_chain(&self, chain_id: u64) -> bool {
		self.networks.iter().any(|n| n.chain_id == chain_id)
	}

	/// Get the network override for a specific chain.
	pub fn get_network(&self, chain_id: u64) -> Option<&NetworkOverride> {
		self.networks.iter().find(|n| n.chain_id == chain_id)
	}
}

impl NetworkOverride {
	/// Check if this network has any tokens configured.
	pub fn has_tokens(&self) -> bool {
		!self.tokens.is_empty()
	}

	/// Check if custom RPC URLs are provided.
	pub fn has_custom_rpcs(&self) -> bool {
		self.rpc_urls.as_ref().is_some_and(|urls| !urls.is_empty())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::str::FromStr;

	fn test_address() -> Address {
		Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap()
	}

	#[test]
	fn test_parse_minimal_config() {
		let json = r#"{
            "networks": [
                {
                    "chain_id": 10,
                    "tokens": [
                        {"symbol": "USDC", "address": "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", "decimals": 6}
                    ]
                }
            ]
        }"#;

		let config: SeedOverrides = serde_json::from_str(json).unwrap();

		assert_eq!(config.networks.len(), 1);
		assert_eq!(config.networks[0].chain_id, 10);
		assert_eq!(config.networks[0].tokens.len(), 1);
		assert_eq!(config.networks[0].tokens[0].symbol, "USDC");
		assert_eq!(config.networks[0].tokens[0].decimals, 6);
		assert!(config.networks[0].rpc_urls.is_none());
	}

	#[test]
	fn test_parse_full_config() {
		let json = r#"{
            "networks": [
                {
                    "chain_id": 10,
                    "tokens": [
                        {"symbol": "USDC", "address": "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", "decimals": 6},
                        {"symbol": "WETH", "address": "0x4200000000000000000000000000000000000006", "decimals": 18}
                    ],
                    "rpc_urls": ["https://custom-rpc.com", "https://backup-rpc.com"]
                },
                {
                    "chain_id": 8453,
                    "tokens": [
                        {"symbol": "USDC", "address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "decimals": 6}
                    ]
                }
            ]
        }"#;

		let config: SeedOverrides = serde_json::from_str(json).unwrap();

		assert_eq!(config.networks.len(), 2);

		// First network with custom RPCs
		assert_eq!(config.networks[0].chain_id, 10);
		assert_eq!(config.networks[0].tokens.len(), 2);
		assert!(config.networks[0].has_custom_rpcs());
		assert_eq!(config.networks[0].rpc_urls.as_ref().unwrap().len(), 2);

		// Second network without custom RPCs
		assert_eq!(config.networks[1].chain_id, 8453);
		assert!(!config.networks[1].has_custom_rpcs());
	}

	#[test]
	fn test_chain_ids() {
		let config = SeedOverrides {
			solver_id: None,
			networks: vec![
				NetworkOverride {
					chain_id: 10,
					tokens: vec![],
					rpc_urls: None,
				},
				NetworkOverride {
					chain_id: 8453,
					tokens: vec![],
					rpc_urls: None,
				},
			],
		};

		let chain_ids = config.chain_ids();
		assert_eq!(chain_ids, vec![10, 8453]);
	}

	#[test]
	fn test_has_chain() {
		let config = SeedOverrides {
			solver_id: None,
			networks: vec![NetworkOverride {
				chain_id: 10,
				tokens: vec![],
				rpc_urls: None,
			}],
		};

		assert!(config.has_chain(10));
		assert!(!config.has_chain(8453));
	}

	#[test]
	fn test_get_network() {
		let config = SeedOverrides {
			solver_id: None,
			networks: vec![NetworkOverride {
				chain_id: 10,
				tokens: vec![Token {
					symbol: "USDC".to_string(),
					address: test_address(),
					decimals: 6,
				}],
				rpc_urls: None,
			}],
		};

		let network = config.get_network(10);
		assert!(network.is_some());
		assert_eq!(network.unwrap().tokens[0].symbol, "USDC");

		assert!(config.get_network(8453).is_none());
	}

	#[test]
	fn test_has_tokens() {
		let with_tokens = NetworkOverride {
			chain_id: 10,
			tokens: vec![Token {
				symbol: "USDC".to_string(),
				address: test_address(),
				decimals: 6,
			}],
			rpc_urls: None,
		};

		let without_tokens = NetworkOverride {
			chain_id: 10,
			tokens: vec![],
			rpc_urls: None,
		};

		assert!(with_tokens.has_tokens());
		assert!(!without_tokens.has_tokens());
	}

	#[test]
	fn test_json_roundtrip() {
		let config = SeedOverrides {
			solver_id: Some("test-solver".to_string()),
			networks: vec![NetworkOverride {
				chain_id: 10,
				tokens: vec![Token {
					symbol: "USDC".to_string(),
					address: test_address(),
					decimals: 6,
				}],
				rpc_urls: Some(vec!["https://rpc.com".to_string()]),
			}],
		};

		let json = serde_json::to_string(&config).unwrap();
		let parsed: SeedOverrides = serde_json::from_str(&json).unwrap();

		assert_eq!(parsed.networks.len(), 1);
		assert_eq!(parsed.networks[0].chain_id, 10);
		assert_eq!(parsed.networks[0].tokens[0], config.networks[0].tokens[0]);
	}
}
