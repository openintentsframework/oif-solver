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
//!   "solver_name": "My Solver Instance",
//!   "networks": [
//!     {
//!       "chain_id": 10,
//!       "name": "optimism",
//!       "type": "parent",
//!       "tokens": [
//!         {"symbol": "USDC", "name": "USD Coin", "address": "0x...", "decimals": 6}
//!       ],
//!       "rpc_urls": ["https://user-rpc.com"]
//!     }
//!   ],
//!   "min_profitability_pct": "2.0",
//!   "gas_buffer_bps": 1500,
//!   "admin": {
//!     "enabled": true,
//!     "domain": "solver.example.com",
//!     "admin_addresses": ["0xYourAdminWallet"]
//!   }
//! }
//! ```

use crate::networks::NetworkType;
use alloy_primitives::Address;
use rust_decimal::Decimal;
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

	/// Optional human-readable solver name for display and identification.
	#[serde(default)]
	pub solver_name: Option<String>,

	/// List of networks the solver should support.
	/// Each network must exist in the seed configuration.
	pub networks: Vec<NetworkOverride>,

	/// Optional account configuration to override the default local wallet.
	/// Use this to configure KMS or other account implementations.
	#[serde(default)]
	pub account: Option<AccountOverride>,

	/// Optional admin configuration for wallet-based admin authentication.
	/// If provided, enables admin API endpoints with EIP-712 signature auth.
	#[serde(default)]
	pub admin: Option<AdminOverride>,

	/// Minimum profitability percentage (e.g., 1.0 = 1%).
	/// If not set, uses seed default (typically 1.0%).
	#[serde(default, with = "option_decimal_str")]
	pub min_profitability_pct: Option<Decimal>,

	/// Gas buffer in basis points (e.g., 1000 = 10%).
	/// If not set, uses default (1000 = 10%).
	#[serde(default)]
	pub gas_buffer_bps: Option<u32>,

	/// Commission in basis points (e.g., 20 = 0.20%).
	/// If not set, uses default.
	#[serde(default)]
	pub commission_bps: Option<u32>,

	/// Rate buffer in basis points (e.g., 14 = 0.14%).
	/// If not set, uses default.
	#[serde(default)]
	pub rate_buffer_bps: Option<u32>,
}

/// Account configuration override for non-default signing backends.
///
/// Allows specifying which account implementation to use (e.g., "kms")
/// and its configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountOverride {
	/// Primary account implementation to use (e.g., "local", "kms").
	pub primary: String,

	/// Implementation-specific configurations.
	/// Keys are implementation names, values are their configuration.
	pub implementations: std::collections::HashMap<String, serde_json::Value>,
}

/// Admin configuration for wallet-based admin authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminOverride {
	/// Enable admin authentication. Defaults to true if admin config is present.
	#[serde(default = "default_admin_enabled")]
	pub enabled: bool,

	/// Domain for signature verification (prevents cross-site attacks).
	/// Example: "solver.example.com"
	pub domain: String,

	/// Chain ID for EIP-712 domain separator.
	/// The wallet must be connected to this chain when signing admin actions.
	/// If not set, uses the first network's chain ID from config.
	#[serde(default)]
	pub chain_id: Option<u64>,

	/// List of authorized admin wallet addresses.
	/// Only these addresses can perform admin operations.
	pub admin_addresses: Vec<Address>,

	/// Optional nonce TTL in seconds. Default: 300 (5 minutes).
	#[serde(default)]
	pub nonce_ttl_seconds: Option<u64>,

	/// Withdrawal policy overrides.
	#[serde(default)]
	pub withdrawals: WithdrawalsOverride,
}

fn default_admin_enabled() -> bool {
	true
}

/// Withdrawal policy overrides for admin withdrawals.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WithdrawalsOverride {
	/// Whether withdrawals are enabled.
	#[serde(default)]
	pub enabled: bool,
}

/// Helper module for Option<Decimal> serialization.
/// Accepts both string and number input for flexibility.
mod option_decimal_str {
	use rust_decimal::Decimal;
	use serde::{self, Deserialize, Deserializer, Serializer};
	use std::str::FromStr;

	pub fn serialize<S>(value: &Option<Decimal>, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match value {
			Some(d) => serializer.serialize_str(&d.to_string()),
			None => serializer.serialize_none(),
		}
	}

	pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Decimal>, D::Error>
	where
		D: Deserializer<'de>,
	{
		// Accept both string and number input
		let opt: Option<serde_json::Value> = Option::deserialize(deserializer)?;
		match opt {
			Some(v) => {
				let s = match v {
					serde_json::Value::String(s) => s,
					serde_json::Value::Number(n) => n.to_string(),
					_ => return Err(serde::de::Error::custom("invalid decimal value")),
				};
				Decimal::from_str(&s)
					.map(Some)
					.map_err(serde::de::Error::custom)
			},
			None => Ok(None),
		}
	}
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

	/// Optional human-readable network name override.
	#[serde(default)]
	pub name: Option<String>,

	/// Network role classification.
	#[serde(default, rename = "type")]
	pub network_type: Option<NetworkType>,

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

	/// Optional human-readable token name (e.g., "USD Coin").
	#[serde(default)]
	pub name: Option<String>,

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
	use rust_decimal::Decimal;
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
			solver_name: None,
			networks: vec![
				NetworkOverride {
					chain_id: 10,
					name: None,
					network_type: None,
					tokens: vec![],
					rpc_urls: None,
				},
				NetworkOverride {
					chain_id: 8453,
					name: None,
					network_type: None,
					tokens: vec![],
					rpc_urls: None,
				},
			],
			account: None,
			admin: None,
			min_profitability_pct: None,
			gas_buffer_bps: None,
			commission_bps: None,
			rate_buffer_bps: None,
		};

		let chain_ids = config.chain_ids();
		assert_eq!(chain_ids, vec![10, 8453]);
	}

	#[test]
	fn test_has_chain() {
		let config = SeedOverrides {
			solver_id: None,
			solver_name: None,
			networks: vec![NetworkOverride {
				chain_id: 10,
				name: None,
				network_type: None,
				tokens: vec![],
				rpc_urls: None,
			}],
			account: None,
			admin: None,
			min_profitability_pct: None,
			gas_buffer_bps: None,
			commission_bps: None,
			rate_buffer_bps: None,
		};

		assert!(config.has_chain(10));
		assert!(!config.has_chain(8453));
	}

	#[test]
	fn test_get_network() {
		let config = SeedOverrides {
			solver_id: None,
			solver_name: None,
			networks: vec![NetworkOverride {
				chain_id: 10,
				name: None,
				network_type: None,
				tokens: vec![Token {
					symbol: "USDC".to_string(),
					name: Some("USD Coin".to_string()),
					address: test_address(),
					decimals: 6,
				}],
				rpc_urls: None,
			}],
			account: None,
			admin: None,
			min_profitability_pct: None,
			gas_buffer_bps: None,
			commission_bps: None,
			rate_buffer_bps: None,
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
				name: Some("USD Coin".to_string()),
				address: test_address(),
				decimals: 6,
			}],
			name: None,
			network_type: None,
			rpc_urls: None,
		};

		let without_tokens = NetworkOverride {
			chain_id: 10,
			tokens: vec![],
			name: None,
			network_type: None,
			rpc_urls: None,
		};

		assert!(with_tokens.has_tokens());
		assert!(!without_tokens.has_tokens());
	}

	#[test]
	fn test_json_roundtrip() {
		let config = SeedOverrides {
			solver_id: Some("test-solver".to_string()),
			solver_name: Some("Test Solver".to_string()),
			networks: vec![NetworkOverride {
				chain_id: 10,
				name: Some("optimism".to_string()),
				network_type: Some(NetworkType::Parent),
				tokens: vec![Token {
					symbol: "USDC".to_string(),
					name: Some("USD Coin".to_string()),
					address: test_address(),
					decimals: 6,
				}],
				rpc_urls: Some(vec!["https://rpc.com".to_string()]),
			}],
			account: None,
			admin: None,
			min_profitability_pct: None,
			gas_buffer_bps: None,
			commission_bps: None,
			rate_buffer_bps: None,
		};

		let json = serde_json::to_string(&config).unwrap();
		let parsed: SeedOverrides = serde_json::from_str(&json).unwrap();

		assert_eq!(parsed.solver_name, Some("Test Solver".to_string()));
		assert_eq!(parsed.networks.len(), 1);
		assert_eq!(parsed.networks[0].chain_id, 10);
		assert_eq!(parsed.networks[0].name, Some("optimism".to_string()));
		assert_eq!(parsed.networks[0].network_type, Some(NetworkType::Parent));
		assert_eq!(parsed.networks[0].tokens[0], config.networks[0].tokens[0]);
	}

	#[test]
	fn test_parse_fee_config_fields() {
		let json = r#"{
            "networks": [
                {
                    "chain_id": 10,
                    "tokens": [
                        {"symbol": "USDC", "address": "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", "decimals": 6}
                    ]
                }
            ],
            "min_profitability_pct": "2.5",
            "gas_buffer_bps": 1500,
            "commission_bps": 20,
            "rate_buffer_bps": 14
        }"#;

		let config: SeedOverrides = serde_json::from_str(json).unwrap();

		assert_eq!(
			config.min_profitability_pct,
			Some(Decimal::from_str("2.5").unwrap())
		);
		assert_eq!(config.gas_buffer_bps, Some(1500));
		assert_eq!(config.commission_bps, Some(20));
		assert_eq!(config.rate_buffer_bps, Some(14));
	}

	#[test]
	fn test_parse_fee_config_as_number() {
		// Test that min_profitability_pct accepts numeric input too
		let json = r#"{
            "networks": [
                {
                    "chain_id": 10,
                    "tokens": [
                        {"symbol": "USDC", "address": "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", "decimals": 6}
                    ]
                }
            ],
            "min_profitability_pct": 3.0
        }"#;

		let config: SeedOverrides = serde_json::from_str(json).unwrap();

		assert_eq!(
			config.min_profitability_pct,
			Some(Decimal::from_str("3.0").unwrap())
		);
		assert_eq!(config.gas_buffer_bps, None);
		assert_eq!(config.commission_bps, None);
		assert_eq!(config.rate_buffer_bps, None);
	}

	#[test]
	fn test_fee_config_defaults_to_none() {
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

		assert_eq!(config.min_profitability_pct, None);
		assert_eq!(config.gas_buffer_bps, None);
		assert_eq!(config.commission_bps, None);
		assert_eq!(config.rate_buffer_bps, None);
	}

	#[test]
	fn test_parse_account_override() {
		let json = r#"{
            "solver_id": "kms-solver",
            "account": {
                "primary": "kms",
                "implementations": {
                    "kms": {
                        "key_id": "1fa50595-bfee-45db-b333-fe906244231f",
                        "region": "us-east-1"
                    }
                }
            },
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

		assert!(config.account.is_some());
		let account = config.account.as_ref().unwrap();
		assert_eq!(account.primary, "kms");
		assert!(account.implementations.contains_key("kms"));

		let kms_config = &account.implementations["kms"];
		assert_eq!(
			kms_config["key_id"].as_str().unwrap(),
			"1fa50595-bfee-45db-b333-fe906244231f"
		);
		assert_eq!(kms_config["region"].as_str().unwrap(), "us-east-1");
	}

	#[test]
	fn test_account_override_defaults_to_none() {
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
		assert!(config.account.is_none());
	}

	#[test]
	fn test_parse_full_kms_config_with_admin() {
		// Test parsing a full config with all optional fields including account and admin
		let json = r#"{
            "solver_id": "test-kms-solver",
            "account": {
                "primary": "kms",
                "implementations": {
                    "kms": {
                        "key_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                        "region": "us-east-1"
                    }
                }
            },
            "networks": [
                {
                    "chain_id": 11155420,
                    "tokens": [
                        {
                            "symbol": "USDC",
                            "address": "0x191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6",
                            "decimals": 6
                        }
                    ]
                },
                {
                    "chain_id": 84532,
                    "tokens": [
                        {
                            "symbol": "USDC",
                            "address": "0x73c83DAcc74bB8a704717AC09703b959E74b9705",
                            "decimals": 6
                        }
                    ]
                }
            ],
            "admin": {
                "enabled": true,
                "domain": "localhost",
                "admin_addresses": ["0x33848cc530581B2CeFef58CC9D3c935311D4b940"]
            }
        }"#;

		let config: SeedOverrides = serde_json::from_str(json).unwrap();

		// Verify solver_id
		assert_eq!(config.solver_id, Some("test-kms-solver".to_string()));

		// Verify account
		assert!(config.account.is_some(), "Account should be Some");
		let account = config.account.as_ref().unwrap();
		assert_eq!(account.primary, "kms");
		assert!(account.implementations.contains_key("kms"));
		assert!(
			!account.implementations.contains_key("local"),
			"Should NOT have local"
		);
		let kms_config = &account.implementations["kms"];
		assert_eq!(
			kms_config["key_id"].as_str().unwrap(),
			"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
		);
		assert_eq!(kms_config["region"].as_str().unwrap(), "us-east-1");

		// Verify networks
		assert_eq!(config.networks.len(), 2);
		assert_eq!(config.networks[0].chain_id, 11155420);
		assert_eq!(config.networks[1].chain_id, 84532);

		// Verify admin
		assert!(config.admin.is_some());
		let admin = config.admin.as_ref().unwrap();
		assert!(admin.enabled);
		assert_eq!(admin.domain, "localhost");
	}
}
