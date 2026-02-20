//! Operator configuration types for runtime configuration storage.
//!
//! `OperatorConfig` is the complete solver configuration stored in Redis.
//! It represents the merged result of Seeds (hardcoded Rust defaults) and
//! Initializer (JSON file) on first boot.
//!
//! # Architecture
//!
//! - **First boot**: Seeds + Initializer → merge → OperatorConfig (stored in Redis)
//! - **After first boot**: OperatorConfig loaded directly from Redis
//! - **Runtime**: Admin API can modify any field in OperatorConfig
//!
//! # Example
//!
//! ```rust,ignore
//! use solver_types::OperatorConfig;
//!
//! // Load from Redis
//! let config: OperatorConfig = config_store.get().await?.data;
//!
//! // Modify tokens
//! config.networks.get_mut(&84532).unwrap().tokens.push(token);
//!
//! // Save back to Redis
//! config_store.update(config, version).await?;
//! ```

use crate::networks::NetworkType;
use alloy_primitives::{Address, B256};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Complete operator configuration stored in Redis.
///
/// This is the source of truth for all solver configuration after first boot.
/// Every field is modifiable via the Admin API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorConfig {
	/// Unique solver instance identifier.
	pub solver_id: String,

	/// Optional human-readable solver name.
	#[serde(default)]
	pub solver_name: Option<String>,

	/// Per-network configuration, keyed by chain ID.
	pub networks: HashMap<u64, OperatorNetworkConfig>,

	/// Settlement configuration including Hyperlane settings.
	pub settlement: OperatorSettlementConfig,

	/// Gas estimation settings per flow type.
	pub gas: OperatorGasConfig,

	/// Pricing provider configuration.
	pub pricing: OperatorPricingConfig,

	/// Solver behavior settings.
	pub solver: OperatorSolverConfig,

	/// Admin authentication settings.
	pub admin: OperatorAdminConfig,

	/// Whether JWT auth is required for API routes.
	#[serde(default)]
	pub auth_enabled: bool,

	/// Account signing backend configuration.
	/// If None, defaults to local wallet with SOLVER_PRIVATE_KEY.
	#[serde(default)]
	pub account: Option<OperatorAccountConfig>,
}

/// Account configuration for signing backends.
///
/// Specifies which account implementation to use (e.g., "local", "kms")
/// and any non-sensitive configuration parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorAccountConfig {
	/// Primary account implementation to use (e.g., "local", "kms").
	pub primary: String,

	/// Implementation-specific configurations.
	/// Keys are implementation names, values are their configuration.
	/// Note: Sensitive values like private keys should come from environment variables.
	pub implementations: HashMap<String, serde_json::Value>,
}

/// Per-network configuration including contracts, tokens, and RPCs.
///
/// Contains everything needed to interact with a specific chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorNetworkConfig {
	/// Chain ID (e.g., 10 for Optimism, 8453 for Base).
	pub chain_id: u64,

	/// Human-readable network name.
	#[serde(default = "default_network_name")]
	pub name: String,

	/// Network role classification.
	#[serde(default, rename = "type")]
	pub network_type: NetworkType,

	/// Tokens supported on this network.
	pub tokens: Vec<OperatorToken>,

	/// RPC endpoints for this network.
	pub rpc_urls: Vec<OperatorRpcEndpoint>,

	/// Input settler contract address (permit2/EIP-3009 escrow).
	pub input_settler_address: Address,

	/// Output settler contract address.
	pub output_settler_address: Address,

	/// Input settler address for compact/resource-lock flow.
	pub input_settler_compact_address: Option<Address>,

	/// The Compact contract address.
	pub the_compact_address: Option<Address>,

	/// Allocator contract address for compact flow.
	pub allocator_address: Option<Address>,
}

fn default_network_name() -> String {
	"unknown".to_string()
}

/// Token configuration for a network.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OperatorToken {
	/// Token symbol (e.g., "USDC", "WETH").
	pub symbol: String,

	/// Optional human-readable token name (e.g., "USD Coin").
	#[serde(default)]
	pub name: Option<String>,

	/// Token contract address.
	pub address: Address,

	/// Number of decimals (e.g., 6 for USDC, 18 for ETH).
	pub decimals: u8,
}

/// RPC endpoint configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorRpcEndpoint {
	/// HTTP RPC URL.
	pub http: String,

	/// Optional WebSocket URL for subscriptions.
	pub ws: Option<String>,
}

impl OperatorRpcEndpoint {
	/// Create an HTTP-only endpoint.
	pub fn http_only(url: String) -> Self {
		Self {
			http: url,
			ws: None,
		}
	}

	/// Create an endpoint with both HTTP and WebSocket URLs.
	pub fn with_ws(http: String, ws: String) -> Self {
		Self { http, ws: Some(ws) }
	}
}

/// Settlement configuration including Hyperlane settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorSettlementConfig {
	/// Interval in seconds for polling settlement status.
	pub settlement_poll_interval_seconds: u64,

	/// Selected settlement implementation type.
	#[serde(default = "default_settlement_type")]
	pub settlement_type: OperatorSettlementType,

	/// Hyperlane-specific settlement configuration.
	#[serde(default)]
	pub hyperlane: Option<OperatorHyperlaneConfig>,

	/// Direct settlement configuration.
	#[serde(default)]
	pub direct: Option<OperatorDirectConfig>,

	/// Broadcaster settlement configuration.
	#[serde(default)]
	pub broadcaster: Option<OperatorBroadcasterConfig>,
}

/// Selected settlement implementation type.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperatorSettlementType {
	#[default]
	Hyperlane,
	Direct,
	Broadcaster,
}

fn default_settlement_type() -> OperatorSettlementType {
	OperatorSettlementType::Hyperlane
}

/// Hyperlane cross-chain messaging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorHyperlaneConfig {
	/// Default gas limit for Hyperlane messages.
	pub default_gas_limit: u64,

	/// Timeout in seconds for Hyperlane messages.
	pub message_timeout_seconds: u64,

	/// Whether finalization is required before claiming.
	pub finalization_required: bool,

	/// Mailbox contract address per chain.
	pub mailboxes: HashMap<u64, Address>,

	/// IGP (Interchain Gas Paymaster) address per chain.
	pub igp_addresses: HashMap<u64, Address>,

	/// Oracle addresses for input and output verification.
	pub oracles: OperatorOracleConfig,

	/// Valid routes: source chain → [destination chains].
	pub routes: HashMap<u64, Vec<u64>>,

	/// Optional minimum required `expires` window (seconds) for accepting intents.
	#[serde(default)]
	pub intent_min_expiry_seconds: Option<u64>,
}

/// Oracle addresses for cross-chain verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorOracleConfig {
	/// Input oracle addresses per chain.
	pub input: HashMap<u64, Vec<Address>>,

	/// Output oracle addresses per chain.
	pub output: HashMap<u64, Vec<Address>>,
}

/// Oracle selection strategy for direct settlement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum OperatorOracleSelectionStrategy {
	#[default]
	First,
	RoundRobin,
	Random,
}

/// Direct settlement configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorDirectConfig {
	/// Dispute period duration in seconds.
	#[serde(default = "default_dispute_period_seconds")]
	pub dispute_period_seconds: u64,

	/// Oracle addresses for input and output verification.
	pub oracles: OperatorOracleConfig,

	/// Valid routes: source chain -> destination chains.
	pub routes: HashMap<u64, Vec<u64>>,

	/// Strategy for selecting an oracle.
	#[serde(default)]
	pub oracle_selection_strategy: OperatorOracleSelectionStrategy,

	/// Optional minimum required `expires` window (seconds) for accepting intents.
	#[serde(default)]
	pub intent_min_expiry_seconds: Option<u64>,
}

/// Broadcaster settlement configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorBroadcasterConfig {
	/// Oracle addresses for input and output verification.
	pub oracles: OperatorOracleConfig,

	/// Valid routes: source chain -> destination chains.
	pub routes: HashMap<u64, Vec<u64>>,

	/// Broadcaster contract addresses by destination chain ID.
	pub broadcaster_addresses: HashMap<u64, Address>,

	/// Receiver contract addresses by source chain ID.
	pub receiver_addresses: HashMap<u64, Address>,

	/// Broadcaster IDs by remote chain ID.
	pub broadcaster_ids: HashMap<u64, B256>,

	/// External proof service base URL.
	pub proof_service_url: String,

	/// Minimum delay after fill before trying to generate proofs.
	#[serde(default = "default_proof_wait_time_seconds")]
	pub proof_wait_time_seconds: u64,

	/// Timeout for proof service requests.
	#[serde(default = "default_storage_proof_timeout_seconds")]
	pub storage_proof_timeout_seconds: u64,

	/// Default finality blocks before proof generation.
	#[serde(default = "default_broadcaster_finality_blocks")]
	pub default_finality_blocks: u64,

	/// Per-chain finality block overrides.
	#[serde(default)]
	pub finality_blocks: HashMap<u64, u64>,

	/// Optional per-chain block time overrides in seconds (for intent admission budgeting).
	#[serde(default)]
	pub chain_block_time_seconds: HashMap<u64, u64>,

	/// Optional additional safety buffer in seconds (for intent admission budgeting).
	#[serde(default)]
	pub intent_safety_buffer_seconds: Option<u64>,

	/// Optional minimum required `expires` window (seconds) for accepting intents.
	#[serde(default)]
	pub intent_min_expiry_seconds: Option<u64>,

	/// Strategy for selecting an oracle.
	#[serde(default)]
	pub oracle_selection_strategy: OperatorOracleSelectionStrategy,
}

fn default_dispute_period_seconds() -> u64 {
	300
}

fn default_proof_wait_time_seconds() -> u64 {
	30
}

fn default_storage_proof_timeout_seconds() -> u64 {
	30
}

fn default_broadcaster_finality_blocks() -> u64 {
	20
}

/// Gas estimation settings per flow type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorGasConfig {
	/// Gas units for resource-lock flow.
	pub resource_lock: OperatorGasFlowUnits,

	/// Gas units for permit2 escrow flow.
	pub permit2_escrow: OperatorGasFlowUnits,

	/// Gas units for EIP-3009 escrow flow.
	pub eip3009_escrow: OperatorGasFlowUnits,
}

/// Gas units for each step in an order flow.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OperatorGasFlowUnits {
	/// Gas units for open/prepare step.
	pub open: u64,

	/// Gas units for fill step.
	pub fill: u64,

	/// Gas units for claim/finalize step.
	pub claim: u64,
}

/// Pricing provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorPricingConfig {
	/// Primary pricing provider (e.g., "coingecko", "defillama").
	pub primary: String,

	/// Fallback providers in order of preference.
	pub fallbacks: Vec<String>,

	/// Cache duration in seconds for price data.
	pub cache_duration_seconds: u64,

	/// Custom token prices in USD for tokens not on price feeds.
	/// Key is token symbol, value is price as decimal string.
	#[serde(default)]
	pub custom_prices: HashMap<String, String>,
}

/// Solver behavior settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorSolverConfig {
	/// Minimum profitability percentage required to execute orders.
	#[serde(with = "rust_decimal::serde::str")]
	pub min_profitability_pct: Decimal,

	/// Gas buffer in basis points (e.g., 1000 = 10%).
	/// Applied as safety margin on gas cost estimates.
	#[serde(default = "default_gas_buffer_bps")]
	pub gas_buffer_bps: u32,

	/// Commission in basis points (e.g., 20 = 0.20%).
	/// Added to solver profit requirement.
	#[serde(default = "default_commission_bps")]
	pub commission_bps: u32,

	/// Rate buffer in basis points (e.g., 14 = 0.14%).
	/// Applied to exchange rate to protect against price volatility.
	#[serde(default = "default_rate_buffer_bps")]
	pub rate_buffer_bps: u32,

	/// Timeout in seconds for monitoring transactions.
	pub monitoring_timeout_seconds: u64,
}

fn default_gas_buffer_bps() -> u32 {
	1000 // 10%
}

fn default_commission_bps() -> u32 {
	0 // Disabled by default for backward compatibility (was not used before)
}

fn default_rate_buffer_bps() -> u32 {
	14 // 0.14%
}

/// Admin authentication settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorAdminConfig {
	/// Whether admin authentication is enabled.
	pub enabled: bool,

	/// Domain for EIP-712 signature verification.
	pub domain: String,

	/// Chain ID for EIP-712 domain separator.
	pub chain_id: u64,

	/// Nonce TTL in seconds.
	pub nonce_ttl_seconds: u64,

	/// Authorized admin wallet addresses.
	pub admin_addresses: Vec<Address>,

	/// Withdrawal policy for admin-initiated transfers.
	#[serde(default)]
	pub withdrawals: OperatorWithdrawalsConfig,
}

/// Withdrawal policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OperatorWithdrawalsConfig {
	/// Whether withdrawals are enabled.
	#[serde(default)]
	pub enabled: bool,
}

impl OperatorConfig {
	/// Get a network configuration by chain ID.
	pub fn get_network(&self, chain_id: u64) -> Option<&OperatorNetworkConfig> {
		self.networks.get(&chain_id)
	}

	/// Get a mutable network configuration by chain ID.
	pub fn get_network_mut(&mut self, chain_id: u64) -> Option<&mut OperatorNetworkConfig> {
		self.networks.get_mut(&chain_id)
	}

	/// Get all chain IDs configured in this operator config.
	pub fn chain_ids(&self) -> Vec<u64> {
		self.networks.keys().copied().collect()
	}

	/// Check if an address is an authorized admin.
	pub fn is_admin(&self, address: &Address) -> bool {
		self.admin.enabled && self.admin.admin_addresses.contains(address)
	}
}

impl OperatorNetworkConfig {
	/// Find a token by symbol.
	pub fn get_token_by_symbol(&self, symbol: &str) -> Option<&OperatorToken> {
		self.tokens.iter().find(|t| t.symbol == symbol)
	}

	/// Find a token by address.
	pub fn get_token_by_address(&self, address: &Address) -> Option<&OperatorToken> {
		self.tokens.iter().find(|t| &t.address == address)
	}

	/// Check if a token exists by address.
	pub fn has_token(&self, address: &Address) -> bool {
		self.tokens.iter().any(|t| &t.address == address)
	}

	/// Get the primary HTTP RPC URL.
	pub fn get_http_url(&self) -> Option<&str> {
		self.rpc_urls.first().map(|r| r.http.as_str())
	}

	/// Get the primary WebSocket URL if available.
	pub fn get_ws_url(&self) -> Option<&str> {
		self.rpc_urls.iter().find_map(|r| r.ws.as_deref())
	}
}

impl OperatorAdminConfig {
	/// Check if admin authentication is enabled and address is authorized.
	pub fn is_authorized(&self, address: &Address) -> bool {
		self.enabled && self.admin_addresses.contains(address)
	}

	/// Add an admin address.
	pub fn add_admin(&mut self, address: Address) -> bool {
		if self.admin_addresses.contains(&address) {
			false
		} else {
			self.admin_addresses.push(address);
			true
		}
	}

	/// Remove an admin address.
	pub fn remove_admin(&mut self, address: &Address) -> bool {
		if let Some(pos) = self.admin_addresses.iter().position(|a| a == address) {
			self.admin_addresses.remove(pos);
			true
		} else {
			false
		}
	}
}

impl Default for OperatorAdminConfig {
	fn default() -> Self {
		Self {
			enabled: false,
			domain: String::new(),
			chain_id: 1,
			nonce_ttl_seconds: 300,
			admin_addresses: Vec::new(),
			withdrawals: OperatorWithdrawalsConfig::default(),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::str::FromStr;

	fn test_address() -> Address {
		Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap()
	}

	fn test_token_address() -> Address {
		Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap()
	}

	#[test]
	fn test_operator_token_serialization() {
		let token = OperatorToken {
			symbol: "USDC".to_string(),
			name: Some("USD Coin".to_string()),
			address: test_token_address(),
			decimals: 6,
		};

		let json = serde_json::to_string(&token).unwrap();
		let parsed: OperatorToken = serde_json::from_str(&json).unwrap();

		assert_eq!(parsed.symbol, "USDC");
		assert_eq!(parsed.name, Some("USD Coin".to_string()));
		assert_eq!(parsed.decimals, 6);
		assert_eq!(parsed.address, token.address);
	}

	#[test]
	fn test_operator_admin_config() {
		let mut admin = OperatorAdminConfig {
			enabled: true,
			domain: "test.example.com".to_string(),
			chain_id: 1,
			nonce_ttl_seconds: 300,
			admin_addresses: vec![test_address()],
			withdrawals: OperatorWithdrawalsConfig::default(),
		};

		assert!(admin.is_authorized(&test_address()));

		let other = Address::from_str("0x70997970C51812dc3A010C7d01b50e0d17dc79C8").unwrap();
		assert!(!admin.is_authorized(&other));

		// Add new admin
		assert!(admin.add_admin(other));
		assert!(admin.is_authorized(&other));

		// Can't add duplicate
		assert!(!admin.add_admin(other));

		// Remove admin
		assert!(admin.remove_admin(&other));
		assert!(!admin.is_authorized(&other));

		// Can't remove non-existent
		assert!(!admin.remove_admin(&other));
	}

	#[test]
	fn test_operator_network_config_tokens() {
		let network = OperatorNetworkConfig {
			chain_id: 10,
			name: "optimism".to_string(),
			network_type: NetworkType::Parent,
			tokens: vec![
				OperatorToken {
					symbol: "USDC".to_string(),
					name: Some("USD Coin".to_string()),
					address: test_token_address(),
					decimals: 6,
				},
				OperatorToken {
					symbol: "WETH".to_string(),
					name: Some("Wrapped Ether".to_string()),
					address: test_address(),
					decimals: 18,
				},
			],
			rpc_urls: vec![OperatorRpcEndpoint::http_only(
				"https://rpc.example.com".to_string(),
			)],
			input_settler_address: test_address(),
			output_settler_address: test_address(),
			input_settler_compact_address: None,
			the_compact_address: None,
			allocator_address: None,
		};

		assert!(network.get_token_by_symbol("USDC").is_some());
		assert!(network.get_token_by_symbol("DAI").is_none());

		assert!(network.has_token(&test_token_address()));
		assert!(!network
			.has_token(&Address::from_str("0x1111111111111111111111111111111111111111").unwrap()));

		assert_eq!(network.get_http_url(), Some("https://rpc.example.com"));
		assert_eq!(network.get_ws_url(), None);
	}

	#[test]
	fn test_rpc_endpoint() {
		let http_only = OperatorRpcEndpoint::http_only("https://rpc.example.com".to_string());
		assert_eq!(http_only.http, "https://rpc.example.com");
		assert!(http_only.ws.is_none());

		let with_ws = OperatorRpcEndpoint::with_ws(
			"https://rpc.example.com".to_string(),
			"wss://ws.example.com".to_string(),
		);
		assert_eq!(with_ws.http, "https://rpc.example.com");
		assert_eq!(with_ws.ws, Some("wss://ws.example.com".to_string()));
	}

	#[test]
	fn test_operator_config_json_roundtrip() {
		let config = OperatorConfig {
			solver_id: "test-solver".to_string(),
			solver_name: Some("Test Solver".to_string()),
			networks: {
				let mut networks = HashMap::new();
				networks.insert(
					10,
					OperatorNetworkConfig {
						chain_id: 10,
						name: "optimism".to_string(),
						network_type: NetworkType::Parent,
						tokens: vec![OperatorToken {
							symbol: "USDC".to_string(),
							name: Some("USD Coin".to_string()),
							address: test_token_address(),
							decimals: 6,
						}],
						rpc_urls: vec![OperatorRpcEndpoint::http_only(
							"https://rpc.example.com".to_string(),
						)],
						input_settler_address: test_address(),
						output_settler_address: test_address(),
						input_settler_compact_address: Some(test_address()),
						the_compact_address: Some(test_address()),
						allocator_address: Some(test_address()),
					},
				);
				networks
			},
			settlement: OperatorSettlementConfig {
				settlement_poll_interval_seconds: 10,
				settlement_type: OperatorSettlementType::Hyperlane,
				hyperlane: Some(OperatorHyperlaneConfig {
					default_gas_limit: 300_000,
					message_timeout_seconds: 600,
					finalization_required: true,
					mailboxes: HashMap::new(),
					igp_addresses: HashMap::new(),
					oracles: OperatorOracleConfig {
						input: HashMap::new(),
						output: HashMap::new(),
					},
					routes: HashMap::new(),
				}),
				direct: None,
				broadcaster: None,
			},
			gas: OperatorGasConfig {
				resource_lock: OperatorGasFlowUnits {
					open: 0,
					fill: 77298,
					claim: 122793,
				},
				permit2_escrow: OperatorGasFlowUnits::default(),
				eip3009_escrow: OperatorGasFlowUnits::default(),
			},
			pricing: OperatorPricingConfig {
				primary: "coingecko".to_string(),
				fallbacks: vec!["defillama".to_string()],
				cache_duration_seconds: 60,
				custom_prices: HashMap::new(),
			},
			solver: OperatorSolverConfig {
				min_profitability_pct: Decimal::ONE,
				gas_buffer_bps: 1000,
				commission_bps: 20,
				rate_buffer_bps: 14,
				monitoring_timeout_seconds: 28800,
			},
			admin: OperatorAdminConfig {
				enabled: true,
				domain: "test.example.com".to_string(),
				chain_id: 1,
				nonce_ttl_seconds: 300,
				admin_addresses: vec![test_address()],
				withdrawals: OperatorWithdrawalsConfig::default(),
			},
			auth_enabled: false,
			account: None,
		};

		let json = serde_json::to_string_pretty(&config).unwrap();
		let parsed: OperatorConfig = serde_json::from_str(&json).unwrap();

		assert_eq!(parsed.solver_id, "test-solver");
		assert_eq!(parsed.solver_name, Some("Test Solver".to_string()));
		assert_eq!(parsed.networks.len(), 1);
		assert!(parsed.networks.contains_key(&10));
		assert_eq!(parsed.admin.admin_addresses.len(), 1);
		assert_eq!(parsed.gas.resource_lock.fill, 77298);
		assert_eq!(
			parsed.settlement.settlement_type,
			OperatorSettlementType::Hyperlane
		);
		assert!(parsed.settlement.hyperlane.is_some());
		assert!(parsed.settlement.direct.is_none());
	}

	#[test]
	fn test_operator_config_deserializes_legacy_network_without_name() {
		let json = serde_json::json!({
			"solver_id": "legacy-solver",
			"networks": {
				"10": {
					"chain_id": 10,
					"tokens": [{
						"symbol": "USDC",
						"address": "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85",
						"decimals": 6
					}],
					"rpc_urls": [{
						"http": "https://rpc.example.com",
						"ws": null
					}],
					"input_settler_address": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
					"output_settler_address": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
					"input_settler_compact_address": null,
					"the_compact_address": null,
					"allocator_address": null
				}
			},
			"settlement": {
				"settlement_poll_interval_seconds": 10,
				"hyperlane": {
					"default_gas_limit": 300000,
					"message_timeout_seconds": 600,
					"finalization_required": true,
					"mailboxes": {},
					"igp_addresses": {},
					"oracles": {"input": {}, "output": {}},
					"routes": {}
				}
			},
			"gas": {
				"resource_lock": {"open": 0, "fill": 77298, "claim": 122793},
				"permit2_escrow": {"open": 0, "fill": 0, "claim": 0},
				"eip3009_escrow": {"open": 0, "fill": 0, "claim": 0}
			},
			"pricing": {
				"primary": "coingecko",
				"fallbacks": [],
				"cache_duration_seconds": 60,
				"custom_prices": {}
			},
			"solver": {
				"min_profitability_pct": "1",
				"gas_buffer_bps": 1000,
				"commission_bps": 0,
				"rate_buffer_bps": 14,
				"monitoring_timeout_seconds": 28800
			},
			"admin": {
				"enabled": false,
				"domain": "",
				"chain_id": 1,
				"nonce_ttl_seconds": 300,
				"admin_addresses": [],
				"withdrawals": {"enabled": false}
			},
			"account": null
		});

		let parsed: OperatorConfig = serde_json::from_value(json).unwrap();
		let network = parsed.networks.get(&10).unwrap();
		assert_eq!(network.name, "unknown");
		assert_eq!(network.network_type, NetworkType::New);
		assert_eq!(
			parsed.settlement.settlement_type,
			OperatorSettlementType::Hyperlane
		);
		assert!(parsed.settlement.hyperlane.is_some());
	}
}
