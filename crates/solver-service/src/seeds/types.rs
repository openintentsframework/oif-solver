//! Seed type definitions for hardcoded configuration values.
//!
//! These types define the structure of seed data that contains all the
//! contract addresses, Hyperlane configuration, and default settings
//! that are combined with user-provided deployment configuration.

use alloy_primitives::Address;
use rust_decimal::Decimal;

/// Hardcoded seed configuration for a preset (mainnet, testnet).
///
/// Contains all the network configurations and default settings
/// that don't change between deployments.
#[derive(Debug, Clone)]
pub struct SeedConfig {
	/// Network-specific seed data.
	pub networks: &'static [NetworkSeed],
	/// Default configuration values.
	pub defaults: SeedDefaults,
}

impl SeedConfig {
	/// Get the network seed for a specific chain ID.
	pub fn get_network(&self, chain_id: u64) -> Option<&NetworkSeed> {
		self.networks.iter().find(|n| n.chain_id == chain_id)
	}

	/// Get all supported chain IDs.
	pub fn supported_chain_ids(&self) -> Vec<u64> {
		self.networks.iter().map(|n| n.chain_id).collect()
	}

	/// Check if a chain ID is supported.
	pub fn supports_chain(&self, chain_id: u64) -> bool {
		self.networks.iter().any(|n| n.chain_id == chain_id)
	}

	/// Get all networks that are selected from a list of chain IDs.
	pub fn get_networks(&self, chain_ids: &[u64]) -> Vec<&NetworkSeed> {
		chain_ids
			.iter()
			.filter_map(|id| self.get_network(*id))
			.collect()
	}
}

/// Per-network seed data containing hardcoded contract addresses and settings.
#[derive(Debug, Clone, Copy)]
pub struct NetworkSeed {
	/// Chain ID (e.g., 10 for Optimism, 8453 for Base).
	pub chain_id: u64,
	/// Human-readable network name (e.g., "optimism", "base").
	pub name: &'static str,
	/// Default public RPC URLs for fallback.
	pub default_rpc_urls: &'static [&'static str],
	/// Input settler contract address (permit2/EIP-3009 escrow).
	pub input_settler: Address,
	/// Output settler contract address.
	pub output_settler: Address,
	/// Input settler address for compact/resource-lock flow.
	pub input_settler_compact: Address,
	/// The Compact contract address.
	pub the_compact: Address,
	/// Allocator contract address for compact flow.
	pub allocator: Address,
	/// Hyperlane mailbox contract address.
	pub hyperlane_mailbox: Address,
	/// Hyperlane IGP (Interchain Gas Paymaster) address.
	pub hyperlane_igp: Address,
	/// Hyperlane oracle contract address.
	pub hyperlane_oracle: Address,
}

/// Default configuration values used across all solvers.
///
/// These are the standard implementation settings that don't
/// depend on the specific networks or tokens being used.
#[derive(Debug, Clone)]
pub struct SeedDefaults {
	// Solver settings
	/// Minimum profitability percentage required to execute orders.
	pub min_profitability_pct: Decimal,
	/// Commission in basis points (e.g., 20 = 0.20%).
	pub commission_bps: u32,
	/// Rate buffer in basis points (e.g., 14 = 0.14%).
	pub rate_buffer_bps: u32,
	/// Timeout in seconds for monitoring transactions.
	pub monitoring_timeout_seconds: u64,

	// Storage settings
	/// Primary storage implementation name.
	pub storage_primary: &'static str,
	/// Storage cleanup interval in seconds.
	pub cleanup_interval_seconds: u64,

	// Account settings
	/// Primary account implementation name.
	pub account_primary: &'static str,

	// Delivery settings
	/// Minimum confirmations required for transactions.
	pub min_confirmations: u64,

	// Discovery settings
	/// Polling interval for discovery in seconds.
	pub polling_interval_secs: u64,

	// Order settings
	/// Primary order strategy implementation name.
	pub order_strategy_primary: &'static str,
	/// Maximum gas price in gwei.
	pub max_gas_price_gwei: u64,
	/// Whether to simulate callbacks before filling.
	pub simulate_callbacks: bool,

	// Pricing settings
	/// Primary pricing implementation name.
	pub pricing_primary: &'static str,
	/// Fallback pricing implementations.
	pub pricing_fallbacks: &'static [&'static str],
	/// Pricing cache duration in seconds.
	pub cache_duration_seconds: u64,

	// Settlement settings
	/// Settlement poll interval in seconds.
	pub settlement_poll_interval_seconds: u64,
	/// Default Hyperlane gas limit.
	pub hyperlane_default_gas_limit: u64,
	/// Hyperlane message timeout in seconds.
	pub hyperlane_message_timeout_seconds: u64,
	/// Whether Hyperlane finalization is required.
	pub hyperlane_finalization_required: bool,

	// Gas flow settings
	/// Gas units for resource-lock flow.
	pub gas_resource_lock: GasFlowUnits,
	/// Gas units for permit2 escrow flow.
	pub gas_permit2_escrow: GasFlowUnits,
	/// Gas units for EIP-3009 escrow flow.
	pub gas_eip3009_escrow: GasFlowUnits,
}

/// Gas unit configuration for a specific order flow.
#[derive(Debug, Clone, Copy)]
pub struct GasFlowUnits {
	/// Gas units for open/prepare step.
	pub open: u64,
	/// Gas units for fill step.
	pub fill: u64,
	/// Gas units for claim/finalize step.
	pub claim: u64,
}

/// Common defaults shared between mainnet and testnet.
pub const COMMON_DEFAULTS: SeedDefaults = SeedDefaults {
	// Solver
	min_profitability_pct: Decimal::ONE,
	commission_bps: 0, // Disabled by default for backward compatibility
	rate_buffer_bps: 14,
	monitoring_timeout_seconds: 28800, // 8 hours

	// Storage
	storage_primary: "redis",
	cleanup_interval_seconds: 3600, // 1 hour

	// Account
	account_primary: "local",

	// Delivery
	min_confirmations: 3,

	// Discovery
	polling_interval_secs: 5,

	// Order
	order_strategy_primary: "simple",
	max_gas_price_gwei: 100,
	simulate_callbacks: true,

	// Pricing
	pricing_primary: "coingecko",
	pricing_fallbacks: &["defillama"],
	cache_duration_seconds: 60,

	// Settlement
	settlement_poll_interval_seconds: 10,
	hyperlane_default_gas_limit: 300_000,
	hyperlane_message_timeout_seconds: 600, // 10 minutes
	hyperlane_finalization_required: true,

	// Gas flows
	gas_resource_lock: GasFlowUnits {
		open: 0,
		fill: 77298,
		claim: 122793,
	},
	gas_permit2_escrow: GasFlowUnits {
		open: 146306,
		fill: 77298,
		claim: 60084,
	},
	gas_eip3009_escrow: GasFlowUnits {
		open: 130254,
		fill: 77298,
		claim: 60084,
	},
};

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::address;

	// Static test networks for testing SeedConfig methods
	static TEST_NETWORK_1: NetworkSeed = NetworkSeed {
		chain_id: 1,
		name: "test1",
		default_rpc_urls: &["https://rpc1.example.com"],
		input_settler: address!("1111111111111111111111111111111111111111"),
		output_settler: address!("2222222222222222222222222222222222222222"),
		input_settler_compact: address!("3333333333333333333333333333333333333333"),
		the_compact: address!("4444444444444444444444444444444444444444"),
		allocator: address!("5555555555555555555555555555555555555555"),
		hyperlane_mailbox: address!("6666666666666666666666666666666666666666"),
		hyperlane_igp: address!("7777777777777777777777777777777777777777"),
		hyperlane_oracle: address!("8888888888888888888888888888888888888888"),
	};

	static TEST_NETWORK_2: NetworkSeed = NetworkSeed {
		chain_id: 2,
		name: "test2",
		default_rpc_urls: &["https://rpc2.example.com"],
		input_settler: address!("1111111111111111111111111111111111111111"),
		output_settler: address!("2222222222222222222222222222222222222222"),
		input_settler_compact: address!("3333333333333333333333333333333333333333"),
		the_compact: address!("4444444444444444444444444444444444444444"),
		allocator: address!("5555555555555555555555555555555555555555"),
		hyperlane_mailbox: address!("9999999999999999999999999999999999999999"),
		hyperlane_igp: address!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		hyperlane_oracle: address!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
	};

	static TEST_SEED: SeedConfig = SeedConfig {
		networks: &[TEST_NETWORK_1, TEST_NETWORK_2],
		defaults: COMMON_DEFAULTS,
	};

	#[test]
	fn test_get_network() {
		let network = TEST_SEED.get_network(1);
		assert!(network.is_some());
		assert_eq!(network.unwrap().name, "test1");

		let network = TEST_SEED.get_network(2);
		assert!(network.is_some());
		assert_eq!(network.unwrap().name, "test2");

		let network = TEST_SEED.get_network(999);
		assert!(network.is_none());
	}

	#[test]
	fn test_supported_chain_ids() {
		let chain_ids = TEST_SEED.supported_chain_ids();

		assert_eq!(chain_ids.len(), 2);
		assert!(chain_ids.contains(&1));
		assert!(chain_ids.contains(&2));
	}

	#[test]
	fn test_supports_chain() {
		assert!(TEST_SEED.supports_chain(1));
		assert!(TEST_SEED.supports_chain(2));
		assert!(!TEST_SEED.supports_chain(999));
	}

	#[test]
	fn test_get_networks() {
		let networks = TEST_SEED.get_networks(&[1, 2]);
		assert_eq!(networks.len(), 2);

		let networks = TEST_SEED.get_networks(&[1]);
		assert_eq!(networks.len(), 1);

		let networks = TEST_SEED.get_networks(&[999]);
		assert_eq!(networks.len(), 0);

		let networks = TEST_SEED.get_networks(&[1, 999]);
		assert_eq!(networks.len(), 1);
	}

	#[test]
	fn test_common_defaults() {
		assert_eq!(COMMON_DEFAULTS.storage_primary, "redis");
		assert_eq!(COMMON_DEFAULTS.min_confirmations, 3);
		assert_eq!(COMMON_DEFAULTS.hyperlane_default_gas_limit, 300_000);
	}

	#[test]
	fn test_gas_flow_units() {
		assert_eq!(COMMON_DEFAULTS.gas_resource_lock.open, 0);
		assert_eq!(COMMON_DEFAULTS.gas_resource_lock.fill, 77298);
		assert_eq!(COMMON_DEFAULTS.gas_resource_lock.claim, 122793);

		assert_eq!(COMMON_DEFAULTS.gas_permit2_escrow.open, 146306);
		assert_eq!(COMMON_DEFAULTS.gas_permit2_escrow.fill, 77298);
		assert_eq!(COMMON_DEFAULTS.gas_permit2_escrow.claim, 60084);
	}
}
