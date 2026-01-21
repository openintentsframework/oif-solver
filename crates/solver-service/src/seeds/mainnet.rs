//! Mainnet seed configuration.
//!
//! Contains hardcoded configuration for mainnet networks:
//! - Optimism (chain ID: 10)
//! - Base (chain ID: 8453)
//! - Arbitrum (chain ID: 42161)

use super::types::{NetworkSeed, SeedConfig, COMMON_DEFAULTS};
use alloy_primitives::address;

/// Mainnet seed configuration.
pub static MAINNET_SEED: SeedConfig = SeedConfig {
	networks: &[OPTIMISM, BASE, ARBITRUM],
	defaults: COMMON_DEFAULTS,
};

/// Optimism network seed (chain ID: 10).
pub static OPTIMISM: NetworkSeed = NetworkSeed {
	chain_id: 10,
	name: "optimism",
	default_rpc_urls: &["https://mainnet.optimism.io"],
	// Permit2/EIP-3009 escrow input settler
	input_settler: address!("2778258002a69a0cB1DfD29b360a0bB1654C8652"),
	// Output settler
	output_settler: address!("2404F8e3c37c002c89bA78086a119e68E3fF8824"),
	// Compact/resource-lock input settler
	input_settler_compact: address!("7dfFC9e7db5a96887666c1a6D215E5d3Fb306d69"),
	// The Compact contract
	the_compact: address!("00000000000000171ede64904551eedf3c6c9788"),
	// Allocator for compact flow
	allocator: address!("191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6"),
	// Hyperlane contracts
	hyperlane_mailbox: address!("d4C1905BB1D26BC93DAC913e13CaCC278CdCC80D"),
	hyperlane_igp: address!("D8A76C4D91fCbB7Cc8eA795DFDF870E48368995C"),
	hyperlane_oracle: address!("0b88D54A39F330Dd7e773af4806BDC490c79cAB6"),
};

/// Base network seed (chain ID: 8453).
pub static BASE: NetworkSeed = NetworkSeed {
	chain_id: 8453,
	name: "base",
	default_rpc_urls: &["https://mainnet.base.org"],
	// Permit2/EIP-3009 escrow input settler
	input_settler: address!("2778258002a69a0cB1DfD29b360a0bB1654C8652"),
	// Output settler
	output_settler: address!("2404F8e3c37c002c89bA78086a119e68E3fF8824"),
	// Compact/resource-lock input settler
	input_settler_compact: address!("7dfFC9e7db5a96887666c1a6D215E5d3Fb306d69"),
	// The Compact contract
	the_compact: address!("00000000000000171ede64904551eedf3c6c9788"),
	// Allocator for compact flow
	allocator: address!("191688B2Ff5Be8F0A5BCAB3E819C900a810FAaf6"),
	// Hyperlane contracts
	hyperlane_mailbox: address!("eA87ae93Fa0019a82A727bfd3eBd1cFCa8f64f1D"),
	hyperlane_igp: address!("c3F23848Ed2e04C0c6d41bd7804fa8f89F940B94"),
	hyperlane_oracle: address!("0b88D54A39F330Dd7e773af4806BDC490c79cAB6"),
};

/// Arbitrum network seed (chain ID: 42161).
pub static ARBITRUM: NetworkSeed = NetworkSeed {
	chain_id: 42161,
	name: "arbitrum",
	default_rpc_urls: &["https://arb1.arbitrum.io/rpc"],
	// Permit2/EIP-3009 escrow input settler
	input_settler: address!("79750615FD0c3DBE3bBCD7e8E7BDdCbB554b10a8"),
	// Output settler
	output_settler: address!("28E8D349d76bf9d553452bF6f02279196E7c5929"),
	// Compact/resource-lock input settler
	input_settler_compact: address!("CC4Ef1264489c40DcD674c7Fe6edf49cD2C40a6A"),
	// The Compact contract
	the_compact: address!("00000000000000171ede64904551eedf3c6c9788"),
	// Allocator for compact flow
	allocator: address!("b8Eb0f7851B4F5E44cFE21C856FAb5A6378AD280"),
	// Hyperlane contracts
	hyperlane_mailbox: address!("979Ca5202784112f4738403dBec5D0F3B9daabB9"),
	hyperlane_igp: address!("3b6044acd6767f017e99318AA6Ef93b7B06A5a22"),
	hyperlane_oracle: address!("0b88D54A39F330Dd7e773af4806BDC490c79cAB6"),
};

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_mainnet_seed_networks() {
		assert_eq!(MAINNET_SEED.networks.len(), 3);
	}

	#[test]
	fn test_optimism_chain_id() {
		assert_eq!(OPTIMISM.chain_id, 10);
		assert_eq!(OPTIMISM.name, "optimism");
	}

	#[test]
	fn test_base_chain_id() {
		assert_eq!(BASE.chain_id, 8453);
		assert_eq!(BASE.name, "base");
	}

	#[test]
	fn test_arbitrum_chain_id() {
		assert_eq!(ARBITRUM.chain_id, 42161);
		assert_eq!(ARBITRUM.name, "arbitrum");
	}

	#[test]
	fn test_get_network() {
		let optimism = MAINNET_SEED.get_network(10);
		assert!(optimism.is_some());
		assert_eq!(optimism.unwrap().name, "optimism");

		let base = MAINNET_SEED.get_network(8453);
		assert!(base.is_some());
		assert_eq!(base.unwrap().name, "base");

		let arbitrum = MAINNET_SEED.get_network(42161);
		assert!(arbitrum.is_some());
		assert_eq!(arbitrum.unwrap().name, "arbitrum");

		let unknown = MAINNET_SEED.get_network(1);
		assert!(unknown.is_none());
	}

	#[test]
	fn test_supported_chain_ids() {
		let chain_ids = MAINNET_SEED.supported_chain_ids();
		assert_eq!(chain_ids.len(), 3);
		assert!(chain_ids.contains(&10));
		assert!(chain_ids.contains(&8453));
		assert!(chain_ids.contains(&42161));
	}

	#[test]
	fn test_contract_addresses_not_zero() {
		// Verify all addresses are not zero address
		let zero = address!("0000000000000000000000000000000000000000");

		// Optimism
		assert_ne!(OPTIMISM.input_settler, zero);
		assert_ne!(OPTIMISM.output_settler, zero);
		assert_ne!(OPTIMISM.input_settler_compact, zero);
		assert_ne!(OPTIMISM.the_compact, zero);
		assert_ne!(OPTIMISM.allocator, zero);
		assert_ne!(OPTIMISM.hyperlane_mailbox, zero);
		assert_ne!(OPTIMISM.hyperlane_igp, zero);
		assert_ne!(OPTIMISM.hyperlane_oracle, zero);

		// Base
		assert_ne!(BASE.input_settler, zero);
		assert_ne!(BASE.output_settler, zero);
		assert_ne!(BASE.input_settler_compact, zero);
		assert_ne!(BASE.the_compact, zero);
		assert_ne!(BASE.allocator, zero);
		assert_ne!(BASE.hyperlane_mailbox, zero);
		assert_ne!(BASE.hyperlane_igp, zero);
		assert_ne!(BASE.hyperlane_oracle, zero);

		// Arbitrum
		assert_ne!(ARBITRUM.input_settler, zero);
		assert_ne!(ARBITRUM.output_settler, zero);
		assert_ne!(ARBITRUM.input_settler_compact, zero);
		assert_ne!(ARBITRUM.the_compact, zero);
		assert_ne!(ARBITRUM.allocator, zero);
		assert_ne!(ARBITRUM.hyperlane_mailbox, zero);
		assert_ne!(ARBITRUM.hyperlane_igp, zero);
		assert_ne!(ARBITRUM.hyperlane_oracle, zero);
	}

	#[test]
	fn test_the_compact_same_across_networks() {
		// The Compact should be the same address across all networks
		assert_eq!(OPTIMISM.the_compact, BASE.the_compact);
		assert_eq!(BASE.the_compact, ARBITRUM.the_compact);
	}

	#[test]
	fn test_hyperlane_oracle_same_on_mainnet() {
		// On mainnet, all networks share the same Hyperlane oracle
		assert_eq!(OPTIMISM.hyperlane_oracle, BASE.hyperlane_oracle);
		assert_eq!(BASE.hyperlane_oracle, ARBITRUM.hyperlane_oracle);
	}

	#[test]
	fn test_settler_addresses_same_on_optimism_and_base() {
		// Optimism and Base share the same settler addresses
		assert_eq!(OPTIMISM.input_settler, BASE.input_settler);
		assert_eq!(OPTIMISM.output_settler, BASE.output_settler);
		assert_eq!(OPTIMISM.input_settler_compact, BASE.input_settler_compact);
		assert_eq!(OPTIMISM.allocator, BASE.allocator);
	}
}
