//! Testnet seed configuration.
//!
//! Contains hardcoded configuration for testnet networks:
//! - Optimism Sepolia (chain ID: 11155420)
//! - Base Sepolia (chain ID: 84532)

use super::types::{NetworkSeed, SeedConfig, COMMON_DEFAULTS};
use alloy_primitives::address;

/// Testnet seed configuration.
pub static TESTNET_SEED: SeedConfig = SeedConfig {
    networks: &[OPTIMISM_SEPOLIA, BASE_SEPOLIA],
    defaults: COMMON_DEFAULTS,
};

/// Optimism Sepolia network seed (chain ID: 11155420).
pub static OPTIMISM_SEPOLIA: NetworkSeed = NetworkSeed {
    chain_id: 11155420,
    name: "optimism-sepolia",
    default_rpc_urls: &["https://sepolia.optimism.io"],
    // Permit2/EIP-3009 escrow input settler
    input_settler: address!("1F0b9d6984f5f9187Db70469085f7935453b815F"),
    // Output settler
    output_settler: address!("923aa6CC898540092616f97cA770FFb8080354Fc"),
    // Compact/resource-lock input settler
    input_settler_compact: address!("086e28545bB8494C6041225922A705877AE5362A"),
    // The Compact contract
    the_compact: address!("00000000000000171ede64904551eedf3c6c9788"),
    // Allocator for compact flow
    allocator: address!("565466528d126141ddb5c7d558803f79d9b66a6d"),
    // Hyperlane contracts
    hyperlane_mailbox: address!("6966b0E55883d49BFB24539356a2f8A673E02039"),
    hyperlane_igp: address!("28B02B97a850872C4D33C3E024fab6499ad96564"),
    hyperlane_oracle: address!("c8604e4aBC757C5C1990BAe679A7b219808EDc9c"),
};

/// Base Sepolia network seed (chain ID: 84532).
pub static BASE_SEPOLIA: NetworkSeed = NetworkSeed {
    chain_id: 84532,
    name: "base-sepolia",
    default_rpc_urls: &["https://sepolia.base.org"],
    // Permit2/EIP-3009 escrow input settler
    input_settler: address!("6C0428cc521CC418A8842d46d413F5F96775c67B"),
    // Output settler
    output_settler: address!("C450A11afb68731833BE13225A88ecdad7D7Ed52"),
    // Compact/resource-lock input settler
    input_settler_compact: address!("a7B995442F909849F96B5ED07ff7f58E57a41fc9"),
    // The Compact contract
    the_compact: address!("00000000000000171ede64904551eedf3c6c9788"),
    // Allocator for compact flow
    allocator: address!("04bb6e565f0067e0411528e2d3a55a712d9a8b32"),
    // Hyperlane contracts
    hyperlane_mailbox: address!("6966b0E55883d49BFB24539356a2f8A673E02039"),
    hyperlane_igp: address!("28B02B97a850872C4D33C3E024fab6499ad96564"),
    hyperlane_oracle: address!("3f1ED0CEf17842C8cD47CcbaDf534eaB6BEf5d46"),
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_testnet_seed_networks() {
        assert_eq!(TESTNET_SEED.networks.len(), 2);
    }

    #[test]
    fn test_optimism_sepolia_chain_id() {
        assert_eq!(OPTIMISM_SEPOLIA.chain_id, 11155420);
        assert_eq!(OPTIMISM_SEPOLIA.name, "optimism-sepolia");
    }

    #[test]
    fn test_base_sepolia_chain_id() {
        assert_eq!(BASE_SEPOLIA.chain_id, 84532);
        assert_eq!(BASE_SEPOLIA.name, "base-sepolia");
    }

    #[test]
    fn test_get_network() {
        let optimism = TESTNET_SEED.get_network(11155420);
        assert!(optimism.is_some());
        assert_eq!(optimism.unwrap().name, "optimism-sepolia");

        let base = TESTNET_SEED.get_network(84532);
        assert!(base.is_some());
        assert_eq!(base.unwrap().name, "base-sepolia");

        let unknown = TESTNET_SEED.get_network(1);
        assert!(unknown.is_none());
    }

    #[test]
    fn test_supported_chain_ids() {
        let chain_ids = TESTNET_SEED.supported_chain_ids();
        assert_eq!(chain_ids.len(), 2);
        assert!(chain_ids.contains(&11155420));
        assert!(chain_ids.contains(&84532));
    }

    #[test]
    fn test_contract_addresses_not_zero() {
        // Verify all addresses are not zero address
        let zero = address!("0000000000000000000000000000000000000000");

        // Optimism Sepolia
        assert_ne!(OPTIMISM_SEPOLIA.input_settler, zero);
        assert_ne!(OPTIMISM_SEPOLIA.output_settler, zero);
        assert_ne!(OPTIMISM_SEPOLIA.input_settler_compact, zero);
        assert_ne!(OPTIMISM_SEPOLIA.the_compact, zero);
        assert_ne!(OPTIMISM_SEPOLIA.allocator, zero);
        assert_ne!(OPTIMISM_SEPOLIA.hyperlane_mailbox, zero);
        assert_ne!(OPTIMISM_SEPOLIA.hyperlane_igp, zero);
        assert_ne!(OPTIMISM_SEPOLIA.hyperlane_oracle, zero);

        // Base Sepolia
        assert_ne!(BASE_SEPOLIA.input_settler, zero);
        assert_ne!(BASE_SEPOLIA.output_settler, zero);
        assert_ne!(BASE_SEPOLIA.input_settler_compact, zero);
        assert_ne!(BASE_SEPOLIA.the_compact, zero);
        assert_ne!(BASE_SEPOLIA.allocator, zero);
        assert_ne!(BASE_SEPOLIA.hyperlane_mailbox, zero);
        assert_ne!(BASE_SEPOLIA.hyperlane_igp, zero);
        assert_ne!(BASE_SEPOLIA.hyperlane_oracle, zero);
    }

    #[test]
    fn test_the_compact_same_across_networks() {
        // The Compact should be the same address across all networks
        assert_eq!(OPTIMISM_SEPOLIA.the_compact, BASE_SEPOLIA.the_compact);
    }

    #[test]
    fn test_hyperlane_mailbox_same_on_testnet() {
        // On testnets, mailbox addresses may be the same
        assert_eq!(
            OPTIMISM_SEPOLIA.hyperlane_mailbox,
            BASE_SEPOLIA.hyperlane_mailbox
        );
    }
}
