//! Protocol and token registry for managing capabilities.
//!
//! Centralizes knowledge about protocol deployments and token capabilities
//! to avoid duplication and make it easy to add new chains/tokens.

use alloy_primitives::Address;
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet};

/// Global protocol registry instance
pub static PROTOCOL_REGISTRY: Lazy<ProtocolRegistry> = Lazy::new(ProtocolRegistry::default);

/// Registry for protocol deployments and token capabilities
#[derive(Debug, Clone)]
pub struct ProtocolRegistry {
	/// Permit2 deployment addresses by chain ID
	permit2_deployments: HashMap<u64, Address>,
	/// EIP-3009 capable tokens by chain ID
	eip3009_tokens: HashMap<u64, HashSet<Address>>,
}

impl Default for ProtocolRegistry {
	fn default() -> Self {
		let mut registry = Self {
			permit2_deployments: HashMap::new(),
			eip3009_tokens: HashMap::new(),
		};

		// Configure Permit2 deployments (using canonical address for most chains)
		const PERMIT2_CANONICAL: &str = "0x000000000022D473030F116dDEE9F6B43aC78BA3";

		// Standard deployments at canonical address
		registry.add_permit2_deployment(1, PERMIT2_CANONICAL); // Ethereum Mainnet
		registry.add_permit2_deployment(137, PERMIT2_CANONICAL); // Polygon
		registry.add_permit2_deployment(42161, PERMIT2_CANONICAL); // Arbitrum One
		registry.add_permit2_deployment(10, PERMIT2_CANONICAL); // Optimism
		registry.add_permit2_deployment(8453, PERMIT2_CANONICAL); // Base
		registry.add_permit2_deployment(31337, PERMIT2_CANONICAL); // Local Anvil
		registry.add_permit2_deployment(31338, PERMIT2_CANONICAL); // Local Anvil secondary

		// Testnet deployments
		registry.add_permit2_deployment(84532, PERMIT2_CANONICAL); // Base Sepolia
		registry.add_permit2_deployment(421614, PERMIT2_CANONICAL); // Arbitrum Sepolia
		registry.add_permit2_deployment(11155111, PERMIT2_CANONICAL); // Ethereum Sepolia
		registry.add_permit2_deployment(11155420, PERMIT2_CANONICAL); // Optimism Sepolia

		// Configure EIP-3009 tokens (USDC on various chains)
		registry.add_eip3009_token(1, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"); // Mainnet USDC
		registry.add_eip3009_token(137, "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359"); // Polygon native USDC
		registry.add_eip3009_token(42161, "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"); // Arbitrum native USDC
		registry.add_eip3009_token(10, "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85"); // Optimism native USDC
		registry.add_eip3009_token(8453, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"); // Base USDC

		// Testnet USDC tokens
		registry.add_eip3009_token(84532, "0x036CbD53842c5426634e7929541eC2318f3dCF7e"); // Base Sepolia USDC
		registry.add_eip3009_token(421614, "0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d"); // Arbitrum Sepolia USDC
		registry.add_eip3009_token(11155111, "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"); // Ethereum Sepolia USDC
		registry.add_eip3009_token(11155420, "0x5fd84259d66Cd46123540766Be93DFE6D43130D7"); // Optimism Sepolia USDC

		// Configure test tokens for demo/development (both chains 31337 and 31338)
		registry.add_eip3009_token(31337, "0x5FbDB2315678afecb367f032d93F642f64180aa3"); // Demo TOKA chain 31337
		registry.add_eip3009_token(31337, "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"); // Demo TOKB chain 31337
		registry.add_eip3009_token(31338, "0x5FbDB2315678afecb367f032d93F642f64180aa3"); // Demo TOKA chain 31338
		registry.add_eip3009_token(31338, "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"); // Demo TOKB chain 31338
		registry
	}
}

impl ProtocolRegistry {
	/// Adds a Permit2 deployment for a specific chain
	pub fn add_permit2_deployment(&mut self, chain_id: u64, permit2_address: &str) {
		let address = permit2_address
			.parse()
			.unwrap_or_else(|_| panic!("Valid Permit2 address: {}", permit2_address));

		self.permit2_deployments.insert(chain_id, address);
	}

	/// Adds an EIP-3009 capable token
	pub fn add_eip3009_token(&mut self, chain_id: u64, token_address: &str) {
		let address = token_address
			.parse()
			.unwrap_or_else(|_| panic!("Valid token address: {}", token_address));

		self.eip3009_tokens
			.entry(chain_id)
			.or_default()
			.insert(address);
	}

	/// Checks if Permit2 is available on a specific chain
	pub fn supports_permit2(&self, chain_id: u64) -> bool {
		self.permit2_deployments.contains_key(&chain_id)
	}

	/// Gets the Permit2 address if available on the chain
	pub fn get_permit2_address(&self, chain_id: u64) -> Option<Address> {
		self.permit2_deployments.get(&chain_id).copied()
	}

	/// Checks if a token supports EIP-3009
	pub fn supports_eip3009(&self, chain_id: u64, token_address: Address) -> bool {
		self.eip3009_tokens
			.get(&chain_id)
			.map(|tokens| tokens.contains(&token_address))
			.unwrap_or(false)
	}

	#[allow(dead_code)]
	/// Gets all EIP-3009 tokens for a specific chain
	pub fn get_eip3009_tokens(&self, chain_id: u64) -> Option<&HashSet<Address>> {
		self.eip3009_tokens.get(&chain_id)
	}

	/// Gets complete token capabilities
	pub fn get_token_capabilities(
		&self,
		chain_id: u64,
		token_address: Address,
	) -> TokenCapabilities {
		TokenCapabilities {
			supports_eip3009: self.supports_eip3009(chain_id, token_address),
			permit2_available: self.supports_permit2(chain_id),
		}
	}
}

/// Token capabilities for deposit/settlement decisions
#[derive(Debug, Clone)]
pub struct TokenCapabilities {
	pub supports_eip3009: bool,
	pub permit2_available: bool,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_permit2_availability() {
		let registry = ProtocolRegistry::default();

		assert!(registry.supports_permit2(1)); // Mainnet
		assert!(registry.supports_permit2(137)); // Polygon
		assert!(!registry.supports_permit2(999)); // Unknown chain
	}

	#[test]
	fn test_eip3009_support() {
		let registry = ProtocolRegistry::default();

		// Test mainnet USDC
		let usdc_mainnet: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
			.parse()
			.unwrap();
		assert!(registry.supports_eip3009(1, usdc_mainnet));

		// Test demo tokens (TOKA and TOKB) on test chains
		let demo_toka: Address = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
			.parse()
			.unwrap();
		let demo_tokb: Address = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"
			.parse()
			.unwrap();

		assert!(registry.supports_eip3009(31337, demo_toka)); // TOKA on chain 31337
		assert!(registry.supports_eip3009(31337, demo_tokb)); // TOKB on chain 31337
		assert!(registry.supports_eip3009(31338, demo_toka)); // TOKA on chain 31338
		assert!(registry.supports_eip3009(31338, demo_tokb)); // TOKB on chain 31338

		// Test random token
		let random_token: Address = "0x0000000000000000000000000000000000000000"
			.parse()
			.unwrap();
		assert!(!registry.supports_eip3009(1, random_token));
		assert!(!registry.supports_eip3009(31337, random_token)); // Random token shouldn't be supported
	}
}
