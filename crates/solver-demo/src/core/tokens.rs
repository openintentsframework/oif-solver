//! Token registry and information management
//!
//! This module provides token-related functionality including token information
//! storage, decimal conversions, and registry management for tokens across
//! different blockchain networks. Supports configuration-based token loading.

use crate::types::{
	chain::ChainId,
	error::{Error, Result},
};
use alloy_primitives::Address;
use std::collections::HashMap;

use super::config::Config;

/// Token metadata and decimal conversion utilities
///
/// Contains essential information about a token including its symbol, address,
/// decimal places, and blockchain network. Provides methods for converting
/// between human-readable amounts and wei values.
#[derive(Debug, Clone)]
pub struct TokenInfo {
	pub symbol: String,
	pub address: Address,
	pub decimals: u8,
	pub chain: ChainId,
}

impl TokenInfo {
	/// Convert human-readable token amount to wei using token decimals
	///
	/// # Arguments
	/// * `amount` - Token amount in human-readable decimal format
	///
	/// # Returns
	/// Amount converted to wei as U256
	pub fn to_wei(&self, amount: f64) -> alloy_primitives::U256 {
		let decimals_multiplier = 10_u128.pow(self.decimals as u32);
		let amount_wei = (amount * decimals_multiplier as f64) as u128;
		alloy_primitives::U256::from(amount_wei)
	}

	/// Convert wei amount to human-readable token units using token decimals
	///
	/// # Arguments
	/// * `amount_wei` - Amount in wei as U256
	///
	/// # Returns
	/// Amount converted to human-readable decimal format as f64
	pub fn from_wei(&self, amount_wei: alloy_primitives::U256) -> f64 {
		let decimals_divisor = 10_f64.powi(self.decimals as i32);
		amount_wei.to::<u128>() as f64 / decimals_divisor
	}
}

/// Centralized token information storage and retrieval system
///
/// Manages token metadata across multiple blockchain networks with efficient
/// lookup capabilities by symbol or address. Provides case-insensitive symbol
/// matching and chain-specific filtering for token discovery operations.
#[derive(Debug, Clone, Default)]
pub struct TokenRegistry {
	tokens: HashMap<(ChainId, String), TokenInfo>,
}

impl TokenRegistry {
	/// Create empty token registry instance
	///
	/// # Returns
	/// New TokenRegistry with no registered tokens
	pub fn new() -> Self {
		Self {
			tokens: HashMap::new(),
		}
	}

	/// Build token registry from configuration file data
	///
	/// Extracts token information from all configured networks and populates
	/// the registry with converted address formats and metadata
	///
	/// # Arguments
	/// * `config` - Configuration containing network and token definitions
	///
	/// # Returns
	/// Populated TokenRegistry with all configured tokens
	///
	/// # Errors
	/// Returns Error if token address conversion fails or configuration is invalid
	pub fn from_config(config: &Config) -> Result<Self> {
		let mut registry = Self::new();

		// Extract tokens from network configs
		for chain in config.chains() {
			if let Some(network) = config.network(chain) {
				for token in &network.tokens {
					use alloy_primitives::Address as AlloyAddress;

					// Convert solver-types Address (Vec<u8>) to alloy Address
					let addr_bytes: [u8; 20] =
						token.address.0.as_slice().try_into().map_err(|_| {
							Error::InvalidAddress(format!("Invalid address for {}", token.symbol))
						})?;

					let info = TokenInfo {
						symbol: token.symbol.clone(),
						address: AlloyAddress::from(addr_bytes),
						decimals: token.decimals,
						chain,
					};

					registry.register(info);
				}
			}
		}

		Ok(registry)
	}

	/// Add token information to the registry
	///
	/// Stores token metadata using uppercase symbol and chain ID as key
	/// for case-insensitive lookups
	///
	/// # Arguments
	/// * `info` - Token information including symbol, address, decimals, and chain
	pub fn register(&mut self, info: TokenInfo) {
		let key = (info.chain, info.symbol.to_uppercase());
		self.tokens.insert(key, info);
	}

	/// Retrieve token information by symbol and blockchain network
	///
	/// Performs case-insensitive symbol matching for user convenience
	///
	/// # Arguments
	/// * `chain` - Target blockchain network identifier
	/// * `symbol` - Token symbol to search for
	///
	/// # Returns
	/// Optional reference to TokenInfo if found, None otherwise
	pub fn get(&self, chain: ChainId, symbol: &str) -> Option<&TokenInfo> {
		self.tokens.get(&(chain, symbol.to_uppercase()))
	}

	/// Retrieve token information by contract address and blockchain network
	///
	/// Searches through all registered tokens to find matching address and chain
	///
	/// # Arguments
	/// * `chain` - Target blockchain network identifier
	/// * `address` - Token contract address to search for
	///
	/// # Returns
	/// Optional reference to TokenInfo if found, None otherwise
	pub fn get_by_address(&self, chain: ChainId, address: Address) -> Option<&TokenInfo> {
		self.tokens
			.values()
			.find(|t| t.chain == chain && t.address == address)
	}

	/// Retrieve all registered tokens for a specific blockchain network
	///
	/// Filters the token registry to return only tokens deployed on the specified chain
	///
	/// # Arguments
	/// * `chain` - Target blockchain network identifier
	///
	/// # Returns
	/// Vector of TokenInfo references for all tokens on the specified chain
	pub fn tokens_for_chain(&self, chain: ChainId) -> Vec<&TokenInfo> {
		self.tokens.values().filter(|t| t.chain == chain).collect()
	}

	/// Retrieve list of all blockchain networks with registered tokens
	///
	/// Extracts unique chain identifiers from registered tokens and returns
	/// them in sorted order by chain ID
	///
	/// # Returns
	/// Vector of ChainId instances sorted by chain ID, with duplicates removed
	pub fn chains(&self) -> Vec<ChainId> {
		let mut chains: Vec<ChainId> = self.tokens.keys().map(|(chain, _)| *chain).collect();
		chains.sort_by_key(|c| c.id());
		chains.dedup();
		chains
	}

	/// Verify if a token is registered for the specified chain and symbol
	///
	/// Performs case-insensitive symbol matching for convenience
	///
	/// # Arguments
	/// * `chain` - Target blockchain network identifier
	/// * `symbol` - Token symbol to check for existence
	///
	/// # Returns
	/// True if token is registered, false otherwise
	pub fn exists(&self, chain: ChainId, symbol: &str) -> bool {
		self.tokens.contains_key(&(chain, symbol.to_uppercase()))
	}

	/// Retrieve token information with error handling for missing tokens
	///
	/// Convenience method that returns a descriptive error instead of None
	/// when the requested token is not found
	///
	/// # Arguments
	/// * `chain` - Target blockchain network identifier
	/// * `symbol` - Token symbol to retrieve
	///
	/// # Returns
	/// Reference to TokenInfo if found
	///
	/// # Errors
	/// Returns TokenNotFound error if token is not registered
	pub fn get_or_error(&self, chain: ChainId, symbol: &str) -> Result<&TokenInfo> {
		self.get(chain, symbol)
			.ok_or_else(|| Error::TokenNotFound(symbol.to_string(), chain.id()))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::types::hex::Hex;

	#[test]
	fn test_token_registry() {
		let mut registry = TokenRegistry::new();

		let token = TokenInfo {
			symbol: "USDC".to_string(),
			address: Hex::to_address("0x0000000000000000000000000000000000000001").unwrap(),
			decimals: 6,
			chain: ChainId::from_u64(1),
		};

		registry.register(token.clone());

		// Test get by symbol (case insensitive)
		assert!(registry.get(ChainId::from_u64(1), "USDC").is_some());
		assert!(registry.get(ChainId::from_u64(1), "usdc").is_some());

		// Test get by address
		assert!(registry
			.get_by_address(ChainId::from_u64(1), token.address)
			.is_some());

		// Test non-existent token
		assert!(registry.get(ChainId::from_u64(1), "ETH").is_none());
		assert!(registry.get(ChainId::from_u64(2), "USDC").is_none());
	}
}
