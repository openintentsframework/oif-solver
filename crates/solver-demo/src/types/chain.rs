//! Blockchain chain identifier types and utilities
//!
//! This module provides the ChainId enum for representing different blockchain
//! networks, including Ethereum mainnet and custom chains. It includes conversion
//! utilities and display formatting for chain identifiers.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Identifier for blockchain networks
///
/// Represents different blockchain networks including Ethereum mainnet
/// and custom chains identified by their numeric chain ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChainId {
	Mainnet,
	Custom { id: u64 },
}

impl ChainId {
	/// Create ChainId from numeric identifier
	///
	/// # Arguments
	/// * `id` - The numeric chain identifier
	///
	/// # Returns
	/// ChainId::Mainnet for ID 1, ChainId::Custom for all other IDs
	pub fn from_u64(id: u64) -> Self {
		match id {
			1 => Self::Mainnet,
			id => Self::Custom { id },
		}
	}

	/// Get the numeric chain identifier
	///
	/// # Returns
	/// The numeric chain ID as u64
	pub fn id(&self) -> u64 {
		match self {
			Self::Mainnet => 1,
			Self::Custom { id } => *id,
		}
	}

	/// Get a human-readable name for the chain
	///
	/// # Returns
	/// A string slice containing the chain's display name
	pub fn name(&self) -> &str {
		match self {
			Self::Mainnet => "Ethereum Mainnet",
			Self::Custom { id: 1 } => "Ethereum Mainnet",
			Self::Custom { id: 5 } => "Goerli",
			Self::Custom { id: 11155111 } => "Sepolia",
			Self::Custom { id: 137 } => "Polygon",
			Self::Custom { id: 42161 } => "Arbitrum One",
			Self::Custom { id: 10 } => "Optimism",
			Self::Custom { .. } => "Custom Chain",
		}
	}
}

impl fmt::Display for ChainId {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Mainnet => write!(f, "1 (Mainnet)"),
			Self::Custom { id } => write!(f, "{} ({})", id, self.name()),
		}
	}
}

impl From<u64> for ChainId {
	fn from(id: u64) -> Self {
		Self::from_u64(id)
	}
}

impl From<ChainId> for u64 {
	fn from(chain: ChainId) -> Self {
		chain.id()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_chain_id_conversion() {
		assert_eq!(ChainId::from_u64(1), ChainId::Mainnet);
		assert_eq!(ChainId::from_u64(42), ChainId::Custom { id: 42 });
	}

	#[test]
	fn test_chain_id_to_u64() {
		assert_eq!(ChainId::Mainnet.id(), 1);
		assert_eq!(ChainId::Custom { id: 42 }.id(), 42);
	}
}
