//! Seed configuration module for hardcoded network and contract data.
//!
//! This module provides the predefined seed configurations that contain all
//! the hardcoded values (contract addresses, Hyperlane oracles, etc.) that
//! are combined with user-provided deployment configuration to create the
//! final solver configuration.
//!
//! # Available Seeds
//!
//! - [`MAINNET_SEED`] - Mainnet networks (Optimism, Base, Arbitrum)
//! - [`TESTNET_SEED`] - Testnet networks (Optimism Sepolia, Base Sepolia)
//!
//! # Usage
//!
//! ```rust,ignore
//! use solver_service::seeds::{MAINNET_SEED, TESTNET_SEED, SeedPreset};
//!
//! // Get seed by preset name
//! let seed = SeedPreset::Mainnet.get_seed();
//! let optimism = seed.get_network(10).unwrap();
//! ```

mod mainnet;
mod testnet;
pub mod types;

pub use mainnet::MAINNET_SEED;
pub use testnet::TESTNET_SEED;
pub use types::{NetworkSeed, SeedConfig, SeedDefaults};

/// Seed preset enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedPreset {
	/// Mainnet preset (Optimism, Base, Arbitrum).
	Mainnet,
	/// Testnet preset (Optimism Sepolia, Base Sepolia).
	Testnet,
}

impl SeedPreset {
	/// Get the seed configuration for this preset.
	pub fn get_seed(&self) -> &'static SeedConfig {
		match self {
			SeedPreset::Mainnet => &MAINNET_SEED,
			SeedPreset::Testnet => &TESTNET_SEED,
		}
	}

	/// Parse a preset from a string name.
	pub fn from_str(s: &str) -> Option<Self> {
		match s.to_lowercase().as_str() {
			"mainnet" => Some(SeedPreset::Mainnet),
			"testnet" => Some(SeedPreset::Testnet),
			_ => None,
		}
	}

	/// Get all available preset names.
	pub fn all_names() -> &'static [&'static str] {
		&["mainnet", "testnet"]
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_seed_preset_from_str() {
		assert_eq!(SeedPreset::from_str("mainnet"), Some(SeedPreset::Mainnet));
		assert_eq!(SeedPreset::from_str("MAINNET"), Some(SeedPreset::Mainnet));
		assert_eq!(SeedPreset::from_str("testnet"), Some(SeedPreset::Testnet));
		assert_eq!(SeedPreset::from_str("TESTNET"), Some(SeedPreset::Testnet));
		assert_eq!(SeedPreset::from_str("invalid"), None);
	}

	#[test]
	fn test_seed_preset_get_seed() {
		let mainnet = SeedPreset::Mainnet.get_seed();
		assert!(!mainnet.networks.is_empty());

		let testnet = SeedPreset::Testnet.get_seed();
		assert!(!testnet.networks.is_empty());
	}

	#[test]
	fn test_all_names() {
		let names = SeedPreset::all_names();
		assert!(names.contains(&"mainnet"));
		assert!(names.contains(&"testnet"));
	}
}
