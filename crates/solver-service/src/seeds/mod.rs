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

use std::str::FromStr;

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

/// Error type for parsing seed presets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseSeedPresetError(String);

impl std::fmt::Display for ParseSeedPresetError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(
			f,
			"Unknown seed preset: '{}'. Available presets: {:?}",
			self.0,
			SeedPreset::all_names()
		)
	}
}

impl std::error::Error for ParseSeedPresetError {}

impl FromStr for SeedPreset {
	type Err = ParseSeedPresetError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s.to_lowercase().as_str() {
			"mainnet" => Ok(SeedPreset::Mainnet),
			"testnet" => Ok(SeedPreset::Testnet),
			_ => Err(ParseSeedPresetError(s.to_string())),
		}
	}
}

impl SeedPreset {
	/// Get the seed configuration for this preset.
	pub fn get_seed(&self) -> &'static SeedConfig {
		match self {
			SeedPreset::Mainnet => &MAINNET_SEED,
			SeedPreset::Testnet => &TESTNET_SEED,
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
		assert_eq!(SeedPreset::from_str("mainnet"), Ok(SeedPreset::Mainnet));
		assert_eq!(SeedPreset::from_str("MAINNET"), Ok(SeedPreset::Mainnet));
		assert_eq!(SeedPreset::from_str("testnet"), Ok(SeedPreset::Testnet));
		assert_eq!(SeedPreset::from_str("TESTNET"), Ok(SeedPreset::Testnet));
		assert!(SeedPreset::from_str("invalid").is_err());
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

	#[test]
	fn test_parse_seed_preset_error_display() {
		let error = ParseSeedPresetError("unknown".to_string());
		let error_msg = format!("{error}");
		assert!(error_msg.contains("Unknown seed preset"));
		assert!(error_msg.contains("unknown"));
		assert!(error_msg.contains("mainnet"));
		assert!(error_msg.contains("testnet"));
	}

	#[test]
	fn test_parse_seed_preset_error_is_error_trait() {
		let error = ParseSeedPresetError("bad".to_string());
		// Test that it implements std::error::Error
		let _: &dyn std::error::Error = &error;
	}

	#[test]
	fn test_parse_seed_preset_error_debug() {
		let error = ParseSeedPresetError("test".to_string());
		let debug_str = format!("{error:?}");
		assert!(debug_str.contains("ParseSeedPresetError"));
		assert!(debug_str.contains("test"));
	}

	#[test]
	fn test_seed_preset_copy() {
		let preset = SeedPreset::Mainnet;
		let copied = preset; // Copy trait
		assert_eq!(preset, copied);

		let preset2 = SeedPreset::Testnet;
		let copied2 = preset2;
		assert_eq!(preset2, copied2);
	}

	#[test]
	fn test_seed_preset_equality() {
		assert_eq!(SeedPreset::Mainnet, SeedPreset::Mainnet);
		assert_eq!(SeedPreset::Testnet, SeedPreset::Testnet);
		assert_ne!(SeedPreset::Mainnet, SeedPreset::Testnet);
	}

	#[test]
	fn test_seed_preset_debug() {
		let mainnet = SeedPreset::Mainnet;
		let testnet = SeedPreset::Testnet;
		assert_eq!(format!("{mainnet:?}"), "Mainnet");
		assert_eq!(format!("{testnet:?}"), "Testnet");
	}
}
