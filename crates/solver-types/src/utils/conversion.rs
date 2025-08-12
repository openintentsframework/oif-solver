//! Conversion utilities for common data transformations.
//!
//! This module provides utility functions for converting between different
//! data formats commonly used in the solver system.

use super::formatting::without_0x_prefix;
use alloy_primitives::hex;

/// Converts a bytes32 value to an Ethereum address string without "0x" prefix.
///
/// This function extracts the last 20 bytes (40 hex characters) from a bytes32
/// value and returns it as a lowercase hex string without prefix.
///
/// # Arguments
///
/// * `bytes32` - A 32-byte array, typically from EIP-7683 token/recipient fields
///
/// # Returns
///
/// A formatted Ethereum address string without "0x" prefix.
pub fn bytes32_to_address(bytes32: &[u8; 32]) -> String {
	let hex_string = hex::encode(bytes32);

	// Extract last 40 characters (20 bytes) for the address
	// Ethereum addresses are 20 bytes, but often stored as bytes32 with leading zeros
	let address = if hex_string.len() >= 40 {
		hex_string[hex_string.len() - 40..].to_string()
	} else {
		hex_string
	};

	// Ensure the result never has "0x" prefix
	without_0x_prefix(&address).to_string()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_bytes32_to_address() {
		// Test with a typical bytes32 value (address padded with zeros)
		let mut bytes32 = [0u8; 32];
		// Set last 20 bytes to represent an address
		bytes32[12..].copy_from_slice(&[
			0x5F, 0xbD, 0xB2, 0x31, 0x56, 0x78, 0xaf, 0xec, 0xb3, 0x67, 0xf0, 0x32, 0xd9, 0x3F,
			0x64, 0x2f, 0x64, 0x18, 0x0a, 0xa3,
		]);

		let address = bytes32_to_address(&bytes32);
		assert_eq!(address, "5fbdb2315678afecb367f032d93f642f64180aa3");
	}
}
