//! Conversion utilities for common data transformations.
//!
//! This module provides utility functions for converting between different
//! data formats commonly used in the solver system.

use super::formatting::without_0x_prefix;
use alloy_primitives::{hex, Address as AlloyAddress};

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

/// Converts a 20-byte slice to an Alloy `Address`.
///
/// Returns an error string if the slice is not exactly 20 bytes.
pub fn bytes20_to_alloy_address(bytes: &[u8]) -> Result<AlloyAddress, String> {
	if bytes.len() != 20 {
		return Err(format!("Expected 20-byte address, got {}", bytes.len()));
	}
	let mut arr = [0u8; 20];
	arr.copy_from_slice(bytes);
	Ok(AlloyAddress::from(arr))
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

	#[test]
	fn test_bytes20_to_alloy_address_valid() {
		// Test with a valid 20-byte address
		let bytes = [
			0x5F, 0xbD, 0xB2, 0x31, 0x56, 0x78, 0xaf, 0xec, 0xb3, 0x67, 0xf0, 0x32, 0xd9, 0x3F,
			0x64, 0x2f, 0x64, 0x18, 0x0a, 0xa3,
		];

		let result = bytes20_to_alloy_address(&bytes);
		assert!(result.is_ok());

		let address = result.unwrap();
		assert_eq!(
			format!("{:x}", address),
			"5fbdb2315678afecb367f032d93f642f64180aa3"
		);
	}

	#[test]
	fn test_bytes20_to_alloy_address_zero_address() {
		// Test with zero address (all zeros)
		let bytes = [0u8; 20];

		let result = bytes20_to_alloy_address(&bytes);
		assert!(result.is_ok());

		let address = result.unwrap();
		assert_eq!(address, AlloyAddress::ZERO);
		assert_eq!(
			format!("{:x}", address),
			"0000000000000000000000000000000000000000"
		);
	}

	#[test]
	fn test_bytes20_to_alloy_address_too_short() {
		// Test with less than 20 bytes
		let bytes = [0x5F, 0xbD, 0xB2, 0x31, 0x56];

		let result = bytes20_to_alloy_address(&bytes);
		assert!(result.is_err());
		assert_eq!(result.unwrap_err(), "Expected 20-byte address, got 5");
	}

	#[test]
	fn test_bytes20_to_alloy_address_too_long() {
		// Test with more than 20 bytes
		let bytes = [
			0x5F, 0xbD, 0xB2, 0x31, 0x56, 0x78, 0xaf, 0xec, 0xb3, 0x67, 0xf0, 0x32, 0xd9, 0x3F,
			0x64, 0x2f, 0x64, 0x18, 0x0a, 0xa3, 0xff, 0xff, 0xff, 0xff, 0xff,
		];

		let result = bytes20_to_alloy_address(&bytes);
		assert!(result.is_err());
		assert_eq!(result.unwrap_err(), "Expected 20-byte address, got 25");
	}

	#[test]
	fn test_bytes20_to_alloy_address_empty_slice() {
		// Test with empty slice
		let bytes: &[u8] = &[];

		let result = bytes20_to_alloy_address(bytes);
		assert!(result.is_err());
		assert_eq!(result.unwrap_err(), "Expected 20-byte address, got 0");
	}

	#[test]
	fn test_bytes20_to_alloy_address_common_addresses() {
		// Test with common known addresses

		// USDC address on Ethereum: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
		let usdc_bytes = [
			0xA0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9D, 0x4a, 0x2e, 0x9E,
			0xb0, 0xcE, 0x36, 0x06, 0xeB, 0x48,
		];
		let result = bytes20_to_alloy_address(&usdc_bytes);
		assert!(result.is_ok());
		let address = result.unwrap();
		assert_eq!(
			format!("{:x}", address),
			"a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
		);

		// WETH address on Ethereum: 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2
		let weth_bytes = [
			0xC0, 0x2a, 0xaA, 0x39, 0xb2, 0x23, 0xFE, 0x8D, 0x0A, 0x0e, 0x5C, 0x4F, 0x27, 0xeA,
			0xD9, 0x08, 0x3C, 0x75, 0x6C, 0xc2,
		];
		let result = bytes20_to_alloy_address(&weth_bytes);
		assert!(result.is_ok());
		let address = result.unwrap();
		assert_eq!(
			format!("{:x}", address),
			"c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
		);
	}

	#[test]
	fn test_bytes20_to_alloy_address_roundtrip() {
		// Test roundtrip conversion: bytes -> Address -> bytes
		let original_bytes = [
			0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
			0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
		];

		let address = bytes20_to_alloy_address(&original_bytes).unwrap();
		let bytes_from_address: [u8; 20] = address.into();

		assert_eq!(original_bytes, bytes_from_address);
	}
}
