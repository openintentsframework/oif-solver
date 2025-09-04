//! Conversion utilities for common data transformations.
//!
//! This module provides utility functions for converting between different
//! data formats commonly used in the solver system.

use crate::Address;

use super::formatting::without_0x_prefix;
use alloy_primitives::{
	hex,
	utils::{format_ether, parse_ether},
	Address as AlloyAddress, U256,
};

/// Normalize a bytes32 that is expected to embed an `address` into
/// a canonical left-padded form: 12 zero bytes followed by 20 address bytes.
///
/// If the input looks right-padded (address in the first 20 bytes and 12 zero
/// bytes at the end), it will be converted to left-padded. Otherwise it is
/// returned unchanged.
pub fn normalize_bytes32_address(bytes32_value: [u8; 32]) -> [u8; 32] {
	// Detect right-padded shape: [address(20)][zeros(12)]
	let is_trailing_zeros = bytes32_value[20..32].iter().all(|&b| b == 0);
	let has_nonzero_prefix = bytes32_value[0..20].iter().any(|&b| b != 0);
	if is_trailing_zeros && has_nonzero_prefix {
		let mut normalized = [0u8; 32];
		normalized[12..32].copy_from_slice(&bytes32_value[0..20]);
		normalized
	} else {
		bytes32_value
	}
}

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

/// Parse a hex string address to solver Address type.
///
/// This function parses a hex string (with or without "0x" prefix) into
/// a 20-byte Address type used throughout the solver system.
///
/// # Arguments
/// * `hex_str` - A hex string representing an Ethereum address
///
/// # Returns
/// * `Ok(Address)` if the string is a valid 20-byte address
/// * `Err(String)` with error description if parsing fails
pub fn parse_address(hex_str: &str) -> Result<Address, String> {
	let hex = without_0x_prefix(hex_str);
	hex::decode(hex)
		.map_err(|e| format!("Invalid hex: {}", e))
		.and_then(|bytes| {
			if bytes.len() != 20 {
				Err(format!(
					"Invalid address length: expected 20 bytes, got {}",
					bytes.len()
				))
			} else {
				Ok(Address(bytes))
			}
		})
}

/// Convert wei (U256) to ETH string using Alloy's format_ether helper.
///
/// This function provides a convenient wrapper around Alloy's format_ether
/// utility for converting wei amounts to human-readable ETH strings.
///
/// # Arguments
/// * `wei_amount` - The amount in wei as a U256
///
/// # Returns
/// A string representation of the ETH amount (e.g., "1.5" for 1.5 ETH)
///
/// # Example
/// ```text
/// use alloy_primitives::U256;
/// use solver_types::utils::conversion::wei_to_eth_string;
///
/// let wei = U256::from(1500000000000000000u64); // 1.5 ETH in wei
/// let eth_str = wei_to_eth_string(wei);
/// assert_eq!(eth_str, "1.5");
/// ```
pub fn wei_to_eth_string(wei_amount: U256) -> String {
	format_ether(wei_amount)
}

/// Convert ETH string to wei (U256) using Alloy's parse_ether helper.
///
/// This function provides a convenient wrapper around Alloy's parse_ether
/// utility for converting ETH amounts to wei.
///
/// # Arguments
/// * `eth_amount` - The ETH amount as a string (e.g., "1.5")
///
/// # Returns
/// * `Ok(U256)` - The amount in wei
/// * `Err(String)` - Error message if parsing fails
///
/// # Example
/// ```text
/// use solver_types::utils::conversion::eth_string_to_wei;
///
/// let wei = eth_string_to_wei("1.5").unwrap();
/// assert_eq!(wei.to_string(), "1500000000000000000");
/// ```
pub fn eth_string_to_wei(eth_amount: &str) -> Result<U256, String> {
	parse_ether(eth_amount)
		.map_err(|e| format!("Failed to parse ETH amount '{}': {}", eth_amount, e))
}

/// Convert wei string to ETH string using Alloy utilities.
///
/// This function combines string parsing with Alloy's format_ether for
/// convenient conversion from wei strings to ETH strings.
///
/// # Arguments
/// * `wei_string` - The wei amount as a decimal string
///
/// # Returns
/// * `Ok(String)` - The ETH amount as a string
/// * `Err(String)` - Error message if parsing fails
///
/// # Example
/// ```text
/// use solver_types::utils::conversion::wei_string_to_eth_string;
///
/// let eth_str = wei_string_to_eth_string("1500000000000000000").unwrap();
/// assert_eq!(eth_str, "1.5");
/// ```
pub fn wei_string_to_eth_string(wei_string: &str) -> Result<String, String> {
	let wei = U256::from_str_radix(wei_string, 10)
		.map_err(|e| format!("Invalid wei amount '{}': {}", wei_string, e))?;
	Ok(format_ether(wei))
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

	#[test]
	fn test_wei_to_eth_string() {
		// Test 1 ETH
		let one_eth_wei = U256::from(1_000_000_000_000_000_000u64);
		assert_eq!(wei_to_eth_string(one_eth_wei), "1.000000000000000000");

		// Test 1.5 ETH
		let one_and_half_eth_wei = U256::from(1_500_000_000_000_000_000u64);
		assert_eq!(
			wei_to_eth_string(one_and_half_eth_wei),
			"1.500000000000000000"
		);

		// Test 0.1 ETH
		let tenth_eth_wei = U256::from(100_000_000_000_000_000u64);
		assert_eq!(wei_to_eth_string(tenth_eth_wei), "0.100000000000000000");

		// Test 0 ETH
		let zero_wei = U256::ZERO;
		assert_eq!(wei_to_eth_string(zero_wei), "0.000000000000000000");
	}

	#[test]
	fn test_eth_string_to_wei() {
		// Test 1 ETH
		let wei = eth_string_to_wei("1.0").unwrap();
		assert_eq!(wei, U256::from(1_000_000_000_000_000_000u64));

		// Test 1.5 ETH
		let wei = eth_string_to_wei("1.5").unwrap();
		assert_eq!(wei, U256::from(1_500_000_000_000_000_000u64));

		// Test 0.1 ETH
		let wei = eth_string_to_wei("0.1").unwrap();
		assert_eq!(wei, U256::from(100_000_000_000_000_000u64));

		// Test 0 ETH
		let wei = eth_string_to_wei("0").unwrap();
		assert_eq!(wei, U256::ZERO);

		// Test invalid input
		let result = eth_string_to_wei("invalid");
		assert!(result.is_err());
	}

	#[test]
	fn test_wei_string_to_eth_string() {
		// Test 1 ETH
		let eth_str = wei_string_to_eth_string("1000000000000000000").unwrap();
		assert_eq!(eth_str, "1.000000000000000000");

		// Test 1.5 ETH
		let eth_str = wei_string_to_eth_string("1500000000000000000").unwrap();
		assert_eq!(eth_str, "1.500000000000000000");

		// Test 0.1 ETH
		let eth_str = wei_string_to_eth_string("100000000000000000").unwrap();
		assert_eq!(eth_str, "0.100000000000000000");

		// Test 0 ETH
		let eth_str = wei_string_to_eth_string("0").unwrap();
		assert_eq!(eth_str, "0.000000000000000000");

		// Test invalid input
		let result = wei_string_to_eth_string("invalid");
		assert!(result.is_err());

		let result = wei_string_to_eth_string("123.456");
		assert!(result.is_err());
	}

	#[test]
	fn test_roundtrip_conversions() {
		// Test roundtrip: ETH -> wei -> ETH (note: format_ether returns full precision)
		let original_eth = "2.5";
		let wei = eth_string_to_wei(original_eth).unwrap();
		let converted_eth = wei_to_eth_string(wei);
		assert_eq!(converted_eth, "2.500000000000000000");

		// Test roundtrip: wei string -> ETH -> wei
		let original_wei_str = "2500000000000000000";
		let eth_str = wei_string_to_eth_string(original_wei_str).unwrap();
		let wei = eth_string_to_wei(&eth_str).unwrap();
		assert_eq!(wei.to_string(), original_wei_str);

		// Test that wei -> ETH -> wei maintains precision
		let original_wei = U256::from(1_234_567_890_123_456_789u64);
		let eth_str = wei_to_eth_string(original_wei);
		let converted_wei = eth_string_to_wei(&eth_str).unwrap();
		assert_eq!(converted_wei, original_wei);
	}
}
