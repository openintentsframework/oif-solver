//! Hexadecimal string parsing and encoding utilities
//!
//! This module provides utilities for converting between hexadecimal strings
//! and various types including addresses, private keys, hashes, and raw bytes.
//! It handles both prefixed (0x) and unprefixed hex strings.

use crate::types::error::{Error, Result};
use alloy_primitives::{Address, Bytes, B256};
use alloy_signer_local::PrivateKeySigner;

/// Utility struct providing hexadecimal conversion functions
///
/// Provides static methods for converting between hex strings and various
/// blockchain-related types including addresses, private keys, and hashes.
pub struct Hex;

impl Hex {
	/// Decode a hexadecimal string to bytes
	///
	/// # Arguments
	/// * `s` - Hex string with or without 0x prefix
	///
	/// # Returns
	/// Decoded bytes as Bytes type
	///
	/// # Errors
	/// Returns Error::InvalidHex if the string contains invalid hex characters
	pub fn decode(s: &str) -> Result<Bytes> {
		let s = s.trim_start_matches("0x");
		hex::decode(s)
			.map(Into::into)
			.map_err(|e| Error::InvalidHex(format!("{}: {}", s, e)))
	}

	/// Encode bytes to hexadecimal string with 0x prefix
	///
	/// # Arguments
	/// * `bytes` - Byte array to encode
	///
	/// # Returns
	/// Hex string with 0x prefix
	pub fn encode(bytes: &[u8]) -> String {
		format!("0x{}", hex::encode(bytes))
	}

	/// Parse a private key from hexadecimal string
	///
	/// # Arguments
	/// * `key` - Hex string containing 32-byte private key with or without 0x prefix
	///
	/// # Returns
	/// A PrivateKeySigner instance for the parsed key
	///
	/// # Errors
	/// Returns Error::InvalidHex or Error::InvalidPrivateKey if parsing fails
	pub fn to_private_key(key: &str) -> Result<PrivateKeySigner> {
		let key = key.trim_start_matches("0x");
		let bytes = hex::decode(key).map_err(|e| Error::InvalidHex(e.to_string()))?;

		if bytes.len() != 32 {
			return Err(Error::InvalidPrivateKey);
		}

		let mut array = [0u8; 32];
		array.copy_from_slice(&bytes);

		PrivateKeySigner::from_bytes(&B256::from(array)).map_err(|_e| Error::InvalidPrivateKey)
	}

	/// Parse an Ethereum address from hexadecimal string
	///
	/// # Arguments
	/// * `s` - Hex string containing address in 20-byte or 32-byte padded format
	///
	/// # Returns
	/// An Address instance for the parsed address
	///
	/// # Errors
	/// Returns Error::InvalidAddress if the string cannot be parsed as a valid address
	pub fn to_address(s: &str) -> Result<Address> {
		// Use the robust utility from solver-types that handles both formats
		use solver_types::utils::conversion::hex_to_alloy_address;

		let alloy_addr =
			hex_to_alloy_address(s).map_err(|e| Error::InvalidAddress(format!("{}: {}", s, e)))?;

		// Convert alloy Address to our Address type
		Ok(Address::from_slice(alloy_addr.as_slice()))
	}

	/// Parse a 32-byte hash from hexadecimal string
	///
	/// # Arguments
	/// * `s` - Hex string containing exactly 32 bytes with or without 0x prefix
	///
	/// # Returns
	/// A B256 hash instance
	///
	/// # Errors
	/// Returns Error::InvalidHex if the string is not exactly 32 bytes or contains invalid hex
	pub fn to_hash(s: &str) -> Result<B256> {
		let s = s.trim_start_matches("0x");
		let bytes = hex::decode(s).map_err(|e| Error::InvalidHex(e.to_string()))?;

		if bytes.len() != 32 {
			return Err(Error::InvalidHex(format!(
				"Expected 32 bytes, got {}",
				bytes.len()
			)));
		}

		Ok(B256::from_slice(&bytes))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_hex_decode() {
		let bytes = Hex::decode("0xdeadbeef").unwrap();
		assert_eq!(bytes, Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]));

		let bytes2 = Hex::decode("deadbeef").unwrap();
		assert_eq!(bytes, bytes2);
	}

	#[test]
	fn test_hex_encode() {
		let encoded = Hex::encode(&[0xde, 0xad, 0xbe, 0xef]);
		assert_eq!(encoded, "0xdeadbeef");
	}

	#[test]
	fn test_address_parsing() {
		// Test 20-byte address
		let addr = Hex::to_address("0x0000000000000000000000000000000000000001").unwrap();
		assert_eq!(
			addr,
			Address::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
		);

		// Should work without 0x prefix
		let addr2 = Hex::to_address("0000000000000000000000000000000000000001").unwrap();
		assert_eq!(addr, addr2);

		// Test 32-byte padded address (like the one causing the error)
		let padded_addr =
			Hex::to_address("0x00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8")
				.unwrap();
		let expected_addr = Hex::to_address("0x70997970c51812dc3a010c7d01b50e0d17dc79c8").unwrap();
		assert_eq!(padded_addr, expected_addr);
	}

	#[test]
	fn test_invalid_address() {
		assert!(Hex::to_address("0x123").is_err());
		assert!(Hex::to_address("not hex").is_err());
	}
}
