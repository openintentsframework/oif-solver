//! ERC-7930 Interoperable Address Standard Implementation
//!
//! This module implements types and utilities for ERC-7930 interoperable addresses,
//! which encode chain information alongside addresses to enable cross-chain operations.
//!
//! ## Address Format
//!
//! An ERC-7930 interoperable address has the following structure:
//! ```text
//! 0x00010000010114D8DA6BF26964AF9D7EED9E03E53415D37AA96045
//!   ^^^^-------------------------------------------------- Version:              decimal 1 (2 bytes, big-endian)
//!       ^^^^---------------------------------------------- ChainType:            2 bytes of CAIP namespace
//!           ^^-------------------------------------------- ChainReferenceLength: decimal 1
//!             ^^------------------------------------------ ChainReference:       1 byte to store uint8(1)
//!               ^^---------------------------------------- AddressLength:        decimal 20
//!                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Address:              20 bytes of ethereum address
//! ```

use crate::with_0x_prefix;
use alloy_primitives::Address;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use thiserror::Error;

/// ERC-7930 Interoperable Address
#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
pub struct InteropAddress {
	/// Version of the interoperable address format (2 bytes per EIP-7930 spec)
	pub version: u16,
	/// CAIP namespace (2 bytes)
	pub chain_type: [u8; 2],
	/// Chain reference data
	pub chain_reference: Vec<u8>,
	/// The actual address bytes
	pub address: Vec<u8>,
}

/// CAIP namespace constants for common chain types
pub mod caip_namespaces {
	/// Ethereum mainnet and testnets (CAIP namespace "eip155")
	pub const EIP155: [u8; 2] = [0x00, 0x00]; // Encoded as 2 bytes
	/// Bitcoin (CAIP namespace "bip122")
	pub const BIP122: [u8; 2] = [0x00, 0x01];
	/// Cosmos (CAIP namespace "cosmos")
	pub const COSMOS: [u8; 2] = [0x00, 0x02];
}

/// Errors that can occur when working with ERC-7930 addresses
#[derive(Debug, Error)]
pub enum InteropAddressError {
	#[error("Invalid hex format: {0}")]
	InvalidHex(String),
	#[error("Address too short: expected at least {expected} bytes, got {actual}")]
	TooShort { expected: usize, actual: usize },
	#[error("Unsupported version: {0}")]
	UnsupportedVersion(u16),
	#[error("Invalid chain reference length: expected {expected}, got {actual}")]
	InvalidChainReferenceLength { expected: u8, actual: usize },
	#[error("Invalid address length: expected {expected}, got {actual}")]
	InvalidAddressLength { expected: u8, actual: usize },
	#[error("Unsupported chain type: {0:?}")]
	UnsupportedChainType([u8; 2]),
}

impl InteropAddress {
	/// Current supported version of ERC-7930 (2-byte field per spec)
	pub const CURRENT_VERSION: u16 = 1;

	/// Standard Ethereum address length
	pub const ETH_ADDRESS_LENGTH: u8 = 20;

	/// Create a new ERC-7930 interoperable address for Ethereum
	pub fn new_ethereum(chain_id: u64, address: Address) -> Self {
		let chain_reference = if chain_id <= 255 {
			vec![chain_id as u8]
		} else if chain_id <= 65535 {
			vec![(chain_id >> 8) as u8, chain_id as u8]
		} else {
			// For larger chain IDs, use more bytes as needed
			let mut bytes = Vec::new();
			let mut id = chain_id;
			while id > 0 {
				bytes.insert(0, (id & 0xFF) as u8);
				id >>= 8;
			}
			bytes
		};

		Self {
			version: Self::CURRENT_VERSION,
			chain_type: caip_namespaces::EIP155,
			chain_reference,
			address: address.as_slice().to_vec(),
		}
	}

	/// Parse an ERC-7930 interoperable address from hex string
	pub fn from_hex(hex_str: &str) -> Result<Self, InteropAddressError> {
		let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
		let bytes =
			hex::decode(hex_str).map_err(|e| InteropAddressError::InvalidHex(e.to_string()))?;

		Self::from_bytes(&bytes)
	}

	/// Parse an ERC-7930 interoperable address from bytes
	/// Format per EIP-7930: Version (2) | ChainType (2) | ChainRefLen (1) | ChainRef | AddrLen (1) | Address
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, InteropAddressError> {
		// Minimum: 2 (version) + 2 (chain_type) + 1 (chain_ref_len) + 1 (addr_len) = 6 bytes
		if bytes.len() < 6 {
			return Err(InteropAddressError::TooShort {
				expected: 6,
				actual: bytes.len(),
			});
		}

		// Version is 2 bytes, big-endian
		let version = u16::from_be_bytes([bytes[0], bytes[1]]);
		if version != Self::CURRENT_VERSION {
			return Err(InteropAddressError::UnsupportedVersion(version));
		}

		let chain_type = [bytes[2], bytes[3]];
		let chain_ref_length = bytes[4] as usize;

		// Check we have enough bytes for chain_reference + address_length byte
		if bytes.len() < 5 + chain_ref_length + 1 {
			return Err(InteropAddressError::TooShort {
				expected: 5 + chain_ref_length + 1,
				actual: bytes.len(),
			});
		}

		let chain_reference = bytes[5..5 + chain_ref_length].to_vec();
		let address_length = bytes[5 + chain_ref_length] as usize;

		let expected_total_length = 6 + chain_ref_length + address_length;
		if bytes.len() != expected_total_length {
			return Err(InteropAddressError::TooShort {
				expected: expected_total_length,
				actual: bytes.len(),
			});
		}

		let address = bytes[6 + chain_ref_length..].to_vec();

		if chain_reference.len() != chain_ref_length {
			return Err(InteropAddressError::InvalidChainReferenceLength {
				expected: chain_ref_length as u8,
				actual: chain_reference.len(),
			});
		}

		if address.len() != address_length {
			return Err(InteropAddressError::InvalidAddressLength {
				expected: address_length as u8,
				actual: address.len(),
			});
		}

		Ok(Self {
			version,
			chain_type,
			chain_reference,
			address,
		})
	}

	/// Convert to bytes representation
	/// Format per EIP-7930: Version (2) | ChainType (2) | ChainRefLen (1) | ChainRef | AddrLen (1) | Address
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::new();
		// Version is 2 bytes, big-endian per EIP-7930
		bytes.extend_from_slice(&self.version.to_be_bytes());
		bytes.extend_from_slice(&self.chain_type);
		bytes.push(self.chain_reference.len() as u8);
		bytes.extend_from_slice(&self.chain_reference);
		bytes.push(self.address.len() as u8);
		bytes.extend_from_slice(&self.address);
		bytes
	}

	/// Convert to hex string with 0x prefix
	pub fn to_hex(&self) -> String {
		with_0x_prefix(&hex::encode(self.to_bytes()))
	}

	/// Extract Ethereum chain ID (only works for EIP155 addresses)
	pub fn ethereum_chain_id(&self) -> Result<u64, InteropAddressError> {
		if self.chain_type != caip_namespaces::EIP155 {
			return Err(InteropAddressError::UnsupportedChainType(self.chain_type));
		}

		let mut chain_id = 0u64;
		for &byte in &self.chain_reference {
			chain_id = (chain_id << 8) | (byte as u64);
		}
		Ok(chain_id)
	}

	/// Extract Ethereum address (only works for EIP155 addresses)
	pub fn ethereum_address(&self) -> Result<Address, InteropAddressError> {
		if self.chain_type != caip_namespaces::EIP155 {
			return Err(InteropAddressError::UnsupportedChainType(self.chain_type));
		}

		if self.address.len() != Self::ETH_ADDRESS_LENGTH as usize {
			return Err(InteropAddressError::InvalidAddressLength {
				expected: Self::ETH_ADDRESS_LENGTH,
				actual: self.address.len(),
			});
		}

		let mut addr_bytes = [0u8; 20];
		addr_bytes.copy_from_slice(&self.address);
		Ok(Address::from(addr_bytes))
	}

	/// Check if this is an Ethereum address
	pub fn is_ethereum(&self) -> bool {
		self.chain_type == caip_namespaces::EIP155
	}

	/// Validate the interoperable address format
	pub fn validate(&self) -> Result<(), InteropAddressError> {
		if self.version != Self::CURRENT_VERSION {
			return Err(InteropAddressError::UnsupportedVersion(self.version));
		}

		// For Ethereum addresses, validate standard length
		if self.is_ethereum() && self.address.len() != Self::ETH_ADDRESS_LENGTH as usize {
			return Err(InteropAddressError::InvalidAddressLength {
				expected: Self::ETH_ADDRESS_LENGTH,
				actual: self.address.len(),
			});
		}

		Ok(())
	}
}

impl fmt::Display for InteropAddress {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.to_hex())
	}
}

impl Serialize for InteropAddress {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&self.to_hex())
	}
}

impl<'de> Deserialize<'de> for InteropAddress {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		InteropAddress::from_hex(&s).map_err(serde::de::Error::custom)
	}
}

/// Utility functions for working with ERC-7930 addresses
pub mod utils {
	use super::*;

	pub fn create_interop_address(chain_id: u64, address: Address) -> InteropAddress {
		InteropAddress::new_ethereum(chain_id, address)
	}

	/// Create an Ethereum mainnet interoperable address
	pub fn ethereum_mainnet_address(address: Address) -> InteropAddress {
		InteropAddress::new_ethereum(1, address)
	}

	/// Create an Ethereum Sepolia testnet interoperable address  
	pub fn ethereum_sepolia_address(address: Address) -> InteropAddress {
		InteropAddress::new_ethereum(11155111, address)
	}

	/// Validate that a string is a valid ERC-7930 interoperable address
	pub fn validate_interop_address(address: &str) -> Result<InteropAddress, InteropAddressError> {
		let interop_addr = InteropAddress::from_hex(address)?;
		interop_addr.validate()?;
		Ok(interop_addr)
	}

	/// Check if a string might be an ERC-7930 interoperable address
	pub fn is_likely_interop_address(address: &str) -> bool {
		// Basic heuristic: starts with 0x, longer than standard Ethereum address
		address.starts_with("0x") && address.len() > 42
	}
}

/// Convenient conversion from (chain_id, custom_address) tuple to InteropAddress
impl From<(u64, crate::Address)> for InteropAddress {
	fn from((chain_id, custom_address): (u64, crate::Address)) -> Self {
		let alloy_address = Address::from_slice(&custom_address.0);
		InteropAddress::new_ethereum(chain_id, alloy_address)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::address;

	#[test]
	fn test_ethereum_address_creation() {
		let eth_address = address!("D8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
		let interop_addr = InteropAddress::new_ethereum(1, eth_address);

		assert_eq!(interop_addr.version, 1);
		assert_eq!(interop_addr.chain_type, caip_namespaces::EIP155);
		assert_eq!(interop_addr.chain_reference, vec![1]);
		assert_eq!(interop_addr.address, eth_address.as_slice());
	}

	#[test]
	fn test_hex_roundtrip() {
		let eth_address = address!("D8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
		let interop_addr = InteropAddress::new_ethereum(1, eth_address);

		let hex = interop_addr.to_hex();
		let parsed = InteropAddress::from_hex(&hex).unwrap();

		assert_eq!(interop_addr, parsed);
	}

	#[test]
	fn test_example_address() {
		// Create an interoperable address and test round-trip
		let eth_address = address!("D8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
		let interop_addr = InteropAddress::new_ethereum(1, eth_address);

		// Test round-trip: to hex and back
		let hex = interop_addr.to_hex();
		let parsed = InteropAddress::from_hex(&hex).unwrap();

		assert_eq!(parsed.version, 1);
		assert_eq!(parsed.chain_type, [0x00, 0x00]);
		assert_eq!(parsed.chain_reference, vec![1]);
		assert_eq!(parsed.address.len(), 20);

		let chain_id = parsed.ethereum_chain_id().unwrap();
		assert_eq!(chain_id, 1);

		let recovered_addr = parsed.ethereum_address().unwrap();
		assert_eq!(recovered_addr, eth_address);
	}

	#[test]
	fn test_large_chain_id() {
		let eth_address = address!("D8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
		let interop_addr = InteropAddress::new_ethereum(11155111, eth_address); // Sepolia

		let chain_id = interop_addr.ethereum_chain_id().unwrap();
		assert_eq!(chain_id, 11155111);
	}

	#[test]
	fn test_validation() {
		let eth_address = address!("D8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
		let interop_addr = InteropAddress::new_ethereum(1, eth_address);

		assert!(interop_addr.validate().is_ok());
	}

	#[test]
	fn test_from_bytes_correct_eip7930_format() {
		// Test that from_bytes correctly parses the EIP-7930 format:
		// Version (2) | ChainType (2) | ChainRefLen (1) | ChainRef | AddrLen (1) | Address
		//
		// Example: chain_id=11155420 (0xaa37dc), address=0x067e39121f2bba7531ccdf393bb76306ac11cac1
		// Correct format: 0x0001000003aa37dc14067e39121f2bba7531ccdf393bb76306ac11cac1
		let correct_bytes =
			hex::decode("0001000003aa37dc14067e39121f2bba7531ccdf393bb76306ac11cac1").unwrap();

		let parsed = InteropAddress::from_bytes(&correct_bytes).unwrap();

		assert_eq!(parsed.version, 1);
		assert_eq!(parsed.chain_type, [0x00, 0x00]);
		assert_eq!(parsed.chain_reference, vec![0xaa, 0x37, 0xdc]); // chain_id = 11155420
		assert_eq!(parsed.address.len(), 20);
		assert_eq!(
			parsed.address,
			hex::decode("067e39121f2bba7531ccdf393bb76306ac11cac1").unwrap()
		);

		// Verify chain_id extraction
		assert_eq!(parsed.ethereum_chain_id().unwrap(), 11155420);
	}

	#[test]
	fn test_from_bytes_rejects_old_incorrect_format() {
		// The OLD incorrect format had: ChainRefLen | AddrLen | ChainRef | Address
		// This should fail to parse correctly or produce wrong results
		//
		// Old format: 0x000100000314aa37dc067e39121f2bba7531ccdf393bb76306ac11cac1
		// Breakdown: 0001 (version) | 0000 (chain_type) | 03 (chain_ref_len) | 14 (addr_len - WRONG POS) | aa37dc...
		let old_format_bytes =
			hex::decode("000100000314aa37dc067e39121f2bba7531ccdf393bb76306ac11cac1").unwrap();

		// This will parse but produce WRONG results because:
		// - It reads chain_ref_len=3, then chain_ref from bytes[5..8] = [0x14, 0xaa, 0x37]
		// - Then addr_len from bytes[8] = 0xdc = 220, which is wrong
		let result = InteropAddress::from_bytes(&old_format_bytes);

		// Should fail because addr_len (220) doesn't match remaining bytes
		assert!(result.is_err());
	}

	#[test]
	fn test_from_bytes_to_bytes_roundtrip_preserves_format() {
		// Verify that encoding then decoding preserves the correct format
		let eth_address = address!("067e39121f2bBa7531CcdF393Bb76306AC11CaC1");
		let interop_addr = InteropAddress::new_ethereum(11155420, eth_address);

		let bytes = interop_addr.to_bytes();
		let parsed = InteropAddress::from_bytes(&bytes).unwrap();

		assert_eq!(interop_addr, parsed);
		assert_eq!(parsed.ethereum_chain_id().unwrap(), 11155420);
		assert_eq!(parsed.ethereum_address().unwrap(), eth_address);
	}

	#[test]
	fn test_from_bytes_format_matches_eip7930_spec() {
		// Verify byte positions match EIP-7930 spec exactly
		let eth_address = address!("D8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
		let interop_addr = InteropAddress::new_ethereum(1, eth_address);

		let bytes = interop_addr.to_bytes();

		// Verify byte layout per EIP-7930:
		// Bytes 0-1: Version (big-endian)
		assert_eq!(&bytes[0..2], &[0x00, 0x01], "Version should be 1");

		// Bytes 2-3: ChainType
		assert_eq!(&bytes[2..4], &[0x00, 0x00], "ChainType should be EIP155");

		// Byte 4: ChainRefLen
		assert_eq!(bytes[4], 1, "ChainRefLen should be 1 for chain_id=1");

		// Byte 5: ChainRef (for chain_id=1, this is just 0x01)
		assert_eq!(bytes[5], 0x01, "ChainRef should be 0x01 for chain_id=1");

		// Byte 6: AddrLen (should be 20 = 0x14)
		assert_eq!(bytes[6], 0x14, "AddrLen should be 20 (0x14)");

		// Bytes 7-26: Address (20 bytes)
		assert_eq!(
			&bytes[7..27],
			eth_address.as_slice(),
			"Address should match"
		);

		// Total length should be 2 + 2 + 1 + 1 + 1 + 20 = 27 bytes
		assert_eq!(bytes.len(), 27);
	}

	#[test]
	fn test_from_bytes_too_short() {
		// Less than minimum 6 bytes
		let short_bytes = hex::decode("00010000").unwrap();
		let result = InteropAddress::from_bytes(&short_bytes);
		assert!(matches!(result, Err(InteropAddressError::TooShort { .. })));
	}

	#[test]
	fn test_from_bytes_invalid_version() {
		// Version 2 is not supported
		let invalid_version =
			hex::decode("0002000001011406067e39121f2bba7531ccdf393bb76306ac11cac1").unwrap();
		let result = InteropAddress::from_bytes(&invalid_version);
		assert!(matches!(
			result,
			Err(InteropAddressError::UnsupportedVersion(2))
		));
	}

	#[test]
	fn test_from_bytes_truncated_address() {
		// Valid header but address is truncated
		// Format: version(0001) | chain_type(0000) | chain_ref_len(01) | chain_ref(01) | addr_len(14=20) | address(only 10 bytes)
		let truncated = hex::decode("00010000010114067e39121f2bba7531ccdf").unwrap();
		let result = InteropAddress::from_bytes(&truncated);
		assert!(matches!(result, Err(InteropAddressError::TooShort { .. })));
	}
}
