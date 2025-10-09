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
//!   ^^^^-------------------------------------------------- Version:              decimal 1
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
	/// Version of the interoperable address format
	pub version: u8,
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
	UnsupportedVersion(u8),
	#[error("Invalid chain reference length: expected {expected}, got {actual}")]
	InvalidChainReferenceLength { expected: u8, actual: usize },
	#[error("Invalid address length: expected {expected}, got {actual}")]
	InvalidAddressLength { expected: u8, actual: usize },
	#[error("Unsupported chain type: {0:?}")]
	UnsupportedChainType([u8; 2]),
}

impl InteropAddress {
	/// Current supported version of ERC-7930
	pub const CURRENT_VERSION: u8 = 1;

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
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, InteropAddressError> {
		if bytes.len() < 6 {
			return Err(InteropAddressError::TooShort {
				expected: 6,
				actual: bytes.len(),
			});
		}

		let version = bytes[0];
		if version != Self::CURRENT_VERSION {
			return Err(InteropAddressError::UnsupportedVersion(version));
		}

		let chain_type = [bytes[1], bytes[2]];
		let chain_ref_length = bytes[3];
		let address_length = bytes[4];

		let expected_total_length = 5 + chain_ref_length as usize + address_length as usize;
		if bytes.len() != expected_total_length {
			return Err(InteropAddressError::TooShort {
				expected: expected_total_length,
				actual: bytes.len(),
			});
		}

		let chain_reference = bytes[5..5 + chain_ref_length as usize].to_vec();
		let address = bytes[5 + chain_ref_length as usize..].to_vec();

		if chain_reference.len() != chain_ref_length as usize {
			return Err(InteropAddressError::InvalidChainReferenceLength {
				expected: chain_ref_length,
				actual: chain_reference.len(),
			});
		}

		if address.len() != address_length as usize {
			return Err(InteropAddressError::InvalidAddressLength {
				expected: address_length,
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
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::new();
		bytes.push(self.version);
		bytes.extend_from_slice(&self.chain_type);
		bytes.push(self.chain_reference.len() as u8);
		bytes.push(self.address.len() as u8);
		bytes.extend_from_slice(&self.chain_reference);
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
}
