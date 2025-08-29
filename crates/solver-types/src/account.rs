//! Account-related types for the solver system.
//!
//! This module defines types for blockchain addresses, signatures, and transactions
//! that are used throughout the solver for account management and transaction processing.

use crate::with_0x_prefix;
use alloy_primitives::{Address as AlloyAddress, Bytes, PrimitiveSignature, U256};
use alloy_rpc_types::TransactionRequest;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Blockchain address representation.
///
/// Stores addresses as raw bytes to support different blockchain formats.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address(pub Vec<u8>);

/// Custom serialization for Address - serializes as hex string
impl Serialize for Address {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		// Serialize as hex string with 0x prefix
		serializer.serialize_str(&with_0x_prefix(&hex::encode(&self.0)))
	}
}

/// Custom deserialization for Address - accepts hex strings
impl<'de> Deserialize<'de> for Address {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		let hex_str = s.trim_start_matches("0x");
		let bytes = hex::decode(hex_str)
			.map_err(|e| serde::de::Error::custom(format!("Invalid hex address: {}", e)))?;

		// Validate address length (should be 20 bytes for Ethereum addresses)
		if bytes.len() != 20 {
			return Err(serde::de::Error::custom(format!(
				"Invalid address length: expected 20 bytes, got {}",
				bytes.len()
			)));
		}

		Ok(Address(bytes))
	}
}

impl fmt::Display for Address {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		// Format as hex string with 0x prefix
		write!(f, "0x{}", hex::encode(&self.0))
	}
}

/// Cryptographic signature representation.
///
/// Stores signatures as raw bytes in the standard Ethereum format (r, s, v).
#[derive(Debug, Clone)]
pub struct Signature(pub Vec<u8>);

impl From<PrimitiveSignature> for Signature {
	fn from(sig: PrimitiveSignature) -> Self {
		// Convert to standard Ethereum signature format (r, s, v)
		let mut bytes = Vec::with_capacity(65);
		bytes.extend_from_slice(&sig.r().to_be_bytes::<32>());
		bytes.extend_from_slice(&sig.s().to_be_bytes::<32>());
		// For EIP-155, v = chain_id * 2 + 35 + y_parity
		// For non-EIP-155, v = 27 + y_parity
		let v = if sig.v() { 28 } else { 27 };
		bytes.push(v);
		Signature(bytes)
	}
}

/// Blockchain transaction representation.
///
/// Contains all fields necessary for constructing and submitting transactions
/// to various blockchain networks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
	/// Recipient address (None for contract creation).
	pub to: Option<Address>,
	/// Transaction data/calldata.
	pub data: Vec<u8>,
	/// Value to transfer in native currency.
	pub value: U256,
	/// Chain ID for replay protection.
	pub chain_id: u64,
	/// Transaction nonce (optional, can be filled by provider).
	pub nonce: Option<u64>,
	/// Gas limit for transaction execution.
	pub gas_limit: Option<u64>,
	/// Legacy gas price (for non-EIP-1559 transactions).
	pub gas_price: Option<u128>,
	/// Maximum fee per gas (EIP-1559).
	pub max_fee_per_gas: Option<u128>,
	/// Maximum priority fee per gas (EIP-1559).
	pub max_priority_fee_per_gas: Option<u128>,
}

/// Conversion from Alloy's TransactionRequest to our Transaction type.
impl From<TransactionRequest> for Transaction {
	fn from(req: TransactionRequest) -> Self {
		Transaction {
			to: req.to.map(|addr| match addr {
				alloy_primitives::TxKind::Call(a) => Address(a.as_slice().to_vec()),
				alloy_primitives::TxKind::Create => panic!("Create transactions not supported"),
			}),
			data: req.input.input.clone().unwrap_or_default().to_vec(),
			value: req.value.unwrap_or(U256::ZERO),
			chain_id: req.chain_id.unwrap_or(1),
			nonce: req.nonce,
			gas_limit: req.gas,
			gas_price: req.gas_price,
			max_fee_per_gas: req.max_fee_per_gas,
			max_priority_fee_per_gas: req.max_priority_fee_per_gas,
		}
	}
}

/// Conversion from our Transaction type to Alloy's TransactionRequest.
impl From<Transaction> for TransactionRequest {
	fn from(tx: Transaction) -> Self {
		let to = tx.to.map(|to| {
			let mut addr_bytes = [0u8; 20];
			addr_bytes.copy_from_slice(&to.0[..20]);
			alloy_primitives::TxKind::Call(AlloyAddress::from(addr_bytes))
		});

		TransactionRequest {
			chain_id: Some(tx.chain_id),
			value: Some(tx.value),
			to,
			nonce: tx.nonce,
			gas: tx.gas_limit,
			gas_price: tx.gas_price,
			max_fee_per_gas: tx.max_fee_per_gas,
			max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
			input: alloy_rpc_types::TransactionInput {
				input: Some(Bytes::from(tx.data)),
				data: None,
			},
			..Default::default()
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::utils::{builders::TransactionBuilder, conversion::parse_address};
	use alloy_primitives::{address, U256};
	use serde_json;

	// Helper function to create a test address from hex string
	fn test_address(hex: &str) -> Address {
		parse_address(hex).expect("Invalid test address")
	}

	// Helper function to create a test address from bytes
	fn test_address_bytes(bytes: &[u8]) -> Address {
		Address(bytes.to_vec())
	}

	#[test]
	fn test_address_creation() {
		let addr_bytes = vec![
			0xA0, 0xb8, 0x6a, 0x33, 0xE6, 0x77, 0x6F, 0xb7, 0x8B, 0x3e, 0x1E, 0x6B, 0x2D, 0x0d,
			0x2E, 0x8F, 0x0C, 0x1D, 0x2A, 0x3B,
		];
		let address = Address(addr_bytes.clone());
		assert_eq!(address.0, addr_bytes);
	}

	#[test]
	fn test_address_display() {
		let address = test_address("0xa0b86a33e6776fb78b3e1e6b2d0d2e8f0c1d2a3b");
		let display_str = format!("{}", address);
		assert_eq!(display_str, "0xa0b86a33e6776fb78b3e1e6b2d0d2e8f0c1d2a3b");
	}

	#[test]
	fn test_address_serialization() {
		let address = test_address("0xa0b86a33e6776fb78b3e1e6b2d0d2e8f0c1d2a3b");

		let json = serde_json::to_string(&address).unwrap();
		assert_eq!(json, "\"0xa0b86a33e6776fb78b3e1e6b2d0d2e8f0c1d2a3b\"");
	}

	#[test]
	fn test_address_deserialization_valid() {
		// Test with 0x prefix
		let json = "\"0xa0b86a33e6776fb78b3e1e6b2d0d2e8f0c1d2a3b\"";
		let address: Address = serde_json::from_str(json).unwrap();

		let expected = test_address("0xa0b86a33e6776fb78b3e1e6b2d0d2e8f0c1d2a3b");
		assert_eq!(address, expected);

		// Test without 0x prefix
		let json_no_prefix = "\"a0b86a33e6776fb78b3e1e6b2d0d2e8f0c1d2a3b\"";
		let address_no_prefix: Address = serde_json::from_str(json_no_prefix).unwrap();
		assert_eq!(address_no_prefix, expected);
	}

	#[test]
	fn test_address_deserialization_invalid_hex() {
		let invalid_hex = "\"0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\"";
		let result: Result<Address, _> = serde_json::from_str(invalid_hex);
		assert!(result.is_err());
		assert!(result
			.unwrap_err()
			.to_string()
			.contains("Invalid hex address"));
	}

	#[test]
	fn test_address_deserialization_invalid_length() {
		// Too short (19 bytes)
		let too_short = "\"0xa0b86a33e6776fb78b3e1e6b2d0d2e8f0c1d2a\"";
		let result: Result<Address, _> = serde_json::from_str(too_short);
		assert!(result.is_err());
		assert!(result
			.unwrap_err()
			.to_string()
			.contains("Invalid address length"));

		// Too long (21 bytes)
		let too_long = "\"0xa0b86a33e6776fb78b3e1e6b2d0d2e8f0c1d2a3bff\"";
		let result: Result<Address, _> = serde_json::from_str(too_long);
		assert!(result.is_err());
		assert!(result
			.unwrap_err()
			.to_string()
			.contains("Invalid address length"));
	}

	#[test]
	fn test_address_round_trip_serialization() {
		let original = test_address("0x123456789abcdef0112233445566778899aabbcc");

		let json = serde_json::to_string(&original).unwrap();
		let deserialized: Address = serde_json::from_str(&json).unwrap();

		assert_eq!(original, deserialized);
	}

	#[test]
	fn test_address_equality_and_hash() {
		use std::collections::HashSet;

		let addr1 = test_address_bytes(&[1; 20]);
		let addr2 = test_address_bytes(&[1; 20]);
		let addr3 = test_address_bytes(&[2; 20]);

		assert_eq!(addr1, addr2);
		assert_ne!(addr1, addr3);

		let mut set = HashSet::new();
		assert!(set.insert(addr1.clone()));
		assert!(!set.insert(addr2)); // Should not insert duplicate
		assert!(set.insert(addr3));
		assert_eq!(set.len(), 2);
	}

	#[test]
	fn test_signature_creation() {
		let sig_bytes = vec![1u8; 65]; // 65 bytes for r + s + v
		let signature = Signature(sig_bytes.clone());
		assert_eq!(signature.0, sig_bytes);
	}

	#[test]
	fn test_signature_from_primitive_signature() {
		use alloy_primitives::{PrimitiveSignature, U256};

		let r = U256::from(1);
		let s = U256::from(2);
		let y_parity = false; // v = 27

		let primitive_sig = PrimitiveSignature::new(r, s, y_parity);
		let signature = Signature::from(primitive_sig);

		assert_eq!(signature.0.len(), 65);
		// Check v value (should be 27 for y_parity = false)
		assert_eq!(signature.0[64], 27);
	}

	#[test]
	fn test_signature_from_primitive_signature_odd_parity() {
		use alloy_primitives::{PrimitiveSignature, U256};

		let r = U256::from(1);
		let s = U256::from(2);
		let y_parity = true; // v = 28

		let primitive_sig = PrimitiveSignature::new(r, s, y_parity);
		let signature = Signature::from(primitive_sig);

		assert_eq!(signature.0.len(), 65);
		// Check v value (should be 28 for y_parity = true)
		assert_eq!(signature.0[64], 28);
	}

	#[test]
	fn test_signature_debug() {
		let sig_bytes = vec![0xde, 0xad, 0xbe, 0xef];
		let signature = Signature(sig_bytes);
		let debug_str = format!("{:?}", signature);
		assert!(debug_str.contains("Signature"));
	}

	#[test]
	fn test_signature_clone() {
		let sig_bytes = vec![1u8; 65];
		let original = Signature(sig_bytes.clone());
		let cloned = original.clone();
		assert_eq!(original.0, cloned.0);
	}

	#[test]
	fn test_transaction_creation_with_builder() {
		let tx = TransactionBuilder::new()
			.to(test_address("0x1111111111111111111111111111111111111111"))
			.data(vec![0x12, 0x34])
			.value_u64(1000)
			.chain_id(1)
			.nonce(42)
			.gas_limit(21000)
			.gas_price_gwei(20)
			.build();

		assert!(tx.to.is_some());
		assert_eq!(tx.data, vec![0x12, 0x34]);
		assert_eq!(tx.value, U256::from(1000));
		assert_eq!(tx.chain_id, 1);
		assert_eq!(tx.nonce, Some(42));
		assert_eq!(tx.gas_limit, Some(21000));
		assert_eq!(tx.gas_price, Some(20_000_000_000));
	}

	#[test]
	fn test_transaction_creation_eip1559_with_builder() {
		let tx = TransactionBuilder::new()
			.to_hex("0xa0b86a33e6776fb78b3e1e6b2d0d2e8f0c1d2a3b")
			.unwrap()
			.value_u64(500)
			.chain_id(137)
			.nonce(10)
			.gas_limit(50000)
			.eip1559(25, 2) // max_fee_gwei, priority_fee_gwei
			.build();

		assert!(tx.to.is_some());
		assert_eq!(tx.value, U256::from(500));
		assert_eq!(tx.chain_id, 137);
		assert_eq!(tx.nonce, Some(10));
		assert_eq!(tx.gas_limit, Some(50000));
		assert_eq!(tx.max_fee_per_gas, Some(25_000_000_000));
		assert_eq!(tx.max_priority_fee_per_gas, Some(2_000_000_000));
		assert!(tx.gas_price.is_none()); // Should be None for EIP-1559
	}

	#[test]
	fn test_transaction_creation_minimal_with_builder() {
		let tx = TransactionBuilder::new()
			.chain_id(1)
			.gas_price_gwei(20)
			.build();

		assert!(tx.to.is_none());
		assert_eq!(tx.value, U256::ZERO);
		assert_eq!(tx.chain_id, 1);
		assert!(tx.data.is_empty());
		assert!(tx.nonce.is_none());
		assert_eq!(tx.gas_price, Some(20_000_000_000));
	}

	#[test]
	fn test_transaction_from_alloy_request() {
		use alloy_primitives::{address, Bytes, TxKind};
		use alloy_rpc_types::{TransactionInput, TransactionRequest};

		let alloy_addr = address!("A0b86a33E6776Fb78B3e1E6B2D0d2E8F0C1D2A3B");
		let req = TransactionRequest {
			to: Some(TxKind::Call(alloy_addr)),
			value: Some(U256::from(500)),
			chain_id: Some(137),
			nonce: Some(10),
			gas: Some(50000),
			gas_price: Some(25_000_000_000),
			input: TransactionInput {
				input: Some(Bytes::from(vec![0xab, 0xcd])),
				data: None,
			},
			..Default::default()
		};

		let tx = Transaction::from(req);

		assert!(tx.to.is_some());
		assert_eq!(tx.to.unwrap().0, alloy_addr.as_slice());
		assert_eq!(tx.value, U256::from(500));
		assert_eq!(tx.chain_id, 137);
		assert_eq!(tx.nonce, Some(10));
		assert_eq!(tx.gas_limit, Some(50000));
		assert_eq!(tx.gas_price, Some(25_000_000_000));
		assert_eq!(tx.data, vec![0xab, 0xcd]);
	}

	#[test]
	fn test_transaction_from_alloy_request_minimal() {
		use alloy_rpc_types::TransactionRequest;

		// Minimal request with defaults
		let req = TransactionRequest::default();
		let tx = Transaction::from(req);

		assert!(tx.to.is_none());
		assert_eq!(tx.value, U256::ZERO);
		assert_eq!(tx.chain_id, 1); // Default chain_id
		assert!(tx.data.is_empty());
		assert!(tx.nonce.is_none());
	}

	#[test]
	fn test_transaction_to_alloy_request_with_builder() {
		let tx = TransactionBuilder::new()
			.to_hex("0xa0b86a33e6776fb78b3e1e6b2d0d2e8f0c1d2a3b")
			.unwrap()
			.data_hex("0xffee")
			.unwrap()
			.value_u64(750)
			.chain_id(42)
			.nonce(15)
			.gas_limit(30000)
			.gas_price_gwei(30)
			.max_fee_per_gas_gwei(40)
			.max_priority_fee_per_gas_gwei(2)
			.build();

		let req: TransactionRequest = tx.into();

		assert!(req.to.is_some());
		assert_eq!(req.value, Some(U256::from(750)));
		assert_eq!(req.chain_id, Some(42));
		assert_eq!(req.nonce, Some(15));
		assert_eq!(req.gas, Some(30000));
		assert_eq!(req.gas_price, Some(30_000_000_000));
		assert_eq!(req.max_fee_per_gas, Some(40_000_000_000));
		assert_eq!(req.max_priority_fee_per_gas, Some(2_000_000_000));
		assert_eq!(req.input.input.unwrap().to_vec(), vec![0xff, 0xee]);
	}

	#[test]
	fn test_transaction_to_alloy_request_no_to() {
		let tx = TransactionBuilder::new()
			.chain_id(1)
			.gas_price_gwei(20)
			.build();

		let req: TransactionRequest = tx.into();

		assert!(req.to.is_none());
		assert_eq!(req.value, Some(U256::ZERO));
		assert_eq!(req.chain_id, Some(1));
		assert!(req.nonce.is_none());
		assert!(req.gas.is_none());
	}

	#[test]
	fn test_transaction_round_trip_conversion() {
		use alloy_primitives::{address, Bytes, TxKind};
		use alloy_rpc_types::{TransactionInput, TransactionRequest};

		let original_req = TransactionRequest {
			to: Some(TxKind::Call(address!(
				"A0b86a33E6776Fb78B3e1E6B2D0d2E8F0C1D2A3B"
			))),
			value: Some(U256::from(1234)),
			chain_id: Some(5),
			nonce: Some(99),
			gas: Some(60000),
			gas_price: Some(35_000_000_000),
			input: TransactionInput {
				input: Some(Bytes::from(vec![0x12, 0x34, 0x56])),
				data: None,
			},
			..Default::default()
		};

		let tx = Transaction::from(original_req.clone());
		let converted_req: TransactionRequest = tx.into();

		assert_eq!(converted_req.to, original_req.to);
		assert_eq!(converted_req.value, original_req.value);
		assert_eq!(converted_req.chain_id, original_req.chain_id);
		assert_eq!(converted_req.nonce, original_req.nonce);
		assert_eq!(converted_req.gas, original_req.gas);
		assert_eq!(converted_req.gas_price, original_req.gas_price);
		assert_eq!(converted_req.input.input, original_req.input.input);
	}

	#[test]
	fn test_transaction_debug() {
		let tx = TransactionBuilder::new()
			.chain_id(1)
			.gas_price_gwei(20)
			.build();

		let debug_str = format!("{:?}", tx);
		assert!(debug_str.contains("Transaction"));
		assert!(debug_str.contains("chain_id: 1"));
	}

	#[test]
	fn test_transaction_clone() {
		let original = TransactionBuilder::new()
			.to(test_address_bytes(&[1u8; 20]))
			.data(vec![0x11, 0x22])
			.value_u64(500)
			.chain_id(10)
			.nonce(5)
			.gas_limit(25000)
			.gas_price_gwei(20)
			.build();

		let cloned = original.clone();

		assert_eq!(cloned.to, original.to);
		assert_eq!(cloned.data, original.data);
		assert_eq!(cloned.value, original.value);
		assert_eq!(cloned.chain_id, original.chain_id);
	}
}
