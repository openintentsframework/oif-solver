//! EIP-7683 Cross-Chain Order Types
//!
//! This module defines the data structures for EIP-7683 cross-chain orders
//! that are shared across the solver system. Updated to match the new OIF
//! contracts structure with StandardOrder and MandateOutput types.

use alloy_primitives::U256;
use serde::{Deserialize, Serialize};

/// Lock type for cross-chain orders, determining the custody mechanism used.
///
/// This enum represents the different ways user funds can be locked/held
/// during the cross-chain order lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LockType {
	/// Permit2-based escrow mechanism
	/// Uses Permit2 signatures for gasless token approvals
	#[serde(rename = "permit2_escrow")]
	#[default]
	Permit2Escrow = 1,
	/// EIP-3009 based escrow mechanism  
	/// Uses transferWithAuthorization for gasless transfers
	#[serde(rename = "eip3009_escrow")]
	Eip3009Escrow = 2,
	/// Resource lock mechanism (The Compact)
	/// Uses TheCompact protocol for resource locking
	#[serde(rename = "resource_lock")]
	ResourceLock = 3,
}

impl LockType {
	/// Convert from u8 representation for backward compatibility
	pub fn from_u8(value: u8) -> Option<Self> {
		match value {
			1 => Some(LockType::Permit2Escrow),
			2 => Some(LockType::Eip3009Escrow),
			3 => Some(LockType::ResourceLock),
			_ => None,
		}
	}

	/// Convert to u8 representation for backward compatibility
	pub fn to_u8(self) -> u8 {
		self as u8
	}

	/// Returns true if this lock type uses compact settlement
	pub fn is_compact(&self) -> bool {
		matches!(self, LockType::ResourceLock)
	}

	/// Returns true if this lock type uses escrow settlement
	pub fn is_escrow(&self) -> bool {
		matches!(self, LockType::Permit2Escrow | LockType::Eip3009Escrow)
	}
}
/// Gas limit overrides for various transaction types
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct GasLimitOverrides {
	/// Gas limit for settlement transaction
	#[serde(skip_serializing_if = "Option::is_none")]
	pub settle_gas_limit: Option<u64>,
	/// Gas limit for fill transaction
	#[serde(skip_serializing_if = "Option::is_none")]
	pub fill_gas_limit: Option<u64>,
	/// Gas limit for prepare transaction
	#[serde(skip_serializing_if = "Option::is_none")]
	pub prepare_gas_limit: Option<u64>,
}

/// EIP-7683 specific order data structure.
///
/// Contains all the necessary information for processing a cross-chain order
/// based on the StandardOrder format from the OIF contracts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip7683OrderData {
	/// The address of the user initiating the cross-chain order
	pub user: String,
	/// Unique nonce to prevent order replay attacks
	pub nonce: U256,
	/// Chain ID where the order originates
	pub origin_chain_id: U256,
	/// Unix timestamp when the order expires
	pub expires: u32,
	/// Deadline by which the order must be filled
	pub fill_deadline: u32,
	/// Address of the oracle responsible for validating fills
	pub input_oracle: String,
	/// Input tokens and amounts as tuples of [token_address, amount]
	/// Format: Vec<[token_as_U256, amount_as_U256]>
	pub inputs: Vec<[U256; 2]>,
	/// Unique 32-byte identifier for the order
	pub order_id: [u8; 32],
	/// Gas limit overrides for transaction execution
	pub gas_limit_overrides: GasLimitOverrides,
	/// List of outputs specifying tokens, amounts, and recipients
	pub outputs: Vec<MandateOutput>,
	/// Optional raw order data (StandardOrder encoded as bytes)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub raw_order_data: Option<String>,
	/// Optional signature for off-chain order validation (Permit2Witness signature)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub signature: Option<String>,
	/// Optional sponsor address for off-chain orders
	#[serde(skip_serializing_if = "Option::is_none")]
	pub sponsor: Option<String>,
	/// Optional lock type determining the custody mechanism
	#[serde(skip_serializing_if = "Option::is_none")]
	pub lock_type: Option<LockType>,
}

/// Represents a MandateOutput of the OIF contracts.
///
/// Outputs define the tokens and amounts that should be received by recipients
/// as a result of executing the cross-chain order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MandateOutput {
	/// Oracle implementation responsible for collecting proof (bytes32)
	/// Zero value indicates same-chain or default oracle
	pub oracle: [u8; 32],
	/// Output Settler on the output chain responsible for settling (bytes32)
	pub settler: [u8; 32],
	/// The chain ID where the output should be delivered
	pub chain_id: U256,
	/// The token to be received (bytes32 - padded address)
	pub token: [u8; 32],
	/// The amount of tokens to be received
	pub amount: U256,
	/// The recipient that should receive the tokens (bytes32 - padded address)
	pub recipient: [u8; 32],
	/// Data delivered to recipient through settlement callback
	#[serde(with = "hex_string")]
	pub call: Vec<u8>,
	/// Additional output context for settlement
	#[serde(with = "hex_string")]
	pub context: Vec<u8>,
}

/// Alias for backward compatibility
pub type Output = MandateOutput;

/// Hex string serialization helper
mod hex_string {
	use crate::with_0x_prefix;
	use serde::{Deserialize, Deserializer, Serializer};

	pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&with_0x_prefix(&hex::encode(bytes)))
	}

	pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
	where
		D: Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		let s = s.strip_prefix("0x").unwrap_or(&s);
		hex::decode(s).map_err(serde::de::Error::custom)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::U256;
	use serde_json;

	#[test]
	fn test_lock_type_default() {
		let lock_type = LockType::default();
		assert_eq!(lock_type, LockType::Permit2Escrow);
	}

	#[test]
	fn test_lock_type_from_u8() {
		assert_eq!(LockType::from_u8(1), Some(LockType::Permit2Escrow));
		assert_eq!(LockType::from_u8(2), Some(LockType::Eip3009Escrow));
		assert_eq!(LockType::from_u8(3), Some(LockType::ResourceLock));
		assert_eq!(LockType::from_u8(0), None);
		assert_eq!(LockType::from_u8(4), None);
		assert_eq!(LockType::from_u8(255), None);
	}

	#[test]
	fn test_lock_type_to_u8() {
		assert_eq!(LockType::Permit2Escrow.to_u8(), 1);
		assert_eq!(LockType::Eip3009Escrow.to_u8(), 2);
		assert_eq!(LockType::ResourceLock.to_u8(), 3);
	}

	#[test]
	fn test_lock_type_is_compact() {
		assert!(!LockType::Permit2Escrow.is_compact());
		assert!(!LockType::Eip3009Escrow.is_compact());
		assert!(LockType::ResourceLock.is_compact());
	}

	#[test]
	fn test_lock_type_is_escrow() {
		assert!(LockType::Permit2Escrow.is_escrow());
		assert!(LockType::Eip3009Escrow.is_escrow());
		assert!(!LockType::ResourceLock.is_escrow());
	}

	#[test]
	fn test_lock_type_serialization() {
		let permit2 = LockType::Permit2Escrow;
		let json = serde_json::to_string(&permit2).unwrap();
		assert_eq!(json, "\"permit2_escrow\"");

		let eip3009 = LockType::Eip3009Escrow;
		let json = serde_json::to_string(&eip3009).unwrap();
		assert_eq!(json, "\"eip3009_escrow\"");

		let resource_lock = LockType::ResourceLock;
		let json = serde_json::to_string(&resource_lock).unwrap();
		assert_eq!(json, "\"resource_lock\"");
	}

	#[test]
	fn test_lock_type_deserialization() {
		let permit2: LockType = serde_json::from_str("\"permit2_escrow\"").unwrap();
		assert_eq!(permit2, LockType::Permit2Escrow);

		let eip3009: LockType = serde_json::from_str("\"eip3009_escrow\"").unwrap();
		assert_eq!(eip3009, LockType::Eip3009Escrow);

		let resource_lock: LockType = serde_json::from_str("\"resource_lock\"").unwrap();
		assert_eq!(resource_lock, LockType::ResourceLock);
	}

	#[test]
	fn test_gas_limit_overrides_default() {
		let overrides = GasLimitOverrides::default();
		assert_eq!(overrides.settle_gas_limit, None);
		assert_eq!(overrides.fill_gas_limit, None);
		assert_eq!(overrides.prepare_gas_limit, None);
	}

	#[test]
	fn test_gas_limit_overrides_serialization_empty() {
		let overrides = GasLimitOverrides::default();
		let json = serde_json::to_string(&overrides).unwrap();
		assert_eq!(json, "{}");
	}

	#[test]
	fn test_gas_limit_overrides_serialization_with_values() {
		let overrides = GasLimitOverrides {
			settle_gas_limit: Some(100000),
			fill_gas_limit: Some(200000),
			prepare_gas_limit: None,
		};
		let json = serde_json::to_string(&overrides).unwrap();
		let expected = r#"{"settle_gas_limit":100000,"fill_gas_limit":200000}"#;
		assert_eq!(json, expected);
	}

	#[test]
	fn test_gas_limit_overrides_deserialization() {
		let json = r#"{"settle_gas_limit":100000,"fill_gas_limit":200000}"#;
		let overrides: GasLimitOverrides = serde_json::from_str(json).unwrap();
		assert_eq!(overrides.settle_gas_limit, Some(100000));
		assert_eq!(overrides.fill_gas_limit, Some(200000));
		assert_eq!(overrides.prepare_gas_limit, None);
	}

	#[test]
	fn test_mandate_output_serialization() {
		let output = MandateOutput {
			oracle: [1u8; 32],
			settler: [2u8; 32],
			chain_id: U256::from(1),
			token: [3u8; 32],
			amount: U256::from(1000),
			recipient: [4u8; 32],
			call: vec![0xab, 0xcd],
			context: vec![0x12, 0x34],
		};

		let json = serde_json::to_string(&output).unwrap();
		assert!(json.contains("\"call\":\"0xabcd\""));
		assert!(json.contains("\"context\":\"0x1234\""));
	}

	#[test]
	fn test_mandate_output_deserialization_with_0x_prefix() {
		let json = r#"{
			"oracle": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
			"settler": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
			"chain_id": "1",
			"token": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
			"amount": "1000",
			"recipient": [4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4],
			"call": "0xabcd",
			"context": "0x1234"
		}"#;

		let output: MandateOutput = serde_json::from_str(json).unwrap();
		assert_eq!(output.call, vec![0xab, 0xcd]);
		assert_eq!(output.context, vec![0x12, 0x34]);
	}

	#[test]
	fn test_mandate_output_deserialization_without_0x_prefix() {
		let json = r#"{
			"oracle": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
			"settler": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
			"chain_id": "1",
			"token": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
			"amount": "1000",
			"recipient": [4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4],
			"call": "abcd",
			"context": "1234"
		}"#;

		let output: MandateOutput = serde_json::from_str(json).unwrap();
		assert_eq!(output.call, vec![0xab, 0xcd]);
		assert_eq!(output.context, vec![0x12, 0x34]);
	}

	#[test]
	fn test_mandate_output_empty_hex_fields() {
		let output = MandateOutput {
			oracle: [0u8; 32],
			settler: [0u8; 32],
			chain_id: U256::from(1),
			token: [0u8; 32],
			amount: U256::from(0),
			recipient: [0u8; 32],
			call: vec![],
			context: vec![],
		};

		let json = serde_json::to_string(&output).unwrap();
		assert!(json.contains("\"call\":\"0x\""));
		assert!(json.contains("\"context\":\"0x\""));

		// Test round-trip
		let deserialized: MandateOutput = serde_json::from_str(&json).unwrap();
		assert_eq!(deserialized.call, Vec::<u8>::new());
		assert_eq!(deserialized.context, Vec::<u8>::new());
	}

	#[test]
	fn test_eip7683_order_data_serialization() {
		let order = Eip7683OrderData {
			user: "0x1234567890123456789012345678901234567890".to_string(),
			nonce: U256::from(123),
			origin_chain_id: U256::from(1),
			expires: 1234567890,
			fill_deadline: 1234567900,
			input_oracle: "0xoracle123".to_string(),
			inputs: vec![[U256::from(1), U256::from(1000)]],
			order_id: [5u8; 32],
			gas_limit_overrides: GasLimitOverrides::default(),
			outputs: vec![MandateOutput {
				oracle: [1u8; 32],
				settler: [2u8; 32],
				chain_id: U256::from(1),
				token: [3u8; 32],
				amount: U256::from(1000),
				recipient: [4u8; 32],
				call: vec![0xab, 0xcd],
				context: vec![0x12, 0x34],
			}],
			raw_order_data: Some("0xrawdata".to_string()),
			signature: Some("0xsignature".to_string()),
			sponsor: None,
			lock_type: Some(LockType::Permit2Escrow),
		};

		let json = serde_json::to_string(&order).unwrap();
		assert!(json.contains("\"user\":"));
		assert!(json.contains("\"raw_order_data\":\"0xrawdata\""));
		assert!(json.contains("\"signature\":\"0xsignature\""));
		assert!(json.contains("\"lock_type\":\"permit2_escrow\""));
		assert!(!json.contains("\"sponsor\":")); // Should be omitted when None
	}

	#[test]
	fn test_eip7683_order_data_deserialization() {
		let json = r#"{
			"user": "0x1234567890123456789012345678901234567890",
			"nonce": "123",
			"origin_chain_id": "1",
			"expires": 1234567890,
			"fill_deadline": 1234567900,
			"input_oracle": "0xoracle123",
			"inputs": [["1", "1000"]],
			"order_id": [5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5],
			"gas_limit_overrides": {},
			"outputs": [{
				"oracle": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
				"settler": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
				"chain_id": "1",
				"token": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
				"amount": "1000",
				"recipient": [4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4],
				"call": "0xabcd",
				"context": "0x1234"
			}]
		}"#;

		let order: Eip7683OrderData = serde_json::from_str(json).unwrap();
		assert_eq!(order.user, "0x1234567890123456789012345678901234567890");
		assert_eq!(order.nonce, U256::from(123));
		assert_eq!(order.inputs.len(), 1);
		assert_eq!(order.inputs[0], [U256::from(1), U256::from(1000)]);
		assert_eq!(order.outputs.len(), 1);
		assert_eq!(order.raw_order_data, None);
		assert_eq!(order.signature, None);
		assert_eq!(order.sponsor, None);
		assert_eq!(order.lock_type, None);
	}

	#[test]
	fn test_output_type_alias() {
		// Test that Output is indeed an alias for MandateOutput
		let output: Output = MandateOutput {
			oracle: [1u8; 32],
			settler: [2u8; 32],
			chain_id: U256::from(1),
			token: [3u8; 32],
			amount: U256::from(1000),
			recipient: [4u8; 32],
			call: vec![0xab, 0xcd],
			context: vec![0x12, 0x34],
		};

		assert_eq!(output.amount, U256::from(1000));
		assert_eq!(output.call, vec![0xab, 0xcd]);
	}

	#[test]
	fn test_hex_string_serialization_empty() {
		use super::hex_string;
		use serde_json;

		#[derive(Serialize)]
		struct TestStruct {
			#[serde(with = "hex_string")]
			data: Vec<u8>,
		}

		let test = TestStruct { data: vec![] };
		let json = serde_json::to_string(&test).unwrap();
		assert_eq!(json, r#"{"data":"0x"}"#);
	}

	#[test]
	fn test_clone_and_debug() {
		let lock_type = LockType::Permit2Escrow;
		let cloned = lock_type.clone();
		assert_eq!(lock_type, cloned);

		let debug_str = format!("{:?}", lock_type);
		assert!(debug_str.contains("Permit2Escrow"));

		let overrides = GasLimitOverrides::default();
		let cloned_overrides = overrides.clone();
		assert_eq!(
			overrides.settle_gas_limit,
			cloned_overrides.settle_gas_limit
		);

		let output = MandateOutput {
			oracle: [1u8; 32],
			settler: [2u8; 32],
			chain_id: U256::from(1),
			token: [3u8; 32],
			amount: U256::from(1000),
			recipient: [4u8; 32],
			call: vec![0xab, 0xcd],
			context: vec![0x12, 0x34],
		};
		let cloned_output = output.clone();
		assert_eq!(output.amount, cloned_output.amount);
		assert_eq!(output.call, cloned_output.call);
	}

	#[test]
	fn test_large_values() {
		let large_u256 = U256::MAX;
		let output = MandateOutput {
			oracle: [255u8; 32],
			settler: [0u8; 32],
			chain_id: large_u256,
			token: [128u8; 32],
			amount: large_u256,
			recipient: [64u8; 32],
			call: vec![0; 1000],     // Large call data
			context: vec![255; 500], // Large context
		};

		// Test serialization/deserialization with large values
		let json = serde_json::to_string(&output).unwrap();
		let deserialized: MandateOutput = serde_json::from_str(&json).unwrap();

		assert_eq!(deserialized.chain_id, large_u256);
		assert_eq!(deserialized.amount, large_u256);
		assert_eq!(deserialized.call.len(), 1000);
		assert_eq!(deserialized.context.len(), 500);
	}
}
