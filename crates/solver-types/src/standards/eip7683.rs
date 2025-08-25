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
