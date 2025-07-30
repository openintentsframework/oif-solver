//! EIP-7683 Cross-Chain Order Types
//!
//! This module defines the data structures for EIP-7683 cross-chain orders
//! that are shared across the solver system.

use alloy_primitives::U256;
use serde::{Deserialize, Serialize};

/// EIP-7683 specific order data structure.
///
/// Contains all the necessary information for processing a cross-chain order
/// according to the EIP-7683 standard. This structure supports both on-chain
/// and off-chain order types, with optional fields for off-chain specific data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip7683OrderData {
	/// The address of the user initiating the cross-chain order
	pub user: String,
	/// Unique nonce to prevent order replay attacks
	pub nonce: u64,
	/// Chain ID where the order originates
	pub origin_chain_id: u64,
	/// Chain ID where the order should be filled
	pub destination_chain_id: u64,
	/// Unix timestamp when the order expires
	pub expires: u32,
	/// Deadline by which the order must be filled
	pub fill_deadline: u32,
	/// Address of the oracle responsible for validating fills
	pub local_oracle: String,
	/// Input tokens and amounts as tuples of [token_address, amount]
	pub inputs: Vec<[U256; 2]>,
	/// Unique 32-byte identifier for the order
	pub order_id: [u8; 32],
	/// Gas limit for settlement transaction
	pub settle_gas_limit: u64,
	/// Gas limit for fill transaction
	pub fill_gas_limit: u64,
	/// List of outputs specifying tokens, amounts, and recipients
	pub outputs: Vec<Output>,
	/// Optional raw order data for off-chain orders
	#[serde(skip_serializing_if = "Option::is_none")]
	pub raw_order_data: Option<String>,
	/// Optional type identifier for off-chain order data format
	#[serde(skip_serializing_if = "Option::is_none")]
	pub order_data_type: Option<[u8; 32]>,
	/// Optional signature for off-chain order validation
	#[serde(skip_serializing_if = "Option::is_none")]
	pub signature: Option<String>,
}

/// Represents an output in an EIP-7683 cross-chain order.
///
/// Outputs define the tokens and amounts that should be received by recipients
/// as a result of executing the cross-chain order. Each output can specify
/// a different chain, allowing for multi-chain settlement patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Output {
	/// The address of the token to be received
	pub token: String,
	/// The amount of tokens to be received
	pub amount: U256,
	/// The address that should receive the tokens
	pub recipient: String,
	/// The chain ID where the output should be delivered
	pub chain_id: u64,
}
