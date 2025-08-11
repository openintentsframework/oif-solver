//! Transaction delivery types for the solver system.
//!
//! This module defines types related to blockchain transaction submission
//! and monitoring, including transaction hashes and receipts.

/// Blockchain transaction hash representation.
///
/// Stores transaction hashes as raw bytes to support different blockchain formats.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TransactionHash(pub Vec<u8>);

/// Transaction receipt containing execution details.
///
/// Provides information about a transaction after it has been included in a block,
/// including its success status and block number.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TransactionReceipt {
	/// The hash of the transaction.
	pub hash: TransactionHash,
	/// The block number where the transaction was included.
	pub block_number: u64,
	/// Whether the transaction executed successfully.
	pub success: bool,
}

/// Chain data structure containing current blockchain state information.
///
/// This structure provides a snapshot of blockchain state at a specific point in time,
/// useful for making execution decisions and calculating transaction costs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChainData {
	/// The chain ID.
	pub chain_id: u64,
	/// Current gas price as a string in wei.
	pub gas_price: String,
	/// Latest block number.
	pub block_number: u64,
	/// Timestamp when this data was fetched (Unix timestamp).
	pub timestamp: u64,
}
