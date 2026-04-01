//! Transaction delivery types for the solver system.
//!
//! This module defines types related to blockchain transaction submission
//! and monitoring, including transaction hashes and receipts.

use crate::Address;
use alloy_rpc_types::TransactionReceipt as AlloyReceipt;

/// Blockchain transaction hash representation.
///
/// Stores transaction hashes as raw bytes to support different blockchain formats.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TransactionHash(pub Vec<u8>);

/// Fixed-size hash type for log topics.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct H256(pub [u8; 32]);

/// Event log emitted by smart contracts.
///
/// Contains event data and indexed parameters (topics).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Log {
	/// Contract address that emitted the log.
	pub address: Address,
	/// Indexed event parameters.
	/// Topic[0] is typically the event signature hash.
	pub topics: Vec<H256>,
	/// Non-indexed event data.
	pub data: Vec<u8>,
}

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
	/// Event logs emitted during transaction execution.
	pub logs: Vec<Log>,
	/// Block timestamp (Unix timestamp) - extracted from logs if available
	#[serde(skip_serializing_if = "Option::is_none")]
	pub block_timestamp: Option<u64>,
}

impl From<&AlloyReceipt> for TransactionReceipt {
	fn from(receipt: &AlloyReceipt) -> Self {
		// Extract block timestamp from the first log that has it
		let block_timestamp = receipt.logs().iter().find_map(|log| log.block_timestamp);

		// Convert alloy logs to our Log type
		let logs = receipt
			.logs()
			.iter()
			.map(|log| Log {
				address: log.address().into(),
				topics: log.topics().iter().map(|topic| H256(topic.0)).collect(),
				data: log.data().data.to_vec(),
			})
			.collect();

		TransactionReceipt {
			hash: TransactionHash(receipt.transaction_hash.0.to_vec()),
			block_number: receipt.block_number.unwrap_or(0),
			success: receipt.inner.status(),
			logs,
			block_timestamp,
		}
	}
}

/// Filter parameters for querying event logs.
/// Topics are capped at 4 (Ethereum RPC limit) via the constructor.
#[derive(Debug, Clone)]
pub struct LogFilter {
	/// Contract address to filter logs from.
	pub address: Address,
	/// Block to start scanning from (inclusive).
	pub from_block: u64,
	/// Block to scan to (inclusive). None = latest.
	pub to_block: Option<u64>,
	/// Topic filters (private — enforced via constructor).
	topics: Vec<Option<H256>>,
}

impl LogFilter {
	/// Create a new log filter. Topics beyond 4 are truncated with a warning.
	pub fn new(
		address: Address,
		from_block: u64,
		to_block: Option<u64>,
		topics: Vec<Option<H256>>,
	) -> Self {
		let topics = if topics.len() > 4 {
			tracing::warn!("LogFilter topics truncated from {} to 4", topics.len());
			topics.into_iter().take(4).collect()
		} else {
			topics
		};
		Self {
			address,
			from_block,
			to_block,
			topics,
		}
	}

	/// Access the topic filters.
	pub fn topics(&self) -> &[Option<H256>] {
		&self.topics
	}
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
