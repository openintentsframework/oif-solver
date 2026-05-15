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
/// Contains event data and indexed parameters (topics), plus optional
/// transaction metadata (`transaction_hash`, `block_number`) that is
/// populated when the log originates from a `getLogs` or receipt response.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Log {
	/// Contract address that emitted the log.
	pub address: Address,
	/// Indexed event parameters.
	/// Topic[0] is typically the event signature hash.
	pub topics: Vec<H256>,
	/// Non-indexed event data.
	pub data: Vec<u8>,
	/// Hash of the transaction that emitted this log. `None` when the log
	/// came from a source that doesn't carry tx metadata (e.g., test fixtures).
	#[serde(default)]
	pub transaction_hash: Option<TransactionHash>,
	/// Block that included the emitting transaction. `None` for unknown.
	#[serde(default)]
	pub block_number: Option<u64>,
}

impl Default for Log {
	fn default() -> Self {
		Self {
			address: Address(Vec::new()),
			topics: Vec::new(),
			data: Vec::new(),
			transaction_hash: None,
			block_number: None,
		}
	}
}

#[cfg(test)]
mod log_tests {
	use super::*;

	#[test]
	fn log_default_has_no_tx_metadata() {
		let log = Log::default();
		assert!(log.transaction_hash.is_none());
		assert!(log.block_number.is_none());
		assert!(log.address.0.is_empty());
		assert!(log.topics.is_empty());
		assert!(log.data.is_empty());
	}

	#[test]
	fn log_carries_optional_tx_metadata() {
		let log = Log {
			address: Address(vec![0xab; 20]),
			topics: vec![H256([0x01; 32])],
			data: vec![0xde, 0xad],
			transaction_hash: Some(TransactionHash(vec![0xcc; 32])),
			block_number: Some(123_456),
		};
		assert_eq!(log.block_number, Some(123_456));
		assert_eq!(log.transaction_hash.unwrap().0.len(), 32);
	}
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
				transaction_hash: log.transaction_hash.map(|h| TransactionHash(h.0.to_vec())),
				block_number: log.block_number,
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
	/// Quote-cost-per-gas in wei (decimal string), sourced from the
	/// delivery layer's resolved [`FeeParams::cost_per_gas`]. This is the
	/// same value used to price quote gas legs, not raw `eth_gasPrice`.
	pub gas_price: String,
	/// Latest block number.
	pub block_number: u64,
	/// Timestamp when this data was fetched (Unix timestamp).
	pub timestamp: u64,
}
