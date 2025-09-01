//! Transaction receipt builder utilities for creating test and production TransactionReceipt instances.

use crate::{TransactionHash, TransactionReceipt};

/// Builder for creating TransactionReceipt instances with sensible defaults.
///
/// This builder provides a fluent interface for constructing TransactionReceipt objects,
/// particularly useful for testing and creating receipts with common patterns.
#[derive(Debug, Clone)]
pub struct TransactionReceiptBuilder {
	hash: TransactionHash,
	block_number: u64,
	success: bool,
}

impl Default for TransactionReceiptBuilder {
	fn default() -> Self {
		Self {
			hash: TransactionHash(vec![0x11; 32]),
			block_number: 12345,
			success: true,
		}
	}
}

impl TransactionReceiptBuilder {
	/// Creates a new TransactionReceiptBuilder with default values.
	pub fn new() -> Self {
		Self::default()
	}

	/// Sets the transaction hash.
	pub fn with_hash(mut self, hash: TransactionHash) -> Self {
		self.hash = hash;
		self
	}

	/// Sets the block number.
	pub fn with_block_number(mut self, block_number: u64) -> Self {
		self.block_number = block_number;
		self
	}

	/// Sets the success status.
	pub fn with_success(mut self, success: bool) -> Self {
		self.success = success;
		self
	}

	/// Convenience method to create a successful receipt.
	pub fn successful(mut self) -> Self {
		self.success = true;
		self
	}

	/// Convenience method to create a failed receipt.
	pub fn failed(mut self) -> Self {
		self.success = false;
		self
	}

	/// Builds the TransactionReceipt instance.
	pub fn build(self) -> TransactionReceipt {
		TransactionReceipt {
			hash: self.hash,
			block_number: self.block_number,
			success: self.success,
		}
	}
}
