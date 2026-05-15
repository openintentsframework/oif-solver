use crate::{
	current_timestamp, Address, Transaction, TransactionHash, TransactionReceipt, TransactionType,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TransactionAttemptStatus {
	Planned,
	Broadcast,
	Confirmed,
	SubmitRejected,
	Reverted,
	Indeterminate,
}

impl TransactionAttemptStatus {
	pub fn is_terminal(self) -> bool {
		matches!(
			self,
			Self::Confirmed | Self::SubmitRejected | Self::Reverted
		)
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionAttempt {
	pub id: String,
	pub order_id: String,
	pub signer: Option<Address>,
	pub tx_type: TransactionType,
	pub chain_id: u64,
	pub nonce: Option<u64>,
	pub tx_hash: Option<TransactionHash>,
	pub receipt: Option<TransactionReceipt>,
	pub tx: Transaction,
	pub status: TransactionAttemptStatus,
	pub error: Option<String>,
	pub created_at: u64,
	pub updated_at: u64,
}

impl TransactionAttempt {
	pub fn planned(
		id: String,
		order_id: String,
		signer: Option<Address>,
		tx_type: TransactionType,
		tx: Transaction,
	) -> Self {
		let now = current_timestamp();
		Self {
			id,
			order_id,
			signer,
			tx_type,
			chain_id: tx.chain_id,
			nonce: tx.nonce,
			tx_hash: None,
			receipt: None,
			tx,
			status: TransactionAttemptStatus::Planned,
			error: None,
			created_at: now,
			updated_at: now,
		}
	}

	pub fn is_terminal(&self) -> bool {
		self.status.is_terminal()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{Address, Log, TransactionHash, TransactionReceipt};
	use alloy_primitives::U256;

	fn sample_tx() -> Transaction {
		Transaction {
			to: Some(Address(vec![1; 20])),
			data: vec![0xab, 0xcd],
			value: U256::from(5u64),
			chain_id: 10,
			nonce: Some(7),
			gas_limit: Some(21000),
			gas_price: None,
			max_fee_per_gas: Some(100),
			max_priority_fee_per_gas: Some(2),
		}
	}

	#[test]
	fn planned_attempt_copies_tx_metadata() {
		let attempt = TransactionAttempt::planned(
			"attempt-1".to_string(),
			"order-1".to_string(),
			Some(Address(vec![9; 20])),
			TransactionType::Fill,
			sample_tx(),
		);

		assert_eq!(attempt.id, "attempt-1");
		assert_eq!(attempt.order_id, "order-1");
		assert_eq!(attempt.signer, Some(Address(vec![9; 20])));
		assert_eq!(attempt.tx_type, TransactionType::Fill);
		assert_eq!(attempt.chain_id, 10);
		assert_eq!(attempt.nonce, Some(7));
		assert_eq!(attempt.tx_hash, None);
		assert_eq!(attempt.receipt, None);
		assert_eq!(attempt.status, TransactionAttemptStatus::Planned);
		assert_eq!(attempt.error, None);
		assert!(!attempt.is_terminal());
		assert!(attempt.created_at > 0);
		assert_eq!(attempt.created_at, attempt.updated_at);
	}

	#[test]
	fn terminal_statuses_are_explicit() {
		assert!(!TransactionAttemptStatus::Planned.is_terminal());
		assert!(!TransactionAttemptStatus::Broadcast.is_terminal());
		assert!(!TransactionAttemptStatus::Indeterminate.is_terminal());
		assert!(TransactionAttemptStatus::Confirmed.is_terminal());
		assert!(TransactionAttemptStatus::SubmitRejected.is_terminal());
		assert!(TransactionAttemptStatus::Reverted.is_terminal());
	}

	#[test]
	fn status_serializes_as_camel_case() {
		let json = serde_json::to_string(&TransactionAttemptStatus::SubmitRejected).unwrap();
		assert_eq!(json, "\"submitRejected\"");
	}

	#[test]
	fn attempt_round_trips_through_json() {
		let mut attempt = TransactionAttempt::planned(
			"attempt-1".to_string(),
			"order-1".to_string(),
			Some(Address(vec![9; 20])),
			TransactionType::Fill,
			sample_tx(),
		);
		attempt.tx_hash = Some(TransactionHash(vec![4; 32]));
		attempt.receipt = Some(TransactionReceipt {
			hash: TransactionHash(vec![4; 32]),
			block_number: 123,
			success: true,
			logs: vec![Log {
				address: Address(vec![8; 20]),
				topics: vec![],
				data: vec![0xaa],
			}],
			block_timestamp: Some(456),
		});
		attempt.status = TransactionAttemptStatus::Broadcast;
		attempt.error = Some("temporary rpc timeout".to_string());

		let json = serde_json::to_string(&attempt).unwrap();
		let decoded: TransactionAttempt = serde_json::from_str(&json).unwrap();

		assert_eq!(decoded.id, attempt.id);
		assert_eq!(decoded.order_id, attempt.order_id);
		assert_eq!(decoded.signer, attempt.signer);
		assert_eq!(decoded.tx_type, attempt.tx_type);
		assert_eq!(decoded.chain_id, attempt.chain_id);
		assert_eq!(decoded.nonce, attempt.nonce);
		assert_eq!(decoded.tx_hash.as_ref().unwrap().0, vec![4; 32]);
		assert_eq!(decoded.receipt.as_ref().unwrap().block_number, 123);
		assert!(decoded.receipt.as_ref().unwrap().success);
		assert_eq!(decoded.status, attempt.status);
		assert_eq!(decoded.error, attempt.error);
		assert_eq!(decoded.tx.data, attempt.tx.data);
		assert_eq!(decoded.tx.chain_id, attempt.tx.chain_id);
	}
}
