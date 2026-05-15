//! Durable transaction attempt storage.
//!
//! This ledger tracks delivery attempts separately from the order lifecycle so
//! recovery can reason about what was broadcast without adding transport states
//! to `OrderStatus`.

use std::sync::Arc;

use solver_delivery::{TransactionAttemptRecorder, TransactionAttemptRecorderError};
use solver_storage::{QueryFilter, StorageError, StorageIndexes, StorageService};
use solver_types::{
	current_timestamp, Address, StorageKey, Transaction, TransactionAttempt,
	TransactionAttemptStatus, TransactionHash, TransactionReceipt, TransactionType,
};
use thiserror::Error;
use uuid::Uuid;

const ORDER_ID_INDEX_FIELD: &str = "order_id";
const TX_HASH_INDEX_FIELD: &str = "tx_hash";
const IS_TERMINAL_INDEX_FIELD: &str = "is_terminal";

#[derive(Debug, Error)]
pub enum TransactionAttemptStoreError {
	#[error("storage error: {0}")]
	Storage(String),
	#[error("transaction attempt not found: {0}")]
	NotFound(String),
	#[error("transaction attempt is terminal and cannot be updated: {0}")]
	TerminalAttempt(String),
	#[error("transaction attempt changed concurrently: {0}")]
	ConcurrentModification(String),
}

impl From<StorageError> for TransactionAttemptStoreError {
	fn from(value: StorageError) -> Self {
		match value {
			StorageError::NotFound(id) => Self::NotFound(id),
			other => Self::Storage(other.to_string()),
		}
	}
}

pub struct TransactionAttemptStore {
	storage: Arc<StorageService>,
}

fn tx_hash_index_value(tx_hash: &TransactionHash) -> String {
	hex::encode(&tx_hash.0)
}

fn transaction_attempt_indexes(attempt: &TransactionAttempt) -> StorageIndexes {
	let mut indexes = StorageIndexes::new()
		.with_field(ORDER_ID_INDEX_FIELD, &attempt.order_id)
		.with_field(IS_TERMINAL_INDEX_FIELD, attempt.is_terminal());

	if let Some(tx_hash) = &attempt.tx_hash {
		indexes = indexes.with_field(TX_HASH_INDEX_FIELD, tx_hash_index_value(tx_hash));
	}

	indexes
}

impl TransactionAttemptStore {
	pub fn new(storage: Arc<StorageService>) -> Self {
		Self { storage }
	}

	pub async fn create_planned_attempt(
		&self,
		order_id: &str,
		signer: Option<Address>,
		tx_type: TransactionType,
		tx: Transaction,
	) -> Result<TransactionAttempt, TransactionAttemptStoreError> {
		let attempt = TransactionAttempt::planned(
			Uuid::new_v4().hyphenated().to_string(),
			order_id.to_string(),
			signer,
			tx_type,
			tx,
		);
		self.save_attempt(&attempt).await?;
		Ok(attempt)
	}

	pub async fn save_attempt(
		&self,
		attempt: &TransactionAttempt,
	) -> Result<(), TransactionAttemptStoreError> {
		self.storage
			.store(
				StorageKey::TransactionAttempts.as_str(),
				&attempt.id,
				attempt,
				Some(transaction_attempt_indexes(attempt)),
			)
			.await?;
		Ok(())
	}

	pub async fn get_attempt(
		&self,
		attempt_id: &str,
	) -> Result<TransactionAttempt, TransactionAttemptStoreError> {
		Ok(self
			.storage
			.retrieve(StorageKey::TransactionAttempts.as_str(), attempt_id)
			.await?)
	}

	pub async fn attempts_for_order(
		&self,
		order_id: &str,
	) -> Result<Vec<TransactionAttempt>, TransactionAttemptStoreError> {
		let rows = self
			.storage
			.query(
				StorageKey::TransactionAttempts.as_str(),
				QueryFilter::Equals(
					ORDER_ID_INDEX_FIELD.to_string(),
					serde_json::json!(order_id),
				),
			)
			.await?;
		Ok(rows.into_iter().map(|(_, attempt)| attempt).collect())
	}

	pub async fn attempt_by_hash(
		&self,
		tx_hash: &TransactionHash,
	) -> Result<Option<TransactionAttempt>, TransactionAttemptStoreError> {
		let rows = self
			.storage
			.query(
				StorageKey::TransactionAttempts.as_str(),
				QueryFilter::Equals(
					TX_HASH_INDEX_FIELD.to_string(),
					serde_json::json!(tx_hash_index_value(tx_hash)),
				),
			)
			.await?;
		Ok(rows.into_iter().map(|(_, attempt)| attempt).next())
	}

	pub async fn update_attempt_status<F>(
		&self,
		attempt_id: &str,
		status: TransactionAttemptStatus,
		error: Option<String>,
		mutate: F,
	) -> Result<TransactionAttempt, TransactionAttemptStoreError>
	where
		F: FnOnce(&mut TransactionAttempt),
	{
		let namespace = StorageKey::TransactionAttempts.as_str();
		let current_bytes = self.storage.retrieve_bytes(namespace, attempt_id).await?;
		let mut attempt: TransactionAttempt = serde_json::from_slice(&current_bytes)
			.map_err(|e| TransactionAttemptStoreError::Storage(e.to_string()))?;

		if attempt.is_terminal() {
			return Err(TransactionAttemptStoreError::TerminalAttempt(
				attempt_id.to_string(),
			));
		}

		mutate(&mut attempt);
		attempt.status = status;
		attempt.error = error;
		attempt.updated_at = current_timestamp();

		let updated_bytes = serde_json::to_vec(&attempt)
			.map_err(|e| TransactionAttemptStoreError::Storage(e.to_string()))?;

		let swapped = self
			.storage
			.compare_and_swap_bytes(
				namespace,
				&attempt.id,
				&current_bytes,
				updated_bytes,
				Some(transaction_attempt_indexes(&attempt)),
				None,
			)
			.await?;

		if swapped {
			return Ok(attempt);
		}

		let latest_bytes = self.storage.retrieve_bytes(namespace, attempt_id).await?;
		let latest: TransactionAttempt = serde_json::from_slice(&latest_bytes)
			.map_err(|e| TransactionAttemptStoreError::Storage(e.to_string()))?;

		if latest.is_terminal() {
			return Err(TransactionAttemptStoreError::TerminalAttempt(
				attempt_id.to_string(),
			));
		}

		Err(TransactionAttemptStoreError::ConcurrentModification(
			attempt_id.to_string(),
		))
	}
}

#[async_trait::async_trait]
impl TransactionAttemptRecorder for TransactionAttemptStore {
	async fn record_planned_attempt(
		&self,
		order_id: &str,
		signer: Option<Address>,
		tx_type: TransactionType,
		tx: Transaction,
	) -> Result<TransactionAttempt, TransactionAttemptRecorderError> {
		self.create_planned_attempt(order_id, signer, tx_type, tx)
			.await
			.map_err(|e| TransactionAttemptRecorderError::Storage(e.to_string()))
	}

	async fn record_attempt_update(
		&self,
		attempt_id: &str,
		status: TransactionAttemptStatus,
		tx_hash: Option<TransactionHash>,
		receipt: Option<TransactionReceipt>,
		error: Option<String>,
	) -> Result<(), TransactionAttemptRecorderError> {
		self.update_attempt_status(attempt_id, status, error, |attempt| {
			if let Some(tx_hash) = tx_hash {
				attempt.tx_hash = Some(tx_hash);
			}
			if let Some(receipt) = receipt {
				attempt.receipt = Some(receipt);
			}
		})
		.await
		.map_err(|e| TransactionAttemptRecorderError::Storage(e.to_string()))?;
		Ok(())
	}
}
