//! Durable transaction attempt storage.
//!
//! This ledger tracks delivery attempts separately from the order lifecycle so
//! recovery can reason about what was broadcast without adding transport states
//! to `OrderStatus`.

use std::sync::Arc;

use solver_delivery::{
	PlannedAttemptInit, TransactionAttemptRecorder, TransactionAttemptRecorderError,
};
use solver_storage::{QueryFilter, StorageError, StorageIndexes, StorageService};
use solver_types::{
	current_timestamp, Address, StorageKey, Transaction, TransactionAttempt,
	TransactionAttemptScope, TransactionAttemptStatus, TransactionHash, TransactionReceipt,
	TransactionType,
};
use thiserror::Error;
use uuid::Uuid;

const ORDER_ID_INDEX_FIELD: &str = "order_id";
const SCOPE_KIND_INDEX_FIELD: &str = "scope_kind";
const SCOPE_ID_INDEX_FIELD: &str = "scope_id";
const TX_HASH_INDEX_FIELD: &str = "tx_hash";
const IS_TERMINAL_INDEX_FIELD: &str = "is_terminal";
const SCOPE_KIND_ORDER: &str = "order";
const SCOPE_KIND_SYSTEM: &str = "system";

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
	let scope_kind = if attempt.scope.is_system() {
		SCOPE_KIND_SYSTEM
	} else {
		SCOPE_KIND_ORDER
	};
	let mut indexes = StorageIndexes::new()
		.with_field(SCOPE_KIND_INDEX_FIELD, scope_kind)
		.with_field(SCOPE_ID_INDEX_FIELD, attempt.scope_id())
		.with_field(IS_TERMINAL_INDEX_FIELD, attempt.is_terminal());

	if let Some(order_id) = attempt.order_id() {
		indexes = indexes.with_field(ORDER_ID_INDEX_FIELD, order_id);
	}

	if let Some(tx_hash) = &attempt.tx_hash {
		indexes = indexes.with_field(TX_HASH_INDEX_FIELD, tx_hash_index_value(tx_hash));
	}

	indexes
}

impl TransactionAttemptStore {
	pub fn new(storage: Arc<StorageService>) -> Self {
		Self { storage }
	}

	/// **Legacy direct constructor.** New callers MUST prefer the trait method
	/// [`TransactionAttemptRecorder::record_planned_attempt`] which carries a
	/// `PlannedAttemptInit` and sets the `replacement_of` lineage field.
	/// This method leaves `replacement_of` as `None` regardless of context;
	/// the recovery service still uses it because it never bumps a tx, but
	/// any code path that participates in same-nonce gas bumping MUST use
	/// the trait carrier.
	pub async fn create_planned_attempt(
		&self,
		order_id: &str,
		signer: Option<Address>,
		tx_type: TransactionType,
		tx: Transaction,
	) -> Result<TransactionAttempt, TransactionAttemptStoreError> {
		let attempt = TransactionAttempt::planned(
			Uuid::new_v4().hyphenated().to_string(),
			TransactionAttemptScope::order(order_id),
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
			.query::<TransactionAttempt>(
				StorageKey::TransactionAttempts.as_str(),
				QueryFilter::Equals(
					ORDER_ID_INDEX_FIELD.to_string(),
					serde_json::json!(order_id),
				),
			)
			.await?;
		Ok(rows.into_iter().map(|(_, attempt)| attempt).collect())
	}

	pub async fn non_terminal_system_attempts(
		&self,
	) -> Result<Vec<TransactionAttempt>, TransactionAttemptStoreError> {
		let rows = self
			.storage
			.query::<TransactionAttempt>(
				StorageKey::TransactionAttempts.as_str(),
				QueryFilter::Equals(
					SCOPE_KIND_INDEX_FIELD.to_string(),
					serde_json::json!(SCOPE_KIND_SYSTEM),
				),
			)
			.await?;
		Ok(rows
			.into_iter()
			.map(|(_, attempt)| attempt)
			.filter(|attempt| !attempt.is_terminal())
			.collect())
	}

	pub async fn non_terminal_order_attempts(
		&self,
	) -> Result<Vec<TransactionAttempt>, TransactionAttemptStoreError> {
		let rows = self
			.storage
			.query::<TransactionAttempt>(
				StorageKey::TransactionAttempts.as_str(),
				QueryFilter::Equals(
					IS_TERMINAL_INDEX_FIELD.to_string(),
					serde_json::json!(false),
				),
			)
			.await?;
		Ok(rows
			.into_iter()
			.map(|(_, attempt)| attempt)
			.filter(|attempt| matches!(attempt.scope, TransactionAttemptScope::Order { .. }))
			.collect())
	}

	pub async fn attempts_for_system_scope(
		&self,
		scope_id: &str,
	) -> Result<Vec<TransactionAttempt>, TransactionAttemptStoreError> {
		let rows = self
			.storage
			.query::<TransactionAttempt>(
				StorageKey::TransactionAttempts.as_str(),
				QueryFilter::Equals(
					SCOPE_ID_INDEX_FIELD.to_string(),
					serde_json::json!(scope_id),
				),
			)
			.await?;
		Ok(rows
			.into_iter()
			.map(|(_, attempt)| attempt)
			.filter(|attempt| {
				matches!(
					&attempt.scope,
					TransactionAttemptScope::System { scope_id: stored } if stored == scope_id
				)
			})
			.collect())
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

	/// Sets `attempt.replaced_by = Some(child_id)` for a non-terminal parent.
	/// CAS-protected. Silently no-ops if the parent transitioned to terminal
	/// between read and write (the sweeper's lineage traversal will discover
	/// the child via `child.replacement_of` anyway, so missing this hint is
	/// harmless).
	pub async fn set_replaced_by(
		&self,
		parent_id: &str,
		child_id: &str,
	) -> Result<(), TransactionAttemptStoreError> {
		let namespace = StorageKey::TransactionAttempts.as_str();
		let current_bytes = self.storage.retrieve_bytes(namespace, parent_id).await?;
		let mut attempt: TransactionAttempt = serde_json::from_slice(&current_bytes)
			.map_err(|e| TransactionAttemptStoreError::Storage(e.to_string()))?;

		if attempt.is_terminal() {
			// Parent already terminal; lineage stays valid via child.replacement_of.
			return Ok(());
		}

		attempt.replaced_by = Some(child_id.to_string());
		attempt.updated_at = current_timestamp();

		let updated_bytes = serde_json::to_vec(&attempt)
			.map_err(|e| TransactionAttemptStoreError::Storage(e.to_string()))?;

		let _ = self
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
		// Accept CAS-conflict as "parent transitioned mid-call"; same outcome as
		// the terminal check above. We don't propagate a conflict error because
		// the sweeper's set_replaced_by is a best-effort optimization.
		Ok(())
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

	pub async fn mark_attempt_confirmed_from_receipt(
		&self,
		attempt_id: &str,
		tx_hash: TransactionHash,
		receipt: TransactionReceipt,
	) -> Result<TransactionAttempt, TransactionAttemptStoreError> {
		self.update_attempt_status(
			attempt_id,
			TransactionAttemptStatus::Confirmed,
			None,
			|attempt| {
				attempt.tx_hash = Some(tx_hash.clone());
				attempt.receipt = Some(receipt.clone());
			},
		)
		.await
	}
}

#[async_trait::async_trait]
impl TransactionAttemptRecorder for TransactionAttemptStore {
	async fn record_planned_attempt(
		&self,
		init: PlannedAttemptInit,
	) -> Result<TransactionAttempt, TransactionAttemptRecorderError> {
		let id = init
			.attempt_id_override
			.unwrap_or_else(|| Uuid::new_v4().hyphenated().to_string());
		let mut attempt =
			TransactionAttempt::planned(id, init.scope, init.signer, init.tx_type, init.tx);
		attempt.replacement_of = init.replacement_of;
		self.save_attempt(&attempt)
			.await
			.map_err(|e| TransactionAttemptRecorderError::Storage(e.to_string()))?;
		Ok(attempt)
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

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::U256;
	use solver_storage::implementations::file::{FileStorage, TtlConfig};

	fn test_storage() -> (Arc<StorageService>, tempfile::TempDir) {
		let temp_dir = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp_dir.path().to_path_buf(),
			TtlConfig::default(),
		))));
		(storage, temp_dir)
	}

	fn sample_tx() -> Transaction {
		Transaction {
			to: Some(Address(vec![2; 20])),
			data: vec![1, 2, 3],
			value: U256::ZERO,
			chain_id: 1,
			nonce: Some(11),
			gas_limit: Some(100_000),
			gas_price: None,
			max_fee_per_gas: Some(1_000),
			max_priority_fee_per_gas: Some(10),
		}
	}

	#[tokio::test]
	async fn record_planned_attempt_uses_attempt_id_override_when_provided() {
		let (storage, _tmp) = test_storage();
		let store = TransactionAttemptStore::new(storage);
		let init = PlannedAttemptInit {
			scope: TransactionAttemptScope::order("order-1"),
			signer: Some(Address(vec![9; 20])),
			tx_type: TransactionType::Fill,
			tx: sample_tx(),
			attempt_id_override: Some("forced-id".into()),
			replacement_of: Some("parent-id".into()),
		};
		let attempt = store.record_planned_attempt(init).await.unwrap();
		assert_eq!(attempt.id, "forced-id");
		assert_eq!(attempt.replacement_of.as_deref(), Some("parent-id"));
		assert!(attempt.replaced_by.is_none());
	}

	#[tokio::test]
	async fn record_planned_attempt_generates_id_when_override_absent() {
		let (storage, _tmp) = test_storage();
		let store = TransactionAttemptStore::new(storage);
		let init = PlannedAttemptInit {
			scope: TransactionAttemptScope::order("order-1"),
			signer: None,
			tx_type: TransactionType::Fill,
			tx: sample_tx(),
			attempt_id_override: None,
			replacement_of: None,
		};
		let attempt = store.record_planned_attempt(init).await.unwrap();
		let parsed = uuid::Uuid::parse_str(&attempt.id).expect("attempt id must be a UUID");
		assert_eq!(parsed.get_version(), Some(uuid::Version::Random)); // v4
		assert!(attempt.replacement_of.is_none());
	}

	#[tokio::test]
	async fn set_replaced_by_succeeds_for_non_terminal_parent() {
		let (storage, _tmp) = test_storage();
		let store = TransactionAttemptStore::new(storage);

		let parent = store
			.record_planned_attempt(solver_delivery::PlannedAttemptInit {
				scope: TransactionAttemptScope::order("o"),
				signer: None,
				tx_type: TransactionType::Fill,
				tx: sample_tx(),
				attempt_id_override: Some("parent".into()),
				replacement_of: None,
			})
			.await
			.unwrap();

		store
			.update_attempt_status(&parent.id, TransactionAttemptStatus::Broadcast, None, |a| {
				a.tx_hash = Some(TransactionHash(vec![0xaa; 32]));
			})
			.await
			.unwrap();

		store.set_replaced_by(&parent.id, "child-1").await.unwrap();

		let reloaded = store.get_attempt(&parent.id).await.unwrap();
		assert_eq!(reloaded.replaced_by.as_deref(), Some("child-1"));
	}

	#[tokio::test]
	async fn set_replaced_by_silently_skips_terminal_parent() {
		let (storage, _tmp) = test_storage();
		let store = TransactionAttemptStore::new(storage);

		let parent = store
			.record_planned_attempt(solver_delivery::PlannedAttemptInit {
				scope: TransactionAttemptScope::order("o"),
				signer: None,
				tx_type: TransactionType::Fill,
				tx: sample_tx(),
				attempt_id_override: Some("parent".into()),
				replacement_of: None,
			})
			.await
			.unwrap();

		// Transition parent to Confirmed (terminal).
		store
			.update_attempt_status(
				&parent.id,
				TransactionAttemptStatus::Confirmed,
				None,
				|_| {},
			)
			.await
			.unwrap();

		// Terminal parent; set_replaced_by should NOT error, should NOT overwrite.
		store.set_replaced_by(&parent.id, "child-1").await.unwrap();

		let reloaded = store.get_attempt(&parent.id).await.unwrap();
		assert!(reloaded.replaced_by.is_none());
		assert_eq!(reloaded.status, TransactionAttemptStatus::Confirmed);
	}

	#[tokio::test]
	async fn update_attempt_status_can_write_replaced_from_broadcast() {
		let (storage, _tmp) = test_storage();
		let store = TransactionAttemptStore::new(storage);

		let a = store
			.record_planned_attempt(solver_delivery::PlannedAttemptInit {
				scope: TransactionAttemptScope::order("o"),
				signer: None,
				tx_type: TransactionType::Fill,
				tx: sample_tx(),
				attempt_id_override: Some("loser".into()),
				replacement_of: Some("parent".into()),
			})
			.await
			.unwrap();
		store
			.update_attempt_status(
				&a.id,
				TransactionAttemptStatus::Broadcast,
				None,
				|attempt| {
					attempt.tx_hash = Some(TransactionHash(vec![0xbb; 32]));
				},
			)
			.await
			.unwrap();

		let updated = store
			.update_attempt_status(
				&a.id,
				TransactionAttemptStatus::Replaced,
				Some("superseded by winner".into()),
				|_| {},
			)
			.await
			.unwrap();

		assert_eq!(updated.status, TransactionAttemptStatus::Replaced);
		assert!(updated.is_terminal());
	}

	#[tokio::test]
	async fn update_attempt_status_rejects_replaced_from_terminal() {
		let (storage, _tmp) = test_storage();
		let store = TransactionAttemptStore::new(storage);

		let a = store
			.record_planned_attempt(solver_delivery::PlannedAttemptInit {
				scope: TransactionAttemptScope::order("o"),
				signer: None,
				tx_type: TransactionType::Fill,
				tx: sample_tx(),
				attempt_id_override: Some("loser".into()),
				replacement_of: Some("parent".into()),
			})
			.await
			.unwrap();
		store
			.update_attempt_status(&a.id, TransactionAttemptStatus::Reverted, None, |_| {})
			.await
			.unwrap();

		let err = store
			.update_attempt_status(&a.id, TransactionAttemptStatus::Replaced, None, |_| {})
			.await
			.unwrap_err();

		assert!(matches!(
			err,
			TransactionAttemptStoreError::TerminalAttempt(_)
		));
	}
}
