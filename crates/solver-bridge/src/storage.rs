//! Bridge transfer persistence helpers.
//!
//! Stores and queries `PendingBridgeTransfer` records in Redis via `StorageService`.
//! Transfers are indexed by status, pair_id, source/dest chain, and trigger
//! so that active/history queries do not require scanning every key.

use crate::types::{BridgeTransferStatus, PendingBridgeTransfer};
use solver_storage::{QueryFilter, StorageError, StorageIndexes, StorageService};
use solver_types::{
	current_timestamp, StorageKey, TransactionAttempt, TransactionAttemptScope,
	TransactionAttemptStatus,
};
use std::sync::Arc;
use std::time::Duration;

/// Storage namespace for bridge transfers.
const BRIDGE_TRANSFER_NS: &str = "bridge-transfer";

/// Storage namespace for cooldown keys.
const BRIDGE_COOLDOWN_NS: &str = "bridge-cooldown";

/// TTL for completed/failed transfers (7 days).
const TERMINAL_TRANSFER_TTL: Duration = Duration::from_secs(7 * 24 * 3600);

const RETIRE_SYSTEM_ATTEMPT_CAS_RETRIES: usize = 3;

/// Manages bridge transfer persistence.
pub struct BridgeStorage {
	storage: Arc<StorageService>,
	solver_id: String,
}

impl BridgeStorage {
	pub fn new(storage: Arc<StorageService>, solver_id: String) -> Self {
		Self { storage, solver_id }
	}

	pub(crate) fn storage_service(&self) -> Arc<StorageService> {
		self.storage.clone()
	}

	/// Full namespace prefix for this solver's bridge transfers.
	fn namespace(&self) -> String {
		format!("{}-{}", self.solver_id, BRIDGE_TRANSFER_NS)
	}

	/// Cooldown namespace for this solver.
	fn cooldown_namespace(&self) -> String {
		format!("{}-{}", self.solver_id, BRIDGE_COOLDOWN_NS)
	}

	/// Build storage indexes for a transfer.
	fn build_indexes(transfer: &PendingBridgeTransfer) -> StorageIndexes {
		let status_str = match &transfer.status {
			BridgeTransferStatus::WrapPending => "wrap_pending",
			BridgeTransferStatus::Submitted => "submitted",
			BridgeTransferStatus::Relaying => "relaying",
			BridgeTransferStatus::PendingRedemption => "pending_redemption",
			BridgeTransferStatus::UnwrapPending => "unwrap_pending",
			BridgeTransferStatus::Completed => "completed",
			BridgeTransferStatus::Failed(_) => "failed",
			BridgeTransferStatus::NeedsIntervention(_) => "needs_intervention",
		};

		let trigger_str = match &transfer.trigger {
			crate::types::RebalanceTrigger::Auto => "auto",
			crate::types::RebalanceTrigger::Manual => "manual",
		};

		StorageIndexes::new()
			.with_field("status", status_str)
			.with_field("pair_id", &transfer.pair_id)
			.with_field("source_chain", transfer.source_chain)
			.with_field("dest_chain", transfer.dest_chain)
			.with_field("trigger", trigger_str)
	}

	/// Store a new or updated transfer.
	///
	/// Terminal transfers (Completed, Failed) get a TTL so they auto-expire.
	/// Non-terminal transfers (including NeedsIntervention) have no TTL because
	/// they require admin resolution and must not silently disappear.
	pub async fn save_transfer(
		&self,
		transfer: &PendingBridgeTransfer,
	) -> Result<(), StorageError> {
		let indexes = Self::build_indexes(transfer);

		if transfer.status.is_terminal() {
			self.storage
				.store_with_ttl(
					&self.namespace(),
					&transfer.id,
					transfer,
					Some(indexes),
					Some(TERMINAL_TRANSFER_TTL),
				)
				.await
		} else {
			self.storage
				.store(&self.namespace(), &transfer.id, transfer, Some(indexes))
				.await
		}
	}

	/// Retrieve a transfer by ID.
	pub async fn get_transfer(&self, id: &str) -> Result<PendingBridgeTransfer, StorageError> {
		self.storage.retrieve(&self.namespace(), id).await
	}

	/// Get all active (non-terminal) transfers.
	pub async fn get_active_transfers(&self) -> Result<Vec<PendingBridgeTransfer>, StorageError> {
		let mut active = Vec::new();

		for status in &[
			"wrap_pending",
			"submitted",
			"relaying",
			"pending_redemption",
			"unwrap_pending",
			"needs_intervention",
		] {
			let filter = QueryFilter::Equals(
				"status".to_string(),
				serde_json::Value::String(status.to_string()),
			);
			let results: Vec<(String, PendingBridgeTransfer)> =
				self.storage.query(&self.namespace(), filter).await?;
			active.extend(results.into_iter().map(|(_, t)| t));
		}

		Ok(active)
	}

	/// Get active transfers for a specific pair.
	pub async fn get_active_transfers_for_pair(
		&self,
		pair_id: &str,
	) -> Result<Vec<PendingBridgeTransfer>, StorageError> {
		let all_active = self.get_active_transfers().await?;
		Ok(all_active
			.into_iter()
			.filter(|t| t.pair_id == pair_id)
			.collect())
	}

	/// Get completed/failed transfers (for history).
	pub async fn get_transfer_history(
		&self,
		limit: usize,
	) -> Result<Vec<PendingBridgeTransfer>, StorageError> {
		let mut history = Vec::new();

		for status in &["completed", "failed"] {
			let filter = QueryFilter::Equals(
				"status".to_string(),
				serde_json::Value::String(status.to_string()),
			);
			let results: Vec<(String, PendingBridgeTransfer)> =
				self.storage.query(&self.namespace(), filter).await?;
			history.extend(results.into_iter().map(|(_, t)| t));
		}

		// Sort by updated_at descending
		history.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
		history.truncate(limit);

		Ok(history)
	}

	/// Count active (non-terminal) transfers.
	pub async fn active_transfer_count(&self) -> Result<usize, StorageError> {
		Ok(self.get_active_transfers().await?.len())
	}

	/// Check if a cooldown is active for a pair.
	pub async fn is_cooldown_active(&self, pair_id: &str) -> Result<bool, StorageError> {
		self.storage
			.exists(&self.cooldown_namespace(), pair_id)
			.await
	}

	/// Set a cooldown for a pair with the given TTL.
	pub async fn set_cooldown(&self, pair_id: &str, ttl_seconds: u64) -> Result<(), StorageError> {
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs();

		self.storage
			.store_with_ttl(
				&self.cooldown_namespace(),
				pair_id,
				&serde_json::json!({ "set_at": now }),
				None,
				Some(Duration::from_secs(ttl_seconds)),
			)
			.await
	}
}

fn transaction_attempt_indexes(attempt: &TransactionAttempt) -> StorageIndexes {
	let scope_kind = if attempt.scope.is_system() {
		"system"
	} else {
		"order"
	};
	let mut indexes = StorageIndexes::new()
		.with_field("scope_kind", scope_kind)
		.with_field("scope_id", attempt.scope.scope_id())
		.with_field("is_terminal", attempt.is_terminal());

	if let Some(order_id) = attempt.scope.order_id() {
		indexes = indexes.with_field("order_id", order_id);
	}

	if let Some(tx_hash) = &attempt.tx_hash {
		indexes = indexes.with_field("tx_hash", hex::encode(&tx_hash.0));
	}

	indexes
}

pub(crate) async fn retire_system_attempt_scope(
	storage: &Arc<StorageService>,
	scope_id: &str,
	reason: &str,
) -> Result<(), crate::BridgeError> {
	let rows = storage
		.query::<TransactionAttempt>(
			StorageKey::TransactionAttempts.as_str(),
			QueryFilter::Equals("scope_id".to_string(), serde_json::json!(scope_id)),
		)
		.await
		.map_err(|e| crate::BridgeError::Storage(e.to_string()))?;

	for (attempt_id, attempt) in rows {
		if attempt.is_terminal()
			|| !matches!(
				&attempt.scope,
				TransactionAttemptScope::System { scope_id: stored } if stored == scope_id
			) {
			continue;
		}

		let namespace = StorageKey::TransactionAttempts.as_str();
		let mut retired = false;
		for _ in 0..RETIRE_SYSTEM_ATTEMPT_CAS_RETRIES {
			let current_bytes = storage
				.retrieve_bytes(namespace, &attempt_id)
				.await
				.map_err(|e| crate::BridgeError::Storage(e.to_string()))?;
			let mut current: TransactionAttempt = serde_json::from_slice(&current_bytes)
				.map_err(|e| crate::BridgeError::Storage(e.to_string()))?;
			if current.is_terminal()
				|| !matches!(
					&current.scope,
					TransactionAttemptScope::System { scope_id: stored } if stored == scope_id
				) {
				retired = true;
				break;
			}

			current.status = TransactionAttemptStatus::Replaced;
			current.error = Some(reason.to_string());
			current.updated_at = current_timestamp();
			let updated_bytes = serde_json::to_vec(&current)
				.map_err(|e| crate::BridgeError::Storage(e.to_string()))?;
			let swapped = storage
				.compare_and_swap_bytes(
					namespace,
					&attempt_id,
					&current_bytes,
					updated_bytes,
					Some(transaction_attempt_indexes(&current)),
					None,
				)
				.await
				.map_err(|e| crate::BridgeError::Storage(e.to_string()))?;
			if swapped {
				retired = true;
				break;
			}
		}

		if !retired {
			return Err(crate::BridgeError::Storage(format!(
				"concurrent update while retiring system attempt {attempt_id} for scope {scope_id}"
			)));
		}
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::test_support::pending_transfer;
	use alloy_primitives::U256;
	use solver_storage::implementations::file::{FileStorage, TtlConfig};
	use solver_storage::{MockStorageInterface, QueryFilter, StorageService};
	use solver_types::{Address, Transaction, TransactionHash, TransactionType};
	use std::fs;
	use std::path::{Path, PathBuf};
	use std::sync::atomic::{AtomicUsize, Ordering};
	use uuid::Uuid;

	fn make_storage() -> (BridgeStorage, PathBuf) {
		let base_path = std::env::temp_dir().join(format!("solver-bridge-test-{}", Uuid::new_v4()));
		fs::create_dir_all(&base_path).unwrap();
		let backend = FileStorage::new(base_path.clone(), TtlConfig::default());
		let storage = BridgeStorage::new(
			Arc::new(StorageService::new(Box::new(backend))),
			"solver-a".to_string(),
		);
		(storage, base_path)
	}

	fn storage_key(namespace: &str, id: &str) -> String {
		format!("{namespace}:{id}")
	}

	fn file_path(base_path: &Path, key: &str) -> PathBuf {
		base_path.join(format!("{}.bin", key.replace(['/', ':'], "_")))
	}

	fn file_expires_at(base_path: &Path, key: &str) -> u64 {
		let data = fs::read(file_path(base_path, key)).unwrap();
		let mut expires_bytes = [0u8; 8];
		expires_bytes.copy_from_slice(&data[6..14]);
		u64::from_le_bytes(expires_bytes)
	}

	fn sample_attempt(scope_id: &str) -> TransactionAttempt {
		let tx = Transaction {
			to: Some(Address(vec![0xbb; 20])),
			data: vec![0x12, 0x34],
			value: U256::ZERO,
			chain_id: 1,
			nonce: Some(5),
			gas_limit: Some(100000),
			gas_price: None,
			max_fee_per_gas: Some(100),
			max_priority_fee_per_gas: Some(2),
		};
		let mut attempt = TransactionAttempt::planned(
			"attempt-cas".to_string(),
			TransactionAttemptScope::system(scope_id.to_string()),
			Some(Address(vec![0xaa; 20])),
			TransactionType::Bridge,
			tx,
		);
		attempt.status = TransactionAttemptStatus::Broadcast;
		attempt.tx_hash = Some(TransactionHash(vec![0x11; 32]));
		attempt
	}

	#[tokio::test]
	async fn test_bridge_storage_save_transfer_sets_ttl_only_for_terminal_statuses() {
		let (storage, base_path) = make_storage();

		let mut completed = pending_transfer(BridgeTransferStatus::Completed);
		completed.id = "completed-1".to_string();
		let mut failed = pending_transfer(BridgeTransferStatus::Failed("boom".to_string()));
		failed.id = "failed-1".to_string();
		let mut active = pending_transfer(BridgeTransferStatus::NeedsIntervention(
			"manual review".to_string(),
		));
		active.id = "active-1".to_string();

		storage.save_transfer(&completed).await.unwrap();
		storage.save_transfer(&failed).await.unwrap();
		storage.save_transfer(&active).await.unwrap();

		assert!(
			file_expires_at(
				&base_path,
				&storage_key(&storage.namespace(), "completed-1")
			) > 0
		);
		assert!(file_expires_at(&base_path, &storage_key(&storage.namespace(), "failed-1")) > 0);
		assert_eq!(
			file_expires_at(&base_path, &storage_key(&storage.namespace(), "active-1")),
			0
		);
	}

	#[tokio::test]
	async fn test_bridge_storage_get_active_transfers_includes_all_active_statuses() {
		let (storage, _) = make_storage();

		let mut wrap_pending = pending_transfer(BridgeTransferStatus::WrapPending);
		wrap_pending.id = "wrap-pending-1".to_string();
		wrap_pending.pair_id = "eth-katana".to_string();
		let mut submitted = pending_transfer(BridgeTransferStatus::Submitted);
		submitted.id = "submitted-1".to_string();
		submitted.pair_id = "eth-katana".to_string();
		let mut relaying = pending_transfer(BridgeTransferStatus::Relaying);
		relaying.id = "relaying-1".to_string();
		relaying.pair_id = "eth-katana".to_string();
		let mut pending_redemption = pending_transfer(BridgeTransferStatus::PendingRedemption);
		pending_redemption.id = "pending-redemption-1".to_string();
		pending_redemption.pair_id = "eth-katana".to_string();
		let mut unwrap_pending = pending_transfer(BridgeTransferStatus::UnwrapPending);
		unwrap_pending.id = "unwrap-pending-1".to_string();
		unwrap_pending.pair_id = "eth-katana".to_string();
		let mut intervention = pending_transfer(BridgeTransferStatus::NeedsIntervention(
			"manual review".to_string(),
		));
		intervention.id = "intervention-1".to_string();
		intervention.pair_id = "eth-katana".to_string();

		storage.save_transfer(&wrap_pending).await.unwrap();
		storage.save_transfer(&submitted).await.unwrap();
		storage.save_transfer(&relaying).await.unwrap();
		storage.save_transfer(&pending_redemption).await.unwrap();
		storage.save_transfer(&unwrap_pending).await.unwrap();
		storage.save_transfer(&intervention).await.unwrap();

		let transfers = storage.get_active_transfers().await.unwrap();

		assert_eq!(transfers.len(), 6);
		assert!(transfers
			.iter()
			.any(|transfer| matches!(transfer.status, BridgeTransferStatus::WrapPending)));
		assert!(transfers
			.iter()
			.any(|transfer| matches!(transfer.status, BridgeTransferStatus::Submitted)));
		assert!(transfers
			.iter()
			.any(|transfer| matches!(transfer.status, BridgeTransferStatus::Relaying)));
		assert!(transfers
			.iter()
			.any(|transfer| matches!(transfer.status, BridgeTransferStatus::PendingRedemption)));
		assert!(transfers
			.iter()
			.any(|transfer| matches!(transfer.status, BridgeTransferStatus::UnwrapPending)));
		assert!(transfers
			.iter()
			.any(|transfer| matches!(transfer.status, BridgeTransferStatus::NeedsIntervention(_))));
	}

	#[tokio::test]
	async fn test_retire_system_attempt_scope_retries_cas_conflict() {
		let scope_id = "system:bridge:deposit:cas-conflict";
		let attempt = sample_attempt(scope_id);
		let mut concurrent = attempt.clone();
		concurrent.error = Some("concurrent monitor update".to_string());
		concurrent.updated_at += 1;
		let first_bytes = serde_json::to_vec(&attempt).unwrap();
		let second_bytes = serde_json::to_vec(&concurrent).unwrap();
		let namespace = StorageKey::TransactionAttempts.as_str().to_string();
		let key = format!("{namespace}:attempt-cas");
		let mut backend = MockStorageInterface::new();

		{
			let key = key.clone();
			let namespace = namespace.clone();
			backend
				.expect_query()
				.times(1)
				.returning(move |ns, _filter| {
					assert_eq!(ns, namespace);
					let key = key.clone();
					Box::pin(async move { Ok(vec![key]) })
				});
		}
		{
			let key = key.clone();
			let first_bytes = first_bytes.clone();
			backend.expect_get_batch().times(1).returning(move |keys| {
				assert_eq!(keys, &[key.clone()]);
				let key = key.clone();
				let first_bytes = first_bytes.clone();
				Box::pin(async move { Ok(vec![(key, first_bytes)]) })
			});
		}
		{
			let key = key.clone();
			let first_bytes = first_bytes.clone();
			let second_bytes = second_bytes.clone();
			let calls = Arc::new(AtomicUsize::new(0));
			backend
				.expect_get_bytes()
				.times(2)
				.returning(move |requested| {
					assert_eq!(requested, key);
					let call = calls.fetch_add(1, Ordering::SeqCst);
					let bytes = if call == 0 {
						first_bytes.clone()
					} else {
						second_bytes.clone()
					};
					Box::pin(async move { Ok(bytes) })
				});
		}
		{
			let key = key.clone();
			let first_bytes = first_bytes.clone();
			let second_bytes = second_bytes.clone();
			let calls = Arc::new(AtomicUsize::new(0));
			backend
				.expect_compare_and_swap_with_indexes()
				.times(2)
				.returning(move |requested, expected, _new_value, _indexes, _ttl| {
					assert_eq!(requested, key);
					let call = calls.fetch_add(1, Ordering::SeqCst);
					if call == 0 {
						assert_eq!(expected, first_bytes.as_slice());
						Box::pin(async move { Ok(false) })
					} else {
						assert_eq!(expected, second_bytes.as_slice());
						Box::pin(async move { Ok(true) })
					}
				});
		}

		let storage = Arc::new(StorageService::new(Box::new(backend)));

		retire_system_attempt_scope(&storage, scope_id, "retired after conflict")
			.await
			.unwrap();
	}

	#[tokio::test]
	async fn test_bridge_storage_get_active_transfers_for_pair_filters_by_pair_id() {
		let (storage, _) = make_storage();

		let mut matching_submitted = pending_transfer(BridgeTransferStatus::Submitted);
		matching_submitted.id = "match-submitted".to_string();
		matching_submitted.pair_id = "eth-katana".to_string();
		let mut matching_wrap_pending = pending_transfer(BridgeTransferStatus::WrapPending);
		matching_wrap_pending.id = "match-wrap-pending".to_string();
		matching_wrap_pending.pair_id = "eth-katana".to_string();
		let mut matching_unwrap_pending = pending_transfer(BridgeTransferStatus::UnwrapPending);
		matching_unwrap_pending.id = "match-unwrap-pending".to_string();
		matching_unwrap_pending.pair_id = "eth-katana".to_string();
		let mut matching_intervention = pending_transfer(BridgeTransferStatus::NeedsIntervention(
			"manual review".to_string(),
		));
		matching_intervention.id = "match-intervention".to_string();
		matching_intervention.pair_id = "eth-katana".to_string();
		let mut other_pair = pending_transfer(BridgeTransferStatus::Relaying);
		other_pair.id = "other-relaying".to_string();
		other_pair.pair_id = "arb-eth".to_string();

		storage.save_transfer(&matching_submitted).await.unwrap();
		storage.save_transfer(&matching_wrap_pending).await.unwrap();
		storage
			.save_transfer(&matching_unwrap_pending)
			.await
			.unwrap();
		storage.save_transfer(&matching_intervention).await.unwrap();
		storage.save_transfer(&other_pair).await.unwrap();

		let transfers = storage
			.get_active_transfers_for_pair("eth-katana")
			.await
			.unwrap();

		assert_eq!(transfers.len(), 4);
		assert!(transfers
			.iter()
			.all(|transfer| transfer.pair_id == "eth-katana"));
		assert!(transfers
			.iter()
			.any(|transfer| matches!(transfer.status, BridgeTransferStatus::WrapPending)));
		assert!(transfers
			.iter()
			.any(|transfer| matches!(transfer.status, BridgeTransferStatus::Submitted)));
		assert!(transfers
			.iter()
			.any(|transfer| matches!(transfer.status, BridgeTransferStatus::UnwrapPending)));
		assert!(transfers
			.iter()
			.any(|transfer| matches!(transfer.status, BridgeTransferStatus::NeedsIntervention(_))));
	}

	#[tokio::test]
	async fn test_bridge_storage_same_transfer_lifecycle_moves_between_buckets_once() {
		let (storage, base_path) = make_storage();

		let mut transfer = pending_transfer(BridgeTransferStatus::Submitted);
		transfer.id = "lifecycle-1".to_string();
		transfer.pair_id = "eth-katana".to_string();

		storage.save_transfer(&transfer).await.unwrap();
		assert_eq!(storage.get_active_transfers().await.unwrap().len(), 1);
		assert_eq!(
			file_expires_at(
				&base_path,
				&storage_key(&storage.namespace(), "lifecycle-1")
			),
			0
		);

		transfer.transition_to(BridgeTransferStatus::Relaying);
		storage.save_transfer(&transfer).await.unwrap();

		let submitted = storage
			.storage
			.query::<PendingBridgeTransfer>(
				&storage.namespace(),
				QueryFilter::Equals("status".to_string(), serde_json::json!("submitted")),
			)
			.await
			.unwrap();
		assert!(submitted.is_empty());

		let relaying = storage
			.storage
			.query::<PendingBridgeTransfer>(
				&storage.namespace(),
				QueryFilter::Equals("status".to_string(), serde_json::json!("relaying")),
			)
			.await
			.unwrap();
		assert_eq!(relaying.len(), 1);
		assert_eq!(relaying[0].0, "lifecycle-1");
		assert!(matches!(
			relaying[0].1.status,
			BridgeTransferStatus::Relaying
		));
		assert_eq!(
			file_expires_at(
				&base_path,
				&storage_key(&storage.namespace(), "lifecycle-1")
			),
			0
		);

		transfer.transition_to(BridgeTransferStatus::Completed);
		storage.save_transfer(&transfer).await.unwrap();

		let completed = storage
			.storage
			.query::<PendingBridgeTransfer>(
				&storage.namespace(),
				QueryFilter::Equals("status".to_string(), serde_json::json!("completed")),
			)
			.await
			.unwrap();
		assert_eq!(completed.len(), 1);
		assert_eq!(completed[0].0, "lifecycle-1");
		assert!(matches!(
			completed[0].1.status,
			BridgeTransferStatus::Completed
		));
		assert!(storage.get_active_transfers().await.unwrap().is_empty());

		let history = storage.get_transfer_history(10).await.unwrap();
		assert_eq!(history.len(), 1);
		assert!(matches!(history[0].status, BridgeTransferStatus::Completed));
		assert!(
			file_expires_at(
				&base_path,
				&storage_key(&storage.namespace(), "lifecycle-1")
			) > 0
		);
	}

	#[tokio::test]
	async fn test_bridge_storage_get_transfer_history_sorts_by_updated_at_desc() {
		let (storage, _) = make_storage();

		let mut completed_old = pending_transfer(BridgeTransferStatus::Completed);
		completed_old.id = "completed-old".to_string();
		completed_old.updated_at = 10;
		let mut failed_mid = pending_transfer(BridgeTransferStatus::Failed("boom".to_string()));
		failed_mid.id = "failed-mid".to_string();
		failed_mid.updated_at = 20;
		let mut completed_new = pending_transfer(BridgeTransferStatus::Completed);
		completed_new.id = "completed-new".to_string();
		completed_new.updated_at = 30;

		storage.save_transfer(&completed_old).await.unwrap();
		storage.save_transfer(&failed_mid).await.unwrap();
		storage.save_transfer(&completed_new).await.unwrap();

		let history = storage.get_transfer_history(10).await.unwrap();

		assert_eq!(
			history.iter().map(|t| t.updated_at).collect::<Vec<_>>(),
			vec![30, 20, 10]
		);
		assert!(history.iter().all(|transfer| transfer.status.is_terminal()));
	}

	#[tokio::test]
	async fn test_bridge_storage_is_cooldown_active_uses_pair_id_namespace() {
		let (storage, base_path) = make_storage();

		assert!(!storage.is_cooldown_active("eth-katana").await.unwrap());

		storage.set_cooldown("eth-katana", 42).await.unwrap();

		let cooldown_key = storage_key(&storage.cooldown_namespace(), "eth-katana");
		assert!(file_expires_at(&base_path, &cooldown_key) > 0);
		assert!(storage.is_cooldown_active("eth-katana").await.unwrap());
		assert!(!file_path(&base_path, "eth-katana").exists());
	}
}
