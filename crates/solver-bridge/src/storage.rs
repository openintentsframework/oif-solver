//! Bridge transfer persistence helpers.
//!
//! Stores and queries `PendingBridgeTransfer` records in Redis via `StorageService`.
//! Transfers are indexed by status, pair_id, source/dest chain, and trigger
//! so that active/history queries do not require scanning every key.

use crate::types::{BridgeTransferStatus, PendingBridgeTransfer};
use solver_storage::{QueryFilter, StorageError, StorageIndexes, StorageService};
use std::sync::Arc;
use std::time::Duration;

/// Storage namespace for bridge transfers.
const BRIDGE_TRANSFER_NS: &str = "bridge-transfer";

/// Storage namespace for cooldown keys.
const BRIDGE_COOLDOWN_NS: &str = "bridge-cooldown";

/// TTL for completed/failed transfers (7 days).
const TERMINAL_TRANSFER_TTL: Duration = Duration::from_secs(7 * 24 * 3600);

/// Manages bridge transfer persistence.
pub struct BridgeStorage {
	storage: Arc<StorageService>,
	solver_id: String,
}

impl BridgeStorage {
	pub fn new(storage: Arc<StorageService>, solver_id: String) -> Self {
		Self { storage, solver_id }
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
			BridgeTransferStatus::Submitted => "submitted",
			BridgeTransferStatus::Relaying => "relaying",
			BridgeTransferStatus::PendingRedemption => "pending_redemption",
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
			"submitted",
			"relaying",
			"pending_redemption",
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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::test_support::pending_transfer;
	use solver_storage::implementations::file::{FileStorage, TtlConfig};
	use solver_storage::{QueryFilter, StorageService};
	use std::fs;
	use std::path::{Path, PathBuf};
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
	async fn test_bridge_storage_get_active_transfers_includes_needs_intervention() {
		let (storage, _) = make_storage();

		let mut submitted = pending_transfer(BridgeTransferStatus::Submitted);
		submitted.id = "submitted-1".to_string();
		submitted.pair_id = "eth-katana".to_string();
		let mut intervention = pending_transfer(BridgeTransferStatus::NeedsIntervention(
			"manual review".to_string(),
		));
		intervention.id = "intervention-1".to_string();
		intervention.pair_id = "eth-katana".to_string();

		storage.save_transfer(&submitted).await.unwrap();
		storage.save_transfer(&intervention).await.unwrap();

		let transfers = storage.get_active_transfers().await.unwrap();

		assert_eq!(transfers.len(), 2);
		assert!(transfers
			.iter()
			.any(|transfer| matches!(transfer.status, BridgeTransferStatus::Submitted)));
		assert!(transfers
			.iter()
			.any(|transfer| matches!(transfer.status, BridgeTransferStatus::NeedsIntervention(_))));
	}

	#[tokio::test]
	async fn test_bridge_storage_get_active_transfers_for_pair_filters_by_pair_id() {
		let (storage, _) = make_storage();

		let mut matching_submitted = pending_transfer(BridgeTransferStatus::Submitted);
		matching_submitted.id = "match-submitted".to_string();
		matching_submitted.pair_id = "eth-katana".to_string();
		let mut matching_intervention = pending_transfer(BridgeTransferStatus::NeedsIntervention(
			"manual review".to_string(),
		));
		matching_intervention.id = "match-intervention".to_string();
		matching_intervention.pair_id = "eth-katana".to_string();
		let mut other_pair = pending_transfer(BridgeTransferStatus::Relaying);
		other_pair.id = "other-relaying".to_string();
		other_pair.pair_id = "arb-eth".to_string();

		storage.save_transfer(&matching_submitted).await.unwrap();
		storage.save_transfer(&matching_intervention).await.unwrap();
		storage.save_transfer(&other_pair).await.unwrap();

		let transfers = storage
			.get_active_transfers_for_pair("eth-katana")
			.await
			.unwrap();

		assert_eq!(transfers.len(), 2);
		assert!(transfers
			.iter()
			.all(|transfer| transfer.pair_id == "eth-katana"));
		assert!(transfers
			.iter()
			.any(|transfer| matches!(transfer.status, BridgeTransferStatus::Submitted)));
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
