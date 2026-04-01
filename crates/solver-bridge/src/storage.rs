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
const BRIDGE_TRANSFER_NS: &str = "bridge:transfer";

/// Storage namespace for cooldown keys.
const BRIDGE_COOLDOWN_NS: &str = "bridge:cooldown";

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
