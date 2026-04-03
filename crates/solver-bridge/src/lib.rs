//! Cross-chain bridge service for solver rebalancing.
//!
//! This crate provides a pluggable `BridgeInterface` trait and a `BridgeService`
//! orchestrator for automated and manual cross-chain token rebalancing.
//!
//! # Architecture
//!
//! - `BridgeInterface`: trait for bridge implementations (e.g., LayerZero VaultBridge)
//! - `BridgeService`: orchestrates transfers, manages Redis-persisted state
//! - `BridgeStorage`: persistence helpers for transfer records and cooldowns
//! - `RebalanceMonitor`: background task for automated threshold-based rebalancing

pub mod implementations;
pub mod monitor;
pub mod storage;
#[cfg(test)]
mod test_support;
pub mod threshold;
pub mod types;

use crate::storage::BridgeStorage;
use crate::types::{
	BridgeDepositResult, BridgeRequest, BridgeTransferStatus, PendingBridgeTransfer,
	RebalanceTrigger,
};
use alloy_primitives::U256;
use async_trait::async_trait;
use solver_storage::StorageService;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

/// Errors that can occur during bridge operations.
#[derive(Debug, Error)]
pub enum BridgeError {
	#[error("Configuration error: {0}")]
	Config(String),

	#[error("Bridge implementation not found: {0}")]
	BridgeNotFound(String),

	#[error("Unsupported route: chain {0} -> chain {1}")]
	UnsupportedRoute(u64, u64),

	#[error("Transaction failed: {0}")]
	TransactionFailed(String),

	#[error("Fee estimation failed: {0}")]
	FeeEstimation(String),

	#[error("Storage error: {0}")]
	Storage(String),

	#[error("Delivery error: {0}")]
	Delivery(String),

	#[error("Max pending transfers reached ({0})")]
	MaxPendingReached(u32),

	#[error("Cooldown active for pair {0}")]
	CooldownActive(String),

	#[error("Pair locked by transfer {0} in NeedsIntervention state")]
	PairLocked(String),

	#[error("Transfer not found: {0}")]
	TransferNotFound(String),

	#[error("Invalid state transition: {0}")]
	InvalidTransition(String),
}

impl From<solver_storage::StorageError> for BridgeError {
	fn from(err: solver_storage::StorageError) -> Self {
		BridgeError::Storage(err.to_string())
	}
}

/// Pluggable bridge interface. Implementations handle the protocol-specific
/// details (LayerZero OFT, Hyperlane Warp, AggLayer, etc.).
#[async_trait]
pub trait BridgeInterface: Send + Sync {
	/// Returns all supported (source_chain, dest_chain) pairs.
	fn supported_routes(&self) -> Vec<(u64, u64)>;

	/// Execute a cross-chain bridge transfer.
	/// Handles approval, fee quoting, and submission internally.
	async fn bridge_asset(
		&self,
		request: &BridgeRequest,
	) -> Result<BridgeDepositResult, BridgeError>;

	/// Check the current status of a pending transfer.
	async fn check_status(
		&self,
		transfer: &PendingBridgeTransfer,
	) -> Result<BridgeTransferStatus, BridgeError>;

	/// Estimate the bridge fee for a transfer (in native gas token).
	async fn estimate_fee(&self, request: &BridgeRequest) -> Result<U256, BridgeError>;
}

/// Bridge factory function type (mirrors the solver's pluggable factory pattern).
/// The `Address` parameter is the solver's on-chain address, required for
/// constructing bridges that need to approve tokens or check balances.
pub type BridgeFactory = fn(
	&serde_json::Value,
	Arc<solver_delivery::DeliveryService>,
	alloy_primitives::Address,
) -> Result<Box<dyn BridgeInterface>, BridgeError>;

/// Orchestrates bridge implementations and manages transfer lifecycle.
pub struct BridgeService {
	implementations: HashMap<String, Arc<dyn BridgeInterface>>,
	storage: BridgeStorage,
}

impl BridgeService {
	pub fn new(
		implementations: HashMap<String, Arc<dyn BridgeInterface>>,
		storage_service: Arc<StorageService>,
		solver_id: String,
	) -> Self {
		Self {
			implementations,
			storage: BridgeStorage::new(storage_service, solver_id),
		}
	}

	/// Get a bridge implementation by name.
	pub fn get_implementation(&self, name: &str) -> Result<&Arc<dyn BridgeInterface>, BridgeError> {
		self.implementations
			.get(name)
			.ok_or_else(|| BridgeError::BridgeNotFound(name.to_string()))
	}

	/// Initiate a rebalance transfer. Creates a persistent record.
	pub async fn rebalance_token(
		&self,
		bridge_impl: &str,
		request: &BridgeRequest,
		trigger: RebalanceTrigger,
		metadata: types::TransferMetadata,
	) -> Result<PendingBridgeTransfer, BridgeError> {
		let bridge = self.get_implementation(bridge_impl)?;

		// Persist the transfer intent BEFORE sending funds.
		// If bridge_asset succeeds but save fails, we'd have an untracked transfer.
		let mut transfer = PendingBridgeTransfer::new(
			request.pair_id.clone(),
			request.source_chain,
			request.dest_chain,
			request.amount.to_string(),
			trigger,
			None, // tx_hash set after submission
			None, // message_guid set after submission
			None, // fee_paid set after confirmation
		);
		// Populate metadata for delivery detection and redeem path
		transfer.dest_token_address = Some(metadata.dest_token_address);
		transfer.dest_oft_address = Some(metadata.dest_oft_address);
		transfer.is_composer_flow = Some(metadata.is_composer_flow);
		transfer.vault_address = metadata.vault_address;
		self.storage.save_transfer(&transfer).await?;

		// Execute the bridge transfer
		let result = match bridge.bridge_asset(request).await {
			Ok(result) => result,
			Err(err) => {
				transfer.transition_to(BridgeTransferStatus::Failed(err.to_string()));
				if let Err(save_err) = self.storage.save_transfer(&transfer).await {
					tracing::warn!(
						transfer_id = %transfer.id,
						error = %save_err,
						"Failed to persist failed bridge transfer after bridge_asset error"
					);
				}
				return Err(err);
			},
		};

		// Update the record with the tx hash and message GUID
		transfer.tx_hash = Some(result.tx_hash);
		transfer.message_guid = result.message_guid;
		transfer.updated_at = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs();
		if let Err(save_err) = self.storage.save_transfer(&transfer).await {
			let reason = format!("post-submit persistence failed: {save_err}");
			transfer.transition_to(BridgeTransferStatus::NeedsIntervention(reason));
			if let Err(repair_err) = self.storage.save_transfer(&transfer).await {
				tracing::warn!(
					transfer_id = %transfer.id,
					error = %repair_err,
					"Failed to persist NeedsIntervention bridge transfer after save failure"
				);
			}
			return Err(BridgeError::Storage(save_err.to_string()));
		}

		Ok(transfer)
	}

	/// Get all active (non-terminal) transfers.
	pub async fn get_active_transfers(&self) -> Result<Vec<PendingBridgeTransfer>, BridgeError> {
		Ok(self.storage.get_active_transfers().await?)
	}

	/// Get active transfers for a specific pair.
	pub async fn get_active_transfers_for_pair(
		&self,
		pair_id: &str,
	) -> Result<Vec<PendingBridgeTransfer>, BridgeError> {
		Ok(self.storage.get_active_transfers_for_pair(pair_id).await?)
	}

	/// Get completed/failed transfer history.
	pub async fn get_transfer_history(
		&self,
		limit: usize,
	) -> Result<Vec<PendingBridgeTransfer>, BridgeError> {
		Ok(self.storage.get_transfer_history(limit).await?)
	}

	/// Get a single transfer by ID.
	pub async fn get_transfer(&self, id: &str) -> Result<PendingBridgeTransfer, BridgeError> {
		self.storage.get_transfer(id).await.map_err(|e| match e {
			solver_storage::StorageError::NotFound(_) => {
				BridgeError::TransferNotFound(id.to_string())
			},
			other => BridgeError::Storage(other.to_string()),
		})
	}

	/// Count active (non-terminal) transfers.
	pub async fn active_transfer_count(&self) -> Result<usize, BridgeError> {
		Ok(self.storage.active_transfer_count().await?)
	}

	/// Check if a cooldown is active for a pair.
	pub async fn is_cooldown_active(&self, pair_id: &str) -> Result<bool, BridgeError> {
		Ok(self.storage.is_cooldown_active(pair_id).await?)
	}

	/// Set a cooldown for a pair.
	pub async fn set_cooldown(&self, pair_id: &str, ttl_seconds: u64) -> Result<(), BridgeError> {
		Ok(self.storage.set_cooldown(pair_id, ttl_seconds).await?)
	}

	/// Update and persist a transfer's status.
	pub async fn update_transfer(
		&self,
		transfer: &mut PendingBridgeTransfer,
		new_status: BridgeTransferStatus,
	) -> Result<(), BridgeError> {
		transfer.transition_to(new_status);
		self.storage.save_transfer(transfer).await?;
		Ok(())
	}

	/// Resolve a NeedsIntervention transfer (admin action).
	pub async fn resolve_transfer(
		&self,
		transfer_id: &str,
		resolution: &str,
		reason: &str,
	) -> Result<PendingBridgeTransfer, BridgeError> {
		let mut transfer = self.get_transfer(transfer_id).await?;

		if !matches!(transfer.status, BridgeTransferStatus::NeedsIntervention(_)) {
			return Err(BridgeError::InvalidTransition(format!(
				"Transfer {} is in {:?}, not NeedsIntervention",
				transfer_id, transfer.status
			)));
		}

		match resolution {
			"mark_completed" => {
				transfer.transition_to(BridgeTransferStatus::Completed);
			},
			"mark_failed" => {
				transfer.transition_to(BridgeTransferStatus::Failed(
					"Manually resolved by admin".to_string(),
				));
			},
			"retry" => {
				transfer.failure_count = 0;
				if let Some(prev_status) = transfer.status_before_intervention.take() {
					transfer.status = prev_status;
				} else {
					transfer.status = BridgeTransferStatus::Relaying;
				}
				transfer.updated_at = std::time::SystemTime::now()
					.duration_since(std::time::UNIX_EPOCH)
					.unwrap_or_default()
					.as_secs();
			},
			other => {
				return Err(BridgeError::InvalidTransition(format!(
					"Unknown resolution: {other}. Expected: mark_completed, mark_failed, retry"
				)));
			},
		}

		transfer.resolution_reason = Some(reason.to_string());

		self.storage.save_transfer(&transfer).await?;
		Ok(transfer)
	}

	/// Access the storage layer directly (for the monitor).
	pub fn storage(&self) -> &BridgeStorage {
		&self.storage
	}
}

/// Returns all registered bridge implementations.
pub fn get_all_implementations() -> Vec<(&'static str, BridgeFactory)> {
	vec![("layerzero", implementations::layerzero::create_bridge)]
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::test_support::{bridge_request, pending_transfer, storage_service_from_mock};
	use solver_storage::{MockStorageInterface, StorageError};
	use std::sync::{Arc, Mutex};

	#[derive(Default)]
	struct TestBridge {
		bridge_asset_result: Mutex<Option<Result<BridgeDepositResult, BridgeError>>>,
		check_status_result: Mutex<Option<Result<BridgeTransferStatus, BridgeError>>>,
		estimate_fee_result: Mutex<Option<Result<U256, BridgeError>>>,
		events: Option<Arc<Mutex<Vec<&'static str>>>>,
	}

	impl TestBridge {
		fn new() -> Self {
			Self::default()
		}
	}

	#[async_trait]
	impl BridgeInterface for TestBridge {
		fn supported_routes(&self) -> Vec<(u64, u64)> {
			vec![(1, 747474)]
		}

		async fn bridge_asset(
			&self,
			_request: &BridgeRequest,
		) -> Result<BridgeDepositResult, BridgeError> {
			if let Some(events) = &self.events {
				let mut events = events.lock().unwrap();
				assert_eq!(events.as_slice(), ["save1"]);
				events.push("bridge_asset");
			}

			self.bridge_asset_result
				.lock()
				.unwrap()
				.take()
				.expect("bridge_asset_result not configured")
		}

		async fn check_status(
			&self,
			_transfer: &PendingBridgeTransfer,
		) -> Result<BridgeTransferStatus, BridgeError> {
			self.check_status_result
				.lock()
				.unwrap()
				.take()
				.expect("check_status_result not configured")
		}

		async fn estimate_fee(&self, _request: &BridgeRequest) -> Result<U256, BridgeError> {
			self.estimate_fee_result
				.lock()
				.unwrap()
				.take()
				.expect("estimate_fee_result not configured")
		}
	}

	fn make_service(
		bridge: Arc<dyn BridgeInterface>,
		storage: MockStorageInterface,
	) -> BridgeService {
		let implementations = HashMap::from([("mock-bridge".to_string(), bridge)]);
		BridgeService::new(
			implementations,
			storage_service_from_mock(storage),
			"solver-a".to_string(),
		)
	}

	fn bridge_metadata() -> types::TransferMetadata {
		types::TransferMetadata {
			dest_token_address: "0x3333333333333333333333333333333333333333".to_string(),
			dest_oft_address: "0x4444444444444444444444444444444444444444".to_string(),
			is_composer_flow: true,
			vault_address: None,
		}
	}

	fn configured_deposit_result() -> BridgeDepositResult {
		BridgeDepositResult {
			tx_hash: "0xabc123".to_string(),
			message_guid: Some("guid-1".to_string()),
			estimated_arrival: Some(1_700_000_100),
		}
	}

	fn assert_intent_transfer(transfer: &PendingBridgeTransfer) {
		assert!(matches!(transfer.status, BridgeTransferStatus::Submitted));
		assert!(transfer.tx_hash.is_none());
		assert!(transfer.message_guid.is_none());
	}

	fn assert_submitted_with_result(transfer: &PendingBridgeTransfer) {
		assert!(matches!(transfer.status, BridgeTransferStatus::Submitted));
		assert_eq!(transfer.tx_hash.as_deref(), Some("0xabc123"));
		assert_eq!(transfer.message_guid.as_deref(), Some("guid-1"));
	}

	fn assert_failed_transfer(transfer: &PendingBridgeTransfer, reason_substring: &str) {
		assert!(
			matches!(&transfer.status, BridgeTransferStatus::Failed(reason) if reason.contains(reason_substring))
		);
		assert!(transfer.tx_hash.is_none());
		assert!(transfer.message_guid.is_none());
	}

	fn transfer_json(transfer: &PendingBridgeTransfer) -> Vec<u8> {
		serde_json::to_vec(transfer).unwrap()
	}

	#[tokio::test]
	async fn test_rebalance_token_persists_intent_before_bridge_asset() {
		let events = Arc::new(Mutex::new(Vec::<&'static str>::new()));
		let first_saved = Arc::new(Mutex::new(None));
		let second_saved = Arc::new(Mutex::new(None));
		let request = bridge_request();
		let mut storage = MockStorageInterface::new();
		{
			let events = events.clone();
			let first_saved = first_saved.clone();
			let second_saved = second_saved.clone();
			storage
				.expect_set_bytes()
				.times(2)
				.returning(move |_key, value, _indexes, _ttl| {
					let events = events.clone();
					let first_saved = first_saved.clone();
					let second_saved = second_saved.clone();
					Box::pin(async move {
						let mut events = events.lock().unwrap();
						let transfer: PendingBridgeTransfer =
							serde_json::from_slice(&value).unwrap();
						if events.is_empty() {
							assert_intent_transfer(&transfer);
							*first_saved.lock().unwrap() = Some(transfer);
							events.push("save1");
							Ok(())
						} else {
							assert_eq!(events.as_slice(), ["save1", "bridge_asset"]);
							assert_eq!(
								first_saved
									.lock()
									.unwrap()
									.as_ref()
									.expect("first save missing")
									.id,
								transfer.id
							);
							assert_submitted_with_result(&transfer);
							*second_saved.lock().unwrap() = Some(transfer);
							events.push("save2");
							Ok(())
						}
					})
				});
		}

		let bridge = Arc::new(TestBridge {
			bridge_asset_result: Mutex::new(Some(Ok(configured_deposit_result()))),
			check_status_result: Mutex::new(None),
			estimate_fee_result: Mutex::new(None),
			events: Some(events.clone()),
		});
		let bridge: Arc<dyn BridgeInterface> = bridge;
		let service = make_service(bridge, storage);
		let result = service
			.rebalance_token(
				"mock-bridge",
				&request,
				RebalanceTrigger::Auto,
				bridge_metadata(),
			)
			.await
			.unwrap();

		assert_eq!(result.tx_hash.as_deref(), Some("0xabc123"));
		assert_eq!(result.message_guid.as_deref(), Some("guid-1"));
		assert_eq!(
			events.lock().unwrap().as_slice(),
			["save1", "bridge_asset", "save2"]
		);
		assert_intent_transfer(first_saved.lock().unwrap().as_ref().unwrap());
		assert_submitted_with_result(second_saved.lock().unwrap().as_ref().unwrap());
	}

	#[tokio::test]
	async fn test_rebalance_token_persists_failed_state_when_bridge_asset_fails() {
		let events = Arc::new(Mutex::new(Vec::<&'static str>::new()));
		let first_saved = Arc::new(Mutex::new(None));
		let failed_saved = Arc::new(Mutex::new(None));
		let request = bridge_request();
		let mut storage = MockStorageInterface::new();
		{
			let events = events.clone();
			let first_saved = first_saved.clone();
			let failed_saved = failed_saved.clone();
			storage
				.expect_set_bytes()
				.times(2)
				.returning(move |_key, value, _indexes, _ttl| {
					let events = events.clone();
					let first_saved = first_saved.clone();
					let failed_saved = failed_saved.clone();
					Box::pin(async move {
						let mut events = events.lock().unwrap();
						let transfer: PendingBridgeTransfer =
							serde_json::from_slice(&value).unwrap();
						if events.is_empty() {
							assert_intent_transfer(&transfer);
							*first_saved.lock().unwrap() = Some(transfer);
							events.push("save1");
							Ok(())
						} else {
							assert_eq!(events.as_slice(), ["save1", "bridge_asset"]);
							assert_failed_transfer(&transfer, "bridge send failed");
							*failed_saved.lock().unwrap() = Some(transfer);
							events.push("save2");
							Ok(())
						}
					})
				});
		}

		let bridge = Arc::new(TestBridge {
			bridge_asset_result: Mutex::new(Some(Err(BridgeError::TransactionFailed(
				"bridge send failed".to_string(),
			)))),
			check_status_result: Mutex::new(None),
			estimate_fee_result: Mutex::new(None),
			events: Some(events.clone()),
		});
		let bridge: Arc<dyn BridgeInterface> = bridge;
		let service = make_service(bridge, storage);
		let result = service
			.rebalance_token(
				"mock-bridge",
				&request,
				RebalanceTrigger::Auto,
				bridge_metadata(),
			)
			.await;

		assert_eq!(
			events.lock().unwrap().as_slice(),
			["save1", "bridge_asset", "save2"]
		);
		assert!(matches!(
			result,
			Err(BridgeError::TransactionFailed(msg)) if msg.contains("bridge send failed")
		));
		assert_intent_transfer(first_saved.lock().unwrap().as_ref().unwrap());
		assert_failed_transfer(
			failed_saved.lock().unwrap().as_ref().unwrap(),
			"bridge send failed",
		);
	}

	#[tokio::test]
	async fn test_rebalance_token_persists_intervention_state_when_second_save_fails() {
		let events = Arc::new(Mutex::new(Vec::<&'static str>::new()));
		let first_saved = Arc::new(Mutex::new(None));
		let repaired_saved = Arc::new(Mutex::new(None));
		let request = bridge_request();
		let mut storage = MockStorageInterface::new();
		{
			let events = events.clone();
			let first_saved = first_saved.clone();
			let repaired_saved = repaired_saved.clone();
			storage
				.expect_set_bytes()
				.times(3)
				.returning(move |_key, value, _indexes, _ttl| {
					let events = events.clone();
					let first_saved = first_saved.clone();
					let repaired_saved = repaired_saved.clone();
					Box::pin(async move {
						let mut events = events.lock().unwrap();
						let transfer: PendingBridgeTransfer =
							serde_json::from_slice(&value).unwrap();
						if events.is_empty() {
							assert_intent_transfer(&transfer);
							*first_saved.lock().unwrap() = Some(transfer);
							events.push("save1");
							Ok(())
						} else if events.as_slice() == ["save1", "bridge_asset"] {
							assert_eq!(
								first_saved
									.lock()
									.unwrap()
									.as_ref()
									.expect("first save missing")
									.id,
								transfer.id
							);
							assert_submitted_with_result(&transfer);
							events.push("save2");
							Err(StorageError::Backend("second save failed".to_string()))
						} else {
							assert_eq!(events.as_slice(), ["save1", "bridge_asset", "save2"]);
							assert!(matches!(
								&transfer.status,
								BridgeTransferStatus::NeedsIntervention(reason)
									if reason.contains("post-submit persistence failed")
							));
							assert_eq!(transfer.tx_hash.as_deref(), Some("0xabc123"));
							assert_eq!(transfer.message_guid.as_deref(), Some("guid-1"));
							assert_eq!(
								transfer.status_before_intervention,
								Some(BridgeTransferStatus::Submitted)
							);
							*repaired_saved.lock().unwrap() = Some(transfer);
							events.push("save3");
							Ok(())
						}
					})
				});
		}

		let bridge = Arc::new(TestBridge {
			bridge_asset_result: Mutex::new(Some(Ok(configured_deposit_result()))),
			check_status_result: Mutex::new(None),
			estimate_fee_result: Mutex::new(None),
			events: Some(events.clone()),
		});
		let bridge: Arc<dyn BridgeInterface> = bridge;
		let service = make_service(bridge, storage);
		let result = service
			.rebalance_token(
				"mock-bridge",
				&request,
				RebalanceTrigger::Auto,
				bridge_metadata(),
			)
			.await;

		assert_eq!(
			events.lock().unwrap().as_slice(),
			["save1", "bridge_asset", "save2", "save3"]
		);
		assert!(
			matches!(result, Err(BridgeError::Storage(msg)) if msg.contains("second save failed"))
		);
		assert_intent_transfer(first_saved.lock().unwrap().as_ref().unwrap());
		let repaired = repaired_saved.lock().unwrap().clone().unwrap();
		assert!(matches!(
			repaired.status,
			BridgeTransferStatus::NeedsIntervention(ref reason)
				if reason.contains("post-submit persistence failed")
		));
		assert_eq!(repaired.tx_hash.as_deref(), Some("0xabc123"));
		assert_eq!(repaired.message_guid.as_deref(), Some("guid-1"));
	}

	#[tokio::test]
	async fn test_get_transfer_maps_not_found_without_collapsing_other_storage_errors() {
		let mut storage = MockStorageInterface::new();
		storage.expect_get_bytes().times(2).returning(|key| {
			let key = key.to_string();
			if key.ends_with(":missing") {
				Box::pin(async move { Err(StorageError::NotFound(key)) })
			} else {
				Box::pin(async move { Err(StorageError::Backend("boom".to_string())) })
			}
		});

		let service = make_service(Arc::new(TestBridge::new()), storage);

		let missing = service.get_transfer("missing").await.unwrap_err();
		assert!(matches!(missing, BridgeError::TransferNotFound(id) if id == "missing"));

		let backend = service.get_transfer("backend").await.unwrap_err();
		assert!(
			matches!(backend, BridgeError::Storage(msg) if msg.contains("Backend error: boom"))
		);
	}

	#[tokio::test]
	async fn test_resolve_transfer_mark_completed_transitions_to_completed() {
		let transfer = pending_transfer(BridgeTransferStatus::NeedsIntervention(
			"timeout".to_string(),
		));
		let saved = Arc::new(Mutex::new(None));
		let mut storage = MockStorageInterface::new();
		{
			let expected_transfer = transfer.clone();
			storage.expect_get_bytes().returning(move |_| {
				let expected_transfer = expected_transfer.clone();
				Box::pin(async move { Ok(transfer_json(&expected_transfer)) })
			});
		}
		{
			let saved = saved.clone();
			storage
				.expect_set_bytes()
				.returning(move |_key, value, _indexes, _ttl| {
					let transfer: PendingBridgeTransfer = serde_json::from_slice(&value).unwrap();
					*saved.lock().unwrap() = Some(transfer);
					Box::pin(async move { Ok(()) })
				});
		}

		let service = make_service(Arc::new(TestBridge::new()), storage);
		let resolved = service
			.resolve_transfer(&transfer.id, "mark_completed", "done")
			.await
			.unwrap();

		assert!(matches!(resolved.status, BridgeTransferStatus::Completed));
		assert_eq!(resolved.resolution_reason.as_deref(), Some("done"));
		let saved = saved.lock().unwrap().clone().unwrap();
		assert!(matches!(saved.status, BridgeTransferStatus::Completed));
		assert_eq!(saved.resolution_reason.as_deref(), Some("done"));
	}

	#[tokio::test]
	async fn test_resolve_transfer_mark_failed_transitions_to_failed() {
		let transfer = pending_transfer(BridgeTransferStatus::NeedsIntervention(
			"timeout".to_string(),
		));
		let saved = Arc::new(Mutex::new(None));
		let mut storage = MockStorageInterface::new();
		{
			let expected_transfer = transfer.clone();
			storage.expect_get_bytes().returning(move |_| {
				let expected_transfer = expected_transfer.clone();
				Box::pin(async move { Ok(transfer_json(&expected_transfer)) })
			});
		}
		{
			let saved = saved.clone();
			storage
				.expect_set_bytes()
				.returning(move |_key, value, _indexes, _ttl| {
					let transfer: PendingBridgeTransfer = serde_json::from_slice(&value).unwrap();
					*saved.lock().unwrap() = Some(transfer);
					Box::pin(async move { Ok(()) })
				});
		}

		let service = make_service(Arc::new(TestBridge::new()), storage);
		let resolved = service
			.resolve_transfer(&transfer.id, "mark_failed", "done")
			.await
			.unwrap();

		assert!(matches!(resolved.status, BridgeTransferStatus::Failed(_)));
		assert_eq!(resolved.resolution_reason.as_deref(), Some("done"));
		let saved = saved.lock().unwrap().clone().unwrap();
		assert!(matches!(saved.status, BridgeTransferStatus::Failed(_)));
		assert_eq!(saved.resolution_reason.as_deref(), Some("done"));
	}

	#[tokio::test]
	async fn test_resolve_transfer_retry_restores_status_before_intervention() {
		let mut transfer = pending_transfer(BridgeTransferStatus::NeedsIntervention(
			"timeout".to_string(),
		));
		transfer.status_before_intervention = Some(BridgeTransferStatus::Relaying);
		transfer.failure_count = 3;
		let saved = Arc::new(Mutex::new(None));
		let mut storage = MockStorageInterface::new();
		{
			let expected_transfer = transfer.clone();
			storage.expect_get_bytes().returning(move |_| {
				let expected_transfer = expected_transfer.clone();
				Box::pin(async move { Ok(transfer_json(&expected_transfer)) })
			});
		}
		{
			let saved = saved.clone();
			storage
				.expect_set_bytes()
				.returning(move |_key, value, _indexes, _ttl| {
					let transfer: PendingBridgeTransfer = serde_json::from_slice(&value).unwrap();
					*saved.lock().unwrap() = Some(transfer);
					Box::pin(async move { Ok(()) })
				});
		}

		let service = make_service(Arc::new(TestBridge::new()), storage);
		let resolved = service
			.resolve_transfer(&transfer.id, "retry", "retrying")
			.await
			.unwrap();

		assert!(matches!(resolved.status, BridgeTransferStatus::Relaying));
		assert_eq!(resolved.failure_count, 0);
		assert_eq!(resolved.resolution_reason.as_deref(), Some("retrying"));
		let saved = saved.lock().unwrap().clone().unwrap();
		assert!(matches!(saved.status, BridgeTransferStatus::Relaying));
		assert_eq!(saved.failure_count, 0);
		assert!(saved.status_before_intervention.is_none());
		assert_eq!(saved.resolution_reason.as_deref(), Some("retrying"));
	}

	#[tokio::test]
	async fn test_resolve_transfer_retry_defaults_to_relaying_without_previous_status() {
		let mut transfer = pending_transfer(BridgeTransferStatus::NeedsIntervention(
			"timeout".to_string(),
		));
		transfer.status_before_intervention = None;
		let saved = Arc::new(Mutex::new(None));
		let mut storage = MockStorageInterface::new();
		{
			let expected_transfer = transfer.clone();
			storage.expect_get_bytes().returning(move |_| {
				let expected_transfer = expected_transfer.clone();
				Box::pin(async move { Ok(transfer_json(&expected_transfer)) })
			});
		}
		{
			let saved = saved.clone();
			storage
				.expect_set_bytes()
				.returning(move |_key, value, _indexes, _ttl| {
					let transfer: PendingBridgeTransfer = serde_json::from_slice(&value).unwrap();
					*saved.lock().unwrap() = Some(transfer);
					Box::pin(async move { Ok(()) })
				});
		}

		let service = make_service(Arc::new(TestBridge::new()), storage);
		let resolved = service
			.resolve_transfer(&transfer.id, "retry", "retrying")
			.await
			.unwrap();

		assert!(matches!(resolved.status, BridgeTransferStatus::Relaying));
		assert_eq!(resolved.failure_count, 0);
		let saved = saved.lock().unwrap().clone().unwrap();
		assert!(matches!(saved.status, BridgeTransferStatus::Relaying));
	}

	#[tokio::test]
	async fn test_resolve_transfer_rejects_non_intervention_transfer() {
		let transfer = pending_transfer(BridgeTransferStatus::Submitted);
		let mut storage = MockStorageInterface::new();
		{
			let expected_transfer = transfer.clone();
			storage.expect_get_bytes().returning(move |_| {
				let expected_transfer = expected_transfer.clone();
				Box::pin(async move { Ok(transfer_json(&expected_transfer)) })
			});
		}
		storage.expect_set_bytes().times(0);

		let service = make_service(Arc::new(TestBridge::new()), storage);
		let err = service
			.resolve_transfer(&transfer.id, "mark_completed", "nope")
			.await
			.unwrap_err();

		assert!(
			matches!(err, BridgeError::InvalidTransition(msg) if msg.contains("not NeedsIntervention"))
		);
	}

	#[tokio::test]
	async fn test_resolve_transfer_rejects_unknown_resolution_without_saving() {
		let transfer = pending_transfer(BridgeTransferStatus::NeedsIntervention(
			"timeout".to_string(),
		));
		let mut storage = MockStorageInterface::new();
		{
			let expected_transfer = transfer.clone();
			storage.expect_get_bytes().returning(move |_| {
				let expected_transfer = expected_transfer.clone();
				Box::pin(async move { Ok(transfer_json(&expected_transfer)) })
			});
		}
		storage.expect_set_bytes().times(0);

		let service = make_service(Arc::new(TestBridge::new()), storage);
		let err = service
			.resolve_transfer(&transfer.id, "unknown_resolution", "noop")
			.await
			.unwrap_err();

		assert!(
			matches!(err, BridgeError::InvalidTransition(msg) if msg.contains("Unknown resolution"))
		);
	}
}
