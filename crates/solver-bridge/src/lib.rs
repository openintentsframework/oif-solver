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
pub type BridgeFactory = fn(
	&serde_json::Value,
	Arc<solver_delivery::DeliveryService>,
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
	) -> Result<PendingBridgeTransfer, BridgeError> {
		let bridge = self.get_implementation(bridge_impl)?;

		// Execute the bridge transfer
		let result = bridge.bridge_asset(request).await?;

		// Create and persist the transfer record
		let transfer = PendingBridgeTransfer::new(
			request.pair_symbol.clone(),
			request.source_chain,
			request.dest_chain,
			request.amount.to_string(),
			trigger,
			Some(result.tx_hash),
			result.message_guid,
			None, // fee_paid set later after confirmation
		);

		self.storage.save_transfer(&transfer).await?;

		Ok(transfer)
	}

	/// Get all active (non-terminal) transfers.
	pub async fn get_active_transfers(&self) -> Result<Vec<PendingBridgeTransfer>, BridgeError> {
		Ok(self.storage.get_active_transfers().await?)
	}

	/// Get active transfers for a specific pair.
	pub async fn get_active_transfers_for_pair(
		&self,
		pair_symbol: &str,
	) -> Result<Vec<PendingBridgeTransfer>, BridgeError> {
		Ok(self
			.storage
			.get_active_transfers_for_pair(pair_symbol)
			.await?)
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
		self.storage
			.get_transfer(id)
			.await
			.map_err(|_| BridgeError::TransferNotFound(id.to_string()))
	}

	/// Count active (non-terminal) transfers.
	pub async fn active_transfer_count(&self) -> Result<usize, BridgeError> {
		Ok(self.storage.active_transfer_count().await?)
	}

	/// Check if a cooldown is active for a pair.
	pub async fn is_cooldown_active(&self, pair_symbol: &str) -> Result<bool, BridgeError> {
		Ok(self.storage.is_cooldown_active(pair_symbol).await?)
	}

	/// Set a cooldown for a pair.
	pub async fn set_cooldown(
		&self,
		pair_symbol: &str,
		ttl_seconds: u64,
	) -> Result<(), BridgeError> {
		Ok(self.storage.set_cooldown(pair_symbol, ttl_seconds).await?)
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
		_reason: &str,
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
	vec![
		// LayerZero VaultBridge will be registered here once implemented
		// ("layerzero_vaultbridge", implementations::layerzero_vaultbridge::create_bridge),
	]
}
