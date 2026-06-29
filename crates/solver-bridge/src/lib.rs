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

use crate::storage::{retire_system_attempt_scope, BridgeStorage};
use crate::types::{
	bridge_system_scope, BridgeDepositResult, BridgeRequest, BridgeTransferStatus,
	PendingBridgeTransfer, RebalanceTrigger, TransferMetadata,
};
use alloy_primitives::U256;
use async_trait::async_trait;
use solver_storage::StorageService;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
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

	#[error("Insufficient native gas before bridge submit: {0}")]
	InsufficientNativeGas(String),

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

	/// Approve tx was broadcast but did not reach a confirmation within the
	/// polling window. The tx may yet confirm. The caller MUST persist the
	/// returned hash and let the next reconciliation tick re-check. This is
	/// NOT a terminal failure — `BridgeError::TransactionFailed` is.
	#[error("approve tx pending confirmation (hash: {tx_hash})")]
	ApprovePending { tx_hash: String },

	/// Approve tx was broadcast and observed to revert on chain (status = 0).
	/// Terminal — the transfer should be marked Failed.
	#[error("approve tx reverted (hash: {tx_hash}): {error}")]
	ApproveReverted { tx_hash: String, error: String },

	/// Approve submission failed before a durable, visible approve hash was
	/// produced. No deposit/source bridge transaction was attempted.
	#[error("approve submit failed before deposit attempt: {error}")]
	ApproveSubmitFailed { error: String },

	/// Delivery returned `NonceTooLow` — the nonce cache had drifted relative
	/// to the chain's pending count when the tx was built. The next call to
	/// `next_nonce_for` will resync against `eth_getTransactionCount(pending)`,
	/// so this is a transient condition: the caller should retry on the next
	/// monitor tick rather than mark the transfer terminally failed.
	///
	/// NOT terminal — paired with `ApprovePending` as the explicitly-retryable
	/// pre-deposit outcomes.
	#[error("delivery reported nonce too low (transient): {0}")]
	NonceTooLow(String),
}

impl From<solver_storage::StorageError> for BridgeError {
	fn from(err: solver_storage::StorageError) -> Self {
		BridgeError::Storage(err.to_string())
	}
}

/// Pluggable bridge interface. Implementations handle the protocol-specific
/// details (LayerZero OFT, Hyperlane Warp, AggLayer, etc.).
///
/// Native-asset support: `wrap_native` / `unwrap_native` / `redeem_shares` /
/// `parse_redeem_assets` are protocol-only methods used when a pair side is
/// native (`token_address == 0x000…`) and routes through a wrapper (e.g.,
/// WETH on Ethereum, vbETH on Katana). `preflight` runs once at engine
/// startup to cross-check operator-declared route data against on-chain state.
/// `bridge_asset` / `estimate_fee` take `&TransferMetadata` so the per-pair
/// route is available at submit/quote time.
#[async_trait]
pub trait BridgeInterface: Send + Sync {
	/// Returns all supported (source_chain, dest_chain) pairs.
	fn supported_routes(&self) -> Vec<(u64, u64)>;

	/// Execute a cross-chain bridge transfer.
	/// Handles approval, fee quoting, and submission internally. The `metadata`
	/// carries the per-pair `bridge_route` so the implementation can deserialize
	/// the correct composer/vault/wrapper addresses for this transfer.
	async fn bridge_asset(
		&self,
		request: &BridgeRequest,
		metadata: &TransferMetadata,
	) -> Result<BridgeDepositResult, BridgeError>;

	/// Check the current status of a pending transfer.
	async fn check_status(
		&self,
		transfer: &PendingBridgeTransfer,
	) -> Result<BridgeTransferStatus, BridgeError>;

	/// Estimate the bridge fee for a transfer (in native gas token).
	/// Takes `&TransferMetadata` so fee quoting uses the per-pair composer
	/// address from the route, not a chain-keyed lookup.
	async fn estimate_fee(
		&self,
		request: &BridgeRequest,
		metadata: &TransferMetadata,
	) -> Result<U256, BridgeError>;

	// --- Native-asset rebalance methods (default impls so non-LayerZero impls
	//     don't have to override). ----------------------------------------

	/// Wrap source-side native asset into the configured wrapper (e.g.,
	/// `WETH.deposit{value: amount}` on Ethereum, `vbETH.deposit{value}` on Katana).
	/// Returns the wrap tx hash. Persistence and crash-window handling live in
	/// `BridgeService`; this method only builds and submits the tx.
	#[allow(unused_variables)]
	async fn wrap_native(
		&self,
		transfer: &PendingBridgeTransfer,
	) -> Result<solver_types::TransactionHash, BridgeError> {
		Err(BridgeError::Config(
			"wrap_native not supported by this bridge implementation".into(),
		))
	}

	/// Unwrap destination-side wrapper to native asset
	/// (e.g., `vbETH.withdraw(amount)` on Katana, `WETH.withdraw(amount)` on Ethereum).
	#[allow(unused_variables)]
	async fn unwrap_native(
		&self,
		transfer: &PendingBridgeTransfer,
	) -> Result<solver_types::TransactionHash, BridgeError> {
		Err(BridgeError::Config(
			"unwrap_native not supported by this bridge implementation".into(),
		))
	}

	/// Submit `vault.redeem(received_shares, solver, solver)` on the destination
	/// chain for the non-composer inbound flow. Returns the redeem tx hash;
	/// `BridgeService` polls the receipt then calls `parse_redeem_assets`.
	#[allow(unused_variables)]
	async fn redeem_shares(
		&self,
		transfer: &PendingBridgeTransfer,
	) -> Result<solver_types::TransactionHash, BridgeError> {
		Err(BridgeError::Config(
			"redeem_shares not supported by this bridge implementation".into(),
		))
	}

	/// Parse the asset amount paid out by a redeem tx from its receipt logs.
	/// The bridge implementation owns the ABI binding (ERC-4626 `Withdraw` event
	/// for LayerZero OVault) — this keeps `BridgeService` generic.
	///
	/// Receipts do NOT expose Solidity return values; this method MUST read from
	/// `receipt.logs`, not from any imaginary return field.
	#[allow(unused_variables)]
	fn parse_redeem_assets(
		&self,
		receipt: &solver_types::TransactionReceipt,
	) -> Result<U256, BridgeError> {
		Err(BridgeError::Config(
			"parse_redeem_assets not supported by this bridge implementation".into(),
		))
	}

	/// One-shot startup cross-check. Verifies operator-declared route data against
	/// on-chain state for every pair using this bridge. Invoked once by the engine
	/// after `DeliveryService` is up, before the rebalance monitor starts.
	/// Default returns `Ok(())` so impls without preflight needs don't have to override.
	#[allow(unused_variables)]
	async fn preflight(
		&self,
		pairs: &[solver_types::OperatorRebalancePairConfig],
	) -> Result<(), BridgeError> {
		Ok(())
	}
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

	/// Inspect a `TransferMetadata.bridge_route` JSON blob for a wrapper on the
	/// `source_chain` side. Bridge-generic by convention:
	/// `route.<chain_key>.wrapper.address` is a hex string when that side is
	/// native. Returns false when the metadata has no route or the side has no
	/// wrapper (legacy ERC-20 pairs).
	fn route_has_source_wrapper(metadata: &TransferMetadata, source_chain: u64) -> bool {
		let Some(route) = metadata.bridge_route.as_ref() else {
			return false;
		};
		for side_key in ["chain_a", "chain_b"] {
			let Some(side) = route.get(side_key) else {
				continue;
			};
			let chain_id = side.get("chain_id").and_then(|v| v.as_u64()).unwrap_or(0);
			if chain_id == source_chain {
				return side
					.get("wrapper")
					.and_then(|w| w.get("address"))
					.and_then(|a| a.as_str())
					.is_some();
			}
		}
		false
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
		mut metadata: types::TransferMetadata,
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
		// Populate metadata for delivery detection and redeem path.
		// Clone to avoid partially moving — `metadata` is still needed below for
		// `bridge.bridge_asset(request, &metadata)`.
		transfer.dest_token_address = Some(metadata.dest_token_address.clone());
		transfer.dest_oft_address = Some(metadata.dest_oft_address.clone());
		transfer.is_composer_flow = Some(metadata.is_composer_flow);
		transfer.vault_address = metadata.vault_address.clone();
		// Snapshot the per-pair route at submission so the resume path uses the
		// same routing even if config changes mid-flight.
		transfer.route_snapshot = metadata.bridge_route.clone();
		// Source-side request fields. Snapshot from `request`. The monitor's
		// resume path reads these to reconstruct `BridgeRequest` after a crash.
		// Prefer the caller-supplied effective source token from metadata —
		// for native pairs this is the wrapper address (e.g., WETH) instead of
		// the zero address that lives in `request.source_token`.
		transfer.source_token_address = if !metadata.source_token_address.is_empty() {
			Some(metadata.source_token_address.clone())
		} else {
			Some(format!(
				"0x{}",
				hex::encode(request.source_token.as_slice())
			))
		};
		transfer.source_oft_address =
			Some(format!("0x{}", hex::encode(request.source_oft.as_slice())));
		transfer.recipient_address =
			Some(format!("0x{}", hex::encode(request.recipient.as_slice())));
		transfer.min_amount = request.min_amount.map(|m| m.to_string());
		let transfer_id = transfer.id.clone();
		let approve_scope_id = bridge_system_scope("approve", request.source_chain, &transfer_id);
		let tx_scope_id = bridge_system_scope("deposit", request.source_chain, &transfer_id);
		transfer.approve_scope_id = Some(approve_scope_id.clone());
		transfer.tx_scope_id = Some(tx_scope_id.clone());
		metadata.transfer_id = Some(transfer_id.clone());
		metadata.approve_scope_id = Some(approve_scope_id);
		metadata.tx_scope_id = Some(tx_scope_id);

		// CRASH-WINDOW GUARD: persist `bridge_submit_attempted = true` BEFORE the
		// bridge_asset call. If we crash between the call and the next save (which
		// would write tx_hash on Ok), the monitor's crash-window branch will see
		// the marker without a tx_hash and escalate to NeedsIntervention rather
		// than auto-retry — auto-retrying could double-broadcast the deposit at
		// a fresh nonce. Rolled back on Err(ApprovePending) and Err(ApproveReverted)
		// below, since neither path actually broadcasts the deposit.
		// Native-source wrap step (when the route declares a source wrapper).
		// Submits `wrap_native`, persists `wrap_tx_hash`, and leaves the
		// transfer in `WrapPending`. The monitor picks it up next tick:
		// polls the wrap receipt, then transitions Submitted and triggers
		// the bridge call via the existing `run_bridge_asset_after_approve`
		// resume path. This split keeps `rebalance_token` short and ensures
		// the wrap is verified on-chain before any composer interaction.
		//
		// Crash-window discipline mirrors the bridge submit:
		//   - persist `wrap_submit_attempted = true` BEFORE the call
		//   - on Ok: persist `wrap_tx_hash`, return — monitor handles receipt
		//   - on pre-broadcast errors: roll the marker back, escalate
		//   - on ambiguous errors: keep the marker set, escalate to
		//     NeedsIntervention so the monitor doesn't auto-retry the wrap
		if metadata.bridge_route.is_some()
			&& transfer.wrap_tx_hash.is_none()
			&& Self::route_has_source_wrapper(&metadata, request.source_chain)
		{
			transfer.status = BridgeTransferStatus::WrapPending;
			transfer.wrap_submit_attempted = true;
			transfer.wrap_scope_id = Some(bridge_system_scope(
				"wrap-native",
				request.source_chain,
				&transfer.id,
			));
			self.storage.save_transfer(&transfer).await?;

			match bridge.wrap_native(&transfer).await {
				Ok(hash) => {
					transfer.wrap_tx_hash = Some(format!("0x{}", hex::encode(&hash.0)));
					transfer.updated_at = std::time::SystemTime::now()
						.duration_since(std::time::UNIX_EPOCH)
						.unwrap_or_default()
						.as_secs();
					self.storage.save_transfer(&transfer).await?;
					tracing::info!(
						transfer_id = %transfer.id,
						"Wrap submitted; monitor will poll the receipt and advance to Submitted"
					);
					// Return the transfer here. The monitor's WrapPending branch
					// finishes the rest of the orchestration once the receipt
					// confirms, so callers see the same lifecycle they get on
					// the approve-then-bridge resume path.
					return Ok(transfer);
				},
				Err(BridgeError::InsufficientNativeGas(reason)) => {
					transfer.wrap_submit_attempted = false; // pre-broadcast: safe to roll back
					transfer.transition_to(BridgeTransferStatus::NeedsIntervention(reason.clone()));
					self.storage.save_transfer(&transfer).await?;
					return Err(BridgeError::InsufficientNativeGas(reason));
				},
				Err(BridgeError::NonceTooLow(reason)) => {
					transfer.wrap_submit_attempted = false;
					if let Err(save_err) = self.storage.save_transfer(&transfer).await {
						tracing::warn!(
							transfer_id = %transfer.id,
							error = %save_err,
							"Failed to persist NonceTooLow rollback on wrap"
						);
					}
					return Err(BridgeError::NonceTooLow(reason));
				},
				Err(err) => {
					// Ambiguous error: tx MAY have broadcast. Keep marker set;
					// admin resolves manually.
					transfer.transition_to(BridgeTransferStatus::NeedsIntervention(format!(
						"wrap submit attempted but bridge returned generic error: {err}; possible deposit broadcast — verify chain before retry"
					)));
					if let Err(save_err) = self.storage.save_transfer(&transfer).await {
						tracing::warn!(
							transfer_id = %transfer.id,
							error = %save_err,
							"Failed to persist NeedsIntervention after wrap error"
						);
					}
					return Err(err);
				},
			}
		}

		transfer.bridge_submit_attempted = true;
		self.storage.save_transfer(&transfer).await?;

		// Execute the bridge transfer
		let result = match bridge.bridge_asset(request, &metadata).await {
			Ok(result) => result,
			Err(BridgeError::ApprovePending { tx_hash }) => {
				let now = std::time::SystemTime::now()
					.duration_since(std::time::UNIX_EPOCH)
					.unwrap_or_default()
					.as_secs();
				transfer.bridge_submit_attempted = false; // ROLLBACK: deposit never attempted.
				transfer.approve_tx_hash = Some(tx_hash);
				if !transfer.approve_was_broadcast {
					transfer.approve_was_broadcast = true;
					transfer.approve_submitted_at = Some(now);
				}
				transfer.updated_at = now;
				if let Err(save_err) = self.storage.save_transfer(&transfer).await {
					tracing::warn!(
						transfer_id = %transfer.id,
						error = %save_err,
						"Failed to persist approve_tx_hash after ApprovePending"
					);
					return Err(BridgeError::Storage(save_err.to_string()));
				}
				// Return Ok so the admin API surfaces success: the approve was
				// broadcast and the next reconciliation tick will re-check it.
				return Ok(transfer);
			},
			Err(BridgeError::ApproveReverted { tx_hash, error }) => {
				transfer.bridge_submit_attempted = false; // ROLLBACK: deposit never attempted.
				transfer.approve_tx_hash = Some(tx_hash.clone());
				transfer.transition_to(BridgeTransferStatus::Failed(format!(
					"approve reverted (tx {tx_hash}): {error}"
				)));
				// Propagate save failures (mirroring `ApprovePending` above).
				// If we only warn, the in-memory rollback never reaches storage,
				// so the next monitor tick still sees `bridge_submit_attempted = true`
				// (from the line-204 pre-call save) without a tx hash and escalates
				// it as a possible-double-deposit crash-window case — even though
				// the deposit was never attempted.
				if let Err(save_err) = self.storage.save_transfer(&transfer).await {
					return Err(BridgeError::Storage(format!(
						"failed to persist approve-reverted rollback for transfer {}: {save_err}",
						transfer.id,
					)));
				}
				return Err(BridgeError::ApproveReverted { tx_hash, error });
			},
			Err(BridgeError::ApproveSubmitFailed { error }) => {
				transfer.bridge_submit_attempted = false; // ROLLBACK: deposit never attempted.
				if let Some(scope_id) = transfer.approve_scope_id.as_deref() {
					retire_system_attempt_scope(
						&self.storage.storage_service(),
						scope_id,
						"approve submit failed before bridge deposit",
					)
					.await?;
				}
				transfer.transition_to(BridgeTransferStatus::Failed(format!(
					"approve failed before deposit attempt: {error}"
				)));
				if let Err(save_err) = self.storage.save_transfer(&transfer).await {
					return Err(BridgeError::Storage(format!(
						"failed to persist approve-submit-failed rollback for transfer {}: {save_err}",
						transfer.id,
					)));
				}
				return Err(BridgeError::ApproveSubmitFailed { error });
			},
			Err(BridgeError::InsufficientNativeGas(reason)) => {
				// Pre-broadcast affordability failure. No tx was sent, so roll
				// the crash-window marker back and block the pair for operator
				// action instead of auto-looping on every monitor tick.
				transfer.bridge_submit_attempted = false;
				transfer.transition_to(BridgeTransferStatus::NeedsIntervention(reason.clone()));
				if let Err(save_err) = self.storage.save_transfer(&transfer).await {
					return Err(BridgeError::Storage(format!(
						"failed to persist insufficient-native-gas rollback for transfer {}: {save_err}",
						transfer.id,
					)));
				}
				return Err(BridgeError::InsufficientNativeGas(reason));
			},
			Err(BridgeError::NonceTooLow(reason)) => {
				// Nonce drift is transient and pre-broadcast: the RPC rejected
				// the tx because the local nonce cache was stale. The next call
				// to `next_nonce_for` resyncs against `eth_getTransactionCount`,
				// so we roll back the crash-window marker and leave the transfer
				// in its current status (typically `Submitted`) for the next
				// monitor tick to retry. We do NOT mark NeedsIntervention or
				// Failed — there's no operator action required; the underlying
				// resync happens automatically.
				transfer.bridge_submit_attempted = false;
				if let Err(save_err) = self.storage.save_transfer(&transfer).await {
					tracing::warn!(
						transfer_id = %transfer.id,
						error = %save_err,
						"Failed to persist NonceTooLow rollback"
					);
				}
				return Err(BridgeError::NonceTooLow(reason));
			},
			Err(err) => {
				// Generic error path: any other error is ambiguous — the deposit
				// MAY have been broadcast on chain. Transition to NeedsIntervention
				// (NOT Failed) so the pair stays blocked and admin sees it via the
				// dashboard. `Failed` is terminal and would unblock the pair, which
				// could lead to a double-deposit if a later auto-rebalance fires.
				// Do NOT roll back `bridge_submit_attempted` — per behavioral rule
				// 7b, the marker stays set for safety on ambiguous errors.
				let reason = format!(
					"bridge submit attempted but bridge_asset returned generic error: {err}; possible deposit broadcast — verify chain before retry"
				);
				transfer.transition_to(BridgeTransferStatus::NeedsIntervention(reason));
				if let Err(save_err) = self.storage.save_transfer(&transfer).await {
					tracing::warn!(
						transfer_id = %transfer.id,
						error = %save_err,
						"Failed to persist NeedsIntervention bridge transfer after bridge_asset error"
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
				// Clear the deposit crash-window marker. The operator's explicit
				// retry implies they've checked the chain and confirmed no
				// deposit was broadcast — without this the monitor's crash-window
				// guard (status==Submitted && tx_hash==None && bridge_submit_attempted)
				// would immediately re-escalate the transfer back to
				// NeedsIntervention on the next tick.
				transfer.bridge_submit_attempted = false;
				let attempt_storage = self.storage.storage_service();
				for scope_id in [
					transfer.wrap_scope_id.clone(),
					transfer.tx_scope_id.clone(),
					transfer.approve_scope_id.clone(),
					transfer.redeem_scope_id.clone(),
					transfer.unwrap_scope_id.clone(),
				]
				.into_iter()
				.flatten()
				{
					retire_system_attempt_scope(
						&attempt_storage,
						&scope_id,
						"admin retry cleared bridge phase scope",
					)
					.await?;
				}
				transfer.wrap_submit_attempted = false;
				transfer.wrap_tx_hash = None;
				transfer.wrap_scope_id = None;
				transfer.wrap_missing_checks = 0;
				transfer.redeem_submit_attempted = false;
				transfer.redeem_tx_hash = None;
				transfer.redeem_scope_id = None;
				transfer.redeem_missing_checks = 0;
				transfer.redeem_missing_since = None;
				transfer.unwrap_submit_attempted = false;
				transfer.unwrap_tx_hash = None;
				transfer.unwrap_scope_id = None;
				transfer.unwrap_missing_checks = 0;
				transfer.tx_scope_id = None;
				transfer.approve_scope_id = None;
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

static BRIDGE_REGISTRY: OnceLock<Mutex<HashMap<&'static str, BridgeFactory>>> = OnceLock::new();

/// Runtime-extensible bridge registry.
///
/// The production default remains LayerZero. Tests and future bootstrap paths can
/// register additional bridge factories before the solver constructs services.
pub struct BridgeRegistry;

impl BridgeRegistry {
	fn registry() -> &'static Mutex<HashMap<&'static str, BridgeFactory>> {
		BRIDGE_REGISTRY.get_or_init(|| {
			let mut implementations = HashMap::new();
			implementations.insert(
				"layerzero",
				implementations::layerzero::create_bridge as BridgeFactory,
			);
			Mutex::new(implementations)
		})
	}

	pub fn register(name: &'static str, factory: BridgeFactory) -> Result<(), BridgeError> {
		let mut implementations = Self::registry()
			.lock()
			.map_err(|_| BridgeError::Config("bridge registry lock poisoned".to_string()))?;
		if implementations.contains_key(name) {
			return Err(BridgeError::Config(format!(
				"bridge implementation already registered: {name}"
			)));
		}
		implementations.insert(name, factory);
		Ok(())
	}

	pub fn all() -> Result<Vec<(&'static str, BridgeFactory)>, BridgeError> {
		let implementations = Self::registry()
			.lock()
			.map_err(|_| BridgeError::Config("bridge registry lock poisoned".to_string()))?;
		Ok(implementations
			.iter()
			.map(|(name, factory)| (*name, *factory))
			.collect())
	}
}

/// Returns all registered bridge implementations.
pub fn get_all_implementations() -> Result<Vec<(&'static str, BridgeFactory)>, BridgeError> {
	BridgeRegistry::all()
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::test_support::{bridge_request, pending_transfer, storage_service_from_mock};
	use solver_storage::implementations::file::{FileStorage, TtlConfig};
	use solver_storage::{MockStorageInterface, StorageError, StorageIndexes};
	use solver_types::{
		Address as DeliveryAddress, StorageKey, Transaction, TransactionAttempt,
		TransactionAttemptScope, TransactionAttemptStatus, TransactionType,
	};
	use std::sync::{Arc, Mutex};
	use uuid::Uuid;

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

	struct ApproveSubmitFailedBridge {
		storage: Arc<StorageService>,
	}

	#[async_trait]
	impl BridgeInterface for ApproveSubmitFailedBridge {
		fn supported_routes(&self) -> Vec<(u64, u64)> {
			vec![(1, 747474)]
		}

		async fn bridge_asset(
			&self,
			request: &BridgeRequest,
			metadata: &TransferMetadata,
		) -> Result<BridgeDepositResult, BridgeError> {
			let scope_id = metadata
				.approve_scope_id
				.clone()
				.expect("rebalance_token must provide approve scope");
			let mut attempt = TransactionAttempt::planned(
				"approve-timeout-attempt".to_string(),
				TransactionAttemptScope::system(scope_id),
				Some(DeliveryAddress(vec![0x99; 20])),
				TransactionType::Bridge,
				sample_attempt_tx(request.source_chain),
			);
			attempt.status = TransactionAttemptStatus::Broadcast;
			store_system_attempt(&self.storage, &attempt).await;
			Err(BridgeError::ApproveSubmitFailed {
				error: "approve receipt timeout".to_string(),
			})
		}

		async fn check_status(
			&self,
			_transfer: &PendingBridgeTransfer,
		) -> Result<BridgeTransferStatus, BridgeError> {
			Ok(BridgeTransferStatus::Submitted)
		}

		async fn estimate_fee(
			&self,
			_request: &BridgeRequest,
			_metadata: &TransferMetadata,
		) -> Result<U256, BridgeError> {
			Ok(U256::ZERO)
		}
	}

	fn registry_test_bridge_factory(
		_config: &serde_json::Value,
		_delivery: Arc<solver_delivery::DeliveryService>,
		_solver: alloy_primitives::Address,
	) -> Result<Box<dyn BridgeInterface>, BridgeError> {
		Ok(Box::new(TestBridge::new()))
	}

	#[async_trait]
	impl BridgeInterface for TestBridge {
		fn supported_routes(&self) -> Vec<(u64, u64)> {
			vec![(1, 747474)]
		}

		async fn bridge_asset(
			&self,
			_request: &BridgeRequest,
			_metadata: &TransferMetadata,
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

		async fn estimate_fee(
			&self,
			_request: &BridgeRequest,
			_metadata: &TransferMetadata,
		) -> Result<U256, BridgeError> {
			self.estimate_fee_result
				.lock()
				.unwrap()
				.take()
				.expect("estimate_fee_result not configured")
		}
	}

	#[test]
	fn bridge_registry_includes_runtime_registered_factories() {
		BridgeRegistry::register("unit-test-bridge", registry_test_bridge_factory)
			.expect("register test bridge");

		let implementations = get_all_implementations().expect("read bridge registry");

		assert!(
			implementations.iter().any(|(name, _)| *name == "layerzero"),
			"default layerzero implementation should remain registered"
		);
		assert!(
			implementations
				.iter()
				.any(|(name, _)| *name == "unit-test-bridge"),
			"runtime registered bridge should be returned"
		);
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

	fn file_storage_service() -> Arc<StorageService> {
		let base_path =
			std::env::temp_dir().join(format!("solver-bridge-service-test-{}", Uuid::new_v4()));
		Arc::new(StorageService::new(Box::new(FileStorage::new(
			base_path,
			TtlConfig::default(),
		))))
	}

	fn make_service_with_storage(
		bridge: Arc<dyn BridgeInterface>,
		storage: Arc<StorageService>,
	) -> BridgeService {
		let implementations = HashMap::from([("mock-bridge".to_string(), bridge)]);
		BridgeService::new(implementations, storage, "solver-a".to_string())
	}

	fn sample_attempt_tx(chain_id: u64) -> Transaction {
		Transaction {
			to: Some(DeliveryAddress(vec![0xbb; 20])),
			data: vec![0x12, 0x34],
			value: U256::ZERO,
			chain_id,
			nonce: Some(5),
			gas_limit: Some(100000),
			gas_price: None,
			max_fee_per_gas: Some(100),
			max_priority_fee_per_gas: Some(2),
		}
	}

	async fn store_system_attempt(storage: &Arc<StorageService>, attempt: &TransactionAttempt) {
		let indexes = StorageIndexes::new()
			.with_field("scope_kind", "system")
			.with_field("scope_id", attempt.scope.scope_id())
			.with_field("is_terminal", attempt.is_terminal());
		storage
			.store(
				StorageKey::TransactionAttempts.as_str(),
				&attempt.id,
				attempt,
				Some(indexes),
			)
			.await
			.unwrap();
	}

	fn bridge_metadata() -> types::TransferMetadata {
		types::TransferMetadata {
			source_token_address: "0x1111111111111111111111111111111111111111".to_string(),
			dest_token_address: "0x3333333333333333333333333333333333333333".to_string(),
			dest_oft_address: "0x4444444444444444444444444444444444444444".to_string(),
			is_composer_flow: true,
			vault_address: None,
			..Default::default()
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
	async fn test_rebalance_token_persists_intervention_state_when_bridge_asset_fails() {
		// Updated for crash-window guard: a generic `bridge_asset` error is now
		// persisted as NeedsIntervention (not Failed), because the deposit MAY
		// have been broadcast and a Failed status would unblock the pair —
		// allowing a later auto-rebalance to double-deposit.
		let events = Arc::new(Mutex::new(Vec::<&'static str>::new()));
		let first_saved = Arc::new(Mutex::new(None));
		let intervention_saved = Arc::new(Mutex::new(None));
		let request = bridge_request();
		let mut storage = MockStorageInterface::new();
		{
			let events = events.clone();
			let first_saved = first_saved.clone();
			let intervention_saved = intervention_saved.clone();
			storage
				.expect_set_bytes()
				.times(2)
				.returning(move |_key, value, _indexes, _ttl| {
					let events = events.clone();
					let first_saved = first_saved.clone();
					let intervention_saved = intervention_saved.clone();
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
							assert!(matches!(
								&transfer.status,
								BridgeTransferStatus::NeedsIntervention(reason)
									if reason.contains("bridge submit attempted")
										&& reason.contains("bridge send failed")
							));
							assert!(transfer.bridge_submit_attempted);
							*intervention_saved.lock().unwrap() = Some(transfer);
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
		let intervention = intervention_saved.lock().unwrap().clone().unwrap();
		assert!(matches!(
			intervention.status,
			BridgeTransferStatus::NeedsIntervention(_)
		));
		assert!(intervention.bridge_submit_attempted);
		assert!(intervention.status.blocks_pair());
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
	async fn rebalance_token_returns_ok_and_persists_approve_hash_on_approve_pending() {
		let request = bridge_request();
		// Capture every saved state for inspection.
		let saved_states: Arc<Mutex<Vec<PendingBridgeTransfer>>> = Arc::new(Mutex::new(Vec::new()));
		let mut storage = MockStorageInterface::new();
		{
			let saved_states = saved_states.clone();
			storage
				.expect_set_bytes()
				.times(2)
				.returning(move |_key, value, _indexes, _ttl| {
					let saved_states = saved_states.clone();
					Box::pin(async move {
						let transfer: PendingBridgeTransfer =
							serde_json::from_slice(&value).unwrap();
						saved_states.lock().unwrap().push(transfer);
						Ok(())
					})
				});
		}

		let bridge = Arc::new(TestBridge {
			bridge_asset_result: Mutex::new(Some(Err(BridgeError::ApprovePending {
				tx_hash: "0xab1234".to_string(),
			}))),
			check_status_result: Mutex::new(None),
			estimate_fee_result: Mutex::new(None),
			events: None,
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

		// Critical: result is Ok (NOT Err) so admin API surfaces success.
		let returned = result.expect("rebalance_token must return Ok on ApprovePending");
		assert!(returned.tx_hash.is_none());

		// The last persisted state is what storage holds at end-of-call.
		let final_state = saved_states
			.lock()
			.unwrap()
			.last()
			.cloned()
			.expect("expected at least one save");
		assert_eq!(final_state.id, returned.id);
		assert!(matches!(
			final_state.status,
			BridgeTransferStatus::Submitted
		));
		assert!(final_state.tx_hash.is_none());
		assert_eq!(final_state.approve_tx_hash.as_deref(), Some("0xab1234"));
		assert!(final_state.approve_was_broadcast);
		assert!(final_state.approve_submitted_at.is_some());
		assert!(!final_state.bridge_submit_attempted); // rolled back on ApprovePending
												 // Source fields populated:
		assert!(final_state.source_token_address.is_some());
		assert!(final_state.source_oft_address.is_some());
		assert!(final_state.recipient_address.is_some());

		// First save (intent) should have bridge_submit_attempted = true.
		let first_state = saved_states
			.lock()
			.unwrap()
			.first()
			.cloned()
			.expect("expected the first save");
		assert!(first_state.bridge_submit_attempted);
		assert!(first_state.tx_hash.is_none());
		assert!(first_state.source_token_address.is_some());
		assert!(first_state.source_oft_address.is_some());
		assert!(first_state.recipient_address.is_some());
	}

	#[tokio::test]
	async fn rebalance_token_marks_failed_on_approve_submit_failed_before_deposit() {
		let request = bridge_request();
		let saved_states: Arc<Mutex<Vec<PendingBridgeTransfer>>> = Arc::new(Mutex::new(Vec::new()));
		let mut storage = MockStorageInterface::new();
		{
			let saved_states = saved_states.clone();
			storage
				.expect_set_bytes()
				.times(2)
				.returning(move |_key, value, _indexes, _ttl| {
					let saved_states = saved_states.clone();
					Box::pin(async move {
						let transfer: PendingBridgeTransfer =
							serde_json::from_slice(&value).unwrap();
						saved_states.lock().unwrap().push(transfer);
						Ok(())
					})
				});
		}
		storage
			.expect_query()
			.times(1)
			.returning(|namespace, _filter| {
				assert_eq!(namespace, StorageKey::TransactionAttempts.as_str());
				Box::pin(async move { Ok(Vec::new()) })
			});
		storage.expect_get_batch().times(1).returning(|keys| {
			assert!(keys.is_empty());
			Box::pin(async move { Ok(Vec::new()) })
		});

		let bridge = Arc::new(TestBridge {
			bridge_asset_result: Mutex::new(Some(Err(BridgeError::ApproveSubmitFailed {
				error: "Composer approve receipt not found after 12 attempts".to_string(),
			}))),
			check_status_result: Mutex::new(None),
			estimate_fee_result: Mutex::new(None),
			events: None,
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

		assert!(matches!(
			result,
			Err(BridgeError::ApproveSubmitFailed { .. })
		));
		let final_state = saved_states
			.lock()
			.unwrap()
			.last()
			.cloned()
			.expect("expected final saved transfer");
		assert!(matches!(
			final_state.status,
			BridgeTransferStatus::Failed(ref reason)
				if reason.contains("approve failed before deposit attempt")
		));
		assert!(!final_state.bridge_submit_attempted);
		assert!(final_state.tx_hash.is_none());
	}

	#[tokio::test]
	async fn rebalance_token_marks_needs_intervention_on_insufficient_native_gas() {
		let request = bridge_request();
		let saved_states: Arc<Mutex<Vec<PendingBridgeTransfer>>> = Arc::new(Mutex::new(Vec::new()));
		let mut storage = MockStorageInterface::new();
		{
			let saved_states = saved_states.clone();
			storage
				.expect_set_bytes()
				.times(2)
				.returning(move |_key, value, _indexes, _ttl| {
					let saved_states = saved_states.clone();
					Box::pin(async move {
						let transfer: PendingBridgeTransfer =
							serde_json::from_slice(&value).unwrap();
						saved_states.lock().unwrap().push(transfer);
						Ok(())
					})
				});
		}

		let bridge = Arc::new(TestBridge {
			bridge_asset_result: Mutex::new(Some(Err(BridgeError::InsufficientNativeGas(
				"Insufficient native gas on chain 1 for signer 0xsolver: balance 10 wei, required 30 wei, shortfall 20 wei".to_string(),
			)))),
			check_status_result: Mutex::new(None),
			estimate_fee_result: Mutex::new(None),
			events: None,
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

		assert!(matches!(
			result,
			Err(BridgeError::InsufficientNativeGas(reason))
				if reason.contains("shortfall 20 wei")
		));
		let final_state = saved_states
			.lock()
			.unwrap()
			.last()
			.cloned()
			.expect("expected final saved transfer");
		assert!(matches!(
			final_state.status,
			BridgeTransferStatus::NeedsIntervention(ref reason)
				if reason.contains("Insufficient native gas")
					&& reason.contains("shortfall 20 wei")
		));
		assert!(!final_state.bridge_submit_attempted);
		assert!(final_state.tx_hash.is_none());
		assert!(final_state.status.blocks_pair());
	}

	#[tokio::test]
	async fn rebalance_token_marks_needs_intervention_on_generic_error_when_submit_attempted() {
		// Stub bridge.bridge_asset → Err(BridgeError::TransactionFailed("rpc blip"))
		// Expect:
		//   - returns Err(BridgeError::TransactionFailed(_))
		//   - stored transfer has status == NeedsIntervention(reason) where reason
		//     mentions "bridge submit attempted" and the underlying error
		//   - bridge_submit_attempted == true (KEPT set, NOT rolled back)
		//   - blocks_pair() == true on the stored status (so monitor still sees it)
		let request = bridge_request();
		let saved_states: Arc<Mutex<Vec<PendingBridgeTransfer>>> = Arc::new(Mutex::new(Vec::new()));
		let mut storage = MockStorageInterface::new();
		{
			let saved_states = saved_states.clone();
			storage
				.expect_set_bytes()
				.times(2)
				.returning(move |_key, value, _indexes, _ttl| {
					let saved_states = saved_states.clone();
					Box::pin(async move {
						let transfer: PendingBridgeTransfer =
							serde_json::from_slice(&value).unwrap();
						saved_states.lock().unwrap().push(transfer);
						Ok(())
					})
				});
		}

		let bridge = Arc::new(TestBridge {
			bridge_asset_result: Mutex::new(Some(Err(BridgeError::TransactionFailed(
				"rpc blip".to_string(),
			)))),
			check_status_result: Mutex::new(None),
			estimate_fee_result: Mutex::new(None),
			events: None,
		});
		let bridge: Arc<dyn BridgeInterface> = bridge;
		let service = make_service(bridge, storage);
		let err = service
			.rebalance_token(
				"mock-bridge",
				&request,
				RebalanceTrigger::Auto,
				bridge_metadata(),
			)
			.await
			.expect_err("rebalance_token must return Err on generic bridge error");
		assert!(
			matches!(&err, BridgeError::TransactionFailed(msg) if msg.contains("rpc blip")),
			"expected TransactionFailed, got {err:?}"
		);

		let final_state = saved_states
			.lock()
			.unwrap()
			.last()
			.cloned()
			.expect("expected the post-error save");

		// Must be NeedsIntervention with a reason mentioning the marker and the underlying error.
		match &final_state.status {
			BridgeTransferStatus::NeedsIntervention(reason) => {
				assert!(
					reason.contains("bridge submit attempted"),
					"reason should mention 'bridge submit attempted', got: {reason}"
				);
				assert!(
					reason.contains("rpc blip"),
					"reason should mention underlying error 'rpc blip', got: {reason}"
				);
			},
			other => panic!("expected NeedsIntervention, got {other:?}"),
		}

		// The marker must STAY set (not rolled back) for generic errors.
		assert!(
			final_state.bridge_submit_attempted,
			"bridge_submit_attempted must remain true on generic error"
		);

		// Pair must still be blocked so the monitor's crash-window guard sees it.
		assert!(
			final_state.status.blocks_pair(),
			"NeedsIntervention must block the pair (so monitor sees it)"
		);
		assert!(
			!final_state.status.is_terminal(),
			"NeedsIntervention must be non-terminal"
		);

		// Original status (Submitted) preserved for retry recovery.
		assert_eq!(
			final_state.status_before_intervention,
			Some(BridgeTransferStatus::Submitted)
		);
	}

	#[tokio::test]
	async fn rebalance_token_marks_failed_and_returns_err_on_approve_reverted() {
		let request = bridge_request();
		let saved_states: Arc<Mutex<Vec<PendingBridgeTransfer>>> = Arc::new(Mutex::new(Vec::new()));
		let mut storage = MockStorageInterface::new();
		{
			let saved_states = saved_states.clone();
			storage
				.expect_set_bytes()
				.times(2)
				.returning(move |_key, value, _indexes, _ttl| {
					let saved_states = saved_states.clone();
					Box::pin(async move {
						let transfer: PendingBridgeTransfer =
							serde_json::from_slice(&value).unwrap();
						saved_states.lock().unwrap().push(transfer);
						Ok(())
					})
				});
		}

		let bridge = Arc::new(TestBridge {
			bridge_asset_result: Mutex::new(Some(Err(BridgeError::ApproveReverted {
				tx_hash: "0xrevert".to_string(),
				error: "execution reverted".to_string(),
			}))),
			check_status_result: Mutex::new(None),
			estimate_fee_result: Mutex::new(None),
			events: None,
		});
		let bridge: Arc<dyn BridgeInterface> = bridge;
		let service = make_service(bridge, storage);
		let err = service
			.rebalance_token(
				"mock-bridge",
				&request,
				RebalanceTrigger::Auto,
				bridge_metadata(),
			)
			.await
			.expect_err("rebalance_token must return Err on ApproveReverted");
		assert!(matches!(err, BridgeError::ApproveReverted { .. }));

		let final_state = saved_states
			.lock()
			.unwrap()
			.last()
			.cloned()
			.expect("expected the failed save");
		assert!(matches!(
			final_state.status,
			BridgeTransferStatus::Failed(_)
		));
		assert_eq!(final_state.approve_tx_hash.as_deref(), Some("0xrevert"));
		assert!(!final_state.bridge_submit_attempted); // rolled back on ApproveReverted
	}

	#[tokio::test]
	async fn rebalance_token_persists_source_fields_before_bridge_asset() {
		// Capture transfer state at the moment bridge_asset is invoked.
		struct CapturingBridge {
			seen_at_call: Arc<Mutex<Option<PendingBridgeTransfer>>>,
			latest_saved: Arc<Mutex<Option<PendingBridgeTransfer>>>,
			result: Mutex<Option<Result<BridgeDepositResult, BridgeError>>>,
		}

		#[async_trait]
		impl BridgeInterface for CapturingBridge {
			fn supported_routes(&self) -> Vec<(u64, u64)> {
				vec![(1, 747474)]
			}

			async fn bridge_asset(
				&self,
				_request: &BridgeRequest,
				_metadata: &TransferMetadata,
			) -> Result<BridgeDepositResult, BridgeError> {
				// Snapshot the most recent saved state — this is what storage held
				// at the moment we entered bridge_asset.
				*self.seen_at_call.lock().unwrap() = self.latest_saved.lock().unwrap().clone();
				self.result
					.lock()
					.unwrap()
					.take()
					.expect("result not configured")
			}

			async fn check_status(
				&self,
				_transfer: &PendingBridgeTransfer,
			) -> Result<BridgeTransferStatus, BridgeError> {
				unreachable!()
			}

			async fn estimate_fee(
				&self,
				_request: &BridgeRequest,
				_metadata: &TransferMetadata,
			) -> Result<U256, BridgeError> {
				unreachable!()
			}
		}

		let request = bridge_request();
		let latest_saved: Arc<Mutex<Option<PendingBridgeTransfer>>> = Arc::new(Mutex::new(None));
		let seen_at_call: Arc<Mutex<Option<PendingBridgeTransfer>>> = Arc::new(Mutex::new(None));
		let mut storage = MockStorageInterface::new();
		{
			let latest_saved = latest_saved.clone();
			storage
				.expect_set_bytes()
				.returning(move |_key, value, _indexes, _ttl| {
					let latest_saved = latest_saved.clone();
					Box::pin(async move {
						let transfer: PendingBridgeTransfer =
							serde_json::from_slice(&value).unwrap();
						*latest_saved.lock().unwrap() = Some(transfer);
						Ok(())
					})
				});
		}

		let bridge = Arc::new(CapturingBridge {
			seen_at_call: seen_at_call.clone(),
			latest_saved: latest_saved.clone(),
			result: Mutex::new(Some(Ok(configured_deposit_result()))),
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
			.expect("happy path must succeed");

		let snapshot_at_call = seen_at_call
			.lock()
			.unwrap()
			.clone()
			.expect("bridge_asset should have observed a saved state");
		assert!(
			snapshot_at_call.bridge_submit_attempted,
			"bridge_submit_attempted must be true BEFORE bridge_asset is called"
		);
		assert!(snapshot_at_call.source_token_address.is_some());
		assert!(snapshot_at_call.source_oft_address.is_some());
		assert!(snapshot_at_call.recipient_address.is_some());

		// After the Ok branch: storage has tx_hash populated.
		let final_saved = latest_saved
			.lock()
			.unwrap()
			.clone()
			.expect("expected post-success save");
		assert_eq!(final_saved.tx_hash.as_deref(), Some("0xabc123"));
		assert!(final_saved.bridge_submit_attempted);
		assert_eq!(result.tx_hash.as_deref(), Some("0xabc123"));
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
	async fn test_resolve_transfer_retry_clears_bridge_submit_attempted_marker() {
		// Regression for the retry-loop bug: a transfer escalated to
		// NeedsIntervention via the deposit crash-window (Submitted +
		// tx_hash=None + bridge_submit_attempted=true) must, after an admin
		// retry, come back with bridge_submit_attempted=false. Otherwise the
		// monitor's crash-window guard would re-escalate it on the next tick,
		// looping forever.
		let mut transfer = pending_transfer(BridgeTransferStatus::NeedsIntervention(
			"deposit crash window".to_string(),
		));
		transfer.status_before_intervention = Some(BridgeTransferStatus::Submitted);
		transfer.bridge_submit_attempted = true;
		transfer.tx_hash = None;
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
			.resolve_transfer(
				&transfer.id,
				"retry",
				"operator confirmed no deposit broadcast",
			)
			.await
			.unwrap();

		// Returned-by-the-call view: status restored, marker cleared.
		assert!(matches!(resolved.status, BridgeTransferStatus::Submitted));
		assert!(
			!resolved.bridge_submit_attempted,
			"retry must clear bridge_submit_attempted to break the crash-window loop"
		);
		assert!(resolved.tx_hash.is_none());

		// Persisted view (what the monitor will read next tick): same shape.
		let saved = saved.lock().unwrap().clone().unwrap();
		assert!(matches!(saved.status, BridgeTransferStatus::Submitted));
		assert!(!saved.bridge_submit_attempted);
		assert!(saved.tx_hash.is_none());
	}

	#[tokio::test]
	async fn test_resolve_transfer_retry_clears_native_phase_markers() {
		let mut transfer = pending_transfer(BridgeTransferStatus::NeedsIntervention(
			"native crash window".to_string(),
		));
		transfer.status_before_intervention = Some(BridgeTransferStatus::WrapPending);
		transfer.wrap_submit_attempted = true;
		transfer.wrap_tx_hash = Some("0xwrap".to_string());
		transfer.wrap_missing_checks = 2;
		transfer.redeem_submit_attempted = true;
		transfer.redeem_tx_hash = Some("0xredeem".to_string());
		transfer.redeem_missing_checks = 2;
		transfer.redeem_missing_since = Some(1_700_000_010);
		transfer.unwrap_submit_attempted = true;
		transfer.unwrap_tx_hash = Some("0xunwrap".to_string());
		transfer.unwrap_missing_checks = 2;
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
			.resolve_transfer(&transfer.id, "retry", "operator verified native phases")
			.await
			.unwrap();

		assert!(matches!(resolved.status, BridgeTransferStatus::WrapPending));
		assert!(!resolved.wrap_submit_attempted);
		assert!(resolved.wrap_tx_hash.is_none());
		assert_eq!(resolved.wrap_missing_checks, 0);
		assert!(!resolved.redeem_submit_attempted);
		assert!(resolved.redeem_tx_hash.is_none());
		assert_eq!(resolved.redeem_missing_checks, 0);
		assert!(resolved.redeem_missing_since.is_none());
		assert!(!resolved.unwrap_submit_attempted);
		assert!(resolved.unwrap_tx_hash.is_none());
		assert_eq!(resolved.unwrap_missing_checks, 0);

		let saved = saved.lock().unwrap().clone().unwrap();
		assert!(matches!(saved.status, BridgeTransferStatus::WrapPending));
		assert!(!saved.wrap_submit_attempted);
		assert!(saved.wrap_tx_hash.is_none());
		assert!(!saved.redeem_submit_attempted);
		assert!(saved.redeem_tx_hash.is_none());
		assert!(!saved.unwrap_submit_attempted);
		assert!(saved.unwrap_tx_hash.is_none());
	}

	#[tokio::test]
	async fn test_resolve_transfer_retry_retires_cleared_system_attempt_scopes() {
		let storage = file_storage_service();
		let service = make_service_with_storage(Arc::new(TestBridge::new()), storage.clone());
		let mut transfer = pending_transfer(BridgeTransferStatus::NeedsIntervention(
			"native retry requested".to_string(),
		));
		transfer.status_before_intervention = Some(BridgeTransferStatus::WrapPending);
		transfer.wrap_scope_id = Some("system:bridge:wrap:transfer-1".to_string());
		transfer.tx_scope_id = Some("system:bridge:deposit:transfer-1".to_string());
		transfer.approve_scope_id = Some("system:bridge:approve:transfer-1".to_string());
		transfer.redeem_scope_id = Some("system:bridge:redeem:transfer-1".to_string());
		transfer.unwrap_scope_id = Some("system:bridge:unwrap:transfer-1".to_string());
		service.storage.save_transfer(&transfer).await.unwrap();

		let mut pending = TransactionAttempt::planned(
			"attempt-wrap".to_string(),
			TransactionAttemptScope::system(transfer.wrap_scope_id.clone().unwrap()),
			Some(DeliveryAddress(vec![0x99; 20])),
			TransactionType::Bridge,
			sample_attempt_tx(1),
		);
		pending.status = TransactionAttemptStatus::Broadcast;
		store_system_attempt(&storage, &pending).await;
		let mut confirmed = TransactionAttempt::planned(
			"attempt-confirmed".to_string(),
			TransactionAttemptScope::system(transfer.tx_scope_id.clone().unwrap()),
			Some(DeliveryAddress(vec![0x99; 20])),
			TransactionType::Bridge,
			sample_attempt_tx(1),
		);
		confirmed.status = TransactionAttemptStatus::Confirmed;
		store_system_attempt(&storage, &confirmed).await;

		let resolved = service
			.resolve_transfer(&transfer.id, "retry", "operator verified phases")
			.await
			.unwrap();

		assert!(matches!(resolved.status, BridgeTransferStatus::WrapPending));
		assert!(resolved.wrap_scope_id.is_none());
		assert!(resolved.tx_scope_id.is_none());
		assert!(resolved.approve_scope_id.is_none());
		assert!(resolved.redeem_scope_id.is_none());
		assert!(resolved.unwrap_scope_id.is_none());
		let retired: TransactionAttempt = storage
			.retrieve(StorageKey::TransactionAttempts.as_str(), "attempt-wrap")
			.await
			.unwrap();
		assert_eq!(retired.status, TransactionAttemptStatus::Replaced);
		assert_eq!(
			retired.error.as_deref(),
			Some("admin retry cleared bridge phase scope")
		);
		let untouched: TransactionAttempt = storage
			.retrieve(
				StorageKey::TransactionAttempts.as_str(),
				"attempt-confirmed",
			)
			.await
			.unwrap();
		assert_eq!(untouched.status, TransactionAttemptStatus::Confirmed);
	}

	#[tokio::test]
	async fn rebalance_token_retires_approve_scope_on_submit_failed_terminal_transfer() {
		let storage = file_storage_service();
		let bridge = Arc::new(ApproveSubmitFailedBridge {
			storage: storage.clone(),
		});
		let service = make_service_with_storage(bridge, storage.clone());

		let err = service
			.rebalance_token(
				"mock-bridge",
				&bridge_request(),
				RebalanceTrigger::Auto,
				bridge_metadata(),
			)
			.await
			.expect_err("approve submit failure should be returned");

		assert!(matches!(err, BridgeError::ApproveSubmitFailed { .. }));
		let attempt: TransactionAttempt = storage
			.retrieve(
				StorageKey::TransactionAttempts.as_str(),
				"approve-timeout-attempt",
			)
			.await
			.unwrap();
		assert_eq!(attempt.status, TransactionAttemptStatus::Replaced);
		assert_eq!(
			attempt.error.as_deref(),
			Some("approve submit failed before bridge deposit")
		);
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
