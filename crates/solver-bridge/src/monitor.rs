//! Rebalance monitor background task.
//!
//! Spawned inside `SolverEngine::run()` where `transaction_semaphore` is in scope.
//! Continuously:
//! 1. Advances pending transfers through the state machine
//! 2. Checks balances against configured thresholds
//! 3. Auto-triggers rebalance when thresholds are breached (respecting safety guards)
//!
//! Uses `pair.pair_id` (operator-chosen unique key) for cooldowns, transfer
//! lookups, and any pair-level state.

use crate::threshold::{analyze_pair, RebalanceDirection};
use crate::types::{BridgeRequest, BridgeTransferStatus, RebalanceTrigger};
use crate::BridgeService;
use alloy_primitives::{Address, U256};
use solver_config::RebalanceConfig;
use solver_storage::StorageService;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, RwLock, Semaphore};

/// Timeout for Submitted state before NeedsIntervention.
const SUBMITTED_TIMEOUT_SECS: u64 = 30 * 60;

/// Absolute upper bound on the approve phase. Catches a low-gas approve that
/// stays in the mempool forever (tx_exists keeps returning true). After this,
/// the only safe action is admin intervention — automatic fee bumping is
/// deferred (requires Fix 3 / TxAttempt outbox).
const APPROVE_PHASE_TIMEOUT_SECS: u64 = 60 * 60; // 1 hour

/// Timeout for Relaying state before NeedsIntervention.
const RELAYING_TIMEOUT_SECS: u64 = 30 * 60;

/// Timeout for PendingRedemption before NeedsIntervention.
const PENDING_REDEMPTION_TIMEOUT_SECS: u64 = 24 * 3600;

/// Max retries for PendingRedemption before NeedsIntervention.
const MAX_REDEEM_RETRIES: u32 = 3;

fn is_source_transaction_missing(reason: &str) -> bool {
	reason.contains("Source transaction not found") || reason.contains("Source transaction missing")
}

/// Background rebalance monitor.
/// Shared monitor timing state, readable by the admin status API.
#[derive(Debug, Default, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RebalanceMonitorStatus {
	/// Unix timestamp of the last completed tick (None if never ran).
	pub last_check_at: Option<u64>,
	/// Unix timestamp of the next scheduled tick (None if disabled).
	pub next_check_at: Option<u64>,
}

pub struct RebalanceMonitor {
	bridge_service: Arc<BridgeService>,
	delivery: Arc<solver_delivery::DeliveryService>,
	dynamic_config: Arc<RwLock<solver_config::Config>>,
	#[allow(dead_code)]
	storage: Arc<StorageService>,
	transaction_semaphore: Arc<Semaphore>,
	solver_address: String,
	monitor_status: Arc<RwLock<RebalanceMonitorStatus>>,
}

impl RebalanceMonitor {
	pub fn new(
		bridge_service: Arc<BridgeService>,
		delivery: Arc<solver_delivery::DeliveryService>,
		dynamic_config: Arc<RwLock<solver_config::Config>>,
		storage: Arc<StorageService>,
		transaction_semaphore: Arc<Semaphore>,
		solver_address: String,
		monitor_status: Arc<RwLock<RebalanceMonitorStatus>>,
	) -> Self {
		Self {
			bridge_service,
			delivery,
			dynamic_config,
			storage,
			transaction_semaphore,
			solver_address,
			monitor_status,
		}
	}

	/// Main polling loop. Runs until shutdown signal.
	pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
		tracing::info!("Rebalance monitor started");

		loop {
			let (interval_seconds, rebalance_enabled) = {
				let config = self.dynamic_config.read().await;
				match config.rebalance.as_ref() {
					Some(r) if r.enabled => (r.monitor_interval_seconds, true),
					_ => (60, false),
				}
			};

			// Only report next_check_at when rebalance is enabled
			{
				let now = std::time::SystemTime::now()
					.duration_since(std::time::UNIX_EPOCH)
					.unwrap_or_default()
					.as_secs();
				let mut status = self.monitor_status.write().await;
				status.next_check_at = if rebalance_enabled {
					Some(now + interval_seconds)
				} else {
					None
				};
			}

			tokio::select! {
				_ = tokio::time::sleep(Duration::from_secs(interval_seconds)) => {
					match self.tick().await {
						Ok(()) => {
							let now = std::time::SystemTime::now()
								.duration_since(std::time::UNIX_EPOCH)
								.unwrap_or_default()
								.as_secs();
							let mut status = self.monitor_status.write().await;
							status.last_check_at = Some(now);
						},
						Err(e) => {
							tracing::warn!("Rebalance monitor tick failed: {}", e);
						},
					}
				}
				_ = shutdown.changed() => {
					tracing::info!("Rebalance monitor shutting down");
					break;
				}
			}
		}
	}

	/// Single monitoring cycle.
	async fn tick(&self) -> Result<(), crate::BridgeError> {
		let config = self.dynamic_config.read().await;
		let rebalance_config = match config.rebalance.as_ref() {
			Some(c) if c.enabled => c.clone(),
			_ => return Ok(()),
		};
		drop(config);

		self.advance_pending_transfers(&rebalance_config).await?;
		self.check_thresholds_and_trigger(&rebalance_config).await?;

		Ok(())
	}

	/// Advance all active transfers through the state machine.
	async fn advance_pending_transfers(
		&self,
		config: &RebalanceConfig,
	) -> Result<(), crate::BridgeError> {
		let active = self.bridge_service.get_active_transfers().await?;
		let bridge_impl = self
			.bridge_service
			.get_implementation(&config.implementation)?;

		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs();

		for mut transfer in active {
			let age = now.saturating_sub(transfer.updated_at);

			// (0) DEPOSIT CRASH-WINDOW GUARD — HIGHEST priority.
			// We marked the transfer "about to call bridge_asset" but never persisted
			// a tx_hash. The deposit may have broadcast on-chain at a nonce we'll never
			// re-derive. Auto-retry would risk a second deposit. Escalate to admin.
			if matches!(transfer.status, BridgeTransferStatus::Submitted)
				&& transfer.tx_hash.is_none()
				&& transfer.bridge_submit_attempted
			{
				tracing::warn!(
					transfer_id = %transfer.id,
					pair = %transfer.pair_id,
					"Deposit crash window detected (bridge_submit_attempted=true, tx_hash=None); escalating"
				);
				self.bridge_service
					.update_transfer(
						&mut transfer,
						BridgeTransferStatus::NeedsIntervention(
							"bridge submit attempted but tx_hash not persisted; possible double-deposit risk if auto-retried"
								.to_string(),
						),
					)
					.await?;
				continue;
			}

			// (d) Approve-phase absolute timeout. Catches a low-gas approve that sits in
			// the mempool indefinitely with tx_exists==true. Without this rule, the
			// "still pending" branch below would loop forever.
			//
			// Two bypass paths the previous shape allowed:
			//
			// 1. approve_submitted_at == None: `.unwrap_or(false)` made the timestamp
			//    comparison fail-open. Older serialized records or any partial-metadata
			//    write skipped the timeout entirely.
			//
			// 2. approve_tx_hash == Some(valid) && approve_was_broadcast == false: the
			//    guard required approve_was_broadcast, and the mid-flight approve branch
			//    runs first and `continue`s every tick. The stale-hash counter only
			//    increments when tx_exists() returns Ok(false) — so a slow underpriced
			//    approve where tx_exists() == Ok(true) indefinitely had no escalation.
			//
			// Fix both at once: derive "phase started" from EITHER signal, and "phase
			// start time" with a fallback to created_at.
			if matches!(transfer.status, BridgeTransferStatus::Submitted)
				&& transfer.tx_hash.is_none()
				&& {
					let approve_phase_started =
						transfer.approve_was_broadcast || transfer.approve_tx_hash.is_some();
					let phase_start = transfer
						.approve_submitted_at
						.unwrap_or(transfer.created_at);
					approve_phase_started
						&& now.saturating_sub(phase_start) > APPROVE_PHASE_TIMEOUT_SECS
				} {
				let phase_age = now.saturating_sub(
					transfer
						.approve_submitted_at
						.unwrap_or(transfer.created_at),
				);
				tracing::warn!(
					transfer_id = %transfer.id,
					pair = %transfer.pair_id,
					approve_phase_age_secs = phase_age,
					approve_was_broadcast = transfer.approve_was_broadcast,
					approve_tx_hash_present = transfer.approve_tx_hash.is_some(),
					approve_submitted_at = ?transfer.approve_submitted_at,
					"Approve phase exceeded absolute timeout; escalating to NeedsIntervention"
				);
				self.bridge_service
					.update_transfer(
						&mut transfer,
						BridgeTransferStatus::NeedsIntervention(format!(
							"approve phase exceeded {APPROVE_PHASE_TIMEOUT_SECS}s without confirmation; possible underpriced tx"
						)),
					)
					.await?;
				continue;
			}

			// (e) Impossible-state invariant — transfer was created but NEVER had an
			// approve broadcast AND never marked an attempted bridge submit. Both `!`
			// guards are critical: cleared-hash recovery (`approve_was_broadcast == true`)
			// is excluded by the first; the deposit crash window
			// (`bridge_submit_attempted == true`) is excluded by the second (handled by
			// branch (0) above).
			if matches!(transfer.status, BridgeTransferStatus::Submitted)
				&& transfer.tx_hash.is_none()
				&& transfer.approve_tx_hash.is_none()
				&& !transfer.approve_was_broadcast
				&& !transfer.bridge_submit_attempted
				&& now.saturating_sub(transfer.created_at) > 300
			{
				tracing::warn!(
					transfer_id = %transfer.id,
					pair = %transfer.pair_id,
					age_secs = now.saturating_sub(transfer.created_at),
					"Transfer in impossible state; escalating"
				);
				self.bridge_service
					.update_transfer(
						&mut transfer,
						BridgeTransferStatus::NeedsIntervention(
							"approve never broadcast — likely crashed before bridge_asset returned"
								.to_string(),
						),
					)
					.await?;
				continue;
			}

			// (a) Mid-flight approve handling: status Submitted, tx_hash None, and we
			// have an approve hash to re-check. Placed BEFORE the SUBMITTED_TIMEOUT
			// match below so a slow-but-honest approve is not reaped by the 30-min timeout.
			if matches!(transfer.status, BridgeTransferStatus::Submitted)
				&& transfer.tx_hash.is_none()
				&& transfer.approve_tx_hash.is_some()
			{
				let approve_hash_str = transfer.approve_tx_hash.clone().unwrap();
				let approve_hash_bytes =
					match hex::decode(approve_hash_str.trim_start_matches("0x")) {
						Ok(b) if b.len() == 32 => solver_types::TransactionHash(b),
						Ok(b) => {
							// Valid hex but wrong length. Transaction hashes are
							// exactly 32 bytes by definition; anything else is a
							// malformed record. No future tick can heal a persisted
							// bad-length hash, so escalate immediately rather than
							// passing the malformed bytes to the RPC layer where the
							// failure mode is provider-dependent.
							let actual_len = b.len();
							tracing::error!(
								transfer_id = %transfer.id,
								approve_tx_hash = %approve_hash_str,
								actual_byte_len = actual_len,
								"approve_tx_hash decoded but length != 32; escalating to NeedsIntervention"
							);
							self.bridge_service
								.update_transfer(
									&mut transfer,
									BridgeTransferStatus::NeedsIntervention(format!(
										"invalid approve_tx_hash length: got {actual_len} bytes, want 32 (persisted: {approve_hash_str})"
									)),
								)
								.await?;
							continue;
						},
						Err(_) => {
							// A malformed (non-hex / odd-length) hash will fail every
							// future tick — there's no path forward from a parse
							// failure. Escalate so an operator can inspect the
							// persisted record. Without this, the transfer loops
							// silently with the same warn log every tick until restart.
							tracing::error!(
								transfer_id = %transfer.id,
								approve_tx_hash = %approve_hash_str,
								"Invalid approve_tx_hash format; escalating to NeedsIntervention"
							);
							self.bridge_service
								.update_transfer(
									&mut transfer,
									BridgeTransferStatus::NeedsIntervention(format!(
										"invalid approve_tx_hash format ({approve_hash_str}); cannot decode as hex — operator must inspect persisted record"
									)),
								)
								.await?;
							continue;
						},
					};

				match self
					.delivery
					.get_receipt(&approve_hash_bytes, transfer.source_chain)
					.await
				{
					Ok(receipt) if receipt.success => {
						// (b) Approve confirmed. Reset miss counters, run bridge_asset.
						tracing::info!(
							transfer_id = %transfer.id,
							approve_hash = %approve_hash_str,
							"Approve confirmed; resuming bridge_asset for deposit"
						);
						transfer.approve_missing_checks = 0;
						transfer.approve_missing_since = None;
						self.run_bridge_asset_after_approve(
							&mut transfer,
							bridge_impl.as_ref(),
							now,
						)
						.await?;
						continue;
					},
					Ok(_receipt) => {
						// status == false → revert. Mark Failed.
						tracing::warn!(
							transfer_id = %transfer.id,
							"Approve reverted on chain"
						);
						self.bridge_service
							.update_transfer(
								&mut transfer,
								BridgeTransferStatus::Failed(
									"approve reverted on chain".to_string(),
								),
							)
							.await?;
						continue;
					},
					Err(_) => {
						// Receipt not yet available. Check if the tx is on chain at all.
						match self
							.delivery
							.tx_exists(&approve_hash_bytes, transfer.source_chain)
							.await
						{
							Ok(false) => {
								// (c) Stale-hash retry: definitively not on chain.
								transfer.approve_missing_checks += 1;
								if transfer.approve_missing_since.is_none() {
									transfer.approve_missing_since = Some(now);
								}
								if transfer.approve_missing_checks >= 3 {
									tracing::warn!(
										transfer_id = %transfer.id,
										approve_hash = %approve_hash_str,
										"Approve hash remained missing; clearing AND re-running bridge_asset"
									);
									// Clear stale hash. Preserve approve_was_broadcast +
									// approve_submitted_at so absolute cap measures whole phase.
									transfer.approve_tx_hash = None;
									transfer.approve_missing_checks = 0;
									transfer.approve_missing_since = None;
									// Same-tick retry — actually retry, do not just clear.
									self.run_bridge_asset_after_approve(
										&mut transfer,
										bridge_impl.as_ref(),
										now,
									)
									.await?;
									continue;
								}
								// Below threshold — persist counter without refreshing
								// updated_at (the absolute cap is the upper bound; we
								// don't want a periodic refresh to keep an underpriced
								// tx alive forever).
								self.bridge_service
									.storage()
									.save_transfer(&transfer)
									.await?;
								continue;
							},
							_ => {
								// tx_exists returned Ok(true) or Err — still pending in mempool.
								// Do NOT refresh updated_at; the absolute approve-phase cap
								// (rule d) is the authoritative upper bound.
								tracing::debug!(
									transfer_id = %transfer.id,
									"Approve still pending in mempool"
								);
								continue;
							},
						}
					},
				}
			}

			// Timeout checks
			match &transfer.status {
				BridgeTransferStatus::Submitted if age > SUBMITTED_TIMEOUT_SECS => {
					tracing::warn!(
						transfer_id = %transfer.id,
						pair = %transfer.pair_id,
						age_secs = age,
						"Transfer stuck in Submitted, moving to NeedsIntervention"
					);
					self.bridge_service
						.update_transfer(
							&mut transfer,
							BridgeTransferStatus::NeedsIntervention(
								"Submitted tx not confirmed after 30 min".to_string(),
							),
						)
						.await?;
					continue;
				},
				BridgeTransferStatus::Relaying if age > RELAYING_TIMEOUT_SECS => {
					tracing::warn!(
						transfer_id = %transfer.id,
						pair = %transfer.pair_id,
						age_secs = age,
						"Transfer stuck in Relaying, moving to NeedsIntervention"
					);
					self.bridge_service
						.update_transfer(
							&mut transfer,
							BridgeTransferStatus::NeedsIntervention(
								"LayerZero delivery not detected after 30 min".to_string(),
							),
						)
						.await?;
					continue;
				},
				BridgeTransferStatus::PendingRedemption
					if age > PENDING_REDEMPTION_TIMEOUT_SECS =>
				{
					tracing::warn!(
						transfer_id = %transfer.id,
						pair = %transfer.pair_id,
						"Transfer stuck in PendingRedemption, moving to NeedsIntervention"
					);
					self.bridge_service
						.update_transfer(
							&mut transfer,
							BridgeTransferStatus::NeedsIntervention(
								"Vault redemption not completed after 24h".to_string(),
							),
						)
						.await?;
					continue;
				},
				BridgeTransferStatus::PendingRedemption
					if transfer.failure_count >= MAX_REDEEM_RETRIES =>
				{
					let retries = transfer.failure_count;
					tracing::warn!(
						transfer_id = %transfer.id,
						pair = %transfer.pair_id,
						retries,
						"Redeem retry limit exhausted, moving to NeedsIntervention"
					);
					self.bridge_service
						.update_transfer(
							&mut transfer,
							BridgeTransferStatus::NeedsIntervention(format!(
								"Vault redeem failed after {retries} attempts"
							)),
						)
						.await?;
					continue;
				},
				_ => {},
			}

			// Poll bridge implementation for status update.
			// Isolate per-transfer errors so one flaky RPC doesn't block all others.
			let new_status = match bridge_impl.check_status(&transfer).await {
				Ok(status) => status,
				Err(e) => {
					tracing::warn!(
						transfer_id = %transfer.id,
						pair = %transfer.pair_id,
						"check_status failed, skipping transfer this tick: {e}"
					);
					continue;
				},
			};
			// Track submitted-missing checks for dropped tx detection.
			// Only increment when the driver explicitly signals "tx not found" via
			// a Failed status containing source transaction missing/not found. Do NOT
			// increment on normal Submitted→Submitted (tx still pending in mempool).
			if matches!(transfer.status, BridgeTransferStatus::Submitted) {
				match &new_status {
					BridgeTransferStatus::Failed(reason)
						if is_source_transaction_missing(reason) =>
					{
						transfer.submitted_missing_checks += 1;
						if transfer.submitted_missing_since.is_none() {
							transfer.submitted_missing_since = Some(now);
						}
						if transfer.submitted_missing_checks < 3 {
							// Not enough misses yet — stay Submitted, don't apply Failed
							tracing::debug!(
								transfer_id = %transfer.id,
								checks = transfer.submitted_missing_checks,
								"Source tx not found, will recheck"
							);
							// Don't apply the Failed status — let it retry
							transfer.last_status_poll_at = Some(now);
							self.bridge_service
								.storage()
								.save_transfer(&transfer)
								.await?;
							continue;
						}
						// 3+ misses — let the Failed status apply below
					},
					BridgeTransferStatus::Submitted => {
						// Normal pending — don't touch the counter
					},
					_ => {
						// Moving to a new state — reset counters
						transfer.submitted_missing_checks = 0;
						transfer.submitted_missing_since = None;
					},
				}
			}

			// Handle auto-triggered transfers with dropped source txs — fail fast
			if matches!(&transfer.trigger, RebalanceTrigger::Auto)
				&& matches!(&new_status, BridgeTransferStatus::Failed(reason) if is_source_transaction_missing(reason))
			{
				tracing::warn!(
					transfer_id = %transfer.id,
					pair = %transfer.pair_id,
					"Auto-rebalance source tx dropped, failing fast for retry"
				);
				self.bridge_service
					.update_transfer(&mut transfer, new_status)
					.await?;
				continue;
			}

			// Manual transfers with dropped source txs go to NeedsIntervention
			if matches!(&transfer.trigger, RebalanceTrigger::Manual)
				&& matches!(&new_status, BridgeTransferStatus::Failed(reason) if is_source_transaction_missing(reason))
			{
				tracing::warn!(
					transfer_id = %transfer.id,
					pair = %transfer.pair_id,
					"Manual trigger source tx dropped, escalating to NeedsIntervention"
				);
				self.bridge_service
					.update_transfer(
						&mut transfer,
						BridgeTransferStatus::NeedsIntervention(
							"Manual transfer source tx missing from chain".to_string(),
						),
					)
					.await?;
				continue;
			}

			if new_status != transfer.status {
				// Stale-redeem-hash recovery: a stored redeem_tx_hash that the
				// driver reports as "not found" on chain is not a redeem business
				// failure — it's most likely a tx that never propagated or was
				// dropped from the mempool. Track consecutive missing checks; below
				// the threshold, keep the hash and wait. At threshold, clear the
				// hash so the next tick can resubmit via the existing
				// `redeem_tx_hash.is_none()` path. Do NOT increment failure_count
				// for this signal.
				if matches!(&transfer.status, BridgeTransferStatus::PendingRedemption)
					&& matches!(
						&new_status,
						BridgeTransferStatus::Failed(reason)
							if reason.contains("Redeem transaction not found")
					) {
					transfer.redeem_missing_checks += 1;
					if transfer.redeem_missing_since.is_none() {
						transfer.redeem_missing_since = Some(now);
					}

					if transfer.redeem_missing_checks < 3 {
						tracing::debug!(
							transfer_id = %transfer.id,
							checks = transfer.redeem_missing_checks,
							"Redeem tx not found, will recheck before resubmitting"
						);
						transfer.last_status_poll_at = Some(now);
						self.bridge_service
							.storage()
							.save_transfer(&transfer)
							.await?;
						continue;
					}

					tracing::warn!(
						transfer_id = %transfer.id,
						pair = %transfer.pair_id,
						redeem_tx_hash = ?transfer.redeem_tx_hash,
						checks = transfer.redeem_missing_checks,
						"Redeem tx hash remained missing; clearing stale hash for resubmission"
					);
					transfer.redeem_tx_hash = None;
					transfer.redeem_missing_checks = 0;
					transfer.redeem_missing_since = None;
					transfer.last_status_poll_at = Some(now);
					self.bridge_service
						.storage()
						.save_transfer(&transfer)
						.await?;
					continue;
				}

				// Handle PendingRedemption retry: if driver reports Failed for a
				// redeem attempt, don't apply the Failed status — increment
				// failure_count and stay PendingRedemption for retry.
				if matches!(&transfer.status, BridgeTransferStatus::PendingRedemption)
					&& matches!(&new_status, BridgeTransferStatus::Failed(_))
				{
					transfer.failure_count += 1;
					tracing::warn!(
						transfer_id = %transfer.id,
						pair = %transfer.pair_id,
						failure_count = transfer.failure_count,
						"Redeem attempt failed, will retry"
					);
					transfer.redeem_tx_hash = None;
				} else {
					tracing::info!(
						transfer_id = %transfer.id,
						pair = %transfer.pair_id,
						old_status = ?transfer.status,
						new_status = ?new_status,
						"Transfer status changed"
					);

					// Record destination scan anchor when entering Relaying
					if matches!(new_status, BridgeTransferStatus::Relaying)
						&& transfer.dest_scan_from_block.is_none()
					{
						if let Ok(block) = self.delivery.get_block_number(transfer.dest_chain).await
						{
							transfer.dest_scan_from_block = Some(block);
						}
					}

					// Set cooldown when source tx confirms (Submitted → Relaying)
					if matches!(&transfer.status, BridgeTransferStatus::Submitted)
						&& matches!(new_status, BridgeTransferStatus::Relaying)
					{
						self.bridge_service
							.set_cooldown(&transfer.pair_id, config.cooldown_seconds)
							.await?;
					}

					// Reset redeem-missing counters when leaving PendingRedemption
					// successfully (e.g. → Completed). Without this, stale counter
					// values from a previous miss streak would carry over.
					if matches!(&transfer.status, BridgeTransferStatus::PendingRedemption)
						&& !matches!(&new_status, BridgeTransferStatus::PendingRedemption)
					{
						transfer.redeem_missing_checks = 0;
						transfer.redeem_missing_since = None;
					}

					self.bridge_service
						.update_transfer(&mut transfer, new_status)
						.await?;
				}
			}

			// Retry dest_scan_from_block if it was never set (transient RPC failure on transition)
			if matches!(transfer.status, BridgeTransferStatus::Relaying)
				&& transfer.dest_scan_from_block.is_none()
			{
				if let Ok(block) = self.delivery.get_block_number(transfer.dest_chain).await {
					transfer.dest_scan_from_block = Some(block);
					tracing::info!(
						transfer_id = %transfer.id,
						block,
						"Destination scan anchor seeded on retry"
					);
				}
			}

			// Delivery detection: scan destination chain for Transfer events.
			// For composer flows (ETH→Katana): shares arrive at dest_token (vbUSDC on Katana).
			// For non-composer flows (Katana→ETH): shares arrive at the vault contract on
			// Ethereum (vault share token emits ERC-20 Transfer), NOT at the OFT Adapter
			// (which emits OFTReceived, not Transfer) and NOT at the final USDC token.
			let scan_address = if transfer.is_composer_flow == Some(true) {
				transfer.dest_token_address.as_ref()
			} else {
				// Non-composer: vault share token emits Transfer when shares are unlocked
				transfer
					.vault_address
					.as_ref()
					.or(transfer.dest_token_address.as_ref())
			};

			if matches!(transfer.status, BridgeTransferStatus::Relaying)
				&& transfer.dest_scan_from_block.is_some()
				&& scan_address.is_some()
			{
				let dest_token_addr = scan_address.unwrap();
				let dest_token_hex = dest_token_addr
					.strip_prefix("0x")
					.unwrap_or(dest_token_addr);

				if let Ok(addr_bytes) = hex::decode(dest_token_hex) {
					// Transfer event topic0 = keccak256("Transfer(address,address,uint256)")
					let transfer_sig: [u8; 32] =
						alloy_primitives::keccak256(b"Transfer(address,address,uint256)").0;

					// topic2 = solver address (left-padded to 32 bytes)
					let solver_hex = self
						.solver_address
						.strip_prefix("0x")
						.unwrap_or(&self.solver_address);
					let mut solver_topic = [0u8; 32];
					if let Ok(solver_bytes) = hex::decode(solver_hex) {
						let start = 32 - solver_bytes.len().min(32);
						solver_topic[start..]
							.copy_from_slice(&solver_bytes[..solver_bytes.len().min(32)]);
					}

					let filter = solver_types::LogFilter::new(
						solver_types::Address(addr_bytes),
						transfer
							.last_scanned_dest_block
							.unwrap_or(transfer.dest_scan_from_block.unwrap()),
						None,
						vec![
							Some(solver_types::H256(transfer_sig)),
							None,                                   // topic1: from (any)
							Some(solver_types::H256(solver_topic)), // topic2: to = solver
						],
					);

					match self.delivery.get_logs(transfer.dest_chain, filter).await {
						Ok(logs) => {
							let expected =
								U256::from_str_radix(&transfer.amount, 10).unwrap_or(U256::ZERO);
							let min_expected = expected * U256::from(95) / U256::from(100);
							let max_expected = expected * U256::from(105) / U256::from(100);

							let matched = logs.iter().find(|log| {
								if log.data.len() < 32 {
									return false;
								}
								let value = U256::from_be_slice(&log.data[..32]);
								value >= min_expected && value <= max_expected
							});

							if let Some(matched_log) = matched {
								// Store actual received shares from the Transfer event
								let received = U256::from_be_slice(&matched_log.data[..32]);
								transfer.received_shares = Some(received.to_string());

								tracing::info!(
									transfer_id = %transfer.id,
									received_shares = %received,
									"Delivery detected on destination chain"
								);
								let new_status = if transfer.is_composer_flow == Some(true) {
									BridgeTransferStatus::Completed
								} else {
									BridgeTransferStatus::PendingRedemption
								};
								self.bridge_service
									.update_transfer(&mut transfer, new_status)
									.await?;
							} else if let Ok(head) =
								self.delivery.get_block_number(transfer.dest_chain).await
							{
								transfer.last_scanned_dest_block = Some(head);
							}
						},
						Err(e) => {
							tracing::debug!(
								transfer_id = %transfer.id,
								"Log scan failed: {e}"
							);
						},
					}
				}
			}

			// Redeem submission: for PendingRedemption without a redeem tx, submit vault redeem
			if matches!(transfer.status, BridgeTransferStatus::PendingRedemption)
				&& transfer.redeem_tx_hash.is_none()
				&& transfer.vault_address.is_some()
			{
				let vault_addr_str = transfer.vault_address.as_ref().unwrap();
				if let Ok(vault_addr) = Self::parse_address(vault_addr_str) {
					let solver_addr = match Self::parse_address(&self.solver_address) {
						Ok(a) => a,
						Err(_) => {
							tracing::warn!(
								transfer_id = %transfer.id,
								"Invalid solver address for redeem"
							);
							continue;
						},
					};

					// Use the actual received shares from the Transfer event, not the bridged amount.
					// After slippage/fees, the received shares may differ from transfer.amount.
					let shares = match &transfer.received_shares {
						Some(s) => match U256::from_str_radix(s, 10) {
							Ok(v) if !v.is_zero() => v,
							Ok(_) => {
								tracing::warn!(transfer_id = %transfer.id, "Received shares is zero");
								continue;
							},
							Err(e) => {
								tracing::warn!(transfer_id = %transfer.id, "Invalid received_shares: {e}");
								continue;
							},
						},
						None => {
							tracing::debug!(
								transfer_id = %transfer.id,
								"No received_shares yet, waiting for delivery scan"
							);
							continue;
						},
					};
					{
						use alloy_sol_types::SolCall;
						let redeem_data =
							crate::implementations::layerzero::contracts::redeemCall {
								shares,
								receiver: solver_addr,
								owner: solver_addr,
							}
							.abi_encode();

						let redeem_tx = solver_types::Transaction {
							to: Some(solver_types::Address(vault_addr.as_slice().to_vec())),
							data: redeem_data,
							value: U256::ZERO,
							chain_id: transfer.dest_chain,
							nonce: None,
							gas_limit: None,
							gas_price: None,
							max_fee_per_gas: None,
							max_priority_fee_per_gas: None,
						};

						// Acquire semaphore just before submitting — don't hold it during
						// the preceding calldata building.
						let _permit = self.transaction_semaphore.acquire().await.map_err(|e| {
							crate::BridgeError::TransactionFailed(format!(
								"Failed to acquire semaphore for redeem: {e}"
							))
						})?;

						match self.delivery.deliver(redeem_tx, None).await {
							Ok(tx_hash) => {
								transfer.redeem_tx_hash =
									Some(format!("0x{}", hex::encode(&tx_hash.0)));
								tracing::info!(
									transfer_id = %transfer.id,
									"Vault redeem submitted"
								);
							},
							// Residual nonce drift after the delivery layer's resync retry.
							// This is transient — the next monitor tick will retry once the
							// nonce manager has caught up. Do NOT count it as a redeem
							// business failure; leaving failure_count untouched keeps the
							// transfer in PendingRedemption instead of escalating to
							// NeedsIntervention.
							Err(solver_delivery::DeliveryError::NonceTooLow(reason)) => {
								tracing::warn!(
									transfer_id = %transfer.id,
									reason = %reason,
									"Redeem submission hit residual nonce-drift after resync; will retry next tick"
								);
							},
							Err(e) => {
								transfer.failure_count += 1;
								tracing::warn!(
									transfer_id = %transfer.id,
									failure_count = transfer.failure_count,
									"Redeem submission failed: {e}"
								);
							},
						}
					}
				}
			}

			// Persist last_status_poll_at
			transfer.last_status_poll_at = Some(now);
			self.bridge_service
				.storage()
				.save_transfer(&transfer)
				.await?;
		}

		Ok(())
	}

	/// Check balances against thresholds and auto-trigger rebalances.
	async fn check_thresholds_and_trigger(
		&self,
		config: &RebalanceConfig,
	) -> Result<(), crate::BridgeError> {
		let active_count = self.bridge_service.active_transfer_count().await?;
		if active_count >= config.max_pending_transfers as usize {
			tracing::debug!(
				active = active_count,
				max = config.max_pending_transfers,
				"Max pending transfers reached, skipping threshold check"
			);
			return Ok(());
		}

		let solver_address = &self.solver_address;

		for pair in &config.pairs {
			if self
				.bridge_service
				.is_cooldown_active(&pair.pair_id)
				.await?
			{
				tracing::debug!(pair = %pair.pair_id, "Cooldown active, skipping");
				continue;
			}

			let pair_transfers = self
				.bridge_service
				.get_active_transfers_for_pair(&pair.pair_id)
				.await?;
			if !pair_transfers.is_empty() {
				continue;
			}

			// Query balances
			let balance_a = self
				.delivery
				.get_balance(
					pair.chain_a.chain_id,
					solver_address,
					Some(&pair.chain_a.token_address),
				)
				.await;
			let balance_b = self
				.delivery
				.get_balance(
					pair.chain_b.chain_id,
					solver_address,
					Some(&pair.chain_b.token_address),
				)
				.await;

			let (balance_a, balance_b) = match (balance_a, balance_b) {
				(Ok(a), Ok(b)) => {
					let a = match U256::from_str_radix(&a, 10) {
						Ok(v) => v,
						Err(e) => {
							tracing::warn!(pair = %pair.pair_id, "Failed to parse balance_a '{a}': {e}");
							continue;
						},
					};
					let b = match U256::from_str_radix(&b, 10) {
						Ok(v) => v,
						Err(e) => {
							tracing::warn!(pair = %pair.pair_id, "Failed to parse balance_b '{b}': {e}");
							continue;
						},
					};
					(a, b)
				},
				(Err(e), _) | (_, Err(e)) => {
					tracing::warn!(pair = %pair.pair_id, "Failed to query balance: {e}");
					continue;
				},
			};

			// Parse config values with proper error handling
			let target_a = U256::from_str_radix(&pair.target_balance_a, 10).map_err(|e| {
				crate::BridgeError::Config(format!(
					"Pair '{}': invalid target_balance_a: {e}",
					pair.pair_id
				))
			})?;
			let target_b = U256::from_str_radix(&pair.target_balance_b, 10).map_err(|e| {
				crate::BridgeError::Config(format!(
					"Pair '{}': invalid target_balance_b: {e}",
					pair.pair_id
				))
			})?;
			let max_amount = U256::from_str_radix(&pair.max_bridge_amount, 10).map_err(|e| {
				crate::BridgeError::Config(format!(
					"Pair '{}': invalid max_bridge_amount: {e}",
					pair.pair_id
				))
			})?;

			let analysis = analyze_pair(
				balance_a,
				balance_b,
				target_a,
				target_b,
				pair.deviation_band_bps,
				max_amount,
			);

			if analysis.both_sides_low {
				tracing::warn!(
					pair = %pair.pair_id,
					balance_a = %balance_a,
					balance_b = %balance_b,
					"Both sides below lower bound, cannot rebalance"
				);
				continue;
			}

			if let Some(direction) = &analysis.direction_needed {
				if analysis.suggested_amount.is_zero() {
					continue;
				}

				// Direction-aware side mapping
				let (source_side, dest_side) = match direction {
					RebalanceDirection::AToB => (&pair.chain_a, &pair.chain_b),
					RebalanceDirection::BToA => (&pair.chain_b, &pair.chain_a),
				};

				let source_token = Self::parse_address(&source_side.token_address)?;
				let source_oft = Self::parse_address(&source_side.oft_address)?;
				let dest_token = Self::parse_address(&dest_side.token_address)?;
				let dest_oft = Self::parse_address(&dest_side.oft_address)?;
				let recipient = Self::parse_address(solver_address)?;

				let request = BridgeRequest {
					pair_id: pair.pair_id.clone(),
					source_chain: source_side.chain_id,
					dest_chain: dest_side.chain_id,
					source_token,
					source_oft,
					dest_token,
					dest_oft,
					amount: analysis.suggested_amount,
					min_amount: None,
					recipient,
				};

				tracing::info!(
					pair = %pair.pair_id,
					direction = ?direction,
					source = source_side.chain_id,
					dest = dest_side.chain_id,
					amount = %analysis.suggested_amount,
					"Auto-triggering rebalance"
				);

				let _permit = self.transaction_semaphore.acquire().await.map_err(|e| {
					crate::BridgeError::TransactionFailed(format!(
						"Failed to acquire semaphore: {e}"
					))
				})?;

				// Build metadata for delivery detection and redeem path
				let is_composer = config
					.bridge_config
					.as_ref()
					.and_then(|bc| bc.get("composer_addresses"))
					.and_then(|ca| ca.get(source_side.chain_id.to_string()))
					.is_some();
				let vault_addr = config
					.bridge_config
					.as_ref()
					.and_then(|bc| bc.get("vault_addresses"))
					.and_then(|va| va.get(dest_side.chain_id.to_string()))
					.and_then(|v| v.as_str())
					.map(|s| s.to_string());

				if !is_composer && vault_addr.is_none() {
					tracing::warn!(
						pair = %pair.pair_id,
						dest_chain = dest_side.chain_id,
						"Skipping auto-rebalance: missing vault address for non-composer flow"
					);
					continue;
				}

				let metadata = crate::types::TransferMetadata {
					dest_token_address: dest_side.token_address.clone(),
					dest_oft_address: dest_side.oft_address.clone(),
					is_composer_flow: is_composer,
					vault_address: vault_addr,
				};

				match self
					.bridge_service
					.rebalance_token(
						&config.implementation,
						&request,
						RebalanceTrigger::Auto,
						metadata,
					)
					.await
				{
					Ok(transfer) => {
						tracing::info!(
							transfer_id = %transfer.id,
							pair = %pair.pair_id,
							"Auto-rebalance initiated"
						);
						// Cooldown is set after source tx confirms (Submitted → Relaying),
						// not on initiation. This allows fast retry if the source tx is dropped.
					},
					Err(e) => {
						tracing::error!(pair = %pair.pair_id, "Auto-rebalance failed: {e}");
					},
				}
			}
		}

		Ok(())
	}

	fn parse_address(addr: &str) -> Result<Address, crate::BridgeError> {
		let hex_str = addr.strip_prefix("0x").unwrap_or(addr);
		let bytes = hex::decode(hex_str)
			.map_err(|e| crate::BridgeError::Config(format!("Invalid address: {e}")))?;
		let arr: [u8; 20] = bytes
			.try_into()
			.map_err(|_| crate::BridgeError::Config("Address must be 20 bytes".to_string()))?;
		Ok(Address::from(arr))
	}

	/// Reconstruct a `BridgeRequest` from a transfer's persisted fields.
	/// Used by the resume-after-approve path so the monitor can re-run
	/// `bridge_asset` with the same shape as the original submission, even
	/// across solver restarts and config changes.
	fn reconstruct_bridge_request(
		transfer: &crate::types::PendingBridgeTransfer,
	) -> Result<crate::types::BridgeRequest, String> {
		let source_token_str = transfer
			.source_token_address
			.as_deref()
			.ok_or("missing source_token_address (pre-Task-1 transfer?)")?;
		let source_oft_str = transfer
			.source_oft_address
			.as_deref()
			.ok_or("missing source_oft_address")?;
		let dest_token_str = transfer
			.dest_token_address
			.as_deref()
			.ok_or("missing dest_token_address")?;
		let dest_oft_str = transfer
			.dest_oft_address
			.as_deref()
			.ok_or("missing dest_oft_address")?;
		let recipient_str = transfer
			.recipient_address
			.as_deref()
			.ok_or("missing recipient_address")?;

		let source_token = Self::parse_address(source_token_str).map_err(|e| e.to_string())?;
		let source_oft = Self::parse_address(source_oft_str).map_err(|e| e.to_string())?;
		let dest_token = Self::parse_address(dest_token_str).map_err(|e| e.to_string())?;
		let dest_oft = Self::parse_address(dest_oft_str).map_err(|e| e.to_string())?;
		let recipient = Self::parse_address(recipient_str).map_err(|e| e.to_string())?;

		let amount = U256::from_str_radix(&transfer.amount, 10)
			.map_err(|e| format!("invalid amount: {e}"))?;
		let min_amount = transfer
			.min_amount
			.as_deref()
			.map(|s| U256::from_str_radix(s, 10))
			.transpose()
			.map_err(|e| format!("invalid min_amount: {e}"))?;

		Ok(crate::types::BridgeRequest {
			pair_id: transfer.pair_id.clone(),
			source_chain: transfer.source_chain,
			dest_chain: transfer.dest_chain,
			source_token,
			source_oft,
			dest_token,
			dest_oft,
			amount,
			min_amount,
			recipient,
		})
	}

	/// Reconstruct a `BridgeRequest` from a transfer's persisted fields and
	/// call `bridge.bridge_asset`. Mirrors `rebalance_token`'s error handling
	/// so the confirmed-approve resume path AND the stale-hash retry path
	/// share one canonical implementation.
	async fn run_bridge_asset_after_approve(
		&self,
		transfer: &mut crate::types::PendingBridgeTransfer,
		bridge_impl: &dyn crate::BridgeInterface,
		now: u64,
	) -> Result<(), crate::BridgeError> {
		let request = match Self::reconstruct_bridge_request(transfer) {
			Ok(r) => r,
			Err(reason) => {
				tracing::error!(
					transfer_id = %transfer.id,
					reason = %reason,
					"BridgeRequest reconstruction failed; escalating"
				);
				self.bridge_service
					.update_transfer(
						transfer,
						crate::types::BridgeTransferStatus::NeedsIntervention(format!(
							"Cannot resume bridge: {reason}"
						)),
					)
					.await?;
				return Ok(());
			},
		};

		// CRASH-WINDOW GUARD: persist marker BEFORE the bridge_asset call.
		transfer.bridge_submit_attempted = true;
		self.bridge_service
			.storage()
			.save_transfer(transfer)
			.await?;

		// Intentional: the permit is held across the entire `bridge_asset`
		// call, which internally broadcasts the deposit *and* polls for
		// receipt confirmation (~12 × 5 s = 60 s worst case). The redeem path
		// at line ~829 uses a narrower acquire+broadcast pattern because
		// `delivery.deliver()` returns immediately after submit; bridge
		// implementations bundle submit+confirm in `bridge_asset`, so without
		// a trait-level split we can't narrow without breaking the API
		// contract. Serializing here is acceptable: the resume path is rare
		// (only after an approve completes), and the alternative — letting
		// concurrent submissions race during confirmation — risks nonce
		// collisions on the same signer. Tracked as follow-up: split
		// `bridge_asset` into `bridge_submit` + `bridge_confirm` so this
		// site can acquire only around `bridge_submit`.
		let _permit = self.transaction_semaphore.acquire().await.map_err(|e| {
			crate::BridgeError::TransactionFailed(format!(
				"Failed to acquire semaphore for bridge resume: {e}"
			))
		})?;

		match bridge_impl.bridge_asset(&request).await {
			Ok(result) => {
				transfer.tx_hash = Some(result.tx_hash);
				transfer.message_guid = result.message_guid;
				transfer.updated_at = now;
				self.bridge_service
					.storage()
					.save_transfer(transfer)
					.await?;
				Ok(())
			},
			Err(crate::BridgeError::ApprovePending { tx_hash }) => {
				// Allowance still insufficient — implementation re-broadcast approve.
				// No deposit was attempted. Roll back the marker.
				// Preserve approve_was_broadcast and approve_submitted_at so the
				// absolute cap continues measuring the same approve phase.
				transfer.bridge_submit_attempted = false; // ROLLBACK
				transfer.approve_tx_hash = Some(tx_hash);
				transfer.updated_at = now;
				self.bridge_service
					.storage()
					.save_transfer(transfer)
					.await?;
				Ok(())
			},
			Err(crate::BridgeError::ApproveReverted { tx_hash, error }) => {
				// Approve reverted on resume — no deposit. Roll back marker.
				transfer.bridge_submit_attempted = false; // ROLLBACK
				transfer.approve_tx_hash = Some(tx_hash.clone());
				self.bridge_service
					.update_transfer(
						transfer,
						crate::types::BridgeTransferStatus::Failed(format!(
							"approve reverted on resume (tx {tx_hash}): {error}"
						)),
					)
					.await?;
				Ok(())
			},
			Err(crate::BridgeError::ApproveSubmitFailed { error }) => {
				transfer.bridge_submit_attempted = false; // ROLLBACK
				self.bridge_service
					.update_transfer(
						transfer,
						crate::types::BridgeTransferStatus::Failed(format!(
							"approve failed before deposit attempt: {error}"
						)),
					)
					.await?;
				Ok(())
			},
			Err(crate::BridgeError::InsufficientNativeGas(reason)) => {
				// Pre-broadcast failure: no deposit/source tx was submitted.
				// Keep the pair locked in NeedsIntervention with a clear operator
				// reason, but do not abort the whole monitor tick.
				transfer.bridge_submit_attempted = false;
				self.bridge_service
					.update_transfer(
						transfer,
						crate::types::BridgeTransferStatus::NeedsIntervention(reason),
					)
					.await?;
				Ok(())
			},
			Err(e) => {
				// Generic error — we don't know if deposit broadcast or not.
				// KEEP marker set so branch (0) catches this on next tick.
				tracing::warn!(
					transfer_id = %transfer.id,
					error = %e,
					"bridge_asset failed on resume; marker stays set, next tick will escalate"
				);
				self.bridge_service
					.storage()
					.save_transfer(transfer)
					.await?;
				Ok(())
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::test_support::{pending_transfer, rebalance_config};
	use crate::{BridgeDepositResult, BridgeInterface};
	use async_trait::async_trait;
	use solver_config::ConfigBuilder;
	use solver_delivery::{DeliveryError, DeliveryService, MockDeliveryInterface};
	use solver_storage::implementations::file::{FileStorage, TtlConfig};
	use solver_storage::StorageService;
	use solver_types::{
		Address as DeliveryAddress, Log, LogFilter, Transaction, TransactionHash,
		TransactionReceipt, H256,
	};
	use std::collections::{HashMap, VecDeque};
	use std::fs;
	use std::sync::{Arc, Mutex};
	use tokio::sync::{RwLock, Semaphore};
	use uuid::Uuid;

	const SOLVER_ADDRESS: &str = "0x5555555555555555555555555555555555555555";

	#[derive(Default)]
	struct StubBridge {
		bridge_asset_results: Mutex<VecDeque<Result<BridgeDepositResult, crate::BridgeError>>>,
		check_status_results: Mutex<VecDeque<Result<BridgeTransferStatus, crate::BridgeError>>>,
		recorded_requests: Arc<Mutex<Vec<crate::types::BridgeRequest>>>,
	}

	#[async_trait]
	impl BridgeInterface for StubBridge {
		fn supported_routes(&self) -> Vec<(u64, u64)> {
			vec![(1, 747474), (747474, 1)]
		}

		async fn bridge_asset(
			&self,
			request: &crate::types::BridgeRequest,
		) -> Result<BridgeDepositResult, crate::BridgeError> {
			self.recorded_requests.lock().unwrap().push(request.clone());
			self.bridge_asset_results
				.lock()
				.unwrap()
				.pop_front()
				.unwrap_or_else(|| {
					Ok(BridgeDepositResult {
						tx_hash: "0xfeedbeef".to_string(),
						message_guid: None,
						estimated_arrival: None,
					})
				})
		}

		async fn check_status(
			&self,
			transfer: &crate::types::PendingBridgeTransfer,
		) -> Result<BridgeTransferStatus, crate::BridgeError> {
			self.check_status_results
				.lock()
				.unwrap()
				.pop_front()
				.unwrap_or_else(|| Ok(transfer.status.clone()))
		}

		async fn estimate_fee(
			&self,
			_request: &crate::types::BridgeRequest,
		) -> Result<U256, crate::BridgeError> {
			Ok(U256::ZERO)
		}
	}

	fn make_storage() -> Arc<StorageService> {
		let base_path =
			std::env::temp_dir().join(format!("solver-monitor-test-{}", Uuid::new_v4()));
		fs::create_dir_all(&base_path).unwrap();
		Arc::new(StorageService::new(Box::new(FileStorage::new(
			base_path,
			TtlConfig::default(),
		))))
	}

	fn make_delivery(mock: MockDeliveryInterface) -> Arc<DeliveryService> {
		let shared = Arc::new(mock);
		Arc::new(DeliveryService::new(
			HashMap::from([
				(
					1_u64,
					shared.clone() as Arc<dyn solver_delivery::DeliveryInterface>,
				),
				(
					747474_u64,
					shared as Arc<dyn solver_delivery::DeliveryInterface>,
				),
			]),
			3,
			300,
			60,
		))
	}

	fn make_monitor(
		bridge: Arc<dyn BridgeInterface>,
		delivery: Arc<DeliveryService>,
		storage: Arc<StorageService>,
		rebalance: solver_config::RebalanceConfig,
	) -> (Arc<crate::BridgeService>, RebalanceMonitor) {
		let bridge_service = Arc::new(crate::BridgeService::new(
			HashMap::from([("mock-bridge".to_string(), bridge)]),
			storage.clone(),
			"solver-a".to_string(),
		));
		let mut config = ConfigBuilder::new()
			.solver_id("solver-a".to_string())
			.build();
		config.rebalance = Some(rebalance);
		let monitor = RebalanceMonitor::new(
			bridge_service.clone(),
			delivery,
			Arc::new(RwLock::new(config)),
			storage,
			Arc::new(Semaphore::new(1)),
			SOLVER_ADDRESS.to_string(),
			Arc::new(RwLock::new(RebalanceMonitorStatus::default())),
		);
		(bridge_service, monitor)
	}

	fn transfer_event_signature() -> [u8; 32] {
		alloy_primitives::keccak256(b"Transfer(address,address,uint256)").0
	}

	fn topic_for_address(addr: &str) -> H256 {
		let bytes = hex::decode(addr.strip_prefix("0x").unwrap_or(addr)).unwrap();
		let mut topic = [0u8; 32];
		topic[12..].copy_from_slice(&bytes);
		H256(topic)
	}

	fn delivery_address(hex_addr: &str) -> DeliveryAddress {
		DeliveryAddress(hex::decode(hex_addr.strip_prefix("0x").unwrap_or(hex_addr)).unwrap())
	}

	fn amount_data(amount: U256) -> Vec<u8> {
		let mut buf = [0u8; 32];
		amount
			.to_be_bytes::<32>()
			.iter()
			.enumerate()
			.for_each(|(i, b)| {
				buf[i] = *b;
			});
		buf.to_vec()
	}

	fn transfer_log(token: &str, from: &str, to: &str, amount: U256) -> Log {
		Log {
			address: delivery_address(token),
			topics: vec![
				H256(transfer_event_signature()),
				topic_for_address(from),
				topic_for_address(to),
			],
			data: amount_data(amount),
		}
	}

	fn current_timestamp() -> u64 {
		std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap()
			.as_secs()
	}

	fn fresh_transfer(status: BridgeTransferStatus) -> crate::types::PendingBridgeTransfer {
		let mut transfer = pending_transfer(status);
		let now = current_timestamp();
		transfer.created_at = now;
		transfer.updated_at = now;
		transfer
	}

	#[tokio::test]
	async fn test_submitted_timeout_moves_to_needs_intervention() {
		let storage = make_storage();
		let delivery = make_delivery(MockDeliveryInterface::new());
		let bridge = Arc::new(StubBridge::default()) as Arc<dyn BridgeInterface>;
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance_config());

		let mut transfer = pending_transfer(BridgeTransferStatus::Submitted);
		// Deposit was broadcast (tx_hash present) but never advanced past Submitted.
		// This isolates the SUBMITTED_TIMEOUT branch from the new impossible-state /
		// mid-flight-approve / crash-window branches (which all require tx_hash.is_none()).
		transfer.tx_hash =
			Some("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string());
		transfer.updated_at = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap()
			.as_secs()
			- SUBMITTED_TIMEOUT_SECS
			- 1;
		bridge_service
			.storage()
			.save_transfer(&transfer)
			.await
			.unwrap();

		monitor
			.advance_pending_transfers(&rebalance_config())
			.await
			.unwrap();

		let stored = bridge_service.get_transfer(&transfer.id).await.unwrap();
		assert!(matches!(
			stored.status,
			BridgeTransferStatus::NeedsIntervention(ref reason)
				if reason.contains("Submitted tx not confirmed")
		));
		assert_eq!(
			stored.status_before_intervention,
			Some(BridgeTransferStatus::Submitted)
		);
	}

	#[tokio::test]
	async fn test_pending_redemption_failed_receipt_increments_failure_count_and_stays_pending() {
		let storage = make_storage();
		let delivery = make_delivery(MockDeliveryInterface::new());
		let bridge = Arc::new(StubBridge {
			check_status_results: Mutex::new(VecDeque::from([Ok(BridgeTransferStatus::Failed(
				"Redeem transaction reverted".to_string(),
			))])),
			..Default::default()
		}) as Arc<dyn BridgeInterface>;
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance_config());

		let transfer = fresh_transfer(BridgeTransferStatus::PendingRedemption);
		bridge_service
			.storage()
			.save_transfer(&transfer)
			.await
			.unwrap();

		monitor
			.advance_pending_transfers(&rebalance_config())
			.await
			.unwrap();

		let stored = bridge_service.get_transfer(&transfer.id).await.unwrap();
		assert!(matches!(
			stored.status,
			BridgeTransferStatus::PendingRedemption
		));
		assert_eq!(stored.failure_count, 1);
		assert!(stored.redeem_tx_hash.is_none());
	}

	#[tokio::test]
	async fn test_manual_source_tx_not_found_escalates_to_needs_intervention_after_threshold() {
		let storage = make_storage();
		let delivery = make_delivery(MockDeliveryInterface::new());
		let bridge = Arc::new(StubBridge {
			check_status_results: Mutex::new(VecDeque::from([Ok(BridgeTransferStatus::Failed(
				"Source transaction not found".to_string(),
			))])),
			..Default::default()
		}) as Arc<dyn BridgeInterface>;
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance_config());

		let mut transfer = fresh_transfer(BridgeTransferStatus::Submitted);
		transfer.trigger = RebalanceTrigger::Manual;
		transfer.tx_hash =
			Some("0xabababababababababababababababababababababababababababababababab".to_string());
		transfer.submitted_missing_checks = 2;
		bridge_service
			.storage()
			.save_transfer(&transfer)
			.await
			.unwrap();

		monitor
			.advance_pending_transfers(&rebalance_config())
			.await
			.unwrap();

		let stored = bridge_service.get_transfer(&transfer.id).await.unwrap();
		assert!(
			matches!(
				&stored.status,
				BridgeTransferStatus::NeedsIntervention(reason)
					if reason.contains("Manual transfer source tx missing")
			),
			"unexpected status: {:?}",
			stored.status
		);
	}

	#[tokio::test]
	async fn test_relaying_detects_delivery_only_when_amount_within_bounds() {
		let storage = make_storage();
		let expected_token = "0x3333333333333333333333333333333333333333".to_string();
		let expected_token_for_logs = expected_token.clone();
		let mut mock = MockDeliveryInterface::new();
		mock.expect_get_logs()
			.times(1)
			.returning(move |_chain_id, filter: LogFilter| {
				assert_eq!(filter.address, delivery_address(&expected_token_for_logs));
				assert_eq!(filter.topics().len(), 3);
				assert_eq!(filter.topics()[0], Some(H256(transfer_event_signature())));
				assert_eq!(filter.topics()[2], Some(topic_for_address(SOLVER_ADDRESS)));
				let low = transfer_log(
					&expected_token_for_logs,
					"0x1111111111111111111111111111111111111111",
					SOLVER_ADDRESS,
					U256::from(949_999u64),
				);
				let ok = transfer_log(
					&expected_token_for_logs,
					"0x1111111111111111111111111111111111111111",
					SOLVER_ADDRESS,
					U256::from(1_000_000u64),
				);
				Box::pin(async move { Ok(vec![low, ok]) })
			});
		let delivery = make_delivery(mock);
		let bridge = Arc::new(StubBridge::default()) as Arc<dyn BridgeInterface>;
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance_config());

		let mut transfer = fresh_transfer(BridgeTransferStatus::Relaying);
		transfer.dest_scan_from_block = Some(100);
		transfer.dest_token_address = Some(expected_token.clone());
		transfer.is_composer_flow = Some(false);
		bridge_service
			.storage()
			.save_transfer(&transfer)
			.await
			.unwrap();

		monitor
			.advance_pending_transfers(&rebalance_config())
			.await
			.unwrap();

		let stored = bridge_service.get_transfer(&transfer.id).await.unwrap();
		assert!(matches!(
			stored.status,
			BridgeTransferStatus::PendingRedemption
		));
		assert_eq!(stored.received_shares.as_deref(), Some("1000000"));
	}

	#[tokio::test]
	async fn test_relaying_ignores_transfer_above_max_tolerance() {
		let storage = make_storage();
		let expected_token = "0x3333333333333333333333333333333333333333".to_string();
		let expected_token_for_logs = expected_token.clone();
		let mut mock = MockDeliveryInterface::new();
		mock.expect_get_logs()
			.times(1)
			.returning(move |_chain_id, _filter| {
				let high = transfer_log(
					&expected_token_for_logs,
					"0x1111111111111111111111111111111111111111",
					SOLVER_ADDRESS,
					U256::from(1_100_000u64),
				);
				Box::pin(async move { Ok(vec![high]) })
			});
		mock.expect_get_block_number()
			.times(1)
			.returning(|_| Box::pin(async move { Ok(150) }));
		let delivery = make_delivery(mock);
		let bridge = Arc::new(StubBridge::default()) as Arc<dyn BridgeInterface>;
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance_config());

		let mut transfer = fresh_transfer(BridgeTransferStatus::Relaying);
		transfer.dest_scan_from_block = Some(100);
		transfer.dest_token_address = Some(expected_token);
		transfer.is_composer_flow = Some(false);
		bridge_service
			.storage()
			.save_transfer(&transfer)
			.await
			.unwrap();

		monitor
			.advance_pending_transfers(&rebalance_config())
			.await
			.unwrap();

		let stored = bridge_service.get_transfer(&transfer.id).await.unwrap();
		assert!(matches!(stored.status, BridgeTransferStatus::Relaying));
		assert_eq!(stored.last_scanned_dest_block, Some(150));
		assert!(stored.received_shares.is_none());
	}

	#[tokio::test]
	async fn test_composer_flow_completes_while_oft_flow_enters_pending_redemption() {
		let expected_token = "0x3333333333333333333333333333333333333333".to_string();
		let amount = U256::from(1_000_000u64);

		for (is_composer, expected_status) in [
			(true, BridgeTransferStatus::Completed),
			(false, BridgeTransferStatus::PendingRedemption),
		] {
			let storage = make_storage();
			let mut mock = MockDeliveryInterface::new();
			let expected_token_inner = expected_token.clone();
			mock.expect_get_logs()
				.times(1)
				.returning(move |_chain_id, _filter| {
					let log = transfer_log(
						&expected_token_inner,
						"0x1111111111111111111111111111111111111111",
						SOLVER_ADDRESS,
						amount,
					);
					Box::pin(async move { Ok(vec![log]) })
				});
			let delivery = make_delivery(mock);
			let bridge = Arc::new(StubBridge::default()) as Arc<dyn BridgeInterface>;
			let (bridge_service, monitor) =
				make_monitor(bridge, delivery, storage, rebalance_config());

			let mut transfer = fresh_transfer(BridgeTransferStatus::Relaying);
			transfer.id = format!("flow-{is_composer}");
			transfer.dest_scan_from_block = Some(100);
			transfer.dest_token_address = Some(expected_token.clone());
			transfer.is_composer_flow = Some(is_composer);
			bridge_service
				.storage()
				.save_transfer(&transfer)
				.await
				.unwrap();

			monitor
				.advance_pending_transfers(&rebalance_config())
				.await
				.unwrap();

			let stored = bridge_service.get_transfer(&transfer.id).await.unwrap();
			assert_eq!(stored.status, expected_status);
		}
	}

	#[tokio::test]
	async fn test_pending_redemption_missing_redeem_tx_waits_before_resubmit() {
		// Below the missing-tx threshold (3 consecutive misses) the monitor
		// must keep the existing redeem_tx_hash and increment its missing
		// counter without touching failure_count. Otherwise a single transient
		// "tx not found" reading would burn a retry slot and discard a hash
		// that may still be in the mempool.
		let storage = make_storage();
		let delivery = make_delivery(MockDeliveryInterface::new());
		let bridge = Arc::new(StubBridge {
			check_status_results: Mutex::new(VecDeque::from([Ok(BridgeTransferStatus::Failed(
				"Redeem transaction not found".to_string(),
			))])),
			..Default::default()
		}) as Arc<dyn BridgeInterface>;
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance_config());

		let mut transfer = fresh_transfer(BridgeTransferStatus::PendingRedemption);
		transfer.redeem_tx_hash =
			Some("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string());
		bridge_service
			.storage()
			.save_transfer(&transfer)
			.await
			.unwrap();

		monitor
			.advance_pending_transfers(&rebalance_config())
			.await
			.unwrap();

		let stored = bridge_service.get_transfer(&transfer.id).await.unwrap();
		assert!(matches!(
			stored.status,
			BridgeTransferStatus::PendingRedemption
		));
		assert_eq!(stored.redeem_missing_checks, 1);
		assert!(stored.redeem_missing_since.is_some());
		assert_eq!(stored.failure_count, 0);
		assert!(stored.redeem_tx_hash.is_some());
	}

	#[tokio::test]
	async fn test_pending_redemption_missing_redeem_tx_clears_hash_after_three_misses() {
		// Once the missing-tx counter reaches the threshold, clear the stale
		// redeem_tx_hash and reset counters so the next monitor tick can
		// resubmit through the existing redeem_tx_hash.is_none() path. This
		// is the recovery path for a hash that was persisted but never
		// propagated / was dropped.
		let storage = make_storage();
		let delivery = make_delivery(MockDeliveryInterface::new());
		let bridge = Arc::new(StubBridge {
			check_status_results: Mutex::new(VecDeque::from([Ok(BridgeTransferStatus::Failed(
				"Redeem transaction not found".to_string(),
			))])),
			..Default::default()
		}) as Arc<dyn BridgeInterface>;
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance_config());

		let mut transfer = fresh_transfer(BridgeTransferStatus::PendingRedemption);
		transfer.redeem_tx_hash =
			Some("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string());
		transfer.redeem_missing_checks = 2;
		bridge_service
			.storage()
			.save_transfer(&transfer)
			.await
			.unwrap();

		monitor
			.advance_pending_transfers(&rebalance_config())
			.await
			.unwrap();

		let stored = bridge_service.get_transfer(&transfer.id).await.unwrap();
		assert!(matches!(
			stored.status,
			BridgeTransferStatus::PendingRedemption
		));
		assert_eq!(stored.redeem_missing_checks, 0);
		assert!(stored.redeem_missing_since.is_none());
		assert_eq!(stored.failure_count, 0);
		assert!(stored.redeem_tx_hash.is_none());
	}

	#[tokio::test]
	async fn test_pending_redemption_nonce_too_low_does_not_increment_failure_count() {
		// A residual `DeliveryError::NonceTooLow` indicates transient nonce drift,
		// not a redeem business failure. The monitor must leave the transfer in
		// PendingRedemption with failure_count unchanged so the next monitor tick
		// can retry after the nonce manager has resynced.
		let storage = make_storage();
		let mut mock = MockDeliveryInterface::new();
		mock.expect_submit().times(1).returning(|_tx, _tracking| {
			Box::pin(async move {
				Err(DeliveryError::NonceTooLow(
					"chain pending advanced past local cache".to_string(),
				))
			})
		});
		let delivery = make_delivery(mock);
		let bridge = Arc::new(StubBridge::default()) as Arc<dyn BridgeInterface>;
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance_config());

		let mut transfer = fresh_transfer(BridgeTransferStatus::PendingRedemption);
		transfer.vault_address = Some("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string());
		transfer.received_shares = Some("12345".to_string());
		bridge_service
			.storage()
			.save_transfer(&transfer)
			.await
			.unwrap();

		monitor
			.advance_pending_transfers(&rebalance_config())
			.await
			.unwrap();

		let stored = bridge_service.get_transfer(&transfer.id).await.unwrap();
		assert_eq!(
			stored.failure_count, 0,
			"NonceTooLow must not increment failure_count"
		);
		assert!(
			stored.redeem_tx_hash.is_none(),
			"No tx hash should be persisted on NonceTooLow"
		);
		assert!(
			matches!(stored.status, BridgeTransferStatus::PendingRedemption),
			"Status should remain PendingRedemption, got {:?}",
			stored.status
		);
	}

	#[tokio::test]
	async fn test_pending_redemption_network_error_still_increments_failure_count() {
		// Regression check: a generic DeliveryError::Network from the redeem
		// submission is still a real business failure and must increment
		// failure_count as before.
		let storage = make_storage();
		let mut mock = MockDeliveryInterface::new();
		mock.expect_submit().times(1).returning(|_tx, _tracking| {
			Box::pin(async move { Err(DeliveryError::Network("connection refused".to_string())) })
		});
		let delivery = make_delivery(mock);
		let bridge = Arc::new(StubBridge::default()) as Arc<dyn BridgeInterface>;
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance_config());

		let mut transfer = fresh_transfer(BridgeTransferStatus::PendingRedemption);
		transfer.vault_address = Some("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string());
		transfer.received_shares = Some("12345".to_string());
		bridge_service
			.storage()
			.save_transfer(&transfer)
			.await
			.unwrap();

		monitor
			.advance_pending_transfers(&rebalance_config())
			.await
			.unwrap();

		let stored = bridge_service.get_transfer(&transfer.id).await.unwrap();
		assert_eq!(stored.failure_count, 1);
		assert!(stored.redeem_tx_hash.is_none());
	}

	#[tokio::test]
	async fn test_pending_redemption_submits_redeem_once_and_persists_hash() {
		let storage = make_storage();
		let mut mock = MockDeliveryInterface::new();
		mock.expect_submit()
			.times(1)
			.returning(|tx: Transaction, _tracking| {
				assert_eq!(tx.chain_id, 747474);
				let to = tx.to.expect("redeem tx recipient");
				assert_eq!(
					Address::from_slice(&to.0),
					Address::from_slice(
						&hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap()
					)
				);
				Box::pin(async move { Ok(TransactionHash(vec![0x77; 32])) })
			});
		let delivery = make_delivery(mock);
		let bridge = Arc::new(StubBridge::default()) as Arc<dyn BridgeInterface>;
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance_config());

		let mut transfer = fresh_transfer(BridgeTransferStatus::PendingRedemption);
		transfer.vault_address = Some("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string());
		transfer.received_shares = Some("12345".to_string());
		bridge_service
			.storage()
			.save_transfer(&transfer)
			.await
			.unwrap();

		monitor
			.advance_pending_transfers(&rebalance_config())
			.await
			.unwrap();

		let stored = bridge_service.get_transfer(&transfer.id).await.unwrap();
		assert_eq!(
			stored.redeem_tx_hash.as_deref(),
			Some("0x7777777777777777777777777777777777777777777777777777777777777777")
		);
	}

	#[tokio::test]
	async fn test_check_thresholds_builds_direction_aware_request_and_uses_solver_address() {
		let storage = make_storage();
		let recorded = Arc::new(Mutex::new(Vec::new()));
		let bridge = Arc::new(StubBridge {
			recorded_requests: recorded.clone(),
			..Default::default()
		}) as Arc<dyn BridgeInterface>;

		let solver_address = SOLVER_ADDRESS.to_string();
		let mut mock = MockDeliveryInterface::new();
		mock.expect_get_balance()
			.times(2)
			.returning(move |address, token, chain_id| {
				assert_eq!(address, solver_address);
				match (chain_id, token) {
					(1, Some("0x1111111111111111111111111111111111111111")) => {
						Box::pin(async move { Ok("500000".to_string()) })
					},
					(747474, Some("0x3333333333333333333333333333333333333333")) => {
						Box::pin(async move { Ok("1500000".to_string()) })
					},
					other => panic!("unexpected balance query: {other:?}"),
				}
			});
		let delivery = make_delivery(mock);
		let mut rebalance = rebalance_config();
		rebalance.bridge_config = Some(serde_json::json!({
			"composer_addresses": {},
			"vault_addresses": { "1": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
		}));
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance.clone());

		monitor
			.check_thresholds_and_trigger(&rebalance)
			.await
			.unwrap();

		let requests = {
			let requests = recorded.lock().unwrap();
			requests.clone()
		};
		assert_eq!(requests.len(), 1);
		let request = &requests[0];
		assert_eq!(request.source_chain, 747474);
		assert_eq!(request.dest_chain, 1);
		assert_eq!(request.source_token, Address::from([0x33; 20]));
		assert_eq!(request.source_oft, Address::from([0x44; 20]));
		assert_eq!(request.dest_token, Address::from([0x11; 20]));
		assert_eq!(request.dest_oft, Address::from([0x22; 20]));
		assert_eq!(request.recipient, Address::from([0x55; 20]));

		let active = bridge_service.get_active_transfers().await.unwrap();
		assert_eq!(active.len(), 1);
		assert_eq!(active[0].pair_id, "eth-katana");
		assert_eq!(
			active[0].dest_token_address.as_deref(),
			Some("0x1111111111111111111111111111111111111111")
		);
		assert_eq!(
			active[0].vault_address.as_deref(),
			Some("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		);
		assert_eq!(active[0].is_composer_flow, Some(false));
		// Cooldown is now set after source tx confirms (Submitted → Relaying),
		// not on initiation. So it should NOT be active yet.
		assert!(!bridge_service
			.is_cooldown_active("eth-katana")
			.await
			.unwrap());
	}

	#[tokio::test]
	async fn test_check_thresholds_skips_non_composer_route_without_vault() {
		let storage = make_storage();
		let recorded = Arc::new(Mutex::new(Vec::new()));
		let bridge = Arc::new(StubBridge {
			recorded_requests: recorded.clone(),
			..Default::default()
		}) as Arc<dyn BridgeInterface>;

		let solver_address = SOLVER_ADDRESS.to_string();
		let mut mock = MockDeliveryInterface::new();
		mock.expect_get_balance()
			.times(2)
			.returning(move |address, token, chain_id| {
				assert_eq!(address, solver_address);
				match (chain_id, token) {
					(1, Some("0x1111111111111111111111111111111111111111")) => {
						Box::pin(async move { Ok("500000".to_string()) })
					},
					(747474, Some("0x3333333333333333333333333333333333333333")) => {
						Box::pin(async move { Ok("1500000".to_string()) })
					},
					other => panic!("unexpected balance query: {other:?}"),
				}
			});
		let delivery = make_delivery(mock);
		let rebalance = rebalance_config();
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance.clone());

		monitor
			.check_thresholds_and_trigger(&rebalance)
			.await
			.unwrap();

		let requests = {
			let requests = recorded.lock().unwrap();
			requests.clone()
		};
		assert!(requests.is_empty());
		assert!(bridge_service
			.get_active_transfers()
			.await
			.unwrap()
			.is_empty());
		assert!(!bridge_service
			.is_cooldown_active("eth-katana")
			.await
			.unwrap());
	}

	#[tokio::test]
	async fn test_failed_tick_does_not_update_last_check_at() {
		let storage = make_storage();
		let solver_address = SOLVER_ADDRESS.to_string();
		let mut mock = MockDeliveryInterface::new();
		mock.expect_get_balance()
			.times(2)
			.returning(move |address, token, chain_id| {
				assert_eq!(address, solver_address);
				match (chain_id, token) {
					(1, Some("0x1111111111111111111111111111111111111111")) => {
						Box::pin(async move { Ok("500000".to_string()) })
					},
					(747474, Some("0x3333333333333333333333333333333333333333")) => {
						Box::pin(async move { Ok("1500000".to_string()) })
					},
					other => panic!("unexpected balance query: {other:?}"),
				}
			});
		let delivery = make_delivery(mock);
		let bridge = Arc::new(StubBridge::default()) as Arc<dyn BridgeInterface>;
		let mut rebalance = rebalance_config();
		rebalance.monitor_interval_seconds = 1;
		rebalance.pairs[0].chain_a.token_address = "not-an-address".to_string();
		let (_bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance);
		let status = monitor.monitor_status.clone();

		let (tx, rx) = tokio::sync::watch::channel(false);
		let handle = tokio::spawn(monitor.run(rx));

		tokio::time::sleep(Duration::from_millis(1100)).await;
		tokio::task::yield_now().await;

		let status_guard = status.read().await;
		assert!(status_guard.last_check_at.is_none());
		assert!(status_guard.next_check_at.is_some());
		drop(status_guard);

		let _ = tx.send(true);
		let _ = handle.await;
	}

	// ----------------------------------------------------------------------
	// Task 7: monitor approve-durability behavioral branches.
	// ----------------------------------------------------------------------

	const APPROVE_HASH: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	const NEW_APPROVE_HASH: &str =
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
	const DEPOSIT_HASH: &str = "0xdededededededededededededededededededededededededededededededede";

	/// Build a transfer pre-seeded with all the source/dest fields the resume
	/// path needs to reconstruct a `BridgeRequest`.
	fn resumable_transfer(now: u64) -> crate::types::PendingBridgeTransfer {
		let mut t = pending_transfer(BridgeTransferStatus::Submitted);
		t.created_at = now;
		t.updated_at = now;
		// pair_id "eth-katana" maps source_chain=1 → dest_chain=747474 in
		// rebalance_config(); chain_a has token=0x11.., oft=0x22..; chain_b has
		// token=0x33.., oft=0x44.. — keep these in sync with the pair config.
		t.source_token_address = Some("0x1111111111111111111111111111111111111111".to_string());
		t.source_oft_address = Some("0x2222222222222222222222222222222222222222".to_string());
		t.dest_token_address = Some("0x3333333333333333333333333333333333333333".to_string());
		t.dest_oft_address = Some("0x4444444444444444444444444444444444444444".to_string());
		t.recipient_address = Some(SOLVER_ADDRESS.to_string());
		t
	}

	fn ok_receipt() -> TransactionReceipt {
		TransactionReceipt {
			hash: TransactionHash(vec![0xaa; 32]),
			block_number: 100,
			success: true,
			logs: vec![],
			block_timestamp: None,
		}
	}

	fn reverted_receipt() -> TransactionReceipt {
		TransactionReceipt {
			hash: TransactionHash(vec![0xaa; 32]),
			block_number: 100,
			success: false,
			logs: vec![],
			block_timestamp: None,
		}
	}

	#[tokio::test]
	async fn monitor_escalates_deposit_crash_window_without_running_bridge_asset() {
		// (0) Crash-window guard: bridge_submit_attempted=true + tx_hash=None must
		// escalate BEFORE any other branch — including the approve-confirmed resume —
		// to avoid a possible double-deposit.
		let storage = make_storage();
		// Mock should NOT see any get_receipt call (crash-window fires first).
		let mut mock = MockDeliveryInterface::new();
		mock.expect_get_receipt().times(0);
		let delivery = make_delivery(mock);
		// Bridge stub asserts bridge_asset is never invoked.
		let recorded = Arc::new(Mutex::new(Vec::new()));
		let bridge = Arc::new(StubBridge {
			recorded_requests: recorded.clone(),
			..Default::default()
		}) as Arc<dyn BridgeInterface>;
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance_config());

		let now = current_timestamp();
		let mut transfer = resumable_transfer(now);
		transfer.tx_hash = None;
		transfer.approve_tx_hash = Some(APPROVE_HASH.to_string());
		transfer.approve_was_broadcast = true;
		transfer.approve_submitted_at = Some(now - 60);
		transfer.bridge_submit_attempted = true; // ← the marker
		bridge_service
			.storage()
			.save_transfer(&transfer)
			.await
			.unwrap();

		monitor
			.advance_pending_transfers(&rebalance_config())
			.await
			.unwrap();

		let stored = bridge_service.get_transfer(&transfer.id).await.unwrap();
		assert!(
			matches!(
				&stored.status,
				BridgeTransferStatus::NeedsIntervention(reason)
					if reason.contains("bridge submit attempted")
						&& reason.contains("tx_hash not persisted")
			),
			"unexpected status: {:?}",
			stored.status
		);
		assert!(
			recorded.lock().unwrap().is_empty(),
			"bridge_asset must NOT be called by the crash-window branch"
		);
	}

	#[tokio::test]
	async fn monitor_does_not_treat_fresh_transfer_as_crash_window() {
		// A brand-new transfer with bridge_submit_attempted=false (default) must
		// NOT be escalated by the crash-window guard, even if the rest of the
		// fields look like an in-flight approve state.
		let storage = make_storage();
		let mut mock = MockDeliveryInterface::new();
		mock.expect_get_receipt()
			.times(1)
			.returning(|_, _| Box::pin(async move { Ok(ok_receipt()) }));
		let delivery = make_delivery(mock);
		let recorded = Arc::new(Mutex::new(Vec::new()));
		let bridge = Arc::new(StubBridge {
			bridge_asset_results: Mutex::new(VecDeque::from([Ok(BridgeDepositResult {
				tx_hash: DEPOSIT_HASH.to_string(),
				message_guid: None,
				estimated_arrival: None,
			})])),
			recorded_requests: recorded.clone(),
			..Default::default()
		}) as Arc<dyn BridgeInterface>;
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance_config());

		let now = current_timestamp();
		let mut transfer = resumable_transfer(now);
		transfer.tx_hash = None;
		transfer.approve_tx_hash = Some(APPROVE_HASH.to_string());
		transfer.approve_was_broadcast = true;
		transfer.approve_submitted_at = Some(now - 60);
		transfer.bridge_submit_attempted = false; // ← NOT a crash window
		bridge_service
			.storage()
			.save_transfer(&transfer)
			.await
			.unwrap();

		monitor
			.advance_pending_transfers(&rebalance_config())
			.await
			.unwrap();

		let stored = bridge_service.get_transfer(&transfer.id).await.unwrap();
		assert!(
			matches!(stored.status, BridgeTransferStatus::Submitted),
			"unexpected status: {:?}",
			stored.status
		);
		assert_eq!(stored.tx_hash.as_deref(), Some(DEPOSIT_HASH));
		assert!(stored.bridge_submit_attempted);
		assert_eq!(recorded.lock().unwrap().len(), 1);
	}

	#[tokio::test]
	async fn monitor_resumes_bridge_when_approve_confirms() {
		// (b) Approve receipt success → reconstruct BridgeRequest from the
		// persisted source/dest fields → call bridge_asset → persist tx_hash.
		let storage = make_storage();
		let mut mock = MockDeliveryInterface::new();
		mock.expect_get_receipt()
			.times(1)
			.returning(|_, _| Box::pin(async move { Ok(ok_receipt()) }));
		let delivery = make_delivery(mock);
		let recorded = Arc::new(Mutex::new(Vec::new()));
		let bridge = Arc::new(StubBridge {
			bridge_asset_results: Mutex::new(VecDeque::from([Ok(BridgeDepositResult {
				tx_hash: DEPOSIT_HASH.to_string(),
				message_guid: None,
				estimated_arrival: None,
			})])),
			recorded_requests: recorded.clone(),
			..Default::default()
		}) as Arc<dyn BridgeInterface>;
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance_config());

		let now = current_timestamp();
		let mut transfer = resumable_transfer(now);
		transfer.tx_hash = None;
		transfer.approve_tx_hash = Some(APPROVE_HASH.to_string());
		transfer.approve_was_broadcast = true;
		transfer.approve_submitted_at = Some(now - 60);
		transfer.approve_missing_checks = 0;
		transfer.bridge_submit_attempted = false;
		bridge_service
			.storage()
			.save_transfer(&transfer)
			.await
			.unwrap();

		monitor
			.advance_pending_transfers(&rebalance_config())
			.await
			.unwrap();

		let stored = bridge_service.get_transfer(&transfer.id).await.unwrap();
		assert!(matches!(stored.status, BridgeTransferStatus::Submitted));
		assert_eq!(stored.tx_hash.as_deref(), Some(DEPOSIT_HASH));
		assert_eq!(stored.approve_missing_checks, 0);
		assert!(stored.bridge_submit_attempted);

		// Validate the reconstructed BridgeRequest matches the source/dest fields.
		let recorded = recorded.lock().unwrap();
		assert_eq!(recorded.len(), 1);
		let request = &recorded[0];
		assert_eq!(request.pair_id, transfer.pair_id);
		assert_eq!(request.source_chain, 1);
		assert_eq!(request.dest_chain, 747474);
		assert_eq!(request.source_token, Address::from([0x11; 20]));
		assert_eq!(request.source_oft, Address::from([0x22; 20]));
		assert_eq!(request.dest_token, Address::from([0x33; 20]));
		assert_eq!(request.dest_oft, Address::from([0x44; 20]));
		assert_eq!(request.recipient, Address::from([0x55; 20]));
		assert_eq!(request.amount, U256::from(1_000_000u64));
	}

	#[tokio::test]
	async fn monitor_clears_stale_approve_hash_and_retries_bridge_asset_same_tick() {
		// (c) Stale-hash retry must (a) clear stale hash and (b) actually rerun
		// bridge_asset in the same tick — leaving approve_was_broadcast intact.
		let storage = make_storage();
		let mut mock = MockDeliveryInterface::new();
		mock.expect_get_receipt().times(1).returning(|_, _| {
			Box::pin(async move {
				Err(solver_delivery::DeliveryError::Network(
					"receipt not found".to_string(),
				))
			})
		});
		mock.expect_tx_exists()
			.times(1)
			.returning(|_, _| Box::pin(async move { Ok(false) }));
		let delivery = make_delivery(mock);
		let recorded = Arc::new(Mutex::new(Vec::new()));
		let bridge = Arc::new(StubBridge {
			bridge_asset_results: Mutex::new(VecDeque::from([Ok(BridgeDepositResult {
				tx_hash: DEPOSIT_HASH.to_string(),
				message_guid: None,
				estimated_arrival: None,
			})])),
			recorded_requests: recorded.clone(),
			..Default::default()
		}) as Arc<dyn BridgeInterface>;
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance_config());

		let now = current_timestamp();
		let mut transfer = resumable_transfer(now);
		transfer.tx_hash = None;
		transfer.approve_tx_hash = Some(APPROVE_HASH.to_string());
		transfer.approve_was_broadcast = true;
		transfer.approve_submitted_at = Some(now - 60);
		transfer.approve_missing_checks = 2; // one more miss → threshold
		transfer.bridge_submit_attempted = false;
		bridge_service
			.storage()
			.save_transfer(&transfer)
			.await
			.unwrap();

		monitor
			.advance_pending_transfers(&rebalance_config())
			.await
			.unwrap();

		let stored = bridge_service.get_transfer(&transfer.id).await.unwrap();
		assert!(matches!(stored.status, BridgeTransferStatus::Submitted));
		assert!(
			stored.approve_tx_hash.is_none(),
			"stale hash should be cleared"
		);
		assert_eq!(stored.approve_missing_checks, 0);
		assert_eq!(stored.tx_hash.as_deref(), Some(DEPOSIT_HASH));
		assert!(
			stored.approve_was_broadcast,
			"approve_was_broadcast must be preserved"
		);
		assert_eq!(
			recorded.lock().unwrap().len(),
			1,
			"bridge_asset should be called exactly once in the same tick"
		);
	}

	#[tokio::test]
	async fn monitor_stale_approve_retry_persists_new_approve_pending_hash() {
		// Companion to the previous test: bridge_asset on retry returns
		// ApprovePending → persist new approve hash, roll back the marker, leave
		// approve_was_broadcast and approve_submitted_at intact.
		let storage = make_storage();
		let mut mock = MockDeliveryInterface::new();
		mock.expect_get_receipt().times(1).returning(|_, _| {
			Box::pin(async move {
				Err(solver_delivery::DeliveryError::Network(
					"receipt not found".to_string(),
				))
			})
		});
		mock.expect_tx_exists()
			.times(1)
			.returning(|_, _| Box::pin(async move { Ok(false) }));
		let delivery = make_delivery(mock);
		let bridge = Arc::new(StubBridge {
			bridge_asset_results: Mutex::new(VecDeque::from([Err(
				crate::BridgeError::ApprovePending {
					tx_hash: NEW_APPROVE_HASH.to_string(),
				},
			)])),
			..Default::default()
		}) as Arc<dyn BridgeInterface>;
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance_config());

		let now = current_timestamp();
		let original_phase_start = now - 60;
		let mut transfer = resumable_transfer(now);
		transfer.tx_hash = None;
		transfer.approve_tx_hash = Some(APPROVE_HASH.to_string());
		transfer.approve_was_broadcast = true;
		transfer.approve_submitted_at = Some(original_phase_start);
		transfer.approve_missing_checks = 2;
		transfer.bridge_submit_attempted = false;
		bridge_service
			.storage()
			.save_transfer(&transfer)
			.await
			.unwrap();

		monitor
			.advance_pending_transfers(&rebalance_config())
			.await
			.unwrap();

		let stored = bridge_service.get_transfer(&transfer.id).await.unwrap();
		assert!(matches!(stored.status, BridgeTransferStatus::Submitted));
		assert_eq!(stored.tx_hash, None);
		assert_eq!(stored.approve_tx_hash.as_deref(), Some(NEW_APPROVE_HASH));
		assert_eq!(stored.approve_missing_checks, 0);
		assert!(stored.approve_was_broadcast);
		assert_eq!(
			stored.approve_submitted_at,
			Some(original_phase_start),
			"approve_submitted_at must NOT be refreshed; it measures the original phase"
		);
		assert!(
			!stored.bridge_submit_attempted,
			"bridge_submit_attempted must be rolled back on ApprovePending"
		);
	}

	#[tokio::test]
	async fn monitor_marks_failed_when_approve_reverts_on_chain() {
		// Approve receipt with success=false → mark Failed("approve reverted on chain").
		let storage = make_storage();
		let mut mock = MockDeliveryInterface::new();
		mock.expect_get_receipt()
			.times(1)
			.returning(|_, _| Box::pin(async move { Ok(reverted_receipt()) }));
		let delivery = make_delivery(mock);
		let bridge = Arc::new(StubBridge::default()) as Arc<dyn BridgeInterface>;
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance_config());

		let now = current_timestamp();
		let mut transfer = resumable_transfer(now);
		transfer.tx_hash = None;
		transfer.approve_tx_hash = Some(APPROVE_HASH.to_string());
		transfer.approve_was_broadcast = true;
		transfer.approve_submitted_at = Some(now - 60);
		transfer.bridge_submit_attempted = false;
		bridge_service
			.storage()
			.save_transfer(&transfer)
			.await
			.unwrap();

		monitor
			.advance_pending_transfers(&rebalance_config())
			.await
			.unwrap();

		let stored = bridge_service.get_transfer(&transfer.id).await.unwrap();
		assert!(
			matches!(
				&stored.status,
				BridgeTransferStatus::Failed(reason) if reason == "approve reverted on chain"
			),
			"unexpected status: {:?}",
			stored.status
		);
	}

	#[tokio::test]
	async fn monitor_keeps_bridge_submit_marker_on_generic_error_then_escalates_next_tick() {
		// Tick 1: get_receipt → success=true; bridge_asset → generic Err.
		//   Expect status Submitted, bridge_submit_attempted=TRUE (kept set).
		// Tick 2: branch (0) crash-window fires before any RPC.
		//   Expect status NeedsIntervention; bridge_asset NOT called again.
		let storage = make_storage();
		let mut mock = MockDeliveryInterface::new();
		// get_receipt is only called on the first tick; the second tick short-circuits
		// at branch (0).
		mock.expect_get_receipt()
			.times(1)
			.returning(|_, _| Box::pin(async move { Ok(ok_receipt()) }));
		let delivery = make_delivery(mock);

		let recorded = Arc::new(Mutex::new(Vec::new()));
		let bridge = Arc::new(StubBridge {
			bridge_asset_results: Mutex::new(VecDeque::from([Err(
				crate::BridgeError::TransactionFailed("rpc blip".to_string()),
			)])),
			recorded_requests: recorded.clone(),
			..Default::default()
		}) as Arc<dyn BridgeInterface>;
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance_config());

		let now = current_timestamp();
		let mut transfer = resumable_transfer(now);
		transfer.tx_hash = None;
		transfer.approve_tx_hash = Some(APPROVE_HASH.to_string());
		transfer.approve_was_broadcast = true;
		transfer.approve_submitted_at = Some(now - 60);
		transfer.bridge_submit_attempted = false;
		bridge_service
			.storage()
			.save_transfer(&transfer)
			.await
			.unwrap();

		// Tick 1
		monitor
			.advance_pending_transfers(&rebalance_config())
			.await
			.unwrap();
		let after_first = bridge_service.get_transfer(&transfer.id).await.unwrap();
		assert!(matches!(
			after_first.status,
			BridgeTransferStatus::Submitted
		));
		assert!(after_first.tx_hash.is_none());
		assert!(
			after_first.bridge_submit_attempted,
			"marker must stay set on generic Err"
		);
		assert_eq!(recorded.lock().unwrap().len(), 1);

		// Tick 2: crash-window guard fires before any RPC.
		monitor
			.advance_pending_transfers(&rebalance_config())
			.await
			.unwrap();
		let after_second = bridge_service.get_transfer(&transfer.id).await.unwrap();
		assert!(
			matches!(
				&after_second.status,
				BridgeTransferStatus::NeedsIntervention(reason)
					if reason.contains("bridge submit attempted")
			),
			"unexpected status: {:?}",
			after_second.status
		);
		assert_eq!(
			recorded.lock().unwrap().len(),
			1,
			"bridge_asset must be called exactly once across both ticks"
		);
	}

	#[tokio::test]
	async fn monitor_marks_needs_intervention_on_insufficient_native_gas_after_approve() {
		let storage = make_storage();
		let mut mock = MockDeliveryInterface::new();
		mock.expect_get_receipt()
			.times(1)
			.returning(|_, _| Box::pin(async move { Ok(ok_receipt()) }));
		let delivery = make_delivery(mock);

		let recorded = Arc::new(Mutex::new(Vec::new()));
		let bridge = Arc::new(StubBridge {
			bridge_asset_results: Mutex::new(VecDeque::from([Err(
				crate::BridgeError::InsufficientNativeGas(
					"Insufficient native gas on chain 1 for signer 0xsolver: balance 10 wei, required 30 wei, shortfall 20 wei".to_string(),
				),
			)])),
			recorded_requests: recorded.clone(),
			..Default::default()
		}) as Arc<dyn BridgeInterface>;
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance_config());

		let now = current_timestamp();
		let mut transfer = resumable_transfer(now);
		transfer.tx_hash = None;
		transfer.approve_tx_hash = Some(APPROVE_HASH.to_string());
		transfer.approve_was_broadcast = true;
		transfer.approve_submitted_at = Some(now - 60);
		transfer.bridge_submit_attempted = false;
		bridge_service
			.storage()
			.save_transfer(&transfer)
			.await
			.unwrap();

		monitor
			.advance_pending_transfers(&rebalance_config())
			.await
			.unwrap();

		let stored = bridge_service.get_transfer(&transfer.id).await.unwrap();
		assert!(
			matches!(
				&stored.status,
				BridgeTransferStatus::NeedsIntervention(reason)
					if reason.contains("Insufficient native gas")
						&& reason.contains("shortfall 20 wei")
			),
			"unexpected status: {:?}",
			stored.status
		);
		assert!(
			!stored.bridge_submit_attempted,
			"pre-broadcast insufficient gas must roll back the crash-window marker"
		);
		assert_eq!(recorded.lock().unwrap().len(), 1);
	}

	#[tokio::test]
	async fn monitor_escalates_when_approve_phase_exceeds_timeout() {
		// (d) Approve-phase absolute timeout fires BEFORE the mid-flight branch,
		// so get_receipt is never called.
		let storage = make_storage();
		let mut mock = MockDeliveryInterface::new();
		mock.expect_get_receipt().times(0);
		let delivery = make_delivery(mock);
		let bridge = Arc::new(StubBridge::default()) as Arc<dyn BridgeInterface>;
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance_config());

		let now = current_timestamp();
		let mut transfer = resumable_transfer(now);
		transfer.tx_hash = None;
		transfer.approve_tx_hash = Some(APPROVE_HASH.to_string());
		transfer.approve_was_broadcast = true;
		transfer.approve_submitted_at = Some(now - APPROVE_PHASE_TIMEOUT_SECS - 1);
		transfer.bridge_submit_attempted = false;
		bridge_service
			.storage()
			.save_transfer(&transfer)
			.await
			.unwrap();

		monitor
			.advance_pending_transfers(&rebalance_config())
			.await
			.unwrap();

		let stored = bridge_service.get_transfer(&transfer.id).await.unwrap();
		assert!(
			matches!(
				&stored.status,
				BridgeTransferStatus::NeedsIntervention(reason)
					if reason.contains("approve phase exceeded")
			),
			"unexpected status: {:?}",
			stored.status
		);
	}

	#[tokio::test]
	async fn monitor_escalates_approve_timeout_when_approve_submitted_at_is_missing() {
		// (d) Bypass #2 regression: a transfer with approve_was_broadcast=true
		// but approve_submitted_at=None must NOT skip the timeout. Without the
		// fix, .unwrap_or(false) made the timestamp comparison fail-open and
		// such records bypassed escalation forever.
		//
		// With the fix: the guard falls back to created_at. With created_at
		// well past timeout, branch (d) fires.
		let storage = make_storage();
		let mut mock = MockDeliveryInterface::new();
		// Branch (d) fires before the mid-flight branch, so get_receipt isn't called.
		mock.expect_get_receipt().times(0);
		let delivery = make_delivery(mock);
		let bridge = Arc::new(StubBridge::default()) as Arc<dyn BridgeInterface>;
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance_config());

		let now = current_timestamp();
		let mut transfer = resumable_transfer(now);
		transfer.tx_hash = None;
		transfer.approve_tx_hash = None; // no hash, but flag is set
		transfer.approve_was_broadcast = true;
		transfer.approve_submitted_at = None; // ← the trap
		transfer.bridge_submit_attempted = false;
		transfer.created_at = now - APPROVE_PHASE_TIMEOUT_SECS - 60;
		bridge_service
			.storage()
			.save_transfer(&transfer)
			.await
			.unwrap();

		monitor
			.advance_pending_transfers(&rebalance_config())
			.await
			.unwrap();

		let stored = bridge_service.get_transfer(&transfer.id).await.unwrap();
		assert!(
			matches!(
				&stored.status,
				BridgeTransferStatus::NeedsIntervention(reason)
					if reason.contains("approve phase exceeded")
			),
			"missing approve_submitted_at must not bypass timeout; got {:?}",
			stored.status
		);
	}

	#[tokio::test]
	async fn monitor_escalates_approve_timeout_when_hash_set_but_broadcast_flag_false() {
		// (d) Bypass #1 regression: a transfer with approve_tx_hash=Some(valid)
		// but approve_was_broadcast=false must STILL be subject to the timeout.
		// Without the fix, the guard required approve_was_broadcast and the
		// mid-flight approve branch ran first, looping every tick. The stale-
		// hash counter only increments on tx_exists()==Ok(false), so a slow
		// underpriced approve where tx_exists()==Ok(true) indefinitely had no
		// escalation path.
		//
		// With the fix: "approve phase started" is derived from EITHER signal,
		// so this transfer escalates via branch (d).
		let storage = make_storage();
		let mut mock = MockDeliveryInterface::new();
		// Branch (d) fires before the mid-flight branch, so the receipt /
		// tx_exists calls aren't reached.
		mock.expect_get_receipt().times(0);
		mock.expect_tx_exists().times(0);
		let delivery = make_delivery(mock);
		let bridge = Arc::new(StubBridge::default()) as Arc<dyn BridgeInterface>;
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance_config());

		let now = current_timestamp();
		let mut transfer = resumable_transfer(now);
		transfer.tx_hash = None;
		transfer.approve_tx_hash = Some(APPROVE_HASH.to_string()); // valid 32-byte hex
		transfer.approve_was_broadcast = false; // ← the trap
		transfer.approve_submitted_at = None;
		transfer.bridge_submit_attempted = false;
		transfer.created_at = now - APPROVE_PHASE_TIMEOUT_SECS - 60;
		bridge_service
			.storage()
			.save_transfer(&transfer)
			.await
			.unwrap();

		monitor
			.advance_pending_transfers(&rebalance_config())
			.await
			.unwrap();

		let stored = bridge_service.get_transfer(&transfer.id).await.unwrap();
		assert!(
			matches!(
				&stored.status,
				BridgeTransferStatus::NeedsIntervention(reason)
					if reason.contains("approve phase exceeded")
			),
			"approve_tx_hash set but flag false must not bypass timeout; got {:?}",
			stored.status
		);
	}

	#[tokio::test]
	async fn monitor_escalates_when_approve_tx_hash_is_non_hex() {
		// Mid-flight branch: a non-hex approve_tx_hash will fail every tick
		// forever. With the fix, escalate immediately to NeedsIntervention
		// instead of looping silently.
		let storage = make_storage();
		let mut mock = MockDeliveryInterface::new();
		// We never reach the receipt fetch — escalation happens at parse time.
		mock.expect_get_receipt().times(0);
		let delivery = make_delivery(mock);
		let bridge = Arc::new(StubBridge::default()) as Arc<dyn BridgeInterface>;
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance_config());

		let now = current_timestamp();
		let mut transfer = resumable_transfer(now);
		transfer.tx_hash = None;
		transfer.approve_tx_hash = Some("0xZZZZ-not-hex".to_string());
		transfer.approve_was_broadcast = true;
		transfer.approve_submitted_at = Some(now);
		transfer.bridge_submit_attempted = false;
		bridge_service
			.storage()
			.save_transfer(&transfer)
			.await
			.unwrap();

		monitor
			.advance_pending_transfers(&rebalance_config())
			.await
			.unwrap();

		let stored = bridge_service.get_transfer(&transfer.id).await.unwrap();
		match &stored.status {
			BridgeTransferStatus::NeedsIntervention(reason) => {
				assert!(
					reason.to_lowercase().contains("approve_tx_hash")
						&& reason.to_lowercase().contains("format"),
					"expected reason to mention approve_tx_hash format; got: {reason}"
				);
			},
			other => panic!("expected NeedsIntervention, got {other:?}"),
		}
	}

	#[tokio::test]
	async fn monitor_escalates_when_approve_tx_hash_is_odd_length_hex() {
		// Odd-length hex: hex::decode returns Err. Same escalation path as
		// non-hex.
		let storage = make_storage();
		let mut mock = MockDeliveryInterface::new();
		mock.expect_get_receipt().times(0);
		let delivery = make_delivery(mock);
		let bridge = Arc::new(StubBridge::default()) as Arc<dyn BridgeInterface>;
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance_config());

		let now = current_timestamp();
		let mut transfer = resumable_transfer(now);
		transfer.tx_hash = None;
		transfer.approve_tx_hash = Some("0xabc".to_string()); // 3 hex chars
		transfer.approve_was_broadcast = true;
		transfer.approve_submitted_at = Some(now);
		transfer.bridge_submit_attempted = false;
		bridge_service
			.storage()
			.save_transfer(&transfer)
			.await
			.unwrap();

		monitor
			.advance_pending_transfers(&rebalance_config())
			.await
			.unwrap();

		let stored = bridge_service.get_transfer(&transfer.id).await.unwrap();
		match &stored.status {
			BridgeTransferStatus::NeedsIntervention(reason) => {
				assert!(
					reason.to_lowercase().contains("approve_tx_hash")
						&& reason.to_lowercase().contains("format"),
					"expected reason to mention approve_tx_hash format; got: {reason}"
				);
			},
			other => panic!("expected NeedsIntervention, got {other:?}"),
		}
	}

	#[tokio::test]
	async fn monitor_escalates_when_approve_tx_hash_is_wrong_length() {
		// Valid hex but only 2 bytes — hex::decode succeeds but
		// TransactionHash is malformed. Without the length check, the
		// 2-byte vec would be passed to delivery.get_receipt where the RPC
		// layer's behavior is provider-dependent (most return a transient
		// error that the existing branch treats as "not yet confirmed",
		// causing the same silent-loop pattern). Escalate immediately.
		let storage = make_storage();
		let mut mock = MockDeliveryInterface::new();
		mock.expect_get_receipt().times(0);
		let delivery = make_delivery(mock);
		let bridge = Arc::new(StubBridge::default()) as Arc<dyn BridgeInterface>;
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance_config());

		let now = current_timestamp();
		let mut transfer = resumable_transfer(now);
		transfer.tx_hash = None;
		transfer.approve_tx_hash = Some("0xaabb".to_string()); // 2 bytes
		transfer.approve_was_broadcast = true;
		transfer.approve_submitted_at = Some(now);
		transfer.bridge_submit_attempted = false;
		bridge_service
			.storage()
			.save_transfer(&transfer)
			.await
			.unwrap();

		monitor
			.advance_pending_transfers(&rebalance_config())
			.await
			.unwrap();

		let stored = bridge_service.get_transfer(&transfer.id).await.unwrap();
		match &stored.status {
			BridgeTransferStatus::NeedsIntervention(reason) => {
				assert!(
					reason.to_lowercase().contains("approve_tx_hash")
						&& reason.to_lowercase().contains("length")
						&& reason.contains("2"),
					"expected reason to mention approve_tx_hash length with byte count; got: {reason}"
				);
			},
			other => panic!("expected NeedsIntervention, got {other:?}"),
		}
	}

	#[tokio::test]
	async fn monitor_escalates_impossible_submitted_state_to_needs_intervention() {
		// (e) Impossible-state invariant: never-broadcast transfer >5min old.
		let storage = make_storage();
		let mock = MockDeliveryInterface::new();
		let delivery = make_delivery(mock);
		let bridge = Arc::new(StubBridge::default()) as Arc<dyn BridgeInterface>;
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance_config());

		let now = current_timestamp();
		let mut transfer = resumable_transfer(now);
		transfer.tx_hash = None;
		transfer.approve_tx_hash = None;
		transfer.approve_was_broadcast = false;
		transfer.bridge_submit_attempted = false;
		transfer.created_at = now - 600;
		bridge_service
			.storage()
			.save_transfer(&transfer)
			.await
			.unwrap();

		monitor
			.advance_pending_transfers(&rebalance_config())
			.await
			.unwrap();

		let stored = bridge_service.get_transfer(&transfer.id).await.unwrap();
		assert!(
			matches!(
				&stored.status,
				BridgeTransferStatus::NeedsIntervention(reason)
					if reason.contains("approve never broadcast")
			),
			"unexpected status: {:?}",
			stored.status
		);
	}

	#[tokio::test]
	async fn monitor_does_not_escalate_when_approve_was_broadcast_then_cleared() {
		// (e) The impossible-state branch's `!approve_was_broadcast` guard must
		// exclude the cleared-hash recovery state. With approve_was_broadcast=true
		// and approve_tx_hash=None, the transfer falls through impossible-state and
		// the mid-flight-approve branch is also skipped (no hash to re-check), so
		// the transfer is not escalated by Task 7's branches. Adapt the test from
		// the plan's "retry path runs bridge_asset" framing — the actual point of
		// the test is the invariant: approve_was_broadcast=true means impossible-state
		// must NOT fire.
		let storage = make_storage();
		let mock = MockDeliveryInterface::new();
		let delivery = make_delivery(mock);
		let bridge = Arc::new(StubBridge::default()) as Arc<dyn BridgeInterface>;
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance_config());

		let now = current_timestamp();
		let mut transfer = resumable_transfer(now);
		transfer.tx_hash = None;
		transfer.approve_tx_hash = None;
		transfer.approve_was_broadcast = true; // ← cleared-hash window
		transfer.bridge_submit_attempted = false;
		transfer.created_at = now - 600; // older than the impossible-state threshold
		bridge_service
			.storage()
			.save_transfer(&transfer)
			.await
			.unwrap();

		monitor
			.advance_pending_transfers(&rebalance_config())
			.await
			.unwrap();

		let stored = bridge_service.get_transfer(&transfer.id).await.unwrap();
		assert!(
			matches!(stored.status, BridgeTransferStatus::Submitted),
			"impossible-state branch must NOT fire when approve_was_broadcast=true; got {:?}",
			stored.status
		);
		// And the cleared-hash window is preserved across the tick.
		assert!(stored.approve_tx_hash.is_none());
		assert!(stored.approve_was_broadcast);
	}

	#[tokio::test]
	async fn monitor_does_not_apply_submitted_timeout_to_mid_flight_approve() {
		// Regression: a slow-but-honest approve under the absolute cap must NOT be
		// reaped by the existing 30-min Submitted timeout. Also verifies that
		// updated_at is NOT refreshed on the "still pending in mempool" branch.
		let storage = make_storage();
		let mut mock = MockDeliveryInterface::new();
		mock.expect_get_receipt().times(1).returning(|_, _| {
			Box::pin(async move {
				Err(solver_delivery::DeliveryError::Network(
					"receipt not found".to_string(),
				))
			})
		});
		mock.expect_tx_exists()
			.times(1)
			.returning(|_, _| Box::pin(async move { Ok(true) }));
		let delivery = make_delivery(mock);
		let bridge = Arc::new(StubBridge::default()) as Arc<dyn BridgeInterface>;
		let (bridge_service, monitor) = make_monitor(bridge, delivery, storage, rebalance_config());

		let now = current_timestamp();
		let mut transfer = resumable_transfer(now);
		transfer.tx_hash = None;
		transfer.approve_tx_hash = Some(APPROVE_HASH.to_string());
		transfer.approve_was_broadcast = true;
		transfer.approve_submitted_at = Some(now - 60); // well under the 1h cap
		transfer.approve_missing_checks = 0;
		transfer.bridge_submit_attempted = false;
		// Would normally trip the 30-min Submitted timeout, but the mid-flight branch
		// fires first.
		let stale_updated_at = now - SUBMITTED_TIMEOUT_SECS - 1;
		transfer.updated_at = stale_updated_at;
		bridge_service
			.storage()
			.save_transfer(&transfer)
			.await
			.unwrap();

		monitor
			.advance_pending_transfers(&rebalance_config())
			.await
			.unwrap();

		let stored = bridge_service.get_transfer(&transfer.id).await.unwrap();
		assert!(
			matches!(stored.status, BridgeTransferStatus::Submitted),
			"unexpected status: {:?}",
			stored.status
		);
		assert_eq!(stored.approve_tx_hash.as_deref(), Some(APPROVE_HASH));
		assert_eq!(stored.approve_missing_checks, 0);
		assert_eq!(
			stored.updated_at, stale_updated_at,
			"updated_at must NOT be refreshed by the 'still pending' branch"
		);
	}
}
