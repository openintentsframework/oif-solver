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

/// Timeout for Relaying state before NeedsIntervention.
const RELAYING_TIMEOUT_SECS: u64 = 30 * 60;

/// Timeout for PendingRedemption before NeedsIntervention.
const PENDING_REDEMPTION_TIMEOUT_SECS: u64 = 24 * 3600;

/// Max retries for PendingRedemption before NeedsIntervention.
const MAX_REDEEM_RETRIES: u32 = 3;

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
			// a Failed status containing "Source transaction not found". Do NOT
			// increment on normal Submitted→Submitted (tx still pending in mempool).
			if matches!(transfer.status, BridgeTransferStatus::Submitted) {
				match &new_status {
					BridgeTransferStatus::Failed(reason)
						if reason.contains("Source transaction not found") =>
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
				&& matches!(&new_status, BridgeTransferStatus::Failed(reason) if reason.contains("Source transaction missing"))
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
				&& matches!(&new_status, BridgeTransferStatus::Failed(reason) if reason.contains("Source transaction missing"))
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
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::test_support::{pending_transfer, rebalance_config};
	use crate::{BridgeDepositResult, BridgeInterface};
	use async_trait::async_trait;
	use solver_config::ConfigBuilder;
	use solver_delivery::{DeliveryService, MockDeliveryInterface};
	use solver_storage::implementations::file::{FileStorage, TtlConfig};
	use solver_storage::StorageService;
	use solver_types::{
		Address as DeliveryAddress, Log, LogFilter, Transaction, TransactionHash, H256,
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
}
