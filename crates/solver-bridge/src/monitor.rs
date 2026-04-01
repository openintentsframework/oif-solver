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
pub struct RebalanceMonitor {
	bridge_service: Arc<BridgeService>,
	delivery: Arc<solver_delivery::DeliveryService>,
	dynamic_config: Arc<RwLock<solver_config::Config>>,
	#[allow(dead_code)]
	storage: Arc<StorageService>,
	transaction_semaphore: Arc<Semaphore>,
	solver_address: String,
}

impl RebalanceMonitor {
	pub fn new(
		bridge_service: Arc<BridgeService>,
		delivery: Arc<solver_delivery::DeliveryService>,
		dynamic_config: Arc<RwLock<solver_config::Config>>,
		storage: Arc<StorageService>,
		transaction_semaphore: Arc<Semaphore>,
		solver_address: String,
	) -> Self {
		Self {
			bridge_service,
			delivery,
			dynamic_config,
			storage,
			transaction_semaphore,
			solver_address,
		}
	}

	/// Main polling loop. Runs until shutdown signal.
	pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
		tracing::info!("Rebalance monitor started");

		loop {
			let interval_seconds = {
				let config = self.dynamic_config.read().await;
				config
					.rebalance
					.as_ref()
					.map(|r| r.monitor_interval_seconds)
					.unwrap_or(60)
			};

			tokio::select! {
				_ = tokio::time::sleep(Duration::from_secs(interval_seconds)) => {
					if let Err(e) = self.tick().await {
						tracing::warn!("Rebalance monitor tick failed: {}", e);
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

			// Poll bridge implementation for status update
			let new_status = bridge_impl.check_status(&transfer).await?;
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

					self.bridge_service
						.update_transfer(&mut transfer, new_status)
						.await?;
				}
			}

			// Delivery detection: scan destination chain for Transfer events
			if matches!(transfer.status, BridgeTransferStatus::Relaying)
				&& transfer.dest_scan_from_block.is_some()
				&& transfer.dest_token_address.is_some()
			{
				let dest_token_addr = transfer.dest_token_address.as_ref().unwrap();
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
					let a = U256::from_str_radix(&a, 10).unwrap_or(U256::ZERO);
					let b = U256::from_str_radix(&b, 10).unwrap_or(U256::ZERO);
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
					recipient: Address::ZERO,
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
						self.bridge_service
							.set_cooldown(&pair.pair_id, config.cooldown_seconds)
							.await?;
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
