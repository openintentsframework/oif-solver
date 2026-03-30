//! Rebalance monitor background task.
//!
//! Spawned inside `SolverEngine::run()` where `transaction_semaphore` is in scope.
//! Continuously:
//! 1. Advances pending transfers through the state machine
//! 2. Checks balances against configured thresholds
//! 3. Auto-triggers rebalance when thresholds are breached (respecting safety guards)

use crate::types::{BridgeRequest, BridgeTransferStatus, RebalanceTrigger};
use crate::BridgeService;
use alloy_primitives::{Address, U256};
use solver_config::RebalanceConfig;
use solver_storage::StorageService;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, RwLock, Semaphore};

/// Minimum deviation band bps allowed (config guardrail).
const MIN_DEVIATION_BAND_BPS: u32 = 500;

/// Timeout for Submitted state (30 min) before NeedsIntervention.
const SUBMITTED_TIMEOUT_SECS: u64 = 30 * 60;

/// Timeout for Relaying state (30 min) before NeedsIntervention.
const RELAYING_TIMEOUT_SECS: u64 = 30 * 60;

/// Timeout for PendingRedemption state (24h) before NeedsIntervention.
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
}

impl RebalanceMonitor {
	pub fn new(
		bridge_service: Arc<BridgeService>,
		delivery: Arc<solver_delivery::DeliveryService>,
		dynamic_config: Arc<RwLock<solver_config::Config>>,
		storage: Arc<StorageService>,
		transaction_semaphore: Arc<Semaphore>,
	) -> Self {
		Self {
			bridge_service,
			delivery,
			dynamic_config,
			storage,
			transaction_semaphore,
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
		drop(config); // Release the read lock before doing async work

		// Step 1: Advance pending transfers
		self.advance_pending_transfers(&rebalance_config).await?;

		// Step 2: Check thresholds and auto-trigger if needed
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
			// Check for timeouts first
			let age = now.saturating_sub(transfer.updated_at);

			match &transfer.status {
				BridgeTransferStatus::Submitted if age > SUBMITTED_TIMEOUT_SECS => {
					tracing::warn!(
						transfer_id = %transfer.id,
						pair = %transfer.pair_symbol,
						age_secs = age,
						"Transfer stuck in Submitted state, moving to NeedsIntervention"
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
						pair = %transfer.pair_symbol,
						age_secs = age,
						"Transfer stuck in Relaying state, moving to NeedsIntervention"
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
				BridgeTransferStatus::PendingRedemption if age > PENDING_REDEMPTION_TIMEOUT_SECS => {
					tracing::warn!(
						transfer_id = %transfer.id,
						pair = %transfer.pair_symbol,
						age_secs = age,
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
						pair = %transfer.pair_symbol,
						retries,
						"Redeem retry limit exhausted, moving to NeedsIntervention"
					);
					self.bridge_service
						.update_transfer(
							&mut transfer,
							BridgeTransferStatus::NeedsIntervention(
								format!("Vault redeem failed after {retries} attempts"),
							),
						)
						.await?;
					continue;
				},
				_ => {},
			}

			// Poll the bridge implementation for status updates
			let new_status = bridge_impl.check_status(&transfer).await?;
			if new_status != transfer.status {
				tracing::info!(
					transfer_id = %transfer.id,
					pair = %transfer.pair_symbol,
					old_status = ?transfer.status,
					new_status = ?new_status,
					"Transfer status changed"
				);

				// If transitioning to Relaying, record the destination scan anchor
				if matches!(new_status, BridgeTransferStatus::Relaying)
					&& transfer.dest_scan_from_block.is_none()
				{
					// TODO: Query destination chain head block and store as dest_scan_from_block
				}

				self.bridge_service
					.update_transfer(&mut transfer, new_status)
					.await?;
			}

			transfer.last_status_poll_at = Some(now);
		}

		Ok(())
	}

	/// Check balances against thresholds and auto-trigger rebalances.
	async fn check_thresholds_and_trigger(
		&self,
		config: &RebalanceConfig,
	) -> Result<(), crate::BridgeError> {
		// Safety: check max pending transfers
		let active_count = self.bridge_service.active_transfer_count().await?;
		if active_count >= config.max_pending_transfers as usize {
			tracing::debug!(
				active = active_count,
				max = config.max_pending_transfers,
				"Max pending transfers reached, skipping threshold check"
			);
			return Ok(());
		}

		for pair in &config.pairs {
			// Config guardrail: skip if deviation band is too narrow
			if pair.deviation_band_bps < MIN_DEVIATION_BAND_BPS {
				tracing::warn!(
					pair = %pair.symbol,
					band_bps = pair.deviation_band_bps,
					min_bps = MIN_DEVIATION_BAND_BPS,
					"Deviation band too narrow, skipping pair"
				);
				continue;
			}

			// Check cooldown
			if self
				.bridge_service
				.is_cooldown_active(&pair.symbol)
				.await?
			{
				tracing::debug!(pair = %pair.symbol, "Cooldown active, skipping");
				continue;
			}

			// Check if any transfer for this pair is active or in NeedsIntervention
			let pair_transfers = self
				.bridge_service
				.get_active_transfers_for_pair(&pair.symbol)
				.await?;
			if !pair_transfers.is_empty() {
				tracing::debug!(
					pair = %pair.symbol,
					active = pair_transfers.len(),
					"Active transfers exist for pair, skipping"
				);
				continue;
			}

			// Query balances for both sides
			let balance_a = self
				.get_token_balance(pair.chain_a.chain_id, &pair.chain_a.token_address)
				.await;
			let balance_b = self
				.get_token_balance(pair.chain_b.chain_id, &pair.chain_b.token_address)
				.await;

			let (balance_a, balance_b) = match (balance_a, balance_b) {
				(Ok(a), Ok(b)) => (a, b),
				(Err(e), _) | (_, Err(e)) => {
					tracing::warn!(
						pair = %pair.symbol,
						"Failed to query balance: {e}, skipping"
					);
					continue;
				},
			};

			// Parse thresholds (all in nominal units)
			let target_a = U256::from_str_radix(&pair.target_balance_a, 10).unwrap_or(U256::ZERO);
			let target_b = U256::from_str_radix(&pair.target_balance_b, 10).unwrap_or(U256::ZERO);
			let max_amount =
				U256::from_str_radix(&pair.max_bridge_amount, 10).unwrap_or(U256::MAX);

			let band = U256::from(pair.deviation_band_bps);
			let bps_base = U256::from(10_000u64);

			// Compute bounds for side A
			let lower_a = target_a * (bps_base - band) / bps_base;
			let upper_a = target_a * (bps_base + band) / bps_base;

			// Compute bounds for side B
			let lower_b = target_b * (bps_base - band) / bps_base;
			let upper_b = target_b * (bps_base + band) / bps_base;

			// Determine direction
			let direction = if balance_a < lower_a && balance_b > lower_b {
				// Side A needs funds — bridge from B to A
				let deficit = target_a.saturating_sub(balance_a);
				let amount = deficit.min(max_amount);
				Some((
					pair.chain_b.chain_id,
					pair.chain_a.chain_id,
					pair.chain_b.token_address.clone(),
					pair.chain_a.token_address.clone(),
					amount,
				))
			} else if balance_b < lower_b && balance_a > lower_a {
				// Side B needs funds — bridge from A to B
				let deficit = target_b.saturating_sub(balance_b);
				let amount = deficit.min(max_amount);
				Some((
					pair.chain_a.chain_id,
					pair.chain_b.chain_id,
					pair.chain_a.token_address.clone(),
					pair.chain_b.token_address.clone(),
					amount,
				))
			} else if balance_a > upper_a {
				// Side A has surplus — bridge from A to B
				let surplus = balance_a.saturating_sub(target_a);
				let amount = surplus.min(max_amount);
				Some((
					pair.chain_a.chain_id,
					pair.chain_b.chain_id,
					pair.chain_a.token_address.clone(),
					pair.chain_b.token_address.clone(),
					amount,
				))
			} else if balance_b > upper_b {
				// Side B has surplus — bridge from B to A
				let surplus = balance_b.saturating_sub(target_b);
				let amount = surplus.min(max_amount);
				Some((
					pair.chain_b.chain_id,
					pair.chain_a.chain_id,
					pair.chain_b.token_address.clone(),
					pair.chain_a.token_address.clone(),
					amount,
				))
			} else {
				None // Within band
			};

			if balance_a < lower_a && balance_b < lower_b {
				tracing::warn!(
					pair = %pair.symbol,
					balance_a = %balance_a,
					balance_b = %balance_b,
					lower_a = %lower_a,
					lower_b = %lower_b,
					"Both sides below lower bound, cannot rebalance"
				);
				continue;
			}

			if let Some((source_chain, dest_chain, source_token, dest_token, amount)) = direction {
				if amount.is_zero() {
					continue;
				}

				// Safety: check native gas reserve on source chain
				if let Some(reserve_str) = config.min_native_gas_reserve.get(&source_chain) {
					if let Ok(reserve) = U256::from_str_radix(reserve_str, 10) {
						match self.get_native_balance(source_chain).await {
							Ok(native_balance) if native_balance < reserve => {
								tracing::warn!(
									pair = %pair.symbol,
									chain = source_chain,
									native_balance = %native_balance,
									reserve = %reserve,
									"Native gas below reserve, skipping"
								);
								continue;
							},
							Err(e) => {
								tracing::warn!(
									pair = %pair.symbol,
									chain = source_chain,
									"Failed to check native balance: {e}, skipping"
								);
								continue;
							},
							_ => {},
						}
					}
				}

				// TODO: Implement fee guardrail check (max_fee_bps).
				// Requires calling estimate_fee() on the bridge implementation,
				// then comparing fee/amount * 10000 against config.max_fee_bps.

				// Execute the rebalance
				let source_token_addr = Self::parse_address(&source_token)?;
				let dest_token_addr = Self::parse_address(&dest_token)?;

				let request = BridgeRequest {
					pair_symbol: pair.symbol.clone(),
					source_chain,
					dest_chain,
					source_token: source_token_addr,
					dest_token: dest_token_addr,
					amount,
					min_amount: None,
					recipient: Address::ZERO, // Solver address (set by implementation)
				};

				tracing::info!(
					pair = %pair.symbol,
					source = source_chain,
					dest = dest_chain,
					amount = %amount,
					"Auto-triggering rebalance"
				);

				// Acquire transaction semaphore to prevent nonce conflicts
				let _permit = self.transaction_semaphore.acquire().await.map_err(|e| {
					crate::BridgeError::TransactionFailed(format!(
						"Failed to acquire transaction semaphore: {e}"
					))
				})?;

				match self
					.bridge_service
					.rebalance_token(&config.implementation, &request, RebalanceTrigger::Auto)
					.await
				{
					Ok(transfer) => {
						tracing::info!(
							transfer_id = %transfer.id,
							pair = %pair.symbol,
							"Auto-rebalance initiated"
						);
						// Set cooldown
						self.bridge_service
							.set_cooldown(&pair.symbol, config.cooldown_seconds)
							.await?;
					},
					Err(e) => {
						tracing::error!(
							pair = %pair.symbol,
							"Auto-rebalance failed: {e}"
						);
					},
				}
			}
		}

		Ok(())
	}

	/// Query ERC-20 token balance on a chain.
	async fn get_token_balance(
		&self,
		chain_id: u64,
		token_address: &str,
	) -> Result<U256, crate::BridgeError> {
		let solver_address = "0x0000000000000000000000000000000000000000"; // TODO: get from account service

		let balance_str = self
			.delivery
			.get_balance(chain_id, solver_address, Some(token_address))
			.await
			.map_err(|e| crate::BridgeError::Delivery(format!("Balance query failed: {e}")))?;

		U256::from_str_radix(&balance_str, 10)
			.map_err(|e| crate::BridgeError::Delivery(format!("Invalid balance value: {e}")))
	}

	/// Query native gas balance on a chain.
	async fn get_native_balance(
		&self,
		chain_id: u64,
	) -> Result<U256, crate::BridgeError> {
		let solver_address = "0x0000000000000000000000000000000000000000"; // TODO: get from account service

		let balance_str = self
			.delivery
			.get_balance(chain_id, solver_address, None)
			.await
			.map_err(|e| crate::BridgeError::Delivery(format!("Native balance query failed: {e}")))?;

		U256::from_str_radix(&balance_str, 10)
			.map_err(|e| crate::BridgeError::Delivery(format!("Invalid balance value: {e}")))
	}

	/// Parse a hex address string.
	fn parse_address(addr: &str) -> Result<Address, crate::BridgeError> {
		let addr = addr.strip_prefix("0x").unwrap_or(addr);
		let bytes = hex::decode(addr)
			.map_err(|e| crate::BridgeError::Config(format!("Invalid address: {e}")))?;
		let arr: [u8; 20] = bytes
			.try_into()
			.map_err(|_| crate::BridgeError::Config("Address must be 20 bytes".to_string()))?;
		Ok(Address::from(arr))
	}
}

/// Validate rebalance config at startup (config guardrails).
pub fn validate_rebalance_config(config: &RebalanceConfig) -> Vec<String> {
	let mut warnings = Vec::new();

	for pair in &config.pairs {
		if pair.deviation_band_bps < MIN_DEVIATION_BAND_BPS {
			warnings.push(format!(
				"Pair {}: deviation_band_bps ({}) is below minimum ({}), will be skipped by monitor",
				pair.symbol, pair.deviation_band_bps, MIN_DEVIATION_BAND_BPS
			));
		}

		let target_a = U256::from_str_radix(&pair.target_balance_a, 10).unwrap_or(U256::ZERO);
		let max_amount =
			U256::from_str_radix(&pair.max_bridge_amount, 10).unwrap_or(U256::ZERO);

		if !max_amount.is_zero() && max_amount > target_a && !target_a.is_zero() {
			warnings.push(format!(
				"Pair {}: max_bridge_amount ({}) > target_balance_a ({}), likely misconfiguration",
				pair.symbol, pair.max_bridge_amount, pair.target_balance_a
			));
		}
	}

	if config.cooldown_seconds < 300 {
		warnings.push(format!(
			"cooldown_seconds ({}) is shorter than typical bridge latency (~300s for LayerZero)",
			config.cooldown_seconds
		));
	}

	if config.max_pending_transfers == 0 && config.enabled {
		warnings.push(
			"max_pending_transfers is 0 but rebalancing is enabled — no transfers will execute"
				.to_string(),
		);
	}

	warnings
}
