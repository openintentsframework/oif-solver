//! Rebalance monitor background task.
//!
//! Spawned inside `SolverEngine::run()` where `transaction_semaphore` is in scope.
//! Continuously:
//! 1. Advances pending transfers through the state machine
//! 2. Checks balances against configured thresholds
//! 3. Auto-triggers rebalance when thresholds are breached (respecting safety guards)
//!
//! TODO: Implement full threshold checking and auto-trigger logic.

use crate::BridgeService;
use solver_storage::StorageService;
use std::sync::Arc;
use tokio::sync::{watch, RwLock, Semaphore};

/// Background rebalance monitor.
pub struct RebalanceMonitor {
	bridge_service: Arc<BridgeService>,
	delivery: Arc<solver_delivery::DeliveryService>,
	dynamic_config: Arc<RwLock<solver_config::Config>>,
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
			// Read interval from hot-reloaded config
			let interval_seconds = {
				let config = self.dynamic_config.read().await;
				config
					.rebalance
					.as_ref()
					.map(|r| r.monitor_interval_seconds)
					.unwrap_or(60)
			};

			tokio::select! {
				_ = tokio::time::sleep(std::time::Duration::from_secs(interval_seconds)) => {
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
		// Read current config
		let config = self.dynamic_config.read().await;
		let rebalance_config = match config.rebalance.as_ref() {
			Some(c) if c.enabled => c,
			_ => return Ok(()), // Disabled, skip
		};

		// TODO: Implement full tick logic:
		// 1. Advance pending transfers (check_status on each active transfer)
		// 2. For each configured pair:
		//    a. Query on-chain balances
		//    b. Compute effective_balance = on_chain - outbound_in_flight
		//    c. Check against thresholds
		//    d. If outside band and all safety checks pass, trigger rebalance
		let _ = rebalance_config;

		Ok(())
	}
}
