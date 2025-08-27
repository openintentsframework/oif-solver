//! Settlement monitoring for filled orders.
//!
//! Monitors orders after fill confirmation to determine when they are ready
//! for claiming, retrieving attestations and checking claim conditions.

use crate::engine::event_bus::EventBus;
use crate::state::OrderStateMachine;
use solver_settlement::SettlementService;
use solver_types::{
	truncate_id, Order, OrderStatus, SettlementEvent, SolverEvent, TransactionHash,
};
use std::sync::Arc;

/// Monitor for tracking settlement readiness of filled orders.
///
/// The SettlementMonitor watches filled orders to determine when they are ready
/// for claiming by retrieving attestations and checking claim conditions periodically
/// until the order is claimable or a timeout is reached.
pub struct SettlementMonitor {
	settlement: Arc<SettlementService>,
	state_machine: Arc<OrderStateMachine>,
	event_bus: EventBus,
	timeout_minutes: u64,
}

impl SettlementMonitor {
	pub fn new(
		settlement: Arc<SettlementService>,
		state_machine: Arc<OrderStateMachine>,
		event_bus: EventBus,
		timeout_minutes: u64,
	) -> Self {
		Self {
			settlement,
			state_machine,
			event_bus,
			timeout_minutes,
		}
	}

	/// Monitors an order for claim readiness after fill confirmation
	pub async fn monitor_claim_readiness(&self, order: Order, tx_hash: TransactionHash) {
		let settlement = &self.settlement;

		// Retrieve and extract proof
		let fill_proof = match settlement.get_attestation(&order, &tx_hash).await {
			Ok(proof) => proof,
			Err(e) => {
				tracing::error!(
					order_id = %truncate_id(&order.id),
					error = %e,
					"Failed to get attestation for fill transaction"
				);
				return;
			},
		};

		// Store the fill proof
		if let Err(e) = self
			.state_machine
			.set_fill_proof(&order.id, fill_proof.clone())
			.await
		{
			tracing::error!(
				order_id = %truncate_id(&order.id),
				error = %e,
				"Failed to store fill proof"
			);
			return;
		}

		// Monitor claim readiness
		let monitoring_timeout = tokio::time::Duration::from_secs(self.timeout_minutes * 60);
		let check_interval = tokio::time::Duration::from_secs(3);
		let start_time = tokio::time::Instant::now();

		loop {
			// Check if we've exceeded the timeout
			if start_time.elapsed() > monitoring_timeout {
				tracing::warn!(
					order_id = %truncate_id(&order.id),
					"Claim readiness monitoring timeout reached after {} minutes",
					self.timeout_minutes
				);
				break;
			}

			// Check if we can claim
			if settlement.can_claim(&order, &fill_proof).await {
				// Update status to Settled
				self.state_machine
					.transition_order_status(&order.id, OrderStatus::Settled)
					.await
					.ok();

				// Always emit PreClaimReady with optional transaction
				let pre_claim_tx = match settlement
					.generate_pre_claim_transaction(&order, &fill_proof)
					.await
				{
					Ok(tx) => tx,
					Err(e) => {
						tracing::error!(
							order_id = %truncate_id(&order.id),
							error = %e,
							"Failed to generate pre-claim transaction, will proceed directly without the pre-claim transaction"
						);
						None
					},
				};

				self.event_bus
					.publish(SolverEvent::Settlement(SettlementEvent::PreClaimReady {
						order_id: order.id,
						transaction: pre_claim_tx,
					}))
					.ok();
				break;
			}

			// Wait before next check
			tokio::time::sleep(check_interval).await;
		}
	}
}
