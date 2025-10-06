//! Transaction monitoring for pending blockchain transactions.
//!
//! Polls transaction status at regular intervals until confirmation or failure,
//! publishing appropriate events to the event bus for further processing.

use crate::engine::event_bus::EventBus;
use alloy_primitives::hex;
use solver_delivery::DeliveryService;
use solver_types::{truncate_id, DeliveryEvent, SolverEvent, TransactionHash, TransactionType};
use std::sync::Arc;
use tracing::instrument;

/// Monitor for tracking pending blockchain transactions.
///
/// The TransactionMonitor polls transaction status at regular intervals
/// until confirmation or failure, publishing appropriate events to the
/// event bus for further processing by the transaction handler.
pub struct TransactionMonitor {
	delivery: Arc<DeliveryService>,
	event_bus: EventBus,
	timeout_minutes: u64,
}

impl TransactionMonitor {
	pub fn new(delivery: Arc<DeliveryService>, event_bus: EventBus, timeout_minutes: u64) -> Self {
		Self {
			delivery,
			event_bus,
			timeout_minutes,
		}
	}

	/// Monitors a pending transaction until it is confirmed or fails.
	#[instrument(skip_all, fields(order_id = %truncate_id(&order_id), tx_hash = %truncate_id(&hex::encode(&tx_hash.0)), tx_type = ?tx_type))]
	pub async fn monitor(
		&self,
		order_id: String,
		tx_hash: TransactionHash,
		tx_type: TransactionType,
		tx_chain_id: u64,
	) {
		tracing::debug!(
			order_id = %truncate_id(&order_id),
			timeout_minutes = self.timeout_minutes,
			"Starting transaction monitoring"
		);

		// Use confirm_with_default directly - it handles all the waiting and polling internally
		match self
			.delivery
			.confirm_with_default(&tx_hash, tx_chain_id)
			.await
		{
			Ok(receipt) => {
				tracing::info!("Transaction confirmed");
				self.event_bus
					.publish(SolverEvent::Delivery(DeliveryEvent::TransactionConfirmed {
						order_id,
						tx_hash,
						tx_type,
						receipt,
					}))
					.ok();
			},
			Err(e) => {
				tracing::error!(
					order_id = %truncate_id(&order_id),
					tx_hash = %truncate_id(&hex::encode(&tx_hash.0)),
					tx_type = ?tx_type,
					error = %e,
					"Transaction failed or timed out"
				);
				self.event_bus
					.publish(SolverEvent::Delivery(DeliveryEvent::TransactionFailed {
						order_id,
						tx_hash,
						tx_type,
						error: e.to_string(),
					}))
					.ok();
			},
		}
	}
}
