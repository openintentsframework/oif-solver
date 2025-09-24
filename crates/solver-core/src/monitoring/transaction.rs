//! Transaction monitoring for pending blockchain transactions.
//!
//! Polls transaction status at regular intervals until confirmation or failure,
//! publishing appropriate events to the event bus for further processing.

use crate::engine::event_bus::EventBus;
use alloy_primitives::hex;
use solver_delivery::{DeliveryError, DeliveryService};
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
		let monitoring_timeout = tokio::time::Duration::from_secs(self.timeout_minutes * 60);
		// Get poll interval from delivery service
		let poll_interval_seconds = self.delivery.poll_interval_seconds();
		let poll_interval = tokio::time::Duration::from_secs(poll_interval_seconds);

		let start_time = tokio::time::Instant::now();

		tracing::debug!(
			order_id = %truncate_id(&order_id),
			poll_interval_secs = poll_interval_seconds,
			timeout_minutes = self.timeout_minutes,
			"Starting transaction monitoring"
		);

		loop {
			// Check if we've exceeded the timeout
			if start_time.elapsed() > monitoring_timeout {
				tracing::warn!(
					order_id = %truncate_id(&order_id),
					tx_hash = %truncate_id(&hex::encode(&tx_hash.0)),
					tx_type = ?tx_type,
					"Transaction monitoring timeout reached after {} minutes",
					self.timeout_minutes
				);
				break;
			}

			// Try to get transaction status
			match self.delivery.get_status(&tx_hash, tx_chain_id).await {
				Ok(true) => {
					// Transaction is confirmed and successful
					match self
						.delivery
						.confirm_with_default(&tx_hash, tx_chain_id)
						.await
					{
						Ok(receipt) => {
							tracing::info!("Confirmed",);
							self.event_bus
								.publish(SolverEvent::Delivery(
									DeliveryEvent::TransactionConfirmed {
										order_id,
										tx_hash: tx_hash.clone(),
										tx_type,
										receipt,
									},
								))
								.ok();
						},
						Err(e) => {
							tracing::error!(
								order_id = %truncate_id(&order_id),
								tx_hash = %truncate_id(&hex::encode(&tx_hash.0)),
								tx_type = ?tx_type,
								error = %e,
								"Failed to wait for confirmations"
							);
						},
					}
					break;
				},
				Ok(false) => {
					// Transaction failed
					self.event_bus
						.publish(SolverEvent::Delivery(DeliveryEvent::TransactionFailed {
							order_id,
							tx_hash: tx_hash.clone(),
							tx_type,
							error: "Transaction reverted".to_string(),
						}))
						.ok();
					break;
				},
				Err(e) => {
					// Transaction not yet confirmed or error
					let message = match &e {
						DeliveryError::NoImplementationAvailable => {
							"Waiting for transaction to be mined"
						},
						_ => "Checking transaction status",
					};

					tracing::info!(
						elapsed_secs = start_time.elapsed().as_secs(),
						reason = e.to_string(),
						"{}",
						message
					);
				},
			}

			tokio::time::sleep(poll_interval).await;
		}
	}
}
