//! Transaction monitoring for pending blockchain transactions.
//!
//! Polls transaction status at regular intervals until confirmation or failure,
//! publishing appropriate events to the event bus for further processing.

use crate::engine::event_bus::EventBus;
use crate::utils::truncate_id;
use alloy_primitives::hex;
use solver_delivery::{DeliveryError, DeliveryService};
use solver_types::{DeliveryEvent, SolverEvent, TransactionHash, TransactionType};
use std::sync::Arc;
use tracing::instrument;

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
	) {
		let monitoring_timeout = tokio::time::Duration::from_secs(self.timeout_minutes * 60);
		let poll_interval = tokio::time::Duration::from_secs(3);

		let start_time = tokio::time::Instant::now();

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
			match self.delivery.get_status(&tx_hash).await {
				Ok(true) => {
					// Transaction is confirmed and successful
					match self.delivery.confirm_with_default(&tx_hash).await {
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
						}
						Err(e) => {
							tracing::error!(
								order_id = %truncate_id(&order_id),
								tx_hash = %truncate_id(&hex::encode(&tx_hash.0)),
								tx_type = ?tx_type,
								error = %e,
								"Failed to wait for confirmations"
							);
						}
					}
					break;
				}
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
				}
				Err(e) => {
					// Transaction not yet confirmed or error
					let message = match &e {
						DeliveryError::NoProviderAvailable => "Waiting for transaction to be mined",
						_ => "Checking transaction status",
					};

					tracing::info!(elapsed_secs = start_time.elapsed().as_secs(), "{}", message);
				}
			}

			tokio::time::sleep(poll_interval).await;
		}
	}
}
