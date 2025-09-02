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

					tracing::info!(elapsed_secs = start_time.elapsed().as_secs(), "{}", message);
				},
			}

			tokio::time::sleep(poll_interval).await;
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use mockall::predicate::*;
	use solver_delivery::MockDeliveryInterface;
	use solver_types::{TransactionReceipt, TransactionType};
	use std::{collections::HashMap, time::Duration};
	use tokio::sync::broadcast;

	fn create_test_tx_hash() -> TransactionHash {
		TransactionHash(vec![0xab; 32])
	}

	fn create_test_receipt(success: bool) -> TransactionReceipt {
		TransactionReceipt {
			hash: create_test_tx_hash(),
			block_number: 12345,
			success,
		}
	}

	async fn create_test_monitor_with_mock<F>(
		setup_delivery: F,
		timeout_minutes: u64,
	) -> (TransactionMonitor, broadcast::Receiver<SolverEvent>)
	where
		F: FnOnce(&mut MockDeliveryInterface),
	{
		let mut mock_delivery = MockDeliveryInterface::new();
		setup_delivery(&mut mock_delivery);

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				137u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
		));

		let event_bus = EventBus::new(100);
		let receiver = event_bus.subscribe();

		let monitor = TransactionMonitor::new(delivery, event_bus, timeout_minutes);

		(monitor, receiver)
	}

	#[test]
	fn test_new_transaction_monitor() {
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1));
		let event_bus = EventBus::new(100);
		let timeout_minutes = 30;

		let monitor = TransactionMonitor::new(delivery, event_bus, timeout_minutes);

		assert_eq!(monitor.timeout_minutes, 30);
	}

	#[tokio::test]
	async fn test_monitor_transaction_confirmed_success() {
		let order_id = "test_order_123".to_string();
		let tx_hash = create_test_tx_hash();
		let tx_type = TransactionType::Fill;
		let tx_chain_id = 137u64;

		let (monitor, mut event_rx) = create_test_monitor_with_mock(
			|mock_delivery| {
				// First call returns true (transaction confirmed)
				mock_delivery
					.expect_get_receipt()
					.with(eq(tx_hash.clone()), eq(tx_chain_id))
					.times(1)
					.returning(move |_, _| Box::pin(async move { Ok(create_test_receipt(true)) }));

				// Then confirm_with_default is called
				mock_delivery
					.expect_wait_for_confirmation()
					.with(eq(tx_hash.clone()), eq(tx_chain_id), eq(1u64))
					.times(1)
					.returning(move |_, _, _| {
						Box::pin(async move { Ok(create_test_receipt(true)) })
					});
			},
			30,
		)
		.await;

		let order_id_clone = order_id.clone();
		let tx_hash_clone = tx_hash.clone();

		// Start monitoring in a separate task
		let monitor_task = tokio::spawn(async move {
			monitor
				.monitor(order_id_clone, tx_hash_clone, tx_type, tx_chain_id)
				.await;
		});

		// Wait for the event
		let event = tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
			.await
			.expect("Should receive event within timeout")
			.expect("Should receive valid event");

		// Verify the event
		match event {
			SolverEvent::Delivery(DeliveryEvent::TransactionConfirmed {
				order_id: event_order_id,
				tx_hash: event_tx_hash,
				tx_type: event_tx_type,
				receipt: event_receipt,
			}) => {
				assert_eq!(event_order_id, order_id);
				assert_eq!(event_tx_hash, tx_hash);
				assert_eq!(event_tx_type, tx_type);
				assert!(event_receipt.success);
			},
			_ => panic!("Expected TransactionConfirmed event"),
		}

		// Wait for the monitor task to complete
		monitor_task.await.expect("Monitor task should complete");
	}

	#[tokio::test]
	async fn test_monitor_transaction_failed() {
		let order_id = "test_order_123".to_string();
		let tx_hash = create_test_tx_hash();
		let tx_type = TransactionType::Fill;
		let tx_chain_id = 137u64;

		let (monitor, mut event_rx) = create_test_monitor_with_mock(
			|mock_delivery| {
				// Return false (transaction failed)
				mock_delivery
					.expect_get_receipt()
					.with(eq(tx_hash.clone()), eq(tx_chain_id))
					.times(1)
					.returning(move |_, _| Box::pin(async move { Ok(create_test_receipt(false)) }));
			},
			30,
		)
		.await;

		let order_id_clone = order_id.clone();
		let tx_hash_clone = tx_hash.clone();

		// Start monitoring in a separate task
		let monitor_task = tokio::spawn(async move {
			monitor
				.monitor(order_id_clone, tx_hash_clone, tx_type, tx_chain_id)
				.await;
		});

		// Wait for the event
		let event = tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
			.await
			.expect("Should receive event within timeout")
			.expect("Should receive valid event");

		// Verify the event
		match event {
			SolverEvent::Delivery(DeliveryEvent::TransactionFailed {
				order_id: event_order_id,
				tx_hash: event_tx_hash,
				tx_type: event_tx_type,
				error,
			}) => {
				assert_eq!(event_order_id, order_id);
				assert_eq!(event_tx_hash, tx_hash);
				assert_eq!(event_tx_type, tx_type);
				assert_eq!(error, "Transaction reverted");
			},
			_ => panic!("Expected TransactionFailed event"),
		}

		// Wait for the monitor task to complete
		monitor_task.await.expect("Monitor task should complete");
	}

	#[tokio::test]
	async fn test_monitor_different_transaction_types() {
		let test_cases = vec![
			TransactionType::Prepare,
			TransactionType::Fill,
			TransactionType::PostFill,
			TransactionType::PreClaim,
			TransactionType::Claim,
		];

		for tx_type in test_cases {
			let order_id = format!("test_order_{:?}", tx_type);
			let tx_hash = create_test_tx_hash();
			let tx_chain_id = 137u64;

			let (monitor, mut event_rx) = create_test_monitor_with_mock(
				|mock_delivery| {
					mock_delivery
						.expect_get_receipt()
						.with(eq(tx_hash.clone()), eq(tx_chain_id))
						.times(1)
						.returning(move |_, _| {
							Box::pin(async move { Ok(create_test_receipt(true)) })
						});

					mock_delivery
						.expect_wait_for_confirmation()
						.with(eq(tx_hash.clone()), eq(tx_chain_id), eq(1u64))
						.times(1)
						.returning(move |_, _, _| {
							Box::pin(async move { Ok(create_test_receipt(true)) })
						});
				},
				30,
			)
			.await;

			let order_id_clone = order_id.clone();
			let tx_hash_clone = tx_hash.clone();

			// Start monitoring in a separate task
			let monitor_task = tokio::spawn(async move {
				monitor
					.monitor(order_id_clone, tx_hash_clone, tx_type, tx_chain_id)
					.await;
			});

			// Wait for the event
			let event = tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
				.await
				.expect("Should receive event within timeout")
				.expect("Should receive valid event");

			// Verify the event has the correct transaction type
			match event {
				SolverEvent::Delivery(DeliveryEvent::TransactionConfirmed {
					tx_type: event_tx_type,
					..
				}) => {
					assert_eq!(event_tx_type, tx_type);
				},
				_ => panic!("Expected TransactionConfirmed event for {:?}", tx_type),
			}

			// Wait for the monitor task to complete
			monitor_task.await.expect("Monitor task should complete");
		}
	}
}
