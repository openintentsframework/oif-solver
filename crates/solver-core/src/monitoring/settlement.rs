//! Settlement monitoring for filled orders.
//!
//! Monitors orders after fill confirmation (and optional post-fill transaction)
//! to determine when they are ready for claiming, retrieving attestations and
//! checking claim conditions before initiating the claim process.

use crate::engine::event_bus::EventBus;
use crate::state::OrderStateMachine;
use solver_delivery::DeliveryService;
use solver_settlement::{ActionRequired, SettlementReadiness, SettlementService};
use solver_types::{
	current_timestamp, truncate_id, NetworksConfig, Order, OrderStatus, SettlementEvent,
	SolverEvent, TransactionHash,
};
use std::sync::Arc;

/// Monitor for tracking settlement readiness of filled orders.
///
/// The SettlementMonitor watches filled orders to determine when they are ready
/// for claiming by retrieving attestations and checking claim conditions periodically
/// until the order is claimable or a timeout is reached.
///
/// On each poll it also checks whether the L2 block-hash buffer needs to be
/// advanced (via `push_if_needed`) before a storage proof can be generated.
pub struct SettlementMonitor {
	settlement: Arc<SettlementService>,
	state_machine: Arc<OrderStateMachine>,
	event_bus: EventBus,
	timeout_minutes: u64,
	delivery: Arc<DeliveryService>,
	networks: NetworksConfig,
}

impl SettlementMonitor {
	pub fn new(
		settlement: Arc<SettlementService>,
		state_machine: Arc<OrderStateMachine>,
		event_bus: EventBus,
		timeout_minutes: u64,
		delivery: Arc<DeliveryService>,
		networks: NetworksConfig,
	) -> Self {
		Self {
			settlement,
			state_machine,
			event_bus,
			timeout_minutes,
			delivery,
			networks,
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
		// Get poll interval from settlement service
		let poll_interval_seconds = self.settlement.poll_interval_seconds();
		let check_interval = tokio::time::Duration::from_secs(poll_interval_seconds);
		let start_time = tokio::time::Instant::now();

		tracing::debug!(
			order_id = %truncate_id(&order.id),
			poll_interval_secs = poll_interval_seconds,
			timeout_minutes = self.timeout_minutes,
			"Starting settlement monitoring"
		);

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

			// Check whether the L2 buffer needs to be advanced for this order.
			if let Some((direction, required_block)) =
				self.settlement.buffer_coverage_check(&order).await
			{
				self.settlement
					.push_if_needed(&direction, required_block, &self.delivery, &self.networks)
					.await;
			}

			let mut next_check_delay = check_interval;

			match settlement.readiness(&order, &fill_proof).await {
				SettlementReadiness::Ready => {
					// Update status to Settled
					self.state_machine
						.transition_order_status(&order.id, OrderStatus::Settled)
						.await
						.ok();

					// Emit PreClaimReady event - handler will generate transaction if needed
					self.event_bus
						.publish(SolverEvent::Settlement(SettlementEvent::PreClaimReady {
							order_id: order.id,
						}))
						.ok();
					break;
				},
				SettlementReadiness::Waiting(reason) => match &reason {
					solver_settlement::WaitingReason::WaitingForProofDelay { until } => {
						let remaining_proof_delay_secs =
							until.saturating_sub(current_timestamp()).max(1);
						let remaining_monitoring_time =
							monitoring_timeout.saturating_sub(start_time.elapsed());
						next_check_delay =
							tokio::time::Duration::from_secs(remaining_proof_delay_secs)
								.min(remaining_monitoring_time);

						tracing::debug!(
							order_id = %truncate_id(&order.id),
							?reason,
							sleep_secs = next_check_delay.as_secs(),
							"Settlement waiting on proof delay; backing off monitor"
						);
					},
					solver_settlement::WaitingReason::ProofServiceNotReady
					| solver_settlement::WaitingReason::RpcUnavailable
					| solver_settlement::WaitingReason::StorageUnavailable => {
						tracing::warn!(
							order_id = %truncate_id(&order.id),
							?reason,
							"Settlement blocked by infrastructure issue"
						);
					},
					_ => {
						tracing::debug!(
							order_id = %truncate_id(&order.id),
							?reason,
							"Settlement not ready yet"
						);
					},
				},
				SettlementReadiness::NeedsAction(ActionRequired::BufferBehind {
					direction,
					required_block,
				}) => {
					self.settlement
						.push_if_needed(&direction, required_block, &self.delivery, &self.networks)
						.await;
				},
				SettlementReadiness::PermanentFailure(error) => {
					tracing::error!(
						order_id = %truncate_id(&order.id),
						error = %error,
						"Settlement monitoring hit a permanent failure"
					);
					break;
				},
			}

			// Wait before next check
			if !next_check_delay.is_zero() {
				tokio::time::sleep(next_check_delay).await;
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use mockall::predicate::eq;
	use solver_delivery::DeliveryService;
	use solver_settlement::{
		MockSettlementInterface, OracleConfig, OracleSelectionStrategy, SettlementReadiness,
		SettlementService,
	};
	use solver_storage::{MockStorageInterface, StorageService};
	use solver_types::{
		utils::tests::builders::OrderBuilder, FillProof, NetworksConfig, Order, SettlementEvent,
		SolverEvent,
	};
	use std::{collections::HashMap, sync::Arc, time::Duration};
	use tokio::sync::broadcast;

	fn create_test_order() -> Order {
		OrderBuilder::new().build()
	}

	fn create_test_tx_hash() -> TransactionHash {
		TransactionHash(vec![0xab; 32])
	}

	fn create_test_fill_proof() -> FillProof {
		FillProof {
			tx_hash: create_test_tx_hash(),
			block_number: 12345,
			attestation_data: Some(vec![0x01, 0x02, 0x03]),
			filled_timestamp: 1234567890,
			oracle_address: "0x1234567890123456789012345678901234567890".to_string(),
		}
	}

	async fn create_test_monitor_with_mocks<F1, F2>(
		setup_settlement: F1,
		setup_storage: F2,
		timeout_minutes: u64,
	) -> (SettlementMonitor, broadcast::Receiver<SolverEvent>)
	where
		F1: FnOnce(&mut MockSettlementInterface),
		F2: FnOnce(&mut MockStorageInterface),
	{
		let mut mock_settlement = MockSettlementInterface::new();
		let mut mock_storage = MockStorageInterface::new();

		// Set up expectations using the provided closures
		setup_settlement(&mut mock_settlement);
		setup_storage(&mut mock_storage);

		// Create services with configured mocks
		let settlement = Arc::new(SettlementService::new(
			HashMap::from([(
				"eip7683".to_string(),
				Box::new(mock_settlement) as Box<dyn solver_settlement::SettlementInterface>,
			)]),
			"eip7683".to_string(),
			20,
		));

		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let event_bus = EventBus::new(100);
		let receiver = event_bus.subscribe();

		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20));
		let networks: NetworksConfig = HashMap::new();

		let monitor = SettlementMonitor::new(
			settlement,
			state_machine,
			event_bus,
			timeout_minutes,
			delivery,
			networks,
		);

		(monitor, receiver)
	}

	#[test]
	fn test_new_settlement_monitor() {
		let settlement = Arc::new(SettlementService::new(HashMap::new(), String::new(), 20));
		let storage = Arc::new(StorageService::new(Box::new(
			solver_storage::implementations::memory::MemoryStorage::new(),
		)));
		let state_machine = Arc::new(OrderStateMachine::new(storage));
		let event_bus = EventBus::new(100);
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20));
		let networks: NetworksConfig = HashMap::new();
		let timeout_minutes = 30;

		let monitor = SettlementMonitor::new(
			settlement,
			state_machine,
			event_bus,
			timeout_minutes,
			delivery,
			networks,
		);

		assert_eq!(monitor.timeout_minutes, 30);
	}

	#[tokio::test]
	async fn test_monitor_claim_readiness_success() {
		let order = create_test_order();
		let tx_hash = create_test_tx_hash();

		let (monitor, mut receiver) = create_test_monitor_with_mocks(
			|settlement| {
				// Add oracle config mocks
				settlement
					.expect_oracle_config()
					.return_const(OracleConfig {
						input_oracles: std::collections::HashMap::new(),
						output_oracles: std::collections::HashMap::new(),
						routes: std::collections::HashMap::new(),
						selection_strategy: OracleSelectionStrategy::RoundRobin,
					});

				settlement
					.expect_is_input_oracle_supported()
					.return_const(true);

				settlement
					.expect_is_output_oracle_supported()
					.return_const(true);

				settlement
					.expect_get_attestation()
					.times(1)
					.returning(|_, _| Box::pin(async move { Ok(create_test_fill_proof()) }));

				settlement
					.expect_buffer_coverage_check()
					.times(1)
					.returning(|_| Box::pin(async { None }));

				settlement
					.expect_readiness()
					.times(1)
					.returning(|_, _| Box::pin(async move { SettlementReadiness::Ready }));
			},
			|storage| {
				// Mock exists check
				storage
					.expect_exists()
					.with(eq("orders:test_order_123"))
					.returning(|_| Box::pin(async move { Ok(true) }));

				// Mock storage operations for set_fill_proof
				storage
					.expect_get_bytes()
					.with(eq("orders:test_order_123"))
					.times(2) // Only called once for set_fill_proof
					.returning({
						let order = order.clone();
						move |_| {
							let order = order.clone();
							Box::pin(async move { Ok(serde_json::to_vec(&order).unwrap()) })
						}
					});

				storage
					.expect_set_bytes()
					.times(1) // Only called once for set_fill_proof
					.returning(|_, _, _, _| Box::pin(async move { Ok(()) }));
			},
			1,
		)
		.await;

		// Call monitor_claim_readiness directly
		monitor.monitor_claim_readiness(order, tx_hash).await;

		// Check for the event
		match receiver.try_recv() {
			Ok(SolverEvent::Settlement(SettlementEvent::PreClaimReady { order_id })) => {
				assert_eq!(order_id, "test_order_123");
			},
			Ok(other) => panic!("Expected PreClaimReady event, got: {other:?}"),
			Err(e) => panic!("Expected event but got error: {e:?}"),
		}
	}

	#[tokio::test]
	async fn test_monitor_claim_readiness_attestation_error() {
		let order = create_test_order();
		let tx_hash = create_test_tx_hash();

		let (monitor, mut receiver) = create_test_monitor_with_mocks(
			|settlement| {
				// Add oracle config mocks
				settlement
					.expect_oracle_config()
					.return_const(OracleConfig {
						input_oracles: std::collections::HashMap::new(),
						output_oracles: std::collections::HashMap::new(),
						routes: std::collections::HashMap::new(),
						selection_strategy: OracleSelectionStrategy::RoundRobin,
					});

				settlement
					.expect_is_input_oracle_supported()
					.return_const(true);

				settlement
					.expect_is_output_oracle_supported()
					.return_const(true);

				settlement
					.expect_get_attestation()
					.times(1)
					.returning(|_, _| {
						Box::pin(async move {
							Err(solver_settlement::SettlementError::ValidationFailed(
								"Test error".to_string(),
							))
						})
					});
			},
			|_storage| {
				// No storage expectations since we should return early on attestation error
			},
			1, // 1 minute timeout for faster test
		)
		.await;

		// Start monitoring
		monitor.monitor_claim_readiness(order, tx_hash).await;

		// Should not receive any events due to early return on error
		// Use a small timeout to verify no events are sent
		let result = tokio::time::timeout(Duration::from_millis(100), receiver.recv()).await;
		assert!(
			result.is_err(),
			"Should not receive any events on attestation error"
		);
	}

	#[tokio::test]
	async fn test_monitor_claim_readiness_storage_error() {
		let order = create_test_order();
		let tx_hash = create_test_tx_hash();

		let (monitor, mut receiver) = create_test_monitor_with_mocks(
			|settlement| {
				// Add oracle config mocks
				settlement
					.expect_oracle_config()
					.return_const(OracleConfig {
						input_oracles: std::collections::HashMap::new(),
						output_oracles: std::collections::HashMap::new(),
						routes: std::collections::HashMap::new(),
						selection_strategy: OracleSelectionStrategy::RoundRobin,
					});

				settlement
					.expect_is_input_oracle_supported()
					.return_const(true);

				settlement
					.expect_is_output_oracle_supported()
					.return_const(true);

				settlement
					.expect_get_attestation()
					.times(1)
					.returning(|_, _| Box::pin(async move { Ok(create_test_fill_proof()) }));
			},
			|storage| {
				// Mock exists check
				storage
					.expect_exists()
					.with(eq("orders:test_order_123"))
					.times(1)
					.returning(|_| Box::pin(async move { Ok(true) }));

				// Mock get_bytes for retrieve operation in set_fill_proof
				storage
					.expect_get_bytes()
					.with(eq("orders:test_order_123"))
					.times(1)
					.returning({
						let order = order.clone();
						move |_| {
							let order = order.clone();
							Box::pin(async move { Ok(serde_json::to_vec(&order).unwrap()) })
						}
					});

				// Mock set_bytes to fail (this should cause the storage error)
				storage.expect_set_bytes().times(1).returning(|_, _, _, _| {
					Box::pin(async move {
						Err(solver_storage::StorageError::Serialization(
							"Test storage error".to_string(),
						))
					})
				});
			},
			1,
		)
		.await;

		// Call monitor_claim_readiness directly
		monitor.monitor_claim_readiness(order, tx_hash).await;

		// Should not receive any events due to early return on storage error
		let result = tokio::time::timeout(Duration::from_millis(100), receiver.recv()).await;
		assert!(
			result.is_err(),
			"Should not receive any events on storage error"
		);
	}

	#[tokio::test]
	async fn test_monitor_claim_readiness_permanent_failure_emits_no_event() {
		let order = create_test_order();
		let tx_hash = create_test_tx_hash();

		let (monitor, mut receiver) = create_test_monitor_with_mocks(
			|settlement| {
				settlement
					.expect_oracle_config()
					.return_const(OracleConfig {
						input_oracles: std::collections::HashMap::new(),
						output_oracles: std::collections::HashMap::new(),
						routes: std::collections::HashMap::new(),
						selection_strategy: OracleSelectionStrategy::RoundRobin,
					});

				settlement
					.expect_is_input_oracle_supported()
					.return_const(true);

				settlement
					.expect_is_output_oracle_supported()
					.return_const(true);

				settlement
					.expect_get_attestation()
					.times(1)
					.returning(|_, _| Box::pin(async move { Ok(create_test_fill_proof()) }));

				settlement
					.expect_buffer_coverage_check()
					.times(1)
					.returning(|_| Box::pin(async { None }));

				settlement.expect_readiness().times(1).returning(|_, _| {
					Box::pin(async move {
						SettlementReadiness::PermanentFailure("misconfigured proof path".into())
					})
				});
			},
			|storage| {
				storage
					.expect_exists()
					.with(eq("orders:test_order_123"))
					.returning(|_| Box::pin(async move { Ok(true) }));
				storage
					.expect_get_bytes()
					.with(eq("orders:test_order_123"))
					.returning({
						let order = order.clone();
						move |_| {
							let order = order.clone();
							Box::pin(async move { Ok(serde_json::to_vec(&order).unwrap()) })
						}
					});
				storage
					.expect_set_bytes()
					.times(1)
					.returning(|_, _, _, _| Box::pin(async move { Ok(()) }));
			},
			1,
		)
		.await;

		monitor.monitor_claim_readiness(order, tx_hash).await;

		let result = tokio::time::timeout(Duration::from_millis(100), receiver.recv()).await;
		assert!(
			result.is_err(),
			"Permanent settlement failure should not emit settlement events"
		);
	}

	#[tokio::test]
	async fn test_monitor_claim_readiness_buffer_action_then_failure_emits_no_event() {
		let order = create_test_order();
		let tx_hash = create_test_tx_hash();

		let (monitor, mut receiver) = create_test_monitor_with_mocks(
			|settlement| {
				settlement
					.expect_oracle_config()
					.return_const(OracleConfig {
						input_oracles: std::collections::HashMap::new(),
						output_oracles: std::collections::HashMap::new(),
						routes: std::collections::HashMap::new(),
						selection_strategy: OracleSelectionStrategy::RoundRobin,
					});

				settlement
					.expect_is_input_oracle_supported()
					.return_const(true);

				settlement
					.expect_is_output_oracle_supported()
					.return_const(true);

				settlement
					.expect_get_attestation()
					.times(1)
					.returning(|_, _| Box::pin(async move { Ok(create_test_fill_proof()) }));

				let direction = solver_settlement::PusherDirection {
					label: "eth-to-arb-sepolia".into(),
					l1_chain_id: 11155111,
					pusher_address: solver_types::Address(vec![0x11; 20]),
					l2_chain_id: 421614,
					buffer_address: solver_types::Address(vec![0x22; 20]),
					batch_size: 256,
					push_cooldown_seconds: 60,
					l2_params: solver_types::PusherL2Params::Raw {
						data: "0x".into(),
						value_wei: None,
					},
				};
				settlement
					.expect_buffer_coverage_check()
					.times(1)
					.returning(move |_| {
						let direction = direction.clone();
						Box::pin(async move { Some((direction, 12345)) })
					});

				settlement.expect_readiness().times(1).returning(|_, _| {
					Box::pin(async move {
						SettlementReadiness::PermanentFailure("buffer still unavailable".into())
					})
				});
			},
			|storage| {
				storage
					.expect_exists()
					.with(eq("orders:test_order_123"))
					.returning(|_| Box::pin(async move { Ok(true) }));
				storage
					.expect_get_bytes()
					.with(eq("orders:test_order_123"))
					.returning({
						let order = order.clone();
						move |_| {
							let order = order.clone();
							Box::pin(async move { Ok(serde_json::to_vec(&order).unwrap()) })
						}
					});
				storage
					.expect_set_bytes()
					.times(1)
					.returning(|_, _, _, _| Box::pin(async move { Ok(()) }));
			},
			1,
		)
		.await;

		monitor.monitor_claim_readiness(order, tx_hash).await;

		let result = tokio::time::timeout(Duration::from_millis(100), receiver.recv()).await;
		assert!(
			result.is_err(),
			"Buffer action branch should not emit settlement events on failure"
		);
	}
}
