//! Settlement handler for processing settlement operations.
//!
//! Manages post-fill, pre-claim, and claim transaction generation and submission.
//! Handles the complete settlement lifecycle including optional oracle interactions
//! and proof generation through the settlement service.

use crate::engine::event_bus::EventBus;
use crate::monitoring::SettlementMonitor;
use crate::state::OrderStateMachine;
use alloy_primitives::hex;
use solver_delivery::DeliveryService;
use solver_order::OrderService;
use solver_settlement::SettlementService;
use solver_storage::StorageService;
use solver_types::{
	truncate_id, DeliveryEvent, Order, SettlementEvent, SolverEvent, StorageKey, TransactionHash,
	TransactionType,
};
use std::sync::Arc;
use thiserror::Error;
use tracing::instrument;

/// Errors that can occur during settlement processing.
///
/// These errors represent failures in storage operations,
/// service operations, or state transitions during settlement handling.
#[derive(Debug, Error)]
pub enum SettlementError {
	#[error("Storage error: {0}")]
	Storage(String),
	#[error("Service error: {0}")]
	Service(String),
	#[error("State error: {0}")]
	State(String),
}

/// Handler for processing settlement operations.
///
/// The SettlementHandler manages the complete settlement lifecycle including:
/// - Post-fill transaction generation and submission (e.g., oracle attestation requests)
/// - Pre-claim transaction generation and submission (e.g., oracle signature submission)
/// - Claim transaction batch processing for reward collection
/// - Settlement monitoring coordination
pub struct SettlementHandler {
	settlement: Arc<SettlementService>,
	order_service: Arc<OrderService>,
	delivery: Arc<DeliveryService>,
	storage: Arc<StorageService>,
	state_machine: Arc<OrderStateMachine>,
	event_bus: EventBus,
	monitoring_timeout_minutes: u64,
}

impl SettlementHandler {
	pub fn new(
		settlement: Arc<SettlementService>,
		order_service: Arc<OrderService>,
		delivery: Arc<DeliveryService>,
		storage: Arc<StorageService>,
		state_machine: Arc<OrderStateMachine>,
		event_bus: EventBus,
		monitoring_timeout_minutes: u64,
	) -> Self {
		Self {
			settlement,
			order_service,
			delivery,
			storage,
			state_machine,
			event_bus,
			monitoring_timeout_minutes,
		}
	}

	/// Helper method to spawn settlement monitoring task.
	pub fn spawn_settlement_monitor(&self, order: Order, fill_tx_hash: TransactionHash) {
		let monitor = SettlementMonitor::new(
			self.settlement.clone(),
			self.state_machine.clone(),
			self.event_bus.clone(),
			self.monitoring_timeout_minutes,
		);

		tokio::spawn(async move {
			monitor.monitor_claim_readiness(order, fill_tx_hash).await;
		});
	}

	/// Handles PostFillReady event by generating and submitting PostFill transaction if needed.
	#[instrument(skip_all, fields(order_id = %truncate_id(&order_id)))]
	pub async fn handle_post_fill_ready(&self, order_id: String) -> Result<(), SettlementError> {
		// Retrieve the order
		let order: Order = self
			.storage
			.retrieve(StorageKey::Orders.as_str(), &order_id)
			.await
			.map_err(|e| SettlementError::Storage(e.to_string()))?;

		// Get the fill transaction hash
		let fill_tx_hash = order.fill_tx_hash.clone().ok_or_else(|| {
			SettlementError::Service("Order missing fill transaction hash".to_string())
		})?;

		// Get the destination chain for the fill
		let chain_id = *order
			.output_chain_ids
			.first()
			.ok_or_else(|| SettlementError::Service("No output chains in order".to_string()))?;

		// Get the fill receipt
		let receipt = self
			.delivery
			.get_receipt(&fill_tx_hash, chain_id)
			.await
			.map_err(|e| SettlementError::Service(format!("Failed to get fill receipt: {}", e)))?;

		// Generate post-fill transaction
		let post_fill_tx = self
			.settlement
			.generate_post_fill_transaction(&order, &receipt)
			.await
			.map_err(|e| SettlementError::Service(e.to_string()))?;

		match post_fill_tx {
			Some(post_fill_tx) => {
				let tx_hash = self
					.delivery
					.deliver(post_fill_tx.clone())
					.await
					.map_err(|e| SettlementError::Service(e.to_string()))?;

				// Store tx hash
				self.state_machine
					.set_transaction_hash(&order_id, tx_hash.clone(), TransactionType::PostFill)
					.await
					.map_err(|e| SettlementError::State(e.to_string()))?;

				// Store reverse mapping
				self.storage
					.store(
						StorageKey::OrderByTxHash.as_str(),
						&hex::encode(&tx_hash.0),
						&order_id,
						None,
					)
					.await
					.map_err(|e| SettlementError::Storage(e.to_string()))?;

				// Publish pending event
				self.event_bus
					.publish(SolverEvent::Delivery(DeliveryEvent::TransactionPending {
						order_id,
						tx_hash,
						tx_type: TransactionType::PostFill,
						tx_chain_id: post_fill_tx.chain_id,
					}))
					.ok();
			},
			None => {
				// No PostFill needed, start monitoring immediately
				tracing::info!(
					order_id = %truncate_id(&order_id),
					"No PostFill transaction needed, proceeding to settlement monitoring"
				);

				// Retrieve order
				let order: Order = self
					.storage
					.retrieve(StorageKey::Orders.as_str(), &order_id)
					.await
					.map_err(|e| SettlementError::Storage(e.to_string()))?;

				let fill_tx_hash = order.fill_tx_hash.clone().ok_or_else(|| {
					SettlementError::Service(
						"Missing fill transaction hash: required for settlement monitoring".into(),
					)
				})?;

				self.event_bus
					.publish(SolverEvent::Settlement(SettlementEvent::StartMonitoring {
						order_id,
						fill_tx_hash,
					}))
					.ok();
			},
		}
		Ok(())
	}

	/// Handles PreClaimReady event by generating and submitting PreClaim transaction if needed.
	#[instrument(skip_all, fields(order_id = %truncate_id(&order_id)))]
	pub async fn handle_pre_claim_ready(&self, order_id: String) -> Result<(), SettlementError> {
		// Retrieve the order
		let order: Order = self
			.storage
			.retrieve(StorageKey::Orders.as_str(), &order_id)
			.await
			.map_err(|e| SettlementError::Storage(e.to_string()))?;

		// Get the fill proof
		let fill_proof = order
			.fill_proof
			.clone()
			.ok_or_else(|| SettlementError::Service("Order missing fill proof".to_string()))?;

		// Generate pre-claim transaction
		let pre_claim_tx = self
			.settlement
			.generate_pre_claim_transaction(&order, &fill_proof)
			.await
			.map_err(|e| SettlementError::Service(e.to_string()))?;

		match pre_claim_tx {
			Some(pre_claim_tx) => {
				let tx_hash = self
					.delivery
					.deliver(pre_claim_tx.clone())
					.await
					.map_err(|e| SettlementError::Service(e.to_string()))?;

				// Store tx hash
				self.state_machine
					.set_transaction_hash(&order_id, tx_hash.clone(), TransactionType::PreClaim)
					.await
					.map_err(|e| SettlementError::State(e.to_string()))?;

				// Store reverse mapping
				self.storage
					.store(
						StorageKey::OrderByTxHash.as_str(),
						&hex::encode(&tx_hash.0),
						&order_id,
						None,
					)
					.await
					.map_err(|e| SettlementError::Storage(e.to_string()))?;

				// Publish pending event
				self.event_bus
					.publish(SolverEvent::Delivery(DeliveryEvent::TransactionPending {
						order_id,
						tx_hash,
						tx_type: TransactionType::PreClaim,
						tx_chain_id: pre_claim_tx.chain_id,
					}))
					.ok();
			},
			None => {
				// No PreClaim needed, emit ClaimReady
				tracing::info!(
					order_id = %truncate_id(&order_id),
					"No PreClaim transaction needed, proceeding to claim"
				);

				self.event_bus
					.publish(SolverEvent::Settlement(SettlementEvent::ClaimReady {
						order_id,
					}))
					.ok();
			},
		}
		Ok(())
	}

	/// Processes a batch of orders ready for claiming.
	#[instrument(skip_all)]
	pub async fn process_claim_batch(
		&self,
		batch: &mut Vec<String>,
	) -> Result<(), SettlementError> {
		for order_id in batch.drain(..) {
			// Retrieve order
			let order: Order = self
				.storage
				.retrieve(StorageKey::Orders.as_str(), &order_id)
				.await
				.map_err(|e| SettlementError::Storage(e.to_string()))?;

			// Retrieve fill proof (already validated when ClaimReady was emitted)
			let fill_proof = order
				.fill_proof
				.clone()
				.ok_or_else(|| SettlementError::Service("Order missing fill proof".to_string()))?;

			// Generate claim transaction
			let claim_tx = self
				.order_service
				.generate_claim_transaction(&order, &fill_proof)
				.await
				.map_err(|e| SettlementError::Service(e.to_string()))?;

			// Submit claim transaction through delivery service
			let claim_tx_hash = self
				.delivery
				.deliver(claim_tx.clone())
				.await
				.map_err(|e| SettlementError::Service(e.to_string()))?;

			self.event_bus
				.publish(SolverEvent::Delivery(DeliveryEvent::TransactionPending {
					order_id: order.id.clone(),
					tx_hash: claim_tx_hash.clone(),
					tx_type: TransactionType::Claim,
					tx_chain_id: claim_tx.chain_id,
				}))
				.ok();

			// Update order with claim transaction hash
			self.state_machine
				.set_transaction_hash(&order.id, claim_tx_hash.clone(), TransactionType::Claim)
				.await
				.map_err(|e| SettlementError::State(e.to_string()))?;

			// Store reverse mapping: tx_hash -> order_id
			self.storage
				.store(
					StorageKey::OrderByTxHash.as_str(),
					&hex::encode(&claim_tx_hash.0),
					&order.id,
					None,
				)
				.await
				.map_err(|e| SettlementError::Storage(e.to_string()))?;
		}
		Ok(())
	}
}
