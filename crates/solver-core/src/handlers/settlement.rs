//! Settlement handler for processing claim operations.
//!
//! Manages the batch processing of orders ready for claiming, generating
//! claim transactions and submitting them through the delivery service.

use crate::engine::event_bus::EventBus;
use crate::state::OrderStateMachine;
use alloy_primitives::hex;
use solver_delivery::DeliveryService;
use solver_order::OrderService;
use solver_settlement::SettlementService;
use solver_storage::StorageService;
use solver_types::{DeliveryEvent, Order, SolverEvent, StorageKey, TransactionType};
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

/// Handler for processing settlement claim operations.
/// 
/// The SettlementHandler manages batch processing of orders ready for claiming,
/// generating claim transactions and submitting them through the delivery service
/// to complete the settlement lifecycle.
pub struct SettlementHandler {
	#[allow(dead_code)]
	settlement: Arc<SettlementService>,
	order_service: Arc<OrderService>,
	delivery: Arc<DeliveryService>,
	storage: Arc<StorageService>,
	state_machine: Arc<OrderStateMachine>,
	event_bus: EventBus,
}

impl SettlementHandler {
	pub fn new(
		settlement: Arc<SettlementService>,
		order_service: Arc<OrderService>,
		delivery: Arc<DeliveryService>,
		storage: Arc<StorageService>,
		state_machine: Arc<OrderStateMachine>,
		event_bus: EventBus,
	) -> Self {
		Self {
			settlement,
			order_service,
			delivery,
			storage,
			state_machine,
			event_bus,
		}
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
				.deliver(claim_tx)
				.await
				.map_err(|e| SettlementError::Service(e.to_string()))?;

			self.event_bus
				.publish(SolverEvent::Delivery(DeliveryEvent::TransactionPending {
					order_id: order.id.clone(),
					tx_hash: claim_tx_hash.clone(),
					tx_type: TransactionType::Claim,
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
				)
				.await
				.map_err(|e| SettlementError::Storage(e.to_string()))?;
		}
		Ok(())
	}
}
