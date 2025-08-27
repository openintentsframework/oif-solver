//! Transaction handler for managing blockchain transaction lifecycle.
//!
//! Handles transaction confirmations, failures, and state transitions based on
//! transaction type (prepare, fill, post-fill, pre-claim, claim). Spawns monitoring
//! tasks for pending transactions and emits events for settlement processing.

use crate::engine::event_bus::EventBus;
use crate::monitoring::TransactionMonitor;
use crate::state::OrderStateMachine;
use alloy_primitives::hex;
use solver_delivery::DeliveryService;
use solver_storage::StorageService;
use solver_types::{
	truncate_id, DeliveryEvent, Order, OrderEvent, OrderStatus, SettlementEvent, SolverEvent,
	StorageKey, TransactionHash, TransactionReceipt, TransactionType,
};
use std::sync::Arc;
use thiserror::Error;
use tracing::instrument;

/// Errors that can occur during transaction processing.
///
/// These errors represent failures in storage operations,
/// state transitions, or service operations during transaction handling.
#[derive(Debug, Error)]
pub enum TransactionError {
	#[error("Storage error: {0}")]
	Storage(String),
	#[error("State error: {0}")]
	State(String),
	#[error("Service error: {0}")]
	Service(String),
}

/// Handler for managing blockchain transaction lifecycle.
///
/// The TransactionHandler manages transaction confirmations, failures,
/// and state transitions based on transaction type. It spawns monitoring
/// tasks for pending transactions and emits appropriate events to trigger
/// subsequent processing by other handlers (e.g., settlement handler for
/// post-fill and pre-claim transactions).
pub struct TransactionHandler {
	delivery: Arc<DeliveryService>,
	storage: Arc<StorageService>,
	state_machine: Arc<OrderStateMachine>,
	event_bus: EventBus,
	monitoring_timeout_minutes: u64,
}

impl TransactionHandler {
	pub fn new(
		delivery: Arc<DeliveryService>,
		storage: Arc<StorageService>,
		state_machine: Arc<OrderStateMachine>,
		event_bus: EventBus,
		monitoring_timeout_minutes: u64,
	) -> Self {
		Self {
			delivery,
			storage,
			state_machine,
			event_bus,
			monitoring_timeout_minutes,
		}
	}

	/// Spawns a monitoring task for a pending transaction
	pub async fn monitor_transaction(
		&self,
		order_id: String,
		tx_hash: TransactionHash,
		tx_type: TransactionType,
		tx_chain_id: u64,
	) {
		let monitor = TransactionMonitor::new(
			self.delivery.clone(),
			self.event_bus.clone(),
			self.monitoring_timeout_minutes,
		);

		tokio::spawn(async move {
			monitor
				.monitor(order_id, tx_hash, tx_type, tx_chain_id)
				.await;
		});
	}

	/// Handles confirmed transactions based on their type.
	///
	/// Routes to the appropriate handler based on transaction type:
	/// - Prepare: Updates status to Executing and emits OrderEvent::Executing
	/// - Fill: Updates status to Executed and emits SettlementEvent::PostFillReady
	/// - PostFill: Updates status to PostFilled and emits SettlementEvent::StartMonitoring
	/// - PreClaim: Updates status to PreClaimed and emits SettlementEvent::ClaimReady
	/// - Claim: Updates status to Finalized and emits SettlementEvent::Completed
	#[instrument(skip_all, fields(order_id = %truncate_id(&order_id), tx_type = ?tx_type))]
	pub async fn handle_confirmed(
		&self,
		order_id: String,
		tx_hash: TransactionHash,
		tx_type: TransactionType,
		receipt: TransactionReceipt,
	) -> Result<(), TransactionError> {
		// Defensive check
		if !receipt.success {
			self.event_bus
				.publish(SolverEvent::Delivery(DeliveryEvent::TransactionFailed {
					order_id,
					tx_hash,
					tx_type,
					error: "Transaction reverted".to_string(),
				}))
				.ok();
			return Ok(());
		}

		// Handle based on transaction type
		match tx_type {
			TransactionType::Prepare => {
				self.handle_prepare_confirmed(tx_hash).await?;
			},
			TransactionType::Fill => {
				self.handle_fill_confirmed(receipt).await?;
			},
			TransactionType::PostFill => {
				self.handle_post_fill_confirmed(tx_hash).await?;
			},
			TransactionType::PreClaim => {
				self.handle_pre_claim_confirmed(tx_hash).await?;
			},
			TransactionType::Claim => {
				self.handle_claim_confirmed(tx_hash).await?;
			},
		}

		Ok(())
	}

	/// Handles failed transactions.
	#[instrument(skip_all, fields(order_id = %truncate_id(&order_id), tx_hash = %truncate_id(&hex::encode(&tx_hash.0)), tx_type = ?tx_type))]
	pub async fn handle_failed(
		&self,
		order_id: String,
		tx_hash: TransactionHash,
		tx_type: TransactionType,
		error: String,
	) -> Result<(), TransactionError> {
		tracing::error!("Transaction failed: {}", error);

		// Update order status with specific failure type
		self.state_machine
			.transition_order_status(&order_id, OrderStatus::Failed(tx_type))
			.await
			.map_err(|e| TransactionError::State(e.to_string()))?;

		Ok(())
	}

	/// Handles prepare transaction confirmation.
	///
	/// Updates status to Executing and publishes OrderEvent::Executing
	/// to trigger the fill transaction.
	async fn handle_prepare_confirmed(
		&self,
		tx_hash: TransactionHash,
	) -> Result<(), TransactionError> {
		// Look up the order ID from the transaction hash
		let order_id = self
			.storage
			.retrieve::<String>(StorageKey::OrderByTxHash.as_str(), &hex::encode(&tx_hash.0))
			.await
			.map_err(|e| TransactionError::Storage(e.to_string()))?;

		// Retrieve the full order with execution parameters
		let order: Order = self
			.storage
			.retrieve(StorageKey::Orders.as_str(), &order_id)
			.await
			.map_err(|e| TransactionError::Storage(format!("Failed to retrieve order: {}", e)))?;

		// Extract execution params
		let params = order.execution_params.clone().ok_or_else(|| {
			TransactionError::Service("Order missing execution params".to_string())
		})?;

		// Update order status to executing (prepare done, fill in progress)
		self.state_machine
			.transition_order_status(&order.id, OrderStatus::Executing)
			.await
			.map_err(|e| TransactionError::State(e.to_string()))?;

		// Now publish Executing event to proceed with fill
		self.event_bus
			.publish(SolverEvent::Order(OrderEvent::Executing { order, params }))
			.ok();

		Ok(())
	}

	/// Handles confirmed fill transactions.
	///
	/// Updates status to Executed and emits PostFillReady event to trigger
	/// post-fill transaction generation if needed.
	async fn handle_fill_confirmed(
		&self,
		receipt: TransactionReceipt,
	) -> Result<(), TransactionError> {
		// Look up the order ID from the transaction hash
		let order_id = self
			.storage
			.retrieve::<String>(
				StorageKey::OrderByTxHash.as_str(),
				&hex::encode(&receipt.hash.0),
			)
			.await
			.map_err(|e| TransactionError::Storage(e.to_string()))?;

		// Retrieve the order
		let order: Order = self
			.storage
			.retrieve(StorageKey::Orders.as_str(), &order_id)
			.await
			.map_err(|e| TransactionError::Storage(e.to_string()))?;

		// Update status from Executing to Executed (fill completed)
		self.state_machine
			.transition_order_status(&order.id, OrderStatus::Executed)
			.await
			.map_err(|e| TransactionError::State(e.to_string()))?;

		// Emit PostFillReady event - handler will determine if transaction needed
		self.event_bus
			.publish(SolverEvent::Settlement(SettlementEvent::PostFillReady {
				order_id,
			}))
			.ok();

		Ok(())
	}

	/// Handles confirmed post-fill transactions.
	///
	/// Updates status to PostFilled and emits StartMonitoring event to begin
	/// monitoring for settlement readiness.
	async fn handle_post_fill_confirmed(
		&self,
		tx_hash: TransactionHash,
	) -> Result<(), TransactionError> {
		// Look up the order ID from the transaction hash
		let order_id = self
			.storage
			.retrieve::<String>(StorageKey::OrderByTxHash.as_str(), &hex::encode(&tx_hash.0))
			.await
			.map_err(|e| TransactionError::Storage(e.to_string()))?;

		// Retrieve the order
		let order: Order = self
			.storage
			.retrieve(StorageKey::Orders.as_str(), &order_id)
			.await
			.map_err(|e| TransactionError::Storage(e.to_string()))?;

		// Update status to PostFilled
		self.state_machine
			.transition_order_status(&order.id, OrderStatus::PostFilled)
			.await
			.map_err(|e| TransactionError::State(e.to_string()))?;

		// Get fill transaction hash for monitoring
		let fill_tx_hash = order
			.fill_tx_hash
			.clone()
			.ok_or_else(|| TransactionError::Service("Missing fill transaction hash: required for post-fill transaction processing and settlement monitoring".into()))?;

		self.event_bus
			.publish(SolverEvent::Settlement(SettlementEvent::StartMonitoring {
				order_id,
				fill_tx_hash,
			}))
			.ok();

		Ok(())
	}

	/// Handles confirmed pre-claim transactions.
	///
	/// Updates status to PreClaimed and emits ClaimReady event to trigger
	/// the final claim transaction.
	async fn handle_pre_claim_confirmed(
		&self,
		tx_hash: TransactionHash,
	) -> Result<(), TransactionError> {
		// Look up the order ID from the transaction hash
		let order_id = self
			.storage
			.retrieve::<String>(StorageKey::OrderByTxHash.as_str(), &hex::encode(&tx_hash.0))
			.await
			.map_err(|e| TransactionError::Storage(e.to_string()))?;

		// Update status from Settled to PreClaimed
		self.state_machine
			.transition_order_status(&order_id, OrderStatus::PreClaimed)
			.await
			.map_err(|e| TransactionError::State(e.to_string()))?;

		// PreClaim confirmed, emit ClaimReady
		self.event_bus
			.publish(SolverEvent::Settlement(SettlementEvent::ClaimReady {
				order_id,
			}))
			.ok();

		Ok(())
	}

	/// Handles confirmed claim transactions.
	///
	/// Updates status to Finalized and emits Completed event to signal
	/// successful order completion.
	async fn handle_claim_confirmed(
		&self,
		tx_hash: TransactionHash,
	) -> Result<(), TransactionError> {
		// Look up the order ID from the transaction hash
		let order_id = self
			.storage
			.retrieve::<String>(StorageKey::OrderByTxHash.as_str(), &hex::encode(&tx_hash.0))
			.await
			.map_err(|e| TransactionError::Storage(e.to_string()))?;

		// Update order with claim transaction hash and mark as finalized
		self.state_machine
			.update_order_with(&order_id, |order| {
				order.claim_tx_hash = Some(tx_hash.clone());
				order.status = OrderStatus::Finalized;
			})
			.await
			.map_err(|e| TransactionError::State(e.to_string()))?;

		// Publish completed event
		self.event_bus
			.publish(SolverEvent::Settlement(
				solver_types::SettlementEvent::Completed { order_id },
			))
			.ok();

		Ok(())
	}
}
