//! Order handler for processing order preparation and execution.
//!
//! Manages the generation and submission of prepare transactions (for off-chain orders)
//! and fill transactions, updating order state and publishing appropriate events.

use crate::engine::event_bus::EventBus;
use crate::state::OrderStateMachine;
use crate::utils::truncate_id;
use alloy_primitives::hex;
use solver_delivery::DeliveryService;
use solver_order::OrderService;
use solver_storage::StorageService;
use solver_types::{
	DeliveryEvent, ExecutionParams, Intent, Order, OrderEvent, OrderStatus, SolverEvent,
	StorageKey, TransactionType,
};
use std::sync::Arc;
use thiserror::Error;
use tracing::instrument;

/// Errors that can occur during order processing.
/// 
/// These errors represent failures in service operations,
/// storage operations, or state transitions during order handling.
#[derive(Debug, Error)]
pub enum OrderError {
	#[error("Service error: {0}")]
	Service(String),
	#[error("Storage error: {0}")]
	Storage(String),
	#[error("State error: {0}")]
	State(String),
}

/// Handler for processing order preparation and execution.
/// 
/// The OrderHandler manages the generation and submission of prepare
/// transactions for off-chain orders and fill transactions for all orders,
/// while updating order state and publishing relevant events.
pub struct OrderHandler {
	order_service: Arc<OrderService>,
	delivery: Arc<DeliveryService>,
	storage: Arc<StorageService>,
	state_machine: Arc<OrderStateMachine>,
	event_bus: EventBus,
}

impl OrderHandler {
	pub fn new(
		order_service: Arc<OrderService>,
		delivery: Arc<DeliveryService>,
		storage: Arc<StorageService>,
		state_machine: Arc<OrderStateMachine>,
		event_bus: EventBus,
	) -> Self {
		Self {
			order_service,
			delivery,
			storage,
			state_machine,
			event_bus,
		}
	}

	/// Handles order preparation for off-chain orders.
	#[instrument(skip_all, fields(order_id = %truncate_id(&order.id)))]
	pub async fn handle_preparation(
		&self,
		intent: Intent,
		order: Order,
		params: ExecutionParams,
	) -> Result<(), OrderError> {
		// Generate prepare transaction
		if let Some(prepare_tx) = self
			.order_service
			.generate_prepare_transaction(&intent, &order, &params)
			.await
			.map_err(|e| OrderError::Service(e.to_string()))?
		{
			// Submit prepare transaction
			let prepare_tx_hash = self
				.delivery
				.deliver(prepare_tx)
				.await
				.map_err(|e| OrderError::Service(e.to_string()))?;

			self.event_bus
				.publish(SolverEvent::Delivery(DeliveryEvent::TransactionPending {
					order_id: order.id.clone(),
					tx_hash: prepare_tx_hash.clone(),
					tx_type: TransactionType::Prepare,
				}))
				.ok();

			// Store tx_hash -> order_id mapping
			self.storage
				.store(
					StorageKey::OrderByTxHash.as_str(),
					&hex::encode(&prepare_tx_hash.0),
					&order.id,
				)
				.await
				.map_err(|e| OrderError::Storage(e.to_string()))?;

			// Update order with execution params and prepare tx hash
			self.state_machine
				.update_order_with(&order.id, |o| {
					o.execution_params = Some(params.clone());
					o.status = OrderStatus::Pending;
					o.prepare_tx_hash = Some(prepare_tx_hash);
				})
				.await
				.map_err(|e| OrderError::State(e.to_string()))?;
		} else {
			// No preparation needed, set execution params and proceed
			self.state_machine
				.update_order_with(&order.id, |o| {
					o.execution_params = Some(params.clone());
					o.status = OrderStatus::Pending;
				})
				.await
				.map_err(|e| OrderError::State(e.to_string()))?;

			self.event_bus
				.publish(SolverEvent::Order(OrderEvent::Executing {
					order: order.clone(),
					params,
				}))
				.ok();
		}

		Ok(())
	}

	/// Handles order execution by generating and submitting a fill transaction.
	#[instrument(skip_all, fields(order_id = %truncate_id(&order.id)))]
	pub async fn handle_execution(
		&self,
		order: Order,
		params: ExecutionParams,
	) -> Result<(), OrderError> {
		// Generate fill transaction
		let tx = self
			.order_service
			.generate_fill_transaction(&order, &params)
			.await
			.map_err(|e| OrderError::Service(e.to_string()))?;

		// Submit transaction
		let tx_hash = self
			.delivery
			.deliver(tx)
			.await
			.map_err(|e| OrderError::Service(e.to_string()))?;

		self.event_bus
			.publish(SolverEvent::Delivery(DeliveryEvent::TransactionPending {
				order_id: order.id.clone(),
				tx_hash: tx_hash.clone(),
				tx_type: TransactionType::Fill,
			}))
			.ok();

		// Store fill transaction
		self.state_machine
			.set_transaction_hash(&order.id, tx_hash.clone(), TransactionType::Fill)
			.await
			.map_err(|e| OrderError::State(e.to_string()))?;

		// Store reverse mapping: tx_hash -> order_id
		self.storage
			.store(
				StorageKey::OrderByTxHash.as_str(),
				&hex::encode(&tx_hash.0),
				&order.id,
			)
			.await
			.map_err(|e| OrderError::Storage(e.to_string()))?;

		Ok(())
	}
}
