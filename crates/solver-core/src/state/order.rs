//! Order state machine implementation.
//!
//! Manages order state transitions with validation, ensuring orders move through
//! valid lifecycle states: Created -> Pending -> Executed -> Settled -> Finalized.
//! Also handles failure states and provides utilities for updating order fields.

use once_cell::sync::Lazy;
use solver_storage::{StorageIndexes, StorageService};
use solver_types::{Order, OrderStatus, StorageKey, TransactionType};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Errors that can occur during order state management.
///
/// These errors represent failures in storage operations,
/// invalid state transitions, missing orders, or time-related issues.
#[derive(Debug, Error)]
pub enum OrderStateError {
	#[error("Storage error: {0}")]
	Storage(String),
	#[error("Invalid state transition from {from:?} to {to:?}")]
	InvalidTransition { from: OrderStatus, to: OrderStatus },
	#[error("Order not found: {0}")]
	OrderNotFound(String),
	#[error("Time error: {0}")]
	TimeError(String),
}

/// Manages order state transitions and persistence
pub struct OrderStateMachine {
	storage: Arc<StorageService>,
}

impl OrderStateMachine {
	pub fn new(storage: Arc<StorageService>) -> Self {
		Self { storage }
	}

	/// Updates an order with a closure and persists it
	pub async fn update_order_with<F>(
		&self,
		order_id: &str,
		updater: F,
	) -> Result<Order, OrderStateError>
	where
		F: FnOnce(&mut Order),
	{
		let mut order: Order = self
			.storage
			.retrieve(StorageKey::Orders.as_str(), order_id)
			.await
			.map_err(|e| OrderStateError::Storage(e.to_string()))?;

		// Apply the update
		updater(&mut order);

		// Automatically set updated_at timestamp
		order.updated_at = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.map_err(|e| OrderStateError::TimeError(e.to_string()))?
			.as_secs();

		// Update with status index
		let indexes = StorageIndexes::new().with_field("status", order.status.to_string());

		self.storage
			.update(StorageKey::Orders.as_str(), order_id, &order, Some(indexes))
			.await
			.map_err(|e| OrderStateError::Storage(e.to_string()))?;

		Ok(order)
	}

	/// Transitions an order to a new status with validation
	pub async fn transition_order_status(
		&self,
		order_id: &str,
		new_status: OrderStatus,
	) -> Result<Order, OrderStateError> {
		let order: Order = self
			.storage
			.retrieve(StorageKey::Orders.as_str(), order_id)
			.await
			.map_err(|e| OrderStateError::Storage(e.to_string()))?;

		// Validate state transition
		if !Self::is_valid_transition(&order.status, &new_status) {
			return Err(OrderStateError::InvalidTransition {
				from: order.status,
				to: new_status,
			});
		}

		self.update_order_with(order_id, |o| {
			o.status = new_status;
		})
		.await
	}

	/// Checks if a state transition is valid
	fn is_valid_transition(from: &OrderStatus, to: &OrderStatus) -> bool {
		#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
		enum OrderStatusKind {
			Created,
			Pending,
			Executed,
			PostFilled,
			PreClaimed,
			Settled,
			Finalized,
			Failed,
		}

		// Static transition table - each state maps to allowed next states
		static TRANSITIONS: Lazy<HashMap<OrderStatusKind, HashSet<OrderStatusKind>>> =
			Lazy::new(|| {
				let mut m = HashMap::new();
				m.insert(
					OrderStatusKind::Created,
					HashSet::from([OrderStatusKind::Pending, OrderStatusKind::Failed]),
				);
				m.insert(
					OrderStatusKind::Pending,
					HashSet::from([OrderStatusKind::Executed, OrderStatusKind::Failed]),
				);
				m.insert(
					OrderStatusKind::Executed,
					HashSet::from([
						OrderStatusKind::PostFilled,
						OrderStatusKind::Settled,
						OrderStatusKind::Failed,
					]),
				);
				m.insert(
					OrderStatusKind::PostFilled,
					HashSet::from([OrderStatusKind::Settled, OrderStatusKind::Failed]),
				);
				m.insert(
					OrderStatusKind::PreClaimed,
					HashSet::from([OrderStatusKind::Finalized, OrderStatusKind::Failed]),
				);
				m.insert(
					OrderStatusKind::Settled,
					HashSet::from([
						OrderStatusKind::PreClaimed,
						OrderStatusKind::Finalized,
						OrderStatusKind::Failed,
					]),
				);
				m.insert(OrderStatusKind::Failed, HashSet::new()); // terminal
				m.insert(OrderStatusKind::Finalized, HashSet::new()); // terminal
				m
			});

		// Helper to convert OrderStatus to OrderStatusKind
		let status_kind = |status: &OrderStatus| -> OrderStatusKind {
			match status {
				OrderStatus::Created => OrderStatusKind::Created,
				OrderStatus::Pending => OrderStatusKind::Pending,
				OrderStatus::Executed => OrderStatusKind::Executed,
				OrderStatus::PostFilled => OrderStatusKind::PostFilled,
				OrderStatus::PreClaimed => OrderStatusKind::PreClaimed,
				OrderStatus::Settled => OrderStatusKind::Settled,
				OrderStatus::Finalized => OrderStatusKind::Finalized,
				OrderStatus::Failed(_) => OrderStatusKind::Failed,
			}
		};

		let from_kind = status_kind(from);
		let to_kind = status_kind(to);
		TRANSITIONS
			.get(&from_kind)
			.is_some_and(|set| set.contains(&to_kind))
	}

	/// Gets an order by ID
	pub async fn get_order(&self, order_id: &str) -> Result<Order, OrderStateError> {
		self.storage
			.retrieve(StorageKey::Orders.as_str(), order_id)
			.await
			.map_err(|e| OrderStateError::Storage(e.to_string()))
	}

	/// Stores a new order with indexed status
	pub async fn store_order(&self, order: &Order) -> Result<(), OrderStateError> {
		// Store with status index for recovery queries
		let indexes = StorageIndexes::new().with_field("status", order.status.to_string());

		self.storage
			.store(StorageKey::Orders.as_str(), &order.id, order, Some(indexes))
			.await
			.map_err(|e| OrderStateError::Storage(e.to_string()))
	}

	/// Updates order with transaction hash based on type
	pub async fn set_transaction_hash(
		&self,
		order_id: &str,
		tx_hash: solver_types::TransactionHash,
		tx_type: TransactionType,
	) -> Result<Order, OrderStateError> {
		self.update_order_with(order_id, |order| match tx_type {
			TransactionType::Prepare => order.prepare_tx_hash = Some(tx_hash),
			TransactionType::Fill => order.fill_tx_hash = Some(tx_hash),
			TransactionType::PostFill => order.post_fill_tx_hash = Some(tx_hash),
			TransactionType::PreClaim => order.pre_claim_tx_hash = Some(tx_hash),
			TransactionType::Claim => order.claim_tx_hash = Some(tx_hash),
		})
		.await
	}

	/// Sets execution parameters for an order
	pub async fn set_execution_params(
		&self,
		order_id: &str,
		params: solver_types::ExecutionParams,
	) -> Result<Order, OrderStateError> {
		self.update_order_with(order_id, |order| {
			order.execution_params = Some(params);
		})
		.await
	}

	/// Sets fill proof for an order
	pub async fn set_fill_proof(
		&self,
		order_id: &str,
		proof: solver_types::FillProof,
	) -> Result<Order, OrderStateError> {
		self.update_order_with(order_id, |order| {
			order.fill_proof = Some(proof);
		})
		.await
	}
}
