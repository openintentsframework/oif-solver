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
			Executing,
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
					HashSet::from([
						OrderStatusKind::Pending,
						OrderStatusKind::Executing,
						OrderStatusKind::Failed,
					]),
				);
				m.insert(
					OrderStatusKind::Pending,
					HashSet::from([OrderStatusKind::Executing, OrderStatusKind::Failed]),
				);
				m.insert(
					OrderStatusKind::Executing,
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
				OrderStatus::Executing => OrderStatusKind::Executing,
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

#[cfg(test)]
mod tests {
	use super::*;
	use solver_storage::StorageService;
	use solver_types::{OrderStatus, TransactionType};
	use std::sync::Arc;
	use tokio;

	fn create_test_storage() -> Arc<StorageService> {
		let backend = Box::new(solver_storage::implementations::memory::MemoryStorage::new());
		Arc::new(StorageService::new(backend))
	}

	fn create_test_order() -> Order {
		use solver_types::parse_address;

		Order {
			id: "test_order_1".to_string(),
			standard: "eip7683".to_string(),
			created_at: 1000000,
			updated_at: 1000000,
			status: OrderStatus::Created,
			post_fill_tx_hash: None,
			pre_claim_tx_hash: None,
			data: serde_json::json!({}),
			solver_address: parse_address("1234567890123456789012345678901234567890").unwrap(),
			quote_id: Some("quote_1".to_string()),
			input_chain_ids: vec![1],
			output_chain_ids: vec![137],
			execution_params: None,
			prepare_tx_hash: None,
			fill_tx_hash: None,
			claim_tx_hash: None,
			fill_proof: None,
		}
	}

	#[tokio::test]
	async fn test_store_and_retrieve_order() {
		let storage = create_test_storage();
		let state_machine = OrderStateMachine::new(storage);
		let order = create_test_order();

		// Store order
		state_machine.store_order(&order).await.unwrap();

		// Retrieve order
		let retrieved = state_machine.get_order("test_order_1").await.unwrap();
		assert_eq!(retrieved.id, order.id);
		assert_eq!(retrieved.status, order.status);
	}

	#[tokio::test]
	async fn test_order_state_transitions() {
		let storage = create_test_storage();
		let state_machine = OrderStateMachine::new(storage);
		let order = create_test_order();

		// Store initial order
		state_machine.store_order(&order).await.unwrap();

		// Test valid transition
		let updated = state_machine
			.transition_order_status("test_order_1", OrderStatus::Pending)
			.await
			.unwrap();
		assert_eq!(updated.status, OrderStatus::Pending);

		// Test invalid transition
		let result = state_machine
			.transition_order_status("test_order_1", OrderStatus::Finalized)
			.await;
		assert!(result.is_err());
	}

	#[tokio::test]
	async fn test_set_transaction_hashes() {
		let storage = create_test_storage();
		let state_machine = OrderStateMachine::new(storage);
		let order = create_test_order();

		state_machine.store_order(&order).await.unwrap();

		// Test setting different transaction types
		let tx_hash = solver_types::TransactionHash("0xprepare".as_bytes().to_vec());
		let updated = state_machine
			.set_transaction_hash("test_order_1", tx_hash.clone(), TransactionType::Prepare)
			.await
			.unwrap();
		assert_eq!(updated.prepare_tx_hash, Some(tx_hash));

		let tx_hash = solver_types::TransactionHash("0xfill".as_bytes().to_vec());
		let updated = state_machine
			.set_transaction_hash("test_order_1", tx_hash.clone(), TransactionType::Fill)
			.await
			.unwrap();
		assert_eq!(updated.fill_tx_hash, Some(tx_hash));
	}

	#[test]
	fn test_state_transition_validation() {
		// Test transition logic without storage
		assert!(OrderStateMachine::is_valid_transition(
			&OrderStatus::Created,
			&OrderStatus::Pending
		));
		assert!(!OrderStateMachine::is_valid_transition(
			&OrderStatus::Created,
			&OrderStatus::Executed
		));
		assert!(!OrderStateMachine::is_valid_transition(
			&OrderStatus::Finalized,
			&OrderStatus::Pending
		));
	}
}
