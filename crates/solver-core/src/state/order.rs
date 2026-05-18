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

/// Kind of order status for state transition validation
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

pub(crate) const STATUS_KIND_INDEX_FIELD: &str = "status_kind";
pub(crate) const IS_TERMINAL_INDEX_FIELD: &str = "is_terminal";
pub(crate) const FINALIZED_STATUS_KIND_INDEX_VALUE: &str = "finalized";
pub(crate) const FAILED_STATUS_KIND_INDEX_VALUE: &str = "failed";

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

/// Static transition table — each state maps to its allowed forward next states.
///
/// Lifted to module scope so both `is_valid_transition` and `is_at_or_past`
/// (used by `try_transition_order_status`) can share a single edge list.
static TRANSITIONS: Lazy<HashMap<OrderStatusKind, HashSet<OrderStatusKind>>> = Lazy::new(|| {
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

/// Outcome of an idempotent order-status transition.
#[derive(Debug, Clone)]
pub enum OrderTransitionOutcome {
	/// Status actually changed.
	Applied(Order),
	/// Current status is at-or-downstream of the target in the state
	/// graph (target was already passed). No write performed.
	AlreadyApplied(Order),
}

impl OrderTransitionOutcome {
	pub fn applied(&self) -> bool {
		matches!(self, Self::Applied(_))
	}
	pub fn order(&self) -> &Order {
		match self {
			Self::Applied(o) | Self::AlreadyApplied(o) => o,
		}
	}
	pub fn into_order(self) -> Order {
		match self {
			Self::Applied(o) | Self::AlreadyApplied(o) => o,
		}
	}
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

		// Update with canonical status indexes used by recovery queries.
		let indexes = order_storage_indexes(&order);

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

		// Skip transition if already in the same status kind
		// (ignoring error message differences in Failed status)
		if status_kind(&order.status) == status_kind(&new_status) {
			return Ok(order);
		}

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
		let from_kind = status_kind(from);
		let to_kind = status_kind(to);

		TRANSITIONS
			.get(&from_kind)
			.is_some_and(|set| set.contains(&to_kind))
	}

	/// Idempotent variant of `transition_order_status`. Returns:
	/// - `Applied(Order)`        when the transition fired and persisted
	/// - `AlreadyApplied(Order)` when the current status is at-or-past the
	///   target in the forward transition graph
	/// - `Err(InvalidTransition)` only for genuinely backward moves
	///
	/// Used by handlers that may receive duplicate `Confirmed` callbacks
	/// from same-nonce lineages to gate downstream event publication on
	/// the actual transition.
	pub async fn try_transition_order_status(
		&self,
		order_id: &str,
		new_status: OrderStatus,
	) -> Result<OrderTransitionOutcome, OrderStateError> {
		let order: Order = self
			.storage
			.retrieve(StorageKey::Orders.as_str(), order_id)
			.await
			.map_err(|e| OrderStateError::Storage(e.to_string()))?;

		// Same-kind → no-op idempotency (matches existing behavior).
		if status_kind(&order.status) == status_kind(&new_status) {
			return Ok(OrderTransitionOutcome::AlreadyApplied(order));
		}

		// Current is downstream of target (current at-or-past) → no-op.
		if Self::is_at_or_past(&order.status, &new_status) {
			return Ok(OrderTransitionOutcome::AlreadyApplied(order));
		}

		// Otherwise validate forward transition.
		if !Self::is_valid_transition(&order.status, &new_status) {
			return Err(OrderStateError::InvalidTransition {
				from: order.status,
				to: new_status,
			});
		}

		let updated = self
			.update_order_with(order_id, |o| {
				o.status = new_status;
			})
			.await?;
		Ok(OrderTransitionOutcome::Applied(updated))
	}

	/// `current` is "at or past" `target` iff `current` is reachable from
	/// `target` going forward through the transition graph — i.e., `current`
	/// is downstream of `target`. Reuses the module-level `TRANSITIONS`
	/// static. Same-kind case is handled by the caller.
	fn is_at_or_past(current: &OrderStatus, target: &OrderStatus) -> bool {
		let current_kind = status_kind(current);
		let target_kind = status_kind(target);
		if current_kind == target_kind {
			return true;
		}
		// BFS from `target_kind` over forward edges. If `current_kind` is
		// reachable, then current is downstream of target → at-or-past.
		let mut frontier: Vec<OrderStatusKind> = vec![target_kind];
		let mut seen: HashSet<OrderStatusKind> = HashSet::new();
		seen.insert(target_kind);
		while let Some(kind) = frontier.pop() {
			if let Some(nexts) = TRANSITIONS.get(&kind) {
				for next in nexts {
					if *next == current_kind {
						return true;
					}
					if seen.insert(*next) {
						frontier.push(*next);
					}
				}
			}
		}
		false
	}

	/// Gets an order by ID
	pub async fn get_order(&self, order_id: &str) -> Result<Order, OrderStateError> {
		self.storage
			.retrieve(StorageKey::Orders.as_str(), order_id)
			.await
			.map_err(|e| OrderStateError::Storage(e.to_string()))
	}

	/// Stores a new order with canonical status indexes.
	pub async fn store_order(&self, order: &Order) -> Result<(), OrderStateError> {
		let indexes = order_storage_indexes(order);

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

/// Helper to convert OrderStatus to OrderStatusKind for comparison
fn status_kind(status: &OrderStatus) -> OrderStatusKind {
	match status {
		OrderStatus::Created => OrderStatusKind::Created,
		OrderStatus::Pending => OrderStatusKind::Pending,
		OrderStatus::Executing => OrderStatusKind::Executing,
		OrderStatus::Executed => OrderStatusKind::Executed,
		OrderStatus::PostFilled => OrderStatusKind::PostFilled,
		OrderStatus::PreClaimed => OrderStatusKind::PreClaimed,
		OrderStatus::Settled => OrderStatusKind::Settled,
		OrderStatus::Finalized => OrderStatusKind::Finalized,
		OrderStatus::Failed(_, _) => OrderStatusKind::Failed,
	}
}

pub(crate) fn status_kind_index_value(status: &OrderStatus) -> &'static str {
	match status {
		OrderStatus::Created => "created",
		OrderStatus::Pending => "pending",
		OrderStatus::Executing => "executing",
		OrderStatus::Executed => "executed",
		OrderStatus::PostFilled => "post_filled",
		OrderStatus::PreClaimed => "pre_claimed",
		OrderStatus::Settled => "settled",
		OrderStatus::Finalized => FINALIZED_STATUS_KIND_INDEX_VALUE,
		OrderStatus::Failed(_, _) => FAILED_STATUS_KIND_INDEX_VALUE,
	}
}

pub(crate) fn is_terminal_status(status: &OrderStatus) -> bool {
	matches!(status, OrderStatus::Finalized | OrderStatus::Failed(_, _))
}

fn order_storage_indexes(order: &Order) -> StorageIndexes {
	StorageIndexes::new()
		.with_field(
			STATUS_KIND_INDEX_FIELD,
			status_kind_index_value(&order.status),
		)
		.with_field(IS_TERMINAL_INDEX_FIELD, is_terminal_status(&order.status))
}

#[cfg(test)]
mod tests {
	use super::*;
	use solver_storage::{MockStorageInterface, StorageService};
	use solver_types::{utils::tests::builders::OrderBuilder, OrderStatus, TransactionType};
	use std::sync::Arc;
	use tokio;

	fn create_test_storage() -> Arc<StorageService> {
		let backend = Box::new(solver_storage::implementations::memory::MemoryStorage::new());
		Arc::new(StorageService::new(backend))
	}

	fn create_test_order() -> Order {
		OrderBuilder::new().with_id("test_order_1").build()
	}

	#[tokio::test]
	async fn store_order_writes_canonical_status_indexes() {
		let mut mock_storage = MockStorageInterface::new();
		let order = OrderBuilder::new()
			.with_id("indexed_order")
			.with_status(OrderStatus::Pending)
			.build();

		mock_storage
			.expect_set_bytes()
			.times(1)
			.withf(|key, _bytes, indexes, ttl| {
				if key != "orders:indexed_order" || ttl.is_some() {
					return false;
				}

				let Some(indexes) = indexes else {
					return false;
				};

				indexes.fields.get("status_kind") == Some(&serde_json::json!("pending"))
					&& indexes.fields.get("is_terminal") == Some(&serde_json::json!(false))
					&& !indexes.fields.contains_key("status")
			})
			.returning(|_, _, _, _| Box::pin(async move { Ok(()) }));

		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let state_machine = OrderStateMachine::new(storage);

		state_machine.store_order(&order).await.unwrap();
	}

	#[tokio::test]
	async fn update_order_with_rewrites_canonical_status_indexes() {
		let mut mock_storage = MockStorageInterface::new();
		let order = OrderBuilder::new()
			.with_id("update_indexed_order")
			.with_status(OrderStatus::Pending)
			.build();
		let order_bytes = serde_json::to_vec(&order).unwrap();

		mock_storage
			.expect_get_bytes()
			.with(mockall::predicate::eq("orders:update_indexed_order"))
			.times(1)
			.return_once(move |_| Box::pin(async move { Ok(order_bytes) }));

		mock_storage
			.expect_exists()
			.with(mockall::predicate::eq("orders:update_indexed_order"))
			.times(1)
			.returning(|_| Box::pin(async move { Ok(true) }));

		mock_storage
			.expect_set_bytes()
			.times(1)
			.withf(|key, bytes, indexes, ttl| {
				if key != "orders:update_indexed_order" || ttl.is_some() {
					return false;
				}

				let Ok(order) = serde_json::from_slice::<Order>(bytes) else {
					return false;
				};
				if order.status != OrderStatus::Finalized {
					return false;
				}

				let Some(indexes) = indexes else {
					return false;
				};

				indexes.fields.get("status_kind") == Some(&serde_json::json!("finalized"))
					&& indexes.fields.get("is_terminal") == Some(&serde_json::json!(true))
					&& !indexes.fields.contains_key("status")
			})
			.returning(|_, _, _, _| Box::pin(async move { Ok(()) }));

		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let state_machine = OrderStateMachine::new(storage);

		let updated = state_machine
			.update_order_with("update_indexed_order", |order| {
				order.status = OrderStatus::Finalized;
			})
			.await
			.unwrap();

		assert_eq!(updated.status, OrderStatus::Finalized);
	}

	#[test]
	fn status_kind_index_values_are_stable() {
		let cases = [
			(OrderStatus::Created, "created", false),
			(OrderStatus::Pending, "pending", false),
			(OrderStatus::Executing, "executing", false),
			(OrderStatus::Executed, "executed", false),
			(OrderStatus::PostFilled, "post_filled", false),
			(OrderStatus::PreClaimed, "pre_claimed", false),
			(OrderStatus::Settled, "settled", false),
			(OrderStatus::Finalized, "finalized", true),
			(
				OrderStatus::Failed(TransactionType::Fill, "boom".to_string()),
				"failed",
				true,
			),
		];

		for (status, expected_kind, expected_terminal) in cases {
			assert_eq!(status_kind_index_value(&status), expected_kind);
			assert_eq!(is_terminal_status(&status), expected_terminal);
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

	async fn test_state_machine_with_order(
		status: OrderStatus,
	) -> (Arc<OrderStateMachine>, tempfile::TempDir) {
		use solver_storage::implementations::file::{FileStorage, TtlConfig};
		let temp = tempfile::tempdir().unwrap();
		let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp.path().to_path_buf(),
			TtlConfig::default(),
		))));
		let sm = Arc::new(OrderStateMachine::new(storage));
		let mut order = create_test_order();
		order.status = status;
		sm.store_order(&order).await.unwrap();
		(sm, temp)
	}

	#[tokio::test]
	async fn try_transition_returns_applied_when_status_changes() {
		let (state_machine, _temp) = test_state_machine_with_order(OrderStatus::Executing).await;
		let outcome = state_machine
			.try_transition_order_status("test_order_1", OrderStatus::Executed)
			.await
			.unwrap();
		assert!(outcome.applied());
		assert_eq!(outcome.order().status, OrderStatus::Executed);
	}

	#[tokio::test]
	async fn try_transition_returns_already_applied_when_status_matches() {
		let (state_machine, _temp) = test_state_machine_with_order(OrderStatus::Executed).await;
		let outcome = state_machine
			.try_transition_order_status("test_order_1", OrderStatus::Executed)
			.await
			.unwrap();
		assert!(!outcome.applied());
		assert!(matches!(outcome, OrderTransitionOutcome::AlreadyApplied(_)));
	}

	#[tokio::test]
	async fn try_transition_returns_already_applied_when_current_is_downstream() {
		let (state_machine, _temp) = test_state_machine_with_order(OrderStatus::PostFilled).await;
		let outcome = state_machine
			.try_transition_order_status("test_order_1", OrderStatus::Executed)
			.await
			.unwrap();
		assert!(!outcome.applied());
		assert!(matches!(outcome, OrderTransitionOutcome::AlreadyApplied(_)));
	}

	#[tokio::test]
	async fn try_transition_returns_already_applied_when_current_is_finalized() {
		let (state_machine, _temp) = test_state_machine_with_order(OrderStatus::Finalized).await;
		let outcome = state_machine
			.try_transition_order_status("test_order_1", OrderStatus::Executed)
			.await
			.unwrap();
		assert!(matches!(outcome, OrderTransitionOutcome::AlreadyApplied(_)));
	}

	#[tokio::test]
	async fn try_transition_errors_on_backward_move() {
		// A truly invalid transition is one where:
		//   - the current status is NOT downstream of the target (so we don't
		//     short-circuit to `AlreadyApplied`)
		//   - AND there is no direct forward edge from current to target
		//
		// `Created → Settled` qualifies: Settled is not reachable from Created
		// in one hop (must pass through Executing → Executed first), and
		// Created is not downstream of Settled in the forward graph. Backward
		// moves between states on the same lineage (e.g. Executing → Created)
		// are absorbed into `AlreadyApplied` by design — the current status
		// is already past the target — so they do NOT surface as errors.
		let (state_machine, _temp) = test_state_machine_with_order(OrderStatus::Created).await;

		let err = state_machine
			.try_transition_order_status("test_order_1", OrderStatus::Settled)
			.await
			.unwrap_err();
		assert!(matches!(err, OrderStateError::InvalidTransition { .. }));
	}
}
