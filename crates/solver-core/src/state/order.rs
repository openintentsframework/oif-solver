//! Order state machine implementation.
//!
//! Manages order state transitions with validation, ensuring orders move through
//! valid lifecycle states: Created -> Pending -> Executed -> Settled -> Finalized.
//! Also handles failure states and provides utilities for updating order fields.

use once_cell::sync::Lazy;
use solver_storage::{
	compact_reservations::CompactReservationStore, StorageIndexes, StorageService,
};
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
const ORDER_CAS_MAX_RETRIES: usize = 8;

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
	/// Shared in-flight Compact-deposit reservation accounting.
	///
	/// MUST be the same instance the intake path (`IntentHandler`) reserves
	/// through: `CompactReservationStore` holds per-lock-id mutex guards that
	/// only serialize admissions when the SAME store instance is reused. A
	/// fresh `::new()` per call would defeat the file-backend race fix.
	compact_reservations: Arc<CompactReservationStore>,
}

impl OrderStateMachine {
	pub fn new(storage: Arc<StorageService>) -> Self {
		let compact_reservations = Arc::new(CompactReservationStore::new(storage.clone()));
		Self::with_compact_reservations(storage, compact_reservations)
	}

	/// Constructs a state machine sharing an existing reservation store.
	///
	/// Production wiring (`SolverEngine::new`) builds one
	/// `Arc<CompactReservationStore>` and passes it here AND to `IntentHandler`
	/// so reserve (intake) and release (terminal transition) serialize against
	/// the same per-lock-id guards.
	pub fn with_compact_reservations(
		storage: Arc<StorageService>,
		compact_reservations: Arc<CompactReservationStore>,
	) -> Self {
		Self {
			storage,
			compact_reservations,
		}
	}

	/// The shared in-flight Compact-deposit reservation store.
	///
	/// `IntentHandler` clones this so intake reservation and terminal-state
	/// release go through the SAME `CompactReservationStore` instance — the
	/// per-lock-id mutex guards only serialize when the instance is shared.
	pub fn compact_reservations(&self) -> Arc<CompactReservationStore> {
		self.compact_reservations.clone()
	}

	/// Updates an order with a closure and persists it
	pub async fn update_order_with<F>(
		&self,
		order_id: &str,
		mut updater: F,
	) -> Result<Order, OrderStateError>
	where
		F: FnMut(&mut Order),
	{
		for _ in 0..ORDER_CAS_MAX_RETRIES {
			let expected = self
				.storage
				.retrieve_bytes(StorageKey::Orders.as_str(), order_id)
				.await
				.map_err(|e| OrderStateError::Storage(e.to_string()))?;
			let mut order = decode_order(&expected)?;

			updater(&mut order);
			stamp_updated_at(&mut order)?;

			let indexes = order_storage_indexes(&order);
			let new_value =
				serde_json::to_vec(&order).map_err(|e| OrderStateError::Storage(e.to_string()))?;

			let swapped = self
				.storage
				.compare_and_swap_bytes(
					StorageKey::Orders.as_str(),
					order_id,
					&expected,
					new_value,
					Some(indexes),
					None,
				)
				.await
				.map_err(|e| OrderStateError::Storage(e.to_string()))?;

			if swapped {
				return Ok(order);
			}
		}

		Err(OrderStateError::Storage(format!(
			"CAS conflict after {ORDER_CAS_MAX_RETRIES} retries updating order {order_id}"
		)))
	}

	/// Transitions an order to a new status with validation
	pub async fn transition_order_status(
		&self,
		order_id: &str,
		new_status: OrderStatus,
	) -> Result<Order, OrderStateError> {
		let outcome = self
			.try_transition_order_status(order_id, new_status, |_| {})
			.await?;
		Ok(outcome.into_order())
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
		mut updater: impl FnMut(&mut Order),
	) -> Result<OrderTransitionOutcome, OrderStateError> {
		for _ in 0..ORDER_CAS_MAX_RETRIES {
			let expected = self
				.storage
				.retrieve_bytes(StorageKey::Orders.as_str(), order_id)
				.await
				.map_err(|e| OrderStateError::Storage(e.to_string()))?;
			let mut order = decode_order(&expected)?;

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

			order.status = new_status.clone();
			updater(&mut order);
			stamp_updated_at(&mut order)?;

			let indexes = order_storage_indexes(&order);
			let new_value =
				serde_json::to_vec(&order).map_err(|e| OrderStateError::Storage(e.to_string()))?;

			let swapped = self
				.storage
				.compare_and_swap_bytes(
					StorageKey::Orders.as_str(),
					order_id,
					&expected,
					new_value,
					Some(indexes),
					None,
				)
				.await
				.map_err(|e| OrderStateError::Storage(e.to_string()))?;

			if swapped {
				if should_release_compact_reservations(&order.status) {
					self.release_compact_reservations(&order).await;
				}
				return Ok(OrderTransitionOutcome::Applied(order));
			}
		}

		Err(OrderStateError::Storage(format!(
			"CAS conflict after {ORDER_CAS_MAX_RETRIES} retries transitioning order {order_id}"
		)))
	}

	/// Best-effort release of the compact deposit reservations taken at
	/// intake for a resource-lock order reaching a terminal state.
	///
	/// Delegates to the shared
	/// [`crate::handlers::compact_reservation::release_compact_reservations`];
	/// failures only delay reuse of the deposit until the reservation lapses at
	/// the order's `expires` timestamp, so they are logged, not propagated.
	async fn release_compact_reservations(&self, order: &Order) {
		if order.standard != "eip7683" {
			return;
		}
		crate::handlers::compact_reservation::release_compact_reservations(
			&self.compact_reservations,
			order,
			"terminal transition",
		)
		.await;
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
			TransactionType::Prepare => order.prepare_tx_hash = Some(tx_hash.clone()),
			TransactionType::Fill => order.fill_tx_hash = Some(tx_hash.clone()),
			TransactionType::PostFill => order.post_fill_tx_hash = Some(tx_hash.clone()),
			TransactionType::PreClaim => order.pre_claim_tx_hash = Some(tx_hash.clone()),
			TransactionType::Claim => order.claim_tx_hash = Some(tx_hash.clone()),
			TransactionType::Approval
			| TransactionType::Withdrawal
			| TransactionType::Bridge
			| TransactionType::Pusher => {},
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
			order.execution_params = Some(params.clone());
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
			order.fill_proof = Some(proof.clone());
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

/// Whether reaching `status` may safely release a resource-lock order's
/// reserved Compact deposit.
///
/// A reservation must NOT be released while the solver might still need the
/// origin deposit — either because the destination fill has committed (recovery
/// must still claim) or because a fill tx the solver broadcast might yet land
/// on-chain. Releasing in either case would let another order consume the same
/// balance and oversubscribe the deposit (the exact C-06 failure mode).
///
/// Release policy: release ONLY on `Finalized`. Every `Failed(_)` variant holds
/// the reservation and lets it lapse at the order's `expires` (the TTL
/// backstop in `CompactReservationStore`).
///
/// - `Finalized` — the full lifecycle completed (the claim landed); the
///   reservation is no longer needed.
/// - `Failed(Fill)` is AMBIGUOUS and must NOT release. The engine
///   (`engine/mod.rs`, the `OrderExecuting` arm) marks an order
///   `Failed(Fill, ...)` whenever `OrderHandler::handle_execution` returns Err.
///   That includes the window in `handle_execution` AFTER `delivery.deliver`
///   has already broadcast the fill tx but a subsequent metadata write fails —
///   either `set_transaction_hash` or the `OrderByTxHash` reverse-mapping
///   `storage.store`. In that window the delivered fill tx may still mine
///   successfully on-chain while the order is marked `Failed(Fill)`. Releasing
///   then could admit another order against the same deposit before the first
///   fill lands → oversubscription. So we cannot prove from `Failed(Fill)`
///   alone that the deposit was never consumed; we hold the reservation.
/// - `Failed(Prepare)` and all post-fill failures — `Failed(PostFill)`,
///   `Failed(PreClaim)`, `Failed(Claim)` — are likewise held, for symmetry and
///   safety: none of them can prove the fill never landed, and holding is never
///   unsafe.
///
/// Trade-off: capacity for a failed order stays held until the order's
/// `expires` timestamp instead of being freed immediately. This is deliberate.
/// The reservation is keyed by `expires` and lapses on its own (no leak), so
/// the only cost is delayed reuse of that specific deposit for the failed
/// order's lifetime — which is strictly safe, whereas an early release on an
/// ambiguous `Failed` is not.
fn should_release_compact_reservations(status: &OrderStatus) -> bool {
	matches!(status, OrderStatus::Finalized)
}

fn order_storage_indexes(order: &Order) -> StorageIndexes {
	StorageIndexes::new()
		.with_field(
			STATUS_KIND_INDEX_FIELD,
			status_kind_index_value(&order.status),
		)
		.with_field(IS_TERMINAL_INDEX_FIELD, is_terminal_status(&order.status))
}

fn decode_order(bytes: &[u8]) -> Result<Order, OrderStateError> {
	serde_json::from_slice(bytes).map_err(|e| OrderStateError::Storage(e.to_string()))
}

fn stamp_updated_at(order: &mut Order) -> Result<(), OrderStateError> {
	order.updated_at = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map_err(|e| OrderStateError::TimeError(e.to_string()))?
		.as_secs();
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::U256;
	use solver_storage::{MockStorageInterface, StorageService};
	use solver_types::{
		standards::eip7683::{Eip7683OrderData, LockType},
		utils::tests::builders::OrderBuilder,
		OrderStatus, TransactionHash, TransactionType,
	};
	use std::collections::VecDeque;
	use std::sync::{
		atomic::{AtomicUsize, Ordering},
		Arc, Mutex,
	};
	use tokio;

	fn create_test_storage() -> Arc<StorageService> {
		let backend = Box::new(solver_storage::implementations::memory::MemoryStorage::new());
		Arc::new(StorageService::new(backend))
	}

	fn create_test_order() -> Order {
		OrderBuilder::new().with_id("test_order_1").build()
	}

	#[tokio::test]
	async fn terminal_transition_releases_compact_reservation() {
		use solver_storage::compact_reservations::{CompactReservationStore, DepositReservation};
		use solver_types::standards::eip7683::GasLimitOverrides;

		let storage = create_test_storage();
		let state_machine = OrderStateMachine::new(storage.clone());
		let reservations = CompactReservationStore::new(storage);

		let user = "0x1234567890123456789012345678901234567890";
		let token_id = U256::from(7u64);
		let amount = U256::from(500u64);
		let expires = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap()
			.as_secs()
			+ 3600;

		let deposit = DepositReservation {
			chain_id: 1,
			owner: user.to_string(),
			token_id,
			amount,
			available_balance: amount,
		};
		reservations
			.reserve_order("rl_order", expires, &[deposit.clone()])
			.await
			.unwrap();
		// Deposit fully reserved: a second order must be rejected.
		assert!(reservations
			.reserve_order("rl_other", expires, &[deposit.clone()])
			.await
			.is_err());

		let order_data = Eip7683OrderData {
			user: user.to_string(),
			nonce: U256::from(1u64),
			origin_chain_id: U256::from(1u64),
			expires: expires as u32,
			fill_deadline: expires as u32,
			input_oracle: user.to_string(),
			inputs: vec![[token_id, amount]],
			order_id: [0u8; 32],
			gas_limit_overrides: GasLimitOverrides::default(),
			outputs: vec![],
			raw_order_data: None,
			signature: None,
			sponsor: None,
			lock_type: Some(LockType::ResourceLock),
		};
		let order = OrderBuilder::new()
			.with_id("rl_order")
			.with_status(OrderStatus::Settled)
			.with_data(serde_json::to_value(&order_data).unwrap())
			.build();
		state_machine.store_order(&order).await.unwrap();

		state_machine
			.transition_order_status("rl_order", OrderStatus::Finalized)
			.await
			.unwrap();

		// The terminal transition released the reservation, freeing the
		// deposit for the next order.
		reservations
			.reserve_order("rl_other", expires, &[deposit])
			.await
			.unwrap();
	}

	/// Builds a resource-lock order whose single input fully subscribes a
	/// `token_id` deposit, plus the matching `DepositReservation`.
	fn resource_lock_order_and_deposit(
		order_id: &str,
		status: OrderStatus,
		expires: u64,
	) -> (
		Order,
		solver_storage::compact_reservations::DepositReservation,
	) {
		use solver_storage::compact_reservations::DepositReservation;
		use solver_types::standards::eip7683::GasLimitOverrides;

		let user = "0x1234567890123456789012345678901234567890";
		let token_id = U256::from(7u64);
		let amount = U256::from(500u64);

		let order_data = Eip7683OrderData {
			user: user.to_string(),
			nonce: U256::from(1u64),
			origin_chain_id: U256::from(1u64),
			expires: expires as u32,
			fill_deadline: expires as u32,
			input_oracle: user.to_string(),
			inputs: vec![[token_id, amount]],
			order_id: [0u8; 32],
			gas_limit_overrides: GasLimitOverrides::default(),
			outputs: vec![],
			raw_order_data: None,
			signature: None,
			sponsor: None,
			lock_type: Some(LockType::ResourceLock),
		};
		let order = OrderBuilder::new()
			.with_id(order_id)
			.with_status(status)
			.with_data(serde_json::to_value(&order_data).unwrap())
			.build();
		let deposit = DepositReservation {
			chain_id: 1,
			owner: user.to_string(),
			token_id,
			amount,
			available_balance: amount,
		};
		(order, deposit)
	}

	#[tokio::test]
	async fn failed_post_fill_transition_does_not_release_compact_reservation() {
		// Fix B: once the fill has committed, a post-fill failure must keep the
		// deposit reserved so recovery can still claim. Releasing here would let
		// another order consume the same balance and strand recovery.
		use solver_storage::compact_reservations::CompactReservationStore;

		let storage = create_test_storage();
		let state_machine = OrderStateMachine::new(storage.clone());
		let reservations = CompactReservationStore::new(storage);

		let expires = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap()
			.as_secs()
			+ 3600;

		// Order is at `Executed` (fill already confirmed on-chain).
		let (order, deposit) =
			resource_lock_order_and_deposit("rl_pf", OrderStatus::Executed, expires);
		reservations
			.reserve_order("rl_pf", expires, &[deposit.clone()])
			.await
			.unwrap();
		state_machine.store_order(&order).await.unwrap();

		state_machine
			.transition_order_status(
				"rl_pf",
				OrderStatus::Failed(TransactionType::PostFill, "boom".to_string()),
			)
			.await
			.unwrap();

		// The reservation must STILL be held: a competing order against the
		// same fully-subscribed deposit must be rejected.
		assert!(
			reservations
				.reserve_order("rl_other", expires, &[deposit])
				.await
				.is_err(),
			"post-fill failure must not release the reservation"
		);
	}

	#[tokio::test]
	async fn failed_fill_transition_does_not_release_compact_reservation() {
		// Fix 1 (C-06 round 2): `Failed(Fill)` is ambiguous — the engine sets it
		// when `handle_execution` returns Err, which includes the window AFTER
		// `delivery.deliver` has broadcast the fill tx but a later metadata write
		// (`set_transaction_hash` / `OrderByTxHash`) fails. The delivered fill may
		// still land on-chain, so releasing here could admit another order against
		// the same deposit and oversubscribe it. The reservation must be HELD and
		// allowed to lapse at the order's `expires` (the TTL backstop).
		use solver_storage::compact_reservations::CompactReservationStore;

		let storage = create_test_storage();
		let state_machine = OrderStateMachine::new(storage.clone());
		let reservations = CompactReservationStore::new(storage);

		let expires = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap()
			.as_secs()
			+ 3600;

		// Order is at `Executing` (fill submitted but not confirmed).
		let (order, deposit) =
			resource_lock_order_and_deposit("rl_fail", OrderStatus::Executing, expires);
		reservations
			.reserve_order("rl_fail", expires, &[deposit.clone()])
			.await
			.unwrap();
		state_machine.store_order(&order).await.unwrap();

		state_machine
			.transition_order_status(
				"rl_fail",
				OrderStatus::Failed(TransactionType::Fill, "reverted".to_string()),
			)
			.await
			.unwrap();

		// The reservation must STILL be held: a competing order against the same
		// fully-subscribed deposit must be rejected, since the fill tx may have
		// landed on-chain.
		assert!(
			reservations
				.reserve_order("rl_other", expires, &[deposit])
				.await
				.is_err(),
			"Failed(Fill) must not release the reservation: the fill tx may still land"
		);
	}

	#[test]
	fn should_release_compact_reservations_policy() {
		// Fix 1 (C-06 round 2): release ONLY on `Finalized`. Every `Failed(_)`
		// variant holds the reservation and lets it lapse at `expires`, because
		// no failure status can prove the fill tx never landed on-chain.
		assert!(should_release_compact_reservations(&OrderStatus::Finalized));
		assert!(!should_release_compact_reservations(&OrderStatus::Failed(
			TransactionType::Prepare,
			"x".to_string()
		)));
		assert!(!should_release_compact_reservations(&OrderStatus::Failed(
			TransactionType::Fill,
			"x".to_string()
		)));
		assert!(!should_release_compact_reservations(&OrderStatus::Failed(
			TransactionType::PostFill,
			"x".to_string()
		)));
		assert!(!should_release_compact_reservations(&OrderStatus::Failed(
			TransactionType::PreClaim,
			"x".to_string()
		)));
		assert!(!should_release_compact_reservations(&OrderStatus::Failed(
			TransactionType::Claim,
			"x".to_string()
		)));
		// Non-terminal statuses never release.
		assert!(!should_release_compact_reservations(&OrderStatus::Executed));
		assert!(!should_release_compact_reservations(&OrderStatus::Settled));
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
			.expect_compare_and_swap_with_indexes()
			.times(1)
			.withf(|key, expected, new_value, indexes, ttl| {
				if key != "orders:update_indexed_order" || ttl.is_some() {
					return false;
				}

				let Ok(expected_order) = serde_json::from_slice::<Order>(expected) else {
					return false;
				};
				if expected_order.status != OrderStatus::Pending {
					return false;
				}

				let Ok(order) = serde_json::from_slice::<Order>(new_value) else {
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
			.returning(|_, _, _, _, _| Box::pin(async move { Ok(true) }));

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

	#[tokio::test]
	async fn update_order_with_uses_cas_and_retries_on_conflict() {
		let mut mock_storage = MockStorageInterface::new();
		let order = OrderBuilder::new()
			.with_id("cas_order")
			.with_status(OrderStatus::Pending)
			.build();
		let order_bytes = serde_json::to_vec(&order).unwrap();
		let reads = Arc::new(Mutex::new(VecDeque::from([
			order_bytes.clone(),
			order_bytes.clone(),
		])));

		let reads_for_mock = reads.clone();
		mock_storage
			.expect_get_bytes()
			.with(mockall::predicate::eq("orders:cas_order"))
			.times(2)
			.returning(move |_| {
				let bytes = reads_for_mock.lock().unwrap().pop_front().unwrap();
				Box::pin(async move { Ok(bytes) })
			});

		let cas_attempts = Arc::new(AtomicUsize::new(0));
		let cas_attempts_for_mock = cas_attempts.clone();
		mock_storage
			.expect_compare_and_swap_with_indexes()
			.times(2)
			.withf(|key, _expected, new_value, indexes, ttl| {
				if key != "orders:cas_order" || ttl.is_some() {
					return false;
				}

				let Ok(order) = serde_json::from_slice::<Order>(new_value) else {
					return false;
				};
				if order.status != OrderStatus::Executing {
					return false;
				}

				let Some(indexes) = indexes else {
					return false;
				};
				indexes.fields.get("status_kind") == Some(&serde_json::json!("executing"))
					&& indexes.fields.get("is_terminal") == Some(&serde_json::json!(false))
			})
			.returning(move |_, _, _, _, _| {
				let attempt = cas_attempts_for_mock.fetch_add(1, Ordering::SeqCst);
				Box::pin(async move { Ok(attempt > 0) })
			});

		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let state_machine = OrderStateMachine::new(storage);
		let updater_attempts = Arc::new(AtomicUsize::new(0));
		let updater_attempts_for_closure = updater_attempts.clone();

		let updated = state_machine
			.update_order_with("cas_order", move |order| {
				updater_attempts_for_closure.fetch_add(1, Ordering::SeqCst);
				order.status = OrderStatus::Executing;
			})
			.await
			.unwrap();

		assert_eq!(updated.status, OrderStatus::Executing);
		assert_eq!(cas_attempts.load(Ordering::SeqCst), 2);
		assert_eq!(updater_attempts.load(Ordering::SeqCst), 2);
	}

	#[tokio::test]
	async fn try_transition_order_status_writes_status_and_hash_in_one_cas() {
		let mut mock_storage = MockStorageInterface::new();
		let order = OrderBuilder::new()
			.with_id("transition_cas_order")
			.with_status(OrderStatus::Executing)
			.build();
		let order_bytes = serde_json::to_vec(&order).unwrap();
		let fill_hash = TransactionHash(vec![0x33; 32]);

		mock_storage
			.expect_get_bytes()
			.with(mockall::predicate::eq("orders:transition_cas_order"))
			.times(1)
			.return_once(move |_| Box::pin(async move { Ok(order_bytes) }));

		let expected_hash = fill_hash.clone();
		mock_storage
			.expect_compare_and_swap_with_indexes()
			.times(1)
			.withf(move |key, _expected, new_value, indexes, ttl| {
				if key != "orders:transition_cas_order" || ttl.is_some() {
					return false;
				}

				let Ok(order) = serde_json::from_slice::<Order>(new_value) else {
					return false;
				};
				if order.status != OrderStatus::Executed
					|| order.fill_tx_hash != Some(expected_hash.clone())
				{
					return false;
				}

				let Some(indexes) = indexes else {
					return false;
				};
				indexes.fields.get("status_kind") == Some(&serde_json::json!("executed"))
					&& indexes.fields.get("is_terminal") == Some(&serde_json::json!(false))
			})
			.returning(|_, _, _, _, _| Box::pin(async move { Ok(true) }));

		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let state_machine = OrderStateMachine::new(storage);

		let outcome = state_machine
			.try_transition_order_status("transition_cas_order", OrderStatus::Executed, |order| {
				order.fill_tx_hash = Some(fill_hash.clone());
			})
			.await
			.unwrap();

		assert!(outcome.applied());
		assert_eq!(outcome.order().status, OrderStatus::Executed);
		assert_eq!(outcome.order().fill_tx_hash, Some(fill_hash));
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
			.try_transition_order_status("test_order_1", OrderStatus::Executed, |_| {})
			.await
			.unwrap();
		assert!(outcome.applied());
		assert_eq!(outcome.order().status, OrderStatus::Executed);
	}

	#[tokio::test]
	async fn try_transition_returns_already_applied_when_status_matches() {
		let (state_machine, _temp) = test_state_machine_with_order(OrderStatus::Executed).await;
		let outcome = state_machine
			.try_transition_order_status("test_order_1", OrderStatus::Executed, |_| {})
			.await
			.unwrap();
		assert!(!outcome.applied());
		assert!(matches!(outcome, OrderTransitionOutcome::AlreadyApplied(_)));
	}

	#[tokio::test]
	async fn try_transition_returns_already_applied_when_current_is_downstream() {
		let (state_machine, _temp) = test_state_machine_with_order(OrderStatus::PostFilled).await;
		let outcome = state_machine
			.try_transition_order_status("test_order_1", OrderStatus::Executed, |_| {})
			.await
			.unwrap();
		assert!(!outcome.applied());
		assert!(matches!(outcome, OrderTransitionOutcome::AlreadyApplied(_)));
	}

	#[tokio::test]
	async fn try_transition_returns_already_applied_when_current_is_finalized() {
		let (state_machine, _temp) = test_state_machine_with_order(OrderStatus::Finalized).await;
		let outcome = state_machine
			.try_transition_order_status("test_order_1", OrderStatus::Executed, |_| {})
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
			.try_transition_order_status("test_order_1", OrderStatus::Settled, |_| {})
			.await
			.unwrap_err();
		assert!(matches!(err, OrderStateError::InvalidTransition { .. }));
	}
}
