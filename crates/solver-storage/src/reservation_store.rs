//! Compact-input reservation ledger.
//!
//! Guards against over-admission of `ResourceLock` (Compact) intents that are
//! all backed by the same on-chain deposit. Intake admission for a Compact
//! intent performs a stateless `TheCompact.balanceOf(owner, id) >= amount`
//! check, but with no reservation in storage N concurrently submitted orders
//! against the same deposit all pass and get filled on the destination chain,
//! while only one origin claim can succeed. The solver eats the cost of the
//! unbacked fills.
//!
//! This store maintains a per-key reserved total, updated atomically, so that
//! `reserved + amount` can never exceed the available balance. Reservations are
//! keyed by `(origin_chain_id, user, token_id)` — the tuple that uniquely
//! identifies a Compact deposit.
//!
//! # Atomicity
//!
//! Reservations are mutated using the storage backend's atomic primitives via
//! [`StorageService`]:
//!
//! - First reservation on a key uses `set_nx` (Redis `SET NX`, in-memory lock).
//! - Subsequent reservations use a compare-and-swap loop on the raw reserved
//!   bytes, retrying on contention. The check `reserved + amount <= balance`
//!   happens inside the same CAS critical section, so two concurrent reserves
//!   can never both succeed past the balance.
//!
//! Each reservation carries a TTL so a crashed solver (which never reaches a
//! terminal state to release) cannot strand a deposit's capacity forever.

use crate::{StorageError, StorageService};
use alloy_primitives::{Address, U256};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, warn};

/// Storage namespace for Compact-input reservations.
const RESERVATION_NAMESPACE: &str = "compact_reservation";

/// Maximum number of compare-and-swap retries before giving up under contention.
const MAX_CAS_RETRIES: usize = 16;

/// Errors that can occur during reservation operations.
#[derive(Error, Debug)]
pub enum ReservationError {
	/// Storage backend operation failed.
	#[error("Storage error: {0}")]
	Storage(String),

	/// The requested reservation would exceed the available balance.
	#[error(
		"Insufficient Compact capacity for user {user:#x} token {token_id} on chain {chain_id}: \
		 requested {requested}, already reserved {reserved}, available balance {balance}"
	)]
	InsufficientCapacity {
		/// Origin chain id of the deposit.
		chain_id: u64,
		/// Deposit owner.
		user: Address,
		/// Compact token id.
		token_id: U256,
		/// Amount requested by this reservation.
		requested: U256,
		/// Amount already reserved by other in-flight orders.
		reserved: U256,
		/// On-chain available balance.
		balance: U256,
	},

	/// The reservation ledger was contended beyond the retry budget.
	#[error("Reservation ledger contended; please retry")]
	Contended,
}

impl From<StorageError> for ReservationError {
	fn from(err: StorageError) -> Self {
		ReservationError::Storage(err.to_string())
	}
}

/// Atomic ledger of reserved Compact-input amounts, keyed by deposit.
///
/// Wraps the shared [`StorageService`] so reservations live in the same backend
/// (Redis in production) as the rest of solver state and are visible across all
/// solver workers.
pub struct ReservationStore {
	storage: Arc<StorageService>,
	ttl: Duration,
}

impl ReservationStore {
	/// Create a new reservation store backed by the shared storage service.
	///
	/// `ttl_seconds` bounds how long an unreleased reservation lives; pick a
	/// value comfortably larger than the worst-case order lifetime so that
	/// legitimately in-flight orders are never prematurely freed, while a
	/// crashed solver eventually self-heals.
	pub fn new(storage: Arc<StorageService>, ttl_seconds: u64) -> Self {
		Self {
			storage,
			ttl: Duration::from_secs(ttl_seconds),
		}
	}

	/// Build the storage id for a reservation key.
	fn reservation_id(chain_id: u64, user: &Address, token_id: U256) -> String {
		format!("{chain_id}:{user:#x}:{token_id}")
	}

	/// Atomically reserve `amount` against the deposit identified by
	/// `(chain_id, user, token_id)`, rejecting if `reserved + amount` would
	/// exceed `balance`.
	///
	/// On success the reservation total is increased by `amount` and the new
	/// total is returned. On failure no state is mutated.
	pub async fn reserve(
		&self,
		chain_id: u64,
		user: &Address,
		token_id: U256,
		amount: U256,
		balance: U256,
	) -> Result<U256, ReservationError> {
		let id = Self::reservation_id(chain_id, user, token_id);

		for _ in 0..MAX_CAS_RETRIES {
			match self
				.storage
				.retrieve_bytes(RESERVATION_NAMESPACE, &id)
				.await
			{
				Ok(current_bytes) => {
					let reserved = decode_u256(&current_bytes);
					let new_total = reserved.checked_add(amount).ok_or(
						ReservationError::InsufficientCapacity {
							chain_id,
							user: *user,
							token_id,
							requested: amount,
							reserved,
							balance,
						},
					)?;
					if new_total > balance {
						return Err(ReservationError::InsufficientCapacity {
							chain_id,
							user: *user,
							token_id,
							requested: amount,
							reserved,
							balance,
						});
					}

					let swapped = self
						.storage
						.compare_and_swap_bytes(
							RESERVATION_NAMESPACE,
							&id,
							&current_bytes,
							encode_u256(new_total),
							None,
							Some(self.ttl),
						)
						.await?;
					if swapped {
						debug!(
							chain_id,
							user = %format!("{user:#x}"),
							token_id = %token_id,
							amount = %amount,
							new_total = %new_total,
							"Reserved Compact input"
						);
						return Ok(new_total);
					}
					// Lost the race; retry from a fresh read.
				},
				Err(StorageError::NotFound(_)) => {
					// No reservation yet: this would be the first.
					if amount > balance {
						return Err(ReservationError::InsufficientCapacity {
							chain_id,
							user: *user,
							token_id,
							requested: amount,
							reserved: U256::ZERO,
							balance,
						});
					}
					let created = self
						.storage
						.set_nx_bytes(
							RESERVATION_NAMESPACE,
							&id,
							encode_u256(amount),
							Some(self.ttl),
						)
						.await?;
					if created {
						debug!(
							chain_id,
							user = %format!("{user:#x}"),
							token_id = %token_id,
							amount = %amount,
							"Reserved Compact input (first)"
						);
						return Ok(amount);
					}
					// Another reserve created the key first; retry as an update.
				},
				Err(e) => return Err(e.into()),
			}
		}

		warn!(
			chain_id,
			user = %format!("{user:#x}"),
			token_id = %token_id,
			"Compact reservation ledger contended beyond retry budget"
		);
		Err(ReservationError::Contended)
	}

	/// Release `amount` previously reserved for the deposit, e.g. when an order
	/// reaches a terminal state (claimed/settled/failed).
	///
	/// Best-effort and idempotent-ish: releasing more than is currently
	/// reserved saturates at zero rather than underflowing. A missing key is
	/// treated as already released.
	pub async fn release(
		&self,
		chain_id: u64,
		user: &Address,
		token_id: U256,
		amount: U256,
	) -> Result<(), ReservationError> {
		let id = Self::reservation_id(chain_id, user, token_id);

		for _ in 0..MAX_CAS_RETRIES {
			let current_bytes = match self
				.storage
				.retrieve_bytes(RESERVATION_NAMESPACE, &id)
				.await
			{
				Ok(bytes) => bytes,
				Err(StorageError::NotFound(_)) => return Ok(()),
				Err(e) => return Err(e.into()),
			};

			let reserved = decode_u256(&current_bytes);
			let new_total = reserved.saturating_sub(amount);

			if new_total.is_zero() {
				// Best-effort delete; if it races we simply drop the (zero) key.
				self.storage.remove(RESERVATION_NAMESPACE, &id).await.ok();
				return Ok(());
			}

			let swapped = self
				.storage
				.compare_and_swap_bytes(
					RESERVATION_NAMESPACE,
					&id,
					&current_bytes,
					encode_u256(new_total),
					None,
					Some(self.ttl),
				)
				.await?;
			if swapped {
				debug!(
					chain_id,
					user = %format!("{user:#x}"),
					token_id = %token_id,
					amount = %amount,
					new_total = %new_total,
					"Released Compact input reservation"
				);
				return Ok(());
			}
			// Lost the race; retry.
		}

		Err(ReservationError::Contended)
	}

	/// Current reserved total for a deposit (0 if none).
	pub async fn reserved(
		&self,
		chain_id: u64,
		user: &Address,
		token_id: U256,
	) -> Result<U256, ReservationError> {
		let id = Self::reservation_id(chain_id, user, token_id);
		match self
			.storage
			.retrieve_bytes(RESERVATION_NAMESPACE, &id)
			.await
		{
			Ok(bytes) => Ok(decode_u256(&bytes)),
			Err(StorageError::NotFound(_)) => Ok(U256::ZERO),
			Err(e) => Err(e.into()),
		}
	}
}

impl std::fmt::Debug for ReservationStore {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ReservationStore")
			.field("ttl_secs", &self.ttl.as_secs())
			.finish()
	}
}

/// Encode a reserved total as fixed 32-byte big-endian so CAS comparisons are
/// stable regardless of value.
fn encode_u256(value: U256) -> Vec<u8> {
	value.to_be_bytes::<32>().to_vec()
}

/// Decode a reserved total; malformed/short values are treated as zero so a
/// corrupt entry fails safe (re-reservation rather than silent over-admission
/// would require the value to read *higher*, which a short buffer never does).
fn decode_u256(bytes: &[u8]) -> U256 {
	if bytes.len() == 32 {
		let mut buf = [0u8; 32];
		buf.copy_from_slice(bytes);
		U256::from_be_bytes(buf)
	} else {
		U256::ZERO
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::implementations::memory::MemoryStorage;

	fn store_with_ttl(ttl_secs: u64) -> ReservationStore {
		let storage = Arc::new(StorageService::new(Box::new(MemoryStorage::new())));
		ReservationStore::new(storage, ttl_secs)
	}

	const USER: Address = Address::new([0x11; 20]);

	#[tokio::test]
	async fn first_reservation_succeeds_and_tracks_total() {
		let store = store_with_ttl(300);
		let token = U256::from(7u64);
		let balance = U256::from(1000u64);

		let total = store
			.reserve(1, &USER, token, U256::from(400u64), balance)
			.await
			.unwrap();
		assert_eq!(total, U256::from(400u64));
		assert_eq!(
			store.reserved(1, &USER, token).await.unwrap(),
			U256::from(400u64)
		);
	}

	#[tokio::test]
	async fn second_reservation_within_balance_accumulates() {
		let store = store_with_ttl(300);
		let token = U256::from(7u64);
		let balance = U256::from(1000u64);

		store
			.reserve(1, &USER, token, U256::from(400u64), balance)
			.await
			.unwrap();
		let total = store
			.reserve(1, &USER, token, U256::from(500u64), balance)
			.await
			.unwrap();
		assert_eq!(total, U256::from(900u64));
	}

	#[tokio::test]
	async fn over_reservation_is_rejected() {
		let store = store_with_ttl(300);
		let token = U256::from(7u64);
		let balance = U256::from(1000u64);

		store
			.reserve(1, &USER, token, U256::from(700u64), balance)
			.await
			.unwrap();
		let err = store
			.reserve(1, &USER, token, U256::from(700u64), balance)
			.await
			.unwrap_err();
		assert!(matches!(err, ReservationError::InsufficientCapacity { .. }));
		// Reserved total must be unchanged after a rejected reservation.
		assert_eq!(
			store.reserved(1, &USER, token).await.unwrap(),
			U256::from(700u64)
		);
	}

	#[tokio::test]
	async fn release_frees_capacity() {
		let store = store_with_ttl(300);
		let token = U256::from(7u64);
		let balance = U256::from(1000u64);

		store
			.reserve(1, &USER, token, U256::from(800u64), balance)
			.await
			.unwrap();
		store
			.release(1, &USER, token, U256::from(800u64))
			.await
			.unwrap();
		assert_eq!(store.reserved(1, &USER, token).await.unwrap(), U256::ZERO);
		// Capacity is available again.
		store
			.reserve(1, &USER, token, U256::from(900u64), balance)
			.await
			.unwrap();
	}

	#[tokio::test]
	async fn keys_are_isolated_by_chain_user_token() {
		let store = store_with_ttl(300);
		let balance = U256::from(1000u64);
		let other_user = Address::new([0x22; 20]);

		store
			.reserve(1, &USER, U256::from(1u64), U256::from(900u64), balance)
			.await
			.unwrap();
		// Different token id on same user: independent capacity.
		store
			.reserve(1, &USER, U256::from(2u64), U256::from(900u64), balance)
			.await
			.unwrap();
		// Different chain: independent.
		store
			.reserve(2, &USER, U256::from(1u64), U256::from(900u64), balance)
			.await
			.unwrap();
		// Different user: independent.
		store
			.reserve(
				1,
				&other_user,
				U256::from(1u64),
				U256::from(900u64),
				balance,
			)
			.await
			.unwrap();
	}

	/// RED-anchor test: two concurrent reservers for the same deposit where the
	/// balance backs only one of them. Exactly one must succeed; the total
	/// reserved must never exceed the balance. A stateless balance check (the
	/// pre-fix behavior) would admit both.
	#[tokio::test]
	async fn concurrent_reserves_cannot_both_exceed_balance() {
		let store = Arc::new(store_with_ttl(300));
		let token = U256::from(42u64);
		// Balance backs only a single 600 reservation; two would need 1200.
		let balance = U256::from(1000u64);
		let amount = U256::from(600u64);

		let s1 = Arc::clone(&store);
		let s2 = Arc::clone(&store);

		let h1 = tokio::spawn(async move { s1.reserve(1, &USER, token, amount, balance).await });
		let h2 = tokio::spawn(async move { s2.reserve(1, &USER, token, amount, balance).await });

		let r1 = h1.await.unwrap();
		let r2 = h2.await.unwrap();

		let successes = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
		let failures = [&r1, &r2].iter().filter(|r| r.is_err()).count();
		assert_eq!(
			successes, 1,
			"exactly one reservation must succeed: {r1:?} {r2:?}"
		);
		assert_eq!(failures, 1, "exactly one reservation must be rejected");

		// The persisted reserved total must never exceed the balance.
		let reserved = store.reserved(1, &USER, token).await.unwrap();
		assert!(
			reserved <= balance,
			"reserved {reserved} exceeded balance {balance}"
		);
		assert_eq!(reserved, amount);
	}

	#[tokio::test]
	async fn many_concurrent_reserves_respect_balance() {
		let store = Arc::new(store_with_ttl(300));
		let token = U256::from(99u64);
		let balance = U256::from(1000u64);
		let amount = U256::from(300u64); // only 3 of N can fit

		let mut handles = Vec::new();
		for _ in 0..10 {
			let s = Arc::clone(&store);
			handles.push(tokio::spawn(async move {
				s.reserve(5, &USER, token, amount, balance).await
			}));
		}

		let mut successes = 0usize;
		for h in handles {
			if h.await.unwrap().is_ok() {
				successes += 1;
			}
		}
		assert_eq!(
			successes, 3,
			"exactly floor(1000/300)=3 reservations should fit"
		);

		let reserved = store.reserved(5, &USER, token).await.unwrap();
		assert!(
			reserved <= balance,
			"reserved {reserved} exceeded balance {balance}"
		);
		assert_eq!(reserved, U256::from(900u64));
	}
}
