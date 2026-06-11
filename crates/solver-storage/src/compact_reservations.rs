//! In-flight reservation accounting for TheCompact resource-lock deposits.
//!
//! A single Compact deposit can back at most the value it secures, but the
//! deposit's on-chain balance is not reduced until the origin claim lands.
//! Order intake must therefore reserve the deposited amount before the
//! solver commits its own capital on the destination chain, so that two
//! orders drawing on the same deposit are never both admitted.
//!
//! Reservations are stored per lock — keyed by `(chain_id, owner, token_id)`
//! — as a map of `order_id -> (amount, expires_at)`. All mutations go through
//! compare-and-swap on the serialized map, so concurrent admissions cannot
//! oversubscribe. Entries lapse at the order's `expires` timestamp (after
//! which the origin claim is no longer admissible), so a crashed solver or a
//! missed release cannot strand deposit capacity forever.

use crate::{StorageError, StorageService};
use alloy_primitives::U256;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::Mutex;

/// Storage namespace for per-lock reservation maps.
pub const NAMESPACE: &str = "compact_reservations";
const CAS_MAX_RETRIES: usize = 8;
/// Grace added to key TTLs so a reservation never expires from storage
/// before its own `expires_at` lapses.
const TTL_GRACE_SECS: u64 = 60;
/// Bounded attempts for rolling back already-taken locks after a partial
/// reserve fails. Best-effort: if all attempts fail the capacity stays held
/// until the entry lapses at `expires_at` (see `reserve_order`).
const ROLLBACK_MAX_ATTEMPTS: usize = 3;
/// Brief backoff between rollback attempts.
const ROLLBACK_BACKOFF: Duration = Duration::from_millis(20);

/// Errors that can occur during reservation operations.
#[derive(Debug, Error)]
pub enum ReservationError {
	/// The deposit cannot cover this order on top of in-flight reservations.
	#[error(
		"compact deposit oversubscribed: requested {requested}, already reserved {reserved}, available {available}"
	)]
	Oversubscribed {
		requested: U256,
		reserved: U256,
		available: U256,
	},
	/// Storage backend operation failed.
	#[error("storage error: {0}")]
	Storage(String),
}

impl From<StorageError> for ReservationError {
	fn from(err: StorageError) -> Self {
		ReservationError::Storage(err.to_string())
	}
}

/// A single deposit-backed input to reserve at admission.
#[derive(Debug, Clone)]
pub struct DepositReservation {
	/// Origin chain the deposit lives on.
	pub chain_id: u64,
	/// Sponsor address as 0x-prefixed hex (normalized to lowercase internally).
	pub owner: String,
	/// ERC-6909 token id of the lock.
	pub token_id: U256,
	/// Amount this order draws from the deposit.
	pub amount: U256,
	/// On-chain `balanceOf(owner, token_id)` read at admission time.
	pub available_balance: U256,
}

/// One order's claim on a lock, kept until the order reaches a terminal
/// state or `expires_at` lapses.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReservationEntry {
	amount: U256,
	expires_at: u64,
}

type LockReservations = BTreeMap<String, ReservationEntry>;

/// Tracks in-flight reservations against TheCompact deposits.
///
/// Reserve at admission, release on terminal order states. Re-reserving the
/// same `order_id` replaces its entry instead of double-counting, so
/// duplicate submissions of one order are idempotent.
///
/// # Single-process atomicity
///
/// The Redis backend's compare-and-swap is the cross-process guarantee against
/// oversubscription. File and memory backends, however, do NOT provide an
/// atomic create: `set_nx` (used for the first reservation on a lock) does a
/// non-atomic `path.exists()`-then-write, so two concurrent first-reservations
/// can both win the create race and oversubscribe a deposit. To close that
/// window the store holds a process-local async mutex per lock id and serializes
/// the entire read-modify-write critical section under it. The CAS/`set_nx`
/// logic is preserved unchanged inside the mutex so Redis keeps its
/// cross-process guarantee while file/memory backends become race-free within
/// this process.
pub struct CompactReservationStore {
	storage: Arc<StorageService>,
	/// Per-lock-id critical-section guards. Each lock id gets its own mutex so
	/// reservations against different deposits never serialize against each
	/// other. The outer `StdMutex` guards only the map insert (a non-async,
	/// uncontended operation), never held across `.await`.
	lock_guards: StdMutex<BTreeMap<String, Arc<Mutex<()>>>>,
}

impl CompactReservationStore {
	pub fn new(storage: Arc<StorageService>) -> Self {
		Self {
			storage,
			lock_guards: StdMutex::new(BTreeMap::new()),
		}
	}

	fn lock_id(chain_id: u64, owner: &str, token_id: &U256) -> String {
		format!("{}:{}:{:#x}", chain_id, owner.to_lowercase(), token_id)
	}

	/// Returns the per-lock-id critical-section guard, creating it on first use.
	fn guard_for(&self, id: &str) -> Arc<Mutex<()>> {
		let mut guards = self
			.lock_guards
			.lock()
			.expect("compact reservation guard map poisoned");
		guards.entry(id.to_string()).or_default().clone()
	}

	/// Reserves all deposits backing one order, atomically per lock.
	///
	/// Duplicate `(chain_id, owner, token_id)` inputs are aggregated into a
	/// single entry. If any lock is oversubscribed, reservations already taken
	/// for this order are rolled back on a best-effort basis (each release is
	/// retried up to `ROLLBACK_MAX_ATTEMPTS` times with a brief backoff) before
	/// returning the error. If a rollback release still fails after retries, the
	/// failure is logged and that lock's capacity stays held until its entry
	/// lapses at `expires_at` — it is never stranded forever.
	pub async fn reserve_order(
		&self,
		order_id: &str,
		expires_at: u64,
		deposits: &[DepositReservation],
	) -> Result<(), ReservationError> {
		let mut aggregated: BTreeMap<String, DepositReservation> = BTreeMap::new();
		for deposit in deposits {
			let id = Self::lock_id(deposit.chain_id, &deposit.owner, &deposit.token_id);
			match aggregated.get_mut(&id) {
				Some(existing) => {
					existing.amount =
						existing.amount.checked_add(deposit.amount).ok_or_else(|| {
							ReservationError::Storage("reservation amount overflow".to_string())
						})?;
					existing.available_balance =
						existing.available_balance.min(deposit.available_balance);
				},
				None => {
					aggregated.insert(id, deposit.clone());
				},
			}
		}

		let mut taken: Vec<&DepositReservation> = Vec::new();
		for deposit in aggregated.values() {
			if let Err(err) = self.reserve_one(order_id, expires_at, deposit).await {
				for done in taken {
					self.rollback_one(order_id, done).await;
				}
				return Err(err);
			}
			taken.push(deposit);
		}
		Ok(())
	}

	/// Best-effort rollback of a single already-taken lock after a partial
	/// reserve. Retries the release up to `ROLLBACK_MAX_ATTEMPTS` times with a
	/// brief backoff; if it still fails, the capacity stays held until the
	/// entry lapses at its `expires_at`, never stranded forever.
	async fn rollback_one(&self, order_id: &str, deposit: &DepositReservation) {
		for attempt in 1..=ROLLBACK_MAX_ATTEMPTS {
			match self
				.release_one(
					order_id,
					deposit.chain_id,
					&deposit.owner,
					&deposit.token_id,
				)
				.await
			{
				Ok(()) => return,
				Err(release_err) => {
					if attempt == ROLLBACK_MAX_ATTEMPTS {
						tracing::warn!(
							order_id,
							attempts = ROLLBACK_MAX_ATTEMPTS,
							error = %release_err,
							"failed to roll back compact reservation after partial reserve; \
							 capacity held until expiry"
						);
					} else {
						tokio::time::sleep(ROLLBACK_BACKOFF).await;
					}
				},
			}
		}
	}

	/// Releases an order's reservations on the given locks.
	///
	/// Missing locks or entries are a no-op, so releasing an order that was
	/// never reserved (or already lapsed) is safe.
	pub async fn release_order(
		&self,
		order_id: &str,
		locks: &[(u64, String, U256)],
	) -> Result<(), ReservationError> {
		for (chain_id, owner, token_id) in locks {
			self.release_one(order_id, *chain_id, owner, token_id)
				.await?;
		}
		Ok(())
	}

	async fn reserve_one(
		&self,
		order_id: &str,
		expires_at: u64,
		deposit: &DepositReservation,
	) -> Result<(), ReservationError> {
		let id = Self::lock_id(deposit.chain_id, &deposit.owner, &deposit.token_id);

		// Serialize the read-modify-write for this lock id against other
		// in-process admissions. Redis CAS already guards cross-process; this
		// closes the non-atomic `set_nx` create race on file/memory backends.
		let guard = self.guard_for(&id);
		let _critical = guard.lock().await;

		for _ in 0..CAS_MAX_RETRIES {
			let now = unix_now()?;
			match self.storage.retrieve_bytes(NAMESPACE, &id).await {
				// A lapsed file-backed key surfaces as `Expired` rather than
				// `NotFound`; treat both as absent so admission isn't blocked
				// by a stale entry that storage cleanup hasn't reaped yet.
				// `set_nx` already overwrites an expired file, so the create
				// path below works after the key has lapsed.
				Err(StorageError::NotFound(_)) | Err(StorageError::Expired(_)) => {
					check_capacity(U256::ZERO, deposit)?;
					let mut map = LockReservations::new();
					map.insert(
						order_id.to_string(),
						ReservationEntry {
							amount: deposit.amount,
							expires_at,
						},
					);
					let bytes = encode(&map)?;
					if self
						.storage
						.store_bytes_if_absent(NAMESPACE, &id, bytes, Some(ttl_for(&map, now)))
						.await?
					{
						return Ok(());
					}
					// Lost the create race; retry against the existing map.
				},
				Err(err) => return Err(err.into()),
				Ok(expected) => {
					let mut map: LockReservations = decode(&expected)?;
					map.retain(|_, entry| entry.expires_at > now);
					let reserved = map
						.iter()
						.filter(|(existing_id, _)| existing_id.as_str() != order_id)
						.try_fold(U256::ZERO, |acc, (_, entry)| acc.checked_add(entry.amount))
						.ok_or_else(|| {
							ReservationError::Storage("reservation amount overflow".to_string())
						})?;
					check_capacity(reserved, deposit)?;
					map.insert(
						order_id.to_string(),
						ReservationEntry {
							amount: deposit.amount,
							expires_at,
						},
					);
					let new_bytes = encode(&map)?;
					match self
						.storage
						.compare_and_swap_bytes(
							NAMESPACE,
							&id,
							&expected,
							new_bytes,
							None,
							Some(ttl_for(&map, now)),
						)
						.await
					{
						Ok(true) => return Ok(()),
						Ok(false) => continue,
						// Key expired between read and swap; retry from scratch.
						Err(StorageError::NotFound(_)) => continue,
						Err(err) => return Err(err.into()),
					}
				},
			}
		}

		Err(ReservationError::Storage(format!(
			"CAS conflict after {CAS_MAX_RETRIES} retries reserving compact lock {id}"
		)))
	}

	async fn release_one(
		&self,
		order_id: &str,
		chain_id: u64,
		owner: &str,
		token_id: &U256,
	) -> Result<(), ReservationError> {
		let id = Self::lock_id(chain_id, owner, token_id);

		// Serialize against concurrent reservations/releases on this lock id;
		// see `reserve_one` for why the in-process guard is needed alongside CAS.
		let guard = self.guard_for(&id);
		let _critical = guard.lock().await;

		for _ in 0..CAS_MAX_RETRIES {
			let now = unix_now()?;
			let expected = match self.storage.retrieve_bytes(NAMESPACE, &id).await {
				// Missing or already-lapsed: nothing to release.
				Err(StorageError::NotFound(_)) | Err(StorageError::Expired(_)) => return Ok(()),
				Err(err) => return Err(err.into()),
				Ok(bytes) => bytes,
			};

			let mut map: LockReservations = decode(&expected)?;
			map.retain(|_, entry| entry.expires_at > now);
			map.remove(order_id);

			let new_bytes = encode(&map)?;
			match self
				.storage
				.compare_and_swap_bytes(
					NAMESPACE,
					&id,
					&expected,
					new_bytes,
					None,
					Some(ttl_for(&map, now)),
				)
				.await
			{
				Ok(true) => return Ok(()),
				Ok(false) => continue,
				Err(StorageError::NotFound(_)) => return Ok(()),
				Err(err) => return Err(err.into()),
			}
		}

		Err(ReservationError::Storage(format!(
			"CAS conflict after {CAS_MAX_RETRIES} retries releasing compact lock {id}"
		)))
	}
}

fn check_capacity(reserved: U256, deposit: &DepositReservation) -> Result<(), ReservationError> {
	let total = reserved
		.checked_add(deposit.amount)
		.ok_or(ReservationError::Oversubscribed {
			requested: deposit.amount,
			reserved,
			available: deposit.available_balance,
		})?;
	if total > deposit.available_balance {
		return Err(ReservationError::Oversubscribed {
			requested: deposit.amount,
			reserved,
			available: deposit.available_balance,
		});
	}
	Ok(())
}

/// Key TTL covering the longest-lived entry plus grace; an empty map gets
/// just the grace period so released locks fall out of storage on their own.
fn ttl_for(map: &LockReservations, now: u64) -> Duration {
	let latest = map
		.values()
		.map(|entry| entry.expires_at)
		.max()
		.unwrap_or(now);
	Duration::from_secs(latest.saturating_sub(now) + TTL_GRACE_SECS)
}

fn unix_now() -> Result<u64, ReservationError> {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs())
		.map_err(|e| ReservationError::Storage(e.to_string()))
}

fn encode(map: &LockReservations) -> Result<Vec<u8>, ReservationError> {
	serde_json::to_vec(map).map_err(|e| ReservationError::Storage(e.to_string()))
}

fn decode(bytes: &[u8]) -> Result<LockReservations, ReservationError> {
	serde_json::from_slice(bytes).map_err(|e| ReservationError::Storage(e.to_string()))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::implementations::file::{FileStorage, TtlConfig};
	use crate::implementations::memory::MemoryStorage;

	const OWNER: &str = "0xAAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa";
	const CHAIN: u64 = 1;

	fn store() -> CompactReservationStore {
		CompactReservationStore::new(Arc::new(StorageService::new(
			Box::new(MemoryStorage::new()),
		)))
	}

	fn file_store(temp: &tempfile::TempDir) -> CompactReservationStore {
		CompactReservationStore::new(Arc::new(StorageService::new(Box::new(FileStorage::new(
			temp.path().to_path_buf(),
			TtlConfig::default(),
		)))))
	}

	fn deposit(amount: u64, balance: u64) -> DepositReservation {
		DepositReservation {
			chain_id: CHAIN,
			owner: OWNER.to_string(),
			token_id: U256::from(7u64),
			amount: U256::from(amount),
			available_balance: U256::from(balance),
		}
	}

	fn far_future() -> u64 {
		unix_now().unwrap() + 3600
	}

	#[tokio::test]
	async fn test_second_order_on_same_deposit_is_rejected() {
		let store = store();
		let expires = far_future();

		store
			.reserve_order("order-a", expires, &[deposit(600, 1000)])
			.await
			.unwrap();

		// Order B draws on the same deposit; only 400 of 1000 remains.
		let err = store
			.reserve_order("order-b", expires, &[deposit(600, 1000)])
			.await
			.unwrap_err();
		assert!(matches!(err, ReservationError::Oversubscribed { .. }));

		// A smaller order that fits the remainder is admitted.
		store
			.reserve_order("order-c", expires, &[deposit(400, 1000)])
			.await
			.unwrap();
	}

	#[tokio::test]
	async fn test_same_order_re_reserve_is_idempotent() {
		let store = store();
		let expires = far_future();

		store
			.reserve_order("order-a", expires, &[deposit(600, 1000)])
			.await
			.unwrap();
		// Duplicate submission must replace, not double-count.
		store
			.reserve_order("order-a", expires, &[deposit(600, 1000)])
			.await
			.unwrap();

		store
			.reserve_order("order-b", expires, &[deposit(400, 1000)])
			.await
			.unwrap();
	}

	#[tokio::test]
	async fn test_release_frees_capacity() {
		let store = store();
		let expires = far_future();

		store
			.reserve_order("order-a", expires, &[deposit(1000, 1000)])
			.await
			.unwrap();
		assert!(store
			.reserve_order("order-b", expires, &[deposit(1, 1000)])
			.await
			.is_err());

		store
			.release_order("order-a", &[(CHAIN, OWNER.to_string(), U256::from(7u64))])
			.await
			.unwrap();

		store
			.reserve_order("order-b", expires, &[deposit(1000, 1000)])
			.await
			.unwrap();
	}

	#[tokio::test]
	async fn test_release_of_unknown_order_is_noop() {
		let store = store();
		store
			.release_order("ghost", &[(CHAIN, OWNER.to_string(), U256::from(7u64))])
			.await
			.unwrap();
	}

	#[tokio::test]
	async fn test_expired_entries_free_capacity() {
		let store = store();
		let past = unix_now().unwrap() - 1;

		store
			.reserve_order("order-a", past, &[deposit(1000, 1000)])
			.await
			.unwrap();

		// order-a's entry has lapsed; its capacity must be reusable.
		store
			.reserve_order("order-b", far_future(), &[deposit(1000, 1000)])
			.await
			.unwrap();
	}

	#[tokio::test]
	async fn test_duplicate_inputs_in_one_order_are_aggregated() {
		let store = store();
		let expires = far_future();

		// Two inputs of 600 against a 1000 deposit must be rejected together.
		let err = store
			.reserve_order(
				"order-a",
				expires,
				&[deposit(600, 1000), deposit(600, 1000)],
			)
			.await
			.unwrap_err();
		assert!(matches!(err, ReservationError::Oversubscribed { .. }));
	}

	#[tokio::test]
	async fn test_partial_failure_rolls_back_prior_locks() {
		let store = store();
		let expires = far_future();

		let other_token = DepositReservation {
			token_id: U256::from(8u64),
			..deposit(600, 500)
		};

		// First lock (token 7) fits, second (token 8) oversubscribes.
		let err = store
			.reserve_order("order-a", expires, &[deposit(600, 1000), other_token])
			.await
			.unwrap_err();
		assert!(matches!(err, ReservationError::Oversubscribed { .. }));

		// The token-7 reservation must have been rolled back.
		store
			.reserve_order("order-b", expires, &[deposit(1000, 1000)])
			.await
			.unwrap();
	}

	#[tokio::test]
	async fn test_owner_case_is_normalized() {
		let store = store();
		let expires = far_future();

		store
			.reserve_order("order-a", expires, &[deposit(600, 1000)])
			.await
			.unwrap();

		let lowercase_owner = DepositReservation {
			owner: OWNER.to_lowercase(),
			..deposit(600, 1000)
		};
		let err = store
			.reserve_order("order-b", expires, &[lowercase_owner])
			.await
			.unwrap_err();
		assert!(matches!(err, ReservationError::Oversubscribed { .. }));
	}

	#[tokio::test]
	async fn test_concurrent_reservations_never_oversubscribe() {
		let store = Arc::new(store());
		let expires = far_future();

		// 10 orders of 100 against a 500 deposit: exactly 5 may win.
		let mut handles = Vec::new();
		for i in 0..10 {
			let store = Arc::clone(&store);
			handles.push(tokio::spawn(async move {
				store
					.reserve_order(&format!("order-{i}"), expires, &[deposit(100, 500)])
					.await
					.is_ok()
			}));
		}

		let mut admitted = 0;
		for handle in handles {
			if handle.await.unwrap() {
				admitted += 1;
			}
		}
		assert_eq!(admitted, 5);
	}

	#[tokio::test]
	async fn test_concurrent_reservations_never_oversubscribe_file_backend() {
		// Fix C regression guard: `FileStorage::set_nx` is non-atomic
		// (path.exists() then write). Without the per-lock in-process mutex,
		// two concurrent first-reservations could both win the create race and
		// oversubscribe the deposit. With the mutex, exactly 5 of 10 orders of
		// 100 against a 500 deposit may win.
		let temp = tempfile::tempdir().unwrap();
		let store = Arc::new(file_store(&temp));
		let expires = far_future();

		let mut handles = Vec::new();
		for i in 0..10 {
			let store = Arc::clone(&store);
			handles.push(tokio::spawn(async move {
				store
					.reserve_order(&format!("order-{i}"), expires, &[deposit(100, 500)])
					.await
					.is_ok()
			}));
		}

		let mut admitted = 0;
		for handle in handles {
			if handle.await.unwrap() {
				admitted += 1;
			}
		}
		assert_eq!(admitted, 5);
	}

	#[tokio::test]
	async fn test_storage_expired_key_is_re_reservable_file_backend() {
		// Fix D regression guard: `FileStorage::get_bytes` returns
		// `StorageError::Expired` (not `NotFound`) once a key's storage TTL has
		// lapsed but cleanup hasn't reaped the file yet. `reserve_one` must
		// treat `Expired` identically to `NotFound`, or admission would fail
		// with a storage error until cleanup runs.
		//
		// Plant a reservation key directly with a sub-second storage TTL, then
		// sleep past it so `get_bytes` yields `Expired` on the next read.
		let temp = tempfile::tempdir().unwrap();
		let store = file_store(&temp);

		let id = CompactReservationStore::lock_id(CHAIN, OWNER, &U256::from(7u64));
		let mut planted = LockReservations::new();
		planted.insert(
			"order-a".to_string(),
			ReservationEntry {
				amount: U256::from(1000u64),
				expires_at: far_future(),
			},
		);
		let bytes = encode(&planted).unwrap();
		assert!(store
			.storage
			.store_bytes_if_absent(NAMESPACE, &id, bytes, Some(Duration::from_secs(1)))
			.await
			.unwrap());

		// FileHeader stores TTL at second granularity; sleep past the boundary
		// so the key reliably surfaces as `Expired` on the next read.
		tokio::time::sleep(Duration::from_millis(1_100)).await;

		// The planted key now storage-expires. A fresh order against the same
		// fully-subscribed deposit must be admitted because the expired key is
		// treated as absent.
		store
			.reserve_order("order-b", far_future(), &[deposit(1000, 1000)])
			.await
			.unwrap();
	}

	#[tokio::test]
	async fn test_storage_expired_key_releases_as_noop_file_backend() {
		// Releasing against a storage-expired key must be a no-op, not an error.
		let temp = tempfile::tempdir().unwrap();
		let store = file_store(&temp);

		let id = CompactReservationStore::lock_id(CHAIN, OWNER, &U256::from(7u64));
		let mut planted = LockReservations::new();
		planted.insert(
			"order-a".to_string(),
			ReservationEntry {
				amount: U256::from(500u64),
				expires_at: far_future(),
			},
		);
		let bytes = encode(&planted).unwrap();
		assert!(store
			.storage
			.store_bytes_if_absent(NAMESPACE, &id, bytes, Some(Duration::from_secs(1)))
			.await
			.unwrap());

		tokio::time::sleep(Duration::from_millis(1_100)).await;

		store
			.release_order("order-a", &[(CHAIN, OWNER.to_string(), U256::from(7u64))])
			.await
			.unwrap();
	}
}
