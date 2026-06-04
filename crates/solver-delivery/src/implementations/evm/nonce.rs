//! Solver-owned resettable nonce manager.
//!
//! Replaces direct use of Alloy's opaque `CachedNonceManager` with a manager
//! whose local cache can be explicitly resynced from chain after a `nonce too
//! low` submission error or after a definitely-rejected pre-pool failure.
//!
//! # Invariant
//!
//! The local nonce cache may advance only when:
//! 1. A transaction was accepted by `eth_sendRawTransaction` (returned `Ok`), OR
//! 2. Chain `latest`/`pending` proves the nonce has advanced, OR
//! 3. The error from `send_transaction` does NOT prove the tx was rejected
//!    pre-pool (i.e. the outcome is `Replacement` or `Ambiguous`).
//!
//! Conversely: cache rollback is only safe when:
//! - The submission error is in `SubmissionOutcome::DefinitelyRejected`, AND
//! - A fresh chain-pending read succeeds. If the read fails, the caller MUST
//!   keep the cache advanced — we never reset without authoritative chain state.
//!
//! Two rollback primitives exist, with different safety profiles:
//! - `reset_next_nonce`: forward-only high-water clamp. Safe for an arbitrary
//!   resync, but cannot *reclaim* a nonce a rejection leaked.
//! - `reclaim_rejected_nonce`: moves the cache back to the rejected nonce, but
//!   only when that nonce was the most recently handed-out one and the chain
//!   has not advanced past it — otherwise it falls back to the forward-only
//!   behavior. This closes the nonce gap left by a pre-pool rejection without
//!   ever reissuing a nonce that is still in flight.
//!
//! Ambiguous transport errors (timeout, 5xx, malformed JSON) and replacement-
//! class errors keep the cache advanced — the transaction may have propagated
//! (ambiguous) or another tx already holds the nonce (replacement). Rolling
//! back in either case risks a same-nonce conflict.

use alloy_primitives::Address;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Resettable, monotonic per-address nonce cache.
///
/// `set_next_nonce` and `take_next` are the only mutators. The cache only
/// advances; downward updates are rejected to avoid re-handing-out a nonce
/// that has already been used in-process. This cache is still needed even when
/// callers sample chain `pending` before allocation: RPC pending nonce can lag
/// immediately after a successful submit, so chain state alone can reissue the
/// previous nonce inside one process.
#[derive(Debug, Default, Clone)]
pub struct ResettableNonceManager {
	cache: Arc<Mutex<HashMap<Address, u64>>>,
}

impl ResettableNonceManager {
	pub fn new() -> Self {
		Self::default()
	}

	/// Advance the next-to-hand-out nonce for `address` to at least `next`.
	/// If the current cached value is already at or above `next`, no change.
	/// Returns the cached value after the call.
	pub fn set_next_nonce(&self, address: Address, next: u64) -> u64 {
		let mut cache = self.cache.lock().expect("nonce cache mutex poisoned");
		let entry = cache.entry(address).or_insert(next);
		if *entry < next {
			*entry = next;
		}
		*entry
	}

	/// Replace the next-to-hand-out nonce for `address` using authoritative
	/// chain state, clamped by the local high-water mark. This avoids
	/// reissuing a nonce already handed out by this process when multiple
	/// same-signer submissions are in flight.
	pub fn reset_next_nonce(&self, address: Address, next: u64) -> u64 {
		let mut cache = self.cache.lock().expect("nonce cache mutex poisoned");
		let reset = cache
			.get(&address)
			.copied()
			.map_or(next, |local| local.max(next));
		cache.insert(address, reset);
		reset
	}

	/// Reconcile the local next nonce with chain `pending`.
	/// Moves forward when the chain has advanced and backward when local-only
	/// ghost broadcasts made the cache run ahead of chain state.
	pub fn reconcile_with_chain_pending(
		&self,
		address: Address,
		chain_pending: u64,
	) -> (Option<u64>, u64) {
		let mut cache = self.cache.lock().expect("nonce cache mutex poisoned");
		let before = cache.get(&address).copied();
		let reconciled = match before {
			Some(local) if local > chain_pending => chain_pending,
			Some(local) => local.max(chain_pending),
			None => chain_pending,
		};
		cache.insert(address, reconciled);
		(before, reconciled)
	}

	/// Reclaim a nonce that was allocated to a transaction which was then
	/// definitively rejected pre-pool (the tx never entered any mempool, so the
	/// nonce was never consumed on-chain).
	///
	/// This is the rollback counterpart to [`Self::reset_next_nonce`]. Where
	/// `reset_next_nonce` is a forward-only high-water clamp — safe for an
	/// arbitrary resync but unable to *reclaim* a nonce — this method moves the
	/// cache back to `rejected_nonce`, but **only when it is provably safe**:
	///
	/// 1. `chain_pending <= rejected_nonce`: the chain has not advanced past the
	///    rejected nonce, confirming the tx did not land out-of-band; and
	/// 2. the local cache is exactly `rejected_nonce + 1`: the rejected nonce was
	///    the most recently handed-out nonce, so nothing newer is in flight that
	///    rolling back would strand.
	///
	/// When both hold, the cache is set to `rejected_nonce` so the next
	/// allocation re-hands-it-out, closing the nonce gap a pre-pool rejection
	/// would otherwise leak (the wedge described in audit finding H-27).
	/// Otherwise the cache is left advanced — moving forward to `chain_pending`
	/// if the chain is ahead — because a higher nonce is already in flight or
	/// the chain shows the nonce consumed, and reusing it would risk a
	/// same-nonce conflict. That is the conservative, never-reuse choice;
	/// recovery of any resulting gap is left to the bump sweeper / nonce-too-low
	/// resync.
	///
	/// Returns `(before, after)` for tracing.
	pub fn reclaim_rejected_nonce(
		&self,
		address: Address,
		rejected_nonce: u64,
		chain_pending: u64,
	) -> (Option<u64>, u64) {
		let mut cache = self.cache.lock().expect("nonce cache mutex poisoned");
		let before = cache.get(&address).copied();
		let after = match before {
			// Safe to reclaim: the rejected nonce was the top of the local
			// allocation and the chain has not consumed it.
			Some(local)
				if chain_pending <= rejected_nonce && local == rejected_nonce.saturating_add(1) =>
			{
				rejected_nonce
			},
			// A higher nonce is in flight, or the chain advanced past the
			// rejected nonce — keep the cache advanced (honoring forward chain
			// movement) and never reuse an in-flight nonce.
			Some(local) => local.max(chain_pending),
			None => chain_pending,
		};
		cache.insert(address, after);
		(before, after)
	}

	/// Take the next nonce and advance the counter.
	/// Returns `None` if no nonce has been cached yet for this address —
	/// callers should fetch chain-pending and call `set_next_nonce` first.
	pub fn take_next(&self, address: Address) -> Option<u64> {
		let mut cache = self.cache.lock().expect("nonce cache mutex poisoned");
		let n = cache.get_mut(&address)?;
		let taken = *n;
		*n = taken.checked_add(1)?;
		Some(taken)
	}

	/// Peek the current next-to-hand-out value without advancing.
	/// Intended for observability/tests.
	pub fn peek(&self, address: Address) -> Option<u64> {
		self.cache
			.lock()
			.expect("nonce cache mutex poisoned")
			.get(&address)
			.copied()
	}

	/// Returns `local_next_nonce - chain_pending` for the given address.
	/// Positive values mean the local cache is ahead of the chain — expected
	/// during in-flight broadcasts, suspicious if it persists. Negative values
	/// mean chain has advanced past the local view (e.g. another signer or
	/// out-of-band tx). Returns 0 if no local entry exists yet.
	///
	/// Returns `i128` instead of `i64` because `u64 - u64` can theoretically
	/// produce values outside `i64::MIN..=i64::MAX` at the extremes (a stuck
	/// cache near `u64::MAX` against a fresh chain). `i128` preserves the
	/// arithmetic without saturation. In practice for Ethereum signers this
	/// will never get close, but using `i128` removes a foot-gun.
	///
	/// Intended for observability / drift monitoring; does not mutate the cache.
	pub fn cache_lead(&self, address: Address, chain_pending: u64) -> i128 {
		let cache = self.cache.lock().expect("nonce cache mutex poisoned");
		let local = cache.get(&address).copied().unwrap_or(chain_pending);
		local as i128 - chain_pending as i128
	}
}

/// Classification of a `provider.send_transaction(...)` error response.
///
/// Used by the broadcast wrapper to decide whether to roll back the local
/// nonce cache. The four classes have different cache-action implications:
///
/// - `NonceTooLow`: handled by the existing resync-and-retry path.
/// - `DefinitelyRejected`: tx never entered any pool — safe to roll back.
/// - `Replacement`: another tx already holds this nonce — keep advanced
///   (rolling back would reuse a nonce that already has a tx, leading to
///   replacement-underpriced loops or self-conflict).
/// - `Ambiguous`: transport / unknown error — keep advanced (tx may have
///   propagated despite the failed response).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmissionOutcome {
	NonceTooLow,
	DefinitelyRejected,
	Replacement,
	Ambiguous,
}

/// Classifies a transaction submission error response. See
/// `SubmissionOutcome` for the cache-action implications.
///
/// The allowlists below are intentionally conservative. Every phrase under
/// `DefinitelyRejected` represents a pre-pool validation that proves no tx
/// reached any mempool. Phrases must NOT be added without evidence; the
/// default fallthrough is `Ambiguous` so misclassification fails safe (we
/// keep the nonce advanced, never reuse, and the drift monitor will catch
/// any leak that results).
pub fn classify_submission_outcome(message: &str) -> SubmissionOutcome {
	let lower = message.to_lowercase();

	// 1. NonceTooLow first — the existing retry path needs it.
	if lower.contains("nonce too low") || lower.contains("nonce is too low") {
		return SubmissionOutcome::NonceTooLow;
	}

	// 2. Replacement-class: ANOTHER tx already holds this nonce.
	//    Keep cache advanced; rolling back would reuse a nonce that already
	//    has a tx, causing replacement-underpriced loops or self-replacement.
	if lower.contains("replacement transaction underpriced") || lower.contains("already known") {
		return SubmissionOutcome::Replacement;
	}

	// 3. Definitely rejected pre-pool. Safe to roll back the cache.
	let fee_cap_below_base_fee = lower.contains("max fee per gas less than block base fee")
		|| lower.contains("fee cap less than block base fee")
		|| lower.contains("max fee per gas below block base fee");

	if lower.contains("insufficient funds")
		|| lower.contains("transaction underpriced")
		|| lower.contains("intrinsic gas too low")
		|| lower.contains("exceeds block gas limit")
		|| lower.contains("gas required exceeds")
		|| fee_cap_below_base_fee
		// Nonce upper-bound (the lower-bound `nonce too low` was handled above)
		|| lower.contains("nonce too high")
		// Signature / sender / chain pre-validation
		|| lower.contains("invalid sender")
		|| lower.contains("invalid signature")
		|| lower.contains("invalid signer")
		|| lower.contains("invalid chain id")
		// Pool-level rejections — full pool, not a replacement of an existing tx
		|| lower.contains("txpool is full")
		|| lower.contains("tx pool is full")
		|| lower.contains("transaction pool is full")
		// Type / encoding rejections
		|| lower.contains("transaction type not supported")
		|| lower.contains("invalid transaction")
	{
		return SubmissionOutcome::DefinitelyRejected;
	}

	// 4. Default: ambiguous. Tx may have propagated despite the failed
	//    response; keeping the cache advanced is the conservative choice.
	SubmissionOutcome::Ambiguous
}

/// Returns true if the given error string indicates a nonce-too-low submission
/// failure from an Ethereum RPC. Match is case-insensitive and tolerant of the
/// most common phrasings emitted by go-ethereum, reth, erigon, anvil, and most
/// managed RPC providers.
pub fn is_nonce_too_low_error(message: &str) -> bool {
	matches!(
		classify_submission_outcome(message),
		SubmissionOutcome::NonceTooLow
	)
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::address;

	const ADDR: Address = address!("0000000000000000000000000000000000000001");
	const ADDR2: Address = address!("0000000000000000000000000000000000000002");

	#[test]
	fn set_next_nonce_seeds_empty_cache() {
		let mgr = ResettableNonceManager::new();
		let result = mgr.set_next_nonce(ADDR, 100);
		assert_eq!(result, 100);
		assert_eq!(mgr.peek(ADDR), Some(100));
	}

	#[test]
	fn take_next_returns_cached_value_and_advances() {
		let mgr = ResettableNonceManager::new();
		mgr.set_next_nonce(ADDR, 100);

		assert_eq!(mgr.take_next(ADDR), Some(100));
		assert_eq!(mgr.take_next(ADDR), Some(101));
		assert_eq!(mgr.peek(ADDR), Some(102));
	}

	#[test]
	fn take_next_on_empty_cache_returns_none() {
		let mgr = ResettableNonceManager::new();
		assert_eq!(mgr.take_next(ADDR), None);
	}

	#[test]
	fn take_next_returns_none_without_wrapping_at_u64_max() {
		let mgr = ResettableNonceManager::new();
		mgr.set_next_nonce(ADDR, u64::MAX);

		assert_eq!(mgr.take_next(ADDR), None);
		assert_eq!(mgr.peek(ADDR), Some(u64::MAX));
	}

	#[test]
	fn set_next_nonce_is_monotonic_and_rejects_backward_updates() {
		let mgr = ResettableNonceManager::new();
		mgr.set_next_nonce(ADDR, 200);

		// Backward update is a no-op; cache stays at 200.
		let result = mgr.set_next_nonce(ADDR, 100);
		assert_eq!(result, 200);
		assert_eq!(mgr.peek(ADDR), Some(200));
	}

	#[test]
	fn set_next_nonce_advances_above_current() {
		let mgr = ResettableNonceManager::new();
		mgr.set_next_nonce(ADDR, 100);

		let result = mgr.set_next_nonce(ADDR, 150);
		assert_eq!(result, 150);
		assert_eq!(mgr.peek(ADDR), Some(150));
	}

	#[test]
	fn resync_after_drift_advances_cache_and_subsequent_take_uses_new_value() {
		// Simulates the bridge-redeem incident: local cache lagging behind chain.
		let mgr = ResettableNonceManager::new();
		mgr.set_next_nonce(ADDR, 121);
		assert_eq!(mgr.take_next(ADDR), Some(121)); // we hand out 121, fails on chain

		// Resync to chain pending = 124.
		mgr.set_next_nonce(ADDR, 124);

		assert_eq!(mgr.take_next(ADDR), Some(124));
		assert_eq!(mgr.peek(ADDR), Some(125));
	}

	#[test]
	fn reset_next_nonce_does_not_reissue_locally_allocated_nonces() {
		let mgr = ResettableNonceManager::new();
		mgr.set_next_nonce(ADDR, 139);
		assert_eq!(mgr.take_next(ADDR), Some(139));
		assert_eq!(mgr.take_next(ADDR), Some(140));
		assert_eq!(mgr.peek(ADDR), Some(141));

		// Chain pending is still 139, but the local cache has already handed
		// out nonces through 140. Rollback must not move below that local
		// high-water mark or concurrent submitters can reissue an in-flight
		// nonce.
		assert_eq!(mgr.reset_next_nonce(ADDR, 139), 141);

		assert_eq!(mgr.take_next(ADDR), Some(141));
		assert_eq!(mgr.peek(ADDR), Some(142));
	}

	#[test]
	fn reset_next_nonce_preserves_local_high_water_when_chain_pending_lags() {
		let mgr = ResettableNonceManager::new();
		mgr.set_next_nonce(ADDR, 10);
		assert_eq!(mgr.take_next(ADDR), Some(10));
		assert_eq!(mgr.take_next(ADDR), Some(11));
		assert_eq!(mgr.peek(ADDR), Some(12));

		assert_eq!(mgr.reset_next_nonce(ADDR, 9), 12);
		assert_eq!(mgr.peek(ADDR), Some(12));
	}

	#[test]
	fn reconcile_with_chain_pending_moves_backward_when_local_cache_is_ahead() {
		let mgr = ResettableNonceManager::new();
		mgr.set_next_nonce(ADDR, 141);

		assert_eq!(
			mgr.reconcile_with_chain_pending(ADDR, 139),
			(Some(141), 139)
		);

		assert_eq!(mgr.take_next(ADDR), Some(139));
		assert_eq!(mgr.peek(ADDR), Some(140));
	}

	#[test]
	fn reconcile_with_chain_pending_moves_forward_when_chain_is_ahead() {
		let mgr = ResettableNonceManager::new();
		mgr.set_next_nonce(ADDR, 139);

		assert_eq!(
			mgr.reconcile_with_chain_pending(ADDR, 142),
			(Some(139), 142)
		);

		assert_eq!(mgr.take_next(ADDR), Some(142));
		assert_eq!(mgr.peek(ADDR), Some(143));
	}

	#[test]
	fn reclaim_rejected_nonce_reclaims_lone_in_flight_nonce() {
		// H-27 scenario: a single in-flight tx is rejected pre-pool. The local
		// cache is one past the rejected nonce and the chain has not consumed
		// it, so the nonce must be reclaimed (not leaked).
		let mgr = ResettableNonceManager::new();
		mgr.set_next_nonce(ADDR, 5);
		assert_eq!(mgr.take_next(ADDR), Some(5)); // allocate nonce 5
		assert_eq!(mgr.peek(ADDR), Some(6));

		// Tx at nonce 5 is DefinitelyRejected; chain pending is still 5.
		assert_eq!(mgr.reclaim_rejected_nonce(ADDR, 5, 5), (Some(6), 5));

		// Nonce 5 is re-handed-out instead of being permanently skipped.
		assert_eq!(mgr.take_next(ADDR), Some(5));
		assert_eq!(mgr.peek(ADDR), Some(6));
	}

	#[test]
	fn reclaim_rejected_nonce_does_not_reclaim_when_higher_nonce_in_flight() {
		// A newer nonce was allocated after the rejected one — reclaiming the
		// middle nonce would risk reissuing an in-flight nonce, so the cache
		// must stay advanced.
		let mgr = ResettableNonceManager::new();
		mgr.set_next_nonce(ADDR, 5);
		assert_eq!(mgr.take_next(ADDR), Some(5));
		assert_eq!(mgr.take_next(ADDR), Some(6));
		assert_eq!(mgr.peek(ADDR), Some(7));

		// Nonce 5 rejected, but 6 is still in flight (cache at 7, not 6).
		assert_eq!(mgr.reclaim_rejected_nonce(ADDR, 5, 5), (Some(7), 7));
		assert_eq!(mgr.peek(ADDR), Some(7));
	}

	#[test]
	fn reclaim_rejected_nonce_does_not_reclaim_when_chain_advanced_past_it() {
		// The chain pending is already past the rejected nonce, so the nonce
		// was consumed out-of-band; never reclaim it. The cache also moves
		// forward to honor the chain.
		let mgr = ResettableNonceManager::new();
		mgr.set_next_nonce(ADDR, 5);
		assert_eq!(mgr.take_next(ADDR), Some(5));
		assert_eq!(mgr.peek(ADDR), Some(6));

		assert_eq!(mgr.reclaim_rejected_nonce(ADDR, 5, 6), (Some(6), 6));
		assert_eq!(mgr.take_next(ADDR), Some(6));
	}

	#[test]
	fn reclaim_rejected_nonce_on_empty_cache_seeds_from_chain() {
		let mgr = ResettableNonceManager::new();
		assert_eq!(mgr.reclaim_rejected_nonce(ADDR, 5, 5), (None, 5));
		assert_eq!(mgr.peek(ADDR), Some(5));
	}

	#[test]
	fn cache_is_per_address() {
		let mgr = ResettableNonceManager::new();
		mgr.set_next_nonce(ADDR, 100);
		mgr.set_next_nonce(ADDR2, 5000);

		assert_eq!(mgr.take_next(ADDR), Some(100));
		assert_eq!(mgr.take_next(ADDR2), Some(5000));
		assert_eq!(mgr.peek(ADDR), Some(101));
		assert_eq!(mgr.peek(ADDR2), Some(5001));
	}

	#[test]
	fn is_nonce_too_low_error_matches_common_phrasings() {
		assert!(is_nonce_too_low_error("nonce too low"));
		assert!(is_nonce_too_low_error("Nonce too low"));
		assert!(is_nonce_too_low_error(
			"transaction underpriced: nonce too low: ..."
		));
		assert!(is_nonce_too_low_error(
			"nonce is too low for sender 0xabc..."
		));
		assert!(is_nonce_too_low_error(
			"ERROR: nonce too low (have 121, want 124)"
		));
	}

	#[test]
	fn is_nonce_too_low_error_rejects_unrelated_messages() {
		assert!(!is_nonce_too_low_error("connection refused"));
		assert!(!is_nonce_too_low_error(
			"replacement transaction underpriced"
		));
		assert!(!is_nonce_too_low_error("insufficient funds for gas"));
		assert!(!is_nonce_too_low_error("execution reverted"));
		assert!(!is_nonce_too_low_error(""));
	}

	#[test]
	fn classify_submission_outcome_definitely_rejected() {
		use SubmissionOutcome::*;
		// go-ethereum / reth / erigon / anvil phrasings
		assert_eq!(
			classify_submission_outcome("insufficient funds for gas * price + value"),
			DefinitelyRejected
		);
		assert_eq!(
			classify_submission_outcome("transaction underpriced"),
			DefinitelyRejected
		);
		assert_eq!(
			classify_submission_outcome("intrinsic gas too low"),
			DefinitelyRejected
		);
		assert_eq!(
			classify_submission_outcome("nonce too high"),
			DefinitelyRejected
		);
		assert_eq!(
			classify_submission_outcome("invalid sender"),
			DefinitelyRejected
		);
		assert_eq!(
			classify_submission_outcome("invalid signature"),
			DefinitelyRejected
		);
		assert_eq!(
			classify_submission_outcome("invalid chain id"),
			DefinitelyRejected
		);
		assert_eq!(
			classify_submission_outcome("txpool is full"),
			DefinitelyRejected
		);
		assert_eq!(
			classify_submission_outcome("exceeds block gas limit"),
			DefinitelyRejected
		);
		assert_eq!(
			classify_submission_outcome("transaction type not supported"),
			DefinitelyRejected
		);
		// Mixed case
		assert_eq!(
			classify_submission_outcome("ERROR: Insufficient Funds"),
			DefinitelyRejected
		);
		assert_eq!(
			classify_submission_outcome("max fee per gas less than block base fee"),
			DefinitelyRejected
		);
		assert_eq!(
			classify_submission_outcome("fee cap less than block base fee"),
			DefinitelyRejected
		);
		assert_eq!(
			classify_submission_outcome("max fee per gas below block base fee"),
			DefinitelyRejected
		);
	}

	#[test]
	fn classify_submission_outcome_replacement_class() {
		use SubmissionOutcome::*;
		// These prove ANOTHER tx already holds the nonce. Cache stays advanced.
		assert_eq!(
			classify_submission_outcome("replacement transaction underpriced"),
			Replacement
		);
		assert_eq!(classify_submission_outcome("already known"), Replacement);
	}

	#[test]
	fn classify_submission_outcome_ambiguous_transport() {
		use SubmissionOutcome::*;
		assert_eq!(classify_submission_outcome("connection timeout"), Ambiguous);
		assert_eq!(
			classify_submission_outcome("connection reset by peer"),
			Ambiguous
		);
		assert_eq!(
			classify_submission_outcome("server returned status 503: service unavailable"),
			Ambiguous
		);
		assert_eq!(
			classify_submission_outcome("server returned status 502: bad gateway"),
			Ambiguous
		);
		assert_eq!(
			classify_submission_outcome("failed to decode response"),
			Ambiguous
		);
		assert_eq!(
			classify_submission_outcome("Max retries exceeded"),
			Ambiguous
		);
		assert_eq!(classify_submission_outcome(""), Ambiguous);
		assert_eq!(classify_submission_outcome("unknown error"), Ambiguous);
	}

	#[test]
	fn classify_submission_outcome_nonce_too_low() {
		// Must take precedence — existing retry path depends on it.
		assert_eq!(
			classify_submission_outcome("nonce too low"),
			SubmissionOutcome::NonceTooLow
		);
		assert_eq!(
			classify_submission_outcome("nonce is too low"),
			SubmissionOutcome::NonceTooLow
		);
	}

	#[test]
	fn cache_lead_returns_local_minus_chain_pending() {
		let mgr = ResettableNonceManager::new();
		let addr = Address::ZERO;
		// No entry yet → treat as "in sync with chain" → 0.
		assert_eq!(mgr.cache_lead(addr, 100), 0i128);

		mgr.set_next_nonce(addr, 100);
		assert_eq!(mgr.cache_lead(addr, 100), 0i128);

		// After two takes, cache is at 102. Chain still at 100 → lead = 2.
		mgr.take_next(addr);
		mgr.take_next(addr);
		assert_eq!(mgr.cache_lead(addr, 100), 2i128);

		// Chain catches up to 102 → lead back to 0.
		assert_eq!(mgr.cache_lead(addr, 102), 0i128);

		// Chain ahead of cache (e.g. another signer pushed it forward) — defensive.
		assert_eq!(mgr.cache_lead(addr, 110), -8i128);

		// Edge case: defensive against u64 → signed conversion. With cache at
		// u64::MAX and pending at 0 the i128 result is exactly 2^64 - 1, which
		// fits without lossy saturation that an i64 return would hit.
		mgr.reset_next_nonce(addr, u64::MAX);
		assert_eq!(mgr.cache_lead(addr, 0), (u64::MAX as i128));
	}
}
