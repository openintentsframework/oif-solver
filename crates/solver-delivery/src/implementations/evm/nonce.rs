//! Solver-owned resettable nonce manager.
//!
//! Replaces direct use of Alloy's opaque `CachedNonceManager` with a manager
//! whose local cache can be explicitly resynced from chain after a `nonce too low`
//! submission error.

use alloy_primitives::Address;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Resettable, monotonic per-address nonce cache.
///
/// `set_next_nonce` and `take_next` are the only mutators. The cache only
/// advances; downward updates are rejected to avoid re-handing-out a nonce
/// that has already been used in-process.
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

	/// Replace the next-to-hand-out nonce for `address` exactly.
	/// Use only after reading authoritative chain state; unlike
	/// `set_next_nonce`, this may move the local cache backward to recover
	/// from ghost broadcasts that advanced only the in-process counter.
	pub fn reset_next_nonce(&self, address: Address, next: u64) -> u64 {
		let mut cache = self.cache.lock().expect("nonce cache mutex poisoned");
		cache.insert(address, next);
		next
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

	/// Take the next nonce and advance the counter.
	/// Returns `None` if no nonce has been cached yet for this address —
	/// callers should fetch chain-pending and call `set_next_nonce` first.
	pub fn take_next(&self, address: Address) -> Option<u64> {
		let mut cache = self.cache.lock().expect("nonce cache mutex poisoned");
		let n = cache.get_mut(&address)?;
		let taken = *n;
		*n = taken + 1;
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
}

/// Returns true if the given error string indicates a nonce-too-low submission
/// failure from an Ethereum RPC. Match is case-insensitive and tolerant of the
/// most common phrasings emitted by go-ethereum, reth, erigon, anvil, and most
/// managed RPC providers.
pub fn is_nonce_too_low_error(message: &str) -> bool {
	let lower = message.to_lowercase();
	lower.contains("nonce too low") || lower.contains("nonce is too low")
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
	fn reset_next_nonce_can_recover_from_local_cache_ahead_of_chain() {
		let mgr = ResettableNonceManager::new();
		mgr.set_next_nonce(ADDR, 139);
		assert_eq!(mgr.take_next(ADDR), Some(139));
		assert_eq!(mgr.take_next(ADDR), Some(140));
		assert_eq!(mgr.peek(ADDR), Some(141));

		// Chain pending is still 139 because the locally handed-out txs were
		// ghost broadcasts. A real resync must be allowed to move backward.
		assert_eq!(mgr.reset_next_nonce(ADDR, 139), 139);

		assert_eq!(mgr.take_next(ADDR), Some(139));
		assert_eq!(mgr.peek(ADDR), Some(140));
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
}
