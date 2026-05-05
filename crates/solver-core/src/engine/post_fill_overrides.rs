//! Pure-function helpers for building Alchemy `stateOverride` payloads
//! that pre-populate the OutputSettler's `_fillRecords` mapping so
//! quote-time `eth_estimateGas` of the Hyperlane `submit(...)` call
//! does not revert with `0x0ef392ae` (FillNotRecorded).
//!
//! This module owns NO I/O. All functions are deterministic.
//!
//! # Storage layout
//!
//! Per Task 1's appendix in
//! `docs/superpowers/plans/2026-05-05-post-fill-state-override-estimation.md`,
//! the `OutputSettlerSimple` contract (parent: `OutputSettlerBase`) declares:
//!
//! ```solidity
//! mapping(bytes32 orderId => mapping(bytes32 outputHash => bytes32 fillRecordHash))
//!     internal _fillRecords;
//! ```
//!
//! at storage slot index `1`. The value written by `_fill(...)` is:
//!
//! ```solidity
//! _fillRecords[orderId][outputHash] = keccak256(abi.encodePacked(solver, fillTimestamp));
//! //                                                                          ^ uint32 (4 bytes BE)
//! ```
//!
//! See `OutputSettlerBase.sol` in the validated commit
//! `1f9cbbe6e2f9b7f8c68c705be97637fb0555f86e` of `oif-contracts`.

use alloy_primitives::map::{AddressHashMap, B256HashMap};
use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_rpc_types::state::{AccountOverride, StateOverride};

/// Storage slot index of the outer `_fillRecords` mapping in
/// `OutputSettlerBase`. Verified via `forge inspect ... storageLayout`
/// against `OutputSettlerSimple` (see Task 1 appendix).
pub const FILL_RECORDS_SLOT: u64 = 1;

/// Compute the storage slot of `_fillRecords[order_id][output_hash]`.
///
/// Two-level nested mapping per Solidity rules:
///
/// ```text
/// inner_slot = keccak256(abi.encode(order_id,    uint256(FILL_RECORDS_SLOT)))
/// final_slot = keccak256(abi.encode(output_hash, inner_slot))
/// ```
///
/// `abi.encode` of a `(bytes32, uint256)` pair is a 64-byte buffer:
/// the 32-byte key followed by the 32-byte big-endian slot index. We
/// build that buffer manually to avoid pulling in the heavier
/// `SolValue::abi_encode` codepath for what is ultimately two
/// concatenations and two keccak256 calls.
pub fn fill_record_slot(order_id: B256, output_hash: B256) -> B256 {
	// inner_slot = keccak256(order_id || u256_be(FILL_RECORDS_SLOT))
	let mut inner_buf = [0u8; 64];
	inner_buf[..32].copy_from_slice(order_id.as_slice());
	inner_buf[32..].copy_from_slice(&U256::from(FILL_RECORDS_SLOT).to_be_bytes::<32>());
	let inner_slot = keccak256(inner_buf);

	// final_slot = keccak256(output_hash || inner_slot)
	let mut final_buf = [0u8; 64];
	final_buf[..32].copy_from_slice(output_hash.as_slice());
	final_buf[32..].copy_from_slice(inner_slot.as_slice());
	keccak256(final_buf)
}

/// Compute the value `fill(...)` writes to `_fillRecords[orderId][outputHash]`.
///
/// Per `OutputSettlerBase._getFillRecordHash`:
///
/// ```solidity
/// keccak256(abi.encodePacked(solver, timestamp))
/// // solver: bytes32  (32 bytes, no padding)
/// // timestamp: uint32 (4 bytes big-endian, no padding)
/// ```
///
/// `abi.encodePacked` does NOT pad the `uint32`, so the preimage is
/// exactly 36 bytes: 32 bytes of solver identifier followed by 4 bytes
/// of big-endian timestamp.
pub fn synthetic_fill_record(solver: B256, fill_timestamp: u32) -> B256 {
	let mut buf = [0u8; 36];
	buf[..32].copy_from_slice(solver.as_slice());
	buf[32..].copy_from_slice(&fill_timestamp.to_be_bytes());
	keccak256(buf)
}

/// Build a single-account `stateOverride` that pre-populates
/// `_fillRecords[order_id][output_hash]` on the `OutputSettler` with
/// the value a real `fill(...)` would write.
///
/// The returned [`StateOverride`] is a typed alias for
/// `AddressHashMap<AccountOverride>` and serializes to the JSON-RPC
/// `stateOverride` parameter accepted by `eth_estimateGas` /
/// `eth_call`.
pub fn build_post_fill_state_override(
	output_settler: Address,
	order_id: B256,
	output_hash: B256,
	solver: B256,
	fill_timestamp: u32,
) -> StateOverride {
	let slot = fill_record_slot(order_id, output_hash);
	let value = synthetic_fill_record(solver, fill_timestamp);

	let mut state_diff: B256HashMap<B256> = B256HashMap::default();
	state_diff.insert(slot, value);

	let override_account = AccountOverride {
		state_diff: Some(state_diff),
		..Default::default()
	};

	let mut overrides: AddressHashMap<AccountOverride> = AddressHashMap::default();
	overrides.insert(output_settler, override_account);
	StateOverride::from(overrides)
}

/// Test-only helper that drives the production override-based post-fill
/// estimate via the public `DeliveryInterface`. Public so integration
/// tests under `crates/solver-core/tests/` can exercise the same code
/// path without reaching into private `cost_profit.rs` helpers.
///
/// Gated behind `cfg(any(test, feature = "test-helpers"))` so it never
/// ships in release builds. See Task 6 in
/// `docs/superpowers/plans/2026-05-05-post-fill-state-override-estimation.md`.
#[cfg(any(test, feature = "test-helpers"))]
pub async fn estimate_post_fill_with_overrides_for_test(
	delivery: &dyn solver_delivery::DeliveryInterface,
	tx: solver_types::Transaction,
	state_override: alloy_rpc_types::state::StateOverride,
) -> Result<u64, solver_delivery::DeliveryError> {
	delivery.estimate_gas_with_overrides(tx, state_override).await
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn fill_record_slot_matches_solidity_keccak() {
		// Pick a known (order_id, output_hash) and compute the slot
		// two ways: via `fill_record_slot` and via the explicit
		// Solidity-style nested-mapping formula. They must agree.
		let order_id = B256::repeat_byte(0xab);
		let output_hash = B256::repeat_byte(0xcd);
		let computed = fill_record_slot(order_id, output_hash);

		// Reference: keccak256(order_id || u256_be(SLOT))
		let mut inner_buf = Vec::with_capacity(64);
		inner_buf.extend_from_slice(order_id.as_slice());
		inner_buf.extend_from_slice(&U256::from(FILL_RECORDS_SLOT).to_be_bytes::<32>());
		let inner_slot = keccak256(&inner_buf);

		// Reference: keccak256(output_hash || inner_slot)
		let mut final_buf = Vec::with_capacity(64);
		final_buf.extend_from_slice(output_hash.as_slice());
		final_buf.extend_from_slice(inner_slot.as_slice());
		let reference = keccak256(&final_buf);

		assert_eq!(computed, reference);
	}

	#[test]
	fn fill_record_slot_is_deterministic() {
		let order_id = B256::repeat_byte(0x42);
		let output_hash = B256::repeat_byte(0x24);
		assert_eq!(
			fill_record_slot(order_id, output_hash),
			fill_record_slot(order_id, output_hash)
		);
	}

	#[test]
	fn fill_record_slot_differs_per_order_id() {
		let a = B256::repeat_byte(0x01);
		let b = B256::repeat_byte(0x02);
		let output_hash = B256::repeat_byte(0xcc);
		assert_ne!(
			fill_record_slot(a, output_hash),
			fill_record_slot(b, output_hash)
		);
	}

	#[test]
	fn fill_record_slot_differs_per_output_hash() {
		let order_id = B256::repeat_byte(0xaa);
		let a = B256::repeat_byte(0x01);
		let b = B256::repeat_byte(0x02);
		assert_ne!(
			fill_record_slot(order_id, a),
			fill_record_slot(order_id, b)
		);
	}

	#[test]
	fn synthetic_fill_record_matches_packed_keccak() {
		// keccak256(abi.encodePacked(solver_bytes32, timestamp_uint32))
		// → 36-byte preimage, NOT abi.encode-padded to 64 bytes.
		let solver = B256::repeat_byte(0xee);
		let timestamp: u32 = 0x12345678;

		let computed = synthetic_fill_record(solver, timestamp);

		// Reference: build the 36-byte buffer manually.
		let mut buf = [0u8; 36];
		buf[..32].copy_from_slice(solver.as_slice());
		buf[32..].copy_from_slice(&timestamp.to_be_bytes());
		let reference = keccak256(buf);

		assert_eq!(computed, reference);

		// Sanity check: a packed-encoded preimage MUST differ from an
		// abi.encode-padded preimage. If `synthetic_fill_record` ever
		// regressed to abi.encode (left-pad timestamp to 32 bytes),
		// the on-chain check would fail silently.
		let mut padded_buf = [0u8; 64];
		padded_buf[..32].copy_from_slice(solver.as_slice());
		padded_buf[60..].copy_from_slice(&timestamp.to_be_bytes());
		let padded = keccak256(padded_buf);
		assert_ne!(
			computed, padded,
			"synthetic_fill_record must use abi.encodePacked (36 bytes), not abi.encode (64 bytes)"
		);
	}

	/// Validates `synthetic_fill_record` byte-for-byte against a
	/// real on-chain `_fillRecords[orderId][outputHash]` storage
	/// value.
	///
	/// Currently ignored: the Task 1 appendix did not capture a
	/// historical fill fixture (no `cast storage` snapshot is
	/// included). The same validation is performed live in Task 6's
	/// integration test, which queries the destination chain RPC for
	/// an actual recent fill and asserts the override produces the
	/// correct storage value. See
	/// `docs/superpowers/plans/2026-05-05-post-fill-state-override-estimation.md`,
	/// Task 6.
	#[test]
	#[ignore]
	fn synthetic_fill_record_matches_real_fill_storage() {
		// Intentionally unimplemented — superseded by the live
		// integration test in Task 6 against Alchemy.
		unimplemented!("see Task 6 live integration test");
	}

	#[test]
	fn build_override_targets_correct_account_and_slot() {
		let settler = Address::repeat_byte(0xaa);
		let order_id = B256::repeat_byte(0xbb);
		let output_hash = B256::repeat_byte(0xcc);
		let solver = B256::repeat_byte(0xdd);
		let timestamp: u32 = 1_700_000_000;

		let ov = build_post_fill_state_override(
			settler,
			order_id,
			output_hash,
			solver,
			timestamp,
		);

		let acct = ov.get(&settler).expect("settler key present");
		let diff = acct.state_diff.as_ref().expect("state_diff present");
		assert_eq!(diff.len(), 1);
		let (slot, value) = diff.iter().next().unwrap();
		assert_eq!(*slot, fill_record_slot(order_id, output_hash));
		assert_eq!(*value, synthetic_fill_record(solver, timestamp));
	}

	#[test]
	fn build_override_omits_other_accounts() {
		let settler = Address::repeat_byte(0xcc);
		let ov = build_post_fill_state_override(
			settler,
			B256::ZERO,
			B256::ZERO,
			B256::ZERO,
			0,
		);
		assert_eq!(ov.len(), 1);
		assert!(ov.contains_key(&settler));
	}
}

#[cfg(test)]
mod proptests {
	use super::*;
	use proptest::prelude::*;

	/// Strategy: any 32-byte value as a [`B256`].
	fn arb_b256() -> impl Strategy<Value = B256> {
		prop::array::uniform32(any::<u8>()).prop_map(B256::new)
	}

	proptest! {
		/// Property 1 — cross-implementation consistency.
		///
		/// `fill_record_slot` uses fixed-size `[u8; 64]` buffers. An
		/// independent reference builds the preimages via `Vec<u8>`
		/// concatenation. Both must agree on every input — disagreement
		/// would indicate a padding / endianness / off-by-one bug in
		/// the buffer assembly.
		#[test]
		fn slot_derivation_matches_independent_impl(
			order_id in arb_b256(),
			output_hash in arb_b256(),
		) {
			let ours = fill_record_slot(order_id, output_hash);

			let mut inner_pre = Vec::with_capacity(64);
			inner_pre.extend_from_slice(order_id.as_slice());
			inner_pre.extend_from_slice(&U256::from(FILL_RECORDS_SLOT).to_be_bytes::<32>());
			let inner_slot = keccak256(&inner_pre);

			let mut final_pre = Vec::with_capacity(64);
			final_pre.extend_from_slice(output_hash.as_slice());
			final_pre.extend_from_slice(inner_slot.as_slice());
			let theirs = keccak256(&final_pre);

			prop_assert_eq!(ours, theirs);
		}

		/// Property 2 — collision-resistance proxy.
		///
		/// For any two distinct `(order_id, output_hash)` pairs the
		/// derived slots must also be distinct. keccak256 makes this
		/// overwhelmingly likely; the property catches off-by-one
		/// bugs that would map all inputs to the same slot, or that
		/// ignore one of the keys entirely.
		#[test]
		fn distinct_inputs_yield_distinct_slots(
			a_order in arb_b256(),
			a_output in arb_b256(),
			b_order in arb_b256(),
			b_output in arb_b256(),
		) {
			prop_assume!((a_order, a_output) != (b_order, b_output));
			prop_assert_ne!(
				fill_record_slot(a_order, a_output),
				fill_record_slot(b_order, b_output),
			);
		}

		/// Property 3 — slot is purely a function of its inputs and
		/// `FILL_RECORDS_SLOT`. No global state, no time, no I/O.
		/// Calling the function twice on the same inputs always
		/// returns the same slot.
		#[test]
		fn slot_derivation_is_deterministic(
			order_id in arb_b256(),
			output_hash in arb_b256(),
		) {
			let first = fill_record_slot(order_id, output_hash);
			let second = fill_record_slot(order_id, output_hash);
			prop_assert_eq!(first, second);
		}
	}
}
