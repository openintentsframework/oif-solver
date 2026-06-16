//! Canonical economic binding between a stored quote and the order it priced.
//!
//! Audit finding H-07: a `quote_id` must only unlock a stored cost context for the
//! *same* order the quote was generated for. Without this, an order presenting an
//! unrelated `quote_id` is judged against that quote's (cheaper) stored economics,
//! letting a loss-making fill clear the profitability gate.
//!
//! [`quote_order_binding`] derives a deterministic hash over the economically
//! relevant, **order-derived** fields, including the execution **flow key** that
//! selects gas units from `config.gas.flows`. The two callers compute it for the
//! same logical order so the hashes match byte-for-byte:
//! - at quote time (`solver-service` `store_quotes`): inputs/outputs from the same
//!   [`crate::Eip7683OrderData`] parse methods, and the flow key from
//!   [`crate::OifOrder::flow_key`].
//! - at the profitability gate (`solver-core` `validate_profitability`):
//!   inputs/outputs from the submitted order, and the flow key from
//!   [`crate::order::OrderParsable::parse_lock_type`].
//!
//! The flow key is included because cost context is flow-specific: two orders with
//! identical economic amounts but different lock/auth flow (`permit2_escrow`,
//! `eip3009_escrow`, `resource_lock`) select different gas units, so they must not
//! share a binding. It is derived **explicitly on each side** (not via
//! `From<StandardOrder>`, which drops `lock_type`); `OifOrder::flow_key()` and
//! `LockType::Display` produce the identical strings by construction.
//!
//! Deliberately **excluded**:
//! - `swap_type` and `settlement_name` — these are quote *metadata*, not properties
//!   of the order, so they cannot be recomputed from the submitted order. The binding
//!   answers "is this the order I quoted?"; once it matches, the stored metadata
//!   legitimately applies. (`settlement_name` is also re-derived from the stored
//!   quote's settlement binding before execution, so it is not load-bearing here.)
//! - `nonce` / `signature` / `fillDeadline` / `expires` / `inputOracle` — not economic
//!   and may legitimately differ between the quote and the signed submission.

use crate::api::{OrderInput, OrderOutput};
use alloy_primitives::{keccak256, B256};

/// Version tag mixed into the binding so a future encoding change can't silently
/// collide with v1 hashes.
pub const QUOTE_BINDING_VERSION: u8 = 1;

const DOMAIN: &[u8] = b"oif.quote-order-binding.v1";

/// Deterministic economic binding for an order.
///
/// Encoding is explicit and length-prefixed (no `serde`/map iteration, whose
/// ordering is not a stable security primitive). Inputs and outputs are hashed in
/// their on-chain order — order is economically meaningful and is not sorted.
pub fn quote_order_binding(
	origin_chain_id: u64,
	flow_key: Option<&str>,
	inputs: &[OrderInput],
	outputs: &[OrderOutput],
) -> B256 {
	let mut buf: Vec<u8> = Vec::new();
	buf.extend_from_slice(DOMAIN);
	buf.push(QUOTE_BINDING_VERSION);
	buf.extend_from_slice(&origin_chain_id.to_be_bytes());

	// Execution flow key (lock/auth path) — selects gas units, so it is part of the
	// order's economic identity. Presence byte distinguishes `None` from `Some("")`.
	match flow_key {
		Some(flow) => {
			buf.push(1);
			push_field(&mut buf, flow.as_bytes());
		},
		None => buf.push(0),
	}

	buf.extend_from_slice(&(inputs.len() as u64).to_be_bytes());
	for input in inputs {
		// `to_bytes` is the canonical EIP-7930 encoding; it embeds the chain id,
		// so per-field chain ids do not need to be hashed separately.
		push_field(&mut buf, &input.user.to_bytes());
		push_field(&mut buf, &input.asset.to_bytes());
		buf.extend_from_slice(&input.amount.to_be_bytes::<32>());
	}

	buf.extend_from_slice(&(outputs.len() as u64).to_be_bytes());
	for output in outputs {
		push_field(&mut buf, &output.receiver.to_bytes());
		push_field(&mut buf, &output.asset.to_bytes());
		buf.extend_from_slice(&output.amount.to_be_bytes::<32>());
		push_field(
			&mut buf,
			normalize_calldata(output.calldata.as_deref()).as_bytes(),
		);
	}

	keccak256(&buf)
}

/// Length-prefix a variable-length field so concatenation is unambiguous
/// (prevents `["ab","c"]` colliding with `["a","bc"]`).
fn push_field(buf: &mut Vec<u8>, bytes: &[u8]) {
	buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
	buf.extend_from_slice(bytes);
}

/// Canonicalize the hex calldata string so equivalent encodings hash equally.
/// `None` and an empty/`0x` payload are all treated as "no calldata".
fn normalize_calldata(calldata: Option<&str>) -> String {
	let raw = calldata.unwrap_or("");
	let stripped = raw
		.strip_prefix("0x")
		.or_else(|| raw.strip_prefix("0X"))
		.unwrap_or(raw);
	stripped.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::standards::eip7930::InteropAddress;
	use crate::Address;
	use alloy_primitives::U256;

	fn addr(chain: u64, byte: u8) -> InteropAddress {
		InteropAddress::from((chain, Address(vec![byte; 20])))
	}

	fn input(chain: u64, asset: u8, amount: u64) -> OrderInput {
		OrderInput {
			user: addr(chain, 0xAA),
			asset: addr(chain, asset),
			amount: U256::from(amount),
			lock: None,
		}
	}

	fn output(chain: u64, asset: u8, amount: u64, calldata: Option<&str>) -> OrderOutput {
		OrderOutput {
			receiver: addr(chain, 0xBB),
			asset: addr(chain, asset),
			amount: U256::from(amount),
			calldata: calldata.map(|s| s.to_string()),
		}
	}

	// Canonical flow key held fixed in field-isolation tests.
	const FLOW: Option<&str> = Some("permit2_escrow");

	#[test]
	fn binding_is_deterministic() {
		let i = vec![input(1, 0x01, 100)];
		let o = vec![output(10, 0x02, 90, Some("0xdeadbeef"))];
		assert_eq!(
			quote_order_binding(1, FLOW, &i, &o),
			quote_order_binding(1, FLOW, &i, &o)
		);
	}

	#[test]
	fn binding_changes_with_input_amount() {
		let o = vec![output(10, 0x02, 90, None)];
		let a = quote_order_binding(1, FLOW, &[input(1, 0x01, 100)], &o);
		let b = quote_order_binding(1, FLOW, &[input(1, 0x01, 101)], &o);
		assert_ne!(a, b);
	}

	#[test]
	fn binding_changes_with_output_amount() {
		let i = vec![input(1, 0x01, 100)];
		let a = quote_order_binding(1, FLOW, &i, &[output(10, 0x02, 90, None)]);
		let b = quote_order_binding(1, FLOW, &i, &[output(10, 0x02, 91, None)]);
		assert_ne!(a, b);
	}

	#[test]
	fn binding_changes_with_asset() {
		let i = vec![input(1, 0x01, 100)];
		let a = quote_order_binding(1, FLOW, &i, &[output(10, 0x02, 90, None)]);
		let b = quote_order_binding(1, FLOW, &i, &[output(10, 0x03, 90, None)]);
		assert_ne!(a, b);
	}

	#[test]
	fn binding_changes_with_destination_chain() {
		let i = vec![input(1, 0x01, 100)];
		let a = quote_order_binding(1, FLOW, &i, &[output(10, 0x02, 90, None)]);
		let b = quote_order_binding(1, FLOW, &i, &[output(11, 0x02, 90, None)]);
		assert_ne!(a, b);
	}

	#[test]
	fn binding_changes_with_origin_chain() {
		let i = vec![input(1, 0x01, 100)];
		let o = vec![output(10, 0x02, 90, None)];
		assert_ne!(
			quote_order_binding(1, FLOW, &i, &o),
			quote_order_binding(2, FLOW, &i, &o)
		);
	}

	#[test]
	fn binding_changes_with_flow_key() {
		// Same economic amounts, different lock/auth flow → different gas units →
		// must not share a binding (the P1 finding).
		let i = vec![input(1, 0x01, 100)];
		let o = vec![output(10, 0x02, 90, None)];
		let permit2 = quote_order_binding(1, Some("permit2_escrow"), &i, &o);
		let eip3009 = quote_order_binding(1, Some("eip3009_escrow"), &i, &o);
		let lock = quote_order_binding(1, Some("resource_lock"), &i, &o);
		let none = quote_order_binding(1, None, &i, &o);
		assert_ne!(permit2, eip3009);
		assert_ne!(permit2, lock);
		assert_ne!(eip3009, lock);
		assert_ne!(permit2, none);
	}

	#[test]
	fn binding_changes_with_calldata() {
		let i = vec![input(1, 0x01, 100)];
		let a = quote_order_binding(1, FLOW, &i, &[output(10, 0x02, 90, Some("0xdeadbeef"))]);
		let b = quote_order_binding(1, FLOW, &i, &[output(10, 0x02, 90, Some("0xdeadbe"))]);
		assert_ne!(a, b);
	}

	#[test]
	fn binding_changes_with_output_count_or_order() {
		let i = vec![input(1, 0x01, 100)];
		let one = vec![output(10, 0x02, 90, None)];
		let two = vec![output(10, 0x02, 90, None), output(10, 0x03, 90, None)];
		assert_ne!(
			quote_order_binding(1, FLOW, &i, &one),
			quote_order_binding(1, FLOW, &i, &two)
		);

		let ab = vec![output(10, 0x02, 90, None), output(10, 0x03, 90, None)];
		let ba = vec![output(10, 0x03, 90, None), output(10, 0x02, 90, None)];
		assert_ne!(
			quote_order_binding(1, FLOW, &i, &ab),
			quote_order_binding(1, FLOW, &i, &ba)
		);
	}

	#[test]
	fn calldata_none_matches_empty_and_0x() {
		let i = vec![input(1, 0x01, 100)];
		let none = quote_order_binding(1, FLOW, &i, &[output(10, 0x02, 90, None)]);
		let empty = quote_order_binding(1, FLOW, &i, &[output(10, 0x02, 90, Some(""))]);
		let zerox = quote_order_binding(1, FLOW, &i, &[output(10, 0x02, 90, Some("0x"))]);
		assert_eq!(none, empty);
		assert_eq!(none, zerox);
	}
}
