//! Allocator authorization validation for TheCompact ResourceLock orders (pC-02).
//!
//! For a ResourceLock order, `intent.signature` is
//! `abi.encode(bytes sponsorSig, bytes allocatorData)`. Sponsor-signature
//! validation only covers `sponsorSig`; the `allocatorData` half is forwarded
//! unchanged to `IInputSettlerCompact::finalise`, where TheCompact passes it to
//! the allocator's `authorizeClaim`. An enforcing allocator rejects unauthorized
//! `allocatorData`, so without this check the solver could fill destination
//! outputs and then have its claim revert (stranded funds).
//!
//! This module validates `allocatorData` at intake — before any fill — using the
//! allocator's own `isClaimAuthorized` view (the off-chain counterpart of the
//! on-chain `authorizeClaim`), against the exact claim hash `finalise` will use.

use std::sync::Arc;

use alloy_primitives::{Address as AlloyAddress, Bytes, FixedBytes, U256};
use alloy_sol_types::SolCall;
use solver_delivery::DeliveryService;
use solver_types::{
	standards::eip7683::interfaces::{IAllocator, ITheCompact, StandardOrder as OifStandardOrder},
	APIError, Address, ApiErrorType, Transaction,
};

fn validation_error(message: impl Into<String>) -> APIError {
	APIError::BadRequest {
		error_type: ApiErrorType::OrderValidationFailed,
		message: message.into(),
		details: None,
	}
}

/// Build a `view`-style transaction for an `eth_call`.
fn view_tx(to: &Address, chain_id: u64, data: Vec<u8>) -> Transaction {
	Transaction {
		to: Some(to.clone()),
		data,
		value: U256::ZERO,
		chain_id,
		nonce: None,
		gas_limit: None,
		gas_price: None,
		max_fee_per_gas: None,
		max_priority_fee_per_gas: None,
	}
}

/// Map The Compact `ResetPeriod` enum (`uint8`, as returned by `getLockDetails`)
/// to seconds. Returns `None` for an unrecognized value — the caller treats that
/// as un-validatable and rejects rather than guessing.
fn reset_period_seconds(reset_period: u8) -> Option<u64> {
	Some(match reset_period {
		0 => 1,         // OneSecond
		1 => 15,        // FifteenSeconds
		2 => 60,        // OneMinute
		3 => 600,       // TenMinutes
		4 => 3_900,     // OneHourAndFiveMinutes
		5 => 86_400,    // OneDay
		6 => 608_400,   // SevenDaysAndOneHour
		7 => 2_592_000, // ThirtyDays
		_ => return None,
	})
}

/// Resolve the allocator address and reset period controlling a Compact
/// resource-lock `id` via `TheCompact.getLockDetails(id)`.
async fn resolve_allocator(
	delivery: &Arc<DeliveryService>,
	the_compact_address: &Address,
	chain_id: u64,
	id: U256,
) -> Result<(AlloyAddress, u8), APIError> {
	let call = ITheCompact::getLockDetailsCall { id };
	let tx = view_tx(the_compact_address, chain_id, call.abi_encode());

	let result = delivery
		.contract_call(chain_id, tx)
		.await
		.map_err(|e| validation_error(format!("Failed to query TheCompact.getLockDetails: {e}")))?;

	let decoded = ITheCompact::getLockDetailsCall::abi_decode_returns_validate(&result)
		.map_err(|e| validation_error(format!("Failed to decode getLockDetails: {e}")))?;

	Ok((decoded.allocator, decoded.resetPeriod))
}

/// Validate that `allocator_data` is authorized by the allocator that controls
/// the order inputs, before destination fills are allowed.
///
/// - `claim_hash` is the BatchCompact struct hash (the value the allocator's
///   `isClaimAuthorized` / on-chain `authorizeClaim` receives). The caller has
///   already computed this; it must use `arbiter` as the BatchCompact arbiter.
/// - `arbiter` is the `InputSettlerCompact` address (the account that calls
///   `TheCompact.batchClaim` during finalisation).
/// - `configured_allocator`, when present (`network.allocator_address`), pins the
///   allocator the solver expects; a mismatch is rejected.
/// - `route_required_reset_secs` is the route-level minimum settlement window
///   needed after fill. It closes the gap where a signed order sets a far-future
///   fill deadline but a narrow `expires - fillDeadline` interval.
#[allow(clippy::too_many_arguments)]
pub async fn validate_allocator_authorization(
	order: &OifStandardOrder,
	allocator_data: &Bytes,
	claim_hash: FixedBytes<32>,
	arbiter: AlloyAddress,
	the_compact_address: &Address,
	configured_allocator: Option<&Address>,
	delivery: &Arc<DeliveryService>,
	chain_id: u64,
	route_required_reset_secs: u64,
) -> Result<(), APIError> {
	if order.inputs.is_empty() {
		return Err(validation_error(
			"ResourceLock order has no inputs to authorize against an allocator",
		));
	}

	// (C-02/C-03) The lock's reset period must outlast the window between filling
	// the destination output and claiming the input; otherwise the user could
	// force-withdraw after the solver has filled. Use the stricter of the signed
	// order's `expires - fillDeadline` window and the route-level settlement
	// window. The latter prevents an order from using a far-future fill deadline
	// with a narrow signed interval to understate actual fill-to-claim latency.
	let signed_fill_to_claim_secs =
		u64::from(order.expires).saturating_sub(u64::from(order.fillDeadline));
	if signed_fill_to_claim_secs == 0 {
		return Err(validation_error(
			"ResourceLock order is malformed: expires must exceed fillDeadline",
		));
	}
	let required_reset_secs = signed_fill_to_claim_secs.max(route_required_reset_secs);
	let required_reset_label = if route_required_reset_secs > signed_fill_to_claim_secs {
		"route settlement window"
	} else {
		"fill-to-claim window"
	};

	// (C-02) ResourceLock orders require a solver-trusted allocator. Allocator
	// registration in The Compact is permissionless, so without pinning, a user
	// could resolve to an allocator they control, authorize the claim at intake,
	// then refuse it after the fill (or force-withdraw / consume the nonce).
	let expected = match configured_allocator {
		Some(addr) => AlloyAddress::from_slice(&addr.0),
		None => {
			return Err(validation_error(
				"ResourceLock orders require a configured trusted allocator (allocator_address); refusing to fill",
			));
		},
	};

	// Resolve every input lock: require a single consistent allocator, and that
	// each input's reset period exceeds the fill-to-claim window. A mixed-allocator
	// batch cannot be authorized by one `authorizeClaim` call.
	let mut resolved: Option<AlloyAddress> = None;
	for input in &order.inputs {
		let (allocator, reset_period_raw) =
			resolve_allocator(delivery, the_compact_address, chain_id, input[0]).await?;

		let reset_secs = reset_period_seconds(reset_period_raw).ok_or_else(|| {
			validation_error(format!(
				"ResourceLock input lock has an unrecognized reset period ({reset_period_raw})"
			))
		})?;
		if reset_secs <= required_reset_secs {
			return Err(validation_error(format!(
					"ResourceLock input reset period ({reset_secs}s) does not exceed the {required_reset_label} ({required_reset_secs}s)"
				)));
		}

		match resolved {
			None => resolved = Some(allocator),
			Some(existing) if existing != allocator => {
				return Err(validation_error(
					"ResourceLock inputs resolve to multiple allocators",
				));
			},
			Some(_) => {},
		}
	}
	let allocator = resolved.expect("inputs is non-empty");

	// The resolved allocator must match the solver's configured trusted one.
	if expected != allocator {
		return Err(validation_error(
			"ResourceLock inputs use an allocator that differs from the configured allocator_address",
		));
	}

	// Ask the allocator whether this claim (with its allocatorData) is authorized.
	let call = IAllocator::isClaimAuthorizedCall {
		claimHash: claim_hash,
		arbiter,
		sponsor: order.user,
		nonce: order.nonce,
		expires: U256::from(order.expires),
		idsAndAmounts: order.inputs.clone(),
		allocatorData: allocator_data.clone(),
	};
	let allocator_addr = Address(allocator.as_slice().to_vec());
	let tx = view_tx(&allocator_addr, chain_id, call.abi_encode());

	let result = delivery
		.contract_call(chain_id, tx)
		.await
		.map_err(|e| validation_error(format!("Allocator isClaimAuthorized call failed: {e}")))?;

	let authorized = IAllocator::isClaimAuthorizedCall::abi_decode_returns_validate(&result)
		.map_err(|e| {
			validation_error(format!("Failed to decode isClaimAuthorized response: {e}"))
		})?;

	if !authorized {
		return Err(validation_error(
			"Allocator did not authorize the provided allocatorData",
		));
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_sol_types::SolCall;
	use solver_delivery::{DeliveryInterface, MockDeliveryInterface};
	use std::collections::HashMap;

	const CHAIN: u64 = 1;

	// Order timing: the fill-to-claim window is `expires - fillDeadline`.
	const FILL_DEADLINE: u32 = 1_700_000_000;
	const EXPIRES: u32 = 1_700_000_600; // 600s window
	const WINDOW_SECS: u64 = (EXPIRES - FILL_DEADLINE) as u64;

	// The Compact `ResetPeriod` enum (uint8) values used by the tests.
	const RESET_ONE_SECOND: u8 = 0; // 1s     (< window)
	const RESET_TEN_MINUTES: u8 = 3; // 600s   (== window, boundary)
	const RESET_ONE_DAY: u8 = 5; // 86_400s (> window)

	fn allocator(byte: u8) -> AlloyAddress {
		AlloyAddress::from([byte; 20])
	}

	fn the_compact() -> Address {
		Address(vec![0x88u8; 20])
	}

	/// The trusted allocator the solver pins (0xA1...), matching `allocator(0xA1)`.
	fn trusted() -> Address {
		Address(vec![0xA1u8; 20])
	}

	fn arbiter() -> AlloyAddress {
		AlloyAddress::from([0x99u8; 20])
	}

	fn claim_hash() -> FixedBytes<32> {
		FixedBytes::from([0x12u8; 32])
	}

	/// token_id = lockTag(12) || token(20), distinct per `byte`.
	fn id_from(byte: u8) -> U256 {
		let mut b = [0u8; 32];
		b[0] = byte;
		b[31] = byte;
		U256::from_be_bytes(b)
	}

	/// ABI-encode the `getLockDetails` return tuple
	/// `(token, allocator, resetPeriod, scope, lockTag)`: allocator is word 1
	/// (bytes 44..64); resetPeriod (uint8) is the last byte of word 2 (byte 95).
	fn encode_lock_details(allocator: AlloyAddress, reset_period: u8) -> Bytes {
		let mut out = vec![0u8; 160];
		out[44..64].copy_from_slice(allocator.as_slice());
		out[95] = reset_period;
		Bytes::from(out)
	}

	fn encode_bool(value: bool) -> Bytes {
		let mut out = vec![0u8; 32];
		if value {
			out[31] = 1;
		}
		Bytes::from(out)
	}

	fn order_with_window(ids: &[U256], expires: u32, fill_deadline: u32) -> OifStandardOrder {
		OifStandardOrder {
			user: AlloyAddress::from([0x22u8; 20]),
			nonce: U256::from(1u64),
			originChainId: U256::from(CHAIN),
			expires,
			fillDeadline: fill_deadline,
			inputOracle: AlloyAddress::from([0x33u8; 20]),
			inputs: ids.iter().map(|id| [*id, U256::from(1000u64)]).collect(),
			outputs: vec![],
		}
	}

	fn order_with_inputs(ids: &[U256]) -> OifStandardOrder {
		order_with_window(ids, EXPIRES, FILL_DEADLINE)
	}

	/// Delivery mock: `getLockDetails(id)` resolves the allocator via
	/// `lock_allocator_for(id)` and reports `reset_period`; `isClaimAuthorized`
	/// returns `authorized`.
	fn delivery(
		lock_allocator_for: impl Fn(U256) -> AlloyAddress + Send + Sync + 'static,
		reset_period: u8,
		authorized: bool,
	) -> Arc<DeliveryService> {
		let mut mock = MockDeliveryInterface::new();
		mock.expect_eth_call().returning(move |tx| {
			let selector = tx.data.get(0..4).map(|s| [s[0], s[1], s[2], s[3]]);
			let resp = match selector {
				Some(s) if s == ITheCompact::getLockDetailsCall::SELECTOR => {
					let mut id_bytes = [0u8; 32];
					id_bytes.copy_from_slice(&tx.data[4..36]);
					encode_lock_details(
						lock_allocator_for(U256::from_be_bytes(id_bytes)),
						reset_period,
					)
				},
				Some(s) if s == IAllocator::isClaimAuthorizedCall::SELECTOR => {
					encode_bool(authorized)
				},
				_ => Bytes::from(vec![0u8; 32]),
			};
			Box::pin(async move { Ok(resp) })
		});
		let mut impls: HashMap<u64, Arc<dyn DeliveryInterface>> = HashMap::new();
		impls.insert(CHAIN, Arc::new(mock) as Arc<dyn DeliveryInterface>);
		Arc::new(DeliveryService::new(impls, 1, 30, 60))
	}

	#[tokio::test]
	async fn configured_allocator_match_passes() {
		let order = order_with_inputs(&[id_from(1)]);
		let d = delivery(|_| allocator(0xA1), RESET_ONE_DAY, true);
		validate_allocator_authorization(
			&order,
			&Bytes::new(),
			claim_hash(),
			arbiter(),
			&the_compact(),
			Some(&trusted()),
			&d,
			CHAIN,
			0,
		)
		.await
		.expect("trusted allocator + authorized + sufficient reset period should pass");
	}

	#[tokio::test]
	async fn no_configured_allocator_rejected() {
		let order = order_with_inputs(&[id_from(1)]);
		let d = delivery(|_| allocator(0xA1), RESET_ONE_DAY, true);
		let err = validate_allocator_authorization(
			&order,
			&Bytes::new(),
			claim_hash(),
			arbiter(),
			&the_compact(),
			None,
			&d,
			CHAIN,
			0,
		)
		.await
		.expect_err("ResourceLock order without a configured trusted allocator must be rejected");
		assert!(
			matches!(err, APIError::BadRequest { message, .. } if message.contains("trusted allocator"))
		);
	}

	#[tokio::test]
	async fn configured_allocator_mismatch_rejected() {
		let order = order_with_inputs(&[id_from(1)]);
		let d = delivery(|_| allocator(0xA1), RESET_ONE_DAY, true);
		let configured = Address(vec![0xB2u8; 20]);
		let err = validate_allocator_authorization(
			&order,
			&Bytes::new(),
			claim_hash(),
			arbiter(),
			&the_compact(),
			Some(&configured),
			&d,
			CHAIN,
			0,
		)
		.await
		.expect_err("allocator not matching configured allocator must be rejected");
		assert!(
			matches!(err, APIError::BadRequest { message, .. } if message.contains("configured allocator"))
		);
	}

	#[tokio::test]
	async fn unauthorized_allocator_data_rejected() {
		let order = order_with_inputs(&[id_from(1)]);
		let d = delivery(|_| allocator(0xA1), RESET_ONE_DAY, false);
		let err = validate_allocator_authorization(
			&order,
			&Bytes::from_static(b"garbage allocator data"),
			claim_hash(),
			arbiter(),
			&the_compact(),
			Some(&trusted()),
			&d,
			CHAIN,
			0,
		)
		.await
		.expect_err("unauthorized allocator data must be rejected");
		assert!(
			matches!(err, APIError::BadRequest { message, .. } if message.contains("authorize"))
		);
	}

	#[tokio::test]
	async fn mixed_allocators_rejected() {
		let id1 = id_from(1);
		let id2 = id_from(2);
		let order = order_with_inputs(&[id1, id2]);
		let (a1, a2) = (allocator(0xA1), allocator(0xB2));
		let d = delivery(
			move |id| if id == id1 { a1 } else { a2 },
			RESET_ONE_DAY,
			true,
		);
		let err = validate_allocator_authorization(
			&order,
			&Bytes::new(),
			claim_hash(),
			arbiter(),
			&the_compact(),
			Some(&trusted()),
			&d,
			CHAIN,
			0,
		)
		.await
		.expect_err("mixed allocators must be rejected");
		assert!(
			matches!(err, APIError::BadRequest { message, .. } if message.contains("multiple allocators"))
		);
	}

	#[tokio::test]
	async fn no_inputs_rejected() {
		let order = order_with_inputs(&[]);
		let d = delivery(|_| allocator(0xA1), RESET_ONE_DAY, true);
		let err = validate_allocator_authorization(
			&order,
			&Bytes::new(),
			claim_hash(),
			arbiter(),
			&the_compact(),
			Some(&trusted()),
			&d,
			CHAIN,
			0,
		)
		.await
		.expect_err("order with no inputs must be rejected");
		assert!(
			matches!(err, APIError::BadRequest { message, .. } if message.contains("no inputs"))
		);
	}

	#[tokio::test]
	async fn reset_period_below_window_rejected() {
		let order = order_with_inputs(&[id_from(1)]);
		let d = delivery(|_| allocator(0xA1), RESET_ONE_SECOND, true);
		let err = validate_allocator_authorization(
			&order,
			&Bytes::new(),
			claim_hash(),
			arbiter(),
			&the_compact(),
			Some(&trusted()),
			&d,
			CHAIN,
			0,
		)
		.await
		.expect_err("reset period below the fill-to-claim window must be rejected");
		assert!(
			matches!(err, APIError::BadRequest { message, .. } if message.contains("reset period"))
		);
	}

	#[tokio::test]
	async fn reset_period_equal_window_rejected() {
		// resetPeriod == window must reject ("does not exceed").
		assert_eq!(WINDOW_SECS, 600);
		let order = order_with_inputs(&[id_from(1)]);
		let d = delivery(|_| allocator(0xA1), RESET_TEN_MINUTES, true);
		let err = validate_allocator_authorization(
			&order,
			&Bytes::new(),
			claim_hash(),
			arbiter(),
			&the_compact(),
			Some(&trusted()),
			&d,
			CHAIN,
			0,
		)
		.await
		.expect_err("reset period equal to the window must be rejected (does not exceed)");
		assert!(
			matches!(err, APIError::BadRequest { message, .. } if message.contains("reset period"))
		);
	}

	#[tokio::test]
	async fn reset_period_below_route_window_rejected() {
		let order = order_with_inputs(&[id_from(1)]);
		let d = delivery(|_| allocator(0xA1), RESET_TEN_MINUTES, true);
		let err = validate_allocator_authorization(
			&order,
			&Bytes::new(),
			claim_hash(),
			arbiter(),
			&the_compact(),
			Some(&trusted()),
			&d,
			CHAIN,
			3_600,
		)
		.await
		.expect_err("reset period below the route settlement window must be rejected");
		assert!(
			matches!(err, APIError::BadRequest { message, .. } if message.contains("route settlement window"))
		);
	}

	#[tokio::test]
	async fn malformed_expires_le_fill_deadline_rejected() {
		// expires == fillDeadline => zero window => reject regardless of reset period.
		let order = order_with_window(&[id_from(1)], FILL_DEADLINE, FILL_DEADLINE);
		let d = delivery(|_| allocator(0xA1), RESET_ONE_DAY, true);
		let err = validate_allocator_authorization(
			&order,
			&Bytes::new(),
			claim_hash(),
			arbiter(),
			&the_compact(),
			Some(&trusted()),
			&d,
			CHAIN,
			0,
		)
		.await
		.expect_err("order whose expires does not exceed fillDeadline must be rejected");
		assert!(
			matches!(err, APIError::BadRequest { message, .. } if message.contains("fillDeadline"))
		);
	}

	#[test]
	fn reset_period_seconds_maps_known_enum_values() {
		assert_eq!(reset_period_seconds(0), Some(1));
		assert_eq!(reset_period_seconds(1), Some(15));
		assert_eq!(reset_period_seconds(2), Some(60));
		assert_eq!(reset_period_seconds(3), Some(600));
		assert_eq!(reset_period_seconds(4), Some(3_900));
		assert_eq!(reset_period_seconds(5), Some(86_400));
		assert_eq!(reset_period_seconds(6), Some(608_400));
		assert_eq!(reset_period_seconds(7), Some(2_592_000));
	}

	#[test]
	fn reset_period_seconds_unknown_is_none() {
		assert_eq!(reset_period_seconds(8), None);
		assert_eq!(reset_period_seconds(255), None);
	}
}
