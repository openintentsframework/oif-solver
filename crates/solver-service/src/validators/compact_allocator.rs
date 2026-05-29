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

/// Resolve the allocator address controlling a Compact resource-lock `id` via
/// `TheCompact.getLockDetails(id)`.
async fn resolve_allocator(
	delivery: &Arc<DeliveryService>,
	the_compact_address: &Address,
	chain_id: u64,
	id: U256,
) -> Result<AlloyAddress, APIError> {
	let call = ITheCompact::getLockDetailsCall { id };
	let tx = view_tx(the_compact_address, chain_id, call.abi_encode());

	let result = delivery
		.contract_call(chain_id, tx)
		.await
		.map_err(|e| validation_error(format!("Failed to query TheCompact.getLockDetails: {e}")))?;

	let decoded = ITheCompact::getLockDetailsCall::abi_decode_returns_validate(&result)
		.map_err(|e| validation_error(format!("Failed to decode getLockDetails: {e}")))?;

	Ok(decoded.allocator)
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
) -> Result<(), APIError> {
	if order.inputs.is_empty() {
		return Err(validation_error(
			"ResourceLock order has no inputs to authorize against an allocator",
		));
	}

	// Resolve the allocator for every input and require a single, consistent one.
	// A mixed-allocator batch cannot be authorized by one `authorizeClaim` call.
	let mut resolved: Option<AlloyAddress> = None;
	for input in &order.inputs {
		let allocator =
			resolve_allocator(delivery, the_compact_address, chain_id, input[0]).await?;
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

	// If the solver pins an allocator, the resolved one must match it.
	if let Some(expected) = configured_allocator {
		let expected = AlloyAddress::from_slice(&expected.0);
		if expected != allocator {
			return Err(validation_error(
				"ResourceLock inputs use an allocator that differs from the configured allocator_address",
			));
		}
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

	fn allocator(byte: u8) -> AlloyAddress {
		AlloyAddress::from([byte; 20])
	}

	fn the_compact() -> Address {
		Address(vec![0x88u8; 20])
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

	fn encode_lock_details(allocator: AlloyAddress) -> Bytes {
		let mut out = vec![0u8; 160];
		out[44..64].copy_from_slice(allocator.as_slice());
		Bytes::from(out)
	}

	fn encode_bool(value: bool) -> Bytes {
		let mut out = vec![0u8; 32];
		if value {
			out[31] = 1;
		}
		Bytes::from(out)
	}

	fn order_with_inputs(ids: &[U256]) -> OifStandardOrder {
		OifStandardOrder {
			user: AlloyAddress::from([0x22u8; 20]),
			nonce: U256::from(1u64),
			originChainId: U256::from(CHAIN),
			expires: 2_000_000_000u32,
			fillDeadline: 1_700_000_000u32,
			inputOracle: AlloyAddress::from([0x33u8; 20]),
			inputs: ids.iter().map(|id| [*id, U256::from(1000u64)]).collect(),
			outputs: vec![],
		}
	}

	/// Delivery mock: `getLockDetails(id)` resolves via `lock_allocator_for(id)`;
	/// `isClaimAuthorized` returns `authorized`.
	fn delivery(
		lock_allocator_for: impl Fn(U256) -> AlloyAddress + Send + Sync + 'static,
		authorized: bool,
	) -> Arc<DeliveryService> {
		let mut mock = MockDeliveryInterface::new();
		mock.expect_eth_call().returning(move |tx| {
			let selector = tx.data.get(0..4).map(|s| [s[0], s[1], s[2], s[3]]);
			let resp = match selector {
				Some(s) if s == ITheCompact::getLockDetailsCall::SELECTOR => {
					let mut id_bytes = [0u8; 32];
					id_bytes.copy_from_slice(&tx.data[4..36]);
					encode_lock_details(lock_allocator_for(U256::from_be_bytes(id_bytes)))
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
	async fn authorized_allocator_data_passes() {
		let order = order_with_inputs(&[id_from(1)]);
		let d = delivery(|_| allocator(0xA1), true);
		validate_allocator_authorization(
			&order,
			&Bytes::new(),
			claim_hash(),
			arbiter(),
			&the_compact(),
			None,
			&d,
			CHAIN,
		)
		.await
		.expect("authorized empty allocator data should pass");
	}

	#[tokio::test]
	async fn unauthorized_allocator_data_rejected() {
		let order = order_with_inputs(&[id_from(1)]);
		let d = delivery(|_| allocator(0xA1), false);
		let err = validate_allocator_authorization(
			&order,
			&Bytes::from_static(b"garbage allocator data"),
			claim_hash(),
			arbiter(),
			&the_compact(),
			None,
			&d,
			CHAIN,
		)
		.await
		.expect_err("unauthorized allocator data must be rejected");
		assert!(
			matches!(err, APIError::BadRequest { message, .. } if message.contains("allocator"))
		);
	}

	#[tokio::test]
	async fn mixed_allocators_rejected() {
		let id1 = id_from(1);
		let id2 = id_from(2);
		let order = order_with_inputs(&[id1, id2]);
		let (a1, a2) = (allocator(0xA1), allocator(0xB2));
		let d = delivery(move |id| if id == id1 { a1 } else { a2 }, true);
		let err = validate_allocator_authorization(
			&order,
			&Bytes::new(),
			claim_hash(),
			arbiter(),
			&the_compact(),
			None,
			&d,
			CHAIN,
		)
		.await
		.expect_err("mixed allocators must be rejected");
		assert!(
			matches!(err, APIError::BadRequest { message, .. } if message.contains("multiple allocators"))
		);
	}

	#[tokio::test]
	async fn configured_allocator_mismatch_rejected() {
		let order = order_with_inputs(&[id_from(1)]);
		let d = delivery(|_| allocator(0xA1), true);
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
		)
		.await
		.expect_err("allocator not matching configured allocator must be rejected");
		assert!(
			matches!(err, APIError::BadRequest { message, .. } if message.contains("configured allocator"))
		);
	}

	#[tokio::test]
	async fn configured_allocator_match_passes() {
		let order = order_with_inputs(&[id_from(1)]);
		let d = delivery(|_| allocator(0xA1), true);
		let configured = Address(vec![0xA1u8; 20]);
		validate_allocator_authorization(
			&order,
			&Bytes::new(),
			claim_hash(),
			arbiter(),
			&the_compact(),
			Some(&configured),
			&d,
			CHAIN,
		)
		.await
		.expect("resolved allocator matching configured one should pass");
	}

	#[tokio::test]
	async fn no_inputs_rejected() {
		let order = order_with_inputs(&[]);
		let d = delivery(|_| allocator(0xA1), true);
		let err = validate_allocator_authorization(
			&order,
			&Bytes::new(),
			claim_hash(),
			arbiter(),
			&the_compact(),
			None,
			&d,
			CHAIN,
		)
		.await
		.expect_err("order with no inputs must be rejected");
		assert!(
			matches!(err, APIError::BadRequest { message, .. } if message.contains("no inputs"))
		);
	}
}
