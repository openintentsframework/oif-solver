//! Just-in-time forced-withdrawal guard for TheCompact ResourceLock orders (C-03).
//!
//! Intake-time validation (`solver-service`) already pins a trusted allocator and
//! requires each input lock's `resetPeriod` to outlast the fill-to-claim window
//! (PR #381). That floor only defends against a forced withdrawal *initiated after*
//! the order is signed: the reset period has to elapse before the funds can be
//! pulled. It does NOT defend against a sponsor who calls `enableForcedWithdrawal`
//! and lets the reset period elapse *before* submitting the order — by the time the
//! solver fills, the lock can already be force-withdrawn on demand, stranding the
//! solver's destination outlay.
//!
//! This module closes that gap by querying `TheCompact.getForcedWithdrawalStatus`
//! for each input lock as close as possible before the destination fill is
//! released. If any lock reports a status other than `Disabled` (i.e. `Pending` or
//! `Enabled`), the fill is aborted: a pending/enabled forced withdrawal means the
//! sponsor can (or soon can) pull the input out from under the claim.
//!
//! Residual TOCTOU: the check is an `eth_call` against the origin chain performed
//! immediately before submitting the destination fill, so a sponsor could still
//! `enableForcedWithdrawal` in the narrow window between this call and on-chain
//! fill inclusion. The intake reset-period floor is what bounds that residual
//! window — a freshly-enabled withdrawal cannot complete until its reset period
//! elapses, which by construction exceeds the fill-to-claim window. This check
//! eliminates the *already-elapsed* case the floor cannot see.

use std::sync::Arc;

use alloy_primitives::{Address as AlloyAddress, U256};
use alloy_sol_types::SolCall;
use solver_delivery::{fetch_compact_balance, DeliveryService};
use solver_types::{standards::eip7683::interfaces::ITheCompact, Address, Transaction};

/// `ForcedWithdrawalStatus` enum value meaning no forced withdrawal is pending or
/// enabled. Any other value (`Pending` = 1, `Enabled` = 2) means the sponsor can
/// pull the locked input before the solver claims, so the fill must be aborted.
const FORCED_WITHDRAWAL_DISABLED: u8 = 0;

/// Error raised when the just-in-time forced-withdrawal guard refuses to release a
/// fill. Treated by the caller as a fatal, non-retryable reason to skip the order.
#[derive(Debug, thiserror::Error)]
pub enum ForcedWithdrawalError {
	/// A lock reports a non-`Disabled` forced-withdrawal status.
	#[error("ResourceLock input {lock_id} has forced withdrawal active (status {status}); refusing to fill")]
	Active { lock_id: U256, status: u8 },
	/// The lock balance is no longer sufficient to cover the order input.
	#[error("ResourceLock input {lock_id} balance {available} is below required amount {required}; refusing to fill")]
	InsufficientBalance {
		lock_id: U256,
		required: U256,
		available: U256,
	},
	/// The on-chain query or its decoding failed; fail closed rather than fill blind.
	#[error("Failed to query TheCompact resource lock state: {0}")]
	Query(String),
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

/// Just-in-time check that no input resource lock has a pending or enabled forced
/// withdrawal, performed immediately before the destination fill is released.
///
/// - `sponsor` is the account whose locks back the order inputs (the StandardOrder
///   `user`); it is the `account` argument to `getForcedWithdrawalStatus`.
/// - `lock_ids` are the ERC-6909 lock identifiers (`inputs[i][0]`).
/// - `the_compact_address` / `origin_chain_id` locate TheCompact on the origin chain.
///
/// Returns `Err` (aborting the fill) if any lock reports a non-`Disabled` status, or
/// if the query/decoding fails (fail closed — never fill on an un-verifiable lock).
pub async fn ensure_no_forced_withdrawal(
	delivery: &Arc<DeliveryService>,
	the_compact_address: &Address,
	origin_chain_id: u64,
	sponsor: AlloyAddress,
	lock_ids: &[U256],
) -> Result<(), ForcedWithdrawalError> {
	for &lock_id in lock_ids {
		let call = ITheCompact::getForcedWithdrawalStatusCall {
			account: sponsor,
			id: lock_id,
		};
		let tx = view_tx(the_compact_address, origin_chain_id, call.abi_encode());

		let result = delivery
			.contract_call(origin_chain_id, tx)
			.await
			.map_err(|e| ForcedWithdrawalError::Query(e.to_string()))?;

		let decoded =
			ITheCompact::getForcedWithdrawalStatusCall::abi_decode_returns_validate(&result)
				.map_err(|e| ForcedWithdrawalError::Query(e.to_string()))?;

		if decoded.status != FORCED_WITHDRAWAL_DISABLED {
			return Err(ForcedWithdrawalError::Active {
				lock_id,
				status: decoded.status,
			});
		}
	}

	Ok(())
}

/// Just-in-time ResourceLock claimability check performed immediately before a
/// destination fill is released.
///
/// This composes two origin-chain reads per non-zero input: the forced-withdrawal
/// status must still be `Disabled`, and `balanceOf(sponsor, id)` must still cover
/// the amount the solver expects to claim.
pub async fn ensure_resource_locks_claimable(
	delivery: &Arc<DeliveryService>,
	the_compact_address: &Address,
	origin_chain_id: u64,
	sponsor: AlloyAddress,
	inputs: &[[U256; 2]],
) -> Result<(), ForcedWithdrawalError> {
	let lock_ids: Vec<_> = inputs.iter().map(|input| input[0]).collect();
	ensure_no_forced_withdrawal(
		delivery,
		the_compact_address,
		origin_chain_id,
		sponsor,
		&lock_ids,
	)
	.await?;

	for &[lock_id, required] in inputs {
		if required.is_zero() {
			continue;
		}

		let available = fetch_compact_balance(
			delivery.as_ref(),
			origin_chain_id,
			the_compact_address.clone(),
			sponsor,
			lock_id,
		)
		.await
		.map_err(ForcedWithdrawalError::Query)?;

		if available < required {
			return Err(ForcedWithdrawalError::InsufficientBalance {
				lock_id,
				required,
				available,
			});
		}
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use solver_delivery::{DeliveryInterface, MockDeliveryInterface};
	use std::collections::HashMap;

	const CHAIN: u64 = 1;

	fn the_compact() -> Address {
		Address(vec![0x88u8; 20])
	}

	fn sponsor() -> AlloyAddress {
		AlloyAddress::from([0x22u8; 20])
	}

	fn id_from(byte: u8) -> U256 {
		let mut b = [0u8; 32];
		b[0] = byte;
		b[31] = byte;
		U256::from_be_bytes(b)
	}

	/// ABI-encode the `getForcedWithdrawalStatus` return tuple
	/// `(uint8 status, uint256 forcedWithdrawalAvailableAt)`: status is the last
	/// byte of word 0; the second word carries the timestamp.
	fn encode_status(status: u8, available_at: u64) -> alloy_primitives::Bytes {
		let mut out = vec![0u8; 64];
		out[31] = status;
		out[56..64].copy_from_slice(&available_at.to_be_bytes());
		alloy_primitives::Bytes::from(out)
	}

	fn encode_u256(value: U256) -> alloy_primitives::Bytes {
		alloy_primitives::Bytes::from(value.to_be_bytes::<32>().to_vec())
	}

	/// Delivery mock: `getForcedWithdrawalStatus(account, id)` resolves its return
	/// tuple via `status_for(id)`.
	fn delivery(
		status_for: impl Fn(U256) -> (u8, u64) + Send + Sync + 'static,
	) -> Arc<DeliveryService> {
		let mut mock = MockDeliveryInterface::new();
		mock.expect_eth_call().returning(move |tx| {
			let selector = tx.data.get(0..4).map(|s| [s[0], s[1], s[2], s[3]]);
			let resp = match selector {
				Some(s) if s == ITheCompact::getForcedWithdrawalStatusCall::SELECTOR => {
					// account occupies word 0 (bytes 4..36); id occupies word 1 (36..68).
					let mut id_bytes = [0u8; 32];
					id_bytes.copy_from_slice(&tx.data[36..68]);
					let (status, at) = status_for(U256::from_be_bytes(id_bytes));
					encode_status(status, at)
				},
				_ => alloy_primitives::Bytes::from(vec![0u8; 64]),
			};
			Box::pin(async move { Ok(resp) })
		});
		let mut impls: HashMap<u64, Arc<dyn DeliveryInterface>> = HashMap::new();
		impls.insert(CHAIN, Arc::new(mock) as Arc<dyn DeliveryInterface>);
		Arc::new(DeliveryService::new(impls, 1, 30, 60))
	}

	/// Delivery mock for the full pre-fill ResourceLock guard:
	/// `getForcedWithdrawalStatus(account, id)` resolves via `status_for(id)`, and
	/// `balanceOf(account, id)` resolves via `balance_for(id)`.
	fn delivery_with_balances(
		status_for: impl Fn(U256) -> (u8, u64) + Send + Sync + 'static,
		balance_for: impl Fn(U256) -> U256 + Send + Sync + 'static,
	) -> Arc<DeliveryService> {
		let mut mock = MockDeliveryInterface::new();
		mock.expect_eth_call().returning(move |tx| {
			let selector = tx.data.get(0..4).map(|s| [s[0], s[1], s[2], s[3]]);
			let resp = match selector {
				Some(s) if s == ITheCompact::getForcedWithdrawalStatusCall::SELECTOR => {
					let mut id_bytes = [0u8; 32];
					id_bytes.copy_from_slice(&tx.data[36..68]);
					let (status, at) = status_for(U256::from_be_bytes(id_bytes));
					encode_status(status, at)
				},
				Some(s) if s == ITheCompact::balanceOfCall::SELECTOR => {
					let mut id_bytes = [0u8; 32];
					id_bytes.copy_from_slice(&tx.data[36..68]);
					encode_u256(balance_for(U256::from_be_bytes(id_bytes)))
				},
				_ => alloy_primitives::Bytes::from(vec![0u8; 64]),
			};
			Box::pin(async move { Ok(resp) })
		});
		let mut impls: HashMap<u64, Arc<dyn DeliveryInterface>> = HashMap::new();
		impls.insert(CHAIN, Arc::new(mock) as Arc<dyn DeliveryInterface>);
		Arc::new(DeliveryService::new(impls, 1, 30, 60))
	}

	#[tokio::test]
	async fn forced_withdrawal_enabled_lock_rejected_before_fill() {
		// A lock whose forced withdrawal is Enabled (status 2) must abort the fill.
		let d = delivery(|_| (2u8, 0));
		let err = ensure_no_forced_withdrawal(&d, &the_compact(), CHAIN, sponsor(), &[id_from(1)])
			.await
			.expect_err("Enabled forced withdrawal must reject the fill");
		assert!(matches!(
			err,
			ForcedWithdrawalError::Active { status: 2, .. }
		));
	}

	#[tokio::test]
	async fn forced_withdrawal_pending_lock_rejected_before_fill() {
		// A lock whose forced withdrawal is Pending (status 1) must abort the fill.
		let d = delivery(|_| (1u8, 9_999_999_999));
		let err = ensure_no_forced_withdrawal(&d, &the_compact(), CHAIN, sponsor(), &[id_from(1)])
			.await
			.expect_err("Pending forced withdrawal must reject the fill");
		assert!(matches!(
			err,
			ForcedWithdrawalError::Active { status: 1, .. }
		));
	}

	#[tokio::test]
	async fn disabled_forced_withdrawal_passes() {
		let d = delivery(|_| (0u8, 0));
		ensure_no_forced_withdrawal(
			&d,
			&the_compact(),
			CHAIN,
			sponsor(),
			&[id_from(1), id_from(2)],
		)
		.await
		.expect("Disabled forced withdrawal on all locks should pass");
	}

	#[tokio::test]
	async fn any_active_lock_in_batch_rejected() {
		// First lock Disabled, second lock Enabled => reject.
		let id1 = id_from(1);
		let d = delivery(move |id| if id == id1 { (0u8, 0) } else { (2u8, 0) });
		let err =
			ensure_no_forced_withdrawal(&d, &the_compact(), CHAIN, sponsor(), &[id1, id_from(2)])
				.await
				.expect_err("a single active lock in the batch must reject the fill");
		assert!(matches!(err, ForcedWithdrawalError::Active { .. }));
	}

	#[tokio::test]
	async fn insufficient_compact_balance_rejected_before_fill() {
		let d = delivery_with_balances(|_| (0u8, 0), |_| U256::from(999u64));
		let err = ensure_resource_locks_claimable(
			&d,
			&the_compact(),
			CHAIN,
			sponsor(),
			&[[id_from(1), U256::from(1000u64)]],
		)
		.await
		.expect_err("insufficient JIT balance must reject the fill");
		assert!(matches!(
			err,
			ForcedWithdrawalError::InsufficientBalance { .. }
		));
	}

	#[tokio::test]
	async fn disabled_forced_withdrawal_and_sufficient_balance_passes() {
		let d = delivery_with_balances(|_| (0u8, 0), |_| U256::from(1000u64));
		ensure_resource_locks_claimable(
			&d,
			&the_compact(),
			CHAIN,
			sponsor(),
			&[[id_from(1), U256::from(1000u64)]],
		)
		.await
		.expect("disabled forced withdrawal plus sufficient balance should pass");
	}
}
