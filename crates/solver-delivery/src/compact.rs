//! Shared on-chain read for TheCompact ERC-6909 deposit balances.
//!
//! Both the fast intake capacity check (`solver-service`) and the authoritative
//! reservation glue (`solver-core`) need the same `balanceOf(owner, id)` read on
//! TheCompact. This helper is the single implementation: it lives here because it
//! needs [`DeliveryService`], and both caller crates already depend on
//! `solver-delivery`. The `ITheCompact` ABI it encodes is the shared interface in
//! `solver-types` (feature `oif-interfaces`, on by default).

use crate::{DeliveryError, DeliveryService};
use alloy_primitives::U256;
use alloy_sol_types::SolCall;
use solver_types::standards::eip7683::interfaces::ITheCompact;
use solver_types::{Address, Transaction};

/// Reads `balanceOf(owner, token_id)` on TheCompact at `the_compact` for the
/// given chain via a stateless `eth_call`.
///
/// Returns a human-readable error string on any RPC/decoding problem, suitable
/// for surfacing in an intake-rejection reason or wrapping in an API error.
pub async fn fetch_compact_balance(
	delivery: &DeliveryService,
	chain_id: u64,
	the_compact: Address,
	owner: alloy_primitives::Address,
	token_id: U256,
) -> Result<U256, String> {
	let call_data = ITheCompact::balanceOfCall {
		owner,
		id: token_id,
	}
	.abi_encode();

	let tx = Transaction {
		to: Some(the_compact),
		data: call_data,
		value: U256::ZERO,
		chain_id,
		nonce: None,
		gas_limit: None,
		gas_price: None,
		max_fee_per_gas: None,
		max_priority_fee_per_gas: None,
	};

	let response = delivery
		.contract_call(chain_id, tx)
		.await
		.map_err(|e: DeliveryError| format!("Failed to query TheCompact deposit: {e}"))?;

	if response.len() != 32 {
		return Err(format!(
			"Unexpected TheCompact balanceOf response length: expected 32 bytes, got {}",
			response.len()
		));
	}

	let mut balance_buf = [0u8; 32];
	balance_buf.copy_from_slice(response.as_ref());
	Ok(U256::from_be_bytes(balance_buf))
}
