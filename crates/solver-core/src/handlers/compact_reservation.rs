//! Orchestration glue for reserving TheCompact deposits at engine acceptance.
//!
//! A resource-lock order is backed by an on-chain Compact deposit whose balance
//! is not reduced until the origin claim lands. The engine must therefore
//! reserve the deposited amount the moment it accepts the order, so two orders
//! drawing on the same deposit are never both admitted. The reservation store
//! itself lives in `solver-storage`; this module is the thin glue that derives
//! the per-input [`DepositReservation`]s from an [`Eip7683OrderData`] by reading
//! `balanceOf(owner, id)` on TheCompact via the delivery service.
//!
//! It mirrors the stateless balanceOf capacity check in
//! `solver-service::validators::order::validate_compact_deposit_for_order`, but
//! produces the reservation inputs (carrying the on-chain balance) that the
//! store needs. The service keeps its own fast-intake balance check; this is
//! the authoritative reservation, taken once the engine has committed to the
//! order.
//!
//! It also owns the single source of truth for a resource-lock order's lock
//! identity ([`compact_lock_keys`]) and the best-effort release of those locks
//! ([`release_compact_reservations`]). Both the engine-side intake-abandon path
//! (`IntentHandler`) and the terminal-transition path (`OrderStateMachine`) call
//! the shared release helper, and the reserve path derives its lock identity via
//! the same `[token_id, amount]` parse, so reserve/release key agreement is
//! guaranteed by construction.

use alloy_primitives::U256;
use solver_config::Config;
use solver_delivery::fetch_compact_balance;
use solver_storage::compact_reservations::{CompactReservationStore, DepositReservation};
use solver_types::standards::eip7683::{Eip7683OrderData, LockType};
use solver_types::Order;

/// Derives the deposit reservations for a resource-lock order by reading each
/// input lock's on-chain `balanceOf(owner, token_id)` on TheCompact.
///
/// Lock identity (`chain_id`, `owner`, `token_id`) is derived via
/// [`compact_lock_keys`] so it agrees with the release path by construction.
/// Zero-amount inputs are skipped. Returns an error string (suitable for an
/// `IntentRejected` reason) on any chain/config/RPC problem.
pub async fn derive_compact_deposit_reservations(
	delivery: &solver_delivery::DeliveryService,
	config: &Config,
	order_data: &Eip7683OrderData,
) -> Result<Vec<DepositReservation>, String> {
	let Some(locks) = compact_lock_keys(order_data)? else {
		return Ok(Vec::new());
	};

	let chain_id = u64::try_from(order_data.origin_chain_id)
		.map_err(|_| "Origin chain ID missing or invalid in order".to_string())?;

	let parsed_owner = parse_owner(&order_data.user)?;

	let network = config
		.networks
		.get(&chain_id)
		.ok_or_else(|| format!("Network {chain_id} not configured for solver"))?;
	let compact_address = network
		.the_compact_address
		.as_ref()
		.ok_or_else(|| format!("TheCompact address not configured for chain {chain_id}"))?;

	let mut deposits = Vec::new();
	for (input, (lock_chain_id, owner, token_id)) in order_data.inputs.iter().zip(locks.iter()) {
		let amount = input[1];
		if amount.is_zero() {
			continue;
		}

		let balance = fetch_compact_balance(
			delivery,
			*lock_chain_id,
			compact_address.clone(),
			parsed_owner,
			*token_id,
		)
		.await?;

		deposits.push(DepositReservation {
			chain_id: *lock_chain_id,
			owner: owner.clone(),
			token_id: *token_id,
			amount,
			available_balance: balance,
		});
	}

	Ok(deposits)
}

/// Derives a resource-lock order's lock keys as `(chain_id, owner, token_id)`.
///
/// Returns `Ok(None)` for non-resource-lock orders and `Err` when the origin
/// chain id of a resource-lock order does not fit in a `u64` — the two cases
/// must stay distinct so the reserve path fails closed on a malformed chain id
/// instead of treating it as "nothing to reserve". `token_id` is `input[0]` for
/// each input, matching the reservation store's keying. The owner is the
/// order's raw `user` string; the store normalizes case internally via its
/// `lock_id` derivation (`owner.to_lowercase()`), so reserve and release agree
/// on the key regardless of the input casing.
pub(crate) type CompactLockKey = (u64, String, U256);

pub(crate) fn compact_lock_keys(
	order_data: &Eip7683OrderData,
) -> Result<Option<Vec<CompactLockKey>>, String> {
	if order_data.lock_type != Some(LockType::ResourceLock) {
		return Ok(None);
	}
	let chain_id = u64::try_from(order_data.origin_chain_id)
		.map_err(|_| "Origin chain ID missing or invalid in order".to_string())?;
	Ok(Some(
		order_data
			.inputs
			.iter()
			.map(|input| (chain_id, order_data.user.clone(), input[0]))
			.collect(),
	))
}

/// Best-effort release of a resource-lock order's Compact reservations.
///
/// Shared by both the engine-side intake-abandon path (`IntentHandler`, on a
/// Skip decision or a storage failure after reserving) and the terminal
/// transition path (`OrderStateMachine`). Non-resource-lock orders and orders
/// whose data cannot be parsed are a no-op. Failures only delay reuse of the
/// deposit until the reservation lapses at the order's `expires`, so they are
/// logged, not propagated. `context` is included in the warn log to distinguish
/// the calling path.
pub(crate) async fn release_compact_reservations(
	store: &CompactReservationStore,
	order: &Order,
	context: &str,
) {
	let order_data: Eip7683OrderData = match serde_json::from_value(order.data.clone()) {
		Ok(data) => data,
		Err(e) => {
			tracing::debug!(
				order_id = %order.id,
				error = %e,
				"could not parse order data for compact reservation release"
			);
			return;
		},
	};
	// An Err here means the lock keys cannot be derived (malformed origin
	// chain id) — the reserve path fails closed on the same condition, so
	// nothing was ever reserved and skipping the release is sound.
	let locks = match compact_lock_keys(&order_data) {
		Ok(Some(locks)) => locks,
		Ok(None) => return,
		Err(e) => {
			tracing::debug!(
				order_id = %order.id,
				error = %e,
				"could not derive lock keys for compact reservation release"
			);
			return;
		},
	};

	if let Err(e) = store.release_order(&order.id, &locks).await {
		tracing::warn!(
			order_id = %order.id,
			context,
			error = %e,
			"failed to release compact deposit reservations"
		);
	}
}

/// Parses an order's `user` field (0x-prefixed hex) into an alloy address.
fn parse_owner(user: &str) -> Result<alloy_primitives::Address, String> {
	let trimmed = user.trim_start_matches("0x");
	let bytes =
		alloy_primitives::hex::decode(trimmed).map_err(|e| format!("Invalid user address: {e}"))?;
	if bytes.len() != 20 {
		return Err(format!(
			"Invalid user address length: expected 20 bytes, got {}",
			bytes.len()
		));
	}
	Ok(alloy_primitives::Address::from_slice(&bytes))
}

#[cfg(test)]
mod tests {
	use super::*;
	use solver_config::ConfigBuilder;
	use solver_delivery::DeliveryService;
	use solver_types::standards::eip7683::GasLimitOverrides;
	use std::collections::HashMap;
	use std::sync::Arc;

	fn rl_order_data(origin_chain_id: U256) -> Eip7683OrderData {
		Eip7683OrderData {
			user: "0x00000000000000000000000000000000000000aa".to_string(),
			nonce: U256::from(1u64),
			origin_chain_id,
			expires: 100,
			fill_deadline: 100,
			input_oracle: "0x00000000000000000000000000000000000000bb".to_string(),
			inputs: vec![[U256::from(7u64), U256::from(500u64)]],
			order_id: [0u8; 32],
			gas_limit_overrides: GasLimitOverrides::default(),
			outputs: vec![],
			raw_order_data: None,
			signature: None,
			sponsor: None,
			lock_type: Some(LockType::ResourceLock),
		}
	}

	#[tokio::test]
	async fn derive_reservations_fails_closed_on_invalid_origin_chain_id() {
		// A resource-lock order whose origin chain id does not fit `u64` must be
		// rejected at the reserve boundary, not silently treated as "nothing to
		// reserve" (fail-open would admit the order with no reservation).
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20, 60));
		let config = ConfigBuilder::new().build();
		let order_data = rl_order_data(U256::MAX);

		let result = derive_compact_deposit_reservations(&delivery, &config, &order_data).await;
		let err = result.expect_err("invalid origin chain id must fail closed");
		assert!(
			err.contains("Origin chain ID"),
			"error should name the origin chain id, got: {err}"
		);
	}
}
