//! Fee bump math.

use solver_types::{BumpCapField, Transaction};

/// Bumped fee fields, ready to be written onto a replacement Transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BumpFees {
	pub max_fee_per_gas: Option<u128>,
	pub max_priority_fee_per_gas: Option<u128>,
	pub gas_price: Option<u128>,
}

/// Apply `bump_percent` (e.g., 15 for +15%) to whichever fields the source
/// Transaction has set. Saturating arithmetic — never overflows.
pub fn apply_bump_percent(tx: &Transaction, bump_percent: u32) -> BumpFees {
	let bump = |v: u128| -> u128 {
		let mut increase = v.saturating_mul(bump_percent as u128) / 100;
		if bump_percent > 0 && v > 0 {
			increase = increase.max(1);
		}
		v.saturating_add(increase)
	};
	BumpFees {
		max_fee_per_gas: tx.max_fee_per_gas.map(bump),
		max_priority_fee_per_gas: tx.max_priority_fee_per_gas.map(bump),
		gas_price: tx.gas_price.map(bump),
	}
}

/// Returns the cap field that's the binding constraint, or `None` if
/// no cap is hit. Checks `max_fee_per_gas` first (the harder ceiling).
/// For legacy chains (no EIP-1559 fields), `gas_price` is checked
/// against `max_fee_cap_wei`.
pub fn bumped_fees_exceed_cap(
	fees: &BumpFees,
	max_fee_cap_wei: Option<u128>,
	max_priority_fee_cap_wei: Option<u128>,
) -> Option<BumpCapField> {
	if let (Some(fee), Some(cap)) = (fees.max_fee_per_gas, max_fee_cap_wei) {
		if fee > cap {
			return Some(BumpCapField::MaxFeePerGas);
		}
	}
	if let (Some(priority), Some(cap)) = (fees.max_priority_fee_per_gas, max_priority_fee_cap_wei) {
		if priority > cap {
			return Some(BumpCapField::MaxPriorityFeePerGas);
		}
	}
	// Legacy gas_price: use max_fee_per_gas_cap as the ceiling
	// (matches openzeppelin-relayer's gas_price_cap policy).
	if let (Some(gp), Some(cap)) = (fees.gas_price, max_fee_cap_wei) {
		if gp > cap {
			return Some(BumpCapField::MaxFeePerGas);
		}
	}
	None
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::U256;
	use solver_types::{Address, Transaction};

	fn eip1559_tx() -> Transaction {
		Transaction {
			to: Some(Address(vec![1; 20])),
			data: vec![],
			value: U256::ZERO,
			chain_id: 1,
			nonce: Some(0),
			gas_limit: Some(100_000),
			gas_price: None,
			max_fee_per_gas: Some(10_000_000_000),         // 10 gwei
			max_priority_fee_per_gas: Some(1_000_000_000), // 1 gwei
		}
	}

	fn legacy_tx() -> Transaction {
		Transaction {
			to: Some(Address(vec![1; 20])),
			data: vec![],
			value: U256::ZERO,
			chain_id: 1,
			nonce: Some(0),
			gas_limit: Some(100_000),
			gas_price: Some(10_000_000_000),
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
		}
	}

	#[test]
	fn apply_bump_percent_15_to_eip1559_bumps_both_fields() {
		let bumped = apply_bump_percent(&eip1559_tx(), 15);
		assert_eq!(bumped.max_fee_per_gas, Some(11_500_000_000));
		assert_eq!(bumped.max_priority_fee_per_gas, Some(1_150_000_000));
		assert!(bumped.gas_price.is_none());
	}

	#[test]
	fn apply_bump_percent_10_to_legacy_bumps_gas_price() {
		let bumped = apply_bump_percent(&legacy_tx(), 10);
		assert_eq!(bumped.gas_price, Some(11_000_000_000));
		assert!(bumped.max_fee_per_gas.is_none());
	}

	#[test]
	fn apply_bump_percent_saturates_near_u128_max() {
		let mut tx = eip1559_tx();
		tx.max_fee_per_gas = Some(u128::MAX);
		let bumped = apply_bump_percent(&tx, 15);
		assert_eq!(bumped.max_fee_per_gas, Some(u128::MAX));
	}

	#[test]
	fn apply_bump_percent_always_increases_non_zero_fee() {
		let mut tx = legacy_tx();
		tx.gas_price = Some(1);
		let bumped = apply_bump_percent(&tx, 10);
		assert_eq!(bumped.gas_price, Some(2));
	}

	#[test]
	fn cap_check_returns_none_when_under_cap() {
		let fees = BumpFees {
			max_fee_per_gas: Some(10_000),
			max_priority_fee_per_gas: Some(1_000),
			gas_price: None,
		};
		assert!(bumped_fees_exceed_cap(&fees, Some(20_000), Some(5_000)).is_none());
	}

	#[test]
	fn cap_check_returns_max_fee_when_fee_exceeds() {
		let fees = BumpFees {
			max_fee_per_gas: Some(30_000),
			max_priority_fee_per_gas: Some(1_000),
			gas_price: None,
		};
		assert_eq!(
			bumped_fees_exceed_cap(&fees, Some(20_000), None),
			Some(BumpCapField::MaxFeePerGas)
		);
	}

	#[test]
	fn cap_check_returns_priority_when_priority_exceeds_only() {
		let fees = BumpFees {
			max_fee_per_gas: Some(10_000),
			max_priority_fee_per_gas: Some(7_000),
			gas_price: None,
		};
		assert_eq!(
			bumped_fees_exceed_cap(&fees, None, Some(5_000)),
			Some(BumpCapField::MaxPriorityFeePerGas)
		);
	}

	#[test]
	fn cap_check_no_cap_set_returns_none() {
		let fees = BumpFees {
			max_fee_per_gas: Some(u128::MAX),
			max_priority_fee_per_gas: Some(u128::MAX),
			gas_price: None,
		};
		assert!(bumped_fees_exceed_cap(&fees, None, None).is_none());
	}

	#[test]
	fn cap_check_legacy_uses_max_fee_cap() {
		let fees = BumpFees {
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
			gas_price: Some(50_000),
		};
		assert_eq!(
			bumped_fees_exceed_cap(&fees, Some(40_000), None),
			Some(BumpCapField::MaxFeePerGas)
		);
	}
}
