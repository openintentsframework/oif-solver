//! Shared threshold math for monitor and status API.
//!
//! Both the `RebalanceMonitor` and the `GET /admin/rebalance/status` endpoint
//! must produce identical results. This module is the single source of truth.

use alloy_primitives::U256;

/// Result of evaluating a single side's balance against its target.
#[derive(Debug, Clone)]
pub struct ThresholdResult {
	/// Lower bound: `target * (10000 - deviation_band_bps) / 10000`.
	pub lower_bound: U256,
	/// Upper bound: `target * (10000 + deviation_band_bps) / 10000`.
	pub upper_bound: U256,
	/// Whether the current balance is within [lower, upper].
	pub within_band: bool,
	/// Deficit below target (0 if at or above target).
	pub deficit: U256,
	/// Surplus above target (0 if at or below target).
	pub surplus: U256,
}

/// Direction of a needed rebalance.
#[derive(Debug, Clone, PartialEq)]
pub enum RebalanceDirection {
	/// Transfer from side A to side B.
	AToB,
	/// Transfer from side B to side A.
	BToA,
}

/// Full analysis of a pair's threshold state.
#[derive(Debug, Clone)]
pub struct PairThresholdAnalysis {
	/// Threshold result for side A.
	pub side_a: ThresholdResult,
	/// Threshold result for side B.
	pub side_b: ThresholdResult,
	/// Direction needed, if any.
	pub direction_needed: Option<RebalanceDirection>,
	/// Suggested transfer amount (capped by max_bridge_amount).
	pub suggested_amount: U256,
	/// Whether both sides are below their lower bounds (can't rebalance).
	pub both_sides_low: bool,
}

const BPS_BASE: u64 = 10_000;

/// Evaluate a single side's balance against its target and deviation band.
pub fn evaluate_threshold(
	current_balance: U256,
	target_balance: U256,
	deviation_band_bps: u32,
) -> ThresholdResult {
	// Clamp band to [0, 10000] to prevent U256 underflow on (base - band)
	let clamped_bps = deviation_band_bps.min(BPS_BASE as u32);
	let band = U256::from(clamped_bps);
	let base = U256::from(BPS_BASE);

	let lower_bound = target_balance * (base - band) / base;
	let upper_bound = target_balance * (base + band) / base;

	let within_band = current_balance >= lower_bound && current_balance <= upper_bound;
	let deficit = target_balance.saturating_sub(current_balance);
	let surplus = current_balance.saturating_sub(target_balance);

	ThresholdResult {
		lower_bound,
		upper_bound,
		within_band,
		deficit: if current_balance < target_balance {
			deficit
		} else {
			U256::ZERO
		},
		surplus: if current_balance > target_balance {
			surplus
		} else {
			U256::ZERO
		},
	}
}

/// Analyze a pair to determine if rebalancing is needed and in which direction.
pub fn analyze_pair(
	balance_a: U256,
	balance_b: U256,
	target_a: U256,
	target_b: U256,
	deviation_band_bps: u32,
	max_bridge_amount: U256,
) -> PairThresholdAnalysis {
	let side_a = evaluate_threshold(balance_a, target_a, deviation_band_bps);
	let side_b = evaluate_threshold(balance_b, target_b, deviation_band_bps);

	let both_sides_low = balance_a < side_a.lower_bound && balance_b < side_b.lower_bound;

	let (direction_needed, suggested_amount) = if both_sides_low {
		// Can't rebalance — both sides are depleted
		(None, U256::ZERO)
	} else if balance_a < side_a.lower_bound && balance_b > side_b.lower_bound {
		// Side A needs funds — bridge from B to A
		// Cap by what B can donate without going below its own lower bound
		let b_headroom = balance_b.saturating_sub(side_b.lower_bound);
		let amount = side_a.deficit.min(max_bridge_amount).min(b_headroom);
		(Some(RebalanceDirection::BToA), amount)
	} else if balance_b < side_b.lower_bound && balance_a > side_a.lower_bound {
		// Side B needs funds — bridge from A to B
		let a_headroom = balance_a.saturating_sub(side_a.lower_bound);
		let amount = side_b.deficit.min(max_bridge_amount).min(a_headroom);
		(Some(RebalanceDirection::AToB), amount)
	} else if balance_a > side_a.upper_bound {
		// Side A has surplus — bridge from A to B, but never overfund B past its upper bound
		let receiver_headroom = side_b.upper_bound.saturating_sub(balance_b);
		let amount = side_a.surplus.min(max_bridge_amount).min(receiver_headroom);
		if amount.is_zero() {
			(None, U256::ZERO)
		} else {
			(Some(RebalanceDirection::AToB), amount)
		}
	} else if balance_b > side_b.upper_bound {
		// Side B has surplus — bridge from B to A, but never overfund A past its upper bound
		let receiver_headroom = side_a.upper_bound.saturating_sub(balance_a);
		let amount = side_b.surplus.min(max_bridge_amount).min(receiver_headroom);
		if amount.is_zero() {
			(None, U256::ZERO)
		} else {
			(Some(RebalanceDirection::BToA), amount)
		}
	} else {
		// Both within band
		(None, U256::ZERO)
	};

	PairThresholdAnalysis {
		side_a,
		side_b,
		direction_needed,
		suggested_amount,
		both_sides_low,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_evaluate_threshold_within_band() {
		let result = evaluate_threshold(
			U256::from(1000u64),
			U256::from(1000u64),
			2000, // 20%
		);
		assert!(result.within_band);
		assert_eq!(result.lower_bound, U256::from(800u64));
		assert_eq!(result.upper_bound, U256::from(1200u64));
		assert_eq!(result.deficit, U256::ZERO);
		assert_eq!(result.surplus, U256::ZERO);
	}

	#[test]
	fn test_evaluate_threshold_below_lower() {
		let result = evaluate_threshold(U256::from(700u64), U256::from(1000u64), 2000);
		assert!(!result.within_band);
		assert_eq!(result.deficit, U256::from(300u64));
		assert_eq!(result.surplus, U256::ZERO);
	}

	#[test]
	fn test_evaluate_threshold_above_upper() {
		let result = evaluate_threshold(U256::from(1300u64), U256::from(1000u64), 2000);
		assert!(!result.within_band);
		assert_eq!(result.deficit, U256::ZERO);
		assert_eq!(result.surplus, U256::from(300u64));
	}

	#[test]
	fn test_analyze_pair_both_within_band() {
		let analysis = analyze_pair(
			U256::from(1000u64),
			U256::from(1000u64),
			U256::from(1000u64),
			U256::from(1000u64),
			2000,
			U256::from(500u64),
		);
		assert!(analysis.side_a.within_band);
		assert!(analysis.side_b.within_band);
		assert_eq!(analysis.direction_needed, None);
		assert_eq!(analysis.suggested_amount, U256::ZERO);
		assert!(!analysis.both_sides_low);
	}

	#[test]
	fn test_analyze_pair_a_below_triggers_b_to_a() {
		let analysis = analyze_pair(
			U256::from(500u64),  // A below lower (800)
			U256::from(1000u64), // B within band
			U256::from(1000u64),
			U256::from(1000u64),
			2000,
			U256::from(10000u64),
		);
		assert_eq!(analysis.direction_needed, Some(RebalanceDirection::BToA));
		// deficit=500, B headroom=1000-800=200 → capped at 200
		assert_eq!(analysis.suggested_amount, U256::from(200u64));
	}

	#[test]
	fn test_analyze_pair_respects_max_bridge_amount() {
		// B has lots of headroom (2000, lower=800, headroom=1200), max=150 is the binding constraint
		let analysis = analyze_pair(
			U256::from(500u64),
			U256::from(2000u64),
			U256::from(1000u64),
			U256::from(1000u64),
			2000,
			U256::from(150u64), // max = 150
		);
		assert_eq!(analysis.direction_needed, Some(RebalanceDirection::BToA));
		assert_eq!(analysis.suggested_amount, U256::from(150u64)); // capped by max
	}

	#[test]
	fn test_analyze_pair_both_low() {
		let analysis = analyze_pair(
			U256::from(500u64),
			U256::from(500u64),
			U256::from(1000u64),
			U256::from(1000u64),
			2000,
			U256::from(10000u64),
		);
		assert!(analysis.both_sides_low);
		assert_eq!(analysis.direction_needed, None);
	}

	#[test]
	fn test_evaluate_threshold_clamps_excessive_bps() {
		let result = evaluate_threshold(U256::from(1000u64), U256::from(1000u64), 15000);
		// deviation_band_bps = 15000 (>100%) should be clamped to 10000
		assert_eq!(result.lower_bound, U256::ZERO);
		assert_eq!(result.upper_bound, U256::from(2000u64));
	}

	#[test]
	fn test_analyze_pair_caps_by_donor_headroom() {
		// A needs 500 (deficit), B has 1000 with lower bound 800 → B can donate 200
		let analysis = analyze_pair(
			U256::from(500u64),
			U256::from(1000u64),
			U256::from(1000u64),
			U256::from(1000u64),
			2000,
			U256::from(10000u64),
		);
		assert_eq!(analysis.direction_needed, Some(RebalanceDirection::BToA));
		// B headroom = 1000 - 800 = 200; deficit = 500; min(500, 10000, 200) = 200
		assert_eq!(analysis.suggested_amount, U256::from(200u64));
	}

	#[test]
	fn test_analyze_pair_surplus_triggers_rebalance() {
		let analysis = analyze_pair(
			U256::from(1500u64), // A above upper (1200)
			U256::from(1000u64), // B within band
			U256::from(1000u64),
			U256::from(1000u64),
			2000,
			U256::from(10000u64),
		);
		assert_eq!(analysis.direction_needed, Some(RebalanceDirection::AToB));
		assert_eq!(analysis.suggested_amount, U256::from(200u64)); // capped by B headroom to upper bound
	}

	#[test]
	fn test_analyze_pair_surplus_does_not_rebalance_when_both_sides_above_upper_bound() {
		let analysis = analyze_pair(
			U256::from(1300u64),
			U256::from(1250u64),
			U256::from(1000u64),
			U256::from(1000u64),
			2000,
			U256::from(500u64),
		);
		assert_eq!(analysis.direction_needed, None);
		assert_eq!(analysis.suggested_amount, U256::ZERO);
	}

	#[test]
	fn test_analyze_pair_surplus_caps_by_receiver_headroom() {
		let analysis = analyze_pair(
			U256::from(1500u64),
			U256::from(1150u64),
			U256::from(1000u64),
			U256::from(1000u64),
			2000,
			U256::from(500u64),
		);
		assert_eq!(analysis.direction_needed, Some(RebalanceDirection::AToB));
		assert_eq!(analysis.suggested_amount, U256::from(50u64));
	}
}
