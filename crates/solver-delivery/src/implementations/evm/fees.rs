//! Solver-specific EIP-1559 fee policy on top of alloy.
//!
//! This module provides the per-chain fee policy struct and the
//! `SolverEip1559Estimator` that plugs into alloy's `Eip1559EstimatorFn`
//! pipeline. Reward extraction (median of nonzero rewards from the requested
//! percentile column), per-chain priority floor + fallback, one-block base-fee
//! projection, and optional cap application all live here. Fee-history
//! retrieval and base-fee parsing are handled by alloy itself.

use alloy_provider::utils::{Eip1559Estimation, Eip1559EstimatorFn};
use std::collections::HashMap;

use crate::{FeeCostStrategy, FeeSpeed};

const BASE_PRIORITY_FEE_FALLBACK_WEI: u128 = 10_000_000; // 0.01 gwei

/// Per-chain fee-policy knobs that sit on top of alloy's EIP-1559 pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainFeePolicy {
	pub speed: FeeSpeed,
	pub min_priority_fee_per_gas: Option<u128>,
	pub priority_fee_fallback: u128,
	pub quote_cost_strategy: FeeCostStrategy,
	pub gas_price_cap: Option<u128>,
}

impl ChainFeePolicy {
	pub fn default_for_chain(_chain_id: u64) -> Self {
		Self {
			speed: FeeSpeed::Fast,
			min_priority_fee_per_gas: Some(BASE_PRIORITY_FEE_FALLBACK_WEI),
			priority_fee_fallback: BASE_PRIORITY_FEE_FALLBACK_WEI,
			quote_cost_strategy: FeeCostStrategy::BufferedEffective125,
			gas_price_cap: None,
		}
	}
}

// Note: we deliberately do NOT carry an `average_block_time_ms` here.
// The 2× base-fee projection in `SolverEip1559Estimator::estimate`
// follows alloy's default headroom. If a future strategy needs a per-chain
// projection multiplier, add the field then — not as speculative config now.

/// Errors returned when parsing/validating a [`FeePolicyConfig`] into a
/// [`FeePolicyRegistry`]. Each variant carries enough context (chain id,
/// field name) to point an operator at the offending entry without having
/// to re-derive it from a backtrace.
#[derive(Debug, thiserror::Error)]
pub enum FeePolicyError {
	/// A wei-string field on a chain entry could not be parsed as a u128.
	/// `field` is the JSON key (`"min_priority_fee_per_gas"`, etc.) so the
	/// operator can grep their config straight to the broken field.
	#[error(
		"Invalid decimal wei value for fee_policy.chains.{chain_id}.{field}: {value:?} ({source})"
	)]
	InvalidWeiValue {
		chain_id: String,
		field: &'static str,
		value: String,
		#[source]
		source: std::num::ParseIntError,
	},
	/// A chain id key in `fee_policy.chains` did not parse as a u64.
	#[error("Invalid chain id in fee_policy.chains: {chain_id:?} ({source})")]
	InvalidChainId {
		chain_id: String,
		#[source]
		source: std::num::ParseIntError,
	},
	/// A network was configured for the delivery implementation but no
	/// matching policy entry exists in `fee_policy.chains`. Startup MUST
	/// fail loudly per the production invariant — there is no implicit
	/// fallback to `default_for_chain`.
	#[error(
		"Missing fee_policy.chains entry for chain {chain_id} \
		 (every configured network must declare a fee policy)"
	)]
	MissingChainPolicy { chain_id: u64 },
}

/// Top-level fee-policy block consumed by the Alloy delivery config.
///
/// `chains` is keyed by chain id stringified (TOML/JSON object keys are
/// always strings). Conversion into a [`FeePolicyRegistry`] parses each
/// key into a `u64`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct FeePolicyConfig {
	pub default_speed: FeeSpeed,
	pub chains: HashMap<String, ChainFeePolicyConfig>,
}

/// Per-chain fee policy as it appears in config. Wei values are decimal
/// strings to avoid JSON's 53-bit float precision pit; conversion to
/// `u128` happens in [`ChainFeePolicy::from_config`].
///
/// We deliberately do NOT include `average_block_time_ms` here — see the
/// note above [`SolverEip1559Estimator`] for rationale.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ChainFeePolicyConfig {
	pub min_priority_fee_per_gas: Option<String>,
	pub priority_fee_fallback: String,
	pub quote_cost_strategy: FeeCostStrategy,
	pub gas_price_cap: Option<String>,
}

/// Parse a decimal wei string into u128, mapping failure into a
/// `FeePolicyError::InvalidWeiValue` carrying the offending field name.
fn parse_wei_field(
	chain_id: &str,
	field: &'static str,
	value: &str,
) -> Result<u128, FeePolicyError> {
	value
		.parse::<u128>()
		.map_err(|source| FeePolicyError::InvalidWeiValue {
			chain_id: chain_id.to_string(),
			field,
			value: value.to_string(),
			source,
		})
}

impl ChainFeePolicy {
	/// Build a runtime [`ChainFeePolicy`] from a config entry. `default_speed`
	/// from the parent [`FeePolicyConfig`] is plumbed through because the
	/// per-chain block does not currently override speed (one solver-wide
	/// percentile target is enough until a real use-case for per-chain speed
	/// override appears).
	pub fn from_config(
		chain_id: &str,
		default_speed: FeeSpeed,
		cfg: &ChainFeePolicyConfig,
	) -> Result<Self, FeePolicyError> {
		let min_priority_fee_per_gas = cfg
			.min_priority_fee_per_gas
			.as_deref()
			.map(|raw| parse_wei_field(chain_id, "min_priority_fee_per_gas", raw))
			.transpose()?;
		let priority_fee_fallback = parse_wei_field(
			chain_id,
			"priority_fee_fallback",
			&cfg.priority_fee_fallback,
		)?;
		let gas_price_cap = cfg
			.gas_price_cap
			.as_deref()
			.map(|raw| parse_wei_field(chain_id, "gas_price_cap", raw))
			.transpose()?;
		Ok(Self {
			speed: default_speed,
			min_priority_fee_per_gas,
			priority_fee_fallback,
			quote_cost_strategy: cfg.quote_cost_strategy,
			gas_price_cap,
		})
	}
}

/// Validated, runtime-shaped per-chain fee policy lookup.
///
/// Built once at startup from a [`FeePolicyConfig`] alongside the list of
/// chain ids the delivery implementation is being constructed for. Missing
/// chain entries are a hard error: there is no silent fallback — the
/// production invariant says configs without `fee_policy` (or without an
/// entry for a configured chain) MUST fail to validate.
#[derive(Debug, Clone)]
pub struct FeePolicyRegistry {
	chains: HashMap<u64, ChainFeePolicy>,
}

impl FeePolicyRegistry {
	/// Build a registry from a [`FeePolicyConfig`] and the list of chain ids
	/// that MUST have a policy entry. The construction fails if:
	/// - any key in `config.chains` is not a valid u64,
	/// - any wei-string field fails to parse,
	/// - any `required_chain_ids` is missing from `config.chains`.
	pub fn from_config(
		config: &FeePolicyConfig,
		required_chain_ids: &[u64],
	) -> Result<Self, FeePolicyError> {
		let mut chains: HashMap<u64, ChainFeePolicy> = HashMap::new();
		for (chain_key, cfg) in &config.chains {
			let chain_id: u64 =
				chain_key
					.parse::<u64>()
					.map_err(|source| FeePolicyError::InvalidChainId {
						chain_id: chain_key.clone(),
						source,
					})?;
			let policy = ChainFeePolicy::from_config(chain_key, config.default_speed, cfg)?;
			chains.insert(chain_id, policy);
		}
		for chain_id in required_chain_ids {
			if !chains.contains_key(chain_id) {
				return Err(FeePolicyError::MissingChainPolicy {
					chain_id: *chain_id,
				});
			}
		}
		Ok(Self { chains })
	}

	/// Look up the validated policy for `chain_id`. The registry is built
	/// against the exact list of supported chains, so a missing entry here
	/// means a programmer error (some new chain id slipped past startup
	/// validation). Panicking is the right shape: it's loud, traceable, and
	/// production-incidental — never user-facing.
	pub fn policy_for_chain(&self, chain_id: u64) -> &ChainFeePolicy {
		self.chains.get(&chain_id).unwrap_or_else(|| {
			panic!(
				"FeePolicyRegistry has no entry for chain_id {chain_id}; \
				 startup validation should have rejected this config"
			)
		})
	}
}

/// Solver-specific EIP-1559 estimator. Wraps alloy's `Eip1559EstimatorFn`
/// trait so we can plug per-chain priority floor + fallback + projection
/// multiplier + cap into the alloy estimator pipeline.
///
/// Reward extraction (median of nonzero rewards from the requested percentile
/// column) is the only piece of arithmetic kept here; everything else —
/// fee-history retrieval, base-fee parsing, multi-percentile fan-out — is
/// handled by alloy. See `Provider::get_fee_history` in alloy 1.0.37.
#[derive(Debug, Clone)]
pub struct SolverEip1559Estimator {
	pub policy: ChainFeePolicy,
}

impl SolverEip1559Estimator {
	/// Inherent method so callers can invoke `.estimate(...)` without
	/// importing the `Eip1559EstimatorFn` trait. The trait impl below
	/// delegates here so alloy's `Eip1559Estimator::Custom` can also
	/// dispatch to the same body.
	pub fn estimate(&self, base_fee: u128, rewards: &[Vec<u128>]) -> Eip1559Estimation {
		// We always request a single percentile column when calling
		// get_fee_history, so column 0 is always the right index.
		let mut nonzero: Vec<u128> = rewards
			.iter()
			.filter_map(|row| row.first().copied())
			.filter(|v| *v > 0)
			.collect();
		nonzero.sort_unstable();
		let median = nonzero.get(nonzero.len() / 2).copied().unwrap_or(0);

		// Apply per-chain floor and fallback. priority_fee_fallback ensures
		// priority > 0 even when fee-history rewards are empty (e.g., Katana).
		let priority = median
			.max(self.policy.min_priority_fee_per_gas.unwrap_or(0))
			.max(self.policy.priority_fee_fallback);

		// Project base fee forward using alloy's default 2x headroom.
		let projected_base = base_fee.saturating_mul(2);
		let raw_max = projected_base.saturating_add(priority);
		let max_fee = self
			.policy
			.gas_price_cap
			.map_or(raw_max, |cap| raw_max.min(cap))
			.max(priority); // never let cap drop max_fee below priority

		Eip1559Estimation {
			max_fee_per_gas: max_fee,
			max_priority_fee_per_gas: priority,
		}
	}
}

pub(crate) fn clamp_legacy_gas_price_to_cap(gas_price: u128, policy: &ChainFeePolicy) -> u128 {
	policy
		.gas_price_cap
		.map_or(gas_price, |cap| gas_price.min(cap))
}

/// Trait impl so `SolverEip1559Estimator` can be passed to alloy's
/// `Eip1559Estimator::Custom(...)` if a future caller wants to use
/// alloy's `estimate_eip1559_fees_with(...)` wrapper. Today our
/// `get_fee_params` calls the inherent method directly because we
/// also need to control the percentile passed to `get_fee_history`.
impl Eip1559EstimatorFn for SolverEip1559Estimator {
	fn estimate(&self, base_fee: u128, rewards: &[Vec<u128>]) -> Eip1559Estimation {
		SolverEip1559Estimator::estimate(self, base_fee, rewards)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::FeeParams;

	#[test]
	fn default_policy_has_low_priority_floor() {
		let policy = ChainFeePolicy::default_for_chain(1);
		assert_eq!(policy.min_priority_fee_per_gas, Some(10_000_000));
	}

	#[test]
	fn non_mainnet_default_policy_uses_same_low_floor() {
		let policy = ChainFeePolicy::default_for_chain(747474);
		assert_eq!(policy.min_priority_fee_per_gas, Some(10_000_000));
	}

	#[test]
	fn empty_rewards_use_nonzero_priority_fallback() {
		let policy = ChainFeePolicy::default_for_chain(747474);
		let estimator = SolverEip1559Estimator { policy };
		let est = estimator.estimate(30_000_000, &[]);
		assert!(est.max_priority_fee_per_gas > 0);
	}

	#[test]
	fn eip1559_estimator_projects_base_fee_at_2x() {
		let policy = ChainFeePolicy::default_for_chain(1);
		let estimator = SolverEip1559Estimator { policy };
		let rewards = vec![vec![100_000_000u128]];
		let base_fee = 500_000_000u128;

		let est = estimator.estimate(base_fee, &rewards);

		assert_eq!(
			est.max_fee_per_gas,
			base_fee.saturating_mul(2) + 100_000_000
		);
	}

	#[test]
	fn eip1559_estimator_uses_observed_priority_above_low_floor() {
		let policy = ChainFeePolicy::default_for_chain(1);
		let estimator = SolverEip1559Estimator {
			policy: policy.clone(),
		};
		let rewards = vec![vec![100_000_000u128]];
		let est = estimator.estimate(500_000_000, &rewards);

		assert_eq!(est.max_priority_fee_per_gas, 100_000_000);
		assert!(est.max_fee_per_gas >= 100_000_000);
		assert!(est.max_fee_per_gas >= est.max_priority_fee_per_gas);

		// Cost strategy selection is independent of the estimator output;
		// verify it produces a value within [priority, max_fee].
		let params = FeeParams::eip1559_with_strategy(
			1,
			est.max_fee_per_gas,
			est.max_priority_fee_per_gas,
			500_000_000,
			FeeCostStrategy::BufferedEffective125,
		);
		assert!(params.cost_per_gas <= params.max_fee_per_gas.unwrap());
		assert!(params.cost_per_gas >= params.max_priority_fee_per_gas.unwrap());
	}

	#[test]
	fn cost_strategy_selection_matches_documented_formula() {
		// Same estimator inputs, three strategies, three different cost_per_gas.
		let base_fee = 1_000_000_000u128;
		let priority = 2_000_000_000u128;
		let max_fee = 5_000_000_000u128;

		let max = FeeParams::eip1559_with_strategy(
			1,
			max_fee,
			priority,
			base_fee,
			FeeCostStrategy::MaxFee,
		);
		let effective = FeeParams::eip1559_with_strategy(
			1,
			max_fee,
			priority,
			base_fee,
			FeeCostStrategy::Effective,
		);
		let buffered = FeeParams::eip1559_with_strategy(
			1,
			max_fee,
			priority,
			base_fee,
			FeeCostStrategy::BufferedEffective125,
		);

		assert_eq!(max.cost_per_gas, max_fee);
		// Effective = base + priority = 3 gwei
		assert_eq!(effective.cost_per_gas, base_fee + priority);
		// Buffered = base*1.25 + priority = 3.25 gwei (still < max_fee)
		assert_eq!(
			buffered.cost_per_gas,
			(base_fee.saturating_mul(125) / 100).saturating_add(priority),
		);
		assert!(max.cost_per_gas > buffered.cost_per_gas);
		assert!(buffered.cost_per_gas > effective.cost_per_gas);
	}

	// ------------------------------------------------------------------
	// FeePolicyConfig / FeePolicyRegistry tests (Task 8)
	// ------------------------------------------------------------------

	fn parse_fee_policy(value: serde_json::Value) -> FeePolicyConfig {
		serde_json::from_value(value).expect("valid FeePolicyConfig fixture")
	}

	#[test]
	fn fee_policy_config_deserializes_known_speeds_and_strategies() {
		// `default_speed: "fast"` and `quote_cost_strategy: "buffered_effective_125"`
		// must round-trip through serde without introducing a new local enum.
		let cfg = parse_fee_policy(serde_json::json!({
			"default_speed": "fast",
			"chains": {
				"1": {
					"min_priority_fee_per_gas": "2000000000",
					"priority_fee_fallback": "100000000",
					"quote_cost_strategy": "buffered_effective_125",
					"gas_price_cap": "100000000000"
				}
			}
		}));
		assert_eq!(cfg.default_speed, FeeSpeed::Fast);
		let entry = cfg.chains.get("1").expect("chain 1 entry");
		assert_eq!(
			entry.quote_cost_strategy,
			FeeCostStrategy::BufferedEffective125
		);
	}

	#[test]
	fn fee_policy_registry_round_trips_mainnet_floor_and_cap() {
		let cfg = parse_fee_policy(serde_json::json!({
			"default_speed": "fast",
			"chains": {
				"1": {
					"min_priority_fee_per_gas": "2000000000",
					"priority_fee_fallback": "100000000",
					"quote_cost_strategy": "buffered_effective_125",
					"gas_price_cap": "100000000000"
				}
			}
		}));
		let registry = FeePolicyRegistry::from_config(&cfg, &[1]).expect("valid registry");
		let policy = registry.policy_for_chain(1);
		assert_eq!(policy.min_priority_fee_per_gas, Some(2_000_000_000));
		assert_eq!(policy.priority_fee_fallback, 100_000_000);
		assert_eq!(policy.gas_price_cap, Some(100_000_000_000));
		assert_eq!(policy.speed, FeeSpeed::Fast);
		assert_eq!(
			policy.quote_cost_strategy,
			FeeCostStrategy::BufferedEffective125
		);
	}

	#[test]
	fn fee_policy_registry_accepts_katana_without_average_block_time() {
		// Katana entry MUST be representable without `average_block_time_ms`
		// (the field is deliberately absent from the runtime struct).
		let cfg = parse_fee_policy(serde_json::json!({
			"default_speed": "fast",
			"chains": {
				"747474": {
					"priority_fee_fallback": "100000000",
					"quote_cost_strategy": "buffered_effective_125"
				}
			}
		}));
		let registry = FeePolicyRegistry::from_config(&cfg, &[747474]).expect("valid registry");
		let policy = registry.policy_for_chain(747474);
		assert_eq!(policy.min_priority_fee_per_gas, None);
		assert_eq!(policy.gas_price_cap, None);
	}

	#[test]
	fn fee_policy_registry_missing_chain_is_startup_error() {
		let cfg = parse_fee_policy(serde_json::json!({
			"default_speed": "fast",
			"chains": {
				"1": {
					"priority_fee_fallback": "100000000",
					"quote_cost_strategy": "buffered_effective_125"
				}
			}
		}));
		let err = FeePolicyRegistry::from_config(&cfg, &[1, 137])
			.expect_err("chain 137 has no policy entry");
		match err {
			FeePolicyError::MissingChainPolicy { chain_id } => assert_eq!(chain_id, 137),
			other => panic!("expected MissingChainPolicy, got {other:?}"),
		}
	}

	#[test]
	fn fee_policy_registry_rejects_invalid_decimal_with_field_name() {
		let cfg = parse_fee_policy(serde_json::json!({
			"default_speed": "fast",
			"chains": {
				"1": {
					"min_priority_fee_per_gas": "not-a-number",
					"priority_fee_fallback": "100000000",
					"quote_cost_strategy": "buffered_effective_125"
				}
			}
		}));
		let err = FeePolicyRegistry::from_config(&cfg, &[1])
			.expect_err("min_priority_fee_per_gas is non-numeric");
		match err {
			FeePolicyError::InvalidWeiValue {
				chain_id,
				field,
				value,
				..
			} => {
				assert_eq!(chain_id, "1");
				assert_eq!(field, "min_priority_fee_per_gas");
				assert_eq!(value, "not-a-number");
			},
			other => panic!("expected InvalidWeiValue, got {other:?}"),
		}
	}

	#[test]
	fn fee_policy_registry_priority_fallback_pins_zero_reward_priority() {
		// Empty fee-history rewards on a chain configured ONLY with a fallback
		// (no min floor) must still produce a non-zero priority — the
		// fallback's whole purpose.
		let cfg = parse_fee_policy(serde_json::json!({
			"default_speed": "fast",
			"chains": {
				"747474": {
					"priority_fee_fallback": "750000000",
					"quote_cost_strategy": "buffered_effective_125"
				}
			}
		}));
		let registry = FeePolicyRegistry::from_config(&cfg, &[747474]).expect("valid registry");
		let policy = registry.policy_for_chain(747474).clone();
		let estimator = SolverEip1559Estimator { policy };
		let est = estimator.estimate(30_000_000, &[]);
		assert_eq!(est.max_priority_fee_per_gas, 750_000_000);
	}

	#[test]
	fn fee_policy_registry_min_priority_floor_overrides_observed_rewards() {
		// Configured floor must clamp observed rewards from below.
		let cfg = parse_fee_policy(serde_json::json!({
			"default_speed": "fast",
			"chains": {
				"1": {
					"min_priority_fee_per_gas": "2000000000",
					"priority_fee_fallback": "100000000",
					"quote_cost_strategy": "buffered_effective_125"
				}
			}
		}));
		let registry = FeePolicyRegistry::from_config(&cfg, &[1]).expect("valid registry");
		let policy = registry.policy_for_chain(1).clone();
		let estimator = SolverEip1559Estimator { policy };
		// Observed reward 100 mwei is well below the configured 2 gwei floor.
		let est = estimator.estimate(500_000_000, &[vec![100_000_000u128]]);
		assert_eq!(est.max_priority_fee_per_gas, 2_000_000_000);
	}

	#[test]
	fn fee_policy_registry_gas_price_cap_clamps_max_fee() {
		// `gas_price_cap` must cap `max_fee_per_gas` while still respecting
		// the priority-floor invariant (max >= priority).
		let cfg = parse_fee_policy(serde_json::json!({
			"default_speed": "fast",
			"chains": {
				"1": {
					"min_priority_fee_per_gas": "2000000000",
					"priority_fee_fallback": "100000000",
					"quote_cost_strategy": "buffered_effective_125",
					"gas_price_cap": "2500000000"
				}
			}
		}));
		let registry = FeePolicyRegistry::from_config(&cfg, &[1]).expect("valid registry");
		let policy = registry.policy_for_chain(1).clone();
		let estimator = SolverEip1559Estimator { policy };
		// Pick a base fee high enough that without the cap the max_fee would
		// significantly exceed 2.5 gwei.
		let est = estimator.estimate(10_000_000_000, &[vec![100_000_000u128]]);
		assert!(est.max_fee_per_gas <= 2_500_000_000.max(est.max_priority_fee_per_gas));
	}

	#[test]
	fn gas_price_cap_clamps_legacy_fallback_price() {
		let policy = ChainFeePolicy {
			speed: FeeSpeed::Fast,
			min_priority_fee_per_gas: Some(100_000_000),
			priority_fee_fallback: 100_000_000,
			quote_cost_strategy: FeeCostStrategy::BufferedEffective125,
			gas_price_cap: Some(2_500_000_000),
		};

		assert_eq!(
			super::clamp_legacy_gas_price_to_cap(10_000_000_000, &policy),
			2_500_000_000
		);
	}

	#[test]
	fn fee_policy_quote_cost_strategy_changes_cost_not_max_fee() {
		// Submit-side `max_fee_per_gas` is decoupled from the quote-side
		// `cost_per_gas`. Switching strategy moves the quote cost without
		// touching the submit max-fee.
		//
		// Use a hand-built (max_fee, priority, base_fee) triple where the
		// max_fee leaves headroom above the buffered formula — otherwise
		// `BufferedEffective125` clamps to max_fee and tied with
		// `MaxFee` (a real but uninteresting case for this assertion).
		let max_fee = 5_000_000_000u128;
		let priority = 2_000_000_000u128;
		let base_fee = 1_000_000_000u128;

		let buffered = FeeParams::eip1559_with_strategy(
			1,
			max_fee,
			priority,
			base_fee,
			FeeCostStrategy::BufferedEffective125,
		);
		let max = FeeParams::eip1559_with_strategy(
			1,
			max_fee,
			priority,
			base_fee,
			FeeCostStrategy::MaxFee,
		);
		assert_eq!(buffered.max_fee_per_gas, max.max_fee_per_gas);
		assert_ne!(buffered.cost_per_gas, max.cost_per_gas);
	}
}

#[cfg(test)]
mod proptests {
	use super::*;
	use proptest::prelude::*;

	proptest! {
		#[test]
		fn estimator_never_violates_fee_invariants(
			base_fee in 0u128..1_000_000_000_000u128,
			observed_priority in 0u128..100_000_000_000u128,
			floor in prop::option::of(0u128..100_000_000_000u128),
			cap_extra in prop::option::of(0u128..1_000_000_000_000u128),
		) {
			let fallback = 100_000_000u128;
			let cap_floor = floor.unwrap_or(fallback).max(observed_priority).max(fallback);
			let cap = cap_extra.map(|extra| cap_floor.saturating_add(extra));
			let policy = ChainFeePolicy {
				speed: FeeSpeed::Fast,
				min_priority_fee_per_gas: floor,
				priority_fee_fallback: fallback,
				quote_cost_strategy: FeeCostStrategy::BufferedEffective125,
				gas_price_cap: cap,
			};
			let estimator = SolverEip1559Estimator { policy: policy.clone() };
			let rewards = vec![vec![observed_priority]];

			let est = estimator.estimate(base_fee, &rewards);

			// Real invariants only — alloy itself is trusted to do the rest.
			prop_assert!(est.max_priority_fee_per_gas >= floor.unwrap_or(0));
			prop_assert!(est.max_priority_fee_per_gas >= fallback);
			prop_assert!(est.max_fee_per_gas >= est.max_priority_fee_per_gas);
			if let Some(cap) = cap {
				prop_assert!(est.max_fee_per_gas <= cap.max(est.max_priority_fee_per_gas));
			}
		}
	}
}
