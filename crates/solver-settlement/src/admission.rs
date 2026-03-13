//! Helpers for settlement-aware order admission decisions.

use crate::utils::parse_oracle_config;
use solver_types::{utils::parse_address, Address, Eip7683OrderData};
use std::collections::HashMap;

const DEFAULT_BROADCASTER_PROOF_WAIT_SECONDS: u64 = 30;
const DEFAULT_BROADCASTER_PROOF_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_BROADCASTER_FINALITY_BLOCKS: u64 = 20;
const DEFAULT_SETTLEMENT_SAFETY_BUFFER_SECONDS: u64 = 90;
const DEFAULT_BLOCK_TIME_SECONDS: u64 = 12;

fn parse_optional_u64(value: Option<&serde_json::Value>, default_value: u64) -> u64 {
	value
		.and_then(serde_json::Value::as_u64)
		.unwrap_or(default_value)
}

fn parse_chain_u64_table(value: Option<&serde_json::Value>) -> HashMap<u64, u64> {
	let mut parsed = HashMap::new();
	let Some(table) = value.and_then(serde_json::Value::as_object) else {
		return parsed;
	};

	for (chain_id, raw_value) in table {
		if let (Ok(chain_id), Some(raw_value)) = (chain_id.parse::<u64>(), raw_value.as_u64()) {
			parsed.insert(chain_id, raw_value);
		}
	}

	parsed
}

fn implementation_supports_order(
	implementation_cfg: &serde_json::Value,
	order_data: &Eip7683OrderData,
	input_oracle: &Address,
) -> bool {
	let origin_chain = order_data.origin_chain_id.to::<u64>();
	let cross_chain_outputs: Vec<u64> = order_data
		.outputs
		.iter()
		.map(|output| output.chain_id.to::<u64>())
		.filter(|destination| *destination != origin_chain)
		.collect();

	if cross_chain_outputs.is_empty() {
		return false;
	}

	let Ok(oracle_config) = parse_oracle_config(implementation_cfg) else {
		return false;
	};

	let Some(source_input_oracles) = oracle_config.input_oracles.get(&origin_chain) else {
		return false;
	};
	if !source_input_oracles.contains(input_oracle) {
		return false;
	}

	let Some(route_destinations) = oracle_config.routes.get(&origin_chain) else {
		return false;
	};
	for destination in cross_chain_outputs {
		if !route_destinations.contains(&destination) {
			return false;
		}
		if oracle_config
			.output_oracles
			.get(&destination)
			.is_none_or(|oracles| oracles.is_empty())
		{
			return false;
		}
	}

	true
}

fn estimated_block_time_seconds(chain_id: u64, chain_block_times: &HashMap<u64, u64>) -> u64 {
	if let Some(custom) = chain_block_times.get(&chain_id) {
		return (*custom).max(1);
	}

	match chain_id {
		10 | 11155420 | 8453 | 84532 | 7777777 => 2,
		42161 | 421614 => 2,
		_ => DEFAULT_BLOCK_TIME_SECONDS,
	}
}

fn estimate_broadcaster_expiry_buffer_seconds(
	order_data: &Eip7683OrderData,
	implementation_cfg: &serde_json::Value,
	poll_interval_seconds: u64,
) -> Option<(u64, String)> {
	let cfg_table = implementation_cfg.as_object()?;
	let proof_wait = parse_optional_u64(
		cfg_table.get("proof_wait_time_seconds"),
		DEFAULT_BROADCASTER_PROOF_WAIT_SECONDS,
	);
	let proof_timeout = parse_optional_u64(
		cfg_table.get("storage_proof_timeout_seconds"),
		DEFAULT_BROADCASTER_PROOF_TIMEOUT_SECONDS,
	);
	let default_finality_blocks = parse_optional_u64(
		cfg_table.get("default_finality_blocks"),
		DEFAULT_BROADCASTER_FINALITY_BLOCKS,
	);
	let finality_blocks = parse_chain_u64_table(cfg_table.get("finality_blocks"));
	let chain_block_times = parse_chain_u64_table(cfg_table.get("chain_block_time_seconds"));
	let safety_buffer = parse_optional_u64(
		cfg_table.get("intent_safety_buffer_seconds"),
		DEFAULT_SETTLEMENT_SAFETY_BUFFER_SECONDS,
	);

	let origin_chain = order_data.origin_chain_id.to::<u64>();
	let mut max_finality_seconds = 0u64;
	let mut has_cross_chain_output = false;
	for output in &order_data.outputs {
		let destination_chain = output.chain_id.to::<u64>();
		if destination_chain == origin_chain {
			continue;
		}
		has_cross_chain_output = true;
		let blocks = finality_blocks
			.get(&destination_chain)
			.copied()
			.unwrap_or(default_finality_blocks);
		let chain_finality_seconds = blocks.saturating_mul(estimated_block_time_seconds(
			destination_chain,
			&chain_block_times,
		));
		max_finality_seconds = max_finality_seconds.max(chain_finality_seconds);
	}

	if !has_cross_chain_output {
		return None;
	}

	let poll_window = poll_interval_seconds.saturating_mul(2);
	let required_window = proof_wait
		.saturating_add(max_finality_seconds)
		.saturating_add(proof_timeout)
		.saturating_add(poll_window)
		.saturating_add(safety_buffer);

	Some((
		required_window,
		format!(
			"proof_wait={proof_wait}s + finality={max_finality_seconds}s + proof_timeout={proof_timeout}s + poll_window={poll_window}s + safety={safety_buffer}s"
		),
	))
}

pub fn estimate_required_expiry_window_seconds(
	order_data: &Eip7683OrderData,
	settlement_implementations: &HashMap<String, serde_json::Value>,
	settlement_poll_interval_seconds: u64,
	pinned_settlement_name: Option<&str>,
) -> Option<(u64, String)> {
	let input_oracle = parse_address(&order_data.input_oracle).ok()?;
	let mut matches: Vec<(u64, String)> = Vec::new();

	for (implementation_name, implementation_cfg) in settlement_implementations {
		if let Some(pinned) = pinned_settlement_name {
			if implementation_name != pinned {
				continue;
			}
		}

		if !implementation_supports_order(implementation_cfg, order_data, &input_oracle) {
			continue;
		}

		if let Some(explicit_min_expiry_seconds) = implementation_cfg
			.get("intent_min_expiry_seconds")
			.and_then(serde_json::Value::as_u64)
		{
			matches.push((
				explicit_min_expiry_seconds,
				format!(
					"{implementation_name}: explicit intent_min_expiry_seconds={explicit_min_expiry_seconds}s"
				),
			));
			continue;
		}

		if implementation_name == "broadcaster" {
			if let Some((required_window, breakdown)) = estimate_broadcaster_expiry_buffer_seconds(
				order_data,
				implementation_cfg,
				settlement_poll_interval_seconds,
			) {
				matches.push((
					required_window,
					format!("{implementation_name}: {breakdown}"),
				));
			}
		}
	}

	matches
		.into_iter()
		.max_by_key(|(required_window, _)| *required_window)
}

#[cfg(test)]
mod tests {
	use super::*;
	use solver_types::utils::tests::builders::Eip7683OrderDataBuilder;

	fn broadcaster_config() -> serde_json::Value {
		serde_json::json!({
			"oracles": {
				"input": {
					"1": ["0x0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A"]
				},
				"output": {
					"137": ["0x1111111111111111111111111111111111111111"]
				}
			},
			"routes": {
				"1": [137]
			},
			"proof_wait_time_seconds": 30,
			"storage_proof_timeout_seconds": 30,
			"default_finality_blocks": 20
		})
	}

	fn hyperlane_config(min_window_seconds: u64) -> serde_json::Value {
		serde_json::json!({
			"oracles": {
				"input": {
					"1": ["0x0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A"]
				},
				"output": {
					"137": ["0x1111111111111111111111111111111111111111"]
				}
			},
			"routes": {
				"1": [137]
			},
			"intent_min_expiry_seconds": min_window_seconds
		})
	}

	#[test]
	fn test_estimate_required_expiry_window_respects_pinned_settlement() {
		let implementations = HashMap::from([
			("broadcaster".to_string(), broadcaster_config()),
			("hyperlane".to_string(), hyperlane_config(500)),
		]);
		let order_data = Eip7683OrderDataBuilder::new().build();

		let pinned_broadcaster = estimate_required_expiry_window_seconds(
			&order_data,
			&implementations,
			3,
			Some("broadcaster"),
		)
		.expect("expected broadcaster estimate");
		let unpinned =
			estimate_required_expiry_window_seconds(&order_data, &implementations, 3, None)
				.expect("expected unpinned estimate");

		assert!(pinned_broadcaster.1.contains("broadcaster"));
		assert!(!pinned_broadcaster.1.contains("hyperlane"));
		assert!(unpinned.0 >= 500);
		assert!(pinned_broadcaster.0 < unpinned.0);
	}
}
