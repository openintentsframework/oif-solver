use solver_config::{source_finality_expected_delay_seconds, Config, QuoteConfig};
use solver_settlement::{estimate_required_expiry_window_for_route, RouteExpiryInputs};
use solver_types::Address;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QuoteTiming {
	pub validity_seconds: u64,
	pub fill_deadline_seconds: u64,
	pub expires_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QuoteTimestamps {
	pub fill_deadline: u64,
	pub expires: u64,
}

impl QuoteTiming {
	pub(crate) fn timestamps(&self, now: u64, min_valid_until: Option<u64>) -> QuoteTimestamps {
		let required_fill_deadline = now.saturating_add(self.fill_deadline_seconds);
		let fill_deadline = min_valid_until
			.map(|deadline| deadline.max(required_fill_deadline))
			.unwrap_or(required_fill_deadline);
		let expiry_after_fill = self
			.expires_seconds
			.saturating_sub(self.fill_deadline_seconds);
		let expires = fill_deadline.saturating_add(expiry_after_fill);

		QuoteTimestamps {
			fill_deadline,
			expires,
		}
	}
}

pub(crate) fn quote_timing_for_settlement(
	config: &Config,
	settlement_name: Option<&str>,
	input_oracle: &Address,
	origin_chain_id: u64,
	output_chain_ids: &[u64],
	include_source_finality_delay: bool,
) -> QuoteTiming {
	let quote_config = config.api.as_ref().and_then(|api| api.quote.as_ref());
	let defaults = QuoteConfig::default();
	let validity_seconds = quote_config
		.map(|quote| quote.validity_seconds)
		.unwrap_or(defaults.validity_seconds);
	let fill_deadline_seconds = quote_config
		.map(|quote| quote.fill_deadline_seconds)
		.unwrap_or(defaults.fill_deadline_seconds);
	let source_finality_delay = if include_source_finality_delay {
		source_finality_expected_delay_seconds(config, origin_chain_id)
			.unwrap_or(0)
			.saturating_add(config.source_finality.retry_grace_seconds)
			.saturating_add(validity_seconds)
	} else {
		0
	};
	let fill_deadline_seconds = fill_deadline_seconds.max(source_finality_delay);
	let configured_expires_seconds = quote_config
		.map(|quote| quote.expires_seconds)
		.unwrap_or(defaults.expires_seconds);
	let required_window = estimate_required_expiry_window_for_route(
		&RouteExpiryInputs {
			input_oracle: input_oracle.clone(),
			origin_chain_id,
			output_chain_ids: output_chain_ids.to_vec(),
		},
		&config.settlement.implementations,
		config.settlement.settlement_poll_interval_seconds,
		settlement_name,
	)
	.map(|(window, _breakdown)| window)
	.unwrap_or(0);
	let admission_safe_expires = required_window.saturating_add(fill_deadline_seconds);

	QuoteTiming {
		validity_seconds,
		fill_deadline_seconds,
		expires_seconds: configured_expires_seconds
			.max(fill_deadline_seconds)
			.max(admission_safe_expires),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use solver_config::{
		ApiConfig, ApiImplementations, Config, ConfigBuilder, QuoteConfig, SettlementConfig,
		SourceFinalityChainConfig, SourceFinalityConfig,
		DEFAULT_SOURCE_FINALITY_EXPECTED_DELAY_SECONDS,
	};
	use solver_types::utils::parse_address;
	use solver_types::SourceFinalityMode;
	use std::collections::HashMap;

	fn api_with_default_quote() -> ApiConfig {
		ApiConfig {
			enabled: true,
			host: "0.0.0.0".to_string(),
			port: 3000,
			timeout_seconds: 30,
			max_request_size: 1024 * 1024,
			implementations: ApiImplementations::default(),
			rate_limiting: None,
			cors: None,
			auth: None,
			quote: Some(QuoteConfig::default()),
		}
	}

	fn config_with_broadcaster(broadcaster: serde_json::Value) -> Config {
		ConfigBuilder::new()
			.api(Some(api_with_default_quote()))
			.settlement(SettlementConfig {
				implementations: HashMap::from([("broadcaster".to_string(), broadcaster)]),
				primary: "broadcaster".to_string(),
				settlement_poll_interval_seconds: 3,
			})
			.build()
	}

	fn input_oracle() -> solver_types::Address {
		parse_address("0x1111111111111111111111111111111111111111").unwrap()
	}

	fn broadcaster_with_explicit_min() -> serde_json::Value {
		serde_json::json!({
			"intent_min_expiry_seconds": 691_200,
			"oracles": {
				"input": { "1": ["0x1111111111111111111111111111111111111111"] },
				"output": { "42161": ["0x2222222222222222222222222222222222222222"] }
			},
			"routes": { "1": [42161] }
		})
	}

	fn broadcaster_with_additive_estimate() -> serde_json::Value {
		serde_json::json!({
			"proof_wait_time_seconds": 604_800,
			"storage_proof_timeout_seconds": 120,
			"default_finality_blocks": 20,
			"oracles": {
				"input": { "1": ["0x1111111111111111111111111111111111111111"] },
				"output": { "42161": ["0x2222222222222222222222222222222222222222"] }
			},
			"routes": { "1": [42161] }
		})
	}

	#[test]
	fn quote_timing_clamps_default_api_quote_to_broadcaster_minimum() {
		let config = config_with_broadcaster(broadcaster_with_explicit_min());
		let input_oracle = input_oracle();

		let timing = quote_timing_for_settlement(
			&config,
			Some("broadcaster"),
			&input_oracle,
			1,
			&[42161],
			true,
		);

		assert_eq!(
			timing.fill_deadline_seconds,
			DEFAULT_SOURCE_FINALITY_EXPECTED_DELAY_SECONDS
				+ QuoteConfig::default().validity_seconds
		);
		assert!(timing.expires_seconds >= 691_200 + DEFAULT_SOURCE_FINALITY_EXPECTED_DELAY_SECONDS);
	}

	#[test]
	fn quote_timestamps_with_min_valid_until_leave_full_window() {
		let now = 1_779_000_000;
		let min_valid_until = now + 600;
		let timing = QuoteTiming {
			validity_seconds: 60,
			fill_deadline_seconds: 300,
			expires_seconds: 691_200 + 300,
		};

		let timestamps = timing.timestamps(now, Some(min_valid_until));

		assert_eq!(timestamps.fill_deadline, min_valid_until);
		assert_eq!(timestamps.expires, min_valid_until + 691_200);
		assert!(timestamps.expires >= now + 691_200);
	}

	#[test]
	fn quote_timestamps_treat_min_valid_until_as_floor_not_override() {
		let now = 1_779_000_000;
		let timing = QuoteTiming {
			validity_seconds: 60,
			fill_deadline_seconds: 900,
			expires_seconds: 1_200,
		};

		let timestamps = timing.timestamps(now, Some(now + 300));

		assert_eq!(timestamps.fill_deadline, now + 900);
		assert_eq!(timestamps.expires, now + 1_200);
	}

	#[test]
	fn quote_timing_clamps_fill_deadline_to_source_finality_delay() {
		let mut config = config_with_broadcaster(broadcaster_with_additive_estimate());
		config.source_finality = SourceFinalityConfig {
			default_mode: SourceFinalityMode::Conservative,
			default_blocks: 20,
			default_block_time_seconds: 12,
			default_expected_delay_seconds: None,
			retry_grace_seconds: 10,
			chains: HashMap::from([(
				1,
				SourceFinalityChainConfig {
					mode: Some(SourceFinalityMode::Finalized),
					blocks: Some(20),
					block_time_seconds: None,
					expected_delay_seconds: Some(1_200),
				},
			)]),
		};
		let input_oracle = input_oracle();

		let timing = quote_timing_for_settlement(
			&config,
			Some("broadcaster"),
			&input_oracle,
			1,
			&[42161],
			true,
		);

		assert_eq!(timing.fill_deadline_seconds, 1_270);
		assert!(timing.expires_seconds >= timing.fill_deadline_seconds + 604_800);
	}

	#[test]
	fn quote_timing_does_not_apply_source_finality_delay_when_not_required() {
		let mut config = config_with_broadcaster(broadcaster_with_additive_estimate());
		config.source_finality = SourceFinalityConfig {
			default_mode: SourceFinalityMode::Conservative,
			default_blocks: 20,
			default_block_time_seconds: 12,
			default_expected_delay_seconds: Some(1_200),
			retry_grace_seconds: 10,
			chains: HashMap::new(),
		};
		let input_oracle = input_oracle();

		let timing = quote_timing_for_settlement(
			&config,
			Some("broadcaster"),
			&input_oracle,
			1,
			&[42161],
			false,
		);

		assert_eq!(
			timing.fill_deadline_seconds,
			QuoteConfig::default().fill_deadline_seconds
		);
		assert!(timing.expires_seconds >= timing.fill_deadline_seconds + 604_800);
	}

	#[test]
	fn quote_timing_clamps_to_broadcaster_additive_estimate_without_explicit_key() {
		let config = config_with_broadcaster(broadcaster_with_additive_estimate());
		let input_oracle = input_oracle();

		let timing = quote_timing_for_settlement(
			&config,
			Some("broadcaster"),
			&input_oracle,
			1,
			&[42161],
			true,
		);

		assert_eq!(
			timing.fill_deadline_seconds,
			DEFAULT_SOURCE_FINALITY_EXPECTED_DELAY_SECONDS
				+ QuoteConfig::default().validity_seconds
		);
		assert!(timing.expires_seconds >= 604_800 + DEFAULT_SOURCE_FINALITY_EXPECTED_DELAY_SECONDS);
	}
}
