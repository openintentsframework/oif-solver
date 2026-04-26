//! Exclusive-fill context helpers.
//!
//! Encodes the on-chain marker that `OutputSettlerSimple` reads from
//! `MandateOutput.context`: `0xe0 || bytes32(exclusiveFor) || uint32(startTime)`
//! (see `oif-contracts/src/output/simple/FulfilmentLib.sol`). Before
//! `startTime`, only `exclusiveFor` may fill; after, anyone may.

use solver_config::{ExclusivityConfig, ExclusivityMode};
use solver_types::{Address, QuoteError};

/// Wire prefix for the exclusive-limit-order context (FulfilmentLib.sol).
pub const EXCLUSIVE_CONTEXT_TAG: u8 = 0xe0;

/// Resolved per-request exclusivity decision.
#[derive(Debug, Clone, Copy)]
pub struct ExclusivityParams {
	/// Unix seconds at which the exclusive window ends.
	pub start_time: u32,
}

/// Decide whether to apply exclusivity for this request, given server config
/// and the per-request `intent.metadata` blob.
///
/// Returns `Ok(None)` when no exclusive context should be added, `Ok(Some(_))`
/// when one should, or `Err(_)` for invalid request input. Per-request
/// `durationSeconds` is rejected (not clamped) when out of range so callers
/// see a clear error rather than silently shortened exclusivity.
pub fn resolve_exclusivity(
	cfg: Option<&ExclusivityConfig>,
	metadata: Option<&serde_json::Value>,
	now_secs: u64,
) -> Result<Option<ExclusivityParams>, QuoteError> {
	let cfg = match cfg {
		Some(c) => c,
		None => return Ok(None),
	};
	if matches!(cfg.mode, ExclusivityMode::Disabled) {
		return Ok(None);
	}

	// Strict validation: if `metadata.exclusivity` is present, the caller
	// is opting in and the shape must be valid. Silent fallback masks bugs
	// in callers and contradicts the documented contract.
	let request_duration = parse_request_duration(metadata)?;

	let duration: u32 = match (cfg.mode, request_duration) {
		(ExclusivityMode::Disabled, _) => unreachable!("handled above"),
		(ExclusivityMode::Optional, None) => return Ok(None),
		(ExclusivityMode::Optional, Some(d)) | (ExclusivityMode::Required, Some(d)) => {
			if d == 0 {
				return Err(QuoteError::InvalidRequest(
					"exclusivity.durationSeconds must be > 0".to_string(),
				));
			}
			if d > cfg.max_seconds as u64 {
				return Err(QuoteError::InvalidRequest(format!(
					"exclusivity.durationSeconds {d} exceeds max_seconds {}",
					cfg.max_seconds
				)));
			}
			d as u32
		},
		(ExclusivityMode::Required, None) => cfg.default_seconds,
	};

	let start_time = now_secs.saturating_add(duration as u64);
	let start_time: u32 = u32::try_from(start_time).map_err(|_| {
		QuoteError::InvalidRequest("exclusivity start time overflows uint32".to_string())
	})?;
	Ok(Some(ExclusivityParams { start_time }))
}

/// Strictly parse `metadata.exclusivity.durationSeconds`. Returns:
/// - `Ok(None)` when `metadata` is absent or has no `exclusivity` key.
/// - `Ok(Some(n))` when shape is valid and `durationSeconds` is a non-negative integer.
/// - `Err(InvalidRequest)` when the `exclusivity` key is present but malformed.
fn parse_request_duration(metadata: Option<&serde_json::Value>) -> Result<Option<u64>, QuoteError> {
	let Some(meta) = metadata else {
		return Ok(None);
	};
	let Some(excl) = meta.get("exclusivity") else {
		return Ok(None);
	};
	let obj = excl.as_object().ok_or_else(|| {
		QuoteError::InvalidRequest("metadata.exclusivity must be an object".to_string())
	})?;
	let dur = obj.get("durationSeconds").ok_or_else(|| {
		QuoteError::InvalidRequest("metadata.exclusivity.durationSeconds is required".to_string())
	})?;
	match dur {
		serde_json::Value::Number(n) => n.as_u64().map(Some).ok_or_else(|| {
			QuoteError::InvalidRequest(
				"metadata.exclusivity.durationSeconds must be a non-negative integer".to_string(),
			)
		}),
		_ => Err(QuoteError::InvalidRequest(
			"metadata.exclusivity.durationSeconds must be a non-negative integer".to_string(),
		)),
	}
}

/// Encode the 37-byte exclusive context: `0xe0 || bytes32(addr) || uint32(start)`.
pub fn encode_exclusive_context(solver_address: &Address, start_time: u32) -> Vec<u8> {
	let mut out = Vec::with_capacity(1 + 32 + 4);
	out.push(EXCLUSIVE_CONTEXT_TAG);
	let mut bytes32 = [0u8; 32];
	let addr_bytes = &solver_address.0;
	debug_assert_eq!(addr_bytes.len(), 20, "solver address must be 20 bytes");
	bytes32[12..].copy_from_slice(addr_bytes);
	out.extend_from_slice(&bytes32);
	out.extend_from_slice(&start_time.to_be_bytes());
	out
}

#[cfg(test)]
mod tests {
	use super::*;
	use solver_config::{ExclusivityConfig, ExclusivityMode};
	use solver_types::Address;

	fn cfg(mode: ExclusivityMode) -> ExclusivityConfig {
		ExclusivityConfig {
			mode,
			default_seconds: 60,
			max_seconds: 300,
		}
	}

	#[test]
	fn disabled_returns_none_even_with_metadata() {
		let meta = serde_json::json!({ "exclusivity": { "durationSeconds": 30 } });
		let resolved = resolve_exclusivity(
			Some(&cfg(ExclusivityMode::Disabled)),
			Some(&meta),
			1_000_000,
		)
		.unwrap();
		assert!(resolved.is_none());
	}

	#[test]
	fn optional_no_metadata_returns_none() {
		let resolved =
			resolve_exclusivity(Some(&cfg(ExclusivityMode::Optional)), None, 1_000_000).unwrap();
		assert!(resolved.is_none());
	}

	#[test]
	fn optional_with_metadata_uses_metadata_duration() {
		let meta = serde_json::json!({ "exclusivity": { "durationSeconds": 30 } });
		let r = resolve_exclusivity(
			Some(&cfg(ExclusivityMode::Optional)),
			Some(&meta),
			1_000_000,
		)
		.unwrap()
		.unwrap();
		assert_eq!(r.start_time, 1_000_000 + 30);
	}

	#[test]
	fn required_no_metadata_uses_default() {
		let r = resolve_exclusivity(Some(&cfg(ExclusivityMode::Required)), None, 1_000_000)
			.unwrap()
			.unwrap();
		assert_eq!(r.start_time, 1_000_000 + 60);
	}

	#[test]
	fn required_rejects_duration_above_max() {
		let meta = serde_json::json!({ "exclusivity": { "durationSeconds": 1000 } });
		let err = resolve_exclusivity(
			Some(&cfg(ExclusivityMode::Required)),
			Some(&meta),
			1_000_000,
		)
		.unwrap_err();
		match err {
			QuoteError::InvalidRequest(msg) => assert!(msg.contains("max_seconds")),
			_ => panic!("expected InvalidRequest"),
		}
	}

	#[test]
	fn encode_context_layout() {
		let addr = Address(vec![0x42u8; 20]);
		let bytes = encode_exclusive_context(&addr, 0x11_22_33_44u32);
		assert_eq!(bytes.len(), 1 + 32 + 4);
		assert_eq!(bytes[0], 0xe0);
		assert_eq!(&bytes[1..13], &[0u8; 12]);
		assert_eq!(&bytes[13..33], &[0x42u8; 20]);
		assert_eq!(&bytes[33..37], &[0x11, 0x22, 0x33, 0x44]);
	}

	#[test]
	fn no_config_disables_exclusivity() {
		let meta = serde_json::json!({ "exclusivity": { "durationSeconds": 30 } });
		let resolved = resolve_exclusivity(None, Some(&meta), 1_000_000).unwrap();
		assert!(resolved.is_none());
	}

	#[test]
	fn duration_zero_is_rejected() {
		let meta = serde_json::json!({ "exclusivity": { "durationSeconds": 0 } });
		let err = resolve_exclusivity(
			Some(&cfg(ExclusivityMode::Optional)),
			Some(&meta),
			1_000_000,
		)
		.unwrap_err();
		match err {
			QuoteError::InvalidRequest(msg) => assert!(msg.contains("> 0")),
			_ => panic!("expected InvalidRequest"),
		}
	}

	fn assert_invalid_request(err: QuoteError, needle: &str) {
		match err {
			QuoteError::InvalidRequest(msg) => assert!(
				msg.contains(needle),
				"expected message containing {needle:?}, got: {msg}",
			),
			other => panic!("expected InvalidRequest, got {other:?}"),
		}
	}

	#[test]
	fn malformed_exclusivity_string_is_rejected() {
		let meta = serde_json::json!({ "exclusivity": "invalid" });
		let err = resolve_exclusivity(
			Some(&cfg(ExclusivityMode::Optional)),
			Some(&meta),
			1_000_000,
		)
		.unwrap_err();
		assert_invalid_request(err, "must be an object");
	}

	#[test]
	fn malformed_exclusivity_null_is_rejected() {
		let meta = serde_json::json!({ "exclusivity": null });
		let err = resolve_exclusivity(
			Some(&cfg(ExclusivityMode::Required)),
			Some(&meta),
			1_000_000,
		)
		.unwrap_err();
		assert_invalid_request(err, "must be an object");
	}

	#[test]
	fn missing_duration_seconds_is_rejected_when_exclusivity_key_present() {
		let meta = serde_json::json!({ "exclusivity": {} });
		let err = resolve_exclusivity(
			Some(&cfg(ExclusivityMode::Required)),
			Some(&meta),
			1_000_000,
		)
		.unwrap_err();
		assert_invalid_request(err, "durationSeconds is required");
	}

	#[test]
	fn duration_seconds_string_is_rejected() {
		let meta = serde_json::json!({ "exclusivity": { "durationSeconds": "60" } });
		let err = resolve_exclusivity(
			Some(&cfg(ExclusivityMode::Optional)),
			Some(&meta),
			1_000_000,
		)
		.unwrap_err();
		assert_invalid_request(err, "non-negative integer");
	}

	#[test]
	fn duration_seconds_float_is_rejected() {
		let meta = serde_json::json!({ "exclusivity": { "durationSeconds": 1.5 } });
		let err = resolve_exclusivity(
			Some(&cfg(ExclusivityMode::Optional)),
			Some(&meta),
			1_000_000,
		)
		.unwrap_err();
		assert_invalid_request(err, "non-negative integer");
	}

	#[test]
	fn duration_seconds_negative_is_rejected() {
		let meta = serde_json::json!({ "exclusivity": { "durationSeconds": -1 } });
		let err = resolve_exclusivity(
			Some(&cfg(ExclusivityMode::Required)),
			Some(&meta),
			1_000_000,
		)
		.unwrap_err();
		assert_invalid_request(err, "non-negative integer");
	}

	#[test]
	fn duration_seconds_null_is_rejected() {
		let meta = serde_json::json!({ "exclusivity": { "durationSeconds": null } });
		let err = resolve_exclusivity(
			Some(&cfg(ExclusivityMode::Optional)),
			Some(&meta),
			1_000_000,
		)
		.unwrap_err();
		assert_invalid_request(err, "non-negative integer");
	}

	#[test]
	fn disabled_mode_ignores_malformed_metadata() {
		// Disabled mode short-circuits before validation: sending malformed
		// metadata to a server that does not support exclusivity should not
		// fail the request — the field is irrelevant.
		let meta = serde_json::json!({ "exclusivity": "invalid" });
		let resolved = resolve_exclusivity(
			Some(&cfg(ExclusivityMode::Disabled)),
			Some(&meta),
			1_000_000,
		)
		.unwrap();
		assert!(resolved.is_none());
	}

	#[test]
	fn no_exclusivity_key_in_metadata_is_fine() {
		// Other metadata fields without `exclusivity` must not be rejected.
		let meta = serde_json::json!({ "other": "field" });
		let resolved = resolve_exclusivity(
			Some(&cfg(ExclusivityMode::Optional)),
			Some(&meta),
			1_000_000,
		)
		.unwrap();
		assert!(resolved.is_none());
	}
}
