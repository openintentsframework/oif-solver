//! Helper utilities for common operations.
//!
//! This module provides utility functions used throughout the solver system
//! for common operations like timestamp retrieval.

/// Helper function to get current timestamp, returns 0 if system time is before UNIX epoch.
///
/// This function safely retrieves the current UNIX timestamp in seconds,
/// returning 0 if the system time is somehow before the UNIX epoch.
pub fn current_timestamp() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

/// Convert an order id string into a 32-byte representation suitable for
/// filtering Ethereum logs by indexed `bytes32 orderId`.
///
/// - `"0x..."` hex strings: decode, right-align in 32 bytes (the on-chain
///   bytes32 convention for orderIds).
/// - ASCII strings (e.g., test placeholders like `"test_order_123"`): copy
///   raw bytes, right-align in 32 bytes.
/// - Invalid hex: returns `Err` (does not panic).
/// - Strings longer than 32 bytes: keep the first 32 bytes (right-aligned
///   into the full buffer).
pub fn order_id_to_bytes32(order_id: &str) -> Result<[u8; 32], String> {
	if let Some(hex_str) = order_id.strip_prefix("0x") {
		let mut bytes = [0u8; 32];
		let decoded =
			hex::decode(hex_str).map_err(|e| format!("invalid hex order id '{order_id}': {e}"))?;
		let len = decoded.len().min(32);
		bytes[32 - len..].copy_from_slice(&decoded[..len]);
		Ok(bytes)
	} else {
		let raw = order_id.as_bytes();
		let mut bytes = [0u8; 32];
		let len = raw.len().min(32);
		bytes[32 - len..].copy_from_slice(&raw[..len]);
		Ok(bytes)
	}
}

#[cfg(test)]
mod order_id_to_bytes32_tests {
	use super::*;

	#[test]
	fn hex_order_id_right_aligns() {
		let id = "0xdeadbeef";
		let out = order_id_to_bytes32(id).unwrap();
		assert_eq!(out[28..], [0xde, 0xad, 0xbe, 0xef]);
		assert_eq!(out[..28], [0u8; 28]);
	}

	#[test]
	fn ascii_placeholder_right_aligns() {
		let id = "test_order_123";
		let out = order_id_to_bytes32(id).unwrap();
		assert_eq!(&out[32 - id.len()..], id.as_bytes());
		assert_eq!(&out[..32 - id.len()], &[0u8; 32 - "test_order_123".len()]);
	}

	#[test]
	fn invalid_hex_returns_error() {
		let id = "0xnothex";
		let error = order_id_to_bytes32(id).unwrap_err();
		assert!(error.contains("invalid hex order id"));
	}

	#[test]
	fn long_ascii_string_keeps_first_32_bytes() {
		// The helper copies `raw[..32]` into `bytes[32-32..]` = `bytes[..]`,
		// so a long ASCII input is truncated to its FIRST 32 bytes.
		// Use a distinguishable suffix to prove the tail is dropped, not the head.
		let id = format!("{}{}", "a".repeat(32), "DROPPED_TAIL_XYZ");
		let out = order_id_to_bytes32(&id).unwrap();
		assert_eq!(out, [b'a'; 32]);
	}
}
