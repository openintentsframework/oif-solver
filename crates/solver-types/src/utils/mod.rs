//! Utility functions for common type conversions and transformations.
//!
//! This module provides helper functions for converting between different
//! data formats and string formatting commonly used throughout the solver system.

pub mod constants;
pub mod conversion;
pub mod eip712;
pub mod formatting;
pub mod helpers;

pub use constants::ZERO_BYTES32;
pub use conversion::{bytes20_to_alloy_address, bytes32_to_address, parse_address};
pub use eip712::{
	compute_domain_hash, compute_final_digest, Eip712AbiEncoder, DOMAIN_TYPE, MANDATE_OUTPUT_TYPE,
	NAME_PERMIT2, PERMIT2_WITNESS_TYPE, PERMIT_BATCH_WITNESS_TYPE, TOKEN_PERMISSIONS_TYPE,
};
pub use formatting::{format_token_amount, truncate_id, with_0x_prefix, without_0x_prefix};
pub use helpers::current_timestamp;

/// Normalize a bytes32 that is expected to embed an `address` into
/// a canonical left-padded form: 12 zero bytes followed by 20 address bytes.
///
/// If the input looks right-padded (address in the first 20 bytes and 12 zero
/// bytes at the end), it will be converted to left-padded. Otherwise it is
/// returned unchanged.
pub fn normalize_bytes32_address(bytes32_value: [u8; 32]) -> [u8; 32] {
	// Detect right-padded shape: [address(20)][zeros(12)]
	let is_trailing_zeros = bytes32_value[20..32].iter().all(|&b| b == 0);
	let has_nonzero_prefix = bytes32_value[0..20].iter().any(|&b| b != 0);
	if is_trailing_zeros && has_nonzero_prefix {
		let mut normalized = [0u8; 32];
		normalized[12..32].copy_from_slice(&bytes32_value[0..20]);
		normalized
	} else {
		bytes32_value
	}
}
