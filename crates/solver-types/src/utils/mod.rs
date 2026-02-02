//! Utility functions for common type conversions and transformations.
//!
//! This module provides helper functions for converting between different
//! data formats and string formatting commonly used throughout the solver system.

pub mod constants;
pub mod conversion;
pub mod eip712;
pub mod formatting;
pub mod helpers;
pub mod tests;

pub use constants::{
	DEFAULT_GAS_PRICE_WEI, MOCK_ETH_SOL_PRICE, MOCK_ETH_USD_PRICE, MOCK_SOL_USD_PRICE,
	MOCK_TOKA_USD_PRICE, MOCK_TOKB_USD_PRICE, ZERO_BYTES32,
};
pub use conversion::{
	address_to_bytes32, address_to_bytes32_hex, addresses_equal, bytes20_to_alloy_address,
	bytes32_to_address, hex_to_alloy_address, normalize_bytes32_address, parse_address,
	parse_bytes32_from_hex, solver_address_to_bytes32, wei_string_to_eth_string,
};
pub use eip712::{
	admin_eip712_types, compute_domain_hash, compute_final_digest, reconstruct_compact_digest,
	reconstruct_eip3009_digest, reconstruct_permit2_digest, Eip712AbiEncoder, DOMAIN_TYPE,
	MANDATE_OUTPUT_TYPE, NAME_PERMIT2, PERMIT2_WITNESS_TYPE, PERMIT_BATCH_WITNESS_TYPE,
	TOKEN_PERMISSIONS_TYPE,
};
pub use formatting::{format_token_amount, truncate_id, with_0x_prefix, without_0x_prefix};
pub use helpers::current_timestamp;
