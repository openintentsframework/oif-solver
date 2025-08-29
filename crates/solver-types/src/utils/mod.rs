//! Utility functions for common type conversions and transformations.
//!
//! This module provides helper functions for converting between different
//! data formats and string formatting commonly used throughout the solver system.

pub mod constants;
pub mod conversion;
pub mod eip712;
pub mod formatting;
pub mod helpers;

pub use constants::{
	DEFAULT_GAS_PRICE_WEI, MOCK_ETH_SOL_PRICE, MOCK_ETH_USD_PRICE, MOCK_SOL_USD_PRICE,
	ZERO_BYTES32,
};
pub use conversion::{
	bytes20_to_alloy_address, bytes32_to_address, normalize_bytes32_address, parse_address,
	wei_string_to_eth_string,
};
pub use eip712::{
	compute_domain_hash, compute_final_digest, Eip712AbiEncoder, DOMAIN_TYPE, MANDATE_OUTPUT_TYPE,
	NAME_PERMIT2, PERMIT2_WITNESS_TYPE, PERMIT_BATCH_WITNESS_TYPE, TOKEN_PERMISSIONS_TYPE,
};
pub use formatting::{format_token_amount, truncate_id, with_0x_prefix, without_0x_prefix};
pub use helpers::current_timestamp;
