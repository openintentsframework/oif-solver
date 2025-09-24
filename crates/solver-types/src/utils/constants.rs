//! Common constants used across the solver system.
//!
//! This module contains commonly used constants that are not specific to any
//! particular protocol or standard, making them available for general use
//! throughout the codebase.

/// A zero bytes32 value as a hex string with 0x prefix.
///
/// This represents 32 bytes of zeros and is commonly used in Ethereum
/// contexts where a zero hash or zero address in bytes32 format is needed.
///
/// Example usage:
/// - Oracle fields in cross-chain outputs when no oracle is specified
/// - Placeholder values in structured data
/// - Default values for bytes32 fields
pub const ZERO_BYTES32: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

/// Default gas price in wei (1 gwei).
///
/// This is used as a fallback when gas price cannot be retrieved from the network
/// or as a default value for gas estimation calculations.
pub const DEFAULT_GAS_PRICE_WEI: u64 = 1_000_000_000;

// Mock pricing constants
/// Default ETH/USD price used in mock pricing implementation.
pub const MOCK_ETH_USD_PRICE: &str = "4615.16";

/// Default TOKA/USD price used in mock pricing implementation.
pub const MOCK_TOKA_USD_PRICE: &str = "1.0";

/// Default TOKB/USD price used in mock pricing implementation.
pub const MOCK_TOKB_USD_PRICE: &str = "1.0";

/// Default SOL/USD price used in mock pricing implementation.
pub const MOCK_SOL_USD_PRICE: &str = "240.50";

/// Default ETH/SOL price used in mock pricing implementation.
pub const MOCK_ETH_SOL_PRICE: &str = "19.20";
