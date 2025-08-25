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
