//! Extension traits for enhanced functionality on primitive types
//!
//! This module provides extension traits that add useful methods to Address
//! and U256 types for common operations like formatting, parsing, and
//! conversions used throughout the solver demo application.

use alloy_primitives::{Address, U256};

/// Extension trait providing additional methods for Address types
///
/// Adds useful formatting and validation methods to the Address type
/// including checksum formatting, zero checking, and short display format.
pub trait AddressExt {
	/// Convert address to EIP-55 checksum format
	///
	/// # Returns
	/// String containing the checksummed address
	fn to_checksum(&self) -> String;

	/// Check if the address is the zero address
	///
	/// # Returns
	/// True if the address equals Address::ZERO
	fn is_zero(&self) -> bool;

	/// Format address as shortened display string
	///
	/// # Returns
	/// String in format "0x1234...5678" for readability
	fn to_short(&self) -> String;
}

impl AddressExt for Address {
	fn to_checksum(&self) -> String {
		// Use Alloy's built-in checksum with None for chain_id (mainnet)
		self.to_checksum(None)
	}

	fn is_zero(&self) -> bool {
		self == &Address::ZERO
	}

	fn to_short(&self) -> String {
		let full = format!("0x{}", hex::encode(self.as_slice()));
		if full.len() > 10 {
			format!("{}...{}", &full[..6], &full[full.len() - 4..])
		} else {
			full
		}
	}
}

/// Utility struct providing token-related conversion functions
///
/// Contains static methods for parsing token amounts with decimal handling.
pub struct TokenExtensions;

impl TokenExtensions {
	/// Parse a token amount string to wei using the specified decimals
	///
	/// # Arguments
	/// * `amount_str` - String representation of the amount (e.g., "1.5")
	/// * `decimals` - Number of decimal places for the token
	///
	/// # Returns
	/// U256 value representing the amount in smallest units
	///
	/// # Errors
	/// Returns Error::InvalidAmount if parsing fails
	pub fn to_wei_from_decimals(amount_str: &str, decimals: u8) -> crate::types::Result<U256> {
		U256::parse_with_decimals(amount_str, decimals)
	}
}

/// Extension trait providing decimal formatting and parsing for U256 amounts
///
/// Adds methods to U256 for handling token amounts with decimal places,
/// including conversion between human-readable strings and wei values.
pub trait AmountExt {
	/// Format U256 amount as decimal string with specified decimal places
	///
	/// # Arguments
	/// * `decimals` - Number of decimal places to use for formatting
	///
	/// # Returns
	/// String representation of the amount with decimal formatting
	fn format_with_decimals(&self, decimals: u8) -> String;

	/// Parse decimal string to U256 amount with specified decimal places
	///
	/// # Arguments
	/// * `s` - String representation of the amount (e.g., "1.5")
	/// * `decimals` - Number of decimal places for conversion
	///
	/// # Returns
	/// U256 value representing the amount in smallest units
	///
	/// # Errors
	/// Returns Error::InvalidAmount if parsing fails or has too many decimal places
	fn parse_with_decimals(s: &str, decimals: u8) -> crate::types::Result<U256>;
}

impl AmountExt for U256 {
	fn format_with_decimals(&self, decimals: u8) -> String {
		if decimals == 0 {
			return self.to_string();
		}

		let divisor = U256::from(10).pow(U256::from(decimals));
		let integer = self / divisor;
		let fraction = self % divisor;

		if fraction.is_zero() {
			integer.to_string()
		} else {
			let fraction_str = format!("{:0width$}", fraction, width = decimals as usize);
			let fraction_str = fraction_str.trim_end_matches('0');
			format!("{}.{}", integer, fraction_str)
		}
	}

	fn parse_with_decimals(s: &str, decimals: u8) -> crate::types::Result<U256> {
		let parts: Vec<&str> = s.split('.').collect();

		match parts.len() {
			1 => {
				// No decimal point
				let integer = U256::from_str_radix(parts[0], 10)
					.map_err(|e| crate::types::Error::InvalidAmount(e.to_string()))?;
				Ok(integer * U256::from(10).pow(U256::from(decimals)))
			},
			2 => {
				// Has decimal point
				let integer = if parts[0].is_empty() {
					U256::ZERO
				} else {
					U256::from_str_radix(parts[0], 10)
						.map_err(|e| crate::types::Error::InvalidAmount(e.to_string()))?
				};

				let fraction_str = parts[1];
				if fraction_str.len() > decimals as usize {
					return Err(crate::types::Error::InvalidAmount(format!(
						"Too many decimal places: {} > {}",
						fraction_str.len(),
						decimals
					)));
				}

				let fraction = if fraction_str.is_empty() {
					U256::ZERO
				} else {
					let padded = format!("{:0<width$}", fraction_str, width = decimals as usize);
					U256::from_str_radix(&padded, 10)
						.map_err(|e| crate::types::Error::InvalidAmount(e.to_string()))?
				};

				Ok(integer * U256::from(10).pow(U256::from(decimals)) + fraction)
			},
			_ => Err(crate::types::Error::InvalidAmount(
				"Multiple decimal points".to_string(),
			)),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_address_extensions() {
		let addr = Address::ZERO;
		assert!(addr.is_zero());
		assert_eq!(addr.to_short(), "0x0000...0000");
	}

	#[test]
	fn test_amount_formatting() {
		let amount = U256::from(1_500_000_000_000_000_000u64); // 1.5 ETH
		assert_eq!(amount.format_with_decimals(18), "1.5");

		let amount = U256::from(1_000_000_000_000_000_000u64); // 1 ETH
		assert_eq!(amount.format_with_decimals(18), "1");

		let amount = U256::from(1_234_567_890_123_456_789u64);
		assert_eq!(amount.format_with_decimals(18), "1.234567890123456789");
	}

	#[test]
	fn test_amount_parsing() {
		let amount = U256::parse_with_decimals("1.5", 18).unwrap();
		assert_eq!(amount, U256::from(1_500_000_000_000_000_000u64));

		let amount = U256::parse_with_decimals("1", 18).unwrap();
		assert_eq!(amount, U256::from(1_000_000_000_000_000_000u64));

		let amount = U256::parse_with_decimals("0.000000000000000001", 18).unwrap();
		assert_eq!(amount, U256::from(1u64));
	}
}
