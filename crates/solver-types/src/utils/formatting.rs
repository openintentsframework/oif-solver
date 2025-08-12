//! String formatting utilities.
//!
//! Provides functions for formatting strings for display, including
//! hex string prefix management, token amount formatting, and truncation for readability.

/// Utility function to truncate a hex string for display purposes.
///
/// Shows only the first 8 characters followed by ".." for longer strings.
pub fn truncate_id(id: &str) -> String {
	if id.len() <= 8 {
		id.to_string()
	} else {
		format!("{}..", &id[..8])
	}
}

/// Adds "0x" prefix to a hex string if it doesn't already have one.
///
/// This function ensures that a hex string has the standard "0x" prefix,
/// adding it if missing and leaving it unchanged if already present.
///
/// # Arguments
///
/// * `hex_str` - A hex string that may or may not have "0x" prefix
///
/// # Returns
///
/// A hex string with "0x" prefix.
pub fn with_0x_prefix(hex_str: &str) -> String {
	if hex_str.to_lowercase().starts_with("0x") {
		hex_str.to_string()
	} else {
		format!("0x{}", hex_str)
	}
}

/// Removes "0x" prefix from a hex string if present.
///
/// This function removes the "0x" or "0X" prefix from a hex string if present,
/// returning the hex string without prefix.
///
/// # Arguments
///
/// * `hex_str` - A hex string that may or may not have "0x" prefix
///
/// # Returns
///
/// A hex string without "0x" prefix.
pub fn without_0x_prefix(hex_str: &str) -> &str {
	hex_str
		.strip_prefix("0x")
		.or_else(|| hex_str.strip_prefix("0X"))
		.unwrap_or(hex_str)
}

/// Formats a token amount with decimal places for display.
///
/// Converts a raw token amount (as stored on-chain) to a human-readable
/// format with proper decimal placement.
///
/// # Arguments
///
/// * `amount` - The raw token amount as a string
/// * `decimals` - The number of decimal places for the token
///
/// # Returns
///
/// A formatted string like "1.5" or "1000.0"
pub fn format_token_amount(amount: &str, decimals: u8) -> String {
	if decimals == 0 {
		return amount.to_string();
	}

	let decimal_places = decimals as usize;

	// Handle amounts smaller than 1 token
	let (integer_part, decimal_part) = if amount.len() <= decimal_places {
		// Pad with leading zeros
		let decimal_str = format!("{:0>width$}", amount, width = decimal_places);
		("0".to_string(), decimal_str)
	} else {
		// Split at the decimal point
		let split_pos = amount.len() - decimal_places;
		(
			amount[..split_pos].to_string(),
			amount[split_pos..].to_string(),
		)
	};

	// Remove trailing zeros from decimal part for cleaner display
	let decimal_trimmed = decimal_part.trim_end_matches('0');

	if decimal_trimmed.is_empty() {
		integer_part
	} else {
		format!("{}.{}", integer_part, decimal_trimmed)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_truncate_id() {
		assert_eq!(truncate_id("12345678"), "12345678");
		assert_eq!(truncate_id("123456789"), "12345678..");
		assert_eq!(truncate_id("0x1234567890abcdef"), "0x123456..");
	}

	#[test]
	fn test_with_0x_prefix() {
		// Test adding prefix when missing
		assert_eq!(
			with_0x_prefix("5fbdb2315678afecb367f032d93f642f64180aa3"),
			"0x5fbdb2315678afecb367f032d93f642f64180aa3"
		);

		// Test preserving existing prefix
		assert_eq!(
			with_0x_prefix("0x5fbdb2315678afecb367f032d93f642f64180aa3"),
			"0x5fbdb2315678afecb367f032d93f642f64180aa3"
		);

		// Test with uppercase prefix
		assert_eq!(
			with_0x_prefix("0X5fbdb2315678afecb367f032d93f642f64180aa3"),
			"0X5fbdb2315678afecb367f032d93f642f64180aa3"
		);
	}

	#[test]
	fn test_without_0x_prefix() {
		// Test removing prefix when present
		assert_eq!(
			without_0x_prefix("0x5fbdb2315678afecb367f032d93f642f64180aa3"),
			"5fbdb2315678afecb367f032d93f642f64180aa3"
		);

		// Test when no prefix
		assert_eq!(
			without_0x_prefix("5fbdb2315678afecb367f032d93f642f64180aa3"),
			"5fbdb2315678afecb367f032d93f642f64180aa3"
		);

		// Test with uppercase prefix
		assert_eq!(
			without_0x_prefix("0X5fbdb2315678afecb367f032d93f642f64180aa3"),
			"5fbdb2315678afecb367f032d93f642f64180aa3"
		);
	}

	#[test]
	fn test_format_token_amount() {
		// Test 18 decimals (ETH)
		assert_eq!(format_token_amount("1000000000000000000", 18), "1");
		assert_eq!(format_token_amount("1500000000000000000", 18), "1.5");
		assert_eq!(format_token_amount("100000000000000000", 18), "0.1");

		// Test 6 decimals (USDC)
		assert_eq!(format_token_amount("1000000", 6), "1");
		assert_eq!(format_token_amount("1500000", 6), "1.5");
		assert_eq!(format_token_amount("100000", 6), "0.1");

		// Test 0 decimals
		assert_eq!(format_token_amount("1000", 0), "1000");

		// Test large amounts
		assert_eq!(format_token_amount("102000000000000000000", 18), "102");
		assert_eq!(format_token_amount("98000000000000000000", 18), "98");
	}
}
