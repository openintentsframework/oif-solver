use alloy_primitives::U256;
use anyhow::{anyhow, Result};

/// Parse amount string to U256 with 18 decimals (default for most tokens)
pub fn parse_amount(amount_str: &str) -> Result<U256> {
	parse_amount_with_decimals(amount_str, 18)
}

/// Parse amount string to U256 with specified decimals
pub fn parse_amount_with_decimals(amount_str: &str, decimals: u8) -> Result<U256> {
	// Handle special "max" case
	if amount_str.to_lowercase() == "max" {
		return Ok(U256::MAX);
	}

	let amount_f64: f64 = amount_str
		.parse()
		.map_err(|e| anyhow!("Invalid amount: {}", e))?;

	if amount_f64 < 0.0 {
		return Err(anyhow!("Amount must be positive"));
	}

	// Convert to smallest unit based on decimals
	let multiplier = 10_f64.powi(decimals as i32);
	let smallest_unit = amount_f64 * multiplier;

	// Check for overflow before converting
	if smallest_unit > u128::MAX as f64 {
		return Err(anyhow!("Amount too large"));
	}

	Ok(U256::from(smallest_unit as u128))
}

/// Format amount from wei to human-readable string
pub fn format_amount(amount: U256) -> String {
	format_amount_with_decimals(amount, 18)
}

/// Format amount with specified decimals to human-readable string
pub fn format_amount_with_decimals(amount: U256, decimals: u8) -> String {
	if amount.is_zero() {
		return "0.0".to_string();
	}

	let divisor = U256::from(10).pow(U256::from(decimals));
	let whole = amount / divisor;
	let fractional = amount % divisor;

	// Format fractional part with leading zeros
	let fractional_str = format!("{:0>width$}", fractional, width = decimals as usize);

	// Trim trailing zeros for cleaner display
	let trimmed = fractional_str.trim_end_matches('0');

	if trimmed.is_empty() {
		format!("{}.0", whole)
	} else {
		format!("{}.{}", whole, trimmed)
	}
}

/// Format balance (alias for format_amount for backwards compatibility)
pub fn format_balance(balance: U256) -> String {
	format_amount(balance)
}

/// Format balance with specified decimals (alias for format_amount_with_decimals)
pub fn format_balance_with_decimals(balance: U256, decimals: u8) -> String {
	format_amount_with_decimals(balance, decimals)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_parse_amount() {
		// Test basic parsing
		assert_eq!(
			parse_amount("1.0").unwrap(),
			U256::from(1_000_000_000_000_000_000u128)
		);
		assert_eq!(
			parse_amount("0.1").unwrap(),
			U256::from(100_000_000_000_000_000u128)
		);
		assert_eq!(
			parse_amount("100").unwrap(),
			U256::from(100_000_000_000_000_000_000u128)
		);

		// Test with different decimals
		assert_eq!(
			parse_amount_with_decimals("1.0", 6).unwrap(),
			U256::from(1_000_000u128)
		);
		assert_eq!(
			parse_amount_with_decimals("100", 6).unwrap(),
			U256::from(100_000_000u128)
		);

		// Test max value
		assert_eq!(parse_amount("max").unwrap(), U256::MAX);
		assert_eq!(parse_amount("MAX").unwrap(), U256::MAX);
	}

	#[test]
	fn test_format_amount() {
		// Test basic formatting
		assert_eq!(
			format_amount(U256::from(1_000_000_000_000_000_000u128)),
			"1.0"
		);
		assert_eq!(
			format_amount(U256::from(100_000_000_000_000_000u128)),
			"0.1"
		);
		assert_eq!(
			format_amount(U256::from(1_500_000_000_000_000_000u128)),
			"1.5"
		);
		assert_eq!(format_amount(U256::ZERO), "0.0");

		// Test with different decimals
		assert_eq!(
			format_amount_with_decimals(U256::from(1_000_000u128), 6),
			"1.0"
		);
		assert_eq!(
			format_amount_with_decimals(U256::from(1_500_000u128), 6),
			"1.5"
		);
	}

	#[test]
	fn test_error_cases() {
		// Test negative amounts
		assert!(parse_amount("-1.0").is_err());

		// Test invalid input
		assert!(parse_amount("abc").is_err());
	}
}
