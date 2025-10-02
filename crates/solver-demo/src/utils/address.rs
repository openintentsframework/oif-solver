use alloy_primitives::Address;
use anyhow::{anyhow, Result};
use std::sync::Arc;

use crate::core::SessionManager;

/// Parse an address string that can be either a special identifier or hex address
///
/// Special identifiers:
/// - "user" - returns the user account address
/// - "solver" - returns the solver account address  
/// - "recipient" - returns the recipient account address
/// - Otherwise, parses as hex address
pub async fn parse_address_or_identifier(
	address_str: &str,
	session_manager: &Arc<SessionManager>,
) -> Result<Address> {
	match address_str.to_lowercase().as_str() {
		"user" => Ok(session_manager.get_user_account().await.address),
		"solver" => Ok(session_manager.get_solver_account().await.address),
		"recipient" => Ok(session_manager.get_recipient_account().await.address),
		_ => address_str
			.parse::<Address>()
			.map_err(|e| anyhow!("Invalid address '{}': {}", address_str, e)),
	}
}

/// Parse a hex address string
pub fn parse_address(address_str: &str) -> Result<Address> {
	address_str
		.parse::<Address>()
		.map_err(|e| anyhow!("Invalid address '{}': {}", address_str, e))
}

/// Validate if a string is a valid Ethereum address
pub fn is_valid_address(address_str: &str) -> bool {
	address_str.parse::<Address>().is_ok()
}

/// Converts an address to EIP-55 checksummed format.
///
/// This function takes an alloy Address and returns its EIP-55 checksummed
/// string representation, which is required for compatibility with the
/// old demo format and proper Ethereum address standards.
pub fn to_checksum_address(address: &Address, chain_id: Option<u64>) -> String {
	address.to_checksum(chain_id)
}

/// Converts address bytes to EIP-55 checksummed format.
///
/// This function takes raw address bytes and returns the EIP-55 checksummed
/// string representation. Useful when working with address bytes from
/// solver types or network configurations.
pub fn bytes_to_checksum_address(address_bytes: &[u8], chain_id: Option<u64>) -> String {
	let address = Address::from_slice(address_bytes);
	address.to_checksum(chain_id)
}

/// Format an address for display (shortened form)
pub fn format_address_short(address: Address) -> String {
	let full = to_checksum_address(&address, None);
	if full.len() > 10 {
		format!("{}...{}", &full[0..6], &full[full.len() - 4..])
	} else {
		full
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_parse_address() {
		// Valid address
		let addr = "0x0000000000000000000000000000000000000001";
		assert!(parse_address(addr).is_ok());

		// Invalid address
		assert!(parse_address("0xinvalid").is_err());
		assert!(parse_address("not_an_address").is_err());
	}

	#[test]
	fn test_is_valid_address() {
		assert!(is_valid_address(
			"0x0000000000000000000000000000000000000001"
		));
		assert!(!is_valid_address("0xinvalid"));
		assert!(!is_valid_address(""));
	}

	#[test]
	fn test_format_address_short() {
		let addr = "0x1234567890123456789012345678901234567890"
			.parse::<Address>()
			.unwrap();
		let formatted = format_address_short(addr);
		assert!(formatted.starts_with("0x1234"));
		assert!(formatted.ends_with("7890"));
		assert!(formatted.contains("..."));
	}

	#[test]
	fn test_checksum_formatting() {
		// Test with a known address that should be checksummed
		let addr_str = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";
		let address: Address = addr_str.parse().unwrap();

		let checksummed = to_checksum_address(&address, None);

		// Should have mixed case for this specific address
		assert!(checksummed.contains("C")); // Should have uppercase letters
		assert!(checksummed.starts_with("0x"));
		assert_eq!(checksummed.len(), 42); // 0x + 40 hex chars
	}

	#[test]
	fn test_bytes_to_checksum() {
		let addr_str = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";
		let address: Address = addr_str.parse().unwrap();
		let bytes = address.as_slice();

		let checksummed = bytes_to_checksum_address(bytes, None);
		let direct_checksum = to_checksum_address(&address, None);

		assert_eq!(checksummed, direct_checksum);
	}
}
