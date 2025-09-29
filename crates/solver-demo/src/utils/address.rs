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

/// Format an address for display (shortened form)
pub fn format_address_short(address: Address) -> String {
    let full = format!("{:#x}", address);
    if full.len() > 10 {
        format!("{}...{}", &full[0..6], &full[full.len()-4..])
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
        assert!(is_valid_address("0x0000000000000000000000000000000000000001"));
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
}