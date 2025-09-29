use std::fmt::Display;

/// Format a chain ID for display
pub fn format_chain_id(chain_id: u64) -> String {
    format!("Chain {}", chain_id)
}

/// Format a token and chain combination
pub fn format_token_on_chain(token: &str, chain_id: u64) -> String {
    format!("{} on chain {}", token, chain_id)
}

/// Format a token amount with symbol
pub fn format_token_amount(amount: &str, symbol: &str) -> String {
    format!("{} {}", amount, symbol)
}

/// Format a token amount with symbol and chain
pub fn format_token_amount_on_chain(amount: &str, symbol: &str, chain_id: u64) -> String {
    format!("{} {} on chain {}", amount, symbol, chain_id)
}

/// Format an address for display (with 0x prefix check)
pub fn format_address_display<T: Display>(address: T) -> String {
    let addr_str = address.to_string();
    if !addr_str.starts_with("0x") {
        format!("0x{}", addr_str)
    } else {
        addr_str
    }
}

/// Format order status with emoji
pub fn format_order_status(status: &str) -> String {
    match status.to_lowercase().as_str() {
        "pending" => format!("🟡 {}", status),
        "filled" | "completed" | "success" => format!("✅ {}", status),
        "expired" | "failed" | "error" => format!("❌ {}", status),
        "cancelled" => format!("🚫 {}", status),
        _ => status.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_chain() {
        assert_eq!(format_chain_id(1), "Chain 1");
        assert_eq!(format_chain_id(42161), "Chain 42161");
    }

    #[test]
    fn test_format_token_on_chain() {
        assert_eq!(format_token_on_chain("USDC", 1), "USDC on chain 1");
    }

    #[test]
    fn test_format_order_status() {
        assert_eq!(format_order_status("pending"), "🟡 pending");
        assert_eq!(format_order_status("COMPLETED"), "✅ COMPLETED");
        assert_eq!(format_order_status("unknown"), "unknown");
    }
}