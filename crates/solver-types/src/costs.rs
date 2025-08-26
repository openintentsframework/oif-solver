use serde::{Deserialize, Serialize};

/// Named amount used for cost components.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostComponent {
	/// Human-readable component name (e.g., "base-price", "gas-fill", "gas-claim", "buffer-gas", "buffer-rates", "commission")
	pub name: String,
	/// Amount as a decimal string in the chosen currency units (e.g., USDC). String avoids precision loss across differing decimals.
	pub amount: String,
}

/// Cost breakdown attached to a quote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteCost {
	/// Display currency for cost components (e.g., "USDC", "USD").
	pub currency: String,
	/// Individual components that sum to the subtotal.
	pub components: Vec<CostComponent>,
	/// Commission fee in basis points applied over subtotal.
	#[serde(rename = "commissionBps")]
	pub commission_bps: u32,
	/// Commission amount as a decimal string in the same currency.
	#[serde(rename = "commissionAmount")]
	pub commission_amount: String,
	/// Subtotal before commission, as a decimal string.
	pub subtotal: String,
	/// Total price including commission, as a decimal string.
	pub total: String,
}
