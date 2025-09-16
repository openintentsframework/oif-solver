use crate::Address;
use crate::Order;
use alloy_primitives::U256;
use serde::{Deserialize, Serialize};

// Type aliases to reduce complexity
type AssetTuple = (Address, U256, u64);
type AssetResult = Result<Vec<AssetTuple>, Box<dyn std::error::Error>>;

/// Trait for types that can have their execution costs estimated
pub trait CostEstimatable {
	/// Get the origin chain ID(s) where assets will be sourced
	fn input_chain_ids(&self) -> Vec<u64>;

	/// Get the destination chain ID(s) where assets will be delivered
	fn output_chain_ids(&self) -> Vec<u64>;

	/// Get the lock type for gas configuration lookup
	/// Returns None if no specific lock type is defined
	fn lock_type(&self) -> Option<&str>;

	/// Convert to an Order for transaction generation
	/// This is needed for gas estimation via transaction simulation
	fn as_order_for_estimation(&self) -> Order;
}

/// Trait for types that can have their profitability calculated
///
/// This trait is designed to work with trait objects, allowing different
/// order standards to have their own profitability calculation logic.
pub trait ProfitabilityCalculatable: Send + Sync {
	/// Get input assets as tuples of (token_address, amount, chain_id)
	fn input_assets(&self) -> AssetResult;

	/// Get output assets as tuples of (token_address, amount, chain_id)
	fn output_assets(&self) -> AssetResult;
}

/// Named amount used for cost components.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostComponent {
	/// Human-readable component name (e.g., "base-price", "gas-fill", "gas-claim", "buffer-gas", "buffer-rates", "commission")
	pub name: String,
	/// Amount as a decimal string in the chosen currency units (e.g., USDC). String avoids precision loss across differing decimals.
	pub amount: String,
	/// Amount as a wei string. (if Apply)
	#[serde(rename = "amountWei")]
	pub amount_wei: Option<String>,
}

/// Unified cost estimate for any order type (standard-agnostic).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostEstimate {
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
