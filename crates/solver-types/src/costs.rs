use alloy_primitives::U256;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::InteropAddress;

/// Cost context for quote generation with pre-calculated costs and swap amounts
#[derive(Debug, Clone)]
pub struct CostContext {
	pub total_gas_cost_usd: Decimal,
	pub solver_margin_bps: u32,
	pub execution_costs_by_chain: HashMap<u64, Decimal>,
	pub liquidity_cost_adjustment: Decimal,
	pub protocol_fees: HashMap<String, Decimal>,
	/// Pre-calculated token amounts for costs (token address -> amount in smallest unit)
	pub cost_amounts_in_tokens: HashMap<InteropAddress, U256>,
	/// Base swap amounts before cost adjustments (token address -> amount in smallest unit)
	/// For ExactInput: contains calculated output amounts
	/// For ExactOutput: contains calculated input amounts
	pub swap_amounts: HashMap<InteropAddress, U256>,
	/// Optional constraint violation message if swap amounts don't meet requirements
	pub constraint_violation: Option<String>,
}

impl CostContext {
	/// Calculate total solver fee in USD including all components
	pub fn total_solver_fee_usd(&self) -> Decimal {
		// Calculate margin as percentage of gas costs
		let margin =
			self.total_gas_cost_usd * Decimal::from(self.solver_margin_bps) / Decimal::from(10000);

		// Total = gas + margin + liquidity adjustment + protocol fees
		let protocol_fees_total: Decimal = self.protocol_fees.values().cloned().sum();
		self.total_gas_cost_usd + margin + self.liquidity_cost_adjustment + protocol_fees_total
	}
}

/// Named amount used for cost components.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostComponent {
	/// Human-readable component name (e.g., "base-price", "gas-fill", "gas-claim", "buffer-gas", "buffer-rates", "commission")
	pub name: String,
	/// Amount as a decimal string in the display currency (matches CostEstimate.currency)
	pub amount: String,
	/// Amount as a wei string for gas-related costs (optional)
	#[serde(rename = "amountWei", skip_serializing_if = "Option::is_none")]
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
