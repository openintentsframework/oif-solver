use alloy_primitives::U256;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::InteropAddress;

/// Detailed breakdown of costs for order processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostBreakdown {
	// Gas components
	#[serde(with = "rust_decimal::serde::str")]
	pub gas_open: Decimal,
	#[serde(with = "rust_decimal::serde::str")]
	pub gas_fill: Decimal,
	#[serde(with = "rust_decimal::serde::str")]
	pub gas_claim: Decimal,
	#[serde(with = "rust_decimal::serde::str")]
	pub gas_buffer: Decimal,

	// Market components
	#[serde(with = "rust_decimal::serde::str")]
	pub rate_buffer: Decimal,
	#[serde(with = "rust_decimal::serde::str")]
	pub base_price: Decimal, // Covers negative spreads

	// Profit components
	#[serde(with = "rust_decimal::serde::str")]
	pub min_profit: Decimal, // Based on transaction value, not gas!

	// Totals
	#[serde(with = "rust_decimal::serde::str")]
	pub operational_cost: Decimal, // gas + buffers
	#[serde(with = "rust_decimal::serde::str")]
	pub subtotal: Decimal, // operational + base_price
	#[serde(with = "rust_decimal::serde::str")]
	pub total: Decimal,

	// Market values (for logging/analysis)
	#[serde(with = "rust_decimal::serde::str")]
	pub market_input_value: Decimal,
	#[serde(with = "rust_decimal::serde::str")]
	pub market_output_value: Decimal,

	// Metadata
	pub currency: String,
}

/// Cost context for quote generation with pre-calculated costs and swap amounts
#[derive(Debug, Clone)]
pub struct CostContext {
	pub cost_breakdown: CostBreakdown,
	pub execution_costs_by_chain: HashMap<u64, Decimal>,
	pub liquidity_cost_adjustment: Decimal,
	pub protocol_fees: HashMap<String, Decimal>,
	/// Pre-calculated token amounts for costs (token address -> amount in smallest unit)
	pub cost_amounts_in_tokens: HashMap<InteropAddress, U256>,
	/// Base swap amounts before cost adjustments (token address -> amount in smallest unit)
	/// For ExactInput: contains calculated output amounts
	/// For ExactOutput: contains calculated input amounts
	pub swap_amounts: HashMap<InteropAddress, U256>,
}
