use alloy_primitives::U256;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{InteropAddress, SwapType};

/// Token amount information including decimals
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenAmountInfo {
	/// Token address in interop format
	pub token: InteropAddress,
	/// Amount in smallest unit (wei)
	pub amount: U256,
	/// Token decimals
	pub decimals: u8,
}

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

	// Swap values at market rates (for logging/analysis)
	// These represent the theoretical swap amounts without any costs applied
	#[serde(with = "rust_decimal::serde::str")]
	pub swap_input_value: Decimal,  // USD value of input tokens in the swap
	#[serde(with = "rust_decimal::serde::str")]
	pub swap_output_value: Decimal, // USD value of output tokens in the swap

	// Metadata
	pub currency: String,
}

/// Cost context for quote generation with pre-calculated costs and swap amounts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostContext {
	pub cost_breakdown: CostBreakdown,
	pub execution_costs_by_chain: HashMap<u64, Decimal>,
	#[serde(with = "rust_decimal::serde::str")]
	pub liquidity_cost_adjustment: Decimal,
	pub protocol_fees: HashMap<String, Decimal>,
	/// The swap type used for this quote (ExactInput or ExactOutput)
	pub swap_type: SwapType,
	/// Pre-calculated token amounts for costs (token address -> TokenAmountInfo)
	pub cost_amounts_in_tokens: HashMap<InteropAddress, TokenAmountInfo>,
	/// Base swap amounts before cost adjustments (token address -> TokenAmountInfo)
	/// For ExactInput: contains calculated output amounts
	/// For ExactOutput: contains calculated input amounts
	pub swap_amounts: HashMap<InteropAddress, TokenAmountInfo>,
	/// Adjusted token amounts after cost application (token address -> TokenAmountInfo)
	/// For ExactInput: inputs unchanged, outputs = swap_amounts - cost_amounts
	/// For ExactOutput: outputs unchanged, inputs = swap_amounts + cost_amounts
	pub adjusted_amounts: HashMap<InteropAddress, TokenAmountInfo>,
}
