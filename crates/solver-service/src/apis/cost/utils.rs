//! Shared cost calculation utilities.
//!
//! This module contains common functionality used by both quote generation (CostEngine)
//! and (in the future) direct-intent cost validation. It provides consistent gas estimation,
//! flow detection, and cost calculation logic.

use alloy_primitives::U256;
use rust_decimal::Decimal;
use solver_config::Config;
use solver_core::SolverEngine;
use solver_types::{QuoteError, DEFAULT_GAS_PRICE_WEI};
use std::str::FromStr;

/// Gets the gas price for a specific chain from the solver's delivery service.
///
/// This function fetches chain data and parses the gas price, with fallback to
/// DEFAULT_GAS_PRICE_WEI if parsing fails.
pub async fn get_chain_gas_price_as_u256(
	solver: &SolverEngine,
	chain_id: u64,
) -> Result<U256, QuoteError> {
	let chain_data = solver
		.delivery()
		.get_chain_data(chain_id)
		.await
		.map_err(|e| QuoteError::Internal(e.to_string()))?;

	U256::from_str_radix(&chain_data.gas_price, 10)
		.or_else(|_| Ok(U256::from(DEFAULT_GAS_PRICE_WEI)))
}

/// Estimates gas units using configuration flows with fallback estimates.
///
/// This function:
/// 1. Looks up the flow configuration in config.gas.flows
/// 2. Returns configured values (open, fill, claim) if available  
/// 3. Falls back to provided defaults if config is missing
///
/// This is the core logic shared between CostEngine and intent validation.
pub fn estimate_gas_units_from_config(
	flow_key: &Option<String>,
	config: &Config,
	fallback_open: u64,
	fallback_fill: u64,
	fallback_claim: u64,
) -> (u64, u64, u64) {
	if let Some(gcfg) = config.gas.as_ref() {
		tracing::debug!(
			"Available gas flows: {:?}",
			gcfg.flows.keys().collect::<Vec<_>>()
		);
	}

	// Try to get configured values for the detected flow
	if let (Some(flow), Some(gcfg)) = (flow_key.as_deref(), config.gas.as_ref()) {
		if let Some(units) = gcfg.flows.get(flow) {
			// Use configured values directly when available
			let open = units.open.unwrap_or(fallback_open);
			let fill = units.fill.unwrap_or(fallback_fill);
			let claim = units.claim.unwrap_or(fallback_claim);
			return (open, fill, claim);
		} else {
			tracing::warn!("Flow '{}' not found in gas config flows", flow);
		}
	}

	tracing::warn!(
		"No gas config found for flow {:?}, using fallback estimates",
		flow_key
	);

	(fallback_open, fallback_fill, fallback_claim)
}

/// Adds two decimal string values and returns the sum as a string.
///
/// # Returns
///
/// A string representing the sum of the two input values.
pub fn add_decimals(a: &str, b: &str) -> String {
	add_many(&[a.to_string(), b.to_string()])
}

/// Adds multiple decimal string values and returns the sum as a string.
///
/// # Returns
///
/// A string representing the sum of the input values.
pub fn add_many(values: &[String]) -> String {
	let mut sum = U256::ZERO;
	for v in values {
		if let Ok(n) = U256::from_str_radix(v, 10) {
			sum = sum.saturating_add(n);
		}
	}
	sum.to_string()
}

/// Applies a basis point (bps) to a decimal string value and returns the result as a string.
///
/// # Returns
///
/// A string representing the value multiplied by the basis point value.
pub fn apply_bps(value: &str, bps: u32) -> String {
	let v = U256::from_str_radix(value, 10).unwrap_or(U256::ZERO);
	(v.saturating_mul(U256::from(bps as u64)) / U256::from(10_000u64)).to_string()
}

/// Converts a raw token amount to USD, handling decimals normalization.
pub async fn convert_raw_token_to_usd(
	raw_amount: &U256,
	token_symbol: &str,
	token_decimals: u8,
	pricing_service: &solver_pricing::PricingService,
) -> Result<Decimal, Box<dyn std::error::Error>> {
	// Handle potential overflow for large decimals (tokens normally uses max 18 decimals)
	if token_decimals > 28 {
		// Decimal max precision is 28
		return Err(format!(
			"Token decimals {} exceeds maximum supported precision",
			token_decimals
		)
		.into());
	}

	// Convert U256 to string and then to Decimal
	let raw_amount_str = raw_amount.to_string();
	let raw_amount_decimal = Decimal::from_str(&raw_amount_str)
		.map_err(|e| format!("Failed to parse raw amount {}: {}", raw_amount_str, e))?;

	// Use match for token_decimals normalization
	let normalized_amount = match token_decimals {
		0 => raw_amount_decimal,
		decimals => {
			let divisor = Decimal::new(10_i64.pow(decimals as u32), 0);
			let normalized_amount = raw_amount_decimal / divisor;
			normalized_amount
		},
	};

	// Convert to USD and return as Decimal
	let usd_amount_str = pricing_service
		.convert_asset(token_symbol, "USD", &normalized_amount.to_string())
		.await
		.map_err(|e| format!("Failed to convert {} to USD: {}", token_symbol, e))?;

	Decimal::from_str(&usd_amount_str)
		.map_err(|e| format!("Failed to parse USD amount {}: {}", usd_amount_str, e).into())
}
