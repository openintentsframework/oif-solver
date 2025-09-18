//! Profitability calculation utilities for orders and intents.
//!
//! This module provides reusable logic for calculating profit margins on orders,
//! extracting the core profitability logic to make it available across the codebase
//! (e.g., for on-chain intent filtering, HTTP API validation).

use alloy_primitives::U256;
use rust_decimal::Decimal;
use solver_types::{APIError, ApiErrorType, CostEstimate, Order};
use std::str::FromStr;

/// Service for calculating order profitability within the solver engine context.
pub struct ProfitabilityService;

impl ProfitabilityService {
	/// Calculates the profit margin percentage for an order.
	///
	/// The profit margin is calculated as:
	/// Profit = Total Input Amount (USD) - Total Output Amount (USD) - Execution Costs (USD)
	/// Profit Margin = (Profit / Total Input Amount (USD)) * 100
	///
	/// This represents the percentage profit the solver makes on the input amount.
	/// All amounts are converted to USD using the pricing service for accurate comparison.
	///
	/// # Arguments
	/// * `order` - The order to calculate profitability for
	/// * `cost_estimate` - Pre-calculated cost estimate for the order
	/// * `token_manager` - Token manager for getting token info
	/// * `pricing_service` - Pricing service for USD conversions
	///
	/// # Returns
	/// * `Ok(Decimal)` - The profit margin as a percentage (e.g., 2.5 for 2.5%)
	/// * `Err(Box<dyn std::error::Error>)` - If calculation fails
	pub async fn calculate_profit_margin(
		order: &Order,
		cost_estimate: &CostEstimate,
		token_manager: &crate::engine::token_manager::TokenManager,
		pricing_service: &solver_pricing::PricingService,
	) -> Result<Decimal, Box<dyn std::error::Error>> {
		// Parse the order data
		let parsed_order = order.parse_order_data()?;

		// Get input and output assets from the parsed order
		let available_inputs = parsed_order.parse_available_inputs();
		let requested_outputs = parsed_order.parse_requested_outputs();

		// Calculate total input amount in USD (sum of all inputs converted to USD)
		let mut total_input_amount_usd = Decimal::ZERO;
		for input in available_inputs {
			// Extract chain_id and ethereum address from InteropAddress
			let chain_id = input
				.asset
				.ethereum_chain_id()
				.map_err(|e| format!("Failed to get chain ID from asset: {}", e))?;
			let ethereum_addr = input
				.asset
				.ethereum_address()
				.map_err(|e| format!("Failed to get ethereum address from asset: {}", e))?;
			let token_address = solver_types::Address(ethereum_addr.0.to_vec());

			// Get token info
			let token_info = token_manager
				.get_token_info(chain_id, &token_address)
				.map_err(|e| format!("Failed to get token info: {}", e))?;

			// Convert raw amount to USD using pricing service
			let usd_amount = Self::convert_raw_token_to_usd(
				&input.amount,
				&token_info.symbol,
				token_info.decimals,
				pricing_service,
			)
			.await?;

			total_input_amount_usd += usd_amount;
		}

		// Calculate total output amount in USD (sum of all outputs converted to USD)
		let mut total_output_amount_usd = Decimal::ZERO;
		for output in requested_outputs {
			// Extract chain_id and ethereum address from InteropAddress
			let chain_id = output
				.asset
				.ethereum_chain_id()
				.map_err(|e| format!("Failed to get chain ID from asset: {}", e))?;
			let ethereum_addr = output
				.asset
				.ethereum_address()
				.map_err(|e| format!("Failed to get ethereum address from asset: {}", e))?;
			let token_address = solver_types::Address(ethereum_addr.0.to_vec());

			// Get token info
			let token_info = token_manager
				.get_token_info(chain_id, &token_address)
				.map_err(|e| format!("Failed to get token info: {}", e))?;

			// Convert raw amount to USD using pricing service
			let usd_amount = Self::convert_raw_token_to_usd(
				&output.amount,
				&token_info.symbol,
				token_info.decimals,
				pricing_service,
			)
			.await?;

			total_output_amount_usd += usd_amount;
		}

		// Extract operational cost from the components
		let operational_cost_usd = cost_estimate
			.components
			.iter()
			.find(|c| c.name == "operational-cost")
			.and_then(|c| Decimal::from_str(&c.amount).ok())
			.ok_or_else(|| "Operational cost component not found in cost estimate".to_string())?;

		// Calculate the solver's actual profit margin
		// Profit = Input Value - Output Value - Operational Costs
		// Margin = Profit / Input Value * 100
		if total_input_amount_usd.is_zero() {
			return Err("Division by zero: total_input_amount_usd is zero".into());
		}

		let profit_usd = total_input_amount_usd - total_output_amount_usd - operational_cost_usd;
		let hundred = Decimal::new(100_i64, 0);

		let profit_margin_decimal = (profit_usd / total_input_amount_usd) * hundred;

		tracing::debug!(
            "Profitability calculation: input=${} (USD), output=${} (USD), operational_cost=${} (USD), profit=${} (USD), margin={}%",
            total_input_amount_usd,
            total_output_amount_usd,
            operational_cost_usd,
            profit_usd,
            profit_margin_decimal
        );

		Ok(profit_margin_decimal)
	}

	/// Validates that an order meets the minimum profitability threshold.
	///
	/// # Arguments
	/// * `order` - The order to validate
	/// * `cost_estimate` - Pre-calculated cost estimate for the order
	/// * `min_profitability_pct` - Minimum required profit margin percentage
	/// * `token_manager` - Token manager for getting token info
	/// * `pricing_service` - Pricing service for USD conversions
	///
	/// # Returns
	/// * `Ok(Decimal)` - The actual profit margin if it meets the threshold
	/// * `Err(APIError)` - If profitability is insufficient or calculation fails
	pub async fn validate_profitability(
		order: &Order,
		cost_estimate: &CostEstimate,
		min_profitability_pct: Decimal,
		token_manager: &crate::engine::token_manager::TokenManager,
		pricing_service: &solver_pricing::PricingService,
	) -> Result<Decimal, APIError> {
		// Calculate profit margin
		let actual_profit_margin =
			Self::calculate_profit_margin(order, cost_estimate, token_manager, pricing_service)
				.await
				.map_err(|e| APIError::InternalServerError {
					error_type: ApiErrorType::InternalError,
					message: format!("Failed to calculate profitability: {}", e),
				})?;

		// Check if the actual profit margin meets the minimum requirement
		if actual_profit_margin < min_profitability_pct {
			return Err(APIError::UnprocessableEntity {
				error_type: ApiErrorType::InsufficientProfitability,
				message: format!(
					"Insufficient profit margin: {:.2}% (minimum required: {:.2}%)",
					actual_profit_margin, min_profitability_pct
				),
				details: Some(serde_json::json!({
					"actual_profit_margin": actual_profit_margin,
					"min_required": min_profitability_pct,
					"total_cost": cost_estimate.total,
					"cost_components": cost_estimate.components,
				})),
			});
		}

		Ok(actual_profit_margin)
	}

	/// Converts a raw token amount to USD, handling decimals normalization.
	///
	/// This is extracted from the original implementation to avoid code duplication.
	async fn convert_raw_token_to_usd(
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

		let normalized_amount = match token_decimals {
			0 => raw_amount_decimal,
			decimals => {
				let divisor = Decimal::new(10_i64.pow(decimals as u32), 0);
				raw_amount_decimal / divisor
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
}
