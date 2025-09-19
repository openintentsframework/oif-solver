//! Profitability calculation utilities for orders and intents.
//!
//! This module provides reusable logic for calculating profit margins on orders,
//! extracting the core profitability logic to make it available across the codebase
//! (e.g., for on-chain intent filtering, HTTP API validation).

use alloy_primitives::U256;
use rust_decimal::Decimal;
use solver_types::{APIError, ApiErrorType, CostEstimate, Order, TokenConfig, NetworksConfig, Address};
use std::{str::FromStr, sync::Arc};

/// Service for calculating order profitability within the solver engine context.
pub struct ProfitabilityService {
	/// Pricing service for USD conversions
	pricing_service: Arc<crate::PricingService>,
}

/// Container for token configurations needed for profitability calculations.
#[derive(Debug, Clone)]
pub struct OrderTokenConfigs {
	/// Token configurations for input assets
	pub input_tokens: Vec<TokenConfig>,
	/// Token configurations for output assets  
	pub output_tokens: Vec<TokenConfig>,
}

impl ProfitabilityService {
	/// Creates a new ProfitabilityService with the given pricing service.
	pub fn new(pricing_service: Arc<crate::PricingService>) -> Self {
		Self { pricing_service }
	}

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
	/// * `token_configs` - Pre-fetched token configurations for input and output assets
	///
	/// # Returns
	/// * `Ok(Decimal)` - The profit margin as a percentage (e.g., 2.5 for 2.5%)
	/// * `Err(Box<dyn std::error::Error>)` - If calculation fails
	pub async fn calculate_profit_margin(
		&self,
		order: &Order,
		cost_estimate: &CostEstimate,
		token_configs: &OrderTokenConfigs,
	) -> Result<Decimal, Box<dyn std::error::Error>> {
		// Parse the order data to get amounts
		let parsed_order = order.parse_order_data()?;
		let available_inputs = parsed_order.parse_available_inputs();
		let requested_outputs = parsed_order.parse_requested_outputs();

		// Calculate total input amount in USD using pre-fetched token configs
		let mut total_input_amount_usd = Decimal::ZERO;
		for (i, input) in available_inputs.iter().enumerate() {
			let token_info = token_configs
				.input_tokens
				.get(i)
				.ok_or_else(|| format!("Missing token config for input asset {}", i))?;

			let usd_amount = Self::convert_raw_token_to_usd(
				&input.amount,
				&token_info.symbol,
				token_info.decimals,
				&self.pricing_service,
			)
			.await?;

			total_input_amount_usd += usd_amount;
		}

		// Calculate total output amount in USD using pre-fetched token configs
		let mut total_output_amount_usd = Decimal::ZERO;
		for (i, output) in requested_outputs.iter().enumerate() {
			let token_info = token_configs
				.output_tokens
				.get(i)
				.ok_or_else(|| format!("Missing token config for output asset {}", i))?;

			let usd_amount = Self::convert_raw_token_to_usd(
				&output.amount,
				&token_info.symbol,
				token_info.decimals,
				&self.pricing_service,
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
	/// * `token_configs` - Pre-fetched token configurations for input and output assets
	///
	/// # Returns
	/// * `Ok(Decimal)` - The actual profit margin if it meets the threshold
	/// * `Err(APIError)` - If profitability is insufficient or calculation fails
	pub async fn validate_profitability(
		&self,
		order: &Order,
		cost_estimate: &CostEstimate,
		min_profitability_pct: Decimal,
		token_configs: &OrderTokenConfigs,
	) -> Result<Decimal, APIError> {
		// Calculate profit margin
		let actual_profit_margin = self
			.calculate_profit_margin(order, cost_estimate, token_configs)
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
		pricing_service: &crate::PricingService,
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

/// Helper function to extract token configurations from an order using NetworksConfig.
///
/// This function parses the order data and retrieves the corresponding token configurations
/// for all input and output assets using the networks configuration.
///
/// # Arguments
/// * `order` - The order to extract token configs from
/// * `networks` - Networks configuration containing token information for each chain
///
/// # Returns
/// * `Ok(OrderTokenConfigs)` - Container with input and output token configurations
/// * `Err(Box<dyn std::error::Error>)` - If token lookup fails
pub fn extract_token_configs_from_order(
	order: &Order,
	networks: &NetworksConfig,
) -> Result<OrderTokenConfigs, Box<dyn std::error::Error>> {
	// Parse the order data
	let parsed_order = order.parse_order_data()?;

	// Get input and output assets from the parsed order
	let available_inputs = parsed_order.parse_available_inputs();
	let requested_outputs = parsed_order.parse_requested_outputs();

	// Extract input token configs
	let mut input_tokens = Vec::new();
	for input in available_inputs {
		// Extract chain_id and ethereum address from InteropAddress
		let chain_id = input
			.asset
			.ethereum_chain_id()
			.map_err(|e| format!("Failed to get chain ID from input asset: {}", e))?;
		let ethereum_addr = input
			.asset
			.ethereum_address()
			.map_err(|e| format!("Failed to get ethereum address from input asset: {}", e))?;
		let token_address = Address(ethereum_addr.0.to_vec());

		// Get network config for this chain
		let network = networks
			.get(&chain_id)
			.ok_or_else(|| format!("Network {} not found in configuration", chain_id))?;

		// Find token in network's token list
		let token_info = network
			.tokens
			.iter()
			.find(|t| t.address == token_address)
			.cloned()
			.ok_or_else(|| {
				format!(
					"Token {} not found in network {} configuration",
					hex::encode(&token_address.0),
					chain_id
				)
			})?;

		input_tokens.push(token_info);
	}

	// Extract output token configs
	let mut output_tokens = Vec::new();
	for output in requested_outputs {
		// Extract chain_id and ethereum address from InteropAddress
		let chain_id = output
			.asset
			.ethereum_chain_id()
			.map_err(|e| format!("Failed to get chain ID from output asset: {}", e))?;
		let ethereum_addr = output
			.asset
			.ethereum_address()
			.map_err(|e| format!("Failed to get ethereum address from output asset: {}", e))?;
		let token_address = Address(ethereum_addr.0.to_vec());

		// Get network config for this chain
		let network = networks
			.get(&chain_id)
			.ok_or_else(|| format!("Network {} not found in configuration", chain_id))?;

		// Find token in network's token list
		let token_info = network
			.tokens
			.iter()
			.find(|t| t.address == token_address)
			.cloned()
			.ok_or_else(|| {
				format!(
					"Token {} not found in network {} configuration",
					hex::encode(&token_address.0),
					chain_id
				)
			})?;

		output_tokens.push(token_info);
	}

	Ok(OrderTokenConfigs {
		input_tokens,
		output_tokens,
	})
}
