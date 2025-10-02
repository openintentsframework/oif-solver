//! Cost estimation and profitability calculation service for the OIF solver.
//!
//! This module provides unified functionality for:
//! - Estimating costs associated with executing orders across different blockchain networks
//! - Calculating profit margins for orders and validating profitability thresholds
//! - Unified service combining cost estimation and profitability validation

use crate::engine::token_manager::{TokenManager, TokenManagerError};
use alloy_primitives::U256;
use rust_decimal::Decimal;
use solver_config::Config;
use solver_delivery::DeliveryService;
use solver_pricing::PricingService;
use solver_storage::StorageService;
use solver_types::{
	costs::{CostBreakdown, CostContext, TokenAmountInfo},
	current_timestamp,
	utils::conversion::ceil_dp,
	APIError, Address, ApiErrorType, ExecutionParams, FillProof, InteropAddress, Order, OrderInput,
	OrderOutput, StorageKey, SwapType, Transaction, TransactionHash, DEFAULT_GAS_PRICE_WEI,
};
use std::primitive::str;
use std::{str::FromStr, sync::Arc};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CostProfitError {
	#[error("API error: {0}")]
	Api(#[from] APIError),
	#[error("Calculation error: {0}")]
	Calculation(String),
	#[error("Configuration error: {0}")]
	Config(String),
	#[error("Token manager error: {0}")]
	TokenManager(#[from] TokenManagerError),
	#[error("Storage error: {0}")]
	Storage(#[from] solver_storage::StorageError),
}

/// Parameters for gas unit calculations
pub struct GasUnits {
	pub open_units: u64,
	pub fill_units: u64,
	pub claim_units: u64,
}

/// Unified service for cost estimation and profitability calculation.
pub struct CostProfitService {
	/// Pricing service for USD conversions and asset pricing
	pricing_service: Arc<PricingService>,
	/// Delivery service for blockchain data and gas estimation
	delivery_service: Arc<DeliveryService>,
	/// Token manager for token configuration lookups
	token_manager: Arc<TokenManager>,
	/// Storage service for reading quotes
	storage_service: Arc<StorageService>,
}

impl CostProfitService {
	/// Creates a new CostProfitService with the given services.
	pub fn new(
		pricing_service: Arc<PricingService>,
		delivery_service: Arc<DeliveryService>,
		token_manager: Arc<TokenManager>,
		storage_service: Arc<StorageService>,
	) -> Self {
		Self {
			pricing_service,
			delivery_service,
			token_manager,
			storage_service,
		}
	}

	/// Retrieves a stored cost context by quote ID.
	///
	/// This function looks up the QuoteWithCostContext and extracts the cost context.
	/// Quotes and their contexts are automatically expired based on their TTL.
	pub async fn get_cost_context_by_quote_id(
		&self,
		quote_id: &str,
	) -> Result<CostContext, CostProfitError> {
		use solver_types::QuoteWithCostContext;

		match self
			.storage_service
			.retrieve::<QuoteWithCostContext>(StorageKey::Quotes.as_str(), quote_id)
			.await
		{
			Ok(quote_with_context) => {
				tracing::debug!(
					"Retrieved quote with cost context for {} from storage",
					quote_id
				);
				Ok(quote_with_context.cost_context)
			},
			Err(e) => {
				tracing::warn!(
					"Failed to retrieve quote with cost context for {}: {}",
					quote_id,
					e
				);
				Err(CostProfitError::Storage(e))
			},
		}
	}

	/// Calculate base swap amounts using pricing service exchange rates.
	///
	/// This method determines the required token amounts for a swap based on the swap type:
	/// - **ExactInput**: Calculates output amounts - how much output token the user will receive
	/// - **ExactOutput**: Calculates input amounts - how much input token the user needs to provide
	///
	/// The calculation uses a two-step conversion through USD as a common base:
	/// 1. Convert source token amount to USD value
	/// 2. Convert USD value to target token amount
	///
	/// This approach ensures we can handle any token pair as long as both tokens
	/// have USD pricing available, even if there's no direct trading pair.
	///
	/// # Arguments
	/// * `request` - The quote request with input/output token specifications
	/// * `context` - Validated context with known amounts and swap type
	///
	/// # Returns
	/// HashMap mapping token addresses to their calculated amounts (in smallest unit)
	/// Calculate swap amounts for missing inputs or outputs based on exchange rates.
	///
	/// This method determines the amounts for inputs (in ExactOutput swaps) or outputs
	/// (in ExactInput swaps) by converting through USD as an intermediate currency.
	///
	/// ## Approach
	///
	/// Rather than equal distribution, we match exact input/output pairs:
	/// - For multi-input, multi-output swaps, we pair inputs with outputs in order
	/// - Each input amount is used to calculate its corresponding output amount
	/// - If there are more outputs than inputs, remaining outputs get zero
	/// - If there are more inputs than outputs, extra inputs contribute to the last output
	///
	/// ## Examples
	///
	/// - 1 input (100 USDC) → 2 outputs: First output gets full conversion, second gets zero
	/// - 2 inputs (50 USDC each) → 1 output: Output gets sum of both conversions
	/// - 2 inputs → 2 outputs: Each input converts to its corresponding output
	pub async fn calculate_swap_amounts(
		&self,
		request: &solver_types::GetQuoteRequest,
		context: &solver_types::ValidatedQuoteContext,
		decimals_map: &std::collections::HashMap<InteropAddress, u8>,
	) -> Result<
		std::collections::HashMap<solver_types::InteropAddress, TokenAmountInfo>,
		CostProfitError,
	> {
		use solver_types::SwapType;
		let mut calculated_amounts = std::collections::HashMap::new();

		match context.swap_type {
			SwapType::ExactInput => {
				// ExactInput: User specifies input amounts, we calculate output amounts
				// Flow: Input Token → USD → Output Token
				if let Some(known_inputs) = &context.known_inputs {
					// Convert each input to USD and match with corresponding outputs
					let mut input_usd_values = Vec::new();

					for (input, input_amount) in known_inputs {
						let input_chain_id = input.asset.ethereum_chain_id().map_err(|e| {
							CostProfitError::Calculation(format!("Invalid input chain: {}", e))
						})?;
						let input_addr = input.asset.ethereum_address().map_err(|e| {
							CostProfitError::Calculation(format!("Invalid input address: {}", e))
						})?;
						let input_token = self
							.token_manager
							.get_token_info(input_chain_id, &Address(input_addr.0.to_vec()))?;

						// Convert raw amount to USD
						let usd_value = Self::convert_raw_token_to_usd(
							input_amount,
							&input_token.symbol,
							input_token.decimals,
							&self.pricing_service,
						)
						.await
						.map_err(|e| CostProfitError::Calculation(e.to_string()))?;

						input_usd_values.push(usd_value);
					}

					// Match inputs with outputs
					for (idx, output) in request.intent.outputs.iter().enumerate() {
						let output_usd = if idx < input_usd_values.len() {
							// Direct pairing: use the corresponding input's USD value
							input_usd_values[idx]
						} else if !input_usd_values.is_empty() {
							// More outputs than inputs: extra outputs get zero
							Decimal::ZERO
						} else {
							Decimal::ZERO
						};

						// If there are more inputs than outputs, add remaining inputs to last output
						let final_output_usd = if idx == request.intent.outputs.len() - 1
							&& input_usd_values.len() > request.intent.outputs.len()
						{
							// Sum all remaining input values
							let mut total = output_usd;
							for value in input_usd_values.iter().skip(idx + 1) {
								total += value;
							}
							total
						} else {
							output_usd
						};

						// Convert USD to output token amount
						let output_amount = self
							.convert_usd_to_token_amount(final_output_usd, &output.asset)
							.await?;
						let decimals = decimals_map.get(&output.asset).copied().unwrap_or(18);
						calculated_amounts.insert(
							output.asset.clone(),
							TokenAmountInfo {
								token: output.asset.clone(),
								amount: output_amount,
								decimals,
							},
						);
					}
				}
			},
			SwapType::ExactOutput => {
				// ExactOutput: User specifies output amounts, we calculate input amounts
				// Flow: Output Token → USD → Input Token
				if let Some(known_outputs) = &context.known_outputs {
					// Convert each output to USD and match with corresponding inputs
					let mut output_usd_values = Vec::new();

					for (output, output_amount) in known_outputs {
						let output_chain_id = output.asset.ethereum_chain_id().map_err(|e| {
							CostProfitError::Calculation(format!("Invalid output chain: {}", e))
						})?;
						let output_addr = output.asset.ethereum_address().map_err(|e| {
							CostProfitError::Calculation(format!("Invalid output address: {}", e))
						})?;
						let output_token = self
							.token_manager
							.get_token_info(output_chain_id, &Address(output_addr.0.to_vec()))?;

						// Convert raw amount to USD
						let usd_value = Self::convert_raw_token_to_usd(
							output_amount,
							&output_token.symbol,
							output_token.decimals,
							&self.pricing_service,
						)
						.await
						.map_err(|e| CostProfitError::Calculation(e.to_string()))?;

						output_usd_values.push(usd_value);
					}

					// Match outputs with inputs
					for (idx, input) in request.intent.inputs.iter().enumerate() {
						let input_usd = if idx < output_usd_values.len() {
							// Direct pairing: use the corresponding output's USD value
							output_usd_values[idx]
						} else if !output_usd_values.is_empty() {
							// More inputs than outputs: extra inputs get zero
							Decimal::ZERO
						} else {
							Decimal::ZERO
						};

						// If there are more outputs than inputs, add remaining outputs to last input
						let final_input_usd = if idx == request.intent.inputs.len() - 1
							&& output_usd_values.len() > request.intent.inputs.len()
						{
							// Sum all remaining output values
							let mut total = input_usd;
							for value in output_usd_values.iter().skip(idx + 1) {
								total += value;
							}
							total
						} else {
							input_usd
						};

						// Convert USD to input token amount
						let input_amount = self
							.convert_usd_to_token_amount(final_input_usd, &input.asset)
							.await?;
						let decimals = decimals_map.get(&input.asset).copied().unwrap_or(18);
						calculated_amounts.insert(
							input.asset.clone(),
							TokenAmountInfo {
								token: input.asset.clone(),
								amount: input_amount,
								decimals,
							},
						);
					}
				}
			},
		}

		tracing::debug!(
			"Calculated swap amounts for {:?}: {} tokens",
			context.swap_type,
			calculated_amounts.len()
		);

		Ok(calculated_amounts)
	}

	/// Helper function to get decimals for all tokens in a request
	async fn get_all_token_decimals(
		&self,
		request: &solver_types::GetQuoteRequest,
	) -> std::collections::HashMap<InteropAddress, u8> {
		let mut decimals_map = std::collections::HashMap::new();

		// Get decimals for all input tokens
		for input in &request.intent.inputs {
			if let (Ok(chain_id), Ok(eth_addr)) = (
				input.asset.ethereum_chain_id(),
				input.asset.ethereum_address(),
			) {
				let decimals = self
					.token_manager
					.get_token_info(chain_id, &Address(eth_addr.0.to_vec()))
					.ok()
					.map(|info| info.decimals)
					.unwrap_or(18);
				decimals_map.insert(input.asset.clone(), decimals);
			}
		}

		// Get decimals for all output tokens
		for output in &request.intent.outputs {
			if !decimals_map.contains_key(&output.asset) {
				if let (Ok(chain_id), Ok(eth_addr)) = (
					output.asset.ethereum_chain_id(),
					output.asset.ethereum_address(),
				) {
					let decimals = self
						.token_manager
						.get_token_info(chain_id, &Address(eth_addr.0.to_vec()))
						.ok()
						.map(|info| info.decimals)
						.unwrap_or(18);
					decimals_map.insert(output.asset.clone(), decimals);
				}
			}
		}

		decimals_map
	}

	/// Calculate cost context and swap amounts before quote generation
	pub async fn calculate_cost_context(
		&self,
		request: &solver_types::GetQuoteRequest,
		context: &solver_types::ValidatedQuoteContext,
		config: &Config,
	) -> Result<CostContext, CostProfitError> {
		// Get all token decimals upfront
		let decimals_map = self.get_all_token_decimals(request).await;

		// Calculate base swap amounts FIRST to fill in missing values (now returns TokenAmountInfo)
		let swap_amounts_with_info = self
			.calculate_swap_amounts(request, context, &decimals_map)
			.await?;

		// Use inputs and outputs from request
		let inputs = &request.intent.inputs;
		let outputs = &request.intent.outputs;

		// Extract chain IDs
		let origin_chain_id = inputs
			.iter()
			.filter_map(|input| input.asset.ethereum_chain_id().ok())
			.next()
			.ok_or_else(|| APIError::BadRequest {
				error_type: ApiErrorType::MissingChainId,
				message: "No input chain ID found".to_string(),
				details: None,
			})?;

		let dest_chain_id = outputs
			.iter()
			.filter_map(|output| output.asset.ethereum_chain_id().ok())
			.next()
			.ok_or_else(|| APIError::BadRequest {
				error_type: ApiErrorType::MissingChainId,
				message: "No output chain ID found".to_string(),
				details: None,
			})?;

		// Determine flow key from the request structure
		let flow_key = request.flow_key();
		let (open_units, fill_units, claim_units) =
			estimate_gas_units_from_config(&flow_key, config, 150000, 150000, 150000);

		// Get gas units for cost calculation
		let gas_units = GasUnits {
			open_units,
			fill_units,
			claim_units,
		};

		// Parse inputs/outputs to proper types for cost calculation
		let mut parsed_inputs = Vec::new();
		for input in inputs {
			if let Ok(mut order_input) = <OrderInput>::try_from(input) {
				// Fill in zero amounts with calculated swap amounts
				if order_input.amount == U256::ZERO {
					if let Some(calculated_info) = swap_amounts_with_info.get(&input.asset) {
						order_input.amount = calculated_info.amount;
					}
				}
				parsed_inputs.push(order_input);
			}
		}

		let mut parsed_outputs = Vec::new();
		for output in outputs {
			if let Ok(mut order_output) = <OrderOutput>::try_from(output) {
				// Fill in zero amounts with calculated swap amounts
				if order_output.amount == U256::ZERO {
					if let Some(calculated_info) = swap_amounts_with_info.get(&output.asset) {
						order_output.amount = calculated_info.amount;
					}
				}
				parsed_outputs.push(order_output);
			}
		}

		// First calculate base costs with swap amounts to determine operational costs
		let cost_breakdown = self
			.calculate_total_cost(
				&parsed_inputs,
				&parsed_outputs,
				config,
				origin_chain_id,
				dest_chain_id,
				&gas_units,
			)
			.await?;

		// Pre-calculate cost amounts in relevant tokens
		// Include min_profit for quotes so users know the total they need to provide
		let total_with_profit = cost_breakdown.total + cost_breakdown.min_profit;

		// Ceil to cents to protect our margin during USD -> token -> USD round-trip
		// This ensures we always collect enough to cover costs + min_profit after conversions
		let total_with_profit_rounded = ceil_dp(total_with_profit, 2);

		let mut cost_amounts_in_tokens = std::collections::HashMap::new();

		// Calculate cost in each requested input token
		for input in inputs {
			let cost_in_token = self
				.convert_usd_to_token_amount(total_with_profit_rounded, &input.asset)
				.await
				.unwrap_or(U256::ZERO);

			let decimals = decimals_map.get(&input.asset).copied().unwrap_or(18);
			cost_amounts_in_tokens.insert(
				input.asset.clone(),
				TokenAmountInfo {
					token: input.asset.clone(),
					amount: cost_in_token,
					decimals,
				},
			);
		}

		// Also calculate cost in each requested output token for reference
		for output in outputs {
			// Only add if not already calculated (in case same token appears in inputs)
			if !cost_amounts_in_tokens.contains_key(&output.asset) {
				let cost_in_token = self
					.convert_usd_to_token_amount(total_with_profit_rounded, &output.asset)
					.await
					.unwrap_or(U256::ZERO);

				let decimals = decimals_map.get(&output.asset).copied().unwrap_or(18);
				cost_amounts_in_tokens.insert(
					output.asset.clone(),
					TokenAmountInfo {
						token: output.asset.clone(),
						amount: cost_in_token,
						decimals,
					},
				);
			}
		}

		// Build execution costs by chain from base cost breakdown
		let mut execution_costs_by_chain = std::collections::HashMap::new();
		execution_costs_by_chain.insert(
			origin_chain_id,
			cost_breakdown.gas_open + cost_breakdown.gas_claim,
		);
		execution_costs_by_chain.insert(dest_chain_id, cost_breakdown.gas_fill);

		// Calculate adjusted amounts (swap amounts +/- costs based on swap type)
		let mut adjusted_amounts = std::collections::HashMap::new();
		match context.swap_type {
			SwapType::ExactInput => {
				// For ExactInput: outputs are adjusted (swap_amount - cost)
				for (token, swap_info) in &swap_amounts_with_info {
					let cost_info = cost_amounts_in_tokens.get(token);
					let cost_amount = cost_info.map(|c| c.amount).unwrap_or(U256::ZERO);
					let adjusted = swap_info.amount.saturating_sub(cost_amount);
					adjusted_amounts.insert(
						token.clone(),
						TokenAmountInfo {
							token: token.clone(),
							amount: adjusted,
							decimals: swap_info.decimals,
						},
					);
				}
			},
			SwapType::ExactOutput => {
				// For ExactOutput: inputs are adjusted (swap_amount + cost)
				for (token, swap_info) in &swap_amounts_with_info {
					let cost_info = cost_amounts_in_tokens.get(token);
					let cost_amount = cost_info.map(|c| c.amount).unwrap_or(U256::ZERO);
					let adjusted = swap_info.amount.saturating_add(cost_amount);
					adjusted_amounts.insert(
						token.clone(),
						TokenAmountInfo {
							token: token.clone(),
							amount: adjusted,
							decimals: swap_info.decimals,
						},
					);
				}
			},
		}

		Ok(CostContext {
			cost_breakdown,
			execution_costs_by_chain,
			liquidity_cost_adjustment: Decimal::ZERO,
			protocol_fees: std::collections::HashMap::new(),
			swap_type: context.swap_type.clone(),
			cost_amounts_in_tokens,
			swap_amounts: swap_amounts_with_info,
			adjusted_amounts,
		})
	}

	pub async fn calculate_total_cost(
		&self,
		inputs: &[OrderInput],
		outputs: &[OrderOutput],
		config: &Config,
		origin_chain_id: u64,
		dest_chain_id: u64,
		gas_units: &GasUnits,
	) -> Result<CostBreakdown, CostProfitError> {
		let pricing = self.pricing_service.config();

		// Get gas prices
		let origin_gp = self.get_chain_gas_price(origin_chain_id).await?;
		let dest_gp = self.get_chain_gas_price(dest_chain_id).await?;

		// Calculate gas costs in wei
		let open_cost_wei = origin_gp.saturating_mul(U256::from(gas_units.open_units));
		let fill_cost_wei = dest_gp.saturating_mul(U256::from(gas_units.fill_units));
		let claim_cost_wei = origin_gp.saturating_mul(U256::from(gas_units.claim_units));

		// Convert to USD
		let gas_open = Decimal::from_str(
			&self
				.pricing_service
				.wei_to_currency(&open_cost_wei.to_string(), "USD")
				.await
				.unwrap_or_else(|_| "0".to_string()),
		)
		.unwrap_or(Decimal::ZERO);

		let gas_fill = Decimal::from_str(
			&self
				.pricing_service
				.wei_to_currency(&fill_cost_wei.to_string(), "USD")
				.await
				.unwrap_or_else(|_| "0".to_string()),
		)
		.unwrap_or(Decimal::ZERO);

		let gas_claim = Decimal::from_str(
			&self
				.pricing_service
				.wei_to_currency(&claim_cost_wei.to_string(), "USD")
				.await
				.unwrap_or_else(|_| "0".to_string()),
		)
		.unwrap_or(Decimal::ZERO);

		// Calculate gas buffer
		let gas_subtotal = gas_open + gas_fill + gas_claim;
		let gas_buffer_bps = Decimal::new(pricing.gas_buffer_bps as i64, 0);
		let gas_buffer = (gas_subtotal * gas_buffer_bps) / Decimal::from(10000);

		// Rate buffer (currently 0, placeholder for future)
		let rate_buffer = Decimal::ZERO;

		// Calculate input and output values in USD using helpers
		let total_input_value_usd = self.calculate_inputs_usd_value(inputs).await?;
		let total_output_value_usd = self.calculate_outputs_usd_value(outputs).await?;

		// Calculate spread and base price
		let spread = total_input_value_usd - total_output_value_usd;
		let base_price = if spread < Decimal::ZERO {
			spread.abs() // Cover negative spread
		} else {
			Decimal::ZERO
		};

		// Calculate minimum profit based on TRANSACTION VALUE, not gas
		let transaction_value = total_input_value_usd.max(total_output_value_usd);
		let min_profit =
			(transaction_value * config.solver.min_profitability_pct) / Decimal::from(100);

		// Calculate operational cost (gas + buffers)
		let operational_cost = gas_open + gas_fill + gas_claim + gas_buffer + rate_buffer;

		// Calculate subtotal (actual costs only, excluding profit)
		let subtotal = operational_cost + base_price;

		// Calculate total (actual costs only, excluding profit requirement)
		let total = subtotal;

		Ok(CostBreakdown {
			gas_open,
			gas_fill,
			gas_claim,
			gas_buffer,
			rate_buffer,
			base_price,
			min_profit,
			operational_cost,
			subtotal,
			total,
			currency: "USD".to_string(),
		})
	}

	/// Estimate cost for an Order using its OrderParsable implementation
	pub async fn estimate_cost_for_order(
		&self,
		order: &Order,
		config: &Config,
	) -> Result<CostBreakdown, CostProfitError> {
		// Parse the order data based on its standard
		let order_parsed = order.parse_order_data().map_err(|e| APIError::BadRequest {
			error_type: ApiErrorType::InvalidRequest,
			message: format!("Failed to parse order data: {}", e),
			details: None,
		})?;

		// Extract chain parameters
		let origin_chain_id = order_parsed.origin_chain_id();
		let dest_chain_ids = order_parsed.destination_chain_ids();

		let dest_chain_id =
			dest_chain_ids
				.first()
				.copied()
				.ok_or_else(|| APIError::BadRequest {
					error_type: ApiErrorType::MissingChainId,
					message: "No destination chain ID found".to_string(),
					details: None,
				})?;

		// Extract flow key (lock_type) for gas config lookup
		let flow_key = order_parsed.parse_lock_type();

		// Estimate gas units
		let gas_units = self
			.estimate_gas_units(order, &flow_key, config, origin_chain_id, dest_chain_id)
			.await?;

		// Get inputs and outputs
		let available_inputs = order_parsed.parse_available_inputs();
		let requested_outputs = order_parsed.parse_requested_outputs();

		// Use the unified cost calculation method
		let cost_breakdown = self
			.calculate_total_cost(
				&available_inputs,
				&requested_outputs,
				config,
				origin_chain_id,
				dest_chain_id,
				&gas_units,
			)
			.await?;

		// Convert to API format
		Ok(cost_breakdown)
	}

	/// Validates that an order meets the minimum profitability threshold.
	///
	/// This method checks if an order (whether from our quote system or submitted directly)
	/// provides sufficient profit margin. It recalculates costs and compares actual profit
	/// against the minimum requirement.
	///
	/// If `quote_id` is provided, the quote will be retrieved from storage to get additional context.
	pub async fn validate_profitability(
		&self,
		order: &Order,
		cost_breakdown: &CostBreakdown,
		min_profitability_pct: Decimal,
		quote_id: Option<&str>,
	) -> Result<Decimal, APIError> {
		// Retrieve the cost context if a quote ID is provided
		let cost_context = if let Some(id) = quote_id {
			match self.get_cost_context_by_quote_id(id).await {
				Ok(ctx) => {
					tracing::debug!(
						"Cost context from quote generation: operational_cost=${:.2}, min_profit=${:.2}, total=${:.2}",
						ctx.cost_breakdown.operational_cost,
						ctx.cost_breakdown.min_profit,
						ctx.cost_breakdown.total
					);
					Some(ctx)
				},
				Err(e) => {
					tracing::warn!("Failed to retrieve cost context for quote {}: {}", id, e);
					None
				},
			}
		} else {
			None
		};

		// Parse the order to get actual input/output amounts
		let order_parsed = order.parse_order_data().map_err(|e| APIError::BadRequest {
			error_type: ApiErrorType::InvalidRequest,
			message: format!("Failed to parse order data: {}", e),
			details: None,
		})?;

		let available_inputs = order_parsed.parse_available_inputs();
		let requested_outputs = order_parsed.parse_requested_outputs();

		// Calculate actual USD values from the order amounts
		let total_input_value_usd = self
			.calculate_inputs_usd_value(&available_inputs)
			.await
			.map_err(|e| APIError::InternalServerError {
				error_type: ApiErrorType::InternalError,
				message: format!("Failed to calculate input USD value: {}", e),
			})?;

		let total_output_value_usd = self
			.calculate_outputs_usd_value(&requested_outputs)
			.await
			.map_err(|e| APIError::InternalServerError {
				error_type: ApiErrorType::InternalError,
				message: format!("Failed to calculate output USD value: {}", e),
			})?;

		// Operational cost is already available in the breakdown
		let operational_cost_usd = cost_breakdown.operational_cost;

		// Calculate the actual spread in the order
		// For normal swaps: spread = input - output (positive when user pays more than receives)
		// For arbitrage: spread = input - output (negative when user receives more than pays)
		let order_spread = total_input_value_usd - total_output_value_usd;

		// Actual profit is the spread minus operational costs
		// For normal swaps: profit comes from positive spread
		// For arbitrage: we would lose money (negative spread means user profits, not us)
		let actual_profit_usd = order_spread - operational_cost_usd;

		// Calculate profit margin as percentage of transaction value
		// For ExactOutput swaps, we must use the output value as the base (what the user requested)
		// For ExactInput swaps, we use the input value as the base
		// This ensures consistency with how profit was calculated during quote generation
		let transaction_value = if let Some(ref ctx) = cost_context {
			match ctx.swap_type {
				solver_types::SwapType::ExactOutput => {
					// For ExactOutput: use output value as base (what user wants to receive)
					total_output_value_usd
				},
				solver_types::SwapType::ExactInput => {
					// For ExactInput: use input value as base (what user is sending)
					total_input_value_usd
				},
			}
		} else {
			// No cost context (direct submission), use the larger value
			// This maintains backward compatibility for non-quoted orders
			total_input_value_usd.max(total_output_value_usd)
		};

		if transaction_value.is_zero() {
			return Err(APIError::BadRequest {
				error_type: ApiErrorType::InvalidRequest,
				message: "Cannot calculate profit margin: zero transaction value".to_string(),
				details: None,
			});
		}

		let actual_profit_margin = (actual_profit_usd / transaction_value) * Decimal::from(100);
		let profit_validation_passed = actual_profit_margin >= min_profitability_pct;

		// Calculate what the values would be at different stages
		// Note: We're working backwards from the final quoted values
		// Display the actual minimum profit requirement from cost breakdown
		let display_actual_profit = actual_profit_usd;

		// Calculate effective exchange rate (what % of input value user receives)
		let effective_rate_pct = if !total_input_value_usd.is_zero() {
			(total_output_value_usd / total_input_value_usd * Decimal::from(100)).round_dp(1)
		} else {
			Decimal::ZERO
		};

		// For display: show the absolute spread amount (always positive)
		// and indicate if it's a cost to user or an arbitrage opportunity
		let display_spread = order_spread.abs();
		let spread_type = if order_spread >= Decimal::ZERO {
			"collected from user"
		} else {
			"arbitrage opportunity"
		};

		// Log streamlined profitability validation summary
		tracing::info!(
			"\n\
			╭─ Quote Validation Summary:\n\
			│  ├─ Quote ID:           {}\n\
			│  ├─ Swap Type:          {}\n\
			│  └─ Effective Rate:     {:.1}%\n\
			├─ Order Economics:\n\
			│  ├─ Input:\n\
			│  │  ├─ USD Value:       $ {:>7.4}\n\
			│  ├─ Output:\n\
			│  │  ├─ USD Value:       $ {:>7.4}\n\
			│  └─ Spread:\n\
			│     ├─ Amount:          $ {:>7.4} ({})\n\
			│     └─ Solver P&L:      $ {:>7.4} (after ${:.2} costs)\n\
			├─ Cost Breakdown:\n\
			│  ├─ Gas Costs:\n\
			│  │  ├─ Open:            $ {:>7.4}\n\
			│  │  ├─ Fill:            $ {:>7.4}\n\
			│  │  ├─ Claim:           $ {:>7.4}\n\
			│  │  └─ Buffer (10%):    $ {:>7.4}\n\
			│  ├─ Total Operational:  $ {:>7.4}\n\
			│  └─ Solver Profit:      $ {:>7.4} (target: {:.1}% of transaction)\n\
			├─ Validation Result:\n\
			│  ├─ Profit Margin:      {:.2}%\n\
			│  ├─ Min Required:       {:.2}%\n\
			│  └─ Status:             {}\n\
			╰─ Decision: {}",
			// Quote info
			quote_id.unwrap_or("N/A"),
			if let Some(ref ctx) = cost_context {
				format!("{:?}", ctx.swap_type)
			} else {
				"Unknown".to_string()
			},
			effective_rate_pct,
			// Order values
			total_input_value_usd,
			total_output_value_usd,
			display_spread,
			spread_type,
			display_actual_profit,
			operational_cost_usd,
			// Cost breakdown
			cost_breakdown.gas_open,
			cost_breakdown.gas_fill,
			cost_breakdown.gas_claim,
			cost_breakdown.gas_buffer,
			operational_cost_usd,
			display_actual_profit,
			min_profitability_pct,
			// Validation
			actual_profit_margin,
			min_profitability_pct,
			if profit_validation_passed {
				"✓ PASSED"
			} else {
				"✗ FAILED"
			},
			if profit_validation_passed {
				format!(
					"Order accepted with {:.2}% profit margin",
					actual_profit_margin
				)
			} else {
				format!(
					"Order rejected - insufficient margin ({:.2}% < {:.2}%)",
					actual_profit_margin, min_profitability_pct
				)
			}
		);

		// Check if actual profit meets minimum requirement
		if !profit_validation_passed {
			let error_msg = format!(
				"Insufficient profit margin: {:.2}% < required {:.2}%",
				actual_profit_margin, min_profitability_pct
			);
			return Err(APIError::UnprocessableEntity {
				error_type: ApiErrorType::InsufficientProfitability,
				message: error_msg,
				details: Some(serde_json::json!({
					"input_value": format!("${:.2}", total_input_value_usd),
					"output_value": format!("${:.2}", total_output_value_usd),
					"operational_cost": format!("${:.2}", operational_cost_usd),
					"actual_profit": format!("${:.2}", actual_profit_usd),
					"actual_margin": format!("{:.2}%", actual_profit_margin),
					"required_margin": format!("{:.2}%", min_profitability_pct),
				})),
			});
		}

		Ok(actual_profit_margin)
	}

	/// Estimate gas units with optional live estimation
	async fn estimate_gas_units(
		&self,
		order: &Order,
		flow_key: &Option<String>,
		config: &Config,
		origin_chain_id: u64,
		dest_chain_id: u64,
	) -> Result<GasUnits, CostProfitError> {
		// TODO: For now, we'll use a simple check for live gas estimation and pass it as a parameter
		// in the future we should use the config.gas.enable_live_gas_estimate
		let enable_live_gas_estimate = false;

		// Get base units from config
		let (open_units, mut fill_units, mut claim_units) =
			estimate_gas_units_from_config(flow_key, config, 0, 0, 0);

		// Live estimation if enabled
		if enable_live_gas_estimate {
			// Estimate fill gas
			tracing::info!("Estimating fill gas on destination chain");
			if let Ok(fill_tx) = self.build_fill_tx_for_estimation(order).await {
				match self
					.delivery_service
					.estimate_gas(dest_chain_id, fill_tx.clone())
					.await
				{
					Ok(units) => {
						tracing::info!("Fill gas units: {}", units);
						fill_units = units;
					},
					Err(e) => {
						tracing::warn!(
							error = %e,
							chain = dest_chain_id,
							to = %fill_tx.to.as_ref().map(|a| a.to_string()).unwrap_or_else(|| "<none>".into()),
							"estimate_gas(fill) failed; using heuristic"
						);
					},
				}
			}

			// Estimate claim gas
			if let Ok(claim_tx) = self.build_claim_tx_for_estimation(order).await {
				tracing::debug!(
					"finalise tx bytes_len={} to={}",
					claim_tx.data.len(),
					claim_tx
						.to
						.as_ref()
						.map(|a| a.to_string())
						.unwrap_or_else(|| "<none>".into())
				);
				match self
					.delivery_service
					.estimate_gas(origin_chain_id, claim_tx.clone())
					.await
				{
					Ok(units) => {
						tracing::debug!("Claim gas units: {}", units);
						claim_units = units;
					},
					Err(e) => {
						tracing::warn!(
							error = %e,
							chain = origin_chain_id,
							to = %claim_tx.to.as_ref().map(|a| a.to_string()).unwrap_or_else(|| "<none>".into()),
							"estimate_gas(finalise) failed; using heuristic"
						);
					},
				}
			}
		}

		Ok(GasUnits {
			open_units,
			fill_units,
			claim_units,
		})
	}

	/// Build fill transaction for gas estimation
	async fn build_fill_tx_for_estimation(&self, order: &Order) -> Result<Transaction, APIError> {
		// Create execution params for estimation
		let params = ExecutionParams {
			gas_price: U256::from(DEFAULT_GAS_PRICE_WEI),
			priority_fee: None,
		};

		// Parse the order to get the destination chain ID
		let order_parsed = order.parse_order_data().map_err(|e| APIError::BadRequest {
			error_type: ApiErrorType::InvalidRequest,
			message: format!("Failed to parse order data for fill tx: {}", e),
			details: None,
		})?;
		let dest_chain_ids = order_parsed.destination_chain_ids();
		let chain_id = dest_chain_ids.first().copied().unwrap_or(1);

		Ok(Transaction {
			chain_id,
			to: None,     // Will be filled by actual implementation
			data: vec![], // Minimal data for estimation
			gas_price: Some(params.gas_price.try_into().unwrap_or(u128::MAX)),
			gas_limit: None,
			value: alloy_primitives::U256::ZERO,
			nonce: None,
			max_fee_per_gas: params
				.priority_fee
				.map(|fee| fee.try_into().unwrap_or(u128::MAX)),
			max_priority_fee_per_gas: None,
		})
	}

	/// Build claim transaction for gas estimation
	async fn build_claim_tx_for_estimation(&self, order: &Order) -> Result<Transaction, APIError> {
		// Create minimal fill proof for estimation
		let _fill_proof = FillProof {
			oracle_address: "0x0000000000000000000000000000000000000000".to_string(),
			filled_timestamp: current_timestamp(),
			block_number: 1,
			tx_hash: TransactionHash(vec![0u8; 32]),
			attestation_data: Some(vec![]),
		};

		// Parse the order to get the origin chain ID
		let order_parsed = order.parse_order_data().map_err(|e| APIError::BadRequest {
			error_type: ApiErrorType::InvalidRequest,
			message: format!("Failed to parse order data for claim tx: {}", e),
			details: None,
		})?;
		let chain_id = order_parsed.origin_chain_id();

		Ok(Transaction {
			chain_id,
			to: None,     // Will be filled by actual implementation
			data: vec![], // Minimal data for estimation
			gas_price: Some(DEFAULT_GAS_PRICE_WEI as u128),
			gas_limit: None,
			value: alloy_primitives::U256::ZERO,
			nonce: None,
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
		})
	}

	/// Gets the gas price for a specific chain
	async fn get_chain_gas_price(&self, chain_id: u64) -> Result<U256, APIError> {
		let chain_data = self
			.delivery_service
			.get_chain_data(chain_id)
			.await
			.map_err(|e| APIError::InternalServerError {
				error_type: ApiErrorType::ServiceError,
				message: format!("Failed to get chain data: {}", e),
			})?;

		match U256::from_str_radix(&chain_data.gas_price, 10) {
			Ok(gas_price) => Ok(gas_price),
			Err(_) => Ok(U256::from(DEFAULT_GAS_PRICE_WEI)),
		}
	}

	/// Converts a raw token amount to USD, handling decimals normalization.
	async fn convert_raw_token_to_usd(
		raw_amount: &U256,
		token_symbol: &str,
		token_decimals: u8,
		pricing_service: &PricingService,
	) -> Result<Decimal, Box<dyn std::error::Error>> {
		// Handle potential overflow for large decimals
		if token_decimals > 28 {
			return Err(format!(
				"Token decimals {} exceeds maximum supported precision",
				token_decimals
			)
			.into());
		}

		// Convert U256 to Decimal
		let raw_amount_str = raw_amount.to_string();
		let raw_amount_decimal = Decimal::from_str(&raw_amount_str)
			.map_err(|e| format!("Failed to parse raw amount {}: {}", raw_amount_str, e))?;

		// Normalize amount by token decimals
		let normalized_amount = match token_decimals {
			0 => raw_amount_decimal,
			decimals => {
				let divisor = Decimal::new(10_i64.pow(decimals as u32), 0);
				raw_amount_decimal / divisor
			},
		};

		// Convert to USD
		let usd_amount_str = pricing_service
			.convert_asset(token_symbol, "USD", &normalized_amount.to_string())
			.await
			.map_err(|e| format!("Failed to convert {} to USD: {}", token_symbol, e))?;

		Decimal::from_str(&usd_amount_str)
			.map_err(|e| format!("Failed to parse USD amount {}: {}", usd_amount_str, e).into())
	}

	/// Helper to calculate total USD value for a list of inputs
	async fn calculate_inputs_usd_value(
		&self,
		inputs: &[OrderInput],
	) -> Result<Decimal, CostProfitError> {
		let mut total_usd = Decimal::ZERO;

		for input in inputs {
			let chain_id = input.asset.ethereum_chain_id().map_err(|e| {
				CostProfitError::Calculation(format!("Failed to get chain ID: {}", e))
			})?;
			let ethereum_addr = input.asset.ethereum_address().map_err(|e| {
				CostProfitError::Calculation(format!("Failed to get address: {}", e))
			})?;
			let token_address = Address(ethereum_addr.0.to_vec());

			let token_info = self
				.token_manager
				.get_token_info(chain_id, &token_address)?;

			let usd_amount = Self::convert_raw_token_to_usd(
				&input.amount,
				&token_info.symbol,
				token_info.decimals,
				&self.pricing_service,
			)
			.await
			.map_err(|e| CostProfitError::Calculation(e.to_string()))?;

			total_usd += usd_amount;
		}

		Ok(total_usd)
	}

	/// Helper to calculate total USD value for a list of outputs
	async fn calculate_outputs_usd_value(
		&self,
		outputs: &[OrderOutput],
	) -> Result<Decimal, CostProfitError> {
		let mut total_usd = Decimal::ZERO;

		for output in outputs {
			let chain_id = output.asset.ethereum_chain_id().map_err(|e| {
				CostProfitError::Calculation(format!("Failed to get chain ID: {}", e))
			})?;
			let ethereum_addr = output.asset.ethereum_address().map_err(|e| {
				CostProfitError::Calculation(format!("Failed to get address: {}", e))
			})?;
			let token_address = Address(ethereum_addr.0.to_vec());

			let token_info = self
				.token_manager
				.get_token_info(chain_id, &token_address)?;

			let usd_amount = Self::convert_raw_token_to_usd(
				&output.amount,
				&token_info.symbol,
				token_info.decimals,
				&self.pricing_service,
			)
			.await
			.map_err(|e| CostProfitError::Calculation(e.to_string()))?;

			total_usd += usd_amount;
		}

		Ok(total_usd)
	}

	/// Converts a USD amount to token amount in smallest unit
	async fn convert_usd_to_token_amount(
		&self,
		usd_amount: Decimal,
		asset: &solver_types::InteropAddress,
	) -> Result<U256, CostProfitError> {
		// Get token info
		let chain_id = asset
			.ethereum_chain_id()
			.map_err(|e| CostProfitError::Calculation(format!("Failed to get chain ID: {}", e)))?;
		let ethereum_addr = asset.ethereum_address().map_err(|e| {
			CostProfitError::Calculation(format!("Failed to get ethereum address: {}", e))
		})?;
		let token_address = Address(ethereum_addr.0.to_vec());

		let token_info = self
			.token_manager
			.get_token_info(chain_id, &token_address)?;

		// Convert USD to token amount (normalized)
		let token_amount_str = self
			.pricing_service
			.convert_asset("USD", &token_info.symbol, &usd_amount.to_string())
			.await
			.map_err(|e| {
				CostProfitError::Calculation(format!(
					"Failed to convert USD to {}: {}",
					token_info.symbol, e
				))
			})?;

		let token_amount_decimal = Decimal::from_str(&token_amount_str).map_err(|e| {
			CostProfitError::Calculation(format!("Failed to parse token amount: {}", e))
		})?;

		// Convert to smallest unit (apply decimals), rounding up to ensure we collect enough
		// This protects our margin when costs are deducted from outputs or added to inputs
		let multiplier = Decimal::new(10_i64.pow(token_info.decimals as u32), 0);
		let token_amount_in_smallest = token_amount_decimal * multiplier;

		// Ceil to ensure we always collect enough to cover costs after USD->token->USD round-trip
		let token_amount_ceiled = token_amount_in_smallest.ceil();

		// Convert to U256
		let result = U256::from_str(&token_amount_ceiled.to_string()).map_err(|e| {
			CostProfitError::Calculation(format!("Failed to convert ceiled amount to U256: {}", e))
		})?;

		Ok(result)
	}
}

/// Estimates gas units using configuration flows with fallback estimates.
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
