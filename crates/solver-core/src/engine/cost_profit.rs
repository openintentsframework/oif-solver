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
	utils::{conversion::ceil_dp, formatting::format_percentage},
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

/// Result of callback simulation
#[derive(Debug, Clone)]
pub struct CallbackSimulationResult {
	/// Whether callback simulation passed (no revert detected)
	pub success: bool,
	/// Estimated gas units for the fill transaction (includes callback execution)
	pub estimated_gas_units: u64,
	/// Chain ID where the callback will be executed
	pub chain_id: u64,
	/// Whether the order has callback data
	pub has_callback: bool,
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
							CostProfitError::Calculation(format!("Invalid input chain: {e}"))
						})?;
						let input_addr = input.asset.ethereum_address().map_err(|e| {
							CostProfitError::Calculation(format!("Invalid input address: {e}"))
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
							CostProfitError::Calculation(format!("Invalid output chain: {e}"))
						})?;
						let output_addr = output.asset.ethereum_address().map_err(|e| {
							CostProfitError::Calculation(format!("Invalid output address: {e}"))
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
		// Read gas_buffer_bps from solver config (hot-reloadable)
		let gas_buffer_bps_value = config.solver.gas_buffer_bps;

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

		// Calculate gas buffer using config value (hot-reloadable)
		let gas_subtotal = gas_open + gas_fill + gas_claim;
		let gas_buffer_bps = Decimal::new(gas_buffer_bps_value as i64, 0);
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
		self.estimate_cost_for_order_with_gas(order, config, None)
			.await
	}

	/// Estimates the cost for an order with an optional simulated fill gas override.
	///
	/// When `simulated_fill_gas` is provided (from `eth_estimateGas`), it will be used
	/// instead of the config defaults. This provides accurate gas estimation for orders
	/// with callbacks or complex fill logic.
	///
	/// # Arguments
	/// * `order` - The order to estimate costs for
	/// * `config` - Solver configuration
	/// * `simulated_fill_gas` - Optional gas units from simulation (overrides config default)
	pub async fn estimate_cost_for_order_with_gas(
		&self,
		order: &Order,
		config: &Config,
		simulated_fill_gas: Option<u64>,
	) -> Result<CostBreakdown, CostProfitError> {
		// Parse the order data based on its standard
		let order_parsed = order.parse_order_data().map_err(|e| APIError::BadRequest {
			error_type: ApiErrorType::InvalidRequest,
			message: format!("Failed to parse order data: {e}"),
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

		// Estimate gas units (may be overridden by simulated value)
		let mut gas_units = self
			.estimate_gas_units(order, &flow_key, config, origin_chain_id, dest_chain_id)
			.await?;

		// Override fill gas with simulated value if provided and non-zero
		if let Some(simulated_gas) = simulated_fill_gas {
			if simulated_gas > 0 {
				tracing::info!(
					"Using simulated fill gas: {} units (config default was: {} units)",
					simulated_gas,
					gas_units.fill_units
				);
				gas_units.fill_units = simulated_gas;
			}
		}

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
	/// The `intent_source` parameter indicates whether the intent is "on-chain" or "off-chain".
	pub async fn validate_profitability(
		&self,
		order: &Order,
		cost_breakdown: &CostBreakdown,
		min_profitability_pct: Decimal,
		quote_id: Option<&str>,
		intent_source: &str,
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
			message: format!("Failed to parse order data: {e}"),
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
				message: format!("Failed to calculate input USD value: {e}"),
			})?;

		let total_output_value_usd = self
			.calculate_outputs_usd_value(&requested_outputs)
			.await
			.map_err(|e| APIError::InternalServerError {
				error_type: ApiErrorType::InternalError,
				message: format!("Failed to calculate output USD value: {e}"),
			})?;

		// Operational cost is already available in the breakdown
		// For onchain intents, subtract the open cost since it's already paid by the user
		let operational_cost_usd = if intent_source == "on-chain" {
			// On-chain intent: user already paid for the open transaction
			cost_breakdown.operational_cost - cost_breakdown.gas_open
		} else {
			// Off-chain intent: solver will pay for all costs including open
			cost_breakdown.operational_cost
		};

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
			│  │  ├─ Open:            {}\n\
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
			// Cost breakdown - show N/A for gas_open if onchain intent
			if intent_source == "on-chain" {
				"N/A (on-chain intent)".to_string()
			} else {
				format!("$ {:>7.4}", cost_breakdown.gas_open)
			},
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
					"Order accepted with {} profit margin",
					format_percentage(actual_profit_margin)
				)
			} else {
				format!(
					"Order rejected - insufficient margin ({} < {})",
					format_percentage(actual_profit_margin),
					format_percentage(min_profitability_pct)
				)
			}
		);

		// Check if actual profit meets minimum requirement
		if !profit_validation_passed {
			let error_msg = format!(
				"Insufficient profit margin: {actual_profit_margin:.2}% < required {min_profitability_pct:.2}%"
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
			message: format!("Failed to parse order data for fill tx: {e}"),
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
			message: format!("Failed to parse order data for claim tx: {e}"),
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
				message: format!("Failed to get chain data: {e}"),
			})?;

		match U256::from_str_radix(&chain_data.gas_price, 10) {
			Ok(gas_price) => Ok(gas_price),
			Err(_) => Ok(U256::from(DEFAULT_GAS_PRICE_WEI)),
		}
	}

	/// Validates callback safety and simulates fill transaction gas for an order with callbackData.
	///
	/// This method performs:
	/// 1. Whitelist validation for callback recipients
	/// 2. Gas estimation via eth_estimateGas to detect reverts and get accurate gas costs
	///
	/// # Arguments
	/// * `order` - The order to validate
	/// * `fill_tx` - The fill transaction to simulate (generated by OrderService)
	/// * `config` - Solver configuration
	///
	/// # Returns
	/// * `CallbackSimulationResult` containing success status and estimated gas
	pub async fn simulate_callback_and_estimate_gas(
		&self,
		order: &Order,
		fill_tx: &Transaction,
		config: &Config,
	) -> Result<CallbackSimulationResult, CostProfitError> {
		tracing::info!("🔍 Starting callback simulation for order {}", order.id);

		let chain_id = fill_tx.chain_id;

		// Parse order to check for callbacks
		let order_data = order.parse_order_data().map_err(|e| {
			CostProfitError::Calculation(format!("Failed to parse order data: {e}"))
		})?;

		let outputs = order_data.parse_requested_outputs();

		// Currently only single-output orders are supported
		if outputs.len() > 1 {
			return Err(CostProfitError::Calculation(format!(
				"Multiple outputs ({}) not supported. Only single-output orders can be processed",
				outputs.len()
			)));
		}

		let output = outputs
			.first()
			.ok_or_else(|| CostProfitError::Calculation("No outputs found in order".to_string()))?;

		// Check if there's callback data
		let has_callback = output
			.calldata
			.as_ref()
			.is_some_and(|c| !c.is_empty() && c != "0x");

		if !has_callback {
			tracing::info!("✓ No callback data - using default gas estimate");
			// For orders without callbacks, we still estimate gas but don't enforce whitelist
			return self.estimate_fill_gas(fill_tx, chain_id, false).await;
		}

		tracing::info!("⚠️  Order has callback data: {:?}", output.calldata);

		// Check if callback simulation is enabled
		if !config.order.simulate_callbacks {
			tracing::warn!(
				"❌ Order has callback but callback simulation is disabled. \
				Enable 'simulate_callbacks = true' in config to support callbacks."
			);
			return Err(CostProfitError::Config(
				"Order has callback data but callback simulation is disabled. \
				Callbacks are not supported when simulate_callbacks = false in config."
					.to_string(),
			));
		}

		// Extract recipient info for whitelist check
		// The receiver is already an InteropAddress (EIP-7930 format)
		let recipient_interop_hex = output.receiver.to_hex().to_lowercase();

		let output_chain_id = output.receiver.ethereum_chain_id().map_err(|e| {
			CostProfitError::Config(format!("Failed to extract chain ID from recipient: {e}"))
		})?;

		let recipient_eth_address = output
			.receiver
			.ethereum_address()
			.map(|addr| format!("0x{}", alloy_primitives::hex::encode(addr)))
			.unwrap_or_else(|_| "unknown".to_string());

		// Check whitelist using EIP-7930 InteropAddress format
		// Whitelist entries should be in EIP-7930 hex format (e.g., "0x0001000002210514...")
		let is_whitelisted = config
			.order
			.callback_whitelist
			.iter()
			.any(|entry| entry.to_lowercase() == recipient_interop_hex);

		if !is_whitelisted {
			tracing::warn!(
				"❌ Callback recipient {} (chain {}) is NOT whitelisted. InteropAddress: {}",
				recipient_eth_address,
				output_chain_id,
				recipient_interop_hex
			);
			return Err(CostProfitError::Config(format!(
				"Callback recipient {recipient_eth_address} on chain {output_chain_id} not in whitelist. Add '{recipient_interop_hex}' to order.callback_whitelist in config (EIP-7930 format)"
			)));
		}

		tracing::info!(
			"✅ Callback recipient {} (chain {}) is whitelisted - simulating gas",
			recipient_eth_address,
			output_chain_id
		);

		// Simulate the fill transaction to get accurate gas estimate
		self.estimate_fill_gas(fill_tx, chain_id, true).await
	}

	/// Estimates gas for a fill transaction using eth_estimateGas.
	///
	/// This serves two purposes:
	/// 1. Detects if the transaction would revert (callback execution failure)
	/// 2. Gets accurate gas estimate including callback execution cost
	async fn estimate_fill_gas(
		&self,
		fill_tx: &Transaction,
		chain_id: u64,
		has_callback: bool,
	) -> Result<CallbackSimulationResult, CostProfitError> {
		tracing::info!(
			"📊 Estimating gas for fill transaction on chain {} (has_callback: {})",
			chain_id,
			has_callback
		);

		match self
			.delivery_service
			.estimate_gas(chain_id, fill_tx.clone())
			.await
		{
			Ok(estimated_gas) => {
				tracing::info!(
					"✅ Gas estimation successful: {} units (has_callback: {})",
					estimated_gas,
					has_callback
				);
				Ok(CallbackSimulationResult {
					success: true,
					estimated_gas_units: estimated_gas,
					chain_id,
					has_callback,
				})
			},
			Err(e) => {
				let error_msg = e.to_string();
				tracing::warn!("❌ Gas estimation failed (likely revert): {}", error_msg);

				// Check if this is a revert error
				if error_msg.contains("revert")
					|| error_msg.contains("execution reverted")
					|| error_msg.contains("out of gas")
					|| error_msg.contains("insufficient funds")
				{
					Err(CostProfitError::Calculation(format!(
						"Fill transaction simulation failed (callback would revert): {error_msg}"
					)))
				} else {
					// For other errors (network issues, etc.), we might want to retry or use fallback
					tracing::warn!(
						"⚠️  Non-revert error during gas estimation, using fallback: {}",
						error_msg
					);
					// Return success with 0 gas to signal fallback to config default
					Ok(CallbackSimulationResult {
						success: true,
						estimated_gas_units: 0,
						chain_id,
						has_callback,
					})
				}
			},
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
				"Token decimals {token_decimals} exceeds maximum supported precision"
			)
			.into());
		}

		// Convert U256 to Decimal
		let raw_amount_str = raw_amount.to_string();
		let raw_amount_decimal = Decimal::from_str(&raw_amount_str)
			.map_err(|e| format!("Failed to parse raw amount {raw_amount_str}: {e}"))?;

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
			.map_err(|e| format!("Failed to convert {token_symbol} to USD: {e}"))?;

		Decimal::from_str(&usd_amount_str)
			.map_err(|e| format!("Failed to parse USD amount {usd_amount_str}: {e}").into())
	}

	/// Helper to calculate total USD value for a list of inputs
	async fn calculate_inputs_usd_value(
		&self,
		inputs: &[OrderInput],
	) -> Result<Decimal, CostProfitError> {
		let mut total_usd = Decimal::ZERO;

		for input in inputs {
			let chain_id = input.asset.ethereum_chain_id().map_err(|e| {
				CostProfitError::Calculation(format!("Failed to get chain ID: {e}"))
			})?;
			let ethereum_addr = input.asset.ethereum_address().map_err(|e| {
				CostProfitError::Calculation(format!("Failed to get address: {e}"))
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
				CostProfitError::Calculation(format!("Failed to get chain ID: {e}"))
			})?;
			let ethereum_addr = output.asset.ethereum_address().map_err(|e| {
				CostProfitError::Calculation(format!("Failed to get address: {e}"))
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
			.map_err(|e| CostProfitError::Calculation(format!("Failed to get chain ID: {e}")))?;
		let ethereum_addr = asset.ethereum_address().map_err(|e| {
			CostProfitError::Calculation(format!("Failed to get ethereum address: {e}"))
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
			CostProfitError::Calculation(format!("Failed to parse token amount: {e}"))
		})?;

		// Convert to smallest unit (apply decimals), rounding up to ensure we collect enough
		// This protects our margin when costs are deducted from outputs or added to inputs
		let multiplier = Decimal::new(10_i64.pow(token_info.decimals as u32), 0);
		let token_amount_in_smallest = token_amount_decimal * multiplier;

		// Ceil to ensure we always collect enough to cover costs after USD->token->USD round-trip
		let token_amount_ceiled = token_amount_in_smallest.ceil();

		// Convert to U256
		let result = U256::from_str(&token_amount_ceiled.to_string()).map_err(|e| {
			CostProfitError::Calculation(format!("Failed to convert ceiled amount to U256: {e}"))
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

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::address;
	use mockall::predicate::*;
	use solver_account::{AccountService, MockAccountInterface};
	use solver_config::ConfigBuilder;
	use solver_delivery::MockDeliveryInterface;
	use solver_pricing::MockPricingInterface;
	use solver_storage::MockStorageInterface;
	use solver_types::{
		current_timestamp, oif_versions,
		standards::eip7683::{GasLimitOverrides, MandateOutput},
		utils::tests::builders::{NetworkConfigBuilder, NetworksConfigBuilder},
		ChainSettlerInfo, CostContext, Eip7683OrderData, FailureHandlingMode, GetQuoteRequest,
		IntentRequest, IntentType, InteropAddress, NetworksConfig, OifOrder, OrderPayload,
		OrderStatus, Quote, QuoteInput, QuoteOutput, QuotePreference, QuoteWithCostContext,
		SignatureType, SwapType, ValidatedQuoteContext,
	};
	use std::collections::HashMap;
	use std::str::FromStr;
	use std::sync::Arc;
	use tokio;

	// Test price constants for consistent mock pricing across test functions
	const ETH_USD_PRICE: f64 = 4000.0;
	const USDC_USD_PRICE: f64 = 1.0;

	fn create_test_networks_config() -> NetworksConfig {
		let input_token = solver_types::utils::tests::builders::TokenConfigBuilder::new()
			.address({
				// Convert U256::from(1000) to Address - token 1000 = 0x3e8
				let mut addr_bytes = [0u8; 20];
				addr_bytes[18] = 0x03; // 0x03e8 = 1000
				addr_bytes[19] = 0xe8;
				solver_types::Address(addr_bytes.to_vec())
			})
			.symbol("INPUT".to_string())
			.decimals(18)
			.build();
		let output_token = solver_types::utils::tests::builders::TokenConfigBuilder::new()
			.address(solver_types::Address(vec![0u8; 20])) // Zero address for output
			.symbol("OUTPUT".to_string())
			.decimals(18)
			.build();
		NetworksConfigBuilder::new()
			.add_network(
				1,
				NetworkConfigBuilder::new()
					.tokens(vec![input_token])
					.build(),
			)
			.add_network(
				137,
				NetworkConfigBuilder::new()
					.tokens(vec![output_token])
					.build(),
			)
			.build()
	}

	// Helper functions for creating test data
	fn create_test_config() -> Config {
		ConfigBuilder::new()
			.with_min_profitability_pct(Decimal::from_str("5.0").unwrap())
			.build()
	}
	fn create_test_request(is_exact_input: bool) -> GetQuoteRequest {
		GetQuoteRequest {
			user: InteropAddress::new_ethereum(
				1,
				address!("1111111111111111111111111111111111111111"),
			),
			intent: IntentRequest {
				intent_type: IntentType::OifSwap,
				inputs: vec![QuoteInput {
					user: InteropAddress::new_ethereum(
						1,
						address!("1111111111111111111111111111111111111111"),
					),
					asset: InteropAddress::new_ethereum(
						1,
						address!("A0b86a33E6441b8C6A7f4C5C1C5C5C5C5C5C5C5C"),
					),
					amount: if is_exact_input {
						Some(U256::from(1000).to_string()) // For ExactInput, specify input amount
					} else {
						None // For ExactOutput, input amount will be calculated
					},
					lock: None,
				}],
				outputs: vec![QuoteOutput {
					receiver: InteropAddress::new_ethereum(
						137,
						address!("2222222222222222222222222222222222222222"),
					),
					asset: InteropAddress::new_ethereum(
						137,
						address!("B0b86a33E6441b8C6A7f4C5C1C5C5C5C5C5C5C5C"),
					),
					amount: if is_exact_input {
						Some(U256::from(950).to_string()) // For ExactInput, this is estimated
					} else {
						Some(U256::from_str("2000000000").unwrap().to_string()) // For ExactOutput, specify exact output amount (2000 USDC)
					},
					calldata: None,
				}],
				swap_type: None,
				min_valid_until: None,
				preference: Some(QuotePreference::Speed),
				origin_submission: None,
				failure_handling: None,
				partial_fill: None,
				metadata: None,
			},
			supported_types: vec![oif_versions::escrow_order_type("v0")],
		}
	}

	fn create_test_validated_context(is_exact_input: bool) -> ValidatedQuoteContext {
		match is_exact_input {
			true => {
				let input = QuoteInput {
					user: InteropAddress::new_ethereum(
						1,
						address!("1111111111111111111111111111111111111111"),
					),
					asset: InteropAddress::new_ethereum(
						1,
						address!("A0b86a33E6441b8C6A7f4C5C1C5C5C5C5C5C5C5C"),
					),
					amount: Some("1000000000000000000".to_string()), // 1 ETH
					lock: None,
				};
				let input_amount = U256::from_str("1000000000000000000").unwrap();

				ValidatedQuoteContext {
					swap_type: SwapType::ExactInput,
					known_inputs: Some(vec![(input, input_amount)]),
					constraint_inputs: None,
					constraint_outputs: None,
					known_outputs: None,
				}
			},
			false => {
				let output = QuoteOutput {
					receiver: InteropAddress::new_ethereum(
						137,
						address!("2222222222222222222222222222222222222222"),
					),
					asset: InteropAddress::new_ethereum(
						137,
						address!("B0b86a33E6441b8C6A7f4C5C1C5C5C5C5C5C5C5C"),
					),
					amount: Some(U256::from_str("2000000000").unwrap().to_string()), // 2000 USDC (6 decimals)
					calldata: None,
				};
				let output_amount = U256::from_str("2000000000").unwrap();

				ValidatedQuoteContext {
					swap_type: SwapType::ExactOutput,
					known_inputs: None,
					constraint_inputs: None,
					constraint_outputs: None,
					known_outputs: Some(vec![(output, output_amount)]),
				}
			},
		}
	}

	fn create_test_cost_breakdown() -> CostBreakdown {
		CostBreakdown {
			gas_open: Decimal::from_str("0.01").unwrap(),
			gas_fill: Decimal::from_str("0.02").unwrap(),
			gas_claim: Decimal::from_str("0.01").unwrap(),
			gas_buffer: Decimal::from_str("0.004").unwrap(),
			rate_buffer: Decimal::ZERO,
			base_price: Decimal::ZERO,
			min_profit: Decimal::from_str("5.00").unwrap(),
			operational_cost: Decimal::from_str("0.044").unwrap(),
			subtotal: Decimal::from_str("0.044").unwrap(),
			total: Decimal::from_str("0.044").unwrap(),
			currency: "USD".to_string(),
		}
	}

	fn create_test_quote_with_cost_context() -> QuoteWithCostContext {
		QuoteWithCostContext {
			quote: Quote {
				order: OifOrder::OifEscrowV0 {
					payload: OrderPayload {
						signature_type: SignatureType::Eip712,
						domain: serde_json::json!({}),
						primary_type: "Order".to_string(),
						message: serde_json::json!({}),
						types: Some(serde_json::json!({})),
					},
				},
				failure_handling: FailureHandlingMode::RefundAutomatic,
				partial_fill: false,
				valid_until: current_timestamp() + 300,
				eta: Some(60),
				quote_id: "test_quote_123".to_string(),
				provider: Some("test_solver".to_string()),
				preview: solver_types::QuotePreview {
					inputs: vec![],
					outputs: vec![],
				},
			},
			cost_context: CostContext {
				cost_breakdown: create_test_cost_breakdown(),
				execution_costs_by_chain: HashMap::new(),
				liquidity_cost_adjustment: Decimal::ZERO,
				protocol_fees: HashMap::new(),
				swap_type: SwapType::ExactInput,
				cost_amounts_in_tokens: HashMap::new(),
				swap_amounts: HashMap::new(),
				adjusted_amounts: HashMap::new(),
			},
		}
	}

	fn create_mock_pricing_service() -> Arc<PricingService> {
		let mock = MockPricingInterface::new();
		Arc::new(PricingService::new(Box::new(mock), Vec::new()))
	}

	fn create_mock_delivery_service() -> Arc<DeliveryService> {
		let implementations = HashMap::new();
		Arc::new(DeliveryService::new(implementations, 1, 3600))
	}

	fn create_mock_token_manager() -> Arc<TokenManager> {
		Arc::new(TokenManager::new(
			create_test_networks_config(),
			create_mock_delivery_service(),
			create_mock_account_service(),
		))
	}

	fn create_mock_account_service() -> Arc<AccountService> {
		let mut mock_account = MockAccountInterface::new();
		mock_account
			.expect_address()
			.returning(|| Box::pin(async move { Ok(solver_types::Address([0xAB; 20].to_vec())) }));
		mock_account
			.expect_config_schema()
			.returning(|| Box::new(solver_account::implementations::local::LocalWalletSchema));
		mock_account.expect_signer().returning(|| {
			use alloy_signer_local::PrivateKeySigner;
			let signer: PrivateKeySigner =
				"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
					.parse()
					.unwrap();
			solver_account::AccountSigner::Local(signer)
		});

		Arc::new(AccountService::new(Box::new(mock_account)))
	}

	#[tokio::test]
	async fn test_get_cost_context_by_quote_id_success() {
		// Arrange
		let mut mock_storage = MockStorageInterface::new();
		let test_quote_with_context = create_test_quote_with_cost_context();
		let expected_cost_context = test_quote_with_context.cost_context.clone();

		mock_storage
			.expect_get_bytes()
			.with(eq("quotes:test_quote_123"))
			.times(1)
			.returning(move |_| {
				let serialized = serde_json::to_vec(&test_quote_with_context).unwrap();
				Box::pin(async move { Ok(serialized) })
			});

		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let pricing = create_mock_pricing_service();
		let delivery = create_mock_delivery_service();
		let token_manager = create_mock_token_manager();

		let service = CostProfitService::new(pricing, delivery, token_manager, storage);

		// Act
		let result = service.get_cost_context_by_quote_id("test_quote_123").await;

		// Assert
		assert!(result.is_ok());
		let cost_context = result.unwrap();
		assert_eq!(cost_context.swap_type, expected_cost_context.swap_type);
	}

	#[tokio::test]
	async fn test_get_cost_context_by_quote_id_not_found() {
		// Arrange
		let mut mock_storage = MockStorageInterface::new();

		mock_storage
			.expect_get_bytes()
			.with(eq("quotes:nonexistent_quote"))
			.times(1)
			.returning(|_| {
				Box::pin(async move {
					Err(solver_storage::StorageError::NotFound(
						"Quote not found".to_string(),
					))
				})
			});

		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let pricing = create_mock_pricing_service();
		let delivery = create_mock_delivery_service();
		let token_manager = create_mock_token_manager();

		let service = CostProfitService::new(pricing, delivery, token_manager, storage);

		// Act
		let result = service
			.get_cost_context_by_quote_id("nonexistent_quote")
			.await;

		// Assert
		assert!(result.is_err());
		match result.unwrap_err() {
			CostProfitError::Storage(_) => {
				// Expected error type
			},
			other => panic!("Expected Storage error, got: {other:?}"),
		}
	}

	#[tokio::test]
	async fn test_calculate_cost_context_exact_input() {
		// Arrange
		let mut mock_pricing = MockPricingInterface::new();
		let mut mock_delivery = MockDeliveryInterface::new();
		let mock_storage = MockStorageInterface::new();

		// Mock pricing service calls - allow any convert_asset calls
		mock_pricing
			.expect_convert_asset()
			.returning(|from, to, amount| {
				let from = from.to_string();
				let to = to.to_string();
				let amount_f64: f64 = amount.parse().unwrap_or(0.0);
				Box::pin(async move {
					match (from.as_str(), to.as_str()) {
						("ETH", "USD") => Ok((amount_f64 * ETH_USD_PRICE).to_string()),
						("USD", "ETH") => Ok((amount_f64 / ETH_USD_PRICE).to_string()),
						("USDC", "USD") => Ok((amount_f64 * USDC_USD_PRICE).to_string()),
						("USD", "USDC") => Ok((amount_f64 / USDC_USD_PRICE).to_string()),
						_ => Ok("1.0".to_string()),
					}
				})
			});

		mock_pricing
			.expect_wei_to_currency()
			.returning(|_, _| Box::pin(async move { Ok("0.01".to_string()) }));

		// Add config_schema expectation for the mock
		mock_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});

		// Remove duplicate expectations and add proper setup
		mock_delivery
			.expect_get_gas_price()
			.returning(|_| Box::pin(async move { Ok("20000000000".to_string()) }));

		mock_delivery
			.expect_get_block_number()
			.returning(|_| Box::pin(async move { Ok(12345u64) }));

		// Create services with proper delivery implementations
		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));

		// Create delivery service with mock implementations for both chains
		let mut delivery_implementations = HashMap::new();
		delivery_implementations.insert(
			1,
			Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
		);

		// Create a second mock for chain 137
		let mut mock_delivery_137 = MockDeliveryInterface::new();
		mock_delivery_137.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});
		mock_delivery_137
			.expect_get_gas_price()
			.returning(|_| Box::pin(async move { Ok("20000000000".to_string()) }));
		mock_delivery_137
			.expect_get_block_number()
			.returning(|_| Box::pin(async move { Ok(12345u64) }));

		delivery_implementations.insert(
			137,
			Arc::new(mock_delivery_137) as Arc<dyn solver_delivery::DeliveryInterface>,
		);

		let delivery = Arc::new(DeliveryService::new(delivery_implementations, 1, 3600));

		// Create proper token manager with required tokens
		let mut networks = solver_types::NetworksConfig::new();

		// Add chain 1 with ETH token
		let network_1 = solver_types::NetworkConfig {
			rpc_urls: vec![],
			input_settler_address: solver_types::Address([0x11; 20].to_vec()),
			output_settler_address: solver_types::Address([0x22; 20].to_vec()),
			tokens: vec![solver_types::TokenConfig {
				address: solver_types::Address(
					[
						0xA0, 0xb8, 0x6a, 0x33, 0xE6, 0x44, 0x1b, 0x8C, 0x6A, 0x7f, 0x4C, 0x5C,
						0x1C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
					]
					.to_vec(),
				),
				decimals: 18,
				symbol: "ETH".to_string(),
			}],
			input_settler_compact_address: None,
			the_compact_address: None,
			allocator_address: None,
		};
		networks.insert(1, network_1);

		// Add chain 137 with USDC token
		let network_137 = solver_types::NetworkConfig {
			rpc_urls: vec![],
			input_settler_address: solver_types::Address([0x11; 20].to_vec()),
			output_settler_address: solver_types::Address([0x22; 20].to_vec()),
			tokens: vec![solver_types::TokenConfig {
				address: solver_types::Address(
					[
						0xB0, 0xb8, 0x6a, 0x33, 0xE6, 0x44, 0x1b, 0x8C, 0x6A, 0x7f, 0x4C, 0x5C,
						0x1C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
					]
					.to_vec(),
				),
				decimals: 6,
				symbol: "USDC".to_string(),
			}],
			input_settler_compact_address: None,
			the_compact_address: None,
			allocator_address: None,
		};
		networks.insert(137, network_137);

		let token_manager = Arc::new(TokenManager::new(
			networks,
			delivery.clone(),
			create_mock_account_service(),
		));

		// Create services
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));

		let service = CostProfitService::new(pricing, delivery, token_manager, storage);

		let request = create_test_request(true); // true for ExactInput
		let context = create_test_validated_context(true); // true for ExactInput
		let config = create_test_config();

		// Act
		let result = service
			.calculate_cost_context(&request, &context, &config)
			.await;

		// Assert
		assert!(result.is_ok());
		let cost_context = result.unwrap();

		// Verify swap type
		assert_eq!(cost_context.swap_type, SwapType::ExactInput);

		// Verify cost breakdown exists and has reasonable values
		assert!(cost_context.cost_breakdown.total >= Decimal::ZERO);
		assert!(cost_context.cost_breakdown.operational_cost >= Decimal::ZERO);

		// Verify execution costs by chain
		assert!(!cost_context.execution_costs_by_chain.is_empty());

		// Verify swap amounts were calculated
		assert!(!cost_context.swap_amounts.is_empty());

		// Verify adjusted amounts (for ExactInput, outputs should be adjusted down)
		assert!(!cost_context.adjusted_amounts.is_empty());
	}

	#[tokio::test]
	async fn test_calculate_cost_context_exact_output() {
		// Arrange
		let mut mock_pricing = MockPricingInterface::new();
		let mock_storage = MockStorageInterface::new();

		// Mock pricing service calls for reverse conversion (output -> input)
		mock_pricing
			.expect_convert_asset()
			.with(eq("USDC"), eq("USD"), eq("2000"))
			.times(1)
			.returning(|_, _, _| Box::pin(async move { Ok("2000.0".to_string()) }));

		mock_pricing
			.expect_convert_asset()
			.with(eq("USD"), eq("ETH"), eq("2000.0"))
			.times(1)
			.returning(|_, _, _| Box::pin(async move { Ok("1.0".to_string()) }));

		// Additional mock calls that might be needed for cost calculations
		mock_pricing
			.expect_convert_asset()
			.with(eq("ETH"), eq("USD"), eq("1"))
			.returning(|_, _, _| Box::pin(async move { Ok("4000.0".to_string()) }));

		mock_pricing
			.expect_convert_asset()
			.with(eq("USD"), eq("USDC"), eq("4000.0"))
			.returning(|_, _, _| Box::pin(async move { Ok("4000.0".to_string()) }));

		// Allow any additional convert_asset calls
		mock_pricing
			.expect_convert_asset()
			.returning(|from, to, amount| {
				let from = from.to_string();
				let to = to.to_string();
				let amount_f64: f64 = amount.parse().unwrap_or(0.0);
				Box::pin(async move {
					match (from.as_str(), to.as_str()) {
						("ETH", "USD") => Ok((amount_f64 * ETH_USD_PRICE).to_string()),
						("USD", "ETH") => Ok((amount_f64 / ETH_USD_PRICE).to_string()),
						("USDC", "USD") => Ok((amount_f64 * USDC_USD_PRICE).to_string()),
						("USD", "USDC") => Ok((amount_f64 / USDC_USD_PRICE).to_string()),
						_ => Ok("1.0".to_string()),
					}
				})
			});

		mock_pricing
			.expect_wei_to_currency()
			.returning(|_, _| Box::pin(async move { Ok("0.01".to_string()) }));

		// Create mock delivery for chain 1
		let mut mock_delivery_1 = MockDeliveryInterface::new();
		mock_delivery_1.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});
		mock_delivery_1
			.expect_get_gas_price()
			.returning(|_| Box::pin(async move { Ok("20000000000".to_string()) }));
		mock_delivery_1
			.expect_get_block_number()
			.returning(|_| Box::pin(async move { Ok(12345u64) }));

		// Create mock delivery for chain 137
		let mut mock_delivery_137 = MockDeliveryInterface::new();
		mock_delivery_137.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});
		mock_delivery_137
			.expect_get_gas_price()
			.returning(|_| Box::pin(async move { Ok("20000000000".to_string()) }));
		mock_delivery_137
			.expect_get_block_number()
			.returning(|_| Box::pin(async move { Ok(12345u64) }));

		// Create delivery service with mock implementations for both chains
		let mut delivery_implementations = HashMap::new();
		delivery_implementations.insert(
			1,
			Arc::new(mock_delivery_1) as Arc<dyn solver_delivery::DeliveryInterface>,
		);
		delivery_implementations.insert(
			137,
			Arc::new(mock_delivery_137) as Arc<dyn solver_delivery::DeliveryInterface>,
		);

		let delivery = Arc::new(DeliveryService::new(delivery_implementations, 1, 3600));

		// Create proper token manager with required tokens
		let mut networks = solver_types::NetworksConfig::new();

		// Add chain 1 with ETH token
		let network_1 = solver_types::NetworkConfig {
			rpc_urls: vec![],
			input_settler_address: solver_types::Address([0x11; 20].to_vec()),
			output_settler_address: solver_types::Address([0x22; 20].to_vec()),
			tokens: vec![solver_types::TokenConfig {
				address: solver_types::Address(
					[
						0xA0, 0xb8, 0x6a, 0x33, 0xE6, 0x44, 0x1b, 0x8C, 0x6A, 0x7f, 0x4C, 0x5C,
						0x1C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
					]
					.to_vec(),
				),
				decimals: 18,
				symbol: "ETH".to_string(),
			}],
			input_settler_compact_address: None,
			the_compact_address: None,
			allocator_address: None,
		};
		networks.insert(1, network_1);

		// Add chain 137 with USDC token
		let network_137 = solver_types::NetworkConfig {
			rpc_urls: vec![],
			input_settler_address: solver_types::Address([0x11; 20].to_vec()),
			output_settler_address: solver_types::Address([0x22; 20].to_vec()),
			tokens: vec![solver_types::TokenConfig {
				address: solver_types::Address(
					[
						0xB0, 0xb8, 0x6a, 0x33, 0xE6, 0x44, 0x1b, 0x8C, 0x6A, 0x7f, 0x4C, 0x5C,
						0x1C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
					]
					.to_vec(),
				),
				decimals: 6,
				symbol: "USDC".to_string(),
			}],
			input_settler_compact_address: None,
			the_compact_address: None,
			allocator_address: None,
		};
		networks.insert(137, network_137);

		let token_manager = Arc::new(TokenManager::new(
			networks,
			delivery.clone(),
			create_mock_account_service(),
		));

		// Create services
		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));

		let service = CostProfitService::new(pricing, delivery, token_manager, storage);

		// Create test request for ExactOutput
		let request = create_test_request(false); // false for ExactOutput
		let context = create_test_validated_context(false); // false for ExactOutput
		let config = create_test_config();

		// Act
		let result = service
			.calculate_cost_context(&request, &context, &config)
			.await;

		// Assert
		assert!(result.is_ok());
		let cost_context = result.unwrap();

		// Verify swap type
		assert_eq!(cost_context.swap_type, SwapType::ExactOutput);

		// Verify cost breakdown exists and has reasonable values
		assert!(cost_context.cost_breakdown.total >= Decimal::ZERO);
		assert!(cost_context.cost_breakdown.operational_cost >= Decimal::ZERO);

		// Verify execution costs by chain
		assert!(!cost_context.execution_costs_by_chain.is_empty());

		// Verify swap amounts were calculated
		assert!(!cost_context.swap_amounts.is_empty());

		// Verify adjusted amounts (for ExactOutput, inputs should be adjusted up)
		assert!(!cost_context.adjusted_amounts.is_empty());

		// The adjusted amount should be higher than the swap amount for inputs in ExactOutput
		for (token, adjusted_info) in &cost_context.adjusted_amounts {
			if let Some(swap_info) = cost_context.swap_amounts.get(token) {
				if let Some(cost_info) = cost_context.cost_amounts_in_tokens.get(token) {
					// For ExactOutput inputs: adjusted = swap + cost
					let expected_adjusted = swap_info.amount.saturating_add(cost_info.amount);
					assert_eq!(adjusted_info.amount, expected_adjusted);
				}
			}
		}
	}

	// ============================================================================
	// Profitability Validation Tests
	// ============================================================================

	// Helpers for profitability validation
	fn create_test_order_with_amounts(input_amount: U256, output_amount: U256) -> Order {
		// Create EIP-7683 order data
		let eip7683_data = Eip7683OrderData {
			user: "0x1111111111111111111111111111111111111111".to_string(),
			nonce: U256::from(1),
			origin_chain_id: U256::from(1),
			expires: (current_timestamp() + 3600) as u32,
			fill_deadline: (current_timestamp() + 300) as u32,
			input_oracle: "0x0000000000000000000000000000000000000000".to_string(),
			inputs: vec![[
				// Use the INPUT token address from create_test_networks_config (0x3e8 = 1000)
				U256::from(1000),
				input_amount, // amount
			]],
			order_id: [1u8; 32],
			gas_limit_overrides: GasLimitOverrides::default(),
			outputs: vec![MandateOutput {
				oracle: [0u8; 32],  // Zero oracle for test
				settler: [0u8; 32], // Zero settler for test
				token: [0u8; 32],   // Use zero address for OUTPUT token
				amount: output_amount,
				recipient: U256::from_str("0x2222222222222222222222222222222222222222")
					.unwrap()
					.to_be_bytes(),
				chain_id: U256::from(137),
				call: vec![],
				context: vec![], // Empty context for test
			}],
			raw_order_data: None,
			signature: None,
			sponsor: None,
			lock_type: None,
		};

		Order {
			id: "test_order_id".to_string(),
			standard: "eip7683".to_string(),
			created_at: current_timestamp(),
			updated_at: current_timestamp(),
			status: OrderStatus::Created,
			data: serde_json::to_value(eip7683_data).unwrap(),
			solver_address: solver_types::Address([0xAB; 20].to_vec()),
			quote_id: Some("test_quote_id".to_string()),
			input_chains: vec![ChainSettlerInfo {
				chain_id: 1,
				settler_address: solver_types::Address([0x11; 20].to_vec()),
			}],
			output_chains: vec![ChainSettlerInfo {
				chain_id: 137,
				settler_address: solver_types::Address([0x22; 20].to_vec()),
			}],
			execution_params: None,
			prepare_tx_hash: None,
			fill_tx_hash: None,
			post_fill_tx_hash: None,
			pre_claim_tx_hash: None,
			claim_tx_hash: None,
			fill_proof: None,
		}
	}

	fn create_profitable_order() -> Order {
		// Input: 1 INPUT (~$4000), Output: 3900 OUTPUT = $100 profit (2.5% margin)
		create_test_order_with_amounts(
			U256::from_str("1000000000000000000").unwrap(), // 1 INPUT (18 decimals)
			U256::from_str("3900000000000000000000").unwrap(), // 3900 OUTPUT (18 decimals)
		)
	}

	fn create_unprofitable_order() -> Order {
		// Input: 1 INPUT (~$4000), Output: 3990 OUTPUT = -$34 loss (considering $44 operational cost)
		create_test_order_with_amounts(
			U256::from_str("1000000000000000000").unwrap(), // 1 INPUT (18 decimals)
			U256::from_str("3990000000000000000000").unwrap(), // 3990 OUTPUT (18 decimals)
		)
	}

	fn create_zero_value_order() -> Order {
		// Both input and output are zero
		create_test_order_with_amounts(U256::ZERO, U256::ZERO)
	}

	fn create_test_cost_breakdown_with_profit(min_profit: Decimal) -> CostBreakdown {
		CostBreakdown {
			gas_open: Decimal::from_str("0.01").unwrap(),
			gas_fill: Decimal::from_str("0.02").unwrap(),
			gas_claim: Decimal::from_str("0.01").unwrap(),
			gas_buffer: Decimal::from_str("0.004").unwrap(),
			rate_buffer: Decimal::ZERO,
			base_price: Decimal::ZERO,
			min_profit,
			operational_cost: Decimal::from_str("0.044").unwrap(),
			subtotal: Decimal::from_str("0.044").unwrap(),
			total: Decimal::from_str("0.044").unwrap(),
			currency: "USD".to_string(),
		}
	}

	fn create_cost_context_with_swap_type(swap_type: SwapType) -> CostContext {
		CostContext {
			cost_breakdown: create_test_cost_breakdown_with_profit(
				Decimal::from_str("200.0").unwrap(),
			),
			execution_costs_by_chain: HashMap::new(),
			liquidity_cost_adjustment: Decimal::ZERO,
			protocol_fees: HashMap::new(),
			swap_type,
			cost_amounts_in_tokens: HashMap::new(),
			swap_amounts: HashMap::new(),
			adjusted_amounts: HashMap::new(),
		}
	}

	async fn setup_profitable_mocks() -> (
		Arc<PricingService>,
		Arc<DeliveryService>,
		Arc<TokenManager>,
		Arc<StorageService>,
	) {
		let mut mock_pricing = MockPricingInterface::new();
		let mock_storage = MockStorageInterface::new();

		// Mock INPUT to USD conversion (1 INPUT = $4000)
		mock_pricing
			.expect_convert_asset()
			.with(eq("INPUT"), eq("USD"), eq("1"))
			.returning(|_, _, _| Box::pin(async move { Ok("4000.0".to_string()) }));

		// Mock OUTPUT to USD conversion (normalized amount)
		mock_pricing
			.expect_convert_asset()
			.with(eq("OUTPUT"), eq("USD"), eq("3900"))
			.returning(|_, _, _| Box::pin(async move { Ok("3900.0".to_string()) }));

		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));
		let delivery = create_mock_delivery_service();
		let token_manager = create_mock_token_manager();
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));

		(pricing, delivery, token_manager, storage)
	}

	async fn setup_unprofitable_mocks() -> (
		Arc<PricingService>,
		Arc<DeliveryService>,
		Arc<TokenManager>,
		Arc<StorageService>,
	) {
		let mut mock_pricing = MockPricingInterface::new();
		let mock_storage = MockStorageInterface::new();

		// Mock INPUT to USD conversion (1 INPUT = $4000)
		mock_pricing
			.expect_convert_asset()
			.with(eq("INPUT"), eq("USD"), eq("1"))
			.returning(|_, _, _| Box::pin(async move { Ok("4000.0".to_string()) }));

		// Mock OUTPUT to USD conversion - higher output (less profitable)
		mock_pricing
			.expect_convert_asset()
			.with(eq("OUTPUT"), eq("USD"), eq("3990"))
			.returning(|_, _, _| Box::pin(async move { Ok("3990.0".to_string()) }));

		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));
		let delivery = create_mock_delivery_service();
		let token_manager = create_mock_token_manager();
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));

		(pricing, delivery, token_manager, storage)
	}

	// ============================================================================
	// Basic Profitability Scenarios
	// ============================================================================

	#[tokio::test]
	async fn test_validate_profitability_profitable_order() {
		// Arrange
		let (pricing, delivery, token_manager, storage) = setup_profitable_mocks().await;
		let service = CostProfitService::new(pricing, delivery, token_manager, storage);

		let order = create_profitable_order();
		let cost_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		let min_profitability_pct = Decimal::from_str("2.0").unwrap(); // 2% minimum

		// Act
		let result = service
			.validate_profitability(
				&order,
				&cost_breakdown,
				min_profitability_pct,
				None,
				"off-chain",
			)
			.await;

		// Assert
		match result {
			Ok(actual_margin) => {
				assert!(actual_margin >= min_profitability_pct);
			},
			Err(e) => {
				panic!("Expected success but got error: {e:?}");
			},
		}
	}

	#[tokio::test]
	async fn test_validate_profitability_unprofitable_order() {
		let (pricing, delivery, token_manager, storage) = setup_unprofitable_mocks().await;
		let service = CostProfitService::new(pricing, delivery, token_manager, storage);

		let order = create_unprofitable_order();
		let cost_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		let min_profitability_pct = Decimal::from_str("5.0").unwrap(); // 5% minimum

		// Act
		let result = service
			.validate_profitability(
				&order,
				&cost_breakdown,
				min_profitability_pct,
				None,
				"off-chain",
			)
			.await;

		assert!(result.is_err());
		match result.unwrap_err() {
			APIError::UnprocessableEntity {
				error_type,
				message,
				..
			} => {
				assert_eq!(error_type, ApiErrorType::InsufficientProfitability);
				assert!(message.contains("Insufficient profit margin"));
			},
			other => panic!("Expected UnprocessableEntity error, got: {other:?}"),
		}
	}

	// ============================================================================
	// Swap Type Variations
	// ============================================================================

	#[tokio::test]
	async fn test_validate_profitability_exact_input_with_context() {
		// Arrange
		let mut mock_storage = MockStorageInterface::new();
		let test_quote_with_context = QuoteWithCostContext {
			quote: Quote {
				order: OifOrder::OifEscrowV0 {
					payload: OrderPayload {
						signature_type: SignatureType::Eip712,
						domain: serde_json::json!({}),
						primary_type: "Order".to_string(),
						message: serde_json::json!({}),
						types: Some(serde_json::json!({})),
					},
				},
				failure_handling: FailureHandlingMode::RefundAutomatic,
				partial_fill: false,
				valid_until: current_timestamp() + 300,
				eta: Some(60),
				quote_id: "test_quote_exact_input".to_string(),
				provider: Some("test_solver".to_string()),
				preview: solver_types::QuotePreview {
					inputs: vec![],
					outputs: vec![],
				},
			},
			cost_context: create_cost_context_with_swap_type(SwapType::ExactInput),
		};

		mock_storage
			.expect_get_bytes()
			.with(eq("quotes:test_quote_exact_input"))
			.returning(move |_| {
				let serialized = serde_json::to_vec(&test_quote_with_context).unwrap();
				Box::pin(async move { Ok(serialized) })
			});

		let (pricing, delivery, token_manager, _) = setup_profitable_mocks().await;
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let service = CostProfitService::new(pricing, delivery, token_manager, storage);

		let order = create_profitable_order();
		let cost_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		let min_profitability_pct = Decimal::from_str("2.0").unwrap();

		// Act - with quote context for ExactInput
		let result = service
			.validate_profitability(
				&order,
				&cost_breakdown,
				min_profitability_pct,
				Some("test_quote_exact_input"),
				"off-chain",
			)
			.await;

		// Assert
		assert!(result.is_ok());
		let actual_margin = result.unwrap();
		assert!(actual_margin >= min_profitability_pct);
	}

	#[tokio::test]
	async fn test_validate_profitability_exact_output_with_context() {
		// Arrange
		let mut mock_storage = MockStorageInterface::new();
		let test_quote_with_context = QuoteWithCostContext {
			quote: Quote {
				order: OifOrder::OifEscrowV0 {
					payload: OrderPayload {
						signature_type: SignatureType::Eip712,
						domain: serde_json::json!({}),
						primary_type: "Order".to_string(),
						message: serde_json::json!({}),
						types: Some(serde_json::json!({})),
					},
				},
				failure_handling: FailureHandlingMode::RefundAutomatic,
				partial_fill: false,
				valid_until: current_timestamp() + 300,
				eta: Some(60),
				quote_id: "test_quote_exact_output".to_string(),
				provider: Some("test_solver".to_string()),
				preview: solver_types::QuotePreview {
					inputs: vec![],
					outputs: vec![],
				},
			},
			cost_context: create_cost_context_with_swap_type(SwapType::ExactOutput),
		};

		mock_storage
			.expect_get_bytes()
			.with(eq("quotes:test_quote_exact_output"))
			.returning(move |_| {
				let serialized = serde_json::to_vec(&test_quote_with_context).unwrap();
				Box::pin(async move { Ok(serialized) })
			});

		let (pricing, delivery, token_manager, _) = setup_profitable_mocks().await;
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let service = CostProfitService::new(pricing, delivery, token_manager, storage);

		let order = create_profitable_order();
		let cost_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		let min_profitability_pct = Decimal::from_str("2.0").unwrap();

		// Act - with quote context for ExactOutput
		let result = service
			.validate_profitability(
				&order,
				&cost_breakdown,
				min_profitability_pct,
				Some("test_quote_exact_output"),
				"off-chain",
			)
			.await;

		// Assert
		assert!(result.is_ok());
		let actual_margin = result.unwrap();
		assert!(actual_margin >= min_profitability_pct);
	}

	// ============================================================================
	// Intent Source Handling
	// ============================================================================

	#[tokio::test]
	async fn test_validate_profitability_onchain_intent() {
		// Arrange
		let (pricing, delivery, token_manager, storage) = setup_profitable_mocks().await;
		let service = CostProfitService::new(pricing, delivery, token_manager, storage);

		let order = create_profitable_order();
		let cost_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		let min_profitability_pct = Decimal::from_str("2.0").unwrap();

		// On-chain intent (gas_open cost already paid by user)
		let result = service
			.validate_profitability(
				&order,
				&cost_breakdown,
				min_profitability_pct,
				None,
				"on-chain",
			)
			.await;

		// Assert
		assert!(result.is_ok());
		let actual_margin = result.unwrap();
		// Should be higher than off-chain because gas_open is not deducted
		assert!(actual_margin >= min_profitability_pct);
	}

	#[tokio::test]
	async fn test_validate_profitability_offchain_intent() {
		// Arrange
		let (pricing, delivery, token_manager, storage) = setup_profitable_mocks().await;
		let service = CostProfitService::new(pricing, delivery, token_manager, storage);

		let order = create_profitable_order();
		let cost_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		let min_profitability_pct = Decimal::from_str("2.0").unwrap();

		// Off-chain intent (solver pays all costs including gas_open)
		let result = service
			.validate_profitability(
				&order,
				&cost_breakdown,
				min_profitability_pct,
				None,
				"off-chain",
			)
			.await;

		// Assert
		assert!(result.is_ok());
		let actual_margin = result.unwrap();
		assert!(actual_margin >= min_profitability_pct);
	}

	// ============================================================================
	// Error Scenarios & Edge Cases
	// ============================================================================

	#[tokio::test]
	async fn test_validate_profitability_zero_transaction_value() {
		// Arrange
		let mut mock_pricing = MockPricingInterface::new();
		let mock_storage = MockStorageInterface::new();

		// Mock zero conversions
		mock_pricing
			.expect_convert_asset()
			.returning(|_, _, _| Box::pin(async move { Ok("0.0".to_string()) }));

		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));
		let delivery = create_mock_delivery_service();
		let token_manager = create_mock_token_manager();
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));

		let service = CostProfitService::new(pricing, delivery, token_manager, storage);

		let order = create_zero_value_order();
		let cost_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		let min_profitability_pct = Decimal::from_str("5.0").unwrap();

		// Act
		let result = service
			.validate_profitability(
				&order,
				&cost_breakdown,
				min_profitability_pct,
				None,
				"off-chain",
			)
			.await;

		// Assert
		assert!(result.is_err());
		match result.unwrap_err() {
			APIError::BadRequest {
				error_type,
				message,
				..
			} => {
				assert_eq!(error_type, ApiErrorType::InvalidRequest);
				assert!(message.contains("zero transaction value"));
			},
			other => panic!("Expected BadRequest error, got: {other:?}"),
		}
	}

	#[tokio::test]
	async fn test_validate_profitability_order_parsing_failure() {
		// Arrange
		let (pricing, delivery, token_manager, storage) = setup_profitable_mocks().await;
		let service = CostProfitService::new(pricing, delivery, token_manager, storage);

		// Create invalid order with malformed JSON
		let mut invalid_order = create_profitable_order();
		// Directly set invalid data structure (missing required EIP-7683 fields)
		invalid_order.data = serde_json::json!({
			"invalid": "structure"
			// Missing required fields like user, nonce, origin_chain_id, etc.
		});

		let cost_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		let min_profitability_pct = Decimal::from_str("5.0").unwrap();

		// Act
		let result = service
			.validate_profitability(
				&invalid_order,
				&cost_breakdown,
				min_profitability_pct,
				None,
				"off-chain",
			)
			.await;

		// Assert
		assert!(result.is_err());
		match result.unwrap_err() {
			APIError::BadRequest {
				error_type,
				message,
				..
			} => {
				assert_eq!(error_type, ApiErrorType::InvalidRequest);
				assert!(message.contains("Failed to parse order data"));
			},
			other => panic!("Expected BadRequest error, got: {other:?}"),
		}
	}

	#[tokio::test]
	async fn test_validate_profitability_pricing_service_failure() {
		// Arrange
		let mut mock_pricing = MockPricingInterface::new();
		let mock_storage = MockStorageInterface::new();

		// Mock pricing service failure
		mock_pricing.expect_convert_asset().returning(|_, _, _| {
			Box::pin(async move {
				Err(solver_types::PricingError::InvalidData(
					"Pricing service unavailable".to_string(),
				))
			})
		});

		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));
		let delivery = create_mock_delivery_service();
		let token_manager = create_mock_token_manager();
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));

		let service = CostProfitService::new(pricing, delivery, token_manager, storage);

		let order = create_profitable_order();
		let cost_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		let min_profitability_pct = Decimal::from_str("5.0").unwrap();

		// Act
		let result = service
			.validate_profitability(
				&order,
				&cost_breakdown,
				min_profitability_pct,
				None,
				"off-chain",
			)
			.await;

		// Assert
		assert!(result.is_err());
		match result.unwrap_err() {
			APIError::InternalServerError {
				error_type,
				message,
				..
			} => {
				assert_eq!(error_type, ApiErrorType::InternalError);
				assert!(message.contains("Failed to calculate"));
			},
			other => panic!("Expected InternalServerError error, got: {other:?}"),
		}
	}

	// ============================================================================
	// Quote Context Scenarios
	// ============================================================================

	#[tokio::test]
	async fn test_validate_profitability_missing_quote_context() {
		// Arrange
		let mut mock_storage = MockStorageInterface::new();

		// Mock quote not found
		mock_storage
			.expect_get_bytes()
			.with(eq("quotes:nonexistent_quote"))
			.returning(|_| {
				Box::pin(async move {
					Err(solver_storage::StorageError::NotFound(
						"Quote not found".to_string(),
					))
				})
			});

		let (pricing, delivery, token_manager, _) = setup_profitable_mocks().await;
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let service = CostProfitService::new(pricing, delivery, token_manager, storage);

		let order = create_profitable_order();
		let cost_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		let min_profitability_pct = Decimal::from_str("2.0").unwrap();

		// Act - quote ID provided but not found (should still work, just without context)
		let result = service
			.validate_profitability(
				&order,
				&cost_breakdown,
				min_profitability_pct,
				Some("nonexistent_quote"),
				"off-chain",
			)
			.await;

		// Assert
		assert!(result.is_ok());
		// Should fall back to using max of input/output value as transaction base
	}

	#[tokio::test]
	async fn test_validate_profitability_without_quote_context() {
		// Arrange
		let (pricing, delivery, token_manager, storage) = setup_profitable_mocks().await;
		let service = CostProfitService::new(pricing, delivery, token_manager, storage);

		let order = create_profitable_order();
		let cost_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		let min_profitability_pct = Decimal::from_str("2.0").unwrap();

		// No quote ID provided (direct order submission)
		let result = service
			.validate_profitability(
				&order,
				&cost_breakdown,
				min_profitability_pct,
				None,
				"off-chain",
			)
			.await;

		// Assert
		assert!(result.is_ok());
		let actual_margin = result.unwrap();
		assert!(actual_margin >= min_profitability_pct);
	}

	#[tokio::test]
	async fn test_validate_profitability_high_margin_order() {
		// Arrange
		let mut mock_pricing = MockPricingInterface::new();
		let mock_storage = MockStorageInterface::new();

		// Very profitable scenario: Input $4000, Output $3000 = $1000 spread
		mock_pricing
			.expect_convert_asset()
			.with(eq("INPUT"), eq("USD"), eq("1"))
			.returning(|_, _, _| Box::pin(async move { Ok("4000.0".to_string()) }));

		mock_pricing
			.expect_convert_asset()
			.with(eq("OUTPUT"), eq("USD"), eq("3000"))
			.returning(|_, _, _| Box::pin(async move { Ok("3000.0".to_string()) }));

		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));
		let delivery = create_mock_delivery_service();
		let token_manager = create_mock_token_manager();
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));

		let service = CostProfitService::new(pricing, delivery, token_manager, storage);

		let order = create_test_order_with_amounts(
			U256::from_str("1000000000000000000").unwrap(), // 1 INPUT
			U256::from_str("3000000000000000000000").unwrap(), // 3000 OUTPUT (18 decimals)
		);
		let cost_breakdown =
			create_test_cost_breakdown_with_profit(Decimal::from_str("200.0").unwrap());
		let min_profitability_pct = Decimal::from_str("5.0").unwrap();

		// Act
		let result = service
			.validate_profitability(
				&order,
				&cost_breakdown,
				min_profitability_pct,
				None,
				"off-chain",
			)
			.await;

		// Assert
		assert!(result.is_ok());
		let actual_margin = result.unwrap();
		// Should be much higher than minimum
		assert!(actual_margin > Decimal::from_str("20.0").unwrap());
	}

	// ============================================================================
	// Callback Gas Simulation Tests
	// ============================================================================

	fn create_order_with_callback(callback_data: Vec<u8>) -> Order {
		let eip7683_data = Eip7683OrderData {
			user: "0x1111111111111111111111111111111111111111".to_string(),
			nonce: U256::from(1),
			origin_chain_id: U256::from(1),
			expires: (current_timestamp() + 3600) as u32,
			fill_deadline: (current_timestamp() + 300) as u32,
			input_oracle: "0x0000000000000000000000000000000000000000".to_string(),
			inputs: vec![[U256::from(1000), U256::from(1000000)]],
			order_id: [1u8; 32],
			gas_limit_overrides: GasLimitOverrides::default(),
			outputs: vec![MandateOutput {
				oracle: [0u8; 32],
				settler: [0u8; 32],
				token: [0u8; 32],
				amount: U256::from(1000000),
				recipient: U256::from_str("0x2222222222222222222222222222222222222222")
					.unwrap()
					.to_be_bytes(),
				chain_id: U256::from(137),
				call: callback_data,
				context: vec![],
			}],
			raw_order_data: None,
			signature: None,
			sponsor: None,
			lock_type: None,
		};

		Order {
			id: "test_callback_order".to_string(),
			standard: "eip7683".to_string(),
			created_at: current_timestamp(),
			updated_at: current_timestamp(),
			status: OrderStatus::Created,
			data: serde_json::to_value(eip7683_data).unwrap(),
			solver_address: solver_types::Address([0xAB; 20].to_vec()),
			quote_id: None,
			input_chains: vec![ChainSettlerInfo {
				chain_id: 1,
				settler_address: solver_types::Address([0x11; 20].to_vec()),
			}],
			output_chains: vec![ChainSettlerInfo {
				chain_id: 137,
				settler_address: solver_types::Address([0x22; 20].to_vec()),
			}],
			execution_params: None,
			prepare_tx_hash: None,
			fill_tx_hash: None,
			post_fill_tx_hash: None,
			pre_claim_tx_hash: None,
			claim_tx_hash: None,
			fill_proof: None,
		}
	}

	fn create_order_with_multiple_outputs() -> Order {
		let eip7683_data = Eip7683OrderData {
			user: "0x1111111111111111111111111111111111111111".to_string(),
			nonce: U256::from(1),
			origin_chain_id: U256::from(1),
			expires: (current_timestamp() + 3600) as u32,
			fill_deadline: (current_timestamp() + 300) as u32,
			input_oracle: "0x0000000000000000000000000000000000000000".to_string(),
			inputs: vec![[U256::from(1000), U256::from(1000000)]],
			order_id: [1u8; 32],
			gas_limit_overrides: GasLimitOverrides::default(),
			outputs: vec![
				MandateOutput {
					oracle: [0u8; 32],
					settler: [0u8; 32],
					token: [0u8; 32],
					amount: U256::from(500000),
					recipient: U256::from_str("0x2222222222222222222222222222222222222222")
						.unwrap()
						.to_be_bytes(),
					chain_id: U256::from(137),
					call: vec![],
					context: vec![],
				},
				MandateOutput {
					oracle: [0u8; 32],
					settler: [0u8; 32],
					token: [0u8; 32],
					amount: U256::from(500000),
					recipient: U256::from_str("0x3333333333333333333333333333333333333333")
						.unwrap()
						.to_be_bytes(),
					chain_id: U256::from(42161), // Different chain
					call: vec![],
					context: vec![],
				},
			],
			raw_order_data: None,
			signature: None,
			sponsor: None,
			lock_type: None,
		};

		Order {
			id: "test_multi_output_order".to_string(),
			standard: "eip7683".to_string(),
			created_at: current_timestamp(),
			updated_at: current_timestamp(),
			status: OrderStatus::Created,
			data: serde_json::to_value(eip7683_data).unwrap(),
			solver_address: solver_types::Address([0xAB; 20].to_vec()),
			quote_id: None,
			input_chains: vec![ChainSettlerInfo {
				chain_id: 1,
				settler_address: solver_types::Address([0x11; 20].to_vec()),
			}],
			output_chains: vec![
				ChainSettlerInfo {
					chain_id: 137,
					settler_address: solver_types::Address([0x22; 20].to_vec()),
				},
				ChainSettlerInfo {
					chain_id: 42161,
					settler_address: solver_types::Address([0x33; 20].to_vec()),
				},
			],
			execution_params: None,
			prepare_tx_hash: None,
			fill_tx_hash: None,
			post_fill_tx_hash: None,
			pre_claim_tx_hash: None,
			claim_tx_hash: None,
			fill_proof: None,
		}
	}

	fn create_test_fill_transaction() -> Transaction {
		Transaction {
			to: Some(solver_types::Address([0x22; 20].to_vec())),
			data: vec![0xde, 0xad, 0xbe, 0xef],
			value: U256::ZERO,
			chain_id: 137,
			nonce: None,
			gas_limit: None,
			gas_price: None,
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
		}
	}

	fn create_config_with_callback_whitelist(whitelist: Vec<String>) -> Config {
		let mut config = create_test_config();
		config.order.callback_whitelist = whitelist;
		config.order.simulate_callbacks = true;
		config
	}

	#[tokio::test]
	async fn test_simulate_callback_no_callback_data() {
		// Arrange
		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});
		mock_delivery
			.expect_estimate_gas()
			.returning(|_| Box::pin(async move { Ok(75000u64) }));

		let mut delivery_implementations = HashMap::new();
		delivery_implementations.insert(
			137,
			Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
		);
		let delivery = Arc::new(DeliveryService::new(delivery_implementations, 137, 3600));

		let mock_pricing = MockPricingInterface::new();
		let mock_storage = MockStorageInterface::new();
		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let token_manager = create_mock_token_manager();

		let service = CostProfitService::new(pricing, delivery, token_manager, storage);

		let order = create_order_with_callback(vec![]); // Empty callback
		let fill_tx = create_test_fill_transaction();
		let config = create_config_with_callback_whitelist(vec![]);

		// Act
		let result = service
			.simulate_callback_and_estimate_gas(&order, &fill_tx, &config)
			.await;

		// Assert
		assert!(result.is_ok());
		let simulation_result = result.unwrap();
		assert!(!simulation_result.has_callback);
		assert_eq!(simulation_result.estimated_gas_units, 75000);
		assert_eq!(simulation_result.chain_id, 137);
	}

	#[tokio::test]
	async fn test_simulate_callback_with_callback_data_whitelisted() {
		// Arrange
		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});
		mock_delivery
			.expect_estimate_gas()
			.returning(|_| Box::pin(async move { Ok(95000u64) }));

		let mut delivery_implementations = HashMap::new();
		delivery_implementations.insert(
			137,
			Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
		);
		let delivery = Arc::new(DeliveryService::new(delivery_implementations, 137, 3600));

		let mock_pricing = MockPricingInterface::new();
		let mock_storage = MockStorageInterface::new();
		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let token_manager = create_mock_token_manager();

		let service = CostProfitService::new(pricing, delivery, token_manager, storage);

		// Callback data: some arbitrary bytes
		let callback_data = vec![0xde, 0xad, 0xbe, 0xef];
		let order = create_order_with_callback(callback_data);
		let fill_tx = create_test_fill_transaction();

		// Whitelist the recipient (chain 137, recipient from order)
		// The recipient in the order is 0x2222...2222
		// EIP-7930 format: Version(2) | ChainType(2) | ChainRefLen(1) | ChainRef | AddrLen(1) | Address
		// For chain 137 (0x89): 0x0001 | 0x0000 | 0x01 | 0x89 | 0x14 | <20-byte address>
		let whitelist =
			vec!["0x000100000189142222222222222222222222222222222222222222".to_lowercase()];
		let config = create_config_with_callback_whitelist(whitelist);

		// Act
		let result = service
			.simulate_callback_and_estimate_gas(&order, &fill_tx, &config)
			.await;

		// Assert
		assert!(result.is_ok());
		let simulation_result = result.unwrap();
		assert!(simulation_result.has_callback);
		assert_eq!(simulation_result.estimated_gas_units, 95000);
	}

	#[tokio::test]
	async fn test_simulate_callback_not_whitelisted() {
		// Arrange
		let mock_delivery = MockDeliveryInterface::new();
		let mut delivery_implementations = HashMap::new();
		delivery_implementations.insert(
			137,
			Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
		);
		let delivery = Arc::new(DeliveryService::new(delivery_implementations, 137, 3600));

		let mock_pricing = MockPricingInterface::new();
		let mock_storage = MockStorageInterface::new();
		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let token_manager = create_mock_token_manager();

		let service = CostProfitService::new(pricing, delivery, token_manager, storage);

		let callback_data = vec![0xde, 0xad, 0xbe, 0xef];
		let order = create_order_with_callback(callback_data);
		let fill_tx = create_test_fill_transaction();

		// Empty whitelist - recipient not whitelisted
		let config = create_config_with_callback_whitelist(vec![]);

		// Act
		let result = service
			.simulate_callback_and_estimate_gas(&order, &fill_tx, &config)
			.await;

		// Assert - should fail because recipient is not whitelisted
		assert!(result.is_err());
		let error = result.unwrap_err();
		match error {
			CostProfitError::Config(msg) => {
				assert!(msg.contains("not in whitelist"));
			},
			other => panic!("Expected Config error, got: {other:?}"),
		}
	}

	#[tokio::test]
	async fn test_simulate_callback_multiple_outputs_rejected() {
		// Arrange
		let mock_delivery = MockDeliveryInterface::new();
		let mut delivery_implementations = HashMap::new();
		delivery_implementations.insert(
			137,
			Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
		);
		let delivery = Arc::new(DeliveryService::new(delivery_implementations, 137, 3600));

		let mock_pricing = MockPricingInterface::new();
		let mock_storage = MockStorageInterface::new();
		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let token_manager = create_mock_token_manager();

		let service = CostProfitService::new(pricing, delivery, token_manager, storage);

		let order = create_order_with_multiple_outputs();
		let fill_tx = create_test_fill_transaction();
		let config = create_config_with_callback_whitelist(vec![]);

		// Act
		let result = service
			.simulate_callback_and_estimate_gas(&order, &fill_tx, &config)
			.await;

		// Assert - should fail because multiple outputs are not supported
		assert!(result.is_err());
		let error = result.unwrap_err();
		match error {
			CostProfitError::Calculation(msg) => {
				assert!(msg.contains("Multiple outputs"));
				assert!(msg.contains("not supported"));
			},
			other => panic!("Expected Calculation error, got: {other:?}"),
		}
	}

	#[tokio::test]
	async fn test_simulate_callback_gas_estimation_failure_revert() {
		// Arrange
		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});
		mock_delivery.expect_estimate_gas().returning(|_| {
			Box::pin(async move {
				Err(solver_delivery::DeliveryError::Network(
					"execution reverted".to_string(),
				))
			})
		});

		let mut delivery_implementations = HashMap::new();
		delivery_implementations.insert(
			137,
			Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
		);
		let delivery = Arc::new(DeliveryService::new(delivery_implementations, 137, 3600));

		let mock_pricing = MockPricingInterface::new();
		let mock_storage = MockStorageInterface::new();
		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let token_manager = create_mock_token_manager();

		let service = CostProfitService::new(pricing, delivery, token_manager, storage);

		let callback_data = vec![0xde, 0xad, 0xbe, 0xef];
		let order = create_order_with_callback(callback_data);
		let fill_tx = create_test_fill_transaction();

		// Whitelist the recipient
		// EIP-7930 format for chain 137 (0x89): 0x0001 | 0x0000 | 0x01 | 0x89 | 0x14 | <address>
		let whitelist =
			vec!["0x000100000189142222222222222222222222222222222222222222".to_lowercase()];
		let config = create_config_with_callback_whitelist(whitelist);

		// Act
		let result = service
			.simulate_callback_and_estimate_gas(&order, &fill_tx, &config)
			.await;

		// Assert - should fail because callback would revert
		assert!(result.is_err());
		let error = result.unwrap_err();
		match error {
			CostProfitError::Calculation(msg) => {
				assert!(msg.contains("callback would revert"));
			},
			other => panic!("Expected Calculation error, got: {other:?}"),
		}
	}

	#[tokio::test]
	async fn test_simulate_callback_disabled_with_callback_data_rejected() {
		// Arrange
		let mock_delivery = MockDeliveryInterface::new();
		let mut delivery_implementations = HashMap::new();
		delivery_implementations.insert(
			137,
			Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
		);
		let delivery = Arc::new(DeliveryService::new(delivery_implementations, 137, 3600));

		let mock_pricing = MockPricingInterface::new();
		let mock_storage = MockStorageInterface::new();
		let pricing = Arc::new(PricingService::new(Box::new(mock_pricing), Vec::new()));
		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let token_manager = create_mock_token_manager();

		let service = CostProfitService::new(pricing, delivery, token_manager, storage);

		// Order with callback data
		let callback_data = vec![0xde, 0xad, 0xbe, 0xef];
		let order = create_order_with_callback(callback_data);
		let fill_tx = create_test_fill_transaction();

		// Config with simulate_callbacks = false
		let mut config = create_test_config();
		config.order.simulate_callbacks = false;

		// Act
		let result = service
			.simulate_callback_and_estimate_gas(&order, &fill_tx, &config)
			.await;

		// Assert - should fail because callbacks are not supported when simulation is disabled
		assert!(result.is_err());
		let error = result.unwrap_err();
		match error {
			CostProfitError::Config(msg) => {
				assert!(msg.contains("callback simulation is disabled"));
				assert!(msg.contains("not supported"));
			},
			other => panic!("Expected Config error, got: {other:?}"),
		}
	}
}
