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
use solver_types::{
	costs::{CostComponent, CostEstimate},
	current_timestamp, APIError, Address, ApiErrorType, AvailableInput, ExecutionParams, FillProof,
	Order, Quote, RequestedOutput, Transaction, TransactionHash, DEFAULT_GAS_PRICE_WEI,
};
use std::{str::FromStr, sync::Arc};
use thiserror::Error;

const HUNDRED: i64 = 10000;

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
}

/// Parameters for chain-related information
struct ChainParams {
	origin_chain_id: u64,
	dest_chain_id: u64,
}

/// Parameters for gas unit calculations
struct GasUnits {
	open_units: u64,
	fill_units: u64,
	claim_units: u64,
}

/// Unified service for cost estimation and profitability calculation.
pub struct CostProfitService {
	/// Pricing service for USD conversions and asset pricing
	pricing_service: Arc<PricingService>,
	/// Delivery service for blockchain data and gas estimation
	delivery_service: Arc<DeliveryService>,
	/// Token manager for token configuration lookups
	token_manager: Arc<TokenManager>,
}

impl CostProfitService {
	/// Creates a new CostProfitService with the given services.
	pub fn new(
		pricing_service: Arc<PricingService>,
		delivery_service: Arc<DeliveryService>,
		token_manager: Arc<TokenManager>,
	) -> Self {
		Self {
			pricing_service,
			delivery_service,
			token_manager,
		}
	}

	/// Estimate cost for a Quote
	pub async fn estimate_cost_for_quote(
		&self,
		quote: &Quote,
		config: &Config,
	) -> Result<CostEstimate, CostProfitError> {
		// Extract chain parameters from quote
		let origin_chain_id = quote
			.details
			.available_inputs
			.iter()
			.filter_map(|input| input.asset.ethereum_chain_id().ok())
			.next()
			.ok_or_else(|| APIError::BadRequest {
				error_type: ApiErrorType::MissingChainId,
				message: "No input chain ID found".to_string(),
				details: None,
			})?;

		let dest_chain_id = quote
			.details
			.requested_outputs
			.iter()
			.filter_map(|output| output.asset.ethereum_chain_id().ok())
			.next()
			.ok_or_else(|| APIError::BadRequest {
				error_type: ApiErrorType::MissingChainId,
				message: "No output chain ID found".to_string(),
				details: None,
			})?;

		let chain_params = ChainParams {
			origin_chain_id,
			dest_chain_id,
		};

		// Extract flow key (lock_type) for gas config lookup
		let flow_key = Some(quote.lock_type.clone());

		// TODO: pass standard as part of quote request
		let standard = "eip7683";
		let order = quote
			.to_order_for_estimation(standard)
			.map_err(|e| APIError::BadRequest {
				error_type: ApiErrorType::InvalidRequest,
				message: format!("Failed to convert quote to order: {}", e),
				details: None,
			})?;

		// Estimate gas units
		let gas_units = self
			.estimate_gas_units(
				&order,
				&flow_key,
				config,
				chain_params.origin_chain_id,
				chain_params.dest_chain_id,
			)
			.await?;

		// Calculate cost components
		self.calculate_cost_components(
			chain_params,
			gas_units,
			&quote.details.available_inputs,
			&quote.details.requested_outputs,
			config,
		)
		.await
	}

	/// Estimate cost for an Order using its OrderParsable implementation
	pub async fn estimate_cost_for_order(
		&self,
		order: &Order,
		config: &Config,
	) -> Result<CostEstimate, CostProfitError> {
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

		let chain_params = ChainParams {
			origin_chain_id,
			dest_chain_id,
		};

		// Extract flow key (lock_type) for gas config lookup
		let flow_key = order_parsed.parse_lock_type();

		// Estimate gas units
		let gas_units = self
			.estimate_gas_units(
				order,
				&flow_key,
				config,
				chain_params.origin_chain_id,
				chain_params.dest_chain_id,
			)
			.await?;

		// Calculate cost components
		let available_inputs = order_parsed.parse_available_inputs();
		let requested_outputs = order_parsed.parse_requested_outputs();
		self.calculate_cost_components(
			chain_params,
			gas_units,
			&available_inputs,
			&requested_outputs,
			config,
		)
		.await
	}

	/// Calculates the profit margin percentage for an order.
	///
	/// The profit margin is calculated as:
	/// Profit = Total Input Amount (USD) - Total Output Amount (USD) - Execution Costs (USD)
	/// Profit Margin = (Profit / Total Input Amount (USD)) * 100
	///
	/// This represents the percentage profit the solver makes on the input amount.
	/// All amounts are converted to USD using the pricing service for accurate comparison.
	pub async fn calculate_profit_margin(
		&self,
		order: &Order,
		cost_estimate: &CostEstimate,
	) -> Result<Decimal, CostProfitError> {
		// Parse the order data to get amounts
		let parsed_order = order.parse_order_data().map_err(|e| {
			CostProfitError::Calculation(format!("Failed to parse order data: {}", e))
		})?;
		let available_inputs = parsed_order.parse_available_inputs();
		let requested_outputs = parsed_order.parse_requested_outputs();

		// Calculate total input amount in USD using token manager
		let mut total_input_amount_usd = Decimal::ZERO;
		for input in available_inputs.iter() {
			let chain_id = input.asset.ethereum_chain_id().map_err(|e| {
				CostProfitError::Calculation(format!(
					"Failed to get chain ID from input asset: {}",
					e
				))
			})?;
			let ethereum_addr = input.asset.ethereum_address().map_err(|e| {
				CostProfitError::Calculation(format!(
					"Failed to get ethereum address from input asset: {}",
					e
				))
			})?;
			let token_address = Address(ethereum_addr.0.to_vec());

			let token_info = self
				.token_manager
				.get_token_info(chain_id, &token_address)
				.map_err(|e| {
					CostProfitError::Calculation(format!("Failed to get input token info: {}", e))
				})?;

			let usd_amount = Self::convert_raw_token_to_usd(
				&input.amount,
				&token_info.symbol,
				token_info.decimals,
				&self.pricing_service,
			)
			.await
			.map_err(|e| CostProfitError::Calculation(e.to_string()))?;

			total_input_amount_usd += usd_amount;
		}

		// Calculate total output amount in USD using token manager
		let mut total_output_amount_usd = Decimal::ZERO;
		for output in requested_outputs.iter() {
			let chain_id = output.asset.ethereum_chain_id().map_err(|e| {
				CostProfitError::Calculation(format!(
					"Failed to get chain ID from output asset: {}",
					e
				))
			})?;
			let ethereum_addr = output.asset.ethereum_address().map_err(|e| {
				CostProfitError::Calculation(format!(
					"Failed to get ethereum address from output asset: {}",
					e
				))
			})?;
			let token_address = Address(ethereum_addr.0.to_vec());

			let token_info = self
				.token_manager
				.get_token_info(chain_id, &token_address)
				.map_err(|e| {
					CostProfitError::Calculation(format!("Failed to get output token info: {}", e))
				})?;

			let usd_amount = Self::convert_raw_token_to_usd(
				&output.amount,
				&token_info.symbol,
				token_info.decimals,
				&self.pricing_service,
			)
			.await
			.map_err(|e| CostProfitError::Calculation(e.to_string()))?;

			total_output_amount_usd += usd_amount;
		}

		// Extract operational cost from the components
		let operational_cost_usd = cost_estimate
			.components
			.iter()
			.find(|c| c.name == "operational-cost")
			.and_then(|c| Decimal::from_str(&c.amount).ok())
			.ok_or_else(|| {
				CostProfitError::Calculation(
					"Operational cost component not found in cost estimate".to_string(),
				)
			})?;

		// Calculate the solver's actual profit margin
		// Profit = Input Value - Output Value - Operational Costs
		// Margin = Profit / Input Value * 100
		if total_input_amount_usd.is_zero() {
			return Err(CostProfitError::Calculation(
				"Division by zero: total_input_amount_usd is zero".to_string(),
			));
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
	pub async fn validate_profitability(
		&self,
		order: &Order,
		cost_estimate: &CostEstimate,
		min_profitability_pct: Decimal,
	) -> Result<Decimal, APIError> {
		// Calculate profit margin
		let actual_profit_margin = self
			.calculate_profit_margin(order, cost_estimate)
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

	/// Validates cost estimation and profitability for an already-validated order from API requests.
	///
	/// This method combines cost estimation and profitability validation specifically for API-originated orders,
	/// returning APIError types that can be properly handled by the HTTP layer.
	/// For internally discovered intents, use the individual methods or IntentHandler directly.
	pub async fn validate_order_profitability_for_api(
		&self,
		order: &Order,
		config: &Config,
	) -> Result<(), APIError> {
		use solver_types::truncate_id;

		// Calculate cost estimation
		let cost_estimate =
			self.estimate_cost_for_order(order, config)
				.await
				.map_err(|e| match e {
					CostProfitError::Api(api_error) => api_error,
					other => APIError::InternalServerError {
						error_type: ApiErrorType::InternalError,
						message: format!("Cost estimation failed: {}", other),
					},
				})?;

		// Validate profitability
		let actual_profit_margin = self
			.validate_profitability(order, &cost_estimate, config.solver.min_profitability_pct)
			.await?;

		tracing::info!(
			order_id = %truncate_id(&order.id),
			margin = %actual_profit_margin,
			cost = %cost_estimate.total,
			"Order profitability validation successful for API request"
		);

		Ok(())
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

	/// Calculate cost components for the order
	async fn calculate_cost_components(
		&self,
		chain_params: ChainParams,
		gas_units: GasUnits,
		available_inputs: &[AvailableInput],
		requested_outputs: &[RequestedOutput],
		config: &Config,
	) -> Result<CostEstimate, CostProfitError> {
		let pricing = self.pricing_service.config();

		// Gas prices
		let origin_gp = self
			.get_chain_gas_price(chain_params.origin_chain_id)
			.await?;
		let dest_gp = self.get_chain_gas_price(chain_params.dest_chain_id).await?;

		// Calculate gas costs in wei
		let open_cost_wei = origin_gp.saturating_mul(U256::from(gas_units.open_units));
		let fill_cost_wei = dest_gp.saturating_mul(U256::from(gas_units.fill_units));
		let claim_cost_wei = origin_gp.saturating_mul(U256::from(gas_units.claim_units));

		// Convert wei amounts to display currency
		let open_cost_currency = self
			.pricing_service
			.wei_to_currency(&open_cost_wei.to_string(), &pricing.currency)
			.await
			.unwrap_or_else(|_| "0".to_string());
		let fill_cost_currency = self
			.pricing_service
			.wei_to_currency(&fill_cost_wei.to_string(), &pricing.currency)
			.await
			.unwrap_or_else(|_| "0".to_string());
		let claim_cost_currency = self
			.pricing_service
			.wei_to_currency(&claim_cost_wei.to_string(), &pricing.currency)
			.await
			.unwrap_or_else(|_| "0".to_string());

		// Calculate gas buffer using Decimal arithmetic
		let gas_subtotal_wei = open_cost_wei + fill_cost_wei + claim_cost_wei;
		let bps_decimal = Decimal::new(pricing.gas_buffer_bps as i64, 0);
		let bps_divisor = Decimal::new(10000, 0); // 10000 basis points = 100%

		let gas_subtotal_decimal =
			Decimal::from_str(&gas_subtotal_wei.to_string()).unwrap_or(Decimal::ZERO);
		let buffer_gas_decimal = (gas_subtotal_decimal * bps_decimal) / bps_divisor;
		let buffer_gas_wei = buffer_gas_decimal.to_string();

		let buffer_gas_currency = self
			.pricing_service
			.wei_to_currency(&buffer_gas_wei, &pricing.currency)
			.await
			.unwrap_or_else(|_| "0".to_string());

		// Calculate base price and minimum profit requirement in USD
		let (base_price_usd, min_profit_usd) = self
			.calculate_pricing_components(available_inputs, requested_outputs, config)
			.await
			.unwrap_or_else(|e| {
				tracing::warn!("Failed to calculate pricing components: {}", e);
				("0".to_string(), "0".to_string())
			});

		// Calculate buffer rates (currently 0 since we don't have rate buffers implemented)
		let buffer_rates = "0".to_string();

		// Calculate operational costs (gas + buffers only) in USD
		let operational_cost_usd = Decimal::from_str(&open_cost_currency).unwrap_or(Decimal::ZERO)
			+ Decimal::from_str(&fill_cost_currency).unwrap_or(Decimal::ZERO)
			+ Decimal::from_str(&claim_cost_currency).unwrap_or(Decimal::ZERO)
			+ Decimal::from_str(&buffer_gas_currency).unwrap_or(Decimal::ZERO);

		// Calculate subtotal: all cost components before commission
		let subtotal_usd = operational_cost_usd
			+ Decimal::from_str(&base_price_usd).unwrap_or(Decimal::ZERO)
			+ Decimal::from_str(&min_profit_usd).unwrap_or(Decimal::ZERO);

		// Calculate commission on the subtotal
		let commission_amount_usd = if pricing.commission_bps > 0 {
			let commission_bps = Decimal::new(pricing.commission_bps as i64, 0);
			let commission_divisor = Decimal::new(HUNDRED, 0);
			(subtotal_usd * commission_bps) / commission_divisor
		} else {
			Decimal::ZERO
		};

		// Calculate total: subtotal + commission
		let total_usd = subtotal_usd + commission_amount_usd;

		Ok(CostEstimate {
			currency: pricing.currency.clone(),
			components: vec![
				CostComponent {
					name: "base-price".into(),
					amount: base_price_usd.to_string(),
					amount_wei: None,
				},
				CostComponent {
					name: "gas-open".into(),
					amount: open_cost_currency,
					amount_wei: Some(open_cost_wei.to_string()),
				},
				CostComponent {
					name: "gas-fill".into(),
					amount: fill_cost_currency,
					amount_wei: Some(fill_cost_wei.to_string()),
				},
				CostComponent {
					name: "gas-claim".into(),
					amount: claim_cost_currency,
					amount_wei: Some(claim_cost_wei.to_string()),
				},
				CostComponent {
					name: "buffer-gas".into(),
					amount: buffer_gas_currency,
					amount_wei: Some(buffer_gas_wei),
				},
				CostComponent {
					name: "buffer-rates".into(),
					amount: buffer_rates.clone(),
					amount_wei: Some(buffer_rates),
				},
				CostComponent {
					name: "min-profit".into(),
					amount: min_profit_usd.to_string(),
					amount_wei: None,
				},
				CostComponent {
					name: "operational-cost".into(),
					amount: operational_cost_usd.to_string(),
					amount_wei: None,
				},
			],
			commission_bps: pricing.commission_bps,
			commission_amount: commission_amount_usd.to_string(),
			subtotal: subtotal_usd.to_string(),
			total: total_usd.to_string(),
		})
	}

	/// Calculate the base price and minimum profit requirement in USD
	async fn calculate_pricing_components(
		&self,
		available_inputs: &[AvailableInput],
		requested_outputs: &[RequestedOutput],
		config: &Config,
	) -> Result<(String, String), Box<dyn std::error::Error>> {
		// Calculate total input value in USD
		let mut total_input_value_usd = Decimal::ZERO;
		for input in available_inputs.iter() {
			let chain_id = input
				.asset
				.ethereum_chain_id()
				.map_err(|e| format!("Failed to get chain ID from input asset: {}", e))?;
			let ethereum_addr = input
				.asset
				.ethereum_address()
				.map_err(|e| format!("Failed to get ethereum address from input asset: {}", e))?;
			let token_address = Address(ethereum_addr.0.to_vec());

			let token_info = self
				.token_manager
				.get_token_info(chain_id, &token_address)
				.map_err(|e| format!("Failed to get input token info: {}", e))?;

			let usd_amount = Self::convert_raw_token_to_usd(
				&input.amount,
				&token_info.symbol,
				token_info.decimals,
				&self.pricing_service,
			)
			.await?;

			total_input_value_usd += usd_amount;
		}

		// Calculate total output value in USD
		let mut total_output_value_usd = Decimal::ZERO;
		for output in requested_outputs.iter() {
			let chain_id = output
				.asset
				.ethereum_chain_id()
				.map_err(|e| format!("Failed to get chain ID from output asset: {}", e))?;
			let ethereum_addr = output
				.asset
				.ethereum_address()
				.map_err(|e| format!("Failed to get ethereum address from output asset: {}", e))?;
			let token_address = Address(ethereum_addr.0.to_vec());

			let token_info = self
				.token_manager
				.get_token_info(chain_id, &token_address)
				.map_err(|e| format!("Failed to get output token info: {}", e))?;

			let usd_amount = Self::convert_raw_token_to_usd(
				&output.amount,
				&token_info.symbol,
				token_info.decimals,
				&self.pricing_service,
			)
			.await?;

			total_output_value_usd += usd_amount;
		}

		// Calculate the spread (can be negative if solver provides more value than received)
		let spread = total_input_value_usd - total_output_value_usd;

		// Calculate base price needed to cover any negative spread
		let base_price_usd = if spread < Decimal::ZERO {
			spread.abs()
		} else {
			Decimal::ZERO
		};

		// Calculate minimum required profit based on the transaction size
		let transaction_value = total_input_value_usd.max(total_output_value_usd);
		let hundred = Decimal::new(100_i64, 0);
		let min_required_profit =
			(transaction_value * config.solver.min_profitability_pct) / hundred;

		tracing::info!(
            "Pricing components: input_value={}, output_value={}, spread={}, base_price={}, min_profit={}",
            total_input_value_usd,
            total_output_value_usd,
            spread,
            base_price_usd,
            min_required_profit
        );

		Ok((base_price_usd.to_string(), min_required_profit.to_string()))
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
