use crate::apis::cost::convert_raw_token_to_usd;
use crate::apis::cost::{
	add_many, apply_bps, estimate_gas_units_from_config, get_chain_gas_price_as_u256,
};
use alloy_primitives::U256;
use rust_decimal::Decimal;
use solver_config::Config;
use solver_core::SolverEngine;
use solver_pricing::PricingService;
use solver_types::RequestedOutput;
use solver_types::{
	costs::{CostComponent, CostEstimate},
	current_timestamp, APIError, ApiErrorType, AvailableInput, ExecutionParams, FillProof, Order,
	Quote, Transaction, TransactionHash, DEFAULT_GAS_PRICE_WEI,
};
use std::str::FromStr;

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

pub struct CostEngine;

impl CostEngine {
	pub fn new() -> Self {
		Self
	}

	/// Estimate cost for a Quote
	pub async fn estimate_cost_for_quote(
		&self,
		quote: &Quote,
		solver: &SolverEngine,
		config: &Config,
	) -> Result<CostEstimate, APIError> {
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

		// Determine the standard - for quotes, we default to eip7683
		// TODO: In the future, this should be determined from the quote
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
				solver,
				chain_params.origin_chain_id,
				chain_params.dest_chain_id,
			)
			.await?;

		// Calculate cost components
		self.calculate_cost_components(
			solver,
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
		solver: &SolverEngine,
		config: &Config,
	) -> Result<CostEstimate, APIError> {
		// Parse the order data based on its standard
		let parsable = order.parse_order_data().map_err(|e| APIError::BadRequest {
			error_type: ApiErrorType::InvalidRequest,
			message: format!("Failed to parse order data: {}", e),
			details: None,
		})?;

		// Extract chain parameters
		let origin_chain_id = parsable.origin_chain_id();
		let dest_chain_ids = parsable.destination_chain_ids();

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
		let flow_key = parsable.parse_lock_type();

		// Estimate gas units
		let gas_units = self
			.estimate_gas_units(
				order,
				&flow_key,
				config,
				solver,
				chain_params.origin_chain_id,
				chain_params.dest_chain_id,
			)
			.await?;

		// Calculate cost components
		let available_inputs = parsable.parse_available_inputs();
		let requested_outputs = parsable.parse_requested_outputs();
		self.calculate_cost_components(
			solver,
			chain_params,
			gas_units,
			&available_inputs,
			&requested_outputs,
			config,
		)
		.await
	}

	/// Estimate gas units with optional live estimation
	async fn estimate_gas_units(
		&self,
		order: &Order,
		flow_key: &Option<String>,
		config: &Config,
		solver: &SolverEngine,
		origin_chain_id: u64,
		dest_chain_id: u64,
	) -> Result<GasUnits, APIError> {
		let pricing = solver.pricing().config();

		// Get base units from config
		let (open_units, mut fill_units, mut claim_units) =
			estimate_gas_units_from_config(flow_key, config, 0, 0, 0);

		// Live estimation if enabled
		if pricing.enable_live_gas_estimate {
			// Estimate fill gas
			tracing::info!("Estimating fill gas on destination chain");
			if let Ok(fill_tx) = self.build_fill_tx_for_estimation(order, solver).await {
				match solver
					.delivery()
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
			if let Ok(claim_tx) = self.build_claim_tx_for_estimation(order, solver).await {
				tracing::debug!(
					"finalise tx bytes_len={} to={}",
					claim_tx.data.len(),
					claim_tx
						.to
						.as_ref()
						.map(|a| a.to_string())
						.unwrap_or_else(|| "<none>".into())
				);
				match solver
					.delivery()
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
	async fn build_fill_tx_for_estimation(
		&self,
		order: &Order,
		solver: &SolverEngine,
	) -> Result<Transaction, APIError> {
		// Create execution params for estimation
		let params = ExecutionParams {
			gas_price: U256::from(DEFAULT_GAS_PRICE_WEI),
			priority_fee: None,
		};

		// Use OrderService to generate transaction
		solver
			.order()
			.generate_fill_transaction(order, &params)
			.await
			.map_err(|e| APIError::InternalServerError {
				error_type: ApiErrorType::FillTxGenerationFailed,
				message: format!("Failed to generate fill transaction: {}", e),
			})
	}

	/// Build claim transaction for gas estimation
	async fn build_claim_tx_for_estimation(
		&self,
		order: &Order,
		solver: &SolverEngine,
	) -> Result<Transaction, APIError> {
		// Create minimal fill proof for estimation
		let fill_proof = FillProof {
			oracle_address: "0x0000000000000000000000000000000000000000".to_string(),
			filled_timestamp: current_timestamp(),
			block_number: 1,
			tx_hash: TransactionHash(vec![0u8; 32]),
			attestation_data: Some(vec![]),
		};

		solver
			.order()
			.generate_claim_transaction(order, &fill_proof)
			.await
			.map_err(|e| APIError::InternalServerError {
				error_type: ApiErrorType::ClaimTxGenerationFailed,
				message: format!("Failed to generate claim transaction: {}", e),
			})
	}

	/// Calculate cost components for the order
	async fn calculate_cost_components(
		&self,
		solver: &SolverEngine,
		chain_params: ChainParams,
		gas_units: GasUnits,
		available_inputs: &[AvailableInput],
		requested_outputs: &[RequestedOutput],
		config: &Config,
	) -> Result<CostEstimate, APIError> {
		let pricing_service = solver.pricing();
		let pricing = pricing_service.config();

		// Gas prices using shared utility
		let origin_gp = get_chain_gas_price_as_u256(solver, chain_params.origin_chain_id)
			.await
			.map_err(|e| APIError::InternalServerError {
				error_type: ApiErrorType::GasEstimationFailed,
				message: format!("Failed to get origin chain gas price: {}", e),
			})?;
		let dest_gp = get_chain_gas_price_as_u256(solver, chain_params.dest_chain_id)
			.await
			.map_err(|e| APIError::InternalServerError {
				error_type: ApiErrorType::GasEstimationFailed,
				message: format!("Failed to get destination chain gas price: {}", e),
			})?;

		// Costs: open+claim on origin, fill on dest
		let open_cost_wei_uint = origin_gp.saturating_mul(U256::from(gas_units.open_units));
		let fill_cost_wei_uint = dest_gp.saturating_mul(U256::from(gas_units.fill_units));
		let claim_cost_wei_uint = origin_gp.saturating_mul(U256::from(gas_units.claim_units));

		let open_cost_wei_str = open_cost_wei_uint.to_string();
		let fill_cost_wei_str = fill_cost_wei_uint.to_string();
		let claim_cost_wei_str = claim_cost_wei_uint.to_string();

		// Convert wei amounts to display currency
		let open_cost_currency = pricing_service
			.wei_to_currency(&open_cost_wei_str, &pricing.currency)
			.await
			.unwrap_or_else(|_| "0".to_string());
		let fill_cost_currency = pricing_service
			.wei_to_currency(&fill_cost_wei_str, &pricing.currency)
			.await
			.unwrap_or_else(|_| "0".to_string());
		let claim_cost_currency = pricing_service
			.wei_to_currency(&claim_cost_wei_str, &pricing.currency)
			.await
			.unwrap_or_else(|_| "0".to_string());

		let gas_subtotal_w = add_many(&[
			open_cost_wei_str.clone(),
			fill_cost_wei_str.clone(),
			claim_cost_wei_str.clone(),
		]);
		let buffer_gas = apply_bps(&gas_subtotal_w, pricing.gas_buffer_bps);
		let buffer_gas_currency = pricing_service
			.wei_to_currency(&buffer_gas, &pricing.currency)
			.await
			.unwrap_or_else(|_| "0".to_string());

		// Calculate base price and minimum profit requirement in USD
		let (base_price_usd, min_profit_usd) = self
			.calculate_pricing_components(
				solver,
				pricing_service,
				available_inputs,
				requested_outputs,
				&chain_params,
				config,
			)
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
		// subtotal = operational costs + base price + min profit
		let subtotal_usd = operational_cost_usd
			+ Decimal::from_str(&base_price_usd).unwrap_or(Decimal::ZERO)
			+ Decimal::from_str(&min_profit_usd).unwrap_or(Decimal::ZERO);

		// Calculate commission on the subtotal
		let commission_amount_usd = if pricing.commission_bps > 0 {
			let bps_divisor = Decimal::new(10000, 0);
			let commission_rate = Decimal::new(pricing.commission_bps as i64, 0) / bps_divisor;
			(subtotal_usd * commission_rate).to_string()
		} else {
			"0".to_string()
		};

		// Calculate total: subtotal + commission
		let total_usd =
			subtotal_usd + Decimal::from_str(&commission_amount_usd).unwrap_or(Decimal::ZERO);

		Ok(CostEstimate {
			currency: pricing.currency.clone(),
			components: vec![
				CostComponent {
					name: "base-price".into(),
					amount: base_price_usd.clone(),
					amount_wei: None,
				},
				CostComponent {
					name: "gas-open".into(),
					amount: open_cost_currency,
					amount_wei: Some(open_cost_wei_str),
				},
				CostComponent {
					name: "gas-fill".into(),
					amount: fill_cost_currency,
					amount_wei: Some(fill_cost_wei_str),
				},
				CostComponent {
					name: "gas-claim".into(),
					amount: claim_cost_currency,
					amount_wei: Some(claim_cost_wei_str),
				},
				CostComponent {
					name: "buffer-gas".into(),
					amount: buffer_gas_currency,
					amount_wei: Some(buffer_gas),
				},
				CostComponent {
					name: "buffer-rates".into(),
					amount: buffer_rates.clone(),
					amount_wei: Some(buffer_rates),
				},
				CostComponent {
					name: "min-profit".into(),
					amount: min_profit_usd,
					amount_wei: None, // No wei equivalent needed
				},
				CostComponent {
					name: "operational-cost".into(),
					amount: operational_cost_usd.to_string(),
					amount_wei: None, // This is a calculated summary, not a wei value
				},
			],
			commission_bps: pricing.commission_bps,
			commission_amount: commission_amount_usd.clone(),
			subtotal: subtotal_usd.to_string(),
			total: total_usd.to_string(),
		})
	}

	/// Calculate the base price and minimum profit requirement in USD
	/// This considers the spread between input and output values
	async fn calculate_pricing_components(
		&self,
		solver: &SolverEngine,
		pricing_service: &PricingService,
		available_inputs: &[AvailableInput],
		requested_outputs: &[RequestedOutput],
		chain_params: &ChainParams,
		config: &Config,
	) -> Result<(String, String), Box<dyn std::error::Error>> {
		let token_manager = solver.token_manager();

		// Calculate total input value in USD
		let mut total_input_value_usd = Decimal::ZERO;
		for input in available_inputs {
			// Get the chain ID from the input asset, fallback to origin_chain_id
			let chain_id = input
				.asset
				.ethereum_chain_id()
				.unwrap_or(chain_params.origin_chain_id);

			// Get token info
			let ethereum_addr = input
				.asset
				.ethereum_address()
				.map_err(|e| format!("Failed to extract input ethereum address: {}", e))?;
			let solver_addr = solver_types::Address(ethereum_addr.0.to_vec());
			let token_info = token_manager
				.get_token_info(chain_id, &solver_addr)
				.map_err(|e| format!("Failed to get input token info: {}", e))?;

			// Convert raw amount to USD using pricing service
			let usd_amount = convert_raw_token_to_usd(
				&input.amount,
				&token_info.symbol,
				token_info.decimals,
				pricing_service,
			)
			.await?;

			total_input_value_usd += usd_amount;
		}

		// Calculate total output value in USD
		let mut total_output_value_usd = Decimal::ZERO;
		for output in requested_outputs {
			// Get the chain ID from the output asset, fallback to dest_chain_id
			let chain_id = output
				.asset
				.ethereum_chain_id()
				.unwrap_or(chain_params.dest_chain_id);

			// Get token info
			let ethereum_addr = output
				.asset
				.ethereum_address()
				.map_err(|e| format!("Failed to extract output ethereum address: {}", e))?;
			let solver_addr = solver_types::Address(ethereum_addr.0.to_vec());
			let token_info = token_manager
				.get_token_info(chain_id, &solver_addr)
				.map_err(|e| format!("Failed to get output token info: {}", e))?;

			// Convert raw amount to USD using pricing service
			let usd_amount = convert_raw_token_to_usd(
				&output.amount,
				&token_info.symbol,
				token_info.decimals,
				pricing_service,
			)
			.await?;

			total_output_value_usd += usd_amount;
		}

		// Calculate the spread (can be negative if solver provides more value than received)
		let spread = total_input_value_usd - total_output_value_usd;

		// Calculate base price needed to cover any negative spread
		// If outputs > inputs, solver needs to charge at least the difference
		let base_price_usd = if spread < Decimal::ZERO {
			spread.abs() // Convert negative spread to positive base price
		} else {
			Decimal::ZERO // No base price needed if there's natural profit
		};

		// Calculate minimum required profit based on the transaction size
		// Use the larger value to ensure profitability scales with transaction size
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

		// Return both base price and minimum profit separately
		Ok((base_price_usd.to_string(), min_required_profit.to_string()))
	}
}
