use crate::apis::cost::{
	add_decimals, add_many, apply_bps, estimate_gas_units_from_config, get_chain_gas_price_as_u256,
};
use alloy_primitives::U256;
use solver_config::Config;
use solver_core::SolverEngine;
use solver_pricing::PricingService;
use solver_types::{
	costs::{CostComponent, CostEstimatable, CostEstimate},
	current_timestamp, APIError, ApiErrorType, ExecutionParams, FillProof, Order, Transaction,
	TransactionHash, DEFAULT_GAS_PRICE_WEI,
};

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

	/// Unified cost estimation for any CostEstimatable type
	pub async fn estimate_cost<T: CostEstimatable>(
		&self,
		estimatable: &T,
		solver: &SolverEngine,
		config: &Config,
	) -> Result<CostEstimate, APIError> {
		// Extract chain parameters
		let origin_chain_id = estimatable
			.input_chain_ids()
			.first()
			.copied()
			.ok_or_else(|| APIError::BadRequest {
				error_type: ApiErrorType::MissingChainId,
				message: "No input chain ID found".to_string(),
				details: None,
			})?;

		let dest_chain_id = estimatable
			.output_chain_ids()
			.first()
			.copied()
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
		let flow_key = estimatable.lock_type().map(String::from);

		// Get Order for transaction generation (only if needed)
		let order = estimatable.as_order_for_estimation();

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
		let pricing_service = solver.pricing();
		self.calculate_cost_components(solver, pricing_service, chain_params, gas_units)
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
		pricing_service: &PricingService,
		chain_params: ChainParams,
		gas_units: GasUnits,
	) -> Result<CostEstimate, APIError> {
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

		let base_price = "0".to_string();
		let buffer_rates = apply_bps(&base_price, pricing.rate_buffer_bps);

		let subtotal = add_many(&[
			base_price.clone(),
			gas_subtotal_w.clone(),
			buffer_gas.clone(),
			buffer_rates.clone(),
		]);
		let subtotal_currency = pricing_service
			.wei_to_currency(&subtotal, &pricing.currency)
			.await
			.unwrap_or_else(|_| "0".to_string());

		let commission_amount = apply_bps(&subtotal, pricing.commission_bps);
		let commission_amount_currency = pricing_service
			.wei_to_currency(&commission_amount, &pricing.currency)
			.await
			.unwrap_or_else(|_| "0".to_string());

		let total = add_decimals(&subtotal, &commission_amount);
		let total_currency = pricing_service
			.wei_to_currency(&total, &pricing.currency)
			.await
			.unwrap_or_else(|_| "0".to_string());

		Ok(CostEstimate {
			currency: pricing.currency.clone(),
			components: vec![
				CostComponent {
					name: "base-price".into(),
					amount: base_price.clone(),
					amount_wei: Some(base_price),
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
			],
			commission_bps: pricing.commission_bps,
			commission_amount: commission_amount_currency,
			subtotal: subtotal_currency,
			total: total_currency,
		})
	}
}
