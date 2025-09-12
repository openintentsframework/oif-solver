use crate::apis::cost::{
	add_decimals, add_many, apply_bps, determine_flow_key_from_quote_orders,
	estimate_gas_units_from_config, get_chain_gas_price_as_u256,
};
use alloy_primitives::U256;
use solver_config::Config;
use solver_core::SolverEngine;
use solver_pricing::PricingService;
use solver_types::{
	costs::{CostComponent, QuoteCost},
	Quote, QuoteError, TradingPair,
};
use solver_types::{
	current_timestamp,
	standards::eip7683::{interfaces::StandardOrder, Eip7683OrderData, MandateOutput},
	APIError, Address, ApiErrorType, ExecutionParams, FillProof, Order, OrderStatus, Transaction,
	TransactionHash, DEFAULT_GAS_PRICE_WEI,
};

/// Context for gas estimation - either Quote or StandardOrder
#[derive(Clone, Copy)]
enum EstimationContext<'a> {
	Quote(&'a Quote),
	StandardOrder(&'a StandardOrder),
}

/// Shared result structure for cost calculations
struct CostCalculationResult {
	currency: String,
	components: Vec<CostComponent>,
	commission_bps: u32,
	commission_amount: String,
	subtotal: String,
	total: String,
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

pub struct CostEngine;

impl CostEngine {
	pub fn new() -> Self {
		Self
	}

	/// Validates that the pricing service supports the required pairs for cross-chain operations.
	pub async fn validate_pricing_support(
		&self,
		quote: &Quote,
		pricing_service: &PricingService,
	) -> Result<(), QuoteError> {
		let supported_pairs = pricing_service.get_supported_pairs().await;

		// Extract origin and destination assets from quote for validation
		let _input = quote
			.details
			.available_inputs
			.first()
			.ok_or_else(|| QuoteError::InvalidRequest("missing input".to_string()))?;
		let _output = quote
			.details
			.requested_outputs
			.first()
			.ok_or_else(|| QuoteError::InvalidRequest("missing output".to_string()))?;

		// For now, we primarily care about ETH/USD support for gas cost calculations
		let required_pairs = vec![
			TradingPair::new("ETH", "USD"),
			TradingPair::new("USD", "ETH"),
		];

		for required_pair in &required_pairs {
			let has_direct_support = supported_pairs.iter().any(|p| {
				(p.base == required_pair.base && p.quote == required_pair.quote)
					|| (p.base == required_pair.quote && p.quote == required_pair.base)
			});

			if !has_direct_support {
				tracing::warn!(
					"Pricing service may not support required pair: {}",
					required_pair.to_string()
				);
			}
		}

		Ok(())
	}

	pub async fn estimate_cost(
		&self,
		quote: &Quote,
		solver: &SolverEngine,
		config: &Config,
		pricing_service: &PricingService,
	) -> Result<QuoteCost, QuoteError> {
		// Validate pricing support for this quote
		self.validate_pricing_support(quote, pricing_service)
			.await?;

		let (origin_chain_id, dest_chain_id) = self.extract_origin_dest_chain_ids(quote)?;

		// Get gas units from config using shared utility
		let flow_key = determine_flow_key_from_quote_orders(&quote.orders);
		let (open_units, fill_units, claim_units) = self
			.estimate_gas_units_with_live_estimation(
				&flow_key,
				config,
				solver,
				origin_chain_id,
				dest_chain_id,
				EstimationContext::Quote(quote),
			)
			.await?;

		// Use shared cost calculation
		let cost_result = self
			.calculate_cost_components(
				solver,
				pricing_service,
				ChainParams {
					origin_chain_id,
					dest_chain_id,
				},
				GasUnits {
					open_units,
					fill_units,
					claim_units,
				},
			)
			.await?;

		Ok(QuoteCost {
			currency: cost_result.currency,
			components: cost_result.components,
			commission_bps: cost_result.commission_bps,
			commission_amount: cost_result.commission_amount,
			subtotal: cost_result.subtotal,
			total: cost_result.total,
		})
	}

	/// Estimates the cost for executing a validated StandardOrder
	pub async fn estimate_order_cost(
		&self,
		standard_order: &StandardOrder,
		lock_type: &str,
		solver: &SolverEngine,
		config: &Config,
	) -> Result<solver_types::costs::OrderCost, APIError> {
		// Extract chain IDs from StandardOrder
		let origin_chain_id = standard_order.originChainId.to::<u64>();
		let dest_chain_id = standard_order
			.outputs
			.first()
			.ok_or_else(|| APIError::BadRequest {
				error_type: ApiErrorType::NoOutputs,
				message: "Order must have at least one output".to_string(),
				details: None,
			})?
			.chainId
			.to::<u64>();

		// Get gas units with live estimation
		let (open_units, fill_units, claim_units) = self
			.estimate_gas_units_with_live_estimation(
				&Some(lock_type.to_string()),
				config,
				solver,
				origin_chain_id,
				dest_chain_id,
				EstimationContext::StandardOrder(standard_order),
			)
			.await
			.map_err(|e| APIError::InternalServerError {
				error_type: ApiErrorType::GasEstimationFailed,
				message: format!("Gas estimation failed: {}", e),
			})?;

		let pricing_service = solver.pricing();

		// Use shared cost calculation
		let cost_result = self
			.calculate_cost_components(
				solver,
				pricing_service,
				ChainParams {
					origin_chain_id,
					dest_chain_id,
				},
				GasUnits {
					open_units,
					fill_units,
					claim_units,
				},
			)
			.await
			.map_err(|e| APIError::InternalServerError {
				error_type: ApiErrorType::CostCalculationFailed,
				message: format!("Cost calculation failed: {}", e),
			})?;

		Ok(solver_types::costs::OrderCost {
			currency: cost_result.currency,
			components: cost_result.components,
			commission_bps: cost_result.commission_bps,
			commission_amount: cost_result.commission_amount,
			subtotal: cost_result.subtotal,
			total: cost_result.total,
		})
	}

	fn extract_origin_dest_chain_ids(&self, quote: &Quote) -> Result<(u64, u64), QuoteError> {
		let input = quote
			.details
			.available_inputs
			.first()
			.ok_or_else(|| QuoteError::InvalidRequest("missing input".to_string()))?;
		let output = quote
			.details
			.requested_outputs
			.first()
			.ok_or_else(|| QuoteError::InvalidRequest("missing output".to_string()))?;
		let origin = input
			.asset
			.ethereum_chain_id()
			.map_err(|e| QuoteError::InvalidRequest(e.to_string()))?;
		let dest = output
			.asset
			.ethereum_chain_id()
			.map_err(|e| QuoteError::InvalidRequest(e.to_string()))?;
		Ok((origin, dest))
	}

	/// Create a minimal Order for gas estimation from a Quote
	async fn create_order_for_estimation(
		&self,
		quote: &Quote,
		_solver: &SolverEngine,
	) -> Result<Order, QuoteError> {
		// Create a minimal order for gas estimation purposes
		// This is safe because we only use it for transaction generation, not actual execution
		Ok(Order {
			id: format!("estimate-{}", quote.quote_id),
			standard: "eip7683".to_string(),
			created_at: solver_types::current_timestamp(),
			updated_at: solver_types::current_timestamp(),
			status: OrderStatus::Created,
			data: serde_json::to_value(&quote.details)
				.map_err(|e| QuoteError::Internal(e.to_string()))?, // Convert QuoteDetails to serde_json::Value
			solver_address: Address(vec![0u8; 20]), // Dummy solver address for estimation
			quote_id: Some(quote.quote_id.clone()),
			input_chain_ids: vec![quote
				.details
				.available_inputs
				.first()
				.ok_or_else(|| QuoteError::InvalidRequest("missing input".to_string()))?
				.asset
				.ethereum_chain_id()
				.map_err(|e| QuoteError::InvalidRequest(e.to_string()))?],
			output_chain_ids: vec![quote
				.details
				.requested_outputs
				.first()
				.ok_or_else(|| QuoteError::InvalidRequest("missing output".to_string()))?
				.asset
				.ethereum_chain_id()
				.map_err(|e| QuoteError::InvalidRequest(e.to_string()))?],
			execution_params: None,
			prepare_tx_hash: None,
			fill_tx_hash: None,
			post_fill_tx_hash: None,
			pre_claim_tx_hash: None,
			claim_tx_hash: None,
			fill_proof: None,
		})
	}

	/// Build fill transaction using the proper order implementation
	async fn build_fill_tx_for_estimation(
		&self,
		quote: &Quote,
		_dest_chain_id: u64,
		solver: &SolverEngine,
	) -> Result<Transaction, QuoteError> {
		let order = self.create_order_for_estimation(quote, solver).await?;
		// Create minimal execution params for estimation
		let params = ExecutionParams {
			gas_price: U256::from(DEFAULT_GAS_PRICE_WEI), // 1 gwei default
			priority_fee: None,
		};

		solver
			.order()
			.generate_fill_transaction(&order, &params)
			.await
			.map_err(|e| QuoteError::Internal(e.to_string()))
	}

	/// Build claim transaction using the proper order implementation
	async fn build_claim_tx_for_estimation(
		&self,
		quote: &Quote,
		_origin_chain_id: u64,
		solver: &SolverEngine,
	) -> Result<Transaction, QuoteError> {
		let order = self.create_order_for_estimation(quote, solver).await?;

		// Create minimal fill proof for estimation
		let fill_proof = FillProof {
			oracle_address: "0x0000000000000000000000000000000000000000".to_string(),
			filled_timestamp: solver_types::current_timestamp(),
			block_number: 1,
			tx_hash: TransactionHash(vec![0u8; 32]),
			attestation_data: Some(vec![]),
		};

		solver
			.order()
			.generate_claim_transaction(&order, &fill_proof)
			.await
			.map_err(|e| QuoteError::Internal(e.to_string()))
	}

	/// Creates a minimal Order from StandardOrder for cost estimation
	fn create_order_from_standard_order(
		&self,
		standard_order: &StandardOrder,
	) -> Result<Order, APIError> {
		// Convert StandardOrder to Eip7683OrderData format
		let order_data = Eip7683OrderData {
			user: format!("0x{:x}", standard_order.user),
			nonce: standard_order.nonce,
			origin_chain_id: standard_order.originChainId,
			expires: standard_order.expires,
			fill_deadline: standard_order.fillDeadline,
			input_oracle: format!("0x{:x}", standard_order.inputOracle),
			inputs: standard_order.inputs.clone(),
			order_id: [0u8; 32], // Dummy for estimation
			gas_limit_overrides: Default::default(),
			outputs: standard_order
				.outputs
				.iter()
				.map(|o| MandateOutput {
					oracle: o.oracle.0,
					settler: o.settler.0,
					chain_id: o.chainId,
					token: o.token.0,
					amount: o.amount,
					recipient: o.recipient.0,
					call: o.call.to_vec(),
					context: o.context.to_vec(),
				})
				.collect(),
			raw_order_data: None,
			signature: None,
			sponsor: None,
			lock_type: None,
		};

		Ok(Order {
			id: "estimate-order".to_string(),
			standard: "eip7683".to_string(),
			created_at: current_timestamp(),
			updated_at: current_timestamp(),
			status: OrderStatus::Created,
			data: serde_json::to_value(&order_data).map_err(|e| APIError::InternalServerError {
				error_type: ApiErrorType::SerializationFailed,
				message: format!("Failed to serialize order data: {}", e),
			})?,
			solver_address: Address(vec![0u8; 20]), // Dummy solver address for estimation
			quote_id: None,
			input_chain_ids: vec![standard_order.originChainId.to::<u64>()],
			output_chain_ids: standard_order
				.outputs
				.iter()
				.map(|o| o.chainId.to::<u64>())
				.collect(),
			execution_params: None,
			prepare_tx_hash: None,
			fill_tx_hash: None,
			post_fill_tx_hash: None,
			pre_claim_tx_hash: None,
			claim_tx_hash: None,
			fill_proof: None,
		})
	}

	/// Build fill transaction using the proper order implementation (for StandardOrder estimation)
	async fn build_fill_tx_for_standard_order_estimation(
		&self,
		standard_order: StandardOrder,
		solver: &SolverEngine,
	) -> Result<Transaction, APIError> {
		let order = self.create_order_from_standard_order(&standard_order)?;

		// Create minimal execution params for estimation
		let params = ExecutionParams {
			gas_price: U256::from(DEFAULT_GAS_PRICE_WEI), // 1 gwei default
			priority_fee: None,
		};

		solver
			.order()
			.generate_fill_transaction(&order, &params)
			.await
			.map_err(|e| APIError::InternalServerError {
				error_type: ApiErrorType::FillTxGenerationFailed,
				message: format!("Failed to generate fill transaction: {}", e),
			})
	}

	/// Build claim transaction using the proper order implementation (for StandardOrder estimation)
	async fn build_claim_tx_for_standard_order_estimation(
		&self,
		standard_order: StandardOrder,
		solver: &SolverEngine,
	) -> Result<Transaction, APIError> {
		let order = self.create_order_from_standard_order(&standard_order)?;

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
			.generate_claim_transaction(&order, &fill_proof)
			.await
			.map_err(|e| APIError::InternalServerError {
				error_type: ApiErrorType::ClaimTxGenerationFailed,
				message: format!("Failed to generate claim transaction: {}", e),
			})
	}

	/// Shared gas estimation logic with live estimation support
	async fn estimate_gas_units_with_live_estimation(
		&self,
		flow_key: &Option<String>,
		config: &Config,
		solver: &SolverEngine,
		origin_chain_id: u64,
		dest_chain_id: u64,
		context: EstimationContext<'_>,
	) -> Result<(u64, u64, u64), QuoteError> {
		let pricing_service = solver.pricing();
		let pricing = pricing_service.config();

		// Get base gas units from config
		let (open_units, mut fill_units, mut claim_units) = estimate_gas_units_from_config(
			flow_key, config, 0, // fallback open - CostEngine uses minimal defaults
			0, // fallback fill - will be replaced with live estimate if enabled
			0, // fallback claim - will be replaced with live estimate if enabled
		);

		// Live gas estimation for fill transaction
		if pricing.enable_live_gas_estimate {
			tracing::info!("Estimating fill gas on destination chain");

			if let Ok(fill_tx) = self.build_fill_tx_for_context(context, solver).await {
				match solver
					.delivery()
					.estimate_gas(dest_chain_id, fill_tx.clone())
					.await
				{
					Ok(g) => {
						tracing::info!("Fill gas units: {}", g);
						fill_units = g;
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
			} else {
				tracing::warn!("Failed to build fill transaction for estimation");
			}
		}

		// Live gas estimation for claim transaction
		if pricing.enable_live_gas_estimate {
			if let Ok(claim_tx) = self.build_claim_tx_for_context(context, solver).await {
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
					Ok(g) => {
						tracing::debug!("Claim gas units: {}", g);
						claim_units = g;
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

		Ok((open_units, fill_units, claim_units))
	}

	/// Shared cost calculation logic
	async fn calculate_cost_components(
		&self,
		solver: &SolverEngine,
		pricing_service: &PricingService,
		chain_params: ChainParams,
		gas_units: GasUnits,
	) -> Result<CostCalculationResult, QuoteError> {
		let pricing = pricing_service.config();

		// Gas prices using shared utility
		let origin_gp = get_chain_gas_price_as_u256(solver, chain_params.origin_chain_id).await?;
		let dest_gp = get_chain_gas_price_as_u256(solver, chain_params.dest_chain_id).await?;

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

		Ok(CostCalculationResult {
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

	/// Build transaction for estimation based on context
	async fn build_fill_tx_for_context(
		&self,
		context: EstimationContext<'_>,
		solver: &SolverEngine,
	) -> Result<Transaction, QuoteError> {
		match context {
			EstimationContext::Quote(quote) => {
				self.build_fill_tx_for_estimation(quote, 0, solver).await
			},
			EstimationContext::StandardOrder(standard_order) => self
				.build_fill_tx_for_standard_order_estimation(standard_order.clone(), solver)
				.await
				.map_err(|e| QuoteError::Internal(e.to_string())),
		}
	}

	/// Build claim transaction for estimation based on context
	async fn build_claim_tx_for_context(
		&self,
		context: EstimationContext<'_>,
		solver: &SolverEngine,
	) -> Result<Transaction, QuoteError> {
		match context {
			EstimationContext::Quote(quote) => {
				self.build_claim_tx_for_estimation(quote, 0, solver).await
			},
			EstimationContext::StandardOrder(standard_order) => self
				.build_claim_tx_for_standard_order_estimation(standard_order.clone(), solver)
				.await
				.map_err(|e| QuoteError::Internal(e.to_string())),
		}
	}
}
