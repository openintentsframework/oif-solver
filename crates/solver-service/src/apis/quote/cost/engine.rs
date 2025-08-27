use alloy_primitives::U256;
use solver_config::Config;
use solver_core::SolverEngine;
use solver_types::{
	costs::{CostComponent, QuoteCost},
	Quote, QuoteError, QuoteOrder, SignatureType,
};
use solver_types::{
	Address, ExecutionParams, FillProof, Order, OrderStatus, Transaction, TransactionHash,
};

#[derive(Debug, Clone)]
pub struct PricingConfig {
	currency: String,
	commission_bps: u32,
	gas_buffer_bps: u32,
	rate_buffer_bps: u32,
	enable_live_gas_estimate: bool,
}

impl PricingConfig {
	pub fn default_values() -> Self {
		Self {
			currency: "USDC".to_string(),
			commission_bps: 20,
			gas_buffer_bps: 1000,
			rate_buffer_bps: 14,
			enable_live_gas_estimate: false,
		}
	}

	/// Builds pricing config from a TOML table (e.g. strategy implementation table)
	pub fn from_table(table: &toml::Value) -> Self {
		let defaults = Self::default_values();
		Self {
			currency: table
				.get("pricing_currency")
				.and_then(|v| v.as_str())
				.unwrap_or(&defaults.currency)
				.to_string(),
			commission_bps: table
				.get("commission_bps")
				.and_then(|v| v.as_integer())
				.unwrap_or(defaults.commission_bps as i64) as u32,
			gas_buffer_bps: table
				.get("gas_buffer_bps")
				.and_then(|v| v.as_integer())
				.unwrap_or(defaults.gas_buffer_bps as i64) as u32,
			rate_buffer_bps: table
				.get("rate_buffer_bps")
				.and_then(|v| v.as_integer())
				.unwrap_or(defaults.rate_buffer_bps as i64) as u32,
			enable_live_gas_estimate: table
				.get("enable_live_gas_estimate")
				.and_then(|v| v.as_bool())
				.unwrap_or(defaults.enable_live_gas_estimate),
		}
	}

	fn from_config(config: &Config) -> Self {
		// Try to get the config table from the primary strategy implementation
		let strategy_name = &config.order.strategy.primary;
		let default_table = toml::Value::Table(toml::map::Map::new());
		let table = config
			.order
			.strategy
			.implementations
			.get(strategy_name)
			.unwrap_or(&default_table);
		tracing::info!("Pricing config: {:?}", table);
		Self::from_table(table)
	}
}

pub struct CostEngine;

impl CostEngine {
	pub fn new() -> Self {
		Self
	}

	pub async fn estimate_cost(
		&self,
		quote: &Quote,
		solver: &SolverEngine,
		config: &Config,
		pricing: &PricingConfig,
	) -> Result<QuoteCost, QuoteError> {
		let (origin_chain_id, dest_chain_id) = self.extract_origin_dest_chain_ids(quote)?;

		// Get gas units from config (preferred) or fallback to minimal defaults
		let (open_units, mut fill_units, mut claim_units) =
			self.estimate_gas_units_for_orders(&quote.orders, config);

		if pricing.enable_live_gas_estimate {
			tracing::info!("Estimating fill gas on destination chain");
			if let Ok(tx) = self
				.build_fill_tx_for_estimation(quote, dest_chain_id, solver)
				.await
			{
				match solver
					.delivery()
					.estimate_gas(dest_chain_id, tx.clone())
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
							to = %tx.to.as_ref().map(|a| a.to_string()).unwrap_or_else(|| "<none>".into()),
							"estimate_gas(fill) failed; using heuristic"
						);
					},
				}
			} else {
				tracing::warn!("Failed to build fill transaction for estimation");
			}
		}

		if pricing.enable_live_gas_estimate {
			if let Ok(tx) = self
				.build_claim_tx_for_estimation(quote, origin_chain_id, solver)
				.await
			{
				tracing::debug!(
					"finalise tx bytes_len={} to={}",
					tx.data.len(),
					tx.to
						.as_ref()
						.map(|a| a.to_string())
						.unwrap_or_else(|| "<none>".into())
				);
				match solver
					.delivery()
					.estimate_gas(origin_chain_id, tx.clone())
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
							to = %tx.to.as_ref().map(|a| a.to_string()).unwrap_or_else(|| "<none>".into()),
							"estimate_gas(finalise) failed; using heuristic"
						);
					},
				}
			}
		}

		// Gas prices
		let origin_gp = U256::from_str_radix(
			&solver
				.delivery()
				.get_chain_data(origin_chain_id)
				.await
				.map_err(|e| QuoteError::Internal(e.to_string()))?
				.gas_price,
			10,
		)
		.unwrap_or(U256::from(1_000_000_000u64));
		let dest_gp = U256::from_str_radix(
			&solver
				.delivery()
				.get_chain_data(dest_chain_id)
				.await
				.map_err(|e| QuoteError::Internal(e.to_string()))?
				.gas_price,
			10,
		)
		.unwrap_or(U256::from(1_000_000_000u64));
		// Costs: open+claim on origin, fill on dest
		let open_cost_wei_uint = origin_gp.saturating_mul(U256::from(open_units));
		let fill_cost_wei_uint = dest_gp.saturating_mul(U256::from(fill_units));
		let claim_cost_wei_uint = origin_gp.saturating_mul(U256::from(claim_units));

		let open_cost_wei_str = open_cost_wei_uint.to_string();
		let fill_cost_wei_str = fill_cost_wei_uint.to_string();
		let claim_cost_wei_str = claim_cost_wei_uint.to_string();

		let gas_subtotal_w = add_many(&[
			open_cost_wei_str.clone(),
			fill_cost_wei_str.clone(),
			claim_cost_wei_str.clone(),
		]);
		let buffer_gas = apply_bps(&gas_subtotal_w, pricing.gas_buffer_bps);

		let base_price = "0".to_string();
		let buffer_rates = apply_bps(&base_price, pricing.rate_buffer_bps);

		let subtotal = add_many(&[
			base_price.clone(),
			gas_subtotal_w.clone(),
			buffer_gas.clone(),
			buffer_rates.clone(),
		]);
		let commission_amount = apply_bps(&subtotal, pricing.commission_bps);
		let total = add_decimals(&subtotal, &commission_amount);
		// all values are in wei
		Ok(QuoteCost {
			currency: pricing.currency.clone(),
			components: vec![
				CostComponent {
					name: "base-price".into(),
					amount: base_price.clone(),
					amount_wei: Some(base_price),
				},
				CostComponent {
					name: "gas-open".into(),
					amount: open_cost_wei_str.clone(),
					amount_wei: Some(open_cost_wei_str),
				},
				CostComponent {
					name: "gas-fill".into(),
					amount: fill_cost_wei_str.clone(),
					amount_wei: Some(fill_cost_wei_str),
				},
				CostComponent {
					name: "gas-claim".into(),
					amount: claim_cost_wei_str.clone(),
					amount_wei: Some(claim_cost_wei_str),
				},
				CostComponent {
					name: "buffer-gas".into(),
					amount: buffer_gas.clone(),
					amount_wei: Some(buffer_gas),
				},
				CostComponent {
					name: "buffer-rates".into(),
					amount: buffer_rates.clone(),
					amount_wei: Some(buffer_rates),
				},
			],
			commission_bps: pricing.commission_bps,
			commission_amount,
			subtotal,
			total,
		})
	}

	fn estimate_gas_units_for_orders(
		&self,
		orders: &[QuoteOrder],
		config: &Config,
	) -> (u64, u64, u64) {
		// Detect flow type and try to get from config first
		let flow_key = self.determine_flow_key(orders);

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
				let open = units.open.unwrap_or(0);
				let fill = units.fill.unwrap_or(0);
				let claim = units.claim.unwrap_or(0);
				return (open, fill, claim);
			} else {
				tracing::warn!("Flow '{}' not found in gas config flows", flow);
			}
		}
		tracing::warn!(
			"No gas config found for flow {:?}, using minimal fallbacks",
			flow_key
		);
		let open = 0; // Compact flows have no open step
		let fill = 0; // Conservative estimate - should be replaced with real data
		let claim = 0; // Conservative estimate - should be replaced with real data

		(open, fill, claim)
	}

	/// Detect a coarse flow type for selecting config overrides
	fn determine_flow_key(&self, orders: &[QuoteOrder]) -> Option<String> {
		if orders
			.iter()
			.any(|o| o.primary_type.contains("Lock") || o.primary_type.contains("Compact"))
		{
			return Some("compact_resource_lock".to_string());
		}
		// Default to permit2-based escrow if using EIP-712 style signatures
		if orders
			.iter()
			.any(|o| matches!(o.signature_type, SignatureType::Eip712))
		{
			return Some("permit2_escrow".to_string());
		}
		None
	}

	fn extract_origin_dest_chain_ids(&self, quote: &Quote) -> Result<(u64, u64), QuoteError> {
		let input = quote
			.details
			.available_inputs
			.get(0)
			.ok_or_else(|| QuoteError::InvalidRequest("missing input".to_string()))?;
		let output = quote
			.details
			.requested_outputs
			.get(0)
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
				.get(0)
				.ok_or_else(|| QuoteError::InvalidRequest("missing input".to_string()))?
				.asset
				.ethereum_chain_id()
				.map_err(|e| QuoteError::InvalidRequest(e.to_string()))?],
			output_chain_ids: vec![quote
				.details
				.requested_outputs
				.get(0)
				.ok_or_else(|| QuoteError::InvalidRequest("missing output".to_string()))?
				.asset
				.ethereum_chain_id()
				.map_err(|e| QuoteError::InvalidRequest(e.to_string()))?],
			execution_params: None,
			prepare_tx_hash: None,
			fill_tx_hash: None,
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
			gas_price: U256::from(1_000_000_000u64), // 1 gwei default
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
}

// helpers
fn add_decimals(a: &str, b: &str) -> String {
	add_many(&[a.to_string(), b.to_string()])
}

fn add_many(values: &[String]) -> String {
	let mut sum = U256::ZERO;
	for v in values {
		if let Ok(n) = U256::from_str_radix(v, 10) {
			sum = sum.saturating_add(n);
		}
	}
	sum.to_string()
}

fn apply_bps(value: &str, bps: u32) -> String {
	let v = U256::from_str_radix(value, 10).unwrap_or(U256::ZERO);
	(v.saturating_mul(U256::from(bps as u64)) / U256::from(10_000u64)).to_string()
}
