// Uniswap V3 on-chain routing (no API required)
//
// This module provides on-chain routing for Uniswap V3 by:
// 1. Querying the Quoter V2 contract for best quotes
// 2. Encoding calldata for the SwapRouter contract
// 3. Supporting single-hop and 2-hop (via WETH) routes

use alloy_primitives::{address, Address, U256, Uint};
use alloy_sol_types::{sol, SolCall};
use solver_types::QuoteError;
use std::collections::HashMap;

// Uniswap V3 Quoter V2 ABI (with struct params)
sol! {
	interface IQuoterV2 {
		struct QuoteExactInputSingleParams {
			address tokenIn;
			address tokenOut;
			uint256 amountIn;
			uint24 fee;
			uint160 sqrtPriceLimitX96;
		}

		function quoteExactInputSingle(
			QuoteExactInputSingleParams memory params
		) external returns (
			uint256 amountOut,
			uint160 sqrtPriceX96After,
			uint32 initializedTicksCrossed,
			uint256 gasEstimate
		);

		struct QuoteExactInputParams {
			bytes path;
			uint256 amountIn;
		}

		function quoteExactInput(
			QuoteExactInputParams memory params
		) external returns (
			uint256 amountOut,
			uint160[] memory sqrtPriceX96AfterList,
			uint32[] memory initializedTicksCrossedList,
			uint256 gasEstimate
		);
	}
}

// Uniswap V3 SwapRouter ABI
sol! {
	interface ISwapRouter {
		struct ExactInputSingleParams {
			address tokenIn;
			address tokenOut;
			uint24 fee;
			address recipient;
			uint256 deadline;
			uint256 amountIn;
			uint256 amountOutMinimum;
			uint160 sqrtPriceLimitX96;
		}

		function exactInputSingle(ExactInputSingleParams calldata params) external payable returns (uint256 amountOut);

		struct ExactInputParams {
			bytes path;
			address recipient;
			uint256 deadline;
			uint256 amountIn;
			uint256 amountOutMinimum;
		}

		function exactInput(ExactInputParams calldata params) external payable returns (uint256 amountOut);
	}
}

/// Configuration for Uniswap V3 on-chain routing
#[derive(Debug, Clone)]
pub struct UniswapV3OnchainRouter {
	pub weth_addresses: HashMap<u64, Address>,
	pub quoter_addresses: HashMap<u64, Address>,
	pub router_addresses: HashMap<u64, Address>,
	pub default_fees: Vec<u32>,
	pub slippage_bps: u16,
	pub bridge_via_weth: bool,
}

impl UniswapV3OnchainRouter {
	/// Create a new Uniswap V3 on-chain router from config
	pub fn from_config(config: &solver_config::UniswapV3OnchainConfig) -> Result<Self, QuoteError> {
		let weth_addresses: HashMap<u64, Address> = config
			.weth
			.iter()
			.map(|(chain_id, addr)| {
				let address = addr
					.parse::<Address>()
					.map_err(|e| QuoteError::InvalidRequest(format!("Invalid WETH address: {}", e)))?;
				Ok((*chain_id, address))
			})
			.collect::<Result<_, QuoteError>>()?;

		let quoter_addresses: HashMap<u64, Address> = config
			.quoter
			.iter()
			.map(|(chain_id, addr)| {
				let address = addr
					.parse::<Address>()
					.map_err(|e| QuoteError::InvalidRequest(format!("Invalid Quoter address: {}", e)))?;
				Ok((*chain_id, address))
			})
			.collect::<Result<_, QuoteError>>()?;

		let router_addresses: HashMap<u64, Address> = config
			.router
			.iter()
			.map(|(chain_id, addr)| {
				let address = addr
					.parse::<Address>()
					.map_err(|e| QuoteError::InvalidRequest(format!("Invalid Router address: {}", e)))?;
				Ok((*chain_id, address))
			})
			.collect::<Result<_, QuoteError>>()?;

		Ok(Self {
			weth_addresses,
			quoter_addresses,
			router_addresses,
			default_fees: config.default_fees.clone(),
			slippage_bps: config.slippage_bps,
			bridge_via_weth: config.bridge_via_weth,
		})
	}

	/// Quote a single-hop swap
	pub async fn quote_single_hop(
		&self,
		rpc_url: &str,
		chain_id: u64,
		token_in: Address,
		token_out: Address,
		amount_in: U256,
		fee: u32,
	) -> Result<U256, QuoteError> {
		let quoter = self
			.quoter_addresses
			.get(&chain_id)
			.ok_or_else(|| QuoteError::InvalidRequest(format!("No Quoter for chain {}", chain_id)))?;

		// Build the call with struct params
		let params = IQuoterV2::QuoteExactInputSingleParams {
			tokenIn: token_in,
			tokenOut: token_out,
			amountIn: amount_in,
			fee: Uint::<24, 1>::from(fee),
			sqrtPriceLimitX96: Uint::<160, 3>::ZERO, // No price limit
		};

		let call = IQuoterV2::quoteExactInputSingleCall { params };

		let calldata = call.abi_encode();

		// Execute eth_call
		let client = reqwest::Client::new();
		let response = client
			.post(rpc_url)
			.json(&serde_json::json!({
				"jsonrpc": "2.0",
				"id": 1,
				"method": "eth_call",
				"params": [{
					"to": format!("{:?}", quoter),
					"data": format!("0x{}", hex::encode(&calldata))
				}, "latest"]
			}))
			.send()
			.await
			.map_err(|e| QuoteError::Internal(format!("RPC call failed: {}", e)))?;

	let json: serde_json::Value = response
		.json()
		.await
		.map_err(|e| QuoteError::Internal(format!("Failed to parse RPC response: {}", e)))?;

	if let Some(error) = json.get("error") {
		let error_msg = error.get("message").and_then(|m| m.as_str()).unwrap_or("unknown");
		let error_code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
		tracing::warn!(
			"RPC eth_call failed: chain={}, quoter={:?}, token_in={:?}, token_out={:?}, fee={}, error_code={}, error_msg={}",
			chain_id,
			quoter,
			token_in,
			token_out,
			fee,
			error_code,
			error_msg
		);
		return Err(QuoteError::Internal(format!(
			"RPC error (code {}): {}",
			error_code,
			error_msg
		)));
	}

		let result_hex = json
			.get("result")
			.and_then(|r| r.as_str())
			.ok_or_else(|| QuoteError::Internal("No result in RPC response".to_string()))?;

		let result_bytes = hex::decode(result_hex.trim_start_matches("0x"))
			.map_err(|e| QuoteError::Internal(format!("Invalid hex result: {}", e)))?;

		// Decode the result (amountOut is the first return value)
		if result_bytes.len() < 32 {
			return Err(QuoteError::Internal("Invalid Quoter response length".to_string()));
		}

		let amount_out = U256::from_be_slice(&result_bytes[0..32]);
		Ok(amount_out)
	}

	/// Try to find the best single-hop route by testing all default fees
	pub async fn find_best_single_hop(
		&self,
		rpc_url: &str,
		chain_id: u64,
		token_in: Address,
		token_out: Address,
		amount_in: U256,
	) -> Result<(U256, u32), QuoteError> {
		let mut best_amount_out = U256::ZERO;
		let mut best_fee = 0u32;

	for &fee in &self.default_fees {
		match self
			.quote_single_hop(rpc_url, chain_id, token_in, token_out, amount_in, fee)
			.await
		{
			Ok(amount_out) if amount_out > best_amount_out => {
				tracing::debug!("Single-hop quote: fee={}, amount_out={}", fee, amount_out);
				best_amount_out = amount_out;
				best_fee = fee;
			}
			Ok(_) => {} // Lower quote, skip
			Err(e) => {
				tracing::debug!("Single-hop quote failed for fee={}: {}", fee, e);
			}
		}
	}

	if best_amount_out == U256::ZERO {
		tracing::warn!(
			"No single-hop route found: chain={}, token_in={:?}, token_out={:?}",
			chain_id,
			token_in,
			token_out
		);
		return Err(QuoteError::InsufficientLiquidity);
	}

		Ok((best_amount_out, best_fee))
	}

	/// Quote a 2-hop swap via WETH
	pub async fn quote_two_hop_via_weth(
		&self,
		rpc_url: &str,
		chain_id: u64,
		token_in: Address,
		token_out: Address,
		amount_in: U256,
	) -> Result<(U256, u32, u32), QuoteError> {
		let weth = self
			.weth_addresses
			.get(&chain_id)
			.ok_or_else(|| QuoteError::InvalidRequest(format!("No WETH for chain {}", chain_id)))?;

		// Skip if token_in or token_out is already WETH
		if token_in == *weth || token_out == *weth {
			return Err(QuoteError::InvalidRequest("Cannot bridge via WETH when one token is WETH".to_string()));
		}

		let mut best_amount_out = U256::ZERO;
		let mut best_fee1 = 0u32;
		let mut best_fee2 = 0u32;

		// Try all fee combinations for token_in -> WETH -> token_out
		for &fee1 in &self.default_fees {
			for &fee2 in &self.default_fees {
				// First hop: token_in -> WETH
				let amount_mid = match self
					.quote_single_hop(rpc_url, chain_id, token_in, *weth, amount_in, fee1)
					.await
				{
					Ok(amt) => amt,
					Err(_) => continue,
				};

				// Second hop: WETH -> token_out
				let amount_out = match self
					.quote_single_hop(rpc_url, chain_id, *weth, token_out, amount_mid, fee2)
					.await
				{
					Ok(amt) => amt,
					Err(_) => continue,
				};

				if amount_out > best_amount_out {
					best_amount_out = amount_out;
					best_fee1 = fee1;
					best_fee2 = fee2;
				}
			}
		}

		if best_amount_out == U256::ZERO {
			return Err(QuoteError::InsufficientLiquidity);
		}

		Ok((best_amount_out, best_fee1, best_fee2))
	}

	/// Build calldata for exactInputSingle
	pub fn build_exact_input_single_calldata(
		&self,
		token_in: Address,
		token_out: Address,
		fee: u32,
		recipient: Address,
		amount_in: U256,
		amount_out_min: U256,
	) -> Result<Vec<u8>, QuoteError> {
		let deadline = U256::from(u64::MAX); // Far future deadline

		let params = ISwapRouter::ExactInputSingleParams {
			tokenIn: token_in,
			tokenOut: token_out,
			fee: Uint::<24, 1>::from(fee),
			recipient,
			deadline,
			amountIn: amount_in,
			amountOutMinimum: amount_out_min,
			sqrtPriceLimitX96: Uint::<160, 3>::ZERO,
		};

		let call = ISwapRouter::exactInputSingleCall { params };
		Ok(call.abi_encode())
	}

	/// Build calldata for exactInput (multi-hop)
	pub fn build_exact_input_calldata(
		&self,
		path: Vec<u8>,
		recipient: Address,
		amount_in: U256,
		amount_out_min: U256,
	) -> Result<Vec<u8>, QuoteError> {
		let deadline = U256::from(u64::MAX);

		let params = ISwapRouter::ExactInputParams {
			path: path.into(),
			recipient,
			deadline,
			amountIn: amount_in,
			amountOutMinimum: amount_out_min,
		};

		let call = ISwapRouter::exactInputCall { params };
		Ok(call.abi_encode())
	}

	/// Encode a Uniswap V3 path (token0, fee0, token1, fee1, token2, ...)
	pub fn encode_path(tokens: &[Address], fees: &[u32]) -> Result<Vec<u8>, QuoteError> {
		if tokens.len() != fees.len() + 1 {
			return Err(QuoteError::InvalidRequest(
				"Path encoding: tokens.len() must be fees.len() + 1".to_string(),
			));
		}

		let mut path = Vec::new();
		for i in 0..fees.len() {
			path.extend_from_slice(tokens[i].as_slice());
			path.extend_from_slice(&fees[i].to_be_bytes()[1..]); // 3 bytes for fee (uint24)
		}
		path.extend_from_slice(tokens.last().unwrap().as_slice());

		Ok(path)
	}

	/// Calculate minimum output amount with slippage
	pub fn apply_slippage(&self, amount_out: U256) -> U256 {
		let slippage_multiplier = 10000 - self.slippage_bps as u128;
		(amount_out * U256::from(slippage_multiplier)) / U256::from(10000u128)
	}

	/// Get the best route and build calldata
	pub async fn get_route_and_calldata(
		&self,
		rpc_url: &str,
		chain_id: u64,
		token_in: Address,
		token_out: Address,
		amount_in: U256,
		recipient: Address,
	) -> Result<(Vec<u8>, U256, Address), QuoteError> {
		tracing::info!(
			"Uniswap V3 on-chain: finding route for chain={}, token_in={:?}, token_out={:?}, amount_in={}",
			chain_id,
			token_in,
			token_out,
			amount_in
		);

		// Try single-hop first
		match self
			.find_best_single_hop(rpc_url, chain_id, token_in, token_out, amount_in)
			.await
		{
			Ok((amount_out, fee)) => {
				tracing::info!(
					"Uniswap V3 on-chain: found single-hop route with fee={}, amount_out={}",
					fee,
					amount_out
				);

				let amount_out_min = self.apply_slippage(amount_out);
				let calldata = self.build_exact_input_single_calldata(
					token_in,
					token_out,
					fee,
					recipient,
					amount_in,
					amount_out_min,
				)?;

				let router = self
					.router_addresses
					.get(&chain_id)
					.ok_or_else(|| QuoteError::InvalidRequest(format!("No Router for chain {}", chain_id)))?;

				return Ok((calldata, amount_out, *router));
			}
			Err(e) => {
				tracing::debug!("Single-hop failed: {}", e);
			}
		}

		// Try 2-hop via WETH if enabled
		if self.bridge_via_weth {
			match self
				.quote_two_hop_via_weth(rpc_url, chain_id, token_in, token_out, amount_in)
				.await
			{
				Ok((amount_out, fee1, fee2)) => {
					tracing::info!(
						"Uniswap V3 on-chain: found 2-hop route via WETH with fees={}/{}, amount_out={}",
						fee1,
						fee2,
						amount_out
					);

					let weth = *self.weth_addresses.get(&chain_id).unwrap();
					let path = Self::encode_path(&[token_in, weth, token_out], &[fee1, fee2])?;

					let amount_out_min = self.apply_slippage(amount_out);
					let calldata = self.build_exact_input_calldata(path, recipient, amount_in, amount_out_min)?;

					let router = self
						.router_addresses
						.get(&chain_id)
						.ok_or_else(|| QuoteError::InvalidRequest(format!("No Router for chain {}", chain_id)))?;

					return Ok((calldata, amount_out, *router));
				}
				Err(e) => {
					tracing::warn!("2-hop via WETH failed: {}", e);
				}
			}
		}

		Err(QuoteError::InsufficientLiquidity)
	}
}

