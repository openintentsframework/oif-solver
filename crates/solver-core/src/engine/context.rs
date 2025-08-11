//! Execution context utilities for the OIF solver system.
//!
//! This module provides utilities for building execution contexts by extracting
//! chain information from intents and fetching real-time blockchain data such as
//! gas prices and solver balances.

use solver_config::Config;
use solver_delivery::DeliveryService;
use solver_types::{Address, ExecutionContext, Intent};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::SolverError;

/// Execution context builder for the solver engine.
///
/// This struct provides methods to build chain-aware execution contexts
/// by extracting chain information from intents and fetching real-time data.
pub struct ContextBuilder {
	delivery: Arc<DeliveryService>,
	solver_address: Address,
	_config: Config,
}

impl ContextBuilder {
	/// Creates a new context builder.
	pub fn new(delivery: Arc<DeliveryService>, solver_address: Address, config: Config) -> Self {
		Self {
			delivery,
			solver_address,
			_config: config,
		}
	}

	/// Builds the execution context for strategy decisions.
	///
	/// Fetches chain-specific data and solver balances for all chains involved in the intent.
	pub async fn build_execution_context(
		&self,
		intent: &Intent,
	) -> Result<ExecutionContext, SolverError> {
		let timestamp = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or(Duration::ZERO)
			.as_secs();

		// 1. Extract chains involved from the intent data
		let involved_chains = match self.extract_chains_from_intent(intent) {
			Ok(chains) => {
				tracing::debug!(
					intent_id = %intent.id,
					chains = ?chains,
					"Successfully extracted chains from intent"
				);
				chains
			}
			Err(e) => {
				tracing::error!(
					intent_id = %intent.id,
					error = %e,
					"Failed to extract chains from intent"
				);
				return Err(e);
			}
		};

		// 2. Fetch chain data for each relevant chain
		let mut chain_data = HashMap::new();
		for chain_id in &involved_chains {
			if let Ok(data) = self.delivery.get_chain_data(*chain_id).await {
				chain_data.insert(*chain_id, data);
			} else {
				tracing::warn!(
					chain_id = chain_id,
					intent_id = %intent.id,
					"Failed to fetch chain data, decision may be suboptimal"
				);
			}
		}

		// 3. Get solver balances for relevant chains/tokens
		let solver_balances = self.fetch_solver_balances(&involved_chains).await?;

		Ok(ExecutionContext {
			chain_data,
			solver_balances,
			timestamp,
		})
	}

	/// Extracts chain IDs involved in the intent based on its standard.
	///
	/// Parses the intent data to determine which chains are involved
	/// in the cross-chain operation.
	fn extract_chains_from_intent(&self, intent: &Intent) -> Result<Vec<u64>, SolverError> {
		tracing::debug!(
			intent_id = %intent.id,
			standard = %intent.standard,
			"Attempting to extract chains from intent"
		);

		match intent.standard.as_str() {
			"eip7683" => self.extract_eip7683_chains(&intent.data),
			_ => {
				tracing::warn!(
					standard = %intent.standard,
					intent_id = %intent.id,
					"Unsupported intent standard, using fallback chain detection"
				);
				Err(SolverError::Service(format!(
					"Unsupported intent standard: {}",
					intent.standard
				)))
			}
		}
	}

	/// Extracts chain IDs from EIP-7683 intent data.
	fn extract_eip7683_chains(&self, data: &serde_json::Value) -> Result<Vec<u64>, SolverError> {
		let mut chains = Vec::new();

		// Helper function to parse chain ID from either string or number, supporting hex
		let parse_chain_id = |value: &serde_json::Value| -> Option<u64> {
			match value {
				serde_json::Value::Number(n) => n.as_u64(),
				serde_json::Value::String(s) => {
					if let Some(hex_str) = s.strip_prefix("0x") {
						// Parse hex string
						match u64::from_str_radix(hex_str, 16) {
							Ok(parsed) => Some(parsed),
							Err(e) => {
								tracing::warn!("Failed to parse hex chain ID '{}': {}", s, e);
								None
							}
						}
					} else {
						// Parse decimal string
						match s.parse::<u64>() {
							Ok(parsed) => {
								tracing::info!("Parsed decimal chain ID '{}' as {}", s, parsed);
								Some(parsed)
							}
							Err(e) => {
								tracing::warn!("Failed to parse decimal chain ID '{}': {}", s, e);
								None
							}
						}
					}
				}
				_ => None,
			}
		};

		// Check for direct chain_id fields in the intent data first
		if let Some(origin_chain_value) = data.get("origin_chain_id") {
			if let Some(origin_chain) = parse_chain_id(origin_chain_value) {
				chains.push(origin_chain);
			}
		}

		// Extract from requested outputs (ERC-7930 interoperable addresses)
		if let Some(outputs) = data.get("requestedOutputs").and_then(|v| v.as_array()) {
			for (_, output) in outputs.iter().enumerate() {
				if let Some(asset) = output.get("asset").and_then(|v| v.as_str()) {
					match self.extract_chain_from_interop_address(asset) {
						Ok(chain_id) => {
							chains.push(chain_id);
						}
						Err(e) => {
							tracing::warn!("Failed to extract chain from asset {}: {}", asset, e);
						}
					}
				}
			}
		}

		// Remove duplicates and sort
		chains.sort_unstable();
		chains.dedup();

		if chains.is_empty() {
			return Err(SolverError::Service(
				"No chains found in EIP-7683 specific fields".to_string(),
			));
		}

		Ok(chains)
	}

	/// Extracts chain ID from ERC-7930 interoperable address format.
	///
	/// Expected format: "eip155:{chain_id}:{address}" or similar
	/// Handles both decimal and hex chain IDs (e.g., "0x7a69").
	fn extract_chain_from_interop_address(&self, address: &str) -> Result<u64, SolverError> {
		tracing::trace!("Attempting to extract chain from address: {}", address);

		// Handle ERC-7930 format: "eip155:1:0x..." or "eip155:0x7a69:0x..."
		if let Some(eip155_part) = address.strip_prefix("eip155:") {
			tracing::trace!("Found eip155 prefix, remaining part: {}", eip155_part);
			if let Some(colon_pos) = eip155_part.find(':') {
				let chain_part = &eip155_part[..colon_pos];
				tracing::trace!("Extracting chain_id from: {}", chain_part);

				// Try parsing as hex first (if it starts with "0x"), then as decimal
				let chain_id = if let Some(hex_str) = chain_part.strip_prefix("0x") {
					// Parse hex chain ID
					u64::from_str_radix(hex_str, 16).map_err(|e| {
						SolverError::Service(format!(
							"Invalid hex chain ID '{}' in address {}: {}",
							chain_part, address, e
						))
					})?
				} else {
					// Parse decimal chain ID
					chain_part.parse::<u64>().map_err(|e| {
						SolverError::Service(format!(
							"Invalid decimal chain ID '{}' in address {}: {}",
							chain_part, address, e
						))
					})?
				};

				tracing::trace!(
					"Successfully parsed chain_id {} from {}",
					chain_id,
					chain_part
				);
				return Ok(chain_id);
			} else {
				tracing::trace!("No second colon found in eip155 part: {}", eip155_part);
			}
		} else {
			tracing::trace!("Address does not start with eip155: prefix");
		}

		Err(SolverError::Service(format!(
			"Could not extract chain ID from address: {}",
			address
		)))
	}

	/// Fetches solver balances for all relevant chains and tokens.
	///
	/// This method gets the solver's balance for both native tokens and
	/// commonly used ERC-20 tokens on each chain.
	async fn fetch_solver_balances(
		&self,
		chains: &[u64],
	) -> Result<HashMap<(u64, Option<String>), String>, SolverError> {
		let mut balances = HashMap::new();

		// Use the solver address that was provided at initialization
		let solver_address = self.solver_address.to_string();

		for &chain_id in chains {
			// Get native token balance
			match self
				.delivery
				.get_balance(chain_id, &solver_address, None)
				.await
			{
				Ok(balance) => {
					balances.insert((chain_id, None), balance);
				}
				Err(e) => {
					tracing::warn!(
						chain_id = chain_id,
						error = %e,
						"Failed to fetch native balance for chain"
					);
				}
			}

			// Get balances for common tokens on this chain
			// TODO: This should be configurable per chain
			let common_tokens = self.get_common_tokens_for_chain(chain_id);
			for token_address in common_tokens {
				match self
					.delivery
					.get_balance(chain_id, &solver_address, Some(&token_address))
					.await
				{
					Ok(balance) => {
						balances.insert((chain_id, Some(token_address.clone())), balance);
					}
					Err(e) => {
						tracing::warn!(
							chain_id = chain_id,
							token = %token_address,
							error = %e,
							"Failed to fetch token balance"
						);
					}
				}
			}
		}

		Ok(balances)
	}

	/// Gets common token addresses for a given chain.
	///
	/// Returns addresses of commonly used tokens that the solver might hold.
	fn get_common_tokens_for_chain(&self, chain_id: u64) -> Vec<String> {
		// TODO: This should be configurable and loaded from config
		// For now, return some well-known token addresses per chain
		match chain_id {
			1 => vec![
				// Ethereum mainnet
				"0xA0b86a33E6441f8C4e73D2B95b8eCf3f1e9BfECa".to_string(), // USDC
				"0xdAC17F958D2ee523a2206206994597C13D831ec7".to_string(), // USDT
				"0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string(), // WETH
			],
			137 => vec![
				// Polygon
				"0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174".to_string(), // USDC
				"0xc2132D05D31c914a87C6611C10748AEb04B58e8F".to_string(), // USDT
				"0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619".to_string(), // WETH
			],
			42161 => vec![
				// Arbitrum One
				"0xA7D7079b0FEaD91F3e65f86E8915Cb59c1a4C664".to_string(), // USDC
				"0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9".to_string(), // USDT
				"0x82aF49447D8a07e3bd95BD0d56f35241523fBab1".to_string(), // WETH
			],
			_ => vec![], // No common tokens configured for this chain
		}
	}
}
