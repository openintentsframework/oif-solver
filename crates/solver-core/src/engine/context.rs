//! Execution context utilities for the OIF solver system.
//!
//! This module provides utilities for building execution contexts by extracting
//! chain information from intents and fetching real-time blockchain data such as
//! gas prices and solver balances.

use super::token_manager::TokenManager;
use crate::SolverError;
use alloy_primitives::hex;
use solver_config::Config;
use solver_delivery::DeliveryService;
use solver_types::{Address, ExecutionContext, Intent};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Execution context builder for the solver engine.
///
/// This struct provides methods to build chain-aware execution contexts
/// by extracting chain information from intents and fetching real-time data.
pub struct ContextBuilder {
	delivery: Arc<DeliveryService>,
	solver_address: Address,
	token_manager: Arc<TokenManager>,
	_config: Config,
}

impl ContextBuilder {
	/// Creates a new context builder.
	pub fn new(
		delivery: Arc<DeliveryService>,
		solver_address: Address,
		token_manager: Arc<TokenManager>,
		config: Config,
	) -> Self {
		Self {
			delivery,
			solver_address,
			token_manager,
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
			Ok(chains) => chains,
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

		// Extract from outputs array (EIP-7683 orders/intents)
		if let Some(outputs) = data.get("outputs").and_then(|v| v.as_array()) {
			for output in outputs.iter() {
				if let Some(chain_id_value) = output.get("chain_id") {
					if let Some(chain_id) = parse_chain_id(chain_id_value) {
						chains.push(chain_id);
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

	/// Gets token addresses for a given chain from the token manager.
	///
	/// Returns addresses of tokens configured for this chain.
	fn get_common_tokens_for_chain(&self, chain_id: u64) -> Vec<String> {
		self.token_manager
			.get_tokens_for_chain(chain_id)
			.into_iter()
			.map(|token| hex::encode(&token.address.0))
			.collect()
	}
}
