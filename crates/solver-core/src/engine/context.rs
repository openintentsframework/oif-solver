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
			},
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
			},
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
							},
						}
					} else {
						// Parse decimal string
						match s.parse::<u64>() {
							Ok(parsed) => {
								tracing::info!("Parsed decimal chain ID '{}' as {}", s, parsed);
								Some(parsed)
							},
							Err(e) => {
								tracing::warn!("Failed to parse decimal chain ID '{}': {}", s, e);
								None
							},
						}
					}
				},
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
				},
				Err(e) => {
					tracing::warn!(
						chain_id = chain_id,
						error = %e,
						"Failed to fetch native balance for chain"
					);
				},
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
					},
					Err(e) => {
						tracing::warn!(
							chain_id = chain_id,
							token = %token_address,
							error = %e,
							"Failed to fetch token balance"
						);
					},
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

#[cfg(test)]
mod tests {
	use super::*;
	use mockall::predicate::*;
	use serde_json::json;
	use solver_account::MockAccountInterface;
	use solver_delivery::MockDeliveryInterface;
	use solver_types::{
		networks::RpcEndpoint, utils::tests::builders::IntentBuilder, Address, Intent,
		NetworkConfig, NetworksConfig, TokenConfig,
	};
	use std::collections::HashMap;

	fn create_test_intent(standard: &str, data: serde_json::Value) -> Intent {
		IntentBuilder::new()
			.with_standard(standard)
			.with_data(data)
			.build()
	}

	fn create_mock_delivery_service() -> Arc<DeliveryService> {
		let mut mock_delivery = MockDeliveryInterface::new();

		// Mock get_chain_data calls
		mock_delivery
			.expect_get_gas_price()
			.returning(|_| Box::pin(async { Ok("20000000000".to_string()) }));
		mock_delivery
			.expect_get_block_number()
			.returning(|_| Box::pin(async { Ok(12345678) }));

		// Mock get_balance calls
		mock_delivery
			.expect_get_balance()
			.returning(|_, _, _| Box::pin(async { Ok("1000000000000000000".to_string()) }));

		mock_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});

		let mut implementations = HashMap::new();
		implementations.insert(
			1,
			Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
		);

		Arc::new(DeliveryService::new(implementations, 1, 20))
	}

	fn create_mock_account_service() -> Arc<solver_account::AccountService> {
		let mut mock_account = MockAccountInterface::new();

		mock_account
			.expect_address()
			.returning(|| Box::pin(async { Ok(Address([0xAB; 20].to_vec())) }));
		mock_account
			.expect_get_private_key()
			.returning(|| solver_types::SecretString::from("0x1234567890abcdef"));
		mock_account
			.expect_config_schema()
			.returning(|| Box::new(solver_account::implementations::local::LocalWalletSchema));

		Arc::new(solver_account::AccountService::new(Box::new(mock_account)))
	}

	fn create_test_networks_config() -> NetworksConfig {
		let mut networks = NetworksConfig::new();

		// Add test network with some tokens
		let network_config = NetworkConfig {
			rpc_urls: vec![RpcEndpoint::http_only("http://localhost:8545".to_string())],
			input_settler_address: Address([0x11; 20].to_vec()),
			output_settler_address: Address([0x22; 20].to_vec()),
			tokens: vec![
				TokenConfig {
					address: Address([0xA0; 20].to_vec()),
					decimals: 6,
					symbol: "USDC".to_string(),
				},
				TokenConfig {
					address: Address([0xC0; 20].to_vec()),
					decimals: 18,
					symbol: "WETH".to_string(),
				},
			],
			input_settler_compact_address: None,
			the_compact_address: None,
			allocator_address: None,
		};

		networks.insert(1, network_config);
		networks
	}

	fn create_context_builder() -> ContextBuilder {
		let delivery = create_mock_delivery_service();
		let account = create_mock_account_service();
		let networks = create_test_networks_config();
		let token_manager = Arc::new(TokenManager::new(networks, delivery.clone(), account));

		ContextBuilder::new(
			delivery,
			Address([0xAB; 20].to_vec()),
			token_manager,
			solver_config::ConfigBuilder::default().build(),
		)
	}

	#[test]
	fn test_extract_eip7683_chains_with_numeric_chain_ids() {
		let context_builder = create_context_builder();
		let intent_data = json!({
			"origin_chain_id": 1,
			"outputs": [
				{"chain_id": 137, "amount": "1000000"},
				{"chain_id": 42161, "amount": "2000000"}
			]
		});

		let result = context_builder.extract_eip7683_chains(&intent_data);
		assert!(result.is_ok());

		let chains = result.unwrap();
		assert_eq!(chains.len(), 3);
		assert!(chains.contains(&1));
		assert!(chains.contains(&137));
		assert!(chains.contains(&42161));
	}

	#[test]
	fn test_extract_eip7683_chains_with_string_chain_ids() {
		let context_builder = create_context_builder();
		let intent_data = json!({
			"origin_chain_id": "1",
			"outputs": [
				{"chain_id": "137", "amount": "1000000"},
				{"chain_id": "42161", "amount": "2000000"}
			]
		});

		let result = context_builder.extract_eip7683_chains(&intent_data);
		assert!(result.is_ok());

		let chains = result.unwrap();
		assert_eq!(chains.len(), 3);
		assert!(chains.contains(&1));
		assert!(chains.contains(&137));
		assert!(chains.contains(&42161));
	}

	#[test]
	fn test_extract_eip7683_chains_with_hex_chain_ids() {
		let context_builder = create_context_builder();
		let intent_data = json!({
			"origin_chain_id": "0x1",
			"outputs": [
				{"chain_id": "0x89", "amount": "1000000"}, // 137 in hex
				{"chain_id": "0xa4b1", "amount": "2000000"} // 42161 in hex
			]
		});

		let result = context_builder.extract_eip7683_chains(&intent_data);
		assert!(result.is_ok());

		let chains = result.unwrap();
		assert_eq!(chains.len(), 3);
		assert!(chains.contains(&1));
		assert!(chains.contains(&137));
		assert!(chains.contains(&42161));
	}

	#[test]
	fn test_extract_eip7683_chains_removes_duplicates() {
		let context_builder = create_context_builder();
		let intent_data = json!({
			"origin_chain_id": "1",
			"outputs": [
				{"chain_id": "1", "amount": "1000000"},
				{"chain_id": "1", "amount": "2000000"},
				{"chain_id": "137", "amount": "3000000"}
			]
		});

		let result = context_builder.extract_eip7683_chains(&intent_data);
		assert!(result.is_ok());

		let chains = result.unwrap();
		assert_eq!(chains.len(), 2);
		assert!(chains.contains(&1));
		assert!(chains.contains(&137));
	}

	#[test]
	fn test_extract_eip7683_chains_no_chains_found() {
		let context_builder = create_context_builder();
		let intent_data = json!({
			"some_other_field": "value"
		});

		let result = context_builder.extract_eip7683_chains(&intent_data);
		assert!(result.is_err());
		assert!(result.unwrap_err().to_string().contains("No chains found"));
	}

	#[test]
	fn test_extract_eip7683_chains_invalid_chain_id_format() {
		let context_builder = create_context_builder();
		let intent_data = json!({
			"origin_chain_id": "invalid",
			"outputs": [
				{"chain_id": "0xGGG", "amount": "1000000"}, // Invalid hex
				{"chain_id": "not_a_number", "amount": "2000000"}
			]
		});

		let result = context_builder.extract_eip7683_chains(&intent_data);
		assert!(result.is_err());
		assert!(result.unwrap_err().to_string().contains("No chains found"));
	}

	#[test]
	fn test_extract_chains_from_intent_unsupported_standard() {
		let context_builder = create_context_builder();
		let intent_data = json!({"some": "data"});
		let intent = create_test_intent("unsupported_standard", intent_data);

		let result = context_builder.extract_chains_from_intent(&intent);
		assert!(result.is_err());
		assert!(result
			.unwrap_err()
			.to_string()
			.contains("Unsupported intent standard"));
	}

	#[test]
	fn test_get_common_tokens_for_chain() {
		let context_builder = create_context_builder();

		// Test with configured network (chain 1 has USDC and WETH)
		let tokens_chain_1 = context_builder.get_common_tokens_for_chain(1);
		assert_eq!(tokens_chain_1.len(), 2);
		assert!(tokens_chain_1.contains(&"a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0".to_string()));
		assert!(tokens_chain_1.contains(&"c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0".to_string()));

		// Test with unconfigured network
		let tokens_unknown = context_builder.get_common_tokens_for_chain(999);
		assert_eq!(tokens_unknown.len(), 0);
	}

	#[tokio::test]
	async fn test_fetch_solver_balances_success() {
		let context_builder = create_context_builder();
		let chains = vec![1];

		let result = context_builder.fetch_solver_balances(&chains).await;
		assert!(result.is_ok());

		let balances = result.unwrap();
		// Should have native balance + 2 token balances for chain 1
		assert_eq!(balances.len(), 3);

		// Check native balance
		assert!(balances.contains_key(&(1, None)));
		assert_eq!(balances.get(&(1, None)).unwrap(), "1000000000000000000");

		// Check token balances
		assert!(balances.contains_key(&(
			1,
			Some("a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0".to_string())
		)));
		assert!(balances.contains_key(&(
			1,
			Some("c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0".to_string())
		)));
	}

	#[tokio::test]
	async fn test_build_execution_context_success() {
		let context_builder = create_context_builder();
		let intent_data = json!({
			"origin_chain_id": "1"
		});

		let intent = create_test_intent("eip7683", intent_data);
		let result = context_builder.build_execution_context(&intent).await;

		assert!(result.is_ok());
		let context = result.unwrap();

		// Should have chain data for chain 1
		assert_eq!(context.chain_data.len(), 1);
		assert!(context.chain_data.contains_key(&1));

		let chain_data = context.chain_data.get(&1).unwrap();
		assert_eq!(chain_data.chain_id, 1);
		assert_eq!(chain_data.gas_price, "20000000000");
		assert_eq!(chain_data.block_number, 12345678);

		// Should have solver balances (native + 2 tokens)
		assert_eq!(context.solver_balances.len(), 3);

		// Timestamp should be set
		assert!(context.timestamp > 0);
	}

	#[tokio::test]
	async fn test_build_execution_context_with_multiple_chains() {
		// Create a more comprehensive mock for multiple chains
		let mut mock_delivery_1 = MockDeliveryInterface::new();
		let mut mock_delivery_137 = MockDeliveryInterface::new();

		// Setup mocks for chain 1 - should be called 3 times (native + 2 tokens)
		mock_delivery_1
			.expect_get_gas_price()
			.times(1)
			.returning(|_| Box::pin(async { Ok("20000000000".to_string()) }));
		mock_delivery_1
			.expect_get_block_number()
			.times(1)
			.returning(|_| Box::pin(async { Ok(12345678) }));
		mock_delivery_1
			.expect_get_balance()
			.times(3) // native + 2 tokens
			.returning(|_, _, _| Box::pin(async { Ok("1000000000000000000".to_string()) }));
		mock_delivery_1.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});

		// Setup mocks for chain 137 - should be called 1 time (native only)
		mock_delivery_137
			.expect_get_gas_price()
			.times(1)
			.returning(|_| Box::pin(async { Ok("30000000000".to_string()) }));
		mock_delivery_137
			.expect_get_block_number()
			.times(1)
			.returning(|_| Box::pin(async { Ok(87654321) }));
		mock_delivery_137
			.expect_get_balance()
			.times(1) // native only, no tokens configured
			.returning(|_, _, _| Box::pin(async { Ok("2000000000000000000".to_string()) }));
		mock_delivery_137.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});

		let mut implementations = HashMap::new();
		implementations.insert(
			1,
			Arc::new(mock_delivery_1) as Arc<dyn solver_delivery::DeliveryInterface>,
		);
		implementations.insert(
			137,
			Arc::new(mock_delivery_137) as Arc<dyn solver_delivery::DeliveryInterface>,
		);

		let delivery = Arc::new(DeliveryService::new(implementations, 1, 20));
		let account = create_mock_account_service();
		let networks = create_test_networks_config();
		let token_manager = Arc::new(TokenManager::new(networks, delivery.clone(), account));

		let context_builder = ContextBuilder::new(
			delivery,
			Address([0xAB; 20].to_vec()),
			token_manager,
			solver_config::ConfigBuilder::default().build(),
		);

		let intent_data = json!({
			"origin_chain_id": 1,
			"outputs": [
				{"chain_id": 137, "amount": "1000000"}
			]
		});

		let intent = create_test_intent("eip7683", intent_data);
		let result = context_builder.build_execution_context(&intent).await;

		assert!(result.is_ok());
		let context = result.unwrap();

		// Should have chain data for both chains
		assert_eq!(context.chain_data.len(), 2);
		assert!(context.chain_data.contains_key(&1));
		assert!(context.chain_data.contains_key(&137));

		// Verify chain-specific data
		let chain_1_data = context.chain_data.get(&1).unwrap();
		assert_eq!(chain_1_data.gas_price, "20000000000");
		assert_eq!(chain_1_data.block_number, 12345678);

		let chain_137_data = context.chain_data.get(&137).unwrap();
		assert_eq!(chain_137_data.gas_price, "30000000000");
		assert_eq!(chain_137_data.block_number, 87654321);

		// Should have solver balances for both chains: chain 1 (native + 2 tokens) + chain 137 (native only)
		assert_eq!(context.solver_balances.len(), 4);
	}
}
