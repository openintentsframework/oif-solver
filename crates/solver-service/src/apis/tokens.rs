//! Token information API for the OIF Solver.
//!
//! This module provides endpoints to query supported tokens and networks
//! configured in the solver.

use alloy_primitives::hex;
use axum::{
	extract::{Path, State},
	http::StatusCode,
	Json,
};
use serde::Serialize;
use solver_config::Config;
use solver_core::SolverEngine;
use solver_types::with_0x_prefix;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Response structure for all supported tokens across all networks.
#[derive(Debug, Serialize)]
pub struct TokensResponse {
	/// Map of chain ID (as string) to network token information.
	pub networks: HashMap<String, NetworkTokens>,
}

/// Token information for a specific network.
#[derive(Debug, Serialize)]
pub struct NetworkTokens {
	/// The blockchain network ID.
	pub chain_id: u64,
	/// Input settler contract address.
	pub input_settler: String,
	/// Output settler contract address.
	pub output_settler: String,
	/// List of supported tokens on this network.
	pub tokens: Vec<TokenInfo>,
}

/// Information about a specific token.
#[derive(Debug, Serialize)]
pub struct TokenInfo {
	/// Token contract address.
	pub address: String,
	/// Token symbol (e.g., "USDC", "USDT").
	pub symbol: String,
	/// Number of decimal places for the token.
	pub decimals: u8,
}

/// Handles GET /api/v1/tokens requests.
///
/// Returns all supported tokens across all configured networks.
pub async fn get_tokens(State(solver): State<Arc<SolverEngine>>) -> Json<TokensResponse> {
	let networks = solver.token_manager().get_networks();

	let mut response = TokensResponse {
		networks: HashMap::new(),
	};

	for (chain_id, network) in networks {
		response.networks.insert(
			chain_id.to_string(),
			NetworkTokens {
				chain_id: *chain_id,
				input_settler: with_0x_prefix(&hex::encode(&network.input_settler_address.0)),
				output_settler: with_0x_prefix(&hex::encode(&network.output_settler_address.0)),
				tokens: network
					.tokens
					.iter()
					.map(|t| TokenInfo {
						address: with_0x_prefix(&hex::encode(&t.address.0)),
						symbol: t.symbol.clone(),
						decimals: t.decimals,
					})
					.collect(),
			},
		);
	}

	Json(response)
}

/// Handles GET /api/v1/tokens/{chain_id} requests.
///
/// Returns supported tokens for a specific chain.
pub async fn get_tokens_for_chain(
	Path(chain_id): Path<u64>,
	State(solver): State<Arc<SolverEngine>>,
) -> Result<Json<NetworkTokens>, StatusCode> {
	let networks = solver.token_manager().get_networks();

	match networks.get(&chain_id) {
		Some(network) => Ok(Json(NetworkTokens {
			chain_id,
			input_settler: with_0x_prefix(&hex::encode(&network.input_settler_address.0)),
			output_settler: with_0x_prefix(&hex::encode(&network.output_settler_address.0)),
			tokens: network
				.tokens
				.iter()
				.map(|t| TokenInfo {
					address: with_0x_prefix(&hex::encode(&t.address.0)),
					symbol: t.symbol.clone(),
					decimals: t.decimals,
				})
				.collect(),
		})),
		None => Err(StatusCode::NOT_FOUND),
	}
}

/// Handles GET /api/v1/tokens requests using shared_config.
///
/// Returns all supported tokens across all configured networks.
/// This version reads from shared_config to support hot reload.
pub async fn get_tokens_from_config(
	State(shared_config): State<Arc<RwLock<Config>>>,
) -> Json<TokensResponse> {
	let config = shared_config.read().await;

	let mut response = TokensResponse {
		networks: HashMap::new(),
	};

	for (chain_id, network) in &config.networks {
		response.networks.insert(
			chain_id.to_string(),
			NetworkTokens {
				chain_id: *chain_id,
				input_settler: with_0x_prefix(&hex::encode(&network.input_settler_address.0)),
				output_settler: with_0x_prefix(&hex::encode(&network.output_settler_address.0)),
				tokens: network
					.tokens
					.iter()
					.map(|t| TokenInfo {
						address: with_0x_prefix(&hex::encode(&t.address.0)),
						symbol: t.symbol.clone(),
						decimals: t.decimals,
					})
					.collect(),
			},
		);
	}

	Json(response)
}

/// Handles GET /api/v1/tokens/{chain_id} requests using shared_config.
///
/// Returns supported tokens for a specific chain.
/// This version reads from shared_config to support hot reload.
pub async fn get_tokens_for_chain_from_config(
	Path(chain_id): Path<u64>,
	State(shared_config): State<Arc<RwLock<Config>>>,
) -> Result<Json<NetworkTokens>, StatusCode> {
	let config = shared_config.read().await;

	match config.networks.get(&chain_id) {
		Some(network) => Ok(Json(NetworkTokens {
			chain_id,
			input_settler: with_0x_prefix(&hex::encode(&network.input_settler_address.0)),
			output_settler: with_0x_prefix(&hex::encode(&network.output_settler_address.0)),
			tokens: network
				.tokens
				.iter()
				.map(|t| TokenInfo {
					address: with_0x_prefix(&hex::encode(&t.address.0)),
					symbol: t.symbol.clone(),
					decimals: t.decimals,
				})
				.collect(),
		})),
		None => Err(StatusCode::NOT_FOUND),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::Address as AlloyAddress;
	use axum::extract::State;
	use solver_core::engine::token_manager::TokenManager;
	use solver_types::{
		networks::RpcEndpoint, Address, NetworkConfig, NetworksConfig, TokenConfig,
	};
	use std::collections::HashMap;

	/// Creates a mock TokenManager with test data for unit tests.
	fn create_mock_token_manager() -> Arc<TokenManager> {
		// Create test token configurations
		let usdc_token = TokenConfig {
			address: Address(AlloyAddress::from([1u8; 20]).to_vec()),
			symbol: "USDC".to_string(),
			decimals: 6,
		};

		let usdt_token = TokenConfig {
			address: Address(AlloyAddress::from([2u8; 20]).to_vec()),
			symbol: "USDT".to_string(),
			decimals: 6,
		};

		let weth_token = TokenConfig {
			address: Address(AlloyAddress::from([3u8; 20]).to_vec()),
			symbol: "WETH".to_string(),
			decimals: 18,
		};

		// Create test network configurations
		let mut networks = NetworksConfig::new();

		// Ethereum mainnet (chain ID 1)
		networks.insert(
			1,
			NetworkConfig {
				rpc_urls: vec![RpcEndpoint::http_only(
					"https://eth.example.com".to_string(),
				)],
				input_settler_address: Address(AlloyAddress::from([10u8; 20]).to_vec()),
				output_settler_address: Address(AlloyAddress::from([11u8; 20]).to_vec()),
				tokens: vec![usdc_token.clone(), weth_token.clone()],
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);

		// Polygon (chain ID 137)
		networks.insert(
			137,
			NetworkConfig {
				rpc_urls: vec![RpcEndpoint::http_only(
					"https://polygon.example.com".to_string(),
				)],
				input_settler_address: Address(AlloyAddress::from([20u8; 20]).to_vec()),
				output_settler_address: Address(AlloyAddress::from([21u8; 20]).to_vec()),
				tokens: vec![usdc_token, usdt_token],
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);

		// Create minimal mock services for TokenManager
		let delivery = Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1, 20));
		let account = Arc::new(solver_account::AccountService::new(Box::new(
			solver_account::implementations::local::LocalWallet::new(
				"0x1234567890123456789012345678901234567890123456789012345678901234",
			)
			.unwrap(),
		)));

		Arc::new(TokenManager::new(networks, delivery, account))
	}

	/// Creates a mock SolverEngine with test data for unit tests.
	fn create_mock_solver_engine() -> Arc<SolverEngine> {
		let token_manager = create_mock_token_manager();

		// Create minimal config for testing
		let config_toml = r#"
			[solver]
			id = "test-solver"
			monitoring_timeout_seconds = 30
			min_profitability_pct = 1.0
			
			[storage]
			primary = "memory"
			cleanup_interval_seconds = 3600
			[storage.implementations.memory]
			
			[delivery]
			min_confirmations = 1
			[delivery.implementations]
			
			[account]
			primary = "local"
			[account.implementations.local]
			private_key = "0x1234567890123456789012345678901234567890123456789012345678901234"
			
			[discovery]
			[discovery.implementations]
			
			[order]
			[order.implementations]
			[order.strategy]
			primary = "simple"
			[order.strategy.implementations.simple]
			
			[settlement]
			[settlement.implementations]
			
			[networks.1]
			chain_id = 1
			input_settler_address = "0x1111111111111111111111111111111111111111"
			output_settler_address = "0x2222222222222222222222222222222222222222"
			[[networks.1.rpc_urls]]
			http = "http://localhost:8545"
			[[networks.1.tokens]]
			symbol = "TEST"
			address = "0x3333333333333333333333333333333333333333"
			decimals = 18
		"#;
		let config: solver_config::Config =
			toml::from_str(config_toml).expect("Failed to parse test config");

		// Create mock services using proper constructors
		let storage = Arc::new(solver_storage::StorageService::new(Box::new(
			solver_storage::implementations::memory::MemoryStorage::new(),
		)));

		// Create account service with local wallet
		let account_config = toml::from_str(
			r#"private_key = "0x1234567890123456789012345678901234567890123456789012345678901234""#,
		)
		.expect("Failed to parse account config");
		let account = Arc::new(solver_account::AccountService::new(
			solver_account::implementations::local::create_account(&account_config)
				.expect("Failed to create account"),
		));

		// Create address from bytes
		let solver_address = Address(vec![1u8; 20]);

		// Create delivery service - using empty implementations map for testing
		let delivery = Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1, 20));

		// Create discovery service - using empty implementations map for testing
		let discovery = Arc::new(solver_discovery::DiscoveryService::new(HashMap::new()));

		// Create order service - needs implementations and strategy
		let strategy_config = toml::Value::Table(toml::value::Table::new());
		let strategy =
			solver_order::implementations::strategies::simple::create_strategy(&strategy_config)
				.expect("Failed to create strategy");
		let order = Arc::new(solver_order::OrderService::new(HashMap::new(), strategy));

		// Create settlement service - using empty implementations map for testing
		let settlement = Arc::new(solver_settlement::SettlementService::new(
			HashMap::new(),
			20,
		));

		// Create pricing service with mock implementation
		let pricing_config = toml::Value::Table(toml::value::Table::new());
		let pricing_impl =
			solver_pricing::implementations::mock::create_mock_pricing(&pricing_config)
				.expect("Failed to create mock pricing");
		let pricing = Arc::new(solver_pricing::PricingService::new(
			pricing_impl,
			Vec::new(),
		));

		let event_bus = solver_core::engine::event_bus::EventBus::new(100);

		Arc::new(solver_core::SolverEngine::new(
			config,
			storage,
			account,
			solver_address,
			delivery,
			discovery,
			order,
			settlement,
			pricing,
			event_bus,
			token_manager,
		))
	}

	#[tokio::test]
	async fn test_get_tokens_returns_all_networks() {
		let solver = create_mock_solver_engine();
		let response = get_tokens(State(solver)).await;

		let tokens_response = response.0;

		// Should have 2 networks
		assert_eq!(tokens_response.networks.len(), 2);

		// Check Ethereum mainnet (chain ID 1)
		let eth_network = tokens_response.networks.get("1").unwrap();
		assert_eq!(eth_network.chain_id, 1);
		assert_eq!(
			eth_network.input_settler,
			"0x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
		);
		assert_eq!(
			eth_network.output_settler,
			"0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
		);
		assert_eq!(eth_network.tokens.len(), 2);

		// Check tokens on Ethereum
		let usdc_token = eth_network
			.tokens
			.iter()
			.find(|t| t.symbol == "USDC")
			.unwrap();
		assert_eq!(
			usdc_token.address,
			"0x0101010101010101010101010101010101010101"
		);
		assert_eq!(usdc_token.decimals, 6);

		let weth_token = eth_network
			.tokens
			.iter()
			.find(|t| t.symbol == "WETH")
			.unwrap();
		assert_eq!(
			weth_token.address,
			"0x0303030303030303030303030303030303030303"
		);
		assert_eq!(weth_token.decimals, 18);

		// Check Polygon (chain ID 137)
		let polygon_network = tokens_response.networks.get("137").unwrap();
		assert_eq!(polygon_network.chain_id, 137);
		assert_eq!(
			polygon_network.input_settler,
			"0x1414141414141414141414141414141414141414"
		);
		assert_eq!(
			polygon_network.output_settler,
			"0x1515151515151515151515151515151515151515"
		);
		assert_eq!(polygon_network.tokens.len(), 2);

		// Check tokens on Polygon
		let usdc_token = polygon_network
			.tokens
			.iter()
			.find(|t| t.symbol == "USDC")
			.unwrap();
		assert_eq!(
			usdc_token.address,
			"0x0101010101010101010101010101010101010101"
		);

		let usdt_token = polygon_network
			.tokens
			.iter()
			.find(|t| t.symbol == "USDT")
			.unwrap();
		assert_eq!(
			usdt_token.address,
			"0x0202020202020202020202020202020202020202"
		);
		assert_eq!(usdt_token.decimals, 6);
	}

	#[tokio::test]
	async fn test_get_tokens_for_chain_valid_chain_id() {
		let solver = create_mock_solver_engine();
		let response = get_tokens_for_chain(Path(1), State(solver)).await;

		assert!(response.is_ok());
		let network_tokens = response.unwrap().0;

		assert_eq!(network_tokens.chain_id, 1);
		assert_eq!(
			network_tokens.input_settler,
			"0x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
		);
		assert_eq!(
			network_tokens.output_settler,
			"0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
		);
		assert_eq!(network_tokens.tokens.len(), 2);

		// Verify token details
		let usdc_token = network_tokens
			.tokens
			.iter()
			.find(|t| t.symbol == "USDC")
			.unwrap();
		assert_eq!(
			usdc_token.address,
			"0x0101010101010101010101010101010101010101"
		);
		assert_eq!(usdc_token.decimals, 6);
	}

	#[tokio::test]
	async fn test_get_tokens_for_chain_invalid_chain_id() {
		let solver = create_mock_solver_engine();
		let response = get_tokens_for_chain(Path(999), State(solver)).await;

		assert!(response.is_err());
		assert_eq!(response.unwrap_err(), StatusCode::NOT_FOUND);
	}

	#[tokio::test]
	async fn test_get_tokens_for_chain_polygon() {
		let solver = create_mock_solver_engine();
		let response = get_tokens_for_chain(Path(137), State(solver)).await;

		assert!(response.is_ok());
		let network_tokens = response.unwrap().0;

		assert_eq!(network_tokens.chain_id, 137);
		assert_eq!(
			network_tokens.input_settler,
			"0x1414141414141414141414141414141414141414"
		);
		assert_eq!(
			network_tokens.output_settler,
			"0x1515151515151515151515151515151515151515"
		);
		assert_eq!(network_tokens.tokens.len(), 2);

		// Should have USDC and USDT
		let symbols: Vec<&str> = network_tokens
			.tokens
			.iter()
			.map(|t| t.symbol.as_str())
			.collect();
		assert!(symbols.contains(&"USDC"));
		assert!(symbols.contains(&"USDT"));
	}

	#[test]
	fn test_tokens_response_serialization() {
		let mut networks = HashMap::new();
		networks.insert(
			"1".to_string(),
			NetworkTokens {
				chain_id: 1,
				input_settler: "0x1234567890123456789012345678901234567890".to_string(),
				output_settler: "0x0987654321098765432109876543210987654321".to_string(),
				tokens: vec![TokenInfo {
					address: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string(),
					symbol: "TEST".to_string(),
					decimals: 18,
				}],
			},
		);

		let response = TokensResponse { networks };

		// Test that it can be serialized to JSON
		let json = serde_json::to_string(&response).unwrap();
		assert!(json.contains("\"chain_id\":1"));
		assert!(json.contains("\"symbol\":\"TEST\""));
		assert!(json.contains("\"decimals\":18"));
	}

	#[test]
	fn test_network_tokens_serialization() {
		let network_tokens = NetworkTokens {
			chain_id: 42,
			input_settler: "0x1111111111111111111111111111111111111111".to_string(),
			output_settler: "0x2222222222222222222222222222222222222222".to_string(),
			tokens: vec![
				TokenInfo {
					address: "0x3333333333333333333333333333333333333333".to_string(),
					symbol: "TOKEN1".to_string(),
					decimals: 6,
				},
				TokenInfo {
					address: "0x4444444444444444444444444444444444444444".to_string(),
					symbol: "TOKEN2".to_string(),
					decimals: 18,
				},
			],
		};

		// Test that it can be serialized to JSON
		let json = serde_json::to_string(&network_tokens).unwrap();
		assert!(json.contains("\"chain_id\":42"));
		assert!(json.contains("\"TOKEN1\""));
		assert!(json.contains("\"TOKEN2\""));
		assert!(json.contains("\"decimals\":6"));
		assert!(json.contains("\"decimals\":18"));
	}

	#[test]
	fn test_token_info_serialization() {
		let token_info = TokenInfo {
			address: "0x5555555555555555555555555555555555555555".to_string(),
			symbol: "MYTOKEN".to_string(),
			decimals: 8,
		};

		// Test that it can be serialized to JSON
		let json = serde_json::to_string(&token_info).unwrap();
		assert!(json.contains("\"address\":\"0x5555555555555555555555555555555555555555\""));
		assert!(json.contains("\"symbol\":\"MYTOKEN\""));
		assert!(json.contains("\"decimals\":8"));
	}

	#[test]
	fn test_with_0x_prefix_integration() {
		// Test that addresses are properly formatted with 0x prefix
		let address_without_prefix = "1234567890123456789012345678901234567890";
		let address_with_prefix = with_0x_prefix(address_without_prefix);
		assert_eq!(
			address_with_prefix,
			"0x1234567890123456789012345678901234567890"
		);

		// Test that addresses already with prefix are not double-prefixed
		let address_already_prefixed = "0x1234567890123456789012345678901234567890";
		let result = with_0x_prefix(address_already_prefixed);
		assert_eq!(result, "0x1234567890123456789012345678901234567890");
	}
}
