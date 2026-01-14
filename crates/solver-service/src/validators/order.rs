//! Order validator for the OIF solver service.
//!
//! This module contains the validator for the OIF solver service.
//! It validates the order and ensures the user has sufficient capacity to fill the order.

use alloy_primitives::{hex, Address as AlloyAddress, U256};
use alloy_sol_types::SolCall;
use solver_config::Config;
use solver_core::SolverEngine;
use solver_types::{
	standards::eip7683::{interfaces::StandardOrder, LockType},
	APIError, ApiErrorType,
};
use std::convert::TryFrom;

mod interfaces {
	use alloy_sol_types::sol;

	sol! {
		function balanceOf(address owner, uint256 id) external view returns (uint256);
	}
}

pub async fn ensure_user_capacity_for_order(
	solver: &SolverEngine,
	config: &Config,
	lock_type: LockType,
	standard_order: &StandardOrder,
) -> Result<(), APIError> {
	let origin_chain_id: u64 =
		u64::try_from(standard_order.originChainId).map_err(|_| APIError::BadRequest {
			error_type: ApiErrorType::OrderValidationFailed,
			message: "Origin chain ID missing or invalid in order".to_string(),
			details: None,
		})?;

	let user = &standard_order.user;

	match lock_type {
		LockType::ResourceLock => {
			for input in &standard_order.inputs {
				let token_id = input[0];
				let amount = input[1];
				if amount.is_zero() {
					continue;
				}
				validate_compact_deposit_for_order(
					solver,
					config,
					origin_chain_id,
					user,
					token_id,
					amount,
				)
				.await?;
			}
		},
		_ => {
			// Defensive check: validates sufficient balance before calling `openFor`.
			// Trade-off: This adds an extra RPC call, but improves UX by failing fast
			// with a clear error rather than waiting for the `openFor` transaction to revert.
			// The `openFor` call would fail anyway with insufficient balance, so this
			// check is optional but recommended for better user experience.
			for input in &standard_order.inputs {
				let token_field = input[0];
				let amount = input[1];
				if amount.is_zero() {
					continue;
				}

				let token_bytes = token_field.to_be_bytes::<32>();
				let token_address = AlloyAddress::from_slice(&token_bytes[12..]);

				validate_wallet_balance_for_order(
					solver,
					origin_chain_id,
					user,
					&token_address,
					amount,
				)
				.await?;
			}
		},
	}

	Ok(())
}

async fn validate_wallet_balance_for_order(
	solver: &SolverEngine,
	chain_id: u64,
	user: &AlloyAddress,
	token: &AlloyAddress,
	required_amount: U256,
) -> Result<(), APIError> {
	let user_hex = hex::encode(user.as_slice());
	let token_hex = hex::encode(token.as_slice());

	let balance_str = solver
		.delivery()
		.get_balance(chain_id, &user_hex, Some(&token_hex))
		.await
		.map_err(|e| APIError::BadRequest {
			error_type: ApiErrorType::OrderValidationFailed,
			message: format!("Failed to fetch user balance: {}", e),
			details: None,
		})?;

	// Parse balance - handle both hex (0x prefix) and decimal formats
	let balance = if let Some(hex_str) = balance_str.strip_prefix("0x") {
		U256::from_str_radix(hex_str, 16).map_err(|e| APIError::BadRequest {
			error_type: ApiErrorType::OrderValidationFailed,
			message: format!("Failed to parse user balance '{}': {}", balance_str, e),
			details: None,
		})?
	} else {
		U256::from_str_radix(&balance_str, 10).map_err(|e| APIError::BadRequest {
			error_type: ApiErrorType::OrderValidationFailed,
			message: format!("Failed to parse user balance '{}': {}", balance_str, e),
			details: None,
		})?
	};

	if balance < required_amount {
		return Err(APIError::BadRequest {
			error_type: ApiErrorType::OrderValidationFailed,
			message: format!(
				"User {:#x} has insufficient balance for token {:#x} on chain {} (required {}, available {})",
				user,
				token,
				chain_id,
				required_amount,
				balance,
			),
			details: None,
		});
	}

	Ok(())
}

async fn validate_compact_deposit_for_order(
	solver: &SolverEngine,
	config: &Config,
	chain_id: u64,
	user: &AlloyAddress,
	token_id: U256,
	required_amount: U256,
) -> Result<(), APIError> {
	let network = config
		.networks
		.get(&chain_id)
		.ok_or_else(|| APIError::BadRequest {
			error_type: ApiErrorType::OrderValidationFailed,
			message: format!("Network {} not configured for solver", chain_id),
			details: None,
		})?;

	let compact_address =
		network
			.the_compact_address
			.as_ref()
			.ok_or_else(|| APIError::BadRequest {
				error_type: ApiErrorType::OrderValidationFailed,
				message: format!("TheCompact address not configured for chain {}", chain_id),
				details: None,
			})?;

	let call_data = interfaces::balanceOfCall {
		owner: *user,
		id: token_id,
	}
	.abi_encode();

	let tx = solver_types::Transaction {
		to: Some(compact_address.clone()),
		data: call_data,
		value: U256::ZERO,
		chain_id,
		nonce: None,
		gas_limit: None,
		gas_price: None,
		max_fee_per_gas: None,
		max_priority_fee_per_gas: None,
	};

	let response = solver
		.delivery()
		.contract_call(chain_id, tx)
		.await
		.map_err(|e| APIError::BadRequest {
			error_type: ApiErrorType::OrderValidationFailed,
			message: format!("Failed to query TheCompact deposit: {}", e),
			details: None,
		})?;

	if response.len() != 32 {
		return Err(APIError::BadRequest {
			error_type: ApiErrorType::OrderValidationFailed,
			message: format!(
				"Unexpected TheCompact balanceOf response length: expected 32 bytes, got {}",
				response.len()
			),
			details: None,
		});
	}

	let mut balance_buf = [0u8; 32];
	balance_buf.copy_from_slice(response.as_ref());
	let balance = U256::from_be_bytes(balance_buf);

	if balance < required_amount {
		return Err(APIError::BadRequest {
			error_type: ApiErrorType::OrderValidationFailed,
			message: format!(
				"Compact deposit for user {:#x} is insufficient on chain {} (required {}, available {})",
				user,
				chain_id,
				required_amount,
				balance,
			),
			details: None,
		});
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::{hex, Address as AlloyAddress, Bytes};
	use async_trait::async_trait;
	use solver_account::{implementations::local::LocalWallet, AccountService};
	use solver_config::ConfigBuilder;
	use solver_core::{engine::token_manager::TokenManager, EventBus, SolverEngine};
	use solver_delivery::{DeliveryError, DeliveryInterface, DeliveryService};
	use solver_discovery::DiscoveryService;
	use solver_order::{implementations::strategies::simple::create_strategy, OrderService};
	use solver_pricing::{implementations::mock, PricingService};
	use solver_settlement::SettlementService;
	use solver_storage::{implementations::memory::MemoryStorage, StorageService};
	use solver_types::{
		networks::RpcEndpoint,
		utils::tests::builders::{NetworkConfigBuilder, NetworksConfigBuilder},
		validation::ConfigSchema,
	};
	use std::{collections::HashMap, sync::Arc};

	const TEST_CHAIN_ID: u64 = 1;
	const TEST_USER: &str = "0x1111111111111111111111111111111111111111";
	const TEST_TOKEN: &str = "0x2222222222222222222222222222222222222222";
	const TEST_COMPACT: &str = "0x3333333333333333333333333333333333333333";
	const TEST_SOLVER: &str = "0x4444444444444444444444444444444444444444";
	const TEST_PK: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

	struct TestDelivery {
		balances: HashMap<(u64, String, Option<String>), String>,
		contract_responses: HashMap<u64, Vec<u8>>,
	}

	impl TestDelivery {
		fn new(
			balances: HashMap<(u64, String, Option<String>), String>,
			contract_responses: HashMap<u64, Vec<u8>>,
		) -> Self {
			Self {
				balances,
				contract_responses,
			}
		}
	}

	#[async_trait]
	impl DeliveryInterface for TestDelivery {
		fn config_schema(&self) -> Box<dyn ConfigSchema> {
			unimplemented!("config schema not required for tests")
		}

		async fn submit(
			&self,
			_: solver_types::Transaction,
			_: Option<solver_delivery::TransactionTrackingWithConfig>,
		) -> Result<solver_types::TransactionHash, DeliveryError> {
			unimplemented!("submit not used in tests")
		}

		async fn get_receipt(
			&self,
			_: &solver_types::TransactionHash,
			_: u64,
		) -> Result<solver_types::TransactionReceipt, DeliveryError> {
			unimplemented!("get_receipt not used in tests")
		}

		async fn get_gas_price(&self, _: u64) -> Result<String, DeliveryError> {
			unimplemented!("get_gas_price not used in tests")
		}

		async fn get_balance(
			&self,
			address: &str,
			token: Option<&str>,
			chain_id: u64,
		) -> Result<String, DeliveryError> {
			let key = (chain_id, address.to_string(), token.map(|t| t.to_string()));
			self.balances
				.get(&key)
				.cloned()
				.ok_or_else(|| DeliveryError::Network("balance not set".to_string()))
		}

		async fn get_allowance(
			&self,
			_: &str,
			_: &str,
			_: &str,
			_: u64,
		) -> Result<String, DeliveryError> {
			unimplemented!("get_allowance not used in tests")
		}

		async fn get_nonce(&self, _: &str, _: u64) -> Result<u64, DeliveryError> {
			unimplemented!("get_nonce not used in tests")
		}

		async fn get_block_number(&self, _: u64) -> Result<u64, DeliveryError> {
			unimplemented!("get_block_number not used in tests")
		}

		async fn estimate_gas(&self, _: solver_types::Transaction) -> Result<u64, DeliveryError> {
			unimplemented!("estimate_gas not used in tests")
		}

		async fn eth_call(&self, tx: solver_types::Transaction) -> Result<Bytes, DeliveryError> {
			self.contract_responses
				.get(&tx.chain_id)
				.cloned()
				.map(Bytes::from)
				.ok_or_else(|| DeliveryError::Network("contract response not set".to_string()))
		}
	}

	fn build_networks(chain_id: u64, compact_address: &str) -> solver_types::NetworksConfig {
		let network = NetworkConfigBuilder::new()
			.the_compact_address_hex(compact_address)
			.unwrap()
			.add_rpc_endpoint(RpcEndpoint::http_only("http://localhost:8545".to_string()))
			.build();
		NetworksConfigBuilder::new()
			.add_network(chain_id, network)
			.build()
	}

	fn build_config(chain_id: u64, compact_address: &str) -> Config {
		let networks = build_networks(chain_id, compact_address);
		ConfigBuilder::new().networks(networks).build()
	}

	fn build_solver_engine(
		config: Config,
		delivery_impls: HashMap<u64, Arc<dyn DeliveryInterface>>,
	) -> SolverEngine {
		let networks = config.networks.clone();
		let storage = Arc::new(StorageService::new(Box::new(MemoryStorage::new())));
		let account = Arc::new(AccountService::new(Box::new(
			LocalWallet::new(TEST_PK).unwrap(),
		)));
		let delivery = Arc::new(DeliveryService::new(delivery_impls, 1, 3));
		let discovery = Arc::new(DiscoveryService::new(HashMap::new()));
		let strategy = create_strategy(&toml::Value::Table(toml::map::Map::new())).unwrap();
		let order = Arc::new(OrderService::new(HashMap::new(), strategy));
		let settlement = Arc::new(SettlementService::new(HashMap::new(), 3));
		let event_bus = EventBus::new(32);
		let token_manager = Arc::new(TokenManager::new(
			networks,
			delivery.clone(),
			account.clone(),
		));
		let pricing_impl =
			mock::create_mock_pricing(&toml::Value::Table(toml::map::Map::new())).unwrap();
		let pricing = Arc::new(PricingService::new(pricing_impl, Vec::new()));
		let solver_address = solver_types::parse_address(TEST_SOLVER).unwrap();

		SolverEngine::new(
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
		)
	}

	fn parse_alloy_address(value: &str) -> AlloyAddress {
		let bytes = hex::decode(value.trim_start_matches("0x")).unwrap();
		AlloyAddress::from_slice(&bytes)
	}

	fn build_standard_order(chain_id: u64, token_field: U256, amount: U256) -> StandardOrder {
		use solver_types::standards::eip7683::interfaces::SolMandateOutput;

		let output = SolMandateOutput {
			oracle: [0u8; 32].into(),
			settler: [0u8; 32].into(),
			chainId: U256::from(chain_id),
			token: [0u8; 32].into(),
			amount: U256::ZERO,
			recipient: [0u8; 32].into(),
			callbackData: Vec::new().into(),
			context: Vec::new().into(),
		};

		StandardOrder {
			user: parse_alloy_address(TEST_USER),
			nonce: U256::from(1u64),
			originChainId: U256::from(chain_id),
			expires: 0,
			fillDeadline: 0,
			inputOracle: parse_alloy_address("0x0000000000000000000000000000000000000000"),
			inputs: vec![[token_field, amount]],
			outputs: vec![output],
		}
	}

	fn token_to_u256(address: AlloyAddress) -> U256 {
		let mut bytes = [0u8; 32];
		bytes[12..].copy_from_slice(address.as_slice());
		U256::from_be_bytes(bytes)
	}

	#[tokio::test]
	async fn test_ensure_user_capacity_permit2_succeeds() {
		let amount = U256::from(500u64);
		let token_u256 = token_to_u256(parse_alloy_address(TEST_TOKEN));
		let standard_order = build_standard_order(TEST_CHAIN_ID, token_u256, amount);

		let mut balances = HashMap::new();
		let user_hex = hex::encode(parse_alloy_address(TEST_USER).as_slice());
		let token_hex = hex::encode(parse_alloy_address(TEST_TOKEN).as_slice());
		balances.insert(
			(TEST_CHAIN_ID, user_hex, Some(token_hex)),
			"0x3e8".to_string(), // 1000 in hex
		);

		let delivery =
			Arc::new(TestDelivery::new(balances, HashMap::new())) as Arc<dyn DeliveryInterface>;
		let mut delivery_map = HashMap::new();
		delivery_map.insert(TEST_CHAIN_ID, delivery);

		let config = build_config(TEST_CHAIN_ID, TEST_COMPACT);
		let solver = build_solver_engine(config.clone(), delivery_map);

		assert!(super::ensure_user_capacity_for_order(
			&solver,
			&config,
			LockType::Permit2Escrow,
			&standard_order,
		)
		.await
		.is_ok());
	}

	#[tokio::test]
	async fn test_ensure_user_capacity_permit2_insufficient_balance() {
		let amount = U256::from(500u64);
		let token_u256 = token_to_u256(parse_alloy_address(TEST_TOKEN));
		let standard_order = build_standard_order(TEST_CHAIN_ID, token_u256, amount);

		let mut balances = HashMap::new();
		let user_hex = hex::encode(parse_alloy_address(TEST_USER).as_slice());
		let token_hex = hex::encode(parse_alloy_address(TEST_TOKEN).as_slice());
		balances.insert(
			(TEST_CHAIN_ID, user_hex, Some(token_hex)),
			"0xa".to_string(), // 10 in hex
		);

		let delivery =
			Arc::new(TestDelivery::new(balances, HashMap::new())) as Arc<dyn DeliveryInterface>;
		let mut delivery_map = HashMap::new();
		delivery_map.insert(TEST_CHAIN_ID, delivery);

		let config = build_config(TEST_CHAIN_ID, TEST_COMPACT);
		let solver = build_solver_engine(config.clone(), delivery_map);

		let result = super::ensure_user_capacity_for_order(
			&solver,
			&config,
			LockType::Permit2Escrow,
			&standard_order,
		)
		.await;

		match result {
			Err(APIError::BadRequest { message, .. }) => {
				assert!(message.contains("insufficient balance"));
			},
			_ => panic!("expected insufficient balance error"),
		}
	}

	#[tokio::test]
	async fn test_ensure_user_capacity_resource_lock_succeeds() {
		let amount = U256::from(500u64);
		let token_id = U256::from(123u64);
		let standard_order = build_standard_order(TEST_CHAIN_ID, token_id, amount);

		let mut contract_responses = HashMap::new();
		contract_responses.insert(TEST_CHAIN_ID, amount.to_be_bytes::<32>().to_vec());

		let delivery = Arc::new(TestDelivery::new(HashMap::new(), contract_responses))
			as Arc<dyn DeliveryInterface>;
		let mut delivery_map = HashMap::new();
		delivery_map.insert(TEST_CHAIN_ID, delivery);

		let config = build_config(TEST_CHAIN_ID, TEST_COMPACT);
		let solver = build_solver_engine(config.clone(), delivery_map);

		assert!(super::ensure_user_capacity_for_order(
			&solver,
			&config,
			LockType::ResourceLock,
			&standard_order,
		)
		.await
		.is_ok());
	}

	#[tokio::test]
	async fn test_ensure_user_capacity_resource_lock_insufficient() {
		let amount = U256::from(500u64);
		let token_id = U256::from(123u64);
		let standard_order = build_standard_order(TEST_CHAIN_ID, token_id, amount);

		let mut contract_responses = HashMap::new();
		contract_responses.insert(
			TEST_CHAIN_ID,
			U256::from(100u64).to_be_bytes::<32>().to_vec(),
		);

		let delivery = Arc::new(TestDelivery::new(HashMap::new(), contract_responses))
			as Arc<dyn DeliveryInterface>;
		let mut delivery_map = HashMap::new();
		delivery_map.insert(TEST_CHAIN_ID, delivery);

		let config = build_config(TEST_CHAIN_ID, TEST_COMPACT);
		let solver = build_solver_engine(config.clone(), delivery_map);

		let result = super::ensure_user_capacity_for_order(
			&solver,
			&config,
			LockType::ResourceLock,
			&standard_order,
		)
		.await;

		match result {
			Err(APIError::BadRequest { message, .. }) => {
				assert!(message.contains("Compact deposit"));
			},
			_ => panic!("expected compact deposit failure"),
		}
	}

	#[tokio::test]
	async fn test_ensure_user_capacity_invalid_chain_id() {
		let amount = U256::from(500u64);
		let token_u256 = token_to_u256(parse_alloy_address(TEST_TOKEN));
		let mut standard_order = build_standard_order(TEST_CHAIN_ID, token_u256, amount);

		// Set chain ID to a value that exceeds u64::MAX when converted
		standard_order.originChainId = U256::from_be_slice(&[0xff; 32]);

		let delivery = Arc::new(TestDelivery::new(HashMap::new(), HashMap::new()))
			as Arc<dyn DeliveryInterface>;
		let mut delivery_map = HashMap::new();
		delivery_map.insert(TEST_CHAIN_ID, delivery);

		let config = build_config(TEST_CHAIN_ID, TEST_COMPACT);
		let solver = build_solver_engine(config.clone(), delivery_map);

		let result = super::ensure_user_capacity_for_order(
			&solver,
			&config,
			LockType::Permit2Escrow,
			&standard_order,
		)
		.await;

		match result {
			Err(APIError::BadRequest { message, .. }) => {
				assert!(message.contains("Origin chain ID missing or invalid"));
			},
			_ => panic!("expected invalid chain ID error"),
		}
	}

	#[tokio::test]
	async fn test_ensure_user_capacity_network_not_configured() {
		let amount = U256::from(500u64);
		let token_id = U256::from(123u64);
		let wrong_chain_id = 999u64;
		let standard_order = build_standard_order(wrong_chain_id, token_id, amount);

		let mut contract_responses = HashMap::new();
		contract_responses.insert(TEST_CHAIN_ID, amount.to_be_bytes::<32>().to_vec());

		let delivery = Arc::new(TestDelivery::new(HashMap::new(), contract_responses))
			as Arc<dyn DeliveryInterface>;
		let mut delivery_map = HashMap::new();
		delivery_map.insert(TEST_CHAIN_ID, delivery);

		// Config only has TEST_CHAIN_ID, not wrong_chain_id
		let config = build_config(TEST_CHAIN_ID, TEST_COMPACT);
		let solver = build_solver_engine(config.clone(), delivery_map);

		let result = super::ensure_user_capacity_for_order(
			&solver,
			&config,
			LockType::ResourceLock,
			&standard_order,
		)
		.await;

		match result {
			Err(APIError::BadRequest { message, .. }) => {
				assert!(message.contains("Network") && message.contains("not configured"));
			},
			_ => panic!("expected network not configured error"),
		}
	}

	#[tokio::test]
	async fn test_ensure_user_capacity_compact_address_not_configured() {
		use solver_types::{networks::NetworkConfig, parse_address};

		let amount = U256::from(500u64);
		let token_id = U256::from(123u64);
		let standard_order = build_standard_order(TEST_CHAIN_ID, token_id, amount);

		let mut contract_responses = HashMap::new();
		contract_responses.insert(TEST_CHAIN_ID, amount.to_be_bytes::<32>().to_vec());

		let delivery = Arc::new(TestDelivery::new(HashMap::new(), contract_responses))
			as Arc<dyn DeliveryInterface>;
		let mut delivery_map = HashMap::new();
		delivery_map.insert(TEST_CHAIN_ID, delivery);

		// Build config manually without TheCompact address (builder sets a default)
		let network = NetworkConfig {
			rpc_urls: vec![RpcEndpoint::http_only("http://localhost:8545".to_string())],
			input_settler_address: parse_address(TEST_SOLVER).unwrap(),
			output_settler_address: parse_address(TEST_SOLVER).unwrap(),
			tokens: vec![],
			input_settler_compact_address: None,
			the_compact_address: None, // Explicitly set to None
			allocator_address: None,
		};
		let mut networks_config = HashMap::new();
		networks_config.insert(TEST_CHAIN_ID, network);
		let config = ConfigBuilder::new().networks(networks_config).build();
		let solver = build_solver_engine(config.clone(), delivery_map);

		let result = super::ensure_user_capacity_for_order(
			&solver,
			&config,
			LockType::ResourceLock,
			&standard_order,
		)
		.await;

		match result {
			Err(APIError::BadRequest { message, .. }) => {
				assert!(message.contains("TheCompact address not configured"));
			},
			_ => panic!("expected TheCompact address not configured error"),
		}
	}

	#[tokio::test]
	async fn test_ensure_user_capacity_contract_call_fails() {
		let amount = U256::from(500u64);
		let token_id = U256::from(123u64);
		let standard_order = build_standard_order(TEST_CHAIN_ID, token_id, amount);

		// Don't set any contract response, so contract_call will fail
		let delivery = Arc::new(TestDelivery::new(HashMap::new(), HashMap::new()))
			as Arc<dyn DeliveryInterface>;
		let mut delivery_map = HashMap::new();
		delivery_map.insert(TEST_CHAIN_ID, delivery);

		let config = build_config(TEST_CHAIN_ID, TEST_COMPACT);
		let solver = build_solver_engine(config.clone(), delivery_map);

		let result = super::ensure_user_capacity_for_order(
			&solver,
			&config,
			LockType::ResourceLock,
			&standard_order,
		)
		.await;

		match result {
			Err(APIError::BadRequest { message, .. }) => {
				assert!(message.contains("Failed to query TheCompact deposit"));
			},
			_ => panic!("expected contract call failure error"),
		}
	}

	#[tokio::test]
	async fn test_ensure_user_capacity_invalid_response_length() {
		let amount = U256::from(500u64);
		let token_id = U256::from(123u64);
		let standard_order = build_standard_order(TEST_CHAIN_ID, token_id, amount);

		let mut contract_responses = HashMap::new();
		// Return invalid response with wrong length (not 32 bytes)
		contract_responses.insert(TEST_CHAIN_ID, vec![0u8; 16]);

		let delivery = Arc::new(TestDelivery::new(HashMap::new(), contract_responses))
			as Arc<dyn DeliveryInterface>;
		let mut delivery_map = HashMap::new();
		delivery_map.insert(TEST_CHAIN_ID, delivery);

		let config = build_config(TEST_CHAIN_ID, TEST_COMPACT);
		let solver = build_solver_engine(config.clone(), delivery_map);

		let result = super::ensure_user_capacity_for_order(
			&solver,
			&config,
			LockType::ResourceLock,
			&standard_order,
		)
		.await;

		match result {
			Err(APIError::BadRequest { message, .. }) => {
				assert!(message.contains("Unexpected TheCompact balanceOf response length"));
			},
			_ => panic!("expected invalid response length error"),
		}
	}

	#[tokio::test]
	async fn test_ensure_user_capacity_wallet_balance_fetch_fails() {
		let amount = U256::from(500u64);
		let token_u256 = token_to_u256(parse_alloy_address(TEST_TOKEN));
		let standard_order = build_standard_order(TEST_CHAIN_ID, token_u256, amount);

		// Don't set any balance, so get_balance will fail
		let delivery = Arc::new(TestDelivery::new(HashMap::new(), HashMap::new()))
			as Arc<dyn DeliveryInterface>;
		let mut delivery_map = HashMap::new();
		delivery_map.insert(TEST_CHAIN_ID, delivery);

		let config = build_config(TEST_CHAIN_ID, TEST_COMPACT);
		let solver = build_solver_engine(config.clone(), delivery_map);

		let result = super::ensure_user_capacity_for_order(
			&solver,
			&config,
			LockType::Permit2Escrow,
			&standard_order,
		)
		.await;

		match result {
			Err(APIError::BadRequest { message, .. }) => {
				assert!(message.contains("Failed to fetch user balance"));
			},
			_ => panic!("expected balance fetch failure error"),
		}
	}

	#[tokio::test]
	async fn test_ensure_user_capacity_wallet_balance_parse_fails() {
		let amount = U256::from(500u64);
		let token_u256 = token_to_u256(parse_alloy_address(TEST_TOKEN));
		let standard_order = build_standard_order(TEST_CHAIN_ID, token_u256, amount);

		let mut balances = HashMap::new();
		let user_hex = hex::encode(parse_alloy_address(TEST_USER).as_slice());
		let token_hex = hex::encode(parse_alloy_address(TEST_TOKEN).as_slice());
		// Set invalid balance string that can't be parsed
		balances.insert(
			(TEST_CHAIN_ID, user_hex, Some(token_hex)),
			"not_a_number".to_string(),
		);

		let delivery =
			Arc::new(TestDelivery::new(balances, HashMap::new())) as Arc<dyn DeliveryInterface>;
		let mut delivery_map = HashMap::new();
		delivery_map.insert(TEST_CHAIN_ID, delivery);

		let config = build_config(TEST_CHAIN_ID, TEST_COMPACT);
		let solver = build_solver_engine(config.clone(), delivery_map);

		let result = super::ensure_user_capacity_for_order(
			&solver,
			&config,
			LockType::Permit2Escrow,
			&standard_order,
		)
		.await;

		match result {
			Err(APIError::BadRequest { message, .. }) => {
				assert!(message.contains("Failed to parse user balance"));
			},
			_ => panic!("expected balance parse failure error"),
		}
	}

	#[tokio::test]
	async fn test_ensure_user_capacity_zero_amount_skipped() {
		// Test that zero amounts are skipped and don't cause errors
		let token_u256 = token_to_u256(parse_alloy_address(TEST_TOKEN));
		let standard_order = build_standard_order(TEST_CHAIN_ID, token_u256, U256::ZERO);

		// Don't set any balances - if zero amounts weren't skipped, this would fail
		let delivery = Arc::new(TestDelivery::new(HashMap::new(), HashMap::new()))
			as Arc<dyn DeliveryInterface>;
		let mut delivery_map = HashMap::new();
		delivery_map.insert(TEST_CHAIN_ID, delivery);

		let config = build_config(TEST_CHAIN_ID, TEST_COMPACT);
		let solver = build_solver_engine(config.clone(), delivery_map);

		// Should succeed because zero amounts are skipped
		assert!(super::ensure_user_capacity_for_order(
			&solver,
			&config,
			LockType::Permit2Escrow,
			&standard_order,
		)
		.await
		.is_ok());
	}

	#[tokio::test]
	async fn test_ensure_user_capacity_resource_lock_zero_amount_skipped() {
		// Test that zero amounts are skipped for ResourceLock as well
		let token_id = U256::from(123u64);
		let standard_order = build_standard_order(TEST_CHAIN_ID, token_id, U256::ZERO);

		// Don't set any contract responses - if zero amounts weren't skipped, this would fail
		let delivery = Arc::new(TestDelivery::new(HashMap::new(), HashMap::new()))
			as Arc<dyn DeliveryInterface>;
		let mut delivery_map = HashMap::new();
		delivery_map.insert(TEST_CHAIN_ID, delivery);

		let config = build_config(TEST_CHAIN_ID, TEST_COMPACT);
		let solver = build_solver_engine(config.clone(), delivery_map);

		// Should succeed because zero amounts are skipped
		assert!(super::ensure_user_capacity_for_order(
			&solver,
			&config,
			LockType::ResourceLock,
			&standard_order,
		)
		.await
		.is_ok());
	}

	#[tokio::test]
	async fn test_ensure_user_capacity_decimal_format_balance() {
		// Test that decimal format balances are also supported (backward compatibility)
		let amount = U256::from(500u64);
		let token_u256 = token_to_u256(parse_alloy_address(TEST_TOKEN));
		let standard_order = build_standard_order(TEST_CHAIN_ID, token_u256, amount);

		let mut balances = HashMap::new();
		let user_hex = hex::encode(parse_alloy_address(TEST_USER).as_slice());
		let token_hex = hex::encode(parse_alloy_address(TEST_TOKEN).as_slice());
		// Use decimal format without 0x prefix
		balances.insert(
			(TEST_CHAIN_ID, user_hex, Some(token_hex)),
			"1000".to_string(),
		);

		let delivery =
			Arc::new(TestDelivery::new(balances, HashMap::new())) as Arc<dyn DeliveryInterface>;
		let mut delivery_map = HashMap::new();
		delivery_map.insert(TEST_CHAIN_ID, delivery);

		let config = build_config(TEST_CHAIN_ID, TEST_COMPACT);
		let solver = build_solver_engine(config.clone(), delivery_map);

		// Should succeed with decimal format
		assert!(super::ensure_user_capacity_for_order(
			&solver,
			&config,
			LockType::Permit2Escrow,
			&standard_order,
		)
		.await
		.is_ok());
	}
}
