//! OIF Solver Order API Implementation
//!
//! This module implements the order endpoint for the OIF Solver API, providing
//! order retrieval functionality for cross-chain intents. Users can query the
//! status and details of their submitted orders using the order ID.

use axum::extract::Path;
use solver_core::SolverEngine;
use solver_types::{
	bytes32_to_address, parse_address, with_0x_prefix, AssetAmount, GetOrderError,
	GetOrderResponse, InteropAddress, Order, OrderResponse, OrderStatus, Settlement,
	SettlementType, TransactionType,
};

/// Handles GET /orders/{id} requests.
///
/// This endpoint retrieves order details by ID, providing status information
/// and execution details for cross-chain intent orders.
pub async fn get_order_by_id(
	Path(id): Path<String>,
	_solver: &SolverEngine,
) -> Result<GetOrderResponse, GetOrderError> {
	let order = process_order_request(&id, _solver).await?;

	Ok(GetOrderResponse { order })
}

/// Processes an order retrieval request.
async fn process_order_request(
	order_id: &str,
	solver: &SolverEngine,
) -> Result<OrderResponse, GetOrderError> {
	// Validate order ID format
	validate_order_id(order_id)?;

	// Try to retrieve the order from storage
	match solver
		.storage()
		.retrieve::<solver_types::Order>("orders", order_id)
		.await
	{
		Ok(order) => {
			// Order found in storage, convert to OrderResponse
			convert_order_to_response(order).await
		},
		Err(solver_storage::StorageError::NotFound) => {
			// Order not found in storage
			Err(GetOrderError::NotFound(format!(
				"Order not found: {}",
				order_id
			)))
		},
		Err(e) => {
			// Other storage error
			Err(GetOrderError::Internal(format!("Storage error: {}", e)))
		},
	}
}

/// Validates the order ID format.
fn validate_order_id(order_id: &str) -> Result<(), GetOrderError> {
	// Validate order id is not empty
	if order_id.is_empty() {
		return Err(GetOrderError::InvalidId(
			"Order ID cannot be empty".to_string(),
		));
	}

	Ok(())
}

/// Converts a storage Order to an API OrderResponse.
async fn convert_order_to_response(order: Order) -> Result<OrderResponse, GetOrderError> {
	// Handle different order standards
	match order.standard.as_str() {
		"eip7683" => convert_eip7683_order_to_response(order).await,
		_ => {
			// Handle unknown standards
			Err(GetOrderError::Internal(format!(
				"Unsupported order standard: {}",
				order.standard
			)))
		},
	}
}

/// Creates an ERC-7930 interoperable address string from a token address and chain ID.
fn create_interop_address_string(token: &str, chain_id: u64) -> Result<String, GetOrderError> {
	// Parse the token address (with or without 0x prefix)
	let address = parse_address(token)
		.map_err(|e| GetOrderError::Internal(format!("Invalid token address: {}", e)))?;

	// Convert to alloy Address type
	let alloy_address = alloy_primitives::Address::from_slice(&address.0);

	// Create InteropAddress and return as hex string
	let interop_address = InteropAddress::new_ethereum(chain_id, alloy_address);
	Ok(interop_address.to_hex())
}

/// Converts an EIP-7683 order to API OrderResponse format.
async fn convert_eip7683_order_to_response(
	order: solver_types::Order,
) -> Result<OrderResponse, GetOrderError> {
	// Extract input amount from EIP-7683 "inputs" field
	let inputs = order.data.get("inputs").ok_or_else(|| {
		GetOrderError::Internal("Missing inputs field in EIP-7683 order data".to_string())
	})?;

	let inputs_array = inputs.as_array().ok_or_else(|| {
		GetOrderError::Internal("Invalid inputs format - expected array".to_string())
	})?;

	// For now, take the first input (TODO: handle multiple inputs properly)
	let first_input = inputs_array
		.first()
		.ok_or_else(|| GetOrderError::Internal("No inputs found in order".to_string()))?;

	let input_array = first_input.as_array().ok_or_else(|| {
		GetOrderError::Internal("Invalid input format - expected [token, amount] array".to_string())
	})?;

	if input_array.len() != 2 {
		return Err(GetOrderError::Internal(
			"Invalid input format - expected [token, amount]".to_string(),
		));
	}

	let input_token = input_array[0]
		.as_str()
		.ok_or_else(|| GetOrderError::Internal("Invalid input token format".to_string()))?;

	let input_amount_str = input_array[1]
		.as_str()
		.ok_or_else(|| GetOrderError::Internal("Invalid input amount format".to_string()))?;

	let input_amount_u256 = input_amount_str
		.parse::<alloy_primitives::U256>()
		.map_err(|e| GetOrderError::Internal(format!("Invalid input amount: {}", e)))?;

	// Get the input chain ID (use first one if multiple)
	let input_chain_id = order
		.input_chain_ids
		.first()
		.copied()
		.ok_or_else(|| GetOrderError::Internal("No input chain ID found".to_string()))?;

	// Convert input token to InteropAddress format
	let input_interop_address = create_interop_address_string(input_token, input_chain_id)?;

	let input_amount = AssetAmount {
		asset: input_interop_address,
		amount: input_amount_u256,
	};

	// Extract output amount from EIP-7683 "outputs" field
	let outputs = order.data.get("outputs").ok_or_else(|| {
		GetOrderError::Internal("Missing outputs field in EIP-7683 order data".to_string())
	})?;

	let outputs_array = outputs.as_array().ok_or_else(|| {
		GetOrderError::Internal("Invalid outputs format - expected array".to_string())
	})?;

	// For now, take the first output (TODO: handle multiple outputs properly)
	let first_output = outputs_array
		.first()
		.ok_or_else(|| GetOrderError::Internal("No outputs found in order".to_string()))?;

	let output_token_bytes = first_output
		.get("token")
		.ok_or_else(|| GetOrderError::Internal("Missing token field in output".to_string()))?;

	// Convert token bytes array to address
	let token_array = output_token_bytes.as_array().ok_or_else(|| {
		GetOrderError::Internal("Invalid token format - expected bytes array".to_string())
	})?;

	// Convert bytes32 array from JSON to [u8; 32]
	let mut token_bytes32 = [0u8; 32];
	for (i, byte_val) in token_array.iter().take(32).enumerate() {
		token_bytes32[i] = byte_val.as_u64().unwrap_or(0) as u8;
	}
	let output_token_address = with_0x_prefix(&bytes32_to_address(&token_bytes32));

	let output_amount_str = first_output
		.get("amount")
		.and_then(|v| v.as_str())
		.ok_or_else(|| {
			GetOrderError::Internal("Missing or invalid amount field in output".to_string())
		})?;

	let output_amount_u256 = output_amount_str
		.parse::<alloy_primitives::U256>()
		.map_err(|e| GetOrderError::Internal(format!("Invalid output amount: {}", e)))?;

	// Get the output chain ID (use first one if multiple)
	let output_chain_id = order
		.output_chain_ids
		.first()
		.copied()
		.ok_or_else(|| GetOrderError::Internal("No output chain ID found".to_string()))?;

	// Convert output token to InteropAddress format
	let output_interop_address =
		create_interop_address_string(&output_token_address, output_chain_id)?;

	let output_amount = AssetAmount {
		asset: output_interop_address,
		amount: output_amount_u256,
	};

	// For EIP-7683, we can infer settlement type (default to Escrow for now)
	// TODO: Handle other settlement types
	let settlement_type = SettlementType::Escrow;

	// Create settlement data from the raw order data
	let settlement_data = serde_json::json!({
		"raw_order_data": order.data.get("raw_order_data").cloned().unwrap_or(serde_json::json!(null)),
		"signature": order.data.get("signature").cloned().unwrap_or(serde_json::json!(null)),
		"nonce": order.data.get("nonce").cloned().unwrap_or(serde_json::json!(null)),
		"expires": order.data.get("expires").cloned().unwrap_or(serde_json::json!(null))
	});

	// Try to retrieve fill transaction hash from storage
	let fill_transaction = order.fill_tx_hash.as_ref().map(|fill_tx_hash| {
		// Determine fill transaction status based on order status
		let tx_status = match order.status {
			// Fill transaction completed successfully
			OrderStatus::Executed
			| OrderStatus::PostFilled
			| OrderStatus::PreClaimed
			| OrderStatus::Settled
			| OrderStatus::Finalized => "executed",
			// Fill transaction is in progress
			OrderStatus::Executing => "pending",
			// These states shouldn't have a fill_tx_hash, but if they do, log warning
			OrderStatus::Created | OrderStatus::Pending => {
				tracing::warn!(
					order_id = %order.id,
					status = ?order.status,
					"Unexpected fill_tx_hash in pre-execution state"
				);
				"pending"
			},
			// Fill transaction failed
			OrderStatus::Failed(TransactionType::Fill) => "failed",
			// Prepare failed - shouldn't have fill_tx_hash
			OrderStatus::Failed(TransactionType::Prepare) => {
				tracing::warn!(
					order_id = %order.id,
					"Unexpected fill_tx_hash when prepare transaction failed"
				);
				"failed"
			},
			// Fill succeeded but later transaction failed
			OrderStatus::Failed(TransactionType::PostFill)
			| OrderStatus::Failed(TransactionType::PreClaim)
			| OrderStatus::Failed(TransactionType::Claim) => "executed",
		};

		serde_json::json!({
			"hash": with_0x_prefix(&alloy_primitives::hex::encode(&fill_tx_hash.0)),
			"status": tx_status,
			"timestamp": order.updated_at
		})
	});

	let response = OrderResponse {
		id: order.id,
		status: order.status,
		created_at: order.created_at,
		updated_at: order.updated_at,
		quote_id: order.quote_id,
		input_amount,
		output_amount,
		settlement: Settlement {
			settlement_type,
			data: settlement_data,
		},
		fill_transaction,
	};

	Ok(response)
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::{hex, U256};
	use mockall::{mock, predicate::eq};
	use serde_json::json;
	use solver_account::{implementations::local::LocalWallet, AccountService};
	use solver_config::{Config, ConfigBuilder};
	use solver_core::{engine::token_manager::TokenManager, EventBus, SolverEngine};
	use solver_delivery::DeliveryService;
	use solver_discovery::DiscoveryService;
	use solver_order::{implementations::strategies::simple::create_strategy, OrderService};
	use solver_pricing::{implementations::mock, PricingService};
	use solver_settlement::SettlementService;
	use solver_storage::{StorageError, StorageInterface};
	use solver_types::{order::Order, validation::ConfigSchema, OrderStatus, TransactionHash};
	use std::{collections::HashMap, sync::Arc, time::Duration};
	use toml::Value;

	mock! {
		pub Backend {}

		#[async_trait::async_trait]
		impl StorageInterface for Backend {
			async fn get_bytes(&self, key: &str) -> Result<Vec<u8>, StorageError>;
			async fn set_bytes(&self, key: &str, value: Vec<u8>, indexes: Option<solver_storage::StorageIndexes>, ttl: Option<Duration>) -> Result<(), StorageError>;
			async fn delete(&self, key: &str) -> Result<(), StorageError>;
			async fn exists(&self, key: &str) -> Result<bool, StorageError>;
			async fn query(&self, namespace: &str, filter: solver_storage::QueryFilter) -> Result<Vec<String>, StorageError>;
			async fn get_batch(&self, keys: &[String]) -> Result<Vec<(String, Vec<u8>)>, StorageError>;
			fn config_schema(&self) -> Box<dyn ConfigSchema>;
			async fn cleanup_expired(&self) -> Result<usize, StorageError>;
		}
	}

	const TEST_PK: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
	const TEST_ADDR: &str = "0x1234567890123456789012345678901234567890";

	fn test_cfg() -> Config {
		ConfigBuilder::new().build()
	}

	fn addr() -> solver_types::Address {
		let bytes = alloy_primitives::hex::decode(TEST_ADDR.trim_start_matches("0x")).unwrap();
		solver_types::Address(bytes)
	}

	fn test_account() -> Arc<AccountService> {
		Arc::new(AccountService::new(Box::new(
			LocalWallet::new(TEST_PK).unwrap(),
		)))
	}

	async fn create_test_solver_engine(storage_mock: MockBackend) -> SolverEngine {
		let cfg = test_cfg();
		let storage = Arc::new(solver_storage::StorageService::new(Box::new(storage_mock)));
		let account = test_account();
		let providers: HashMap<u64, Arc<dyn solver_delivery::DeliveryInterface>> = HashMap::new();
		let delivery = Arc::new(DeliveryService::new(providers, 1));
		let discovery = Arc::new(DiscoveryService::new(HashMap::new()));
		let strategy = create_strategy(&Value::Table(toml::map::Map::new())).unwrap();
		let order = Arc::new(OrderService::new(HashMap::new(), strategy));
		let settlement = Arc::new(SettlementService::new(HashMap::new()));
		let event_bus = EventBus::new(64);
		let networks: solver_types::NetworksConfig = HashMap::new();
		let token_manager = Arc::new(TokenManager::new(
			networks,
			delivery.clone(),
			account.clone(),
		));
		let solver_address = addr();

		// Create a mock pricing service for tests
		let pricing_config = toml::Value::Table(toml::map::Map::new());
		let pricing_impl = mock::create_mock_pricing(&pricing_config).unwrap();
		let pricing = Arc::new(PricingService::new(pricing_impl));

		SolverEngine::new(
			cfg,
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

	fn create_test_eip7683_order(id: &str, status: OrderStatus) -> Order {
		Order {
			id: id.into(),
			standard: "eip7683".into(),
			created_at: 1640995200,
			updated_at: 1640995200,
			status,
			data: json!({
				"inputs": [[TEST_ADDR, "1000000000000000000"]],
				"outputs": [{ "token": [18,52,86,120,144,18,52,86,120,144,18,52,86,120,144,18,52,86,120,144,18,52,86,120,144,18,52,86,120,144,18,52], "amount": "2000000000000000000" }],
				"raw_order_data": {"some":"data"},
				"signature": "0xsignature",
				"nonce": "42",
				"expires": "1640995800"
			}),
			solver_address: addr(),
			quote_id: Some("quote-test".into()),
			input_chain_ids: vec![1],
			output_chain_ids: vec![2],
			execution_params: None,
			prepare_tx_hash: None,
			fill_tx_hash: Some(TransactionHash(hex::decode(TEST_ADDR).unwrap())),
			post_fill_tx_hash: None,
			pre_claim_tx_hash: None,
			claim_tx_hash: None,
			fill_proof: None,
		}
	}

	#[tokio::test]
	async fn test_get_order_by_id_success() {
		let mut backend = MockBackend::new();
		let order = create_test_eip7683_order("order-test", OrderStatus::Executed);

		let bytes = serde_json::to_vec(&order).unwrap();

		backend
			.expect_get_bytes()
			.with(eq("orders:order-test"))
			.returning(move |_| Ok(bytes.clone()));

		let solver = create_test_solver_engine(backend).await;

		// Test the endpoint
		let result = get_order_by_id(Path("order-test".to_string()), &solver).await;

		assert!(result.is_ok());
		let response = result.unwrap();
		assert_eq!(response.order.id, "order-test");
		assert_eq!(response.order.status, OrderStatus::Executed);
		assert_eq!(response.order.quote_id, Some("quote-test".to_string()));
	}

	#[tokio::test]
	async fn test_process_order_request_success() {
		let mut backend = MockBackend::new();
		let order = create_test_eip7683_order("order-proc", OrderStatus::Executed);
		let bytes = serde_json::to_vec(&order).unwrap();

		backend
			.expect_get_bytes()
			.with(eq("orders:order-proc"))
			.returning(move |_| Ok(bytes.clone()));

		let solver = create_test_solver_engine(backend).await;

		let res = process_order_request("order-proc", &solver).await;
		assert!(res.is_ok());
		let resp = res.unwrap();
		assert_eq!(resp.id, "order-proc");
		assert_eq!(resp.status, OrderStatus::Executed);
	}

	#[tokio::test]
	async fn test_process_order_request_not_found() {
		let mut backend = MockBackend::new();
		backend
			.expect_get_bytes()
			.with(eq("orders:missing"))
			.returning(|_| Err(StorageError::NotFound));

		let solver = create_test_solver_engine(backend).await;

		let res = process_order_request("missing", &solver).await;
		match res {
			Err(GetOrderError::NotFound(msg)) => assert!(msg.contains("missing")),
			other => panic!("expected NotFound, got {:?}", other),
		}
	}

	#[tokio::test]
	async fn test_convert_order_to_response_eip7683_ok() {
		let order = create_test_eip7683_order("order-ok", OrderStatus::Executed);
		let resp = convert_order_to_response(order).await.expect("ok");

		assert_eq!(resp.id, "order-ok");
		assert_eq!(resp.status, OrderStatus::Executed);
		assert_eq!(resp.quote_id, Some("quote-test".to_string()));

		// input - should be an interop address with chain ID 1
		// Format: 0x01000001011234567890123456789012345678901234567890
		// Version: 01, ChainType: 0000, ChainRefLen: 01, ChainRef: 01, AddrLen: 14, Address: 20 bytes
		assert!(resp.input_amount.asset.starts_with("0x01000001"));
		assert!(resp
			.input_amount
			.asset
			.contains("1234567890123456789012345678901234567890"));
		assert_eq!(
			resp.input_amount.amount,
			"1000000000000000000".parse::<U256>().unwrap()
		);

		// output - should be an interop address with chain ID 2
		assert!(resp.output_amount.asset.starts_with("0x01000001"));
		assert_eq!(
			resp.output_amount.amount,
			"2000000000000000000".parse::<U256>().unwrap()
		);

		// settlement
		assert!(matches!(
			resp.settlement.settlement_type,
			SettlementType::Escrow
		));

		// fill tx
		let fill_tx = resp.fill_transaction.expect("has fill tx");
		assert_eq!(
			fill_tx.get("status").and_then(|v| v.as_str()),
			Some("executed")
		);
	}

	#[tokio::test]
	async fn test_convert_order_to_response_unsupported_standard() {
		let mut order = create_test_eip7683_order("order-unsupported", OrderStatus::Executed);
		order.standard = "unsupported".to_string();

		let err = convert_order_to_response(order).await.expect_err("err");
		match err {
			GetOrderError::Internal(msg) => assert!(msg.contains("Unsupported order standard")),
			_ => panic!("expected Internal"),
		}
	}

	#[tokio::test]
	async fn test_convert_order_to_response_missing_inputs() {
		let mut order = create_test_eip7683_order("order-missing-inputs", OrderStatus::Executed);
		order.data = json!({
			"outputs": [{
				"token": [18,52,86,120,144,18,52,86,120,144,18,52,86,120,144,18,52,86,120,144,18,52,86,120,144,18,52,86,120,144,18,52],
				"amount": "2000000000000000000"
			}]
		});

		let err = convert_order_to_response(order).await.expect_err("err");
		match err {
			GetOrderError::Internal(msg) => assert!(msg.contains("Missing inputs field")),
			_ => panic!("expected Internal"),
		}
	}

	#[tokio::test]
	async fn test_convert_order_to_response_pre_execution_pending_fill_status() {
		let order = create_test_eip7683_order("order-pending", OrderStatus::Created);
		// Keep a fill_tx_hash
		let resp = convert_order_to_response(order).await.expect("ok");
		let fill_tx = resp.fill_transaction.expect("has fill tx");
		assert_eq!(
			fill_tx.get("status").and_then(|v| v.as_str()),
			Some("pending")
		);
	}
}
