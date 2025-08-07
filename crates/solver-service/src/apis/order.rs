//! OIF Solver Order API Implementation
//!
//! This module implements the order endpoint for the OIF Solver API, providing
//! order retrieval functionality for cross-chain intents. Users can query the
//! status and details of their submitted orders using the order ID.

use axum::extract::Path;
use solver_core::SolverEngine;
use solver_storage;
use solver_types::{
	AssetAmount, GetOrderError, GetOrderResponse, Order, OrderResponse, OrderStatus, Settlement,
	SettlementType, TransactionType,
};
use tracing::info;

/// Handles GET /orders/{id} requests.
///
/// This endpoint retrieves order details by ID, providing status information
/// and execution details for cross-chain intent orders.
pub async fn get_order_by_id(
	Path(id): Path<String>,
	_solver: &SolverEngine,
) -> Result<GetOrderResponse, GetOrderError> {
	info!("Retrieving order with ID: {}", id);

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
		}
		Err(solver_storage::StorageError::NotFound) => {
			// Order not found in storage
			Err(GetOrderError::NotFound(format!(
				"Order not found: {}",
				order_id
			)))
		}
		Err(e) => {
			// Other storage error
			Err(GetOrderError::Internal(format!("Storage error: {}", e)))
		}
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
	// Handle EIP-7683 order format
	if order.standard == "eip7683" {
		convert_eip7683_order_to_response(order).await
	} else {
		// Handle other standards
		Err(GetOrderError::Internal(
			"Unsupported order standard".to_string(),
		))
	}
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

	let input_amount = AssetAmount {
		asset: input_token.to_string(),
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

	// Extract last 20 bytes (address part) from the 32-byte token field
	let mut token_bytes = [0u8; 20];
	for (i, byte_val) in token_array.iter().skip(12).take(20).enumerate() {
		token_bytes[i] = byte_val.as_u64().unwrap_or(0) as u8;
	}
	let output_token = format!("0x{}", alloy_primitives::hex::encode(token_bytes));

	let output_amount_str = first_output
		.get("amount")
		.and_then(|v| v.as_str())
		.ok_or_else(|| {
			GetOrderError::Internal("Missing or invalid amount field in output".to_string())
		})?;

	let output_amount_u256 = output_amount_str
		.parse::<alloy_primitives::U256>()
		.map_err(|e| GetOrderError::Internal(format!("Invalid output amount: {}", e)))?;

	let output_amount = AssetAmount {
		asset: output_token,
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
			OrderStatus::Executed | OrderStatus::Claimed | OrderStatus::Finalized => "executed",
			OrderStatus::Pending => "pending",
			OrderStatus::Failed(TransactionType::Fill)
			| OrderStatus::Failed(TransactionType::Prepare) => "failed",
			OrderStatus::Failed(TransactionType::Claim) => "executed", // Fill succeeded, Claim failed
		};

		serde_json::json!({
			"hash": format!("0x{}", alloy_primitives::hex::encode(&fill_tx_hash.0)),
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
