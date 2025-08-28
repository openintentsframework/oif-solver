//! API types for the OIF Solver HTTP API.
//!
//! This module defines the request and response types for the OIF Solver API
//! endpoints, following the ERC-7683 Cross-Chain Intents Standard.
use crate::standards::eip7930::InteropAddress;
use alloy_primitives::Bytes;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Asset amount representation using ERC-7930 interoperable address format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetAmount {
	/// Asset address in ERC-7930 interoperable format
	pub asset: InteropAddress,
	/// Amount as a string to preserve precision (e.g., uint256)
	pub amount: String,
}

/// Asset lock reference for inputs that are already locked
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetLockReference {
	/// Type of lock mechanism
	pub kind: LockKind,
	/// Lock-specific parameters
	pub params: Option<serde_json::Value>,
}

/// Supported lock mechanisms
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LockKind {
	TheCompact,
	Rhinestone,
}

/// Available input with lock information and user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailableInput {
	/// User address in ERC-7930 interoperable format
	pub user: InteropAddress,
	/// Asset address in ERC-7930 interoperable format
	pub asset: InteropAddress,
	/// Amount as a string to preserve precision (e.g., uint256)
	pub amount: String,
	/// Lock information if asset is already locked
	pub lock: Option<AssetLockReference>,
}

/// Requested output with receiver and optional calldata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestedOutput {
	/// Receiver address in ERC-7930 interoperable format
	pub receiver: InteropAddress,
	/// Asset address in ERC-7930 interoperable format
	pub asset: InteropAddress,
	/// Amount as a string to preserve precision (e.g., uint256)
	pub amount: String,
	/// Optional calldata for the output
	pub calldata: Option<String>,
}

/// Requested output details with user field (used in quote responses)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestedOutputDetails {
	/// User address in ERC-7930 interoperable format
	pub user: InteropAddress,
	/// Asset address in ERC-7930 interoperable format
	pub asset: InteropAddress,
	/// Amount as a string to preserve precision (e.g., uint256)
	pub amount: String,
	/// Optional calldata for the output
	pub calldata: Option<String>,
}

/// Order type defining how providers must interpret amounts for swaps
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OrderType {
	/// Exact-input (spend exactly the input amounts)
	SwapSell,
	/// Exact-output (receive exactly the output amounts)
	SwapBuy,
}

/// Origin submission mode
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubmissionMode {
	User,
	Protocol,
}

/// Origin submission schemes
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubmissionScheme {
	Erc4337,
	Permit2,
	Erc20Permit,
	Eip3009,
}

/// Origin submission configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OriginSubmission {
	/// Submission mode
	pub mode: SubmissionMode,
	/// Supported schemes
	#[serde(default)]
	pub schemes: Vec<SubmissionScheme>,
}

/// API request for order submission matching OpenAPI PostOrderRequest.
///
/// This structure follows the OpenAPI 3.0.0 specification for order submission.
/// Used by the discovery service to accept orders from users or other systems.
///
/// # Fields
///
/// * `order` - EIP-712 order data as encoded bytes
/// * `signature` - EIP-712 signature as encoded bytes
/// * `quote_id` - Quote identifier for linking to quote
/// * `provider` - Provider/solver identifier  
/// * `failure_handling` - How to handle execution failures
/// * `origin_submission` - Origin submission configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostOrderRequest {
	/// Order data as encoded bytes
	pub order: Bytes,
	/// Signature as encoded bytes
	pub signature: Bytes,
	/// Optional quote identifier
	pub quote_id: Option<String>,
	/// Provider identifier
	pub provider: String,
	/// Failure handling strategy
	pub failure_handling: FailureHandling,
	/// Origin submission configuration
	#[serde(default)]
	pub origin_submission: Option<OriginSubmission>,
}

/// Request for getting price quotes following UII standard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetQuoteRequest {
	/// User making the request in ERC-7930 interoperable format
	pub user: InteropAddress,
	/// Available inputs (order significant if preference is 'input-priority')
	#[serde(rename = "availableInputs")]
	pub available_inputs: Vec<AvailableInput>,
	/// Requested outputs
	#[serde(rename = "requestedOutputs")]
	pub requested_outputs: Vec<RequestedOutput>,
	/// Order type defining how providers interpret amounts
	#[serde(rename = "orderType")]
	pub order_type: Option<OrderType>,
	/// Minimum quote validity duration in seconds
	#[serde(rename = "minValidUntil")]
	pub min_valid_until: Option<u64>,
	/// User preference for optimization
	pub preference: Option<QuotePreference>,
	/// Origin submission configuration
	#[serde(rename = "originSubmission")]
	pub origin_submission: Option<OriginSubmission>,
}

/// Quote optimization preferences following UII standard
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum QuotePreference {
	Price,
	Speed,
	InputPriority,
	TrustMinimization,
}

/// EIP-712 compliant order structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteOrder {
	/// ERC-7930 interoperable address of the domain
	pub domain: InteropAddress,
	/// Primary type for EIP-712 signing
	#[serde(rename = "primaryType")]
	pub primary_type: String,
	/// Message object to be signed and submitted
	pub message: serde_json::Value,
}

/// Available input for quote details (includes lockType instead of full lock)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailableInputDetails {
	/// User address in ERC-7930 interoperable format
	pub user: InteropAddress,
	/// Asset address in ERC-7930 interoperable format
	pub asset: InteropAddress,
	/// Amount as a string to preserve precision (e.g., uint256)
	pub amount: String,
	/// Lock type if asset is already locked
	#[serde(rename = "lockType")]
	pub lock_type: Option<LockKind>,
}

/// Quote details matching the request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteDetails {
	/// Requested outputs for this quote
	#[serde(rename = "requestedOutputs")]
	pub requested_outputs: Vec<RequestedOutputDetails>,
	/// Available inputs for this quote
	#[serde(rename = "availableInputs")]
	pub available_inputs: Vec<AvailableInputDetails>,
}

/// A quote option following UII standard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quote {
	/// Array of EIP-712 compliant orders
	pub orders: Vec<QuoteOrder>,
	/// Quote details matching request structure
	pub details: QuoteDetails,
	/// Quote validity timestamp
	#[serde(rename = "validUntil")]
	pub valid_until: Option<u64>,
	/// Estimated time to completion in seconds
	pub eta: Option<u64>,
	/// Unique quote identifier
	#[serde(rename = "quoteId")]
	pub quote_id: String,
	/// Provider identifier
	pub provider: String, // not used by the solver, only relevant for the aggregator
}

/// Settlement mechanism types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum SettlementType {
	Escrow,
	ResourceLock,
}

/// Response containing quote options following UII standard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetQuoteResponse {
	/// Available quotes
	pub quotes: Vec<Quote>,
}

/// Failure handling strategies for order execution
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FailureHandling {
	Retry,
	RefundInstant,
	RefundClaim,
	NeedsNewSignature,
	#[serde(untagged)]
	PartialFill {
		partial_fill: bool,
		remainder: FailureHandlingStrategy,
	},
}

/// Basic failure handling strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FailureHandlingStrategy {
	Retry,
	RefundInstant,
	RefundClaim,
	NeedsNewSignature,
}

/// Order status values for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiOrderStatus {
	Created,
	Pending,
	Executed,
	Settled,
	Finalized,
	Failed,
}

/// Post order response status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PostOrderResponseStatus {
	Received,
	Rejected,
	Error,
}

/// Response for posting an order
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostOrderResponse {
	/// Assigned order ID
	#[serde(rename = "orderId")]
	pub order_id: Option<String>,
	/// Response status
	pub status: PostOrderResponseStatus,
	/// Status message
	pub message: Option<String>,
	/// Order data (if applicable)
	pub order: Option<serde_json::Value>,
}

/// Settlement information for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSettlement {
	/// Settlement mechanism type
	#[serde(rename = "type")]
	pub settlement_type: SettlementType,
	/// Settlement-specific data
	pub data: serde_json::Value,
}

/// Request for getting order details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetOrderRequest {
	/// Order ID to retrieve
	pub id: String,
}

/// Response containing order details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetOrderResponse {
	/// Order ID
	pub id: String,
	/// Order status
	pub status: ApiOrderStatus,
	/// Creation timestamp
	#[serde(rename = "createdAt")]
	pub created_at: u64,
	/// Last update timestamp
	#[serde(rename = "updatedAt")]
	pub updated_at: u64,
	/// Associated quote ID
	#[serde(rename = "quoteId")]
	pub quote_id: Option<String>,
	/// Input amount
	#[serde(rename = "inputAmount")]
	pub input_amount: AssetAmount,
	/// Output amount
	#[serde(rename = "outputAmount")]
	pub output_amount: AssetAmount,
	/// Settlement information
	pub settlement: ApiSettlement,
	/// Fill transaction details
	#[serde(rename = "fillTransaction")]
	pub fill_transaction: Option<serde_json::Value>,
}

/// API error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
	/// Error type/code
	pub error: String,
	/// Human-readable description
	pub message: String,
	/// Additional error context
	pub details: Option<serde_json::Value>,
	/// Suggested retry delay in seconds
	#[serde(rename = "retryAfter")]
	pub retry_after: Option<u64>,
}

/// Structured API error type with appropriate HTTP status mapping.
#[derive(Debug)]
pub enum APIError {
	/// Bad request with validation errors (400)
	BadRequest {
		error_type: String,
		message: String,
		details: Option<serde_json::Value>,
	},
	/// Unprocessable entity for business logic failures (422)
	UnprocessableEntity {
		error_type: String,
		message: String,
		details: Option<serde_json::Value>,
	},
	/// Service unavailable with optional retry information (503)
	ServiceUnavailable {
		error_type: String,
		message: String,
		retry_after: Option<u64>,
	},
	/// Internal server error (500)
	InternalServerError { error_type: String, message: String },
}

impl APIError {
	/// Get the HTTP status code for this error.
	pub fn status_code(&self) -> u16 {
		match self {
			APIError::BadRequest { .. } => 400,
			APIError::UnprocessableEntity { .. } => 422,
			APIError::ServiceUnavailable { .. } => 503,
			APIError::InternalServerError { .. } => 500,
		}
	}

	/// Convert to ErrorResponse for JSON serialization.
	pub fn to_error_response(&self) -> ErrorResponse {
		match self {
			APIError::BadRequest {
				error_type,
				message,
				details,
			} => ErrorResponse {
				error: error_type.clone(),
				message: message.clone(),
				details: details.clone(),
				retry_after: None,
			},
			APIError::UnprocessableEntity {
				error_type,
				message,
				details,
			} => ErrorResponse {
				error: error_type.clone(),
				message: message.clone(),
				details: details.clone(),
				retry_after: None,
			},
			APIError::ServiceUnavailable {
				error_type,
				message,
				retry_after,
			} => ErrorResponse {
				error: error_type.clone(),
				message: message.clone(),
				details: None,
				retry_after: *retry_after,
			},
			APIError::InternalServerError {
				error_type,
				message,
			} => ErrorResponse {
				error: error_type.clone(),
				message: message.clone(),
				details: None,
				retry_after: None,
			},
		}
	}
}

impl fmt::Display for APIError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			APIError::BadRequest { message, .. } => write!(f, "Bad Request: {}", message),
			APIError::UnprocessableEntity { message, .. } => {
				write!(f, "Unprocessable Entity: {}", message)
			},
			APIError::ServiceUnavailable { message, .. } => {
				write!(f, "Service Unavailable: {}", message)
			},
			APIError::InternalServerError { message, .. } => {
				write!(f, "Internal Server Error: {}", message)
			},
		}
	}
}

impl std::error::Error for APIError {}

impl axum::response::IntoResponse for APIError {
	fn into_response(self) -> axum::response::Response {
		use axum::{http::StatusCode, response::Json};

		let status = match self.status_code() {
			400 => StatusCode::BAD_REQUEST,
			422 => StatusCode::UNPROCESSABLE_ENTITY,
			503 => StatusCode::SERVICE_UNAVAILABLE,
			500 => StatusCode::INTERNAL_SERVER_ERROR,
			_ => StatusCode::INTERNAL_SERVER_ERROR,
		};

		let error_response = self.to_error_response();
		(status, Json(error_response)).into_response()
	}
}

/// Errors that can occur during quote processing.
#[derive(Debug, thiserror::Error)]
pub enum QuoteError {
	#[error("Invalid request: {0}")]
	InvalidRequest(String),
	#[error("Unsupported asset: {0}")]
	UnsupportedAsset(String),
	#[error("Unsupported settlement: {0}")]
	UnsupportedSettlement(String),
	#[error("Insufficient liquidity for requested amount")]
	InsufficientLiquidity,
	#[error("Solver capacity exceeded")]
	SolverCapacityExceeded,
	#[error("Internal error: {0}")]
	Internal(String),
}

impl From<QuoteError> for APIError {
	fn from(quote_error: QuoteError) -> Self {
		match quote_error {
			QuoteError::InvalidRequest(msg) => APIError::BadRequest {
				error_type: "INVALID_REQUEST".to_string(),
				message: msg,
				details: None,
			},
			QuoteError::UnsupportedAsset(asset) => APIError::UnprocessableEntity {
				error_type: "UNSUPPORTED_ASSET".to_string(),
				message: format!("Asset not supported by solver: {}", asset),
				details: Some(serde_json::json!({ "asset": asset })),
			},
			QuoteError::UnsupportedSettlement(msg) => APIError::UnprocessableEntity {
				error_type: "UNSUPPORTED_SETTLEMENT".to_string(),
				message: msg,
				details: None,
			},
			QuoteError::InsufficientLiquidity => APIError::UnprocessableEntity {
				error_type: "INSUFFICIENT_LIQUIDITY".to_string(),
				message: "Insufficient liquidity available for the requested amount".to_string(),
				details: None,
			},
			QuoteError::SolverCapacityExceeded => APIError::ServiceUnavailable {
				error_type: "SOLVER_CAPACITY_EXCEEDED".to_string(),
				message: "Solver capacity exceeded, please try again later".to_string(),
				retry_after: Some(60), // Suggest retry after 60 seconds
			},
			QuoteError::Internal(msg) => APIError::InternalServerError {
				error_type: "INTERNAL_ERROR".to_string(),
				message: format!("An internal error occurred: {}", msg),
			},
		}
	}
}

/// Errors that can occur during order processing.
#[derive(Debug, thiserror::Error)]
pub enum GetOrderError {
	#[error("Order not found: {0}")]
	NotFound(String),
	#[error("Invalid order ID format: {0}")]
	InvalidId(String),
	#[error("Internal error: {0}")]
	Internal(String),
}

/// Convert OrderError to APIError with appropriate HTTP status codes.
impl From<GetOrderError> for APIError {
	fn from(order_error: GetOrderError) -> Self {
		match order_error {
			GetOrderError::NotFound(id) => APIError::BadRequest {
				error_type: "ORDER_NOT_FOUND".to_string(),
				message: format!("Order not found: {}", id),
				details: Some(serde_json::json!({ "order_id": id })),
			},
			GetOrderError::InvalidId(id) => APIError::BadRequest {
				error_type: "INVALID_ORDER_ID".to_string(),
				message: format!("Invalid order ID format: {}", id),
				details: Some(serde_json::json!({ "provided_id": id })),
			},
			GetOrderError::Internal(msg) => APIError::InternalServerError {
				error_type: "INTERNAL_ERROR".to_string(),
				message: format!("An internal error occurred: {}", msg),
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::standards::eip7930::InteropAddress;
	use alloy_primitives::address;
	use serde_json;

	#[test]
	fn test_asset_amount_serialization() {
		let asset_amount = AssetAmount {
			asset: InteropAddress::new_ethereum(
				1,
				address!("A0b86a33E6776Fb78B3e1E6B2D0d2E8F0C1D2A3B"),
			),
			amount: "1000".to_string(),
		};

		let json = serde_json::to_string(&asset_amount).unwrap();
		assert!(json.contains("\"asset\":"));
		assert!(json.contains("\"amount\":\"1000\""));

		let deserialized: AssetAmount = serde_json::from_str(&json).unwrap();
		assert_eq!(deserialized.asset, asset_amount.asset);
		assert_eq!(deserialized.amount, asset_amount.amount);
	}

	#[test]
	fn test_lock_kind_serialization() {
		let lock_kind = LockKind::TheCompact;
		let json = serde_json::to_string(&lock_kind).unwrap();
		assert_eq!(json, "\"the-compact\"");

		let deserialized: LockKind = serde_json::from_str(&json).unwrap();
		assert!(matches!(deserialized, LockKind::TheCompact));
	}

	#[test]
	fn test_lock_serialization() {
		let lock = AssetLockReference {
			kind: LockKind::TheCompact,
			params: Some(serde_json::json!({"resource_id": "0x123"})),
		};

		let json = serde_json::to_string(&lock).unwrap();
		let deserialized: AssetLockReference = serde_json::from_str(&json).unwrap();

		assert!(matches!(deserialized.kind, LockKind::TheCompact));
		assert!(deserialized.params.is_some());
	}

	#[test]
	fn test_available_input_serialization() {
		let input = AvailableInput {
			user: InteropAddress::new_ethereum(
				1,
				address!("A0b86a33E6776Fb78B3e1E6B2D0d2E8F0C1D2A3B"),
			),
			asset: InteropAddress::new_ethereum(
				1,
				address!("6B175474E89094C44Da98b954EedeAC495271d0F"),
			),
			amount: "5000".to_string(),
			lock: Some(AssetLockReference {
				kind: LockKind::TheCompact,
				params: None,
			}),
		};

		let json = serde_json::to_string(&input).unwrap();
		let deserialized: AvailableInput = serde_json::from_str(&json).unwrap();

		assert_eq!(deserialized.amount, "5000".to_string());
		assert!(deserialized.lock.is_some());
	}

	#[test]
	fn test_requested_output_serialization() {
		let output = RequestedOutput {
			receiver: InteropAddress::new_ethereum(
				1,
				address!("A0b86a33E6776Fb78B3e1E6B2D0d2E8F0C1D2A3B"),
			),
			asset: InteropAddress::new_ethereum(
				1,
				address!("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
			),
			amount: "2000".to_string(),
			calldata: Some("0xdeadbeef".to_string()),
		};

		let json = serde_json::to_string(&output).unwrap();
		let deserialized: RequestedOutput = serde_json::from_str(&json).unwrap();

		assert_eq!(deserialized.amount, "2000".to_string());
		assert_eq!(deserialized.calldata, Some("0xdeadbeef".to_string()));
	}

	#[test]
	fn test_quote_preference_serialization() {
		let preferences = [
			QuotePreference::Price,
			QuotePreference::Speed,
			QuotePreference::InputPriority,
			QuotePreference::TrustMinimization,
		];

		let expected_values = [
			"\"price\"",
			"\"speed\"",
			"\"input-priority\"",
			"\"trust-minimization\"",
		];

		for (preference, expected) in preferences.iter().zip(expected_values.iter()) {
			let json = serde_json::to_string(preference).unwrap();
			assert_eq!(json, *expected);

			let deserialized: QuotePreference = serde_json::from_str(&json).unwrap();
			assert_eq!(deserialized, *preference); // Change from matches! to assert_eq!
		}
	}

	#[test]
	fn test_get_quote_request_serialization() {
		let request = GetQuoteRequest {
			user: InteropAddress::new_ethereum(
				1,
				address!("A0b86a33E6776Fb78B3e1E6B2D0d2E8F0C1D2A3B"),
			),
			available_inputs: vec![AvailableInput {
				user: InteropAddress::new_ethereum(
					1,
					address!("A0b86a33E6776Fb78B3e1E6B2D0d2E8F0C1D2A3B"),
				),
				asset: InteropAddress::new_ethereum(
					1,
					address!("6B175474E89094C44Da98b954EedeAC495271d0F"),
				),
				amount: "1000".to_string(),
				lock: None,
			}],
			requested_outputs: vec![RequestedOutput {
				receiver: InteropAddress::new_ethereum(
					1,
					address!("A0b86a33E6776Fb78B3e1E6B2D0d2E8F0C1D2A3B"),
				),
				asset: InteropAddress::new_ethereum(
					1,
					address!("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
				),
				amount: "900".to_string(),
				calldata: None,
			}],
			min_valid_until: Some(1234567890),
			preference: Some(QuotePreference::Price),
			order_type: None,
			origin_submission: None,
		};

		let json = serde_json::to_string(&request).unwrap();
		assert!(json.contains("\"availableInputs\""));
		assert!(json.contains("\"requestedOutputs\""));
		assert!(json.contains("\"minValidUntil\""));

		let deserialized: GetQuoteRequest = serde_json::from_str(&json).unwrap();
		assert_eq!(deserialized.available_inputs.len(), 1);
		assert_eq!(deserialized.requested_outputs.len(), 1);
		assert_eq!(deserialized.min_valid_until, Some(1234567890));
	}

	#[test]
	fn test_quote_order_serialization() {
		let order = QuoteOrder {
			domain: InteropAddress::new_ethereum(
				1,
				address!("7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9"),
			),
			primary_type: "PermitBatchWitnessTransferFrom".to_string(),
			message: serde_json::json!({
				"permitted": [],
				"spender": "0x1234567890123456789012345678901234567890",
				"nonce": "123",
				"deadline": "1234567890"
			}),
		};

		let json = serde_json::to_string(&order).unwrap();
		assert!(json.contains("\"primaryType\""));
		assert!(json.contains("\"message\""));

		let deserialized: QuoteOrder = serde_json::from_str(&json).unwrap();
		assert_eq!(deserialized.primary_type, "PermitBatchWitnessTransferFrom");
	}

	#[test]
	fn test_settlement_type_serialization() {
		let settlement_types = [SettlementType::Escrow, SettlementType::ResourceLock];
		let expected_values = ["\"escrow\"", "\"resourceLock\""];

		for (settlement_type, expected) in settlement_types.iter().zip(expected_values.iter()) {
			let json = serde_json::to_string(settlement_type).unwrap();
			assert_eq!(json, *expected);

			let deserialized: SettlementType = serde_json::from_str(&json).unwrap();
			assert_eq!(deserialized, *settlement_type);
		}
	}

	#[test]
	fn test_quote_serialization() {
		let quote = Quote {
			orders: vec![QuoteOrder {
				domain: InteropAddress::new_ethereum(
					1,
					address!("5555555555555555555555555555555555555555"),
				),
				primary_type: "TestType".to_string(),
				message: serde_json::json!({"test": "value"}),
			}],
			details: QuoteDetails {
				requested_outputs: vec![],
				available_inputs: vec![],
			},
			valid_until: Some(1234567890),
			eta: Some(300),
			quote_id: "quote_123".to_string(),
			provider: "test_solver".to_string(),
		};

		let json = serde_json::to_string(&quote).unwrap();
		assert!(json.contains("\"validUntil\""));
		assert!(json.contains("\"quoteId\""));
		assert!(json.contains("\"provider\""));

		let deserialized: Quote = serde_json::from_str(&json).unwrap();
		assert_eq!(deserialized.quote_id, "quote_123");
		assert_eq!(deserialized.valid_until, Some(1234567890));
		assert_eq!(deserialized.eta, Some(300));
	}

	#[test]
	fn test_get_quote_response_serialization() {
		let response = GetQuoteResponse {
			quotes: vec![Quote {
				orders: vec![],
				details: QuoteDetails {
					requested_outputs: vec![],
					available_inputs: vec![],
				},
				valid_until: None,
				eta: None,
				quote_id: "test_quote".to_string(),
				provider: "test_provider".to_string(),
			}],
		};

		let json = serde_json::to_string(&response).unwrap();
		let deserialized: GetQuoteResponse = serde_json::from_str(&json).unwrap();
		assert_eq!(deserialized.quotes.len(), 1);
		assert_eq!(deserialized.quotes[0].quote_id, "test_quote");
	}

	#[test]
	fn test_error_response_serialization() {
		let error_response = ErrorResponse {
			error: "INVALID_REQUEST".to_string(),
			message: "The request is invalid".to_string(),
			details: Some(serde_json::json!({"field": "amount"})),
			retry_after: Some(60),
		};

		let json = serde_json::to_string(&error_response).unwrap();
		assert!(json.contains("\"retryAfter\""));
		assert!(json.contains("\"details\""));

		let deserialized: ErrorResponse = serde_json::from_str(&json).unwrap();
		assert_eq!(deserialized.error, "INVALID_REQUEST");
		assert_eq!(deserialized.retry_after, Some(60));
	}

	#[test]
	fn test_api_error_status_codes() {
		let bad_request = APIError::BadRequest {
			error_type: "TEST_ERROR".to_string(),
			message: "Test message".to_string(),
			details: None,
		};
		assert_eq!(bad_request.status_code(), 400);

		let unprocessable = APIError::UnprocessableEntity {
			error_type: "TEST_ERROR".to_string(),
			message: "Test message".to_string(),
			details: None,
		};
		assert_eq!(unprocessable.status_code(), 422);

		let unavailable = APIError::ServiceUnavailable {
			error_type: "TEST_ERROR".to_string(),
			message: "Test message".to_string(),
			retry_after: Some(30),
		};
		assert_eq!(unavailable.status_code(), 503);

		let internal_error = APIError::InternalServerError {
			error_type: "TEST_ERROR".to_string(),
			message: "Test message".to_string(),
		};
		assert_eq!(internal_error.status_code(), 500);
	}

	#[test]
	fn test_api_error_to_error_response() {
		let api_error = APIError::BadRequest {
			error_type: "VALIDATION_ERROR".to_string(),
			message: "Invalid input".to_string(),
			details: Some(serde_json::json!({"field": "amount"})),
		};

		let error_response = api_error.to_error_response();
		assert_eq!(error_response.error, "VALIDATION_ERROR");
		assert_eq!(error_response.message, "Invalid input");
		assert!(error_response.details.is_some());
		assert_eq!(error_response.retry_after, None);

		let service_unavailable = APIError::ServiceUnavailable {
			error_type: "RATE_LIMITED".to_string(),
			message: "Too many requests".to_string(),
			retry_after: Some(120),
		};

		let error_response = service_unavailable.to_error_response();
		assert_eq!(error_response.retry_after, Some(120));
		assert!(error_response.details.is_none());
	}

	#[test]
	fn test_api_error_display() {
		let errors = [
			(
				APIError::BadRequest {
					error_type: "TEST".to_string(),
					message: "Bad request message".to_string(),
					details: None,
				},
				"Bad Request: Bad request message",
			),
			(
				APIError::UnprocessableEntity {
					error_type: "TEST".to_string(),
					message: "Unprocessable message".to_string(),
					details: None,
				},
				"Unprocessable Entity: Unprocessable message",
			),
			(
				APIError::ServiceUnavailable {
					error_type: "TEST".to_string(),
					message: "Service unavailable message".to_string(),
					retry_after: None,
				},
				"Service Unavailable: Service unavailable message",
			),
			(
				APIError::InternalServerError {
					error_type: "TEST".to_string(),
					message: "Internal error message".to_string(),
				},
				"Internal Server Error: Internal error message",
			),
		];

		for (error, expected) in errors.iter() {
			assert_eq!(error.to_string(), *expected);
		}
	}

	#[test]
	fn test_quote_error_display() {
		let errors = [
			(
				QuoteError::InvalidRequest("bad format".to_string()),
				"Invalid request: bad format",
			),
			(
				QuoteError::UnsupportedAsset("ETH".to_string()),
				"Unsupported asset: ETH",
			),
			(
				QuoteError::UnsupportedSettlement("escrow".to_string()),
				"Unsupported settlement: escrow",
			),
			(
				QuoteError::InsufficientLiquidity,
				"Insufficient liquidity for requested amount",
			),
			(
				QuoteError::SolverCapacityExceeded,
				"Solver capacity exceeded",
			),
			(
				QuoteError::Internal("database error".to_string()),
				"Internal error: database error",
			),
		];

		for (error, expected) in errors.iter() {
			assert_eq!(error.to_string(), *expected);
		}
	}

	#[test]
	fn test_quote_error_to_api_error() {
		let quote_error = QuoteError::InvalidRequest("Invalid amount".to_string());
		let api_error: APIError = quote_error.into();
		assert_eq!(api_error.status_code(), 400);

		let quote_error = QuoteError::UnsupportedAsset("USDC".to_string());
		let api_error: APIError = quote_error.into();
		assert_eq!(api_error.status_code(), 422);

		let quote_error = QuoteError::SolverCapacityExceeded;
		let api_error: APIError = quote_error.into();
		assert_eq!(api_error.status_code(), 503);
		let error_response = api_error.to_error_response();
		assert_eq!(error_response.retry_after, Some(60));

		let quote_error = QuoteError::Internal("DB connection failed".to_string());
		let api_error: APIError = quote_error.into();
		assert_eq!(api_error.status_code(), 500);
	}

	#[test]
	fn test_get_order_error_display() {
		let errors = [
			(
				GetOrderError::NotFound("order_123".to_string()),
				"Order not found: order_123",
			),
			(
				GetOrderError::InvalidId("invalid_format".to_string()),
				"Invalid order ID format: invalid_format",
			),
			(
				GetOrderError::Internal("storage error".to_string()),
				"Internal error: storage error",
			),
		];

		for (error, expected) in errors.iter() {
			assert_eq!(error.to_string(), *expected);
		}
	}

	#[test]
	fn test_get_order_error_to_api_error() {
		let order_error = GetOrderError::NotFound("order_456".to_string());
		let api_error: APIError = order_error.into();
		assert_eq!(api_error.status_code(), 400);
		let error_response = api_error.to_error_response();
		assert!(error_response.details.is_some());

		let order_error = GetOrderError::InvalidId("bad_id".to_string());
		let api_error: APIError = order_error.into();
		assert_eq!(api_error.status_code(), 400);

		let order_error = GetOrderError::Internal("DB error".to_string());
		let api_error: APIError = order_error.into();
		assert_eq!(api_error.status_code(), 500);
	}

	#[test]
	fn test_debug_implementations() {
		let asset_amount = AssetAmount {
			asset: InteropAddress::new_ethereum(
				1,
				address!("A0b86a33E6776Fb78B3e1E6B2D0d2E8F0C1D2A3B"),
			),
			amount: "100".to_string(),
		};
		let debug_str = format!("{:?}", asset_amount);

		assert!(debug_str.contains("AssetAmount"));
		assert!(debug_str.contains("asset:"));
		assert!(debug_str.contains("InteropAddress"));
		assert!(debug_str.contains("version: 1"));
		assert!(debug_str.contains("chain_type:"));
		assert!(debug_str.contains("chain_reference:"));
		assert!(debug_str.contains("address:"));
		assert!(debug_str.contains("amount: \"100\""));

		let lock_kind = LockKind::TheCompact;
		let debug_str = format!("{:?}", lock_kind);
		assert!(debug_str.contains("TheCompact"));

		let api_error = APIError::BadRequest {
			error_type: "TEST".to_string(),
			message: "Test message".to_string(),
			details: None,
		};
		let debug_str = format!("{:?}", api_error);
		assert!(debug_str.contains("BadRequest"));
		assert!(debug_str.contains("error_type: \"TEST\""));
		assert!(debug_str.contains("message: \"Test message\""));
		assert!(debug_str.contains("details: None"));
	}

	#[test]
	fn test_clone_implementations() {
		let asset_amount = AssetAmount {
			asset: InteropAddress::new_ethereum(
				1,
				address!("A0b86a33E6776Fb78B3e1E6B2D0d2E8F0C1D2A3B"),
			),
			amount: "100".to_string(),
		};
		let cloned = asset_amount.clone();
		assert_eq!(cloned.asset, asset_amount.asset);
		assert_eq!(cloned.amount, asset_amount.amount);

		let preference = QuotePreference::Price;
		let cloned = preference.clone();
		assert!(matches!(cloned, QuotePreference::Price));
	}

	#[test]
	fn test_edge_cases() {
		// Test empty arrays
		let request = GetQuoteRequest {
			user: InteropAddress::new_ethereum(
				1,
				address!("A0b86a33E6776Fb78B3e1E6B2D0d2E8F0C1D2A3B"),
			),
			available_inputs: vec![],
			requested_outputs: vec![],
			min_valid_until: None,
			preference: None,
			order_type: None,
			origin_submission: None,
		};

		let json = serde_json::to_string(&request).unwrap();
		let deserialized: GetQuoteRequest = serde_json::from_str(&json).unwrap();
		assert_eq!(deserialized.available_inputs.len(), 0);
		assert_eq!(deserialized.requested_outputs.len(), 0);

		// Test zero amounts
		let asset_amount = AssetAmount {
			asset: InteropAddress::new_ethereum(
				1,
				address!("A0b86a33E6776Fb78B3e1E6B2D0d2E8F0C1D2A3B"),
			),
			amount: "0".to_string(),
		};

		let json = serde_json::to_string(&asset_amount).unwrap();
		let deserialized: AssetAmount = serde_json::from_str(&json).unwrap();
		assert_eq!(deserialized.amount, "0".to_string());
	}
}
