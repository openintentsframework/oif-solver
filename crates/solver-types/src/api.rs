//! API types for the OIF Solver HTTP API.
//!
//! This module defines the request and response types for the OIF Solver API
//! endpoints, following the ERC-7683 Cross-Chain Intents Standard.
use crate::{standards::eip7930::InteropAddress, OrderStatus};
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
	pub status: OrderStatus,
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
