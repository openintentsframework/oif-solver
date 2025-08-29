//! API types for the OIF Solver HTTP API.
//!
//! This module defines the request and response types for the OIF Solver API
//! endpoints, following the ERC-7683 Cross-Chain Intents Standard.
use crate::standards::eip7930::InteropAddress;
use alloy_primitives::U256;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Asset amount representation using ERC-7930 interoperable address format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetAmount {
	/// Asset address in ERC-7930 interoperable format
	pub asset: String,
	/// Amount as a big integer
	#[serde(with = "u256_serde")]
	pub amount: U256,
}

/// Lock information for inputs that are already locked
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lock {
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
}

/// Available input with lock information and user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailableInput {
	/// User address in ERC-7930 interoperable format
	pub user: InteropAddress,
	/// Asset address in ERC-7930 interoperable format
	pub asset: InteropAddress,
	/// Amount as a big integer
	#[serde(with = "u256_serde")]
	pub amount: U256,
	/// Lock information if asset is already locked
	pub lock: Option<Lock>,
}

/// Requested output with receiver and optional calldata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestedOutput {
	/// Receiver address in ERC-7930 interoperable format
	pub receiver: InteropAddress,
	/// Asset address in ERC-7930 interoperable format
	pub asset: InteropAddress,
	/// Amount as a big integer
	#[serde(with = "u256_serde")]
	pub amount: U256,
	/// Optional calldata for the output
	pub calldata: Option<String>,
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
	/// Minimum quote validity duration in seconds
	#[serde(rename = "minValidUntil")]
	pub min_valid_until: Option<u64>,
	/// User preference for optimization
	pub preference: Option<QuotePreference>,
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
	/// Signature type (eip-712 or erc-3009)
	#[serde(rename = "signatureType")]
	pub signature_type: SignatureType,
	/// ERC-7930 interoperable address of the domain
	pub domain: InteropAddress,
	/// Primary type for EIP-712 signing
	#[serde(rename = "primaryType")]
	pub primary_type: String,
	/// Message object to be signed and submitted
	pub message: serde_json::Value,
}

/// Supported signature types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureType {
	Eip712,
	Erc3009,
}

/// Quote details matching the request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteDetails {
	/// Requested outputs for this quote
	#[serde(rename = "requestedOutputs")]
	pub requested_outputs: Vec<RequestedOutput>,
	/// Available inputs for this quote
	#[serde(rename = "availableInputs")]
	pub available_inputs: Vec<AvailableInput>,
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

/// Response containing order details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetOrderResponse {
	/// Order details
	pub order: crate::order::OrderResponse,
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

/// Serde module for U256 serialization/deserialization.
pub mod u256_serde {
	use alloy_primitives::U256;
	use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

	pub fn serialize<S>(value: &U256, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		value.to_string().serialize(serializer)
	}

	pub fn deserialize<'de, D>(deserializer: D) -> Result<U256, D::Error>
	where
		D: Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		U256::from_str_radix(&s, 10).map_err(D::Error::custom)
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
	use alloy_primitives::U256;
	use serde_json;

	#[test]
	fn test_asset_amount_serialization() {
		let asset_amount = AssetAmount {
			asset: "0x1234567890123456789012345678901234567890".to_string(),
			amount: U256::from(1000),
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
		let lock = Lock {
			kind: LockKind::TheCompact,
			params: Some(serde_json::json!({"resource_id": "0x123"})),
		};

		let json = serde_json::to_string(&lock).unwrap();
		let deserialized: Lock = serde_json::from_str(&json).unwrap();

		assert!(matches!(deserialized.kind, LockKind::TheCompact));
		assert!(deserialized.params.is_some());
	}

	#[test]
	fn test_available_input_serialization() {
		let input = AvailableInput {
			user: InteropAddress::new_ethereum(
				1,
				address!("1111111111111111111111111111111111111111"),
			),
			asset: InteropAddress::new_ethereum(
				1,
				address!("2222222222222222222222222222222222222222"),
			),
			amount: U256::from(5000),
			lock: Some(Lock {
				kind: LockKind::TheCompact,
				params: None,
			}),
		};

		let json = serde_json::to_string(&input).unwrap();
		let deserialized: AvailableInput = serde_json::from_str(&json).unwrap();

		assert_eq!(deserialized.amount, U256::from(5000));
		assert!(deserialized.lock.is_some());
	}

	#[test]
	fn test_requested_output_serialization() {
		let output = RequestedOutput {
			receiver: InteropAddress::new_ethereum(
				1,
				address!("3333333333333333333333333333333333333333"),
			),
			asset: InteropAddress::new_ethereum(
				1,
				address!("4444444444444444444444444444444444444444"),
			),
			amount: U256::from(2000),
			calldata: Some("0xdeadbeef".to_string()),
		};

		let json = serde_json::to_string(&output).unwrap();
		let deserialized: RequestedOutput = serde_json::from_str(&json).unwrap();

		assert_eq!(deserialized.amount, U256::from(2000));
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
			assert_eq!(deserialized, *preference);
		}
	}

	#[test]
	fn test_get_quote_request_serialization() {
		let request = GetQuoteRequest {
			user: InteropAddress::new_ethereum(
				1,
				address!("1111111111111111111111111111111111111111"),
			),
			available_inputs: vec![AvailableInput {
				user: InteropAddress::new_ethereum(
					1,
					address!("1111111111111111111111111111111111111111"),
				),
				asset: InteropAddress::new_ethereum(
					1,
					address!("2222222222222222222222222222222222222222"),
				),
				amount: U256::from(1000),
				lock: None,
			}],
			requested_outputs: vec![RequestedOutput {
				receiver: InteropAddress::new_ethereum(
					1,
					address!("3333333333333333333333333333333333333333"),
				),
				asset: InteropAddress::new_ethereum(
					1,
					address!("4444444444444444444444444444444444444444"),
				),
				amount: U256::from(900),
				calldata: None,
			}],
			min_valid_until: Some(1234567890),
			preference: Some(QuotePreference::Price),
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
	fn test_signature_type_serialization() {
		let sig_types = [SignatureType::Eip712, SignatureType::Erc3009];
		let expected_values = ["\"eip712\"", "\"erc3009\""];

		for (sig_type, expected) in sig_types.iter().zip(expected_values.iter()) {
			let json = serde_json::to_string(sig_type).unwrap();
			assert_eq!(json, *expected);

			let deserialized: SignatureType = serde_json::from_str(&json).unwrap();
			assert_eq!(deserialized, *sig_type);
		}
	}

	#[test]
	fn test_quote_order_serialization() {
		let order = QuoteOrder {
			signature_type: SignatureType::Eip712,
			domain: InteropAddress::new_ethereum(
				1,
				address!("5555555555555555555555555555555555555555"),
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
		assert!(json.contains("\"signatureType\":\"eip712\""));
		assert!(json.contains("\"primaryType\""));
		assert!(json.contains("\"message\""));

		let deserialized: QuoteOrder = serde_json::from_str(&json).unwrap();
		assert!(matches!(deserialized.signature_type, SignatureType::Eip712));
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
				signature_type: SignatureType::Eip712,
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
	fn test_u256_serde_serialize() {
		#[derive(Serialize)]
		struct TestStruct {
			#[serde(with = "u256_serde")]
			amount: U256,
		}

		let test_struct = TestStruct {
			amount: U256::from(12345),
		};
		let json = serde_json::to_string(&test_struct).unwrap();
		assert!(json.contains("\"12345\""));
	}

	#[test]
	fn test_u256_serde_deserialize() {
		let json = r#"{"amount": "98765"}"#;
		#[derive(Deserialize)]
		struct TestStruct {
			#[serde(with = "u256_serde")]
			amount: U256,
		}

		let deserialized: TestStruct = serde_json::from_str(json).unwrap();
		assert_eq!(deserialized.amount, U256::from(98765));

		// Test invalid input
		let invalid_json = r#"{"amount": "not_a_number"}"#;
		let result: Result<TestStruct, _> = serde_json::from_str(invalid_json);
		assert!(result.is_err());
	}

	#[test]
	fn test_u256_serde_large_numbers() {
		#[derive(Serialize, Deserialize)]
		struct TestStruct {
			#[serde(with = "u256_serde")]
			amount: U256,
		}

		let large_value = U256::from_str_radix(
			"115792089237316195423570985008687907853269984665640564039457584007913129639935",
			10,
		)
		.unwrap();
		let test_struct = TestStruct {
			amount: large_value,
		};

		let json = serde_json::to_string(&test_struct).unwrap();
		let deserialized: TestStruct = serde_json::from_str(&json).unwrap();
		assert_eq!(deserialized.amount, large_value);
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
			asset: "test_asset".to_string(),
			amount: U256::from(100),
		};
		let debug_str = format!("{:?}", asset_amount);
		assert!(debug_str.contains("AssetAmount"));
		assert!(debug_str.contains("test_asset"));

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
	}

	#[test]
	fn test_clone_implementations() {
		let asset_amount = AssetAmount {
			asset: "test_asset".to_string(),
			amount: U256::from(100),
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
				address!("1111111111111111111111111111111111111111"),
			),
			available_inputs: vec![],
			requested_outputs: vec![],
			min_valid_until: None,
			preference: None,
		};

		let json = serde_json::to_string(&request).unwrap();
		let deserialized: GetQuoteRequest = serde_json::from_str(&json).unwrap();
		assert_eq!(deserialized.available_inputs.len(), 0);
		assert_eq!(deserialized.requested_outputs.len(), 0);

		// Test zero amounts
		let asset_amount = AssetAmount {
			asset: "test".to_string(),
			amount: U256::ZERO,
		};

		let json = serde_json::to_string(&asset_amount).unwrap();
		let deserialized: AssetAmount = serde_json::from_str(&json).unwrap();
		assert_eq!(deserialized.amount, U256::ZERO);
	}
}
