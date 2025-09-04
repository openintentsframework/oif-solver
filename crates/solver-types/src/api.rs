//! API types for the OIF Solver HTTP API.
//!
//! This module defines the request and response types for the OIF Solver API
//! endpoints, following the ERC-7683 Cross-Chain Intents Standard.
use crate::{costs::QuoteCost, standards::eip7930::InteropAddress};
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
	/// Cost breakdown
	#[serde(skip_serializing_if = "Option::is_none")]
	pub cost: Option<QuoteCost>,
	// Using LockType
	pub lock_type: String,
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

/// A tuple combining Quote and signature for intent request conversion
#[cfg(feature = "oif-interfaces")]
pub struct QuoteWithSignature<'a> {
	pub quote: &'a Quote,
	pub signature: &'a str,
}

#[cfg(feature = "oif-interfaces")]
impl<'a> From<(&'a Quote, &'a str)> for QuoteWithSignature<'a> {
	fn from((quote, signature): (&'a Quote, &'a str)) -> Self {
		Self { quote, signature }
	}
}

#[cfg(feature = "oif-interfaces")]
impl TryFrom<QuoteWithSignature<'_>> for serde_json::Value {
	type Error = Box<dyn std::error::Error>;

	fn try_from(quote_with_sig: QuoteWithSignature<'_>) -> Result<Self, Self::Error> {
		use crate::standards::eip7683::interfaces::{SolMandateOutput, StandardOrder};
		use crate::standards::eip7930::InteropAddress;
		use alloy_primitives::{Address, U256};
		use alloy_sol_types::SolType;

		// Extract user address from the first available input
		let user_str = &quote_with_sig
			.quote
			.details
			.available_inputs
			.first()
			.ok_or("Quote must have at least one available input")?
			.user;
		let interop_address = InteropAddress::from_hex(&user_str.to_string())?;
		let user_address = interop_address.ethereum_address()?;

		// Extract order data from quote
		let quote_order = quote_with_sig
			.quote
			.orders
			.first()
			.ok_or("Quote must contain at least one order")?;
		let message_data = quote_order
			.message
			.as_object()
			.ok_or("Invalid EIP-712 message structure")?;
		let eip712_data = message_data
			.get("eip712")
			.and_then(|e| e.as_object())
			.ok_or("Missing 'eip712' object in message")?;

		// Extract nonce
		let nonce_str = eip712_data
			.get("nonce")
			.and_then(|n| n.as_str())
			.ok_or("Missing nonce in EIP-712 data")?;
		let nonce = U256::from_str_radix(nonce_str, 10)?;

		// Extract witness data
		let witness = eip712_data
			.get("witness")
			.and_then(|w| w.as_object())
			.ok_or("Missing 'witness' object in EIP-712 message")?;

		// Get origin chain ID
		let origin_chain_id = U256::from(interop_address.ethereum_chain_id()?);

		// Extract timing data
		let expires = witness
			.get("expires")
			.and_then(|e| e.as_u64())
			.unwrap_or(quote_with_sig.quote.valid_until.unwrap_or(0)) as u32;
		let fill_deadline = expires;

		// Extract input oracle
		let input_oracle_str = witness
			.get("inputOracle")
			.and_then(|o| o.as_str())
			.ok_or("Missing 'inputOracle' in witness data")?;
		let input_oracle =
			Address::from_slice(&hex::decode(input_oracle_str.trim_start_matches("0x"))?);

		// Extract input data from permitted array
		let permitted = eip712_data
			.get("permitted")
			.and_then(|p| p.as_array())
			.ok_or("Missing permitted array in EIP-712 data")?;
		let first_permitted = permitted
			.first()
			.ok_or("Empty permitted array in EIP-712 data")?;

		let input_amount_str = first_permitted
			.get("amount")
			.and_then(|a| a.as_str())
			.ok_or("Missing amount in permitted token")?;
		let input_amount = U256::from_str_radix(input_amount_str, 10)?;

		let input_token_str = first_permitted
			.get("token")
			.and_then(|t| t.as_str())
			.ok_or("Missing token in permitted array")?;
		let input_token =
			Address::from_slice(&hex::decode(input_token_str.trim_start_matches("0x"))?);

		// Convert input token address to U256
		let mut token_bytes = [0u8; 32];
		token_bytes[12..32].copy_from_slice(&input_token.0 .0);
		let input_token_u256 = U256::from_be_bytes(token_bytes);
		let inputs = vec![[input_token_u256, input_amount]];

		// Extract outputs from witness
		let default_outputs = Vec::new();
		let witness_outputs = witness
			.get("outputs")
			.and_then(|o| o.as_array())
			.unwrap_or(&default_outputs);

		// Parse outputs with proper helper function for hex parsing
		fn parse_bytes32_from_hex(hex_str: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
			let hex_clean = hex_str.trim_start_matches("0x");
			if hex_clean.len() != 64 {
				return Err("Hex string must be exactly 64 characters (32 bytes)".into());
			}
			let mut bytes = [0u8; 32];
			hex::decode_to_slice(hex_clean, &mut bytes)?;
			Ok(bytes)
		}

		let mut sol_outputs = Vec::new();
		for output_item in witness_outputs {
			if let Some(output_obj) = output_item.as_object() {
				let chain_id = output_obj
					.get("chainId")
					.and_then(|c| c.as_u64())
					.unwrap_or(0);
				let amount_str = output_obj
					.get("amount")
					.and_then(|a| a.as_str())
					.unwrap_or("0");
				let token_str = output_obj.get("token").and_then(|t| t.as_str()).unwrap();
				let recipient_str = output_obj
					.get("recipient")
					.and_then(|r| r.as_str())
					.unwrap();
				let oracle_str = output_obj.get("oracle").and_then(|o| o.as_str()).unwrap();
				let settler_str = output_obj.get("settler").and_then(|s| s.as_str()).unwrap();

				if let Ok(amount) = U256::from_str_radix(amount_str, 10) {
					let token_bytes = parse_bytes32_from_hex(token_str).unwrap_or([0u8; 32]);
					let recipient_bytes =
						parse_bytes32_from_hex(recipient_str).unwrap_or([0u8; 32]);
					let oracle_bytes = parse_bytes32_from_hex(oracle_str).unwrap_or([0u8; 32]);
					let settler_bytes = parse_bytes32_from_hex(settler_str).unwrap_or([0u8; 32]);

					sol_outputs.push(SolMandateOutput {
						oracle: oracle_bytes.into(),
						settler: settler_bytes.into(),
						chainId: U256::from(chain_id),
						token: token_bytes.into(),
						amount,
						recipient: recipient_bytes.into(),
						call: Vec::new().into(),
						context: Vec::new().into(),
					});
				}
			}
		}

		// Create and encode the StandardOrder
		let sol_order = StandardOrder {
			user: user_address,
			nonce,
			originChainId: origin_chain_id,
			expires,
			fillDeadline: fill_deadline,
			inputOracle: input_oracle,
			inputs,
			outputs: sol_outputs,
		};

		// ABI encode the StandardOrder
		let encoded_order = StandardOrder::abi_encode(&sol_order);

		// Create IntentRequest
		let intent_request = serde_json::json!({
			"order": format!("0x{}", hex::encode(&encoded_order)),
			"sponsor": format!("{:#x}", user_address),
			"signature": quote_with_sig.signature,
			"lockType": quote_with_sig.quote.lock_type.clone()
		});

		Ok(intent_request)
	}
}

impl Quote {
	/// Extract lock type from quote data with fallback logic
	pub fn extract_lock_type(&self) -> String {
		// First check the direct lock_type field on the quote
		if !self.lock_type.is_empty() {
			return self.lock_type.clone();
		}

		// Check if the quote contains lock type information in order data or witness data
		if let Some(quote_order) = self.orders.first() {
			if let Some(message_data) = quote_order.message.as_object() {
				// Check for lock type in the main message data
				if let Some(lock_type) = message_data.get("lockType").and_then(|v| v.as_str()) {
					return lock_type.to_string();
				}

				// Check for lock type in EIP-712 data
				if let Some(eip712_data) = message_data.get("eip712").and_then(|e| e.as_object()) {
					if let Some(lock_type) = eip712_data.get("lockType").and_then(|v| v.as_str()) {
						return lock_type.to_string();
					}

					// Check witness data for lock type
					if let Some(witness) = eip712_data.get("witness").and_then(|w| w.as_object()) {
						if let Some(lock_type) = witness.get("lockType").and_then(|v| v.as_str()) {
							return lock_type.to_string();
						}
					}
				}
			}
		}

		// Default fallback
		"permit2_escrow".to_string()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::standards::eip7930::InteropAddress;
	use crate::utils::tests::builders::{
		AssetAmountBuilder, AvailableInputBuilder, GetQuoteRequestBuilder, RequestedOutputBuilder,
	};
	use alloy_primitives::address;
	use alloy_primitives::U256;
	use serde_json;

	#[test]
	fn test_asset_amount_serialization() {
		let asset_amount = AssetAmountBuilder::new()
			.asset("0x1234567890123456789012345678901234567890")
			.amount_u64(1000)
			.build();

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
		let input = AvailableInputBuilder::new()
			.user_ethereum(1, address!("1111111111111111111111111111111111111111"))
			.asset_ethereum(1, address!("2222222222222222222222222222222222222222"))
			.amount_u64(5000)
			.lock(Lock {
				kind: LockKind::TheCompact,
				params: None,
			})
			.build();

		let json = serde_json::to_string(&input).unwrap();
		let deserialized: AvailableInput = serde_json::from_str(&json).unwrap();

		assert_eq!(deserialized.amount, U256::from(5000));
		assert!(deserialized.lock.is_some());
	}

	#[test]
	fn test_requested_output_serialization() {
		let output = RequestedOutputBuilder::new()
			.receiver_ethereum(1, address!("3333333333333333333333333333333333333333"))
			.asset_ethereum(1, address!("4444444444444444444444444444444444444444"))
			.amount_u64(2000)
			.calldata("0xdeadbeef")
			.build();

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
		let input = AvailableInputBuilder::new()
			.user_ethereum(1, address!("1111111111111111111111111111111111111111"))
			.asset_ethereum(1, address!("2222222222222222222222222222222222222222"))
			.amount_u64(1000)
			.build();

		let output = RequestedOutputBuilder::new()
			.receiver_ethereum(1, address!("3333333333333333333333333333333333333333"))
			.asset_ethereum(1, address!("4444444444444444444444444444444444444444"))
			.amount_u64(900)
			.build();

		let request = GetQuoteRequestBuilder::new()
			.user_ethereum(1, address!("1111111111111111111111111111111111111111"))
			.add_available_input(input)
			.add_requested_output(output)
			.min_valid_until(1234567890)
			.preference(QuotePreference::Price)
			.build();

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
			cost: None,
			lock_type: "permit2_escrow".to_string(),
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
				cost: None,
				lock_type: "permit2_escrow".to_string(),
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
