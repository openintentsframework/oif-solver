//! API types for the OIF Solver HTTP API.
//!
//! This module defines the request and response types for the OIF Solver API
//! endpoints, following the ERC-7683 Cross-Chain Intents Standard.

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

/// Available input with optional priority weighting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailableInput {
	/// The input asset and amount
	pub input: AssetAmount,
	/// Optional priority weighting (0-100)
	pub priority: Option<u8>,
}

/// Request for getting price quotes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetQuoteRequest {
	/// Available inputs with optional priority
	#[serde(rename = "availableInputs")]
	pub available_inputs: Vec<AvailableInput>,
	/// Requested minimum outputs
	#[serde(rename = "requestedMinOutputs")]
	pub requested_min_outputs: Vec<AssetAmount>,
	/// Minimum quote validity duration in seconds
	#[serde(rename = "minValidUntil")]
	pub min_valid_until: Option<u64>,
	/// User preference for optimization
	pub preference: Option<QuotePreference>,
}

/// Quote optimization preferences.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QuotePreference {
	Price,
	Speed,
	InputPriority,
}

/// Settlement order data for quotes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementOrder {
	/// Settlement contract address
	pub settler: String,
	/// Settlement-specific data to be signed
	pub data: serde_json::Value,
}

/// A quote option with all necessary execution details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteOption {
	/// Settlement orders
	pub orders: SettlementOrder,
	/// Required token allowances
	#[serde(rename = "requiredAllowances")]
	pub required_allowances: Vec<AssetAmount>,
	/// Quote validity timestamp
	#[serde(rename = "validUntil")]
	pub valid_until: u64,
	/// Estimated time to completion in seconds
	pub eta: u64,
	/// Total cost in USD
	#[serde(rename = "totalFeeUsd")]
	pub total_fee_usd: f64,
	/// Unique quote identifier
	#[serde(rename = "quoteId")]
	pub quote_id: String,
	/// Settlement mechanism type
	#[serde(rename = "settlementType")]
	pub settlement_type: SettlementType,
}

/// Settlement mechanism types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SettlementType {
	Escrow,
	ResourceLock,
}

/// Response containing quote options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetQuoteResponse {
	/// Available quote options
	pub quotes: Vec<QuoteOption>,
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
	InternalServerError {
		error_type: String,
		message: String,
	},
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
			APIError::BadRequest { error_type, message, details } => ErrorResponse {
				error: error_type.clone(),
				message: message.clone(),
				details: details.clone(),
				retry_after: None,
			},
			APIError::UnprocessableEntity { error_type, message, details } => ErrorResponse {
				error: error_type.clone(),
				message: message.clone(),
				details: details.clone(),
				retry_after: None,
			},
			APIError::ServiceUnavailable { error_type, message, retry_after } => ErrorResponse {
				error: error_type.clone(),
				message: message.clone(),
				details: None,
				retry_after: *retry_after,
			},
			APIError::InternalServerError { error_type, message } => ErrorResponse {
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
			APIError::UnprocessableEntity { message, .. } => write!(f, "Unprocessable Entity: {}", message),
			APIError::ServiceUnavailable { message, .. } => write!(f, "Service Unavailable: {}", message),
			APIError::InternalServerError { message, .. } => write!(f, "Internal Server Error: {}", message),
		}
	}
}

impl std::error::Error for APIError {}

#[cfg(feature = "axum")]
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

