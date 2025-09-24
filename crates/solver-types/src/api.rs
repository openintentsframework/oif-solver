//! API types for the OIF Solver HTTP API.
//!
//! This module defines the request and response types for the OIF Solver API
//! endpoints, following the ERC-7683 Cross-Chain Intents Standard.
use crate::{
	costs::CostEstimate,
	standards::{eip7683::LockType, eip7930::InteropAddress},
};
use alloy_primitives::{Address, Bytes, U256};
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;

/// Order interpretation for quote requests
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum SwapType {
	ExactInput,
	ExactOutput,
}

/// Origin submission preference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OriginSubmission {
	pub mode: OriginMode,
	pub schemes: Option<Vec<AuthScheme>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OriginMode {
	User,
	Protocol,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthScheme {
	Erc4337,
	Permit2,
	Erc20Permit,
	Eip3009,
}

/// Failure handling policy
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FailureHandlingMode {
	RefundAutomatic,
	RefundClaim,
	NeedsNewSignature,
}

/// Intent type identifier
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum IntentType {
	OifSwap,
}

/// OIF version constants for order types
pub mod oif_versions {
	pub const V0: &str = "v0";
	pub const V1: &str = "v1"; // For future use
	pub const CURRENT: &str = V0; // Currently supported version

	// Order type constructors
	pub fn escrow_order_type(version: &str) -> String {
		format!("oif-escrow-{}", version)
	}

	pub fn resource_lock_order_type(version: &str) -> String {
		format!("oif-resource-lock-{}", version)
	}

	pub fn eip3009_order_type(version: &str) -> String {
		format!("oif-3009-{}", version)
	}

	pub fn generic_order_type(version: &str) -> String {
		format!("oif-generic-{}", version)
	}
}

/// OIF Order union type with versioning support
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum OifOrder {
	#[serde(rename = "oif-escrow-v0")]
	OifEscrowV0 { payload: OrderPayload },
	#[serde(rename = "oif-resource-lock-v0")]
	OifResourceLockV0 { payload: OrderPayload },
	#[serde(rename = "oif-3009-v0")]
	Oif3009V0 {
		payload: OrderPayload,
		metadata: serde_json::Value,
	},
	#[serde(rename = "oif-generic-v0")]
	OifGenericV0 {
		payload: serde_json::Value, // More flexible for generic orders
	},
}

/// Standard order payload structure for most order types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderPayload {
	#[serde(rename = "signatureType")]
	pub signature_type: NewSignatureType,
	pub domain: serde_json::Value,
	#[serde(rename = "primaryType")]
	pub primary_type: String,
	pub message: serde_json::Value,
}

/// New signature types for OIF orders
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NewSignatureType {
	Eip712,
}

impl OifOrder {
	/// Get the order type string for this order
	pub fn order_type(&self) -> &'static str {
		match self {
			OifOrder::OifEscrowV0 { .. } => "oif-escrow-v0",
			OifOrder::OifResourceLockV0 { .. } => "oif-resource-lock-v0",
			OifOrder::Oif3009V0 { .. } => "oif-3009-v0",
			OifOrder::OifGenericV0 { .. } => "oif-generic-v0",
		}
	}

	/// Extract version from order type
	pub fn version(&self) -> &'static str {
		match self {
			OifOrder::OifEscrowV0 { .. }
			| OifOrder::OifResourceLockV0 { .. }
			| OifOrder::Oif3009V0 { .. }
			| OifOrder::OifGenericV0 { .. } => oif_versions::V0,
		}
	}

	/// Check if this order type is supported
	pub fn is_supported(&self) -> bool {
		// For now, only v0 orders are supported
		matches!(self.version(), oif_versions::V0)
	}
}

/// Reference to a lock in a locking system (updated from Lock)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetLockReference {
	pub kind: LockKind,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub params: Option<serde_json::Value>,
}

impl AssetLockReference {
	/// Infer the appropriate order type based on lock kind and version
	pub fn infer_order_type(&self, version: &str) -> String {
		use oif_versions::*;
		match self.kind {
			LockKind::TheCompact => resource_lock_order_type(version),
			LockKind::Rhinestone => resource_lock_order_type(version),
		}
	}

	/// Infer order type using current version
	pub fn infer_current_order_type(&self) -> String {
		self.infer_order_type(oif_versions::CURRENT)
	}
}

/// Post order request that unifies both quote acceptances and direct order submissions.
/// Used as the common type for order validation and forwarding to discovery service.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PostOrderRequest {
	pub order: Bytes,
	pub sponsor: Address,
	pub signature: Bytes,
	#[serde(
		default = "default_lock_type",
		deserialize_with = "deserialize_lock_type_flexible"
	)]
	pub lock_type: LockType,
}

/// Default lock type for PostOrderRequest
fn default_lock_type() -> LockType {
	LockType::Permit2Escrow
}

/// Flexible deserializer for LockType that accepts numbers, strings, or enum names.
fn deserialize_lock_type_flexible<'de, D>(deserializer: D) -> Result<LockType, D::Error>
where
	D: Deserializer<'de>,
{
	use serde::de::Visitor;

	struct LockTypeVisitor;

	impl Visitor<'_> for LockTypeVisitor {
		type Value = LockType;

		fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
			formatter.write_str("a number, string, or null for LockType")
		}

		fn visit_u64<E>(self, value: u64) -> Result<LockType, E>
		where
			E: Error,
		{
			if value <= 255 {
				LockType::from_u8(value as u8)
					.ok_or_else(|| Error::custom("Invalid LockType value"))
			} else {
				Err(Error::custom("LockType value out of range"))
			}
		}

		fn visit_str<E>(self, value: &str) -> Result<LockType, E>
		where
			E: Error,
		{
			if let Ok(num) = value.parse::<u8>() {
				LockType::from_u8(num).ok_or_else(|| Error::custom("Invalid LockType value"))
			} else {
				// Try parsing as enum variant name
				match value {
					"permit2_escrow" | "Permit2Escrow" => Ok(LockType::Permit2Escrow),
					"eip3009_escrow" | "Eip3009Escrow" => Ok(LockType::Eip3009Escrow),
					"compact_resource_lock" | "ResourceLock" => Ok(LockType::ResourceLock),
					_ => Err(Error::custom("Invalid LockType string")),
				}
			}
		}

		fn visit_none<E>(self) -> Result<LockType, E>
		where
			E: Error,
		{
			Ok(default_lock_type())
		}
	}

	deserializer.deserialize_any(LockTypeVisitor)
}

/// API error types as an enum for compile-time safety.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApiErrorType {
	// Order validation errors
	MissingOrderBytes,
	InvalidHexEncoding,
	OrderValidationFailed,

	// Quote errors
	QuoteNotFound,
	QuoteProcessingFailed,
	QuoteConversionFailed,
	MissingSignature,
	InvalidRequest,
	UnsupportedAsset,
	UnsupportedSettlement,
	InsufficientLiquidity,
	SolverCapacityExceeded,

	// Order retrieval errors
	OrderNotFound,
	InvalidOrderId,

	// Discovery service errors
	DiscoveryServiceNotConfigured,
	DiscoveryServiceUnavailable,
	DiscoveryServiceError,

	// Solver address errors
	SolverAddressError,

	// Cost estimation errors
	NoOutputs,
	MissingChainId,
	GasEstimationFailed,
	CostCalculationFailed,
	InsufficientProfitability,

	// Transaction generation errors
	SerializationFailed,
	FillTxGenerationFailed,
	ClaimTxGenerationFailed,

	// Generic errors for extensibility
	ValidationError,
	ProcessingError,
	ServiceError,
	InternalError,
	Unknown,
}

impl fmt::Display for ApiErrorType {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		// Use serde to get the SCREAMING_SNAKE_CASE representation
		let json_str = serde_json::to_string(self).map_err(|_| fmt::Error)?;
		// Remove quotes from JSON string
		write!(f, "{}", json_str.trim_matches('"'))
	}
}

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
	#[serde(alias = "TheCompact", alias = "the_compact")]
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

/// Quote input from a user (amounts optional for quote requests)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteInput {
	/// User address in EIP-7930 Address format
	pub user: String,
	/// Asset address in EIP-7930 Address format
	pub asset: String,
	/// Optional Amount as string - depends on SwapType
	#[serde(skip_serializing_if = "Option::is_none")]
	pub amount: Option<String>,
	/// Lock information if asset is already locked
	#[serde(skip_serializing_if = "Option::is_none")]
	pub lock: Option<AssetLockReference>,
}

/// Quote output for a receiver (amounts optional for quote requests)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteOutput {
	/// Receiver address in EIP-7930 Address format
	pub receiver: String,
	/// Asset address in EIP-7930 Address format
	pub asset: String,
	/// Optional Amount as string - depends on SwapType
	#[serde(skip_serializing_if = "Option::is_none")]
	pub amount: Option<String>,
	/// Optional calldata for the output
	#[serde(skip_serializing_if = "Option::is_none")]
	pub calldata: Option<String>,
}

/// Order input for actual intent/order submission (amounts always required)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderInput {
	/// User address in EIP-7930 Address format
	pub user: String,
	/// Asset address in EIP-7930 Address format
	pub asset: String,
	/// Required Amount as string
	pub amount: String,
	/// Lock information if asset is already locked
	#[serde(skip_serializing_if = "Option::is_none")]
	pub lock: Option<AssetLockReference>,
}

/// Order output for actual intent/order submission (amounts always required)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderOutput {
	/// Receiver address in EIP-7930 Address format
	pub receiver: String,
	/// Asset address in EIP-7930 Address format
	pub asset: String,
	/// Required Amount as string
	pub amount: String,
	/// Optional calldata for the output
	#[serde(skip_serializing_if = "Option::is_none")]
	pub calldata: Option<String>,
}

impl QuoteInput {
	/// Convert string address to InteropAddress for internal use
	pub fn user_as_interop_address(&self) -> Result<InteropAddress, String> {
		InteropAddress::from_hex(&self.user).map_err(|e| e.to_string())
	}

	pub fn asset_as_interop_address(&self) -> Result<InteropAddress, String> {
		InteropAddress::from_hex(&self.asset).map_err(|e| e.to_string())
	}

	/// Convert optional string amount to U256 for internal use
	pub fn amount_as_u256(&self) -> Result<Option<U256>, String> {
		match &self.amount {
			Some(amt_str) => Ok(Some(
				U256::from_str_radix(amt_str, 10).map_err(|e| e.to_string())?,
			)),
			None => Ok(None),
		}
	}

	/// Infer order type from lock, defaulting to escrow if no lock specified
	pub fn infer_order_type(&self, version: &str) -> String {
		match &self.lock {
			Some(lock) => lock.infer_order_type(version),
			None => oif_versions::escrow_order_type(version), // Default to escrow
		}
	}

	/// Infer order type using current version
	pub fn infer_current_order_type(&self) -> String {
		self.infer_order_type(oif_versions::CURRENT)
	}
}

impl QuoteOutput {
	pub fn receiver_as_interop_address(&self) -> Result<InteropAddress, String> {
		InteropAddress::from_hex(&self.receiver).map_err(|e| e.to_string())
	}

	pub fn asset_as_interop_address(&self) -> Result<InteropAddress, String> {
		InteropAddress::from_hex(&self.asset).map_err(|e| e.to_string())
	}

	pub fn amount_as_u256(&self) -> Result<Option<U256>, String> {
		match &self.amount {
			Some(amt_str) => Ok(Some(
				U256::from_str_radix(amt_str, 10).map_err(|e| e.to_string())?,
			)),
			None => Ok(None),
		}
	}
}

impl OrderInput {
	/// Convert string address to InteropAddress for internal use
	pub fn user_as_interop_address(&self) -> Result<InteropAddress, String> {
		InteropAddress::from_hex(&self.user).map_err(|e| e.to_string())
	}

	pub fn asset_as_interop_address(&self) -> Result<InteropAddress, String> {
		InteropAddress::from_hex(&self.asset).map_err(|e| e.to_string())
	}

	/// Convert required string amount to U256 for internal use
	pub fn amount_as_u256(&self) -> Result<U256, String> {
		U256::from_str_radix(&self.amount, 10).map_err(|e| e.to_string())
	}
}

impl OrderOutput {
	pub fn receiver_as_interop_address(&self) -> Result<InteropAddress, String> {
		InteropAddress::from_hex(&self.receiver).map_err(|e| e.to_string())
	}

	pub fn asset_as_interop_address(&self) -> Result<InteropAddress, String> {
		InteropAddress::from_hex(&self.asset).map_err(|e| e.to_string())
	}

	/// Convert required string amount to U256 for internal use
	pub fn amount_as_u256(&self) -> Result<U256, String> {
		U256::from_str_radix(&self.amount, 10).map_err(|e| e.to_string())
	}
}

/// Intent request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntentRequest {
	#[serde(rename = "intentType")]
	pub intent_type: IntentType,
	pub inputs: Vec<QuoteInput>,
	pub outputs: Vec<QuoteOutput>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub swap_type: Option<SwapType>,
	#[serde(rename = "minValidUntil", skip_serializing_if = "Option::is_none")]
	pub min_valid_until: Option<u64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub preference: Option<QuotePreference>,
	#[serde(rename = "originSubmission", skip_serializing_if = "Option::is_none")]
	pub origin_submission: Option<OriginSubmission>,
	#[serde(rename = "failureHandling", skip_serializing_if = "Option::is_none")]
	pub failure_handling: Option<Vec<FailureHandlingMode>>,
	#[serde(rename = "partialFill", skip_serializing_if = "Option::is_none")]
	pub partial_fill: Option<bool>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub metadata: Option<serde_json::Value>,
}

/// Request for getting price quotes - new OIF spec structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetQuoteRequest {
	/// User address in EIP-7930 Address format
	pub user: String,
	/// Intent request structure
	pub intent: IntentRequest,
	/// Supported order types
	#[serde(rename = "supportedTypes")]
	pub supported_types: Vec<String>,
}

/// Legacy V1 structure for backward compatibility during migration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetQuoteRequestV1 {
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
	pub cost: Option<CostEstimate>,
	// Using LockType
	pub lock_type: String,
}

/// Implementation to convert Quote with signature and standard to PostOrderRequest
#[cfg(feature = "oif-interfaces")]
impl TryFrom<(&Quote, &str, &str)> for PostOrderRequest {
	type Error = Box<dyn std::error::Error>;

	fn try_from((quote, signature, standard): (&Quote, &str, &str)) -> Result<Self, Self::Error> {
		match standard {
			"eip7683" => Self::from_eip7683_quote(quote, signature),
			_ => Err(format!("Unsupported standard: {}", standard).into()),
		}
	}
}

#[cfg(feature = "oif-interfaces")]
impl PostOrderRequest {
	/// Main conversion function from EIP-7683 quote to PostOrderRequest
	fn from_eip7683_quote(
		quote: &Quote,
		signature: &str,
	) -> Result<Self, Box<dyn std::error::Error>> {
		use crate::standards::eip7683::interfaces::StandardOrder;
		use alloy_primitives::Bytes;
		use alloy_sol_types::SolType;

		// Use the unified TryFrom implementation that handles all order types automatically
		let sol_order = StandardOrder::try_from(quote)?;

		// Extract the user address from the order
		let user_address = sol_order.user;

		// Encode the order
		let encoded_order = StandardOrder::abi_encode(&sol_order);

		// Parse lock_type
		let lock_type = quote
			.lock_type
			.parse::<LockType>()
			.unwrap_or_else(|_| LockType::default());

		// Create final PostOrderRequest
		tracing::debug!("Creating PostOrderRequest with lock_type: {:?}", lock_type);
		let signature_bytes = Bytes::from(hex::decode(signature.trim_start_matches("0x"))?);
		Ok(PostOrderRequest {
			order: Bytes::from(encoded_order),
			sponsor: user_address,
			signature: signature_bytes,
			lock_type,
		})
	}
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
		error_type: ApiErrorType,
		message: String,
		details: Option<serde_json::Value>,
	},
	/// Unprocessable entity for business logic failures (422)
	UnprocessableEntity {
		error_type: ApiErrorType,
		message: String,
		details: Option<serde_json::Value>,
	},
	/// Service unavailable with optional retry information (503)
	ServiceUnavailable {
		error_type: ApiErrorType,
		message: String,
		retry_after: Option<u64>,
	},
	/// Internal server error (500)
	InternalServerError {
		error_type: ApiErrorType,
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
			APIError::BadRequest {
				error_type,
				message,
				details,
			} => ErrorResponse {
				error: error_type.to_string(),
				message: message.clone(),
				details: details.clone(),
				retry_after: None,
			},
			APIError::UnprocessableEntity {
				error_type,
				message,
				details,
			} => ErrorResponse {
				error: error_type.to_string(),
				message: message.clone(),
				details: details.clone(),
				retry_after: None,
			},
			APIError::ServiceUnavailable {
				error_type,
				message,
				retry_after,
			} => ErrorResponse {
				error: error_type.to_string(),
				message: message.clone(),
				details: None,
				retry_after: *retry_after,
			},
			APIError::InternalServerError {
				error_type,
				message,
			} => ErrorResponse {
				error: error_type.to_string(),
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
	#[error("Unsupported intent type: {0}")]
	UnsupportedIntentType(String),
	#[error("No matching order type found: {0}")]
	NoMatchingOrderType(String),
	#[error("No matching auth scheme found")]
	NoMatchingAuthScheme,
	#[error("Missing input amount for exact-input swap")]
	MissingInputAmount,
	#[error("Missing output amount for exact-output swap")]
	MissingOutputAmount,
	#[error("Invalid EIP-7930 address format: {0}")]
	InvalidEip7930Address(String),
	#[error("Swap type validation failed: {0}")]
	SwapTypeValidation(String),
}

impl From<QuoteError> for APIError {
	fn from(quote_error: QuoteError) -> Self {
		match quote_error {
			QuoteError::InvalidRequest(msg) => APIError::BadRequest {
				error_type: ApiErrorType::InvalidRequest,
				message: msg,
				details: None,
			},
			QuoteError::UnsupportedAsset(asset) => APIError::UnprocessableEntity {
				error_type: ApiErrorType::UnsupportedAsset,
				message: format!("Asset not supported by solver: {}", asset),
				details: Some(serde_json::json!({ "asset": asset })),
			},
			QuoteError::UnsupportedSettlement(msg) => APIError::UnprocessableEntity {
				error_type: ApiErrorType::UnsupportedSettlement,
				message: msg,
				details: None,
			},
			QuoteError::InsufficientLiquidity => APIError::UnprocessableEntity {
				error_type: ApiErrorType::InsufficientLiquidity,
				message: "Insufficient liquidity available for the requested amount".to_string(),
				details: None,
			},
			QuoteError::SolverCapacityExceeded => APIError::ServiceUnavailable {
				error_type: ApiErrorType::SolverCapacityExceeded,
				message: "Solver capacity exceeded, please try again later".to_string(),
				retry_after: Some(60), // Suggest retry after 60 seconds
			},
			QuoteError::Internal(msg) => APIError::InternalServerError {
				error_type: ApiErrorType::InternalError,
				message: format!("An internal error occurred: {}", msg),
			},
			QuoteError::UnsupportedIntentType(msg) => APIError::BadRequest {
				error_type: ApiErrorType::InvalidRequest,
				message: format!("Unsupported intent type: {}", msg),
				details: None,
			},
			QuoteError::NoMatchingOrderType(msg) => APIError::UnprocessableEntity {
				error_type: ApiErrorType::UnsupportedSettlement,
				message: msg,
				details: None,
			},
			QuoteError::NoMatchingAuthScheme => APIError::UnprocessableEntity {
				error_type: ApiErrorType::UnsupportedSettlement,
				message: "No matching authentication scheme found".to_string(),
				details: None,
			},
			QuoteError::MissingInputAmount => APIError::BadRequest {
				error_type: ApiErrorType::InvalidRequest,
				message: "Input amount is required for exact-input swap type".to_string(),
				details: None,
			},
			QuoteError::MissingOutputAmount => APIError::BadRequest {
				error_type: ApiErrorType::InvalidRequest,
				message: "Output amount is required for exact-output swap type".to_string(),
				details: None,
			},
			QuoteError::InvalidEip7930Address(msg) => APIError::BadRequest {
				error_type: ApiErrorType::InvalidRequest,
				message: format!("Invalid address format: {}", msg),
				details: None,
			},
			QuoteError::SwapTypeValidation(msg) => APIError::BadRequest {
				error_type: ApiErrorType::InvalidRequest,
				message: msg,
				details: None,
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
				error_type: ApiErrorType::OrderNotFound,
				message: format!("Order not found: {}", id),
				details: Some(serde_json::json!({ "order_id": id })),
			},
			GetOrderError::InvalidId(id) => APIError::BadRequest {
				error_type: ApiErrorType::InvalidOrderId,
				message: format!("Invalid order ID format: {}", id),
				details: Some(serde_json::json!({ "provided_id": id })),
			},
			GetOrderError::Internal(msg) => APIError::InternalServerError {
				error_type: ApiErrorType::InternalError,
				message: format!("An internal error occurred: {}", msg),
			},
		}
	}
}

/// Trait for converting quotes to orders for gas estimation.
/// Each order standard should implement this trait to provide
/// accurate gas estimation based on its specific data structures.
pub trait QuoteParsable {
	/// Convert a Quote to an Order suitable for gas estimation.
	/// The returned Order should have the proper standard-specific
	/// data structure to enable accurate transaction generation.
	fn quote_to_order_for_estimation(quote: &Quote) -> crate::Order;
}

impl Quote {
	/// Convert the quote to an order for gas estimation based on the standard.
	/// This method dispatches to the appropriate standard-specific implementation.
	pub fn to_order_for_estimation(
		&self,
		standard: &str,
	) -> Result<crate::Order, Box<dyn std::error::Error>> {
		match standard {
			#[cfg(feature = "oif-interfaces")]
			"eip7683" => {
				// Use the EIP-7683 implementation of QuoteParsable
				Ok(crate::Eip7683OrderData::quote_to_order_for_estimation(self))
			},
			_ => Err(format!(
				"Unsupported order standard for quote conversion: {}",
				standard
			)
			.into()),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::standards::eip7930::InteropAddress;
	use crate::utils::tests::builders::AssetAmountBuilder;
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
		let input = AvailableInput {
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
		};

		let output = RequestedOutput {
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
		};

		let request = GetQuoteRequestV1 {
			user: InteropAddress::new_ethereum(
				1,
				address!("1111111111111111111111111111111111111111"),
			),
			available_inputs: vec![input],
			requested_outputs: vec![output],
			min_valid_until: Some(1234567890),
			preference: Some(QuotePreference::Price),
		};

		let json = serde_json::to_string(&request).unwrap();
		assert!(json.contains("\"availableInputs\""));
		assert!(json.contains("\"requestedOutputs\""));
		assert!(json.contains("\"minValidUntil\""));

		let deserialized: GetQuoteRequestV1 = serde_json::from_str(&json).unwrap();
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
			error_type: ApiErrorType::ValidationError,
			message: "Test message".to_string(),
			details: None,
		};
		assert_eq!(bad_request.status_code(), 400);

		let unprocessable = APIError::UnprocessableEntity {
			error_type: ApiErrorType::ProcessingError,
			message: "Test message".to_string(),
			details: None,
		};
		assert_eq!(unprocessable.status_code(), 422);

		let unavailable = APIError::ServiceUnavailable {
			error_type: ApiErrorType::ServiceError,
			message: "Test message".to_string(),
			retry_after: Some(30),
		};
		assert_eq!(unavailable.status_code(), 503);

		let internal_error = APIError::InternalServerError {
			error_type: ApiErrorType::InternalError,
			message: "Test message".to_string(),
		};
		assert_eq!(internal_error.status_code(), 500);
	}

	#[test]
	fn test_api_error_to_error_response() {
		let api_error = APIError::BadRequest {
			error_type: ApiErrorType::ValidationError,
			message: "Invalid input".to_string(),
			details: Some(serde_json::json!({"field": "amount"})),
		};

		let error_response = api_error.to_error_response();
		assert_eq!(error_response.error, "VALIDATION_ERROR");
		assert_eq!(error_response.message, "Invalid input");
		assert!(error_response.details.is_some());
		assert_eq!(error_response.retry_after, None);

		let service_unavailable = APIError::ServiceUnavailable {
			error_type: ApiErrorType::ServiceError,
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
					error_type: ApiErrorType::ValidationError,
					message: "Bad request message".to_string(),
					details: None,
				},
				"Bad Request: Bad request message",
			),
			(
				APIError::UnprocessableEntity {
					error_type: ApiErrorType::ProcessingError,
					message: "Unprocessable message".to_string(),
					details: None,
				},
				"Unprocessable Entity: Unprocessable message",
			),
			(
				APIError::ServiceUnavailable {
					error_type: ApiErrorType::ServiceError,
					message: "Service unavailable message".to_string(),
					retry_after: None,
				},
				"Service Unavailable: Service unavailable message",
			),
			(
				APIError::InternalServerError {
					error_type: ApiErrorType::InternalError,
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
			error_type: ApiErrorType::ValidationError,
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
		let request = GetQuoteRequestV1 {
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
		let deserialized: GetQuoteRequestV1 = serde_json::from_str(&json).unwrap();
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
