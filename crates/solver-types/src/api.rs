//! API types for the OIF Solver HTTP API.
//!
//! This module defines the request and response types for the OIF Solver API
//! endpoints, following the ERC-7683 Cross-Chain Intents Standard.
use crate::account::Address;
use crate::standards::{eip7683::LockType, eip7930::InteropAddress};
use crate::utils::conversion::parse_bytes32_from_hex;
use crate::without_0x_prefix;
use alloy_primitives::{Bytes, U256};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum AuthScheme {
	Erc4337,
	Permit2,
	Erc20Permit,
	Eip3009,
}

/// Failure handling policy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
	pub signature_type: SignatureType,
	pub domain: serde_json::Value,
	#[serde(rename = "primaryType")]
	pub primary_type: String,
	pub message: serde_json::Value,
	/// EIP-712 types definitions
	#[serde(skip_serializing_if = "Option::is_none")]
	pub types: Option<serde_json::Value>,
}

impl From<&Quote> for Option<OrderPayload> {
	fn from(quote: &Quote) -> Self {
		match &quote.order {
			OifOrder::OifEscrowV0 { payload } => Some(payload.clone()),
			OifOrder::OifResourceLockV0 { payload } => Some(payload.clone()),
			OifOrder::Oif3009V0 { payload, .. } => Some(payload.clone()),
			OifOrder::OifGenericV0 { .. } => None, // Generic orders don't have OrderPayload
		}
	}
}

impl OifOrder {
	pub fn origin_chain_id(&self) -> u64 {
		let payload = match self {
			OifOrder::OifEscrowV0 { payload } => payload,
			OifOrder::OifResourceLockV0 { payload } => payload,
			OifOrder::Oif3009V0 { payload, .. } => payload,
			_ => return 0, // Generic orders not supported
		};
		payload
			.domain
			.as_object()
			.and_then(|domain| domain.get("chainId"))
			.and_then(|chain_id| {
				// Try to parse as string first, then as u64
				chain_id
					.as_str()
					.and_then(|s| s.parse::<u64>().ok())
					.or_else(|| chain_id.as_u64())
			})
			.unwrap_or(0)
	}

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

	/// Get the flow key for gas configuration and cost estimation
	/// Returns the appropriate flow key based on the order type
	pub fn flow_key(&self) -> Option<String> {
		match self {
			OifOrder::OifEscrowV0 { .. } => Some("permit2_escrow".to_string()),
			OifOrder::OifResourceLockV0 { .. } => Some("resource_lock".to_string()),
			OifOrder::Oif3009V0 { .. } => Some("eip3009_escrow".to_string()),
			OifOrder::OifGenericV0 { .. } => None, // Generic orders don't have a specific flow
		}
	}

	/// Check if this order type requires signature recovery to determine sponsor
	pub fn requires_ecrecover(&self) -> bool {
		matches!(self, OifOrder::OifEscrowV0 { .. })
	}

	/// Extract sponsor from the order, potentially using ecrecover for Permit2/EIP-3009 orders
	///
	/// # Arguments
	///
	/// * `signature` - Optional signature bytes to use for ecrecover (required for Permit2/EIP-3009)
	///
	/// # Returns
	///
	/// Returns the sponsor address or an error if extraction fails
	pub fn extract_sponsor(&self, signature: Option<&Bytes>) -> Result<Address, String> {
		// First check if we can extract directly from ResourceLock orders
		match self {
			OifOrder::OifResourceLockV0 { payload } => {
				// TheCompact has 'sponsor' field directly in message
				if let Some(message_obj) = payload.message.as_object() {
					if let Some(sponsor_value) = message_obj.get("sponsor") {
						if let Some(sponsor_str) = sponsor_value.as_str() {
							return hex::decode(without_0x_prefix(sponsor_str))
								.ok()
								.map(Address)
								.ok_or_else(|| "Failed to decode sponsor address".to_string());
						}
					}
				}
				Err("Sponsor field not found in ResourceLock order".to_string())
			},
			OifOrder::OifEscrowV0 { payload: _ } | OifOrder::Oif3009V0 { payload: _, .. } => {
				// These require signature recovery
				let sig = signature.ok_or("Signature required for sponsor extraction")?;
				if sig.is_empty() {
					return Err("Empty signature provided".to_string());
				}

				let signature_str = hex::encode(sig);

				// Reconstruct digest based on order type
				let digest = match self {
					OifOrder::OifEscrowV0 { payload } => {
						crate::utils::eip712::reconstruct_permit2_digest(payload)
							.map_err(|e| format!("Failed to reconstruct Permit2 digest: {}", e))?
					},
					OifOrder::Oif3009V0 { payload, metadata } => {
						// Extract domain_separator from metadata if available
						let domain_separator = metadata
							.get("domain_separator")
							.and_then(|v| v.as_str())
							.and_then(|s| parse_bytes32_from_hex(s).ok());

						crate::utils::eip712::reconstruct_eip3009_digest(payload, domain_separator)
							.map_err(|e| format!("Failed to reconstruct EIP-3009 digest: {}", e))?
					},
					_ => unreachable!(),
				};

				// Recover user address from signature
				let recovered =
					crate::utils::eip712::ecrecover_user_from_signature(&digest, &signature_str)
						.map_err(|e| format!("Failed to recover user from signature: {}", e))?;

				// Convert AlloyAddress to our Address type (AlloyAddress implements AsRef<[u8]>)
				Ok(recovered.into())
			},
			OifOrder::OifGenericV0 { .. } => {
				Err("Cannot extract sponsor from generic order".to_string())
			},
		}
	}

	/// Derive the lock type from the order variant
	pub fn get_lock_type(&self) -> LockType {
		match self {
			OifOrder::OifEscrowV0 { .. } => LockType::Permit2Escrow,
			OifOrder::Oif3009V0 { .. } => LockType::Eip3009Escrow,
			OifOrder::OifResourceLockV0 { .. } => LockType::ResourceLock,
			OifOrder::OifGenericV0 { .. } => LockType::Permit2Escrow, // Default to Permit2
		}
	}
}

/// Implement From trait to convert OifOrder to LockType
impl From<&OifOrder> for LockType {
	fn from(order: &OifOrder) -> Self {
		order.get_lock_type()
	}
}

/// Implement From trait to derive OriginSubmission from OifOrder
impl From<&OifOrder> for Option<OriginSubmission> {
	fn from(order: &OifOrder) -> Self {
		match order {
			OifOrder::OifEscrowV0 { .. } => {
				// Permit2 escrow orders
				Some(OriginSubmission {
					mode: OriginMode::User,
					schemes: Some(vec![AuthScheme::Permit2, AuthScheme::Erc20Permit]),
				})
			},
			OifOrder::Oif3009V0 { .. } => {
				// EIP-3009 orders
				Some(OriginSubmission {
					mode: OriginMode::User,
					schemes: Some(vec![AuthScheme::Eip3009]),
				})
			},
			OifOrder::OifResourceLockV0 { .. } => {
				// Resource lock orders don't use origin submission auth
				None
			},
			OifOrder::OifGenericV0 { .. } => {
				// Generic orders default to no specific auth scheme
				None
			},
		}
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

	/// Convert to EIP-7683 LockType for protocol-level usage
	pub fn to_lock_type(&self) -> LockType {
		match self.kind {
			LockKind::TheCompact | LockKind::Rhinestone => LockType::ResourceLock,
		}
	}

	/// Check if this is a resource lock (vs escrow)
	pub fn is_resource_lock(&self) -> bool {
		matches!(self.kind, LockKind::TheCompact | LockKind::Rhinestone)
	}
}

/// Post order request following the OIF specification.
/// Supports both quote acceptances (with quote_id) and direct order submissions.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PostOrderRequest {
	/// The structured order to submit
	pub order: OifOrder,
	/// Signature for the order
	pub signature: Bytes,
	/// Optional reference to a prior quote
	#[serde(rename = "quoteId", skip_serializing_if = "Option::is_none")]
	pub quote_id: Option<String>,
	/// Optional origin submission preferences
	#[serde(rename = "originSubmission", skip_serializing_if = "Option::is_none")]
	pub origin_submission: Option<OriginSubmission>,
}

/// Status for post order response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PostOrderResponseStatus {
	Received,
	Rejected,
	Error,
}

/// Response for post order requests following OIF specification
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostOrderResponse {
	/// Optional order identifier
	#[serde(rename = "orderId", skip_serializing_if = "Option::is_none")]
	pub order_id: Option<String>,
	/// Status of the order submission
	pub status: PostOrderResponseStatus,
	/// Optional message providing additional context
	#[serde(skip_serializing_if = "Option::is_none")]
	pub message: Option<String>,
	/// Optional echo of the submitted order for confirmation
	#[serde(skip_serializing_if = "Option::is_none")]
	pub order: Option<serde_json::Value>,
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

/// Supported lock mechanisms
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LockKind {
	#[serde(alias = "TheCompact", alias = "the_compact")]
	TheCompact,
	Rhinestone,
}

// TODO: Remove these aliases entirely and update all code to use OrderInput/OrderOutput directly
// These are temporary aliases for migration purposes
pub type AvailableInput = OrderInput;
pub type RequestedOutput = OrderOutput;

/// Quote input from a user (amounts optional for quote requests)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteInput {
	/// User address in EIP-7930 Address format
	pub user: InteropAddress,
	/// Asset address in EIP-7930 Address format
	pub asset: InteropAddress,
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
	pub receiver: InteropAddress,
	/// Asset address in EIP-7930 Address format
	pub asset: InteropAddress,
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
	pub user: InteropAddress,
	/// Asset address in EIP-7930 Address format
	pub asset: InteropAddress,
	/// Required Amount as U256
	#[serde(with = "u256_serde")]
	pub amount: U256,
	/// Lock information if asset is already locked
	#[serde(skip_serializing_if = "Option::is_none")]
	pub lock: Option<AssetLockReference>,
}

/// Order output for actual intent/order submission (amounts always required)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderOutput {
	/// Receiver address in EIP-7930 Address format
	pub receiver: InteropAddress,
	/// Asset address in EIP-7930 Address format
	pub asset: InteropAddress,
	/// Required Amount as U256
	#[serde(with = "u256_serde")]
	pub amount: U256,
	/// Optional calldata for the output
	#[serde(skip_serializing_if = "Option::is_none")]
	pub calldata: Option<String>,
}

impl QuoteInput {
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

	/// Infer order type considering both lock and origin submission schemes
	pub fn infer_order_type_with_origin(
		&self,
		version: &str,
		origin_submission: Option<&OriginSubmission>,
	) -> String {
		// If there's a lock, use resource lock order type
		if let Some(lock) = &self.lock {
			return lock.infer_order_type(version);
		}

		// No lock - determine order type based on origin submission schemes
		if let Some(origin) = origin_submission {
			if let Some(schemes) = &origin.schemes {
				// Check for EIP-3009 scheme
				if schemes.contains(&AuthScheme::Eip3009) {
					return oif_versions::eip3009_order_type(version);
				}
				// For Permit2 and other schemes, use escrow
				if schemes.contains(&AuthScheme::Permit2)
					|| schemes.contains(&AuthScheme::Erc20Permit)
				{
					return oif_versions::escrow_order_type(version);
				}
			}
		}

		// Default to escrow if no specific scheme is specified
		oif_versions::escrow_order_type(version)
	}

	/// Infer order type using current version
	pub fn infer_current_order_type(&self) -> String {
		self.infer_order_type(oif_versions::CURRENT)
	}
}

impl QuoteOutput {
	pub fn amount_as_u256(&self) -> Result<Option<U256>, String> {
		match &self.amount {
			Some(amt_str) => Ok(Some(
				U256::from_str_radix(amt_str, 10).map_err(|e| e.to_string())?,
			)),
			None => Ok(None),
		}
	}
}

/// Conversion from OrderInput to QuoteInput
impl From<OrderInput> for QuoteInput {
	fn from(order_input: OrderInput) -> Self {
		QuoteInput {
			user: order_input.user,
			asset: order_input.asset,
			amount: Some(order_input.amount.to_string()), // OrderInput has required amount, QuoteInput has optional
			lock: order_input.lock,
		}
	}
}

/// Conversion from OrderOutput to QuoteOutput
impl From<OrderOutput> for QuoteOutput {
	fn from(order_output: OrderOutput) -> Self {
		QuoteOutput {
			receiver: order_output.receiver,
			asset: order_output.asset,
			amount: Some(order_output.amount.to_string()), // OrderOutput has required amount, QuoteOutput has optional
			calldata: order_output.calldata,
		}
	}
}

impl TryFrom<&QuoteInput> for OrderInput {
	type Error = QuoteError;

	fn try_from(quote_input: &QuoteInput) -> Result<Self, Self::Error> {
		let amount_u256 = if let Some(amount) = quote_input.amount.as_ref() {
			U256::from_str(amount).map_err(|e| {
				QuoteError::InvalidRequest(format!("Failed to parse amount '{}': {}", amount, e))
			})?
		} else {
			U256::ZERO
		};

		Ok(OrderInput {
			user: quote_input.user.clone(),
			asset: quote_input.asset.clone(),
			amount: amount_u256,
			lock: quote_input.lock.clone(),
		})
	}
}

impl TryFrom<&QuoteOutput> for OrderOutput {
	type Error = QuoteError;

	fn try_from(quote_output: &QuoteOutput) -> Result<Self, Self::Error> {
		let amount_u256 = if let Some(amount) = quote_output.amount.as_ref() {
			U256::from_str(amount).map_err(|e| {
				QuoteError::InvalidRequest(format!("Failed to parse amount '{}': {}", amount, e))
			})?
		} else {
			U256::ZERO
		};

		Ok(OrderOutput {
			receiver: quote_output.receiver.clone(),
			asset: quote_output.asset.clone(),
			amount: amount_u256,
			calldata: quote_output.calldata.clone(),
		})
	}
}

/// Conversion from &OrderInput to QuoteInput
impl From<&OrderInput> for QuoteInput {
	fn from(order_input: &OrderInput) -> Self {
		QuoteInput {
			user: order_input.user.clone(),
			asset: order_input.asset.clone(),
			amount: Some(order_input.amount.to_string()),
			lock: order_input.lock.clone(),
		}
	}
}

/// Conversion from &OrderOutput to QuoteOutput
impl From<&OrderOutput> for QuoteOutput {
	fn from(order_output: &OrderOutput) -> Self {
		QuoteOutput {
			receiver: order_output.receiver.clone(),
			asset: order_output.asset.clone(),
			amount: Some(order_output.amount.to_string()),
			calldata: order_output.calldata.clone(),
		}
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
	#[serde(rename = "swapType", skip_serializing_if = "Option::is_none")]
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

/// Rich validation context
#[derive(Debug, Clone)]
pub struct ValidatedQuoteContext {
	pub swap_type: SwapType,
	pub known_inputs: Option<Vec<(QuoteInput, U256)>>,
	pub known_outputs: Option<Vec<(QuoteOutput, U256)>>,
	pub constraint_inputs: Option<Vec<(QuoteInput, Option<U256>)>>,
	pub constraint_outputs: Option<Vec<(QuoteOutput, Option<U256>)>>,
}

/// Request for getting price quotes - new OIF spec structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetQuoteRequest {
	/// User address in EIP-7930 Address format
	pub user: InteropAddress,
	/// Intent request structure
	pub intent: IntentRequest,
	/// Supported order types
	#[serde(rename = "supportedTypes")]
	pub supported_types: Vec<String>,
}

impl GetQuoteRequest {
	/// Determines the appropriate flow key for gas configuration based on the request structure.
	/// Analyzes inputs for lock types and origin submission for auth schemes to construct the flow key.
	pub fn flow_key(&self) -> Option<String> {
		// Check if any input has a lock - if so, use resource lock flow
		for input in &self.intent.inputs {
			if let Some(lock) = &input.lock {
				match lock.kind {
					LockKind::TheCompact => return Some("resource_lock".to_string()),
					LockKind::Rhinestone => return Some("resource_lock".to_string()),
				}
			}
		}

		// No locks found, default to escrow - determine auth scheme from origin submission
		if let Some(origin_submission) = &self.intent.origin_submission {
			if let Some(schemes) = &origin_submission.schemes {
				if let Some(scheme) = schemes.iter().next() {
					match scheme {
						AuthScheme::Eip3009 => return Some("eip3009_escrow".to_string()),
						AuthScheme::Permit2 => return Some("permit2_escrow".to_string()),
						AuthScheme::Erc20Permit => return Some("permit2_escrow".to_string()),
						AuthScheme::Erc4337 => return Some("permit2_escrow".to_string()), // Default to permit2
					}
				}
			}
		}

		// Default fallback to permit2_escrow if no specific scheme is found
		Some("permit2_escrow".to_string())
	}
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
	/// Signature type (eip-712 or eip-3009)
	#[serde(rename = "signatureType")]
	pub signature_type: SignatureType,
	/// ERC-7930 interoperable address of the domain (or domain object for structured domains)
	pub domain: serde_json::Value,
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

/// A quote option following the new OIF standard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quote {
	/// Single versioned Order union type
	pub order: OifOrder,
	/// Failure handling policy
	#[serde(rename = "failureHandling")]
	pub failure_handling: FailureHandlingMode,
	/// Whether partial fills are allowed
	#[serde(rename = "partialFill")]
	pub partial_fill: bool,
	/// Quote validity timestamp
	#[serde(rename = "validUntil")]
	pub valid_until: u64,
	/// Estimated time to completion in seconds
	#[serde(skip_serializing_if = "Option::is_none")]
	pub eta: Option<u64>,
	/// Unique quote identifier
	#[serde(rename = "quoteId")]
	pub quote_id: String,
	/// Provider identifier
	#[serde(skip_serializing_if = "Option::is_none")]
	pub provider: Option<String>,
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
		use alloy_primitives::hex;

		// Parse the signature into Bytes
		let signature_bytes = Bytes::from(hex::decode(signature.trim_start_matches("0x"))?);

		// Derive origin_submission from the order type using From trait
		let origin_submission = Option::<OriginSubmission>::from(&quote.order);

		Ok(PostOrderRequest {
			order: quote.order.clone(),
			signature: signature_bytes,
			quote_id: Some(quote.quote_id.clone()),
			origin_submission,
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

/// Internal structure combining a Quote with its associated CostContext
/// Used for storage to enable single I/O operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteWithCostContext {
	/// The quote data
	pub quote: Quote,
	/// The associated cost context from quote generation
	pub cost_context: crate::costs::CostContext,
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
				address!("1111111111111111111111111111111111111111"),
			),
			asset: InteropAddress::new_ethereum(
				1,
				address!("2222222222222222222222222222222222222222"),
			),
			amount: U256::from(5000),
			lock: Some(AssetLockReference {
				kind: LockKind::TheCompact,
				params: None,
			}),
		};

		let json = serde_json::to_string(&input).unwrap();
		let deserialized: AvailableInput = serde_json::from_str(&json).unwrap();

		assert_eq!(deserialized.amount, 5000);
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

		assert_eq!(deserialized.amount, 2000);
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
		let sig_types = [SignatureType::Eip712];
		let expected_values = ["\"eip712\""];

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
			domain: serde_json::to_value(InteropAddress::new_ethereum(
				1,
				address!("5555555555555555555555555555555555555555"),
			))
			.unwrap(),
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
			order: OifOrder::OifEscrowV0 {
				payload: OrderPayload {
					signature_type: SignatureType::Eip712,
					domain: serde_json::to_value(InteropAddress::new_ethereum(
						1,
						address!("5555555555555555555555555555555555555555"),
					))
					.unwrap(),
					primary_type: "TestType".to_string(),
					message: serde_json::json!({"test": "value"}),
					types: None,
				},
			},
			failure_handling: FailureHandlingMode::RefundAutomatic,
			partial_fill: false,
			valid_until: 1234567890,
			eta: Some(300),
			quote_id: "quote_123".to_string(),
			provider: Some("test_solver".to_string()),
		};

		let json = serde_json::to_string(&quote).unwrap();
		assert!(json.contains("\"validUntil\""));
		assert!(json.contains("\"quoteId\""));
		assert!(json.contains("\"provider\""));

		let deserialized: Quote = serde_json::from_str(&json).unwrap();
		assert_eq!(deserialized.quote_id, "quote_123");
		assert_eq!(deserialized.valid_until, 1234567890);
		assert_eq!(deserialized.eta, Some(300));
	}

	#[test]
	fn test_get_quote_response_serialization() {
		let response = GetQuoteResponse {
			quotes: vec![Quote {
				order: OifOrder::OifEscrowV0 {
					payload: OrderPayload {
						signature_type: SignatureType::Eip712,
						domain: serde_json::json!({"chain": 1, "address": "0x0000000000000000000000000000000000000000"}),
						primary_type: "TestType".to_string(),
						message: serde_json::json!({"test": "value"}),
						types: None,
					},
				},
				failure_handling: FailureHandlingMode::RefundAutomatic,
				partial_fill: false,
				valid_until: 1234567890,
				eta: None,
				quote_id: "test_quote".to_string(),
				provider: Some("test_provider".to_string()),
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
