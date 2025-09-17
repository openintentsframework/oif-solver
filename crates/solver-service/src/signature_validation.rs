//! Signature validation service for different order standards.
//!
//! This module provides a pluggable architecture for validating EIP-712 signatures
//! based on different order standards (EIP-7683, etc.).

use crate::eip712::{
	compact, get_domain_separator, MessageHashComputer, SignatureValidator as EipSignatureValidator,
};
use alloy_primitives::Address as AlloyAddress;
use alloy_sol_types::SolType;
use async_trait::async_trait;
use solver_delivery::DeliveryService;
use solver_types::{
	api::IntentRequest,
	standards::eip7683::{interfaces::StandardOrder as OifStandardOrder, LockType},
	APIError, ApiErrorType, NetworksConfig,
};
use std::collections::HashMap;
use std::sync::Arc;

/// Trait for validating signatures for specific order standards.
#[async_trait]
pub trait OrderSignatureValidator: Send + Sync {
	/// Validates an EIP-712 signature for this standard.
	async fn validate_signature(
		&self,
		intent: &IntentRequest,
		networks_config: &NetworksConfig,
		delivery_service: &Arc<DeliveryService>,
	) -> Result<(), APIError>;
}

/// EIP-7683 signature validator using TheCompact protocol.
pub struct Eip7683SignatureValidator;

#[async_trait]
impl OrderSignatureValidator for Eip7683SignatureValidator {
	async fn validate_signature(
		&self,
		intent: &IntentRequest,
		networks_config: &NetworksConfig,
		delivery_service: &Arc<DeliveryService>,
	) -> Result<(), APIError> {
		// Parse order to get chain info
		let standard_order = OifStandardOrder::abi_decode(&intent.order, true).map_err(|e| {
			APIError::BadRequest {
				error_type: ApiErrorType::OrderValidationFailed,
				message: format!("Failed to decode order: {}", e),
				details: None,
			}
		})?;

		let origin_chain_id = standard_order.originChainId.to::<u64>();
		let network =
			networks_config
				.get(&origin_chain_id)
				.ok_or_else(|| APIError::BadRequest {
					error_type: ApiErrorType::OrderValidationFailed,
					message: format!("Network {} not configured", origin_chain_id),
					details: None,
				})?;

		// Get TheCompact contract address for domain separator
		let the_compact_address =
			network
				.the_compact_address
				.as_ref()
				.ok_or_else(|| APIError::BadRequest {
					error_type: ApiErrorType::OrderValidationFailed,
					message: "TheCompact contract not configured".to_string(),
					details: None,
				})?;

		// Get contract address for signature validation
		let contract_address = {
			let addr = network
				.input_settler_compact_address
				.clone()
				.unwrap_or_else(|| network.input_settler_address.clone());
			AlloyAddress::from_slice(&addr.0)
		};

		// Create compact-specific implementations using factory functions
		let message_hasher = compact::create_message_hasher();
		let signature_validator = compact::create_signature_validator();

		// 1. Get domain separator from TheCompact contract
		let domain_separator =
			get_domain_separator(delivery_service, the_compact_address, origin_chain_id).await?;

		// 2. Compute message hash using interface
		let struct_hash = message_hasher.compute_message_hash(&intent.order, contract_address)?;

		// 3. Extract signature using interface
		let signature = signature_validator.extract_signature(&intent.signature);

		// 4. Validate EIP-712 signature using interface
		let expected_signer = standard_order.user;
		let is_valid = signature_validator.validate_signature(
			domain_separator,
			struct_hash,
			&signature,
			expected_signer,
		)?;

		if !is_valid {
			return Err(APIError::BadRequest {
				error_type: ApiErrorType::OrderValidationFailed,
				message: "Invalid EIP-712 signature".to_string(),
				details: None,
			});
		}
		Ok(())
	}
}

/// Service for managing signature validation across different standards.
pub struct SignatureValidationService {
	validators: HashMap<String, Box<dyn OrderSignatureValidator>>,
}

impl SignatureValidationService {
	/// Creates a new SignatureValidationService with default validators.
	pub fn new() -> Self {
		let mut validators: HashMap<String, Box<dyn OrderSignatureValidator>> = HashMap::new();

		// Register EIP-7683 validator
		validators.insert("eip7683".to_string(), Box::new(Eip7683SignatureValidator));

		Self { validators }
	}

	/// Validates a signature using the appropriate validator for the given standard.
	pub async fn validate_signature(
		&self,
		standard: &str,
		intent: &IntentRequest,
		networks_config: &NetworksConfig,
		delivery_service: &Arc<DeliveryService>,
	) -> Result<(), APIError> {
		let validator = self
			.validators
			.get(standard)
			.ok_or_else(|| APIError::BadRequest {
				error_type: ApiErrorType::OrderValidationFailed,
				message: format!("No signature validator for standard: {}", standard),
				details: None,
			})?;

		validator
			.validate_signature(intent, networks_config, delivery_service)
			.await
	}

	/// Checks if signature validation is required for the given lock type.
	pub fn requires_signature_validation(lock_type: &LockType) -> bool {
		matches!(lock_type, LockType::ResourceLock)
	}
}

impl Default for SignatureValidationService {
	fn default() -> Self {
		Self::new()
	}
}
