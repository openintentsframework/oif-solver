//! EIP-712 signature validation and message hash computation
//!
//! This module provides generic EIP-712 interfaces and TheCompact protocol-specific implementations.

use alloy_primitives::{keccak256, Address as AlloyAddress, Bytes, FixedBytes};
use alloy_sol_types::SolCall;
use solver_delivery::DeliveryService;
use solver_types::{APIError, Address, ApiErrorType, Transaction};
use std::sync::Arc;

pub mod compact;

// Generic EIP-712 interfaces

/// Trait for computing EIP-712 message hashes
pub trait MessageHashComputer {
	/// Compute the struct hash for the given order data
	fn compute_message_hash(
		&self,
		order_bytes: &[u8],
		contract_address: AlloyAddress,
	) -> Result<FixedBytes<32>, APIError>;
}

/// Trait for EIP-712 signature validation
pub trait SignatureValidator {
	/// Validate EIP-712 signature against expected signer
	fn validate_signature(
		&self,
		domain_separator: FixedBytes<32>,
		struct_hash: FixedBytes<32>,
		signature: &Bytes,
		expected_signer: AlloyAddress,
	) -> Result<bool, APIError>;

	/// Extract signature from encoded signature data
	fn extract_signature(&self, signature: &Bytes) -> Bytes;
}

// Generic domain separator functionality

/// Get domain separator from TheCompact contract
pub async fn get_domain_separator(
	delivery: &Arc<DeliveryService>,
	contract_address: &Address,
	chain_id: u64,
) -> Result<FixedBytes<32>, APIError> {
	use solver_types::standards::eip7683::interfaces::ITheCompact::DOMAIN_SEPARATORCall;

	let call = DOMAIN_SEPARATORCall {};
	let encoded = call.abi_encode();

	// Create transaction for contract call
	let tx = Transaction {
		to: Some(contract_address.clone()),
		data: encoded,
		value: alloy_primitives::U256::ZERO,
		chain_id,
		nonce: None,
		gas_limit: None,
		gas_price: None,
		max_fee_per_gas: None,
		max_priority_fee_per_gas: None,
	};

	let result = delivery
		.contract_call(chain_id, tx)
		.await
		.map_err(|e| APIError::BadRequest {
			error_type: ApiErrorType::OrderValidationFailed,
			message: format!("Failed to get domain separator: {}", e),
			details: None,
		})?;

	// Decode the result using ITheCompact DOMAIN_SEPARATOR response
	let domain_separator =
		DOMAIN_SEPARATORCall::abi_decode_returns_validate(&result).map_err(|e| {
			APIError::BadRequest {
				error_type: ApiErrorType::OrderValidationFailed,
				message: format!("Failed to decode domain separator: {}", e),
				details: None,
			}
		})?;

	Ok(domain_separator)
}

// Generic EIP-712 signature validation

/// Validate EIP-712 signature against expected signer
pub fn validate_eip712_signature(
	domain_separator: FixedBytes<32>,
	struct_hash: FixedBytes<32>,
	signature: &Bytes,
	expected_signer: AlloyAddress,
) -> Result<bool, APIError> {
	// Compute EIP-712 message hash
	let message_hash = keccak256(
		[
			&[0x19, 0x01][..],
			domain_separator.as_slice(),
			struct_hash.as_slice(),
		]
		.concat(),
	);

	// Recover signer from signature
	let recovered_signer = recover_signer(message_hash, signature)?;

	Ok(recovered_signer == expected_signer)
}

/// Recover signer address from signature and message hash
fn recover_signer(
	message_hash: FixedBytes<32>,
	signature: &Bytes,
) -> Result<AlloyAddress, APIError> {
	if signature.len() != 65 {
		return Err(APIError::BadRequest {
			error_type: ApiErrorType::OrderValidationFailed,
			message: "Invalid signature length".to_string(),
			details: None,
		});
	}

	let recovery_id = signature[64];
	let recovery_id = if recovery_id >= 27 {
		recovery_id - 27
	} else {
		recovery_id
	};

	let signature_bytes = &signature[0..64];

	use secp256k1::{ecdsa::RecoverableSignature, All, Message, Secp256k1};

	let secp = Secp256k1::<All>::new();

	// Create recoverable signature
	let recovery_id = secp256k1::ecdsa::RecoveryId::try_from(recovery_id as i32).unwrap();
	let recoverable_sig = RecoverableSignature::from_compact(signature_bytes, recovery_id)
		.map_err(|_| APIError::BadRequest {
			error_type: ApiErrorType::OrderValidationFailed,
			message: "Invalid signature format".to_string(),
			details: None,
		})?;

	// Create message from hash
	let message = Message::from_digest(*message_hash);

	// Recover public key
	let public_key =
		secp.recover_ecdsa(message, &recoverable_sig)
			.map_err(|_| APIError::BadRequest {
				error_type: ApiErrorType::OrderValidationFailed,
				message: "Failed to recover public key".to_string(),
				details: None,
			})?;

	// Get address from public key
	let public_key_bytes = public_key.serialize_uncompressed();
	let public_key_hash = keccak256(&public_key_bytes[1..]);
	let address_bytes = &public_key_hash.as_slice()[12..];

	Ok(AlloyAddress::from_slice(address_bytes))
}
