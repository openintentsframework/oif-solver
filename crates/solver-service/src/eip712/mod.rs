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
			message: format!("Failed to get domain separator: {e}"),
			details: None,
		})?;

	// Decode the result using ITheCompact DOMAIN_SEPARATOR response
	let domain_separator =
		DOMAIN_SEPARATORCall::abi_decode_returns_validate(&result).map_err(|e| {
			APIError::BadRequest {
				error_type: ApiErrorType::OrderValidationFailed,
				message: format!("Failed to decode domain separator: {e}"),
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

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::{keccak256, Address as AlloyAddress, Bytes};
	use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
	use solver_delivery::{
		DeliveryError, DeliveryInterface, DeliveryService, MockDeliveryInterface,
	};
	use solver_types::standards::eip7683::interfaces::ITheCompact::DOMAIN_SEPARATORCall;
	use solver_types::Address;
	use std::collections::HashMap;
	use std::sync::Arc;

	fn delivery_service_from_mock(mock: MockDeliveryInterface) -> Arc<DeliveryService> {
		let mut implementations: HashMap<u64, Arc<dyn DeliveryInterface>> = HashMap::new();
		implementations.insert(1, Arc::new(mock) as Arc<dyn DeliveryInterface>);
		Arc::new(DeliveryService::new(implementations, 1, 30))
	}

	fn delivery_service_with_success(response: Bytes) -> Arc<DeliveryService> {
		let mut mock = MockDeliveryInterface::new();
		mock.expect_eth_call().returning(move |_tx| {
			let bytes = response.clone();
			Box::pin(async move { Ok(bytes) })
		});
		delivery_service_from_mock(mock)
	}

	fn delivery_service_with_error(message: &'static str) -> Arc<DeliveryService> {
		let mut mock = MockDeliveryInterface::new();
		mock.expect_eth_call().returning(move |_tx| {
			let msg = message.to_string();
			Box::pin(async move { Err(DeliveryError::Network(msg)) })
		});
		delivery_service_from_mock(mock)
	}

	fn contract_address() -> Address {
		Address(vec![0x11; 20])
	}

	#[tokio::test]
	async fn get_domain_separator_returns_value() {
		let expected = FixedBytes::from([0xAAu8; 32]);
		let encoded = DOMAIN_SEPARATORCall::abi_encode_returns(&expected);
		let delivery = delivery_service_with_success(Bytes::from(encoded));

		let result = get_domain_separator(&delivery, &contract_address(), 1)
			.await
			.expect("domain separator");

		assert_eq!(result, expected);
	}

	#[tokio::test]
	async fn get_domain_separator_propagates_contract_call_errors() {
		let delivery = delivery_service_with_error("call failed");

		let error = get_domain_separator(&delivery, &contract_address(), 1)
			.await
			.expect_err("expected error");

		assert!(matches!(
			error,
			APIError::BadRequest { message, .. } if message.contains("Failed to get domain separator")
		));
	}

	#[tokio::test]
	async fn get_domain_separator_errors_on_decode_failure() {
		let delivery = delivery_service_with_success(Bytes::from(vec![0u8; 4]));
		let error = get_domain_separator(&delivery, &contract_address(), 1)
			.await
			.expect_err("expected decode error");
		assert!(matches!(
			error,
			APIError::BadRequest { message, .. } if message.contains("Failed to decode domain separator")
		));
	}

	#[test]
	fn validate_eip712_signature_returns_true_for_matching_signer() {
		let domain_separator = FixedBytes::from([0x11u8; 32]);
		let struct_hash = FixedBytes::from([0x22u8; 32]);
		let message_hash = keccak256(
			[
				&[0x19, 0x01][..],
				domain_separator.as_slice(),
				struct_hash.as_slice(),
			]
			.concat(),
		);

		let secret = SecretKey::from_byte_array([0x12u8; 32]).expect("secret");
		let secp = Secp256k1::new();
		let message = Message::from_digest(*message_hash);
		let signature = secp.sign_ecdsa_recoverable(message, &secret);
		let (recovery_id, sig_bytes) = signature.serialize_compact();
		let mut signature_bytes = sig_bytes.to_vec();
		let rec: i32 = recovery_id.into();
		signature_bytes.push((rec as u8) + 27);
		let signature = Bytes::from(signature_bytes);

		let public_key = PublicKey::from_secret_key(&secp, &secret);
		let public_key_bytes = public_key.serialize_uncompressed();
		let signer_hash = keccak256(&public_key_bytes[1..]);
		let signer = AlloyAddress::from_slice(&signer_hash.as_slice()[12..]);

		let is_valid = validate_eip712_signature(domain_separator, struct_hash, &signature, signer)
			.expect("validation");
		assert!(is_valid);
	}

	#[test]
	fn validate_eip712_signature_returns_false_for_mismatched_signer() {
		let domain_separator = FixedBytes::from([0x33u8; 32]);
		let struct_hash = FixedBytes::from([0x44u8; 32]);
		let message_hash = keccak256(
			[
				&[0x19, 0x01][..],
				domain_separator.as_slice(),
				struct_hash.as_slice(),
			]
			.concat(),
		);

		let secret = SecretKey::from_byte_array([0x21u8; 32]).expect("secret");
		let secp = Secp256k1::new();
		let message = Message::from_digest(*message_hash);
		let signature = secp.sign_ecdsa_recoverable(message, &secret);
		let (recovery_id, sig_bytes) = signature.serialize_compact();
		let mut signature_bytes = sig_bytes.to_vec();
		let rec: i32 = recovery_id.into();
		signature_bytes.push((rec as u8) + 27);
		let signature = Bytes::from(signature_bytes);

		let other_signer = AlloyAddress::from_slice(&[0xFFu8; 20]);
		let result =
			validate_eip712_signature(domain_separator, struct_hash, &signature, other_signer)
				.expect("validation result");
		assert!(!result);
	}

	#[test]
	fn validate_eip712_signature_errors_on_invalid_length() {
		let signature = Bytes::from(vec![0u8; 10]);
		let err = validate_eip712_signature(
			FixedBytes::from([0x55u8; 32]),
			FixedBytes::from([0x66u8; 32]),
			&signature,
			AlloyAddress::from_slice(&[0u8; 20]),
		)
		.expect_err("expected length error");
		assert!(matches!(
			err,
			APIError::BadRequest { message, .. } if message.contains("Invalid signature length")
		));
	}
}
