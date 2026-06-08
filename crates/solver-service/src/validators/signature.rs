//! Signature validation service for different order standards.
//!
//! This module provides a pluggable architecture for validating EIP-712 signatures
//! based on different order standards (EIP-7683, etc.).

use crate::eip712::{
	compact, get_domain_separator, MessageHashComputer, SignatureValidator as EipSignatureValidator,
};
use alloy_primitives::{Address as AlloyAddress, Bytes};
use async_trait::async_trait;
use solver_delivery::DeliveryService;
use solver_types::{
	api::PostOrderRequest,
	standards::eip7683::{
		compact_signatures::decode_compact_signatures,
		interfaces::StandardOrder as OifStandardOrder, LockType,
	},
	APIError, ApiErrorType, NetworksConfig,
};
use std::collections::HashMap;
use std::sync::Arc;

/// Trait for validating signatures for specific order standards.
#[async_trait]
pub trait OrderSignatureValidator: Send + Sync {
	/// Checks if signature validation is required for the given lock type.
	fn requires_signature_validation(&self, lock_type: &LockType) -> bool;

	/// Validates an EIP-712 signature for this standard.
	async fn validate_signature(
		&self,
		intent: &PostOrderRequest,
		networks_config: &NetworksConfig,
		delivery_service: &Arc<DeliveryService>,
	) -> Result<(), APIError>;
}

/// EIP-7683 signature validator using TheCompact protocol.
pub struct Eip7683SignatureValidator;

#[async_trait]
impl OrderSignatureValidator for Eip7683SignatureValidator {
	/// For EIP-7683, signature validation is required only for ResourceLock orders.
	fn requires_signature_validation(&self, lock_type: &LockType) -> bool {
		matches!(lock_type, LockType::ResourceLock)
	}

	async fn validate_signature(
		&self,
		intent: &PostOrderRequest,
		networks_config: &NetworksConfig,
		delivery_service: &Arc<DeliveryService>,
	) -> Result<(), APIError> {
		use alloy_sol_types::SolType;

		// Convert OifOrder to StandardOrder
		let standard_order =
			OifStandardOrder::try_from(&intent.order).map_err(|e| APIError::BadRequest {
				error_type: ApiErrorType::OrderValidationFailed,
				message: format!("Failed to convert order: {e}"),
				details: None,
			})?;

		// Encode to bytes for hashing
		let order_bytes = Bytes::from(OifStandardOrder::abi_encode(&standard_order));

		let origin_chain_id = standard_order.originChainId.to::<u64>();
		let network =
			networks_config
				.get(&origin_chain_id)
				.ok_or_else(|| APIError::BadRequest {
					error_type: ApiErrorType::OrderValidationFailed,
					message: format!("Network {origin_chain_id} not configured"),
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
		let contract_address = network
			.input_settler_compact_address
			.as_ref()
			.map(|addr| AlloyAddress::from_slice(&addr.0))
			.ok_or_else(|| APIError::BadRequest {
				error_type: ApiErrorType::OrderValidationFailed,
				message: "InputSettlerCompact contract not configured".to_string(),
				details: None,
			})?;

		// Create compact-specific implementations using factory functions
		let message_hasher = compact::create_message_hasher();
		let signature_validator = compact::create_signature_validator();

		// 1. Get domain separator from TheCompact contract
		let domain_separator =
			get_domain_separator(delivery_service, the_compact_address, origin_chain_id).await?;

		// 2. Compute message hash using interface
		let struct_hash = message_hasher.compute_message_hash(&order_bytes, contract_address)?;

		// 3. Decode the canonical Compact signature tuple (sponsor + allocator).
		//    Non-canonical encodings are rejected here (pC-04).
		let decoded = decode_compact_signatures(&intent.signature)?;

		// 4. Validate the sponsor EIP-712 signature using interface.
		let expected_signer = standard_order.user;

		let is_valid = signature_validator.validate_signature(
			domain_separator,
			struct_hash,
			&decoded.sponsor,
			expected_signer,
		)?;

		if !is_valid {
			return Err(APIError::BadRequest {
				error_type: ApiErrorType::OrderValidationFailed,
				message: "Invalid EIP-712 signature".to_string(),
				details: None,
			});
		}
		tracing::debug!("EIP-712 signature validated");

		// 5. Validate allocator authorization for the decoded allocatorData (pC-02).
		//    `struct_hash` is the BatchCompact claim hash the allocator authorizes;
		//    `contract_address` is the InputSettlerCompact (the finalise arbiter).
		crate::validators::compact_allocator::validate_allocator_authorization(
			&standard_order,
			&decoded.allocator_data,
			struct_hash,
			contract_address,
			the_compact_address,
			network.allocator_address.as_ref(),
			delivery_service,
			origin_chain_id,
		)
		.await?;
		tracing::debug!("Compact allocator authorization validated");

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
		intent: &PostOrderRequest,
		networks_config: &NetworksConfig,
		delivery_service: &Arc<DeliveryService>,
	) -> Result<(), APIError> {
		let validator = self
			.validators
			.get(standard)
			.ok_or_else(|| APIError::BadRequest {
				error_type: ApiErrorType::OrderValidationFailed,
				message: format!("No signature validator for standard: {standard}"),
				details: None,
			})?;

		validator
			.validate_signature(intent, networks_config, delivery_service)
			.await
	}

	/// Checks if signature validation is required for the given standard and lock type.
	pub fn requires_signature_validation(&self, standard: &str, lock_type: &LockType) -> bool {
		if let Some(validator) = self.validators.get(standard) {
			validator.requires_signature_validation(lock_type)
		} else {
			false
		}
	}
}

impl Default for SignatureValidationService {
	fn default() -> Self {
		Self::new()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::{hex, keccak256, Address as AlloyAddress, Bytes, FixedBytes, U256};
	use alloy_sol_types::SolType;
	use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
	use serde_json::json;
	use solver_delivery::{
		DeliveryError, DeliveryInterface, DeliveryService, MockDeliveryInterface,
	};
	use solver_types::api::{OrderPayload, PostOrderRequest, SignatureType};
	use solver_types::networks::RpcEndpoint;
	use solver_types::standards::eip7683::compact_signatures::decode_compact_signatures;
	use solver_types::standards::eip7683::interfaces::{SolMandateOutput, StandardOrder};
	use solver_types::standards::eip7683::LockType;
	use solver_types::{Address, NetworkConfig, NetworksConfig};
	use std::collections::HashMap;
	use std::sync::Arc;

	#[derive(Clone)]
	struct SignatureFixture {
		intent: PostOrderRequest,
		networks: NetworksConfig,
		delivery: Arc<DeliveryService>,
		chain_id: u64,
	}

	fn delivery_service_from_mock(
		chain_id: u64,
		mock: MockDeliveryInterface,
	) -> Arc<DeliveryService> {
		let mut implementations: HashMap<u64, Arc<dyn DeliveryInterface>> = HashMap::new();
		implementations.insert(chain_id, Arc::new(mock) as Arc<dyn DeliveryInterface>);
		Arc::new(DeliveryService::new(implementations, 1, 30, 60))
	}

	fn fixture_domain_separator() -> FixedBytes<32> {
		FixedBytes::from([0x99u8; 32])
	}

	fn lock_allocator() -> AlloyAddress {
		AlloyAddress::from([0xA1u8; 20])
	}

	/// ABI return of `getLockDetails`: `(address token, address allocator,
	/// uint8 resetPeriod, uint8 scope, bytes12 lockTag)` — five static words.
	/// Only word 1 (allocator) matters for resolution.
	fn encode_lock_details(allocator: AlloyAddress) -> Bytes {
		let mut out = vec![0u8; 160];
		out[44..64].copy_from_slice(allocator.as_slice());
		out[95] = 5; // resetPeriod = OneDay (86_400s), exceeds the test fill-to-claim window
		Bytes::from(out)
	}

	fn encode_bool(value: bool) -> Bytes {
		let mut out = vec![0u8; 32];
		if value {
			out[31] = 1;
		}
		Bytes::from(out)
	}

	/// Delivery mock answering `DOMAIN_SEPARATOR` (the fixture separator),
	/// `getLockDetails` (resolving to `lock_allocator`), and `isClaimAuthorized`
	/// (returning `authorized`).
	fn compact_delivery(
		chain_id: u64,
		domain_separator: FixedBytes<32>,
		lock_allocator: AlloyAddress,
		authorized: bool,
	) -> Arc<DeliveryService> {
		use alloy_sol_types::SolCall;
		use solver_types::standards::eip7683::interfaces::{IAllocator, ITheCompact};

		let domain = Bytes::from(domain_separator.to_vec());
		let mut mock = MockDeliveryInterface::new();
		mock.expect_eth_call().returning(move |tx| {
			let selector = tx.data.get(0..4).map(|s| [s[0], s[1], s[2], s[3]]);
			let resp = match selector {
				Some(s) if s == ITheCompact::getLockDetailsCall::SELECTOR => {
					encode_lock_details(lock_allocator)
				},
				Some(s) if s == IAllocator::isClaimAuthorizedCall::SELECTOR => {
					encode_bool(authorized)
				},
				_ => domain.clone(),
			};
			Box::pin(async move { Ok(resp) })
		});
		delivery_service_from_mock(chain_id, mock)
	}

	fn address_from_hex(hex_str: &str) -> Address {
		let bytes = hex::decode(hex_str.trim_start_matches("0x")).expect("valid hex address");
		assert_eq!(bytes.len(), 20);
		Address(bytes)
	}

	fn abi_word(value: usize) -> [u8; 32] {
		let mut word = [0u8; 32];
		word[24..32].copy_from_slice(&(value as u64).to_be_bytes());
		word
	}

	fn padded_bytes(bytes: &[u8]) -> Vec<u8> {
		let mut encoded = Vec::new();
		encoded.extend_from_slice(&abi_word(bytes.len()));
		encoded.extend_from_slice(bytes);
		let padding = (32 - (bytes.len() % 32)) % 32;
		encoded.extend(std::iter::repeat_n(0u8, padding));
		encoded
	}

	fn compact_signature(sponsor_sig: &[u8], allocator_data: &[u8]) -> Bytes {
		let sponsor_tail = padded_bytes(sponsor_sig);
		let allocator_offset = 64 + sponsor_tail.len();

		let mut signature = Vec::new();
		signature.extend_from_slice(&abi_word(64));
		signature.extend_from_slice(&abi_word(allocator_offset));
		signature.extend_from_slice(&sponsor_tail);
		signature.extend_from_slice(&padded_bytes(allocator_data));
		Bytes::from(signature)
	}

	fn shifted_compact_signature(valid_sponsor_sig: &[u8]) -> Bytes {
		let fake_fixed_offset_tail = padded_bytes(valid_sponsor_sig);
		let actual_sponsor_sig = vec![0x44u8; valid_sponsor_sig.len()];
		let actual_sponsor_offset = 64 + fake_fixed_offset_tail.len();
		let actual_sponsor_tail = padded_bytes(&actual_sponsor_sig);
		let allocator_offset = actual_sponsor_offset + actual_sponsor_tail.len();

		let mut shifted_payload = Vec::new();
		shifted_payload.extend_from_slice(&abi_word(actual_sponsor_offset));
		shifted_payload.extend_from_slice(&abi_word(allocator_offset));
		shifted_payload.extend_from_slice(&fake_fixed_offset_tail);
		shifted_payload.extend_from_slice(&actual_sponsor_tail);
		shifted_payload.extend_from_slice(&padded_bytes(&[]));
		Bytes::from(shifted_payload)
	}

	fn build_signature_fixture() -> SignatureFixture {
		let chain_id = 1u64;
		let nonce = 1u64;
		let expires = 1_700_000_600u32;
		let fill_deadline = 1_700_000_000u32;
		let input_oracle_hex = "0x2222222222222222222222222222222222222222";
		let lock_tag = [0xAAu8; 12];
		let token_address_bytes = [0x33u8; 20];
		let output_chain_id = 137u64;
		let output_amount = U256::from(500u64);
		let output_token_bytes32 = [0x44u8; 32];
		let output_recipient = [0x55u8; 32];
		let output_oracle = [0x66u8; 32];
		let output_settler = [0x77u8; 32];
		let the_compact_address_hex = "0x8888888888888888888888888888888888888888";
		let compact_settler_hex = "0x9999999999999999999999999999999999999999";
		let input_settler_hex = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
		let output_settler_hex = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

		let token_id = {
			let mut bytes = [0u8; 32];
			bytes[..12].copy_from_slice(&lock_tag);
			bytes[12..].copy_from_slice(&token_address_bytes);
			U256::from_be_bytes(bytes)
		};

		let input_amount = U256::from(1_000u64);

		let secret_bytes = [0x11u8; 32];
		let secret_key = SecretKey::from_byte_array(secret_bytes).expect("valid secret key");
		let secp = Secp256k1::new();
		let public_key = PublicKey::from_secret_key(&secp, &secret_key);
		let public_key_bytes = public_key.serialize_uncompressed();
		let user_hash = keccak256(&public_key_bytes[1..]);
		let user_bytes = &user_hash[12..];
		let user_address = AlloyAddress::from_slice(user_bytes);
		let sponsor_hex = format!("0x{}", hex::encode(user_bytes));

		let input_oracle_bytes = hex::decode(input_oracle_hex.trim_start_matches("0x")).unwrap();
		let input_oracle = AlloyAddress::from_slice(&input_oracle_bytes);

		let outputs = vec![SolMandateOutput {
			oracle: output_oracle.into(),
			settler: output_settler.into(),
			chainId: U256::from(output_chain_id),
			token: output_token_bytes32.into(),
			amount: output_amount,
			recipient: output_recipient.into(),
			callbackData: Vec::new().into(),
			context: Vec::new().into(),
		}];

		let standard_order = StandardOrder {
			user: user_address,
			nonce: U256::from(nonce),
			originChainId: U256::from(chain_id),
			expires,
			fillDeadline: fill_deadline,
			inputOracle: input_oracle,
			inputs: vec![[token_id, input_amount]],
			outputs,
		};

		let order_bytes = StandardOrder::abi_encode(&standard_order);

		let contract_address_bytes = hex::decode(compact_settler_hex.trim_start_matches("0x"))
			.expect("valid contract address hex");
		let contract_address = AlloyAddress::from_slice(&contract_address_bytes);

		let message_hasher = compact::create_message_hasher();
		let struct_hash = message_hasher
			.compute_message_hash(&order_bytes, contract_address)
			.expect("struct hash");

		let domain_separator = fixture_domain_separator();
		let digest = keccak256(
			[
				&[0x19, 0x01][..],
				domain_separator.as_slice(),
				struct_hash.as_slice(),
			]
			.concat(),
		);

		let message = Message::from_digest(*digest);
		let signature = secp.sign_ecdsa_recoverable(message, &secret_key);
		let (recovery_id, sig_bytes) = signature.serialize_compact();
		let mut signature_bytes = sig_bytes.to_vec();
		let rec_id: i32 = recovery_id.into();
		signature_bytes.push((rec_id as u8) + 27);

		let lock_tag_hex = format!("0x{}", hex::encode(lock_tag));
		let token_hex = format!("0x{}", hex::encode(token_address_bytes));
		let order_payload = OrderPayload {
			signature_type: SignatureType::Eip712,
			domain: json!({
				"name": "BatchCompact",
				"version": "1",
				"chainId": chain_id.to_string(),
				"verifyingContract": the_compact_address_hex,
			}),
			primary_type: "BatchCompact".to_string(),
			message: json!({
				"sponsor": sponsor_hex,
				"nonce": nonce.to_string(),
				"expires": expires.to_string(),
				"mandate": {
					"fillDeadline": fill_deadline.to_string(),
					"inputOracle": input_oracle_hex,
					"outputs": [{
						"oracle": format!("0x{}", hex::encode(output_oracle)),
						"settler": format!("0x{}", hex::encode(output_settler)),
						"chainId": output_chain_id.to_string(),
						"token": format!("0x{}", hex::encode(output_token_bytes32)),
						"amount": output_amount.to_string(),
						"recipient": format!("0x{}", hex::encode(output_recipient)),
					}]
				},
				"commitments": [{
					"lockTag": lock_tag_hex,
					"token": token_hex,
					"amount": input_amount.to_string()
				}]
			}),
			types: None,
		};

		let intent = PostOrderRequest {
			order: solver_types::OifOrder::OifResourceLockV0 {
				payload: order_payload,
			},
			signature: compact_signature(&signature_bytes, &[]),
			quote_id: None,
			origin_submission: None,
		};

		let network_config = NetworkConfig {
			name: Some("test-network".to_string()),
			network_type: solver_types::networks::NetworkType::New,
			rpc_urls: vec![RpcEndpoint::http_only("http://localhost:8545".to_string())],
			input_settler_address: address_from_hex(input_settler_hex),
			output_settler_address: address_from_hex(output_settler_hex),
			tokens: Vec::new(),
			input_settler_compact_address: Some(address_from_hex(compact_settler_hex)),
			the_compact_address: Some(address_from_hex(the_compact_address_hex)),
			// Pin the trusted allocator to the one the lock resolves to (`lock_allocator()`).
			allocator_address: Some(address_from_hex(
				"0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
			)),
		};

		let mut networks = NetworksConfig::new();
		networks.insert(chain_id, network_config);

		let delivery = compact_delivery(chain_id, domain_separator, lock_allocator(), true);

		SignatureFixture {
			intent,
			networks,
			delivery,
			chain_id,
		}
	}

	#[test]
	fn requires_signature_validation_only_for_resource_lock() {
		let service = SignatureValidationService::new();
		assert!(service.requires_signature_validation("eip7683", &LockType::ResourceLock));
		assert!(!service.requires_signature_validation("eip7683", &LockType::Permit2Escrow));
		assert!(!service.requires_signature_validation("unknown", &LockType::ResourceLock));
	}

	#[tokio::test]
	async fn validate_signature_succeeds_for_valid_resource_lock() {
		let fixture = build_signature_fixture();
		let service = SignatureValidationService::new();
		service
			.validate_signature(
				"eip7683",
				&fixture.intent,
				&fixture.networks,
				&fixture.delivery,
			)
			.await
			.expect("signature should validate");
	}

	#[tokio::test]
	async fn validate_signature_rejects_shifted_compact_signature_offsets() {
		let mut fixture = build_signature_fixture();
		let valid_sponsor_sig = decode_compact_signatures(&fixture.intent.signature)
			.expect("canonical compact signature")
			.sponsor
			.to_vec();
		fixture.intent.signature = shifted_compact_signature(&valid_sponsor_sig);

		let service = SignatureValidationService::new();
		let result = service
			.validate_signature(
				"eip7683",
				&fixture.intent,
				&fixture.networks,
				&fixture.delivery,
			)
			.await;

		assert!(matches!(
			result,
			Err(APIError::BadRequest { message, .. }) if message.contains("Compact")
		));
	}

	#[tokio::test]
	async fn validate_signature_rejects_unauthorized_allocator_data() {
		let mut fixture = build_signature_fixture();
		// Keep the valid sponsor signature, but supply unauthorized allocator data.
		let sponsor = decode_compact_signatures(&fixture.intent.signature)
			.expect("canonical compact signature")
			.sponsor
			.to_vec();
		fixture.intent.signature = compact_signature(&sponsor, b"garbage allocator data");

		// An enforcing allocator rejects the unauthorized allocatorData.
		let delivery = compact_delivery(
			fixture.chain_id,
			fixture_domain_separator(),
			lock_allocator(),
			false,
		);

		let service = SignatureValidationService::new();
		let result = service
			.validate_signature("eip7683", &fixture.intent, &fixture.networks, &delivery)
			.await;

		assert!(matches!(
			result,
			Err(APIError::BadRequest { message, .. }) if message.contains("allocator")
		));
	}

	#[tokio::test]
	async fn validate_signature_rejects_missing_input_settler_compact_address() {
		let mut fixture = build_signature_fixture();
		fixture
			.networks
			.get_mut(&fixture.chain_id)
			.expect("network")
			.input_settler_compact_address = None;

		let service = SignatureValidationService::new();
		let result = service
			.validate_signature(
				"eip7683",
				&fixture.intent,
				&fixture.networks,
				&fixture.delivery,
			)
			.await;

		assert!(matches!(
			result,
			Err(APIError::BadRequest { message, .. }) if message.contains("InputSettlerCompact")
		));
	}

	#[tokio::test]
	async fn validate_signature_returns_error_for_unknown_standard() {
		let fixture = build_signature_fixture();
		let service = SignatureValidationService::new();
		let result = service
			.validate_signature(
				"unknown",
				&fixture.intent,
				&fixture.networks,
				&fixture.delivery,
			)
			.await;
		assert!(matches!(
			result,
			Err(APIError::BadRequest { message, .. }) if message.contains("No signature validator")
		));
	}

	#[tokio::test]
	async fn validate_signature_errors_when_network_missing() {
		let fixture = build_signature_fixture();
		let service = SignatureValidationService::new();
		let empty_networks = NetworksConfig::new();
		let result = service
			.validate_signature(
				"eip7683",
				&fixture.intent,
				&empty_networks,
				&fixture.delivery,
			)
			.await;
		assert!(matches!(
			result,
			Err(APIError::BadRequest { message, .. }) if message.contains("Network")
		));
	}

	#[tokio::test]
	async fn validate_signature_errors_when_compact_address_missing() {
		let fixture = build_signature_fixture();
		let mut networks = fixture.networks.clone();
		if let Some(network) = networks.get_mut(&fixture.chain_id) {
			network.the_compact_address = None;
		}
		let service = SignatureValidationService::new();
		let result = service
			.validate_signature("eip7683", &fixture.intent, &networks, &fixture.delivery)
			.await;
		assert!(matches!(
			result,
			Err(APIError::BadRequest { message, .. }) if message.contains("TheCompact contract not configured")
		));
	}

	#[tokio::test]
	async fn validate_signature_errors_when_domain_separator_call_fails() {
		let fixture = build_signature_fixture();
		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery.expect_eth_call().returning(|_| {
			Box::pin(async move { Err(DeliveryError::Network("eth_call failed".to_string())) })
		});
		let failing_delivery = delivery_service_from_mock(fixture.chain_id, mock_delivery);
		let service = SignatureValidationService::new();
		let result = service
			.validate_signature(
				"eip7683",
				&fixture.intent,
				&fixture.networks,
				&failing_delivery,
			)
			.await;
		assert!(matches!(
			result,
			Err(APIError::BadRequest { message, .. }) if message.contains("Failed to get domain separator")
		));
	}

	#[tokio::test]
	async fn validate_signature_errors_for_invalid_signature_bytes() {
		let mut fixture = build_signature_fixture();
		fixture.intent.signature = Bytes::from(vec![0u8; 65]);
		let service = SignatureValidationService::new();
		let result = service
			.validate_signature(
				"eip7683",
				&fixture.intent,
				&fixture.networks,
				&fixture.delivery,
			)
			.await;
		match result {
			Ok(_) => panic!("expected signature validation failure"),
			Err(APIError::BadRequest { message, .. }) => {
				assert!(
					(message.contains("Invalid") && message.contains("signature"))
						|| message.contains("Compact")
						|| message.contains("Failed to recover public key"),
					"unexpected error message: {message}"
				);
			},
			Err(other) => panic!("unexpected error: {other:?}"),
		}
	}
}
