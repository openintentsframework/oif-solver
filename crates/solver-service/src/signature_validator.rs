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
	standards::eip7683::{interfaces::StandardOrder as OifStandardOrder, LockType},
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
				message: format!("Failed to convert order: {}", e),
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
		let struct_hash = message_hasher.compute_message_hash(&order_bytes, contract_address)?;

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
		tracing::debug!("EIP-712 signature validated");
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
				message: format!("No signature validator for standard: {}", standard),
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
	use async_trait::async_trait;
	use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
	use serde_json::json;
	use solver_delivery::{DeliveryError, DeliveryInterface, DeliveryService};
	use solver_types::api::{OrderPayload, PostOrderRequest, SignatureType};
	use solver_types::networks::RpcEndpoint;
	use solver_types::standards::eip7683::interfaces::{SolMandateOutput, StandardOrder};
	use solver_types::standards::eip7683::LockType;
	use solver_types::{
		Address, ConfigSchema, NetworkConfig, NetworksConfig, Transaction, TransactionHash,
		TransactionReceipt, ValidationError,
	};
	use std::collections::HashMap;
	use std::sync::Arc;
	use toml::Value;

	struct NoopConfigSchema;

	impl ConfigSchema for NoopConfigSchema {
		fn validate(&self, _config: &Value) -> Result<(), ValidationError> {
			Ok(())
		}
	}

	struct SuccessfulDelivery {
		response: Bytes,
	}

	impl SuccessfulDelivery {
		fn new(response: Bytes) -> Self {
			Self { response }
		}
	}

	struct FailingDelivery;

	#[async_trait]
	impl DeliveryInterface for SuccessfulDelivery {
		fn config_schema(&self) -> Box<dyn ConfigSchema> {
			Box::new(NoopConfigSchema)
		}

		async fn submit(
			&self,
			_tx: Transaction,
			_tracking: Option<solver_delivery::TransactionTrackingWithConfig>,
		) -> Result<TransactionHash, DeliveryError> {
			unimplemented!()
		}

		async fn get_receipt(
			&self,
			_hash: &TransactionHash,
			_chain_id: u64,
		) -> Result<TransactionReceipt, DeliveryError> {
			unimplemented!()
		}

		async fn get_gas_price(&self, _chain_id: u64) -> Result<String, DeliveryError> {
			unimplemented!()
		}

		async fn get_balance(
			&self,
			_address: &str,
			_token: Option<&str>,
			_chain_id: u64,
		) -> Result<String, DeliveryError> {
			unimplemented!()
		}

		async fn get_allowance(
			&self,
			_owner: &str,
			_spender: &str,
			_token_address: &str,
			_chain_id: u64,
		) -> Result<String, DeliveryError> {
			unimplemented!()
		}

		async fn get_nonce(&self, _address: &str, _chain_id: u64) -> Result<u64, DeliveryError> {
			unimplemented!()
		}

		async fn get_block_number(&self, _chain_id: u64) -> Result<u64, DeliveryError> {
			unimplemented!()
		}

		async fn estimate_gas(&self, _tx: Transaction) -> Result<u64, DeliveryError> {
			unimplemented!()
		}

		async fn eth_call(&self, _tx: Transaction) -> Result<Bytes, DeliveryError> {
			Ok(self.response.clone())
		}
	}

	#[async_trait]
	impl DeliveryInterface for FailingDelivery {
		fn config_schema(&self) -> Box<dyn ConfigSchema> {
			Box::new(NoopConfigSchema)
		}

		async fn submit(
			&self,
			_tx: Transaction,
			_tracking: Option<solver_delivery::TransactionTrackingWithConfig>,
		) -> Result<TransactionHash, DeliveryError> {
			unimplemented!()
		}

		async fn get_receipt(
			&self,
			_hash: &TransactionHash,
			_chain_id: u64,
		) -> Result<TransactionReceipt, DeliveryError> {
			unimplemented!()
		}

		async fn get_gas_price(&self, _chain_id: u64) -> Result<String, DeliveryError> {
			unimplemented!()
		}

		async fn get_balance(
			&self,
			_address: &str,
			_token: Option<&str>,
			_chain_id: u64,
		) -> Result<String, DeliveryError> {
			unimplemented!()
		}

		async fn get_allowance(
			&self,
			_owner: &str,
			_spender: &str,
			_token_address: &str,
			_chain_id: u64,
		) -> Result<String, DeliveryError> {
			unimplemented!()
		}

		async fn get_nonce(&self, _address: &str, _chain_id: u64) -> Result<u64, DeliveryError> {
			unimplemented!()
		}

		async fn get_block_number(&self, _chain_id: u64) -> Result<u64, DeliveryError> {
			unimplemented!()
		}

		async fn estimate_gas(&self, _tx: Transaction) -> Result<u64, DeliveryError> {
			unimplemented!()
		}

		async fn eth_call(&self, _tx: Transaction) -> Result<Bytes, DeliveryError> {
			Err(DeliveryError::Network("eth_call failed".to_string()))
		}
	}

	#[derive(Clone)]
	struct SignatureFixture {
		intent: PostOrderRequest,
		networks: NetworksConfig,
		delivery: Arc<DeliveryService>,
		chain_id: u64,
	}

	fn address_from_hex(hex_str: &str) -> Address {
		let bytes = hex::decode(hex_str.trim_start_matches("0x")).expect("valid hex address");
		assert_eq!(bytes.len(), 20);
		Address(bytes)
	}

	fn build_signature_fixture() -> SignatureFixture {
		let chain_id = 1u64;
		let nonce = 1u64;
		let expires = 1_700_000_000u32;
		let fill_deadline = 1_700_000_100u32;
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

		let domain_separator = FixedBytes::from([0x99u8; 32]);
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
			signature: Bytes::from(signature_bytes),
			quote_id: None,
			origin_submission: None,
		};

		let network_config = NetworkConfig {
			rpc_urls: vec![RpcEndpoint::http_only("http://localhost:8545".to_string())],
			input_settler_address: address_from_hex(input_settler_hex),
			output_settler_address: address_from_hex(output_settler_hex),
			tokens: Vec::new(),
			input_settler_compact_address: Some(address_from_hex(compact_settler_hex)),
			the_compact_address: Some(address_from_hex(the_compact_address_hex)),
			allocator_address: None,
		};

		let mut networks = NetworksConfig::new();
		networks.insert(chain_id, network_config);

		let mut implementations: HashMap<u64, Arc<dyn DeliveryInterface>> = HashMap::new();
		implementations.insert(
			chain_id,
			Arc::new(SuccessfulDelivery::new(Bytes::from(
				domain_separator.to_vec(),
			))),
		);
		let delivery = Arc::new(DeliveryService::new(implementations, 1, 30));

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
		let mut implementations: HashMap<u64, Arc<dyn DeliveryInterface>> = HashMap::new();
		implementations.insert(fixture.chain_id, Arc::new(FailingDelivery));
		let failing_delivery = Arc::new(DeliveryService::new(implementations, 1, 30));
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
}
