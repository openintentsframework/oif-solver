//! Cryptographic signing service for EIP-712 and related signatures.
//!
//! This module provides functionality for signing various types of structured data
//! including EIP-712 typed data, Permit2 signatures, EIP-3009 authorizations,
//! and Compact signatures.

use anyhow::{anyhow, Result};
use ethers::{
	abi::{encode, Token},
	prelude::*,
	types::{transaction::eip712, H256, U256 as EthersU256},
	utils::keccak256,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use solver_types::api::{OrderPayload, Quote, SignatureType};
use std::collections::HashMap;
use tracing::info;

/// Service for handling cryptographic signatures.
#[derive(Debug, Clone)]
pub struct SigningService {
	/// Optional wallet for signing operations.
	wallet: Option<LocalWallet>,
}

/// EIP-712 domain separator structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EIP712Domain {
	/// Domain name.
	pub name: String,
	/// Domain version.
	pub version: String,
	/// Chain ID for the domain.
	pub chain_id: u64,
	/// Address of the verifying contract.
	pub verifying_contract: Address,
}

/// EIP-712 typed data structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedData {
	/// Domain information.
	pub domain: EIP712Domain,
	/// Primary type name.
	pub primary_type: String,
	/// Type definitions.
	pub types: HashMap<String, Vec<TypeField>>,
	/// Message data.
	pub message: Value,
}

/// Field definition for EIP-712 types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeField {
	/// Field name.
	pub name: String,
	/// Field type.
	#[serde(rename = "type")]
	pub field_type: String,
}

/// Supported signature schemes.
#[derive(Debug, Clone)]
pub enum SignatureScheme {
	/// Permit2 signature scheme.
	Permit2,
	/// EIP-3009 authorization signature.
	Eip3009,
	/// Compact signature format.
	Compact,
	/// Generic EIP-712 signature.
	Generic,
}

impl SigningService {
	/// Creates a new SigningService with an optional private key.
	pub fn new(private_key: Option<String>) -> Result<Self> {
		let wallet = if let Some(key) = private_key {
			let wallet = key
				.parse::<LocalWallet>()
				.map_err(|e| anyhow!("Failed to parse private key: {}", e))?;
			Some(wallet)
		} else {
			None
		};

		Ok(Self { wallet })
	}

	/// Signs a quote using the appropriate signature scheme.
	pub async fn sign_quote(&self, quote: &Quote) -> Result<String> {
		info!("Signing quote with ID: {}", quote.quote_id);

		let payload = match &quote.order {
			solver_types::api::OifOrder::OifEscrowV0 { payload } => payload,
			solver_types::api::OifOrder::OifResourceLockV0 { payload } => payload,
			solver_types::api::OifOrder::Oif3009V0 { payload, .. } => payload,
			solver_types::api::OifOrder::OifGenericV0 { .. } => {
				return Err(anyhow!("Generic orders not supported for signing"));
			},
		};

		match payload.signature_type {
			SignatureType::Eip712 => self.sign_eip712_payload(payload).await,
			SignatureType::Eip3009 => self.sign_eip3009_payload(payload).await,
		}
	}

	/// Signs an EIP-712 payload.
	async fn sign_eip712_payload(&self, payload: &OrderPayload) -> Result<String> {
		let wallet = self
			.wallet
			.as_ref()
			.ok_or_else(|| anyhow!("No wallet configured for signing"))?;

		// Determine the type of EIP-712 signature based on primary type
		let (digest, signature_type) = match payload.primary_type.as_str() {
			"ReceiveWithAuthorization" | "TransferWithAuthorization" | "CancelAuthorization" => (
				self.compute_eip3009_digest(payload)?,
				SignatureScheme::Eip3009,
			),
			"PermitBatchWitnessTransferFrom" | "PermitWitnessTransferFrom" => (
				self.compute_permit2_digest(payload)?,
				SignatureScheme::Permit2,
			),
			"BatchCompact" | "Compact" => (
				self.compute_compact_digest(payload)?,
				SignatureScheme::Compact,
			),
			_ => {
				// Generic EIP-712 handling
				let typed_data = self.construct_typed_data(payload)?;
				let domain_separator = self.compute_domain_separator(&typed_data.domain)?;
				let struct_hash = self.compute_struct_hash(&typed_data)?;
				(
					self.compute_eip712_digest(domain_separator, struct_hash)?,
					SignatureScheme::Generic,
				)
			},
		};

		let signature = wallet
			.sign_hash(H256::from(digest))
			.map_err(|e| anyhow!("Failed to sign digest: {}", e))?;

		let sig_bytes = self.encode_signature(signature);

		// Add signature type prefix based on the scheme
		let prefixed_signature = match signature_type {
			SignatureScheme::Permit2 => {
				// Prefix with 0x00 for Permit2
				let mut prefixed = vec![0x00];
				prefixed.extend_from_slice(&sig_bytes);
				prefixed
			},
			SignatureScheme::Eip3009 => {
				// Prefix with 0x01 for EIP-3009
				let mut prefixed = vec![0x01];
				prefixed.extend_from_slice(&sig_bytes);
				prefixed
			},
			SignatureScheme::Compact | SignatureScheme::Generic => {
				// No prefix for Compact or generic signatures
				sig_bytes
			},
		};

		Ok(format!("0x{}", hex::encode(prefixed_signature)))
	}

	/// Signs an EIP-3009 authorization payload.
	async fn sign_eip3009_payload(&self, payload: &OrderPayload) -> Result<String> {
		let wallet = self
			.wallet
			.as_ref()
			.ok_or_else(|| anyhow!("No wallet configured for signing"))?;

		let message = &payload.message;

		let from = self.extract_address(message, "from")?;
		let to = self.extract_address(message, "to")?;
		let value = self.extract_u256(message, "value")?;
		let validity_start = self.extract_u256(message, "validAfter")?;
		let validity_end = self.extract_u256(message, "validBefore")?;
		let nonce = self.extract_bytes32(message, "nonce")?;

		let domain_separator = self.compute_eip3009_domain_separator(&payload.domain)?;

		let type_hash = keccak256(
            "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
        );

		let encoded = encode(&[
			Token::FixedBytes(type_hash.to_vec()),
			Token::Address(from),
			Token::Address(to),
			Token::Uint(value),
			Token::Uint(validity_start),
			Token::Uint(validity_end),
			Token::FixedBytes(nonce.to_vec()),
		]);

		let struct_hash = keccak256(encoded);
		let digest = self.compute_eip712_digest(domain_separator, struct_hash)?;

		let signature = wallet
			.sign_hash(H256::from(digest))
			.map_err(|e| anyhow!("Failed to sign EIP-3009 digest: {}", e))?;

		let sig_bytes = self.encode_signature(signature);

		// Prefix with 0x01 for EIP-3009 signatures
		let mut prefixed = vec![0x01];
		prefixed.extend_from_slice(&sig_bytes);

		Ok(format!("0x{}", hex::encode(prefixed)))
	}

	/// Signs a Permit2 authorization.
	pub async fn sign_permit2(&self, permit_data: &Permit2Data) -> Result<String> {
		let wallet = self
			.wallet
			.as_ref()
			.ok_or_else(|| anyhow!("No wallet configured for signing"))?;

		let domain = eip712::EIP712Domain {
			name: Some("Permit2".to_string()),
			version: Some("1".to_string()),
			chain_id: Some(permit_data.chain_id.into()),
			verifying_contract: Some(permit_data.permit2_address),
			salt: None,
		};

		let domain_separator = domain.separator();

		let type_hash = if permit_data.is_batch {
			keccak256("PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,bytes32 witness)")
		} else {
			keccak256("PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,bytes32 witness)")
		};

		let _witness_type_hash = keccak256(&permit_data.witness_type_string);
		let witness_hash = keccak256(&permit_data.witness_data);

		let mut encoded = Vec::new();
		encoded.extend_from_slice(&type_hash);

		if permit_data.is_batch {
			let permissions_hash = self.hash_token_permissions_batch(&permit_data.permissions)?;
			encoded.extend_from_slice(&permissions_hash);
		} else {
			let permission_hash = self.hash_token_permission(&permit_data.permissions[0])?;
			encoded.extend_from_slice(&permission_hash);
		}

		encoded.extend_from_slice(&encode(&[
			Token::Address(permit_data.spender),
			Token::Uint(permit_data.nonce),
			Token::Uint(permit_data.deadline),
			Token::FixedBytes(witness_hash.to_vec()),
		]));

		let struct_hash = keccak256(&encoded);
		let digest = self.compute_eip712_digest(domain_separator, struct_hash)?;

		let signature = wallet
			.sign_hash(H256::from(digest))
			.map_err(|e| anyhow!("Failed to sign Permit2 digest: {}", e))?;

		let sig_bytes = self.encode_compact_signature(signature, permit_data.compact);
		Ok(format!("0x{}", hex::encode(sig_bytes)))
	}

	/// Constructs typed data from an order payload.
	fn construct_typed_data(&self, payload: &OrderPayload) -> Result<TypedData> {
		let domain: EIP712Domain = serde_json::from_value(payload.domain.clone())
			.map_err(|e| anyhow!("Failed to parse domain: {}", e))?;

		let mut types = HashMap::new();

		types.insert(
			"EIP712Domain".to_string(),
			vec![
				TypeField {
					name: "name".to_string(),
					field_type: "string".to_string(),
				},
				TypeField {
					name: "version".to_string(),
					field_type: "string".to_string(),
				},
				TypeField {
					name: "chainId".to_string(),
					field_type: "uint256".to_string(),
				},
				TypeField {
					name: "verifyingContract".to_string(),
					field_type: "address".to_string(),
				},
			],
		);

		Ok(TypedData {
			domain,
			primary_type: payload.primary_type.clone(),
			types,
			message: payload.message.clone(),
		})
	}

	/// Computes the EIP-712 domain separator.
	fn compute_domain_separator(&self, domain: &EIP712Domain) -> Result<[u8; 32]> {
		let domain_type_hash = keccak256(
			"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
		);

		let encoded = encode(&[
			Token::FixedBytes(domain_type_hash.to_vec()),
			Token::FixedBytes(keccak256(domain.name.as_bytes()).to_vec()),
			Token::FixedBytes(keccak256(domain.version.as_bytes()).to_vec()),
			Token::Uint(domain.chain_id.into()),
			Token::Address(domain.verifying_contract),
		]);

		Ok(keccak256(encoded))
	}

	/// Computes the domain separator for EIP-3009.
	fn compute_eip3009_domain_separator(&self, domain_value: &Value) -> Result<[u8; 32]> {
		let domain: EIP712Domain = serde_json::from_value(domain_value.clone())
			.map_err(|e| anyhow!("Failed to parse EIP-3009 domain: {}", e))?;

		self.compute_domain_separator(&domain)
	}

	/// Computes the struct hash for typed data.
	fn compute_struct_hash(&self, typed_data: &TypedData) -> Result<[u8; 32]> {
		let message_str = serde_json::to_string(&typed_data.message)
			.map_err(|e| anyhow!("Failed to serialize message: {}", e))?;

		Ok(keccak256(message_str.as_bytes()))
	}

	/// Computes the digest for EIP-3009 signatures.
	fn compute_eip3009_digest(&self, payload: &OrderPayload) -> Result<[u8; 32]> {
		// EIP-3009 domains don't have version field
		let domain_type_hash =
			keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");

		let domain = payload.domain.clone();
		let name = domain["name"]
			.as_str()
			.ok_or_else(|| anyhow!("Missing domain name"))?;
		let chain_id = domain["chainId"]
			.as_str()
			.and_then(|s| s.parse::<u64>().ok())
			.or_else(|| domain["chainId"].as_u64())
			.ok_or_else(|| anyhow!("Missing or invalid chainId"))?;
		let verifying_contract = domain["verifyingContract"]
			.as_str()
			.ok_or_else(|| anyhow!("Missing verifyingContract"))?
			.parse::<Address>()
			.map_err(|e| anyhow!("Invalid verifyingContract: {}", e))?;

		let domain_separator = keccak256(encode(&[
			Token::FixedBytes(domain_type_hash.to_vec()),
			Token::FixedBytes(keccak256(name.as_bytes()).to_vec()),
			Token::Uint(chain_id.into()),
			Token::Address(verifying_contract),
		]));

		// Compute struct hash based on ReceiveWithAuthorization
		let type_hash = keccak256(
			"ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
		);

		let message = &payload.message;
		let from = self.extract_address(message, "from")?;
		let to = self.extract_address(message, "to")?;
		let value = self.extract_u256(message, "value")?;
		let valid_after = self.extract_u256(message, "validAfter")?;
		let valid_before = self.extract_u256(message, "validBefore")?;
		let nonce = self.extract_bytes32(message, "nonce")?;

		let struct_hash = keccak256(encode(&[
			Token::FixedBytes(type_hash.to_vec()),
			Token::Address(from),
			Token::Address(to),
			Token::Uint(value),
			Token::Uint(valid_after),
			Token::Uint(valid_before),
			Token::FixedBytes(nonce.to_vec()),
		]));

		self.compute_eip712_digest(domain_separator, struct_hash)
	}

	/// Computes the digest for Permit2 signatures.
	fn compute_permit2_digest(&self, payload: &OrderPayload) -> Result<[u8; 32]> {
		// Permit2 domains don't have version field
		let domain_type_hash =
			keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");

		let domain = payload.domain.clone();
		let name = domain["name"]
			.as_str()
			.ok_or_else(|| anyhow!("Missing domain name"))?;
		let chain_id = domain["chainId"]
			.as_str()
			.and_then(|s| s.parse::<u64>().ok())
			.or_else(|| domain["chainId"].as_u64())
			.ok_or_else(|| anyhow!("Missing or invalid chainId"))?;
		let verifying_contract = domain["verifyingContract"]
			.as_str()
			.ok_or_else(|| anyhow!("Missing verifyingContract"))?
			.parse::<Address>()
			.map_err(|e| anyhow!("Invalid verifyingContract: {}", e))?;

		let domain_separator = keccak256(encode(&[
			Token::FixedBytes(domain_type_hash.to_vec()),
			Token::FixedBytes(keccak256(name.as_bytes()).to_vec()),
			Token::Uint(chain_id.into()),
			Token::Address(verifying_contract),
		]));

		// For Permit2, we need to compute the struct hash properly
		// This is a simplified version - full implementation would need to handle the nested structures
		let message_str = serde_json::to_string(&payload.message)
			.map_err(|e| anyhow!("Failed to serialize message: {}", e))?;
		let struct_hash = keccak256(message_str.as_bytes());

		self.compute_eip712_digest(domain_separator, struct_hash)
	}

	/// Computes the digest for Compact signatures.
	fn compute_compact_digest(&self, payload: &OrderPayload) -> Result<[u8; 32]> {
		// Compact domains have version field
		let domain_type_hash = keccak256(
			"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
		);

		let domain = payload.domain.clone();
		let name = domain["name"]
			.as_str()
			.ok_or_else(|| anyhow!("Missing domain name"))?;
		let version = domain["version"]
			.as_str()
			.ok_or_else(|| anyhow!("Missing domain version"))?;
		let chain_id = domain["chainId"]
			.as_str()
			.and_then(|s| s.parse::<u64>().ok())
			.or_else(|| domain["chainId"].as_u64())
			.ok_or_else(|| anyhow!("Missing or invalid chainId"))?;
		let verifying_contract = domain["verifyingContract"]
			.as_str()
			.ok_or_else(|| anyhow!("Missing verifyingContract"))?
			.parse::<Address>()
			.map_err(|e| anyhow!("Invalid verifyingContract: {}", e))?;

		let domain_separator = keccak256(encode(&[
			Token::FixedBytes(domain_type_hash.to_vec()),
			Token::FixedBytes(keccak256(name.as_bytes()).to_vec()),
			Token::FixedBytes(keccak256(version.as_bytes()).to_vec()),
			Token::Uint(chain_id.into()),
			Token::Address(verifying_contract),
		]));

		// For Compact, compute the struct hash
		let message_str = serde_json::to_string(&payload.message)
			.map_err(|e| anyhow!("Failed to serialize message: {}", e))?;
		let struct_hash = keccak256(message_str.as_bytes());

		self.compute_eip712_digest(domain_separator, struct_hash)
	}

	/// Computes the final EIP-712 digest.
	fn compute_eip712_digest(
		&self,
		domain_separator: [u8; 32],
		struct_hash: [u8; 32],
	) -> Result<[u8; 32]> {
		let mut digest_input = Vec::with_capacity(66);
		digest_input.push(0x19);
		digest_input.push(0x01);
		digest_input.extend_from_slice(&domain_separator);
		digest_input.extend_from_slice(&struct_hash);

		Ok(keccak256(&digest_input))
	}

	/// Encodes a signature into bytes.
	fn encode_signature(&self, signature: Signature) -> Vec<u8> {
		let mut sig_bytes = Vec::with_capacity(65);
		let mut r_bytes = [0u8; 32];
		signature.r.to_big_endian(&mut r_bytes);
		sig_bytes.extend_from_slice(&r_bytes);
		let mut s_bytes = [0u8; 32];
		signature.s.to_big_endian(&mut s_bytes);
		sig_bytes.extend_from_slice(&s_bytes);
		sig_bytes.push(signature.v as u8);
		sig_bytes
	}

	/// Encodes a signature in compact format if requested.
	fn encode_compact_signature(&self, signature: Signature, compact: bool) -> Vec<u8> {
		if compact {
			let mut sig_bytes = Vec::with_capacity(64);
			let mut r_bytes = [0u8; 32];
			signature.r.to_big_endian(&mut r_bytes);
			sig_bytes.extend_from_slice(&r_bytes);

			let mut s_bytes = [0u8; 32];
			signature.s.to_big_endian(&mut s_bytes);
			if signature.v == 28 {
				s_bytes[0] |= 0x80;
			}
			sig_bytes.extend_from_slice(&s_bytes);
			sig_bytes
		} else {
			self.encode_signature(signature)
		}
	}

	/// Hashes a single token permission.
	fn hash_token_permission(&self, permission: &TokenPermission) -> Result<[u8; 32]> {
		let type_hash = keccak256("TokenPermissions(address token,uint256 amount)");

		let encoded = encode(&[
			Token::FixedBytes(type_hash.to_vec()),
			Token::Address(permission.token),
			Token::Uint(permission.amount),
		]);

		Ok(keccak256(encoded))
	}

	/// Hashes a batch of token permissions.
	fn hash_token_permissions_batch(&self, permissions: &[TokenPermission]) -> Result<[u8; 32]> {
		let mut hashes = Vec::new();
		for permission in permissions {
			hashes.extend_from_slice(&self.hash_token_permission(permission)?);
		}
		Ok(keccak256(&hashes))
	}

	/// Extracts an Ethereum address from a JSON value.
	fn extract_address(&self, value: &Value, field: &str) -> Result<Address> {
		value
			.get(field)
			.and_then(|v| v.as_str())
			.ok_or_else(|| anyhow!("Missing field: {}", field))
			.and_then(|s| {
				s.parse::<Address>()
					.map_err(|e| anyhow!("Invalid address for {}: {}", field, e))
			})
	}

	/// Extracts a U256 value from a JSON value.
	fn extract_u256(&self, value: &Value, field: &str) -> Result<EthersU256> {
		let field_value = value
			.get(field)
			.ok_or_else(|| anyhow!("Missing field: {}", field))?;

		if let Some(s) = field_value.as_str() {
			EthersU256::from_dec_str(s).map_err(|e| anyhow!("Invalid U256 for {}: {}", field, e))
		} else if let Some(n) = field_value.as_u64() {
			Ok(EthersU256::from(n))
		} else {
			Err(anyhow!("Field {} is not a string or number", field))
		}
	}

	/// Extracts 32 bytes from a JSON value.
	fn extract_bytes32(&self, value: &Value, field: &str) -> Result<[u8; 32]> {
		value
			.get(field)
			.and_then(|v| v.as_str())
			.ok_or_else(|| anyhow!("Missing field: {}", field))
			.and_then(|s| {
				let bytes = hex::decode(s.trim_start_matches("0x"))
					.map_err(|e| anyhow!("Invalid hex for {}: {}", field, e))?;
				if bytes.len() != 32 {
					return Err(anyhow!("{} must be 32 bytes", field));
				}
				let mut arr = [0u8; 32];
				arr.copy_from_slice(&bytes);
				Ok(arr)
			})
	}

	/// Gets the address of the configured signer.
	pub fn get_signer_address(&self) -> Result<Address> {
		self.wallet
			.as_ref()
			.map(|w| w.address())
			.ok_or_else(|| anyhow!("No wallet configured"))
	}
}

/// Data required for Permit2 signatures.
#[derive(Debug, Clone)]
pub struct Permit2Data {
	/// Token permissions to authorize.
	pub permissions: Vec<TokenPermission>,
	/// Address authorized to spend tokens.
	pub spender: Address,
	/// Nonce for replay protection.
	pub nonce: EthersU256,
	/// Expiration timestamp.
	pub deadline: EthersU256,
	/// Type string for witness data.
	pub witness_type_string: String,
	/// Witness data bytes.
	pub witness_data: Vec<u8>,
	/// Chain ID for the permit.
	pub chain_id: u64,
	/// Address of the Permit2 contract.
	pub permit2_address: Address,
	/// Whether this is a batch permit.
	pub is_batch: bool,
	/// Whether to use compact signature encoding.
	pub compact: bool,
}

/// Token permission for Permit2.
#[derive(Debug, Clone)]
pub struct TokenPermission {
	/// Token contract address.
	pub token: Address,
	/// Amount authorized.
	pub amount: EthersU256,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_signing_service_creation() {
		let service = SigningService::new(None).unwrap();
		assert!(service.wallet.is_none());

		let private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
		let service = SigningService::new(Some(private_key.to_string())).unwrap();
		assert!(service.wallet.is_some());
	}
}
