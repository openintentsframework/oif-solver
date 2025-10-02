//! Cryptographic signing service for EIP-712 and related signatures.
//!
//! This module provides functionality for signing various types of structured data
//! including EIP-712 typed data, Permit2 signatures, EIP-3009 authorizations,
//! and Compact signatures.

use alloy_dyn_abi::DynSolValue;
use alloy_primitives::{keccak256, Address, PrimitiveSignature, B256, U256};
use alloy_provider::Provider;
use alloy_rpc_types::TransactionRequest;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use solver_types::{
	api::{OrderPayload, Quote},
	standards::eip7683::interfaces::StandardOrder,
	utils::conversion::parse_bytes32_from_hex,
};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::info;

use crate::utils::address::to_checksum_address;

/// Service for handling cryptographic signatures.
pub struct SigningService {
	/// Contract manager for RPC calls to fetch domain separators.
	contract_manager: Arc<crate::core::ContractManager>,
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
	/// Creates a new SigningService with a contract manager.
	pub fn new(contract_manager: Arc<crate::core::ContractManager>) -> Self {
		Self { contract_manager }
	}

	/// Fetches the domain separator from a contract.
	async fn fetch_domain_separator(
		&self,
		chain_id: u64,
		verifying_contract: Address,
	) -> Result<[u8; 32]> {
		let provider = self.contract_manager.get_provider(chain_id).await?;

		// Call DOMAIN_SEPARATOR() on the contract
		let call_data =
			hex::decode("3644e515").map_err(|e| anyhow!("Failed to decode call data: {}", e))?; // DOMAIN_SEPARATOR()
		let tx = TransactionRequest::default()
			.to(verifying_contract)
			.input(call_data.into());
		let result = provider
			.call(&tx)
			.await
			.map_err(|e| anyhow!("Failed to call DOMAIN_SEPARATOR: {}", e))?;

		if result.len() != 32 {
			return Err(anyhow!("Invalid domain separator length: {}", result.len()));
		}

		let mut domain_separator = [0u8; 32];
		domain_separator.copy_from_slice(&result);
		Ok(domain_separator)
	}

	/// Signs a quote using the appropriate signature scheme with the provided private key.
	pub async fn sign_quote(&self, quote: &Quote, private_key: &str) -> Result<String> {
		info!("Signing quote with ID: {}", quote.quote_id);

		match &quote.order {
			solver_types::api::OifOrder::OifEscrowV0 { payload } => {
				self.sign_eip712_payload(payload, None, private_key).await
			},
			solver_types::api::OifOrder::OifResourceLockV0 { payload } => {
				self.sign_eip712_payload(payload, None, private_key).await
			},
			solver_types::api::OifOrder::Oif3009V0 { payload, metadata } => {
				self.sign_eip712_payload(payload, Some(metadata), private_key)
					.await
			},
			solver_types::api::OifOrder::OifGenericV0 { .. } => {
				Err(anyhow!("Generic orders not supported for signing"))
			},
		}
	}

	/// Signs an EIP-712 payload.
	async fn sign_eip712_payload(
		&self,
		payload: &OrderPayload,
		metadata: Option<&serde_json::Value>,
		private_key: &str,
	) -> Result<String> {
		let wallet = private_key
			.parse::<PrivateKeySigner>()
			.map_err(|e| anyhow!("Failed to parse private key: {}", e))?;

		// Determine the type of EIP-712 signature based on primary type
		let (digest, signature_type) = match payload.primary_type.as_str() {
			"ReceiveWithAuthorization" | "TransferWithAuthorization" | "CancelAuthorization" => {
				let metadata = metadata.ok_or_else(|| anyhow!("Missing metadata for EIP-3009"))?;
				println!(
					"✏️ [SIGNING] Processing EIP-3009 signature for {}",
					payload.primary_type
				);
				(
					self.compute_eip3009_digest(payload, metadata).await?,
					SignatureScheme::Eip3009,
				)
			},
			"PermitBatchWitnessTransferFrom" | "PermitWitnessTransferFrom" => (
				self.compute_permit2_digest(payload)?,
				SignatureScheme::Permit2,
			),
			"BatchCompact" | "Compact" => (
				self.compute_compact_digest(payload).await?,
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

		println!("✏️ [SIGNING] Signing digest with wallet...");
		let signature = wallet
			.sign_hash_sync(&B256::from(digest))
			.map_err(|e| anyhow!("Failed to sign digest: {}", e))?;

		let sig_bytes = self.encode_signature(signature);

		// Add signature type prefix based on the scheme
		let prefixed_signature = match signature_type {
			SignatureScheme::Permit2 => {
				println!("✏️ [SIGNING] Raw signature: 0x{}", hex::encode(&sig_bytes));
				// Prefix with 0x00 for Permit2
				let mut prefixed = vec![0x00];
				prefixed.extend_from_slice(&sig_bytes);
				println!(
					"✏️ [SIGNING] Permit2 prefixed signature: 0x{}",
					hex::encode(&prefixed)
				);
				prefixed
			},
			SignatureScheme::Eip3009 => {
				println!("✏️ [SIGNING] Raw signature: 0x{}", hex::encode(&sig_bytes));
				// Prefix with 0x01 for EIP-3009
				let mut prefixed = vec![0x01];
				prefixed.extend_from_slice(&sig_bytes);
				println!(
					"✏️ [SIGNING] EIP-3009 prefixed signature: 0x{}",
					hex::encode(&prefixed)
				);
				prefixed
			},
			SignatureScheme::Compact => {
				println!("sig_bytes {:?}", sig_bytes);
				// For Compact signatures, ABI-encode as (sponsorSig, allocatorSig) like Bash script
				// allocatorData is empty (0x) for simple allocators like AlwaysOKAllocator
				self.encode_compact_signature(sig_bytes)
			},
			SignatureScheme::Generic => {
				println!("✏️ [SIGNING] Raw signature: 0x{}", hex::encode(&sig_bytes));
				// No prefix for generic signatures
				sig_bytes
			},
		};

		Ok(format!("0x{}", hex::encode(prefixed_signature)))
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

		let encoded = DynSolValue::Tuple(vec![
			DynSolValue::FixedBytes(domain_type_hash, 32),
			DynSolValue::FixedBytes(keccak256(domain.name.as_bytes()), 32),
			DynSolValue::FixedBytes(keccak256(domain.version.as_bytes()), 32),
			DynSolValue::Uint(U256::from(domain.chain_id), 256),
			DynSolValue::Address(domain.verifying_contract),
		])
		.abi_encode();

		Ok(keccak256(encoded).into())
	}

	/// Computes the struct hash for typed data.
	fn compute_struct_hash(&self, typed_data: &TypedData) -> Result<[u8; 32]> {
		let message_str = serde_json::to_string(&typed_data.message)
			.map_err(|e| anyhow!("Failed to serialize message: {}", e))?;

		Ok(keccak256(message_str.as_bytes()).into())
	}

	/// Computes the digest for EIP-3009 signatures with metadata.
	async fn compute_eip3009_digest(
		&self,
		payload: &OrderPayload,
		metadata: &serde_json::Value,
	) -> Result<[u8; 32]> {
		use solver_types::OifOrder;

		println!("🔍 [EIP-3009] Starting digest computation with metadata");
		println!(
			"🔍 [EIP-3009] Metadata: {}",
			serde_json::to_string_pretty(metadata)
				.unwrap_or_else(|_| "Failed to serialize".to_string())
		);

		// Build OifOrder::Oif3009V0 to use the TryFrom implementation
		let oif_order = OifOrder::Oif3009V0 {
			payload: payload.clone(),
			metadata: metadata.clone(),
		};

		// Convert to StandardOrder using the public TryFrom implementation
		let standard_order = StandardOrder::try_from(&oif_order)
			.map_err(|e| anyhow!("Failed to build StandardOrder from EIP-3009 payload: {}", e))?;

		println!("🔍 [DEMO SIGNING] StandardOrder built by demo for signing:");
		println!("{:#?}", standard_order);

		// Get the chain ID from domain
		let domain = payload
			.domain
			.as_object()
			.ok_or_else(|| anyhow!("Missing domain in payload"))?;
		let chain_id = domain["chainId"]
			.as_str()
			.and_then(|s| s.parse::<u64>().ok())
			.or_else(|| domain["chainId"].as_u64())
			.ok_or_else(|| anyhow!("Missing or invalid chainId"))?;

		// Get the InputSettler address from the EIP-3009 message "to" field
		let message = payload
			.message
			.as_object()
			.ok_or_else(|| anyhow!("Missing message in payload"))?;
		let input_settler_str = message["to"]
			.as_str()
			.ok_or_else(|| anyhow!("Missing 'to' address in EIP-3009 message"))?;
		let input_settler_address: alloy_primitives::Address = input_settler_str
			.parse()
			.map_err(|e| anyhow!("Invalid InputSettler address: {}", e))?;

		println!("🔍 [EIP-3009] Contract call params:");
		println!("  - chain_id: {}", chain_id);
		println!(
			"  - input_settler_address: {}",
			to_checksum_address(&input_settler_address, None)
		);

		// Compute the correct order identifier from the contract
		let order_identifier = self
			.contract_manager
			.compute_order_identifier(chain_id, input_settler_address, &standard_order)
			.await
			.map_err(|e| anyhow!("Failed to compute order identifier from contract: {}", e))?;

		println!(
			"🔍 [EIP-3009] Contract returned order identifier: 0x{}",
			hex::encode(order_identifier)
		);

		// Now compute the EIP-3009 digest using the contract-computed order identifier
		let digest = self
			.compute_eip3009_digest_with_order_id(payload, metadata, order_identifier)
			.await?;

		println!("🔍 [EIP-3009] Final digest: 0x{}", hex::encode(digest));

		Ok(digest)
	}

	/// Computes the digest for EIP-3009 signatures with a provided order identifier.
	async fn compute_eip3009_digest_with_order_id(
		&self,
		payload: &OrderPayload,
		_metadata: &serde_json::Value,
		order_identifier: [u8; 32],
	) -> Result<[u8; 32]> {
		println!(
			"🔐 [DIGEST] Computing EIP-3009 digest with order identifier: 0x{}",
			hex::encode(order_identifier)
		);

		let domain = payload
			.domain
			.as_object()
			.ok_or_else(|| anyhow!("Missing domain in payload"))?;
		let message = payload
			.message
			.as_object()
			.ok_or_else(|| anyhow!("Missing message in payload"))?;

		// Extract domain info
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

		println!(
			"🔐 [DIGEST] Token contract (verifyingContract): {}",
			to_checksum_address(&verifying_contract, None)
		);

		// Fetch domain separator directly from token contract like Bash scripts do
		println!("🔐 [DIGEST] Fetching domain separator directly from token contract (matching Bash behavior)");
		let domain_separator = self
			.fetch_domain_separator(chain_id, verifying_contract)
			.await?;

		println!(
			"🔐 [DIGEST] Final domain separator used: 0x{}",
			hex::encode(domain_separator)
		);

		// Extract message fields
		let from_str = message["from"]
			.as_str()
			.ok_or_else(|| anyhow!("Missing from address"))?;
		let from = from_str
			.parse::<Address>()
			.map_err(|e| anyhow!("Invalid from address: {}", e))?;

		let to_str = message["to"]
			.as_str()
			.ok_or_else(|| anyhow!("Missing to address"))?;
		let to = to_str
			.parse::<Address>()
			.map_err(|e| anyhow!("Invalid to address: {}", e))?;

		let value = message["value"]
			.as_str()
			.ok_or_else(|| anyhow!("Missing value"))?
			.parse::<U256>()
			.map_err(|e| anyhow!("Invalid value: {}", e))?;

		let valid_after = message["validAfter"]
			.as_u64()
			.or_else(|| {
				message["validAfter"]
					.as_str()
					.and_then(|s| s.parse::<u64>().ok())
			})
			.unwrap_or(0);
		let valid_before = message["validBefore"]
			.as_u64()
			.or_else(|| {
				message["validBefore"]
					.as_str()
					.and_then(|s| s.parse::<u64>().ok())
			})
			.unwrap_or(0);

		// Use nonce from message (this is what the solver computed and set)
		let nonce_str = message["nonce"]
			.as_str()
			.ok_or_else(|| anyhow!("Missing nonce in EIP-3009 message"))?;
		let nonce_array = parse_bytes32_from_hex(nonce_str)
			.map_err(|e| anyhow!("Invalid nonce: {}", e))?;

		println!("🔐 [DIGEST] EIP-3009 message fields:");
		println!("  - from: {}", to_checksum_address(&from, None));
		println!("  - to: {}", to_checksum_address(&to, None));
		println!("  - value: {}", value);
		println!("  - validAfter: {}", valid_after);
		println!("  - validBefore: {}", valid_before);
		println!("  - nonce from message: {}", nonce_str);
		println!(
			"  - order_identifier (computed): 0x{}",
			hex::encode(order_identifier)
		);
		println!(
			"  - using nonce from message: 0x{}",
			hex::encode(nonce_array)
		);

		// Compute struct hash for ReceiveWithAuthorization
		let type_hash = keccak256(
			"ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)",
		);

		println!("🔐 [DIGEST] Type hash: 0x{}", hex::encode(type_hash));

		let encoded = DynSolValue::Tuple(vec![
			DynSolValue::FixedBytes(type_hash, 32),
			DynSolValue::Address(from),
			DynSolValue::Address(to),
			DynSolValue::Uint(value, 256),
			DynSolValue::Uint(U256::from(valid_after), 256),
			DynSolValue::Uint(U256::from(valid_before), 256),
			DynSolValue::FixedBytes(nonce_array.into(), 32),
		])
		.abi_encode();

		let struct_hash = keccak256(encoded);
		println!("🔐 [DIGEST] Struct hash: 0x{}", hex::encode(struct_hash));

		// Final EIP-712 digest
		let final_digest = self.compute_eip712_digest(domain_separator, struct_hash.into())?;
		println!(
			"🔐 [DIGEST] Final EIP-712 digest: 0x{}",
			hex::encode(final_digest)
		);

		Ok(final_digest)
	}

	/// Computes the digest for Permit2 signatures.
	fn compute_permit2_digest(&self, payload: &OrderPayload) -> Result<[u8; 32]> {
		use solver_types::utils::reconstruct_permit2_digest;

		println!("🔍 [PERMIT2] Computing Permit2 digest");
		println!(
			"🔍 [PERMIT2] Payload domain: {}",
			serde_json::to_string_pretty(&payload.domain)
				.unwrap_or_else(|_| "Failed to serialize".to_string())
		);
		println!(
			"🔍 [PERMIT2] Payload message: {}",
			serde_json::to_string_pretty(&payload.message)
				.unwrap_or_else(|_| "Failed to serialize".to_string())
		);
		println!("🔍 [PERMIT2] Primary type: {}", payload.primary_type);

		// Use the existing reconstruction function which handles all the complex logic
		let digest = reconstruct_permit2_digest(payload)
			.map_err(|e| anyhow!("Failed to reconstruct Permit2 digest: {}", e))?;

		println!("🔍 [PERMIT2] Final digest: 0x{}", hex::encode(digest));

		Ok(digest)
	}

	/// Computes the digest for Compact signatures.
	async fn compute_compact_digest(&self, payload: &OrderPayload) -> Result<[u8; 32]> {
		println!("🔍 [COMPACT] Computing BatchCompact digest with contract domain separator");
		println!(
			"🔍 [COMPACT] Payload domain: {}",
			serde_json::to_string_pretty(&payload.domain)
				.unwrap_or_else(|_| "Failed to serialize".to_string())
		);
		println!(
			"🔍 [COMPACT] Payload message: {}",
			serde_json::to_string_pretty(&payload.message)
				.unwrap_or_else(|_| "Failed to serialize".to_string())
		);

		// Extract domain info to fetch domain separator from contract
		let domain = payload
			.domain
			.as_object()
			.ok_or_else(|| anyhow!("Missing domain"))?;
		let chain_id = domain
			.get("chainId")
			.and_then(|c| {
				c.as_str()
					.and_then(|s| s.parse::<u64>().ok())
					.or_else(|| c.as_u64())
			})
			.ok_or_else(|| anyhow!("Missing or invalid chainId"))?;
		let verifying_contract_str = domain
			.get("verifyingContract")
			.and_then(|v| v.as_str())
			.ok_or_else(|| anyhow!("Missing verifyingContract"))?;
		let verifying_contract = verifying_contract_str
			.parse::<Address>()
			.map_err(|e| anyhow!("Invalid verifyingContract: {}", e))?;

		println!(
			"🔍 [COMPACT] Fetching domain separator from contract: {} on chain {}",
			verifying_contract, chain_id
		);

		// Fetch domain separator directly from TheCompact contract (matching shell script behavior)
		let domain_separator = self
			.fetch_domain_separator(chain_id, verifying_contract)
			.await?;

		println!(
			"🔍 [COMPACT] Contract domain separator: 0x{}",
			hex::encode(domain_separator)
		);

		// Use custom compact digest computation with contract-fetched domain separator
		// This is based on solver_types::utils::reconstruct_compact_digest but uses
		// the domain separator fetched from the contract
		let digest =
			solver_types::utils::reconstruct_compact_digest(payload, Some(domain_separator))
				.map_err(|e| anyhow!("Failed to reconstruct Compact digest: {}", e))?;

		println!("🔍 [COMPACT] Final digest: 0x{}", hex::encode(digest));

		Ok(digest)
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

		Ok(keccak256(&digest_input).into())
	}

	/// Encodes a signature into bytes.
	fn encode_signature(&self, signature: PrimitiveSignature) -> Vec<u8> {
		let mut sig_bytes = Vec::with_capacity(65);
		// alloy PrimitiveSignature has r, s as U256 and v as Parity
		sig_bytes.extend_from_slice(&signature.r().to_be_bytes::<32>());
		sig_bytes.extend_from_slice(&signature.s().to_be_bytes::<32>());
		let v_value = if signature.v() { 28u8 } else { 27u8 };
		sig_bytes.push(v_value);

		println!("🔐 [SIGNATURE] Signature components:");
		println!(
			"  - r: 0x{}",
			hex::encode(signature.r().to_be_bytes::<32>())
		);
		println!(
			"  - s: 0x{}",
			hex::encode(signature.s().to_be_bytes::<32>())
		);
		println!("  - v: {} (recovery: {})", v_value, signature.v());

		sig_bytes
	}

	/// ABI-encodes a compact signature as (sponsorSig, allocatorSig) for TheCompact protocol
	fn encode_compact_signature(&self, sponsor_sig: Vec<u8>) -> Vec<u8> {
		// Empty allocator signature for basic flows (matching Bash script)
		let allocator_sig: Vec<u8> = Vec::new();

		println!("🔐 [COMPACT] Encoding signature as (sponsorSig, allocatorSig)");
		println!(
			"🔐 [COMPACT] Sponsor signature: 0x{}",
			hex::encode(&sponsor_sig)
		);
		println!(
			"🔐 [COMPACT] Allocator signature: 0x{}",
			hex::encode(&allocator_sig)
		);

		// Manual ABI encoding to match cast abi-encode "f(bytes,bytes)" exactly
		// This avoids the tuple overhead that DynSolValue::Tuple creates
		let mut encoded = Vec::new();

		// Offset to first bytes parameter (64 bytes = 0x40)
		encoded.extend_from_slice(&[0u8; 28]); // padding
		encoded.extend_from_slice(&0x40u32.to_be_bytes());

		// Calculate offset to second bytes parameter
		let second_offset = 64 + 32 + ((sponsor_sig.len() + 31) & !31); // 64 + length word + padded sponsor sig
		encoded.extend_from_slice(&[0u8; 28]); // padding
		encoded.extend_from_slice(&(second_offset as u32).to_be_bytes());

		// Encode first bytes parameter (sponsor signature)
		encoded.extend_from_slice(&[0u8; 28]); // padding for length
		encoded.extend_from_slice(&(sponsor_sig.len() as u32).to_be_bytes());
		encoded.extend_from_slice(&sponsor_sig);
		// Pad to 32-byte boundary
		let sponsor_padding = (32 - (sponsor_sig.len() % 32)) % 32;
		encoded.extend_from_slice(&vec![0u8; sponsor_padding]);

		// Encode second bytes parameter (allocator signature)
		encoded.extend_from_slice(&[0u8; 28]); // padding for length
		encoded.extend_from_slice(&(allocator_sig.len() as u32).to_be_bytes());
		encoded.extend_from_slice(&allocator_sig);
		// Pad to 32-byte boundary
		let allocator_padding = (32 - (allocator_sig.len() % 32)) % 32;
		encoded.extend_from_slice(&vec![0u8; allocator_padding]);

		println!(
			"🔐 [COMPACT] Final encoded signature: 0x{}",
			hex::encode(&encoded)
		);
		encoded
	}

	/// Gets the address from a private key.
	pub fn get_signer_address(private_key: &str) -> Result<Address> {
		let wallet = private_key
			.parse::<PrivateKeySigner>()
			.map_err(|e| anyhow!("Failed to parse private key: {}", e))?;
		Ok(wallet.address())
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
	pub nonce: U256,
	/// Expiration timestamp.
	pub deadline: U256,
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
	pub amount: U256,
}
