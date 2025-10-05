//! Cryptographic signature generation and EIP-712 handling
//!
//! This module provides comprehensive signature generation for multiple signature
//! schemes including Permit2, EIP-3009, Compact, and generic EIP-712 signatures.
//! Handles typed data construction, digest computation, and signature encoding
//! with proper scheme-specific prefixes and formatting.

use crate::core::Provider;
use crate::Result;
use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{sol, SolValue};
use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use solver_types::api::{OifOrder, OrderPayload, Quote};
use std::collections::HashMap;
use tracing::{debug, info, instrument, warn};

/// Cryptographic signature service supporting multiple EIP standards
///
/// Provides signature generation capabilities for various signature schemes
/// including Permit2, EIP-3009, Compact, and generic EIP-712 implementations
/// with automatic scheme detection and proper encoding
#[derive(Default)]
pub struct SigningService {}

/// EIP-712 domain specification for typed data signatures
///
/// Defines the domain parameters required for EIP-712 signatures including
/// contract name, version, chain ID, and verifying contract address
#[derive(Debug, Serialize, Deserialize)]
pub struct EIP712Domain {
	pub name: String,
	pub version: String,
	#[serde(rename = "chainId")]
	pub chain_id: u64,
	#[serde(rename = "verifyingContract")]
	pub verifying_contract: Address,
}

/// Complete typed data structure for EIP-712 signature generation
///
/// Contains all components required for EIP-712 signature including domain,
/// type definitions, primary type specification, and message payload
#[derive(Debug, Serialize, Deserialize)]
pub struct TypedData {
	pub domain: EIP712Domain,
	#[serde(rename = "primaryType")]
	pub primary_type: String,
	pub types: HashMap<String, Vec<TypeField>>,
	pub message: serde_json::Value,
}

/// Individual type field definition for EIP-712 type specifications
///
/// Represents a single field within an EIP-712 type definition including
/// field name and Solidity type specification
#[derive(Debug, Serialize, Deserialize)]
pub struct TypeField {
	pub name: String,
	#[serde(rename = "type")]
	pub field_type: String,
}

/// Supported signature schemes for different contract standards
///
/// Defines the available signature schemes with their specific encoding
/// requirements and signature prefixes for proper contract verification
#[derive(Debug, Clone, Copy)]
pub enum SignatureScheme {
	Permit2,
	Eip3009,
	Compact,
	Generic,
}

impl SigningService {
	/// Create new SigningService instance
	///
	/// # Returns
	/// Empty SigningService ready for signature operations
	pub fn new() -> Self {
		Self {}
	}

	/// Generate signature for quote using appropriate signature scheme
	///
	/// Automatically detects the required signature scheme based on order type
	/// and generates properly formatted signature with scheme-specific encoding
	///
	/// # Arguments
	/// * `quote` - Quote containing order payload to sign
	/// * `private_key` - Private key for signature generation
	/// * `provider` - Blockchain provider for contract calls
	///
	/// # Returns
	/// Hex-encoded signature string with appropriate scheme prefix
	///
	/// # Errors
	/// Returns Error if signature generation fails or scheme is unsupported
	#[instrument(skip(self, private_key, provider), fields(quote_id = %quote.quote_id))]
	pub async fn sign_quote(
		&self,
		quote: &Quote,
		private_key: &str,
		provider: Provider,
	) -> Result<String> {
		info!(
			quote_id = %quote.quote_id,
			order_type = ?std::mem::discriminant(&quote.order),
			"Starting quote signature process"
		);

		match &quote.order {
			OifOrder::OifEscrowV0 { payload } => {
				self.sign_eip712_payload(payload, None, private_key, provider)
					.await
			},
			OifOrder::OifResourceLockV0 { payload } => {
				self.sign_eip712_payload(payload, None, private_key, provider)
					.await
			},
			OifOrder::Oif3009V0 { payload, metadata } => {
				self.sign_eip712_payload(payload, Some(metadata), private_key, provider)
					.await
			},
			OifOrder::OifGenericV0 { .. } => {
				Err(anyhow!("Generic orders not supported for signing").into())
			},
		}
	}

	/// Generate signature for EIP-712 payload with scheme-specific handling
	///
	/// Processes order payload to determine signature scheme, computes appropriate
	/// digest, generates signature, and applies proper encoding with prefixes
	///
	/// # Arguments
	/// * `payload` - Order payload containing typed data
	/// * `metadata` - Optional metadata for scheme-specific requirements
	/// * `private_key` - Private key for signature generation
	/// * `provider` - Blockchain provider for contract interactions
	///
	/// # Returns
	/// Hex-encoded signature with scheme-appropriate prefix
	///
	/// # Errors
	/// Returns Error if digest computation, signing, or encoding fails
	#[instrument(skip(self, private_key, provider), fields(primary_type = %payload.primary_type))]
	async fn sign_eip712_payload(
		&self,
		payload: &OrderPayload,
		metadata: Option<&serde_json::Value>,
		private_key: &str,
		provider: Provider,
	) -> Result<String> {
		let wallet = private_key
			.parse::<PrivateKeySigner>()
			.map_err(|e| anyhow!("Failed to parse private key: {}", e))?;

		// Determine signature scheme and compute digest
		let (digest, signature_type) = match payload.primary_type.as_str() {
			"ReceiveWithAuthorization" | "TransferWithAuthorization" | "CancelAuthorization" => {
				let metadata = metadata.ok_or_else(|| anyhow!("Missing metadata for EIP-3009"))?;
				info!(
					primary_type = %payload.primary_type,
					scheme = "EIP-3009",
					"Processing signature for EIP-3009 authorization"
				);
				(
					self.compute_eip3009_digest(payload, metadata, provider)
						.await?,
					SignatureScheme::Eip3009,
				)
			},
			"PermitBatchWitnessTransferFrom" | "PermitWitnessTransferFrom" => (
				self.compute_permit2_digest(payload)?,
				SignatureScheme::Permit2,
			),
			"BatchCompact" | "Compact" => (
				self.compute_compact_digest(payload, provider).await?,
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

		debug!(
			digest = %hex::encode(digest),
			signer_address = %wallet.address(),
			"Signing digest with wallet"
		);
		let signature = wallet
			.sign_hash_sync(&B256::from(digest))
			.map_err(|e| anyhow!("Failed to sign digest: {}", e))?;

		let sig_bytes = signature.as_bytes().to_vec();

		// Add signature type prefix based on the scheme
		let prefixed_signature = match signature_type {
			SignatureScheme::Permit2 => {
				debug!(
					raw_signature = %hex::encode(&sig_bytes),
					signature_length = sig_bytes.len(),
					"Generated raw signature for Permit2"
				);
				// Prefix with 0x00 for Permit2
				let mut prefixed = vec![0x00];
				prefixed.extend_from_slice(&sig_bytes);
				debug!(
					prefixed_signature = %hex::encode(&prefixed),
					prefix = "0x00",
					scheme = "Permit2",
					"Applied Permit2 signature prefix"
				);
				prefixed
			},
			SignatureScheme::Eip3009 => {
				debug!(
					raw_signature = %hex::encode(&sig_bytes),
					signature_length = sig_bytes.len(),
					"Generated raw signature for EIP-3009"
				);
				// Prefix with 0x01 for EIP-3009
				let mut prefixed = vec![0x01];
				prefixed.extend_from_slice(&sig_bytes);
				debug!(
					prefixed_signature = %hex::encode(&prefixed),
					prefix = "0x01",
					scheme = "EIP-3009",
					"Applied EIP-3009 signature prefix"
				);
				prefixed
			},
			SignatureScheme::Compact => {
				debug!(
					signature_bytes = ?sig_bytes,
					signature_length = sig_bytes.len(),
					"Processing Compact signature encoding"
				);
				// For Compact signatures, ABI-encode as (sponsorSig, allocatorSig)
				self.encode_compact_signature(sig_bytes)
			},
			SignatureScheme::Generic => {
				debug!(
					raw_signature = %hex::encode(&sig_bytes),
					signature_length = sig_bytes.len(),
					scheme = "Generic",
					"Generated raw signature for generic EIP-712"
				);
				// No prefix for generic signatures
				sig_bytes
			},
		};

		Ok(format!("0x{}", hex::encode(prefixed_signature)))
	}

	/// Retrieve domain separator from contract by calling DOMAIN_SEPARATOR function
	///
	/// # Arguments
	/// * `chain_id` - Target blockchain network identifier
	/// * `verifying_contract` - Contract address to query
	/// * `provider` - Blockchain provider for contract calls
	///
	/// # Returns
	/// 32-byte domain separator from contract
	///
	/// # Errors
	/// Returns Error if contract call fails or returns invalid data
	async fn fetch_domain_separator(
		&self,
		chain_id: u64,
		verifying_contract: Address,
		provider: Provider,
	) -> Result<[u8; 32]> {
		// Call DOMAIN_SEPARATOR() on the contract
		let call_data =
			hex::decode("3644e515").map_err(|e| anyhow!("Failed to decode call data: {}", e))?;

		let result = provider
			.call_contract(verifying_contract, call_data.into(), Some(chain_id))
			.await
			.map_err(|e| anyhow!("Failed to call DOMAIN_SEPARATOR: {}", e))?;

		if result.len() != 32 {
			return Err(anyhow!("Invalid domain separator length: {}", result.len()).into());
		}

		let mut domain_separator = [0u8; 32];
		domain_separator.copy_from_slice(&result);
		Ok(domain_separator)
	}

	/// Build complete TypedData structure from order payload
	///
	/// # Arguments
	/// * `payload` - Order payload containing domain and message data
	///
	/// # Returns
	/// Complete TypedData structure ready for EIP-712 processing
	///
	/// # Errors
	/// Returns Error if domain parsing fails
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

	/// Calculate EIP-712 domain separator hash
	///
	/// # Arguments
	/// * `domain` - Domain specification for hash calculation
	///
	/// # Returns
	/// 32-byte domain separator hash
	///
	/// # Errors
	/// Returns Error if domain encoding fails
	fn compute_domain_separator(&self, domain: &EIP712Domain) -> Result<[u8; 32]> {
		let domain_type_hash = keccak256(
			"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
		);

		sol! {
			struct DomainSeparator {
				bytes32 typeHash;
				bytes32 nameHash;
				bytes32 versionHash;
				uint256 chainId;
				address verifyingContract;
			}
		}

		let domain_sep = DomainSeparator {
			typeHash: domain_type_hash,
			nameHash: keccak256(domain.name.as_bytes()),
			versionHash: keccak256(domain.version.as_bytes()),
			chainId: U256::from(domain.chain_id),
			verifyingContract: domain.verifying_contract,
		};

		Ok(keccak256(domain_sep.abi_encode()).into())
	}

	/// Calculate struct hash for typed data message
	///
	/// # Arguments
	/// * `typed_data` - Complete typed data structure
	///
	/// # Returns
	/// 32-byte struct hash of the message
	///
	/// # Errors
	/// Returns Error if message serialization fails
	fn compute_struct_hash(&self, typed_data: &TypedData) -> Result<[u8; 32]> {
		let message_str = serde_json::to_string(&typed_data.message)
			.map_err(|e| anyhow!("Failed to serialize message: {}", e))?;
		Ok(keccak256(message_str.as_bytes()).into())
	}

	/// Calculate digest for EIP-3009 signature scheme
	///
	/// # Arguments
	/// * `payload` - Order payload with EIP-3009 data
	/// * `_metadata` - Additional metadata for EIP-3009
	/// * `provider` - Blockchain provider for domain separator fetching
	///
	/// # Returns
	/// 32-byte digest for EIP-3009 signature
	///
	/// # Errors
	/// Returns Error if domain extraction or digest computation fails
	#[instrument(skip(self, provider), fields(primary_type = %payload.primary_type))]
	async fn compute_eip3009_digest(
		&self,
		payload: &OrderPayload,
		_metadata: &serde_json::Value,
		provider: Provider,
	) -> Result<[u8; 32]> {
		debug!("Computing EIP-3009 digest using solver_types utility");

		// Extract domain info to fetch domain separator from contract
		let domain = payload
			.domain
			.as_object()
			.ok_or_else(|| anyhow!("Missing domain in payload"))?;
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

		debug!(
			verifying_contract = %verifying_contract,
			chain_id = chain_id,
			"Fetching domain separator from token contract"
		);

		// Fetch domain separator from token contract (like the old demo)
		let domain_separator = self
			.fetch_domain_separator(chain_id, verifying_contract, provider)
			.await?;
		debug!(
			domain_separator = %hex::encode(domain_separator),
			"Retrieved domain separator from contract"
		);

		// Use solver_types utility function with the contract-fetched domain separator
		let digest =
			solver_types::utils::reconstruct_eip3009_digest(payload, Some(domain_separator))
				.map_err(|e| anyhow!("Failed to reconstruct EIP-3009 digest: {}", e))?;

		debug!(
			digest = %hex::encode(digest),
			"Computed EIP-3009 digest"
		);
		Ok(digest)
	}

	/// Calculate digest for Permit2 signature scheme
	///
	/// # Arguments
	/// * `payload` - Order payload with Permit2 data
	///
	/// # Returns
	/// 32-byte digest for Permit2 signature
	///
	/// # Errors
	/// Returns Error if digest reconstruction fails
	#[instrument(skip(self), fields(primary_type = %payload.primary_type))]
	fn compute_permit2_digest(&self, payload: &OrderPayload) -> Result<[u8; 32]> {
		debug!("Computing Permit2 digest");

		// Use the existing reconstruction function
		let digest = solver_types::utils::reconstruct_permit2_digest(payload)
			.map_err(|e| anyhow!("Failed to reconstruct Permit2 digest: {}", e))?;

		debug!(
			digest = %hex::encode(digest),
			"Computed Permit2 digest"
		);
		Ok(digest)
	}

	/// Calculate digest for Compact signature scheme
	///
	/// # Arguments
	/// * `payload` - Order payload with Compact data
	/// * `provider` - Blockchain provider for domain separator fetching
	///
	/// # Returns
	/// 32-byte digest for Compact signature
	///
	/// # Errors
	/// Returns Error if domain extraction or digest computation fails
	#[instrument(skip(self, provider), fields(primary_type = %payload.primary_type))]
	async fn compute_compact_digest(
		&self,
		payload: &OrderPayload,
		provider: Provider,
	) -> Result<[u8; 32]> {
		debug!("Computing Compact digest");

		// Extract domain info
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
		let verifying_contract = domain
			.get("verifyingContract")
			.and_then(|v| v.as_str())
			.ok_or_else(|| anyhow!("Missing verifyingContract"))?
			.parse::<Address>()
			.map_err(|e| anyhow!("Invalid verifyingContract: {}", e))?;

		// Fetch domain separator from TheCompact contract
		let domain_separator = self
			.fetch_domain_separator(chain_id, verifying_contract, provider)
			.await?;
		debug!(
			domain_separator = %hex::encode(domain_separator),
			verifying_contract = %verifying_contract,
			"Retrieved domain separator from Compact contract"
		);

		// Use solver_types utility with contract domain separator
		let digest =
			solver_types::utils::reconstruct_compact_digest(payload, Some(domain_separator))
				.map_err(|e| anyhow!("Failed to reconstruct Compact digest: {}", e))?;

		debug!(
			digest = %hex::encode(digest),
			"Computed Compact digest"
		);
		Ok(digest)
	}

	/// Calculate final EIP-712 digest from domain separator and struct hash
	///
	/// # Arguments
	/// * `domain_separator` - 32-byte domain separator hash
	/// * `struct_hash` - 32-byte struct hash
	///
	/// # Returns
	/// Final 32-byte EIP-712 digest ready for signing
	///
	/// # Errors
	/// Returns Error if digest computation fails
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

	/// Encode Compact signature as ABI-encoded tuple of sponsor and allocator signatures
	///
	/// # Arguments
	/// * `sponsor_sig` - Sponsor signature bytes
	///
	/// # Returns
	/// ABI-encoded signature tuple as bytes
	fn encode_compact_signature(&self, sponsor_sig: Vec<u8>) -> Vec<u8> {
		// Empty allocator signature for basic flows
		let allocator_sig: Vec<u8> = Vec::new();

		debug!(
			sponsor_sig_length = sponsor_sig.len(),
			allocator_sig_length = allocator_sig.len(),
			"Encoding Compact signature as (sponsorSig, allocatorSig) tuple"
		);
		debug!(
			sponsor_signature = %hex::encode(&sponsor_sig),
			allocator_signature = %hex::encode(&allocator_sig),
			"Compact signature components"
		);

		// Manual ABI encoding to match cast abi-encode "f(bytes,bytes)"
		let mut encoded = Vec::new();

		// Offset to first bytes parameter (64 bytes = 0x40)
		encoded.extend_from_slice(&[0u8; 28]);
		encoded.extend_from_slice(&0x40u32.to_be_bytes());

		// Calculate offset to second bytes parameter
		let second_offset = 64 + 32 + ((sponsor_sig.len() + 31) & !31);
		encoded.extend_from_slice(&[0u8; 28]);
		encoded.extend_from_slice(&(second_offset as u32).to_be_bytes());

		// Encode first bytes parameter (sponsor signature)
		encoded.extend_from_slice(&[0u8; 28]);
		encoded.extend_from_slice(&(sponsor_sig.len() as u32).to_be_bytes());
		encoded.extend_from_slice(&sponsor_sig);
		let sponsor_padding = (32 - (sponsor_sig.len() % 32)) % 32;
		encoded.extend_from_slice(&vec![0u8; sponsor_padding]);

		// Encode second bytes parameter (allocator signature)
		encoded.extend_from_slice(&[0u8; 28]);
		encoded.extend_from_slice(&(allocator_sig.len() as u32).to_be_bytes());
		encoded.extend_from_slice(&allocator_sig);
		let allocator_padding = (32 - (allocator_sig.len() % 32)) % 32;
		encoded.extend_from_slice(&vec![0u8; allocator_padding]);

		debug!(
			encoded_signature = %hex::encode(&encoded),
			encoded_length = encoded.len(),
			"Final ABI-encoded Compact signature"
		);
		encoded
	}

	/// Extract wallet address from private key
	///
	/// # Arguments
	/// * `private_key` - Private key hex string
	///
	/// # Returns
	/// Ethereum address derived from private key
	///
	/// # Errors
	/// Returns Error if private key format is invalid
	#[instrument(skip(private_key))]
	pub fn get_signer_address(private_key: &str) -> Result<Address> {
		let wallet = private_key
			.parse::<PrivateKeySigner>()
			.map_err(|e| anyhow!("Failed to parse private key: {}", e))?;
		Ok(wallet.address())
	}
}
