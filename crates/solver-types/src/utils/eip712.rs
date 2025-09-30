//! Generic EIP-712 utilities shared across the solver.
//!
//! These helpers provide:
//! - Domain hash computation
//! - Final digest computation (0x1901 || domainHash || structHash)
//! - A minimal ABI encoder for static EIP-712 field types used commonly

use super::formatting::{with_0x_prefix, without_0x_prefix};
use alloy_primitives::{keccak256, Address as AlloyAddress, B256, U256};
use alloy_signer::Signature;
use hex;

// Common EIP-712 type strings used across the solver
pub const DOMAIN_TYPE: &str = "EIP712Domain(string name,uint256 chainId,address verifyingContract)";
pub const NAME_PERMIT2: &str = "Permit2";
pub const MANDATE_OUTPUT_TYPE: &str = "MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)";
pub const PERMIT2_WITNESS_TYPE: &str =
	"Permit2Witness(uint32 expires,address inputOracle,MandateOutput[] outputs)";
pub const TOKEN_PERMISSIONS_TYPE: &str = "TokenPermissions(address token,uint256 amount)";
pub const PERMIT_BATCH_WITNESS_TYPE: &str =
	"PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,Permit2Witness witness)";

/// Compute EIP-712 domain hash (keccak256(abi.encode(typeHash, nameHash, chainId, verifyingContract))).
pub fn compute_domain_hash(name: &str, chain_id: u64, verifying_contract: &AlloyAddress) -> B256 {
	let domain_type_hash = keccak256(DOMAIN_TYPE.as_bytes());
	let name_hash = keccak256(name.as_bytes());
	let mut enc = Eip712AbiEncoder::new();
	enc.push_b256(&domain_type_hash);
	enc.push_b256(&name_hash);
	enc.push_u256(U256::from(chain_id));
	enc.push_address(verifying_contract);
	keccak256(enc.finish())
}

/// Compute the final EIP-712 digest: keccak256(0x1901 || domainHash || structHash).
pub fn compute_final_digest(domain_hash: &B256, struct_hash: &B256) -> B256 {
	let mut out = Vec::with_capacity(2 + 32 + 32);
	out.push(0x19);
	out.push(0x01);
	out.extend_from_slice(domain_hash.as_slice());
	out.extend_from_slice(struct_hash.as_slice());
	keccak256(out)
}

/// Minimal ABI encoder for static types used in EIP-712 struct hashing.
pub struct Eip712AbiEncoder {
	buf: Vec<u8>,
}

impl Default for Eip712AbiEncoder {
	fn default() -> Self {
		Self::new()
	}
}

impl Eip712AbiEncoder {
	pub fn new() -> Self {
		Self { buf: Vec::new() }
	}

	pub fn push_b256(&mut self, v: &B256) {
		self.buf.extend_from_slice(v.as_slice());
	}

	pub fn push_address(&mut self, addr: &AlloyAddress) {
		let mut word = [0u8; 32];
		word[12..].copy_from_slice(addr.as_slice());
		self.buf.extend_from_slice(&word);
	}

	pub fn push_u256(&mut self, v: U256) {
		let word: [u8; 32] = v.to_be_bytes::<32>();
		self.buf.extend_from_slice(&word);
	}

	pub fn push_u32(&mut self, v: u32) {
		let mut word = [0u8; 32];
		word[28..].copy_from_slice(&v.to_be_bytes());
		self.buf.extend_from_slice(&word);
	}

	pub fn finish(self) -> Vec<u8> {
		self.buf
	}
}

/// Recovers the user address from a Permit2 signature using ecrecover.
///
/// # Arguments
///
/// * `digest` - The EIP-712 digest that was signed (32 bytes)
/// * `signature` - The signature string with format "0x00<65_byte_signature>"
///
/// # Returns
///
/// Returns the recovered user address or an error if recovery fails.
pub fn ecrecover_user_from_signature(
	digest: &[u8; 32],
	signature: &str,
) -> Result<AlloyAddress, Box<dyn std::error::Error>> {
	// Handle different signature formats before parsing with alloy-signer
	let sig_to_parse = {
		let without_prefix = without_0x_prefix(signature);
		if without_prefix.len() == 132 {
			// 66-byte signature (132 hex chars): skip first byte (signature type)
			with_0x_prefix(&without_prefix[2..])
		} else {
			// Standard 65-byte signature: ensure it has 0x prefix
			with_0x_prefix(signature)
		}
	};

	// Try parsing the processed signature string using alloy-signer
	let sig: Signature = sig_to_parse
		.parse()
		.map_err(|e| format!("Failed to parse signature: {}", e))?;

	// Recover address from the prehash
	let recovered = sig
		.recover_address_from_prehash(&B256::from(*digest))
		.map_err(|e| format!("Recovery failed: {}", e))?;

	Ok(recovered)
}

/// Reconstructs the complete EIP-712 digest for Permit2 orders.
///
/// This function rebuilds the exact same digest that the client computed
/// by following the same steps: domain hash + struct hash → final digest.
pub fn reconstruct_permit2_digest(
	payload: &crate::api::OrderPayload,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
	let domain = payload.domain.as_object().ok_or("Missing domain")?;
	let message = payload.message.as_object().ok_or("Missing message")?;

	// 1. Compute domain hash
	let chain_id = domain
		.get("chainId")
		.and_then(|c| c.as_str())
		.ok_or("Missing chainId")?
		.parse::<u64>()?;
	let name = domain
		.get("name")
		.and_then(|n| n.as_str())
		.ok_or("Missing name")?;
	let contract_str = domain
		.get("verifyingContract")
		.and_then(|c| c.as_str())
		.ok_or("Missing contract")?;
	let contract = AlloyAddress::from_slice(&hex::decode(contract_str.trim_start_matches("0x"))?);

	let domain_hash = compute_domain_hash(name, chain_id, &contract);

	// 2. Compute struct hash for PermitBatchWitnessTransferFrom

	// Type hash for the main struct
	let permit_type = "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,Permit2Witness witness)MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)TokenPermissions(address token,uint256 amount)Permit2Witness(uint32 expires,address inputOracle,MandateOutput[] outputs)";
	let type_hash = keccak256(permit_type.as_bytes());

	// Extract message fields
	let spender_str = message
		.get("spender")
		.and_then(|s| s.as_str())
		.ok_or("Missing spender")?;
	let spender = AlloyAddress::from_slice(&hex::decode(spender_str.trim_start_matches("0x"))?);
	let nonce = message
		.get("nonce")
		.and_then(|n| n.as_str())
		.ok_or("Missing nonce")?
		.parse::<u64>()?;
	let deadline = message
		.get("deadline")
		.and_then(|d| d.as_str())
		.ok_or("Missing deadline")?
		.parse::<u64>()?;

	// Build permitted array hash
	let permitted = message
		.get("permitted")
		.and_then(|p| p.as_array())
		.ok_or("Missing permitted")?;
	let token_type_hash = keccak256("TokenPermissions(address token,uint256 amount)".as_bytes());
	let mut token_hashes = Vec::new();

	for perm in permitted {
		let perm_obj = perm.as_object().ok_or("Invalid permission")?;
		let token_str = perm_obj
			.get("token")
			.and_then(|t| t.as_str())
			.ok_or("Missing token")?;
		let amount_str = perm_obj
			.get("amount")
			.and_then(|a| a.as_str())
			.ok_or("Missing amount")?;

		let token = AlloyAddress::from_slice(&hex::decode(token_str.trim_start_matches("0x"))?);
		let amount = U256::from_str_radix(amount_str, 10)?;

		let mut encoder = Eip712AbiEncoder::new();
		encoder.push_b256(&token_type_hash);
		encoder.push_address(&token);
		encoder.push_u256(amount);
		token_hashes.push(keccak256(encoder.finish()));
	}

	// Hash the token permissions array
	let mut permitted_encoder = Eip712AbiEncoder::new();
	for hash in token_hashes {
		permitted_encoder.push_b256(&hash);
	}
	let permitted_hash = keccak256(permitted_encoder.finish());

	// Build witness hash
	let witness = message
		.get("witness")
		.and_then(|w| w.as_object())
		.ok_or("Missing witness")?;
	let expires = witness
		.get("expires")
		.and_then(|e| e.as_u64())
		.ok_or("Missing expires")? as u32;
	let oracle_str = witness
		.get("inputOracle")
		.and_then(|o| o.as_str())
		.ok_or("Missing inputOracle")?;
	let oracle = AlloyAddress::from_slice(&hex::decode(oracle_str.trim_start_matches("0x"))?);

	// Build outputs array hash
	let outputs = witness
		.get("outputs")
		.and_then(|o| o.as_array())
		.ok_or("Missing outputs")?;
	let output_type_hash = keccak256("MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)".as_bytes());
	let mut output_hashes = Vec::new();

	for output in outputs {
		let output_obj = output.as_object().ok_or("Invalid output")?;
		let oracle_str = output_obj
			.get("oracle")
			.and_then(|o| o.as_str())
			.ok_or("Missing oracle")?;
		let settler_str = output_obj
			.get("settler")
			.and_then(|s| s.as_str())
			.ok_or("Missing settler")?;
		let chain_id = output_obj
			.get("chainId")
			.and_then(|c| {
				c.as_str()
					.and_then(|s| s.parse::<u64>().ok())
					.or_else(|| c.as_u64())
			})
			.ok_or("Missing or invalid chainId")?;
		let token_str = output_obj
			.get("token")
			.and_then(|t| t.as_str())
			.ok_or("Missing token")?;
		let amount_str = output_obj
			.get("amount")
			.and_then(|a| a.as_str())
			.ok_or("Missing amount")?;
		let recipient_str = output_obj
			.get("recipient")
			.and_then(|r| r.as_str())
			.ok_or("Missing recipient")?;
		let call_str = output_obj
			.get("call")
			.and_then(|c| if c.is_null() { Some("0x") } else { c.as_str() })
			.unwrap_or("0x");
		let context_str = output_obj
			.get("context")
			.and_then(|c| c.as_str())
			.unwrap_or("0x");

		// Parse to bytes32 format
		let oracle = crate::utils::parse_bytes32_from_hex(oracle_str)?;
		let settler = crate::utils::parse_bytes32_from_hex(settler_str)?;
		let token = crate::utils::parse_bytes32_from_hex(token_str)?;
		let recipient = crate::utils::parse_bytes32_from_hex(recipient_str)?;
		let amount = U256::from_str_radix(amount_str, 10)?;

		// Hash call and context data
		let call_bytes = if call_str == "0x" {
			Vec::new()
		} else {
			hex::decode(call_str.trim_start_matches("0x"))?
		};
		let context_bytes = if context_str == "0x" {
			Vec::new()
		} else {
			hex::decode(context_str.trim_start_matches("0x"))?
		};
		let call_hash = keccak256(&call_bytes);
		let context_hash = keccak256(&context_bytes);

		// Encode MandateOutput struct
		let mut encoder = Eip712AbiEncoder::new();
		encoder.push_b256(&output_type_hash);
		encoder.push_b256(&B256::from(oracle));
		encoder.push_b256(&B256::from(settler));
		encoder.push_u256(U256::from(chain_id));
		encoder.push_b256(&B256::from(token));
		encoder.push_u256(amount);
		encoder.push_b256(&B256::from(recipient));
		encoder.push_b256(&call_hash);
		encoder.push_b256(&context_hash);

		output_hashes.push(keccak256(encoder.finish()));
	}

	// Hash outputs array
	let mut outputs_encoder = Eip712AbiEncoder::new();
	for hash in output_hashes {
		outputs_encoder.push_b256(&hash);
	}
	let outputs_hash = keccak256(outputs_encoder.finish());

	// Build witness struct hash
	let witness_type_hash = keccak256("Permit2Witness(uint32 expires,address inputOracle,MandateOutput[] outputs)MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)".as_bytes());
	let mut witness_encoder = Eip712AbiEncoder::new();
	witness_encoder.push_b256(&witness_type_hash);
	witness_encoder.push_u32(expires);
	witness_encoder.push_address(&oracle);
	witness_encoder.push_b256(&outputs_hash);
	let witness_hash = keccak256(witness_encoder.finish());

	let mut struct_encoder = Eip712AbiEncoder::new();
	struct_encoder.push_b256(&type_hash);
	struct_encoder.push_b256(&permitted_hash);
	struct_encoder.push_address(&spender);
	struct_encoder.push_u256(U256::from(nonce));
	struct_encoder.push_u256(U256::from(deadline));
	struct_encoder.push_b256(&witness_hash);
	let struct_hash = keccak256(struct_encoder.finish());

	// Final EIP-712 digest
	let final_digest = compute_final_digest(&domain_hash, &struct_hash);

	Ok(final_digest.0)
}

/// Reconstructs the EIP-712 digest for EIP-3009 orders.
///
/// This function rebuilds the exact same digest that the client computed
/// by following the same steps: domain hash + struct hash → final digest.
pub fn reconstruct_3009_digest(
	payload: &crate::api::OrderPayload,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
	use alloy_primitives::{keccak256, Address as AlloyAddress, FixedBytes, U256};

	let domain = payload.domain.as_object().ok_or("Missing domain")?;
	let message = payload.message.as_object().ok_or("Missing message")?;

	// Extract domain information
	let name = domain
		.get("name")
		.and_then(|n| n.as_str())
		.ok_or("Missing name")?;
	let chain_id = domain
		.get("chainId")
		.and_then(|c| {
			c.as_str()
				.and_then(|s| s.parse::<u64>().ok())
				.or_else(|| c.as_u64())
		})
		.ok_or("Missing or invalid chainId")?;
	let verifying_contract = domain
		.get("verifyingContract")
		.and_then(|v| v.as_str())
		.ok_or("Missing verifyingContract")?;

	// Extract message fields
	let from_str = message
		.get("from")
		.and_then(|f| f.as_str())
		.ok_or("Missing from")?;
	let from = AlloyAddress::from_slice(&hex::decode(from_str.trim_start_matches("0x"))?);

	let to_str = message
		.get("to")
		.and_then(|t| t.as_str())
		.ok_or("Missing to")?;
	let to = AlloyAddress::from_slice(&hex::decode(to_str.trim_start_matches("0x"))?);

	let value_str = message
		.get("value")
		.and_then(|v| v.as_str())
		.ok_or("Missing value")?;
	let value = U256::from_str_radix(value_str, 10)?;

	let valid_after = message
		.get("validAfter")
		.and_then(|v| v.as_u64())
		.unwrap_or(0);

	let valid_before = message
		.get("validBefore")
		.and_then(|v| v.as_u64())
		.unwrap_or(0);

	let nonce_str = message
		.get("nonce")
		.and_then(|n| n.as_str())
		.ok_or("Missing nonce")?;
	let nonce_bytes =
		FixedBytes::<32>::from_slice(&hex::decode(nonce_str.trim_start_matches("0x"))?);

	// Compute domain separator (like the client does)
	let domain_type_hash =
		keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)".as_bytes());
	let name_hash = keccak256(name.as_bytes());
	let contract =
		AlloyAddress::from_slice(&hex::decode(verifying_contract.trim_start_matches("0x"))?);

	let mut domain_encoder = Eip712AbiEncoder::new();
	domain_encoder.push_b256(&domain_type_hash);
	domain_encoder.push_b256(&name_hash);
	domain_encoder.push_u256(U256::from(chain_id));
	domain_encoder.push_address(&contract);
	let domain_hash = keccak256(domain_encoder.finish());

	// Compute struct hash for ReceiveWithAuthorization
	let type_hash = keccak256("ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)".as_bytes());

	let mut struct_encoder = Eip712AbiEncoder::new();
	struct_encoder.push_b256(&type_hash);
	struct_encoder.push_address(&from);
	struct_encoder.push_address(&to);
	struct_encoder.push_u256(value);
	struct_encoder.push_u256(U256::from(valid_after));
	struct_encoder.push_u256(U256::from(valid_before));
	struct_encoder.push_b256(&nonce_bytes);
	let struct_hash = keccak256(struct_encoder.finish());

	// Final EIP-712 digest
	let final_digest = compute_final_digest(&domain_hash, &struct_hash);

	Ok(final_digest.0)
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::{address, b256, U256};

	#[test]
	fn test_compute_domain_hash() {
		let name = "TestDomain";
		let chain_id = 1u64;
		let verifying_contract = address!("1234567890123456789012345678901234567890");

		let result = compute_domain_hash(name, chain_id, &verifying_contract);

		// Verify it produces a valid 32-byte hash
		assert_eq!(result.len(), 32);

		// Test deterministic behavior
		let result2 = compute_domain_hash(name, chain_id, &verifying_contract);
		assert_eq!(result, result2);

		// Test different inputs produce different results
		let different_name = compute_domain_hash("DifferentName", chain_id, &verifying_contract);
		assert_ne!(result, different_name);

		let different_chain = compute_domain_hash(name, 42u64, &verifying_contract);
		assert_ne!(result, different_chain);
	}

	#[test]
	fn test_compute_domain_hash_permit2() {
		// Test with Permit2 name specifically
		let chain_id = 1u64;
		let verifying_contract = address!("000000000022D473030F116dDEE9F6B43aC78BA3");

		let result = compute_domain_hash(NAME_PERMIT2, chain_id, &verifying_contract);
		assert_eq!(result.len(), 32);

		// Should be deterministic
		let result2 = compute_domain_hash(NAME_PERMIT2, chain_id, &verifying_contract);
		assert_eq!(result, result2);
	}

	#[test]
	fn test_compute_final_digest() {
		let domain_hash = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
		let struct_hash = b256!("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321");

		let result = compute_final_digest(&domain_hash, &struct_hash);

		// Verify it produces a valid 32-byte hash
		assert_eq!(result.len(), 32);

		// Test deterministic behavior
		let result2 = compute_final_digest(&domain_hash, &struct_hash);
		assert_eq!(result, result2);

		// Test different inputs produce different results
		let different_domain =
			b256!("0000000000000000000000000000000000000000000000000000000000000000");
		let different_result = compute_final_digest(&different_domain, &struct_hash);
		assert_ne!(result, different_result);
	}

	#[test]
	fn test_eip712_abi_encoder_new() {
		let encoder = Eip712AbiEncoder::new();
		assert_eq!(encoder.buf.len(), 0);

		// Test default implementation
		let encoder_default = Eip712AbiEncoder::default();
		assert_eq!(encoder_default.buf.len(), 0);
	}

	#[test]
	fn test_eip712_abi_encoder_push_b256() {
		let mut encoder = Eip712AbiEncoder::new();
		let test_hash = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

		encoder.push_b256(&test_hash);

		let result = encoder.finish();
		assert_eq!(result.len(), 32);
		assert_eq!(result, test_hash.as_slice());
	}

	#[test]
	fn test_eip712_abi_encoder_push_address() {
		let mut encoder = Eip712AbiEncoder::new();
		let test_address = address!("1234567890123456789012345678901234567890");

		encoder.push_address(&test_address);

		let result = encoder.finish();
		assert_eq!(result.len(), 32);

		// Address should be right-aligned in 32-byte word (12 zero bytes + 20 address bytes)
		assert_eq!(&result[0..12], &[0u8; 12]);
		assert_eq!(&result[12..32], test_address.as_slice());
	}

	#[test]
	fn test_eip712_abi_encoder_push_u256() {
		let mut encoder = Eip712AbiEncoder::new();
		let test_value = U256::from(0x123456789abcdefu64);

		encoder.push_u256(test_value);

		let result = encoder.finish();
		assert_eq!(result.len(), 32);

		// Verify big-endian encoding
		let expected = test_value.to_be_bytes::<32>();
		assert_eq!(result, expected);
	}

	#[test]
	fn test_eip712_abi_encoder_push_u32() {
		let mut encoder = Eip712AbiEncoder::new();
		let test_value = 0x12345678u32;

		encoder.push_u32(test_value);

		let result = encoder.finish();
		assert_eq!(result.len(), 32);

		// u32 should be right-aligned in 32-byte word
		assert_eq!(&result[0..28], &[0u8; 28]);
		assert_eq!(&result[28..32], &test_value.to_be_bytes());
	}

	#[test]
	fn test_eip712_abi_encoder_multiple_pushes() {
		let mut encoder = Eip712AbiEncoder::new();

		let test_hash = b256!("1111111111111111111111111111111111111111111111111111111111111111");
		let test_address = address!("2222222222222222222222222222222222222222");
		let test_u256 = U256::from(0x3333u64);
		let test_u32 = 0x4444u32;

		encoder.push_b256(&test_hash);
		encoder.push_address(&test_address);
		encoder.push_u256(test_u256);
		encoder.push_u32(test_u32);

		let result = encoder.finish();
		assert_eq!(result.len(), 32 * 4); // 4 × 32-byte words

		// Verify each section
		assert_eq!(&result[0..32], test_hash.as_slice());

		// Address section (12 zero bytes + 20 address bytes)
		assert_eq!(&result[32..44], &[0u8; 12]);
		assert_eq!(&result[44..64], test_address.as_slice());

		// U256 section
		assert_eq!(&result[64..96], &test_u256.to_be_bytes::<32>());

		// U32 section (28 zero bytes + 4 value bytes)
		assert_eq!(&result[96..124], &[0u8; 28]);
		assert_eq!(&result[124..128], &test_u32.to_be_bytes());
	}

	#[test]
	fn test_eip712_abi_encoder_empty() {
		let encoder = Eip712AbiEncoder::new();
		let result = encoder.finish();
		assert_eq!(result.len(), 0);
	}

	#[test]
	fn test_final_digest_matches_eip712_spec() {
		// Test that the final digest follows EIP-712 specification: 0x1901 || domainHash || structHash
		let domain_hash = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
		let struct_hash = b256!("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321");

		let result = compute_final_digest(&domain_hash, &struct_hash);

		// Manually construct what the result should be
		let mut expected_input = Vec::new();
		expected_input.push(0x19);
		expected_input.push(0x01);
		expected_input.extend_from_slice(domain_hash.as_slice());
		expected_input.extend_from_slice(struct_hash.as_slice());
		let expected = keccak256(expected_input);

		assert_eq!(result, expected);
	}
}
