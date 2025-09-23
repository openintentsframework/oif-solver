//! Generic EIP-712 utilities shared across the solver.
//!
//! These helpers provide:
//! - Domain hash computation
//! - Final digest computation (0x1901 || domainHash || structHash)
//! - A minimal ABI encoder for static EIP-712 field types used commonly

use alloy_primitives::{keccak256, Address as AlloyAddress, B256, U256};

// Common EIP-712 type strings used across the solver
pub const DOMAIN_TYPE: &str = "EIP712Domain(string name,uint256 chainId,address verifyingContract)";
pub const NAME_PERMIT2: &str = "Permit2";
pub const MANDATE_OUTPUT_TYPE: &str = "MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)";
pub const PERMIT2_WITNESS_TYPE: &str =
	"Permit2Witness(uint32 expires,address inputOracle,MandateOutput[] outputs)";
pub const TOKEN_PERMISSIONS_TYPE: &str = "TokenPermissions(address token,uint256 amount)";
pub const PERMIT_BATCH_WITNESS_TYPE: &str =
	"PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,Permit2Witness witness)";

/// Type alias for EIP-712 data extraction result
pub type Eip712ExtractionResult<'a> =
	Result<(&'a serde_json::Map<String, serde_json::Value>, &'a str), Box<dyn std::error::Error>>;

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
