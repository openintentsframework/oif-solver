//! TheCompact protocol-specific EIP-712 implementation
//!
//! This module implements the generic EIP-712 interfaces with TheCompact protocol
//! specific logic for BatchCompact message hash computation and signature handling.

use crate::eip712::{MessageHashComputer, SignatureValidator};
use alloy_primitives::{Address as AlloyAddress, Bytes, FixedBytes};
use alloy_sol_types::SolType;
use solver_types::{
	standards::eip7683::compact_claims::compute_batch_compact_claim_hash,
	standards::eip7683::compact_signatures::decode_compact_signatures,
	standards::eip7683::interfaces::StandardOrder as OifStandardOrder, APIError, ApiErrorType,
};

/// TheCompact implementation of EIP-712 message hash computation
struct CompactMessageHasher;

impl MessageHashComputer for CompactMessageHasher {
	/// Compute BatchCompact struct hash for TheCompact protocol
	fn compute_message_hash(
		&self,
		order_bytes: &[u8],
		contract_address: AlloyAddress,
	) -> Result<FixedBytes<32>, APIError> {
		compute_batch_compact_hash(order_bytes, contract_address)
	}
}

/// TheCompact implementation of EIP-712 signature validation
struct CompactSignatureValidator;

impl SignatureValidator for CompactSignatureValidator {
	/// Validate EIP-712 signature against expected signer
	fn validate_signature(
		&self,
		domain_separator: FixedBytes<32>,
		struct_hash: FixedBytes<32>,
		signature: &Bytes,
		expected_signer: AlloyAddress,
	) -> Result<bool, APIError> {
		crate::eip712::validate_eip712_signature(
			domain_separator,
			struct_hash,
			signature,
			expected_signer,
		)
	}

	/// Extract sponsor signature from ABI-encoded signature bytes
	fn extract_signature(&self, signature: &Bytes) -> Result<Bytes, APIError> {
		extract_sponsor_signature(signature)
	}
}

/// Create a new message hasher for TheCompact protocol
pub fn create_message_hasher() -> impl MessageHashComputer {
	CompactMessageHasher
}

/// Create a new signature validator for TheCompact protocol
pub fn create_signature_validator() -> impl SignatureValidator {
	CompactSignatureValidator
}

/// Extract sponsor signature from ABI-encoded signature bytes
/// This handles ABI-encoded signatures: abi.encode(sponsorSig, allocatorSig)
pub fn extract_sponsor_signature(signature: &Bytes) -> Result<Bytes, APIError> {
	Ok(decode_compact_signatures(signature)?.sponsor)
}

/// Compute BatchCompact struct hash for TheCompact protocol
pub fn compute_batch_compact_hash(
	order_bytes: &[u8],
	contract_address: AlloyAddress,
) -> Result<FixedBytes<32>, APIError> {
	// Parse order
	let order =
		OifStandardOrder::abi_decode_validate(order_bytes).map_err(|e| APIError::BadRequest {
			error_type: ApiErrorType::OrderValidationFailed,
			message: format!("Failed to decode order: {e}"),
			details: None,
		})?;

	compute_batch_compact_claim_hash(&order, contract_address)
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::Bytes;
	use solver_types::standards::eip7683::compact_signatures::decode_compact_signatures;
	use solver_types::standards::eip7683::interfaces::SolMandateOutput as MandateOutput;

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

	#[test]
	fn test_extract_sponsor_signature() {
		// Test case: ABI-encoded signature with sponsor and allocator signatures
		// Structure: abi.encode(sponsorSig, allocatorSig)
		// - First 32 bytes: offset to sponsorSig (0x40 = 64)
		// - Next 32 bytes: offset to allocatorSig (0xC0 = 192)
		// - Next 32 bytes: length of sponsorSig (65 bytes)
		// - Next 65 bytes: actual sponsorSig data plus ABI padding
		// - Next 32 bytes: length of allocatorSig (65 bytes)
		// - Last 65 bytes: actual allocatorSig data plus ABI padding

		let mut abi_encoded_sig = Vec::new();

		// Offset to sponsorSig (64 bytes from start)
		abi_encoded_sig.extend_from_slice(&[0u8; 28]);
		abi_encoded_sig.extend_from_slice(&64u32.to_be_bytes());

		// Sponsor signature data (65 bytes)
		let sponsor_sig_data = vec![0x11u8; 65];
		let sponsor_tail = padded_bytes(&sponsor_sig_data);

		// Offset to allocatorSig (192 bytes from start)
		abi_encoded_sig.extend_from_slice(&abi_word(64 + sponsor_tail.len()));
		abi_encoded_sig.extend_from_slice(&sponsor_tail);

		// Allocator signature data (65 bytes)
		abi_encoded_sig.extend_from_slice(&padded_bytes(&[0x22u8; 65]));

		let signature = Bytes::from(abi_encoded_sig);
		let extracted = extract_sponsor_signature(&signature).unwrap();

		// Should extract the sponsor signature (65 bytes of 0x11)
		assert_eq!(extracted.len(), 65);
		assert_eq!(extracted.to_vec(), sponsor_sig_data);
	}

	#[test]
	fn compact_signature_decoder_must_not_accept_shifted_sponsor_offset_payload() {
		let valid_sponsor_sig = vec![0x11u8; 65];
		let bad_sponsor_sig = vec![0x44u8; 65];

		let fake_fixed_offset_tail = padded_bytes(&valid_sponsor_sig);
		let actual_sponsor_offset = 64 + fake_fixed_offset_tail.len();
		let actual_sponsor_tail = padded_bytes(&bad_sponsor_sig);
		let allocator_offset = actual_sponsor_offset + actual_sponsor_tail.len();
		let allocator_tail = padded_bytes(&[]);

		let mut shifted_payload = Vec::new();
		shifted_payload.extend_from_slice(&abi_word(actual_sponsor_offset));
		shifted_payload.extend_from_slice(&abi_word(allocator_offset));
		shifted_payload.extend_from_slice(&fake_fixed_offset_tail);
		shifted_payload.extend_from_slice(&actual_sponsor_tail);
		shifted_payload.extend_from_slice(&allocator_tail);

		assert!(decode_compact_signatures(&Bytes::from(shifted_payload)).is_err());
	}

	#[test]
	fn compact_signature_decoder_must_not_accept_raw_or_short_payloads() {
		let raw_sig = Bytes::from(vec![0x33u8; 65]);
		let short_sig = Bytes::from(vec![0x44u8; 32]);

		assert!(decode_compact_signatures(&raw_sig).is_err());
		assert!(decode_compact_signatures(&short_sig).is_err());
	}

	/// pC-02 Task 0 parity gate: the solver's BatchCompact struct hash must match
	/// the official `openintentsframework/oif-contracts` release-v1.0.0 claim hash
	/// (the value an allocator's `isClaimAuthorized` receives, pre domain-separator).
	///
	/// The expected value is a known-answer vector generated from the official
	/// release-v1.0.0 test harness formula (`InputSettlerCompact.base.t.sol`,
	/// the-compact submodule `b9c3b54…`) for the order constructed below.
	/// If this fails, the solver hash semantics no longer match the deployment
	/// target and pC-02's allocator check would false-reject every order.
	#[test]
	fn compute_batch_compact_hash_matches_official_release_v1_0_0_vector() {
		use alloy_primitives::U256;

		// token_id = lockTag(12 bytes) || token(20 bytes)
		let id_fb: FixedBytes<32> =
			"0x0102030405060708090a0b0c4444444444444444444444444444444444444444"
				.parse()
				.unwrap();
		let id = U256::from_be_bytes(id_fb.0);

		// bytes32(uint256(v)) — left-padded
		let b32 = |v: u64| FixedBytes::<32>::from(U256::from(v).to_be_bytes::<32>());

		let output = MandateOutput {
			oracle: b32(0xAAAA),
			settler: b32(0xBBBB),
			chainId: U256::from(10u64),
			token: b32(0xCCCC),
			amount: U256::from(555u64),
			recipient: b32(0xDDDD),
			callbackData: Bytes::new(),
			context: Bytes::new(),
		};

		let order = OifStandardOrder {
			user: AlloyAddress::from([0x22u8; 20]),
			nonce: U256::from(1u64),
			originChainId: U256::from(31337u64),
			expires: 2_000_000_000u32,
			fillDeadline: 1_700_000_000u32,
			inputOracle: AlloyAddress::from([0x33u8; 20]),
			inputs: vec![[id, U256::from(123456789u64)]],
			outputs: vec![output],
		};

		let order_bytes = Bytes::from(OifStandardOrder::abi_encode(&order));
		let arbiter = AlloyAddress::from([0x11u8; 20]);

		let got = compute_batch_compact_hash(&order_bytes, arbiter).expect("hash");
		let expected: FixedBytes<32> =
			"0x2142968938e7f2f2a043a1c4a6873e981c18871d77168a7818edf6d2fef10efd"
				.parse()
				.unwrap();

		assert_eq!(
			got, expected,
			"solver BatchCompact hash must match official release-v1.0.0 claim hash"
		);
	}
}
