//! TheCompact protocol-specific EIP-712 implementation
//!
//! This module implements the generic EIP-712 interfaces with TheCompact protocol
//! specific logic for BatchCompact message hash computation and signature handling.

use crate::eip712::{MessageHashComputer, SignatureValidator};
use alloy_primitives::{keccak256, Address as AlloyAddress, Bytes, FixedBytes, Uint};
use alloy_sol_types::SolType;
use solver_types::{
	standards::eip7683::interfaces::{
		SolMandateOutput as MandateOutput, StandardOrder as OifStandardOrder,
	},
	APIError, ApiErrorType,
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
	fn extract_signature(&self, signature: &Bytes) -> Bytes {
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
pub fn extract_sponsor_signature(signature: &Bytes) -> Bytes {
	// Handle ABI-encoded signatures: abi.encode(sponsorSig, allocatorSig)
	if signature.len() > 65 && signature.len() >= 96 {
		let sponsor_sig_length_offset = 64;
		if signature.len() > sponsor_sig_length_offset + 32 {
			let sponsor_sig_length = u32::from_be_bytes([
				signature[sponsor_sig_length_offset + 28],
				signature[sponsor_sig_length_offset + 29],
				signature[sponsor_sig_length_offset + 30],
				signature[sponsor_sig_length_offset + 31],
			]) as usize;

			let sponsor_sig_start = sponsor_sig_length_offset + 32;
			if signature.len() >= sponsor_sig_start + sponsor_sig_length {
				return Bytes::from(
					signature[sponsor_sig_start..sponsor_sig_start + sponsor_sig_length].to_vec(),
				);
			}
		}
	}

	// If not ABI-encoded or extraction failed, use raw signature
	signature.clone()
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
			message: format!("Failed to decode order: {}", e),
			details: None,
		})?;

	// Compute witness hash
	let witness_hash = compute_witness_hash(&order)?;
	let ids_and_amounts = order.inputs.to_vec();
	let lock_hash = compute_lock_hash(&ids_and_amounts)?;

	// Compute BatchCompact struct hash
	compute_batch_compact_struct_hash(
		contract_address,
		order.user,
		order.nonce,
		Uint::<256, 4>::from(order.expires),
		lock_hash,
		witness_hash,
	)
}

/// Compute witness hash for TheCompact mandate
pub fn compute_witness_hash(order: &OifStandardOrder) -> Result<FixedBytes<32>, APIError> {
	let mandate_type_hash = keccak256(
		b"Mandate(uint32 fillDeadline,address inputOracle,MandateOutput[] outputs)MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)"
	);

	let outputs_hash = compute_outputs_hash(&order.outputs)?;

	let mut data = Vec::new();
	data.extend_from_slice(mandate_type_hash.as_slice());

	// fillDeadline as uint32 with proper ABI padding
	let mut fill_deadline_bytes = [0u8; 32];
	fill_deadline_bytes[28..32].copy_from_slice(&order.fillDeadline.to_be_bytes());
	data.extend_from_slice(&fill_deadline_bytes);

	// inputOracle as address with proper ABI padding
	let mut oracle_bytes = [0u8; 32];
	oracle_bytes[12..32].copy_from_slice(order.inputOracle.as_slice());
	data.extend_from_slice(&oracle_bytes);

	data.extend_from_slice(outputs_hash.as_slice());

	Ok(keccak256(data))
}

/// Compute hash of all mandate outputs
pub fn compute_outputs_hash(outputs: &[MandateOutput]) -> Result<FixedBytes<32>, APIError> {
	let mut hashes = Vec::new();

	for output in outputs {
		let output_hash = compute_single_output_hash(output)?;
		hashes.extend_from_slice(output_hash.as_slice());
	}

	Ok(keccak256(hashes))
}

/// Compute hash of a single mandate output
pub fn compute_single_output_hash(output: &MandateOutput) -> Result<FixedBytes<32>, APIError> {
	let output_type_hash = keccak256(
		b"MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes callbackData,bytes context)"
	);

	let mut data = Vec::new();
	data.extend_from_slice(output_type_hash.as_slice());
	data.extend_from_slice(output.oracle.as_slice());
	data.extend_from_slice(output.settler.as_slice());
	data.extend_from_slice(&output.chainId.to_be_bytes::<32>());
	data.extend_from_slice(output.token.as_slice());
	data.extend_from_slice(&output.amount.to_be_bytes::<32>());
	data.extend_from_slice(output.recipient.as_slice());
	data.extend_from_slice(keccak256(&output.callbackData).as_slice());
	data.extend_from_slice(keccak256(&output.context).as_slice());

	Ok(keccak256(data))
}

/// Compute hash of all locks in the compact
pub fn compute_lock_hash(
	ids_and_amounts: &[[Uint<256, 4>; 2]],
) -> Result<FixedBytes<32>, APIError> {
	let mut lock_hashes = Vec::new();

	for id_amount in ids_and_amounts {
		let token_id = id_amount[0];
		let amount = id_amount[1];

		let token_id_bytes = token_id.to_be_bytes::<32>();

		// Extract lock tag (first 12 bytes)
		let mut lock_tag_bytes = [0u8; 12];
		lock_tag_bytes.copy_from_slice(&token_id_bytes[0..12]);
		let lock_tag = FixedBytes::from(lock_tag_bytes);

		// Extract token address (last 20 bytes)
		let mut token_address_bytes = [0u8; 20];
		token_address_bytes.copy_from_slice(&token_id_bytes[12..32]);
		let token_address = AlloyAddress::from(token_address_bytes);

		let lock_type_hash = keccak256(b"Lock(bytes12 lockTag,address token,uint256 amount)");

		let mut lock_data = Vec::new();
		lock_data.extend_from_slice(lock_type_hash.as_slice());

		// lock_tag as bytes12 with proper ABI padding
		let mut lock_tag_bytes = [0u8; 32];
		lock_tag_bytes[0..12].copy_from_slice(lock_tag.as_slice());
		lock_data.extend_from_slice(&lock_tag_bytes);

		// token_address as address with proper ABI padding
		let mut token_address_bytes = [0u8; 32];
		token_address_bytes[12..32].copy_from_slice(token_address.as_slice());
		lock_data.extend_from_slice(&token_address_bytes);

		lock_data.extend_from_slice(&amount.to_be_bytes::<32>());

		let lock_hash = keccak256(lock_data);
		lock_hashes.extend_from_slice(lock_hash.as_slice());
	}

	Ok(keccak256(lock_hashes))
}

/// Compute the final BatchCompact struct hash
pub fn compute_batch_compact_struct_hash(
	contract_address: AlloyAddress,
	sponsor: AlloyAddress,
	nonce: Uint<256, 4>,
	expires: Uint<256, 4>,
	lock_hash: FixedBytes<32>,
	witness: FixedBytes<32>,
) -> Result<FixedBytes<32>, APIError> {
	let batch_compact_type_hash = keccak256(
		b"BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Lock[] commitments,Mandate mandate)Lock(bytes12 lockTag,address token,uint256 amount)Mandate(uint32 fillDeadline,address inputOracle,MandateOutput[] outputs)MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)"
	);

	let mut struct_data = Vec::new();
	struct_data.extend_from_slice(batch_compact_type_hash.as_slice());

	// contract_address as arbiter
	let mut arbiter_bytes = [0u8; 32];
	arbiter_bytes[12..32].copy_from_slice(contract_address.as_slice());
	struct_data.extend_from_slice(&arbiter_bytes);

	// sponsor
	let mut sponsor_bytes = [0u8; 32];
	sponsor_bytes[12..32].copy_from_slice(sponsor.as_slice());
	struct_data.extend_from_slice(&sponsor_bytes);

	struct_data.extend_from_slice(&nonce.to_be_bytes::<32>());
	struct_data.extend_from_slice(&expires.to_be_bytes::<32>());
	struct_data.extend_from_slice(lock_hash.as_slice());
	struct_data.extend_from_slice(witness.as_slice());

	Ok(keccak256(struct_data))
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::Bytes;

	#[test]
	fn test_extract_sponsor_signature() {
		// Test case: ABI-encoded signature with sponsor and allocator signatures
		// Structure: abi.encode(sponsorSig, allocatorSig)
		// - First 32 bytes: offset to sponsorSig (0x40 = 64)
		// - Next 32 bytes: offset to allocatorSig (0x80 = 128)
		// - Next 32 bytes: length of sponsorSig (65 bytes)
		// - Next 65 bytes: actual sponsorSig data
		// - Next 32 bytes: length of allocatorSig (65 bytes)
		// - Last 65 bytes: actual allocatorSig data

		let mut abi_encoded_sig = Vec::new();

		// Offset to sponsorSig (64 bytes from start)
		abi_encoded_sig.extend_from_slice(&[0u8; 28]);
		abi_encoded_sig.extend_from_slice(&64u32.to_be_bytes());

		// Offset to allocatorSig (128 bytes from start)
		abi_encoded_sig.extend_from_slice(&[0u8; 28]);
		abi_encoded_sig.extend_from_slice(&128u32.to_be_bytes());

		// Length of sponsorSig (65 bytes)
		abi_encoded_sig.extend_from_slice(&[0u8; 28]);
		abi_encoded_sig.extend_from_slice(&65u32.to_be_bytes());

		// Sponsor signature data (65 bytes)
		let sponsor_sig_data = vec![0x11u8; 65];
		abi_encoded_sig.extend_from_slice(&sponsor_sig_data);

		// Length of allocatorSig (65 bytes)
		abi_encoded_sig.extend_from_slice(&[0u8; 28]);
		abi_encoded_sig.extend_from_slice(&65u32.to_be_bytes());

		// Allocator signature data (65 bytes)
		abi_encoded_sig.extend_from_slice(&[0x22u8; 65]);

		let signature = Bytes::from(abi_encoded_sig);
		let extracted = extract_sponsor_signature(&signature);

		// Should extract the sponsor signature (65 bytes of 0x11)
		assert_eq!(extracted.len(), 65);
		assert_eq!(extracted.to_vec(), sponsor_sig_data);

		// Test case: Raw signature (not ABI-encoded, should return as-is)
		let raw_sig = Bytes::from(vec![0x33u8; 65]);
		let extracted_raw = extract_sponsor_signature(&raw_sig);
		assert_eq!(extracted_raw, raw_sig);

		// Test case: Short signature (should return as-is)
		let short_sig = Bytes::from(vec![0x44u8; 32]);
		let extracted_short = extract_sponsor_signature(&short_sig);
		assert_eq!(extracted_short, short_sig);
	}

	#[test]
	fn test_compute_lock_hash() {
		use alloy_primitives::Uint;

		// Test case: Single lock with known values
		let token_id = Uint::<256, 4>::from(0x123456789abcdef0u64); // 12 bytes lock tag + 20 bytes token address
		let amount = Uint::<256, 4>::from(1000u64);
		let ids_and_amounts = vec![[token_id, amount]];

		let result = compute_lock_hash(&ids_and_amounts);
		assert!(result.is_ok());

		let lock_hash = result.unwrap();
		// Verify it's a valid 32-byte hash
		assert_eq!(lock_hash.len(), 32);

		// Test case: Multiple locks
		let token_id_2 = Uint::<256, 4>::from(0xfedcba9876543210u64);
		let amount_2 = Uint::<256, 4>::from(2000u64);
		let multiple_locks = vec![[token_id, amount], [token_id_2, amount_2]];

		let result_multiple = compute_lock_hash(&multiple_locks);
		assert!(result_multiple.is_ok());

		let multiple_lock_hash = result_multiple.unwrap();
		assert_eq!(multiple_lock_hash.len(), 32);

		// Different inputs should produce different hashes
		assert_ne!(lock_hash, multiple_lock_hash);

		// Test case: Empty locks array
		let empty_locks: Vec<[Uint<256, 4>; 2]> = vec![];
		let result_empty = compute_lock_hash(&empty_locks);
		assert!(result_empty.is_ok());

		let empty_hash = result_empty.unwrap();
		assert_eq!(empty_hash.len(), 32);
		assert_ne!(empty_hash, lock_hash);
	}
}
