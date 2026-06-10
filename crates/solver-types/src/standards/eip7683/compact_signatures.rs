//! TheCompact signature payload decoding.
//!
//! Compact `finalise` expects `abi.encode(bytes sponsorSig, bytes allocatorData)`.
//! This decoder accepts only the canonical two-element dynamic bytes layout so
//! off-chain validation and on-chain decoding cannot disagree about which bytes
//! are the sponsor signature.

use alloy_primitives::{keccak256, Address as AlloyAddress, Bytes, FixedBytes};
use alloy_signer::Signature;

use crate::{APIError, ApiErrorType};

/// Decoded Compact signature tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactSignatures {
	/// Sponsor EIP-712 signature bytes.
	pub sponsor: Bytes,
	/// Allocator authorization bytes.
	pub allocator_data: Bytes,
}

/// Decode canonical `abi.encode(bytes sponsorSig, bytes allocatorData)`.
pub fn decode_compact_signatures(signature: &Bytes) -> Result<CompactSignatures, APIError> {
	if signature.len() < 64 {
		return invalid_compact_signature(
			"Compact signature payload must contain two ABI head words",
		);
	}

	let sponsor_offset = read_word_usize(signature, 0)?;
	let allocator_offset = read_word_usize(signature, 32)?;
	if sponsor_offset != 64 {
		return invalid_compact_signature("Compact sponsor signature offset is not canonical");
	}

	let (sponsor, sponsor_padded_end) = decode_bytes_at(signature, sponsor_offset)?;
	if allocator_offset != sponsor_padded_end {
		return invalid_compact_signature("Compact allocator data offset is not canonical");
	}

	let (allocator_data, allocator_padded_end) = decode_bytes_at(signature, allocator_offset)?;
	if allocator_padded_end != signature.len() {
		return invalid_compact_signature("Compact signature payload has trailing data");
	}

	Ok(CompactSignatures {
		sponsor,
		allocator_data,
	})
}

fn decode_bytes_at(signature: &Bytes, offset: usize) -> Result<(Bytes, usize), APIError> {
	if offset < 64 || offset % 32 != 0 || offset > signature.len() {
		return invalid_compact_signature("Compact bytes offset is invalid");
	}

	let length_word_end = checked_add(offset, 32)?;
	if length_word_end > signature.len() {
		return invalid_compact_signature("Compact bytes length word is out of bounds");
	}

	let length = read_word_usize(signature, offset)?;
	let data_start = length_word_end;
	let data_end = checked_add(data_start, length)?;
	if data_end > signature.len() {
		return invalid_compact_signature("Compact bytes data is out of bounds");
	}

	let padded_end = checked_add(data_start, padded_len(length)?)?;
	if padded_end > signature.len() {
		return invalid_compact_signature("Compact bytes padding is out of bounds");
	}

	Ok((
		Bytes::copy_from_slice(&signature[data_start..data_end]),
		padded_end,
	))
}

fn read_word_usize(bytes: &Bytes, offset: usize) -> Result<usize, APIError> {
	let end = checked_add(offset, 32)?;
	if end > bytes.len() {
		return invalid_compact_signature("Compact ABI word is out of bounds");
	}

	let word = &bytes[offset..end];
	if word[..24].iter().any(|byte| *byte != 0) {
		return invalid_compact_signature("Compact ABI word exceeds usize range");
	}

	let mut value = [0u8; 8];
	value.copy_from_slice(&word[24..32]);
	Ok(u64::from_be_bytes(value) as usize)
}

fn padded_len(length: usize) -> Result<usize, APIError> {
	let with_padding = checked_add(length, 31)?;
	Ok(with_padding & !31)
}

fn checked_add(left: usize, right: usize) -> Result<usize, APIError> {
	left.checked_add(right)
		.ok_or_else(|| invalid_compact_signature_error("Compact signature payload length overflow"))
}

fn invalid_compact_signature<T>(message: &str) -> Result<T, APIError> {
	Err(invalid_compact_signature_error(message))
}

fn invalid_compact_signature_error(message: &str) -> APIError {
	APIError::BadRequest {
		error_type: ApiErrorType::OrderValidationFailed,
		message: message.to_string(),
		details: None,
	}
}

/// Verify a sponsor's EIP-712 signature over a BatchCompact claim.
///
/// Recomputes the EIP-712 digest (`keccak256(0x1901 || domainSeparator ||
/// structHash)`), recovers the signer from `sponsor_signature`, and checks it
/// equals `expected_signer` (the order's `user`).
///
/// `domain_separator` is `TheCompact.DOMAIN_SEPARATOR()`; `struct_hash` is the
/// BatchCompact claim hash (see [`compute_batch_compact_claim_hash`]).
/// `sponsor_signature` is the canonical sponsor signature decoded from the
/// Compact payload by [`decode_compact_signatures`].
///
/// This is the single shared sponsor-signature check used by both `/orders`
/// intake (solver-service) and direct discovery `/intent` intake
/// (solver-discovery), so the two paths cannot disagree on which key must have
/// signed the order.
///
/// [`compute_batch_compact_claim_hash`]: super::compact_claims::compute_batch_compact_claim_hash
pub fn verify_compact_sponsor_signature(
	domain_separator: FixedBytes<32>,
	struct_hash: FixedBytes<32>,
	sponsor_signature: &Bytes,
	expected_signer: AlloyAddress,
) -> Result<(), APIError> {
	let digest = keccak256(
		[
			&[0x19, 0x01][..],
			domain_separator.as_slice(),
			struct_hash.as_slice(),
		]
		.concat(),
	);

	let signature = Signature::try_from(sponsor_signature.as_ref()).map_err(|e| {
		invalid_compact_signature_error(&format!("Invalid sponsor signature format: {e}"))
	})?;

	let recovered = signature
		.recover_address_from_prehash(&digest)
		.map_err(|e| {
			invalid_compact_signature_error(&format!("Failed to recover sponsor signer: {e}"))
		})?;

	if recovered != expected_signer {
		return Err(invalid_compact_signature_error(
			"Sponsor EIP-712 signature does not match the order user",
		));
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

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

	fn encode_compact_signature(sponsor: &[u8], allocator_data: &[u8]) -> Bytes {
		let sponsor_tail = padded_bytes(sponsor);
		let allocator_offset = 64 + sponsor_tail.len();

		let mut encoded = Vec::new();
		encoded.extend_from_slice(&abi_word(64));
		encoded.extend_from_slice(&abi_word(allocator_offset));
		encoded.extend_from_slice(&sponsor_tail);
		encoded.extend_from_slice(&padded_bytes(allocator_data));
		Bytes::from(encoded)
	}

	#[test]
	fn verify_compact_sponsor_signature_rejects_malformed_signature() {
		// A signature that is not 65 bytes cannot be parsed and must be rejected
		// rather than silently passing or panicking.
		let err = verify_compact_sponsor_signature(
			FixedBytes::from([0x99u8; 32]),
			FixedBytes::from([0x11u8; 32]),
			&Bytes::from(vec![0u8; 10]),
			AlloyAddress::from([0x22u8; 20]),
		)
		.expect_err("malformed signature must be rejected");
		match err {
			APIError::BadRequest { message, .. } => {
				assert!(
					message.contains("Invalid sponsor signature format")
						|| message.contains("Failed to recover sponsor signer"),
					"unexpected message: {message}"
				);
			},
			other => panic!("unexpected error: {other:?}"),
		}
	}

	#[test]
	fn verify_compact_sponsor_signature_rejects_signer_mismatch() {
		// A well-formed 65-byte signature that recovers to some address must be
		// rejected when that address is not the expected signer. Using an all-ones
		// signature with v=27 recovers to *some* deterministic address that will
		// not equal the zero-ish expected signer below.
		let mut sig = vec![0x11u8; 65];
		sig[64] = 27;
		let err = verify_compact_sponsor_signature(
			FixedBytes::from([0x99u8; 32]),
			FixedBytes::from([0x11u8; 32]),
			&Bytes::from(sig),
			AlloyAddress::ZERO,
		)
		.expect_err("signer mismatch must be rejected");
		match err {
			APIError::BadRequest { message, .. } => {
				assert!(
					message.contains("does not match the order user")
						|| message.contains("Failed to recover sponsor signer"),
					"unexpected message: {message}"
				);
			},
			other => panic!("unexpected error: {other:?}"),
		}
	}

	#[test]
	fn compact_signature_accepts_canonical_empty_allocator() {
		let sponsor = vec![0x11u8; 65];
		let signature = encode_compact_signature(&sponsor, &[]);

		let decoded = decode_compact_signatures(&signature).unwrap();

		assert_eq!(decoded.sponsor.to_vec(), sponsor);
		assert_eq!(decoded.allocator_data.to_vec(), Vec::<u8>::new());
	}

	#[test]
	fn compact_signature_accepts_canonical_non_empty_allocator() {
		let sponsor = vec![0x11u8; 65];
		let allocator_data = vec![0x22u8, 0x33, 0x44];
		let signature = encode_compact_signature(&sponsor, &allocator_data);

		let decoded = decode_compact_signatures(&signature).unwrap();

		assert_eq!(decoded.sponsor.to_vec(), sponsor);
		assert_eq!(decoded.allocator_data.to_vec(), allocator_data);
	}

	#[test]
	fn compact_signature_handles_sponsor_padding_boundaries() {
		for sponsor_len in [64usize, 70usize] {
			let sponsor = vec![0x11u8; sponsor_len];
			let allocator_data = vec![0x22u8; 3];
			let signature = encode_compact_signature(&sponsor, &allocator_data);

			let decoded = decode_compact_signatures(&signature).unwrap();

			assert_eq!(decoded.sponsor.to_vec(), sponsor);
			assert_eq!(decoded.allocator_data.to_vec(), allocator_data);
		}
	}

	#[test]
	fn compact_signature_rejects_shifted_sponsor_offset() {
		let valid_fixed_offset_sponsor = vec![0x11u8; 65];
		let actual_sponsor = vec![0x44u8; 65];
		let fake_fixed_offset_tail = padded_bytes(&valid_fixed_offset_sponsor);
		let actual_sponsor_offset = 64 + fake_fixed_offset_tail.len();
		let actual_sponsor_tail = padded_bytes(&actual_sponsor);
		let allocator_offset = actual_sponsor_offset + actual_sponsor_tail.len();

		let mut shifted_payload = Vec::new();
		shifted_payload.extend_from_slice(&abi_word(actual_sponsor_offset));
		shifted_payload.extend_from_slice(&abi_word(allocator_offset));
		shifted_payload.extend_from_slice(&fake_fixed_offset_tail);
		shifted_payload.extend_from_slice(&actual_sponsor_tail);
		shifted_payload.extend_from_slice(&padded_bytes(&[]));

		assert!(decode_compact_signatures(&Bytes::from(shifted_payload)).is_err());
	}

	#[test]
	fn compact_signature_rejects_raw_signature() {
		let raw_sig = Bytes::from(vec![0x33u8; 65]);

		assert!(decode_compact_signatures(&raw_sig).is_err());
	}

	#[test]
	fn compact_signature_rejects_truncated_tail() {
		let mut signature = encode_compact_signature(&[0x11u8; 65], &[0x22u8; 3]).to_vec();
		signature.truncate(signature.len() - 1);

		assert!(decode_compact_signatures(&Bytes::from(signature)).is_err());
	}

	#[test]
	fn compact_signature_rejects_trailing_data() {
		let mut signature = encode_compact_signature(&[0x11u8; 65], &[]).to_vec();
		signature.extend_from_slice(&[0u8; 32]);

		assert!(decode_compact_signatures(&Bytes::from(signature)).is_err());
	}
}
