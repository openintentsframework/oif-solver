//! TheCompact BatchCompact claim-hash computation.
//!
//! Computes the EIP-712 BatchCompact struct hash — the claim hash an allocator's
//! `authorizeClaim` / `isClaimAuthorized` receives (pre domain-separator) and the
//! hash a sponsor signs — for an OIF `StandardOrder`.
//!
//! Matches `openintentsframework/oif-contracts` release-v1.0.0 (the-compact
//! submodule `b9c3b54`). Verified byte-exact by the parity test in this module and
//! by the `solver-service` wrapper test on `compute_batch_compact_hash`. This is the
//! single shared implementation used by both `/orders` intake (solver-service) and
//! direct discovery intake (solver-discovery), so the two paths cannot diverge.

use alloy_primitives::{keccak256, Address, FixedBytes, Uint};

use crate::standards::eip7683::interfaces::{SolMandateOutput, StandardOrder};
use crate::APIError;

/// Compute the BatchCompact claim hash (EIP-712 struct hash) for a `StandardOrder`.
///
/// `arbiter` is the account that calls `TheCompact.batchClaim` during finalisation,
/// i.e. the `InputSettlerCompact` address.
pub fn compute_batch_compact_claim_hash(
	order: &StandardOrder,
	arbiter: Address,
) -> Result<FixedBytes<32>, APIError> {
	let witness_hash = compute_witness_hash(order)?;
	let lock_hash = compute_lock_hash(&order.inputs)?;
	compute_batch_compact_struct_hash(
		arbiter,
		order.user,
		order.nonce,
		Uint::<256, 4>::from(order.expires),
		lock_hash,
		witness_hash,
	)
}

/// Compute witness hash for TheCompact mandate.
fn compute_witness_hash(order: &StandardOrder) -> Result<FixedBytes<32>, APIError> {
	let mandate_type_hash = keccak256(
		b"Mandate(uint32 fillDeadline,address inputOracle,MandateOutput[] outputs)MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes callbackData,bytes context)"
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

/// Compute hash of all mandate outputs.
fn compute_outputs_hash(outputs: &[SolMandateOutput]) -> Result<FixedBytes<32>, APIError> {
	let mut hashes = Vec::new();

	for output in outputs {
		let output_hash = compute_single_output_hash(output)?;
		hashes.extend_from_slice(output_hash.as_slice());
	}

	Ok(keccak256(hashes))
}

/// Compute hash of a single mandate output.
fn compute_single_output_hash(output: &SolMandateOutput) -> Result<FixedBytes<32>, APIError> {
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

/// Compute hash of all locks in the compact (`Lock[] commitments`).
fn compute_lock_hash(ids_and_amounts: &[[Uint<256, 4>; 2]]) -> Result<FixedBytes<32>, APIError> {
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
		let token_address = Address::from(token_address_bytes);

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

/// Compute the final BatchCompact struct hash.
fn compute_batch_compact_struct_hash(
	arbiter: Address,
	sponsor: Address,
	nonce: Uint<256, 4>,
	expires: Uint<256, 4>,
	lock_hash: FixedBytes<32>,
	witness: FixedBytes<32>,
) -> Result<FixedBytes<32>, APIError> {
	let batch_compact_type_hash = keccak256(
		b"BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Lock[] commitments,Mandate mandate)Lock(bytes12 lockTag,address token,uint256 amount)Mandate(uint32 fillDeadline,address inputOracle,MandateOutput[] outputs)MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes callbackData,bytes context)"
	);

	let mut struct_data = Vec::new();
	struct_data.extend_from_slice(batch_compact_type_hash.as_slice());

	// arbiter as address with proper ABI padding
	let mut arbiter_bytes = [0u8; 32];
	arbiter_bytes[12..32].copy_from_slice(arbiter.as_slice());
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
	use alloy_primitives::{Bytes, U256};

	#[test]
	fn test_compute_lock_hash() {
		let token_id = Uint::<256, 4>::from(0x123456789abcdef0u64);
		let amount = Uint::<256, 4>::from(1000u64);
		let ids_and_amounts = vec![[token_id, amount]];

		let lock_hash = compute_lock_hash(&ids_and_amounts).unwrap();
		assert_eq!(lock_hash.len(), 32);

		let token_id_2 = Uint::<256, 4>::from(0xfedcba9876543210u64);
		let amount_2 = Uint::<256, 4>::from(2000u64);
		let multiple_locks = vec![[token_id, amount], [token_id_2, amount_2]];
		let multiple_lock_hash = compute_lock_hash(&multiple_locks).unwrap();
		assert_eq!(multiple_lock_hash.len(), 32);
		assert_ne!(lock_hash, multiple_lock_hash);

		let empty_locks: Vec<[Uint<256, 4>; 2]> = vec![];
		let empty_hash = compute_lock_hash(&empty_locks).unwrap();
		assert_eq!(empty_hash.len(), 32);
		assert_ne!(empty_hash, lock_hash);
	}

	/// pC-02 Task 0 parity gate (shared helper): the claim hash must match the
	/// official `openintentsframework/oif-contracts` release-v1.0.0 value
	/// (the-compact `b9c3b54`). Vector generated from the official
	/// `InputSettlerCompact.base.t.sol` BatchCompact struct-hash formula.
	#[test]
	fn compute_batch_compact_claim_hash_matches_official_release_v1_0_0_vector() {
		// token_id = lockTag(12 bytes) || token(20 bytes)
		let id_fb: FixedBytes<32> =
			"0x0102030405060708090a0b0c4444444444444444444444444444444444444444"
				.parse()
				.unwrap();
		let id = U256::from_be_bytes(id_fb.0);

		// bytes32(uint256(v)) — left-padded
		let b32 = |v: u64| FixedBytes::<32>::from(U256::from(v).to_be_bytes::<32>());

		let output = SolMandateOutput {
			oracle: b32(0xAAAA),
			settler: b32(0xBBBB),
			chainId: U256::from(10u64),
			token: b32(0xCCCC),
			amount: U256::from(555u64),
			recipient: b32(0xDDDD),
			callbackData: Bytes::new(),
			context: Bytes::new(),
		};

		let order = StandardOrder {
			user: Address::from([0x22u8; 20]),
			nonce: U256::from(1u64),
			originChainId: U256::from(31337u64),
			expires: 2_000_000_000u32,
			fillDeadline: 1_700_000_000u32,
			inputOracle: Address::from([0x33u8; 20]),
			inputs: vec![[id, U256::from(123456789u64)]],
			outputs: vec![output],
		};

		let got =
			compute_batch_compact_claim_hash(&order, Address::from([0x11u8; 20])).expect("hash");
		let expected: FixedBytes<32> =
			"0x2142968938e7f2f2a043a1c4a6873e981c18871d77168a7818edf6d2fef10efd"
				.parse()
				.unwrap();

		assert_eq!(
			got, expected,
			"shared BatchCompact claim hash must match official release-v1.0.0 value"
		);
	}
}
