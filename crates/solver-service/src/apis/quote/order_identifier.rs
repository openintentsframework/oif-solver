//! Pure Rust computation of StandardOrder orderIdentifier
//!
//! This module provides a native Rust implementation of the Solidity `orderIdentifier` function
//! from StandardOrderType.sol, eliminating the need for external contract calls or `cast` commands.

use alloy_primitives::{keccak256, Address as AlloyAddress, U256};
use alloy_sol_types::SolType;
use solver_types::{standards::eip7683::interfaces::SolMandateOutput, QuoteError};

/// Computes the order identifier for a StandardOrder using the same algorithm as the Solidity contract.
///
/// Equivalent to StandardOrderType.sol:
/// ```solidity
/// keccak256(
///     abi.encodePacked(
///         block.chainid,
///         address(this),
///         order.user,
///         order.nonce,
///         order.expires,
///         order.fillDeadline,
///         order.inputOracle,
///         keccak256(abi.encodePacked(order.inputs)),
///         abi.encode(order.outputs)
///     )
/// )
/// ```
pub fn compute_order_identifier(
	chain_id: u64,
	settler_address: AlloyAddress,
	user: AlloyAddress,
	nonce: U256,
	expires: u32,
	fill_deadline: u32,
	input_oracle: AlloyAddress,
	inputs: &[[U256; 2]],
	outputs: &[SolMandateOutput],
) -> Result<[u8; 32], QuoteError> {
	// 1. Hash the inputs array: keccak256(abi.encodePacked(order.inputs))
	let inputs_hash = compute_inputs_hash(inputs);

	// 2. Encode the outputs array: abi.encode(order.outputs)
	let outputs_encoded = encode_outputs(outputs)?;

	// 3. Pack all fields together and hash
	let mut packed = Vec::new();

	// Add chain_id (uint256)
	packed.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());

	// Add settler address (address - 20 bytes)
	packed.extend_from_slice(settler_address.as_slice());

	// Add user (address - 20 bytes)
	packed.extend_from_slice(user.as_slice());

	// Add nonce (uint256)
	packed.extend_from_slice(&nonce.to_be_bytes::<32>());

	// Add expires (uint32 - 4 bytes)
	packed.extend_from_slice(&expires.to_be_bytes());

	// Add fillDeadline (uint32 - 4 bytes)
	packed.extend_from_slice(&fill_deadline.to_be_bytes());

	// Add inputOracle (address - 20 bytes)
	packed.extend_from_slice(input_oracle.as_slice());

	// Add inputs hash (bytes32)
	packed.extend_from_slice(&inputs_hash);

	// Add outputs encoded (dynamic bytes)
	packed.extend_from_slice(&outputs_encoded);

	// Hash the packed data
	let order_id = keccak256(&packed);

	Ok(order_id.into())
}

/// Computes keccak256(abi.encodePacked(inputs)) where inputs is uint256[2][]
fn compute_inputs_hash(inputs: &[[U256; 2]]) -> [u8; 32] {
	let mut packed = Vec::new();

	for input in inputs {
		// Pack both U256 values (token_id and amount)
		packed.extend_from_slice(&input[0].to_be_bytes::<32>());
		packed.extend_from_slice(&input[1].to_be_bytes::<32>());
	}

	keccak256(&packed).into()
}

/// Encodes outputs array using abi.encode (not packed)
///
/// This uses proper ABI encoding with dynamic offsets and padding.
fn encode_outputs(outputs: &[SolMandateOutput]) -> Result<Vec<u8>, QuoteError> {
	// Use alloy_sol_types to properly encode the array
	// The SolType trait provides abi_encode for dynamic arrays
	let encoded = <alloy_sol_types::sol_data::Array<
		solver_types::standards::eip7683::interfaces::SolMandateOutput,
	>>::abi_encode(outputs);

	Ok(encoded)
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::{address, Bytes, FixedBytes, Uint};
	use solver_types::standards::eip7683::interfaces::SolMandateOutput;

	#[test]
	fn test_compute_inputs_hash() {
		// Test with simple inputs
		let inputs = vec![[U256::from(100), U256::from(1000)]];

		let hash = compute_inputs_hash(&inputs);

		// Should produce a 32-byte hash
		assert_eq!(hash.len(), 32);
		assert_ne!(hash, [0u8; 32]); // Should not be zero
	}

	#[test]
	fn test_compute_order_identifier_basic() {
		let chain_id = 1;
		let settler = address!("9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0");
		let user = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");
		let nonce = U256::from(1234567890);
		let expires = 1700000000u32;
		let fill_deadline = 1700000000u32;
		let input_oracle = address!("Dc64a140Aa3E981100a9becA4E685f962f0cF6C9");

		let inputs = vec![[
			U256::from_str_radix("5FbDB2315678afecb367f032d93F642f64180aa3", 16).unwrap(),
			U256::from(1_000_000_000_000_000_000u64),
		]];

		let outputs = vec![SolMandateOutput {
			oracle: FixedBytes::<32>::from_slice(&[0u8; 32]),
			settler: FixedBytes::<32>::from_slice(&[0u8; 32]),
			chainId: Uint::<256, 4>::from(137),
			token: FixedBytes::<32>::from_slice(&[0u8; 32]),
			amount: Uint::<256, 4>::from(1_000_000_000u64),
			recipient: FixedBytes::<32>::from_slice(&[0u8; 32]),
			call: Bytes::new(),
			context: Bytes::new(),
		}];

		let result = compute_order_identifier(
			chain_id,
			settler,
			user,
			nonce,
			expires,
			fill_deadline,
			input_oracle,
			&inputs,
			&outputs,
		);

		assert!(result.is_ok());
		let order_id = result.unwrap();
		assert_eq!(order_id.len(), 32);
		assert_ne!(order_id, [0u8; 32]);
	}

	#[test]
	fn test_deterministic_order_id() {
		// Same inputs should produce same order ID
		let chain_id = 1;
		let settler = address!("9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0");
		let user = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");
		let nonce = U256::from(1234567890);
		let expires = 1700000000u32;
		let fill_deadline = 1700000000u32;
		let input_oracle = address!("Dc64a140Aa3E981100a9becA4E685f962f0cF6C9");

		let inputs = vec![[U256::from(100), U256::from(1000)]];
		let outputs = vec![];

		let order_id_1 = compute_order_identifier(
			chain_id,
			settler,
			user,
			nonce,
			expires,
			fill_deadline,
			input_oracle,
			&inputs,
			&outputs,
		)
		.unwrap();

		let order_id_2 = compute_order_identifier(
			chain_id,
			settler,
			user,
			nonce,
			expires,
			fill_deadline,
			input_oracle,
			&inputs,
			&outputs,
		)
		.unwrap();

		assert_eq!(order_id_1, order_id_2);
	}

	#[test]
	fn test_different_nonces_different_ids() {
		// Different nonces should produce different order IDs
		let chain_id = 1;
		let settler = address!("9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0");
		let user = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");
		let expires = 1700000000u32;
		let fill_deadline = 1700000000u32;
		let input_oracle = address!("Dc64a140Aa3E981100a9becA4E685f962f0cF6C9");

		let inputs = vec![[U256::from(100), U256::from(1000)]];
		let outputs = vec![];

		let order_id_1 = compute_order_identifier(
			chain_id,
			settler,
			user,
			U256::from(1),
			expires,
			fill_deadline,
			input_oracle,
			&inputs,
			&outputs,
		)
		.unwrap();

		let order_id_2 = compute_order_identifier(
			chain_id,
			settler,
			user,
			U256::from(2),
			expires,
			fill_deadline,
			input_oracle,
			&inputs,
			&outputs,
		)
		.unwrap();

		assert_ne!(order_id_1, order_id_2);
	}
}
