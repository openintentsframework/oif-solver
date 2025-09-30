//! Pure Rust computation of StandardOrder orderIdentifier
//!
//! This module provides a native Rust implementation of the Solidity `orderIdentifier` function
//! from StandardOrderType.sol, eliminating the need for external contract calls or `cast` commands.

use alloy_primitives::{keccak256, Address as AlloyAddress};
use alloy_sol_types::SolValue;
use solver_types::{standards::eip7683::interfaces::StandardOrder as SolStandardOrder, QuoteError};

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
///
/// # Arguments
/// * `chain_id` - The chain ID where the order will be executed
/// * `settler_address` - The address of the settler contract (address(this) in Solidity)
/// * `order` - The StandardOrder struct containing all order details
///
/// # Returns
/// The 32-byte order identifier hash
pub fn compute_order_identifier(
	chain_id: u64,
	settler_address: AlloyAddress,
	order: &SolStandardOrder,
) -> Result<[u8; 32], QuoteError> {
	// 1. Hash the inputs array: keccak256(abi.encodePacked(order.inputs))
	let inputs_hash = compute_inputs_hash(&order.inputs);

	// 2. Encode the outputs array: abi.encode(order.outputs)
	let outputs_encoded = encode_outputs(&order.outputs)?;

	// 3. Pack all fields together and hash
	let mut packed = Vec::new();

	// Add chain_id (uint256 - 32 bytes)
	packed.extend_from_slice(&alloy_primitives::U256::from(chain_id).to_be_bytes::<32>());

	// Add settler address (address - 20 bytes)
	packed.extend_from_slice(settler_address.as_slice());

	// Add user (address - 20 bytes)
	packed.extend_from_slice(order.user.as_slice());

	// Add nonce (uint256 - 32 bytes)
	packed.extend_from_slice(&order.nonce.to_be_bytes::<32>());

	// Add expires (uint32 - 4 bytes)
	packed.extend_from_slice(&order.expires.to_be_bytes());

	// Add fillDeadline (uint32 - 4 bytes)
	packed.extend_from_slice(&order.fillDeadline.to_be_bytes());

	// Add inputOracle (address - 20 bytes)
	packed.extend_from_slice(order.inputOracle.as_slice());

	// Add inputs hash (bytes32 - 32 bytes)
	packed.extend_from_slice(&inputs_hash);

	// Add outputs encoded (dynamic bytes)
	packed.extend_from_slice(&outputs_encoded);

	// Hash the packed data
	let order_id = keccak256(&packed);

	Ok(order_id.into())
}

/// Computes keccak256(abi.encodePacked(inputs)) where inputs is uint256[2][]
fn compute_inputs_hash(inputs: &[[alloy_primitives::U256; 2]]) -> [u8; 32] {
	let mut packed = Vec::new();

	for input in inputs {
		// Each input is [token_id: U256, amount: U256]
		packed.extend_from_slice(&input[0].to_be_bytes::<32>());
		packed.extend_from_slice(&input[1].to_be_bytes::<32>());
	}

	keccak256(&packed).into()
}

/// Encodes outputs array using abi.encode (not packed)
///
/// This uses proper ABI encoding with dynamic offsets and padding.
fn encode_outputs(
	outputs: &[solver_types::standards::eip7683::interfaces::SolMandateOutput],
) -> Result<Vec<u8>, QuoteError> {
	// Use alloy_sol_types to properly encode the array
	let encoded = outputs.abi_encode();
	Ok(encoded)
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::{address, Bytes, FixedBytes, Uint};
	use solver_types::standards::eip7683::interfaces::SolMandateOutput;

	fn create_test_order() -> SolStandardOrder {
		// Token address: 0x5FbDB2315678afecb367f032d93F642f64180aa3
		let token_id =
			Uint::<256, 4>::from_str_radix("5FbDB2315678afecb367f032d93F642f64180aa3", 16).unwrap();
		// Amount: 1 ether (1000000000000000000 wei)
		let amount = Uint::<256, 4>::from(1_000_000_000_000_000_000u64);

		SolStandardOrder {
			user: address!("70997970C51812dc3A010C7d01b50e0d17dc79C8"),
			nonce: Uint::<256, 4>::from(1234567890u64),
			originChainId: Uint::<256, 4>::from(1),
			expires: 1700000000u32,
			fillDeadline: 1700000000u32,
			inputOracle: address!("Dc64a140Aa3E981100a9becA4E685f962f0cF6C9"),
			inputs: vec![[token_id, amount]],
			outputs: vec![SolMandateOutput {
				oracle: FixedBytes::<32>::ZERO,
				settler: FixedBytes::<32>::ZERO,
				chainId: Uint::<256, 4>::from(137),
				token: FixedBytes::<32>::ZERO,
				amount: Uint::<256, 4>::from(1_000_000_000u64),
				recipient: FixedBytes::<32>::ZERO,
				call: Bytes::new(),
				context: Bytes::new(),
			}],
		}
	}

	#[test]
	fn test_compute_order_identifier() {
		let chain_id = 1;
		let settler = address!("9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0");
		let order = create_test_order();

		let result = compute_order_identifier(chain_id, settler, &order);

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
		let order = create_test_order();

		let order_id_1 = compute_order_identifier(chain_id, settler, &order).unwrap();
		let order_id_2 = compute_order_identifier(chain_id, settler, &order).unwrap();

		assert_eq!(order_id_1, order_id_2);
	}

	#[test]
	fn test_different_nonces_different_ids() {
		// Different nonces should produce different order IDs
		let chain_id = 1;
		let settler = address!("9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0");

		let mut order1 = create_test_order();
		order1.nonce = Uint::<256, 4>::from(1);

		let mut order2 = create_test_order();
		order2.nonce = Uint::<256, 4>::from(2);

		let order_id_1 = compute_order_identifier(chain_id, settler, &order1).unwrap();
		let order_id_2 = compute_order_identifier(chain_id, settler, &order2).unwrap();

		assert_ne!(order_id_1, order_id_2);
	}

	#[test]
	fn test_different_chains_different_ids() {
		// Different chain IDs should produce different order IDs
		let settler = address!("9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0");
		let order = create_test_order();

		let order_id_1 = compute_order_identifier(1, settler, &order).unwrap();
		let order_id_2 = compute_order_identifier(137, settler, &order).unwrap();

		assert_ne!(order_id_1, order_id_2);
	}

	#[test]
	fn test_different_settlers_different_ids() {
		// Different settler addresses should produce different order IDs
		let chain_id = 1;
		let order = create_test_order();

		let settler1 = address!("9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0");
		let settler2 = address!("CfE46736679d2D9a65F0992F2272dE9f3c7fa6e0");

		let order_id_1 = compute_order_identifier(chain_id, settler1, &order).unwrap();
		let order_id_2 = compute_order_identifier(chain_id, settler2, &order).unwrap();

		assert_ne!(order_id_1, order_id_2);
	}

	#[test]
	fn test_compute_inputs_hash() {
		// Test with simple input
		let inputs = vec![[Uint::<256, 4>::from(100), Uint::<256, 4>::from(1000)]];

		let hash = compute_inputs_hash(&inputs);

		// Should produce a 32-byte hash
		assert_eq!(hash.len(), 32);
		assert_ne!(hash, [0u8; 32]); // Should not be zero
	}
}
