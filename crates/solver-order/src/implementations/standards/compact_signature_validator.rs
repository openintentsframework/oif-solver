//! Compact signature validation for ResourceLock orders.
//!
//! This module implements signature validation for The Compact protocol orders,
//! ensuring that signatures are valid and created by the expected user before
//! attempting to fill the order.

use alloy_primitives::{keccak256, Address as AlloyAddress, Bytes, FixedBytes, Uint};
use secp256k1::{
	ecdsa::{RecoverableSignature, RecoveryId},
	Message, Secp256k1,
};
use solver_types::standards::eip7683::interfaces::{
	SolMandateOutput as MandateOutput, StandardOrder as OifStandardOrder,
};

// TheCompact contract interface is defined in solver-types

/// Validation result for compact signature validation
#[derive(Debug)]
pub struct ValidationResult {
	pub valid: bool,
	pub order_id: FixedBytes<32>,
	pub witness_hash: FixedBytes<32>,
	pub recovered_signer: AlloyAddress,
}

/// Compact signature validator for ResourceLock orders
pub struct CompactSignatureValidator {
	pub domain_separator: FixedBytes<32>,
	pub contract_address: AlloyAddress,
}

impl CompactSignatureValidator {
	/// Create a new CompactSignatureValidator
	pub fn new(domain_separator: FixedBytes<32>, contract_address: AlloyAddress) -> Self {
		Self {
			domain_separator,
			contract_address,
		}
	}

	/// Validate that the signature was created by the expected user
	/// This is the production version - no private key needed!
	pub fn validate_compact_signature(
		&self,
		order: &OifStandardOrder,
		signature: &Bytes,
		expected_signer: AlloyAddress, // The user who should have signed
	) -> Result<bool, String> {
		// 1. Compute the message hash that was signed
		let message_hash = self.compute_batch_compact_message_hash(order)?;

		// 2. Recover the signer from the signature
		let recovered_signer = self.recover_signer(message_hash, signature)?;

		// 3. Check if the recovered signer matches the expected signer
		let is_valid = recovered_signer == expected_signer;

		Ok(is_valid)
	}

	/// Compute the complete BatchCompact message hash
	fn compute_batch_compact_message_hash(
		&self,
		order: &OifStandardOrder,
	) -> Result<FixedBytes<32>, String> {
		// 1. Compute witness hash
		let witness_hash = self.compute_witness_hash(order)?;

		// 2. Prepare idsAndAmounts from order.inputs
		let ids_and_amounts = self.prepare_ids_and_amounts(&order.inputs);

		// 3. Compute lock hash
		let lock_hash = self.compute_lock_hash(&ids_and_amounts)?;

		// 4. Compute the EIP-712 message hash

		let message_hash = self.compute_batch_compact_message_hash_internal(
			order.user,
			order.nonce,
			Uint::<256, 4>::from(order.expires),
			lock_hash,
			witness_hash,
		)?;

		Ok(message_hash)
	}

	/// Compute witness hash (matches Solidity exactly)
	fn compute_witness_hash(&self, order: &OifStandardOrder) -> Result<FixedBytes<32>, String> {
		let mandate_type_hash = keccak256(
            b"Mandate(uint32 fillDeadline,address inputOracle,MandateOutput[] outputs)MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)"
        );

		let outputs_hash = self.compute_outputs_hash(&order.outputs)?;

		// Use proper ABI encoding like the shell script: f(bytes32,uint32,address,bytes32)
		let mut data = Vec::new();
		data.extend_from_slice(mandate_type_hash.as_slice()); // bytes32

		// fillDeadline as uint32 with proper ABI padding (leading zeros)
		let mut fill_deadline_bytes = [0u8; 32];
		fill_deadline_bytes[28..32].copy_from_slice(&order.fillDeadline.to_be_bytes());
		data.extend_from_slice(&fill_deadline_bytes); // uint32 encoded as 32 bytes

		// inputOracle as address with proper ABI padding (12 leading zero bytes + 20 address bytes)
		let mut oracle_bytes = [0u8; 32];
		oracle_bytes[12..32].copy_from_slice(order.inputOracle.as_slice());
		data.extend_from_slice(&oracle_bytes); // address encoded as 32 bytes

		data.extend_from_slice(outputs_hash.as_slice()); // bytes32

		Ok(keccak256(data))
	}

	/// Compute outputs hash
	fn compute_outputs_hash(&self, outputs: &[MandateOutput]) -> Result<FixedBytes<32>, String> {
		let mut hashes = Vec::new();

		for output in outputs {
			let output_hash = self.compute_single_output_hash(output)?;
			hashes.extend_from_slice(output_hash.as_slice());
		}

		Ok(keccak256(hashes))
	}

	/// Compute single output hash
	fn compute_single_output_hash(&self, output: &MandateOutput) -> Result<FixedBytes<32>, String> {
		let output_type_hash = keccak256(
            b"MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)"
        );

		let mut data = Vec::new();
		data.extend_from_slice(output_type_hash.as_slice());
		data.extend_from_slice(output.oracle.as_slice());
		data.extend_from_slice(output.settler.as_slice());
		data.extend_from_slice(&output.chainId.to_be_bytes::<32>());
		data.extend_from_slice(output.token.as_slice());
		data.extend_from_slice(&output.amount.to_be_bytes::<32>());
		data.extend_from_slice(output.recipient.as_slice());
		data.extend_from_slice(keccak256(&output.call).as_slice());
		data.extend_from_slice(keccak256(&output.context).as_slice());

		Ok(keccak256(data))
	}

	/// Prepare idsAndAmounts from order inputs
	fn prepare_ids_and_amounts(&self, inputs: &[[Uint<256, 4>; 2]]) -> Vec<[Uint<256, 4>; 2]> {
		inputs.to_vec()
	}

	/// Compute lock hash - simplified version for now
	/// TODO: Integrate with The Compact contract to get actual lock details
	fn compute_lock_hash(
		&self,
		ids_and_amounts: &[[Uint<256, 4>; 2]],
	) -> Result<FixedBytes<32>, String> {
		let mut lock_hashes = Vec::new();

		for id_amount in ids_and_amounts {
			let token_id = id_amount[0];
			let amount = id_amount[1];

			// Extract lock tag and token address from the token ID
			// Token ID format: [12 bytes lock_tag][20 bytes token_address]
			let token_id_bytes = token_id.to_be_bytes::<32>();

			// Extract lock tag (first 12 bytes of the token ID)
			let mut lock_tag_bytes = [0u8; 12];
			lock_tag_bytes.copy_from_slice(&token_id_bytes[0..12]);
			let lock_tag = FixedBytes::from(lock_tag_bytes);

			// Extract token address (last 20 bytes of the token ID)
			let mut token_address_bytes = [0u8; 20];
			token_address_bytes.copy_from_slice(&token_id_bytes[12..32]);
			let token_address = AlloyAddress::from(token_address_bytes);

			let lock_type_hash = keccak256(b"Lock(bytes12 lockTag,address token,uint256 amount)");

			// Use proper ABI encoding like the shell script: f(bytes32,bytes12,address,uint256)
			let mut lock_data = Vec::new();
			lock_data.extend_from_slice(lock_type_hash.as_slice()); // bytes32

			// lock_tag as bytes12 with proper ABI padding (12 lock tag bytes + 20 trailing zero bytes)
			let mut lock_tag_bytes = [0u8; 32];
			lock_tag_bytes[0..12].copy_from_slice(lock_tag.as_slice());
			lock_data.extend_from_slice(&lock_tag_bytes); // bytes12 encoded as 32 bytes

			// token_address as address with proper ABI padding (12 leading zero bytes + 20 address bytes)
			let mut token_address_bytes = [0u8; 32];
			token_address_bytes[12..32].copy_from_slice(token_address.as_slice());
			lock_data.extend_from_slice(&token_address_bytes); // address encoded as 32 bytes

			lock_data.extend_from_slice(&amount.to_be_bytes::<32>()); // uint256

			let lock_hash = keccak256(lock_data);
			lock_hashes.extend_from_slice(lock_hash.as_slice());
		}

		Ok(keccak256(lock_hashes))
	}

	/// Compute BatchCompact message hash (internal)
	fn compute_batch_compact_message_hash_internal(
		&self,
		sponsor: AlloyAddress,
		nonce: Uint<256, 4>,
		expires: Uint<256, 4>,
		lock_hash: FixedBytes<32>,
		witness: FixedBytes<32>,
	) -> Result<FixedBytes<32>, String> {
		let batch_compact_type_hash = keccak256(
            b"BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Lock[] commitments,Mandate mandate)Lock(bytes12 lockTag,address token,uint256 amount)Mandate(uint32 fillDeadline,address inputOracle,MandateOutput[] outputs)MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)"
        );

		// Use proper ABI encoding like the shell script: f(bytes32,address,address,uint256,uint256,bytes32,bytes32)
		let mut struct_data = Vec::new();
		struct_data.extend_from_slice(batch_compact_type_hash.as_slice()); // bytes32

		// contract_address as address with proper ABI padding (12 leading zero bytes + 20 address bytes)
		let mut arbiter_bytes = [0u8; 32];
		arbiter_bytes[12..32].copy_from_slice(self.contract_address.as_slice());
		struct_data.extend_from_slice(&arbiter_bytes); // address encoded as 32 bytes

		// sponsor as address with proper ABI padding (12 leading zero bytes + 20 address bytes)
		let mut sponsor_bytes = [0u8; 32];
		sponsor_bytes[12..32].copy_from_slice(sponsor.as_slice());
		struct_data.extend_from_slice(&sponsor_bytes); // address encoded as 32 bytes

		struct_data.extend_from_slice(&nonce.to_be_bytes::<32>()); // uint256
		struct_data.extend_from_slice(&expires.to_be_bytes::<32>()); // uint256
		struct_data.extend_from_slice(lock_hash.as_slice()); // bytes32
		struct_data.extend_from_slice(witness.as_slice()); // bytes32

		let struct_hash = keccak256(struct_data);

		let mut data = Vec::new();
		data.extend_from_slice(b"\x19\x01");
		data.extend_from_slice(self.domain_separator.as_slice());
		data.extend_from_slice(struct_hash.as_slice());

		Ok(keccak256(data))
	}

	/// Recover signer from signature - PRODUCTION METHOD
	pub fn recover_signer(
		&self,
		message_hash: FixedBytes<32>,
		signature: &Bytes,
	) -> Result<AlloyAddress, String> {
		if signature.len() != 65 {
			return Err(format!(
				"Invalid signature length: expected 65 bytes, got {}",
				signature.len()
			));
		}

		let secp = Secp256k1::new();
		let message = Message::from_digest_slice(message_hash.as_slice())
			.map_err(|e| format!("Invalid message: {}", e))?;

		// Parse signature components (r, s, v)
		let mut sig_bytes = [0u8; 64];
		sig_bytes[..32].copy_from_slice(&signature[0..32]); // r
		sig_bytes[32..].copy_from_slice(&signature[32..64]); // s

		// Extract recovery ID from the last byte
		// Handle both standard v values (27/28) and EIP-155 style (0/1)
		let recovery_byte = signature[64];
		let recovery_id = if recovery_byte >= 27 {
			RecoveryId::try_from((recovery_byte - 27) as i32)
		} else {
			RecoveryId::try_from(recovery_byte as i32)
		}
		.map_err(|e| format!("Invalid recovery ID {}: {}", recovery_byte, e))?;

		// Create recoverable signature
		let recoverable_sig = RecoverableSignature::from_compact(&sig_bytes, recovery_id)
			.map_err(|e| format!("Invalid signature: {}", e))?;

		// Recover public key
		let public_key = secp
			.recover_ecdsa(&message, &recoverable_sig)
			.map_err(|e| format!("Recovery failed: {}", e))?;

		// Convert public key to address
		let public_key_bytes = public_key.serialize_uncompressed();
		let address_hash = keccak256(&public_key_bytes[1..]);
		Ok(AlloyAddress::from_slice(&address_hash[12..]))
	}

	/// Complete order validation for production
	pub fn validate_order_production(
		&self,
		order: &OifStandardOrder,
		signature: &Bytes,
		expected_signer: AlloyAddress,
	) -> Result<ValidationResult, String> {
		// 1. Basic order validation
		self.validate_order_basic(order)?;

		// 2. Signature validation
		let signature_valid = self.validate_compact_signature(order, signature, expected_signer)?;

		if !signature_valid {
			return Err("Invalid signature - signer does not match expected user".to_string());
		}

		Ok(ValidationResult {
			valid: true,
			order_id: self.compute_order_id(order),
			witness_hash: self.compute_witness_hash(order)?,
			recovered_signer: expected_signer,
		})
	}

	/// Compute order ID using the same logic as the contract
	fn compute_order_id(&self, order: &OifStandardOrder) -> FixedBytes<32> {
		// This should match the contract's orderIdentifier function
		// For now, using a simplified version
		let mut data = Vec::new();
		data.extend_from_slice(order.user.as_slice());
		data.extend_from_slice(&order.nonce.to_be_bytes::<32>());
		data.extend_from_slice(&order.originChainId.to_be_bytes::<32>());
		data.extend_from_slice(&order.expires.to_be_bytes());
		data.extend_from_slice(&order.fillDeadline.to_be_bytes());
		data.extend_from_slice(order.inputOracle.as_slice());

		// Add inputs
		for input in &order.inputs {
			data.extend_from_slice(&input[0].to_be_bytes::<32>());
			data.extend_from_slice(&input[1].to_be_bytes::<32>());
		}

		// Add outputs
		for output in &order.outputs {
			data.extend_from_slice(output.oracle.as_slice());
			data.extend_from_slice(output.settler.as_slice());
			data.extend_from_slice(&output.chainId.to_be_bytes::<32>());
			data.extend_from_slice(output.token.as_slice());
			data.extend_from_slice(&output.amount.to_be_bytes::<32>());
			data.extend_from_slice(output.recipient.as_slice());
			data.extend_from_slice(keccak256(&output.call).as_slice());
			data.extend_from_slice(keccak256(&output.context).as_slice());
		}

		keccak256(data)
	}

	fn validate_order_basic(&self, order: &OifStandardOrder) -> Result<(), String> {
		// Check timestamps
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap()
			.as_secs() as u32;

		if order.expires <= now {
			return Err("Order expired".to_string());
		}

		if order.fillDeadline <= now {
			return Err("Fill deadline passed".to_string());
		}

		// TODO: Check chain ID against domain separator once we have proper domain separator computation
		// For now, skip chain validation since we're using hardcoded domain separator

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::{Address as AlloyAddress, U256};

	fn create_test_order() -> OifStandardOrder {
		OifStandardOrder {
			user: AlloyAddress::from([0x11; 20]),
			nonce: U256::from(123),
			originChainId: U256::from(1),
			expires: 1000000000,
			fillDeadline: 1000000100,
			inputOracle: AlloyAddress::from([0x22; 20]),
			inputs: vec![[U256::from(100), U256::from(200)]],
			outputs: vec![MandateOutput {
				oracle: FixedBytes::from([0x33; 32]),
				settler: FixedBytes::from([0x44; 32]),
				chainId: U256::from(137),
				token: FixedBytes::from([0x55; 32]),
				amount: U256::from(1000),
				recipient: FixedBytes::from([0x66; 32]),
				call: vec![].into(),
				context: vec![].into(),
			}],
		}
	}

	#[test]
	fn test_compact_signature_validator_creation() {
		let domain_separator = FixedBytes::from([0x12; 32]);
		let contract_address = AlloyAddress::from([0x34; 20]);

		let validator = CompactSignatureValidator::new(domain_separator, contract_address);

		assert_eq!(validator.domain_separator, FixedBytes::from([0x12; 32]));
		assert_eq!(validator.contract_address, AlloyAddress::from([0x34; 20]));
	}

	#[test]
	fn test_witness_hash_computation() {
		let domain_separator = FixedBytes::from([0x12; 32]);
		let contract_address = AlloyAddress::from([0x34; 20]);
		let validator = CompactSignatureValidator::new(domain_separator, contract_address);

		let order = create_test_order();
		let result = validator.compute_witness_hash(&order);

		assert!(result.is_ok());
		let witness_hash = result.unwrap();
		assert_eq!(witness_hash.len(), 32);
	}

	#[test]
	fn test_order_id_computation() {
		let domain_separator = FixedBytes::from([0x12; 32]);
		let contract_address = AlloyAddress::from([0x34; 20]);
		let validator = CompactSignatureValidator::new(domain_separator, contract_address);

		let order = create_test_order();
		let order_id = validator.compute_order_id(&order);

		assert_eq!(order_id.len(), 32);
	}

	#[test]
	fn test_basic_order_validation() {
		// Use the actual domain separator from the contract
		let domain_separator = FixedBytes::from_slice(
			&hex::decode("330989378c39c177ab3877ced96ca0cdb60d7a6489567b993185beff161d80d7")
				.unwrap(),
		);
		let contract_address = AlloyAddress::from([0x34; 20]);
		let validator = CompactSignatureValidator::new(domain_separator, contract_address);

		let mut order = create_test_order();
		order.expires = 2000000000; // Future timestamp
		order.fillDeadline = 2000000100; // Future timestamp
								   // Use chain ID 1 (Ethereum mainnet) which should match the domain separator
		order.originChainId = U256::from(1);

		let result = validator.validate_order_basic(&order);
		assert!(result.is_ok());
	}

	#[test]
	fn test_basic_order_validation_expired() {
		// Use the actual domain separator from the contract
		let domain_separator = FixedBytes::from_slice(
			&hex::decode("330989378c39c177ab3877ced96ca0cdb60d7a6489567b993185beff161d80d7")
				.unwrap(),
		);
		let contract_address = AlloyAddress::from([0x34; 20]);
		let validator = CompactSignatureValidator::new(domain_separator, contract_address);

		let mut order = create_test_order();
		order.expires = 100; // Past timestamp
		order.originChainId = U256::from(1); // Match the domain separator

		let result = validator.validate_order_basic(&order);
		assert!(result.is_err());
		assert!(result.unwrap_err().contains("Order expired"));
	}
}
