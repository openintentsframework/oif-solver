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
