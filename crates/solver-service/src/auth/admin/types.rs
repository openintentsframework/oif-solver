//! EIP-712 type definitions for admin actions.
//!
//! Each admin action has a corresponding EIP-712 typed data structure
//! that must be signed by an authorized admin wallet.

use alloy_primitives::{Address, FixedBytes, U256};
use alloy_sol_types::sol;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that can occur when computing EIP-712 hashes for admin actions.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum AdminActionHashError {
	/// The amount field could not be parsed as a valid number
	#[error("Invalid amount: {0}")]
	InvalidAmount(String),
}

/// EIP-712 domain for admin actions.
///
/// This domain is used for all admin action signatures.
/// The verifyingContract is set to zero address since these are
/// off-chain signatures verified by the solver backend.
pub const ADMIN_DOMAIN_NAME: &str = "OIF Solver Admin";
pub const ADMIN_DOMAIN_VERSION: &str = "1";

/// Compute the EIP-712 domain separator for admin actions.
///
/// Domain: { name: "OIF Solver Admin", version: "1", chainId: <chain_id> }
///
/// Note: `verifyingContract` is intentionally omitted since these signatures
/// are verified off-chain by the solver backend, not by a smart contract.
/// This is fully EIP-712 compliant - all domain fields are optional.
pub fn admin_domain_separator(chain_id: u64) -> FixedBytes<32> {
	use alloy_primitives::keccak256;

	// EIP-712 domain type hash (without verifyingContract - it's optional per spec)
	let domain_type_hash = keccak256(b"EIP712Domain(string name,string version,uint256 chainId)");

	let name_hash = keccak256(ADMIN_DOMAIN_NAME.as_bytes());
	let version_hash = keccak256(ADMIN_DOMAIN_VERSION.as_bytes());

	// Encode and hash: typeHash || nameHash || versionHash || chainId
	let encoded = [
		domain_type_hash.as_slice(),
		name_hash.as_slice(),
		version_hash.as_slice(),
		&U256::from(chain_id).to_be_bytes::<32>(),
	]
	.concat();

	keccak256(&encoded)
}

// Define EIP-712 types using alloy's sol! macro
sol! {
	/// Add a new token to a network
	struct AddToken {
		uint256 chainId;
		string symbol;
		address tokenAddress;
		uint8 decimals;
		uint256 nonce;
		uint256 deadline;
	}

	/// A single token item for batch additions
	struct AddTokenItem {
		uint256 chainId;
		string symbol;
		address tokenAddress;
		uint8 decimals;
	}

	/// Add multiple tokens in one admin action
	struct AddTokens {
		AddTokenItem[] tokens;
		uint256 nonce;
		uint256 deadline;
	}

	/// Remove a token from a network
	struct RemoveToken {
		uint256 chainId;
		address tokenAddress;
		uint256 nonce;
		uint256 deadline;
	}

	/// Withdraw tokens from the solver
	struct Withdraw {
		uint256 chainId;
		address token;
		uint256 amount;
		address recipient;
		uint256 nonce;
		uint256 deadline;
	}

	/// Update network configuration
	struct UpdateNetwork {
		uint256 chainId;
		string[] rpcUrls;
		uint256 nonce;
		uint256 deadline;
	}

	/// Add an admin address
	struct AddAdmin {
		address newAdmin;
		uint256 nonce;
		uint256 deadline;
	}

	/// Remove an admin address
	struct RemoveAdmin {
		address adminToRemove;
		uint256 nonce;
		uint256 deadline;
	}

	/// Update fee configuration (gas buffer and min profitability)
	struct UpdateFeeConfig {
		uint32 gasBufferBps;
		string minProfitabilityPct;
		uint32 commissionBps;
		uint32 rateBufferBps;
		uint256 nonce;
		uint256 deadline;
	}

	/// Update gas configuration (flow gas units)
	struct UpdateGasConfig {
		uint64 resourceLockOpen;
		uint64 resourceLockFill;
		uint64 resourceLockClaim;
		uint64 permit2EscrowOpen;
		uint64 permit2EscrowFill;
		uint64 permit2EscrowClaim;
		uint64 eip3009EscrowOpen;
		uint64 eip3009EscrowFill;
		uint64 eip3009EscrowClaim;
		uint256 nonce;
		uint256 deadline;
	}

	/// Approve tokens for a specified spender
	/// chainId = 0 means all chains, tokenAddress = 0x0 means all tokens
	struct ApproveTokens {
		uint256 chainId;
		address tokenAddress;
		address spender;
		uint256 amount;
		uint256 nonce;
		uint256 deadline;
	}
}

/// Request wrapper containing signature and contents.
///
/// All admin endpoints accept this format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedAdminRequest<T> {
	/// The EIP-712 signature (65 bytes: r + s + v)
	#[serde(with = "hex_signature")]
	pub signature: Vec<u8>,

	/// The action contents that were signed
	pub contents: T,
}

/// AddToken action contents (JSON-friendly version)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddTokenContents {
	pub chain_id: u64,
	pub symbol: String,
	/// Optional display name metadata.
	/// This is persisted in config but not included in the EIP-712 hash.
	#[serde(default)]
	pub name: Option<String>,
	pub token_address: Address,
	pub decimals: u8,
	#[serde(with = "string_or_number")]
	pub nonce: u64,
	#[serde(with = "string_or_number")]
	pub deadline: u64,
}

impl AddTokenContents {
	/// Convert to EIP-712 struct for hashing
	pub fn to_eip712(&self) -> AddToken {
		AddToken {
			chainId: U256::from(self.chain_id),
			symbol: self.symbol.clone(),
			tokenAddress: self.token_address,
			decimals: self.decimals,
			nonce: U256::from(self.nonce),
			deadline: U256::from(self.deadline),
		}
	}

	/// Compute the EIP-712 struct hash using Alloy's built-in support
	pub fn struct_hash(&self) -> FixedBytes<32> {
		use alloy_sol_types::SolStruct;
		self.to_eip712().eip712_hash_struct()
	}
}

/// AddToken item contents for batch token addition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddTokenItemContents {
	pub chain_id: u64,
	pub symbol: String,
	/// Optional display name metadata.
	/// This is persisted in config but not included in the EIP-712 hash.
	#[serde(default)]
	pub name: Option<String>,
	pub token_address: Address,
	pub decimals: u8,
}

impl AddTokenItemContents {
	/// Convert to EIP-712 struct for hashing.
	pub fn to_eip712(&self) -> AddTokenItem {
		AddTokenItem {
			chainId: U256::from(self.chain_id),
			symbol: self.symbol.clone(),
			tokenAddress: self.token_address,
			decimals: self.decimals,
		}
	}
}

/// AddTokens action contents (batch add).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddTokensContents {
	pub tokens: Vec<AddTokenItemContents>,
	#[serde(with = "string_or_number")]
	pub nonce: u64,
	#[serde(with = "string_or_number")]
	pub deadline: u64,
}

impl AddTokensContents {
	/// Convert to EIP-712 struct for hashing.
	pub fn to_eip712(&self) -> AddTokens {
		AddTokens {
			tokens: self.tokens.iter().map(|token| token.to_eip712()).collect(),
			nonce: U256::from(self.nonce),
			deadline: U256::from(self.deadline),
		}
	}

	/// Compute the EIP-712 struct hash using Alloy's built-in support.
	pub fn struct_hash(&self) -> FixedBytes<32> {
		use alloy_sol_types::SolStruct;
		self.to_eip712().eip712_hash_struct()
	}
}

/// RemoveToken action contents
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveTokenContents {
	pub chain_id: u64,
	pub token_address: Address,
	#[serde(with = "string_or_number")]
	pub nonce: u64,
	#[serde(with = "string_or_number")]
	pub deadline: u64,
}

impl RemoveTokenContents {
	/// Convert to EIP-712 struct for hashing
	pub fn to_eip712(&self) -> RemoveToken {
		RemoveToken {
			chainId: U256::from(self.chain_id),
			tokenAddress: self.token_address,
			nonce: U256::from(self.nonce),
			deadline: U256::from(self.deadline),
		}
	}

	/// Compute the EIP-712 struct hash using Alloy's built-in support
	pub fn struct_hash(&self) -> FixedBytes<32> {
		use alloy_sol_types::SolStruct;
		self.to_eip712().eip712_hash_struct()
	}
}

/// AddAdmin action contents
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddAdminContents {
	pub new_admin: Address,
	#[serde(with = "string_or_number")]
	pub nonce: u64,
	#[serde(with = "string_or_number")]
	pub deadline: u64,
}

impl AddAdminContents {
	/// Convert to EIP-712 struct for hashing
	pub fn to_eip712(&self) -> AddAdmin {
		AddAdmin {
			newAdmin: self.new_admin,
			nonce: U256::from(self.nonce),
			deadline: U256::from(self.deadline),
		}
	}

	/// Compute the EIP-712 struct hash using Alloy's built-in support
	pub fn struct_hash(&self) -> FixedBytes<32> {
		use alloy_sol_types::SolStruct;
		self.to_eip712().eip712_hash_struct()
	}
}

/// RemoveAdmin action contents
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveAdminContents {
	pub admin_to_remove: Address,
	#[serde(with = "string_or_number")]
	pub nonce: u64,
	#[serde(with = "string_or_number")]
	pub deadline: u64,
}

impl RemoveAdminContents {
	/// Convert to EIP-712 struct for hashing
	pub fn to_eip712(&self) -> RemoveAdmin {
		RemoveAdmin {
			adminToRemove: self.admin_to_remove,
			nonce: U256::from(self.nonce),
			deadline: U256::from(self.deadline),
		}
	}

	/// Compute the EIP-712 struct hash using Alloy's built-in support
	pub fn struct_hash(&self) -> FixedBytes<32> {
		use alloy_sol_types::SolStruct;
		self.to_eip712().eip712_hash_struct()
	}
}

/// Withdraw action contents
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawContents {
	pub chain_id: u64,
	pub token: Address,
	pub amount: String, // String to handle large numbers in JSON
	pub recipient: Address,
	#[serde(with = "string_or_number")]
	pub nonce: u64,
	#[serde(with = "string_or_number")]
	pub deadline: u64,
}

impl WithdrawContents {
	/// Convert to EIP-712 struct for hashing
	///
	/// Returns an error if the amount cannot be parsed as a valid U256.
	pub fn to_eip712(&self) -> Result<Withdraw, AdminActionHashError> {
		// Validate amount is not empty
		if self.amount.is_empty() {
			return Err(AdminActionHashError::InvalidAmount(
				"amount cannot be empty".to_string(),
			));
		}

		// Parse amount - fail explicitly on invalid values instead of silently using zero
		let amount = U256::from_str_radix(&self.amount, 10)
			.map_err(|_| AdminActionHashError::InvalidAmount(self.amount.clone()))?;

		Ok(Withdraw {
			chainId: U256::from(self.chain_id),
			token: self.token,
			amount,
			recipient: self.recipient,
			nonce: U256::from(self.nonce),
			deadline: U256::from(self.deadline),
		})
	}

	/// Compute the EIP-712 struct hash using Alloy's built-in support
	pub fn struct_hash(&self) -> Result<FixedBytes<32>, AdminActionHashError> {
		use alloy_sol_types::SolStruct;
		Ok(self.to_eip712()?.eip712_hash_struct())
	}
}

/// UpdateFeeConfig action contents
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateFeeConfigContents {
	/// Gas buffer in basis points (e.g., 1000 = 10%)
	pub gas_buffer_bps: u32,
	/// Minimum profitability percentage as a decimal string (e.g., "1.5" for 1.5%)
	pub min_profitability_pct: String,
	/// Commission in basis points (e.g., 20 = 0.20%)
	pub commission_bps: u32,
	/// Rate buffer in basis points (e.g., 14 = 0.14%)
	pub rate_buffer_bps: u32,
	#[serde(with = "string_or_number")]
	pub nonce: u64,
	#[serde(with = "string_or_number")]
	pub deadline: u64,
}

impl UpdateFeeConfigContents {
	/// Convert to EIP-712 struct for hashing
	pub fn to_eip712(&self) -> UpdateFeeConfig {
		UpdateFeeConfig {
			gasBufferBps: self.gas_buffer_bps,
			minProfitabilityPct: self.min_profitability_pct.clone(),
			commissionBps: self.commission_bps,
			rateBufferBps: self.rate_buffer_bps,
			nonce: U256::from(self.nonce),
			deadline: U256::from(self.deadline),
		}
	}

	/// Compute the EIP-712 struct hash using Alloy's built-in support
	pub fn struct_hash(&self) -> FixedBytes<32> {
		use alloy_sol_types::SolStruct;
		self.to_eip712().eip712_hash_struct()
	}
}

/// UpdateGasConfig action contents
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateGasConfigContents {
	pub resource_lock_open: u64,
	pub resource_lock_fill: u64,
	pub resource_lock_claim: u64,
	pub permit2_escrow_open: u64,
	pub permit2_escrow_fill: u64,
	pub permit2_escrow_claim: u64,
	pub eip3009_escrow_open: u64,
	pub eip3009_escrow_fill: u64,
	pub eip3009_escrow_claim: u64,
	#[serde(with = "string_or_number")]
	pub nonce: u64,
	#[serde(with = "string_or_number")]
	pub deadline: u64,
}

impl UpdateGasConfigContents {
	/// Convert to EIP-712 struct for hashing
	pub fn to_eip712(&self) -> UpdateGasConfig {
		UpdateGasConfig {
			resourceLockOpen: self.resource_lock_open,
			resourceLockFill: self.resource_lock_fill,
			resourceLockClaim: self.resource_lock_claim,
			permit2EscrowOpen: self.permit2_escrow_open,
			permit2EscrowFill: self.permit2_escrow_fill,
			permit2EscrowClaim: self.permit2_escrow_claim,
			eip3009EscrowOpen: self.eip3009_escrow_open,
			eip3009EscrowFill: self.eip3009_escrow_fill,
			eip3009EscrowClaim: self.eip3009_escrow_claim,
			nonce: U256::from(self.nonce),
			deadline: U256::from(self.deadline),
		}
	}

	/// Compute the EIP-712 struct hash using Alloy's built-in support
	pub fn struct_hash(&self) -> FixedBytes<32> {
		use alloy_sol_types::SolStruct;
		self.to_eip712().eip712_hash_struct()
	}
}

/// ApproveTokens action contents
///
/// Used to trigger ERC20 approvals for tokens to a specified spender.
/// - `chain_id = 0` means all chains
/// - `token_address = 0x0` means all tokens on the selected chain(s)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApproveTokensContents {
	pub chain_id: u64,
	pub token_address: Address,
	pub spender: Address,
	/// Amount as decimal string (uint256). Use full max uint256 if needed.
	pub amount: String,
	#[serde(with = "string_or_number")]
	pub nonce: u64,
	#[serde(with = "string_or_number")]
	pub deadline: u64,
}

impl ApproveTokensContents {
	/// Convert to EIP-712 struct for hashing
	pub fn to_eip712(&self) -> Result<ApproveTokens, AdminActionHashError> {
		// Validate amount is not empty
		if self.amount.is_empty() {
			return Err(AdminActionHashError::InvalidAmount(
				"amount cannot be empty".to_string(),
			));
		}

		let amount = U256::from_str_radix(&self.amount, 10)
			.map_err(|e| AdminActionHashError::InvalidAmount(e.to_string()))?;

		Ok(ApproveTokens {
			chainId: U256::from(self.chain_id),
			tokenAddress: self.token_address,
			spender: self.spender,
			amount,
			nonce: U256::from(self.nonce),
			deadline: U256::from(self.deadline),
		})
	}

	/// Compute the EIP-712 struct hash using Alloy's built-in support
	pub fn struct_hash(&self) -> Result<FixedBytes<32>, AdminActionHashError> {
		use alloy_sol_types::SolStruct;
		Ok(self.to_eip712()?.eip712_hash_struct())
	}

	/// Check if this request approves all chains
	pub fn is_all_chains(&self) -> bool {
		self.chain_id == 0
	}

	/// Check if this request approves all tokens
	pub fn is_all_tokens(&self) -> bool {
		self.token_address == Address::ZERO
	}
}

/// Trait for admin action contents that can compute their EIP-712 hash
pub trait AdminAction {
	/// Get the nonce from the action
	fn nonce(&self) -> u64;

	/// Get the deadline from the action
	fn deadline(&self) -> u64;

	/// Compute the EIP-712 struct hash for this action
	fn struct_hash(&self) -> Result<FixedBytes<32>, AdminActionHashError>;

	/// Compute the full EIP-712 message hash
	fn message_hash(&self, chain_id: u64) -> Result<FixedBytes<32>, AdminActionHashError> {
		use alloy_primitives::keccak256;

		let domain_separator = admin_domain_separator(chain_id);
		let struct_hash = self.struct_hash()?;

		// EIP-712: keccak256("\x19\x01" || domainSeparator || structHash)
		let encoded = [
			&[0x19, 0x01][..],
			domain_separator.as_slice(),
			struct_hash.as_slice(),
		]
		.concat();

		Ok(keccak256(&encoded))
	}
}

impl AdminAction for AddTokenContents {
	fn nonce(&self) -> u64 {
		self.nonce
	}

	fn deadline(&self) -> u64 {
		self.deadline
	}

	fn struct_hash(&self) -> Result<FixedBytes<32>, AdminActionHashError> {
		// AddToken has no fallible parsing, always succeeds
		Ok(AddTokenContents::struct_hash(self))
	}
}

impl AdminAction for AddTokensContents {
	fn nonce(&self) -> u64 {
		self.nonce
	}

	fn deadline(&self) -> u64 {
		self.deadline
	}

	fn struct_hash(&self) -> Result<FixedBytes<32>, AdminActionHashError> {
		Ok(AddTokensContents::struct_hash(self))
	}
}

impl AdminAction for RemoveTokenContents {
	fn nonce(&self) -> u64 {
		self.nonce
	}

	fn deadline(&self) -> u64 {
		self.deadline
	}

	fn struct_hash(&self) -> Result<FixedBytes<32>, AdminActionHashError> {
		// RemoveToken has no fallible parsing, always succeeds
		Ok(RemoveTokenContents::struct_hash(self))
	}
}

impl AdminAction for AddAdminContents {
	fn nonce(&self) -> u64 {
		self.nonce
	}

	fn deadline(&self) -> u64 {
		self.deadline
	}

	fn struct_hash(&self) -> Result<FixedBytes<32>, AdminActionHashError> {
		Ok(AddAdminContents::struct_hash(self))
	}
}

impl AdminAction for RemoveAdminContents {
	fn nonce(&self) -> u64 {
		self.nonce
	}

	fn deadline(&self) -> u64 {
		self.deadline
	}

	fn struct_hash(&self) -> Result<FixedBytes<32>, AdminActionHashError> {
		Ok(RemoveAdminContents::struct_hash(self))
	}
}

impl AdminAction for WithdrawContents {
	fn nonce(&self) -> u64 {
		self.nonce
	}

	fn deadline(&self) -> u64 {
		self.deadline
	}

	fn struct_hash(&self) -> Result<FixedBytes<32>, AdminActionHashError> {
		// Withdraw has amount parsing that can fail
		WithdrawContents::struct_hash(self)
	}
}

impl AdminAction for UpdateFeeConfigContents {
	fn nonce(&self) -> u64 {
		self.nonce
	}

	fn deadline(&self) -> u64 {
		self.deadline
	}

	fn struct_hash(&self) -> Result<FixedBytes<32>, AdminActionHashError> {
		// UpdateFeeConfig has no fallible parsing, always succeeds
		Ok(UpdateFeeConfigContents::struct_hash(self))
	}
}

impl AdminAction for UpdateGasConfigContents {
	fn nonce(&self) -> u64 {
		self.nonce
	}

	fn deadline(&self) -> u64 {
		self.deadline
	}

	fn struct_hash(&self) -> Result<FixedBytes<32>, AdminActionHashError> {
		// UpdateGasConfig has no fallible parsing, always succeeds
		Ok(UpdateGasConfigContents::struct_hash(self))
	}
}

impl AdminAction for ApproveTokensContents {
	fn nonce(&self) -> u64 {
		self.nonce
	}

	fn deadline(&self) -> u64 {
		self.deadline
	}

	fn struct_hash(&self) -> Result<FixedBytes<32>, AdminActionHashError> {
		ApproveTokensContents::struct_hash(self)
	}
}

/// Helper module for serializing/deserializing hex signatures
mod hex_signature {
	use serde::{self, Deserialize, Deserializer, Serializer};

	pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let hex_string = format!("0x{}", hex::encode(bytes));
		serializer.serialize_str(&hex_string)
	}

	pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
	where
		D: Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		let s = s.strip_prefix("0x").unwrap_or(&s);
		hex::decode(s).map_err(serde::de::Error::custom)
	}
}

/// Helper module for deserializing u64 from either number or string.
/// This handles JavaScript's precision issues with large numbers (>2^53-1).
mod string_or_number {
	use serde::{self, Deserialize, Deserializer, Serializer};

	pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_u64(*value)
	}

	pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
	where
		D: Deserializer<'de>,
	{
		#[derive(Deserialize)]
		#[serde(untagged)]
		enum StringOrNumber {
			String(String),
			Number(u64),
		}

		match StringOrNumber::deserialize(deserializer)? {
			StringOrNumber::String(s) => s.parse::<u64>().map_err(serde::de::Error::custom),
			StringOrNumber::Number(n) => Ok(n),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::str::FromStr;

	#[test]
	fn test_domain_separator_computation() {
		// Just verify it doesn't panic and produces 32 bytes
		let separator = admin_domain_separator(1);
		assert_eq!(separator.len(), 32);

		// Different chain IDs should produce different separators
		let separator_10 = admin_domain_separator(10);
		assert_ne!(separator, separator_10);
	}

	#[test]
	fn test_add_token_struct_hash() {
		let contents = AddTokenContents {
			chain_id: 10,
			symbol: "USDC".to_string(),
			name: None,
			token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			decimals: 6,
			nonce: 1,
			deadline: 1706184000,
		};

		let hash = contents.struct_hash();
		assert_eq!(hash.len(), 32);

		// Same contents should produce same hash
		let hash2 = contents.struct_hash();
		assert_eq!(hash, hash2);
	}

	#[test]
	fn test_alloy_eip712_hash_struct_matches_manual() {
		use alloy_sol_types::SolStruct;

		let contents = AddTokenContents {
			chain_id: 10,
			symbol: "USDC".to_string(),
			name: None,
			token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			decimals: 6,
			nonce: 1,
			deadline: 1706184000,
		};

		// Manual hash (current implementation)
		let manual_hash = AddTokenContents::struct_hash(&contents);

		// Alloy's hash via SolStruct trait
		let eip712_struct = contents.to_eip712();
		let alloy_hash = eip712_struct.eip712_hash_struct();

		assert_eq!(
			manual_hash, alloy_hash,
			"Alloy's eip712_hash_struct should match manual implementation"
		);
	}

	#[test]
	fn test_add_token_message_hash() {
		let contents = AddTokenContents {
			chain_id: 10,
			symbol: "USDC".to_string(),
			name: None,
			token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			decimals: 6,
			nonce: 1,
			deadline: 1706184000,
		};

		let hash = contents.message_hash(1).unwrap();
		assert_eq!(hash.len(), 32);

		// Different chain should produce different hash
		let hash_other = contents.message_hash(10).unwrap();
		assert_ne!(hash, hash_other);
	}

	#[test]
	fn test_add_tokens_struct_hash() {
		let contents = AddTokensContents {
			tokens: vec![
				AddTokenItemContents {
					chain_id: 10,
					symbol: "USDC".to_string(),
					name: Some("USD Coin".to_string()),
					token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85")
						.unwrap(),
					decimals: 6,
				},
				AddTokenItemContents {
					chain_id: 10,
					symbol: "USDT".to_string(),
					name: Some("Tether USD".to_string()),
					token_address: Address::from_str("0xdAC17F958D2ee523a2206206994597C13D831ec7")
						.unwrap(),
					decimals: 6,
				},
			],
			nonce: 1,
			deadline: 1706184000,
		};

		let hash = contents.struct_hash();
		let hash2 = contents.struct_hash();
		assert_eq!(hash.len(), 32);
		assert_eq!(hash, hash2);
	}

	#[test]
	fn test_add_tokens_message_hash_order_sensitive() {
		let token_a = AddTokenItemContents {
			chain_id: 10,
			symbol: "USDC".to_string(),
			name: Some("USD Coin".to_string()),
			token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			decimals: 6,
		};
		let token_b = AddTokenItemContents {
			chain_id: 10,
			symbol: "USDT".to_string(),
			name: Some("Tether USD".to_string()),
			token_address: Address::from_str("0xdAC17F958D2ee523a2206206994597C13D831ec7").unwrap(),
			decimals: 6,
		};

		let contents_1 = AddTokensContents {
			tokens: vec![token_a.clone(), token_b.clone()],
			nonce: 99,
			deadline: 1706184000,
		};
		let contents_2 = AddTokensContents {
			tokens: vec![token_b, token_a],
			nonce: 99,
			deadline: 1706184000,
		};

		let hash_1 = contents_1.message_hash(1).unwrap();
		let hash_2 = contents_2.message_hash(1).unwrap();
		assert_ne!(hash_1, hash_2);
	}

	#[test]
	fn test_add_tokens_contents_deserialization_from_json() {
		let json = r#"{
			"tokens": [
				{
					"chainId": 10,
					"symbol": "USDC",
					"name": "USD Coin",
					"tokenAddress": "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85",
					"decimals": 6
				},
				{
					"chainId": 137,
					"symbol": "USDT",
					"tokenAddress": "0xc2132D05D31c914a87C6611C10748AaCBfA6fD92",
					"decimals": 6
				}
			],
			"nonce": "12345678901234",
			"deadline": "1706184000"
		}"#;

		let contents: AddTokensContents = serde_json::from_str(json).unwrap();
		assert_eq!(contents.tokens.len(), 2);
		assert_eq!(contents.tokens[0].name.as_deref(), Some("USD Coin"));
		assert_eq!(contents.tokens[1].name, None);
		assert_eq!(contents.nonce, 12345678901234);
		assert_eq!(contents.deadline, 1706184000);
	}

	#[test]
	fn test_signed_request_serialization() {
		let request = SignedAdminRequest {
			signature: vec![0xab; 65],
			contents: AddTokenContents {
				chain_id: 10,
				symbol: "USDC".to_string(),
				name: None,
				token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85")
					.unwrap(),
				decimals: 6,
				nonce: 1,
				deadline: 1706184000,
			},
		};

		let json = serde_json::to_string(&request).unwrap();
		assert!(json.contains("0xab")); // Hex encoded signature

		// Round trip
		let parsed: SignedAdminRequest<AddTokenContents> = serde_json::from_str(&json).unwrap();
		assert_eq!(parsed.signature.len(), 65);
		assert_eq!(parsed.contents.symbol, "USDC");
	}

	#[test]
	fn test_admin_action_trait() {
		let contents = AddTokenContents {
			chain_id: 10,
			symbol: "USDC".to_string(),
			name: None,
			token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			decimals: 6,
			nonce: 42,
			deadline: 1706184000,
		};

		assert_eq!(contents.nonce(), 42);
		assert_eq!(contents.deadline(), 1706184000);
	}

	#[test]
	fn test_withdraw_valid_amount() {
		let contents = WithdrawContents {
			chain_id: 10,
			token: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			amount: "1000000000".to_string(), // Valid amount
			recipient: Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
			nonce: 1,
			deadline: 1706184000,
		};

		// Should succeed
		let hash = contents.struct_hash();
		assert!(hash.is_ok());
		assert_eq!(hash.unwrap().len(), 32);
	}

	#[test]
	fn test_withdraw_invalid_amount_string() {
		let contents = WithdrawContents {
			chain_id: 10,
			token: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			amount: "abc".to_string(), // Invalid - not a number
			recipient: Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
			nonce: 1,
			deadline: 1706184000,
		};

		// Should fail with InvalidAmount error
		let result = contents.struct_hash();
		assert!(result.is_err());
		assert!(matches!(
			result.unwrap_err(),
			AdminActionHashError::InvalidAmount(s) if s == "abc"
		));
	}

	#[test]
	fn test_withdraw_empty_amount() {
		let contents = WithdrawContents {
			chain_id: 10,
			token: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			amount: "".to_string(), // Invalid - empty
			recipient: Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
			nonce: 1,
			deadline: 1706184000,
		};

		// Should fail
		let result = contents.struct_hash();
		assert!(result.is_err());
	}

	#[test]
	fn test_nonce_deserialize_from_string() {
		// Test that nonce/deadline can be deserialized from strings (for JavaScript precision)
		let json = r#"{
			"chainId": 10,
			"symbol": "USDC",
			"tokenAddress": "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85",
			"decimals": 6,
			"nonce": "12345678901234567890",
			"deadline": "1706184000"
		}"#;

		let contents: AddTokenContents = serde_json::from_str(json).unwrap();
		assert_eq!(contents.nonce, 12345678901234567890u64);
		assert_eq!(contents.deadline, 1706184000);
	}

	#[test]
	fn test_nonce_deserialize_from_number() {
		// Test that nonce/deadline can still be deserialized from numbers
		let json = r#"{
			"chainId": 10,
			"symbol": "USDC",
			"tokenAddress": "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85",
			"decimals": 6,
			"nonce": 123456,
			"deadline": 1706184000
		}"#;

		let contents: AddTokenContents = serde_json::from_str(json).unwrap();
		assert_eq!(contents.nonce, 123456);
		assert_eq!(contents.deadline, 1706184000);
	}

	#[test]
	fn test_signed_request_with_string_nonce() {
		// Test full request deserialization with string nonce (what frontend sends)
		let json = r#"{
			"signature": "0xabababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab1b",
			"contents": {
				"chainId": 84532,
				"symbol": "USDT",
				"tokenAddress": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
				"decimals": 6,
				"nonce": "1737925846892",
				"deadline": "1737929446"
			}
		}"#;

		let request: SignedAdminRequest<AddTokenContents> = serde_json::from_str(json).unwrap();
		assert_eq!(request.contents.chain_id, 84532);
		assert_eq!(request.contents.symbol, "USDT");
		assert_eq!(request.contents.nonce, 1737925846892);
		assert_eq!(request.contents.deadline, 1737929446);
		assert_eq!(request.signature.len(), 65);
	}

	#[test]
	fn test_remove_token_struct_hash() {
		let contents = RemoveTokenContents {
			chain_id: 10,
			token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			nonce: 1,
			deadline: 1706184000,
		};

		let hash = contents.struct_hash();
		assert_eq!(hash.len(), 32);

		// Same contents should produce same hash
		let hash2 = contents.struct_hash();
		assert_eq!(hash, hash2);
	}

	#[test]
	fn test_add_admin_struct_hash() {
		let contents = AddAdminContents {
			new_admin: Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
			nonce: 1,
			deadline: 1706184000,
		};

		let hash = contents.struct_hash();
		assert_eq!(hash.len(), 32);
		let hash2 = contents.struct_hash();
		assert_eq!(hash, hash2);
	}

	#[test]
	fn test_remove_admin_struct_hash() {
		let contents = RemoveAdminContents {
			admin_to_remove: Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
				.unwrap(),
			nonce: 1,
			deadline: 1706184000,
		};

		let hash = contents.struct_hash();
		assert_eq!(hash.len(), 32);
		let hash2 = contents.struct_hash();
		assert_eq!(hash, hash2);
	}

	#[test]
	fn test_remove_token_admin_action_trait() {
		let contents = RemoveTokenContents {
			chain_id: 10,
			token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			nonce: 42,
			deadline: 1706184000,
		};

		assert_eq!(contents.nonce(), 42);
		assert_eq!(contents.deadline(), 1706184000);

		// struct_hash via trait should succeed
		let hash = AdminAction::struct_hash(&contents);
		assert!(hash.is_ok());
	}

	#[test]
	fn test_add_admin_admin_action_trait() {
		let contents = AddAdminContents {
			new_admin: Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
			nonce: 42,
			deadline: 1706184000,
		};

		assert_eq!(contents.nonce(), 42);
		assert_eq!(contents.deadline(), 1706184000);
		let hash = AdminAction::struct_hash(&contents);
		assert!(hash.is_ok());
	}

	#[test]
	fn test_remove_admin_admin_action_trait() {
		let contents = RemoveAdminContents {
			admin_to_remove: Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
				.unwrap(),
			nonce: 42,
			deadline: 1706184000,
		};

		assert_eq!(contents.nonce(), 42);
		assert_eq!(contents.deadline(), 1706184000);
		let hash = AdminAction::struct_hash(&contents);
		assert!(hash.is_ok());
	}

	#[test]
	fn test_remove_token_message_hash() {
		let contents = RemoveTokenContents {
			chain_id: 10,
			token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			nonce: 1,
			deadline: 1706184000,
		};

		let hash = contents.message_hash(1).unwrap();
		assert_eq!(hash.len(), 32);

		// Different chain should produce different hash
		let hash_other = contents.message_hash(10).unwrap();
		assert_ne!(hash, hash_other);
	}

	#[test]
	fn test_withdraw_admin_action_trait() {
		let contents = WithdrawContents {
			chain_id: 10,
			token: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			amount: "1000000".to_string(),
			recipient: Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
			nonce: 99,
			deadline: 1706184000,
		};

		assert_eq!(contents.nonce(), 99);
		assert_eq!(contents.deadline(), 1706184000);

		// struct_hash via trait should succeed
		let hash = AdminAction::struct_hash(&contents);
		assert!(hash.is_ok());
	}

	#[test]
	fn test_withdraw_message_hash() {
		let contents = WithdrawContents {
			chain_id: 10,
			token: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			amount: "1000000".to_string(),
			recipient: Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
			nonce: 1,
			deadline: 1706184000,
		};

		let hash = contents.message_hash(1).unwrap();
		assert_eq!(hash.len(), 32);
	}

	#[test]
	fn test_withdraw_message_hash_fails_with_invalid_amount() {
		let contents = WithdrawContents {
			chain_id: 10,
			token: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			amount: "not_a_number".to_string(),
			recipient: Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
			nonce: 1,
			deadline: 1706184000,
		};

		let result = contents.message_hash(1);
		assert!(result.is_err());
	}

	#[test]
	fn test_add_token_to_eip712() {
		let contents = AddTokenContents {
			chain_id: 10,
			symbol: "USDC".to_string(),
			name: None,
			token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			decimals: 6,
			nonce: 1,
			deadline: 1706184000,
		};

		let eip712 = contents.to_eip712();
		assert_eq!(eip712.chainId, U256::from(10));
		assert_eq!(eip712.symbol, "USDC");
		assert_eq!(eip712.decimals, 6);
		assert_eq!(eip712.nonce, U256::from(1));
		assert_eq!(eip712.deadline, U256::from(1706184000));
	}

	#[test]
	fn test_remove_token_contents_serialization() {
		let contents = RemoveTokenContents {
			chain_id: 10,
			token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			nonce: 12345,
			deadline: 1706184000,
		};

		let json = serde_json::to_string(&contents).unwrap();
		assert!(json.contains("\"chainId\":10"));
		assert!(json.contains("\"tokenAddress\""));
		assert!(json.contains("\"nonce\":12345"));
		assert!(json.contains("\"deadline\":1706184000"));

		// Round trip
		let parsed: RemoveTokenContents = serde_json::from_str(&json).unwrap();
		assert_eq!(parsed.chain_id, 10);
		assert_eq!(parsed.nonce, 12345);
	}

	#[test]
	fn test_withdraw_contents_serialization() {
		let contents = WithdrawContents {
			chain_id: 137,
			token: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			amount: "1000000000000000000".to_string(),
			recipient: Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
			nonce: 42,
			deadline: 1706184000,
		};

		let json = serde_json::to_string(&contents).unwrap();
		assert!(json.contains("\"chainId\":137"));
		assert!(json.contains("\"amount\":\"1000000000000000000\""));
		assert!(json.contains("\"nonce\":42"));

		// Round trip
		let parsed: WithdrawContents = serde_json::from_str(&json).unwrap();
		assert_eq!(parsed.chain_id, 137);
		assert_eq!(parsed.amount, "1000000000000000000");
	}

	#[test]
	fn test_hex_signature_round_trip() {
		let request = SignedAdminRequest {
			signature: vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0],
			contents: AddTokenContents {
				chain_id: 1,
				symbol: "TEST".to_string(),
				name: None,
				token_address: Address::from_str("0x0000000000000000000000000000000000000001")
					.unwrap(),
				decimals: 18,
				nonce: 1,
				deadline: 1,
			},
		};

		let json = serde_json::to_string(&request).unwrap();
		assert!(json.contains("0x123456789abcdef0"));

		let parsed: SignedAdminRequest<AddTokenContents> = serde_json::from_str(&json).unwrap();
		assert_eq!(
			parsed.signature,
			vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]
		);
	}

	#[test]
	fn test_hex_signature_without_0x_prefix() {
		let json = r#"{
			"signature": "abcdef0123456789",
			"contents": {
				"chainId": 1,
				"symbol": "TEST",
				"tokenAddress": "0x0000000000000000000000000000000000000001",
				"decimals": 18,
				"nonce": 1,
				"deadline": 1
			}
		}"#;

		let request: SignedAdminRequest<AddTokenContents> = serde_json::from_str(json).unwrap();
		assert_eq!(
			request.signature,
			vec![0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89]
		);
	}

	#[test]
	fn test_admin_action_hash_error_display() {
		let err = AdminActionHashError::InvalidAmount("bad_value".to_string());
		assert_eq!(format!("{err}"), "Invalid amount: bad_value");
	}

	#[test]
	fn test_domain_separator_same_chain_same_result() {
		let sep1 = admin_domain_separator(1);
		let sep2 = admin_domain_separator(1);
		assert_eq!(sep1, sep2);
	}

	#[test]
	fn test_add_token_different_symbols_different_hash() {
		let contents1 = AddTokenContents {
			chain_id: 10,
			symbol: "USDC".to_string(),
			name: None,
			token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			decimals: 6,
			nonce: 1,
			deadline: 1706184000,
		};

		let contents2 = AddTokenContents {
			chain_id: 10,
			symbol: "USDT".to_string(), // Different symbol
			name: None,
			token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			decimals: 6,
			nonce: 1,
			deadline: 1706184000,
		};

		assert_ne!(contents1.struct_hash(), contents2.struct_hash());
	}

	#[test]
	fn test_update_fee_config_struct_hash() {
		let contents = UpdateFeeConfigContents {
			gas_buffer_bps: 1500,
			min_profitability_pct: "2.5".to_string(),
			commission_bps: 20,
			rate_buffer_bps: 14,
			nonce: 1,
			deadline: 1706184000,
		};

		let hash = contents.struct_hash();
		assert_eq!(hash.len(), 32);

		// Same contents should produce same hash
		let hash2 = contents.struct_hash();
		assert_eq!(hash, hash2);
	}

	#[test]
	fn test_update_fee_config_different_values_different_hash() {
		let contents1 = UpdateFeeConfigContents {
			gas_buffer_bps: 1500,
			min_profitability_pct: "2.5".to_string(),
			commission_bps: 20,
			rate_buffer_bps: 14,
			nonce: 1,
			deadline: 1706184000,
		};

		let contents2 = UpdateFeeConfigContents {
			gas_buffer_bps: 2000, // Different gas buffer
			min_profitability_pct: "2.5".to_string(),
			commission_bps: 20,
			rate_buffer_bps: 14,
			nonce: 1,
			deadline: 1706184000,
		};

		assert_ne!(contents1.struct_hash(), contents2.struct_hash());

		let contents3 = UpdateFeeConfigContents {
			gas_buffer_bps: 1500,
			min_profitability_pct: "3.0".to_string(), // Different profitability
			commission_bps: 20,
			rate_buffer_bps: 14,
			nonce: 1,
			deadline: 1706184000,
		};

		assert_ne!(contents1.struct_hash(), contents3.struct_hash());
	}

	#[test]
	fn test_update_fee_config_admin_action_trait() {
		let contents = UpdateFeeConfigContents {
			gas_buffer_bps: 1000,
			min_profitability_pct: "1.5".to_string(),
			commission_bps: 20,
			rate_buffer_bps: 14,
			nonce: 42,
			deadline: 1706184000,
		};

		assert_eq!(contents.nonce(), 42);
		assert_eq!(contents.deadline(), 1706184000);

		// struct_hash via trait should succeed
		let hash = AdminAction::struct_hash(&contents);
		assert!(hash.is_ok());
	}

	#[test]
	fn test_update_fee_config_message_hash() {
		let contents = UpdateFeeConfigContents {
			gas_buffer_bps: 1500,
			min_profitability_pct: "2.5".to_string(),
			commission_bps: 20,
			rate_buffer_bps: 14,
			nonce: 1,
			deadline: 1706184000,
		};

		let hash = contents.message_hash(1).unwrap();
		assert_eq!(hash.len(), 32);

		// Different chain should produce different hash
		let hash_other = contents.message_hash(10).unwrap();
		assert_ne!(hash, hash_other);
	}

	#[test]
	fn test_update_fee_config_serialization() {
		let contents = UpdateFeeConfigContents {
			gas_buffer_bps: 1500,
			min_profitability_pct: "2.5".to_string(),
			commission_bps: 20,
			rate_buffer_bps: 14,
			nonce: 12345,
			deadline: 1706184000,
		};

		let json = serde_json::to_string(&contents).unwrap();
		assert!(json.contains("\"gasBufferBps\":1500"));
		assert!(json.contains("\"minProfitabilityPct\":\"2.5\""));
		assert!(json.contains("\"commissionBps\":20"));
		assert!(json.contains("\"rateBufferBps\":14"));
		assert!(json.contains("\"nonce\":12345"));
		assert!(json.contains("\"deadline\":1706184000"));

		// Round trip
		let parsed: UpdateFeeConfigContents = serde_json::from_str(&json).unwrap();
		assert_eq!(parsed.gas_buffer_bps, 1500);
		assert_eq!(parsed.min_profitability_pct, "2.5");
		assert_eq!(parsed.nonce, 12345);
	}

	#[test]
	fn test_update_fee_config_deserialize_with_string_nonce() {
		let json = r#"{
			"gasBufferBps": 1500,
			"minProfitabilityPct": "2.5",
			"commissionBps": 20,
			"rateBufferBps": 14,
			"nonce": "12345678901234567890",
			"deadline": "1706184000"
		}"#;

		let contents: UpdateFeeConfigContents = serde_json::from_str(json).unwrap();
		assert_eq!(contents.gas_buffer_bps, 1500);
		assert_eq!(contents.min_profitability_pct, "2.5");
		assert_eq!(contents.commission_bps, 20);
		assert_eq!(contents.rate_buffer_bps, 14);
		assert_eq!(contents.nonce, 12345678901234567890u64);
		assert_eq!(contents.deadline, 1706184000);
	}

	#[test]
	fn test_update_fee_config_signed_request() {
		let json = r#"{
			"signature": "0xabababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab1b",
			"contents": {
				"gasBufferBps": 1500,
				"minProfitabilityPct": "2.5",
				"commissionBps": 20,
				"rateBufferBps": 14,
				"nonce": "1737925846892",
				"deadline": "1737929446"
			}
		}"#;

		let request: SignedAdminRequest<UpdateFeeConfigContents> =
			serde_json::from_str(json).unwrap();
		assert_eq!(request.contents.gas_buffer_bps, 1500);
		assert_eq!(request.contents.min_profitability_pct, "2.5");
		assert_eq!(request.contents.commission_bps, 20);
		assert_eq!(request.contents.rate_buffer_bps, 14);
		assert_eq!(request.contents.nonce, 1737925846892);
		assert_eq!(request.contents.deadline, 1737929446);
		assert_eq!(request.signature.len(), 65);
	}

	#[test]
	fn test_approve_tokens_struct_hash() {
		let contents = ApproveTokensContents {
			chain_id: 10,
			token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			spender: Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
			amount: "1000".to_string(),
			nonce: 1,
			deadline: 1706184000,
		};

		let hash = contents.struct_hash().unwrap();
		assert_eq!(hash.len(), 32);

		// Same contents should produce same hash
		let hash2 = contents.struct_hash().unwrap();
		assert_eq!(hash, hash2);
	}

	#[test]
	fn test_approve_tokens_admin_action_trait() {
		let contents = ApproveTokensContents {
			chain_id: 10,
			token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			spender: Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
			amount: "1000".to_string(),
			nonce: 42,
			deadline: 1706184000,
		};

		assert_eq!(contents.nonce(), 42);
		assert_eq!(contents.deadline(), 1706184000);

		// struct_hash via trait should succeed
		let hash = AdminAction::struct_hash(&contents);
		assert!(hash.is_ok());
	}

	#[test]
	fn test_approve_tokens_message_hash() {
		let contents = ApproveTokensContents {
			chain_id: 10,
			token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			spender: Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
			amount: "1000".to_string(),
			nonce: 1,
			deadline: 1706184000,
		};

		let hash = contents.message_hash(1).unwrap();
		assert_eq!(hash.len(), 32);

		// Different chain should produce different hash
		let hash_other = contents.message_hash(10).unwrap();
		assert_ne!(hash, hash_other);
	}

	#[test]
	fn test_approve_tokens_serialization() {
		let contents = ApproveTokensContents {
			chain_id: 10,
			token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			spender: Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
			amount: "1000".to_string(),
			nonce: 12345,
			deadline: 1706184000,
		};

		let json = serde_json::to_string(&contents).unwrap();
		assert!(json.contains("\"chainId\":10"));
		assert!(json.contains("\"tokenAddress\""));
		assert!(json.contains("\"spender\""));
		assert!(json.contains("\"amount\":\"1000\""));
		assert!(json.contains("\"nonce\":12345"));
		assert!(json.contains("\"deadline\":1706184000"));

		// Round trip
		let parsed: ApproveTokensContents = serde_json::from_str(&json).unwrap();
		assert_eq!(parsed.chain_id, 10);
		assert_eq!(parsed.nonce, 12345);
	}

	#[test]
	fn test_approve_tokens_is_all_chains() {
		let all_chains = ApproveTokensContents {
			chain_id: 0,
			token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			spender: Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
			amount: "1000".to_string(),
			nonce: 1,
			deadline: 1706184000,
		};
		assert!(all_chains.is_all_chains());

		let specific_chain = ApproveTokensContents {
			chain_id: 10,
			token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			spender: Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
			amount: "1000".to_string(),
			nonce: 1,
			deadline: 1706184000,
		};
		assert!(!specific_chain.is_all_chains());
	}

	#[test]
	fn test_approve_tokens_is_all_tokens() {
		let all_tokens = ApproveTokensContents {
			chain_id: 10,
			token_address: Address::ZERO,
			spender: Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
			amount: "1000".to_string(),
			nonce: 1,
			deadline: 1706184000,
		};
		assert!(all_tokens.is_all_tokens());

		let specific_token = ApproveTokensContents {
			chain_id: 10,
			token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			spender: Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
			amount: "1000".to_string(),
			nonce: 1,
			deadline: 1706184000,
		};
		assert!(!specific_token.is_all_tokens());
	}

	#[test]
	fn test_approve_tokens_deserialize_with_string_nonce() {
		let json = r#"{
			"chainId": 10,
			"tokenAddress": "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85",
			"spender": "0x1111111111111111111111111111111111111111",
			"amount": "1000",
			"nonce": "12345678901234567890",
			"deadline": "1706184000"
		}"#;

		let contents: ApproveTokensContents = serde_json::from_str(json).unwrap();
		assert_eq!(contents.chain_id, 10);
		assert_eq!(
			contents.spender,
			Address::from_str("0x1111111111111111111111111111111111111111").unwrap()
		);
		assert_eq!(contents.amount, "1000");
		assert_eq!(contents.nonce, 12345678901234567890u64);
		assert_eq!(contents.deadline, 1706184000);
	}

	#[test]
	fn test_approve_tokens_signed_request() {
		let json = r#"{
			"signature": "0xabababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab1b",
			"contents": {
				"chainId": 10,
				"tokenAddress": "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85",
				"spender": "0x1111111111111111111111111111111111111111",
				"amount": "1000",
				"nonce": "1737925846892",
				"deadline": "1737929446"
			}
		}"#;

		let request: SignedAdminRequest<ApproveTokensContents> =
			serde_json::from_str(json).unwrap();
		assert_eq!(request.contents.chain_id, 10);
		assert_eq!(request.contents.nonce, 1737925846892);
		assert_eq!(request.contents.deadline, 1737929446);
		assert_eq!(request.signature.len(), 65);
	}

	#[test]
	fn test_approve_tokens_different_scopes_different_hash() {
		let contents1 = ApproveTokensContents {
			chain_id: 0,
			token_address: Address::ZERO,
			spender: Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
			amount: "1000".to_string(),
			nonce: 1,
			deadline: 1706184000,
		};

		let contents2 = ApproveTokensContents {
			chain_id: 10,
			token_address: Address::ZERO,
			spender: Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
			amount: "1000".to_string(),
			nonce: 1,
			deadline: 1706184000,
		};

		let contents3 = ApproveTokensContents {
			chain_id: 10,
			token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			spender: Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
			amount: "1000".to_string(),
			nonce: 1,
			deadline: 1706184000,
		};

		// Different scopes should produce different hashes
		assert_ne!(
			contents1.struct_hash().unwrap(),
			contents2.struct_hash().unwrap()
		);
		assert_ne!(
			contents2.struct_hash().unwrap(),
			contents3.struct_hash().unwrap()
		);
		assert_ne!(
			contents1.struct_hash().unwrap(),
			contents3.struct_hash().unwrap()
		);
	}
}
