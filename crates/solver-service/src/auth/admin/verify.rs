//! EIP-712 signature verification for admin actions.
//!
//! This module provides the core verification logic:
//! 1. Check nonce exists (without consuming)
//! 2. Verify signature → recover address
//! 3. Check address is in admin registry
//! 4. Consume nonce atomically
//!
//! The order is important: we verify the signature BEFORE consuming the nonce
//! to prevent DoS attacks where an attacker burns valid nonces.

use alloy_primitives::Address;
use solver_storage::nonce_store::NonceStore;
use solver_types::AdminConfig;
use std::sync::Arc;

use super::error::AdminAuthError;
use super::signature::recover_from_hash;
use super::types::AdminAction;

/// Verifier for EIP-712 signed admin actions.
///
/// Handles the complete verification flow including nonce management.
pub struct AdminActionVerifier {
	nonce_store: Arc<NonceStore>,
	admin_config: AdminConfig,
	/// Chain ID for EIP-712 domain
	chain_id: u64,
}

impl AdminActionVerifier {
	/// Create a new verifier.
	///
	/// # Arguments
	///
	/// * `nonce_store` - Redis-backed nonce storage
	/// * `admin_config` - Admin configuration with authorized addresses
	/// * `chain_id` - Chain ID for EIP-712 domain separator
	pub fn new(nonce_store: Arc<NonceStore>, admin_config: AdminConfig, chain_id: u64) -> Self {
		Self {
			nonce_store,
			admin_config,
			chain_id,
		}
	}

	/// Verify an admin action signature.
	///
	/// This performs the complete verification flow:
	/// 1. Check deadline hasn't passed
	/// 2. Check nonce exists (pre-validation)
	/// 3. Verify EIP-712 signature → recover signer
	/// 4. Check signer is in admin registry
	/// 5. Consume nonce atomically
	///
	/// # Arguments
	///
	/// * `action` - The action contents that were signed
	/// * `signature` - The 65-byte EIP-712 signature
	/// * `nonce_string` - The nonce string (used as key in nonce store)
	///
	/// # Returns
	///
	/// The verified admin address, or an error.
	pub async fn verify<T: AdminAction>(
		&self,
		action: &T,
		signature: &[u8],
		nonce_string: &str,
	) -> Result<Address, AdminAuthError> {
		// 1. Check deadline hasn't passed
		let now = chrono::Utc::now().timestamp() as u64;
		if action.deadline() < now {
			return Err(AdminAuthError::Expired);
		}

		// 2. Check nonce exists (don't consume yet - prevents DoS)
		if !self.nonce_store.exists(nonce_string).await? {
			return Err(AdminAuthError::NonceNotFound);
		}

		// 3. Compute message hash and recover signer
		let message_hash = action.message_hash(self.chain_id);
		let signer = recover_from_hash(&message_hash.0, signature)?;

		// 4. Check signer is in admin registry
		if !self.admin_config.is_admin(&signer) {
			return Err(AdminAuthError::NotAuthorized(format!("{:?}", signer)));
		}

		// 5. Consume nonce atomically (prevents replay)
		self.nonce_store.consume(nonce_string).await?;

		tracing::info!(
			admin = %signer,
			action_nonce = %action.nonce(),
			"Admin action verified"
		);

		Ok(signer)
	}

	/// Generate a new nonce for an admin action.
	///
	/// The nonce should be included in the action contents before signing.
	pub async fn generate_nonce(&self) -> Result<String, AdminAuthError> {
		self.nonce_store.generate().await.map_err(Into::into)
	}

	/// Get the configured nonce TTL.
	pub fn nonce_ttl(&self) -> u64 {
		self.nonce_store.ttl_seconds()
	}

	/// Get the chain ID used for EIP-712 domain.
	pub fn chain_id(&self) -> u64 {
		self.chain_id
	}

	/// Check if an address is an admin.
	pub fn is_admin(&self, address: &Address) -> bool {
		self.admin_config.is_admin(address)
	}

	/// Get the domain name for EIP-712.
	pub fn domain(&self) -> &str {
		&self.admin_config.domain
	}
}

/// Result of a successful admin action verification.
#[derive(Debug)]
pub struct VerifiedAdminAction<T> {
	/// The verified admin address
	pub admin: Address,
	/// The action contents
	pub action: T,
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::auth::admin::types::AddTokenContents;
	use alloy_primitives::keccak256;
	use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
	use std::str::FromStr;

	/// Get address from secret key
	fn address_from_secret(secret: &SecretKey) -> Address {
		let secp = Secp256k1::new();
		let public_key = PublicKey::from_secret_key(&secp, secret);
		let public_key_bytes = public_key.serialize_uncompressed();
		let hash = keccak256(&public_key_bytes[1..]);
		Address::from_slice(&hash[12..])
	}

	/// Sign an EIP-712 message hash
	fn sign_hash(hash: &[u8; 32], secret: &SecretKey) -> Vec<u8> {
		let secp = Secp256k1::new();
		let msg = Message::from_digest(*hash);
		let signature = secp.sign_ecdsa_recoverable(msg, secret);
		let (recovery_id, sig_bytes) = signature.serialize_compact();
		let mut signature_bytes = sig_bytes.to_vec();
		let rec: i32 = recovery_id.into();
		signature_bytes.push((rec as u8) + 27);
		signature_bytes
	}

	#[tokio::test]
	#[ignore] // Requires Redis
	async fn test_verify_admin_action() {
		// Setup
		let secret = SecretKey::from_byte_array([0x42u8; 32]).expect("valid secret");
		let admin_address = address_from_secret(&secret);

		let nonce_store =
			Arc::new(NonceStore::new("redis://127.0.0.1:6379", "test-verify", 300).unwrap());

		let admin_config = AdminConfig {
			enabled: true,
			domain: "test.example.com".to_string(),
			nonce_ttl_seconds: 300,
			admin_addresses: vec![admin_address],
		};

		let verifier = AdminActionVerifier::new(nonce_store.clone(), admin_config, 1);

		// Generate nonce
		let nonce_string = verifier.generate_nonce().await.unwrap();

		// Create action
		let action = AddTokenContents {
			chain_id: 10,
			symbol: "USDC".to_string(),
			token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85")
				.unwrap(),
			decimals: 6,
			nonce: 1,
			deadline: (chrono::Utc::now().timestamp() + 300) as u64, // 5 min from now
		};

		// Sign
		let message_hash = action.message_hash(1);
		let signature = sign_hash(&message_hash.0, &secret);

		// Verify
		let result = verifier.verify(&action, &signature, &nonce_string).await;
		assert!(result.is_ok());
		assert_eq!(result.unwrap(), admin_address);

		// Try to reuse nonce - should fail
		let result = verifier.verify(&action, &signature, &nonce_string).await;
		assert!(matches!(result, Err(AdminAuthError::NonceNotFound)));
	}

	#[tokio::test]
	#[ignore] // Requires Redis
	async fn test_verify_expired_action() {
		let secret = SecretKey::from_byte_array([0x42u8; 32]).expect("valid secret");
		let admin_address = address_from_secret(&secret);

		let nonce_store =
			Arc::new(NonceStore::new("redis://127.0.0.1:6379", "test-expired", 300).unwrap());

		let admin_config = AdminConfig {
			enabled: true,
			domain: "test.example.com".to_string(),
			nonce_ttl_seconds: 300,
			admin_addresses: vec![admin_address],
		};

		let verifier = AdminActionVerifier::new(nonce_store.clone(), admin_config, 1);
		let nonce_string = verifier.generate_nonce().await.unwrap();

		// Create expired action
		let action = AddTokenContents {
			chain_id: 10,
			symbol: "USDC".to_string(),
			token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85")
				.unwrap(),
			decimals: 6,
			nonce: 1,
			deadline: 1000, // Far in the past
		};

		let message_hash = action.message_hash(1);
		let signature = sign_hash(&message_hash.0, &secret);

		let result = verifier.verify(&action, &signature, &nonce_string).await;
		assert!(matches!(result, Err(AdminAuthError::Expired)));
	}

	#[tokio::test]
	#[ignore] // Requires Redis
	async fn test_verify_non_admin() {
		let secret = SecretKey::from_byte_array([0x42u8; 32]).expect("valid secret");
		let other_address =
			Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

		let nonce_store =
			Arc::new(NonceStore::new("redis://127.0.0.1:6379", "test-non-admin", 300).unwrap());

		let admin_config = AdminConfig {
			enabled: true,
			domain: "test.example.com".to_string(),
			nonce_ttl_seconds: 300,
			admin_addresses: vec![other_address], // Different address
		};

		let verifier = AdminActionVerifier::new(nonce_store.clone(), admin_config, 1);
		let nonce_string = verifier.generate_nonce().await.unwrap();

		let action = AddTokenContents {
			chain_id: 10,
			symbol: "USDC".to_string(),
			token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85")
				.unwrap(),
			decimals: 6,
			nonce: 1,
			deadline: (chrono::Utc::now().timestamp() + 300) as u64,
		};

		let message_hash = action.message_hash(1);
		let signature = sign_hash(&message_hash.0, &secret);

		let result = verifier.verify(&action, &signature, &nonce_string).await;
		assert!(matches!(result, Err(AdminAuthError::NotAuthorized(_))));
	}
}
