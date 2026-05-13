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

use alloy_primitives::{Address, FixedBytes};
use solver_storage::nonce_store::NonceStore;
use solver_types::AdminConfig;
#[cfg(test)]
use solver_types::{AdminRole, AdminWhitelistEntry};
use std::sync::Arc;

use super::error::AdminAuthError;
use super::signature::recover_from_hash;
use super::types::{admin_domain_salt, AdminAction};

/// Verifier for EIP-712 signed admin actions.
///
/// Handles the complete verification flow including nonce management.
pub struct AdminActionVerifier {
	nonce_store: Arc<NonceStore>,
	admin_config: AdminConfig,
	/// Chain ID for EIP-712 domain
	chain_id: u64,
	/// Per-solver EIP-712 domain salt derived from `solver_id`. Prevents an
	/// admin signature minted for this solver from replaying against another
	/// solver running on the same chain with the same admin key.
	domain_salt: FixedBytes<32>,
}

impl AdminActionVerifier {
	/// Create a new verifier.
	///
	/// # Arguments
	///
	/// * `nonce_store` - Redis-backed nonce storage
	/// * `admin_config` - Admin configuration with authorized addresses
	/// * `chain_id` - Chain ID for EIP-712 domain separator
	/// * `solver_id` - Stable identifier of this solver instance. Folded into
	///   the EIP-712 domain `salt` so signatures cannot be replayed across
	///   solvers sharing a chain and admin key.
	pub fn new(
		nonce_store: Arc<NonceStore>,
		admin_config: AdminConfig,
		chain_id: u64,
		solver_id: &str,
	) -> Self {
		Self {
			nonce_store,
			admin_config,
			chain_id,
			domain_salt: admin_domain_salt(solver_id),
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
	///
	/// # Returns
	///
	/// The verified admin address, or an error.
	///
	/// # Note
	///
	/// The nonce is extracted from the action contents directly, ensuring
	/// the signed nonce matches what we verify against the nonce store.
	pub async fn verify<T: AdminAction>(
		&self,
		action: &T,
		signature: &[u8],
	) -> Result<Address, AdminAuthError> {
		// 1. Check deadline hasn't passed
		let now = chrono::Utc::now().timestamp() as u64;
		if action.deadline() < now {
			return Err(AdminAuthError::Expired);
		}

		// 2. Check nonce exists (don't consume yet - prevents DoS)
		// The nonce comes from the signed action contents
		let nonce = action.nonce();
		if !self.nonce_store.exists(nonce).await? {
			return Err(AdminAuthError::NonceNotFound);
		}

		// 3. Compute message hash and recover signer. Salt binds the digest to
		// this solver instance — see `AdminActionVerifier::domain_salt`.
		let message_hash = action.message_hash(self.chain_id, self.domain_salt)?;
		let signer = recover_from_hash(&message_hash.0, signature)?;

		// 4. Check signer is in admin registry
		if !self.admin_config.is_admin(&signer) {
			return Err(AdminAuthError::NotAuthorized(format!("{signer:?}")));
		}

		// 5. Consume nonce atomically (prevents replay)
		self.nonce_store.consume(nonce).await?;

		tracing::info!(
			admin = %signer,
			nonce = %nonce,
			"Admin action verified"
		);

		Ok(signer)
	}

	/// Generate a new nonce for an admin action.
	///
	/// The nonce should be included in the action contents before signing.
	/// Returns a u64 that is compatible with EIP-712's uint256 nonce field.
	pub async fn generate_nonce(&self) -> Result<u64, AdminAuthError> {
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

	/// Get the per-solver EIP-712 domain salt. Exposed so the admin API can
	/// echo it back to clients alongside the type definitions so they sign the
	/// right digest.
	pub fn domain_salt(&self) -> FixedBytes<32> {
		self.domain_salt
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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::auth::admin::types::AddTokenContents;
	use alloy_primitives::keccak256;
	use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
	use solver_storage::{nonce_store::create_nonce_store, StoreConfig};
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
	async fn test_verify_admin_action() {
		// Setup
		let secret = SecretKey::from_byte_array([0x42u8; 32]).expect("valid secret");
		let admin_address = address_from_secret(&secret);

		let nonce_store =
			Arc::new(create_nonce_store(StoreConfig::Memory, "test-verify", 300).unwrap());

		let admin_config = AdminConfig {
			enabled: true,
			domain: "test.example.com".to_string(),
			chain_id: Some(1),
			nonce_ttl_seconds: 300,
			whitelist: vec![AdminWhitelistEntry {
				address: admin_address,
				role: AdminRole::Admin,
			}],
		};

		let verifier = AdminActionVerifier::new(nonce_store.clone(), admin_config, 1, "test-solver");

		// Generate nonce (now returns u64)
		let nonce = verifier.generate_nonce().await.unwrap();

		// Create action with the generated nonce
		let action = AddTokenContents {
			chain_id: 10,
			symbol: "USDC".to_string(),
			name: None,
			token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			decimals: 6,
			nonce,
			deadline: (chrono::Utc::now().timestamp() + 300) as u64, // 5 min from now
		};

		// Sign
		let message_hash = action
			.message_hash(1, admin_domain_salt("test-solver"))
			.unwrap();
		let signature = sign_hash(&message_hash.0, &secret);

		// Verify - nonce is now extracted from action contents
		let result = verifier.verify(&action, &signature).await;
		assert!(result.is_ok());
		assert_eq!(result.unwrap(), admin_address);

		// Try to reuse nonce - should fail
		let result = verifier.verify(&action, &signature).await;
		assert!(matches!(result, Err(AdminAuthError::NonceNotFound)));
	}

	#[tokio::test]
	async fn test_verify_expired_action() {
		let secret = SecretKey::from_byte_array([0x42u8; 32]).expect("valid secret");
		let admin_address = address_from_secret(&secret);

		let nonce_store =
			Arc::new(create_nonce_store(StoreConfig::Memory, "test-expired", 300).unwrap());

		let admin_config = AdminConfig {
			enabled: true,
			domain: "test.example.com".to_string(),
			chain_id: Some(1),
			nonce_ttl_seconds: 300,
			whitelist: vec![AdminWhitelistEntry {
				address: admin_address,
				role: AdminRole::Admin,
			}],
		};

		let verifier = AdminActionVerifier::new(nonce_store.clone(), admin_config, 1, "test-solver");
		let nonce = verifier.generate_nonce().await.unwrap();

		// Create expired action
		let action = AddTokenContents {
			chain_id: 10,
			symbol: "USDC".to_string(),
			name: None,
			token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			decimals: 6,
			nonce,
			deadline: 1000, // Far in the past
		};

		let message_hash = action
			.message_hash(1, admin_domain_salt("test-solver"))
			.unwrap();
		let signature = sign_hash(&message_hash.0, &secret);

		let result = verifier.verify(&action, &signature).await;
		assert!(matches!(result, Err(AdminAuthError::Expired)));
	}

	#[tokio::test]
	async fn test_cross_solver_replay_is_rejected() {
		// Two solver instances share the same chain id and admin whitelist
		// (the same admin key is authorized on both). An admin signs an action
		// intended for solver A; the same signature presented to solver B must
		// be rejected because B's domain salt — derived from its own
		// `solver_id` — differs.
		let secret = SecretKey::from_byte_array([0x42u8; 32]).expect("valid secret");
		let admin_address = address_from_secret(&secret);

		let admin_config = AdminConfig {
			enabled: true,
			domain: "test.example.com".to_string(),
			chain_id: Some(1),
			nonce_ttl_seconds: 300,
			whitelist: vec![AdminWhitelistEntry {
				address: admin_address,
				role: AdminRole::Admin,
			}],
		};

		let nonce_store_a =
			Arc::new(create_nonce_store(StoreConfig::Memory, "solver-a", 300).unwrap());
		let nonce_store_b =
			Arc::new(create_nonce_store(StoreConfig::Memory, "solver-b", 300).unwrap());

		let verifier_a =
			AdminActionVerifier::new(nonce_store_a.clone(), admin_config.clone(), 1, "solver-a");
		let verifier_b =
			AdminActionVerifier::new(nonce_store_b.clone(), admin_config, 1, "solver-b");

		// Admin gets a nonce from each solver (real flow — clients pre-register
		// the nonce against the solver they intend to act on).
		let nonce_a = verifier_a.generate_nonce().await.unwrap();
		let nonce_b = verifier_b.generate_nonce().await.unwrap();

		// Sign for solver A using solver A's salt.
		let action_a = AddTokenContents {
			chain_id: 10,
			symbol: "USDC".to_string(),
			name: None,
			token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			decimals: 6,
			nonce: nonce_a,
			deadline: (chrono::Utc::now().timestamp() + 300) as u64,
		};
		let digest_a = action_a
			.message_hash(1, verifier_a.domain_salt())
			.expect("message hash for solver A");
		let signature_a = sign_hash(&digest_a.0, &secret);

		// Replay attempt: feed solver B the same signed payload, but with a
		// valid nonce from B's own store (otherwise the nonce check, not the
		// signature check, would be the gate). The signature was computed
		// under A's salt, so when B reconstructs the digest with B's salt the
		// recovered signer differs from `admin_address` and B rejects it.
		let mut action_replayed = action_a.clone();
		action_replayed.nonce = nonce_b;
		let result = verifier_b.verify(&action_replayed, &signature_a).await;
		assert!(
			matches!(result, Err(AdminAuthError::NotAuthorized(_))),
			"solver B must not accept solver A's signature; got {result:?}"
		);

		// Sanity: A accepts its own signature.
		assert!(verifier_a.verify(&action_a, &signature_a).await.is_ok());
	}

	#[tokio::test]
	async fn test_verify_non_admin() {
		let secret = SecretKey::from_byte_array([0x42u8; 32]).expect("valid secret");
		let other_address =
			Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

		let nonce_store =
			Arc::new(create_nonce_store(StoreConfig::Memory, "test-non-admin", 300).unwrap());

		let admin_config = AdminConfig {
			enabled: true,
			domain: "test.example.com".to_string(),
			chain_id: Some(1),
			nonce_ttl_seconds: 300,
			whitelist: vec![AdminWhitelistEntry {
				address: other_address,
				role: AdminRole::Admin,
			}], // Different address
		};

		let verifier = AdminActionVerifier::new(nonce_store.clone(), admin_config, 1, "test-solver");
		let nonce = verifier.generate_nonce().await.unwrap();

		let action = AddTokenContents {
			chain_id: 10,
			symbol: "USDC".to_string(),
			name: None,
			token_address: Address::from_str("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85").unwrap(),
			decimals: 6,
			nonce,
			deadline: (chrono::Utc::now().timestamp() + 300) as u64,
		};

		let message_hash = action
			.message_hash(1, admin_domain_salt("test-solver"))
			.unwrap();
		let signature = sign_hash(&message_hash.0, &secret);

		let result = verifier.verify(&action, &signature).await;
		assert!(matches!(result, Err(AdminAuthError::NotAuthorized(_))));
	}
}
