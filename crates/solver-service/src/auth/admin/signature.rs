//! Signature recovery utilities for admin authentication.
//!
//! Provides functions to recover Ethereum addresses from signatures,
//! supporting both EIP-191 personal_sign and EIP-712 typed data.

use alloy_primitives::{keccak256, Address, B256};
use alloy_signer::Signature;

use super::error::AdminAuthError;
use solver_types::AdminConfig;

/// Recover Ethereum address from an EIP-191 personal_sign signature.
///
/// EIP-191 prepends the message with:
/// `"\x19Ethereum Signed Message:\n" + message.length + message`
///
/// This is the format used by `personal_sign` in wallets.
///
/// # Arguments
///
/// * `message` - The original message that was signed (as bytes)
/// * `signature` - The 65-byte signature (r: 32, s: 32, v: 1)
///
/// # Returns
///
/// The recovered Ethereum address, or an error if recovery fails.
pub fn recover_personal_sign(message: &[u8], signature: &[u8]) -> Result<Address, AdminAuthError> {
	// EIP-191: "\x19Ethereum Signed Message:\n" + len(message) + message
	let prefixed = format!("\x19Ethereum Signed Message:\n{}", message.len());
	let mut prefixed_message = prefixed.into_bytes();
	prefixed_message.extend_from_slice(message);

	let hash = keccak256(&prefixed_message);
	recover_from_hash(&hash.0, signature)
}

/// Recover Ethereum address from a pre-hashed message.
///
/// Use this for EIP-712 typed data where you've already computed the
/// typed data hash according to the EIP-712 specification.
///
/// # Arguments
///
/// * `hash` - The 32-byte message hash
/// * `signature` - The 65-byte signature (r: 32, s: 32, v: 1)
///
/// # Returns
///
/// The recovered Ethereum address, or an error if recovery fails.
pub fn recover_from_hash(hash: &[u8; 32], signature: &[u8]) -> Result<Address, AdminAuthError> {
	if signature.len() != 65 {
		return Err(AdminAuthError::InvalidSignature(format!(
			"Signature must be 65 bytes, got {}",
			signature.len()
		)));
	}

	let sig = Signature::try_from(signature)
		.map_err(|e| AdminAuthError::InvalidSignature(format!("Invalid signature: {e}")))?;

	sig.recover_address_from_prehash(&B256::from(*hash))
		.map_err(|e| AdminAuthError::SignatureVerification(format!("Recovery failed: {e}")))
}

/// Verify a signature and check if the signer is an admin.
///
/// This is a convenience function that combines signature recovery
/// with admin registry lookup.
///
/// # Arguments
///
/// * `message` - The original message that was signed
/// * `signature` - The 65-byte signature
/// * `config` - Admin configuration containing the admin registry
///
/// # Returns
///
/// The recovered address if valid and authorized, or an error.
pub fn verify_admin_signature(
	message: &[u8],
	signature: &[u8],
	config: &AdminConfig,
) -> Result<Address, AdminAuthError> {
	// Recover the signer
	let address = recover_personal_sign(message, signature)?;

	// Check if signer is an admin
	if !config.is_admin(&address) {
		return Err(AdminAuthError::NotAuthorized(format!("{address:?}")));
	}

	Ok(address)
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_signer::SignerSync;
	use alloy_signer_local::PrivateKeySigner;
	use std::str::FromStr;

	/// Create a test signer from a 32-byte secret
	fn test_signer(secret: [u8; 32]) -> PrivateKeySigner {
		PrivateKeySigner::from_bytes(&B256::from(secret)).expect("valid secret")
	}

	#[test]
	fn test_recover_personal_sign() {
		let signer = test_signer([0x42u8; 32]);
		let message = b"Hello, World!";

		let sig = signer.sign_message_sync(message).unwrap();
		let recovered = recover_personal_sign(message, &sig.as_bytes()).unwrap();

		assert_eq!(recovered, signer.address());
	}

	#[test]
	fn test_recover_personal_sign_with_nonce() {
		let signer = test_signer([0x42u8; 32]);
		let message = b"solver.example.com wants you to sign in...\nNonce: abc123";

		let sig = signer.sign_message_sync(message).unwrap();
		let recovered = recover_personal_sign(message, &sig.as_bytes()).unwrap();

		assert_eq!(recovered, signer.address());
	}

	#[test]
	fn test_invalid_signature_length() {
		let result = recover_personal_sign(b"test", &[0u8; 64]); // Too short
		assert!(matches!(result, Err(AdminAuthError::InvalidSignature(_))));

		let result = recover_personal_sign(b"test", &[0u8; 66]); // Too long
		assert!(matches!(result, Err(AdminAuthError::InvalidSignature(_))));
	}

	#[test]
	fn test_invalid_recovery_id() {
		let mut sig = [0u8; 65];
		sig[64] = 30; // Invalid v value

		let result = recover_personal_sign(b"test", &sig);
		assert!(matches!(result, Err(AdminAuthError::InvalidSignature(_))));
	}

	#[test]
	fn test_verify_admin_signature_authorized() {
		let signer = test_signer([0x42u8; 32]);
		let message = b"test message";

		let config = AdminConfig {
			enabled: true,
			domain: "test.example.com".to_string(),
			chain_id: Some(1),
			nonce_ttl_seconds: 300,
			admin_addresses: vec![signer.address()],
		};

		let sig = signer.sign_message_sync(message).unwrap();
		let result = verify_admin_signature(message, &sig.as_bytes(), &config);

		assert!(result.is_ok());
		assert_eq!(result.unwrap(), signer.address());
	}

	#[test]
	fn test_verify_admin_signature_not_authorized() {
		let signer = test_signer([0x42u8; 32]);
		let other_address =
			Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

		let config = AdminConfig {
			enabled: true,
			domain: "test.example.com".to_string(),
			chain_id: Some(1),
			nonce_ttl_seconds: 300,
			admin_addresses: vec![other_address], // Different address
		};

		let sig = signer.sign_message_sync(b"test message").unwrap();
		let result = verify_admin_signature(b"test message", &sig.as_bytes(), &config);

		assert!(matches!(result, Err(AdminAuthError::NotAuthorized(_))));
	}

	#[test]
	fn test_recover_from_hash_directly() {
		let signer = test_signer([0x42u8; 32]);
		let hash = B256::from([0x11u8; 32]);

		let sig = signer.sign_hash_sync(&hash).unwrap();
		let recovered = recover_from_hash(&hash.0, &sig.as_bytes()).unwrap();

		assert_eq!(recovered, signer.address());
	}
}
