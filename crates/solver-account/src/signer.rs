//! Unified signer abstraction for different signing backends.
//!
//! This module provides the `AccountSigner` enum which allows delivery code
//! to work with any signer type without knowing the underlying implementation.

use alloy_consensus::SignableTransaction;
use alloy_network::TxSigner;
use alloy_primitives::{Address, Signature};
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use async_trait::async_trait;

#[cfg(feature = "kms")]
use alloy_signer_aws::AwsSigner;

/// Unified signer that wraps different signing backends.
///
/// This enum allows delivery code to work with any signer type
/// without knowing the underlying implementation.
///
/// Both variants implement Clone (verified: AwsSigner implements Clone).
#[derive(Clone)]
pub enum AccountSigner {
	/// Local signer using a private key stored in memory.
	Local(PrivateKeySigner),
	/// AWS KMS signer (only available with `kms` feature).
	#[cfg(feature = "kms")]
	Kms(AwsSigner),
}

impl AccountSigner {
	/// Returns the signer's Ethereum address.
	pub fn address(&self) -> Address {
		match self {
			Self::Local(s) => Signer::address(s),
			#[cfg(feature = "kms")]
			Self::Kms(s) => Signer::address(s),
		}
	}

	/// Returns a new signer with the specified chain ID.
	pub fn with_chain_id(self, chain_id: Option<u64>) -> Self {
		match self {
			Self::Local(s) => Self::Local(Signer::with_chain_id(s, chain_id)),
			#[cfg(feature = "kms")]
			Self::Kms(s) => Self::Kms(Signer::with_chain_id(s, chain_id)),
		}
	}
}

// Implement TxSigner trait for AccountSigner so it works with EthereumWallet
#[async_trait]
impl TxSigner<Signature> for AccountSigner {
	fn address(&self) -> Address {
		AccountSigner::address(self)
	}

	async fn sign_transaction(
		&self,
		tx: &mut dyn SignableTransaction<Signature>,
	) -> alloy_signer::Result<Signature> {
		match self {
			Self::Local(s) => TxSigner::sign_transaction(s, tx).await,
			#[cfg(feature = "kms")]
			Self::Kms(s) => TxSigner::sign_transaction(s, tx).await,
		}
	}
}

impl std::fmt::Debug for AccountSigner {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Local(_) => f
				.debug_struct("AccountSigner::Local")
				.finish_non_exhaustive(),
			#[cfg(feature = "kms")]
			Self::Kms(_) => f.debug_struct("AccountSigner::Kms").finish_non_exhaustive(),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const TEST_PRIVATE_KEY: &str =
		"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

	fn create_test_signer() -> AccountSigner {
		let signer: PrivateKeySigner = TEST_PRIVATE_KEY.parse().unwrap();
		AccountSigner::Local(signer)
	}

	#[test]
	fn test_account_signer_address() {
		let signer = create_test_signer();
		let address = signer.address();
		// Anvil account #0 address (lowercase)
		assert_eq!(
			format!("{address:?}").to_lowercase(),
			"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
		);
	}

	#[test]
	fn test_account_signer_with_chain_id() {
		let signer = create_test_signer();
		let with_chain = signer.with_chain_id(Some(1));
		// Address must remain stable after binding a chain id
		assert_eq!(
			format!("{:?}", with_chain.address()).to_lowercase(),
			"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
		);
	}

	#[test]
	fn test_account_signer_clone() {
		let signer = create_test_signer();
		let cloned = signer.clone();
		assert_eq!(signer.address(), cloned.address());
	}

	#[tokio::test]
	async fn test_account_signer_tx_signer_address() {
		let signer = create_test_signer();
		let address = <AccountSigner as TxSigner<Signature>>::address(&signer);
		assert_eq!(
			format!("{address:?}").to_lowercase(),
			"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
		);
	}

	#[test]
	fn test_account_signer_debug() {
		let signer = create_test_signer();
		let debug_str = format!("{signer:?}");
		assert!(debug_str.contains("AccountSigner::Local"));
	}
}
