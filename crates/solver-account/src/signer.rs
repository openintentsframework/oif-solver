//! Unified signer abstraction for different signing backends.
//!
//! This module provides the `AccountSigner` enum which allows delivery code
//! to work with any signer type without knowing the underlying implementation.

use alloy_consensus::SignableTransaction;
use alloy_network::TxSigner;
use alloy_primitives::{Address, Signature, B256};
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

	/// Returns the signer's chain ID.
	pub fn chain_id(&self) -> Option<u64> {
		match self {
			Self::Local(s) => Signer::chain_id(s),
			#[cfg(feature = "kms")]
			Self::Kms(s) => Signer::chain_id(s),
		}
	}

	/// Sets the chain ID.
	pub fn set_chain_id(&mut self, chain_id: Option<u64>) {
		match self {
			Self::Local(s) => Signer::set_chain_id(s, chain_id),
			#[cfg(feature = "kms")]
			Self::Kms(s) => Signer::set_chain_id(s, chain_id),
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

	/// Signs the given hash.
	pub async fn sign_hash(&self, hash: &B256) -> alloy_signer::Result<Signature> {
		match self {
			Self::Local(s) => s.sign_hash(hash).await,
			#[cfg(feature = "kms")]
			Self::Kms(s) => s.sign_hash(hash).await,
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
			Self::Local(_) => f.debug_struct("AccountSigner::Local").finish_non_exhaustive(),
			#[cfg(feature = "kms")]
			Self::Kms(_) => f.debug_struct("AccountSigner::Kms").finish_non_exhaustive(),
		}
	}
}
