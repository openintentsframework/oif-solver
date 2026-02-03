//! Token minting operations
//!
//! Provides functionality to mint test tokens on local blockchain networks.
//! Restricted to local mode for security and handles both individual and
//! batch minting operations with automatic transaction management.

use crate::{
	types::{
		chain::ChainId,
		error::{Error, Result},
	},
	Context,
};
use alloy_primitives::{Address, U256};
use std::{str::FromStr, sync::Arc};
use tracing::instrument;

use super::MintResult;

/// Token minting operations handler
///
/// Provides methods for minting test tokens in local development environments.
/// Enforces local mode restrictions and handles transaction signing and execution
/// for both single and batch minting operations.
pub struct MintOps {
	ctx: Arc<Context>,
}

impl MintOps {
	/// Creates a new mint operations handler
	///
	/// # Arguments
	/// * `ctx` - Shared application context containing configuration and services
	///
	/// # Returns
	/// New mint operations instance
	pub fn new(ctx: Arc<Context>) -> Self {
		Self { ctx }
	}

	/// Mints test tokens to a specified recipient
	///
	/// # Arguments
	/// * `chain` - Target blockchain network identifier
	/// * `token_symbol` - Symbol of the token to mint
	/// * `recipient` - Recipient address, uses default user account if None
	/// * `amount` - Amount to mint in token's smallest unit
	///
	/// # Returns
	/// Mint result containing transaction hash and metadata
	///
	/// # Errors
	/// Returns error if not in local mode, token not found, transaction fails,
	/// or provider unavailable
	#[instrument(skip(self))]
	pub async fn mint(
		&self,
		chain: ChainId,
		token_symbol: &str,
		recipient: Option<Address>,
		amount: U256,
	) -> Result<MintResult> {
		use crate::core::logging;
		logging::verbose_tech(
			"Starting token mint operation",
			&format!(
				"chain: {chain}, token: {token_symbol}, amount: {amount}"
			),
		);

		let recipient = recipient.unwrap_or_else(|| self.get_default_recipient());
		let token = self.ctx.tokens.get_or_error(chain, token_symbol)?;
		let provider = self.ctx.provider(chain).await?;

		let contracts = self.ctx.contracts.read().unwrap().clone();
		let call_data = contracts.erc20_mint(recipient, amount)?;

		let solver_signer = self.get_solver_signer()?;
		let tx_builder =
			crate::core::blockchain::TxBuilder::new(provider).with_signer(solver_signer);

		let tx = alloy_rpc_types::TransactionRequest::default()
			.to(token.address)
			.input(call_data.into());

		let receipt = tx_builder.send_and_wait(tx).await?;

		if !receipt.status() {
			return Err(Error::ContractCallFailed(
				"Mint transaction failed".to_string(),
			));
		}

		Ok(MintResult {
			tx_hash: Some(format!("{:?}", receipt.transaction_hash)),
			recipient,
			amount,
			token: token_symbol.to_string(),
		})
	}

	/// Mints multiple tokens in a batch operation
	///
	/// # Arguments
	/// * `chain` - Target blockchain network identifier
	/// * `mints` - Vector of (token_symbol, recipient, amount) tuples
	///
	/// # Returns
	/// Vector of mint results for each minting operation
	///
	/// # Errors
	/// Returns error if any individual mint operation fails
	pub async fn mint_batch(
		&self,
		chain: ChainId,
		mints: Vec<(String, Address, U256)>,
	) -> Result<Vec<MintResult>> {
		let mut results = Vec::new();

		for (token, recipient, amount) in mints {
			let result = self.mint(chain, &token, Some(recipient), amount).await?;
			results.push(result);
		}

		Ok(results)
	}

	/// Retrieves the default recipient address from configuration
	///
	/// # Returns
	/// Default user account address or fallback address if parsing fails
	fn get_default_recipient(&self) -> Address {
		use crate::types::hex::Hex;
		Hex::to_address(&self.ctx.config.accounts().user.address)
			.unwrap_or_else(|_| Address::from([0x01; 20]))
	}

	/// Creates a signer for the solver account
	///
	/// # Returns
	/// Private key signer for transaction signing
	///
	/// # Errors
	/// Returns error if private key parsing fails
	fn get_solver_signer(&self) -> Result<alloy_signer_local::PrivateKeySigner> {
		use crate::constants::anvil_accounts::SOLVER_PRIVATE_KEY;

		if let Some(private_key) = self.ctx.config.accounts().solver.private_key.as_ref() {
			private_key.with_exposed(|key| {
				alloy_signer_local::PrivateKeySigner::from_str(key)
					.map_err(|_| Error::InvalidPrivateKey)
			})
		} else {
			alloy_signer_local::PrivateKeySigner::from_str(SOLVER_PRIVATE_KEY)
				.map_err(|_| Error::InvalidPrivateKey)
		}
	}
}
