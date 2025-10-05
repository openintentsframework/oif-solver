//! Token approval operations
//!
//! Provides functionality to manage ERC20 token approvals for spending by
//! third-party contracts or accounts. Supports approval, revocation, allowance
//! checking, and batch operations with automatic transaction management.

use crate::{
	types::{chain::ChainId, error::Result},
	Context,
};
use alloy_primitives::{Address, U256};
use std::{str::FromStr, sync::Arc};

use super::ApprovalResult;

/// Token approval operations handler
///
/// Provides methods for managing ERC20 token approvals including setting
/// allowances, checking current approvals, revoking permissions, and handling
/// batch approval operations with user account authentication.
pub struct ApprovalOps {
	ctx: Arc<Context>,
}

impl ApprovalOps {
	/// Creates a new approval operations handler
	///
	/// # Arguments
	/// * `ctx` - Shared application context containing configuration and services
	///
	/// # Returns
	/// New approval operations instance
	pub fn new(ctx: Arc<Context>) -> Self {
		Self { ctx }
	}

	/// Approves token spending for a specified spender
	///
	/// # Arguments
	/// * `chain` - Target blockchain network identifier
	/// * `token_symbol` - Symbol of the token to approve
	/// * `spender` - Address authorized to spend tokens
	/// * `amount` - Amount to approve, uses maximum if None
	///
	/// # Returns
	/// Approval result containing transaction hash and metadata
	///
	/// # Errors
	/// Returns error if token not found, transaction fails, or provider unavailable
	pub async fn approve(
		&self,
		chain: ChainId,
		token_symbol: &str,
		spender: Address,
		amount: Option<U256>,
	) -> Result<ApprovalResult> {
		let token = self.ctx.tokens.get_or_error(chain, token_symbol)?;
		let amount = amount.unwrap_or(U256::MAX);
		let provider = self.ctx.provider(chain).await?;

		let contracts = self.ctx.contracts.read().unwrap().clone();
		let call_data = contracts.erc20_approve(spender, amount)?;

		let user_signer = self.get_user_signer()?;
		let tx_builder = crate::core::blockchain::TxBuilder::new(provider).with_signer(user_signer);

		let tx = alloy_rpc_types::TransactionRequest::default()
			.to(token.address)
			.input(call_data.into());

		let receipt = tx_builder.send_and_wait(tx).await?;

		if !receipt.status() {
			return Err(crate::types::error::Error::ContractCallFailed(
				"Approve transaction failed".to_string(),
			));
		}

		Ok(ApprovalResult {
			tx_hash: Some(format!("{:?}", receipt.transaction_hash)),
			spender,
			amount,
			token: token_symbol.to_string(),
		})
	}

	/// Approves multiple tokens in a batch operation
	///
	/// # Arguments
	/// * `chain` - Target blockchain network identifier
	/// * `approvals` - Vector of (token_symbol, spender, amount) tuples
	///
	/// # Returns
	/// Vector of approval results for each approval operation
	///
	/// # Errors
	/// Returns error if any individual approval operation fails
	pub async fn approve_batch(
		&self,
		chain: ChainId,
		approvals: Vec<(String, Address, Option<U256>)>,
	) -> Result<Vec<ApprovalResult>> {
		let mut results = Vec::new();

		for (token, spender, amount) in approvals {
			let result = self.approve(chain, &token, spender, amount).await?;
			results.push(result);
		}

		Ok(results)
	}

	/// Queries the current allowance for a spender
	///
	/// # Arguments
	/// * `chain` - Target blockchain network identifier
	/// * `token_symbol` - Symbol of the token to check
	/// * `owner` - Token owner's address
	/// * `spender` - Address authorized to spend tokens
	///
	/// # Returns
	/// Current allowance amount
	///
	/// # Errors
	/// Returns error if token not found, contract call fails, or provider unavailable
	pub async fn allowance(
		&self,
		chain: ChainId,
		token_symbol: &str,
		owner: Address,
		spender: Address,
	) -> Result<U256> {
		let token = self.ctx.tokens.get_or_error(chain, token_symbol)?;
		let provider = self.ctx.provider(chain).await?;

		let contracts = self.ctx.contracts.read().unwrap().clone();
		let result = contracts
			.erc20_call(
				&provider,
				token.address,
				"allowance",
				vec![
					alloy_dyn_abi::DynSolValue::Address(owner),
					alloy_dyn_abi::DynSolValue::Address(spender),
				],
			)
			.await?;

		let allowance = U256::from_be_slice(&result);
		Ok(allowance)
	}

	/// Revokes approval by setting allowance to zero
	///
	/// # Arguments
	/// * `chain` - Target blockchain network identifier
	/// * `token_symbol` - Symbol of the token to revoke
	/// * `spender` - Address to revoke approval from
	///
	/// # Returns
	/// Approval result for the revocation transaction
	///
	/// # Errors
	/// Returns error if approval transaction fails
	pub async fn revoke(
		&self,
		chain: ChainId,
		token_symbol: &str,
		spender: Address,
	) -> Result<ApprovalResult> {
		self.approve(chain, token_symbol, spender, Some(U256::ZERO))
			.await
	}

	/// Creates a signer for the user account
	///
	/// # Returns
	/// Private key signer for transaction signing
	///
	/// # Errors
	/// Returns error if private key parsing fails
	fn get_user_signer(&self) -> Result<alloy_signer_local::PrivateKeySigner> {
		use crate::constants::anvil_accounts::USER_PRIVATE_KEY;
		let user_pk = self
			.ctx
			.config
			.accounts()
			.user
			.private_key
			.as_ref()
			.map(|secret| secret.expose_secret().to_string())
			.unwrap_or_else(|| USER_PRIVATE_KEY.to_string());

		alloy_signer_local::PrivateKeySigner::from_str(&user_pk)
			.map_err(|_| crate::types::error::Error::InvalidPrivateKey)
	}
}
