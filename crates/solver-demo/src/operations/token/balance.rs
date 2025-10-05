//! Token balance query operations
//!
//! Provides functionality to query token balances across different blockchain networks
//! for both ERC20 tokens and native tokens. Supports both single and batch balance
//! queries with automatic account resolution and balance formatting.

use crate::{
	types::{chain::ChainId, error::Result},
	Context,
};
use alloy_primitives::{Address, U256};
use std::sync::Arc;

use super::BalanceResult;

/// Balance query operations handler
///
/// Provides methods for querying token balances on various blockchain networks.
/// Handles ERC20 token balances, native token balances, and batch operations
/// with automatic formatting and account resolution.
pub struct BalanceOps {
	ctx: Arc<Context>,
}

impl BalanceOps {
	/// Creates a new balance operations handler
	///
	/// # Arguments
	/// * `ctx` - Shared application context containing configuration and services
	///
	/// # Returns
	/// New balance operations instance
	pub fn new(ctx: Arc<Context>) -> Self {
		Self { ctx }
	}

	/// Queries the balance of a specific token for an account
	///
	/// # Arguments
	/// * `chain` - Target blockchain network identifier
	/// * `token_symbol` - Symbol of the token to query
	/// * `account` - Account address to check, uses default user account if None
	///
	/// # Returns
	/// Balance result containing raw balance, formatted balance, and metadata
	///
	/// # Errors
	/// Returns error if token not found, provider unavailable, or balance query fails
	pub async fn balance(
		&self,
		chain: ChainId,
		token_symbol: &str,
		account: Option<Address>,
	) -> Result<BalanceResult> {
		let account = account.unwrap_or_else(|| self.get_default_account());
		let token = self.ctx.tokens.get_or_error(chain, token_symbol)?;
		let provider = self.ctx.provider(chain).await?;

		let balance = self
			.query_balance(&provider, token.address, account)
			.await?;

		let formatted = self.format_balance(balance, token.decimals);

		Ok(BalanceResult {
			balance,
			formatted,
			token: token_symbol.to_string(),
			account,
		})
	}

	/// Queries balances for multiple tokens for an account
	///
	/// # Arguments
	/// * `chain` - Target blockchain network identifier
	/// * `tokens` - Vector of token symbols to query
	/// * `account` - Account address to check, uses default user account if None
	///
	/// # Returns
	/// Vector of balance results for each requested token
	///
	/// # Errors
	/// Returns error if any token query fails
	pub async fn balance_batch(
		&self,
		chain: ChainId,
		tokens: Vec<String>,
		account: Option<Address>,
	) -> Result<Vec<BalanceResult>> {
		let mut results = Vec::new();

		for token in tokens {
			let result = self.balance(chain, &token, account).await?;
			results.push(result);
		}

		Ok(results)
	}

	/// Queries the native token balance for an account
	///
	/// # Arguments
	/// * `chain` - Target blockchain network identifier
	/// * `account` - Account address to check, uses default user account if None
	///
	/// # Returns
	/// Native token balance in wei
	///
	/// # Errors
	/// Returns error if provider unavailable or balance query fails
	pub async fn native_balance(&self, chain: ChainId, account: Option<Address>) -> Result<U256> {
		let account = account.unwrap_or_else(|| self.get_default_account());
		let provider = self.ctx.provider(chain).await?;

		provider.balance(account).await
	}

	/// Executes blockchain balance query using ERC20 contract
	///
	/// # Arguments
	/// * `provider` - Blockchain provider for network communication
	/// * `token_address` - Contract address of the ERC20 token
	/// * `account` - Account address to query balance for
	///
	/// # Returns
	/// Raw token balance from the blockchain
	///
	/// # Errors
	/// Returns error if contract interaction fails or provider error occurs
	async fn query_balance(
		&self,
		provider: &crate::core::blockchain::Provider,
		token_address: Address,
		account: Address,
	) -> Result<U256> {
		let contracts = self.ctx.contracts.read().unwrap().clone();
		contracts
			.erc20_balance(provider, token_address, account)
			.await
	}

	/// Formats raw balance with appropriate decimal places
	///
	/// # Arguments
	/// * `balance` - Raw balance in smallest unit (wei)
	/// * `decimals` - Number of decimal places for the token
	///
	/// # Returns
	/// Human-readable formatted balance string with up to 6 decimal places
	fn format_balance(&self, balance: U256, decimals: u8) -> String {
		let divisor = U256::from(10u64).pow(U256::from(decimals));
		let whole = balance / divisor;
		let fraction = balance % divisor;

		if fraction.is_zero() {
			format!("{}", whole)
		} else {
			let fraction_str = format!("{:0width$}", fraction, width = decimals as usize);
			let trimmed = fraction_str.trim_end_matches('0');
			if trimmed.is_empty() {
				format!("{}", whole)
			} else {
				format!("{}.{}", whole, &trimmed[..trimmed.len().min(6)])
			}
		}
	}

	/// Retrieves the default user account address from configuration
	///
	/// # Returns
	/// Default user account address or fallback address if parsing fails
	fn get_default_account(&self) -> Address {
		use crate::types::hex::Hex;
		Hex::to_address(&self.ctx.config.accounts().user.address)
			.unwrap_or_else(|_| Address::from([0x01; 20]))
	}
}
