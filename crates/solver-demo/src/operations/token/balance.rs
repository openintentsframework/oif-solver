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

use super::{BalanceResult, EnhancedBalanceResult};

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

	/// Balance query method supporting multiple chains, tokens, and accounts
	///
	/// # Arguments
	/// * `chains` - Vector of chain IDs to query
	/// * `tokens` - Vector of token symbols to query on each chain
	/// * `accounts` - Vector of account addresses to query for each token
	///
	/// # Returns
	/// Vector of enhanced balance results for all combinations
	///
	/// # Errors
	/// Individual query failures are logged but don't stop the entire operation
	pub async fn balance(
		&self,
		chains: Vec<ChainId>,
		tokens: Vec<String>,
		accounts: Vec<Address>,
	) -> Result<Vec<EnhancedBalanceResult>> {
		use futures::future::join_all;

		// Create futures for all (chain, token, account) combinations
		let balance_futures: Vec<_> = chains
			.iter()
			.flat_map(|&chain| {
				let accounts_clone = accounts.clone();
				tokens.iter().flat_map(move |token| {
					let accounts_inner = accounts_clone.clone();
					accounts_inner.into_iter().map(move |account| {
						let token_clone = token.clone();
						async move {
							let result = self.query_single_balance(chain, &token_clone, account).await;
							(chain, token_clone, account, result)
						}
					})
				})
			})
			.collect();

		// Execute all queries in parallel
		let query_results = join_all(balance_futures).await;

		// Collect successful results into enhanced format
		let mut results = Vec::new();
		for (chain, token, account, balance_result) in query_results {
			match balance_result {
				Ok(balance_result) => {
					results.push(EnhancedBalanceResult {
						balance: balance_result.balance,
						formatted: balance_result.formatted,
						token: balance_result.token,
						account: balance_result.account,
						chain,
					});
				},
				Err(e) => {
					// Log individual failures but continue
					tracing::warn!(
						"Failed to query balance for chain={:?}, token={}, account={:?}: {}",
						chain,
						token,
						account,
						e
					);
				},
			}
		}

		Ok(results)
	}

	/// Internal method to query a single balance combination
	///
	/// # Arguments
	/// * `chain` - Target blockchain network identifier
	/// * `token_symbol` - Symbol of the token to query
	/// * `account` - Account address to check
	///
	/// # Returns
	/// Balance result containing raw balance, formatted balance, and metadata
	///
	/// # Errors
	/// Returns error if token not found, provider unavailable, or balance query fails
	async fn query_single_balance(
		&self,
		chain: ChainId,
		token_symbol: &str,
		account: Address,
	) -> Result<BalanceResult> {
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
	pub fn get_default_account(&self) -> Address {
		use crate::types::hex::Hex;
		Hex::to_address(&self.ctx.config.accounts().user.address)
			.unwrap_or_else(|_| Address::from([0x01; 20]))
	}
}
