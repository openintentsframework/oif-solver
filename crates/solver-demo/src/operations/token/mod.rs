//! Token operations module
//!
//! Provides comprehensive token management functionality across multiple blockchain
//! networks including token discovery, balance queries, minting operations, and
//! approval management. Coordinates all token-related operations through specialized
//! handlers with unified error handling and address resolution.

mod approve;
mod balance;
mod mint;

pub use approve::ApprovalOps;
pub use balance::BalanceOps;
pub use mint::MintOps;

use crate::{
	types::{
		chain::ChainId,
		error::{Error, Result},
	},
	Context,
};
use alloy_primitives::{Address, U256};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::instrument;

/// Token operations coordinator
///
/// Central coordinator for all token-related operations across blockchain networks.
/// Provides unified access to token listing, minting, balance checking, and approval
/// management through specialized operation handlers with shared context and configuration.
pub struct TokenOps {
	ctx: Arc<Context>,
	mint_ops: MintOps,
	balance_ops: BalanceOps,
	approval_ops: ApprovalOps,
}

impl TokenOps {
	/// Creates a new token operations coordinator
	///
	/// # Arguments
	/// * `ctx` - Shared application context containing configuration and services
	///
	/// # Returns
	/// New token operations coordinator with initialized operation handlers
	pub fn new(ctx: Arc<Context>) -> Self {
		let mint_ops = MintOps::new(ctx.clone());
		let balance_ops = BalanceOps::new(ctx.clone());
		let approval_ops = ApprovalOps::new(ctx.clone());

		Self {
			ctx,
			mint_ops,
			balance_ops,
			approval_ops,
		}
	}

	/// Lists available tokens across multiple blockchain networks
	///
	/// # Arguments
	/// * `chains` - Optional list of chain IDs to query, uses all configured chains if None
	///
	/// # Returns
	/// Token list containing tokens organized by blockchain network
	///
	/// # Errors
	/// Returns error if any chain query fails or address conversion fails
	#[instrument(skip(self))]
	pub async fn list(&self, chains: Option<Vec<ChainId>>) -> Result<TokenList> {
		let chains = chains.unwrap_or_else(|| self.ctx.config.chains());
		let mut tokens_by_chain = HashMap::new();

		for chain in chains {
			let tokens = self.list_for_chain(chain)?;
			if !tokens.is_empty() {
				tokens_by_chain.insert(chain, tokens);
			}
		}

		Ok(TokenList { tokens_by_chain })
	}

	/// Lists tokens available on a specific blockchain network
	///
	/// # Arguments
	/// * `chain` - Target blockchain network identifier
	///
	/// # Returns
	/// Vector of token information for the specified chain
	///
	/// # Errors
	/// Returns error if address conversion fails or network configuration invalid
	pub fn list_for_chain(&self, chain: ChainId) -> Result<Vec<TokenInfo>> {
		let mut tokens = Vec::new();

		if let Some(network) = self.ctx.config.network(chain) {
			for token in &network.tokens {
				let addr_bytes: [u8; 20] = token.address.0.as_slice().try_into().map_err(|_| {
					Error::InvalidAddress(format!("Invalid address for {}", token.symbol))
				})?;

				tokens.push(TokenInfo {
					symbol: token.symbol.clone(),
					address: Address::from(addr_bytes),
					decimals: token.decimals,
				});
			}
		}

		if let Some(contracts) = self.ctx.session.contracts(chain) {
			for (symbol, token_info) in contracts.tokens {
				if let Ok(addr) = token_info.address.parse::<Address>() {
					if !tokens.iter().any(|t| t.symbol == symbol) {
						tokens.push(TokenInfo {
							symbol,
							address: addr,
							decimals: token_info.decimals,
						});
					}
				}
			}
		}

		Ok(tokens)
	}

	/// Retrieves token information by symbol for a specific chain
	///
	/// # Arguments
	/// * `chain` - Target blockchain network identifier
	/// * `symbol` - Token symbol to search for (case-insensitive)
	///
	/// # Returns
	/// Token information if found
	///
	/// # Errors
	/// Returns error if token not found on the specified chain
	pub fn get_token(&self, chain: ChainId, symbol: &str) -> Result<TokenInfo> {
		let tokens = self.list_for_chain(chain)?;
		tokens
			.into_iter()
			.find(|t| t.symbol.eq_ignore_ascii_case(symbol))
			.ok_or_else(|| Error::TokenNotFound(symbol.to_string(), chain.id()))
	}

	/// Mints test tokens with automatic address resolution
	///
	/// # Arguments
	/// * `chain` - Target blockchain network identifier
	/// * `token_symbol` - Symbol of the token to mint
	/// * `recipient_str` - Optional recipient address string, uses default if None
	/// * `amount` - Amount to mint in token's smallest unit
	///
	/// # Returns
	/// Mint result containing transaction hash and metadata
	///
	/// # Errors
	/// Returns error if address resolution fails or minting operation fails
	#[instrument(skip(self))]
	pub async fn mint(
		&self,
		chain: ChainId,
		token_symbol: &str,
		recipient_str: Option<&str>,
		amount: U256,
	) -> Result<MintResult> {
		let recipient = if let Some(addr_str) = recipient_str {
			Some(self.ctx.resolve_address(addr_str)?)
		} else {
			None
		};
		self.mint_ops
			.mint(chain, token_symbol, recipient, amount)
			.await
	}

	/// Checks token balance with automatic address resolution
	///
	/// # Arguments
	/// * `chain` - Target blockchain network identifier
	/// * `token_symbol` - Symbol of the token to check
	/// * `account_str` - Optional account address string, uses default if None
	///
	/// # Returns
	/// Balance result containing raw and formatted balance information
	///
	/// # Errors
	/// Returns error if address resolution fails or balance query fails
	pub async fn balance(
		&self,
		chain: ChainId,
		token_symbol: &str,
		account_str: Option<&str>,
	) -> Result<BalanceResult> {
		let account = if let Some(addr_str) = account_str {
			Some(self.ctx.resolve_address(addr_str)?)
		} else {
			None
		};
		self.balance_ops.balance(chain, token_symbol, account).await
	}

	/// Approves token spending with automatic address resolution
	///
	/// # Arguments
	/// * `chain` - Target blockchain network identifier
	/// * `token_symbol` - Symbol of the token to approve
	/// * `spender_str` - Spender address string
	/// * `amount` - Optional amount to approve, uses maximum if None
	///
	/// # Returns
	/// Approval result containing transaction hash and metadata
	///
	/// # Errors
	/// Returns error if address resolution fails or approval operation fails
	pub async fn approve(
		&self,
		chain: ChainId,
		token_symbol: &str,
		spender_str: &str,
		amount: Option<U256>,
	) -> Result<ApprovalResult> {
		let spender = self.ctx.resolve_address(spender_str)?;
		self.approval_ops
			.approve(chain, token_symbol, spender, amount)
			.await
	}
}

/// Token information
#[derive(Debug, Clone)]
pub struct TokenInfo {
	pub symbol: String,
	pub address: Address,
	pub decimals: u8,
}

/// Token list result
#[derive(Debug, Clone)]
pub struct TokenList {
	pub tokens_by_chain: HashMap<ChainId, Vec<TokenInfo>>,
}

/// Mint operation result
#[derive(Debug, Clone)]
pub struct MintResult {
	pub tx_hash: Option<String>,
	pub recipient: Address,
	pub amount: U256,
	pub token: String,
}

/// Balance query result
#[derive(Debug, Clone)]
pub struct BalanceResult {
	pub balance: U256,
	pub formatted: String,
	pub token: String,
	pub account: Address,
}

/// Approval operation result
#[derive(Debug, Clone)]
pub struct ApprovalResult {
	pub tx_hash: Option<String>,
	pub spender: Address,
	pub amount: U256,
	pub token: String,
}
