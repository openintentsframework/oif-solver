//! Token management module for the OIF solver system.
//!
//! This module provides comprehensive token management functionality including:
//! - Automatic ERC20 token approval management for configured tokens
//! - Token balance monitoring across multiple chains
//! - Token configuration lookups and validation
//! - Multi-network token support
//!
//! # Architecture
//!
//! The `TokenManager` acts as a central registry for all token-related operations
//! in the solver system. It maintains knowledge of supported tokens across different
//! blockchain networks and ensures that the solver has the necessary approvals to
//! interact with these tokens through settler contracts.
//!
//! # Token Approvals
//!
//! The manager automatically sets MAX_UINT256 approvals for all configured tokens
//! to their respective input and output settler contracts. This eliminates the need
//! for per-transaction approvals and reduces gas costs during order execution.

use alloy_primitives::{hex, U256};
use solver_account::AccountService;
use solver_delivery::DeliveryService;
use solver_types::{
	with_0x_prefix, Address, NetworksConfig, TokenConfig, Transaction, TransactionHash,
};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

/// Errors that can occur during token management operations.
#[derive(Debug, Error)]
pub enum TokenManagerError {
	/// Token is not configured for the specified chain.
	#[error("Token not supported: {0} on chain {1}")]
	TokenNotSupported(String, u64),

	/// Network configuration is missing for the specified chain.
	#[error("Network not configured: {0}")]
	NetworkNotConfigured(u64),

	/// Error occurred during transaction delivery.
	#[error("Delivery error: {0}")]
	DeliveryError(#[from] solver_delivery::DeliveryError),

	/// Error occurred during account operations.
	#[error("Account error: {0}")]
	AccountError(#[from] solver_account::AccountError),

	/// Failed to parse a value.
	#[error("Failed to parse value: {0}")]
	ParseError(String),
}

/// Manages token configurations and approvals across multiple blockchain networks.
///
/// The `TokenManager` is responsible for:
/// - Maintaining a registry of supported tokens per network
/// - Setting and managing ERC20 token approvals for settler contracts
/// - Checking token balances for the solver account
/// - Providing token metadata and configuration lookups
///
/// This struct is typically initialized once during solver startup and shared
/// across all components that need token information.
pub struct TokenManager {
	/// Network configurations mapping chain IDs to their token and settler information.
	networks: NetworksConfig,
	/// Service for delivering transactions to various blockchain networks.
	delivery: Arc<DeliveryService>,
	/// Service for managing the solver's account and signatures.
	account: Arc<AccountService>,
}

impl TokenManager {
	/// Creates a new `TokenManager` instance.
	///
	/// # Arguments
	///
	/// * `networks` - Configuration for all supported networks and their tokens
	/// * `delivery` - Service for delivering transactions to blockchain networks
	/// * `account` - Service for managing the solver's account
	pub fn new(
		networks: NetworksConfig,
		delivery: Arc<DeliveryService>,
		account: Arc<AccountService>,
	) -> Self {
		Self {
			networks,
			delivery,
			account,
		}
	}

	/// Ensures all configured tokens have MAX_UINT256 approval for their respective settlers.
	///
	/// This method iterates through all configured tokens on all networks and checks
	/// if the solver has already approved the maximum amount for both input and output
	/// settlers. If not, it submits approval transactions.
	///
	/// # Returns
	///
	/// Returns `Ok(())` if all approvals are successfully set or already exist.
	/// Returns an error if any approval transaction fails.
	///
	/// # Note
	///
	/// This method should be called during solver initialization to ensure all
	/// necessary approvals are in place before processing orders.
	pub async fn ensure_approvals(&self) -> Result<(), TokenManagerError> {
		let solver_address = self.account.get_address().await?;
		let solver_address_str = with_0x_prefix(&hex::encode(&solver_address.0));
		let max_uint256 = U256::MAX;
		let max_uint256_str = max_uint256.to_string();

		for (chain_id, network) in &self.networks {
			for token in &network.tokens {
				// Check allowance for input settler
				let current_allowance_input = self
					.delivery
					.get_allowance(
						*chain_id,
						&solver_address_str,
						&hex::encode(&network.input_settler_address.0),
						&hex::encode(&token.address.0),
					)
					.await?;

				if current_allowance_input != max_uint256_str {
					tracing::info!(
						"Setting approval for token {} on chain {} for input settler",
						token.symbol,
						chain_id
					);
					self.submit_approval(
						*chain_id,
						&token.address,
						&network.input_settler_address,
						max_uint256,
					)
					.await?;
				}

				// Check allowance for output settler
				let current_allowance_output = self
					.delivery
					.get_allowance(
						*chain_id,
						&solver_address_str,
						&hex::encode(&network.output_settler_address.0),
						&hex::encode(&token.address.0),
					)
					.await?;

				if current_allowance_output != max_uint256_str {
					tracing::info!(
						"Setting approval for token {} on chain {} for output settler",
						token.symbol,
						chain_id
					);
					self.submit_approval(
						*chain_id,
						&token.address,
						&network.output_settler_address,
						max_uint256,
					)
					.await?;
				}
			}
		}

		Ok(())
	}

	/// Submits an ERC20 approval transaction.
	///
	/// Creates and submits a transaction to approve the specified spender to transfer
	/// the given amount of tokens on behalf of the solver.
	///
	/// # Arguments
	///
	/// * `chain_id` - The blockchain network ID
	/// * `token_address` - The ERC20 token contract address
	/// * `spender` - The address being granted approval (settler contract)
	/// * `amount` - The amount to approve (typically MAX_UINT256)
	///
	/// # Returns
	///
	/// Returns the transaction hash if successful.
	async fn submit_approval(
		&self,
		chain_id: u64,
		token_address: &Address,
		spender: &Address,
		amount: U256,
	) -> Result<TransactionHash, TokenManagerError> {
		// Create approval transaction data
		// ERC20 approve(address spender, uint256 amount)
		// Function selector: 0x095ea7b3
		let selector = [0x09, 0x5e, 0xa7, 0xb3];
		let mut call_data = Vec::new();
		call_data.extend_from_slice(&selector);

		// Add spender address (32 bytes, left-padded with zeros)
		call_data.extend_from_slice(&[0; 12]); // Pad to 32 bytes
		call_data.extend_from_slice(&spender.0);

		// Add amount (32 bytes)
		let amount_bytes = amount.to_be_bytes::<32>();
		call_data.extend_from_slice(&amount_bytes);

		let tx = Transaction {
			chain_id,
			to: Some(token_address.clone()),
			data: call_data,
			value: U256::ZERO,
			gas_limit: Some(100000),
			gas_price: None,
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
			nonce: None,
		};

		let tx_hash = self.delivery.deliver(tx).await?;

		Ok(tx_hash)
	}

	/// Checks balances for all configured tokens across all networks.
	///
	/// Queries the current token balances for the solver's address on all
	/// configured tokens and networks.
	///
	/// # Returns
	///
	/// Returns a HashMap mapping (chain_id, token_config) tuples to balance strings.
	/// Balances are returned as decimal strings to avoid precision issues.
	/// The token_config includes the token address, symbol, and decimals.
	pub async fn check_balances(
		&self,
	) -> Result<HashMap<(u64, TokenConfig), String>, TokenManagerError> {
		let solver_address = self.account.get_address().await?;
		let solver_address_str = hex::encode(&solver_address.0);
		let mut balances = HashMap::new();

		for (chain_id, network) in &self.networks {
			for token in &network.tokens {
				let balance = self
					.delivery
					.get_balance(
						*chain_id,
						&solver_address_str,
						Some(&hex::encode(&token.address.0)),
					)
					.await?;

				balances.insert((*chain_id, token.clone()), balance);
			}
		}

		Ok(balances)
	}

	/// Checks balance for a single token address on a specific chain.
	///
	/// Queries the current token balance for the solver's address on a
	/// specific token and network.
	///
	/// # Arguments
	///
	/// * `chain_id` - The blockchain network ID
	/// * `token_address` - The token contract address to check
	///
	/// # Returns
	///
	/// Returns the balance as a decimal string to avoid precision issues.
	pub async fn check_balance(
		&self,
		chain_id: u64,
		token_address: &Address,
	) -> Result<String, TokenManagerError> {
		let solver_address = self.account.get_address().await?;
		let solver_address_str = hex::encode(&solver_address.0);

		let balance = self
			.delivery
			.get_balance(
				chain_id,
				&solver_address_str,
				Some(&hex::encode(&token_address.0)),
			)
			.await?;

		Ok(balance)
	}

	/// Checks if a token is supported on a specific chain.
	///
	/// # Arguments
	///
	/// * `chain_id` - The blockchain network ID
	/// * `token_address` - The token contract address to check
	///
	/// # Returns
	///
	/// Returns `true` if the token is configured for the specified chain, `false` otherwise.
	pub fn is_supported(&self, chain_id: u64, token_address: &Address) -> bool {
		if let Some(network) = self.networks.get(&chain_id) {
			network.tokens.iter().any(|t| t.address == *token_address)
		} else {
			false
		}
	}

	/// Gets the configuration for a specific token on a chain.
	///
	/// # Arguments
	///
	/// * `chain_id` - The blockchain network ID
	/// * `token_address` - The token contract address
	///
	/// # Returns
	///
	/// Returns the `TokenConfig` if the token is supported.
	/// Returns an error if the network is not configured or the token is not supported.
	pub fn get_token_info(
		&self,
		chain_id: u64,
		token_address: &Address,
	) -> Result<TokenConfig, TokenManagerError> {
		let network = self
			.networks
			.get(&chain_id)
			.ok_or(TokenManagerError::NetworkNotConfigured(chain_id))?;

		network
			.tokens
			.iter()
			.find(|t| t.address == *token_address)
			.cloned()
			.ok_or_else(|| {
				TokenManagerError::TokenNotSupported(hex::encode(&token_address.0), chain_id)
			})
	}

	/// Gets all supported tokens for a specific chain.
	///
	/// # Arguments
	///
	/// * `chain_id` - The blockchain network ID
	///
	/// # Returns
	///
	/// Returns a vector of `TokenConfig` for all tokens configured on the chain.
	/// Returns an empty vector if the chain is not configured.
	pub fn get_tokens_for_chain(&self, chain_id: u64) -> Vec<TokenConfig> {
		self.networks
			.get(&chain_id)
			.map(|n| n.tokens.clone())
			.unwrap_or_default()
	}

	/// Gets the complete networks configuration.
	///
	/// # Returns
	///
	/// Returns a reference to the `NetworksConfig` containing all network and token configurations.
	pub fn get_networks(&self) -> &NetworksConfig {
		&self.networks
	}
}
