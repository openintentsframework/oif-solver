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
				// Process input settler if not zero address
				if network.input_settler_address.0 != [0u8; 20] {
					// Check allowance for input settler
					let current_allowance_input = self
						.delivery
						.get_allowance(
							*chain_id,
							&solver_address_str,
							&with_0x_prefix(&hex::encode(&network.input_settler_address.0)),
							&with_0x_prefix(&hex::encode(&token.address.0)),
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
				}

				// Process output settler if not zero address
				if network.output_settler_address.0 != [0u8; 20] {
					// Check allowance for output settler
					let current_allowance_output = self
						.delivery
						.get_allowance(
							*chain_id,
							&solver_address_str,
							&with_0x_prefix(&hex::encode(&network.output_settler_address.0)),
							&with_0x_prefix(&hex::encode(&token.address.0)),
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

		let tx_hash = self.delivery.deliver(tx, None).await?;

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

#[cfg(test)]
mod tests {
	use super::*;
	use mockall::predicate::*;
	use solver_account::{AccountService, MockAccountInterface};
	use solver_delivery::{DeliveryService, MockDeliveryInterface};
	use solver_types::{
		parse_address,
		utils::tests::builders::{NetworkConfigBuilder, NetworksConfigBuilder, TokenConfigBuilder},
	};
	use std::collections::HashMap;

	fn create_test_networks_config() -> NetworksConfig {
		NetworksConfigBuilder::new()
			.add_network(
				1,
				NetworkConfigBuilder::new()
					.add_token(
						TokenConfigBuilder::new()
							.address(
								parse_address("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")
									.unwrap(),
							)
							.symbol("WETH")
							.decimals(18)
							.build(),
					)
					.build(),
			)
			.add_network(
				137,
				NetworkConfigBuilder::new()
					.add_token(
						TokenConfigBuilder::new()
							.address(
								parse_address("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")
									.unwrap(),
							)
							.symbol("WETH")
							.decimals(18)
							.build(),
					)
					.build(),
			)
			.build()
	}

	fn create_mock_account_service() -> Arc<AccountService> {
		let mut mock_account = MockAccountInterface::new();
		mock_account.expect_address().returning(|| {
			Box::pin(async move {
				Ok(parse_address("3333333333333333333333333333333333333333").unwrap())
			})
		});
		mock_account
			.expect_config_schema()
			.returning(|| Box::new(solver_account::implementations::local::LocalWalletSchema));
		mock_account
			.expect_get_private_key()
			.returning(|| solver_types::SecretString::from("0x1234567890abcdef"));

		Arc::new(AccountService::new(Box::new(mock_account)))
	}

	fn create_mock_delivery_service() -> Arc<DeliveryService> {
		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_get_balance()
			.returning(|_, _, _| Box::pin(async { Ok("1000000".to_string()) }));
		mock_delivery
			.expect_get_allowance()
			.returning(|_, _, _, _| Box::pin(async { Ok("0".to_string()) }));
		mock_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});

		let mut implementations = HashMap::new();
		implementations.insert(
			1,
			Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
		);

		Arc::new(DeliveryService::new(implementations, 1, 20))
	}

	#[test]
	fn test_new_token_manager() {
		let networks = create_test_networks_config();
		let delivery = create_mock_delivery_service();
		let account = create_mock_account_service();

		let token_manager = TokenManager::new(networks.clone(), delivery, account);

		assert_eq!(token_manager.networks.len(), 2);
		assert!(token_manager.networks.contains_key(&1));
		assert!(token_manager.networks.contains_key(&137));
	}

	#[test]
	fn test_is_supported_existing_token() {
		let networks = create_test_networks_config();

		// Create simple mocks without complex setup since is_supported doesn't use them
		let mock_delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20));
		let mock_account = Arc::new(AccountService::new(Box::new(
			solver_account::implementations::local::LocalWallet::new(
				"0x1234567890123456789012345678901234567890123456789012345678901234",
			)
			.unwrap(),
		)));

		let token_manager = TokenManager::new(networks, mock_delivery, mock_account);
		let usdc_address =
			solver_types::parse_address("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
				.expect("Invalid USDC address");

		assert!(token_manager.is_supported(1, &usdc_address));
		assert!(token_manager.is_supported(137, &usdc_address));
	}

	#[test]
	fn test_is_supported_non_existing_token() {
		let networks = create_test_networks_config();
		let delivery = create_mock_delivery_service();
		let account = create_mock_account_service();
		let token_manager = TokenManager::new(networks, delivery, account);

		let unknown_address = parse_address("1111111111111111111111111111111111111111").unwrap();

		assert!(!token_manager.is_supported(1, &unknown_address));
		assert!(!token_manager.is_supported(137, &unknown_address));
	}

	#[test]
	fn test_get_token_info_success() {
		let networks = create_test_networks_config();
		let delivery = create_mock_delivery_service();
		let account = create_mock_account_service();
		let token_manager = TokenManager::new(networks, delivery, account);

		let usdc_address =
			solver_types::parse_address("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
				.expect("Invalid USDC address");

		let result = token_manager.get_token_info(1, &usdc_address);
		assert!(result.is_ok());

		let token_config = result.unwrap();
		assert_eq!(token_config.symbol, "USDC");
		assert_eq!(token_config.decimals, 6);
		assert_eq!(token_config.address, usdc_address);
	}

	#[test]
	fn test_get_token_info_network_not_configured() {
		let networks = create_test_networks_config();
		let delivery = create_mock_delivery_service();
		let account = create_mock_account_service();
		let token_manager = TokenManager::new(networks, delivery, account);

		let usdc_address =
			solver_types::parse_address("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
				.expect("Invalid USDC address");

		let result = token_manager.get_token_info(999, &usdc_address);
		assert!(result.is_err());

		match result.unwrap_err() {
			TokenManagerError::NetworkNotConfigured(chain_id) => assert_eq!(chain_id, 999),
			_ => panic!("Expected NetworkNotConfigured error"),
		}
	}

	#[test]
	fn test_get_tokens_for_chain_existing_chain() {
		let networks = create_test_networks_config();
		let delivery = create_mock_delivery_service();
		let account = create_mock_account_service();
		let token_manager = TokenManager::new(networks, delivery, account);

		let tokens = token_manager.get_tokens_for_chain(1);
		assert_eq!(tokens.len(), 2);

		let symbols: Vec<&str> = tokens.iter().map(|t| t.symbol.as_str()).collect();
		assert!(symbols.contains(&"USDC"));
		assert!(symbols.contains(&"WETH"));
	}

	#[tokio::test]
	async fn test_check_balance_success() {
		let networks = create_test_networks_config();
		let mock_delivery = create_mock_delivery_service();
		let mock_account = create_mock_account_service();
		let token_manager = TokenManager::new(networks, mock_delivery, mock_account);

		let token_address = parse_address("a0b86991c431e69f7f3aa4ce5a9b9a8ce3606eb4").unwrap();
		let result = token_manager.check_balance(1, &token_address).await;

		assert!(result.is_ok());
		assert_eq!(result.unwrap(), "1000000");
	}

	#[test]
	fn test_token_manager_error_display() {
		let error1 = TokenManagerError::TokenNotSupported("USDC".to_string(), 1);
		assert_eq!(error1.to_string(), "Token not supported: USDC on chain 1");

		let error2 = TokenManagerError::NetworkNotConfigured(999);
		assert_eq!(error2.to_string(), "Network not configured: 999");
	}

	#[test]
	fn test_erc20_approval_constants() {
		// Test the ERC20 approval transaction data construction constants
		let expected_selector = [0x09, 0x5e, 0xa7, 0xb3]; // approve(address,uint256)
		assert_eq!(expected_selector, [0x09, 0x5e, 0xa7, 0xb3]);

		// Verify amount encoding for MAX_UINT256
		let amount = U256::MAX;
		let amount_bytes = amount.to_be_bytes::<32>();
		assert_eq!(amount_bytes.len(), 32);
		assert_eq!(amount_bytes, [0xff; 32]);
	}
}
