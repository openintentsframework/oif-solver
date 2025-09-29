use alloy_primitives::{Address, U256};
use anyhow::{anyhow, Result};
use ethers::abi::Token;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

use crate::core::{ContractManager, SessionManager};
use crate::utils::format_balance_with_decimals;

pub struct TokenService {
	session_manager: Arc<SessionManager>,
	contract_manager: Arc<ContractManager>,
}

impl TokenService {
	pub fn new(
		session_manager: Arc<SessionManager>,
		contract_manager: Arc<ContractManager>,
	) -> Self {
		Self {
			session_manager,
			contract_manager,
		}
	}

	pub async fn mint_tokens(
		&self,
		chain_id: u64,
		token: &str,
		amount: U256,
		recipient: Option<Address>,
	) -> Result<Option<String>> {
		if !self.session_manager.is_local().await {
			return Err(anyhow!("Minting only available in local mode"));
		}

		let token_addr_hex = self
			.session_manager
			.get_token_address(chain_id, token)
			.await?;

		let token_addr = token_addr_hex
			.parse::<Address>()
			.map_err(|e| anyhow!("Failed to parse token address: {}", e))?;

		let to = recipient.unwrap_or_else(|| {
			let user = futures::executor::block_on(self.session_manager.get_user_account());
			user.address
		});

		info!("Minting {} tokens to {} on chain {}", amount, to, chain_id);

		let amount_bytes = amount.to_be_bytes::<32>();
		let eth_amount = ethers::types::U256::from_big_endian(&amount_bytes);
		
		let receipt = self
			.contract_manager
			.send_transaction(
				chain_id,
				token_addr,
				"MockERC20",
				"mint",
				vec![
					Token::Address(ethers::types::H160::from_slice(to.as_slice())),
					Token::Uint(eth_amount),
				],
			)
			.await?;

		let tx_hash = format!("{:?}", receipt.transaction_hash);
		info!("Successfully minted {} tokens with tx: {}", amount, tx_hash);
		Ok(Some(tx_hash))
	}

	pub async fn get_token_balance(
		&self,
		chain_id: u64,
		token_address: Address,
		account: Address,
	) -> Result<U256> {
		debug!(
			"Getting token balance for {} on chain {} from token {}",
			account, chain_id, token_address
		);

		let result = self
			.contract_manager
			.call_contract(
				chain_id,
				token_address,
				"MockERC20",
				"balanceOf",
				vec![Token::Address(ethers::types::H160::from_slice(
					account.as_slice(),
				))],
			)
			.await?;

		debug!("Balance result: {:?}", result);

		if let Some(Token::Uint(balance)) = result.first() {
			let mut bytes = [0u8; 32];
			balance.to_big_endian(&mut bytes);
			let balance_u256 = U256::from_be_bytes(bytes);
			debug!("Parsed balance: {}", balance_u256);
			Ok(balance_u256)
		} else {
			Err(anyhow!("Unexpected response from balanceOf"))
		}
	}

	pub async fn get_all_balances(&self, account: Address) -> Result<BalanceReport> {
		let mut report = BalanceReport::new();

		for chain_id in self.session_manager.get_chain_ids().await {
			debug!("Checking balances on chain {}", chain_id);
			if let Some(network) = self.session_manager.get_network_config(chain_id).await {
				debug!("Found {} tokens for chain {}", network.contracts.tokens.len(), chain_id);
				for (symbol, token_info) in &network.contracts.tokens {
					debug!("Checking token {} at {}", symbol, token_info.address);
					if let Ok(addr) = token_info.address.parse::<Address>() {
						match self.get_token_balance(chain_id, addr, account).await {
							Ok(balance) => {
								debug!("Got balance {} for token {}", balance, symbol);
								report.add(chain_id, symbol.clone(), balance, token_info.decimals);
							},
							Err(e) => {
								debug!(
									"Failed to get balance for {} on chain {}: {}",
									symbol, chain_id, e
								);
							},
						}
					} else {
						debug!("Failed to parse token address for {}: {}", symbol, token_info.address);
					}
				}
			} else {
				debug!("No network config found for chain {}", chain_id);
			}
		}

		debug!("Final balance report: {:?}", report);
		Ok(report)
	}

	pub async fn approve_token(
		&self,
		chain_id: u64,
		token_address: Address,
		spender: Address,
		amount: U256,
	) -> Result<()> {
		info!(
			"Approving {} to spend {} tokens on chain {}",
			spender, amount, chain_id
		);

		self.contract_manager
			.send_transaction(
				chain_id,
				token_address,
				"MockERC20",
				"approve",
				vec![
					Token::Address(ethers::types::H160::from_slice(spender.as_slice())),
					Token::Uint({
						let bytes: [u8; 32] = amount.to_be_bytes();
						ethers::types::U256::from_big_endian(&bytes)
					}),
				],
			)
			.await?;

		info!("Approval successful");
		Ok(())
	}

	pub async fn get_allowance(
		&self,
		chain_id: u64,
		token_address: Address,
		owner: Address,
		spender: Address,
	) -> Result<U256> {
		debug!(
			"Getting allowance for {} -> {} on chain {}",
			owner, spender, chain_id
		);

		let result = self
			.contract_manager
			.call_contract(
				chain_id,
				token_address,
				"MockERC20",
				"allowance",
				vec![
					Token::Address(ethers::types::H160::from_slice(owner.as_slice())),
					Token::Address(ethers::types::H160::from_slice(spender.as_slice())),
				],
			)
			.await?;

		if let Some(Token::Uint(allowance)) = result.first() {
			let mut bytes = [0u8; 32];
			allowance.to_big_endian(&mut bytes);
			Ok(U256::from_be_bytes(bytes))
		} else {
			Err(anyhow!("Unexpected response from allowance"))
		}
	}
}

#[derive(Debug, Default)]
pub struct BalanceReport {
	balances: HashMap<u64, HashMap<String, TokenBalance>>,
}

#[derive(Debug, Clone)]
pub struct TokenBalance {
	amount: U256,
	decimals: u8,
}

impl BalanceReport {
	pub fn new() -> Self {
		Self {
			balances: HashMap::new(),
		}
	}

	pub fn add(&mut self, chain_id: u64, token: String, balance: U256, decimals: u8) {
		self.balances
			.entry(chain_id)
			.or_default()
			.insert(token, TokenBalance { amount: balance, decimals });
	}

	pub fn filter_chains(mut self, chains: Option<Vec<u64>>) -> Self {
		if let Some(chains) = chains {
			self.balances
				.retain(|chain_id, _| chains.contains(chain_id));
		}
		self
	}

	pub fn filter_tokens(mut self, tokens: Option<Vec<String>>) -> Self {
		if let Some(tokens) = tokens {
			for (_, chain_balances) in self.balances.iter_mut() {
				chain_balances.retain(|token, _| tokens.contains(token));
			}
		}
		self
	}

	pub fn to_table_rows(&self) -> Vec<Vec<String>> {
		let mut rows = Vec::new();

		let mut sorted_chains: Vec<_> = self.balances.keys().collect();
		sorted_chains.sort();

		for chain_id in sorted_chains {
			if let Some(tokens) = self.balances.get(chain_id) {
				let mut sorted_tokens: Vec<_> = tokens.iter().collect();
				sorted_tokens.sort_by_key(|(token_name, _)| token_name.as_str());
				
				for (token, token_balance) in sorted_tokens {
					rows.push(vec![
						chain_id.to_string(),
						token.clone(),
						format_balance_with_decimals(token_balance.amount, token_balance.decimals),
					]);
				}
			}
		}

		rows
	}

	pub fn is_empty(&self) -> bool {
		self.balances.is_empty()
	}
}

