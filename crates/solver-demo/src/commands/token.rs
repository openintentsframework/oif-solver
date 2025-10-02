use alloy_primitives::Address;
use anyhow::{anyhow, Result};
use clap::Subcommand;
use std::sync::Arc;
use tracing::info;

use crate::core::{DisplayUtils, SessionManager};
use crate::services::TokenService;
use crate::utils::{parse_address, parse_address_or_identifier, parse_amount_with_decimals};

#[derive(Debug, Subcommand)]
pub enum TokenCommands {
	/// List available tokens
	List {
		/// Filter by chain IDs
		#[arg(short, long, value_delimiter = ',')]
		chains: Option<Vec<u64>>,
	},

	/// Mint tokens (local mode only)
	Mint {
		/// Chain ID
		#[arg(short, long)]
		chain: u64,

		/// Token symbol (e.g., USDC, WETH)
		#[arg(short = 'k', long)]
		token: String,

		/// Amount to mint (in whole units, e.g., 100 for 100 USDC)
		#[arg(short, long)]
		amount: String,

		/// Recipient address (defaults to user account)
		#[arg(short = 'r', long = "to")]
		to: Option<String>,
	},

	/// Check token balance
	Balance {
		/// Filter by chain IDs
		#[arg(short, long)]
		chains: Option<Vec<u64>>,

		/// Filter by token symbols
		#[arg(short = 'k', long = "tokens")]
		tokens: Option<Vec<String>>,

		/// Account to check: 'user', 'solver', 'recipient', 'all', or an address
		#[arg(short, long, default_value = "user")]
		account: Option<String>,

		/// Follow mode: refresh every N seconds
		#[arg(short, long)]
		follow: Option<u64>,
	},

	/// Approve token spending
	Approve {
		/// Chain ID
		#[arg(short, long)]
		chain: u64,

		/// Token symbol
		#[arg(short = 'k', long)]
		token: String,

		/// Spender address
		#[arg(short, long)]
		spender: String,

		/// Amount to approve (use "max" for unlimited)
		#[arg(short, long)]
		amount: String,

		/// Account to approve from: 'user', 'solver', 'recipient', or an address (defaults to 'user')
		#[arg(long, default_value = "user")]
		account: String,
	},
}

pub struct TokenHandler {
	token_service: Arc<TokenService>,
	session_manager: Arc<SessionManager>,
	display: Arc<DisplayUtils>,
}

impl TokenHandler {
	pub fn new(token_service: Arc<TokenService>, session_manager: Arc<SessionManager>) -> Self {
		Self {
			token_service,
			session_manager,
			display: Arc::new(DisplayUtils::new()),
		}
	}

	pub async fn handle(&self, command: TokenCommands) -> Result<()> {
		match command {
			TokenCommands::List { chains } => self.list(chains).await,

			TokenCommands::Mint {
				chain,
				token,
				amount,
				to,
			} => self.mint(chain, token, amount, to).await,

			TokenCommands::Balance {
				chains,
				tokens,
				account,
				follow,
			} => self.balance(chains, tokens, account, follow).await,

			TokenCommands::Approve {
				chain,
				token,
				spender,
				amount,
				account,
			} => self.approve(chain, token, spender, amount, account).await,
		}
	}

	async fn list(&self, chains: Option<Vec<u64>>) -> Result<()> {
		use crate::core::TreeItem;

		self.display.header("AVAILABLE TOKENS");

		// Get all configured chains or filter by provided chains
		let configured_chains = self.session_manager.get_chain_ids().await;
		let chain_filter: Vec<u64> = if let Some(c) = chains {
			c.into_iter()
				.filter(|id| configured_chains.contains(id))
				.collect()
		} else {
			configured_chains
		};

		if chain_filter.is_empty() {
			self.display.info("No chains to display");
			return Ok(());
		}

		// Collect token information for each chain
		for chain_id in chain_filter {
			let chain_section = format!("Chain {}", chain_id);

			// Get all contract addresses for this chain
			if let Some(contracts) = self.session_manager.get_contract_addresses(chain_id).await {
				let mut token_items = Vec::new();

				// Sort tokens by name for consistent display
				let mut tokens: Vec<_> = contracts.tokens.iter().collect();
				tokens.sort_by_key(|(name, _)| name.as_str());

				for (token_name, token_info) in tokens {
					token_items.push(TreeItem::KeyValue(
						token_name.to_string(),
						format!("{} ({}d)", token_info.address, token_info.decimals),
					));
				}

				if !token_items.is_empty() {
					self.display.tree(&chain_section, token_items);
				} else {
					self.display.tree(
						&chain_section,
						vec![TreeItem::Info("No tokens configured".to_string())],
					);
				}
			} else {
				self.display.tree(
					&chain_section,
					vec![TreeItem::Info("Chain not configured".to_string())],
				);
			}
		}

		Ok(())
	}

	async fn mint(
		&self,
		chain_id: u64,
		token: String,
		amount_str: String,
		to: Option<String>,
	) -> Result<()> {
		use crate::core::TreeItem;

		self.display.header("TOKEN MINT");

		// Get token decimals from config
		let decimals = self
			.session_manager
			.get_token_decimals(chain_id, &token)
			.await
			.unwrap_or(18); // Default to 18 if not found

		// Parse amount with correct decimals
		let amount = parse_amount_with_decimals(&amount_str, decimals)?;

		// Parse recipient if provided
		let recipient_addr = if let Some(addr) = to {
			parse_address_or_identifier(&addr, &self.session_manager).await?
		} else {
			self.session_manager.get_user_account().await.address
		};

		self.display.tree(
			"Transaction Details",
			vec![
				TreeItem::KeyValue("Chain".to_string(), chain_id.to_string()),
				TreeItem::KeyValue(
					"Token".to_string(),
					format!("{} ({} decimals)", token, decimals),
				),
				TreeItem::KeyValue("Amount".to_string(), amount_str.clone()),
				TreeItem::KeyValue("Recipient".to_string(), recipient_addr.to_string()),
				TreeItem::KeyValue("Amount (wei)".to_string(), amount.to_string()),
			],
		);

		let tx_hash = self
			.token_service
			.mint_tokens(chain_id, &token, amount, Some(recipient_addr))
			.await?;

		let result_items = if let Some(hash) = tx_hash {
			vec![
				TreeItem::Success("Tokens minted successfully".to_string()),
				TreeItem::KeyValue("Transaction".to_string(), hash.to_string()),
			]
		} else {
			vec![
				TreeItem::Success("Tokens minted successfully".to_string()),
				TreeItem::Info("Transaction hash not available".to_string()),
			]
		};

		self.display.tree("Result", result_items);

		Ok(())
	}

	async fn balance(
		&self,
		chains: Option<Vec<u64>>,
		tokens: Option<Vec<String>>,
		account: Option<String>,
		follow: Option<u64>,
	) -> Result<()> {
		use std::time::Duration;

		// Handle follow mode
		if let Some(interval) = follow {
			self.display.info(&format!(
				"Monitoring balances every {} seconds. Press Ctrl+C to stop.",
				interval
			));
			loop {
				self.print_balances_for_account(account.clone(), chains.clone(), tokens.clone())
					.await?;
				tokio::time::sleep(Duration::from_secs(interval)).await;
				println!("\n---\n");
			}
		} else {
			self.print_balances_for_account(account, chains, tokens)
				.await?;
		}

		Ok(())
	}

	async fn print_balances_for_account(
		&self,
		account: Option<String>,
		chains: Option<Vec<u64>>,
		tokens: Option<Vec<String>>,
	) -> Result<()> {
		// Determine which account to check
		let account_str = account.unwrap_or_else(|| "user".to_string());

		match account_str.to_lowercase().as_str() {
			"all" => {
				// Show balances for all accounts
				self.display.header("ALL ACCOUNT BALANCES");

				let user = self.session_manager.get_user_account().await;
				let solver = self.session_manager.get_solver_account().await;
				let recipient = self.session_manager.get_recipient_account().await;

				let mut accounts = vec![("User", user.address), ("Solver", solver.address)];

				// Only add recipient if it's different from user
				if recipient.address != user.address {
					accounts.push(("Recipient", recipient.address));
				}

				for (j, (name, addr)) in accounts.iter().enumerate() {
					self.display.section(&format!("{} Account", name));
					println!("├─ Address: {}", addr);

					let report = self
						.token_service
						.get_all_balances(*addr)
						.await?
						.filter_chains(chains.clone())
						.filter_tokens(tokens.clone());

					if !report.is_empty() {
						let rows = report.to_table_rows();
						println!("└─ Balances:");
						for (i, row) in rows.iter().enumerate() {
							let indent = if j == accounts.len() - 1 {
								"   "
							} else {
								"│  "
							};
							let prefix = if i == rows.len() - 1 {
								"└─"
							} else {
								"├─"
							};
							println!(
								"{}  {} Chain {} • {} • {}",
								indent, prefix, row[0], row[1], row[2]
							);
						}
					} else {
						println!("└─ No balances found");
					}

					if j < accounts.len() - 1 {
						println!("│");
					}
				}
			},
			_ => {
				// Single account balance
				let address = match account_str.to_lowercase().as_str() {
					"user" => self.session_manager.get_user_account().await.address,
					"solver" => self.session_manager.get_solver_account().await.address,
					"recipient" => self.session_manager.get_recipient_account().await.address,
					addr_str => {
						// Try to parse as address
						parse_address(addr_str)?
					},
				};

				self.display.header("ACCOUNT BALANCES");

				self.display.section("Account");
				println!("└─ Address: {}", address);

				let report = self
					.token_service
					.get_all_balances(address)
					.await?
					.filter_chains(chains)
					.filter_tokens(tokens);

				if report.is_empty() {
					self.display.section("Balances");
					println!("└─ No balances found");
				} else {
					self.display.section("Balances");
					let rows = report.to_table_rows();
					for (i, row) in rows.iter().enumerate() {
						let prefix = if i == rows.len() - 1 {
							"└─"
						} else {
							"├─"
						};
						// row[0] = chain, row[1] = token, row[2] = balance
						println!("{} Chain {} • {} • {}", prefix, row[0], row[1], row[2]);
					}
				}
			},
		}

		Ok(())
	}

	async fn approve(
		&self,
		chain_id: u64,
		token: String,
		spender_str: String,
		amount_str: String,
		account_str: String,
	) -> Result<()> {
		info!(
			"Approving {} to spend {} {} on chain {} from account {}",
			spender_str, amount_str, token, chain_id, account_str
		);

		// Parse spender address - handle special cases
		let spender = match spender_str.to_lowercase().as_str() {
			"solver" => self.session_manager.get_solver_account().await.address,
			"user" => self.session_manager.get_user_account().await.address,
			"recipient" => self.session_manager.get_recipient_account().await.address,
			_ => parse_address(&spender_str)?,
		};

		// Parse account address - who is sending the approval
		let account = parse_address_or_identifier(&account_str, &self.session_manager).await?;

		// Get token decimals from config
		let decimals = self
			.session_manager
			.get_token_decimals(chain_id, &token)
			.await
			.unwrap_or(18); // Default to 18 if not found

		// Parse amount with correct decimals
		let amount = parse_amount_with_decimals(&amount_str, decimals)?;

		// Get token address
		let token_addr_hex = self
			.session_manager
			.get_token_address(chain_id, &token)
			.await?;
		let token_addr = token_addr_hex
			.parse::<Address>()
			.map_err(|e| anyhow!("Invalid token address: {}", e))?;

		self.token_service
			.approve_token(chain_id, token_addr, spender, amount, account)
			.await?;

		self.display.success(&format!(
			"Successfully approved {} to spend {} {} on chain {} from account {}",
			spender_str, amount_str, token, chain_id, account_str
		));
		Ok(())
	}
}
