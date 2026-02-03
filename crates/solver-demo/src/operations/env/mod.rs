//! Environment management operations and blockchain setup
//!
//! Provides comprehensive functionality for managing local blockchain environments
//! including Anvil process lifecycle management, smart contract deployment,
//! environment status monitoring, and coordinated multi-chain setup for
//! development and testing purposes.

mod anvil;
mod deploy;

use alloy_primitives::{Address, U256};
use alloy_rpc_types::TransactionRequest;
use alloy_signer_local::PrivateKeySigner;
pub use anvil::AnvilManager;
pub use deploy::ContractDeployer;
use std::{str::FromStr, sync::Arc};
use tracing::instrument;

use crate::{
	core::{
		blockchain::{Provider, TxBuilder},
		logging,
	},
	types::{
		chain::ChainId,
		error::{Error, Result},
		session::Environment,
	},
	Context,
};

/// Environment management operations coordinator
///
/// Provides unified access to environment management functionality including
/// Anvil blockchain process management, contract deployment coordination,
/// and multi-chain environment setup with automatic dependency resolution.
pub struct EnvOps {
	ctx: Arc<Context>,
	anvil: AnvilManager,
	deployer: ContractDeployer,
}

impl EnvOps {
	/// Creates a new environment operations handler with default settings
	///
	/// # Arguments
	/// * `ctx` - Shared application context containing configuration and services
	///
	/// # Returns
	/// New environment operations instance with default contract deployment path
	pub fn new(ctx: Arc<Context>) -> Self {
		let anvil = AnvilManager::new(ctx.clone());
		let deployer = ContractDeployer::new(ctx.clone());
		Self {
			ctx,
			anvil,
			deployer,
		}
	}

	/// Creates a new environment operations handler with custom contracts path
	///
	/// # Arguments
	/// * `ctx` - Shared application context containing configuration and services
	/// * `contracts_path` - Custom path to compiled contract artifacts
	///
	/// # Returns
	/// New environment operations instance using specified contracts directory
	pub fn with_contracts_path(ctx: Arc<Context>, contracts_path: std::path::PathBuf) -> Self {
		let anvil = AnvilManager::new(ctx.clone());
		let deployer = ContractDeployer::with_path(ctx.clone(), contracts_path);
		Self {
			ctx,
			anvil,
			deployer,
		}
	}

	/// Start the local environment (Anvil chains only)
	#[instrument(skip(self))]
	pub async fn start(&mut self) -> Result<()> {
		if !self.ctx.is_local() {
			return Err(Error::InvalidConfig(
				"Environment start is only available in local mode. Use 'env deploy' for contract deployment on any network.".to_string(),
			));
		}

		use crate::core::logging;

		// Check all chains first and collect any that are already running
		let chains = self.ctx.config.chains();
		let mut already_running = Vec::new();
		let mut to_start = Vec::new();

		for chain in &chains {
			if self.anvil.is_running(*chain) {
				already_running.push(*chain);
			} else {
				to_start.push(*chain);
			}
		}

		// Report already running chains in verbose mode
		if !already_running.is_empty() {
			logging::verbose_operation(
				"Chains already running",
				&format!("{}/{}", already_running.len(), chains.len()),
			);
		}

		// If all chains are running, just report status
		if to_start.is_empty() {
			logging::verbose_operation("All chains running", "no action needed");
			return Ok(());
		}

		// Start only the chains that aren't running
		for chain in &to_start {
			self.anvil.start_chain(*chain)?;
		}

		// Wait for newly started chains to be ready
		for chain in &to_start {
			self.anvil.wait_for_chain(*chain).await?;
		}

		logging::verbose_success(
			"Environment startup",
			&format!("{} chains started", to_start.len()),
		);
		Ok(())
	}

	/// Stop the local environment
	#[instrument(skip(self))]
	pub fn stop(&mut self) -> Result<()> {
		use crate::core::logging;

		// Stop all Anvil processes
		self.anvil.stop_all()?;

		logging::verbose_success("Environment shutdown", "all Anvil processes stopped");
		Ok(())
	}

	/// Get environment status
	pub fn status(&self) -> Result<EnvironmentStatus> {
		let environment = self.ctx.session.environment();
		let chains = self.anvil.get_running_chains();

		Ok(EnvironmentStatus {
			environment,
			chains,
		})
	}

	/// Deploy contracts (used by env deploy command)
	#[instrument(skip(self))]
	pub async fn deploy(&mut self, force: bool) -> Result<()> {
		let chains = self.ctx.config.chains();

		use crate::core::logging;

		// Filter chains that need deployment
		let chains_to_deploy: Vec<ChainId> = chains
			.into_iter()
			.filter(|&chain| {
				if !force && self.ctx.session.has_contracts(chain) {
					logging::verbose_operation(
						"Skipping chain",
						&format!("{chain} (already deployed)"),
					);
					false
				} else {
					true
				}
			})
			.collect();

		if chains_to_deploy.is_empty() {
			logging::verbose_operation("Deployment status", "all chains already deployed");
			return Ok(());
		}

		// Create deployment tasks for all chains
		let mut deployment_handles = Vec::new();

		for chain in &chains_to_deploy {
			let deployer = self.deployer.clone();
			let chain = *chain;

			logging::verbose_operation("Starting deployment", &format!("chain {chain}"));
			let handle = tokio::spawn(async move {
				let addresses = deployer.deploy_to_chain(chain).await?;
				Ok::<(ChainId, crate::types::session::ContractAddresses), Error>((chain, addresses))
			});

			deployment_handles.push(handle);
		}

		// Wait for all deployments to complete
		for handle in deployment_handles {
			let (chain, addresses) = handle
				.await
				.map_err(|e| Error::Other(anyhow::anyhow!("Deployment task failed: {e}")))??;

			// Store contract addresses in session
			self.ctx
				.session
				.set_contract_addresses(chain, addresses.clone())?;

			// Update TOML files with deployed addresses if in local mode
			if self.ctx.is_local() {
				// For each deployed contract, inject its address into the appropriate TOML file
				if let Some(address) = addresses.input_settler {
					self.replace_config_placeholders(chain, "InputSettler", address)
						.await?;
				}
				if let Some(address) = addresses.output_settler {
					self.replace_config_placeholders(chain, "OutputSettler", address)
						.await?;
				}
				if let Some(address) = addresses.the_compact {
					self.replace_config_placeholders(chain, "TheCompact", address)
						.await?;
				}
				if let Some(address) = addresses.input_settler_compact {
					self.replace_config_placeholders(chain, "InputSettlerCompact", address)
						.await?;
				}
				if let Some(address) = addresses.allocator {
					self.replace_config_placeholders(chain, "Allocator", address)
						.await?;
				}
				if let Some(address) = addresses.input_oracle {
					self.replace_config_placeholders(chain, "OracleInput", address)
						.await?;
				}
				if let Some(address) = addresses.output_oracle {
					self.replace_config_placeholders(chain, "OracleOutput", address)
						.await?;
				}
				// Handle tokens
				for (token_symbol, address) in &addresses.tokens {
					match token_symbol.as_str() {
						"TOKA" => {
							self.replace_config_placeholders(chain, "TokenA", address.0)
								.await?
						},
						"TOKB" => {
							self.replace_config_placeholders(chain, "TokenB", address.0)
								.await?
						},
						_ => {}, // Unknown token, skip
					}
				}
			}

			logging::verbose_success("Deployment completed", &format!("chain {chain}"));
		}

		Ok(())
	}

	/// Deploy a single contract to specified chains
	#[instrument(skip(self))]
	pub async fn deploy_single_contract(
		&mut self,
		contract_name: &str,
		chain_ids: Option<Vec<u64>>,
	) -> Result<()> {
		// Determine which chains to deploy to
		let chains = if let Some(chain_ids) = chain_ids {
			chain_ids.into_iter().map(ChainId::from_u64).collect()
		} else {
			self.ctx.config.chains()
		};

		for chain in chains {
			// Deploy to this chain
			let address = self
				.deployer
				.deploy_single_contract(contract_name, chain)
				.await?;

			// Store the deployed address in session
			if contract_name.starts_with("MockERC20") || contract_name.contains("Token") {
				// For tokens, get the symbol from the contract
				self.ctx
					.session
					.set_token_contract(chain, address, &self.ctx)
					.await?;
			} else {
				// For other contracts, use the regular method
				self.ctx
					.session
					.set_single_contract(chain, contract_name, address)?;
			}

			logging::verbose_success(
				"Contract deployed",
				&format!("{contract_name} on chain {chain} at {address}"),
			);

			// Handle TOML updates based on environment
			if self.ctx.is_local() {
				// Local: automatically inject into TOML
				self.replace_config_placeholders(chain, contract_name, address)
					.await?;
			} else {
				// Production: log that manual update is needed
				logging::verbose_operation(
					"Production deployment",
					&format!("manual TOML update required for {contract_name} on chain {chain}"),
				);
			}
		}

		logging::verbose_success(
			"Single contract deployment",
			&format!("{contract_name} completed successfully"),
		);
		Ok(())
	}

	/// List available contracts for deployment
	pub fn list_available_contracts(&self) -> Result<Vec<String>> {
		self.deployer.list_available_contracts()
	}

	/// Setup environment for testing (mint tokens, approve permit2, register allocator)
	#[instrument(skip(self))]
	pub async fn setup(
		&mut self,
		target_chain: Option<u64>,
		amount: u64,
	) -> crate::types::error::Result<()> {
		use crate::types::chain::ChainId;

		// Get chain IDs to setup
		let chain_ids: Vec<ChainId> = if let Some(chain_id) = target_chain {
			vec![ChainId::from(chain_id)]
		} else {
			self.ctx.config.chains()
		};
		logging::verbose_operation("Starting setup", &format!("{} chains", chain_ids.len()));

		// Create setup tasks for all chains
		let mut setup_handles = Vec::new();

		for chain in &chain_ids {
			let ctx = self.ctx.clone();
			let chain = *chain;

			logging::verbose_operation("Setup starting", &format!("chain {chain}"));
			let handle = tokio::spawn(async move {
				Self::setup_single_chain(ctx, chain, amount).await?;
				Ok::<ChainId, crate::types::error::Error>(chain)
			});

			setup_handles.push(handle);
		}

		// Wait for all setups to complete
		for handle in setup_handles {
			let chain = handle
				.await
				.map_err(|e| Error::Other(anyhow::anyhow!("Setup task failed: {e}")))??;
			logging::verbose_success("Chain setup completed", &format!("chain {chain}"));
		}

		logging::verbose_success(
			"Environment setup",
			&format!("{} chains completed", chain_ids.len()),
		);
		Ok(())
	}

	/// Setup a single chain (static method for use in async tasks)
	async fn setup_single_chain(
		ctx: Arc<Context>,
		chain: ChainId,
		amount: u64,
	) -> crate::types::error::Result<()> {
		use crate::operations::token::TokenOps;
		use alloy_primitives::U256;

		// Create token operations handler
		let token_ops = TokenOps::new(ctx.clone());

		// Get provider for this chain
		let provider = ctx.provider(chain).await?;

		// Get contract addresses from session using the proper API
		let contracts = ctx.session.contracts(chain).ok_or_else(|| {
			crate::types::error::Error::from(format!("No contracts found for chain {chain}"))
		})?;

		// Get token addresses
		let tokens = &contracts.tokens;
		if tokens.is_empty() {
			use crate::core::logging;
			logging::warning(&format!(
				"No tokens found for chain {chain}, skipping token operations"
			));
			return Ok(());
		}

		// Mint tokens to user and solver
		for (symbol, token_info) in tokens {
			// Convert amount to token units using proper decimals
			let mint_amount =
				U256::from(amount) * U256::from(10).pow(U256::from(token_info.decimals));

			logging::verbose_operation(
				"Minting tokens",
				&format!("{amount} {symbol} on chain {chain}"),
			);

			// Mint to user
			match token_ops
				.mint(
					chain,
					symbol,
					Some(&ctx.config.accounts().user.address),
					mint_amount,
				)
				.await
			{
				Ok(result) => {
					if let Some(tx_hash) = result.tx_hash {
						logging::verbose_tech(
							"User mint completed",
							&format!("{symbol} on chain {chain} (tx: {tx_hash:?})"),
						);
					}
				},
				Err(e) => {
					logging::warning(&format!(
						"Failed to mint {symbol} tokens to user on chain {chain}: {e}"
					));
					continue;
				},
			}

			// Mint to solver
			match token_ops
				.mint(
					chain,
					symbol,
					Some(&ctx.config.accounts().solver.address),
					mint_amount,
				)
				.await
			{
				Ok(result) => {
					if let Some(tx_hash) = result.tx_hash {
						logging::verbose_tech(
							"Solver mint completed",
							&format!("{symbol} on chain {chain} (tx: {tx_hash:?})"),
						);
					}
				},
				Err(e) => {
					logging::warning(&format!(
						"Failed to mint {symbol} tokens to solver on chain {chain}: {e}"
					));
					continue;
				},
			}

			logging::verbose_success(
				"Token minting completed",
				&format!("{symbol} on chain {chain}"),
			);
		}

		// Approve permit2 allowances for input settlers
		if let Some(permit2_addr) = &contracts.permit2 {
			let permit2_address = permit2_addr
				.parse::<Address>()
				.map_err(|e| Error::InvalidConfig(format!("Invalid permit2 address: {e}")))?;

			// Approve for all tokens
			for symbol in tokens.keys() {
				if let Some(_input_settler_addr) = &contracts.input_settler {
					logging::verbose_operation(
						"Approving token",
						&format!("{symbol} for Permit2 -> InputSettler on chain {chain}"),
					);
					match token_ops
						.approve(chain, symbol, &permit2_address.to_string(), None)
						.await
					{
						Ok(result) => {
							if let Some(tx_hash) = result.tx_hash {
								logging::verbose_tech(
									"InputSettler approval completed",
									&format!("{symbol} on chain {chain} (tx: {tx_hash:?})"),
								);
							}
						},
						Err(e) => {
							logging::warning(&format!(
								"Failed to approve {symbol} for Permit2 -> InputSettler on chain {chain}: {e}"
							));
						},
					}
				}

				if let Some(_input_settler_compact_addr) = &contracts.input_settler_compact {
					logging::verbose_operation(
						"Approving token",
						&format!("{symbol} for Permit2 -> InputSettlerCompact on chain {chain}"),
					);
					match token_ops
						.approve(chain, symbol, &permit2_address.to_string(), None)
						.await
					{
						Ok(result) => {
							if let Some(tx_hash) = result.tx_hash {
								logging::verbose_tech(
									"InputSettlerCompact approval completed",
									&format!("{symbol} on chain {chain} (tx: {tx_hash:?})"),
								);
							}
						},
						Err(e) => {
							logging::warning(&format!("Failed to approve {symbol} for Permit2 -> InputSettlerCompact on chain {chain}: {e}"));
						},
					}
				}
			}

			logging::verbose_success("Permit2 allowances approved", &format!("chain {chain}"));
		}

		// Register allocator with TheCompact
		if let Some(compact_addr) = &contracts.compact {
			if let Some(allocator_addr) = &contracts.allocator {
				logging::verbose_operation(
					"Registering allocator with TheCompact",
					&format!("chain {chain}"),
				);
				Self::register_allocator_with_compact_static(
					&provider,
					compact_addr,
					allocator_addr,
				)
				.await?;
				logging::verbose_success("Allocator registered", &format!("chain {chain}"));
			}
		}

		Ok(())
	}

	/// Static version of register_allocator_with_compact for use in async tasks
	async fn register_allocator_with_compact_static(
		provider: &Provider,
		compact_addr: &str,
		allocator_addr: &str,
	) -> Result<()> {
		// Parse addresses
		let compact_address: Address = compact_addr
			.parse()
			.map_err(|e| Error::InvalidConfig(format!("Invalid compact address: {e}")))?;
		let allocator_address: Address = allocator_addr
			.parse()
			.map_err(|e| Error::InvalidConfig(format!("Invalid allocator address: {e}")))?;

		// Create signer from solver's private key
		let signer =
			PrivateKeySigner::from_str(crate::constants::anvil_accounts::SOLVER_PRIVATE_KEY)
				.map_err(|e| Error::InvalidConfig(format!("Invalid private key: {e}")))?;

		// Build __registerAllocator transaction data using contracts helper
		use crate::core::contracts::Contracts;
		let mut contracts_helper = Contracts::new();
		contracts_helper.load_abis(std::path::Path::new("."))?;
		let data = contracts_helper.thecompact_register_allocator(allocator_address, vec![])?;

		let tx = TransactionRequest::default()
			.to(compact_address)
			.input(data.into())
			.value(U256::ZERO);

		// Send transaction
		let tx_builder = TxBuilder::new(provider.clone()).with_signer(signer);
		let receipt = tx_builder.send_and_wait(tx).await?;

		logging::verbose_tech(
			"Allocator registration completed",
			&format!("tx: {:?}", receipt.transaction_hash),
		);

		Ok(())
	}

	/// Inject a deployed contract address into the appropriate TOML config file
	/// This function looks up the placeholder address and replaces it with the actual address
	pub async fn inject_address_to_toml(
		&self,
		placeholder_key: &str,
		actual_address: &str,
	) -> Result<()> {
		use std::fs;

		// Get the config sections mapping from session
		let config_sections = self.ctx.session.config_sections();

		// Get the placeholder address for this key from the session
		let placeholder_address = self.ctx.session.get_placeholder_address(placeholder_key);

		if placeholder_address.is_none() {
			logging::warning(&format!(
				"No placeholder address found for key {placeholder_key} in session"
			));
			return Ok(());
		}

		let placeholder_address = placeholder_address.unwrap();

		// Determine which TOML file to update based on the placeholder prefix
		let target_file = if placeholder_key.contains("SETTLEMENT") {
			// Settlement domain goes in the main config file (settlement section)
			if let Some(settlement_file) = config_sections.get("settlement") {
				settlement_file.clone()
			} else if let Some(main_file) = config_sections.get("main") {
				main_file.clone()
			} else {
				return Err(Error::InvalidConfig(
					"Settlement config file not found in session".to_string(),
				));
			}
		} else if placeholder_key.contains("INPUT_SETTLER")
			|| placeholder_key.contains("OUTPUT_SETTLER")
			|| placeholder_key.contains("COMPACT")
			|| placeholder_key.contains("ALLOCATOR")
			|| placeholder_key.contains("TOKEN")
		{
			// Network-specific contracts go in networks section
			if let Some(networks_file) = config_sections.get("networks") {
				networks_file.clone()
			} else {
				return Err(Error::InvalidConfig(
					"Networks config file not found in session".to_string(),
				));
			}
		} else if placeholder_key.contains("ORACLE") {
			// Oracle contracts go in settlement section or main config file
			if let Some(settlement_file) = config_sections.get("settlement") {
				settlement_file.clone()
			} else if let Some(main_file) = config_sections.get("main") {
				main_file.clone()
			} else {
				return Err(Error::InvalidConfig(
					"Settlement config file not found in session".to_string(),
				));
			}
		} else {
			return Err(Error::InvalidConfig(format!(
				"Unknown placeholder key: {placeholder_key}"
			)));
		};

		// Read the current file content
		let content = fs::read_to_string(&target_file).map_err(Error::Io)?;

		// Replace the placeholder address with the actual address
		// Look for both quoted and unquoted versions
		let patterns_to_replace = [
			format!("\"{placeholder_address}\""),
			placeholder_address.clone(),
		];

		let mut updated_content = content.clone();
		let mut replacement_made = false;

		for pattern in &patterns_to_replace {
			if updated_content.contains(pattern) {
				updated_content =
					updated_content.replace(pattern, &format!("\"{actual_address}\""));
				replacement_made = true;
			}
		}

		// Check if any replacement was made
		if !replacement_made {
			logging::warning(&format!(
				"Placeholder address {} not found in target file {}",
				placeholder_address,
				target_file.display()
			));
			return Ok(());
		}

		// Write the updated content back to the file
		fs::write(&target_file, updated_content).map_err(Error::Io)?;

		Ok(())
	}

	/// Replace config placeholders with actual deployed addresses
	/// This is called internally after contract deployment
	async fn replace_config_placeholders(
		&self,
		chain: ChainId,
		contract_name: &str,
		address: Address,
	) -> Result<()> {
		use crate::constants::placeholders::*;
		// Map contract names to their placeholder keys based on the chain ID (numeric only)
		let chain_id = chain.id();
		let placeholder_key = match contract_name {
			"InputSettler" => format!("{PLACEHOLDER_INPUT_SETTLER_PREFIX}{chain_id}"),
			"OutputSettler" => format!("{PLACEHOLDER_OUTPUT_SETTLER_PREFIX}{chain_id}"),
			"TheCompact" | "Compact" => format!("{PLACEHOLDER_COMPACT_PREFIX}{chain_id}"),
			"InputSettlerCompact" => {
				format!("{PLACEHOLDER_INPUT_SETTLER_COMPACT_PREFIX}{chain_id}")
			},
			"Allocator" => format!("{PLACEHOLDER_ALLOCATOR_PREFIX}{chain_id}"),
			"TokenA" | "TOKA" => format!("{PLACEHOLDER_TOKEN_A_PREFIX}{chain_id}"),
			"TokenB" | "TOKB" => format!("{PLACEHOLDER_TOKEN_B_PREFIX}{chain_id}"),
			"OracleInput" => format!("{ORACLE_PLACEHOLDER_INPUT_PREFIX}{chain_id}"),
			"OracleOutput" => format!("{ORACLE_PLACEHOLDER_OUTPUT_PREFIX}{chain_id}"),
			_ => return Ok(()), // Unknown contract, skip
		};

		// Inject the address into the appropriate TOML file
		self.inject_address_to_toml(&placeholder_key, &address.to_string())
			.await
	}
}

/// Environment status information
#[derive(Debug, Clone)]
pub struct EnvironmentStatus {
	pub environment: Environment,
	pub chains: Vec<ChainStatus>,
}

/// Chain status information
#[derive(Debug, Clone)]
pub struct ChainStatus {
	pub chain: ChainId,
	pub running: bool,
	pub url: String,
	pub pid: Option<u32>,
}
