//! Local environment management service.
//!
//! This module provides functionality for managing local development environments,
//! including starting and stopping Anvil blockchain instances and deploying
//! infrastructure contracts for testing.

use alloy_dyn_abi::DynSolValue;
use alloy_provider::Provider;
use anyhow::{anyhow, Result};
use futures::future::try_join_all;
use std::collections::HashMap;

use crate::utils::address::bytes_to_checksum_address;
use std::process::{Command, Stdio};
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, warn};
use which::which;

use crate::utils::constants::*;

use crate::core::{ContractManager, SessionManager};
use crate::models::{ContractAddresses, TokenInfo};

/// Service for managing local development environments.
/// Handles starting/stopping Anvil instances and deploying infrastructure contracts.
#[derive(Clone)]
pub struct LocalEnvironmentService {
	/// Manager for session state and configuration.
	session_manager: Arc<SessionManager>,
	/// Manager for contract deployment and interaction.
	contract_manager: Arc<ContractManager>,
}

impl LocalEnvironmentService {
	/// Creates a new LocalEnvironmentService instance.
	pub fn new(
		session_manager: Arc<SessionManager>,
		contract_manager: Arc<ContractManager>,
	) -> Self {
		Self {
			session_manager,
			contract_manager,
		}
	}

	/// Starts the local environment, including Anvil instances and deploying contracts.
	pub async fn start_environment(&self) -> Result<()> {
		info!("Starting local environment");

		if !self.session_manager.is_local().await {
			return Err(anyhow!("Cannot start local environment in production mode"));
		}

		let chain_ids = self.session_manager.get_chain_ids().await;
		if chain_ids.is_empty() {
			return Err(anyhow!("No chains configured"));
		}

		info!("Starting {} local chains", chain_ids.len());

		for chain_id in &chain_ids {
			let port = self.session_manager.get_chain_port(*chain_id).await?;
			self.start_anvil(*chain_id, port).await?;
		}

		info!("Deploying infrastructure contracts to all chains in parallel");

		let deployment_futures: Vec<_> = chain_ids
			.iter()
			.map(|&chain_id| {
				let env_service = self.clone();
				async move {
					info!("Starting deployment to chain {}", chain_id);
					let addresses = env_service.deploy_chain_infrastructure(chain_id).await?;
					info!("Chain {} deployment complete", chain_id);
					Ok::<_, anyhow::Error>((chain_id, addresses))
				}
			})
			.collect();

		let deployments = try_join_all(deployment_futures).await?;

		info!("Updating configuration files with deployed addresses");
		for (chain_id, addresses) in deployments {
			self.session_manager
				.update_contract_addresses(chain_id, addresses)
				.await?;
		}

		// Reload configuration to pick up the freshly updated addresses
		info!("Reloading configuration with updated addresses...");
		self.session_manager.reload_config().await?;

		info!("Setting up token balances and Permit2 approvals...");
		self.setup_token_approvals().await?;

		info!("Local environment started successfully");
		Ok(())
	}

	/// Stops all running Anvil instances in the local environment.
	pub async fn stop_environment(&self) -> Result<()> {
		info!("Stopping local environment");

		let chain_ids = self.session_manager.get_chain_ids().await;
		for chain_id in &chain_ids {
			self.stop_anvil(*chain_id).await?;
		}

		info!("Local environment stopped");
		Ok(())
	}

	/// Gets the current status of all chains in the environment.
	pub async fn get_status(&self) -> Result<EnvironmentStatus> {
		let mut chains = Vec::new();

		for chain_id in self.session_manager.get_chain_ids().await {
			let rpc_url = self
				.session_manager
				.get_rpc_url(chain_id)
				.await
				.unwrap_or_default();

			let is_running = self.check_chain_status(&rpc_url).await;

			chains.push(ChainStatus {
				chain_id,
				rpc_url,
				is_running,
			});
		}

		Ok(EnvironmentStatus { chains })
	}

	/// Starts an Anvil instance for the specified chain.
	async fn start_anvil(&self, chain_id: u64, port: u16) -> Result<()> {
		if self.check_port_in_use(port).await {
			info!(
				"Port {} already in use, assuming Anvil is running for chain {}",
				port, chain_id
			);
			return Ok(());
		}

		if which("anvil").is_err() {
			return Err(anyhow!(
				"Anvil not found. Please install Foundry: https://getfoundry.sh"
			));
		}

		info!("Starting Anvil for chain {} on port {}", chain_id, port);

		let mut cmd = Command::new("anvil");
		cmd.args([
			"--port",
			&port.to_string(),
			"--chain-id",
			&chain_id.to_string(),
			"--accounts",
			ANVIL_ACCOUNTS,
			"--balance",
			ANVIL_BALANCE,
			"--block-time",
			ANVIL_BLOCK_TIME,
		])
		.stdout(Stdio::null())
		.stderr(Stdio::null())
		.stdin(Stdio::null());

		let child = cmd.spawn()?;
		let pid = child.id();

		self.save_pid(chain_id, pid)?;

		std::mem::forget(child);

		self.wait_for_rpc(port).await?;

		info!("Anvil started for chain {} (PID: {})", chain_id, pid);
		Ok(())
	}

	/// Stops the Anvil instance for the specified chain.
	async fn stop_anvil(&self, chain_id: u64) -> Result<()> {
		if let Some(pid) = self.load_pid(chain_id)? {
			info!("Stopping Anvil for chain {} (PID: {})", chain_id, pid);

			#[cfg(unix)]
			{
				use nix::sys::signal::{kill, Signal};
				use nix::unistd::Pid;

				match kill(Pid::from_raw(pid as i32), Signal::SIGTERM) {
					Ok(_) => debug!("Sent SIGTERM to PID {}", pid),
					Err(e) => warn!("Failed to kill process {}: {}", pid, e),
				}
			}

			self.remove_pid_file(chain_id)?;
		}

		Ok(())
	}

	/// Deploys all infrastructure contracts to the specified chain.
	async fn deploy_chain_infrastructure(&self, chain_id: u64) -> Result<ContractAddresses> {
		info!("Deploying infrastructure contracts to chain {}", chain_id);

		let mut addresses = ContractAddresses::default();
		let mut token_addresses: HashMap<String, TokenInfo> = HashMap::new();

		info!("[1/8] Deploying Permit2 at canonical address...");
		let permit2_address = self.ensure_permit2(chain_id).await?;
		addresses.permit2 = Some(bytes_to_checksum_address(&permit2_address, Some(chain_id)));

		info!("[2/8] Deploying TOKA token...");
		let toka_address = self
			.contract_manager
			.deploy_contract(
				chain_id,
				"MockERC20",
				vec![
					DynSolValue::String("Token A".to_string()),
					DynSolValue::String("TOKA".to_string()),
					DynSolValue::Uint(alloy_primitives::U256::from(18), 256),
				],
			)
			.await
			.map_err(|e| anyhow!("Failed to deploy TOKA token: {}", e))?;
		info!("TOKA deployed at: {}", toka_address);
		token_addresses.insert(
			"TOKA".to_string(),
			TokenInfo {
				address: crate::utils::address::to_checksum_address(&toka_address, Some(chain_id)),
				decimals: 18,
			},
		);

		info!("[3/8] Deploying TOKB token...");
		let tokb_address = self
			.contract_manager
			.deploy_contract(
				chain_id,
				"MockERC20",
				vec![
					DynSolValue::String("Token B".to_string()),
					DynSolValue::String("TOKB".to_string()),
					DynSolValue::Uint(alloy_primitives::U256::from(18), 256),
				],
			)
			.await
			.map_err(|e| anyhow!("Failed to deploy TOKB token: {}", e))?;
		info!("TOKB deployed at: {}", tokb_address);
		token_addresses.insert(
			"TOKB".to_string(),
			TokenInfo {
				address: crate::utils::address::to_checksum_address(&tokb_address, Some(chain_id)),
				decimals: 18,
			},
		);

		info!("[4/8] Deploying InputSettlerEscrow contract...");
		let input_settler_address = self
			.contract_manager
			.deploy_contract(
				chain_id,
				"InputSettlerEscrow",
				vec![], // No constructor args
			)
			.await
			.map_err(|e| anyhow!("Failed to deploy InputSettlerEscrow: {}", e))?;
		info!("InputSettlerEscrow deployed at: {}", input_settler_address);
		addresses.input_settler = Some(crate::utils::address::to_checksum_address(
			&input_settler_address,
			Some(chain_id),
		));

		info!("[5/8] Deploying OutputSettlerSimple contract...");
		let output_settler_address = self
			.contract_manager
			.deploy_contract(
				chain_id,
				"OutputSettlerSimple",
				vec![], // No constructor args
			)
			.await
			.map_err(|e| anyhow!("Failed to deploy OutputSettlerSimple: {}", e))?;
		info!(
			"OutputSettlerSimple deployed at: {}",
			output_settler_address
		);
		addresses.output_settler = Some(crate::utils::address::to_checksum_address(
			&output_settler_address,
			Some(chain_id),
		));

		info!("[6/9] Deploying TheCompact contract...");
		let compact_address = self
			.contract_manager
			.deploy_contract(
				chain_id,
				"TheCompact",
				vec![], // No constructor args
			)
			.await
			.map_err(|e| anyhow!("Failed to deploy TheCompact: {}", e))?;
		info!("TheCompact deployed at: {}", compact_address);
		addresses.compact = Some(crate::utils::address::to_checksum_address(
			&compact_address,
			Some(chain_id),
		));

		info!("[7/9] Deploying InputSettlerCompact contract...");
		// InputSettlerCompact takes TheCompact address as constructor argument
		use alloy_dyn_abi::DynSolValue;
		let input_settler_compact_address = self
			.contract_manager
			.deploy_contract(
				chain_id,
				"InputSettlerCompact",
				vec![DynSolValue::Address(compact_address)], // TheCompact address as constructor arg
			)
			.await
			.map_err(|e| anyhow!("Failed to deploy InputSettlerCompact: {}", e))?;
		info!(
			"InputSettlerCompact deployed at: {}",
			input_settler_compact_address
		);
		addresses.input_settler_compact = Some(crate::utils::address::to_checksum_address(
			&input_settler_compact_address,
			Some(chain_id),
		));

		info!("[8/10] Deploying AlwaysOKAllocator contract...");
		let allocator_address = self
			.contract_manager
			.deploy_contract(
				chain_id,
				"AlwaysOKAllocator",
				vec![], // No constructor args
			)
			.await
			.map_err(|e| anyhow!("Failed to deploy AlwaysOKAllocator: {}", e))?;
		info!("AlwaysOKAllocator deployed at: {}", allocator_address);
		addresses.allocator = Some(crate::utils::address::to_checksum_address(
			&allocator_address,
			Some(chain_id),
		));

		// Register the allocator with TheCompact
		info!("[9/10] Registering allocator with TheCompact...");
		self.register_allocator_with_compact(chain_id, compact_address, allocator_address)
			.await
			.map_err(|e| anyhow!("Failed to register allocator with TheCompact: {}", e))?;
		info!("Allocator registered with TheCompact");

		info!("[10/10] Deploying AlwaysYesOracle contract...");
		let oracle_address = self
			.contract_manager
			.deploy_contract(
				chain_id,
				"AlwaysYesOracle",
				vec![], // No constructor args
			)
			.await
			.map_err(|e| anyhow!("Failed to deploy AlwaysYesOracle: {}", e))?;
		info!("AlwaysYesOracle deployed at: {}", oracle_address);
		addresses.oracle = Some(crate::utils::address::to_checksum_address(
			&oracle_address,
			Some(chain_id),
		));

		addresses.tokens = token_addresses;

		info!(
			"Infrastructure deployment completed for chain {} with {} contracts",
			chain_id, 9
		);
		Ok(addresses)
	}

	/// Register an allocator with TheCompact contract
	async fn register_allocator_with_compact(
		&self,
		chain_id: u64,
		compact_address: alloy_primitives::Address,
		allocator_address: alloy_primitives::Address,
	) -> Result<()> {
		info!("Registering allocator with TheCompact contract");
		info!("  Chain ID: {}", chain_id);
		info!("  TheCompact address: {}", compact_address);
		info!("  Allocator address: {}", allocator_address);

		// First, let's verify the allocator is deployed
		let provider = self.contract_manager.get_provider(chain_id).await?;
		let allocator_code = provider
			.get_code_at(allocator_address)
			.await
			.map_err(|e| anyhow!("Failed to check allocator code: {}", e))?;

		if allocator_code.is_empty() {
			return Err(anyhow!("Allocator not deployed at {}", allocator_address));
		}
		info!("  Allocator code size: {} bytes", allocator_code.len());

		// Debug: Let's try different ways of encoding empty bytes
		info!("Attempting to register allocator...");

		// Use contract manager to send the transaction
		match self
			.contract_manager
			.send_transaction(
				chain_id,
				compact_address,
				"TheCompact",
				"__registerAllocator",
				vec![
					DynSolValue::Address(allocator_address),
					DynSolValue::Bytes(vec![]), // Empty bytes for proof
				],
			)
			.await
		{
			Ok(receipt) => {
				info!("✅ Allocator registration successful!");
				info!("  Transaction hash: {:?}", receipt.transaction_hash);
				info!("  Block number: {:?}", receipt.block_number);
				info!("  Gas used: {:?}", receipt.gas_used);
				info!("  Status: {}", receipt.status());

				// Receipt structure debugging
				debug!("Full receipt: {:?}", receipt);

				debug!("Allocator successfully registered with TheCompact");
				Ok(())
			},
			Err(e) => {
				error!("❌ Failed to register allocator: {}", e);

				// Let's try to get more details about the error
				let error_str = format!("{:?}", e);
				if error_str.contains("execution reverted") {
					error!("  Transaction reverted during execution");

					// Try to decode the error if possible
					if error_str.contains("0x") {
						error!("  Revert data present, attempting to decode...");
					}
				}

				Err(anyhow!("Failed to register allocator: {}", e))
			},
		}
	}

	/// Ensures Permit2 is deployed at its canonical address.
	async fn ensure_permit2(&self, chain_id: u64) -> Result<[u8; 20]> {
		let canonical_address_hex = PERMIT2_CANONICAL_ADDRESS.trim_start_matches("0x");
		let canonical_address = hex::decode(canonical_address_hex)
			.map_err(|e| anyhow!("Invalid Permit2 address: {}", e))?;

		if canonical_address.len() != 20 {
			return Err(anyhow!("Permit2 address must be 20 bytes"));
		}

		let mut address_bytes = [0u8; 20];
		address_bytes.copy_from_slice(&canonical_address);

		let rpc_url = self
			.session_manager
			.get_rpc_url(chain_id)
			.await
			.ok_or_else(|| anyhow!("No RPC URL configured for chain {}", chain_id))?;

		info!("Deploying Permit2 at canonical address via anvil_setCode...");

		const PERMIT2_BYTECODE: &str = include_str!("../../data/permit2_bytecode.hex");

		let bytecode_hex = PERMIT2_BYTECODE.trim();

		let bytecode_with_prefix = if bytecode_hex.starts_with("0x") {
			bytecode_hex.to_string()
		} else {
			format!("0x{}", bytecode_hex)
		};

		let set_code_request = serde_json::json!({
			"jsonrpc": "2.0",
			"method": "anvil_setCode",
			"params": [PERMIT2_CANONICAL_ADDRESS, bytecode_with_prefix],
			"id": 1
		});

		let client = reqwest::Client::new();
		let response = client
			.post(&rpc_url)
			.json(&set_code_request)
			.send()
			.await
			.map_err(|e| anyhow!("Failed to send anvil_setCode request: {}", e))?;

		if !response.status().is_success() {
			let error_text = response.text().await.unwrap_or_default();
			return Err(anyhow!("anvil_setCode failed: {}", error_text));
		}

		info!(
			"Permit2 deployed at canonical address: {}",
			PERMIT2_CANONICAL_ADDRESS
		);
		Ok(address_bytes)
	}

	/// Checks if a port is already in use.
	async fn check_port_in_use(&self, port: u16) -> bool {
		use std::net::TcpStream;
		TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok()
	}

	/// Waits for an RPC endpoint to become available on the specified port.
	async fn wait_for_rpc(&self, port: u16) -> Result<()> {
		for i in 0..RPC_READY_MAX_ATTEMPTS {
			if self.check_port_in_use(port).await {
				return Ok(());
			}

			if i == RPC_READY_MAX_ATTEMPTS - 1 {
				return Err(anyhow!("RPC on port {} did not become ready", port));
			}

			sleep(Duration::from_millis(RPC_READY_CHECK_DELAY_MS)).await;
		}
		Ok(())
	}

	/// Checks if a chain is running by making a test RPC call.
	async fn check_chain_status(&self, rpc_url: &str) -> bool {
		(reqwest::Client::new()
			.post(rpc_url)
			.json(&serde_json::json!({
			"jsonrpc": "2.0",
			"method": "eth_blockNumber",
			"params": [],
			"id": 1
			}))
			.timeout(Duration::from_secs(2))
			.send()
			.await)
			.is_ok()
	}

	/// Saves the process ID of an Anvil instance to file.
	fn save_pid(&self, chain_id: u64, pid: u32) -> Result<()> {
		let pids_dir = self.session_manager.pids_dir();

		if !pids_dir.exists() {
			debug!("Creating pids directory: {}", pids_dir.display());
			std::fs::create_dir_all(&pids_dir)?;
		}

		let pid_file = pids_dir.join(format!("anvil_{}.pid", chain_id));
		debug!("Saving PID {} to file: {}", pid, pid_file.display());
		std::fs::write(&pid_file, pid.to_string())?;
		info!(
			"Saved Anvil PID {} for chain {} to {}",
			pid,
			chain_id,
			pid_file.display()
		);
		Ok(())
	}

	/// Loads the process ID of an Anvil instance from file.
	fn load_pid(&self, chain_id: u64) -> Result<Option<u32>> {
		let pid_file = self
			.session_manager
			.pids_dir()
			.join(format!("anvil_{}.pid", chain_id));
		if pid_file.exists() {
			let pid_str = std::fs::read_to_string(pid_file)?;
			Ok(Some(pid_str.trim().parse()?))
		} else {
			Ok(None)
		}
	}

	/// Removes the PID file for an Anvil instance.
	fn remove_pid_file(&self, chain_id: u64) -> Result<()> {
		let pid_file = self
			.session_manager
			.pids_dir()
			.join(format!("anvil_{}.pid", chain_id));
		if pid_file.exists() {
			std::fs::remove_file(pid_file)?;
		}
		Ok(())
	}

	/// Sets up token balances and Permit2 approvals for seamless intent submission.
	/// This mirrors the behavior of the old bash env_up system.
	async fn setup_token_approvals(&self) -> Result<()> {
		use alloy_primitives::{Address, U256};
		use alloy_signer::Signer;

		let chain_ids = self.session_manager.get_chain_ids().await;
		let user_account = self.session_manager.get_user_account().await;
		let solver_account = self.session_manager.get_solver_account().await;
		let permit2_address: Address = PERMIT2_CANONICAL_ADDRESS
			.parse()
			.map_err(|e| anyhow!("Invalid Permit2 address: {}", e))?;

		for chain_id in chain_ids {
			info!(
				"Setting up token balances and approvals for chain {}",
				chain_id
			);

			// Get token addresses for this chain
			let network_config = self.session_manager.get_network_config(chain_id).await;
			if network_config.is_none() {
				warn!("No network config found for chain {}", chain_id);
				continue;
			}
			let network = network_config.unwrap();

			// Set up approvals for each token
			for (token_symbol, token_info) in &network.contracts.tokens {
				let token_address: Address = token_info
					.address
					.parse()
					.map_err(|e| anyhow!("Invalid token address for {}: {}", token_symbol, e))?;

				info!(
					"Setting up {} token balances and approvals on chain {}",
					token_symbol, chain_id
				);

				// 1. Mint tokens to user (100 tokens = 100 * 10^decimals)
				let amount = U256::from(100) * U256::from(10).pow(U256::from(token_info.decimals));

				info!("Minting {} {} to user", amount, token_symbol);
				self.contract_manager
					.send_transaction(
						chain_id,
						token_address,
						"MockERC20",
						"mint",
						vec![
							DynSolValue::Address(user_account.address),
							DynSolValue::Uint(amount, 256),
						],
					)
					.await
					.map_err(|e| {
						anyhow!("Failed to mint {} tokens to user: {}", token_symbol, e)
					})?;

				// 2. Mint tokens to solver (100 tokens = 100 * 10^decimals)
				info!("Minting {} {} to solver", amount, token_symbol);
				self.contract_manager
					.send_transaction(
						chain_id,
						token_address,
						"MockERC20",
						"mint",
						vec![
							DynSolValue::Address(solver_account.address),
							DynSolValue::Uint(amount, 256),
						],
					)
					.await
					.map_err(|e| {
						anyhow!("Failed to mint {} tokens to solver: {}", token_symbol, e)
					})?;

				// 3. Basic ERC20 approval: User approves Permit2 to spend unlimited tokens
				// This matches the old bash system behavior (lines 828-835 in deployment.sh)
				info!(
					"Approving Permit2 to spend {} tokens for user",
					token_symbol
				);
				let max_amount = U256::MAX;

				// Get user's private key for the approval
				let key = user_account
					.private_key
					.as_ref()
					.ok_or_else(|| anyhow!("User account has no private key"))?
					.trim_start_matches("0x");
				let user_private_key =
					alloy_signer_local::PrivateKeySigner::from_slice(&hex::decode(key)?)
						.map_err(|e| anyhow!("Failed to parse user private key: {}", e))?
						.with_chain_id(Some(chain_id));

				self.contract_manager
					.send_transaction_with_key(
						chain_id,
						token_address,
						"MockERC20",
						"approve",
						vec![
							DynSolValue::Address(permit2_address),
							DynSolValue::Uint(max_amount, 256),
						],
						Some(user_private_key),
					)
					.await
					.map_err(|e| {
						anyhow!("Failed to approve Permit2 for {}: {}", token_symbol, e)
					})?;

				info!(
					"✓ {} token setup complete (minted to user+solver + ERC20->Permit2 approval)",
					token_symbol
				);
			}

			info!("✓ Chain {} token setup complete", chain_id);
		}

		Ok(())
	}
}

/// Status of the local environment, containing information about all chains.
#[derive(Debug)]
pub struct EnvironmentStatus {
	/// List of chain statuses.
	pub chains: Vec<ChainStatus>,
}

impl EnvironmentStatus {
	/// Converts the environment status into rows for display.
	pub fn into_rows(self) -> Vec<Vec<String>> {
		self.chains
			.into_iter()
			.map(|chain| {
				vec![
					chain.chain_id.to_string(),
					if chain.is_running {
						"Running"
					} else {
						"Stopped"
					}
					.to_string(),
					chain.rpc_url,
				]
			})
			.collect()
	}
}

/// Status of a single blockchain in the environment.
#[derive(Debug)]
pub struct ChainStatus {
	/// The chain ID.
	pub chain_id: u64,
	/// The RPC URL for the chain.
	pub rpc_url: String,
	/// Whether the chain is currently running.
	pub is_running: bool,
}
