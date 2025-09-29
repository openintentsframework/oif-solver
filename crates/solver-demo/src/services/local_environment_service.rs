//! Local environment management service.
//!
//! This module provides functionality for managing local development environments,
//! including starting and stopping Anvil blockchain instances and deploying
//! infrastructure contracts for testing.

use anyhow::{anyhow, Result};
use futures::future::try_join_all;
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{debug, info, warn};
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
		addresses.permit2 = Some(format!("0x{}", hex::encode(permit2_address)));

		info!("[2/8] Deploying TOKA token...");
		let toka_address = self
			.contract_manager
			.deploy_contract(
				chain_id,
				"MockERC20",
				vec![
					ethers::abi::Token::String("Test Token A".to_string()),
					ethers::abi::Token::String("TOKA".to_string()),
					ethers::abi::Token::Uint(ethers::types::U256::from(6)), // 6 decimals
				],
			)
			.await
			.map_err(|e| anyhow!("Failed to deploy TOKA token: {}", e))?;
		info!("TOKA deployed at: {}", toka_address);
		token_addresses.insert(
			"TOKA".to_string(),
			TokenInfo {
				address: format!("{:#x}", toka_address),
				decimals: 6,
			},
		);

		info!("[3/8] Deploying TOKB token...");
		let tokb_address = self
			.contract_manager
			.deploy_contract(
				chain_id,
				"MockERC20",
				vec![
					ethers::abi::Token::String("Test Token B".to_string()),
					ethers::abi::Token::String("TOKB".to_string()),
					ethers::abi::Token::Uint(ethers::types::U256::from(6)), // 6 decimals
				],
			)
			.await
			.map_err(|e| anyhow!("Failed to deploy TOKB token: {}", e))?;
		info!("TOKB deployed at: {}", tokb_address);
		token_addresses.insert(
			"TOKB".to_string(),
			TokenInfo {
				address: format!("{:#x}", tokb_address),
				decimals: 6,
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
		addresses.input_settler = Some(format!("{:#x}", input_settler_address));

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
		addresses.output_settler = Some(format!("{:#x}", output_settler_address));

		info!("[6/8] Deploying TheCompact contract...");
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
		addresses.compact = Some(format!("{:#x}", compact_address));

		info!("[7/8] Deploying AlwaysOKAllocator contract...");
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
		addresses.allocator = Some(format!("{:#x}", allocator_address));

		info!("[8/8] Deploying AlwaysYesOracle contract...");
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
		addresses.oracle = Some(format!("{:#x}", oracle_address));

		addresses.tokens = token_addresses;

		info!(
			"Infrastructure deployment completed for chain {} with {} contracts",
			chain_id, 8
		);
		Ok(addresses)
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
