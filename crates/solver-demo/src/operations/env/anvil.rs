//! Anvil blockchain process management
//!
//! Provides functionality for managing local Anvil blockchain processes including
//! process lifecycle management, port configuration, health monitoring, and
//! coordinated startup/shutdown operations across multiple chains.

use crate::{
	types::{
		chain::ChainId,
		error::{Error, Result},
	},
	Context,
};
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{Pid, ProcessesToUpdate, System};
use tokio::time::sleep;
use tracing::info;

use super::ChainStatus;

/// Information about a running Anvil process
///
/// Tracks essential information for managing individual Anvil blockchain instances
/// including process identification, network configuration, and connection details.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnvilProcess {
	pub chain: ChainId,
	pub pid: u32,
	pub port: u16,
}

/// Anvil blockchain process manager
///
/// Provides methods for starting, stopping, and monitoring local Anvil blockchain
/// processes. Handles port allocation, process lifecycle management, and health
/// checking for development environments.
pub struct AnvilManager {
	ctx: Arc<Context>,
}

impl AnvilManager {
	/// Creates a new Anvil process manager
	///
	/// # Arguments
	/// * `ctx` - Shared application context containing configuration and services
	///
	/// # Returns
	/// New Anvil manager instance
	pub fn new(ctx: Arc<Context>) -> Self {
		Self { ctx }
	}

	/// Retrieves the configured port for a blockchain network
	///
	/// # Arguments
	/// * `chain` - Chain identifier to get port for
	///
	/// # Returns
	/// Port number for the specified chain
	///
	/// # Errors
	/// Returns error if chain not found or port configuration invalid
	fn get_port(&self, chain: ChainId) -> Result<u16> {
		let network = self
			.ctx
			.config
			.network(chain)
			.ok_or_else(|| Error::ChainNotFound(chain))?;

		if let Some(rpc_endpoint) = network.rpc_urls.first() {
			if let Some(http_url) = &rpc_endpoint.http {
				if let Ok(url) = url::Url::parse(http_url) {
					Ok(url.port().unwrap_or(8545))
				} else {
					Err(Error::InvalidConfig("Invalid RPC URL".to_string()))
				}
			} else {
				Err(Error::InvalidConfig(
					"No HTTP RPC URL configured".to_string(),
				))
			}
		} else {
			Err(Error::InvalidConfig("No RPC URLs configured".to_string()))
		}
	}

	/// Start an Anvil chain
	pub fn start_chain(&mut self, chain: ChainId) -> Result<()> {
		// Check if already running
		if self.is_running(chain) {
			return Err(Error::ChainAlreadyRunning(chain));
		}

		let port = self.get_port(chain)?;

		info!(port = port, chain = %chain, "Starting Anvil process");

		// Build Anvil command to run in background
		let mut cmd = Command::new("anvil");
		cmd.arg("--port")
			.arg(port.to_string())
			.arg("--accounts")
			.arg("10")
			.arg("--balance")
			.arg("10000")
			.arg("--mnemonic")
			.arg("test test test test test test test test test test test junk")
			.arg("--chain-id")
			.arg(chain.id().to_string())
			.arg("--block-time")
			.arg("2")
			.stdout(Stdio::null())
			.stderr(Stdio::null());

		// Start the process and detach it
		let child = cmd
			.spawn()
			.map_err(|e| Error::AnvilStartFailed(format!("Failed to start Anvil: {}", e)))?;

		let pid = child.id();

		// Store process info persistently
		self.store_process_info(AnvilProcess { chain, pid, port })?;

		// Don't wait for the child - let it run in background
		std::mem::forget(child);

		info!(port = port, pid = pid, chain = %chain, "Anvil process started successfully");

		Ok(())
	}

	/// Store process information persistently
	fn store_process_info(&self, process: AnvilProcess) -> Result<()> {
		let mut processes = self.load_running_processes();
		processes.insert(process.chain, process);
		self.save_running_processes(&processes)
	}

	/// Load running processes from storage
	fn load_running_processes(&self) -> HashMap<ChainId, AnvilProcess> {
		// Try to load from session storage as JSON
		if let Ok(processes_map) = self
			.ctx
			.storage
			.load::<HashMap<String, AnvilProcess>>("anvil_processes")
		{
			// Convert string keys back to ChainId and filter out dead processes
			return processes_map
				.into_iter()
				.filter_map(|(key, process)| {
					if let Ok(chain_id) = key.parse::<u64>() {
						let chain = ChainId::from_u64(chain_id);
						if self.is_pid_running(process.pid) {
							Some((chain, process))
						} else {
							None
						}
					} else {
						None
					}
				})
				.collect();
		}
		HashMap::new()
	}

	/// Save running processes to storage
	fn save_running_processes(&self, processes: &HashMap<ChainId, AnvilProcess>) -> Result<()> {
		// Convert ChainId keys to strings for JSON serialization
		let string_keyed_map: HashMap<String, AnvilProcess> = processes
			.iter()
			.map(|(chain_id, process)| (chain_id.id().to_string(), process.clone()))
			.collect();

		self.ctx
			.storage
			.save("anvil_processes", &string_keyed_map)
			.map_err(|e| Error::StorageError(format!("Failed to save processes: {}", e)))
	}

	/// Check if a PID is still running
	fn is_pid_running(&self, pid: u32) -> bool {
		let mut sys = System::new();
		sys.refresh_processes(ProcessesToUpdate::All, true);
		sys.processes().contains_key(&Pid::from(pid as usize))
	}

	/// Wait for all chains to be ready
	pub async fn wait_for_chains(&self) -> Result<()> {
		info!("Waiting for all Anvil chains to be ready");

		let processes = self.load_running_processes();
		for chain in processes.keys() {
			self.wait_for_chain(*chain).await?;
		}

		Ok(())
	}

	/// Wait for a specific chain to be ready
	pub async fn wait_for_chain(&self, chain: ChainId) -> Result<()> {
		let port = self.get_port(chain)?;

		let url = format!("http://localhost:{}", port);
		let max_attempts = 30;
		let mut attempts = 0;

		while attempts < max_attempts {
			// Try to connect
			if self.check_chain_ready(&url).await {
				info!(chain = %chain, "Chain is ready and responding");
				return Ok(());
			}

			attempts += 1;
			sleep(Duration::from_millis(500)).await;
		}

		Err(Error::ChainNotReady(chain))
	}

	/// Check if a chain is ready by making an RPC call
	async fn check_chain_ready(&self, url: &str) -> bool {
		// Try to make a simple eth_blockNumber call
		let client = reqwest::Client::new();
		let response = client
			.post(url)
			.json(&serde_json::json!({
				"jsonrpc": "2.0",
				"method": "eth_blockNumber",
				"params": [],
				"id": 1
			}))
			.send()
			.await;

		response.is_ok()
	}

	/// Stop all Anvil processes
	pub fn stop_all(&mut self) -> Result<()> {
		let processes = self.load_running_processes();
		for (chain, process) in processes {
			info!(chain = %chain, "Stopping Anvil chain");
			self.kill_process(process.pid);
		}
		// Clear the stored processes
		self.save_running_processes(&HashMap::new())?;
		Ok(())
	}

	/// Stop a specific chain
	pub fn stop_chain(&mut self, chain: ChainId) -> Result<()> {
		let mut processes = self.load_running_processes();
		if let Some(process) = processes.remove(&chain) {
			info!(chain = %chain, "Stopping Anvil chain");
			self.kill_process(process.pid);
			self.save_running_processes(&processes)?;
		}
		Ok(())
	}

	/// Kill a process by PID
	fn kill_process(&self, pid: u32) {
		#[cfg(unix)]
		{
			use std::process::Command;
			let _ = Command::new("kill").arg("-9").arg(pid.to_string()).output();
		}

		#[cfg(windows)]
		{
			use std::process::Command;
			let _ = Command::new("taskkill")
				.arg("/F")
				.arg("/PID")
				.arg(pid.to_string())
				.output();
		}
	}

	/// Get list of running chains
	pub fn get_running_chains(&self) -> Vec<ChainStatus> {
		self.load_running_processes()
			.values()
			.map(|process| ChainStatus {
				chain: process.chain,
				running: self.is_pid_running(process.pid),
				url: format!("http://localhost:{}", process.port),
				pid: Some(process.pid),
			})
			.collect()
	}

	/// Check if a chain is running
	pub fn is_running(&self, chain: ChainId) -> bool {
		let processes = self.load_running_processes();
		processes.contains_key(&chain)
	}
}

// Note: No Drop implementation - we want processes to persist
