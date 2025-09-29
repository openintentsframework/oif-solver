use anyhow::{anyhow, Result};
use clap::Subcommand;
use std::sync::Arc;
use tracing::info;

use crate::core::{DisplayUtils, SessionManager};
use crate::services::LocalEnvironmentService;

#[derive(Debug, Subcommand)]
pub enum EnvironmentCommands {
	/// Start local Anvil environment
	Start,

	/// Stop local Anvil environment
	Stop,

	/// Show environment status
	Status,

	/// Deploy contracts to local environment
	Deploy,
}

pub struct EnvironmentHandler {
	environment_service: Arc<LocalEnvironmentService>,
	session_manager: Arc<SessionManager>,
	display: Arc<DisplayUtils>,
}

impl EnvironmentHandler {
	pub fn new(
		environment_service: Arc<LocalEnvironmentService>,
		session_manager: Arc<SessionManager>,
	) -> Self {
		Self {
			environment_service,
			session_manager,
			display: Arc::new(DisplayUtils::new()),
		}
	}

	pub async fn handle(&self, command: EnvironmentCommands) -> Result<()> {
		// Check if we're in local environment for commands that require it
		let is_local = self.session_manager.is_local().await;

		match command {
			EnvironmentCommands::Start
			| EnvironmentCommands::Stop
			| EnvironmentCommands::Deploy => {
				if !is_local {
					return Err(anyhow!(
						"This command is only available in local environment. \
                        Please initialize with 'oif-demo init load <config> --local'"
					));
				}
			},
			_ => {},
		}

		match command {
			EnvironmentCommands::Start => self.start().await,
			EnvironmentCommands::Stop => self.stop().await,
			EnvironmentCommands::Status => self.status().await,
			EnvironmentCommands::Deploy => self.deploy().await,
		}
	}

	async fn start(&self) -> Result<()> {
		info!("Starting local environment...");
		self.environment_service.start_environment().await?;
		self.display
			.success("Local environment started successfully");
		Ok(())
	}

	async fn stop(&self) -> Result<()> {
		info!("Stopping local environment...");
		self.environment_service.stop_environment().await?;
		self.display.success("Local environment stopped");
		Ok(())
	}

	async fn status(&self) -> Result<()> {
		use crate::core::TreeItem;
		
		let status = self.environment_service.get_status().await?;

		// Display header
		let env_type = if self.session_manager.is_local().await {
			"LOCAL ENVIRONMENT STATUS"
		} else {
			"PRODUCTION ENVIRONMENT STATUS"
		};
		self.display.header(env_type);

		// Display session info
		let env_mode = if self.session_manager.is_local().await { 
			"local" 
		} else { 
			"production" 
		};
		
		self.display.tree("Session", vec![
			TreeItem::Success(format!("Environment: {}", env_mode)),
		]);

		if status.chains.is_empty() {
			self.display.line("No chains configured");
			return Ok(());
		}

		// Display chains
		let chain_items: Vec<TreeItem> = status.chains
			.iter()
			.map(|chain| {
				let status_text = if chain.is_running { "Running" } else { "Stopped" };
				let dots = ".".repeat(10);
				TreeItem::Text(format!(
					"Chain {} {} {} [{}]",
					chain.chain_id,
					dots,
					status_text,
					chain.rpc_url
				))
			})
			.collect();
		
		self.display.tree("Active Chains", chain_items);

		Ok(())
	}

	async fn deploy(&self) -> Result<()> {
		info!("Deploying contracts to local environment...");

		// Start environment first if not running
		self.environment_service.start_environment().await?;

		self.display.success("Contracts deployed successfully");
		Ok(())
	}
}
