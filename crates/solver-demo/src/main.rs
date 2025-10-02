use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use tracing::debug;

use solver_demo::{
	commands::{
		accounts::AccountHandler, config_generator, environment::EnvironmentHandler,
		intent::IntentHandler, quote::QuoteHandler, token::TokenHandler, Commands, InitCommand,
	},
	core::{
		init_logging, AbiManager, ContractManager, DeployerManager, DisplayUtils, SessionManager,
	},
	services::{
		ApiClient, IntentService, JwtService, LocalEnvironmentService, QuoteService,
		SigningService, TokenService,
	},
};

#[derive(Parser)]
#[command(name = "oif-demo")]
#[command(about = "OIF Demo Tool - Comprehensive solver testing and management")]
#[command(version)]
pub struct Cli {
	#[command(subcommand)]
	pub command: Commands,

	/// Enable debug logging
	#[arg(global = true, long, env = "OIF_DEBUG")]
	pub debug: bool,

	/// Config file path (can be set via OIF_CONFIG env var)
	#[arg(global = true, long, env = "OIF_CONFIG")]
	pub config: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
	let cli = Cli::parse();

	// Initialize logging
	let _ = init_logging(cli.debug);

	// Create display utilities
	let display = Arc::new(DisplayUtils::new());

	// Handle commands
	match cli.command {
		Commands::Init(init_cmd) => {
			handle_init_command(init_cmd, display).await?;
		},

		Commands::Config => {
			handle_config(display).await?;
		},

		_ => {
			// For all other commands, we need an initialized session
			let session_manager = initialize_session(cli.config, display.clone()).await?;

			// Create core managers
			let contracts_dir = session_manager.contracts_dir().to_path_buf();
			let abi_manager = Arc::new(AbiManager::new(contracts_dir)?);
			// Load all contract artifacts
			abi_manager.load_all().await?;
			let deployer_manager = Arc::new(DeployerManager::new(session_manager.clone()).await?);
			let contract_manager = Arc::new(ContractManager::new(
				abi_manager.clone(),
				deployer_manager.clone(),
			));

			// Create services
			let token_service = Arc::new(TokenService::new(
				session_manager.clone(),
				contract_manager.clone(),
			));

			let environment_service = Arc::new(LocalEnvironmentService::new(
				session_manager.clone(),
				contract_manager.clone(),
			));

			let api_client = Arc::new({
				let base_url = session_manager.get_api_base_url().await;
				let jwt_service =
					Arc::new(JwtService::new(base_url.clone(), session_manager.clone()));
				ApiClient::new(base_url).with_jwt_service(jwt_service)
			});

			let intent_service = Arc::new(IntentService::new(
				session_manager.clone(),
				contract_manager.clone(),
				token_service.clone(),
				api_client.clone(),
			));

			let signing_service = Arc::new(SigningService::new(contract_manager.clone()));

			let quote_service = Arc::new(
				QuoteService::new(
					session_manager.clone(),
					api_client.clone(),
					signing_service.clone(),
				)
				.await?,
			);

			// Route to appropriate handler
			match cli.command {
				Commands::Env(cmd) => {
					let handler =
						EnvironmentHandler::new(environment_service, session_manager.clone());
					handler.handle(cmd).await?;
				},

				Commands::Token(cmd) => {
					let handler = TokenHandler::new(token_service, session_manager.clone());
					handler.handle(cmd).await?;
				},

				Commands::Accounts(cmd) => {
					let handler = AccountHandler::new(session_manager.clone());
					handler.handle(cmd).await?;
				},

				Commands::Intent(cmd) => {
					let handler = IntentHandler::new(intent_service.clone()).await?;
					handler.handle(cmd).await?;
				},

				Commands::Quote(cmd) => {
					let handler = QuoteHandler::new(quote_service);
					handler.handle(cmd).await?;
				},

				_ => unreachable!(),
			}
		},
	}

	Ok(())
}

async fn handle_init_command(init_cmd: InitCommand, display: Arc<DisplayUtils>) -> Result<()> {
	match init_cmd {
		InitCommand::New { path, chains } => handle_init_new(path, chains, display).await,
		InitCommand::Load { path, local } => handle_init_load(path, local, display).await,
	}
}

async fn handle_init_new(
	path: std::path::PathBuf,
	chains: Vec<u64>,
	display: Arc<DisplayUtils>,
) -> Result<()> {
	debug!("Generating new configuration at {:?}", path);

	// Get the config name from the file stem
	let config_name = path.file_stem().and_then(|s| s.to_str()).unwrap_or("demo");

	// Create the config directory if it doesn't exist
	if let Some(parent) = path.parent() {
		std::fs::create_dir_all(parent)?;
	}

	// Generate the main config
	let main_config = config_generator::generate_demo_config(&chains, config_name)?;
	std::fs::write(&path, main_config)?;

	// Create subdirectory for additional configs
	let sub_dir = path
		.parent()
		.map(|p| p.join(config_name))
		.unwrap_or_else(|| std::path::PathBuf::from(format!("config/{}", config_name)));

	std::fs::create_dir_all(&sub_dir)?;

	// Generate networks.toml
	let networks_path = sub_dir.join("networks.toml");
	let networks_config = config_generator::generate_networks_config(&chains)?;
	std::fs::write(&networks_path, networks_config)?;

	// Generate gas.toml
	let gas_path = sub_dir.join("gas.toml");
	let gas_config = config_generator::generate_gas_config()?;
	std::fs::write(&gas_path, gas_config)?;

	// Generate api.toml
	let api_path = sub_dir.join("api.toml");
	let api_config = config_generator::generate_api_config()?;
	std::fs::write(&api_path, api_config)?;

	// Display results
	display.results(vec![
		("Main config", path.display().to_string()),
		("Networks config", networks_path.display().to_string()),
		("Gas config", gas_path.display().to_string()),
		("API config", api_path.display().to_string()),
	]);

	// Display notes
	display.notes(vec![
		"The generated files contain placeholder addresses that will be replaced during deployment",
		"Placeholder addresses start from: 0x00000000000000000000000000000000000003e8",
		"These are valid addresses that allow config validation",
		"They will be automatically replaced when you run 'solver-demo env up'",
	]);

	// Display next steps
	display.next_steps(vec![
		&format!("Run: solver-demo init load {} --local", path.display()),
		"Run: solver-demo env up",
	]);

	Ok(())
}

async fn handle_init_load(
	path: std::path::PathBuf,
	local: bool,
	display: Arc<DisplayUtils>,
) -> Result<()> {
	debug!("Loading configuration from {:?}", path);

	// Initialize session manager with config
	let session_manager = SessionManager::init(&path, local).await?;

	// Display header
	display.header("Configuration Loaded");

	display.success(&format!(
		"Mode: {}",
		if local { "local" } else { "production" }
	));

	// Show configured chains
	let chain_ids = session_manager.get_chain_ids().await;
	let chain_strings: Vec<String> = chain_ids.iter().map(|id| format!("Chain {}", id)).collect();
	display.list(
		"Configured Chains",
		chain_strings.iter().map(|s| s.as_str()).collect(),
	);

	Ok(())
}

async fn handle_config(display: Arc<DisplayUtils>) -> Result<()> {
	use solver_demo::core::TreeItem;

	// Try to load existing session to display current config
	match SessionManager::load().await {
		Ok(session) => {
			// Validate the config path exists and is readable
			if let Some(config_path) = session.get_config_path() {
				let path = std::path::Path::new(&config_path);
				if !path.exists() {
					display.header("CONFIGURATION ERROR");
					display.error(&format!("Configuration file not found: {}", config_path));
					display.notes(vec![
						"The session references a config file that no longer exists.",
						"Run 'solver-demo init load <config>' with a valid config file.",
					]);
					return Ok(());
				}

				// Try to validate the config by loading it
				match solver_config::Config::from_file(&config_path).await {
					Ok(_) => {
						// Config is valid, proceed with display
						display.header("CURRENT CONFIGURATION");

						let env = session.get_environment().await;
						let chains = session.get_chain_ids().await;
						let chain_list: Vec<String> =
							chains.iter().map(|c| c.to_string()).collect();

						display.tree(
							"Configuration Details",
							vec![
								TreeItem::KeyValue("Config path".to_string(), config_path),
								TreeItem::KeyValue("Environment".to_string(), format!("{:?}", env)),
								TreeItem::KeyValue(
									"API URL".to_string(),
									session.get_api_base_url().await,
								),
								TreeItem::KeyValue(
									"Configured chains".to_string(),
									chain_list.join(", "),
								),
							],
						);

						// Display includes information
						let includes = session.get_includes().await;

						if !includes.files.is_empty() {
							let file_items: Vec<TreeItem> = includes
								.get_all_files()
								.iter()
								.map(|(key, path)| {
									TreeItem::Text(format!("{} → {}", key, path.display()))
								})
								.collect();
							display.tree("Included Files", file_items);
						}

						if !includes.section_sources.is_empty() {
							let mut sections: Vec<_> = includes.section_sources.iter().collect();
							sections.sort_by_key(|(k, _)| k.as_str());

							let section_items: Vec<TreeItem> = sections
								.iter()
								.map(|(section, source)| {
									let source_display = source
										.file_name()
										.and_then(|n| n.to_str())
										.unwrap_or("main config");
									TreeItem::Text(format!("[{}] → {}", section, source_display))
								})
								.collect();
							display.tree("Configuration Sections", section_items);
						}
					},
					Err(e) => {
						display.header("CONFIGURATION ERROR");
						display.error(&format!("Configuration file is invalid: {}", e));
						display.notes(vec![
							"The configuration file contains errors.",
							"Please fix the errors or run 'solver-demo init new <path>' to generate a new config.",
						]);
					},
				}
			} else {
				display.header("CONFIGURATION");
				display.tree(
					"Configuration",
					vec![TreeItem::Info(
						"Session exists but no configuration path is set.".to_string(),
					)],
				);
				display.next_steps(vec![
					"Run 'solver-demo init load <config>' to load a configuration.",
				]);
			}
		},
		Err(_) => {
			display.header("CONFIGURATION");
			display.tree(
				"Configuration",
				vec![TreeItem::Info("No active configuration found.".to_string())],
			);
			display.next_steps(vec![
				"Run 'solver-demo init new <path>' to generate a new configuration, or",
				"Run 'solver-demo init load <config>' to load an existing configuration.",
			]);
		},
	}

	Ok(())
}

async fn initialize_session(
	config_path: Option<String>,
	_display: Arc<DisplayUtils>,
) -> Result<Arc<SessionManager>> {
	// If no config path provided, try to load existing session
	if config_path.is_none() {
		debug!("No config specified, loading existing session");
		let session = SessionManager::load().await?;
		// Don't display success message here - let individual commands handle their own output
		return Ok(Arc::new(session));
	}

	// Config path provided - validate it matches existing session or error
	let config = config_path.unwrap();
	debug!("Loading configuration from {}", config);

	// Load existing session - this will preserve the environment type
	// that was set during 'init load' command
	let session = SessionManager::load().await?;

	// Don't display success message here - let individual commands handle their own output

	Ok(Arc::new(session))
}
