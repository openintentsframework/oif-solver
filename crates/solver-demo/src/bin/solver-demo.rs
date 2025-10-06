//! Main binary entry point for the OIF Solver Demo CLI
//!
//! This executable provides a command-line interface for testing and
//! demonstrating cross-chain intent execution using the Open Intent
//! Framework (OIF) Solver. It handles argument parsing, logging setup,
//! and dispatches commands to their respective operation handlers.

use anyhow::Result;
use clap::Parser;
use solver_demo::{
	cli::{Cli, Commands},
	core::logging,
	Context, GetQuoteRequest, PostOrderRequest,
};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
	// Load environment variables from .env file if it exists
	let _ = dotenvy::dotenv();

	// Parse CLI arguments
	let cli = Cli::parse();

	// Set verbose logging if --verbose flag is used
	if cli.verbose {
		std::env::set_var("RUST_LOG", "debug");
	}

	// Initialize logging
	init_logging();

	// Handle commands
	match cli.command {
		Commands::Init(init_cmd) => handle_init(init_cmd).await,
		Commands::Config => handle_config().await,
		Commands::Env(env_cmd) => handle_env(env_cmd).await,
		Commands::Token(token_cmd) => handle_token(token_cmd).await,
		Commands::Account(account_cmd) => handle_account(account_cmd).await,
		Commands::Intent(intent_cmd) => handle_intent(intent_cmd).await,
		Commands::Quote(quote_cmd) => handle_quote(quote_cmd).await,
	}
}

/// Initialize structured logging optimized for CLI usage
///
/// Sets up tracing subscriber with clean formatting for user-facing output.
/// Logs are controlled via RUST_LOG environment variable with sensible defaults.
/// Uses a cleaner format without timestamps and targets for better CLI experience.
fn init_logging() {
	use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};

	// Default to info level for solver-demo, warn for other crates
	let env_filter = EnvFilter::try_from_default_env()
		.unwrap_or_else(|_| EnvFilter::new("solver_demo=info,warn"));

	tracing_subscriber::registry()
		.with(
			fmt::layer()
				.with_target(false)
				.with_thread_ids(false)
				.with_file(false)
				.with_line_number(false)
				.with_level(false)
				.without_time()
				.with_span_events(fmt::format::FmtSpan::NONE)
				.compact()  // Use compact format for minimal output
				.with_ansi(true), // Keep colors for better readability
		)
		.with(env_filter)
		.init();
}

/// Handle init command
async fn handle_init(cmd: solver_demo::cli::commands::InitCommand) -> Result<()> {
	use solver_demo::cli::commands::InitSubcommand;
	use solver_demo::core::logging;
	use solver_demo::operations::init::InitOps;

	match cmd.command {
		InitSubcommand::New {
			path,
			chains,
			force,
		} => {
			logging::operation_start("Creating configuration...");

			// Log verbose details
			logging::verbose_operation("Configuration path", &path.display().to_string());
			logging::verbose_operation("Chain count", &chains.len().to_string());
			logging::verbose_operation("Force mode", &force.to_string());

			// Generate new configuration (no context needed)
			let init_ops = InitOps::without_context();
			init_ops.create(path.clone(), chains.clone(), force).await?;

			logging::success(&format!("Configuration created at {}", path.display()));
			logging::success(&format!(
				"Network templates generated ({} chains)",
				chains.len()
			));
			logging::next_step(&format!(
				"Load configuration with 'oif-demo init load {} --local'",
				path.display()
			));
		},
		InitSubcommand::Load { path, local } => {
			logging::operation_start(&format!("Loading configuration from {}...", path.display()));

			// Log verbose details
			logging::verbose_operation("Local mode", &local.to_string());

			if !path.exists() {
				logging::file_error(
					"Configuration",
					&path.display().to_string(),
					&format!("Create one with: 'oif-demo init new {}'", path.display()),
				);
				return Ok(());
			}

			// Use operations layer for loading
			let init_ops = InitOps::without_context();
			init_ops.load(path.clone(), local).await?;

			let env_type = if local {
				"local mode"
			} else {
				"production mode"
			};
			logging::success(&format!("Configuration loaded ({})", env_type));
			logging::success("Session initialized");

			if local {
				logging::next_step("Start environment with 'oif-demo env start'");
			}
		},
	}

	Ok(())
}

/// Handle config command
async fn handle_config() -> Result<()> {
	use solver_demo::core::logging;

	logging::section_header("Current Configuration");

	// Load config if available
	match Context::load_existing().await {
		Ok(ctx) => {
			logging::success("Configuration loaded successfully");
			logging::info_kv("Config path", &ctx.config.path.display().to_string());
			logging::info_kv("Environment", &format!("{:?}", ctx.session.environment()));
			logging::info_kv("Chains", &ctx.config.chains().len().to_string());

			// Verbose details
			logging::verbose_operation("RPC endpoints", &ctx.config.chains().len().to_string());
		},
		Err(_) => {
			logging::warning("No configuration loaded");
			logging::next_step(
				"Create with 'oif-demo init new <path>' or load with 'oif-demo init load <path>'",
			);
		},
	}

	Ok(())
}

/// Handle environment command
async fn handle_env(cmd: solver_demo::cli::commands::EnvCommand) -> Result<()> {
	use solver_demo::cli::commands::EnvSubcommand;
	use solver_demo::operations::env::EnvOps;

	// Load context
	let ctx = std::sync::Arc::new(Context::load_existing().await?);
	let mut env_ops = match cmd.command {
		EnvSubcommand::Deploy { ref path, .. } => {
			// Use custom contracts path if provided
			EnvOps::with_contracts_path(ctx.clone(), std::path::PathBuf::from(path))
		},
		_ => EnvOps::new(ctx.clone()),
	};

	match cmd.command {
		EnvSubcommand::Start => {
			use solver_demo::core::logging;

			logging::operation_start("Starting local environment...");

			// Start environment (Anvil chains only)
			env_ops.start().await?;

			logging::success("Anvil chains started");
			logging::success("Environment ready");
			logging::next_step("Deploy contracts with 'oif-demo env deploy --all'");
		},
		EnvSubcommand::Stop => {
			use solver_demo::core::logging;

			logging::operation_start("Stopping local environment...");

			env_ops.stop()?;

			logging::success("Environment stopped");
		},
		EnvSubcommand::Status => {
			let status = env_ops.status()?;
			use solver_demo::core::logging;
			logging::info_kv("Environment", &format!("{:?}", status.environment));
			logging::info_kv("Chains running", &status.chains.len().to_string());
			for chain_status in status.chains {
				logging::info_kv(
					&format!("Chain {}", chain_status.chain),
					if chain_status.running {
						"✓ Running"
					} else {
						"✗ Stopped"
					},
				);
			}
		},
		EnvSubcommand::Deploy {
			contract,
			all,
			chain,
			force,
			list,
			path,
		} => {
			use solver_demo::core::logging;

			// Default to listing if no deployment action is specified
			let should_list = list || (contract.is_none() && !all);

			if should_list {
				logging::section_header("Available contracts");
				logging::verbose_tech("Contracts path", &path);

				// Use EnvOps to list available contracts
				match env_ops.list_available_contracts() {
					Ok(contracts) => {
						if contracts.is_empty() {
							logging::warning("No compiled contracts found");
						} else {
							for contract in contracts {
								logging::info_bullet(&contract);
							}
						}
					},
					Err(e) => {
						logging::error_with_guidance(
							"Failed to list contracts",
							"Check that contracts are compiled in the specified path",
						);
						return Err(e.into());
					},
				}
				return Ok(());
			}

			// Verbose deployment details
			logging::verbose_tech("Contracts path", &path);
			logging::verbose_tech("Force mode", &force.to_string());

			if force {
				logging::warning("Force deployment requested");
			}

			if let Some(contract_name) = contract {
				logging::operation_start(&format!("Deploying contract {}...", contract_name));

				// Convert chain option to Vec<u64> if provided
				let chain_ids = chain.map(|c| vec![c]);

				if let Some(chain_id) = chain {
					logging::verbose_operation("Target chain", &chain_id.to_string());
				} else {
					logging::verbose_operation("Target", "all configured chains");
				}

				// Deploy single contract
				match env_ops
					.deploy_single_contract(&contract_name, chain_ids)
					.await
				{
					Ok(()) => {
						logging::success(&format!(
							"Contract {} deployed successfully",
							contract_name
						));
					},
					Err(e) => {
						logging::error_with_guidance(
							&format!("Contract {} deployment failed", contract_name),
							"Check network connectivity and contract compilation",
						);
						return Err(e.into());
					},
				}
			} else if all {
				let chain_count = ctx.config.chains().len();
				logging::operation_start(&format!(
					"Deploying contracts to {} chains...",
					chain_count
				));

				// Filter to specific chain if provided
				if let Some(_chain_id) = chain {
					logging::verbose_operation(
						"Note",
						"single chain deployment not yet implemented, deploying to all chains",
					);
				} else {
					logging::verbose_operation("Target", "all configured chains");
				}

				// Use EnvOps to deploy contracts
				match env_ops.deploy(force).await {
					Ok(()) => {
						logging::success(&format!(
							"All contracts deployed to {} chains",
							chain_count
						));
						logging::next_step("Setup environment with 'oif-demo env setup'");
					},
					Err(e) => {
						logging::error_with_guidance(
							"Deployment failed",
							"Check network connectivity and ensure chains are running",
						);
						return Err(e.into());
					},
				}
			} else {
				logging::error_with_guidance(
					"Please specify deployment action",
					"Use --all to deploy all contracts or --list to see available contracts",
				);
			}
		},
		EnvSubcommand::Setup { chain, amount } => {
			use solver_demo::core::logging;

			logging::operation_start("Setting up test environment...");

			// Verbose details
			if let Some(chain_id) = chain {
				logging::verbose_operation("Target chain", &chain_id.to_string());
			} else {
				logging::verbose_operation("Target", "all configured chains");
			}
			logging::verbose_tech("Token amount", &amount.to_string());

			// Use EnvOps to setup the environment
			match env_ops.setup(chain, amount).await {
				Ok(()) => {
					logging::success("Tokens minted to all accounts");
					logging::success("Permit2 allowances approved");
					logging::success("Allocator registered with TheCompact");
					logging::success("Environment ready for testing");
					logging::next_step("Check balances with 'oif-demo token balance'");
				},
				Err(e) => {
					logging::error_with_guidance(
						"Setup failed",
						"Check that contracts are deployed and chains are running",
					);
					return Err(e.into());
				},
			}
		},
	}

	Ok(())
}

/// Handle token command
async fn handle_token(cmd: solver_demo::cli::commands::TokenCommand) -> Result<()> {
	use solver_demo::cli::commands::TokenSubcommand;
	use solver_demo::operations::token::TokenOps;
	use solver_demo::types::chain::ChainId;

	// Load context
	let ctx = std::sync::Arc::new(Context::load_existing().await?);
	let token_ops = TokenOps::new(ctx.clone());

	match cmd.command {
		TokenSubcommand::List { chains } => {
			use solver_demo::core::logging;

			logging::section_header("Available tokens");

			let chain_ids: Vec<ChainId> = chains
				.map(|c| c.into_iter().map(ChainId::from_u64).collect())
				.unwrap_or_else(|| ctx.config.chains());

			let tokens = token_ops.list(Some(chain_ids)).await?;

			for (chain, token_list) in tokens.tokens_by_chain {
				logging::subsection(&format!("Chain {}", chain));
				for token in token_list {
					logging::item(&format!("{}: {}", token.symbol, token.address));
				}
			}
		},
		TokenSubcommand::Mint {
			chain,
			token,
			amount,
			to,
		} => {
			use solver_demo::core::logging;

			logging::operation_start("Minting tokens...");

			// Verbose details
			logging::verbose_tech("Chain", &chain.to_string());
			logging::verbose_tech("Token", &token);
			logging::verbose_tech("Amount", &amount);
			if let Some(recipient) = &to {
				logging::verbose_tech("Recipient", recipient);
			}

			let chain_id = ChainId::from_u64(chain);

			// Get token info and convert amount to wei
			let token_info = ctx.tokens.get_or_error(chain_id, &token)?;
			let amount_parsed = amount.parse::<f64>()?;
			let amount_u256 = token_info.to_wei(amount_parsed);

			let result = token_ops
				.mint(chain_id, &token, to.as_deref(), amount_u256)
				.await?;

			logging::success(&format!("Minted {} {}", result.amount, result.token));

			if let Some(tx_hash) = result.tx_hash {
				logging::verbose_tech("Transaction", &format!("{:?}", tx_hash));
			}
		},
		TokenSubcommand::Balance {
			account,
			follow,
			chains,
		} => {
			use solver_demo::core::logging;

			logging::section_header("Token Balances");

			// Handle "all" account or specific accounts
			let account_display = format!("{} Account", account);
			let accounts_to_check = if account == "all" {
				vec![
					("user", "User Account"),
					("solver", "Solver Account"),
					("recipient", "Recipient Account"),
				]
			} else {
				vec![(account.as_str(), account_display.as_str())]
			};

			loop {
				let chain_ids: Vec<ChainId> = if let Some(chain_list) = chains.clone() {
					chain_list.into_iter().map(ChainId::from_u64).collect()
				} else {
					ctx.config.chains()
				};

				for (account_name, display_name) in &accounts_to_check {
					logging::subsection(display_name);

					for chain_id in &chain_ids {
						// Get all tokens for this chain
						let tokens = ctx.tokens.tokens_for_chain(*chain_id);

						logging::subsection(&format!("Chain {}", chain_id));

						for token in tokens {
							let result = token_ops
								.balance(*chain_id, &token.symbol, Some(account_name))
								.await?;
							logging::item(&format!("{}: {}", result.token, result.balance));
						}
					}
				}

				if let Some(interval) = follow {
					tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
					logging::info_bullet("---");
				} else {
					break;
				}
			}
		},
		TokenSubcommand::Approve {
			chain,
			token,
			spender,
			amount,
		} => {
			use solver_demo::core::logging;

			logging::operation_start("Approving token...");

			// Verbose details
			logging::verbose_tech("Chain", &chain.to_string());
			logging::verbose_tech("Token", &token);
			logging::verbose_tech("Spender", &spender);
			logging::verbose_tech("Amount", &amount);

			let chain_id = ChainId::from_u64(chain);

			// Get token info and convert amount to wei
			let token_info = ctx.tokens.get_or_error(chain_id, &token)?;
			let amount_parsed = amount.parse::<f64>()?;
			let amount_u256 = token_info.to_wei(amount_parsed);

			let result = token_ops
				.approve(chain_id, &token, &spender, Some(amount_u256))
				.await?;

			logging::success(&format!(
				"Approved {} {} for {}",
				result.amount, result.token, result.spender
			));

			if let Some(tx_hash) = result.tx_hash {
				logging::verbose_tech("Transaction", &format!("{:?}", tx_hash));
			}
		},
	}

	Ok(())
}

/// Handle account command
async fn handle_account(cmd: solver_demo::cli::commands::AccountCommand) -> Result<()> {
	use solver_demo::cli::commands::AccountSubcommand;

	// Load context
	let ctx = Context::load_existing().await?;

	match cmd.command {
		AccountSubcommand::List => {
			use solver_demo::core::logging;

			logging::section_header("Configured Accounts");

			let accounts = ctx.config.accounts();

			logging::info_kv("User", &accounts.user.address);
			logging::info_kv("Solver", &accounts.solver.address);
			logging::info_kv("Recipient", &accounts.recipient.address);
		},
		AccountSubcommand::Info { account } => {
			use solver_demo::core::logging;

			logging::section_header(&format!("Account Info: {}", account));

			let accounts = ctx.config.accounts();

			let account_info = match account.as_str() {
				"user" => &accounts.user,
				"solver" => &accounts.solver,
				"recipient" => &accounts.recipient,
				_ => {
					logging::error_with_guidance(
						&format!("Unknown account: {}", account),
						"Use 'user', 'solver', or 'recipient'",
					);
					return Ok(());
				},
			};

			logging::info_kv("Address", &account_info.address);
			logging::info_kv(
				"Has Private Key",
				if account_info.private_key.is_some() {
					"Yes"
				} else {
					"No"
				},
			);
		},
	}

	Ok(())
}

/// Handle intent command
async fn handle_intent(cmd: solver_demo::cli::commands::IntentCommand) -> Result<()> {
	use solver_demo::cli::commands::IntentSubcommand;
	use solver_demo::operations::intent::IntentOps;
	use solver_demo::types::chain::ChainId;

	// Load context
	let ctx = std::sync::Arc::new(Context::load_existing().await?);
	let intent_ops = IntentOps::new(ctx.clone());

	match cmd.command {
		IntentSubcommand::Build {
			from_chain,
			to_chain,
			from_token,
			to_token,
			amount,
			swap_type,
			settlement,
			auth,
			output,
		} => {
			// Parse swap type first
			let exact_output = match swap_type.as_str() {
				"exact-input" => false,
				"exact-output" => true,
				_ => {
					return Err(anyhow::anyhow!(
						"Invalid swap type: {}. Use 'exact-input' or 'exact-output'",
						swap_type
					))
				},
			};

			// Parse amount according to token decimals
			let from_chain_id = ChainId::from_u64(from_chain);
			let to_chain_id = ChainId::from_u64(to_chain);

			// Get token info to determine decimals for amount formatting
			let (from_token_info, _amount_u256) = if exact_output {
				// For exact output, amount is for the destination token
				let to_token_info = ctx.tokens.get_or_error(to_chain_id, &to_token)?;
				let parsed_amount = to_token_info.to_wei(amount.parse::<f64>()?);
				(
					ctx.tokens.get_or_error(from_chain_id, &from_token)?,
					parsed_amount,
				)
			} else {
				// For exact input, amount is for the source token
				let from_token_info = ctx.tokens.get_or_error(from_chain_id, &from_token)?;
				let parsed_amount = from_token_info.to_wei(amount.parse::<f64>()?);
				(from_token_info, parsed_amount)
			};

			use solver_demo::core::logging;

			logging::operation_start("Building intent...");

			// Verbose parameter details
			logging::verbose_tech("From Chain", &from_chain.to_string());
			logging::verbose_tech("To Chain", &to_chain.to_string());
			logging::verbose_tech("From Token", &from_token);
			logging::verbose_tech("To Token", &to_token);

			// Display formatted amount with token info
			let amount_display = if exact_output {
				let to_token_info = ctx.tokens.get_or_error(to_chain_id, &to_token)?;
				format!("{} {} (output)", amount, to_token_info.symbol)
			} else {
				format!("{} {} (input)", amount, from_token_info.symbol)
			};
			// Create user-friendly intent description
			let intent_desc = format!("{} {} → {}", amount_display, from_token, to_token);
			logging::success(&format!("Intent created: {}", intent_desc));

			// Verbose technical details
			logging::verbose_tech("Swap Type", &swap_type);
			logging::verbose_tech("Settlement", &settlement);
			logging::verbose_tech("Auth", auth.as_deref().unwrap_or("N/A"));

			// Build intent parameters
			use solver_demo::operations::intent::{AuthType, IntentParams, SettlementType};

			let settlement_type = settlement.parse::<SettlementType>()?;
			let auth_type = auth.map(|a| a.parse::<AuthType>()).transpose()?;

			let intent_params = IntentParams {
				from_chain: from_chain_id,
				to_chain: to_chain_id,
				from_token,
				to_token,
				amount: _amount_u256,
				min_amount: None,
				sender: None,
				recipient: None,
				exact_output,
				settlement: settlement_type,
				auth: auth_type,
			};

			// Actually build the intent
			let _quote_request = intent_ops.build(intent_params, output.clone()).await?;

			// Display save location and next steps
			if let Some(output_path) = &output {
				logging::success(&format!("Request saved to {}", output_path.display()));
				logging::next_step(&format!(
					"Get quote with 'oif-demo quote get {}'",
					output_path.display()
				));
			} else {
				logging::success("Request saved to .oif-demo/requests/get_quote.req.json");
				logging::next_step(
					"Get quote with 'oif-demo quote get .oif-demo/requests/get_quote.req.json'",
				);
			}
		},
		IntentSubcommand::BuildBatch { input, output } => {
			logging::operation_start("Building batch intents...");

			logging::verbose_tech("Input file", &input.display().to_string());

			let intents = intent_ops.build_batch(&input).await?;

			let output_path = if let Some(custom_output) = output {
				custom_output
			} else {
				std::path::Path::new(".oif-demo/requests/get_quotes.req.json").to_path_buf()
			};

			// Ensure directory exists
			if let Some(parent) = output_path.parent() {
				std::fs::create_dir_all(parent)?;
			}

			// Save the batch quote requests
			let json = serde_json::to_string_pretty(&intents)?;
			std::fs::write(&output_path, json)?;

			logging::success(&format!("Built {} intents", intents.len()));
			logging::success(&format!("Batch saved to {}", output_path.display()));

			logging::next_step(&format!(
				"Test quotes with 'oif-demo quote test {}'",
				output_path.display()
			));
		},
		IntentSubcommand::Submit {
			input,
			onchain,
			chain: _,
		} => {
			logging::operation_start("Submitting intent...");

			logging::verbose_tech("Input file", &input.display().to_string());

			let order_json = std::fs::read_to_string(&input)?;
			let mut order: PostOrderRequest = serde_json::from_str(&order_json)?;

			if onchain {
				// Inject user address for on-chain submission
				// since we are doing StandardOrder::try_from which is an internal Solver function that requires it
				inject_user_address_for_onchain(&mut order, &ctx)?;
				logging::operation_start("Submitting intent on-chain...");

				let result = intent_ops.submit_onchain(order).await?;

				logging::success(&format!("Order submitted on-chain: {}", result.tx_hash));
				logging::info_kv("Transaction Hash", &result.tx_hash);
				if let Some(order_id) = result.order_id {
					logging::info_kv("Order ID", &order_id);
				}
			} else {
				let order_id = intent_ops.submit(order).await?;

				use solver_demo::core::logging;
				logging::success(&format!("Order submitted: {}", order_id));
				logging::info_kv("Order ID", &order_id);
			}
		},
		IntentSubcommand::Status { order_id } => {
			use solver_demo::core::logging;
			logging::operation_start("Order Status");
			logging::info_kv("Order ID", &order_id);

			let status = intent_ops.status(&order_id).await?;

			logging::info_kv("Status", &status.status);
			logging::info_kv("Timestamp", &status.timestamp);

			if let Some(tx_hash) = &status.fill_tx_hash {
				logging::info_kv("Fill Transaction", tx_hash);
			}
		},
		IntentSubcommand::Test {
			input,
			onchain,
			output: _,
		} => {
			use solver_demo::core::logging;
			logging::operation_start("Testing Intents");
			logging::info_kv("Input file", &input.display().to_string());

			if onchain {
				logging::warning("On-chain testing not yet implemented");
				return Ok(());
			}

			// Check if input file exists
			if !input.exists() {
				logging::error_message(&format!("Input file not found: {}", input.display()));
				logging::next_step("Run 'cargo run -p solver-demo -- quote test' first to create post_orders.req.json");
				return Ok(());
			}

			// Load array of PostOrderRequest
			let content = std::fs::read_to_string(&input)?;
			let post_order_requests: Vec<PostOrderRequest> = serde_json::from_str(&content)?;

			if post_order_requests.is_empty() {
				logging::error_message("No order requests found in input file");
				return Ok(());
			}

			let total_requests = post_order_requests.len();
			logging::operation_start(&format!("Submitting {} order requests...", total_requests));

			let mut successful_count = 0;
			let mut failed_count = 0;
			let start_time = std::time::Instant::now();

			// Process each order request
			for (index, post_order_request) in post_order_requests.into_iter().enumerate() {
				logging::verbose_operation(
					&format!(
						"Submitting order request {} of {}",
						index + 1,
						total_requests
					),
					"",
				);

				match intent_ops.submit(post_order_request).await {
					Ok(order_id) => {
						successful_count += 1;
						logging::verbose_success(
							&format!("Order {} submitted", index + 1),
							&order_id,
						);
					},
					Err(e) => {
						failed_count += 1;
						logging::error_message(&format!("Order {} failed: {}", index + 1, e));
					},
				}
			}

			let total_duration = start_time.elapsed();

			// Display results
			logging::success(&format!(
				"Results: {} successful, {} failed, took {:.2}s",
				successful_count,
				failed_count,
				total_duration.as_secs_f64()
			));

			if successful_count > 0 {
				logging::next_step(
					"Check order status: cargo run -p solver-demo -- intent status <order_id>",
				);
			}
		},
	}

	Ok(())
}

/// Handle quote command
async fn handle_quote(cmd: solver_demo::cli::commands::QuoteCommand) -> Result<()> {
	use solver_demo::cli::commands::QuoteSubcommand;
	use solver_demo::operations::quote::QuoteOps;

	// Load context
	let ctx = std::sync::Arc::new(Context::load_existing().await?);
	let quote_ops = QuoteOps::new(ctx.clone());

	match cmd.command {
		QuoteSubcommand::Get { input, output } => {
			use solver_demo::core::logging;

			logging::operation_start("Getting quote...");

			// Use QuoteOps to get the quote
			let response = quote_ops.get(&input).await?;

			let quote_count = response.quotes.len();
			if quote_count > 0 {
				let first_quote = &response.quotes[0];
				let validity_duration = first_quote
					.valid_until
					.saturating_sub(chrono::Utc::now().timestamp() as u64);
				logging::success(&format!(
					"Received {} quote(s) (valid for {}s)",
					quote_count, validity_duration
				));
			} else {
				logging::warning("No quotes received from solver");
			}

			if let Some(output_path) = output {
				std::fs::write(&output_path, serde_json::to_string_pretty(&response)?)?;
				logging::success(&format!("Quote saved to {}", output_path.display()));
				logging::next_step(&format!(
					"Sign quote with 'oif-demo quote sign {}'",
					output_path.display()
				));
			} else {
				// Display quote summary instead of full JSON
				if !response.quotes.is_empty() {
					logging::section_header("Quote Summary");
					for (i, quote) in response.quotes.iter().enumerate() {
						logging::info_bullet(&format!(
							"Quote {}: ID={}, Valid Until={}, ETA={}s",
							i + 1,
							quote.quote_id,
							quote.valid_until,
							quote.eta.unwrap_or(0)
						));
						if let Some(provider) = &quote.provider {
							logging::verbose_tech("Provider", provider);
						}
					}
				}

				// Default file save location
				let default_path = std::path::Path::new(".oif-demo/requests/get_quote.res.json");
				logging::success(&format!("Quote saved to {}", default_path.display()));
				logging::next_step(&format!(
					"Sign quote with 'oif-demo quote sign {}'",
					default_path.display()
				));
			}
		},
		QuoteSubcommand::Sign {
			input,
			quote_index,
			signature,
			output,
		} => {
			use solver_demo::core::logging;

			logging::operation_start("Signing quote...");

			// Verbose details
			logging::verbose_tech("Quote file", &input.display().to_string());
			logging::verbose_tech("Quote index", &quote_index.to_string());

			let quote_json = std::fs::read_to_string(&input)?;
			let quote_response: solver_demo::GetQuoteResponse = serde_json::from_str(&quote_json)?;

			// Get the specified quote
			let quote = quote_response
				.quotes
				.get(quote_index)
				.ok_or_else(|| anyhow::anyhow!("Quote index {} not found", quote_index))?;

			// Create the order request
			let order_request = if let Some(sig_str) = signature {
				// Use provided signature
				logging::verbose_operation("Using provided signature", &sig_str[..8]);
				PostOrderRequest {
					order: quote.order.clone(),
					signature: alloy_primitives::Bytes::from(hex::decode(&sig_str)?),
					quote_id: Some(quote.quote_id.clone()),
					origin_submission: None,
				}
			} else {
				// Sign the quote
				let order_request = quote_ops.sign(quote_response).await?;
				logging::success("Quote signed successfully");

				// Save the PostOrderRequest to file
				let output_path = if let Some(path) = output {
					path
				} else {
					// Save to default location
					let default_path =
						std::path::Path::new(".oif-demo/requests/post_order.req.json");
					if let Some(parent) = default_path.parent() {
						std::fs::create_dir_all(parent)?;
					}
					default_path.to_path_buf()
				};

				let content = serde_json::to_string_pretty(&order_request)?;
				std::fs::write(&output_path, content)?;
				logging::success(&format!("Order request saved to {}", output_path.display()));
				logging::next_step(&format!(
					"Submit order with 'oif-demo intent submit {}'",
					output_path.display()
				));
				return Ok(());
			};

			if let Some(output_path) = output {
				std::fs::write(&output_path, serde_json::to_string_pretty(&order_request)?)?;
				logging::success(&format!("Order request saved to {}", output_path.display()));
			}
		},
		QuoteSubcommand::Test { input, output: _ } => {
			use solver_demo::core::logging;
			logging::operation_start("Testing Quotes");
			logging::info_kv("Input file", &input.display().to_string());

			// Check if input file exists
			if !input.exists() {
				logging::error_message(&format!("Input file not found: {}", input.display()));
				logging::next_step("Run 'cargo run -p solver-demo -- intent build-batch' first");
				return Ok(());
			}

			// Load array of GetQuoteRequest
			let content = std::fs::read_to_string(&input)?;
			let quote_requests: Vec<GetQuoteRequest> = serde_json::from_str(&content)?;

			if quote_requests.is_empty() {
				logging::error_message("No quote requests found in input file");
				return Ok(());
			}

			let total_requests = quote_requests.len();
			logging::operation_start(&format!("Processing {} quote requests...", total_requests));

			let mut successful_orders = Vec::new();
			let mut failed_count = 0;
			let start_time = std::time::Instant::now();

			// Process each quote request
			for (index, quote_request) in quote_requests.into_iter().enumerate() {
				logging::verbose_operation(
					&format!(
						"Processing quote request {} of {}",
						index + 1,
						total_requests
					),
					"",
				);

				match quote_ops.get_and_sign_quote(quote_request).await {
					Ok(post_order_request) => {
						successful_orders.push(post_order_request);
						logging::verbose_success(
							&format!("Quote request {} succeeded", index + 1),
							"",
						);
					},
					Err(e) => {
						failed_count += 1;
						logging::error_message(&format!(
							"Quote request {} failed: {}",
							index + 1,
							e
						));
						logging::verbose_tech(
							&format!("Quote request {} failed", index + 1),
							&format!("{}", e),
						);
					},
				}
			}

			let total_duration = start_time.elapsed();

			// Save successful signed orders to post_orders.req.json
			let output_file = std::path::Path::new(".oif-demo/requests/post_orders.req.json");
			if !successful_orders.is_empty() {
				if let Some(parent) = output_file.parent() {
					std::fs::create_dir_all(parent)?;
				}
				let orders_json = serde_json::to_string_pretty(&successful_orders)?;
				std::fs::write(output_file, orders_json)?;

				logging::success(&format!(
					"Saved {} signed orders to {}",
					successful_orders.len(),
					output_file.display()
				));
			}

			// Display results
			logging::success(&format!(
				"Results: {} successful, {} failed, took {:.2}s",
				successful_orders.len(),
				failed_count,
				total_duration.as_secs_f64()
			));

			if !successful_orders.is_empty() {
				logging::next_step(&format!(
					"Submit orders: cargo run -p solver-demo -- intent test {}",
					output_file.display()
				));
			}
		},
	}

	Ok(())
}

/// Inject user address into the order payload for on-chain submission
fn inject_user_address_for_onchain(
	order: &mut PostOrderRequest,
	ctx: &Context,
) -> anyhow::Result<()> {
	use solver_types::api::OifOrder;

	// Get user address from config
	let user_address = {
		use solver_demo::types::hex::Hex;
		let address_str = &ctx.config.accounts().user.address;
		Hex::to_address(address_str)?
	};
	let user_address_hex = format!("0x{}", hex::encode(user_address.0));

	// Inject user address based on order type
	match &mut order.order {
		OifOrder::OifEscrowV0 { payload } => {
			// For Permit2 orders, inject user into the message.user field
			if let Some(message_obj) = payload.message.as_object_mut() {
				message_obj.insert(
					"user".to_string(),
					serde_json::Value::String(user_address_hex),
				);
			}
		},
		OifOrder::Oif3009V0 { .. } => {
			// EIP-3009 orders don't need user injection in the message
			// The user is handled through metadata
		},
		OifOrder::OifResourceLockV0 { .. } => {
			// Compact orders already have the sponsor field
		},
		_ => {
			// Other order types don't need user injection
		},
	}

	Ok(())
}
