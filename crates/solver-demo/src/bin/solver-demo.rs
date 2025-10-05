//! Main binary entry point for the OIF Solver Demo CLI
//!
//! This executable provides a command-line interface for testing and
//! demonstrating cross-chain intent execution using the Open Intent
//! Framework (OIF) Solver. It handles argument parsing, logging setup,
//! and dispatches commands to their respective operation handlers.

use anyhow::Result;
use clap::Parser;
use solver_demo::{
	cli::{output::Display, Cli, Commands},
	Context, GetQuoteRequest, PostOrderRequest,
};
use tracing::{info, instrument};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
	// Load environment variables from .env file if it exists
	let _ = dotenvy::dotenv();

	// Initialize logging
	init_logging();

	// Parse CLI arguments
	let cli = Cli::parse();

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

/// Initialize structured logging with configurable verbosity
///
/// Sets up tracing subscriber with optimized formatting for CLI usage.
/// Logs are controlled via RUST_LOG environment variable with sensible defaults.
fn init_logging() {
	use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};

	// Default to info level for solver-demo, warn for other crates
	let env_filter = EnvFilter::try_from_default_env()
		.unwrap_or_else(|_| EnvFilter::new("solver_demo=info,warn"));

	tracing_subscriber::registry()
		.with(
			fmt::layer()
				.with_target(true)
				.with_thread_ids(false)
				.with_file(false)
				.with_line_number(false)
				.compact(),
		)
		.with(env_filter)
		.init();
}

/// Handle init command
#[instrument(skip(cmd))]
async fn handle_init(cmd: solver_demo::cli::commands::InitCommand) -> Result<()> {
	use solver_demo::cli::commands::InitSubcommand;
	use solver_demo::operations::init::InitOps;

	match cmd.command {
		InitSubcommand::New {
			path,
			chains,
			force,
		} => {
			info!(
				config_path = %path.display(),
				chain_count = chains.len(),
				force = force,
				"Creating new configuration"
			);
			Display::header("Generating New Configuration");

			// Generate new configuration (no context needed)
			let init_ops = InitOps::without_context();
			init_ops.create(path.clone(), chains, force).await?;

			Display::next_steps(&[
				"Review the generated configuration",
				"Run 'cargo run -p solver-demo init load <path> --local' to initialize",
				"Start the local environment with 'cargo run -p solver-demo env start'",
			]);
		},
		InitSubcommand::Load { path, local } => {
			info!(
				config_path = %path.display(),
				local_mode = local,
				"Loading configuration"
			);
			Display::header("Loading Configuration");

			if !path.exists() {
				Display::error(&format!("Configuration not found at: {}", path.display()));
				return Ok(());
			}

			// Use operations layer for loading
			let init_ops = InitOps::without_context();
			init_ops.load(path.clone(), local).await?;

			if local {
				Display::next_steps(&[
					"Start the local environment with 'cargo run -p solver-demo env start'",
					"Check available tokens with 'cargo run -p solver-demo token list'",
					"Build an intent with 'cargo run -p solver-demo intent build'",
				]);
			}
		},
	}

	Ok(())
}

/// Handle config command
#[instrument]
async fn handle_config() -> Result<()> {
	Display::header("Current Configuration");

	// Load config if available
	match Context::load_existing().await {
		Ok(ctx) => {
			info!(
				config_path = %ctx.config.path.display(),
				environment = ?ctx.session.environment(),
				chain_count = ctx.config.chains().len(),
				"Configuration loaded successfully"
			);
			Display::kv("Config file", &ctx.config.path.display().to_string());
			Display::kv("Environment", &format!("{:?}", ctx.session.environment()));
			Display::kv("Chains", &format!("{:?}", ctx.config.chains()));
			Display::kv("RPC Endpoints", &format!("{}", ctx.config.chains().len()));
		},
		Err(_) => {
			info!("No configuration found");
			Display::warning("No configuration loaded");
			Display::next_steps(&[
				"Create a new configuration with 'cargo run -p solver-demo init new'",
				"Or load an existing one with 'cargo run -p solver-demo init load <path>'",
			]);
		},
	}

	Ok(())
}

/// Handle environment command
#[instrument(skip(cmd))]
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
			info!("Starting local environment");
			Display::header("Starting Local Environment");

			// Start environment (Anvil chains only)
			env_ops.start().await?;

			Display::success("Environment started successfully");
		},
		EnvSubcommand::Stop => {
			Display::header("Stopping Local Environment");

			env_ops.stop()?;

			Display::success("Environment stopped");
		},
		EnvSubcommand::Status => {
			Display::header("Environment Status");

			let status = env_ops.status()?;
			Display::kv("Environment", &format!("{:?}", status.environment));
			Display::kv("Chains Running", &format!("{}", status.chains.len()));
			for chain_status in status.chains {
				Display::kv(
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
			// Default to listing if no deployment action is specified
			let should_list = list || (contract.is_none() && !all);

			if should_list {
				Display::header("Available Contracts");
				Display::kv("Contracts Path", &path);

				// Use EnvOps to list available contracts
				match env_ops.list_available_contracts() {
					Ok(contracts) => {
						if contracts.is_empty() {
							Display::warning("No compiled contracts found");
						} else {
							for contract in contracts {
								Display::info(&format!("- {}", contract));
							}
						}
					},
					Err(e) => {
						Display::error(&format!("Failed to list contracts: {}", e));
					},
				}
				return Ok(());
			}

			Display::header("Deploying Contracts");
			Display::kv("Contracts Path", &path);

			if force {
				Display::warning("Force deployment requested");
			}

			if let Some(contract_name) = contract {
				Display::kv("Contract", &contract_name);

				// Convert chain option to Vec<u64> if provided
				let chain_ids = chain.map(|c| vec![c]);

				if let Some(chain_id) = chain {
					Display::kv("Target Chain", &chain_id.to_string());
				} else {
					Display::info("Deploying to all configured chains");
				}

				// Deploy single contract
				match env_ops
					.deploy_single_contract(&contract_name, chain_ids)
					.await
				{
					Ok(()) => {
						// Success already logged by deploy_single_contract
					},
					Err(e) => {
						Display::error(&format!("Contract deployment failed: {}", e));
						return Err(e.into());
					},
				}
			} else if all {
				Display::info("Deploying all standard contracts");

				// Filter to specific chain if provided
				if let Some(chain_id) = chain {
					Display::kv("Target Chain", &chain_id.to_string());
					Display::error("Single chain deployment not yet implemented");
					Display::info("Deployment will happen to all configured chains");
				} else {
					Display::info("Deploying to all configured chains");
				}

				// Use EnvOps to deploy contracts
				match env_ops.deploy(force).await {
					Ok(()) => {
						Display::success("All contracts deployed successfully");
					},
					Err(e) => {
						Display::error(&format!("Deployment failed: {}", e));
						return Err(e.into());
					},
				}
			} else {
				Display::error("Please specify --all to deploy all contracts or --list to see available contracts");
			}

			Display::success("Deploy command completed");
		},
		EnvSubcommand::Setup { chain, amount } => {
			Display::header("Setting Up Test Environment");

			if let Some(chain_id) = chain {
				Display::kv("Target Chain", &chain_id.to_string());
			} else {
				Display::info("Setting up all configured chains");
			}
			Display::kv("Token Amount", &format!("{} tokens", amount));

			// Use EnvOps to setup the environment
			match env_ops.setup(chain, amount).await {
				Ok(()) => {
					Display::success("Environment setup completed successfully");
					Display::next_steps(&[
						"Environment is now ready for testing",
						"Tokens have been minted to user and solver addresses",
						"Permit2 allowances have been approved",
						"Allocator has been registered with TheCompact",
					]);
				},
				Err(e) => {
					Display::error(&format!("Setup failed: {}", e));
					return Err(e.into());
				},
			}
		},
	}

	Ok(())
}

/// Handle token command
#[instrument(skip(cmd))]
async fn handle_token(cmd: solver_demo::cli::commands::TokenCommand) -> Result<()> {
	use solver_demo::cli::commands::TokenSubcommand;
	use solver_demo::operations::token::TokenOps;
	use solver_demo::types::chain::ChainId;

	// Load context
	let ctx = std::sync::Arc::new(Context::load_existing().await?);
	let token_ops = TokenOps::new(ctx.clone());

	match cmd.command {
		TokenSubcommand::List { chains } => {
			Display::header("Available Tokens");

			let chain_ids: Vec<ChainId> = chains
				.map(|c| c.into_iter().map(ChainId::from_u64).collect())
				.unwrap_or_else(|| ctx.config.chains());

			let tokens = token_ops.list(Some(chain_ids)).await?;

			for (chain, token_list) in tokens.tokens_by_chain {
				Display::info(&format!("Chain {}:", chain));
				for token in token_list {
					Display::kv(
						&format!("  {}", token.symbol),
						&format!("{}", token.address),
					);
				}
			}
		},
		TokenSubcommand::Mint {
			chain,
			token,
			amount,
			to,
		} => {
			Display::header("Minting Tokens");

			Display::kv("Chain", &chain.to_string());
			Display::kv("Token", &token);
			Display::kv("Amount", &amount);

			let chain_id = ChainId::from_u64(chain);

			// Get token info and convert amount to wei
			let token_info = ctx.tokens.get_or_error(chain_id, &token)?;
			let amount_parsed = amount.parse::<f64>()?;
			let amount_u256 = token_info.to_wei(amount_parsed);

			let result = token_ops
				.mint(chain_id, &token, to.as_deref(), amount_u256)
				.await?;

			Display::success(&format!(
				"Minted {} {} (tx: {})",
				result.amount,
				result.token,
				result
					.tx_hash
					.map(|h| format!("{:?}", h))
					.unwrap_or_else(|| "pending".to_string())
			));
		},
		TokenSubcommand::Balance {
			account,
			follow,
			chains,
		} => {
			Display::header("Token Balances");

			// Handle "all" account or specific accounts
			let accounts_to_check = if account == "all" {
				vec![
					("user", "User"),
					("solver", "Solver"),
					("recipient", "Recipient"),
				]
			} else {
				vec![(account.as_str(), account.as_str())]
			};

			loop {
				let chain_ids: Vec<ChainId> = if let Some(chain_list) = chains.clone() {
					chain_list.into_iter().map(ChainId::from_u64).collect()
				} else {
					ctx.config.chains()
				};

				for (account_name, display_name) in &accounts_to_check {
					if accounts_to_check.len() > 1 {
						Display::info(&format!(
							"
{} Account:",
							display_name
						));
					} else {
						Display::kv("Account", display_name);
					}

					for chain_id in &chain_ids {
						// Get all tokens for this chain
						let tokens = ctx.tokens.tokens_for_chain(*chain_id);

						Display::info(&format!(
							"{}Chain {}:",
							if accounts_to_check.len() > 1 {
								"  "
							} else {
								"
"
							},
							chain_id
						));
						for token in tokens {
							let result = token_ops
								.balance(*chain_id, &token.symbol, Some(account_name))
								.await?;
							Display::kv(
								&format!(
									"{}  {}",
									if accounts_to_check.len() > 1 {
										"  "
									} else {
										""
									},
									result.token
								),
								&format!("{}", result.balance),
							);
						}
					}
				}

				if let Some(interval) = follow {
					tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
					Display::info("---");
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
			Display::header("Token Approval");

			Display::kv("Chain", &chain.to_string());
			Display::kv("Token", &token);
			Display::kv("Spender", &spender);
			Display::kv("Amount", &amount);

			let chain_id = ChainId::from_u64(chain);

			// Get token info and convert amount to wei
			let token_info = ctx.tokens.get_or_error(chain_id, &token)?;
			let amount_parsed = amount.parse::<f64>()?;
			let amount_u256 = token_info.to_wei(amount_parsed);

			let result = token_ops
				.approve(chain_id, &token, &spender, Some(amount_u256))
				.await?;

			Display::success(&format!(
				"Approved {} {} for {} (tx: {})",
				result.amount,
				result.token,
				result.spender,
				result
					.tx_hash
					.map(|h| format!("{:?}", h))
					.unwrap_or_else(|| "pending".to_string())
			));
		},
	}

	Ok(())
}

/// Handle account command
#[instrument(skip(cmd))]
async fn handle_account(cmd: solver_demo::cli::commands::AccountCommand) -> Result<()> {
	use solver_demo::cli::commands::AccountSubcommand;

	// Load context
	let ctx = Context::load_existing().await?;

	match cmd.command {
		AccountSubcommand::List => {
			Display::header("Configured Accounts");

			let accounts = ctx.config.accounts();

			Display::kv("User", &accounts.user.address);
			Display::kv("Solver", &accounts.solver.address);
			Display::kv("Recipient", &accounts.recipient.address);
		},
		AccountSubcommand::Info { account } => {
			Display::header(&format!("Account Info: {}", account));

			let accounts = ctx.config.accounts();

			let account_info = match account.as_str() {
				"user" => &accounts.user,
				"solver" => &accounts.solver,
				"recipient" => &accounts.recipient,
				_ => {
					Display::error(&format!(
						"Unknown account: {}. Use 'user', 'solver', or 'recipient'",
						account
					));
					return Ok(());
				},
			};

			Display::kv("Address", &account_info.address);
			Display::kv(
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
#[instrument(skip(cmd))]
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
			let (from_token_info, amount_u256) = if exact_output {
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

			Display::header("Building Intent");

			Display::kv("From Chain", &from_chain.to_string());
			Display::kv("To Chain", &to_chain.to_string());
			Display::kv("From Token", &from_token);
			Display::kv("To Token", &to_token);

			// Display formatted amount with token info
			let amount_display = if exact_output {
				let to_token_info = ctx.tokens.get_or_error(to_chain_id, &to_token)?;
				format!("{} {} (output)", amount, to_token_info.symbol)
			} else {
				format!("{} {} (input)", amount, from_token_info.symbol)
			};
			Display::kv("Amount", &amount_display);
			Display::kv("Swap Type", &swap_type);
			Display::kv("Settlement", &settlement);
			Display::kv("Auth", auth.as_deref().unwrap_or("N/A"));

			// Parse settlement and auth types
			let settlement_type =
				settlement.parse::<solver_demo::operations::intent::SettlementType>()?;
			let auth_type = match auth {
				Some(auth_str) => {
					Some(auth_str.parse::<solver_demo::operations::intent::AuthType>()?)
				},
				None => None,
			};

			let params = solver_demo::operations::intent::IntentParams {
				from_chain: from_chain_id,
				to_chain: to_chain_id,
				from_token,
				to_token,
				amount: amount_u256,
				min_amount: None,
				sender: None,
				recipient: None,
				exact_output,
				settlement: settlement_type,
				auth: auth_type,
			};

			let quote_request = intent_ops.build(params, output.clone()).await?;

			// Determine where it was saved and display appropriate message
			if let Some(output_path) = &output {
				Display::success(&format!(
					"GetQuoteRequest saved to: {}",
					output_path.display()
				));
			} else {
				Display::success("GetQuoteRequest saved to: .oif-demo/requests/get_quote.req.json");
			}

			// Display the intent details for user reference
			Display::section("Intent Details");
			Display::info(&serde_json::to_string_pretty(&quote_request.intent)?);
		},
		IntentSubcommand::BuildBatch { input, output } => {
			Display::header("Building Batch Intents");

			Display::kv("Input file", &input.display().to_string());

			let intents = intent_ops.build_batch(&input).await?;

			// Determine output file - default to requests/get_quotes.req.json like old demo
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

			Display::success(&format!(
				"Built {} intents and saved to: {}",
				intents.len(),
				output_path.display()
			));

			// Show next steps like old demo
			Display::next_steps(&[
				&format!(
					"Test quotes: cargo run solver-demo -- quote test {}",
					output_path.display()
				),
				"This will create post_orders.req.json for batch submission",
			]);
		},
		IntentSubcommand::Submit {
			input,
			onchain,
			chain: _,
		} => {
			Display::header("Submitting Intent");

			Display::kv("Input file", &input.display().to_string());

			if onchain {
				Display::warning("On-chain submission not yet implemented");
				return Ok(());
			}

			let order_json = std::fs::read_to_string(&input)?;
			let order: PostOrderRequest = serde_json::from_str(&order_json)?;

			let order_id = intent_ops.submit(order).await?;

			Display::success(&format!("Order submitted: {}", order_id));
			Display::kv("Order ID", &order_id);
		},
		IntentSubcommand::Status { order_id } => {
			Display::header("Order Status");

			Display::kv("Order ID", &order_id);

			let status = intent_ops.status(&order_id).await?;

			Display::kv("Status", &status.status);
			Display::kv("Timestamp", &status.timestamp);

			if let Some(tx_hash) = &status.fill_tx_hash {
				Display::kv("Fill Transaction", tx_hash);
			}
		},
		IntentSubcommand::Test {
			input,
			onchain,
			output: _,
		} => {
			Display::header("Testing Intents");

			Display::kv("Input file", &input.display().to_string());

			if onchain {
				Display::warning("On-chain testing not yet implemented");
				return Ok(());
			}

			// Check if input file exists
			if !input.exists() {
				Display::error(&format!("Input file not found: {}", input.display()));
				Display::info("Please run 'cargo run -p solver-demo -- quote test' first to create post_orders.req.json");
				return Ok(());
			}

			// Load array of PostOrderRequest
			let content = std::fs::read_to_string(&input)?;
			let post_order_requests: Vec<PostOrderRequest> = serde_json::from_str(&content)?;

			if post_order_requests.is_empty() {
				Display::error("No order requests found in input file");
				return Ok(());
			}

			let total_requests = post_order_requests.len();
			Display::info(&format!("Submitting {} order requests...", total_requests));

			let mut successful_count = 0;
			let mut failed_count = 0;
			let start_time = std::time::Instant::now();

			// Process each order request
			for (index, post_order_request) in post_order_requests.into_iter().enumerate() {
				Display::info(&format!(
					"Submitting order request {} of {}...",
					index + 1,
					total_requests
				));

				match intent_ops.submit(post_order_request).await {
					Ok(order_id) => {
						successful_count += 1;
						Display::success(&format!("Order {} submitted: {}", index + 1, order_id));
					},
					Err(e) => {
						failed_count += 1;
						Display::error(&format!("Order {} failed: {}", index + 1, e));
					},
				}
			}

			let total_duration = start_time.elapsed();

			// Display results
			Display::info(&format!(
				"Results: {} successful, {} failed, took {:.2}s",
				successful_count,
				failed_count,
				total_duration.as_secs_f64()
			));

			if successful_count > 0 {
				Display::next_steps(&[
					"Check order status: cargo run -p solver-demo -- intent status <order_id>",
				]);
			}
		},
	}

	Ok(())
}

/// Handle quote command
#[instrument(skip(cmd))]
async fn handle_quote(cmd: solver_demo::cli::commands::QuoteCommand) -> Result<()> {
	use solver_demo::cli::commands::QuoteSubcommand;
	use solver_demo::operations::quote::QuoteOps;

	// Load context
	let ctx = std::sync::Arc::new(Context::load_existing().await?);
	let quote_ops = QuoteOps::new(ctx.clone());

	match cmd.command {
		QuoteSubcommand::Get { input, output } => {
			Display::header("Getting Quote");

			// Use QuoteOps to get the quote
			let response = quote_ops.get(&input).await?;

			Display::success(&format!("Received {} quote(s)", response.quotes.len()));

			if let Some(output_path) = output {
				std::fs::write(&output_path, serde_json::to_string_pretty(&response)?)?;
				Display::info(&format!("Quote saved to: {}", output_path.display()));
				info!(
					output_file = %output_path.display(),
					"Quote response saved to file"
				);
			} else {
				Display::info(&serde_json::to_string_pretty(&response)?);
				info!("Quote response displayed to stdout");
			}
		},
		QuoteSubcommand::Sign {
			input,
			quote_index,
			signature,
			output,
		} => {
			Display::header("Signing Quote");

			Display::kv("Quote file", &input.display().to_string());
			Display::kv("Quote index", &quote_index.to_string());

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
				PostOrderRequest {
					order: quote.order.clone(),
					signature: alloy_primitives::Bytes::from(hex::decode(&sig_str)?),
					quote_id: Some(quote.quote_id.clone()),
					origin_submission: None,
				}
			} else {
				// Sign the quote
				let order_request = quote_ops.sign(quote_response).await?;
				Display::success("Quote signed successfully!");

				// Save the PostOrderRequest to file
				if let Some(output_path) = output {
					let content = serde_json::to_string_pretty(&order_request)?;
					std::fs::write(&output_path, content)?;
					Display::info(&format!(
						"Order request saved to: {}",
						output_path.display()
					));
				} else {
					// Save to default location in same directory as quote response
					let output_path =
						std::path::Path::new(".oif-demo/requests/post_order.req.json");
					if let Some(parent) = output_path.parent() {
						std::fs::create_dir_all(parent)?;
					}
					let content = serde_json::to_string_pretty(&order_request)?;
					std::fs::write(output_path, content)?;
					Display::info(&format!(
						"Order request saved to: {}",
						output_path.display()
					));
				}
				return Ok(());
			};

			if let Some(output_path) = output {
				std::fs::write(&output_path, serde_json::to_string_pretty(&order_request)?)?;
				Display::info(&format!(
					"PostOrderRequest saved to: {}",
					output_path.display()
				));
			}
		},
		QuoteSubcommand::Test { input, output: _ } => {
			Display::header("Testing Quotes");

			Display::kv("Input file", &input.display().to_string());

			// Check if input file exists
			if !input.exists() {
				Display::error(&format!("Input file not found: {}", input.display()));
				Display::info("Please run 'cargo run -p solver-demo -- intent build-batch' first");
				return Ok(());
			}

			// Load array of GetQuoteRequest
			let content = std::fs::read_to_string(&input)?;
			let quote_requests: Vec<GetQuoteRequest> = serde_json::from_str(&content)?;

			if quote_requests.is_empty() {
				Display::error("No quote requests found in input file");
				return Ok(());
			}

			let total_requests = quote_requests.len();
			Display::info(&format!("Processing {} quote requests...", total_requests));

			let mut successful_orders = Vec::new();
			let mut failed_count = 0;
			let start_time = std::time::Instant::now();

			// Process each quote request
			for (index, quote_request) in quote_requests.into_iter().enumerate() {
				Display::info(&format!(
					"Processing quote request {} of {}...",
					index + 1,
					total_requests
				));

				match quote_ops.get_and_sign_quote(quote_request).await {
					Ok(post_order_request) => {
						successful_orders.push(post_order_request);
						Display::success(&format!("Quote request {} succeeded", index + 1));
						info!(
							request_index = index + 1,
							total_requests = total_requests,
							"Quote request processed successfully"
						);
					},
					Err(e) => {
						failed_count += 1;
						Display::error(&format!("Quote request {} failed: {}", index + 1, e));
						info!(
							request_index = index + 1,
							error = %e,
							"Quote request failed"
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

				Display::success(&format!(
					"Saved {} signed orders to {}",
					successful_orders.len(),
					output_file.display()
				));
			}

			// Display results
			Display::info(&format!(
				"Results: {} successful, {} failed, took {:.2}s",
				successful_orders.len(),
				failed_count,
				total_duration.as_secs_f64()
			));

			if !successful_orders.is_empty() {
				Display::next_steps(&[&format!(
					"Submit orders: cargo run -p solver-demo -- intent test {}",
					output_file.display()
				)]);
			}
		},
	}

	Ok(())
}
