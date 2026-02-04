//! Main entry point for the OIF solver service.
//!
//! This binary provides a complete solver implementation that discovers,
//! validates, executes, and settles cross-chain orders. It uses a modular
//! architecture with pluggable implementations for different components.
//!
//! # Configuration
//!
//! The solver uses a storage backend (Redis by default) as the single source of truth
//! for runtime configuration. Configuration is seeded once when deploying a new solver,
//! then loaded from storage on subsequent startups.
//! on subsequent startups.
//!
//! # Usage
//!
//! ```bash
//! # First run: seed configuration to storage (Redis by default)
//! export REDIS_URL="redis://localhost:6379"
//! export SOLVER_PRIVATE_KEY="your_64_hex_character_private_key"
//! solver --seed testnet --seed-overrides '{"networks":[...]}'
//!
//! # Subsequent runs: load from storage
//! export SOLVER_ID="your-solver-id"
//! solver
//!
//! # Force re-seed (overwrite existing configuration)
//! solver --seed testnet --seed-overrides '{"networks":[...]}' --force-seed
//! ```

use clap::Parser;
use solver_config::Config;
use solver_service::{
	build_solver_from_config,
	config_merge::{build_runtime_config, config_to_operator_config, merge_config},
	seeds::SeedPreset,
	server,
};
use solver_storage::{config_store::create_config_store, verify_storage_readiness, StoreConfig};
use solver_types::{OperatorConfig, SeedOverrides};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Command-line arguments for the solver service.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
	/// Seed preset to use (mainnet, testnet)
	///
	/// Use this with --seed-overrides to seed initial configuration to storage.
	#[arg(long)]
	seed: Option<String>,

	/// Seed overrides (JSON string or path to JSON file)
	///
	/// Contains the networks and tokens this solver should support.
	/// These values override/extend the seed preset defaults.
	#[arg(long)]
	seed_overrides: Option<String>,

	/// Force re-seed even if configuration exists in storage
	#[arg(long, default_value = "false")]
	force_seed: bool,

	/// Log level (trace, debug, info, warn, error)
	#[arg(short, long, default_value = "info")]
	log_level: String,
}

/// Main entry point for the solver service.
///
/// This function:
/// 1. Parses command-line arguments
/// 2. Initializes logging infrastructure
/// 3. Loads or seeds configuration (from file or storage)
/// 4. Builds the solver engine with all implementations
/// 5. Runs the solver until interrupted
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	let args = Args::parse();

	// Initialize tracing with env filter
	use tracing_subscriber::{fmt, EnvFilter};

	// Create env filter with default from args
	let default_directive = args.log_level.to_string();
	let env_filter =
		EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_directive));

	fmt()
		.with_env_filter(env_filter)
		.with_thread_ids(true)
		.with_target(true)
		.init();

	tracing::info!("Started solver");

	// Build storage configuration from environment
	let store_config = StoreConfig::from_env()?;

	// Verify storage readiness (informational by default)
	verify_storage_readiness(&store_config).await?;

	// Load configuration based on mode
	let config = load_config(&args, store_config.clone()).await?;
	tracing::info!("Loaded configuration [{}]", config.solver.id);

	// Create dynamic config for hot reload support
	// This Arc<RwLock<Config>> is shared between SolverEngine and API server
	let dynamic_config = Arc::new(RwLock::new(config.clone()));

	// Build solver engine with implementations using the factory registry
	// The solver receives the dynamic config for hot reload support
	let solver = build_solver_from_config(dynamic_config.clone()).await?;
	let solver = Arc::new(solver);

	// Check if API server should be started
	let api_enabled = config.api.as_ref().is_some_and(|api| api.enabled);

	if api_enabled {
		let api_config = config.api.as_ref().unwrap().clone();
		let api_solver = Arc::clone(&solver);

		// Start both the solver and the API server concurrently
		let solver_task = solver.run();
		let api_task = server::start_server(api_config, api_solver);

		// Run both tasks concurrently
		tokio::select! {
			result = solver_task => {
				tracing::info!("Solver finished");
				result?;
			}
			result = api_task => {
				tracing::info!("API server finished");
				result?;
			}
		}
	} else {
		// Run only the solver
		tracing::info!("Starting solver only");
		solver.run().await?;
	}

	tracing::info!("Stopped solver");
	Ok(())
}

/// Load configuration based on command-line arguments.
///
/// Configuration is loaded from storage, optionally seeding first with --seed + --seed-overrides.
async fn load_config(
	args: &Args,
	store_config: StoreConfig,
) -> Result<Config, Box<dyn std::error::Error>> {
	// Handle seeding if requested
	if let (Some(seed_name), Some(seed_overrides_str)) = (&args.seed, &args.seed_overrides) {
		// Parse seed preset
		let seed_preset: SeedPreset = seed_name.parse()?;
		let seed = seed_preset.get_seed();

		// Parse seed overrides
		let seed_overrides = parse_seed_overrides(seed_overrides_str)?;

		// Merge seed + overrides to get Config, then convert to OperatorConfig
		tracing::info!("Merging seed overrides with {} seed", seed_name);
		let merged_config = merge_config(seed_overrides, seed)?;
		let operator_config = config_to_operator_config(&merged_config)?;
		let solver_id = operator_config.solver_id.clone();

		// Create OperatorConfig store for seeding (not legacy Config store)
		let operator_store = create_config_store::<OperatorConfig>(
			store_config.clone(),
			format!("{solver_id}-operator"),
		)?;

		// Check if OperatorConfig already exists
		let exists = operator_store.exists().await?;

		if exists && !args.force_seed {
			// OperatorConfig exists, skip seeding and load existing
			tracing::warn!(
				"OperatorConfig already exists for solver '{}'. Use --force-seed to overwrite.",
				solver_id
			);

			let versioned = operator_store.get().await?;
			// Log what account config is in storage
			match &versioned.data.account {
				Some(acc) => tracing::info!(
					primary = %acc.primary,
					implementations = ?acc.implementations.keys().collect::<Vec<_>>(),
					"Loaded account config from storage"
				),
				None => {
					tracing::info!("No account config in storage, will use default local wallet")
				},
			}
			let config = build_runtime_config(&versioned.data)?;

			tracing::info!("════════════════════════════════════════════════════════════");
			tracing::info!("  Configuration already exists (skipping seed)");
			tracing::info!("════════════════════════════════════════════════════════════");
			tracing::info!("  SOLVER_ID: {}", solver_id);
			tracing::info!("  Version:   {}", versioned.version);
			tracing::info!("  Use --force-seed to overwrite existing configuration");
			tracing::info!("════════════════════════════════════════════════════════════");

			return Ok(config);
		}

		// Proceed with seeding (new or force)
		if exists && args.force_seed {
			tracing::warn!("Force seeding: overwriting existing OperatorConfig");
			operator_store.delete().await?;
		}

		// Log what account config will be stored
		match &operator_config.account {
			Some(acc) => tracing::info!(
				primary = %acc.primary,
				implementations = ?acc.implementations.keys().collect::<Vec<_>>(),
				"Seeding account config to storage"
			),
			None => tracing::info!("No account override, seeding with default local wallet config"),
		}
		tracing::info!("Seeding OperatorConfig to storage");
		let versioned = operator_store.seed(operator_config).await?;

		// Build runtime Config from OperatorConfig
		let config = build_runtime_config(&versioned.data)?;

		// Print prominent output for the solver ID
		tracing::info!("════════════════════════════════════════════════════════════");
		tracing::info!("  Configuration seeded successfully!");
		tracing::info!("  SOLVER_ID: {}", solver_id);
		tracing::info!("  Version:   {}", versioned.version);
		tracing::info!("  For subsequent runs, set:");
		tracing::info!("    export SOLVER_ID={}", solver_id);
		tracing::info!("════════════════════════════════════════════════════════════");

		return Ok(config);
	}

	// Try to load from storage
	// First, we need to determine the solver_id to use
	// If not seeding, we need to either:
	// 1. Use a solver_id from environment
	// 2. Error out because we don't know which config to load
	let solver_id = std::env::var("SOLVER_ID").map_err(|_| {
		"No configuration source specified. Use one of:\n\
         1. --seed <preset> --seed-overrides <json> to seed new configuration\n\
         2. Set SOLVER_ID environment variable to load existing configuration from storage"
	})?;

	tracing::info!(
		"Loading configuration from storage for solver: {}",
		solver_id
	);

	// First, try to load OperatorConfig (admin API may have modified it)
	let operator_store = create_config_store::<OperatorConfig>(
		store_config.clone(),
		format!("{solver_id}-operator"),
	)?;

	if !operator_store.exists().await? {
		return Err(format!(
			"OperatorConfig not found in storage for solver '{solver_id}'. \
			Run with --seed <preset> to initialize configuration first."
		)
		.into());
	}

	let versioned = operator_store.get().await.map_err(|e| {
		format!(
			"Failed to load OperatorConfig from storage: {e}. \
			Check storage connectivity or delete key '{solver_id}-operator' to re-seed."
		)
	})?;

	tracing::info!(
		"Loaded OperatorConfig from storage: version={}",
		versioned.version
	);

	build_runtime_config(&versioned.data).map_err(|e| {
		format!(
			"OperatorConfig in storage is invalid: {e}. \
			Fix the config or delete key '{solver_id}-operator' to re-seed."
		)
		.into()
	})
}

/// Parse seed overrides from a JSON string or file path.
fn parse_seed_overrides(input: &str) -> Result<SeedOverrides, Box<dyn std::error::Error>> {
	// Try as file path first
	if std::path::Path::new(input).exists() {
		let content = std::fs::read_to_string(input)?;
		return Ok(serde_json::from_str(&content)?);
	}

	// Treat as JSON string
	Ok(serde_json::from_str(input)?)
}
