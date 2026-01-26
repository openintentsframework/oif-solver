//! Main entry point for the OIF solver service.
//!
//! This binary provides a complete solver implementation that discovers,
//! validates, executes, and settles cross-chain orders. It uses a modular
//! architecture with pluggable implementations for different components.
//!
//! # Configuration
//!
//! The solver uses Redis as the single source of truth for runtime configuration.
//! Configuration is seeded once when deploying a new solver, then loaded from Redis
//! on subsequent startups.
//!
//! # Usage
//!
//! ```bash
//! # First run: seed configuration to Redis
//! export REDIS_URL="redis://localhost:6379"
//! export SOLVER_PRIVATE_KEY="your_64_hex_character_private_key"
//! solver --seed testnet --seed-overrides '{"networks":[...]}'
//!
//! # Subsequent runs: load from Redis
//! export SOLVER_ID="your-solver-id"
//! solver
//!
//! # Force re-seed (overwrite existing configuration)
//! solver --seed testnet --seed-overrides '{"networks":[...]}' --force-seed
//! ```

use clap::Parser;
use solver_config::Config;
use solver_service::{
	build_solver_from_config, config_merge::merge_config, seeds::SeedPreset, server,
};
use solver_storage::config_store::{create_config_store, ConfigStoreConfig};
use solver_types::SeedOverrides;
use std::sync::Arc;

/// Command-line arguments for the solver service.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
	/// Seed preset to use (mainnet, testnet)
	///
	/// Use this with --seed-overrides to seed initial configuration to Redis.
	#[arg(long)]
	seed: Option<String>,

	/// Seed overrides (JSON string or path to JSON file)
	///
	/// Contains the networks and tokens this solver should support.
	/// These values override/extend the seed preset defaults.
	#[arg(long)]
	seed_overrides: Option<String>,

	/// Force re-seed even if configuration exists in Redis
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
/// 3. Loads or seeds configuration (from file or Redis)
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

	// Load configuration based on mode
	let config = load_config(&args).await?;
	tracing::info!("Loaded configuration [{}]", config.solver.id);

	// Build solver engine with implementations using the factory registry
	let solver = build_solver_from_config(config.clone()).await?;
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
/// Configuration is loaded from Redis, optionally seeding first with --seed + --seed-overrides.
async fn load_config(args: &Args) -> Result<Config, Box<dyn std::error::Error>> {
	let redis_url =
		std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

	// Handle seeding if requested
	if let (Some(seed_name), Some(seed_overrides_str)) = (&args.seed, &args.seed_overrides) {
		// Parse seed preset
		let seed_preset: SeedPreset = seed_name.parse()?;
		let seed = seed_preset.get_seed();

		// Parse seed overrides
		let seed_overrides = parse_seed_overrides(seed_overrides_str)?;

		// Merge seed + overrides
		tracing::info!("Merging seed overrides with {} seed", seed_name);
		let merged_config = merge_config(seed_overrides, seed)?;

		// Create config store for seeding
		let config_store = create_config_store::<Config>(
			ConfigStoreConfig::Redis {
				url: redis_url.clone(),
			},
			merged_config.solver.id.clone(),
		)?;

		// Check if we should seed
		let exists = config_store.exists().await?;
		let should_seed = args.force_seed || !exists;

		if should_seed {
			if exists && args.force_seed {
				tracing::warn!("Force seeding: deleting existing configuration");
				config_store.delete().await?;
			}

			tracing::info!("Seeding configuration to Redis");
			let versioned = config_store.seed(merged_config).await?;
			let solver_id = &versioned.data.solver.id;

			// Print prominent output for the solver ID
			tracing::info!("════════════════════════════════════════════════════════════");
			tracing::info!("  Configuration seeded successfully!");
			tracing::info!("  SOLVER_ID: {}", solver_id);
			tracing::info!("  Version:   {}", versioned.version);
			tracing::info!("  For subsequent runs, set:");
			tracing::info!("    export SOLVER_ID={}", solver_id);
			tracing::info!("════════════════════════════════════════════════════════════");

			return Ok(versioned.into_inner());
		} else {
			// Load existing config first to display the correct solver_id
			let versioned = config_store.get().await?;
			let existing_config = versioned.into_inner();

			// Print info about existing config
			tracing::info!("════════════════════════════════════════════════════════════");
			tracing::info!("  Configuration already exists (skipping seed)");
			tracing::info!("════════════════════════════════════════════════════════════");
			tracing::info!("  SOLVER_ID: {}", existing_config.solver.id);
			tracing::info!("  Use --force-seed to overwrite existing configuration");
			tracing::info!("════════════════════════════════════════════════════════════");

			return Ok(existing_config);
		}
	}

	// Try to load from Redis
	// First, we need to determine the solver_id to use
	// If not seeding, we need to either:
	// 1. Use a solver_id from environment
	// 2. Error out because we don't know which config to load
	let solver_id = std::env::var("SOLVER_ID").map_err(|_| {
		"No configuration source specified. Use one of:\n\
         1. --seed <preset> --seed-overrides <json> to seed new configuration\n\
         2. Set SOLVER_ID environment variable to load existing configuration from Redis"
	})?;

	tracing::info!("Loading configuration from Redis for solver: {}", solver_id);

	let config_store =
		create_config_store::<Config>(ConfigStoreConfig::Redis { url: redis_url }, solver_id)?;
	let versioned = config_store.get().await?;

	tracing::info!(
		"Loaded configuration from Redis: version={}",
		versioned.version
	);

	Ok(versioned.into_inner())
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
