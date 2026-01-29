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
	build_solver_from_config,
	config_merge::{build_runtime_config, config_to_operator_config, merge_config},
	seeds::SeedPreset,
	server,
};
use solver_storage::{
	config_store::create_config_store, get_readiness_checker, ReadinessConfig, ReadinessError,
	StoreConfig,
};
use solver_types::{OperatorConfig, SeedOverrides};
use std::sync::Arc;
use tokio::sync::RwLock;

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

	// Verify storage readiness (informational by default)
	verify_storage_readiness().await?;

	// Load configuration based on mode
	let config = load_config(&args).await?;
	tracing::info!("Loaded configuration [{}]", config.solver.id);

	// Create shared config for hot reload support
	// This Arc<RwLock<Config>> is shared between SolverEngine and API server
	let shared_config = Arc::new(RwLock::new(config.clone()));

	// Build solver engine with implementations using the factory registry
	// The solver receives the shared config for hot reload support
	let solver = build_solver_from_config(shared_config.clone()).await?;
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

		// Merge seed + overrides to get Config, then convert to OperatorConfig
		tracing::info!("Merging seed overrides with {} seed", seed_name);
		let merged_config = merge_config(seed_overrides, seed)?;
		let operator_config = config_to_operator_config(&merged_config)?;
		let solver_id = operator_config.solver_id.clone();

		// Create OperatorConfig store for seeding (not legacy Config store)
		let operator_store = create_config_store::<OperatorConfig>(
			StoreConfig::Redis {
				url: redis_url.clone(),
			},
			format!("{}-operator", solver_id),
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

		tracing::info!("Seeding OperatorConfig to Redis");
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

	// First, try to load OperatorConfig (admin API may have modified it)
	let operator_store = create_config_store::<OperatorConfig>(
		StoreConfig::Redis {
			url: redis_url.clone(),
		},
		format!("{}-operator", solver_id),
	)?;

	if operator_store.exists().await? {
		// OperatorConfig exists - this is the expected path for admin API changes
		match operator_store.get().await {
			Ok(versioned) => {
				tracing::info!(
					"Loaded OperatorConfig from Redis: version={} (admin API changes will be applied)",
					versioned.version
				);

				// Build runtime Config from OperatorConfig - fail loudly if invalid
				match build_runtime_config(&versioned.data) {
					Ok(config) => return Ok(config),
					Err(e) => {
						// OperatorConfig exists but is invalid - fail with clear error
						return Err(format!(
							"OperatorConfig in Redis is invalid: {}. \
							Fix the config or delete key '{}-operator' to re-seed.",
							e, solver_id
						)
						.into());
					},
				}
			},
			Err(e) => {
				// OperatorConfig exists but failed to load (corrupted?)
				return Err(format!(
					"Failed to load OperatorConfig from Redis: {}. \
					Check Redis connectivity or delete key '{}-operator' to re-seed.",
					e, solver_id
				)
				.into());
			},
		}
	}

	// Fall back to loading Config directly (backward compatibility for existing deployments)
	tracing::info!("No OperatorConfig found, loading legacy Config directly");
	let config_store =
		create_config_store::<Config>(StoreConfig::Redis { url: redis_url }, solver_id.clone())?;

	match config_store.get().await {
		Ok(versioned) => {
			tracing::info!(
				"Loaded legacy configuration from Redis: version={}",
				versioned.version
			);
			Ok(versioned.into_inner())
		},
		Err(e) => Err(format!(
			"No configuration found for solver '{}': {}. \
			Use --seed <preset> --seed-overrides <json> to create initial configuration.",
			solver_id, e
		)
		.into()),
	}
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

/// Verify storage readiness for the configured backend.
///
/// This function uses the `StorageReadiness` trait to check backend-specific
/// requirements. Currently supports Redis backend.
///
/// By default, this function:
/// - Checks backend connectivity
/// - Logs readiness status (warning if issues found)
/// - Does NOT fail if checks don't pass (informational only)
///
/// # Strict Mode
///
/// Set `REQUIRE_PERSISTENCE=true` to fail startup if persistence is disabled.
/// Set `REQUIRE_PERSISTENCE_STRICT=true` to use more accurate checks (e.g., CONFIG GET
/// for Redis, which may fail on managed Redis with restricted ACLs).
async fn verify_storage_readiness() -> Result<(), Box<dyn std::error::Error>> {
	// Determine backend (default to redis for now)
	let backend_name = std::env::var("STORAGE_BACKEND").unwrap_or_else(|_| "redis".to_string());

	let backend_url = match backend_name.as_str() {
		"redis" => {
			std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string())
		},
		_ => String::new(),
	};

	// Get readiness checker for this backend
	let Some(checker) = get_readiness_checker(&backend_name) else {
		tracing::info!("No readiness checker for backend: {}", backend_name);
		return Ok(());
	};

	// Skip if backend has no checks to perform
	if !checker.has_checks() {
		tracing::warn!(
			"Using {} backend - no readiness checks to perform",
			backend_name
		);
		return Ok(());
	}

	// Build config from environment
	let config = ReadinessConfig {
		strict: std::env::var("REQUIRE_PERSISTENCE")
			.map(|v| v == "1" || v.to_lowercase() == "true")
			.unwrap_or(false),
		strict_checks: std::env::var("REQUIRE_PERSISTENCE_STRICT")
			.map(|v| v == "1" || v.to_lowercase() == "true")
			.unwrap_or(false),
		timeout_ms: 5000,
	};

	tracing::info!("Checking {} storage readiness...", backend_name);

	match checker.check(&backend_url, &config).await {
		Ok(status) => {
			// Log the readiness status
			tracing::info!("════════════════════════════════════════════════════════════");
			tracing::info!("  {} Storage Readiness", status.backend_name);
			tracing::info!("════════════════════════════════════════════════════════════");

			for check in &status.checks {
				if check.passed {
					tracing::info!("  {}: {}", check.name, check.status);
				} else {
					tracing::warn!("  {}: {}", check.name, check.status);
				}
				if let Some(msg) = &check.message {
					tracing::info!("    └─ {}", msg);
				}
			}

			for (key, value) in &status.details {
				tracing::info!("  {}: {}", key, value);
			}

			tracing::info!("════════════════════════════════════════════════════════════");

			// Fail if not ready and strict mode is enabled
			if !status.is_ready {
				tracing::error!("════════════════════════════════════════════════════════════");
				tracing::error!("  STARTUP BLOCKED: Storage not ready");
				tracing::error!("════════════════════════════════════════════════════════════");
				tracing::error!("");
				tracing::error!("  To fix:");
				tracing::error!("  1. Address the failed checks above OR");
				tracing::error!("  2. Set REQUIRE_PERSISTENCE=false (not recommended)");
				tracing::error!("");
				tracing::error!("  See docs/redis-persistence.md for instructions.");
				tracing::error!("════════════════════════════════════════════════════════════");
				return Err(ReadinessError::NotReady(
					"Storage readiness checks failed".to_string(),
				)
				.into());
			}

			Ok(())
		},
		Err(ReadinessError::ConnectionFailed(msg)) => {
			tracing::error!("════════════════════════════════════════════════════════════");
			tracing::error!("  {} Storage: CONNECTION FAILED", backend_name);
			tracing::error!("════════════════════════════════════════════════════════════");
			tracing::error!("  Error: {}", msg);
			tracing::error!("");
			tracing::error!("  Verify that:");
			tracing::error!("  1. The storage backend is running");
			tracing::error!("  2. Connection URL is correct");
			tracing::error!("  3. Network connectivity is available");
			tracing::error!("════════════════════════════════════════════════════════════");
			Err(ReadinessError::ConnectionFailed(msg).into())
		},
		Err(e) => {
			tracing::error!("Storage readiness check failed: {}", e);
			Err(e.into())
		},
	}
}
