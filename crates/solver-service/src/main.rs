//! Main entry point for the OIF solver service.
//!
//! This binary provides a complete solver implementation that discovers,
//! validates, executes, and settles cross-chain orders. It uses a modular
//! architecture with pluggable implementations for different components.

use clap::Parser;
use solver_config::Config;
use solver_core::{SolverBuilder, SolverEngine, SolverFactories};
use std::path::PathBuf;
use std::sync::Arc;

mod apis;
mod server;

// Import implementations from individual crates
use solver_account::implementations::local::create_account;
use solver_delivery::implementations::evm::alloy::create_http_delivery;
use solver_discovery::implementations::offchain::_7683::create_discovery as offchain_create_discovery;
use solver_discovery::implementations::onchain::_7683::create_discovery as onchain_create_discovery;
use solver_order::implementations::{
	standards::_7683::create_order_impl, strategies::simple::create_strategy,
};
use solver_settlement::implementations::direct::create_settlement;
use solver_storage::implementations::file::create_storage as create_file_storage;
use solver_storage::implementations::memory::create_storage as create_memory_storage;

/// Command-line arguments for the solver service.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
	/// Path to configuration file
	#[arg(short, long, default_value = "config.toml")]
	config: PathBuf,

	/// Log level (trace, debug, info, warn, error)
	#[arg(short, long, default_value = "info")]
	log_level: String,
}

/// Main entry point for the solver service.
///
/// This function:
/// 1. Parses command-line arguments
/// 2. Initializes logging infrastructure
/// 3. Loads configuration from file
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

	// Load configuration
	let config = Config::from_file(args.config.to_str().unwrap())?;
	tracing::info!("Loaded configuration [{}]", config.solver.id);

	// Build solver engine with implementations
	let solver = build_solver(config.clone()).await?;
	let solver = Arc::new(solver);
	tracing::info!("Loaded solver engine");

	// Check if API server should be started
	let api_enabled = config.api.as_ref().is_some_and(|api| api.enabled);

	if api_enabled {
		let api_config = config.api.as_ref().unwrap().clone();
		let api_solver = Arc::clone(&solver);

		// Start both the solver and the API server concurrently
		let solver_task = solver.run();
		let api_task = server::start_server(api_config, api_solver);

		tracing::info!("Starting solver and API server");

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

/// Macro to create a factory HashMap with the appropriate type aliases
macro_rules! create_factory_map {
    ($interface:path, $error:path, $( $name:literal => $factory:expr ),* $(,)?) => {{
        let mut factories = std::collections::HashMap::new();
        $(
            factories.insert(
                $name.to_string(),
                $factory as fn(&toml::Value) -> Result<Box<dyn $interface>, $error>
            );
        )*
        factories
    }};
}

/// Builds the solver engine with all necessary implementations.
///
/// This function wires up all the concrete implementations for:
/// - Storage backends (e.g., in-memory, Redis)
/// - Account providers (e.g., local keys, AWS KMS)
/// - Delivery mechanisms (e.g., HTTP RPC, WebSocket)
/// - Discovery sources (e.g., on-chain events, off-chain APIs)
/// - Order implementations (e.g., EIP-7683)
/// - Settlement mechanisms (e.g., direct settlement)
/// - Execution strategies (e.g., always execute, limit orders)
async fn build_solver(config: Config) -> Result<SolverEngine, Box<dyn std::error::Error>> {
	let builder = SolverBuilder::new(config);

	// Create factory maps using the macro - much cleaner!
	let delivery_factories = create_factory_map!(
		solver_delivery::DeliveryInterface,
		solver_delivery::DeliveryError,
		"origin" => create_http_delivery,
		"destination" => create_http_delivery,
	);

	let discovery_factories = create_factory_map!(
		solver_discovery::DiscoveryInterface,
		solver_discovery::DiscoveryError,
		"onchain_eip7683" => onchain_create_discovery,
		"offchain_eip7683" => offchain_create_discovery,
	);

	let order_factories = create_factory_map!(
		solver_order::OrderInterface,
		solver_order::OrderError,
		"eip7683" => create_order_impl,
	);

	let settlement_factories = create_factory_map!(
		solver_settlement::SettlementInterface,
		solver_settlement::SettlementError,
		"eip7683" => create_settlement,
	);

	let storage_factories = create_factory_map!(
		solver_storage::StorageInterface,
		solver_storage::StorageError,
		"file" => create_file_storage,
		"memory" => create_memory_storage,
	);

	let factories = SolverFactories {
		storage_factories,
		account_factory: create_account,
		delivery_factories,
		discovery_factories,
		order_factories,
		settlement_factories,
		strategy_factory: create_strategy,
	};

	Ok(builder.build(factories).await?)
}
