use std::collections::HashMap;

use crate::utils::placeholders::generate_placeholder_map;
use anyhow::{anyhow, Result};

/// Generate the main configuration file
pub fn generate_demo_config(chain_ids: &[u64], config_name: &str) -> Result<String> {
	let placeholders = generate_placeholder_map(chain_ids);
	let mut config = String::new();

	// Header
	config.push_str("# OIF Solver Configuration - Generated File\n");
	config.push_str("# Generated with placeholder values for easy regex replacement\n\n");

	// Include files - using standard naming convention
	// These will be dynamically discovered by scanning the files for their sections
	config.push_str(&format!(
		"include = [\"{}/networks.toml\", \"{}/api.toml\", \"{}/gas.toml\"]\n\n",
		config_name, config_name, config_name
	));

	// Solver configuration
	config.push_str("[solver]\n");
	config.push_str("id = \"oif-solver-demo\"\n");
	config.push_str("monitoring_timeout_minutes = 5\n");
	config.push_str("min_profitability_pct = 10.0\n\n");

	// Storage configuration
	add_storage_config(&mut config);

	// Account configuration
	add_account_config(&mut config);

	// Delivery configuration
	add_delivery_config(&mut config, chain_ids);

	// Discovery configuration
	add_discovery_config(&mut config, chain_ids);

	// Order configuration
	add_order_config(&mut config);

	// Pricing configuration
	add_pricing_config(&mut config);

	// Settlement configuration
	add_settlement_config(&mut config, chain_ids, &placeholders)?;

	Ok(config)
}

fn add_storage_config(config: &mut String) {
	config.push_str(
		"# ============================================================================\n",
	);
	config.push_str("# STORAGE\n");
	config.push_str(
		"# ============================================================================\n",
	);
	config.push_str("[storage]\n");
	config.push_str("primary = \"file\"\n");
	config.push_str("cleanup_interval_seconds = 60\n\n");

	config.push_str("[storage.implementations.memory]\n");
	config.push_str("# Memory storage has no configuration\n\n");

	config.push_str("[storage.implementations.file]\n");
	config.push_str("storage_path = \"./data/storage\"\n");
	config.push_str("ttl_orders = 300                # 5 minutes\n");
	config.push_str("ttl_intents = 120               # 2 minutes\n");
	config.push_str("ttl_order_by_tx_hash = 300      # 5 minutes\n\n");
}

fn add_account_config(config: &mut String) {
	config.push_str(
		"# ============================================================================\n",
	);
	config.push_str("# ACCOUNT\n");
	config.push_str(
		"# ============================================================================\n",
	);
	config.push_str("[account]\n");
	config.push_str("primary = \"local\"\n\n");

	config.push_str("[account.implementations.local]\n");
	config.push_str(&format!(
		"private_key = \"{}\"\n\n",
		crate::utils::constants::DEFAULT_ANVIL_DEPLOYER_KEY
	));
}

fn add_delivery_config(config: &mut String, chain_ids: &[u64]) {
	config.push_str(
		"# ============================================================================\n",
	);
	config.push_str("# DELIVERY\n");
	config.push_str(
		"# ============================================================================\n",
	);
	config.push_str("[delivery]\n");
	config.push_str("min_confirmations = 1\n");
	config.push_str("transaction_poll_interval_seconds = 3\n\n");

	config.push_str("[delivery.implementations.evm_alloy]\n");
	config.push_str(&format!("network_ids = {:?}\n\n", chain_ids));
}

fn add_discovery_config(config: &mut String, chain_ids: &[u64]) {
	config.push_str(
		"# ============================================================================\n",
	);
	config.push_str("# DISCOVERY\n");
	config.push_str(
		"# ============================================================================\n",
	);
	config.push_str("[discovery]\n\n");

	config.push_str("[discovery.implementations.onchain_eip7683]\n");
	config.push_str(&format!("network_ids = {:?}\n", chain_ids));
	config.push_str(
		"polling_interval_secs = 0    # Use WebSocket subscriptions instead of polling\n\n",
	);

	config.push_str("[discovery.implementations.offchain_eip7683]\n");
	config.push_str("api_host = \"127.0.0.1\"\n");
	config.push_str("api_port = 8081\n");
	config.push_str(&format!(
		"network_ids = [{}]\n\n",
		chain_ids.first().unwrap_or(&31337)
	));
}

fn add_order_config(config: &mut String) {
	config.push_str(
		"# ============================================================================\n",
	);
	config.push_str("# ORDER\n");
	config.push_str(
		"# ============================================================================\n",
	);
	config.push_str("[order]\n\n");

	config.push_str("[order.implementations.eip7683]\n\n");

	config.push_str("[order.strategy]\n");
	config.push_str("primary = \"simple\"\n\n");

	config.push_str("[order.strategy.implementations.simple]\n");
	config.push_str("max_gas_price_gwei = 100\n\n");
}

fn add_pricing_config(config: &mut String) {
	config.push_str(
		"# ============================================================================\n",
	);
	config.push_str("# PRICING\n");
	config.push_str(
		"# ============================================================================\n",
	);
	config.push_str("[pricing]\n");
	config.push_str("primary = \"mock\"\n\n");

	config.push_str("[pricing.implementations.mock]\n");
	config.push_str("# Uses default ETH/USD price of 4615.16\n\n");

	config.push_str("[pricing.implementations.coingecko]\n");
	config.push_str("# Free tier configuration (no API key required)\n");
	config.push_str("# api_key = \"CG-YOUR-API-KEY-HERE\"\n");
	config.push_str("cache_duration_seconds = 60\n");
	config.push_str("rate_limit_delay_ms = 1200\n\n");

	config.push_str("# Custom prices for demo/test tokens (in USD)\n");
	config.push_str("[pricing.implementations.coingecko.custom_prices]\n");
	config.push_str("TOKA = \"200.00\"\n");
	config.push_str("TOKB = \"195.00\"\n\n");
}

fn add_settlement_config(
	config: &mut String,
	chain_ids: &[u64],
	placeholders: &HashMap<String, String>,
) -> Result<()> {
	config.push_str(
		"# ============================================================================\n",
	);
	config.push_str("# SETTLEMENT\n");
	config.push_str(
		"# ============================================================================\n",
	);
	config.push_str("[settlement]\n");
	config.push_str("settlement_poll_interval_seconds = 3\n\n");

	config.push_str("[settlement.domain]\n");
	config.push_str("chain_id = 1\n");
	let settlement_addr = placeholders
		.get("PLACEHOLDER_SETTLEMENT_DOMAIN")
		.ok_or_else(|| anyhow!("Missing PLACEHOLDER_SETTLEMENT_DOMAIN"))?;
	config.push_str(&format!("address = \"{}\"\n\n", settlement_addr));

	config.push_str("[settlement.implementations.direct]\n");
	config.push_str("order = \"eip7683\"\n");
	config.push_str(&format!("network_ids = {:?}\n", chain_ids));
	config.push_str("dispute_period_seconds = 1\n");
	config.push_str("# Oracle selection strategy when multiple oracles are available (First, RoundRobin, Random)\n");
	config.push_str("oracle_selection_strategy = \"First\"\n\n");

	// Oracle configuration
	config.push_str("# Oracle configuration with multiple oracle support\n");
	config.push_str("[settlement.implementations.direct.oracles]\n");

	// Input oracles
	config.push_str("# Input oracles (on origin chains)\n");
	config.push_str("input = { ");
	for (i, chain_id) in chain_ids.iter().enumerate() {
		if i > 0 {
			config.push_str(", ");
		}
		let oracle_addr = placeholders
			.get(&format!("ORACLE_PLACEHOLDER_INPUT_{}", chain_id))
			.ok_or_else(|| anyhow!("Missing ORACLE_PLACEHOLDER_INPUT_{}", chain_id))?;
		config.push_str(&format!("{} = [\n    \"{}\",\n]", chain_id, oracle_addr));
	}
	config.push_str(" }\n");

	// Output oracles
	config.push_str("# Output oracles (on destination chains)\n");
	config.push_str("output = { ");
	for (i, chain_id) in chain_ids.iter().enumerate() {
		if i > 0 {
			config.push_str(", ");
		}
		let oracle_addr = placeholders
			.get(&format!("ORACLE_PLACEHOLDER_OUTPUT_{}", chain_id))
			.ok_or_else(|| anyhow!("Missing ORACLE_PLACEHOLDER_OUTPUT_{}", chain_id))?;
		config.push_str(&format!("{} = [\n    \"{}\",\n]", chain_id, oracle_addr));
	}
	config.push_str(" }\n\n");

	// Valid routes
	config.push_str("# Valid routes: from origin chain -> to destination chains\n");
	config.push_str("[settlement.implementations.direct.routes]\n");

	for from_chain in chain_ids {
		let to_chains: Vec<u64> = chain_ids
			.iter()
			.filter(|&c| c != from_chain)
			.cloned()
			.collect();
		if !to_chains.is_empty() {
			config.push_str(&format!("{} = {:?}\n", from_chain, to_chains));
		}
	}

	Ok(())
}

/// Generate networks.toml configuration
pub fn generate_networks_config(chain_ids: &[u64]) -> Result<String> {
	let placeholders = generate_placeholder_map(chain_ids);
	let mut config = String::new();

	// Header
	config.push_str("# Network Configuration - Generated with Placeholders\n");
	config.push_str("# Defines all supported blockchain networks and their tokens\n\n");

	// Generate configuration for each chain
	for (idx, chain_id) in chain_ids.iter().enumerate() {
		config.push_str(&format!("[networks.{}]\n", chain_id));

		// Contract addresses
		let input_settler = placeholders
			.get(&format!("PLACEHOLDER_INPUT_SETTLER_{}", chain_id))
			.ok_or_else(|| anyhow!("Missing PLACEHOLDER_INPUT_SETTLER_{}", chain_id))?;
		config.push_str(&format!("input_settler_address = \"{}\"\n", input_settler));

		let compact = placeholders
			.get(&format!("PLACEHOLDER_COMPACT_{}", chain_id))
			.ok_or_else(|| anyhow!("Missing PLACEHOLDER_COMPACT_{}", chain_id))?;
		config.push_str(&format!(
			"input_settler_compact_address = \"{}\"\n",
			compact
		));
		config.push_str(&format!("the_compact_address = \"{}\"\n", compact));

		let allocator = placeholders
			.get(&format!("PLACEHOLDER_ALLOCATOR_{}", chain_id))
			.ok_or_else(|| anyhow!("Missing PLACEHOLDER_ALLOCATOR_{}", chain_id))?;
		config.push_str(&format!("allocator_address = \"{}\"\n", allocator));

		let output_settler = placeholders
			.get(&format!("PLACEHOLDER_OUTPUT_SETTLER_{}", chain_id))
			.ok_or_else(|| anyhow!("Missing PLACEHOLDER_OUTPUT_SETTLER_{}", chain_id))?;
		config.push_str(&format!(
			"output_settler_address = \"{}\"\n\n",
			output_settler
		));

		// RPC endpoints
		config.push_str("# RPC endpoints with both HTTP and WebSocket URLs for each network\n");
		config.push_str(&format!("[[networks.{}.rpc_urls]]\n", chain_id));

		let port = 8545 + idx;
		config.push_str(&format!("http = \"http://localhost:{}\"\n", port));
		config.push_str(&format!("ws = \"ws://localhost:{}\"\n\n", port));

		// Token configurations
		config.push_str(&format!("[[networks.{}.tokens]]\n", chain_id));
		let token_a = placeholders
			.get(&format!("PLACEHOLDER_TOKEN_A_{}", chain_id))
			.ok_or_else(|| anyhow!("Missing PLACEHOLDER_TOKEN_A_{}", chain_id))?;
		config.push_str(&format!("address = \"{}\"\n", token_a));
		config.push_str("symbol = \"TOKA\"\n");
		config.push_str("decimals = 6\n\n");

		config.push_str(&format!("[[networks.{}.tokens]]\n", chain_id));
		let token_b = placeholders
			.get(&format!("PLACEHOLDER_TOKEN_B_{}", chain_id))
			.ok_or_else(|| anyhow!("Missing PLACEHOLDER_TOKEN_B_{}", chain_id))?;
		config.push_str(&format!("address = \"{}\"\n", token_b));
		config.push_str("symbol = \"TOKB\"\n");
		config.push_str("decimals = 6\n\n");
	}

	Ok(config)
}

/// Generate gas.toml configuration
pub fn generate_gas_config() -> Result<String> {
	let mut config = String::new();

	config.push_str("[gas]\n\n");

	config.push_str("[gas.flows.resource_lock]\n");
	config.push_str("# Gas units captured by scripts/e2e/estimate_gas.sh on local anvil\n");
	config.push_str("open = 0\n");
	config.push_str("fill = 77298\n");
	config.push_str("claim = 122793\n\n");

	config.push_str("[gas.flows.permit2_escrow]\n");
	config.push_str("# Gas units captured by scripts/e2e/estimate_gas.sh on local anvil\n");
	config.push_str("open = 146306\n");
	config.push_str("fill = 77298\n");
	config.push_str("claim = 60084\n\n");

	config.push_str("[gas.flows.eip3009_escrow]\n");
	config.push_str("# Gas units captured by scripts/e2e/estimate_gas.sh on local anvil\n");
	config.push_str("open = 130254\n");
	config.push_str("fill = 77298\n");
	config.push_str("claim = 60084\n");

	Ok(config)
}

/// Generate api.toml configuration
pub fn generate_api_config() -> Result<String> {
	let mut config = String::new();

	config.push_str("# API Server Configuration\n");
	config.push_str("# Configures the HTTP API for receiving off-chain intents\n\n");

	config.push_str("[api]\n");
	config.push_str("enabled = true\n");
	config.push_str("host = \"127.0.0.1\"\n");
	config.push_str("port = 3000\n");
	config.push_str("timeout_seconds = 30\n");
	config.push_str("max_request_size = 1048576  # 1MB\n\n");

	config.push_str("[api.implementations]\n");
	config.push_str("discovery = \"offchain_eip7683\"\n\n");

	config.push_str("# JWT Authentication Configuration\n");
	config.push_str("[api.auth]\n");
	config.push_str("enabled = true\n");
	config.push_str("jwt_secret = \"${JWT_SECRET:-MySuperDuperSecureSecret123!}\"\n");
	config.push_str("access_token_expiry_hours = 1\n");
	config.push_str("refresh_token_expiry_hours = 720  # 30 days\n");
	config.push_str("issuer = \"oif-solver-demo\"\n\n");

	config.push_str("# Quote Configuration\n");
	config.push_str("[api.quote]\n");
	config.push_str("# Quote validity duration in seconds\n");
	config.push_str("# Default is 20 seconds. Customize as needed:\n");
	config.push_str("validity_seconds = 60  # 1 minute validity\n");

	Ok(config)
}
