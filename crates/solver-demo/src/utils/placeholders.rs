use std::collections::HashMap;

/// Contract placeholder keys
pub const PLACEHOLDER_INPUT_SETTLER_PREFIX: &str = "PLACEHOLDER_INPUT_SETTLER_";
pub const PLACEHOLDER_OUTPUT_SETTLER_PREFIX: &str = "PLACEHOLDER_OUTPUT_SETTLER_";
pub const PLACEHOLDER_COMPACT_PREFIX: &str = "PLACEHOLDER_COMPACT_";
pub const PLACEHOLDER_INPUT_SETTLER_COMPACT_PREFIX: &str = "PLACEHOLDER_INPUT_SETTLER_COMPACT_";
pub const PLACEHOLDER_ALLOCATOR_PREFIX: &str = "PLACEHOLDER_ALLOCATOR_";
pub const PLACEHOLDER_TOKEN_A_PREFIX: &str = "PLACEHOLDER_TOKEN_A_";
pub const PLACEHOLDER_TOKEN_B_PREFIX: &str = "PLACEHOLDER_TOKEN_B_";
pub const ORACLE_PLACEHOLDER_INPUT_PREFIX: &str = "ORACLE_PLACEHOLDER_INPUT_";
pub const ORACLE_PLACEHOLDER_OUTPUT_PREFIX: &str = "ORACLE_PLACEHOLDER_OUTPUT_";
pub const PLACEHOLDER_SETTLEMENT_DOMAIN: &str = "PLACEHOLDER_SETTLEMENT_DOMAIN";

/// Starting counter for placeholder addresses
pub const PLACEHOLDER_START_COUNTER: u64 = 1000; // 0x3e8

/// Generate placeholder addresses for contracts
pub fn generate_placeholder_map(chain_ids: &[u64]) -> HashMap<String, String> {
	let mut map = HashMap::new();
	let mut counter = PLACEHOLDER_START_COUNTER;

	// Settlement domain placeholder
	map.insert(
		PLACEHOLDER_SETTLEMENT_DOMAIN.to_string(),
		format!("0x{:040x}", counter),
	);
	counter += 1;

	// Generate placeholders for each chain
	for chain_id in chain_ids {
		// Input settler
		map.insert(
			format!("{}{}", PLACEHOLDER_INPUT_SETTLER_PREFIX, chain_id),
			format!("0x{:040x}", counter),
		);
		counter += 1;

		// Output settler
		map.insert(
			format!("{}{}", PLACEHOLDER_OUTPUT_SETTLER_PREFIX, chain_id),
			format!("0x{:040x}", counter),
		);
		counter += 1;

		// Compact
		map.insert(
			format!("{}{}", PLACEHOLDER_COMPACT_PREFIX, chain_id),
			format!("0x{:040x}", counter),
		);
		counter += 1;

		// InputSettlerCompact
		map.insert(
			format!("{}{}", PLACEHOLDER_INPUT_SETTLER_COMPACT_PREFIX, chain_id),
			format!("0x{:040x}", counter),
		);
		counter += 1;

		// Allocator
		map.insert(
			format!("{}{}", PLACEHOLDER_ALLOCATOR_PREFIX, chain_id),
			format!("0x{:040x}", counter),
		);
		counter += 1;

		// Tokens
		map.insert(
			format!("{}{}", PLACEHOLDER_TOKEN_A_PREFIX, chain_id),
			format!("0x{:040x}", counter),
		);
		counter += 1;

		map.insert(
			format!("{}{}", PLACEHOLDER_TOKEN_B_PREFIX, chain_id),
			format!("0x{:040x}", counter),
		);
		counter += 1;

		// Oracles
		map.insert(
			format!("{}{}", ORACLE_PLACEHOLDER_INPUT_PREFIX, chain_id),
			format!("0x{:040x}", counter),
		);
		counter += 1;

		map.insert(
			format!("{}{}", ORACLE_PLACEHOLDER_OUTPUT_PREFIX, chain_id),
			format!("0x{:040x}", counter),
		);
		counter += 1;
	}

	map
}

/// Get the placeholder address for a specific contract on a chain
pub fn get_placeholder_for_contract(chain_id: u64, contract_type: &str) -> String {
	let key = match contract_type {
		"input_settler" => format!("{}{}", PLACEHOLDER_INPUT_SETTLER_PREFIX, chain_id),
		"output_settler" => format!("{}{}", PLACEHOLDER_OUTPUT_SETTLER_PREFIX, chain_id),
		"compact" | "the_compact" => format!("{}{}", PLACEHOLDER_COMPACT_PREFIX, chain_id),
		"input_settler_compact" => {
			format!("{}{}", PLACEHOLDER_INPUT_SETTLER_COMPACT_PREFIX, chain_id)
		},
		"allocator" => format!("{}{}", PLACEHOLDER_ALLOCATOR_PREFIX, chain_id),
		"token_a" | "toka" => format!("{}{}", PLACEHOLDER_TOKEN_A_PREFIX, chain_id),
		"token_b" | "tokb" => format!("{}{}", PLACEHOLDER_TOKEN_B_PREFIX, chain_id),
		"oracle_input" => format!("{}{}", ORACLE_PLACEHOLDER_INPUT_PREFIX, chain_id),
		"oracle_output" => format!("{}{}", ORACLE_PLACEHOLDER_OUTPUT_PREFIX, chain_id),
		_ => return String::new(),
	};

	let chain_ids = vec![chain_id];
	let map = generate_placeholder_map(&chain_ids);
	map.get(&key).cloned().unwrap_or_default()
}
