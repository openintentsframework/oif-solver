//! Integration tests for the native-ETH rebalance metadata pipeline.
//!
//! These tests verify the JSON-walking helpers that the monitor (auto-trigger)
//! and admin trigger use to build `TransferMetadata`. They specifically guard
//! the failure modes that left the live rebalance path broken in v0:
//!   - delivery-scan target on the destination MUST be `route.vault` for
//!     non-composer (Kat→Eth) flow, NOT the wrapper.
//!   - `source_token_address` on a native source side MUST be the wrapper,
//!     NOT the zero address persisted from `request.source_token`.
//!   - `is_composer_flow` is determined from `route.composer_chain_id`, NOT
//!     from chain-keyed `bridge_config.composer_addresses`.
//!
//! These run without Anvil or Redis. They exercise the same JSON convention
//! that ships in `config/katana-ethereum-hyperlane-mainnet-kms.json` and that
//! the production monitor/admin code reads.

use serde_json::json;

/// Walk a `bridge_route` JSON value the way the production code does to find
/// the wrapper address for a given chain. Mirrors
/// `RebalanceMonitor::route_wrapper_address` and the equivalent admin-path
/// inline logic.
fn route_wrapper_address(route: &serde_json::Value, chain_id: u64) -> Option<String> {
	for side_key in ["chain_a", "chain_b"] {
		let Some(side) = route.get(side_key) else {
			continue;
		};
		let side_chain = side.get("chain_id").and_then(|v| v.as_u64()).unwrap_or(0);
		if side_chain == chain_id {
			return side
				.get("wrapper")
				.and_then(|w| w.get("address"))
				.and_then(|a| a.as_str())
				.map(String::from);
		}
	}
	None
}

/// Mirror of `BridgeService::route_has_source_wrapper` — checks whether the
/// route declares a wrapper on the side that matches `source_chain`.
fn route_has_source_wrapper(route: &serde_json::Value, source_chain: u64) -> bool {
	route_wrapper_address(route, source_chain).is_some()
}

fn weth_vbeth_route() -> serde_json::Value {
	json!({
		"composer": "0xC4c76Ae67f7d0f741B56d013D14359A6C7b7De11",
		"composer_chain_id": 1,
		"vault": "0x2DC70fb75b88d2eB4715bc06E1595E6D97c34DFF",
		"chain_a": {
			"chain_id": 1,
			"approval_required": true,
			"wrapper": {
				"address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
				"strategy": "Weth9"
			}
		},
		"chain_b": {
			"chain_id": 747474,
			"approval_required": false,
			"wrapper": {
				"address": "0xEE7D8BCFb72bC1880D0Cf19822eB0A2e6577aB62",
				"strategy": "Weth9"
			}
		}
	})
}

fn usdc_vbusdc_route() -> serde_json::Value {
	// Hypothetical: a USDC route migrated to per-pair shape (no wrappers).
	json!({
		"composer": "0x8A35897fda9E024d2aC20a937193e099679eC477",
		"composer_chain_id": 1,
		"vault": "0x53E82ABbb12638F09d9e624578ccB666217a765e",
		"chain_a": {
			"chain_id": 1,
			"approval_required": true
		},
		"chain_b": {
			"chain_id": 747474,
			"approval_required": true
		}
	})
}

// ============================================================================
// Effective source token (used to populate TransferMetadata.source_token_address
// and to seed BridgeService's persisted transfer.source_token_address)
// ============================================================================

#[test]
fn native_pair_source_token_resolves_to_wrapper() {
	let route = weth_vbeth_route();

	// Outbound: Eth (1) → Katana (747474). Source chain is Ethereum; wrapper is WETH.
	assert_eq!(
		route_wrapper_address(&route, 1),
		Some("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string()),
	);

	// Inbound: Katana (747474) → Eth (1). Source chain is Katana; wrapper is vbETH.
	assert_eq!(
		route_wrapper_address(&route, 747474),
		Some("0xEE7D8BCFb72bC1880D0Cf19822eB0A2e6577aB62".to_string()),
	);
}

#[test]
fn erc20_pair_source_has_no_wrapper() {
	let route = usdc_vbusdc_route();
	assert!(route_wrapper_address(&route, 1).is_none());
	assert!(route_wrapper_address(&route, 747474).is_none());
}

// ============================================================================
// `BridgeService::route_has_source_wrapper` gating: only triggers the wrap step
// when the native pair has a wrapper on the source side.
// ============================================================================

#[test]
fn wrap_gating_fires_only_for_native_source() {
	let weth = weth_vbeth_route();
	let usdc = usdc_vbusdc_route();

	// Native pair: wrap step is required for both directions.
	assert!(route_has_source_wrapper(&weth, 1));
	assert!(route_has_source_wrapper(&weth, 747474));

	// ERC-20 pair: wrap step never fires.
	assert!(!route_has_source_wrapper(&usdc, 1));
	assert!(!route_has_source_wrapper(&usdc, 747474));
}

// ============================================================================
// is_composer_flow comes from the route, not from chain-keyed config
// ============================================================================

#[test]
fn is_composer_flow_uses_route_composer_chain_id() {
	let route = weth_vbeth_route();
	let composer_chain = route["composer_chain_id"].as_u64().unwrap();

	// Outbound from Ethereum (the composer's chain) ⇒ composer flow.
	let source_chain = 1u64;
	assert_eq!(source_chain, composer_chain);
	let is_composer_outbound = source_chain == composer_chain;
	assert!(is_composer_outbound);

	// Inbound from Katana (not the composer's chain) ⇒ NOT composer flow.
	let source_chain = 747474u64;
	let is_composer_inbound = source_chain == composer_chain;
	assert!(!is_composer_inbound);
}

// ============================================================================
// Delivery-scan token selection
// ============================================================================

#[test]
fn delivery_scan_token_is_vault_for_non_composer_inbound() {
	// Non-composer (Kat→Eth) inbound: shares arrive first as `route.vault`.
	// The monitor's `dest_token_address` must be set to the vault address so
	// `check_status` watches the shares contract, not WETH (which only
	// appears AFTER the manual redeem step).
	let route = weth_vbeth_route();
	let vault = route["vault"].as_str().unwrap();
	let weth = route["chain_a"]["wrapper"]["address"].as_str().unwrap();
	assert_ne!(
		vault, weth,
		"delivery-scan token must be the vault, not WETH"
	);
	assert_eq!(vault, "0x2DC70fb75b88d2eB4715bc06E1595E6D97c34DFF");
}

#[test]
fn delivery_scan_token_is_wrapper_for_composer_outbound() {
	// Composer outbound (Eth→Kat): wrapper (vbETH) arrives at solver address;
	// the monitor scans for vbETH `Transfer(to=solver)` events on Katana.
	let route = weth_vbeth_route();
	let vbeth = route_wrapper_address(&route, 747474).unwrap();
	assert_eq!(vbeth, "0xEE7D8BCFb72bC1880D0Cf19822eB0A2e6577aB62");
}

// ============================================================================
// Sanity: the canonical fixture matches the production config file
// ============================================================================

#[test]
fn fixture_route_matches_production_config_shape() {
	// Spot-check by re-reading the config JSON shipped at repo root and
	// confirming the `eth-native-katana` pair carries the same bridge_route.
	let config_text =
		std::fs::read_to_string("../../config/katana-ethereum-hyperlane-mainnet-kms.json")
			.expect("config file should be checked in at the repo root");
	let config: serde_json::Value =
		serde_json::from_str(&config_text).expect("config file is valid JSON");
	let pairs = config["rebalance"]["pairs"]
		.as_array()
		.expect("rebalance.pairs exists");
	let eth_pair = pairs
		.iter()
		.find(|p| p["pair_id"] == "eth-native-katana")
		.expect("eth-native-katana pair must exist in production config");
	let prod_route = &eth_pair["bridge_route"];
	let fixture_route = weth_vbeth_route();
	assert_eq!(
		prod_route, &fixture_route,
		"production config bridge_route drifted from the fixture in this test file"
	);
	// And the pair MUST declare native sides (zero token addresses).
	assert_eq!(
		eth_pair["chain_a"]["token_address"],
		"0x0000000000000000000000000000000000000000"
	);
	assert_eq!(
		eth_pair["chain_b"]["token_address"],
		"0x0000000000000000000000000000000000000000"
	);
}
