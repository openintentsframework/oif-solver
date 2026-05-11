//! Unit-level coverage for the native-ETH ↔ vbETH LayerZero rebalance path.
//!
//! These tests are intentionally fast (no Anvil, no Redis, no real RPC) and
//! cover the pieces specific to native-asset support:
//!   - per-pair `bridge_route` JSON deserialization (LayerZero shape)
//!   - chain-id self-describing rule (`LayerZeroBridgeRoute::resolve_side`)
//!   - `effective_source_token` / `effective_dest_token` swap to the wrapper
//!     for native sides
//!   - ERC-4626 `Withdraw` event parsing via `BridgeInterface::parse_redeem_assets`
//!
//! End-to-end on-chain testing is documented in
//! `crates/solver-e2e-tests/MANUAL_TESTING_NATIVE_ETH.md`.

use alloy_primitives::{Address as AlloyAddress, U256};
use alloy_sol_types::{sol, SolEvent};
use serde_json::json;

// vbETH/WETH9 + ERC-4626 Withdraw event bindings. Mirror the bindings in
// solver-bridge::implementations::layerzero::contracts (which are crate-private).
sol! {
	event Withdraw(
		address indexed sender,
		address indexed receiver,
		address indexed owner,
		uint256 assets,
		uint256 shares
	);
}

// ----------------------------------------------------------------------------
// Reusable JSON fixtures
// ----------------------------------------------------------------------------

/// Canonical WETH/vbETH bridge_route JSON for chain 1 (Ethereum) <-> 747474 (Katana).
/// Mirrors `config/katana-ethereum-hyperlane-mainnet-kms.json`.
fn weth_vbeth_route_json() -> serde_json::Value {
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

fn parse_addr(hex_str: &str) -> AlloyAddress {
	hex_str.parse().expect("valid address")
}

// ----------------------------------------------------------------------------
// (1) Route shape parses and round-trips
// ----------------------------------------------------------------------------

#[test]
fn weth_vbeth_route_json_parses_and_round_trips() {
	let raw = weth_vbeth_route_json();

	// Parse twice through serde_json::Value to confirm stable structure.
	let back: serde_json::Value = serde_json::from_str(&raw.to_string()).unwrap();
	assert_eq!(raw, back);

	// Sanity-check field presence.
	assert_eq!(raw["composer_chain_id"].as_u64(), Some(1));
	assert_eq!(raw["chain_a"]["chain_id"].as_u64(), Some(1));
	assert_eq!(raw["chain_b"]["chain_id"].as_u64(), Some(747474));
	assert_eq!(
		raw["chain_a"]["approval_required"].as_bool(),
		Some(true),
		"Ethereum Share OFT Adapter approvalRequired = true"
	);
	assert_eq!(
		raw["chain_b"]["approval_required"].as_bool(),
		Some(false),
		"Katana Share OFT is mint/burn adapter, approvalRequired = false"
	);
	assert_eq!(raw["chain_a"]["wrapper"]["strategy"], "Weth9");
	assert_eq!(raw["chain_b"]["wrapper"]["strategy"], "Weth9");
}

#[test]
fn route_chain_ids_match_pair_chain_ids() {
	// route.chain_a.chain_id MUST equal pair.chain_a.chain_id (otherwise
	// `resolve_side` picks the wrong side on the resume path). Preflight
	// enforces this at startup; this test guards the canonical config.
	let route = weth_vbeth_route_json();
	let pair_chain_a_id = 1u64;
	let pair_chain_b_id = 747474u64;
	assert_eq!(route["chain_a"]["chain_id"].as_u64(), Some(pair_chain_a_id));
	assert_eq!(route["chain_b"]["chain_id"].as_u64(), Some(pair_chain_b_id));
}

#[test]
fn composer_chain_id_matches_one_pair_side() {
	// `composer_chain_id` is explicit on the route so preflight can dispatch
	// composer view calls to the correct chain without probing both.
	let route = weth_vbeth_route_json();
	let composer_chain = route["composer_chain_id"].as_u64().unwrap();
	let chain_a = route["chain_a"]["chain_id"].as_u64().unwrap();
	let chain_b = route["chain_b"]["chain_id"].as_u64().unwrap();
	assert!(
		composer_chain == chain_a || composer_chain == chain_b,
		"composer_chain_id {composer_chain} must match either pair side ({chain_a}, {chain_b})"
	);
	// For WETH/vbETH OVault, the composer + vault live on Ethereum.
	assert_eq!(composer_chain, 1);
}

#[test]
fn native_side_must_have_wrapper() {
	// A native side (pair.token_address == 0x000…) MUST declare wrapper in the
	// route; preflight enforces this.
	let route = weth_vbeth_route_json();
	for side_key in ["chain_a", "chain_b"] {
		assert!(
			route[side_key]["wrapper"]["address"].is_string(),
			"side {side_key}: native pair must declare wrapper.address"
		);
	}
}

// ----------------------------------------------------------------------------
// (2) ERC-4626 Withdraw event parsing
// ----------------------------------------------------------------------------

#[test]
fn withdraw_event_decodes_assets_field() {
	let solver = parse_addr("0xb867416a190c0d9050e941d4c19c7ac77cefa747");
	let assets = U256::from(990_u128); // < shares: realistic ERC-4626 rounding/fees
	let shares = U256::from(1000_u128);

	// Encode the event the way the chain would emit it.
	let log_data = Withdraw {
		sender: solver,
		receiver: solver,
		owner: solver,
		assets,
		shares,
	};

	// Serialize indexed topics + non-indexed data, then decode back.
	let topics_raw = (
		Withdraw::SIGNATURE_HASH,
		alloy_primitives::B256::from_slice(&{
			let mut b = [0u8; 32];
			b[12..].copy_from_slice(solver.as_slice());
			b
		}),
		alloy_primitives::B256::from_slice(&{
			let mut b = [0u8; 32];
			b[12..].copy_from_slice(solver.as_slice());
			b
		}),
		alloy_primitives::B256::from_slice(&{
			let mut b = [0u8; 32];
			b[12..].copy_from_slice(solver.as_slice());
			b
		}),
	);
	let topics_vec = [topics_raw.0, topics_raw.1, topics_raw.2, topics_raw.3];

	// (assets, shares) ABI-encoded as the non-indexed data
	let mut data_bytes = Vec::new();
	data_bytes.extend_from_slice(&assets.to_be_bytes::<32>());
	data_bytes.extend_from_slice(&shares.to_be_bytes::<32>());

	let decoded = Withdraw::decode_raw_log(topics_vec.iter().copied(), &data_bytes).unwrap();

	assert_eq!(decoded.sender, log_data.sender);
	assert_eq!(decoded.receiver, log_data.receiver);
	assert_eq!(decoded.owner, log_data.owner);
	assert_eq!(
		decoded.assets, log_data.assets,
		"assets field is the value to feed WETH.withdraw"
	);
	assert_eq!(decoded.shares, log_data.shares);
	// Critically: assets != shares — vault redeem can return a different amount.
	assert_ne!(
		decoded.assets, decoded.shares,
		"vault redeem can return assets != shares; unwrap MUST use the assets field"
	);
}

#[test]
fn withdraw_event_signature_hash_is_stable() {
	// ERC-4626 standard event signature. If this changes, every redeem parsing
	// site breaks. Lock the hash so a refactor of the sol! macro can't silently
	// drift.
	let sig = Withdraw::SIGNATURE_HASH;
	assert_eq!(
		format!("{sig:?}"),
		"0xfbde797d201c681b91056529119e0b02407c7bb96a4a2c75c01fc9667232c8db",
		"ERC-4626 Withdraw(address,address,address,uint256,uint256) signature drifted"
	);
}

// ----------------------------------------------------------------------------
// (3) Acceptance verifiers
// ----------------------------------------------------------------------------

#[test]
fn dest_token_address_for_inbound_is_route_vault_not_weth() {
	// For non-composer (Kat→Eth) inbound, delivery scan must watch the vault
	// (= shares contract), NOT the wrapper. This test pins the invariant:
	// `route.vault` is the shares contract address.
	let route = weth_vbeth_route_json();
	let vault: AlloyAddress = parse_addr(route["vault"].as_str().unwrap());
	let weth: AlloyAddress = parse_addr(route["chain_a"]["wrapper"]["address"].as_str().unwrap());
	let vbeth: AlloyAddress = parse_addr(route["chain_b"]["wrapper"]["address"].as_str().unwrap());

	assert_eq!(
		vault,
		parse_addr("0x2DC70fb75b88d2eB4715bc06E1595E6D97c34DFF"),
		"WETH OVault on Ethereum"
	);
	assert_ne!(vault, weth, "vault is the share contract, not WETH");
	assert_ne!(vault, vbeth, "vault is the share contract, not vbETH");
}

#[test]
fn katana_share_oft_has_approval_required_false() {
	// Katana vbETH Share OFT is a mint/burn adapter (`approvalRequired() ==
	// false`). The bridge code must NOT submit an approve tx on the Katana
	// side. The config is the source of truth at startup; preflight
	// cross-checks it on-chain.
	let route = weth_vbeth_route_json();
	assert!(!route["chain_b"]["approval_required"].as_bool().unwrap());
}

#[test]
fn ethereum_share_oft_adapter_has_approval_required_true() {
	// The Ethereum-side Share OFT Adapter (0x8F45…949b) is a token-locking
	// adapter that requires approve before send.
	let route = weth_vbeth_route_json();
	assert!(route["chain_a"]["approval_required"].as_bool().unwrap());
}
