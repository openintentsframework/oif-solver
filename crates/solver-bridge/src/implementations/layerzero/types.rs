//! LayerZero bridge-specific configuration and types.

use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// LayerZero bridge transport configuration.
/// Deserialized from `bridge_config` JSON in `OperatorRebalanceConfig`.
///
/// Composer/vault addresses on this struct are the legacy chain-keyed shape
/// kept for ERC-20 pairs that haven't migrated. New per-pair routing lives in
/// `LayerZeroBridgeRoute` (deserialized from each pair's `bridge_route` field
/// and snapshotted onto the transfer at submission).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerZeroBridgeConfig {
	/// Maps chain_id -> LayerZero endpoint ID (EID).
	pub endpoint_ids: HashMap<u64, u32>,

	/// Gas limit for lzReceive on destination (default: 200_000).
	#[serde(default = "default_lz_receive_gas")]
	pub lz_receive_gas: u128,

	/// Composer contract addresses per chain (for vault deposit + bridge).
	/// Legacy chain-keyed shape; new pairs should declare composer in their
	/// per-pair `bridge_route` instead.
	#[serde(default)]
	pub composer_addresses: HashMap<u64, String>,

	/// Vault addresses per chain (for ERC-4626 deposit/redeem).
	/// **Deprecated path** — same migration plan as `composer_addresses`.
	#[serde(default)]
	pub vault_addresses: HashMap<u64, String>,
}

fn default_lz_receive_gas() -> u128 {
	200_000
}

// ----------------------------------------------------------------------------
// Per-pair route
// ----------------------------------------------------------------------------

/// Per-pair LayerZero/OVault route. Operator-supplied in
/// `OperatorRebalancePairConfig.bridge_route` as JSON; deserialized lazily by
/// the LayerZero bridge implementation via the `TransferMetadata.bridge_route`
/// snapshot. Self-describing: each side carries its own `chain_id` so the
/// route stays valid across resume without consulting the pair config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerZeroBridgeRoute {
	/// OVault Composer on the vault's chain.
	pub composer: Address,
	/// Chain where the composer + vault live. Used by preflight to dispatch
	/// `composer.VAULT()` / `composer.SHARE_OFT()` / `composer.ASSET_ERC20()`
	/// calls to the right RPC. Verified at preflight to match one of the
	/// pair's chain IDs.
	pub composer_chain_id: u64,
	/// ERC-4626 vault address (matches `composer.VAULT()`).
	pub vault: Address,
	/// Route data for the `pair.chain_a` side.
	pub chain_a: SideRoute,
	/// Route data for the `pair.chain_b` side.
	pub chain_b: SideRoute,
}

/// One side of a `LayerZeroBridgeRoute`.
///
/// Self-describing: `chain_id` is embedded so the route is fully usable from a
/// persisted `route_snapshot` without consulting the pair config (the persisted
/// transfer only has `source_chain` / `dest_chain`, not the canonical pair
/// chain IDs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SideRoute {
	/// Chain this side refers to (matches the pair-side's `chain_id`).
	pub chain_id: u64,
	/// Whether the OFT on this side requires an `approve()` before `send()`.
	/// Operator-supplied; verified at engine startup by `LayerZeroBridge::preflight`
	/// against on-chain `approvalRequired()`. NOT verified in `config_merge`
	/// (which is sync and has no `DeliveryService`).
	pub approval_required: bool,
	/// Wrapper config when the corresponding pair side is native
	/// (`pair.chain_x.token_address == 0x000…`). Absent for ERC-20 sides.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub wrapper: Option<WrapperConfig>,
}

/// Wrapper config for a native pair side (e.g., WETH for native ETH on
/// Ethereum, vbETH for native ETH on Katana).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapperConfig {
	/// Wrapper contract address (e.g., WETH9 or vbETH).
	pub address: Address,
	/// Which wrap/unwrap ABI the bridge implementation should use.
	pub strategy: WrapStrategy,
}

/// Which `deposit()`/`withdraw()` ABI shape the wrapper follows. Only `Weth9`
/// today; enum scaffolded so non-WETH9 wrappers (e.g., AggLayer
/// `NativeConverter`) can be added without a refactor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WrapStrategy {
	/// WETH9 interface: `deposit() payable` + `withdraw(uint256)`. Used by both
	/// Ethereum WETH (`0xC02a…6Cc2`) and Katana vbETH (`0xEE7D…aB62` — the
	/// vault-bridge `CustomTokenWethExtension`).
	Weth9,
}

impl LayerZeroBridgeRoute {
	/// Resolve a side by chain_id. Returns `None` if `target_chain` is not in
	/// the route — config validation should have caught this earlier; callers
	/// can `expect` if appropriate.
	pub fn resolve_side(&self, target_chain: u64) -> Option<&SideRoute> {
		if target_chain == self.chain_a.chain_id {
			Some(&self.chain_a)
		} else if target_chain == self.chain_b.chain_id {
			Some(&self.chain_b)
		} else {
			None
		}
	}
}
