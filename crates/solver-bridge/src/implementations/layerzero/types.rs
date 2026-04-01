//! LayerZero bridge-specific configuration and types.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// LayerZero bridge transport configuration.
/// Deserialized from `bridge_config` JSON in `OperatorRebalanceConfig`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerZeroBridgeConfig {
	/// Maps chain_id -> LayerZero endpoint ID (EID).
	pub endpoint_ids: HashMap<u64, u32>,

	/// Gas limit for lzReceive on destination (default: 200_000).
	#[serde(default = "default_lz_receive_gas")]
	pub lz_receive_gas: u128,

	/// Composer contract addresses per chain (for vault deposit + bridge).
	#[serde(default)]
	pub composer_addresses: HashMap<u64, String>,

	/// Vault addresses per chain (for ERC-4626 deposit/redeem).
	#[serde(default)]
	pub vault_addresses: HashMap<u64, String>,
}

fn default_lz_receive_gas() -> u128 {
	200_000
}
