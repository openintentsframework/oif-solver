//! Types for the admin API request/response payloads.

use crate::{auth::AdminRole, networks::NetworkType};
use serde::Serialize;
use std::collections::HashMap;

/// Response for nonce generation.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NonceResponse {
	pub nonce: String,
	pub expires_in: u64,
	pub domain: String,
	pub chain_id: u64,
}

/// Response for successful admin actions.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminActionResponse {
	pub success: bool,
	pub message: String,
	pub admin: String,
}

/// Response for reading the admin whitelist.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminWhitelistResponse {
	pub entries: Vec<AdminWhitelistEntry>,
	pub count: usize,
}

/// Typed admin whitelist entry response.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminWhitelistEntry {
	pub address: String,
	pub role: AdminRole,
}

/// Response for balances across networks.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BalancesResponse {
	pub solver_address: String,
	pub networks: HashMap<String, ChainBalances>,
}

/// Per-chain balances with optional error information.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainBalances {
	pub chain_id: u64,
	pub tokens: Vec<TokenBalance>,
	pub error: Option<String>,
}

/// Token balance with formatted value.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenBalance {
	pub address: String,
	pub symbol: String,
	pub name: Option<String>,
	pub decimals: u8,
	pub balance: String,
	pub balance_formatted: String,
}

/// Response for gas configuration read.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GasConfigResponse {
	pub resource_lock: GasFlowResponse,
	pub permit2_escrow: GasFlowResponse,
	pub eip3009_escrow: GasFlowResponse,
}

/// Gas flow units response.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GasFlowResponse {
	pub open: u64,
	pub fill: u64,
	pub post_fill: u64,
	pub pre_claim: u64,
	pub claim: u64,
}

/// Response for admin config read (redacted).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminConfigResponse {
	pub solver_id: String,
	pub solver_name: Option<String>,
	pub networks: Vec<AdminNetworkResponse>,
	pub solver: AdminSolverResponse,
	pub gas: GasConfigResponse,
	pub admin: AdminConfigSummary,
	pub version: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminNetworkResponse {
	pub chain_id: u64,
	pub name: String,
	#[serde(rename = "type")]
	pub network_type: NetworkType,
	pub rpc_urls: Vec<String>,
	pub tokens: Vec<AdminTokenResponse>,
	pub input_settler: String,
	pub output_settler: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminTokenResponse {
	pub symbol: String,
	pub name: Option<String>,
	pub address: String,
	pub decimals: u8,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminSolverResponse {
	pub min_profitability_pct: String,
	pub gas_buffer_bps: u32,
	pub commission_bps: u32,
	pub rate_buffer_bps: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminConfigSummary {
	pub enabled: bool,
	pub domain: String,
	pub withdrawals_enabled: bool,
	/// Pre-approved recipient addresses for `POST /admin/withdrawals`. Empty
	/// means no constraint (any recipient is accepted); non-empty means the
	/// recipient must match one of these entries.
	#[serde(default)]
	pub withdrawal_recipient_allowlist: Vec<String>,
}

/// Response for fee configuration read.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FeeConfigResponse {
	pub min_profitability_pct: String,
	pub gas_buffer_bps: u32,
	pub commission_bps: u32,
	pub rate_buffer_bps: u32,
	pub monitoring_timeout_seconds: u64,
}

/// Response for approve tokens action with details.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApproveTokensResponse {
	pub success: bool,
	pub message: String,
	pub admin: String,
	pub approved_count: usize,
	pub chains_processed: Vec<u64>,
}

/// Response for withdrawal action.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalResponse {
	pub success: bool,
	pub status: String,
	pub message: String,
	pub admin: String,
	pub tx_hash: Option<String>,
}

/// EIP-712 type information for client-side signing.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Eip712TypeInfo {
	pub domain: Eip712Domain,
	pub types: serde_json::Value,
}

/// EIP-712 domain published to admin clients.
///
/// `verifyingContract` is intentionally absent because admin signatures are
/// verified off-chain. `salt` is included so clients pin their signature to
/// this specific solver instance, preventing cross-solver replay when the same
/// admin key is authorized on multiple deployments.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Eip712Domain {
	pub name: String,
	pub version: String,
	pub chain_id: u64,
	/// 0x-prefixed hex of the 32-byte domain salt.
	pub salt: String,
}
