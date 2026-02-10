//! Types for the admin API request/response payloads.

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
	pub claim: u64,
}

/// Response for admin config read (redacted).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminConfigResponse {
	pub solver_id: String,
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
	pub rpc_urls: Vec<String>,
	pub tokens: Vec<AdminTokenResponse>,
	pub input_settler: String,
	pub output_settler: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminTokenResponse {
	pub symbol: String,
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

/// EIP-712 domain (without verifyingContract - off-chain verification)
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Eip712Domain {
	pub name: String,
	pub version: String,
	pub chain_id: u64,
}
