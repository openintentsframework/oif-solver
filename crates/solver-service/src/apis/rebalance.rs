//! Admin API endpoints for cross-chain rebalancing.

use crate::apis::admin::{AdminApiState, VerifiedAdmin};
use crate::auth::admin::{
	AdminAuthError, ResolveTransferContents, TriggerRebalanceContents,
	UpdateRebalanceConfigContents, UpdateRebalanceThresholdContents,
};
use alloy_primitives::U256;
use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use solver_bridge::threshold::{analyze_pair, RebalanceDirection};
use solver_bridge::types::PendingBridgeTransfer;

// ---- Response Types ----

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RebalanceConfigResponse {
	pub enabled: bool,
	pub implementation: String,
	pub monitor_interval_seconds: u64,
	pub cooldown_seconds: u64,
	pub max_pending_transfers: u32,
	pub pairs: Vec<PairConfigResponse>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairConfigResponse {
	pub pair_id: String,
	pub chain_a: PairSideConfigResponse,
	pub chain_b: PairSideConfigResponse,
	pub target_balance_a: String,
	pub target_balance_b: String,
	pub deviation_band_bps: u32,
	pub max_bridge_amount: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairSideConfigResponse {
	pub chain_id: u64,
	pub token_address: String,
	pub oft_address: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RebalanceStatusResponse {
	pub pairs: Vec<PairRebalanceStatus>,
	pub active_transfers: usize,
	pub last_check_at: Option<u64>,
	pub next_check_at: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairRebalanceStatus {
	pub pair_id: String,
	pub chain_a: PairSideStatus,
	pub chain_b: PairSideStatus,
	pub deviation_band_bps: u32,
	pub direction_needed: Option<String>,
	pub suggested_amount: String,
	pub cooldown_active: bool,
	pub active_transfer_id: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairSideStatus {
	pub chain_id: u64,
	pub current_balance: String,
	pub target_balance: String,
	pub lower_bound: String,
	pub upper_bound: String,
	pub within_band: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RebalanceTransfersResponse {
	pub active: Vec<BridgeOperationResponse>,
	pub history: Vec<BridgeOperationResponse>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeOperationResponse {
	pub id: String,
	pub pair_id: String,
	pub source_chain_id: u64,
	pub destination_chain_id: u64,
	pub amount: String,
	pub status: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub status_reason: Option<String>,
	pub trigger: String,
	pub created_at: u64,
	pub updated_at: u64,
	pub tx_hash: Option<String>,
	pub message_guid: Option<String>,
	pub redeem_tx_hash: Option<String>,
	pub fee_paid: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TriggerRebalanceResponse {
	pub success: bool,
	pub message: String,
	pub operation_id: Option<String>,
	pub tx_hash: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolveTransferResponse {
	pub success: bool,
	pub message: String,
	pub transfer_id: String,
	pub new_status: String,
}

// ---- Request Types ----

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TriggerRebalanceRequest {
	pub pair_id: String,
	pub source_chain: u64,
	pub dest_chain: u64,
	pub amount: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolveTransferRequest {
	pub resolution: String,
	pub reason: String,
}

// ---- Handlers ----

/// GET /api/v1/admin/rebalance/config
pub async fn handle_get_rebalance_config(
	State(state): State<AdminApiState>,
) -> Result<Json<RebalanceConfigResponse>, axum::http::StatusCode> {
	let versioned = state
		.config_store
		.get()
		.await
		.map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

	let response = match &versioned.data.rebalance {
		Some(config) => RebalanceConfigResponse {
			enabled: config.enabled,
			implementation: config.implementation.clone(),
			monitor_interval_seconds: config.monitor_interval_seconds,
			cooldown_seconds: config.cooldown_seconds,
			max_pending_transfers: config.max_pending_transfers,
			pairs: config
				.pairs
				.iter()
				.map(|p| PairConfigResponse {
					pair_id: p.pair_id.clone(),
					chain_a: PairSideConfigResponse {
						chain_id: p.chain_a.chain_id,
						token_address: p.chain_a.token_address.to_string(),
						oft_address: p.chain_a.oft_address.to_string(),
					},
					chain_b: PairSideConfigResponse {
						chain_id: p.chain_b.chain_id,
						token_address: p.chain_b.token_address.to_string(),
						oft_address: p.chain_b.oft_address.to_string(),
					},
					target_balance_a: p.target_balance_a.clone(),
					target_balance_b: p.target_balance_b.clone(),
					deviation_band_bps: p.deviation_band_bps,
					max_bridge_amount: p.max_bridge_amount.clone(),
				})
				.collect(),
		},
		None => RebalanceConfigResponse {
			enabled: false,
			implementation: String::new(),
			monitor_interval_seconds: 60,
			cooldown_seconds: 3600,
			max_pending_transfers: 3,
			pairs: Vec::new(),
		},
	};

	Ok(Json(response))
}

/// GET /api/v1/admin/rebalance/status — computes real values using shared threshold math.
pub async fn handle_get_rebalance_status(
	State(state): State<AdminApiState>,
) -> Result<Json<RebalanceStatusResponse>, axum::http::StatusCode> {
	let active_transfers = if let Some(bridge_service) = &state.bridge_service {
		bridge_service
			.active_transfer_count()
			.await
			.map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?
	} else {
		0
	};

	let versioned = state
		.config_store
		.get()
		.await
		.map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

	let pairs: Vec<PairRebalanceStatus> = match &versioned.data.rebalance {
		Some(config) => {
			let mut pair_statuses = Vec::new();
			let solver_address = &state.solver_address;

			for pair in &config.pairs {
				// Query actual balances
				let token_a_str = pair.chain_a.token_address.to_string();
				let token_b_str = pair.chain_b.token_address.to_string();
				let balance_a_result = state
					.delivery
					.get_balance(pair.chain_a.chain_id, solver_address, Some(&token_a_str))
					.await;
				let balance_b_result = state
					.delivery
					.get_balance(pair.chain_b.chain_id, solver_address, Some(&token_b_str))
					.await;

				match (balance_a_result, balance_b_result) {
					(Ok(bal_a_str), Ok(bal_b_str)) => {
						let bal_a = match U256::from_str_radix(&bal_a_str, 10) {
							Ok(v) => v,
							Err(e) => {
								pair_statuses.push(error_pair_status(
									pair,
									format!("Failed to parse balance_a: {e}"),
								));
								continue;
							},
						};
						let bal_b = match U256::from_str_radix(&bal_b_str, 10) {
							Ok(v) => v,
							Err(e) => {
								pair_statuses.push(error_pair_status(
									pair,
									format!("Failed to parse balance_b: {e}"),
								));
								continue;
							},
						};
						let target_a = match U256::from_str_radix(&pair.target_balance_a, 10) {
							Ok(v) => v,
							Err(e) => {
								pair_statuses.push(error_pair_status(
									pair,
									format!("Failed to parse target_balance_a: {e}"),
								));
								continue;
							},
						};
						let target_b = match U256::from_str_radix(&pair.target_balance_b, 10) {
							Ok(v) => v,
							Err(e) => {
								pair_statuses.push(error_pair_status(
									pair,
									format!("Failed to parse target_balance_b: {e}"),
								));
								continue;
							},
						};
						let max_amount = match U256::from_str_radix(&pair.max_bridge_amount, 10) {
							Ok(v) => v,
							Err(e) => {
								pair_statuses.push(error_pair_status(
									pair,
									format!("Failed to parse max_bridge_amount: {e}"),
								));
								continue;
							},
						};

						let analysis = analyze_pair(
							bal_a,
							bal_b,
							target_a,
							target_b,
							pair.deviation_band_bps,
							max_amount,
						);

						let direction_needed =
							analysis.direction_needed.as_ref().map(|d| match d {
								RebalanceDirection::AToB => "a_to_b".to_string(),
								RebalanceDirection::BToA => "b_to_a".to_string(),
							});

						// Bridge lookups — use safe defaults on failure, preserve computed analysis
						let mut bridge_error: Option<String> = None;

						let cooldown_active = if let Some(bs) = &state.bridge_service {
							match bs.is_cooldown_active(&pair.pair_id).await {
								Ok(v) => v,
								Err(e) => {
									bridge_error = Some(format!("Cooldown check failed: {e}"));
									false
								},
							}
						} else {
							false
						};

						let active_transfer_id = if let Some(bs) = &state.bridge_service {
							match bs.get_active_transfers_for_pair(&pair.pair_id).await {
								Ok(transfers) => transfers.first().map(|t| t.id.clone()),
								Err(e) => {
									let msg = format!("Active transfer query failed: {e}");
									bridge_error = Some(match bridge_error {
										Some(existing) => format!("{existing}; {msg}"),
										None => msg,
									});
									None
								},
							}
						} else {
							None
						};

						pair_statuses.push(PairRebalanceStatus {
							pair_id: pair.pair_id.clone(),
							chain_a: PairSideStatus {
								chain_id: pair.chain_a.chain_id,
								current_balance: bal_a.to_string(),
								target_balance: pair.target_balance_a.clone(),
								lower_bound: analysis.side_a.lower_bound.to_string(),
								upper_bound: analysis.side_a.upper_bound.to_string(),
								within_band: analysis.side_a.within_band,
							},
							chain_b: PairSideStatus {
								chain_id: pair.chain_b.chain_id,
								current_balance: bal_b.to_string(),
								target_balance: pair.target_balance_b.clone(),
								lower_bound: analysis.side_b.lower_bound.to_string(),
								upper_bound: analysis.side_b.upper_bound.to_string(),
								within_band: analysis.side_b.within_band,
							},
							deviation_band_bps: pair.deviation_band_bps,
							direction_needed,
							suggested_amount: analysis.suggested_amount.to_string(),
							cooldown_active,
							active_transfer_id,
							error: bridge_error,
						});
					},
					(Err(e), _) | (_, Err(e)) => {
						pair_statuses.push(error_pair_status(
							pair,
							format!("Balance query failed: {e}"),
						));
					},
				}
			}
			pair_statuses
		},
		None => Vec::new(),
	};

	let monitor_status = state.rebalance_monitor_status.read().await;

	Ok(Json(RebalanceStatusResponse {
		pairs,
		active_transfers,
		last_check_at: monitor_status.last_check_at,
		next_check_at: monitor_status.next_check_at,
	}))
}

/// GET /api/v1/admin/rebalance/transfers
pub async fn handle_get_rebalance_transfers(
	State(state): State<AdminApiState>,
) -> Result<Json<RebalanceTransfersResponse>, axum::http::StatusCode> {
	let bridge_service = state
		.bridge_service
		.as_ref()
		.ok_or(axum::http::StatusCode::SERVICE_UNAVAILABLE)?;

	let active = bridge_service
		.get_active_transfers()
		.await
		.map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
	let history = bridge_service
		.get_transfer_history(50)
		.await
		.map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

	Ok(Json(RebalanceTransfersResponse {
		active: active.iter().map(to_operation_response).collect(),
		history: history.iter().map(to_operation_response).collect(),
	}))
}

/// POST /api/v1/admin/rebalance/trigger (EIP-712 signed)
pub async fn handle_trigger_rebalance(
	State(state): State<AdminApiState>,
	VerifiedAdmin {
		admin: _,
		contents: request,
	}: VerifiedAdmin<TriggerRebalanceContents>,
) -> Result<Json<TriggerRebalanceResponse>, AdminAuthError> {
	let bridge_service = state
		.bridge_service
		.as_ref()
		.ok_or_else(|| AdminAuthError::Internal("Bridge service not available".to_string()))?;

	let versioned = state
		.config_store
		.get()
		.await
		.map_err(|e| AdminAuthError::Internal(format!("Config store error: {e}")))?;

	let rebalance_config =
		versioned.data.rebalance.as_ref().ok_or_else(|| {
			AdminAuthError::InvalidMessage("Rebalance not configured".to_string())
		})?;

	let pair = rebalance_config
		.pairs
		.iter()
		.find(|p| p.pair_id == request.pair_id)
		.ok_or_else(|| {
			AdminAuthError::InvalidMessage(format!("Pair '{}' not found", request.pair_id))
		})?;

	// Direction-aware side mapping
	let (source_side, dest_side) = if request.source_chain == pair.chain_a.chain_id {
		(&pair.chain_a, &pair.chain_b)
	} else if request.source_chain == pair.chain_b.chain_id {
		(&pair.chain_b, &pair.chain_a)
	} else {
		return Err(AdminAuthError::InvalidMessage(
			"source_chain does not match pair".to_string(),
		));
	};

	if request.dest_chain != dest_side.chain_id {
		return Err(AdminAuthError::InvalidMessage(
			"dest_chain does not match pair".to_string(),
		));
	}

	let amount = U256::from_str_radix(&request.amount, 10).map_err(|_| {
		AdminAuthError::InvalidMessage(format!("Invalid amount: {}", request.amount))
	})?;
	if amount.is_zero() {
		return Err(AdminAuthError::InvalidMessage(
			"amount must be greater than 0".to_string(),
		));
	}
	let recipient: alloy_primitives::Address = state
		.solver_address
		.parse()
		.map_err(|e| AdminAuthError::Internal(format!("Invalid solver address: {e}")))?;

	let bridge_request = solver_bridge::types::BridgeRequest {
		pair_id: request.pair_id.clone(),
		source_chain: request.source_chain,
		dest_chain: request.dest_chain,
		source_token: source_side.token_address,
		source_oft: source_side.oft_address,
		dest_token: dest_side.token_address,
		dest_oft: dest_side.oft_address,
		amount,
		min_amount: None,
		recipient,
	};

	// Build metadata for delivery detection and redeem path
	let is_composer = rebalance_config
		.bridge_config
		.as_ref()
		.and_then(|bc| bc.get("composer_addresses"))
		.and_then(|ca| ca.get(request.source_chain.to_string()))
		.is_some();
	let vault_addr = rebalance_config
		.bridge_config
		.as_ref()
		.and_then(|bc| bc.get("vault_addresses"))
		.and_then(|va| va.get(dest_side.chain_id.to_string()))
		.and_then(|v| v.as_str())
		.map(|s| s.to_string());

	if !is_composer && vault_addr.is_none() {
		return Err(AdminAuthError::InvalidMessage(
			"missing vault address for non-composer destination".to_string(),
		));
	}

	let metadata = solver_bridge::types::TransferMetadata {
		dest_token_address: dest_side.token_address.to_string(),
		dest_oft_address: dest_side.oft_address.to_string(),
		is_composer_flow: is_composer,
		vault_address: vault_addr,
	};

	match bridge_service
		.rebalance_token(
			&rebalance_config.implementation,
			&bridge_request,
			solver_bridge::types::RebalanceTrigger::Manual,
			metadata,
		)
		.await
	{
		Ok(transfer) => Ok(Json(TriggerRebalanceResponse {
			success: true,
			message: "Rebalance initiated".to_string(),
			operation_id: Some(transfer.id),
			tx_hash: transfer.tx_hash,
		})),
		Err(e) => Ok(Json(TriggerRebalanceResponse {
			success: false,
			message: format!("Rebalance failed: {e}"),
			operation_id: None,
			tx_hash: None,
		})),
	}
}

/// POST /api/v1/admin/rebalance/transfers/:id/resolve (EIP-712 signed)
pub async fn handle_resolve_transfer(
	State(state): State<AdminApiState>,
	Path(transfer_id): Path<String>,
	VerifiedAdmin {
		admin: _,
		contents: request,
	}: VerifiedAdmin<ResolveTransferContents>,
) -> Result<Json<ResolveTransferResponse>, AdminAuthError> {
	let bridge_service = state
		.bridge_service
		.as_ref()
		.ok_or_else(|| AdminAuthError::Internal("Bridge service not available".to_string()))?;

	// Verify the transfer_id in the path matches the signed payload
	if transfer_id != request.transfer_id {
		return Err(AdminAuthError::InvalidMessage(
			"Path transfer_id does not match signed payload".to_string(),
		));
	}

	match bridge_service
		.resolve_transfer(&request.transfer_id, &request.resolution, &request.reason)
		.await
	{
		Ok(transfer) => Ok(Json(ResolveTransferResponse {
			success: true,
			message: format!("Transfer resolved: {}", request.resolution),
			transfer_id: transfer.id,
			new_status: transfer.status.to_string(),
		})),
		Err(e) => Ok(Json(ResolveTransferResponse {
			success: false,
			message: format!("Resolve failed: {e}"),
			transfer_id: request.transfer_id,
			new_status: String::new(),
		})),
	}
}

/// PUT /api/v1/admin/rebalance/config (EIP-712 signed)
pub async fn handle_update_rebalance_config(
	State(state): State<AdminApiState>,
	VerifiedAdmin {
		admin,
		contents: request,
	}: VerifiedAdmin<UpdateRebalanceConfigContents>,
) -> Result<Json<solver_types::admin_api::AdminActionResponse>, AdminAuthError> {
	use crate::config_merge::build_runtime_config;

	let versioned = state
		.config_store
		.get()
		.await
		.map_err(|e| AdminAuthError::Internal(format!("Config store error: {e}")))?;

	let mut operator_config = versioned.data;

	match operator_config.rebalance.as_mut() {
		Some(rebalance) => {
			rebalance.enabled = request.enabled;
			rebalance.cooldown_seconds = request.cooldown_seconds;
			rebalance.max_pending_transfers = request.max_pending_transfers as u32;
		},
		None => {
			return Err(AdminAuthError::InvalidMessage(
				"Rebalance not configured. Add rebalance section to bootstrap config first."
					.to_string(),
			));
		},
	}

	// Validate BEFORE persisting — reject invalid config without touching storage
	let new_config = build_runtime_config(&operator_config)
		.map_err(|e| AdminAuthError::Internal(format!("Invalid config: {e}")))?;

	let _new_versioned = state
		.config_store
		.update(operator_config, versioned.version)
		.await
		.map_err(|e| AdminAuthError::Internal(format!("Config store update failed: {e}")))?;

	*state.dynamic_config.write().await = new_config;

	tracing::info!(
		admin = %hex::encode(&admin.0),
		enabled = request.enabled,
		cooldown = request.cooldown_seconds,
		max_pending = request.max_pending_transfers,
		"Rebalance config updated"
	);

	Ok(Json(solver_types::admin_api::AdminActionResponse {
		success: true,
		message: format!(
			"Rebalance config updated: enabled={}, cooldown={}s, max_pending={}",
			request.enabled, request.cooldown_seconds, request.max_pending_transfers
		),
		admin: format!("0x{}", hex::encode(&admin.0)),
	}))
}

/// PUT /api/v1/admin/rebalance/config/threshold (EIP-712 signed)
pub async fn handle_update_rebalance_threshold(
	State(state): State<AdminApiState>,
	VerifiedAdmin {
		admin,
		contents: request,
	}: VerifiedAdmin<UpdateRebalanceThresholdContents>,
) -> Result<Json<solver_types::admin_api::AdminActionResponse>, AdminAuthError> {
	use crate::config_merge::build_runtime_config;

	let versioned = state
		.config_store
		.get()
		.await
		.map_err(|e| AdminAuthError::Internal(format!("Config store error: {e}")))?;

	let mut operator_config = versioned.data;

	let rebalance = operator_config
		.rebalance
		.as_mut()
		.ok_or_else(|| AdminAuthError::InvalidMessage("Rebalance not configured".to_string()))?;

	let pair = rebalance
		.pairs
		.iter_mut()
		.find(|p| p.pair_id == request.pair_id)
		.ok_or_else(|| {
			AdminAuthError::InvalidMessage(format!("Pair '{}' not found", request.pair_id))
		})?;

	pair.target_balance_a = request.target_balance_a.clone();
	pair.target_balance_b = request.target_balance_b.clone();
	pair.deviation_band_bps = request.deviation_band_bps as u32;
	pair.max_bridge_amount = request.max_bridge_amount.clone();

	// Validate BEFORE persisting — reject invalid config without touching storage
	let new_config = build_runtime_config(&operator_config)
		.map_err(|e| AdminAuthError::Internal(format!("Invalid config: {e}")))?;

	let _new_versioned = state
		.config_store
		.update(operator_config, versioned.version)
		.await
		.map_err(|e| AdminAuthError::Internal(format!("Config store update failed: {e}")))?;

	*state.dynamic_config.write().await = new_config;

	tracing::info!(
		admin = %hex::encode(&admin.0),
		pair = %request.pair_id,
		target_a = %request.target_balance_a,
		target_b = %request.target_balance_b,
		band_bps = request.deviation_band_bps,
		"Rebalance threshold updated"
	);

	Ok(Json(solver_types::admin_api::AdminActionResponse {
		success: true,
		message: format!(
			"Threshold updated for pair '{}': target_a={}, target_b={}, band={}bps, max={}",
			request.pair_id,
			request.target_balance_a,
			request.target_balance_b,
			request.deviation_band_bps,
			request.max_bridge_amount
		),
		admin: format!("0x{}", hex::encode(&admin.0)),
	}))
}

fn error_pair_status(
	pair: &solver_types::OperatorRebalancePairConfig,
	error_msg: String,
) -> PairRebalanceStatus {
	PairRebalanceStatus {
		pair_id: pair.pair_id.clone(),
		chain_a: PairSideStatus {
			chain_id: pair.chain_a.chain_id,
			current_balance: "0".to_string(),
			target_balance: pair.target_balance_a.clone(),
			lower_bound: "0".to_string(),
			upper_bound: "0".to_string(),
			within_band: false,
		},
		chain_b: PairSideStatus {
			chain_id: pair.chain_b.chain_id,
			current_balance: "0".to_string(),
			target_balance: pair.target_balance_b.clone(),
			lower_bound: "0".to_string(),
			upper_bound: "0".to_string(),
			within_band: false,
		},
		deviation_band_bps: pair.deviation_band_bps,
		direction_needed: None,
		suggested_amount: "0".to_string(),
		cooldown_active: false,
		active_transfer_id: None,
		error: Some(error_msg),
	}
}

fn to_operation_response(t: &PendingBridgeTransfer) -> BridgeOperationResponse {
	BridgeOperationResponse {
		id: t.id.clone(),
		pair_id: t.pair_id.clone(),
		source_chain_id: t.source_chain,
		destination_chain_id: t.dest_chain,
		amount: t.amount.clone(),
		status: t.status.to_string(),
		status_reason: t.status.reason().map(String::from),
		trigger: t.trigger.to_string(),
		created_at: t.created_at,
		updated_at: t.updated_at,
		tx_hash: t.tx_hash.clone(),
		message_guid: t.message_guid.clone(),
		redeem_tx_hash: t.redeem_tx_hash.clone(),
		fee_paid: t.fee_paid.clone(),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::apis::admin::AdminApiState;
	use crate::auth::admin::AdminActionVerifier;
	use crate::auth::admin::{ResolveTransferContents, TriggerRebalanceContents};
	use alloy_signer_local::PrivateKeySigner;
	use async_trait::async_trait;
	use solver_account::{AccountInterface, AccountService, AccountSigner};
	use solver_bridge::{
		types::{BridgeDepositResult, BridgeRequest, BridgeTransferStatus, RebalanceTrigger},
		BridgeError, BridgeInterface, BridgeService,
	};
	use solver_config::builders::config::ConfigBuilder;
	use solver_delivery::{DeliveryInterface, DeliveryService, MockDeliveryInterface};
	use solver_storage::implementations::file::{FileStorage, TtlConfig};
	use solver_storage::{
		config_store::create_config_store, config_store::ConfigStore,
		nonce_store::create_nonce_store, StorageService, StoreConfig,
	};
	use solver_types::{
		AdminConfig, NetworkType, NetworksConfig, OperatorAdminConfig, OperatorConfig,
		OperatorGasConfig, OperatorGasFlowUnits, OperatorHyperlaneConfig, OperatorNetworkConfig,
		OperatorOracleConfig, OperatorPricingConfig, OperatorRebalanceConfig,
		OperatorRebalancePairConfig, OperatorRpcEndpoint, OperatorSettlementConfig,
		OperatorSettlementType, OperatorSolverConfig, OperatorWithdrawalsConfig, RebalancePairSide,
	};
	use std::collections::HashMap;
	use std::str::FromStr;
	use std::sync::{Arc, Mutex};
	use tokio::sync::RwLock;
	use uuid::Uuid;

	const SOLVER_ADDRESS: &str = "0x5555555555555555555555555555555555555555";

	#[derive(Default)]
	struct StubBridge {
		recorded_requests: Arc<Mutex<Vec<BridgeRequest>>>,
	}

	#[async_trait]
	impl BridgeInterface for StubBridge {
		fn supported_routes(&self) -> Vec<(u64, u64)> {
			vec![(1, 747474), (747474, 1)]
		}

		async fn bridge_asset(
			&self,
			request: &BridgeRequest,
		) -> Result<BridgeDepositResult, BridgeError> {
			self.recorded_requests.lock().unwrap().push(request.clone());
			Ok(BridgeDepositResult {
				tx_hash: "0xabc123".to_string(),
				message_guid: Some("guid-1".to_string()),
				estimated_arrival: None,
			})
		}

		async fn check_status(
			&self,
			transfer: &solver_bridge::types::PendingBridgeTransfer,
		) -> Result<BridgeTransferStatus, BridgeError> {
			Ok(transfer.status.clone())
		}

		async fn estimate_fee(&self, _request: &BridgeRequest) -> Result<U256, BridgeError> {
			Ok(U256::ZERO)
		}
	}

	struct DummyAccount {
		address: solver_types::Address,
	}

	#[async_trait]
	impl AccountInterface for DummyAccount {
		fn config_schema(&self) -> Box<dyn solver_types::ConfigSchema> {
			Box::new(solver_account::implementations::local::LocalWalletSchema)
		}

		async fn address(&self) -> Result<solver_types::Address, solver_account::AccountError> {
			Ok(self.address.clone())
		}

		async fn sign_transaction(
			&self,
			_tx: &solver_types::Transaction,
		) -> Result<solver_types::Signature, solver_account::AccountError> {
			Err(solver_account::AccountError::Implementation(
				"not needed in rebalance tests".to_string(),
			))
		}

		async fn sign_message(
			&self,
			_message: &[u8],
		) -> Result<solver_types::Signature, solver_account::AccountError> {
			Err(solver_account::AccountError::Implementation(
				"not needed in rebalance tests".to_string(),
			))
		}

		fn signer(&self) -> AccountSigner {
			let signer = PrivateKeySigner::from_str(
				"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
			)
			.unwrap();
			AccountSigner::Local(signer)
		}
	}

	fn alloy_address(hex: &str) -> alloy_primitives::Address {
		alloy_primitives::Address::from_str(hex).unwrap()
	}

	fn make_bridge_storage() -> Arc<StorageService> {
		let base_path =
			std::env::temp_dir().join(format!("solver-rebalance-api-test-{}", Uuid::new_v4()));
		std::fs::create_dir_all(&base_path).unwrap();
		Arc::new(StorageService::new(Box::new(FileStorage::new(
			base_path,
			TtlConfig::default(),
		))))
	}

	fn create_delivery_service<F>(balance_fn: F) -> Arc<DeliveryService>
	where
		F: Fn(&str, Option<&str>, u64) -> Result<String, solver_delivery::DeliveryError>
			+ Send
			+ Sync
			+ 'static,
	{
		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_get_balance()
			.returning(move |address, token, chain_id| {
				let result = balance_fn(address, token, chain_id);
				Box::pin(async move { result })
			});
		let shared = Arc::new(mock_delivery);
		let implementations: HashMap<u64, Arc<dyn DeliveryInterface>> = HashMap::from([
			(1_u64, shared.clone() as Arc<dyn DeliveryInterface>),
			(747474_u64, shared as Arc<dyn DeliveryInterface>),
		]);
		Arc::new(DeliveryService::new(implementations, 1, 30))
	}

	fn sample_operator_config() -> OperatorConfig {
		let admin_address = alloy_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
		OperatorConfig {
			solver_id: "test-solver".to_string(),
			solver_name: Some("Test Solver".to_string()),
			networks: HashMap::from([
				(
					1_u64,
					OperatorNetworkConfig {
						chain_id: 1,
						name: "ethereum".to_string(),
						network_type: NetworkType::Parent,
						tokens: vec![],
						rpc_urls: vec![OperatorRpcEndpoint::http_only(
							"http://localhost:8545".to_string(),
						)],
						input_settler_address: alloy_address(
							"0x1111111111111111111111111111111111111111",
						),
						output_settler_address: alloy_address(
							"0x2222222222222222222222222222222222222222",
						),
						input_settler_compact_address: None,
						the_compact_address: None,
						allocator_address: None,
					},
				),
				(
					747474_u64,
					OperatorNetworkConfig {
						chain_id: 747474,
						name: "katana".to_string(),
						network_type: NetworkType::New,
						tokens: vec![],
						rpc_urls: vec![OperatorRpcEndpoint::http_only(
							"http://localhost:9545".to_string(),
						)],
						input_settler_address: alloy_address(
							"0x3333333333333333333333333333333333333333",
						),
						output_settler_address: alloy_address(
							"0x4444444444444444444444444444444444444444",
						),
						input_settler_compact_address: None,
						the_compact_address: None,
						allocator_address: None,
					},
				),
			]),
			settlement: OperatorSettlementConfig {
				settlement_poll_interval_seconds: 3,
				settlement_type: OperatorSettlementType::Hyperlane,
				priority: None,
				hyperlane: Some(OperatorHyperlaneConfig {
					default_gas_limit: 0,
					message_timeout_seconds: 0,
					finalization_required: false,
					mailboxes: HashMap::new(),
					igp_addresses: HashMap::new(),
					oracles: OperatorOracleConfig {
						input: HashMap::new(),
						output: HashMap::new(),
					},
					routes: HashMap::new(),
					intent_min_expiry_seconds: None,
				}),
				direct: None,
				broadcaster: None,
			},
			gas: OperatorGasConfig {
				resource_lock: OperatorGasFlowUnits::default(),
				permit2_escrow: OperatorGasFlowUnits::default(),
				eip3009_escrow: OperatorGasFlowUnits::default(),
			},
			pricing: OperatorPricingConfig {
				primary: "coingecko".to_string(),
				fallbacks: vec![],
				cache_duration_seconds: 60,
				custom_prices: HashMap::new(),
			},
			solver: OperatorSolverConfig {
				min_profitability_pct: rust_decimal::Decimal::ZERO,
				gas_buffer_bps: 1000,
				commission_bps: 20,
				rate_buffer_bps: 14,
				monitoring_timeout_seconds: 60,
				deny_list: None,
			},
			admin: OperatorAdminConfig {
				enabled: true,
				domain: "test.example.com".to_string(),
				chain_id: 1,
				nonce_ttl_seconds: 300,
				admin_addresses: vec![admin_address],
				withdrawals: OperatorWithdrawalsConfig { enabled: false },
			},
			auth_enabled: false,
			account: None,
			rebalance: Some(OperatorRebalanceConfig {
				enabled: true,
				implementation: "mock-bridge".to_string(),
				monitor_interval_seconds: 15,
				cooldown_seconds: 60,
				max_pending_transfers: 3,
				min_native_gas_reserve: HashMap::new(),
				max_fee_bps: Some(100),
				pairs: vec![OperatorRebalancePairConfig {
					pair_id: "eth-katana".to_string(),
					chain_a: RebalancePairSide {
						chain_id: 1,
						token_address: alloy_address("0x1111111111111111111111111111111111111111"),
						oft_address: alloy_address("0x2222222222222222222222222222222222222222"),
					},
					chain_b: RebalancePairSide {
						chain_id: 747474,
						token_address: alloy_address("0x3333333333333333333333333333333333333333"),
						oft_address: alloy_address("0x4444444444444444444444444444444444444444"),
					},
					target_balance_a: "1000000".to_string(),
					target_balance_b: "1000000".to_string(),
					deviation_band_bps: 2000,
					max_bridge_amount: "500000".to_string(),
				}],
				bridge_config: Some(serde_json::json!({
					"composer_addresses": {},
					"vault_addresses": { "1": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
				})),
			}),
		}
	}

	async fn make_admin_state(
		operator_config: OperatorConfig,
		delivery: Arc<DeliveryService>,
		bridge_service: Option<Arc<BridgeService>>,
	) -> AdminApiState {
		let config_store =
			create_config_store::<OperatorConfig>(StoreConfig::Memory, "test-solver".to_string())
				.unwrap();
		config_store.seed(operator_config).await.unwrap();
		let config_store: Arc<dyn ConfigStore<OperatorConfig>> = Arc::from(config_store);

		let nonce_store =
			Arc::new(create_nonce_store(StoreConfig::Memory, "test-solver", 300).unwrap());
		let verifier = AdminActionVerifier::new(
			nonce_store.clone(),
			AdminConfig {
				enabled: true,
				domain: "test.example.com".to_string(),
				chain_id: Some(1),
				nonce_ttl_seconds: 300,
				admin_addresses: vec![alloy_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")],
			},
			1,
		);

		let account = Arc::new(AccountService::new(Box::new(DummyAccount {
			address: solver_types::Address::from(alloy_address(
				"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
			)),
		})));
		let token_manager = Arc::new(solver_core::engine::token_manager::TokenManager::new(
			NetworksConfig::default(),
			delivery.clone(),
			account,
		));
		let dynamic_config = Arc::new(RwLock::new(ConfigBuilder::new().build()));

		AdminApiState {
			verifier: Arc::new(RwLock::new(verifier)),
			config_store,
			dynamic_config,
			nonce_store,
			token_manager,
			bridge_service,
			solver_address: SOLVER_ADDRESS.to_string(),
			delivery,
			rebalance_monitor_status: Arc::new(tokio::sync::RwLock::new(
				solver_bridge::monitor::RebalanceMonitorStatus::default(),
			)),
		}
	}

	fn make_bridge_service(
		recorded_requests: Arc<Mutex<Vec<BridgeRequest>>>,
	) -> Arc<BridgeService> {
		Arc::new(BridgeService::new(
			HashMap::from([(
				"mock-bridge".to_string(),
				Arc::new(StubBridge { recorded_requests }) as Arc<dyn BridgeInterface>,
			)]),
			make_bridge_storage(),
			"test-solver".to_string(),
		))
	}

	#[tokio::test]
	async fn test_handle_get_rebalance_config_serializes_pair_ids_and_addresses() {
		let state = make_admin_state(
			sample_operator_config(),
			create_delivery_service(|_, _, _| Ok("0".to_string())),
			None,
		)
		.await;

		let Json(response) = handle_get_rebalance_config(axum::extract::State(state))
			.await
			.unwrap();

		assert!(response.enabled);
		assert_eq!(response.implementation, "mock-bridge");
		assert_eq!(response.pairs.len(), 1);
		assert_eq!(response.pairs[0].pair_id, "eth-katana");
		assert_eq!(
			response.pairs[0].chain_b.token_address,
			"0x3333333333333333333333333333333333333333"
		);
	}

	#[tokio::test]
	async fn test_handle_get_rebalance_status_uses_shared_threshold_math() {
		let delivery = create_delivery_service(|address, token, chain_id| {
			assert_eq!(address, SOLVER_ADDRESS);
			match (chain_id, token) {
				(1, Some("0x1111111111111111111111111111111111111111")) => Ok("500000".to_string()),
				(747474, Some("0x3333333333333333333333333333333333333333")) => {
					Ok("1500000".to_string())
				},
				other => panic!("unexpected balance query: {other:?}"),
			}
		});
		let bridge_service = make_bridge_service(Arc::new(Mutex::new(Vec::new())));
		let state =
			make_admin_state(sample_operator_config(), delivery, Some(bridge_service)).await;

		let Json(response) = handle_get_rebalance_status(axum::extract::State(state))
			.await
			.unwrap();

		assert_eq!(response.active_transfers, 0);
		assert_eq!(response.pairs.len(), 1);
		let pair = &response.pairs[0];
		assert_eq!(pair.direction_needed.as_deref(), Some("b_to_a"));
		assert_eq!(pair.suggested_amount, "500000");
		assert!(!pair.chain_a.within_band);
		assert!(!pair.cooldown_active);
	}

	#[tokio::test]
	async fn test_handle_get_rebalance_status_reports_balance_query_errors_per_pair() {
		let delivery = create_delivery_service(|_, _, chain_id| {
			if chain_id == 1 {
				Err(solver_delivery::DeliveryError::Network("boom".to_string()))
			} else {
				Ok("1500000".to_string())
			}
		});
		let state = make_admin_state(sample_operator_config(), delivery, None).await;

		let Json(response) = handle_get_rebalance_status(axum::extract::State(state))
			.await
			.unwrap();

		assert_eq!(response.pairs.len(), 1);
		assert_eq!(
			response.pairs[0].error.as_deref(),
			Some("Balance query failed: Network error: boom")
		);
	}

	#[tokio::test]
	async fn test_handle_get_rebalance_transfers_requires_bridge_service() {
		let state = make_admin_state(
			sample_operator_config(),
			create_delivery_service(|_, _, _| Ok("0".to_string())),
			None,
		)
		.await;

		let err = handle_get_rebalance_transfers(axum::extract::State(state)).await;
		assert!(matches!(
			err,
			Err(axum::http::StatusCode::SERVICE_UNAVAILABLE)
		));
	}

	#[tokio::test]
	async fn test_handle_trigger_rebalance_builds_direction_aware_bridge_request() {
		let recorded = Arc::new(Mutex::new(Vec::new()));
		let bridge_service = make_bridge_service(recorded.clone());
		let state = make_admin_state(
			sample_operator_config(),
			create_delivery_service(|_, _, _| Ok("0".to_string())),
			Some(bridge_service.clone()),
		)
		.await;

		let Json(response) = handle_trigger_rebalance(
			axum::extract::State(state),
			crate::apis::admin::VerifiedAdmin {
				admin: solver_types::Address::from(alloy_address(SOLVER_ADDRESS)),
				contents: TriggerRebalanceContents {
					pair_id: "eth-katana".to_string(),
					source_chain: 747474,
					dest_chain: 1,
					amount: "12345".to_string(),
					nonce: 1,
					deadline: 2,
				},
			},
		)
		.await
		.unwrap();

		assert!(response.success);
		let requests = recorded.lock().unwrap();
		assert_eq!(requests.len(), 1);
		let request = &requests[0];
		assert_eq!(request.source_chain, 747474);
		assert_eq!(request.dest_chain, 1);
		assert_eq!(
			request.source_token,
			alloy_primitives::Address::from([0x33; 20])
		);
		assert_eq!(
			request.dest_token,
			alloy_primitives::Address::from([0x11; 20])
		);
		assert_eq!(request.amount, U256::from(12345u64));
		assert_eq!(
			request.recipient,
			alloy_primitives::Address::from([0x55; 20])
		);
	}

	#[tokio::test]
	async fn test_handle_trigger_rebalance_populates_transfer_metadata_for_manual_path() {
		let bridge_service = make_bridge_service(Arc::new(Mutex::new(Vec::new())));
		let state = make_admin_state(
			sample_operator_config(),
			create_delivery_service(|_, _, _| Ok("0".to_string())),
			Some(bridge_service.clone()),
		)
		.await;

		let Json(response) = handle_trigger_rebalance(
			axum::extract::State(state),
			crate::apis::admin::VerifiedAdmin {
				admin: solver_types::Address::from(alloy_address(SOLVER_ADDRESS)),
				contents: TriggerRebalanceContents {
					pair_id: "eth-katana".to_string(),
					source_chain: 747474,
					dest_chain: 1,
					amount: "12345".to_string(),
					nonce: 1,
					deadline: 2,
				},
			},
		)
		.await
		.unwrap();

		let transfer = bridge_service
			.get_transfer(response.operation_id.as_deref().unwrap())
			.await
			.unwrap();
		assert_eq!(
			transfer.dest_token_address.as_deref(),
			Some("0x1111111111111111111111111111111111111111")
		);
		assert_eq!(
			transfer.dest_oft_address.as_deref(),
			Some("0x2222222222222222222222222222222222222222")
		);
		assert_eq!(
			transfer.vault_address.as_deref(),
			Some("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		);
		assert_eq!(transfer.is_composer_flow, Some(false));
		assert_eq!(transfer.trigger, RebalanceTrigger::Manual);
	}

	#[tokio::test]
	async fn test_handle_trigger_rebalance_rejects_non_composer_route_without_vault() {
		let mut operator_config = sample_operator_config();
		operator_config.rebalance.as_mut().unwrap().bridge_config = Some(serde_json::json!({
			"composer_addresses": {},
			"vault_addresses": {}
		}));
		let bridge_service = make_bridge_service(Arc::new(Mutex::new(Vec::new())));
		let state = make_admin_state(
			operator_config,
			create_delivery_service(|_, _, _| Ok("0".to_string())),
			Some(bridge_service),
		)
		.await;

		let result = handle_trigger_rebalance(
			axum::extract::State(state),
			crate::apis::admin::VerifiedAdmin {
				admin: solver_types::Address::from(alloy_address(SOLVER_ADDRESS)),
				contents: TriggerRebalanceContents {
					pair_id: "eth-katana".to_string(),
					source_chain: 747474,
					dest_chain: 1,
					amount: "12345".to_string(),
					nonce: 1,
					deadline: 2,
				},
			},
		)
		.await;

		assert!(matches!(
			result,
			Err(AdminAuthError::InvalidMessage(msg))
				if msg == "missing vault address for non-composer destination"
		));
	}

	#[tokio::test]
	async fn test_handle_trigger_rebalance_rejects_zero_amount() {
		let recorded = Arc::new(Mutex::new(Vec::new()));
		let bridge_service = make_bridge_service(recorded.clone());
		let state = make_admin_state(
			sample_operator_config(),
			create_delivery_service(|_, _, _| Ok("0".to_string())),
			Some(bridge_service),
		)
		.await;

		let result = handle_trigger_rebalance(
			axum::extract::State(state),
			crate::apis::admin::VerifiedAdmin {
				admin: solver_types::Address::from(alloy_address(SOLVER_ADDRESS)),
				contents: TriggerRebalanceContents {
					pair_id: "eth-katana".to_string(),
					source_chain: 747474,
					dest_chain: 1,
					amount: "0".to_string(),
					nonce: 1,
					deadline: 2,
				},
			},
		)
		.await;

		assert!(matches!(
			result,
			Err(AdminAuthError::InvalidMessage(msg)) if msg == "amount must be greater than 0"
		));
		assert!(recorded.lock().unwrap().is_empty());
	}

	#[tokio::test]
	async fn test_handle_trigger_rebalance_reports_backend_faults_as_internal() {
		let state = make_admin_state(
			sample_operator_config(),
			create_delivery_service(|_, _, _| Ok("0".to_string())),
			None,
		)
		.await;

		let result = handle_trigger_rebalance(
			axum::extract::State(state),
			crate::apis::admin::VerifiedAdmin {
				admin: solver_types::Address::from(alloy_address(SOLVER_ADDRESS)),
				contents: TriggerRebalanceContents {
					pair_id: "eth-katana".to_string(),
					source_chain: 747474,
					dest_chain: 1,
					amount: "12345".to_string(),
					nonce: 1,
					deadline: 2,
				},
			},
		)
		.await;

		assert!(matches!(
			result,
			Err(AdminAuthError::Internal(msg)) if msg == "Bridge service not available"
		));
	}

	#[tokio::test]
	async fn test_handle_trigger_rebalance_reports_invalid_solver_address_as_internal() {
		let recorded = Arc::new(Mutex::new(Vec::new()));
		let bridge_service = make_bridge_service(recorded);
		let mut state = make_admin_state(
			sample_operator_config(),
			create_delivery_service(|_, _, _| Ok("0".to_string())),
			Some(bridge_service),
		)
		.await;
		state.solver_address = "not-an-address".to_string();

		let result = handle_trigger_rebalance(
			axum::extract::State(state),
			crate::apis::admin::VerifiedAdmin {
				admin: solver_types::Address::from(alloy_address(SOLVER_ADDRESS)),
				contents: TriggerRebalanceContents {
					pair_id: "eth-katana".to_string(),
					source_chain: 747474,
					dest_chain: 1,
					amount: "12345".to_string(),
					nonce: 1,
					deadline: 2,
				},
			},
		)
		.await;

		assert!(matches!(
			result,
			Err(AdminAuthError::Internal(msg)) if msg.starts_with("Invalid solver address:")
		));
	}

	#[tokio::test]
	async fn test_handle_resolve_transfer_propagates_success_response() {
		let bridge_service = make_bridge_service(Arc::new(Mutex::new(Vec::new())));
		let mut transfer = solver_bridge::types::PendingBridgeTransfer::new(
			"eth-katana".to_string(),
			1,
			747474,
			"1000000".to_string(),
			RebalanceTrigger::Manual,
			None,
			None,
			None,
		);
		transfer.status = BridgeTransferStatus::NeedsIntervention("manual".to_string());
		transfer.status_before_intervention = Some(BridgeTransferStatus::Relaying);
		bridge_service
			.storage()
			.save_transfer(&transfer)
			.await
			.unwrap();
		let transfer_id = transfer.id.clone();

		let state = make_admin_state(
			sample_operator_config(),
			create_delivery_service(|_, _, _| Ok("0".to_string())),
			Some(bridge_service),
		)
		.await;

		let Json(response) = handle_resolve_transfer(
			axum::extract::State(state),
			axum::extract::Path(transfer_id.clone()),
			crate::apis::admin::VerifiedAdmin {
				admin: solver_types::Address::from(alloy_address(SOLVER_ADDRESS)),
				contents: ResolveTransferContents {
					transfer_id: transfer_id.clone(),
					resolution: "mark_completed".to_string(),
					reason: "done".to_string(),
					nonce: 1,
					deadline: 2,
				},
			},
		)
		.await
		.unwrap();

		assert!(response.success);
		assert_eq!(response.transfer_id, transfer_id);
		assert_eq!(response.new_status, "completed");
	}

	#[tokio::test]
	async fn test_handle_resolve_transfer_returns_service_unavailable_without_bridge_service() {
		let state = make_admin_state(
			sample_operator_config(),
			create_delivery_service(|_, _, _| Ok("0".to_string())),
			None,
		)
		.await;

		let err = handle_resolve_transfer(
			axum::extract::State(state),
			axum::extract::Path("missing".to_string()),
			crate::apis::admin::VerifiedAdmin {
				admin: solver_types::Address::from(alloy_address(SOLVER_ADDRESS)),
				contents: ResolveTransferContents {
					transfer_id: "missing".to_string(),
					resolution: "mark_completed".to_string(),
					reason: "done".to_string(),
					nonce: 1,
					deadline: 2,
				},
			},
		)
		.await;

		assert!(matches!(
			err,
			Err(AdminAuthError::Internal(msg)) if msg == "Bridge service not available"
		));
	}
}
