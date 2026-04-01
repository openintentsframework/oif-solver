//! Admin API endpoints for cross-chain rebalancing.

use crate::apis::admin::AdminApiState;
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

						let cooldown_active = if let Some(bs) = &state.bridge_service {
							match bs.is_cooldown_active(&pair.pair_id).await {
								Ok(v) => v,
								Err(e) => {
									pair_statuses.push(error_pair_status(
										pair,
										format!("Cooldown check failed: {e}"),
									));
									continue;
								},
							}
						} else {
							false
						};

						let active_transfer_id = if let Some(bs) = &state.bridge_service {
							match bs.get_active_transfers_for_pair(&pair.pair_id).await {
								Ok(transfers) => transfers.first().map(|t| t.id.clone()),
								Err(e) => {
									pair_statuses.push(error_pair_status(
										pair,
										format!("Active transfer query failed: {e}"),
									));
									continue;
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
							error: None,
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

	Ok(Json(RebalanceStatusResponse {
		pairs,
		active_transfers,
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

/// POST /api/v1/admin/rebalance/trigger
pub async fn handle_trigger_rebalance(
	State(state): State<AdminApiState>,
	Json(request): Json<TriggerRebalanceRequest>,
) -> Result<Json<TriggerRebalanceResponse>, axum::http::StatusCode> {
	let bridge_service = state
		.bridge_service
		.as_ref()
		.ok_or(axum::http::StatusCode::SERVICE_UNAVAILABLE)?;

	let versioned = state
		.config_store
		.get()
		.await
		.map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

	let rebalance_config = versioned
		.data
		.rebalance
		.as_ref()
		.ok_or(axum::http::StatusCode::BAD_REQUEST)?;

	let pair = rebalance_config
		.pairs
		.iter()
		.find(|p| p.pair_id == request.pair_id)
		.ok_or(axum::http::StatusCode::NOT_FOUND)?;

	// Direction-aware side mapping
	let (source_side, dest_side) = if request.source_chain == pair.chain_a.chain_id {
		(&pair.chain_a, &pair.chain_b)
	} else if request.source_chain == pair.chain_b.chain_id {
		(&pair.chain_b, &pair.chain_a)
	} else {
		return Err(axum::http::StatusCode::BAD_REQUEST);
	};

	if request.dest_chain != dest_side.chain_id {
		return Err(axum::http::StatusCode::BAD_REQUEST);
	}

	let amount = U256::from_str_radix(&request.amount, 10)
		.map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;

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
		recipient: alloy_primitives::Address::ZERO,
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
		.and_then(|va| va.get(request.dest_chain.to_string()))
		.and_then(|v| v.as_str())
		.map(|s| s.to_string());

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

/// POST /api/v1/admin/rebalance/transfers/:id/resolve
pub async fn handle_resolve_transfer(
	State(state): State<AdminApiState>,
	Path(transfer_id): Path<String>,
	Json(request): Json<ResolveTransferRequest>,
) -> Result<Json<ResolveTransferResponse>, axum::http::StatusCode> {
	let bridge_service = state
		.bridge_service
		.as_ref()
		.ok_or(axum::http::StatusCode::SERVICE_UNAVAILABLE)?;

	match bridge_service
		.resolve_transfer(&transfer_id, &request.resolution, &request.reason)
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
			transfer_id,
			new_status: String::new(),
		})),
	}
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
