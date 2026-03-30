//! Admin API endpoints for cross-chain rebalancing.
//!
//! Endpoints:
//! - GET  /api/v1/admin/rebalance/config         - Get current rebalance config
//! - PUT  /api/v1/admin/rebalance/config         - Update global settings (EIP-712)
//! - PUT  /api/v1/admin/rebalance/config/threshold - Update per-pair thresholds (EIP-712)
//! - POST /api/v1/admin/rebalance/trigger        - Manual trigger (EIP-712)
//! - POST /api/v1/admin/rebalance/transfers/:id/resolve - Resolve stuck transfer (EIP-712)
//! - GET  /api/v1/admin/rebalance/status         - Balance vs threshold analysis
//! - GET  /api/v1/admin/rebalance/transfers      - Active + history

use crate::apis::admin::AdminApiState;
use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};

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
	pub symbol: String,
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
	pub symbol: String,
	pub chain_a: PairSideStatus,
	pub chain_b: PairSideStatus,
	pub deviation_band_bps: u32,
	pub direction_needed: Option<String>,
	pub cooldown_active: bool,
	pub active_transfer_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairSideStatus {
	pub chain_id: u64,
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
	pub pair_symbol: String,
	pub source_chain_id: u64,
	pub destination_chain_id: u64,
	pub amount: String,
	pub status: String,
	pub trigger: String,
	pub created_at: String,
	pub updated_at: String,
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
	pub symbol: String,
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
					symbol: p.symbol.clone(),
					chain_a: PairSideConfigResponse {
						chain_id: p.chain_a.chain_id,
						token_address: format!("0x{}", hex::encode(p.chain_a.token_address.as_slice())),
						oft_address: format!("0x{}", hex::encode(p.chain_a.oft_address.as_slice())),
					},
					chain_b: PairSideConfigResponse {
						chain_id: p.chain_b.chain_id,
						token_address: format!("0x{}", hex::encode(p.chain_b.token_address.as_slice())),
						oft_address: format!("0x{}", hex::encode(p.chain_b.oft_address.as_slice())),
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

/// GET /api/v1/admin/rebalance/status
pub async fn handle_get_rebalance_status(
	State(state): State<AdminApiState>,
) -> Result<Json<RebalanceStatusResponse>, axum::http::StatusCode> {
	let active_transfers = if let Some(bridge_service) = &state.bridge_service {
		bridge_service
			.active_transfer_count()
			.await
			.unwrap_or(0)
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
			for pair in &config.pairs {
				let target_a = alloy_primitives::U256::from_str_radix(&pair.target_balance_a, 10)
					.unwrap_or(alloy_primitives::U256::ZERO);
				let target_b = alloy_primitives::U256::from_str_radix(&pair.target_balance_b, 10)
					.unwrap_or(alloy_primitives::U256::ZERO);
				let band = alloy_primitives::U256::from(pair.deviation_band_bps);
				let bps = alloy_primitives::U256::from(10_000u64);

				let lower_a = target_a * (bps - band) / bps;
				let upper_a = target_a * (bps + band) / bps;
				let lower_b = target_b * (bps - band) / bps;
				let upper_b = target_b * (bps + band) / bps;

				let cooldown_active = if let Some(bs) = &state.bridge_service {
					bs.is_cooldown_active(&pair.symbol).await.unwrap_or(false)
				} else {
					false
				};

				let active_transfer_id = if let Some(bs) = &state.bridge_service {
					bs.get_active_transfers_for_pair(&pair.symbol)
						.await
						.ok()
						.and_then(|t| t.first().map(|t| t.id.clone()))
				} else {
					None
				};

				pair_statuses.push(PairRebalanceStatus {
					symbol: pair.symbol.clone(),
					chain_a: PairSideStatus {
						chain_id: pair.chain_a.chain_id,
						target_balance: pair.target_balance_a.clone(),
						lower_bound: lower_a.to_string(),
						upper_bound: upper_a.to_string(),
						within_band: true, // TODO: query actual balance
					},
					chain_b: PairSideStatus {
						chain_id: pair.chain_b.chain_id,
						target_balance: pair.target_balance_b.clone(),
						lower_bound: lower_b.to_string(),
						upper_bound: upper_b.to_string(),
						within_band: true, // TODO: query actual balance
					},
					deviation_band_bps: pair.deviation_band_bps,
					direction_needed: None, // TODO: compute from actual balance
					cooldown_active,
					active_transfer_id,
				});
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
		.unwrap_or_default();
	let history = bridge_service
		.get_transfer_history(50)
		.await
		.unwrap_or_default();

	fn to_response(t: &solver_bridge::types::PendingBridgeTransfer) -> BridgeOperationResponse {
		BridgeOperationResponse {
			id: t.id.clone(),
			pair_symbol: t.pair_symbol.clone(),
			source_chain_id: t.source_chain,
			destination_chain_id: t.dest_chain,
			amount: t.amount.clone(),
			status: format!("{:?}", t.status),
			trigger: format!("{:?}", t.trigger),
			created_at: t.created_at.to_string(),
			updated_at: t.updated_at.to_string(),
			tx_hash: t.tx_hash.clone(),
			message_guid: t.message_guid.clone(),
			redeem_tx_hash: t.redeem_tx_hash.clone(),
			fee_paid: t.fee_paid.clone(),
		}
	}

	Ok(Json(RebalanceTransfersResponse {
		active: active.iter().map(to_response).collect(),
		history: history.iter().map(to_response).collect(),
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

	// Find the pair config
	let pair = rebalance_config
		.pairs
		.iter()
		.find(|p| p.symbol == request.symbol)
		.ok_or(axum::http::StatusCode::NOT_FOUND)?;

	// Determine source/dest token addresses from pair config
	let (source_token, dest_token) = if request.source_chain == pair.chain_a.chain_id {
		(pair.chain_a.token_address, pair.chain_b.token_address)
	} else if request.source_chain == pair.chain_b.chain_id {
		(pair.chain_b.token_address, pair.chain_a.token_address)
	} else {
		return Err(axum::http::StatusCode::BAD_REQUEST);
	};

	let amount = alloy_primitives::U256::from_str_radix(&request.amount, 10)
		.map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;

	let bridge_request = solver_bridge::types::BridgeRequest {
		pair_symbol: request.symbol.clone(),
		source_chain: request.source_chain,
		dest_chain: request.dest_chain,
		source_token,
		dest_token,
		amount,
		min_amount: None,
		recipient: alloy_primitives::Address::ZERO,
	};

	match bridge_service
		.rebalance_token(
			&rebalance_config.implementation,
			&bridge_request,
			solver_bridge::types::RebalanceTrigger::Manual,
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
			new_status: format!("{:?}", transfer.status),
		})),
		Err(e) => Ok(Json(ResolveTransferResponse {
			success: false,
			message: format!("Resolve failed: {e}"),
			transfer_id,
			new_status: String::new(),
		})),
	}
}
