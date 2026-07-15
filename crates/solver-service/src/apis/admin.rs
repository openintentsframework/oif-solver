//! Admin API endpoints with EIP-712 signature authentication.
//!
//! All admin endpoints require a signed request in the format:
//! ```json
//! {
//!   "signature": "0x...",
//!   "contents": { ... action-specific fields ... }
//! }
//! ```
//!
//! The signature must be an EIP-712 typed data signature from an authorized admin.

use axum::{
	body::Body,
	extract::{FromRequest, State},
	http::Request,
	Json,
};
use once_cell::sync::Lazy;
use regex::Regex;
use solver_config::Config;
use solver_core::engine::token_manager::{TokenManager, TokenManagerError};
use solver_storage::redact_url_credentials;
use solver_storage::{
	config_store::{ConfigStore, ConfigStoreError},
	nonce_store::NonceStore,
};
pub use solver_types::admin_api::{
	AdminActionResponse, AdminConfigResponse, AdminConfigSummary, AdminNetworkResponse,
	AdminSolverResponse, AdminTokenResponse, AdminWhitelistEntry, AdminWhitelistResponse,
	ApproveTokensResponse, BalancesResponse, ChainBalances, Eip712Domain, Eip712TypeInfo,
	FeeConfigResponse, GasConfigResponse, GasFlowResponse, NonceResponse, TokenBalance,
	WithdrawalResponse,
};
#[cfg(test)]
use solver_types::AdminWhitelistEntry as SolverAdminWhitelistEntry;
use solver_types::{
	format_token_amount, is_native_address, with_0x_prefix, AdminConfig, AdminRole,
	OperatorAdminConfig, OperatorConfig, OperatorToken,
};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::auth::admin::{
	AddTokenContents, AddTokensContents, AdminActionVerifier, AdminAuthError,
	ApproveTokensContents, RemoveAdminContents, RemoveTokenContents, SetAdminRoleContents,
	SignedAdminRequest, UpdateFeeConfigContents, UpdateGasConfigContents, WithdrawContents,
};
use crate::config_merge::build_runtime_config;

/// Shared state for admin endpoints.
#[derive(Clone)]
pub struct AdminApiState {
	/// Verifier for EIP-712 admin signatures (wrapped in RwLock for hot reload).
	pub verifier: Arc<RwLock<AdminActionVerifier>>,
	/// ConfigStore for persisting OperatorConfig to Redis.
	pub config_store: Arc<dyn ConfigStore<OperatorConfig>>,
	/// Dynamic runtime config that supports hot-reload.
	pub dynamic_config: Arc<RwLock<Config>>,
	/// Nonce store (concrete type, kept for rebuilding verifier).
	pub nonce_store: Arc<NonceStore>,
	/// Stable solver identifier, folded into the EIP-712 admin domain salt so
	/// signatures cannot be replayed across solvers on the same chain.
	pub solver_id: String,
	/// Token manager for hot-reloading token configurations.
	pub token_manager: Arc<TokenManager>,
	/// Bridge service for cross-chain rebalancing.
	pub bridge_service: Option<Arc<solver_bridge::BridgeService>>,
	/// The solver's address as a hex string (used by rebalance status endpoint).
	pub solver_address: String,
	/// Delivery service for balance queries (used by rebalance status endpoint).
	pub delivery: Arc<solver_delivery::DeliveryService>,
	/// Shared monitor timing state for rebalance status API.
	pub rebalance_monitor_status:
		Arc<tokio::sync::RwLock<solver_bridge::monitor::RebalanceMonitorStatus>>,
}

/// Extractor that verifies an admin-signed request and returns the signer + contents.
pub struct VerifiedAdmin<T> {
	pub admin: solver_types::Address,
	pub contents: T,
}

impl<T> FromRequest<AdminApiState> for VerifiedAdmin<T>
where
	T: crate::auth::admin::AdminAction + serde::de::DeserializeOwned + Send + Sync,
{
	type Rejection = AdminAuthError;

	async fn from_request(
		req: Request<Body>,
		state: &AdminApiState,
	) -> Result<Self, Self::Rejection> {
		let Json(request) = Json::<SignedAdminRequest<T>>::from_request(req, state)
			.await
			.map_err(|e| AdminAuthError::InvalidMessage(format!("Invalid JSON request: {e}")))?;

		let admin = {
			let verifier = state.verifier.read().await;
			verifier
				.verify(&request.contents, &request.signature)
				.await?
		};

		Ok(Self {
			admin: admin.into(),
			contents: request.contents,
		})
	}
}

impl AdminApiState {
	/// Rebuild the verifier with updated admin configuration.
	///
	/// Call this after modifying `OperatorConfig.admin` fields (admin list, chain_id, etc.)
	/// to make changes take effect immediately without restart.
	pub async fn rebuild_verifier(&self, admin_config: &OperatorAdminConfig) {
		let new_verifier = AdminActionVerifier::new(
			self.nonce_store.clone(),
			AdminConfig {
				enabled: admin_config.enabled,
				domain: admin_config.domain.clone(),
				chain_id: Some(admin_config.chain_id),
				nonce_ttl_seconds: admin_config.nonce_ttl_seconds,
				whitelist: admin_config.whitelist.clone(),
			},
			admin_config.chain_id,
			&self.solver_id,
		);

		*self.verifier.write().await = new_verifier;

		tracing::info!(
			admin_count = admin_config.admin_addresses().len(),
			chain_id = admin_config.chain_id,
			"Admin verifier rebuilt with updated config"
		);
	}
}

/// GET|POST /api/v1/admin/nonce
///
/// Generate a nonce for signing admin actions.
/// The nonce must be included in the action contents before signing.
pub async fn handle_get_nonce(
	State(state): State<AdminApiState>,
) -> Result<Json<NonceResponse>, AdminAuthError> {
	let verifier = state.verifier.read().await;
	let nonce = verifier.generate_nonce().await?;

	Ok(Json(NonceResponse {
		nonce: nonce.to_string(),
		expires_in: verifier.nonce_ttl(),
		domain: verifier.domain().to_string(),
		chain_id: verifier.chain_id(),
	}))
}

/// GET /api/v1/admin/balances
///
/// Returns solver token balances per configured network.
pub async fn handle_get_balances(
	State(state): State<AdminApiState>,
) -> Result<Json<BalancesResponse>, AdminAuthError> {
	let solver_address = state
		.token_manager
		.get_solver_address()
		.await
		.map_err(|e| AdminAuthError::Internal(format!("Failed to get solver address: {e}")))?;
	let solver_address_hex = solver_address.to_string();

	let networks = state.token_manager.get_networks().await;
	let mut response_networks = std::collections::HashMap::new();
	let zero_address = solver_types::Address(vec![0u8; 20]);

	for (chain_id, network) in networks {
		let mut tokens = Vec::new();
		let mut error: Option<String> = None;
		let configured_native = network
			.tokens
			.iter()
			.find(|token| is_native_address(&token.address))
			.cloned();

		for token in &network.tokens {
			if is_native_address(&token.address) {
				continue;
			}

			match state
				.token_manager
				.check_balance(chain_id, &token.address)
				.await
			{
				Ok(balance) => {
					let formatted = format_token_amount(&balance, token.decimals);
					tokens.push(TokenBalance {
						address: token.address.to_string(),
						symbol: token.symbol.clone(),
						name: token.name.clone(),
						decimals: token.decimals,
						balance,
						balance_formatted: formatted,
					});
				},
				Err(e) => {
					if error.is_none() {
						error = Some(e.to_string());
					}
				},
			}
		}

		// Always include native balance
		match state
			.token_manager
			.check_balance_any(chain_id, &zero_address)
			.await
		{
			Ok(balance) => {
				let decimals = configured_native
					.as_ref()
					.map(|token| token.decimals)
					.unwrap_or(18);
				let formatted = format_token_amount(&balance, decimals);
				tokens.push(TokenBalance {
					address: configured_native
						.as_ref()
						.map(|token| token.address.to_string())
						.unwrap_or_else(|| zero_address.to_string()),
					symbol: configured_native
						.as_ref()
						.map(|token| token.symbol.clone())
						.unwrap_or_else(|| "NATIVE".to_string()),
					name: configured_native
						.as_ref()
						.and_then(|token| token.name.clone())
						.or_else(|| Some("Native Token".to_string())),
					decimals,
					balance,
					balance_formatted: formatted,
				});
			},
			Err(e) => {
				if error.is_none() {
					error = Some(e.to_string());
				}
			},
		}

		response_networks.insert(
			chain_id.to_string(),
			ChainBalances {
				chain_id,
				tokens,
				error,
			},
		);
	}

	Ok(Json(BalancesResponse {
		solver_address: solver_address_hex,
		networks: response_networks,
	}))
}

/// GET /api/v1/admin/config
///
/// Returns a redacted view of the current operator configuration.
pub async fn handle_get_config(
	State(state): State<AdminApiState>,
) -> Result<Json<AdminConfigResponse>, AdminAuthError> {
	let versioned = state.config_store.get().await.map_err(config_store_error)?;
	let operator_config = versioned.data;
	let solver_id = operator_config.solver_id.clone();
	let solver_name = operator_config.solver_name.clone();

	let mut networks: Vec<AdminNetworkResponse> = operator_config
		.networks
		.values()
		.map(|network| {
			let mut rpc_urls = Vec::new();
			for rpc in &network.rpc_urls {
				if !rpc.http.is_empty() {
					rpc_urls.push(redact_rpc_url(&rpc.http));
				}
				if let Some(ws) = &rpc.ws {
					rpc_urls.push(redact_rpc_url(ws));
				}
			}

			AdminNetworkResponse {
				chain_id: network.chain_id,
				name: network.name.clone(),
				network_type: network.network_type,
				rpc_urls,
				tokens: network
					.tokens
					.iter()
					.map(|t| AdminTokenResponse {
						symbol: t.symbol.clone(),
						name: t.name.clone(),
						address: with_0x_prefix(&hex::encode(t.address.as_slice())),
						decimals: t.decimals,
					})
					.collect(),
				input_settler: with_0x_prefix(&hex::encode(
					network.input_settler_address.as_slice(),
				)),
				output_settler: with_0x_prefix(&hex::encode(
					network.output_settler_address.as_slice(),
				)),
			}
		})
		.collect();

	networks.sort_by_key(|n| n.chain_id);

	let gas = gas_config_response(&operator_config.gas);

	Ok(Json(AdminConfigResponse {
		solver_id,
		solver_name,
		networks,
		solver: AdminSolverResponse {
			min_profitability_pct: operator_config.solver.min_profitability_pct.to_string(),
			gas_buffer_bps: operator_config.solver.gas_buffer_bps,
			settlement_fee_buffer_bps: operator_config.solver.settlement_fee_buffer_bps,
			commission_bps: operator_config.solver.commission_bps,
			rate_buffer_bps: operator_config.solver.rate_buffer_bps,
		},
		gas,
		admin: AdminConfigSummary {
			enabled: operator_config.admin.enabled,
			domain: operator_config.admin.domain.clone(),
			withdrawals_enabled: operator_config.admin.withdrawals.enabled,
			withdrawal_recipient_allowlist: operator_config
				.admin
				.withdrawals
				.recipient_allowlist
				.iter()
				.map(|addr| with_0x_prefix(&hex::encode(addr.as_slice())))
				.collect(),
		},
		version: versioned.version,
	}))
}

/// GET /api/v1/admin/gas
///
/// Returns current gas unit configuration.
pub async fn handle_get_gas(
	State(state): State<AdminApiState>,
) -> Result<Json<GasConfigResponse>, AdminAuthError> {
	let versioned = state.config_store.get().await.map_err(config_store_error)?;
	Ok(Json(gas_config_response(&versioned.data.gas)))
}

/// GET /api/v1/admin/whitelist
///
/// Returns the configured admin whitelist.
pub async fn handle_get_whitelist(
	State(state): State<AdminApiState>,
) -> Result<Json<AdminWhitelistResponse>, AdminAuthError> {
	let versioned = state.config_store.get().await.map_err(config_store_error)?;
	let entries: Vec<AdminWhitelistEntry> = versioned
		.data
		.admin
		.whitelist
		.iter()
		.map(|entry| AdminWhitelistEntry {
			address: with_0x_prefix(&hex::encode(entry.address.as_slice())),
			role: entry.role,
		})
		.collect();

	Ok(Json(AdminWhitelistResponse {
		count: entries.len(),
		entries,
	}))
}

/// POST /api/v1/admin/whitelist
///
/// Set an admin whitelist role.
pub async fn handle_set_admin_role(
	State(state): State<AdminApiState>,
	VerifiedAdmin { admin, contents }: VerifiedAdmin<SetAdminRoleContents>,
) -> Result<Json<AdminActionResponse>, AdminAuthError> {
	if contents.account == alloy_primitives::Address::ZERO {
		return Err(AdminAuthError::InvalidMessage(
			"Whitelist address cannot be zero".to_string(),
		));
	}

	let versioned = state.config_store.get().await.map_err(config_store_error)?;
	let mut operator_config = versioned.data;

	let demoting_full_admin = operator_config.admin.role_for(&contents.account)
		== Some(AdminRole::Admin)
		&& contents.role != AdminRole::Admin;
	if demoting_full_admin && operator_config.admin.admin_addresses().len() <= 1 {
		return Err(AdminAuthError::InvalidMessage(
			"Cannot demote the last admin".to_string(),
		));
	}

	operator_config
		.admin
		.set_role(contents.account, contents.role);

	let new_versioned = state
		.config_store
		.update(operator_config.clone(), versioned.version)
		.await
		.map_err(|e| match e {
			ConfigStoreError::VersionMismatch { .. } => {
				AdminAuthError::Internal("Config was modified, please retry".to_string())
			},
			other => config_store_error(other),
		})?;

	let new_config = build_runtime_config(&new_versioned.data)
		.map_err(|e| AdminAuthError::Internal(format!("Invalid config: {e}")))?;
	*state.dynamic_config.write().await = new_config;

	state.rebuild_verifier(&new_versioned.data.admin).await;

	Ok(Json(AdminActionResponse {
		success: true,
		message: format!(
			"Whitelist role set: {} -> {}",
			with_0x_prefix(&hex::encode(contents.account.as_slice())),
			contents.role
		),
		admin: with_0x_prefix(&hex::encode(&admin.0)),
	}))
}

/// DELETE /api/v1/admin/whitelist
///
/// Remove an admin address from the authorized list.
pub async fn handle_remove_admin(
	State(state): State<AdminApiState>,
	VerifiedAdmin { admin, contents }: VerifiedAdmin<RemoveAdminContents>,
) -> Result<Json<AdminActionResponse>, AdminAuthError> {
	let versioned = state.config_store.get().await.map_err(config_store_error)?;
	let mut operator_config = versioned.data;

	if operator_config
		.admin
		.role_for(&contents.admin_to_remove)
		.is_none()
	{
		return Err(AdminAuthError::InvalidMessage(
			"Whitelist address not found".to_string(),
		));
	}

	let removing_full_admin =
		operator_config.admin.role_for(&contents.admin_to_remove) == Some(AdminRole::Admin);
	if removing_full_admin && operator_config.admin.admin_addresses().len() <= 1 {
		return Err(AdminAuthError::InvalidMessage(
			"Cannot remove the last admin".to_string(),
		));
	}

	operator_config
		.admin
		.remove_admin(&contents.admin_to_remove);

	let new_versioned = state
		.config_store
		.update(operator_config.clone(), versioned.version)
		.await
		.map_err(|e| match e {
			ConfigStoreError::VersionMismatch { .. } => {
				AdminAuthError::Internal("Config was modified, please retry".to_string())
			},
			other => config_store_error(other),
		})?;

	let new_config = build_runtime_config(&new_versioned.data)
		.map_err(|e| AdminAuthError::Internal(format!("Invalid config: {e}")))?;
	*state.dynamic_config.write().await = new_config;

	state.rebuild_verifier(&new_versioned.data.admin).await;

	Ok(Json(AdminActionResponse {
		success: true,
		message: format!(
			"Admin removed: {}",
			with_0x_prefix(&hex::encode(contents.admin_to_remove.as_slice()))
		),
		admin: with_0x_prefix(&hex::encode(&admin.0)),
	}))
}

/// PUT /api/v1/admin/gas
///
/// Update gas unit configuration for flows.
pub async fn handle_update_gas(
	State(state): State<AdminApiState>,
	VerifiedAdmin {
		admin,
		contents: request,
	}: VerifiedAdmin<UpdateGasConfigContents>,
) -> Result<Json<AdminActionResponse>, AdminAuthError> {
	// Validate bounds
	fn validate_flow(
		label: &str,
		open: u64,
		fill: u64,
		post_fill: u64,
		pre_claim: u64,
		claim: u64,
	) -> Result<(), AdminAuthError> {
		if open > 500_000 {
			return Err(AdminAuthError::InvalidMessage(format!(
				"{label}.open too high"
			)));
		}
		if fill > 1_000_000 {
			return Err(AdminAuthError::InvalidMessage(format!(
				"{label}.fill too high"
			)));
		}
		if post_fill > 1_000_000 {
			return Err(AdminAuthError::InvalidMessage(format!(
				"{label}.postFill too high"
			)));
		}
		if pre_claim > 5_000_000 {
			return Err(AdminAuthError::InvalidMessage(format!(
				"{label}.preClaim too high"
			)));
		}
		if claim > 500_000 {
			return Err(AdminAuthError::InvalidMessage(format!(
				"{label}.claim too high"
			)));
		}
		Ok(())
	}

	validate_flow(
		"resourceLock",
		request.resource_lock_open,
		request.resource_lock_fill,
		request.resource_lock_post_fill,
		request.resource_lock_pre_claim,
		request.resource_lock_claim,
	)?;
	validate_flow(
		"permit2Escrow",
		request.permit2_escrow_open,
		request.permit2_escrow_fill,
		request.permit2_escrow_post_fill,
		request.permit2_escrow_pre_claim,
		request.permit2_escrow_claim,
	)?;
	validate_flow(
		"eip3009Escrow",
		request.eip3009_escrow_open,
		request.eip3009_escrow_fill,
		request.eip3009_escrow_post_fill,
		request.eip3009_escrow_pre_claim,
		request.eip3009_escrow_claim,
	)?;

	let versioned = state.config_store.get().await.map_err(config_store_error)?;
	let mut operator_config = versioned.data;
	operator_config.gas.resource_lock.open = request.resource_lock_open;
	operator_config.gas.resource_lock.fill = request.resource_lock_fill;
	operator_config.gas.resource_lock.post_fill = request.resource_lock_post_fill;
	operator_config.gas.resource_lock.pre_claim = request.resource_lock_pre_claim;
	operator_config.gas.resource_lock.claim = request.resource_lock_claim;
	operator_config.gas.permit2_escrow.open = request.permit2_escrow_open;
	operator_config.gas.permit2_escrow.fill = request.permit2_escrow_fill;
	operator_config.gas.permit2_escrow.post_fill = request.permit2_escrow_post_fill;
	operator_config.gas.permit2_escrow.pre_claim = request.permit2_escrow_pre_claim;
	operator_config.gas.permit2_escrow.claim = request.permit2_escrow_claim;
	operator_config.gas.eip3009_escrow.open = request.eip3009_escrow_open;
	operator_config.gas.eip3009_escrow.fill = request.eip3009_escrow_fill;
	operator_config.gas.eip3009_escrow.post_fill = request.eip3009_escrow_post_fill;
	operator_config.gas.eip3009_escrow.pre_claim = request.eip3009_escrow_pre_claim;
	operator_config.gas.eip3009_escrow.claim = request.eip3009_escrow_claim;
	operator_config.gas.live_post_fill_estimate_chain_ids = request
		.live_post_fill_estimate_chain_ids
		.iter()
		.copied()
		.collect();
	operator_config.gas.live_fill_estimate_enabled = request.live_fill_estimate_enabled;

	let new_versioned = state
		.config_store
		.update(operator_config.clone(), versioned.version)
		.await
		.map_err(|e| match e {
			ConfigStoreError::VersionMismatch { .. } => {
				AdminAuthError::Internal("Config was modified, please retry".to_string())
			},
			other => config_store_error(other),
		})?;

	let new_config = build_runtime_config(&new_versioned.data)
		.map_err(|e| AdminAuthError::Internal(format!("Invalid config: {e}")))?;
	*state.dynamic_config.write().await = new_config;

	Ok(Json(AdminActionResponse {
		success: true,
		message: "Gas configuration updated".to_string(),
		admin: with_0x_prefix(&hex::encode(&admin.0)),
	}))
}

/// POST /api/v1/admin/tokens
///
/// Add a new token to a network's configuration.
///
/// Request body:
/// ```json
/// {
///   "signature": "0x...",
///   "contents": {
///     "chainId": 10,
///     "symbol": "USDC",
///     "tokenAddress": "0x...",
///     "decimals": 6,
///     "nonce": 12345678901234,
///     "deadline": 1706184000
///   }
/// }
/// ```
///
/// The `nonce` must be obtained from `GET /api/v1/admin/nonce` and included
/// in the signed contents. This ensures the client signs the same nonce
/// that the server will verify.
pub async fn handle_add_token(
	State(state): State<AdminApiState>,
	VerifiedAdmin { admin, contents }: VerifiedAdmin<AddTokenContents>,
) -> Result<Json<AdminActionResponse>, AdminAuthError> {
	let additions = vec![TokenAdditionRequest {
		chain_id: contents.chain_id,
		symbol: contents.symbol.clone(),
		name: contents.name.clone(),
		token_address: contents.token_address,
		decimals: contents.decimals,
	}];
	let (version, approvals_set) = process_token_additions(&state, &additions).await?;

	tracing::info!(
		version,
		token = %contents.symbol,
		chain_id = contents.chain_id,
		approvals_set,
		"Token added, config hot-reloaded, and approvals synchronized"
	);

	Ok(Json(AdminActionResponse {
		success: true,
		message: format!(
			"Token {} added to chain {}",
			contents.symbol, contents.chain_id
		),
		admin: with_0x_prefix(&hex::encode(&admin.0)),
	}))
}

/// POST /api/v1/admin/tokens/batch
///
/// Add multiple new tokens to network configurations in a single signed action.
pub async fn handle_add_tokens(
	State(state): State<AdminApiState>,
	VerifiedAdmin { admin, contents }: VerifiedAdmin<AddTokensContents>,
) -> Result<Json<AdminActionResponse>, AdminAuthError> {
	if contents.tokens.len() < MIN_BATCH_ADD_TOKENS {
		return Err(AdminAuthError::InvalidMessage(format!(
			"Batch token add requires at least {MIN_BATCH_ADD_TOKENS} tokens"
		)));
	}
	if contents.tokens.len() > MAX_BATCH_ADD_TOKENS {
		return Err(AdminAuthError::InvalidMessage(format!(
			"Batch token add supports up to {MAX_BATCH_ADD_TOKENS} tokens"
		)));
	}

	let token_count = contents.tokens.len();
	let additions: Vec<TokenAdditionRequest> = contents
		.tokens
		.into_iter()
		.map(|token| TokenAdditionRequest {
			chain_id: token.chain_id,
			symbol: token.symbol,
			name: token.name,
			token_address: token.token_address,
			decimals: token.decimals,
		})
		.collect();
	let (version, approvals_set) = process_token_additions(&state, &additions).await?;

	tracing::info!(
		version,
		token_count,
		approvals_set,
		"Batch tokens added, config hot-reloaded, and approvals synchronized"
	);

	Ok(Json(AdminActionResponse {
		success: true,
		message: format!("Added {token_count} tokens"),
		admin: with_0x_prefix(&hex::encode(&admin.0)),
	}))
}

const MIN_BATCH_ADD_TOKENS: usize = 2;
const MAX_BATCH_ADD_TOKENS: usize = 50;

#[derive(Debug, Clone)]
struct TokenAdditionRequest {
	chain_id: u64,
	symbol: String,
	name: Option<String>,
	token_address: alloy_primitives::Address,
	decimals: u8,
}

#[derive(Debug)]
struct TokenApprovalSyncFailure {
	chain_id: u64,
	symbol: String,
	token_address: alloy_primitives::Address,
	error: String,
}

fn validate_and_apply_token_additions(
	operator_config: &mut OperatorConfig,
	additions: &[TokenAdditionRequest],
) -> Result<(), AdminAuthError> {
	let mut seen = std::collections::HashSet::new();
	for addition in additions {
		let key = (addition.chain_id, addition.token_address);
		if !seen.insert(key) {
			return Err(AdminAuthError::InvalidMessage(format!(
				"Duplicate token {} on chain {} in request payload",
				addition.token_address, addition.chain_id
			)));
		}
	}

	for addition in additions {
		let network = operator_config
			.networks
			.get(&addition.chain_id)
			.ok_or_else(|| {
				AdminAuthError::InvalidMessage(format!("Network {} not found", addition.chain_id))
			})?;
		if network.has_token(&addition.token_address) {
			return Err(AdminAuthError::InvalidMessage(format!(
				"Token {} already exists on chain {}",
				addition.symbol, addition.chain_id
			)));
		}
	}

	for addition in additions {
		let network = operator_config
			.networks
			.get_mut(&addition.chain_id)
			.ok_or_else(|| {
				AdminAuthError::InvalidMessage(format!("Network {} not found", addition.chain_id))
			})?;
		network.tokens.push(OperatorToken {
			symbol: addition.symbol.clone(),
			name: Some(
				addition
					.name
					.clone()
					.unwrap_or_else(|| addition.symbol.clone()),
			),
			address: addition.token_address,
			decimals: addition.decimals,
		});
	}

	Ok(())
}

async fn persist_and_hot_reload_operator_config(
	state: &AdminApiState,
	operator_config: OperatorConfig,
	expected_version: u64,
) -> Result<(u64, Config), AdminAuthError> {
	let new_versioned = state
		.config_store
		.update(operator_config, expected_version)
		.await
		.map_err(|e| match e {
			ConfigStoreError::VersionMismatch { .. } => {
				AdminAuthError::Internal("Config was modified, please retry".to_string())
			},
			other => config_store_error(other),
		})?;

	let new_config = build_runtime_config(&new_versioned.data)
		.map_err(|e| AdminAuthError::Internal(format!("Invalid config: {e}")))?;

	state
		.token_manager
		.update_networks(new_config.networks.clone())
		.await;
	*state.dynamic_config.write().await = new_config.clone();

	Ok((new_versioned.version, new_config))
}

async fn sync_approvals_for_added_tokens(
	state: &AdminApiState,
	additions: &[TokenAdditionRequest],
	new_config: &Config,
) -> Result<usize, Vec<TokenApprovalSyncFailure>> {
	let mut approvals_set = 0usize;
	let mut failures = Vec::new();

	for addition in additions {
		let Some(network_config) = new_config.networks.get(&addition.chain_id) else {
			failures.push(TokenApprovalSyncFailure {
				chain_id: addition.chain_id,
				symbol: addition.symbol.clone(),
				token_address: addition.token_address,
				error: format!(
					"Chain {} missing from rebuilt runtime config after token add",
					addition.chain_id
				),
			});
			continue;
		};

		match ensure_new_token_approvals(
			state.token_manager.as_ref(),
			addition.chain_id,
			addition.token_address,
			network_config,
		)
		.await
		{
			Ok(count) => approvals_set += count,
			Err(e) => failures.push(TokenApprovalSyncFailure {
				chain_id: addition.chain_id,
				symbol: addition.symbol.clone(),
				token_address: addition.token_address,
				error: e.to_string(),
			}),
		}
	}

	if failures.is_empty() {
		Ok(approvals_set)
	} else {
		Err(failures)
	}
}

fn format_approval_failures(failures: &[TokenApprovalSyncFailure]) -> String {
	failures
		.iter()
		.map(|failure| {
			format!(
				"{}:{} ({}) - {}",
				failure.chain_id, failure.token_address, failure.symbol, failure.error
			)
		})
		.collect::<Vec<_>>()
		.join("; ")
}

async fn process_token_additions(
	state: &AdminApiState,
	additions: &[TokenAdditionRequest],
) -> Result<(u64, usize), AdminAuthError> {
	let versioned = state.config_store.get().await.map_err(config_store_error)?;
	let mut operator_config = versioned.data;

	validate_and_apply_token_additions(&mut operator_config, additions)?;

	let candidate_runtime_config = build_runtime_config(&operator_config)
		.map_err(|e| AdminAuthError::Internal(format!("Invalid config: {e}")))?;

	let approvals_set = sync_approvals_for_added_tokens(state, additions, &candidate_runtime_config)
		.await
		.map_err(|failures| {
			AdminAuthError::Internal(format!(
				"Automatic approval setup failed for {} requested token(s): {}. Token additions were not persisted. Retry via POST /api/v1/admin/tokens/approve",
				additions.len(),
				format_approval_failures(&failures)
			))
		})?;

	let (version, _) =
		persist_and_hot_reload_operator_config(state, operator_config, versioned.version).await?;

	Ok((version, approvals_set))
}

async fn ensure_new_token_approvals(
	token_manager: &TokenManager,
	chain_id: u64,
	token_address: alloy_primitives::Address,
	network: &solver_types::NetworkConfig,
) -> Result<usize, TokenManagerError> {
	use alloy_primitives::U256;

	let zero_address = solver_types::Address(vec![0u8; 20]);
	let input_settler = network.input_settler_address.clone();
	let output_settler = network.output_settler_address.clone();

	let mut spenders = Vec::new();
	if input_settler != zero_address {
		spenders.push(input_settler.clone());
	}
	if output_settler != zero_address && output_settler != input_settler {
		spenders.push(output_settler);
	}

	let token_address = solver_types::Address::from(token_address);
	let mut approvals_set = 0usize;

	for spender in spenders {
		if token_manager
			.ensure_token_approval(chain_id, &token_address, &spender, U256::MAX)
			.await?
		{
			approvals_set += 1;
		}
	}

	Ok(approvals_set)
}

/// Builds a per-network map of configured settler addresses.
///
/// The value for each chain is the set of non-zero input/output settler
/// addresses the safe auto-approval path (`ensure_new_token_approvals`) is
/// willing to grant allowances to ON THAT chain. Keeping the mapping
/// per-network — rather than a global union — is what lets the admin `approve`
/// endpoint reject cross-chain address confusion: a settler configured on
/// chain B must not authorize an approval scoped to chain A, where it has no
/// settler role.
async fn configured_settlers_by_chain(
	token_manager: &TokenManager,
) -> std::collections::HashMap<u64, std::collections::HashSet<solver_types::Address>> {
	let zero_address = solver_types::Address(vec![0u8; 20]);
	let networks = token_manager.get_networks().await;
	let mut by_chain: std::collections::HashMap<
		u64,
		std::collections::HashSet<solver_types::Address>,
	> = std::collections::HashMap::new();
	for (chain_id, network) in networks.iter() {
		let entry = by_chain.entry(*chain_id).or_default();
		if network.input_settler_address != zero_address {
			entry.insert(network.input_settler_address.clone());
		}
		if network.output_settler_address != zero_address {
			entry.insert(network.output_settler_address.clone());
		}
	}
	by_chain
}

/// PUT /api/v1/admin/fees
///
/// Update fee configuration (gas buffer, minimum profitability, commission, rate buffer).
///
/// Request body:
/// ```json
/// {
///   "signature": "0x...",
///   "contents": {
///     "gasBufferBps": 1500,
///     "minProfitabilityPct": "2.5",
///     "commissionBps": 20,
///     "rateBufferBps": 14,
///     "nonce": 12345678901234,
///     "deadline": 1706184000
///   }
/// }
/// ```
///
/// - `gasBufferBps`: Gas buffer in basis points (e.g., 1500 = 15%)
/// - `settlementFeeBufferBps`: Native settlement fee buffer in basis points (e.g., 1000 = 10%)
/// - `minProfitabilityPct`: Minimum profitability as decimal string (e.g., "2.5" for 2.5%)
/// - `commissionBps`: Commission in basis points (e.g., 20 = 0.20%)
/// - `rateBufferBps`: Rate buffer in basis points (e.g., 14 = 0.14%)
pub async fn handle_update_fees(
	State(state): State<AdminApiState>,
	VerifiedAdmin {
		admin,
		contents: request,
	}: VerifiedAdmin<UpdateFeeConfigContents>,
) -> Result<Json<AdminActionResponse>, AdminAuthError> {
	use rust_decimal::Decimal;
	use std::str::FromStr;

	// 1. Validate min_profitability_pct is a valid decimal
	let min_profitability = Decimal::from_str(&request.min_profitability_pct).map_err(|_| {
		AdminAuthError::InvalidMessage(format!(
			"Invalid minProfitabilityPct: '{}' is not a valid decimal",
			request.min_profitability_pct
		))
	})?;

	// 2. Validate gas_buffer_bps is reasonable (0-10000 = 0-100%)
	if request.gas_buffer_bps > 10000 {
		return Err(AdminAuthError::InvalidMessage(format!(
			"Invalid gasBufferBps: {} exceeds maximum of 10000 (100%)",
			request.gas_buffer_bps
		)));
	}

	// 2b. Validate settlement_fee_buffer_bps is reasonable (0-10000 = 0-100%)
	if request.settlement_fee_buffer_bps > 10000 {
		return Err(AdminAuthError::InvalidMessage(format!(
			"Invalid settlementFeeBufferBps: {} exceeds maximum of 10000 (100%)",
			request.settlement_fee_buffer_bps
		)));
	}

	// 2c. Validate commission_bps is reasonable (0-10000 = 0-100%)
	if request.commission_bps > 10000 {
		return Err(AdminAuthError::InvalidMessage(format!(
			"Invalid commissionBps: {} exceeds maximum of 10000 (100%)",
			request.commission_bps
		)));
	}

	// 2d. Validate rate_buffer_bps is reasonable (<10000 to avoid zero rate)
	if request.rate_buffer_bps >= 10000 {
		return Err(AdminAuthError::InvalidMessage(format!(
			"Invalid rateBufferBps: {} must be less than 10000",
			request.rate_buffer_bps
		)));
	}

	// 3. Get current OperatorConfig from Redis
	let versioned = state.config_store.get().await.map_err(config_store_error)?;

	// 4. Update fee configuration
	let mut operator_config = versioned.data;
	operator_config.solver.gas_buffer_bps = request.gas_buffer_bps;
	operator_config.solver.settlement_fee_buffer_bps = request.settlement_fee_buffer_bps;
	operator_config.solver.min_profitability_pct = min_profitability;
	operator_config.solver.commission_bps = request.commission_bps;
	operator_config.solver.rate_buffer_bps = request.rate_buffer_bps;

	// 5. Save to Redis with optimistic locking
	let new_versioned = state
		.config_store
		.update(operator_config.clone(), versioned.version)
		.await
		.map_err(|e| match e {
			ConfigStoreError::VersionMismatch { .. } => {
				AdminAuthError::Internal("Config was modified, please retry".to_string())
			},
			other => config_store_error(other),
		})?;

	// 6. HOT RELOAD: Rebuild runtime Config from updated OperatorConfig
	let new_config = build_runtime_config(&new_versioned.data)
		.map_err(|e| AdminAuthError::Internal(format!("Invalid config: {e}")))?;
	*state.dynamic_config.write().await = new_config;

	tracing::info!(
		version = new_versioned.version,
		gas_buffer_bps = request.gas_buffer_bps,
		settlement_fee_buffer_bps = request.settlement_fee_buffer_bps,
		commission_bps = request.commission_bps,
		rate_buffer_bps = request.rate_buffer_bps,
		min_profitability_pct = %request.min_profitability_pct,
		"Fee configuration updated and config hot-reloaded"
	);

	Ok(Json(AdminActionResponse {
		success: true,
		message: format!(
			"Fee configuration updated: gasBufferBps={}, settlementFeeBufferBps={}, minProfitabilityPct={}, commissionBps={}, rateBufferBps={}",
			request.gas_buffer_bps,
			request.settlement_fee_buffer_bps,
			request.min_profitability_pct,
			request.commission_bps,
			request.rate_buffer_bps
		),
		admin: with_0x_prefix(&hex::encode(&admin.0)),
	}))
}

/// GET /api/v1/admin/fees
///
/// Returns current fee configuration.
pub async fn handle_get_fees(State(state): State<AdminApiState>) -> Json<FeeConfigResponse> {
	let config = state.dynamic_config.read().await;

	Json(FeeConfigResponse {
		min_profitability_pct: config.solver.min_profitability_pct.to_string(),
		gas_buffer_bps: config.solver.gas_buffer_bps,
		settlement_fee_buffer_bps: config.solver.settlement_fee_buffer_bps,
		commission_bps: config.solver.commission_bps,
		rate_buffer_bps: config.solver.rate_buffer_bps,
		monitoring_timeout_seconds: config.solver.monitoring_timeout_seconds,
	})
}

/// DELETE /api/v1/admin/tokens
///
/// Remove a token from a network's configuration.
///
/// The request body contains the EIP-712 signed RemoveToken action:
/// ```json
/// {
///   "signature": "0x...",
///   "contents": {
///     "chainId": 10,
///     "tokenAddress": "0x...",
///     "nonce": 12345678901234,
///     "deadline": 1706184000
///   }
/// }
/// ```
pub async fn handle_remove_token(
	State(state): State<AdminApiState>,
	VerifiedAdmin { admin, contents }: VerifiedAdmin<RemoveTokenContents>,
) -> Result<Json<AdminActionResponse>, AdminAuthError> {
	// 1. Get current OperatorConfig from Redis
	let versioned = state.config_store.get().await.map_err(config_store_error)?;

	// 3. Find network and remove token
	let mut operator_config = versioned.data;
	let network = operator_config
		.networks
		.get_mut(&contents.chain_id)
		.ok_or_else(|| {
			AdminAuthError::InvalidMessage(format!("Network {} not found", contents.chain_id))
		})?;

	// 4. Find and remove the token
	let initial_len = network.tokens.len();
	network
		.tokens
		.retain(|t| t.address != contents.token_address);

	if network.tokens.len() == initial_len {
		return Err(AdminAuthError::InvalidMessage(format!(
			"Token {} not found on chain {}",
			contents.token_address, contents.chain_id
		)));
	}

	// 5. Save to Redis with optimistic locking
	let new_versioned = state
		.config_store
		.update(operator_config.clone(), versioned.version)
		.await
		.map_err(|e| match e {
			ConfigStoreError::VersionMismatch { .. } => {
				AdminAuthError::Internal("Config was modified, please retry".to_string())
			},
			other => config_store_error(other),
		})?;

	// 6. HOT RELOAD: Rebuild runtime Config from updated OperatorConfig
	let new_config = build_runtime_config(&new_versioned.data)
		.map_err(|e| AdminAuthError::Internal(format!("Invalid config: {e}")))?;

	// 7. Update TokenManager with new networks configuration
	let new_networks = new_config.networks.clone();
	state.token_manager.update_networks(new_networks).await;

	// 8. Update dynamic_config
	*state.dynamic_config.write().await = new_config;

	tracing::info!(
		version = new_versioned.version,
		token = %contents.token_address,
		chain_id = contents.chain_id,
		"Token removed and config hot-reloaded (TokenManager updated)"
	);

	Ok(Json(AdminActionResponse {
		success: true,
		message: format!(
			"Token {} removed from chain {}",
			contents.token_address, contents.chain_id
		),
		admin: with_0x_prefix(&hex::encode(&admin.0)),
	}))
}

/// POST /api/v1/admin/withdrawals
///
/// Submit a withdrawal transaction from the solver-managed account.
pub async fn handle_withdrawal(
	State(state): State<AdminApiState>,
	VerifiedAdmin { admin, contents }: VerifiedAdmin<WithdrawContents>,
) -> Result<Json<WithdrawalResponse>, AdminAuthError> {
	use alloy_primitives::U256;

	let withdraw = contents.to_eip712()?;
	let recipient = solver_types::Address::from(contents.recipient);
	let token = solver_types::Address::from(contents.token);

	if withdraw.recipient == alloy_primitives::Address::ZERO {
		return Err(AdminAuthError::InvalidMessage(
			"Recipient cannot be zero address".to_string(),
		));
	}

	if withdraw.amount == U256::ZERO {
		return Err(AdminAuthError::InvalidMessage(
			"Amount must be greater than zero".to_string(),
		));
	}

	// Check if withdrawals are enabled
	let versioned = state.config_store.get().await.map_err(config_store_error)?;
	let policy = &versioned.data.admin.withdrawals;

	if !policy.enabled {
		return Err(AdminAuthError::NotAuthorized(
			"Withdrawals are disabled".to_string(),
		));
	}

	// Recipient allowlist: when configured, the recipient must be pre-approved.
	// Reduces the blast radius of a single compromised admin key — a leak that
	// would otherwise drain to any attacker-chosen address can only redirect
	// funds to operator-vetted recipients (e.g. a cold-storage multisig).
	if !policy.recipient_allowed(&contents.recipient) {
		tracing::warn!(
			admin = %hex::encode(&admin.0),
			recipient = %contents.recipient,
			"Rejected withdrawal: recipient not in allowlist"
		);
		return Err(AdminAuthError::NotAuthorized(
			"Withdrawal recipient is not in the configured allowlist".to_string(),
		));
	}

	// Balance check
	let balance_str = state
		.token_manager
		.check_balance_any(contents.chain_id, &token)
		.await
		.map_err(|e| AdminAuthError::Internal(format!("Balance check failed: {e}")))?;

	let balance = U256::from_str_radix(&balance_str, 10).map_err(|e| {
		AdminAuthError::Internal(format!("Invalid balance value '{balance_str}': {e}"))
	})?;

	if balance < withdraw.amount {
		return Err(AdminAuthError::InvalidMessage(
			"Insufficient funds".to_string(),
		));
	}

	let tx_hash = state
		.token_manager
		.withdraw_token(contents.chain_id, &token, &recipient, withdraw.amount)
		.await
		.map_err(|e| AdminAuthError::Internal(format!("Withdrawal failed: {e}")))?;

	let tx_hash_hex = with_0x_prefix(&hex::encode(&tx_hash.0));

	Ok(Json(WithdrawalResponse {
		success: true,
		status: "submitted".to_string(),
		message: format!("Withdrawal submitted on chain {}", contents.chain_id),
		admin: with_0x_prefix(&hex::encode(&admin.0)),
		tx_hash: Some(tx_hash_hex),
	}))
}

/// POST /api/v1/admin/tokens/approve
///
/// Trigger ERC-20 approvals for tokens to a specified spender.
///
/// Request body:
/// ```json
/// {
///   "signature": "0x...",
///   "contents": {
///     "chainId": 10,        // 0 means all chains
///     "tokenAddress": "0x...", // 0x0 means all tokens
///     "spender": "0x...",  // address that will be approved
///     "amount": "1000000", // uint256 as decimal string
///     "nonce": 12345678901234,
///     "deadline": 1706184000
///   }
/// }
/// ```
///
/// Semantics:
/// - `chainId = 0` and `tokenAddress = 0x0` → approve all tokens on all chains
/// - `chainId = X`, `tokenAddress = 0x0` → approve all tokens on chain X
/// - `chainId = X`, `tokenAddress = A` → approve token A on chain X
pub async fn handle_approve_tokens(
	State(state): State<AdminApiState>,
	VerifiedAdmin { admin, contents }: VerifiedAdmin<ApproveTokensContents>,
) -> Result<Json<ApproveTokensResponse>, AdminAuthError> {
	// 1. Parse amount and determine the scope
	let approve = contents.to_eip712()?;
	let spender = solver_types::Address::from(approve.spender);

	// Per-network spender allowlist: the spender MUST be a configured
	// input/output settler ON EVERY CHAIN this approval would touch — exactly the
	// set the safe auto-approval path (`ensure_new_token_approvals`) is willing to
	// grant allowances to on that chain. Validating per-network (rather than
	// against a global union of all settlers) closes the cross-chain address
	// confusion hole: a settler configured only on chain B must not authorize an
	// approval scoped to chain A, where it has no settler role. Without this guard
	// a compromised admin key could `approve(attacker, U256::MAX)`, bypassing the
	// equivalent control the sibling `handle_withdrawal` enforces via its
	// recipient allowlist. This also rejects the fully-wildcarded chainId=0 +
	// token=0x0 + U256::MAX combination unless the spender is a configured settler
	// on every affected chain.
	let settlers_by_chain = configured_settlers_by_chain(&state.token_manager).await;

	// The chains this approval would actually touch: a specific chain when one is
	// requested, or every chain the token manager knows about for the all-chains
	// scope (mirrors `ensure_approvals_for_spender_scope`'s chain iteration).
	let affected_chains: Vec<u64> = if contents.is_all_chains() {
		settlers_by_chain.keys().copied().collect()
	} else {
		vec![contents.chain_id]
	};

	// Reject if there is no chain to authorize against (e.g. an all-chains scope
	// on a solver with no configured networks), or if the spender is not a
	// configured settler on any one of the affected chains.
	let authorized = !affected_chains.is_empty()
		&& affected_chains.iter().all(|chain_id| {
			settlers_by_chain
				.get(chain_id)
				.is_some_and(|settlers| settlers.contains(&spender))
		});

	if !authorized {
		tracing::warn!(
			admin = %hex::encode(&admin.0),
			spender = %with_0x_prefix(&hex::encode(&spender.0)),
			chains = ?affected_chains,
			"Rejected token approval: spender is not a configured settler on every affected chain"
		);
		return Err(AdminAuthError::NotAuthorized(
			"Approval spender is not a configured input/output settler on every affected chain"
				.to_string(),
		));
	}

	let token_filter = if contents.is_all_tokens() {
		None
	} else {
		// Convert alloy_primitives::Address to solver_types::Address
		Some(solver_types::Address::from(contents.token_address))
	};

	let (approved_count, chains_processed) = state
		.token_manager
		.ensure_approvals_for_spender_scope(
			if contents.is_all_chains() {
				None
			} else {
				Some(contents.chain_id)
			},
			token_filter,
			spender,
			approve.amount,
		)
		.await
		.map_err(|e| AdminAuthError::Internal(format!("Approval failed: {e}")))?;

	let scope_desc = match (contents.is_all_chains(), contents.is_all_tokens()) {
		(true, true) => "all tokens on all chains".to_string(),
		(true, false) => format!("token {} on all chains", contents.token_address),
		(false, true) => format!("all tokens on chain {}", contents.chain_id),
		(false, false) => format!(
			"token {} on chain {}",
			contents.token_address, contents.chain_id
		),
	};

	tracing::info!(
		approved_count,
		chains = ?chains_processed,
		scope = %scope_desc,
		"Token approvals completed"
	);

	Ok(Json(ApproveTokensResponse {
		success: true,
		message: format!("Approved {approved_count} allowances ({scope_desc})"),
		admin: with_0x_prefix(&hex::encode(&admin.0)),
		approved_count,
		chains_processed,
	}))
}

fn gas_config_response(gas: &solver_types::OperatorGasConfig) -> GasConfigResponse {
	GasConfigResponse {
		resource_lock: GasFlowResponse {
			open: gas.resource_lock.open,
			fill: gas.resource_lock.fill,
			post_fill: gas.resource_lock.post_fill,
			pre_claim: gas.resource_lock.pre_claim,
			claim: gas.resource_lock.claim,
		},
		permit2_escrow: GasFlowResponse {
			open: gas.permit2_escrow.open,
			fill: gas.permit2_escrow.fill,
			post_fill: gas.permit2_escrow.post_fill,
			pre_claim: gas.permit2_escrow.pre_claim,
			claim: gas.permit2_escrow.claim,
		},
		eip3009_escrow: GasFlowResponse {
			open: gas.eip3009_escrow.open,
			fill: gas.eip3009_escrow.fill,
			post_fill: gas.eip3009_escrow.post_fill,
			pre_claim: gas.eip3009_escrow.pre_claim,
			claim: gas.eip3009_escrow.claim,
		},
	}
}

fn redact_rpc_url(url: &str) -> String {
	let redacted = redact_url_credentials(url);

	let (before_fragment, fragment) = match redacted.split_once('#') {
		Some((left, frag)) => (left, Some(frag)),
		None => (redacted.as_str(), None),
	};

	let (before_query, query) = match before_fragment.split_once('?') {
		Some((left, q)) => (left, Some(q)),
		None => (before_fragment, None),
	};

	let mut base = redact_path_api_key(before_query);

	if let Some(query) = query {
		let redacted_query = redact_query_params(query);
		base.push('?');
		base.push_str(&redacted_query);
	}

	if let Some(fragment) = fragment {
		base.push('#');
		base.push_str(fragment);
	}

	base
}

/// Regex to redact path segments after TLD that look like API keys.
/// Matches: scheme://host.tld/path and redacts everything after the TLD.
/// Examples:
///   https://mainnet.infura.io/v3/abc123 -> https://mainnet.infura.io/[REDACTED]
///   https://eth-mainnet.g.alchemy.com/v2/abc123 -> https://eth-mainnet.g.alchemy.com/[REDACTED]
static PATH_API_KEY_REGEX: Lazy<Regex> = Lazy::new(|| {
	// Match scheme://host.tld and capture it, then redact everything after
	Regex::new(r"^(https?://[^/]+)/.*$").unwrap()
});

fn redact_path_api_key(url: &str) -> String {
	PATH_API_KEY_REGEX
		.replace(url, "$1/[REDACTED]")
		.into_owned()
}

/// Regex to match sensitive query parameters and redact their values.
/// Matches: apikey, api_key, key, token, secret (case-insensitive) followed by =value
static SENSITIVE_PARAM_REGEX: Lazy<Regex> =
	Lazy::new(|| Regex::new(r"(?i)((?:apikey|api_key|key|token|secret)=)[^&]*").unwrap());

fn redact_query_params(query: &str) -> String {
	SENSITIVE_PARAM_REGEX
		.replace_all(query, "$1[REDACTED]")
		.into_owned()
}

/// Convert ConfigStoreError to AdminAuthError.
fn config_store_error(err: ConfigStoreError) -> AdminAuthError {
	match err {
		ConfigStoreError::NotFound(msg) => {
			AdminAuthError::Internal(format!("Configuration not found: {msg}"))
		},
		ConfigStoreError::VersionMismatch { expected, found } => AdminAuthError::Internal(format!(
			"Configuration was modified concurrently (expected version {expected}, found {found}), please retry"
		)),
		ConfigStoreError::Serialization(msg) => {
			AdminAuthError::Internal(format!("Serialization error: {msg}"))
		},
		ConfigStoreError::Backend(msg) => AdminAuthError::Internal(format!("Storage error: {msg}")),
		ConfigStoreError::Configuration(msg) => {
			AdminAuthError::Internal(format!("Configuration error: {msg}"))
		},
		ConfigStoreError::AlreadyExists(msg) => {
			AdminAuthError::Internal(format!("Configuration already exists: {msg}"))
		},
	}
}

/// GET /api/v1/admin/types
///
/// Get EIP-712 type definitions for client-side signing.
/// Clients can use this to construct the typed data for signing.
pub async fn handle_get_types(State(state): State<AdminApiState>) -> Json<Eip712TypeInfo> {
	use crate::auth::admin::{ADMIN_DOMAIN_NAME, ADMIN_DOMAIN_VERSION};
	use solver_types::utils::admin_eip712_types;

	let verifier = state.verifier.read().await;

	Json(Eip712TypeInfo {
		domain: Eip712Domain {
			name: ADMIN_DOMAIN_NAME.to_string(),
			version: ADMIN_DOMAIN_VERSION.to_string(),
			chain_id: verifier.chain_id(),
			salt: with_0x_prefix(&hex::encode(verifier.domain_salt().as_slice())),
		},
		types: admin_eip712_types(),
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use async_trait::async_trait;
	use serial_test::serial;
	use solver_account::{AccountInterface, AccountService, AccountSigner};
	use solver_config::builders::config::ConfigBuilder;
	use solver_delivery::{DeliveryInterface, DeliveryService, MockDeliveryInterface};
	use solver_storage::StoreConfig;
	use solver_storage::{config_store::create_config_store, nonce_store::create_nonce_store};
	use solver_types::{
		NetworkType, NetworksConfig, OperatorAdminConfig, OperatorConfig, OperatorGasConfig,
		OperatorGasFlowUnits, OperatorHyperlaneConfig, OperatorNetworkConfig, OperatorOracleConfig,
		OperatorPricingConfig, OperatorRpcEndpoint, OperatorSettlementConfig,
		OperatorSettlementType, OperatorSolverConfig, OperatorWithdrawalsConfig,
	};
	use std::collections::{HashMap, HashSet};
	use std::str::FromStr;

	#[test]
	fn test_nonce_response_serialization() {
		let response = NonceResponse {
			nonce: "12345678901234567890".to_string(),
			expires_in: 300,
			domain: "test.example.com".to_string(),
			chain_id: 1,
		};

		let json = serde_json::to_string(&response).unwrap();
		// Nonce is now a string to preserve precision for JavaScript clients
		assert!(json.contains("\"nonce\":\"12345678901234567890\""));
		assert!(json.contains("\"expiresIn\":300"));
	}

	#[test]
	fn test_admin_action_response_serialization() {
		let response = AdminActionResponse {
			success: true,
			message: "Token added".to_string(),
			admin: "0x1234".to_string(),
		};

		let json = serde_json::to_string(&response).unwrap();
		assert!(json.contains("\"success\":true"));
	}

	#[test]
	fn test_admin_whitelist_response_serialization() {
		let response = AdminWhitelistResponse {
			entries: vec![
				AdminWhitelistEntry {
					address: "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266".to_string(),
					role: AdminRole::Admin,
				},
				AdminWhitelistEntry {
					address: "0x70997970c51812dc3a010c7d01b50e0d17dc79c8".to_string(),
					role: AdminRole::ReadOnly,
				},
			],
			count: 2,
		};

		let json = serde_json::to_string(&response).unwrap();
		assert!(json.contains("\"entries\""));
		assert!(json.contains("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"));
		assert!(json.contains("\"role\":\"admin\""));
		assert!(json.contains("\"role\":\"read-only\""));
		assert!(json.contains("\"count\":2"));
	}

	#[test]
	fn test_nonce_response_full_serialization() {
		let response = NonceResponse {
			nonce: "9999999999999999999".to_string(),
			expires_in: 600,
			domain: "solver.example.com".to_string(),
			chain_id: 10,
		};

		let json = serde_json::to_string(&response).unwrap();
		assert!(json.contains("\"nonce\":\"9999999999999999999\""));
		assert!(json.contains("\"expiresIn\":600"));
		assert!(json.contains("\"domain\":\"solver.example.com\""));
		assert!(json.contains("\"chainId\":10"));
	}

	#[test]
	fn test_admin_action_response_failure() {
		let response = AdminActionResponse {
			success: false,
			message: "Token already exists".to_string(),
			admin: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
		};

		let json = serde_json::to_string(&response).unwrap();
		assert!(json.contains("\"success\":false"));
		assert!(json.contains("\"message\":\"Token already exists\""));
		assert!(json.contains("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"));
	}

	#[test]
	fn test_eip712_domain_serialization() {
		let domain = Eip712Domain {
			name: "OIF Solver Admin".to_string(),
			version: "1".to_string(),
			chain_id: 1,
			salt: "0x1234".to_string(),
		};

		let json = serde_json::to_string(&domain).unwrap();
		assert!(json.contains("\"name\":\"OIF Solver Admin\""));
		assert!(json.contains("\"version\":\"1\""));
		assert!(json.contains("\"chainId\":1"));
		assert!(json.contains("\"salt\":\"0x1234\""));
	}

	#[test]
	fn test_redact_rpc_url_path_key() {
		// Alchemy-style URL
		let url = "https://eth-mainnet.g.alchemy.com/v2/abc123";
		let redacted = redact_rpc_url(url);
		assert_eq!(redacted, "https://eth-mainnet.g.alchemy.com/[REDACTED]");

		// Infura-style URL
		let url = "https://mainnet.infura.io/v3/abc123";
		let redacted = redact_rpc_url(url);
		assert_eq!(redacted, "https://mainnet.infura.io/[REDACTED]");

		// URL with no path - unchanged
		let url = "https://eth.llamarpc.com";
		let redacted = redact_rpc_url(url);
		assert_eq!(redacted, "https://eth.llamarpc.com");
	}

	#[test]
	fn test_redact_rpc_url_query_key() {
		// Path is redacted, and query params with sensitive keys are also redacted
		let url = "https://example.com/rpc?apiKey=secret&chainId=1";
		let redacted = redact_rpc_url(url);
		assert_eq!(
			redacted,
			"https://example.com/[REDACTED]?apiKey=[REDACTED]&chainId=1"
		);

		// URL with only query params (no path)
		let url = "https://example.com?apiKey=secret";
		let redacted = redact_rpc_url(url);
		assert_eq!(redacted, "https://example.com?apiKey=[REDACTED]");
	}

	#[test]
	fn test_eip712_type_info_serialization() {
		let types = serde_json::json!({
			"EIP712Domain": [
				{"name": "name", "type": "string"}
			]
		});

		let type_info = Eip712TypeInfo {
			domain: Eip712Domain {
				name: "Test".to_string(),
				version: "1".to_string(),
				chain_id: 10,
				salt: "0x00".to_string(),
			},
			types,
		};

		let json = serde_json::to_string(&type_info).unwrap();
		assert!(json.contains("\"domain\""));
		assert!(json.contains("\"types\""));
		assert!(json.contains("\"name\":\"Test\""));
		assert!(json.contains("EIP712Domain"));
	}

	#[test]
	fn test_config_store_error_not_found() {
		let err = ConfigStoreError::NotFound("solver-config".to_string());
		let admin_err = config_store_error(err);
		match admin_err {
			AdminAuthError::Internal(msg) => {
				assert!(msg.contains("Configuration not found"));
				assert!(msg.contains("solver-config"));
			},
			_ => panic!("Expected Internal error"),
		}
	}

	#[test]
	fn test_config_store_error_version_mismatch() {
		let err = ConfigStoreError::VersionMismatch {
			expected: 5,
			found: 6,
		};
		let admin_err = config_store_error(err);
		match admin_err {
			AdminAuthError::Internal(msg) => {
				assert!(msg.contains("modified concurrently"));
				assert!(msg.contains("expected version 5"));
				assert!(msg.contains("found 6"));
			},
			_ => panic!("Expected Internal error"),
		}
	}

	#[test]
	fn test_config_store_error_serialization() {
		let err = ConfigStoreError::Serialization("invalid JSON".to_string());
		let admin_err = config_store_error(err);
		match admin_err {
			AdminAuthError::Internal(msg) => {
				assert!(msg.contains("Serialization error"));
				assert!(msg.contains("invalid JSON"));
			},
			_ => panic!("Expected Internal error"),
		}
	}

	#[test]
	fn test_config_store_error_backend() {
		let err = ConfigStoreError::Backend("Redis connection failed".to_string());
		let admin_err = config_store_error(err);
		match admin_err {
			AdminAuthError::Internal(msg) => {
				assert!(msg.contains("Storage error"));
				assert!(msg.contains("Redis connection failed"));
			},
			_ => panic!("Expected Internal error"),
		}
	}

	#[test]
	fn test_config_store_error_configuration() {
		let err = ConfigStoreError::Configuration("Invalid URL".to_string());
		let admin_err = config_store_error(err);
		match admin_err {
			AdminAuthError::Internal(msg) => {
				assert!(msg.contains("Configuration error"));
				assert!(msg.contains("Invalid URL"));
			},
			_ => panic!("Expected Internal error"),
		}
	}

	#[test]
	fn test_config_store_error_already_exists() {
		let err = ConfigStoreError::AlreadyExists("solver-config".to_string());
		let admin_err = config_store_error(err);
		match admin_err {
			AdminAuthError::Internal(msg) => {
				assert!(msg.contains("already exists"));
				assert!(msg.contains("solver-config"));
			},
			_ => panic!("Expected Internal error"),
		}
	}

	struct DummyAccount {
		address: solver_types::Address,
	}

	#[async_trait]
	impl AccountInterface for DummyAccount {
		async fn address(&self) -> Result<solver_types::Address, solver_account::AccountError> {
			Ok(self.address.clone())
		}

		fn signer(&self) -> AccountSigner {
			use alloy_signer_local::PrivateKeySigner;
			let signer: PrivateKeySigner =
				"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
					.parse()
					.unwrap();
			AccountSigner::Local(signer)
		}
	}

	fn build_operator_config(
		admin_address: alloy_primitives::Address,
		withdrawals: OperatorWithdrawalsConfig,
	) -> OperatorConfig {
		OperatorConfig {
			solver_id: "test-solver".to_string(),
			solver_name: Some("Test Solver".to_string()),
			networks: HashMap::new(),
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
					domains: HashMap::new(),
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
				live_fill_estimate_enabled: true,
				live_post_fill_estimate_chain_ids: HashSet::new(),
			},
			pricing: OperatorPricingConfig {
				primary: "coingecko".to_string(),
				fallbacks: Vec::new(),
				cache_duration_seconds: 60,
				custom_prices: HashMap::new(),
			},
			solver: OperatorSolverConfig {
				min_profitability_pct: rust_decimal::Decimal::ZERO,
				gas_buffer_bps: 1000,
				settlement_fee_buffer_bps: 1000,
				commission_bps: 20,
				rate_buffer_bps: 14,
				monitoring_timeout_seconds: 60,
				deny_list: None,
				resource_lock_enabled: false,
			},
			admin: OperatorAdminConfig {
				enabled: true,
				domain: "test.example.com".to_string(),
				chain_id: 1,
				nonce_ttl_seconds: 300,
				whitelist: vec![solver_types::AdminWhitelistEntry {
					address: admin_address,
					role: AdminRole::Admin,
				}],
				withdrawals,
			},
			orders_auth_enabled: false,
			account: None,
			rebalance: None,
			fee_policy: None,
			tx_bump: solver_types::OperatorTxBumpConfig::default(),
			source_finality: None,
		}
	}

	fn alloy_address(hex: &str) -> alloy_primitives::Address {
		alloy_primitives::Address::from_str(hex).unwrap()
	}

	fn solver_address(hex: &str) -> solver_types::Address {
		solver_types::Address::from(alloy_primitives::Address::from_str(hex).unwrap())
	}

	fn zero_alloy_address() -> alloy_primitives::Address {
		alloy_primitives::Address::ZERO
	}

	fn create_delivery_service(balance: Option<&str>, expect_submit: bool) -> Arc<DeliveryService> {
		let mut mock_delivery = MockDeliveryInterface::new();
		if let Some(balance) = balance {
			let balance_str = balance.to_string();
			mock_delivery
				.expect_get_balance()
				.returning(move |_, _, _| {
					let balance = balance_str.clone();
					Box::pin(async move { Ok(balance) })
				});
		}
		if expect_submit {
			mock_delivery.expect_submit().returning(|_, _| {
				Box::pin(async { Ok(solver_types::TransactionHash(vec![0x11; 32])) })
			});
		}
		mock_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});

		let mut implementations: HashMap<u64, Arc<dyn DeliveryInterface>> = HashMap::new();
		implementations.insert(1, Arc::new(mock_delivery));

		Arc::new(DeliveryService::new(implementations, 1, 30, 60))
	}

	async fn create_admin_state(
		balance: Option<&str>,
		withdrawals: OperatorWithdrawalsConfig,
		expect_submit: bool,
	) -> AdminApiState {
		let admin_alloy = alloy_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
		let admin_solver = solver_types::Address::from(admin_alloy);
		let operator_config = build_operator_config(admin_alloy, withdrawals);

		let config_store =
			create_config_store::<OperatorConfig>(StoreConfig::Memory, "test-solver".to_string())
				.unwrap();
		config_store.seed(operator_config).await.unwrap();
		let config_store: Arc<dyn solver_storage::config_store::ConfigStore<OperatorConfig>> =
			Arc::from(config_store);

		let nonce_store =
			Arc::new(create_nonce_store(StoreConfig::Memory, "test-solver", 300).unwrap());
		let verifier = AdminActionVerifier::new(
			nonce_store.clone(),
			AdminConfig {
				enabled: true,
				domain: "test.example.com".to_string(),
				chain_id: Some(1),
				nonce_ttl_seconds: 300,
				whitelist: vec![SolverAdminWhitelistEntry {
					address: admin_alloy,
					role: AdminRole::Admin,
				}],
			},
			1,
			"test-solver",
		);

		let account = Arc::new(AccountService::new(Box::new(DummyAccount {
			address: admin_solver,
		})));
		let delivery = create_delivery_service(balance, expect_submit);
		let token_manager = Arc::new(TokenManager::new(
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
			solver_id: "test-solver".to_string(),
			token_manager,
			bridge_service: None,
			solver_address: "0x0000000000000000000000000000000000000000".to_string(),
			delivery,
			rebalance_monitor_status: Arc::new(tokio::sync::RwLock::new(
				solver_bridge::monitor::RebalanceMonitorStatus::default(),
			)),
		}
	}

	async fn create_admin_state_with_operator_config(
		operator_config: OperatorConfig,
		delivery: Arc<DeliveryService>,
	) -> AdminApiState {
		let admin_alloy = alloy_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
		let admin_solver = solver_types::Address::from(admin_alloy);

		let config_store =
			create_config_store::<OperatorConfig>(StoreConfig::Memory, "test-solver".to_string())
				.unwrap();
		config_store.seed(operator_config).await.unwrap();
		let config_store: Arc<dyn solver_storage::config_store::ConfigStore<OperatorConfig>> =
			Arc::from(config_store);

		let nonce_store =
			Arc::new(create_nonce_store(StoreConfig::Memory, "test-solver", 300).unwrap());
		let verifier = AdminActionVerifier::new(
			nonce_store.clone(),
			AdminConfig {
				enabled: true,
				domain: "test.example.com".to_string(),
				chain_id: Some(1),
				nonce_ttl_seconds: 300,
				whitelist: vec![SolverAdminWhitelistEntry {
					address: admin_alloy,
					role: AdminRole::Admin,
				}],
			},
			1,
			"test-solver",
		);

		let account = Arc::new(AccountService::new(Box::new(DummyAccount {
			address: admin_solver,
		})));
		let token_manager = Arc::new(TokenManager::new(
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
			solver_id: "test-solver".to_string(),
			token_manager,
			bridge_service: None,
			solver_address: "0x0000000000000000000000000000000000000000".to_string(),
			delivery,
			rebalance_monitor_status: Arc::new(tokio::sync::RwLock::new(
				solver_bridge::monitor::RebalanceMonitorStatus::default(),
			)),
		}
	}

	#[tokio::test]
	async fn test_handle_get_balances_uses_configured_native_metadata_once() {
		use solver_types::networks::{
			NetworkConfig as RuntimeNetworkConfig, RpcEndpoint, TokenConfig,
		};

		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_get_balance()
			.times(2)
			.returning(|_, token, chain_id| {
				assert_eq!(chain_id, 1);
				let balance = match token {
					None => "5000000000000000000".to_string(),
					Some("5555555555555555555555555555555555555555") => "1000000".to_string(),
					Some(other) => panic!("unexpected balance query for {other}"),
				};
				Box::pin(async move { Ok(balance) })
			});
		mock_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});

		let mut implementations: HashMap<u64, Arc<dyn DeliveryInterface>> = HashMap::new();
		implementations.insert(1, Arc::new(mock_delivery));
		let delivery = Arc::new(DeliveryService::new(implementations, 1, 30, 60));
		let withdrawals = OperatorWithdrawalsConfig {
			enabled: true,
			recipient_allowlist: vec![],
		};
		let operator_config = build_operator_config(
			alloy_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
			withdrawals,
		);
		let state = create_admin_state_with_operator_config(operator_config, delivery).await;

		let native = TokenConfig {
			address: solver_types::Address(vec![0u8; 20]),
			symbol: "ETH".to_string(),
			name: Some("Ether".to_string()),
			decimals: 18,
		};
		let erc20 = TokenConfig {
			address: solver_address("0x5555555555555555555555555555555555555555"),
			symbol: "USDC".to_string(),
			name: Some("USD Coin".to_string()),
			decimals: 6,
		};
		let mut networks = NetworksConfig::default();
		networks.insert(
			1,
			RuntimeNetworkConfig {
				name: Some("mainnet".to_string()),
				network_type: NetworkType::Parent,
				rpc_urls: vec![RpcEndpoint::http_only("http://localhost:8545".to_string())],
				input_settler_address: solver_address("0x1111111111111111111111111111111111111111"),
				output_settler_address: solver_address(
					"0x2222222222222222222222222222222222222222",
				),
				tokens: vec![native.clone(), erc20],
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);
		state.token_manager.update_networks(networks).await;

		let response = handle_get_balances(State(state)).await.unwrap().0;
		let tokens = &response.networks.get("1").unwrap().tokens;
		let native_rows: Vec<_> = tokens
			.iter()
			.filter(|token| token.address == native.address.to_string())
			.collect();

		assert_eq!(tokens.len(), 2);
		assert_eq!(native_rows.len(), 1);
		assert_eq!(native_rows[0].symbol, "ETH");
		assert_eq!(native_rows[0].name.as_deref(), Some("Ether"));
		assert_eq!(native_rows[0].balance, "5000000000000000000");
	}

	struct EnvVarGuard {
		key: &'static str,
		original: Option<String>,
	}

	impl EnvVarGuard {
		fn set(key: &'static str, value: impl AsRef<str>) -> Self {
			let original = std::env::var(key).ok();
			std::env::set_var(key, value.as_ref());
			Self { key, original }
		}
	}

	impl Drop for EnvVarGuard {
		fn drop(&mut self) {
			match &self.original {
				Some(value) => std::env::set_var(self.key, value),
				None => std::env::remove_var(self.key),
			}
		}
	}

	fn strong_jwt_secret_guard() -> EnvVarGuard {
		EnvVarGuard::set("JWT_SECRET", "x".repeat(32))
	}

	#[tokio::test]
	#[serial]
	async fn test_handle_add_token_triggers_approval_setup() {
		let _jwt_secret = strong_jwt_secret_guard();
		let admin_alloy = alloy_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
		let mut operator_config = build_operator_config(
			admin_alloy,
			OperatorWithdrawalsConfig {
				enabled: true,
				recipient_allowlist: vec![],
			},
		);

		operator_config.networks.insert(
			1,
			OperatorNetworkConfig {
				chain_id: 1,
				name: "chain-1".to_string(),
				network_type: NetworkType::Parent,
				tokens: vec![],
				rpc_urls: vec![OperatorRpcEndpoint {
					http: "http://localhost:8545".to_string(),
					ws: None,
				}],
				input_settler_address: alloy_address("0x1111111111111111111111111111111111111111"),
				output_settler_address: alloy_address("0x2222222222222222222222222222222222222222"),
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);
		operator_config.networks.insert(
			137,
			OperatorNetworkConfig {
				chain_id: 137,
				name: "chain-137".to_string(),
				network_type: NetworkType::Hub,
				tokens: vec![],
				rpc_urls: vec![OperatorRpcEndpoint {
					http: "http://localhost:8546".to_string(),
					ws: None,
				}],
				input_settler_address: alloy_address("0x3333333333333333333333333333333333333333"),
				output_settler_address: alloy_address("0x4444444444444444444444444444444444444444"),
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);

		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_get_allowance()
			.times(2)
			.returning(|_, _, _, _| Box::pin(async { Ok("0".to_string()) }));
		mock_delivery.expect_submit().times(2).returning(|_, _| {
			Box::pin(async { Ok(solver_types::TransactionHash(vec![0x11; 32])) })
		});
		mock_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});

		let mut implementations: HashMap<u64, Arc<dyn DeliveryInterface>> = HashMap::new();
		implementations.insert(1, Arc::new(mock_delivery));
		let delivery = Arc::new(DeliveryService::new(implementations, 1, 30, 60));

		let state = create_admin_state_with_operator_config(operator_config, delivery).await;
		let state_for_assert = state.clone();

		let contents = AddTokenContents {
			chain_id: 1,
			symbol: "USDC".to_string(),
			name: Some("USD Coin".to_string()),
			token_address: alloy_address("0x5555555555555555555555555555555555555555"),
			decimals: 6,
			nonce: 1,
			deadline: chrono::Utc::now().timestamp() as u64 + 3600,
		};

		let verified = VerifiedAdmin {
			admin: solver_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
			contents,
		};

		let response = handle_add_token(State(state), verified).await.unwrap().0;
		assert!(response.success);
		assert!(response.message.contains("Token USDC added to chain 1"));

		let versioned = state_for_assert.config_store.get().await.unwrap();
		let network = versioned.data.networks.get(&1).unwrap();
		assert_eq!(network.tokens.len(), 1);
		assert_eq!(network.tokens[0].symbol, "USDC");
	}

	#[tokio::test]
	#[serial]
	async fn test_handle_add_tokens_triggers_approval_setup() {
		let _jwt_secret = strong_jwt_secret_guard();
		let admin_alloy = alloy_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
		let mut operator_config = build_operator_config(
			admin_alloy,
			OperatorWithdrawalsConfig {
				enabled: true,
				recipient_allowlist: vec![],
			},
		);

		operator_config.networks.insert(
			1,
			OperatorNetworkConfig {
				chain_id: 1,
				name: "chain-1".to_string(),
				network_type: NetworkType::Parent,
				tokens: vec![],
				rpc_urls: vec![OperatorRpcEndpoint {
					http: "http://localhost:8545".to_string(),
					ws: None,
				}],
				input_settler_address: alloy_address("0x1111111111111111111111111111111111111111"),
				output_settler_address: alloy_address("0x2222222222222222222222222222222222222222"),
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);
		operator_config.networks.insert(
			137,
			OperatorNetworkConfig {
				chain_id: 137,
				name: "chain-137".to_string(),
				network_type: NetworkType::Hub,
				tokens: vec![],
				rpc_urls: vec![OperatorRpcEndpoint {
					http: "http://localhost:8546".to_string(),
					ws: None,
				}],
				input_settler_address: alloy_address("0x3333333333333333333333333333333333333333"),
				output_settler_address: alloy_address("0x4444444444444444444444444444444444444444"),
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);

		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_get_allowance()
			.times(4)
			.returning(|_, _, _, _| Box::pin(async { Ok("0".to_string()) }));
		mock_delivery.expect_submit().times(4).returning(|_, _| {
			Box::pin(async { Ok(solver_types::TransactionHash(vec![0x11; 32])) })
		});
		mock_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});

		let mut implementations: HashMap<u64, Arc<dyn DeliveryInterface>> = HashMap::new();
		implementations.insert(1, Arc::new(mock_delivery));
		let delivery = Arc::new(DeliveryService::new(implementations, 1, 30, 60));

		let state = create_admin_state_with_operator_config(operator_config, delivery).await;
		let state_for_assert = state.clone();

		let contents = AddTokensContents {
			tokens: vec![
				crate::auth::admin::AddTokenItemContents {
					chain_id: 1,
					symbol: "USDC".to_string(),
					name: Some("USD Coin".to_string()),
					token_address: alloy_address("0x5555555555555555555555555555555555555555"),
					decimals: 6,
				},
				crate::auth::admin::AddTokenItemContents {
					chain_id: 1,
					symbol: "USDT".to_string(),
					name: Some("Tether USD".to_string()),
					token_address: alloy_address("0x6666666666666666666666666666666666666666"),
					decimals: 6,
				},
			],
			nonce: 1,
			deadline: chrono::Utc::now().timestamp() as u64 + 3600,
		};

		let verified = VerifiedAdmin {
			admin: solver_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
			contents,
		};

		let response = handle_add_tokens(State(state), verified).await.unwrap().0;
		assert!(response.success);
		assert_eq!(response.message, "Added 2 tokens");

		let versioned = state_for_assert.config_store.get().await.unwrap();
		let network = versioned.data.networks.get(&1).unwrap();
		assert_eq!(network.tokens.len(), 2);
		assert_eq!(network.tokens[0].symbol, "USDC");
		assert_eq!(network.tokens[1].symbol, "USDT");
	}

	#[tokio::test]
	#[serial]
	async fn test_handle_add_token_approval_failure_is_atomic() {
		let _jwt_secret = strong_jwt_secret_guard();
		let admin_alloy = alloy_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
		let mut operator_config = build_operator_config(
			admin_alloy,
			OperatorWithdrawalsConfig {
				enabled: true,
				recipient_allowlist: vec![],
			},
		);

		operator_config.networks.insert(
			1,
			OperatorNetworkConfig {
				chain_id: 1,
				name: "chain-1".to_string(),
				network_type: NetworkType::Parent,
				tokens: vec![],
				rpc_urls: vec![OperatorRpcEndpoint {
					http: "http://localhost:8545".to_string(),
					ws: None,
				}],
				input_settler_address: alloy_address("0x1111111111111111111111111111111111111111"),
				output_settler_address: alloy_address("0x2222222222222222222222222222222222222222"),
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);
		operator_config.networks.insert(
			137,
			OperatorNetworkConfig {
				chain_id: 137,
				name: "chain-137".to_string(),
				network_type: NetworkType::Hub,
				tokens: vec![],
				rpc_urls: vec![OperatorRpcEndpoint {
					http: "http://localhost:8546".to_string(),
					ws: None,
				}],
				input_settler_address: alloy_address("0x3333333333333333333333333333333333333333"),
				output_settler_address: alloy_address("0x4444444444444444444444444444444444444444"),
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);

		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_get_allowance()
			.times(1..)
			.returning(|_, _, _, _| {
				Box::pin(async {
					Err(solver_delivery::DeliveryError::Network(
						"Invalid allowance response".to_string(),
					))
				})
			});
		mock_delivery.expect_submit().times(0);
		mock_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});

		let mut implementations: HashMap<u64, Arc<dyn DeliveryInterface>> = HashMap::new();
		implementations.insert(1, Arc::new(mock_delivery));
		let delivery = Arc::new(DeliveryService::new(implementations, 1, 30, 60));

		let state = create_admin_state_with_operator_config(operator_config, delivery).await;
		let state_for_assert = state.clone();
		let token_address = alloy_address("0x5555555555555555555555555555555555555555");

		let contents = AddTokenContents {
			chain_id: 1,
			symbol: "USDC".to_string(),
			name: Some("USD Coin".to_string()),
			token_address,
			decimals: 6,
			nonce: 1,
			deadline: chrono::Utc::now().timestamp() as u64 + 3600,
		};

		let verified = VerifiedAdmin {
			admin: solver_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
			contents,
		};

		let err = match handle_add_token(State(state), verified).await {
			Err(err) => err,
			Ok(_) => panic!("Expected approval setup failure"),
		};
		assert!(matches!(err, AdminAuthError::Internal(_)));

		let versioned = state_for_assert.config_store.get().await.unwrap();
		let network = versioned.data.networks.get(&1).unwrap();
		assert_eq!(network.tokens.len(), 0);

		let token_address = solver_types::Address::from(token_address);
		assert!(
			!state_for_assert
				.token_manager
				.is_supported(1, &token_address)
				.await
		);
	}

	#[tokio::test]
	#[serial]
	async fn test_handle_add_tokens_approval_failure_is_atomic() {
		let _jwt_secret = strong_jwt_secret_guard();
		let admin_alloy = alloy_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
		let mut operator_config = build_operator_config(
			admin_alloy,
			OperatorWithdrawalsConfig {
				enabled: true,
				recipient_allowlist: vec![],
			},
		);

		operator_config.networks.insert(
			1,
			OperatorNetworkConfig {
				chain_id: 1,
				name: "chain-1".to_string(),
				network_type: NetworkType::Parent,
				tokens: vec![],
				rpc_urls: vec![OperatorRpcEndpoint {
					http: "http://localhost:8545".to_string(),
					ws: None,
				}],
				input_settler_address: alloy_address("0x1111111111111111111111111111111111111111"),
				output_settler_address: alloy_address("0x2222222222222222222222222222222222222222"),
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);
		operator_config.networks.insert(
			137,
			OperatorNetworkConfig {
				chain_id: 137,
				name: "chain-137".to_string(),
				network_type: NetworkType::Hub,
				tokens: vec![],
				rpc_urls: vec![OperatorRpcEndpoint {
					http: "http://localhost:8546".to_string(),
					ws: None,
				}],
				input_settler_address: alloy_address("0x3333333333333333333333333333333333333333"),
				output_settler_address: alloy_address("0x4444444444444444444444444444444444444444"),
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);

		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_get_allowance()
			.times(1..)
			.returning(|_, _, _, _| {
				Box::pin(async {
					Err(solver_delivery::DeliveryError::Network(
						"Invalid allowance response".to_string(),
					))
				})
			});
		mock_delivery.expect_submit().times(0);
		mock_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});

		let mut implementations: HashMap<u64, Arc<dyn DeliveryInterface>> = HashMap::new();
		implementations.insert(1, Arc::new(mock_delivery));
		let delivery = Arc::new(DeliveryService::new(implementations, 1, 30, 60));

		let state = create_admin_state_with_operator_config(operator_config, delivery).await;
		let state_for_assert = state.clone();

		let contents = AddTokensContents {
			tokens: vec![
				crate::auth::admin::AddTokenItemContents {
					chain_id: 1,
					symbol: "USDC".to_string(),
					name: Some("USD Coin".to_string()),
					token_address: alloy_address("0x5555555555555555555555555555555555555555"),
					decimals: 6,
				},
				crate::auth::admin::AddTokenItemContents {
					chain_id: 1,
					symbol: "USDT".to_string(),
					name: Some("Tether USD".to_string()),
					token_address: alloy_address("0x6666666666666666666666666666666666666666"),
					decimals: 6,
				},
			],
			nonce: 1,
			deadline: chrono::Utc::now().timestamp() as u64 + 3600,
		};

		let verified = VerifiedAdmin {
			admin: solver_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
			contents,
		};

		let err = match handle_add_tokens(State(state), verified).await {
			Err(err) => err,
			Ok(_) => panic!("Expected approval setup failure"),
		};
		assert!(matches!(err, AdminAuthError::Internal(_)));

		let versioned = state_for_assert.config_store.get().await.unwrap();
		let network = versioned.data.networks.get(&1).unwrap();
		assert_eq!(network.tokens.len(), 0);
	}

	#[tokio::test]
	async fn test_handle_add_tokens_rejects_small_batch() {
		let admin_alloy = alloy_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
		let mut operator_config = build_operator_config(
			admin_alloy,
			OperatorWithdrawalsConfig {
				enabled: true,
				recipient_allowlist: vec![],
			},
		);
		operator_config.networks.insert(
			1,
			OperatorNetworkConfig {
				chain_id: 1,
				name: "chain-1".to_string(),
				network_type: NetworkType::Parent,
				tokens: vec![],
				rpc_urls: vec![OperatorRpcEndpoint {
					http: "http://localhost:8545".to_string(),
					ws: None,
				}],
				input_settler_address: alloy_address("0x1111111111111111111111111111111111111111"),
				output_settler_address: alloy_address("0x2222222222222222222222222222222222222222"),
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);

		let delivery = create_delivery_service(None, false);
		let state = create_admin_state_with_operator_config(operator_config, delivery).await;

		let contents = AddTokensContents {
			tokens: vec![crate::auth::admin::AddTokenItemContents {
				chain_id: 1,
				symbol: "USDC".to_string(),
				name: Some("USD Coin".to_string()),
				token_address: alloy_address("0x5555555555555555555555555555555555555555"),
				decimals: 6,
			}],
			nonce: 1,
			deadline: chrono::Utc::now().timestamp() as u64 + 3600,
		};

		let verified = VerifiedAdmin {
			admin: solver_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
			contents,
		};

		let err = match handle_add_tokens(State(state), verified).await {
			Err(err) => err,
			Ok(_) => panic!("Expected small batch to fail"),
		};
		assert!(matches!(err, AdminAuthError::InvalidMessage(_)));
		assert!(format!("{err}").contains("at least 2"));
	}

	#[tokio::test]
	async fn test_handle_add_tokens_rejects_duplicate_payload_entries() {
		let admin_alloy = alloy_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
		let mut operator_config = build_operator_config(
			admin_alloy,
			OperatorWithdrawalsConfig {
				enabled: true,
				recipient_allowlist: vec![],
			},
		);
		operator_config.networks.insert(
			1,
			OperatorNetworkConfig {
				chain_id: 1,
				name: "chain-1".to_string(),
				network_type: NetworkType::Parent,
				tokens: vec![],
				rpc_urls: vec![OperatorRpcEndpoint {
					http: "http://localhost:8545".to_string(),
					ws: None,
				}],
				input_settler_address: alloy_address("0x1111111111111111111111111111111111111111"),
				output_settler_address: alloy_address("0x2222222222222222222222222222222222222222"),
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);

		let delivery = create_delivery_service(None, false);
		let state = create_admin_state_with_operator_config(operator_config, delivery).await;
		let state_for_assert = state.clone();
		let duplicate_address = alloy_address("0x5555555555555555555555555555555555555555");

		let contents = AddTokensContents {
			tokens: vec![
				crate::auth::admin::AddTokenItemContents {
					chain_id: 1,
					symbol: "USDC".to_string(),
					name: Some("USD Coin".to_string()),
					token_address: duplicate_address,
					decimals: 6,
				},
				crate::auth::admin::AddTokenItemContents {
					chain_id: 1,
					symbol: "USDCv2".to_string(),
					name: Some("USD Coin v2".to_string()),
					token_address: duplicate_address,
					decimals: 6,
				},
			],
			nonce: 1,
			deadline: chrono::Utc::now().timestamp() as u64 + 3600,
		};

		let verified = VerifiedAdmin {
			admin: solver_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
			contents,
		};

		let err = match handle_add_tokens(State(state), verified).await {
			Err(err) => err,
			Ok(_) => panic!("Expected duplicate payload entries to fail"),
		};
		assert!(matches!(err, AdminAuthError::InvalidMessage(_)));
		assert!(format!("{err}").contains("Duplicate token"));

		let versioned = state_for_assert.config_store.get().await.unwrap();
		assert_eq!(versioned.data.networks.get(&1).unwrap().tokens.len(), 0);
	}

	#[tokio::test]
	async fn test_handle_add_tokens_atomic_validation() {
		let admin_alloy = alloy_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
		let mut operator_config = build_operator_config(
			admin_alloy,
			OperatorWithdrawalsConfig {
				enabled: true,
				recipient_allowlist: vec![],
			},
		);
		operator_config.networks.insert(
			1,
			OperatorNetworkConfig {
				chain_id: 1,
				name: "chain-1".to_string(),
				network_type: NetworkType::Parent,
				tokens: vec![],
				rpc_urls: vec![OperatorRpcEndpoint {
					http: "http://localhost:8545".to_string(),
					ws: None,
				}],
				input_settler_address: alloy_address("0x1111111111111111111111111111111111111111"),
				output_settler_address: alloy_address("0x2222222222222222222222222222222222222222"),
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);

		let delivery = create_delivery_service(None, false);
		let state = create_admin_state_with_operator_config(operator_config, delivery).await;
		let state_for_assert = state.clone();

		let contents = AddTokensContents {
			tokens: vec![
				crate::auth::admin::AddTokenItemContents {
					chain_id: 1,
					symbol: "USDC".to_string(),
					name: Some("USD Coin".to_string()),
					token_address: alloy_address("0x5555555555555555555555555555555555555555"),
					decimals: 6,
				},
				crate::auth::admin::AddTokenItemContents {
					chain_id: 999,
					symbol: "USDT".to_string(),
					name: Some("Tether USD".to_string()),
					token_address: alloy_address("0x6666666666666666666666666666666666666666"),
					decimals: 6,
				},
			],
			nonce: 1,
			deadline: chrono::Utc::now().timestamp() as u64 + 3600,
		};

		let verified = VerifiedAdmin {
			admin: solver_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
			contents,
		};

		let err = match handle_add_tokens(State(state), verified).await {
			Err(err) => err,
			Ok(_) => panic!("Expected validation failure for unknown chain"),
		};
		assert!(matches!(err, AdminAuthError::InvalidMessage(_)));
		assert!(format!("{err}").contains("Network 999 not found"));

		let versioned = state_for_assert.config_store.get().await.unwrap();
		assert_eq!(versioned.data.networks.get(&1).unwrap().tokens.len(), 0);
	}

	#[tokio::test]
	async fn test_withdraw_success() {
		let recipient = alloy_address("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
		let withdrawals = OperatorWithdrawalsConfig {
			enabled: true,
			recipient_allowlist: vec![],
		};

		let state = create_admin_state(Some("1000000000000000000"), withdrawals, true).await;
		let contents = WithdrawContents {
			chain_id: 1,
			token: zero_alloy_address(),
			amount: "100000000000000000".to_string(),
			recipient,
			nonce: 1,
			deadline: chrono::Utc::now().timestamp() as u64 + 3600,
		};

		let verified = VerifiedAdmin {
			admin: solver_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
			contents,
		};

		let response = handle_withdrawal(State(state), verified).await.unwrap();
		assert!(response.success);
		assert_eq!(response.status, "submitted");
		assert!(response.tx_hash.as_ref().unwrap().starts_with("0x"));
	}

	#[tokio::test]
	async fn test_withdraw_recipient_not_in_allowlist_is_rejected() {
		// Operator pinned a single recipient. A different recipient — even one
		// signed by a legitimate admin — must be rejected before any balance
		// query or token transfer is attempted.
		let approved = alloy_address("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
		let attacker = alloy_address("0xdEAdBeEFdEadBEefDEAdbEEFdeadBEEFDEadBeeF");
		let withdrawals = OperatorWithdrawalsConfig {
			enabled: true,
			recipient_allowlist: vec![approved],
		};

		let state = create_admin_state(Some("1000000000000000000"), withdrawals, false).await;
		let contents = WithdrawContents {
			chain_id: 1,
			token: zero_alloy_address(),
			amount: "1".to_string(),
			recipient: attacker,
			nonce: 1,
			deadline: chrono::Utc::now().timestamp() as u64 + 3600,
		};

		let verified = VerifiedAdmin {
			admin: solver_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
			contents,
		};

		let err = handle_withdrawal(State(state), verified).await.unwrap_err();
		assert!(
			matches!(&err, AdminAuthError::NotAuthorized(msg) if msg.contains("allowlist")),
			"expected NotAuthorized(allowlist), got {err:?}"
		);
	}

	#[tokio::test]
	async fn test_withdraw_recipient_in_allowlist_succeeds() {
		// Same allowlist setup as above, but the request targets an approved
		// recipient — must succeed end-to-end.
		let approved = alloy_address("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
		let withdrawals = OperatorWithdrawalsConfig {
			enabled: true,
			recipient_allowlist: vec![approved],
		};

		let state = create_admin_state(Some("1000000000000000000"), withdrawals, true).await;
		let contents = WithdrawContents {
			chain_id: 1,
			token: zero_alloy_address(),
			amount: "100000000000000000".to_string(),
			recipient: approved,
			nonce: 1,
			deadline: chrono::Utc::now().timestamp() as u64 + 3600,
		};

		let verified = VerifiedAdmin {
			admin: solver_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
			contents,
		};

		let response = handle_withdrawal(State(state), verified).await.unwrap();
		assert!(response.success);
	}

	#[tokio::test]
	async fn test_withdraw_insufficient_funds() {
		let recipient = alloy_address("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
		let withdrawals = OperatorWithdrawalsConfig {
			enabled: true,
			recipient_allowlist: vec![],
		};

		let state = create_admin_state(Some("10"), withdrawals, false).await;
		let contents = WithdrawContents {
			chain_id: 1,
			token: zero_alloy_address(),
			amount: "100".to_string(),
			recipient,
			nonce: 1,
			deadline: chrono::Utc::now().timestamp() as u64 + 3600,
		};

		let verified = VerifiedAdmin {
			admin: solver_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
			contents,
		};

		let err = handle_withdrawal(State(state), verified).await.unwrap_err();
		assert!(matches!(err, AdminAuthError::InvalidMessage(_)));
	}

	#[tokio::test]
	async fn test_verified_admin_bad_signature() {
		let recipient = alloy_address("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
		let withdrawals = OperatorWithdrawalsConfig {
			enabled: true,
			recipient_allowlist: vec![],
		};

		let state = create_admin_state(None, withdrawals, false).await;
		let verifier = state.verifier.read().await;
		let nonce = verifier.generate_nonce().await.unwrap();

		let contents = WithdrawContents {
			chain_id: 1,
			token: zero_alloy_address(),
			amount: "1".to_string(),
			recipient,
			nonce,
			deadline: chrono::Utc::now().timestamp() as u64 + 3600,
		};

		let payload = serde_json::json!({
			"signature": "0x12",
			"contents": contents
		});

		let request = Request::builder()
			.method("POST")
			.uri("/admin/withdrawals")
			.header("content-type", "application/json")
			.body(Body::from(payload.to_string()))
			.unwrap();

		let result = VerifiedAdmin::<WithdrawContents>::from_request(request, &state).await;
		assert!(matches!(result, Err(AdminAuthError::InvalidSignature(_))));
	}

	#[test]
	fn test_eip712_domain_different_chains() {
		let mainnet = Eip712Domain {
			name: "Solver".to_string(),
			version: "1".to_string(),
			chain_id: 1,
			salt: "0x00".to_string(),
		};

		let optimism = Eip712Domain {
			name: "Solver".to_string(),
			version: "1".to_string(),
			chain_id: 10,
			salt: "0x00".to_string(),
		};

		let mainnet_json = serde_json::to_string(&mainnet).unwrap();
		let optimism_json = serde_json::to_string(&optimism).unwrap();

		assert!(mainnet_json.contains("\"chainId\":1"));
		assert!(optimism_json.contains("\"chainId\":10"));
		assert_ne!(mainnet_json, optimism_json);
	}

	#[tokio::test]
	async fn test_handle_get_fees() {
		let withdrawals = OperatorWithdrawalsConfig {
			enabled: false,
			recipient_allowlist: vec![],
		};
		let state = create_admin_state(None, withdrawals, false).await;
		let response = handle_get_fees(State(state)).await;

		// ConfigBuilder default values
		assert_eq!(response.min_profitability_pct, "0");
		assert_eq!(response.gas_buffer_bps, 1000);
		assert_eq!(response.settlement_fee_buffer_bps, 1000);
		assert_eq!(response.commission_bps, 0); // Disabled by default for backward compatibility
		assert_eq!(response.rate_buffer_bps, 14);
	}

	#[tokio::test]
	#[serial]
	async fn test_handle_update_fees_updates_settlement_fee_buffer() {
		let _jwt_secret = strong_jwt_secret_guard();
		let admin = alloy_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
		let withdrawals = OperatorWithdrawalsConfig {
			enabled: false,
			recipient_allowlist: vec![],
		};
		let mut operator_config = build_operator_config(admin, withdrawals);
		operator_config.networks.insert(
			1,
			OperatorNetworkConfig {
				chain_id: 1,
				name: "chain-1".to_string(),
				network_type: NetworkType::Parent,
				tokens: vec![],
				rpc_urls: vec![OperatorRpcEndpoint {
					http: "http://localhost:8545".to_string(),
					ws: None,
				}],
				input_settler_address: alloy_address("0x1111111111111111111111111111111111111111"),
				output_settler_address: alloy_address("0x2222222222222222222222222222222222222222"),
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);
		operator_config.networks.insert(
			137,
			OperatorNetworkConfig {
				chain_id: 137,
				name: "chain-137".to_string(),
				network_type: NetworkType::Hub,
				tokens: vec![],
				rpc_urls: vec![OperatorRpcEndpoint {
					http: "http://localhost:8546".to_string(),
					ws: None,
				}],
				input_settler_address: alloy_address("0x3333333333333333333333333333333333333333"),
				output_settler_address: alloy_address("0x4444444444444444444444444444444444444444"),
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);
		let state = create_admin_state_with_operator_config(
			operator_config,
			create_delivery_service(None, false),
		)
		.await;
		let state_for_assert = state.clone();

		let response = handle_update_fees(
			State(state),
			VerifiedAdmin {
				admin: solver_types::Address::from(admin),
				contents: UpdateFeeConfigContents {
					gas_buffer_bps: 1500,
					settlement_fee_buffer_bps: 2500,
					min_profitability_pct: "2.5".to_string(),
					commission_bps: 20,
					rate_buffer_bps: 14,
					nonce: 1,
					deadline: chrono::Utc::now().timestamp() as u64 + 3600,
				},
			},
		)
		.await
		.unwrap()
		.0;

		assert!(response.success);
		assert!(response.message.contains("settlementFeeBufferBps=2500"));

		let versioned = state_for_assert.config_store.get().await.unwrap();
		assert_eq!(versioned.data.solver.settlement_fee_buffer_bps, 2500);
		assert_eq!(
			state_for_assert
				.dynamic_config
				.read()
				.await
				.solver
				.settlement_fee_buffer_bps,
			2500
		);
	}

	#[tokio::test]
	async fn test_handle_get_nonce() {
		let withdrawals = OperatorWithdrawalsConfig {
			enabled: false,
			recipient_allowlist: vec![],
		};
		let state = create_admin_state(None, withdrawals, false).await;
		let result = handle_get_nonce(State(state)).await;

		assert!(result.is_ok());
		let response = result.unwrap();
		assert!(!response.nonce.is_empty());
		assert_eq!(response.expires_in, 300);
		assert_eq!(response.domain, "test.example.com");
		assert_eq!(response.chain_id, 1);
	}

	#[tokio::test]
	async fn test_handle_get_whitelist_returns_configured_admins() {
		let admin_one = alloy_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
		let admin_two = alloy_address("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
		let mut operator_config = build_operator_config(
			admin_one,
			OperatorWithdrawalsConfig {
				enabled: false,
				recipient_allowlist: vec![],
			},
		);
		operator_config
			.admin
			.set_role(admin_two, AdminRole::ReadOnly);

		let state = create_admin_state_with_operator_config(
			operator_config,
			create_delivery_service(None, false),
		)
		.await;
		let response = handle_get_whitelist(State(state)).await.unwrap().0;

		assert_eq!(response.count, 2);
		let entries = response
			.entries
			.iter()
			.map(|entry| (entry.address.clone(), entry.role))
			.collect::<Vec<_>>();
		assert_eq!(
			entries,
			vec![
				(
					"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266".to_string(),
					AdminRole::Admin,
				),
				(
					"0x70997970c51812dc3a010c7d01b50e0d17dc79c8".to_string(),
					AdminRole::ReadOnly,
				),
			]
		);
	}

	#[tokio::test]
	#[serial]
	async fn test_handle_set_admin_role_supports_read_only_role() {
		let _jwt_secret = strong_jwt_secret_guard();
		let admin = alloy_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
		let read_only = alloy_address("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
		let mut operator_config = build_operator_config(
			admin,
			OperatorWithdrawalsConfig {
				enabled: false,
				recipient_allowlist: vec![],
			},
		);
		operator_config.networks.insert(
			1,
			OperatorNetworkConfig {
				chain_id: 1,
				name: "chain-1".to_string(),
				network_type: NetworkType::Parent,
				tokens: vec![],
				rpc_urls: vec![OperatorRpcEndpoint {
					http: "http://localhost:8545".to_string(),
					ws: None,
				}],
				input_settler_address: alloy_address("0x1111111111111111111111111111111111111111"),
				output_settler_address: alloy_address("0x2222222222222222222222222222222222222222"),
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);
		operator_config.networks.insert(
			137,
			OperatorNetworkConfig {
				chain_id: 137,
				name: "chain-137".to_string(),
				network_type: NetworkType::Hub,
				tokens: vec![],
				rpc_urls: vec![OperatorRpcEndpoint {
					http: "http://localhost:8546".to_string(),
					ws: None,
				}],
				input_settler_address: alloy_address("0x3333333333333333333333333333333333333333"),
				output_settler_address: alloy_address("0x4444444444444444444444444444444444444444"),
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);
		let state = create_admin_state_with_operator_config(
			operator_config,
			create_delivery_service(None, false),
		)
		.await;

		let result = handle_set_admin_role(
			State(state.clone()),
			VerifiedAdmin {
				admin: solver_types::Address::from(admin),
				contents: SetAdminRoleContents {
					account: read_only,
					role: AdminRole::ReadOnly,
					nonce: 1,
					deadline: chrono::Utc::now().timestamp() as u64 + 3600,
				},
			},
		)
		.await
		.unwrap()
		.0;

		assert!(result.success);
		let versioned = state.config_store.get().await.unwrap();
		assert_eq!(
			versioned.data.admin.role_for(&read_only),
			Some(AdminRole::ReadOnly)
		);
	}

	#[tokio::test]
	async fn test_legacy_add_admin_payload_is_rejected() {
		let state = create_admin_state(
			None,
			OperatorWithdrawalsConfig {
				enabled: false,
				recipient_allowlist: vec![],
			},
			false,
		)
		.await;
		let payload = serde_json::json!({
			"signature": "0x12",
			"contents": {
				"newAdmin": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
				"nonce": 1,
				"deadline": chrono::Utc::now().timestamp() as u64 + 3600
			}
		});
		let request = Request::builder()
			.method("POST")
			.uri("/admin/whitelist")
			.header("content-type", "application/json")
			.body(Body::from(payload.to_string()))
			.unwrap();

		let result = VerifiedAdmin::<SetAdminRoleContents>::from_request(request, &state).await;

		assert!(matches!(
			result,
			Err(AdminAuthError::InvalidMessage(message))
				if message.contains("missing field `account`")
		));
	}

	#[tokio::test]
	async fn test_handle_get_types() {
		let withdrawals = OperatorWithdrawalsConfig {
			enabled: false,
			recipient_allowlist: vec![],
		};
		let state = create_admin_state(None, withdrawals, false).await;
		let response = handle_get_types(State(state)).await;

		assert_eq!(response.domain.name, "OIF Solver Admin");
		assert_eq!(response.domain.version, "1");
		assert_eq!(response.domain.chain_id, 1);
		assert!(response.domain.salt.starts_with("0x"));
		assert_eq!(response.domain.salt.len(), 66);
		assert!(response.types.is_object());

		let domain_fields = response.types["EIP712Domain"]
			.as_array()
			.expect("EIP712Domain should be an array");
		assert!(domain_fields.iter().any(|field| {
			field["name"].as_str() == Some("salt") && field["type"].as_str() == Some("bytes32")
		}));
	}

	#[tokio::test]
	async fn test_withdraw_disabled() {
		let recipient = alloy_address("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
		let withdrawals = OperatorWithdrawalsConfig {
			enabled: false,
			recipient_allowlist: vec![],
		};

		let state = create_admin_state(None, withdrawals, false).await;
		let contents = WithdrawContents {
			chain_id: 1,
			token: zero_alloy_address(),
			amount: "100".to_string(),
			recipient,
			nonce: 1,
			deadline: chrono::Utc::now().timestamp() as u64 + 3600,
		};

		let verified = VerifiedAdmin {
			admin: solver_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
			contents,
		};

		let err = handle_withdrawal(State(state), verified).await.unwrap_err();
		assert!(matches!(err, AdminAuthError::NotAuthorized(_)));
	}

	#[tokio::test]
	async fn test_withdraw_zero_amount() {
		let recipient = alloy_address("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
		let withdrawals = OperatorWithdrawalsConfig {
			enabled: true,
			recipient_allowlist: vec![],
		};

		let state = create_admin_state(None, withdrawals, false).await;
		let contents = WithdrawContents {
			chain_id: 1,
			token: zero_alloy_address(),
			amount: "0".to_string(), // Zero amount!
			recipient,
			nonce: 1,
			deadline: chrono::Utc::now().timestamp() as u64 + 3600,
		};

		let verified = VerifiedAdmin {
			admin: solver_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
			contents,
		};

		let err = handle_withdrawal(State(state), verified).await.unwrap_err();
		assert!(matches!(err, AdminAuthError::InvalidMessage(_)));
	}

	#[tokio::test]
	async fn test_withdraw_zero_recipient() {
		let withdrawals = OperatorWithdrawalsConfig {
			enabled: true,
			recipient_allowlist: vec![],
		};

		let state = create_admin_state(None, withdrawals, false).await;
		let contents = WithdrawContents {
			chain_id: 1,
			token: zero_alloy_address(),
			amount: "100".to_string(),
			recipient: zero_alloy_address(), // Zero recipient!
			nonce: 1,
			deadline: chrono::Utc::now().timestamp() as u64 + 3600,
		};

		let verified = VerifiedAdmin {
			admin: solver_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
			contents,
		};

		let err = handle_withdrawal(State(state), verified).await.unwrap_err();
		assert!(matches!(err, AdminAuthError::InvalidMessage(_)));
	}

	#[test]
	fn test_fee_config_response_serialization() {
		let response = FeeConfigResponse {
			min_profitability_pct: "2.5".to_string(),
			gas_buffer_bps: 1500,
			settlement_fee_buffer_bps: 2500,
			commission_bps: 20,
			rate_buffer_bps: 14,
			monitoring_timeout_seconds: 60,
		};

		let json = serde_json::to_string(&response).unwrap();
		assert!(json.contains("\"minProfitabilityPct\":\"2.5\""));
		assert!(json.contains("\"gasBufferBps\":1500"));
		assert!(json.contains("\"settlementFeeBufferBps\":2500"));
		assert!(json.contains("\"commissionBps\":20"));
		assert!(json.contains("\"rateBufferBps\":14"));
		assert!(json.contains("\"monitoringTimeoutSeconds\":60"));
	}

	#[test]
	fn test_withdrawal_response_serialization() {
		let response = WithdrawalResponse {
			success: true,
			status: "submitted".to_string(),
			message: "Withdrawal submitted".to_string(),
			admin: "0x1234".to_string(),
			tx_hash: Some("0xabcd".to_string()),
		};

		let json = serde_json::to_string(&response).unwrap();
		assert!(json.contains("\"success\":true"));
		assert!(json.contains("\"status\":\"submitted\""));
		assert!(json.contains("\"txHash\":\"0xabcd\""));
	}

	#[test]
	fn test_approve_tokens_response_serialization() {
		let response = ApproveTokensResponse {
			success: true,
			message: "Approved tokens".to_string(),
			admin: "0x1234".to_string(),
			approved_count: 5,
			chains_processed: vec![1, 10, 137],
		};

		let json = serde_json::to_string(&response).unwrap();
		assert!(json.contains("\"success\":true"));
		assert!(json.contains("\"approvedCount\":5"));
		assert!(json.contains("\"chainsProcessed\":[1,10,137]"));
	}

	/// Build an admin state whose `TokenManager` knows a single chain (id 1)
	/// with a configured input/output settler pair and one supported token.
	/// `expect_submit` gates whether the mock delivery is allowed to submit an
	/// on-chain approve transaction — set it to `false` to assert that a
	/// rejected request never reaches the chain.
	async fn create_admin_state_with_settler_network(expect_submit: bool) -> AdminApiState {
		use solver_types::networks::RpcEndpoint;
		use solver_types::{NetworkConfig as RuntimeNetworkConfig, TokenConfig};

		let admin_alloy = alloy_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
		let withdrawals = OperatorWithdrawalsConfig {
			enabled: true,
			recipient_allowlist: vec![],
		};

		let mut mock_delivery = MockDeliveryInterface::new();
		// Allowance is queried before any approve to decide whether a tx is
		// needed; report a non-matching allowance so a permitted spender would
		// trigger exactly one submit.
		mock_delivery
			.expect_get_allowance()
			.returning(|_, _, _, _| Box::pin(async { Ok("0".to_string()) }));
		if expect_submit {
			mock_delivery.expect_submit().returning(|_, _| {
				Box::pin(async { Ok(solver_types::TransactionHash(vec![0x11; 32])) })
			});
		} else {
			// The on-chain approve MUST NOT be attempted for a rejected request.
			mock_delivery.expect_submit().times(0);
		}
		mock_delivery.expect_config_schema().returning(|| {
			Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
		});

		let mut implementations: HashMap<u64, Arc<dyn DeliveryInterface>> = HashMap::new();
		implementations.insert(1, Arc::new(mock_delivery));
		let delivery = Arc::new(DeliveryService::new(implementations, 1, 30, 60));

		let operator_config = build_operator_config(admin_alloy, withdrawals);
		let state = create_admin_state_with_operator_config(operator_config, delivery).await;

		// Populate the TokenManager with a network carrying real settler
		// addresses and a token, so the allowlist check has a settler set to
		// validate against.
		let mut networks = NetworksConfig::default();
		networks.insert(
			1,
			RuntimeNetworkConfig {
				name: Some("chain-1".to_string()),
				network_type: solver_types::NetworkType::Parent,
				rpc_urls: vec![RpcEndpoint {
					http: Some("http://localhost:8545".to_string()),
					ws: None,
				}],
				input_settler_address: solver_address("0x1111111111111111111111111111111111111111"),
				output_settler_address: solver_address(
					"0x2222222222222222222222222222222222222222",
				),
				tokens: vec![TokenConfig {
					address: solver_address("0x5555555555555555555555555555555555555555"),
					symbol: "USDC".to_string(),
					name: Some("USD Coin".to_string()),
					decimals: 6,
				}],
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);
		state.token_manager.update_networks(networks).await;

		state
	}

	#[tokio::test]
	async fn test_approve_non_settler_spender_is_rejected() {
		// A compromised admin key signs an approve targeting an arbitrary
		// (non-settler) spender. The withdrawal allowlist has a sibling control
		// (recipient allowlist) — approvals must enforce an equivalent guard so
		// the spender cannot be an attacker-chosen address. The request must be
		// rejected BEFORE any on-chain approve is submitted.
		let state = create_admin_state_with_settler_network(false).await;

		let contents = ApproveTokensContents {
			chain_id: 1,
			token_address: alloy_address("0x5555555555555555555555555555555555555555"),
			spender: alloy_address("0xdEAdBeEFdEadBEefDEAdbEEFdeadBEEFDEadBeeF"),
			amount: "1000000".to_string(),
			nonce: 1,
			deadline: chrono::Utc::now().timestamp() as u64 + 3600,
		};

		let verified = VerifiedAdmin {
			admin: solver_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
			contents,
		};

		let result = handle_approve_tokens(State(state), verified).await;
		match result {
			Err(AdminAuthError::NotAuthorized(msg)) => {
				assert!(
					msg.contains("settler"),
					"expected settler message, got {msg}"
				);
			},
			Err(other) => panic!("expected NotAuthorized(settler), got {other:?}"),
			Ok(_) => panic!("non-settler spender approve must be rejected"),
		}
	}

	#[tokio::test]
	async fn test_approve_wildcard_non_settler_spender_is_rejected() {
		// The fully-wildcarded scope (all chains + all tokens + max amount) to a
		// non-settler spender is the worst case: a single signature granting an
		// attacker unlimited allowance on every token/chain. It must be rejected.
		let state = create_admin_state_with_settler_network(false).await;

		let contents = ApproveTokensContents {
			chain_id: 0,                         // all chains
			token_address: zero_alloy_address(), // all tokens
			spender: alloy_address("0xdEAdBeEFdEadBEefDEAdbEEFdeadBEEFDEadBeeF"),
			amount: alloy_primitives::U256::MAX.to_string(),
			nonce: 1,
			deadline: chrono::Utc::now().timestamp() as u64 + 3600,
		};

		let verified = VerifiedAdmin {
			admin: solver_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
			contents,
		};

		let result = handle_approve_tokens(State(state), verified).await;
		match result {
			Err(AdminAuthError::NotAuthorized(msg)) => {
				assert!(
					msg.contains("settler"),
					"expected settler message, got {msg}"
				);
			},
			Err(other) => panic!("expected NotAuthorized(settler), got {other:?}"),
			Ok(_) => panic!("wildcard non-settler spender approve must be rejected"),
		}
	}

	#[tokio::test]
	async fn test_approve_all_chains_fails_closed_when_no_networks_configured() {
		// With no configured networks there is no chain-local settler allowlist
		// against which to authorize an all-chains approval. The request must
		// fail closed before any allowance query or approve submission.
		let withdrawals = OperatorWithdrawalsConfig {
			enabled: true,
			recipient_allowlist: vec![],
		};
		let state = create_admin_state(None, withdrawals, false).await;

		let contents = ApproveTokensContents {
			chain_id: 0,
			token_address: zero_alloy_address(),
			spender: alloy_address("0x2222222222222222222222222222222222222222"),
			amount: "1000000".to_string(),
			nonce: 1,
			deadline: chrono::Utc::now().timestamp() as u64 + 3600,
		};

		let verified = VerifiedAdmin {
			admin: solver_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
			contents,
		};

		let result = handle_approve_tokens(State(state), verified).await;
		match result {
			Err(AdminAuthError::NotAuthorized(msg)) => {
				assert!(
					msg.contains("settler"),
					"expected settler message, got {msg}"
				);
			},
			Err(other) => panic!("expected NotAuthorized(settler), got {other:?}"),
			Ok(_) => panic!("all-chains approval must fail closed with no configured networks"),
		}
	}

	#[tokio::test]
	async fn test_approve_configured_settler_spender_is_allowed() {
		// The legitimate path: approving a configured settler (here the output
		// settler) must still succeed and reach the chain.
		let state = create_admin_state_with_settler_network(true).await;

		let contents = ApproveTokensContents {
			chain_id: 1,
			token_address: alloy_address("0x5555555555555555555555555555555555555555"),
			spender: alloy_address("0x2222222222222222222222222222222222222222"),
			amount: "1000000".to_string(),
			nonce: 1,
			deadline: chrono::Utc::now().timestamp() as u64 + 3600,
		};

		let verified = VerifiedAdmin {
			admin: solver_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
			contents,
		};

		let response = handle_approve_tokens(State(state), verified)
			.await
			.unwrap()
			.0;
		assert!(response.success);
		assert_eq!(response.approved_count, 1);
	}

	/// Build an admin state whose `TokenManager` knows two chains with DISTINCT
	/// settler pairs:
	///   - chain 1: input `0x1111`, output `0x2222`, token `0x5555`
	///   - chain 2: input `0x3333`, output `0x4444`, token `0x6666`
	///
	/// This is the setup the per-network spender validation (M-18) needs: a
	/// global union of settlers would accept `0x4444` for an approval scoped to
	/// chain 1, even though `0x4444` is only chain 2's settler.
	async fn create_admin_state_with_two_settler_networks(expect_submit: bool) -> AdminApiState {
		use solver_types::networks::RpcEndpoint;
		use solver_types::{NetworkConfig as RuntimeNetworkConfig, TokenConfig};

		let admin_alloy = alloy_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
		let withdrawals = OperatorWithdrawalsConfig {
			enabled: true,
			recipient_allowlist: vec![],
		};

		let make_mock = || {
			let mut mock_delivery = MockDeliveryInterface::new();
			mock_delivery
				.expect_get_allowance()
				.returning(|_, _, _, _| Box::pin(async { Ok("0".to_string()) }));
			if expect_submit {
				mock_delivery.expect_submit().returning(|_, _| {
					Box::pin(async { Ok(solver_types::TransactionHash(vec![0x11; 32])) })
				});
			} else {
				// The on-chain approve MUST NOT be attempted for a rejected request.
				mock_delivery.expect_submit().times(0);
			}
			mock_delivery.expect_config_schema().returning(|| {
				Box::new(solver_delivery::implementations::evm::alloy::AlloyDeliverySchema)
			});
			mock_delivery
		};

		let mut implementations: HashMap<u64, Arc<dyn DeliveryInterface>> = HashMap::new();
		implementations.insert(1, Arc::new(make_mock()));
		implementations.insert(2, Arc::new(make_mock()));
		let delivery = Arc::new(DeliveryService::new(implementations, 1, 30, 60));

		let operator_config = build_operator_config(admin_alloy, withdrawals);
		let state = create_admin_state_with_operator_config(operator_config, delivery).await;

		let mut networks = NetworksConfig::default();
		networks.insert(
			1,
			RuntimeNetworkConfig {
				name: Some("chain-1".to_string()),
				network_type: solver_types::NetworkType::Parent,
				rpc_urls: vec![RpcEndpoint {
					http: Some("http://localhost:8545".to_string()),
					ws: None,
				}],
				input_settler_address: solver_address("0x1111111111111111111111111111111111111111"),
				output_settler_address: solver_address(
					"0x2222222222222222222222222222222222222222",
				),
				tokens: vec![TokenConfig {
					address: solver_address("0x5555555555555555555555555555555555555555"),
					symbol: "USDC".to_string(),
					name: Some("USD Coin".to_string()),
					decimals: 6,
				}],
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);
		networks.insert(
			2,
			RuntimeNetworkConfig {
				name: Some("chain-2".to_string()),
				network_type: solver_types::NetworkType::New,
				rpc_urls: vec![RpcEndpoint {
					http: Some("http://localhost:8546".to_string()),
					ws: None,
				}],
				input_settler_address: solver_address("0x3333333333333333333333333333333333333333"),
				output_settler_address: solver_address(
					"0x4444444444444444444444444444444444444444",
				),
				tokens: vec![TokenConfig {
					address: solver_address("0x6666666666666666666666666666666666666666"),
					symbol: "USDT".to_string(),
					name: Some("Tether".to_string()),
					decimals: 6,
				}],
				input_settler_compact_address: None,
				the_compact_address: None,
				allocator_address: None,
			},
		);
		state.token_manager.update_networks(networks).await;

		state
	}

	#[tokio::test]
	async fn test_approve_settler_from_other_chain_is_rejected() {
		// M-18: cross-chain address confusion. `0x4444` is chain 2's output
		// settler but is NOT a settler on chain 1. An approval scoped to chain 1
		// naming `0x4444` as spender must be REJECTED — a global settler union
		// would wrongly accept it and grant an allowance on chain 1 to an
		// address that has no settler role there.
		let state = create_admin_state_with_two_settler_networks(false).await;

		let contents = ApproveTokensContents {
			chain_id: 1,
			token_address: alloy_address("0x5555555555555555555555555555555555555555"),
			spender: alloy_address("0x4444444444444444444444444444444444444444"),
			amount: "1000000".to_string(),
			nonce: 1,
			deadline: chrono::Utc::now().timestamp() as u64 + 3600,
		};

		let verified = VerifiedAdmin {
			admin: solver_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
			contents,
		};

		let result = handle_approve_tokens(State(state), verified).await;
		match result {
			Err(AdminAuthError::NotAuthorized(msg)) => {
				assert!(
					msg.contains("settler"),
					"expected settler message, got {msg}"
				);
			},
			Err(other) => panic!("expected NotAuthorized(settler), got {other:?}"),
			Ok(_) => {
				panic!("settler from another chain must be rejected for a chain-scoped approval")
			},
		}
	}

	#[tokio::test]
	async fn test_approve_settler_on_requested_chain_is_allowed() {
		// The legitimate counterpart: `0x2222` IS chain 1's output settler, so an
		// approval scoped to chain 1 naming `0x2222` must still succeed.
		let state = create_admin_state_with_two_settler_networks(true).await;

		let contents = ApproveTokensContents {
			chain_id: 1,
			token_address: alloy_address("0x5555555555555555555555555555555555555555"),
			spender: alloy_address("0x2222222222222222222222222222222222222222"),
			amount: "1000000".to_string(),
			nonce: 1,
			deadline: chrono::Utc::now().timestamp() as u64 + 3600,
		};

		let verified = VerifiedAdmin {
			admin: solver_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
			contents,
		};

		let response = handle_approve_tokens(State(state), verified)
			.await
			.unwrap()
			.0;
		assert!(response.success);
		assert_eq!(response.approved_count, 1);
	}

	#[tokio::test]
	async fn test_approve_all_chains_partial_settler_is_rejected() {
		// M-18 all-chains scope: `0x2222` is chain 1's settler but NOT a settler
		// on chain 2. An all-chains approval would touch chain 2 too, where
		// `0x2222` has no settler role — so the request must be rejected.
		let state = create_admin_state_with_two_settler_networks(false).await;

		let contents = ApproveTokensContents {
			chain_id: 0,                         // all chains
			token_address: zero_alloy_address(), // all tokens
			spender: alloy_address("0x2222222222222222222222222222222222222222"),
			amount: "1000000".to_string(),
			nonce: 1,
			deadline: chrono::Utc::now().timestamp() as u64 + 3600,
		};

		let verified = VerifiedAdmin {
			admin: solver_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
			contents,
		};

		let result = handle_approve_tokens(State(state), verified).await;
		match result {
			Err(AdminAuthError::NotAuthorized(msg)) => {
				assert!(
					msg.contains("settler"),
					"expected settler message, got {msg}"
				);
			},
			Err(other) => panic!("expected NotAuthorized(settler), got {other:?}"),
			Ok(_) => {
				panic!(
					"all-chains approval must be rejected when spender is not a settler on every chain"
				)
			},
		}
	}

	#[test]
	fn test_redact_rpc_url_userinfo_credentials() {
		// URL with username:password in userinfo
		let url = "https://user:secretpassword@rpc.example.com/v1/abc123";
		let redacted = redact_rpc_url(url);
		// Credentials should be redacted, path should be redacted
		assert!(!redacted.contains("secretpassword"));
		assert!(redacted.contains("[REDACTED]"));
	}

	#[test]
	fn test_redact_rpc_url_with_fragment() {
		// URL with fragment (rarely used but should be preserved)
		let url = "https://rpc.example.com/v1/key123#section";
		let redacted = redact_rpc_url(url);
		assert!(redacted.contains("#section"));
		assert!(redacted.contains("[REDACTED]"));
	}

	#[test]
	fn test_redact_query_params_various_keys() {
		// Test various sensitive parameter names
		let query =
			"apikey=secret1&api_key=secret2&key=secret3&token=secret4&secret=secret5&chainId=1";
		let redacted = redact_query_params(query);
		assert!(redacted.contains("apikey=[REDACTED]"));
		assert!(redacted.contains("api_key=[REDACTED]"));
		assert!(redacted.contains("key=[REDACTED]"));
		assert!(redacted.contains("token=[REDACTED]"));
		assert!(redacted.contains("secret=[REDACTED]"));
		assert!(redacted.contains("chainId=1")); // Non-sensitive should be preserved
	}

	#[test]
	fn test_redact_query_params_case_insensitive() {
		// Test case insensitivity
		let query = "APIKEY=secret1&ApiKey=secret2&TOKEN=secret3";
		let redacted = redact_query_params(query);
		assert!(redacted.contains("[REDACTED]"));
		assert!(!redacted.contains("secret1"));
		assert!(!redacted.contains("secret2"));
		assert!(!redacted.contains("secret3"));
	}

	#[test]
	fn test_redact_path_api_key_no_path() {
		// URL with no path should remain unchanged
		let url = "https://rpc.example.com";
		let redacted = redact_path_api_key(url);
		assert_eq!(redacted, url);
	}

	#[test]
	fn test_redact_path_api_key_root_only() {
		// URL with only root path
		let url = "https://rpc.example.com/";
		let redacted = redact_path_api_key(url);
		assert_eq!(redacted, "https://rpc.example.com/[REDACTED]");
	}

	#[test]
	fn test_gas_config_response_builder() {
		use solver_types::{OperatorGasConfig, OperatorGasFlowUnits};

		let gas_config = OperatorGasConfig {
			resource_lock: OperatorGasFlowUnits {
				open: 100_000,
				fill: 200_000,
				post_fill: 300_000,
				pre_claim: 40_000,
				claim: 150_000,
			},
			permit2_escrow: OperatorGasFlowUnits {
				open: 110_000,
				fill: 210_000,
				post_fill: 310_000,
				pre_claim: 41_000,
				claim: 160_000,
			},
			eip3009_escrow: OperatorGasFlowUnits {
				open: 120_000,
				fill: 220_000,
				post_fill: 320_000,
				pre_claim: 42_000,
				claim: 170_000,
			},
			live_fill_estimate_enabled: true,
			live_post_fill_estimate_chain_ids: HashSet::new(),
		};

		let response = gas_config_response(&gas_config);

		assert_eq!(response.resource_lock.open, 100_000);
		assert_eq!(response.resource_lock.fill, 200_000);
		assert_eq!(response.resource_lock.post_fill, 300_000);
		assert_eq!(response.resource_lock.pre_claim, 40_000);
		assert_eq!(response.resource_lock.claim, 150_000);
		assert_eq!(response.permit2_escrow.open, 110_000);
		assert_eq!(response.permit2_escrow.fill, 210_000);
		assert_eq!(response.permit2_escrow.post_fill, 310_000);
		assert_eq!(response.permit2_escrow.pre_claim, 41_000);
		assert_eq!(response.permit2_escrow.claim, 160_000);
		assert_eq!(response.eip3009_escrow.open, 120_000);
		assert_eq!(response.eip3009_escrow.fill, 220_000);
		assert_eq!(response.eip3009_escrow.post_fill, 320_000);
		assert_eq!(response.eip3009_escrow.pre_claim, 42_000);
		assert_eq!(response.eip3009_escrow.claim, 170_000);
	}

	#[test]
	fn test_gas_config_response_serialization() {
		let response = GasConfigResponse {
			resource_lock: GasFlowResponse {
				open: 100_000,
				fill: 200_000,
				post_fill: 300_000,
				pre_claim: 40_000,
				claim: 150_000,
			},
			permit2_escrow: GasFlowResponse {
				open: 110_000,
				fill: 210_000,
				post_fill: 310_000,
				pre_claim: 41_000,
				claim: 160_000,
			},
			eip3009_escrow: GasFlowResponse {
				open: 120_000,
				fill: 220_000,
				post_fill: 320_000,
				pre_claim: 42_000,
				claim: 170_000,
			},
		};

		let json = serde_json::to_string(&response).unwrap();
		assert!(json.contains("\"resourceLock\""));
		assert!(json.contains("\"permit2Escrow\""));
		assert!(json.contains("\"eip3009Escrow\""));
		assert!(json.contains("\"open\":100000"));
		assert!(json.contains("\"fill\":200000"));
		assert!(json.contains("\"postFill\":300000"));
		assert!(json.contains("\"preClaim\":40000"));
		assert!(json.contains("\"claim\":150000"));
	}

	#[test]
	fn test_balances_response_serialization() {
		use std::collections::HashMap;

		let mut networks = HashMap::new();
		networks.insert(
			"1".to_string(),
			ChainBalances {
				chain_id: 1,
				tokens: vec![TokenBalance {
					symbol: "USDC".to_string(),
					name: Some("USD Coin".to_string()),
					address: "0x1234".to_string(),
					decimals: 6,
					balance: "1000000".to_string(),
					balance_formatted: "1.00".to_string(),
				}],
				error: None,
			},
		);

		let response = BalancesResponse {
			solver_address: "0xabcd".to_string(),
			networks,
		};

		let json = serde_json::to_string(&response).unwrap();
		assert!(json.contains("\"solverAddress\":\"0xabcd\""));
		assert!(json.contains("\"chainId\":1"));
		assert!(json.contains("\"symbol\":\"USDC\""));
		assert!(json.contains("\"balanceFormatted\":\"1.00\""));
	}

	#[test]
	fn test_admin_config_summary_serialization() {
		let summary = AdminConfigSummary {
			enabled: true,
			domain: "localhost".to_string(),
			withdrawals_enabled: true,
			withdrawal_recipient_allowlist: vec![
				"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string()
			],
		};

		let json = serde_json::to_string(&summary).unwrap();
		assert!(json.contains("\"enabled\":true"));
		assert!(json.contains("\"domain\":\"localhost\""));
		assert!(json.contains("\"withdrawalsEnabled\":true"));
		assert!(json.contains("\"withdrawalRecipientAllowlist\""));
	}

	#[test]
	fn test_admin_network_response_serialization() {
		let network = AdminNetworkResponse {
			chain_id: 10,
			name: "optimism".to_string(),
			network_type: solver_types::networks::NetworkType::Parent,
			rpc_urls: vec!["https://rpc.example.com/[REDACTED]".to_string()],
			tokens: vec![AdminTokenResponse {
				symbol: "USDC".to_string(),
				name: Some("USD Coin".to_string()),
				address: "0x1234".to_string(),
				decimals: 6,
			}],
			input_settler: "0xaaa".to_string(),
			output_settler: "0xbbb".to_string(),
		};

		let json = serde_json::to_string(&network).unwrap();
		assert!(json.contains("\"chainId\":10"));
		assert!(json.contains("\"inputSettler\":\"0xaaa\""));
		assert!(json.contains("\"outputSettler\":\"0xbbb\""));
	}
}
