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
	Json,
	body::Body,
	extract::{FromRequest, State},
	http::Request,
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
	AdminSolverResponse, AdminTokenResponse, ApproveTokensResponse, BalancesResponse,
	ChainBalances, Eip712Domain, Eip712TypeInfo, FeeConfigResponse, GasConfigResponse,
	GasFlowResponse, NonceResponse, TokenBalance, WithdrawalResponse,
};
use solver_types::{
	AdminConfig, OperatorAdminConfig, OperatorConfig, OperatorToken, format_token_amount,
	with_0x_prefix,
};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::auth::admin::{
	AddAdminContents, AddTokenContents, AdminActionVerifier, AdminAuthError, ApproveTokensContents,
	RemoveAdminContents, RemoveTokenContents, SignedAdminRequest, UpdateFeeConfigContents,
	UpdateGasConfigContents, WithdrawContents,
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
	/// Token manager for hot-reloading token configurations.
	pub token_manager: Arc<TokenManager>,
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
				admin_addresses: admin_config.admin_addresses.clone(),
			},
			admin_config.chain_id,
		);

		*self.verifier.write().await = new_verifier;

		tracing::info!(
			admin_count = admin_config.admin_addresses.len(),
			chain_id = admin_config.chain_id,
			"Admin verifier rebuilt with updated config"
		);
	}
}

/// GET /api/v1/admin/nonce
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

		for token in &network.tokens {
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
				let formatted = format_token_amount(&balance, 18);
				tokens.push(TokenBalance {
					address: zero_address.to_string(),
					symbol: "NATIVE".to_string(),
					name: Some("Native Token".to_string()),
					decimals: 18,
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
			commission_bps: operator_config.solver.commission_bps,
			rate_buffer_bps: operator_config.solver.rate_buffer_bps,
		},
		gas,
		admin: AdminConfigSummary {
			enabled: operator_config.admin.enabled,
			domain: operator_config.admin.domain.clone(),
			withdrawals_enabled: operator_config.admin.withdrawals.enabled,
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

/// POST /api/v1/admin/whitelist
///
/// Add an admin address to the authorized list.
pub async fn handle_add_admin(
	State(state): State<AdminApiState>,
	VerifiedAdmin { admin, contents }: VerifiedAdmin<AddAdminContents>,
) -> Result<Json<AdminActionResponse>, AdminAuthError> {
	if contents.new_admin == alloy_primitives::Address::ZERO {
		return Err(AdminAuthError::InvalidMessage(
			"Admin address cannot be zero".to_string(),
		));
	}

	let versioned = state.config_store.get().await.map_err(config_store_error)?;
	let mut operator_config = versioned.data;

	if operator_config
		.admin
		.admin_addresses
		.contains(&contents.new_admin)
	{
		return Err(AdminAuthError::InvalidMessage(
			"Admin address already exists".to_string(),
		));
	}

	operator_config
		.admin
		.admin_addresses
		.push(contents.new_admin);

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
			"Admin added: {}",
			with_0x_prefix(&hex::encode(contents.new_admin.as_slice()))
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

	if !operator_config
		.admin
		.admin_addresses
		.contains(&contents.admin_to_remove)
	{
		return Err(AdminAuthError::InvalidMessage(
			"Admin address not found".to_string(),
		));
	}

	if operator_config.admin.admin_addresses.len() <= 1 {
		return Err(AdminAuthError::InvalidMessage(
			"Cannot remove the last admin".to_string(),
		));
	}

	operator_config
		.admin
		.admin_addresses
		.retain(|addr| addr != &contents.admin_to_remove);

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
	fn validate_flow(label: &str, open: u64, fill: u64, claim: u64) -> Result<(), AdminAuthError> {
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
		request.resource_lock_claim,
	)?;
	validate_flow(
		"permit2Escrow",
		request.permit2_escrow_open,
		request.permit2_escrow_fill,
		request.permit2_escrow_claim,
	)?;
	validate_flow(
		"eip3009Escrow",
		request.eip3009_escrow_open,
		request.eip3009_escrow_fill,
		request.eip3009_escrow_claim,
	)?;

	let versioned = state.config_store.get().await.map_err(config_store_error)?;
	let mut operator_config = versioned.data;
	operator_config.gas.resource_lock.open = request.resource_lock_open;
	operator_config.gas.resource_lock.fill = request.resource_lock_fill;
	operator_config.gas.resource_lock.claim = request.resource_lock_claim;
	operator_config.gas.permit2_escrow.open = request.permit2_escrow_open;
	operator_config.gas.permit2_escrow.fill = request.permit2_escrow_fill;
	operator_config.gas.permit2_escrow.claim = request.permit2_escrow_claim;
	operator_config.gas.eip3009_escrow.open = request.eip3009_escrow_open;
	operator_config.gas.eip3009_escrow.fill = request.eip3009_escrow_fill;
	operator_config.gas.eip3009_escrow.claim = request.eip3009_escrow_claim;

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
	// 1. Get current OperatorConfig from Redis
	let versioned = state.config_store.get().await.map_err(config_store_error)?;

	// 3. Find network and add token
	let mut operator_config = versioned.data;
	let network = operator_config
		.networks
		.get_mut(&contents.chain_id)
		.ok_or_else(|| {
			AdminAuthError::InvalidMessage(format!("Network {} not found", contents.chain_id))
		})?;

	// 4. Check for duplicates
	if network.has_token(&contents.token_address) {
		return Err(AdminAuthError::InvalidMessage(format!(
			"Token {} already exists on chain {}",
			contents.symbol, contents.chain_id
		)));
	}

	// 5. Add token to OperatorConfig
	network.tokens.push(OperatorToken {
		symbol: contents.symbol.clone(),
		name: Some(
			contents
				.name
				.clone()
				.unwrap_or_else(|| contents.symbol.clone()),
		),
		address: contents.token_address,
		decimals: contents.decimals,
	});

	// 6. Save to Redis with optimistic locking
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

	// 7. HOT RELOAD: Rebuild runtime Config from updated OperatorConfig
	let new_config = build_runtime_config(&new_versioned.data)
		.map_err(|e| AdminAuthError::Internal(format!("Invalid config: {e}")))?;
	let network_config = new_config
		.networks
		.get(&contents.chain_id)
		.cloned()
		.ok_or_else(|| {
			AdminAuthError::Internal(format!(
				"Chain {} missing from rebuilt runtime config after token add",
				contents.chain_id
			))
		})?;

	// 8. Update TokenManager with new networks configuration
	// This ensures quotes and other token operations immediately see the new token
	let new_networks = new_config.networks.clone();
	state.token_manager.update_networks(new_networks).await;

	// 9. Update dynamic_config
	*state.dynamic_config.write().await = new_config;

	// 10. Ensure approvals for the newly added token on configured settlers.
	let approvals_set = ensure_new_token_approvals(
		state.token_manager.as_ref(),
		contents.chain_id,
		contents.token_address,
		&network_config,
	)
	.await
	.map_err(|e| {
		AdminAuthError::Internal(format!(
			"Token {} added to chain {}, but automatic approval setup failed: {e}. Retry via POST /api/v1/admin/tokens/approve",
			contents.symbol, contents.chain_id
		))
	})?;

	tracing::info!(
		version = new_versioned.version,
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
		let (approved_count, _) = token_manager
			.ensure_approvals_for_spender_scope(
				Some(chain_id),
				Some(token_address.clone()),
				spender,
				U256::MAX,
			)
			.await?;
		approvals_set += approved_count;
	}

	Ok(approvals_set)
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

	// 2b. Validate commission_bps is reasonable (0-10000 = 0-100%)
	if request.commission_bps > 10000 {
		return Err(AdminAuthError::InvalidMessage(format!(
			"Invalid commissionBps: {} exceeds maximum of 10000 (100%)",
			request.commission_bps
		)));
	}

	// 2c. Validate rate_buffer_bps is reasonable (<10000 to avoid zero rate)
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
		commission_bps = request.commission_bps,
		rate_buffer_bps = request.rate_buffer_bps,
		min_profitability_pct = %request.min_profitability_pct,
		"Fee configuration updated and config hot-reloaded"
	);

	Ok(Json(AdminActionResponse {
		success: true,
		message: format!(
			"Fee configuration updated: gasBufferBps={}, minProfitabilityPct={}, commissionBps={}, rateBufferBps={}",
			request.gas_buffer_bps,
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
			claim: gas.resource_lock.claim,
		},
		permit2_escrow: GasFlowResponse {
			open: gas.permit2_escrow.open,
			fill: gas.permit2_escrow.fill,
			claim: gas.permit2_escrow.claim,
		},
		eip3009_escrow: GasFlowResponse {
			open: gas.eip3009_escrow.open,
			fill: gas.eip3009_escrow.fill,
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
		},
		types: admin_eip712_types(),
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use async_trait::async_trait;
	use solver_account::{AccountInterface, AccountService, AccountSigner};
	use solver_config::builders::config::ConfigBuilder;
	use solver_delivery::{DeliveryInterface, DeliveryService, MockDeliveryInterface};
	use solver_storage::StoreConfig;
	use solver_storage::{config_store::create_config_store, nonce_store::create_nonce_store};
	use solver_types::{
		NetworkType, NetworksConfig, OperatorAdminConfig, OperatorConfig, OperatorGasConfig,
		OperatorGasFlowUnits, OperatorHyperlaneConfig, OperatorNetworkConfig, OperatorOracleConfig,
		OperatorPricingConfig, OperatorRpcEndpoint, OperatorSettlementConfig, OperatorSolverConfig,
		OperatorWithdrawalsConfig,
	};
	use std::collections::HashMap;
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
		};

		let json = serde_json::to_string(&domain).unwrap();
		assert!(json.contains("\"name\":\"OIF Solver Admin\""));
		assert!(json.contains("\"version\":\"1\""));
		assert!(json.contains("\"chainId\":1"));
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
			Ok(solver_types::Signature(vec![0u8; 65]))
		}

		async fn sign_message(
			&self,
			_message: &[u8],
		) -> Result<solver_types::Signature, solver_account::AccountError> {
			Ok(solver_types::Signature(vec![0u8; 65]))
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
				hyperlane: OperatorHyperlaneConfig {
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
				},
			},
			gas: OperatorGasConfig {
				resource_lock: OperatorGasFlowUnits::default(),
				permit2_escrow: OperatorGasFlowUnits::default(),
				eip3009_escrow: OperatorGasFlowUnits::default(),
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
				commission_bps: 20,
				rate_buffer_bps: 14,
				monitoring_timeout_seconds: 60,
			},
			admin: OperatorAdminConfig {
				enabled: true,
				domain: "test.example.com".to_string(),
				chain_id: 1,
				nonce_ttl_seconds: 300,
				admin_addresses: vec![admin_address],
				withdrawals,
			},
			account: None,
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

		Arc::new(DeliveryService::new(implementations, 1, 30))
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
				admin_addresses: vec![admin_alloy],
			},
			1,
		);

		let account = Arc::new(AccountService::new(Box::new(DummyAccount {
			address: admin_solver,
		})));
		let delivery = create_delivery_service(balance, expect_submit);
		let token_manager = Arc::new(TokenManager::new(
			NetworksConfig::default(),
			delivery,
			account,
		));
		let dynamic_config = Arc::new(RwLock::new(ConfigBuilder::new().build()));

		AdminApiState {
			verifier: Arc::new(RwLock::new(verifier)),
			config_store,
			dynamic_config,
			nonce_store,
			token_manager,
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
				admin_addresses: vec![admin_alloy],
			},
			1,
		);

		let account = Arc::new(AccountService::new(Box::new(DummyAccount {
			address: admin_solver,
		})));
		let token_manager = Arc::new(TokenManager::new(
			NetworksConfig::default(),
			delivery,
			account,
		));
		let dynamic_config = Arc::new(RwLock::new(ConfigBuilder::new().build()));

		AdminApiState {
			verifier: Arc::new(RwLock::new(verifier)),
			config_store,
			dynamic_config,
			nonce_store,
			token_manager,
		}
	}

	#[tokio::test]
	async fn test_handle_add_token_triggers_approval_setup() {
		let admin_alloy = alloy_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
		let mut operator_config =
			build_operator_config(admin_alloy, OperatorWithdrawalsConfig { enabled: true });

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
		let delivery = Arc::new(DeliveryService::new(implementations, 1, 30));

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
	async fn test_withdraw_success() {
		let recipient = alloy_address("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
		let withdrawals = OperatorWithdrawalsConfig { enabled: true };

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
	async fn test_withdraw_insufficient_funds() {
		let recipient = alloy_address("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
		let withdrawals = OperatorWithdrawalsConfig { enabled: true };

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
		let withdrawals = OperatorWithdrawalsConfig { enabled: true };

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
		};

		let optimism = Eip712Domain {
			name: "Solver".to_string(),
			version: "1".to_string(),
			chain_id: 10,
		};

		let mainnet_json = serde_json::to_string(&mainnet).unwrap();
		let optimism_json = serde_json::to_string(&optimism).unwrap();

		assert!(mainnet_json.contains("\"chainId\":1"));
		assert!(optimism_json.contains("\"chainId\":10"));
		assert_ne!(mainnet_json, optimism_json);
	}

	#[tokio::test]
	async fn test_handle_get_fees() {
		let withdrawals = OperatorWithdrawalsConfig { enabled: false };
		let state = create_admin_state(None, withdrawals, false).await;
		let response = handle_get_fees(State(state)).await;

		// ConfigBuilder default values
		assert_eq!(response.min_profitability_pct, "0");
		assert_eq!(response.gas_buffer_bps, 1000);
		assert_eq!(response.commission_bps, 0); // Disabled by default for backward compatibility
		assert_eq!(response.rate_buffer_bps, 14);
	}

	#[tokio::test]
	async fn test_handle_get_nonce() {
		let withdrawals = OperatorWithdrawalsConfig { enabled: false };
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
	async fn test_handle_get_types() {
		let withdrawals = OperatorWithdrawalsConfig { enabled: false };
		let state = create_admin_state(None, withdrawals, false).await;
		let response = handle_get_types(State(state)).await;

		assert_eq!(response.domain.name, "OIF Solver Admin");
		assert_eq!(response.domain.version, "1");
		assert_eq!(response.domain.chain_id, 1);
		assert!(response.types.is_object());
	}

	#[tokio::test]
	async fn test_withdraw_disabled() {
		let recipient = alloy_address("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
		let withdrawals = OperatorWithdrawalsConfig { enabled: false };

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
		let withdrawals = OperatorWithdrawalsConfig { enabled: true };

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
		let withdrawals = OperatorWithdrawalsConfig { enabled: true };

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
			commission_bps: 20,
			rate_buffer_bps: 14,
			monitoring_timeout_seconds: 60,
		};

		let json = serde_json::to_string(&response).unwrap();
		assert!(json.contains("\"minProfitabilityPct\":\"2.5\""));
		assert!(json.contains("\"gasBufferBps\":1500"));
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
				claim: 150_000,
			},
			permit2_escrow: OperatorGasFlowUnits {
				open: 110_000,
				fill: 210_000,
				claim: 160_000,
			},
			eip3009_escrow: OperatorGasFlowUnits {
				open: 120_000,
				fill: 220_000,
				claim: 170_000,
			},
		};

		let response = gas_config_response(&gas_config);

		assert_eq!(response.resource_lock.open, 100_000);
		assert_eq!(response.resource_lock.fill, 200_000);
		assert_eq!(response.resource_lock.claim, 150_000);
		assert_eq!(response.permit2_escrow.open, 110_000);
		assert_eq!(response.permit2_escrow.fill, 210_000);
		assert_eq!(response.permit2_escrow.claim, 160_000);
		assert_eq!(response.eip3009_escrow.open, 120_000);
		assert_eq!(response.eip3009_escrow.fill, 220_000);
		assert_eq!(response.eip3009_escrow.claim, 170_000);
	}

	#[test]
	fn test_gas_config_response_serialization() {
		let response = GasConfigResponse {
			resource_lock: GasFlowResponse {
				open: 100_000,
				fill: 200_000,
				claim: 150_000,
			},
			permit2_escrow: GasFlowResponse {
				open: 110_000,
				fill: 210_000,
				claim: 160_000,
			},
			eip3009_escrow: GasFlowResponse {
				open: 120_000,
				fill: 220_000,
				claim: 170_000,
			},
		};

		let json = serde_json::to_string(&response).unwrap();
		assert!(json.contains("\"resourceLock\""));
		assert!(json.contains("\"permit2Escrow\""));
		assert!(json.contains("\"eip3009Escrow\""));
		assert!(json.contains("\"open\":100000"));
		assert!(json.contains("\"fill\":200000"));
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
		};

		let json = serde_json::to_string(&summary).unwrap();
		assert!(json.contains("\"enabled\":true"));
		assert!(json.contains("\"domain\":\"localhost\""));
		assert!(json.contains("\"withdrawalsEnabled\":true"));
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
