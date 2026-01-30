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

use axum::{extract::State, Json};
use serde::Serialize;
use solver_config::Config;
use solver_storage::{
	config_store::{ConfigStore, ConfigStoreError},
	nonce_store::NonceStore,
};
use solver_types::{AdminConfig, OperatorAdminConfig, OperatorConfig, OperatorToken};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::auth::admin::{
	AddTokenContents, AdminActionVerifier, AdminAuthError, SignedAdminRequest,
	UpdateFeeConfigContents,
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
	Json(request): Json<SignedAdminRequest<AddTokenContents>>,
) -> Result<Json<AdminActionResponse>, AdminAuthError> {
	// 1. Verify the signature - acquire read lock, then release after verification
	let admin = {
		let verifier = state.verifier.read().await;
		verifier
			.verify(&request.contents, &request.signature)
			.await?
	};

	// 2. Get current OperatorConfig from Redis
	let versioned = state.config_store.get().await.map_err(config_store_error)?;

	// 3. Find network and add token
	let mut operator_config = versioned.data;
	let network = operator_config
		.networks
		.get_mut(&request.contents.chain_id)
		.ok_or_else(|| {
			AdminAuthError::InvalidMessage(format!(
				"Network {} not found",
				request.contents.chain_id
			))
		})?;

	// 4. Check for duplicates
	if network.has_token(&request.contents.token_address) {
		return Err(AdminAuthError::InvalidMessage(format!(
			"Token {} already exists on chain {}",
			request.contents.symbol, request.contents.chain_id
		)));
	}

	// 5. Add token to OperatorConfig
	network.tokens.push(OperatorToken {
		symbol: request.contents.symbol.clone(),
		address: request.contents.token_address,
		decimals: request.contents.decimals,
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
		.map_err(|e| AdminAuthError::Internal(format!("Invalid config: {}", e)))?;
	*state.dynamic_config.write().await = new_config;

	tracing::info!(
		version = new_versioned.version,
		token = %request.contents.symbol,
		chain_id = request.contents.chain_id,
		"Token added and config hot-reloaded"
	);

	Ok(Json(AdminActionResponse {
		success: true,
		message: format!(
			"Token {} added to chain {}",
			request.contents.symbol, request.contents.chain_id
		),
		admin: format!("{:?}", admin),
	}))
}

/// PUT /api/v1/admin/fees
///
/// Update fee configuration (gas buffer and minimum profitability).
///
/// Request body:
/// ```json
/// {
///   "signature": "0x...",
///   "contents": {
///     "gasBufferBps": 1500,
///     "minProfitabilityPct": "2.5",
///     "nonce": 12345678901234,
///     "deadline": 1706184000
///   }
/// }
/// ```
///
/// - `gasBufferBps`: Gas buffer in basis points (e.g., 1500 = 15%)
/// - `minProfitabilityPct`: Minimum profitability as decimal string (e.g., "2.5" for 2.5%)
pub async fn handle_update_fees(
	State(state): State<AdminApiState>,
	Json(request): Json<SignedAdminRequest<UpdateFeeConfigContents>>,
) -> Result<Json<AdminActionResponse>, AdminAuthError> {
	use rust_decimal::Decimal;
	use std::str::FromStr;

	// 1. Verify the signature
	let admin = {
		let verifier = state.verifier.read().await;
		verifier
			.verify(&request.contents, &request.signature)
			.await?
	};

	// 2. Validate min_profitability_pct is a valid decimal
	let min_profitability =
		Decimal::from_str(&request.contents.min_profitability_pct).map_err(|_| {
			AdminAuthError::InvalidMessage(format!(
				"Invalid minProfitabilityPct: '{}' is not a valid decimal",
				request.contents.min_profitability_pct
			))
		})?;

	// 3. Validate gas_buffer_bps is reasonable (0-10000 = 0-100%)
	if request.contents.gas_buffer_bps > 10000 {
		return Err(AdminAuthError::InvalidMessage(format!(
			"Invalid gasBufferBps: {} exceeds maximum of 10000 (100%)",
			request.contents.gas_buffer_bps
		)));
	}

	// 4. Get current OperatorConfig from Redis
	let versioned = state.config_store.get().await.map_err(config_store_error)?;

	// 5. Update fee configuration
	let mut operator_config = versioned.data;
	operator_config.solver.gas_buffer_bps = request.contents.gas_buffer_bps;
	operator_config.solver.min_profitability_pct = min_profitability;

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
		.map_err(|e| AdminAuthError::Internal(format!("Invalid config: {}", e)))?;
	*state.dynamic_config.write().await = new_config;

	tracing::info!(
		version = new_versioned.version,
		gas_buffer_bps = request.contents.gas_buffer_bps,
		min_profitability_pct = %request.contents.min_profitability_pct,
		"Fee configuration updated and config hot-reloaded"
	);

	Ok(Json(AdminActionResponse {
		success: true,
		message: format!(
			"Fee configuration updated: gasBufferBps={}, minProfitabilityPct={}",
			request.contents.gas_buffer_bps, request.contents.min_profitability_pct
		),
		admin: format!("{:?}", admin),
	}))
}

/// Convert ConfigStoreError to AdminAuthError.
fn config_store_error(err: ConfigStoreError) -> AdminAuthError {
	match err {
		ConfigStoreError::NotFound(msg) => {
			AdminAuthError::Internal(format!("Configuration not found: {}", msg))
		},
		ConfigStoreError::VersionMismatch { expected, found } => AdminAuthError::Internal(format!(
			"Configuration was modified concurrently (expected version {}, found {}), please retry",
			expected, found
		)),
		ConfigStoreError::Serialization(msg) => {
			AdminAuthError::Internal(format!("Serialization error: {}", msg))
		},
		ConfigStoreError::Backend(msg) => {
			AdminAuthError::Internal(format!("Storage error: {}", msg))
		},
		ConfigStoreError::Configuration(msg) => {
			AdminAuthError::Internal(format!("Configuration error: {}", msg))
		},
		ConfigStoreError::AlreadyExists(msg) => {
			AdminAuthError::Internal(format!("Configuration already exists: {}", msg))
		},
	}
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

/// GET /api/v1/admin/types
///
/// Get EIP-712 type definitions for client-side signing.
/// Clients can use this to construct the typed data for signing.
pub async fn handle_get_types(State(state): State<AdminApiState>) -> Json<Eip712TypeInfo> {
	use crate::auth::admin::{ADMIN_DOMAIN_NAME, ADMIN_DOMAIN_VERSION};

	let verifier = state.verifier.read().await;

	// EIP-712 types for all admin actions
	// Note: EIP712Domain does NOT include verifyingContract (off-chain verification)
	let types = serde_json::json!({
		"EIP712Domain": [
			{"name": "name", "type": "string"},
			{"name": "version", "type": "string"},
			{"name": "chainId", "type": "uint256"}
		],
		"AddToken": [
			{"name": "chainId", "type": "uint256"},
			{"name": "symbol", "type": "string"},
			{"name": "tokenAddress", "type": "address"},
			{"name": "decimals", "type": "uint8"},
			{"name": "nonce", "type": "uint256"},
			{"name": "deadline", "type": "uint256"}
		],
		"RemoveToken": [
			{"name": "chainId", "type": "uint256"},
			{"name": "tokenAddress", "type": "address"},
			{"name": "nonce", "type": "uint256"},
			{"name": "deadline", "type": "uint256"}
		],
		"Withdraw": [
			{"name": "chainId", "type": "uint256"},
			{"name": "token", "type": "address"},
			{"name": "amount", "type": "uint256"},
			{"name": "recipient", "type": "address"},
			{"name": "nonce", "type": "uint256"},
			{"name": "deadline", "type": "uint256"}
		],
		"UpdateNetwork": [
			{"name": "chainId", "type": "uint256"},
			{"name": "rpcUrls", "type": "string[]"},
			{"name": "nonce", "type": "uint256"},
			{"name": "deadline", "type": "uint256"}
		],
		"AddAdmin": [
			{"name": "newAdmin", "type": "address"},
			{"name": "nonce", "type": "uint256"},
			{"name": "deadline", "type": "uint256"}
		],
		"RemoveAdmin": [
			{"name": "adminToRemove", "type": "address"},
			{"name": "nonce", "type": "uint256"},
			{"name": "deadline", "type": "uint256"}
		],
		"UpdateFeeConfig": [
			{"name": "gasBufferBps", "type": "uint32"},
			{"name": "minProfitabilityPct", "type": "string"},
			{"name": "nonce", "type": "uint256"},
			{"name": "deadline", "type": "uint256"}
		]
	});

	Json(Eip712TypeInfo {
		domain: Eip712Domain {
			name: ADMIN_DOMAIN_NAME.to_string(),
			version: ADMIN_DOMAIN_VERSION.to_string(),
			chain_id: verifier.chain_id(),
		},
		types,
	})
}

#[cfg(test)]
mod tests {
	use super::*;

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
}
