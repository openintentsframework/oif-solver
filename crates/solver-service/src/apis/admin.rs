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
use solver_storage::config_store::{ConfigStore, ConfigStoreError};
use solver_types::{OperatorConfig, OperatorToken};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::auth::admin::{
	AddTokenContents, AdminActionVerifier, AdminAuthError, SignedAdminRequest,
};
use crate::config_merge::build_runtime_config;

/// Shared state for admin endpoints.
#[derive(Clone)]
pub struct AdminApiState {
	/// Verifier for EIP-712 admin signatures.
	pub verifier: Arc<AdminActionVerifier>,
	/// ConfigStore for persisting OperatorConfig to Redis.
	pub config_store: Arc<dyn ConfigStore<OperatorConfig>>,
	/// Shared runtime config that gets hot-reloaded.
	pub shared_config: Arc<RwLock<Config>>,
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
	let nonce = state.verifier.generate_nonce().await?;

	Ok(Json(NonceResponse {
		nonce: nonce.to_string(),
		expires_in: state.verifier.nonce_ttl(),
		domain: state.verifier.domain().to_string(),
		chain_id: state.verifier.chain_id(),
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
	// 1. Verify the signature - nonce is extracted from the signed contents
	let admin = state
		.verifier
		.verify(&request.contents, &request.signature)
		.await?;

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
	*state.shared_config.write().await = new_config;

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
		]
	});

	Json(Eip712TypeInfo {
		domain: Eip712Domain {
			name: ADMIN_DOMAIN_NAME.to_string(),
			version: ADMIN_DOMAIN_VERSION.to_string(),
			chain_id: state.verifier.chain_id(),
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
