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
use std::sync::Arc;

use crate::auth::admin::{
	AddTokenContents, AdminActionVerifier, AdminAuthError, SignedAdminRequest,
};

/// Shared state for admin endpoints.
#[derive(Clone)]
pub struct AdminApiState {
	pub verifier: Arc<AdminActionVerifier>,
}

/// Response for nonce generation.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NonceResponse {
	/// Numeric nonce for EIP-712 signing (uint256 compatible)
	pub nonce: u64,
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
		nonce,
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
	// Verify the signature - nonce is extracted from the signed contents
	let admin = state
		.verifier
		.verify(&request.contents, &request.signature)
		.await?;

	Ok(Json(AdminActionResponse {
		success: true,
		message: format!(
			"Token {} added to chain {}",
			request.contents.symbol, request.contents.chain_id
		),
		admin: format!("{:?}", admin),
	}))
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
			nonce: 12345678901234,
			expires_in: 300,
			domain: "test.example.com".to_string(),
			chain_id: 1,
		};

		let json = serde_json::to_string(&response).unwrap();
		assert!(json.contains("\"nonce\":12345678901234"));
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
