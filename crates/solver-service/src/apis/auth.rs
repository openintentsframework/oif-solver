//! Authentication endpoints for JWT token management.
//!
//! This module provides endpoints for client registration and token refresh
//! operations for API authentication.

use crate::auth::JwtService;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use solver_types::AuthScope;
use std::sync::Arc;

/// Request payload for client registration
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
	/// Client identifier (e.g., application name, user email)
	pub client_id: String,
	/// Optional client name for display purposes
	pub client_name: Option<String>,
	/// Requested scopes (if not provided, defaults to basic read permissions)
	pub scopes: Option<Vec<String>>,
}

/// Response payload for successful registration
#[derive(Debug, Serialize)]
pub struct RegisterResponse {
	/// The generated access token
	pub access_token: String,
	/// The generated refresh token
	pub refresh_token: String,
	/// Client identifier
	pub client_id: String,
	/// Access token expiry time in Unix timestamp
	pub access_token_expires_at: i64,
	/// Refresh token expiry time in Unix timestamp
	pub refresh_token_expires_at: i64,
	/// Granted scopes
	pub scopes: Vec<String>,
	/// Token type (always "Bearer")
	pub token_type: String,
}

/// Request payload for token refresh
#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
	/// The refresh token to exchange for new tokens
	pub refresh_token: String,
}

/// Handles POST /api/auth/register requests.
///
/// This endpoint allows clients to self-register and receive both access and refresh tokens
/// for API authentication. The access token has a short expiry (1 hour by default) while
/// the refresh token has a longer expiry (30 days by default).
pub async fn register_client(
	State(jwt_service): State<Option<Arc<JwtService>>>,
	Json(request): Json<RegisterRequest>,
) -> impl IntoResponse {
	// Check if JWT service is configured
	let jwt_service = match jwt_service {
		Some(service) => service,
		None => {
			return (
				StatusCode::SERVICE_UNAVAILABLE,
				Json(json!({
					"error": "Authentication service is not configured"
				})),
			)
				.into_response();
		},
	};

	// Validate client_id
	if request.client_id.is_empty() {
		return (
			StatusCode::BAD_REQUEST,
			Json(json!({
				"error": "Client ID cannot be empty"
			})),
		)
			.into_response();
	}

	// Validate client_id format (basic validation)
	if request.client_id.len() < 3 || request.client_id.len() > 100 {
		return (
			StatusCode::BAD_REQUEST,
			Json(json!({
				"error": "Client ID must be between 3 and 100 characters"
			})),
		)
			.into_response();
	}

	// Parse requested scopes or use defaults
	let scopes = match parse_scopes(request.scopes) {
		Ok(scopes) => scopes,
		Err(e) => {
			return (
				StatusCode::BAD_REQUEST,
				Json(json!({
					"error": format!("Invalid scopes: {}", e)
				})),
			)
				.into_response();
		},
	};

	// Generate access token
	let access_token = match jwt_service.generate_access_token(&request.client_id, scopes.clone()) {
		Ok(token) => token,
		Err(e) => {
			tracing::error!(
				"Failed to generate access token for client {}: {}",
				request.client_id,
				e
			);
			return (
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(json!({
					"error": "Failed to generate access token"
				})),
			)
				.into_response();
		},
	};

	// Generate refresh token
	let refresh_token = match jwt_service
		.generate_refresh_token(&request.client_id, scopes.clone())
		.await
	{
		Ok(token) => token,
		Err(e) => {
			tracing::error!(
				"Failed to generate refresh token for client {}: {}",
				request.client_id,
				e
			);
			return (
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(json!({
					"error": "Failed to generate refresh token"
				})),
			)
				.into_response();
		},
	};

	// Get access token expiry from the token claims
	let access_token_expires_at = match jwt_service.validate_token(&access_token) {
		Ok(claims) => claims.exp,
		Err(_) => {
			// Fallback calculation if we can't decode our own token
			let expiry_hours = jwt_service.config().access_token_expiry_hours;
			chrono::Utc::now().timestamp() + (expiry_hours as i64 * 3600)
		},
	};

	// Get refresh token expiry from configuration
	let refresh_token_expires_at = chrono::Utc::now().timestamp()
		+ (jwt_service.config().refresh_token_expiry_hours as i64 * 3600);

	// Log successful registration
	tracing::info!(
		client_id = %request.client_id,
		client_name = ?request.client_name,
		scopes = ?scopes,
		"Client registered successfully with refresh token"
	);

	// Return success response
	let response = RegisterResponse {
		access_token,
		refresh_token,
		client_id: request.client_id,
		access_token_expires_at,
		refresh_token_expires_at,
		scopes: scopes.iter().map(|s| s.to_string()).collect(),
		token_type: "Bearer".to_string(),
	};

	(StatusCode::CREATED, Json(response)).into_response()
}

/// Handles POST /api/auth/refresh requests.
///
/// This endpoint exchanges a valid refresh token for new access and refresh tokens.
/// The old refresh token is invalidated and cannot be reused.
pub async fn refresh_token(
	State(jwt_service): State<Option<Arc<JwtService>>>,
	Json(request): Json<RefreshRequest>,
) -> impl IntoResponse {
	// Check if JWT service is configured
	let jwt_service = match jwt_service {
		Some(service) => service,
		None => {
			return (
				StatusCode::SERVICE_UNAVAILABLE,
				Json(json!({
					"error": "Authentication service is not configured"
				})),
			)
				.into_response();
		},
	};

	// Validate refresh token is not empty
	if request.refresh_token.is_empty() {
		return (
			StatusCode::BAD_REQUEST,
			Json(json!({
				"error": "Refresh token cannot be empty"
			})),
		)
			.into_response();
	}

	// First validate the refresh token to extract claims for response
	let refresh_claims = match jwt_service.validate_token(&request.refresh_token) {
		Ok(claims) => claims,
		Err(e) => {
			tracing::warn!("Invalid refresh token: {}", e);
			return (
				StatusCode::UNAUTHORIZED,
				Json(json!({
					"error": "Invalid or expired refresh token"
				})),
			)
				.into_response();
		},
	};

	// Exchange refresh token for new tokens
	let (new_access_token, new_refresh_token) = match jwt_service
		.refresh_access_token(&request.refresh_token)
		.await
	{
		Ok((access, refresh)) => (access, refresh),
		Err(e) => {
			tracing::warn!("Failed to refresh token: {}", e);
			return (
				StatusCode::UNAUTHORIZED,
				Json(json!({
					"error": "Invalid or expired refresh token"
				})),
			)
				.into_response();
		},
	};

	// Get access token expiry from the token claims
	let access_token_expires_at = match jwt_service.validate_token(&new_access_token) {
		Ok(claims) => claims.exp,
		Err(_) => {
			// Fallback calculation if we can't decode our own token
			let expiry_hours = jwt_service.config().access_token_expiry_hours;
			chrono::Utc::now().timestamp() + (expiry_hours as i64 * 3600)
		},
	};

	// Get refresh token expiry from configuration
	let refresh_token_expires_at = chrono::Utc::now().timestamp()
		+ (jwt_service.config().refresh_token_expiry_hours as i64 * 3600);

	tracing::info!("Token refreshed successfully");

	// Return success response
	let response = RegisterResponse {
		access_token: new_access_token,
		refresh_token: new_refresh_token,
		client_id: refresh_claims.sub,
		access_token_expires_at,
		refresh_token_expires_at,
		scopes: refresh_claims.scope.iter().map(|s| s.to_string()).collect(),
		token_type: "Bearer".to_string(),
	};

	(StatusCode::OK, Json(response)).into_response()
}

/// Parse string scopes into AuthScope enums
fn parse_scopes(scopes: Option<Vec<String>>) -> Result<Vec<AuthScope>, String> {
	// If no scopes provided, default to basic read permissions
	let scope_strings = scopes.unwrap_or_else(|| vec!["read-orders".to_string()]);

	scope_strings
		.into_iter()
		.map(|s| s.parse::<AuthScope>())
		.collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_parse_scopes_default() {
		let scopes = parse_scopes(None).unwrap();
		assert_eq!(scopes, vec![AuthScope::ReadOrders]);
	}

	#[test]
	fn test_parse_scopes_valid() {
		let input = Some(vec!["read-orders".to_string(), "create-orders".to_string()]);
		let scopes = parse_scopes(input).unwrap();
		assert_eq!(scopes, vec![AuthScope::ReadOrders, AuthScope::CreateOrders]);
	}

	#[test]
	fn test_parse_scopes_invalid() {
		let input = Some(vec!["invalid-scope".to_string()]);
		let result = parse_scopes(input);
		assert!(result.is_err());
		assert!(result.unwrap_err().contains("Unknown scope"));
	}

	#[test]
	fn test_parse_scopes_admin() {
		let input = Some(vec!["admin-all".to_string()]);
		let scopes = parse_scopes(input).unwrap();
		assert_eq!(scopes, vec![AuthScope::AdminAll]);
	}
}
