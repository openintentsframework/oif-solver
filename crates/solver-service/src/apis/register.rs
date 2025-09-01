//! Client registration endpoint for JWT token generation.
//!
//! This module provides a public endpoint for clients to register
//! and receive JWT tokens for API authentication.

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
	/// Optional custom token expiry in hours
	pub expiry_hours: Option<u32>,
}

/// Response payload for successful registration
#[derive(Debug, Serialize)]
pub struct RegisterResponse {
	/// The generated JWT token
	pub token: String,
	/// Client identifier
	pub client_id: String,
	/// Token expiry time in Unix timestamp
	pub expires_at: i64,
	/// Granted scopes
	pub scopes: Vec<String>,
	/// Token type (always "Bearer")
	pub token_type: String,
}

/// Handles POST /api/register requests.
///
/// This endpoint allows clients to self-register and receive a JWT token
/// for API authentication. In production, you may want to add additional
/// validation, rate limiting, or approval workflows.
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

	// Generate JWT token
	let token = match jwt_service.generate_token(
		&request.client_id,
		scopes.clone(),
		request.expiry_hours,
	) {
		Ok(token) => token,
		Err(e) => {
			tracing::error!(
				"Failed to generate token for client {}: {}",
				request.client_id,
				e
			);
			return (
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(json!({
					"error": "Failed to generate authentication token"
				})),
			)
				.into_response();
		},
	};

	// Decode the token to get the actual expiry from the claims
	let expires_at = match jwt_service.validate_token(&token) {
		Ok(claims) => claims.exp,
		Err(_) => {
			// Fallback: calculate based on config if we can't decode our own token
			let expiry_hours = request.expiry_hours.unwrap_or(24);
			chrono::Utc::now().timestamp() + (expiry_hours as i64 * 3600)
		}
	};

	// Log successful registration
	tracing::info!(
		client_id = %request.client_id,
		client_name = ?request.client_name,
		scopes = ?scopes,
		"Client registered successfully"
	);

	// Return success response
	let response = RegisterResponse {
		token,
		client_id: request.client_id,
		expires_at,
		scopes: scopes.iter().map(|s| s.to_string()).collect(),
		token_type: "Bearer".to_string(),
	};

	(StatusCode::CREATED, Json(response)).into_response()
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
