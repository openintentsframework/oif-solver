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
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
	/// Client identifier (e.g., application name, user email)
	pub client_id: String,
	/// Optional client name for display purposes
	pub client_name: Option<String>,
	/// Requested scopes (if not provided, defaults to basic read permissions)
	pub scopes: Option<Vec<String>>,
}

/// Response payload for successful registration
#[derive(Debug, Serialize, Deserialize)]
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
#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshRequest {
	/// The refresh token to exchange for new tokens
	pub refresh_token: String,
}

/// Handles POST /api/v1/auth/register requests.
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

/// Handles POST /api/v1/auth/refresh requests.
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
	use crate::auth::JwtService;
	use axum::http::StatusCode;
	use serde_json::Value;
	use solver_types::{AuthConfig, SecretString};
	use std::sync::Arc;

	// Helper function to create a test JWT service
	fn create_test_jwt_service() -> Arc<JwtService> {
		let config = AuthConfig {
			enabled: true,
			jwt_secret: SecretString::from("test-secret-key-at-least-32-chars-long"),
			access_token_expiry_hours: 1,
			refresh_token_expiry_hours: 720,
			issuer: "test-issuer".to_string(),
		};
		Arc::new(JwtService::new(config).unwrap())
	}

	// Helper function to extract JSON from response body
	async fn extract_json_from_body(body: axum::body::Body) -> Value {
		let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
		serde_json::from_slice(&bytes).unwrap()
	}

	// Tests for parse_scopes function
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

	#[test]
	fn test_parse_scopes_all_variants() {
		let input = Some(vec![
			"read-orders".to_string(),
			"create-orders".to_string(),
			"read-quotes".to_string(),
			"create-quotes".to_string(),
			"admin-all".to_string(),
		]);
		let scopes = parse_scopes(input).unwrap();
		assert_eq!(
			scopes,
			vec![
				AuthScope::ReadOrders,
				AuthScope::CreateOrders,
				AuthScope::ReadQuotes,
				AuthScope::CreateQuotes,
				AuthScope::AdminAll,
			]
		);
	}

	#[test]
	fn test_parse_scopes_mixed_valid_invalid() {
		let input = Some(vec!["read-orders".to_string(), "invalid-scope".to_string()]);
		let result = parse_scopes(input);
		assert!(result.is_err());
		assert!(result.unwrap_err().contains("Unknown scope"));
	}

	#[test]
	fn test_parse_scopes_empty_list() {
		let input = Some(vec![]);
		let scopes = parse_scopes(input).unwrap();
		assert_eq!(scopes, vec![]); // Empty list should remain empty
	}

	// Tests for register_client endpoint
	#[tokio::test]
	async fn test_register_client_success() {
		let jwt_service = create_test_jwt_service();
		let request = RegisterRequest {
			client_id: "test-client".to_string(),
			client_name: Some("Test Client".to_string()),
			scopes: Some(vec!["read-orders".to_string(), "create-orders".to_string()]),
		};

		let response =
			register_client(axum::extract::State(Some(jwt_service)), Json(request)).await;

		let response_obj = response.into_response();
		let (parts, body) = response_obj.into_parts();
		assert_eq!(parts.status, StatusCode::CREATED);

		let json_body = extract_json_from_body(body).await;
		let response: RegisterResponse = serde_json::from_value(json_body).unwrap();
		assert_eq!(response.client_id, "test-client");
		assert_eq!(response.token_type, "Bearer");
		assert_eq!(response.scopes, vec!["read-orders", "create-orders"]);
		assert!(!response.access_token.is_empty());
		assert!(!response.refresh_token.is_empty());
		assert!(response.access_token_expires_at > 0);
		assert!(response.refresh_token_expires_at > 0);
	}

	#[tokio::test]
	async fn test_register_client_no_jwt_service() {
		let request = RegisterRequest {
			client_id: "test-client".to_string(),
			client_name: None,
			scopes: None,
		};

		let response = register_client(axum::extract::State(None), Json(request)).await;

		let response_obj = response.into_response();
		let (parts, body) = response_obj.into_parts();
		assert_eq!(parts.status, StatusCode::SERVICE_UNAVAILABLE);

		let json_body = extract_json_from_body(body).await;
		assert_eq!(
			json_body["error"],
			"Authentication service is not configured"
		);
	}

	#[tokio::test]
	async fn test_register_client_empty_client_id() {
		let jwt_service = create_test_jwt_service();
		let request = RegisterRequest {
			client_id: "".to_string(),
			client_name: None,
			scopes: None,
		};

		let response =
			register_client(axum::extract::State(Some(jwt_service)), Json(request)).await;

		let response_obj = response.into_response();
		let (parts, body) = response_obj.into_parts();
		assert_eq!(parts.status, StatusCode::BAD_REQUEST);

		let json_body = extract_json_from_body(body).await;
		assert_eq!(json_body["error"], "Client ID cannot be empty");
	}

	#[tokio::test]
	async fn test_register_client_short_client_id() {
		let jwt_service = create_test_jwt_service();
		let request = RegisterRequest {
			client_id: "ab".to_string(), // Too short
			client_name: None,
			scopes: None,
		};

		let response =
			register_client(axum::extract::State(Some(jwt_service)), Json(request)).await;

		let response_obj = response.into_response();
		let (parts, body) = response_obj.into_parts();
		assert_eq!(parts.status, StatusCode::BAD_REQUEST);

		let json_body = extract_json_from_body(body).await;
		assert_eq!(
			json_body["error"],
			"Client ID must be between 3 and 100 characters"
		);
	}

	#[tokio::test]
	async fn test_register_client_long_client_id() {
		let jwt_service = create_test_jwt_service();
		let request = RegisterRequest {
			client_id: "a".repeat(101), // Too long
			client_name: None,
			scopes: None,
		};

		let response =
			register_client(axum::extract::State(Some(jwt_service)), Json(request)).await;

		let response_obj = response.into_response();
		let (parts, body) = response_obj.into_parts();
		assert_eq!(parts.status, StatusCode::BAD_REQUEST);

		let json_body = extract_json_from_body(body).await;
		assert_eq!(
			json_body["error"],
			"Client ID must be between 3 and 100 characters"
		);
	}

	#[tokio::test]
	async fn test_register_client_invalid_scopes() {
		let jwt_service = create_test_jwt_service();
		let request = RegisterRequest {
			client_id: "test-client".to_string(),
			client_name: None,
			scopes: Some(vec!["invalid-scope".to_string()]),
		};

		let response =
			register_client(axum::extract::State(Some(jwt_service)), Json(request)).await;

		let response_obj = response.into_response();
		let (parts, body) = response_obj.into_parts();
		assert_eq!(parts.status, StatusCode::BAD_REQUEST);

		let json_body = extract_json_from_body(body).await;
		assert!(json_body["error"]
			.as_str()
			.unwrap()
			.contains("Invalid scopes"));
	}

	#[tokio::test]
	async fn test_register_client_default_scopes() {
		let jwt_service = create_test_jwt_service();
		let request = RegisterRequest {
			client_id: "test-client".to_string(),
			client_name: None,
			scopes: None, // Should default to read-orders
		};

		let response =
			register_client(axum::extract::State(Some(jwt_service)), Json(request)).await;

		let response_obj = response.into_response();
		let (parts, body) = response_obj.into_parts();
		assert_eq!(parts.status, StatusCode::CREATED);

		let json_body = extract_json_from_body(body).await;
		let response: RegisterResponse = serde_json::from_value(json_body).unwrap();
		assert_eq!(response.scopes, vec!["read-orders"]);
	}

	// Tests for refresh_token endpoint
	#[tokio::test]
	async fn test_refresh_token_success() {
		let jwt_service = create_test_jwt_service();

		// First generate a refresh token
		let refresh_token_str = jwt_service
			.generate_refresh_token("test-client", vec![AuthScope::ReadOrders])
			.await
			.unwrap();

		let request = RefreshRequest {
			refresh_token: refresh_token_str,
		};

		let response = refresh_token(axum::extract::State(Some(jwt_service)), Json(request)).await;

		let response_obj = response.into_response();
		let (parts, body) = response_obj.into_parts();
		assert_eq!(parts.status, StatusCode::OK);

		let json_body = extract_json_from_body(body).await;
		let response: RegisterResponse = serde_json::from_value(json_body).unwrap();
		assert_eq!(response.client_id, "test-client");
		assert_eq!(response.token_type, "Bearer");
		assert_eq!(response.scopes, vec!["read-orders"]);
		assert!(!response.access_token.is_empty());
		assert!(!response.refresh_token.is_empty());
	}

	#[tokio::test]
	async fn test_refresh_token_no_jwt_service() {
		let request = RefreshRequest {
			refresh_token: "some-token".to_string(),
		};

		let response = refresh_token(axum::extract::State(None), Json(request)).await;

		let response_obj = response.into_response();
		let (parts, body) = response_obj.into_parts();
		assert_eq!(parts.status, StatusCode::SERVICE_UNAVAILABLE);

		let json_body = extract_json_from_body(body).await;
		assert_eq!(
			json_body["error"],
			"Authentication service is not configured"
		);
	}

	#[tokio::test]
	async fn test_refresh_token_empty_token() {
		let jwt_service = create_test_jwt_service();
		let request = RefreshRequest {
			refresh_token: "".to_string(),
		};

		let response = refresh_token(axum::extract::State(Some(jwt_service)), Json(request)).await;

		let response_obj = response.into_response();
		let (parts, body) = response_obj.into_parts();
		assert_eq!(parts.status, StatusCode::BAD_REQUEST);

		let json_body = extract_json_from_body(body).await;
		assert_eq!(json_body["error"], "Refresh token cannot be empty");
	}

	#[tokio::test]
	async fn test_refresh_token_invalid_token() {
		let jwt_service = create_test_jwt_service();
		let request = RefreshRequest {
			refresh_token: "invalid-token".to_string(),
		};

		let response = refresh_token(axum::extract::State(Some(jwt_service)), Json(request)).await;

		let response_obj = response.into_response();
		let (parts, body) = response_obj.into_parts();
		assert_eq!(parts.status, StatusCode::UNAUTHORIZED);

		let json_body = extract_json_from_body(body).await;
		assert_eq!(json_body["error"], "Invalid or expired refresh token");
	}

	// Tests for request/response serialization
	#[test]
	fn test_register_request_serialization() {
		let request = RegisterRequest {
			client_id: "test-client".to_string(),
			client_name: Some("Test Client".to_string()),
			scopes: Some(vec!["read-orders".to_string()]),
		};

		let json = serde_json::to_string(&request).unwrap();
		let deserialized: RegisterRequest = serde_json::from_str(&json).unwrap();

		assert_eq!(deserialized.client_id, "test-client");
		assert_eq!(deserialized.client_name, Some("Test Client".to_string()));
		assert_eq!(deserialized.scopes, Some(vec!["read-orders".to_string()]));
	}

	#[test]
	fn test_register_response_serialization() {
		let response = RegisterResponse {
			access_token: "access-token".to_string(),
			refresh_token: "refresh-token".to_string(),
			client_id: "test-client".to_string(),
			access_token_expires_at: 1234567890,
			refresh_token_expires_at: 1234567890,
			scopes: vec!["read-orders".to_string()],
			token_type: "Bearer".to_string(),
		};

		let json = serde_json::to_string(&response).unwrap();
		let deserialized: RegisterResponse = serde_json::from_str(&json).unwrap();

		assert_eq!(deserialized.client_id, "test-client");
		assert_eq!(deserialized.token_type, "Bearer");
		assert_eq!(deserialized.scopes, vec!["read-orders"]);
	}

	#[test]
	fn test_refresh_request_serialization() {
		let request = RefreshRequest {
			refresh_token: "refresh-token".to_string(),
		};

		let json = serde_json::to_string(&request).unwrap();
		let deserialized: RefreshRequest = serde_json::from_str(&json).unwrap();

		assert_eq!(deserialized.refresh_token, "refresh-token");
	}
}
