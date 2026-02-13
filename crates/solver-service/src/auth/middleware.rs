//! Axum middleware for JWT authentication.
//!
//! This module provides middleware that validates JWT tokens in incoming
//! requests and enforces scope-based authorization.

use super::JwtService;
use axum::{
	extract::State,
	http::{HeaderMap, Method, Request, StatusCode},
	middleware::Next,
	response::{IntoResponse, Response},
	Json,
};
use serde_json::json;
use solver_types::AuthScope;
use std::sync::Arc;

/// Authentication state for middleware containing JWT service and required scope.
#[derive(Clone)]
pub struct AuthState {
	/// JWT service for token validation
	pub jwt_service: Arc<JwtService>,
	/// Required scope for accessing the protected endpoint
	pub required_scope: AuthScope,
}

/// Middleware function that validates JWT tokens and enforces authorization.
///
/// This middleware:
/// 1. Extracts the JWT token from the Authorization header
/// 2. Validates the token using the JWT service
/// 3. Checks if the token has the required scope
/// 4. Adds the claims to the request extensions for use in handlers
///
/// # Arguments
/// * `state` - Authentication state containing JWT service and required scope
/// * `request` - The incoming HTTP request
/// * `next` - The next middleware or handler in the chain
///
/// # Returns
/// Either passes the request to the next handler or returns an error response
pub async fn auth_middleware(
	State(state): State<AuthState>,
	mut request: Request<axum::body::Body>,
	next: Next,
) -> Response {
	// Skip auth for OPTIONS requests (CORS preflight)
	if request.method() == Method::OPTIONS {
		return next.run(request).await;
	}

	// Extract headers from request
	let headers = request.headers().clone();

	// Extract token from Authorization header
	let token = match extract_bearer_token(&headers) {
		Some(token) => token,
		None => {
			return (
				StatusCode::UNAUTHORIZED,
				Json(json!({
					"error": "Missing or invalid Authorization header"
				})),
			)
				.into_response();
		},
	};

	// Validate token
	let claims = match state.jwt_service.validate_token(token) {
		Ok(claims) => claims,
		Err(e) => {
			return (
				StatusCode::UNAUTHORIZED,
				Json(json!({
					"error": format!("Invalid token: {}", e)
				})),
			)
				.into_response();
		},
	};

	// Check required scope
	if !JwtService::check_scope(&claims, &state.required_scope) {
		return (
			StatusCode::FORBIDDEN,
			Json(json!({
				"error": "Insufficient permissions",
				"required_scope": state.required_scope.to_string(),
				"provided_scopes": claims.scope.iter().map(|s| s.to_string()).collect::<Vec<_>>()
			})),
		)
			.into_response();
	}

	// Add claims to request extensions for use in handlers
	request.extensions_mut().insert(claims);

	next.run(request).await
}

/// Extracts the bearer token from the Authorization header.
///
/// The header should be in the format: "Bearer <token>"
///
/// # Arguments
/// * `headers` - HTTP headers from the request
///
/// # Returns
/// The token string if present and properly formatted, None otherwise
fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
	headers
		.get("authorization")
		.and_then(|h| h.to_str().ok())
		.and_then(|h| h.strip_prefix("Bearer "))
}

#[cfg(test)]
mod tests {
	use super::*;
	use axum::{
		body::Body,
		http::{Request, StatusCode},
		middleware::from_fn_with_state,
		response::IntoResponse,
		routing::get,
		Router,
	};
	use solver_types::{AuthConfig, SecretString};
	use tower::ServiceExt;

	async fn protected_handler() -> impl IntoResponse {
		Json(json!({"message": "Protected resource accessed"}))
	}

	fn create_test_app(jwt_service: Arc<JwtService>) -> Router {
		let auth_state = AuthState {
			jwt_service,
			required_scope: AuthScope::ReadOrders,
		};

		Router::new()
			.route("/protected", get(protected_handler))
			.layer(from_fn_with_state(auth_state, auth_middleware))
	}

	#[tokio::test]
	async fn test_middleware_with_valid_token() {
		let config = AuthConfig {
			enabled: true,
			jwt_secret: SecretString::from("test-secret-key-at-least-32-chars"),
			access_token_expiry_hours: 1,
			refresh_token_expiry_hours: 720,
			issuer: "test".to_string(),
			public_register_enabled: false,
			token_client_id: "solver-admin".to_string(),
			token_client_secret: None,
			admin: None,
		};

		let jwt_service = Arc::new(JwtService::new(config).unwrap());
		let token = jwt_service
			.generate_access_token("test-client", vec![AuthScope::ReadOrders])
			.unwrap();

		let app = create_test_app(jwt_service);

		let response = app
			.oneshot(
				Request::builder()
					.uri("/protected")
					.header("Authorization", format!("Bearer {token}"))
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::OK);
	}

	#[tokio::test]
	async fn test_middleware_without_token() {
		let config = AuthConfig {
			enabled: true,
			jwt_secret: SecretString::from("test-secret-key-at-least-32-chars"),
			access_token_expiry_hours: 1,
			refresh_token_expiry_hours: 720,
			issuer: "test".to_string(),
			public_register_enabled: false,
			token_client_id: "solver-admin".to_string(),
			token_client_secret: None,
			admin: None,
		};

		let jwt_service = Arc::new(JwtService::new(config).unwrap());
		let app = create_test_app(jwt_service);

		let response = app
			.oneshot(
				Request::builder()
					.uri("/protected")
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
	}

	#[tokio::test]
	async fn test_middleware_with_wrong_scope() {
		let config = AuthConfig {
			enabled: true,
			jwt_secret: SecretString::from("test-secret-key-at-least-32-chars"),
			access_token_expiry_hours: 1,
			refresh_token_expiry_hours: 720,
			issuer: "test".to_string(),
			public_register_enabled: false,
			token_client_id: "solver-admin".to_string(),
			token_client_secret: None,
			admin: None,
		};

		let jwt_service = Arc::new(JwtService::new(config).unwrap());
		let token = jwt_service
			.generate_access_token("test-client", vec![AuthScope::CreateQuotes])
			.unwrap();

		let app = create_test_app(jwt_service);

		let response = app
			.oneshot(
				Request::builder()
					.uri("/protected")
					.header("Authorization", format!("Bearer {token}"))
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::FORBIDDEN);
	}
}
