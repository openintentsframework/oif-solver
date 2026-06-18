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
use solver_config::Config;
use solver_types::AuthScope;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Authentication state for middleware containing JWT service and required scope.
#[derive(Clone)]
pub struct AuthState {
	/// JWT service for token validation
	pub jwt_service: Arc<JwtService>,
	/// Required scope for accessing the protected endpoint
	pub required_scope: AuthScope,
	/// Live runtime config used to re-validate ADMIN tokens against the current
	/// admin whitelist on every request. `None` for public-client routes, where
	/// no whitelist gating applies; `Some` for admin routes so a removed admin's
	/// still-unexpired access token is rejected immediately rather than at expiry.
	pub admin_whitelist_config: Option<Arc<RwLock<Config>>>,
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

	// Live admin-whitelist recheck. Signature/expiry/scope validation above only
	// proves the token was legitimately issued and is unexpired — it cannot
	// detect that the admin was removed (or admin auth disabled) AFTER issuance.
	// For ADMIN-scoped tokens we therefore re-validate the subject against the
	// live whitelist on every request so revocation takes effect immediately
	// rather than lingering until the token's own expiry. Public-client tokens
	// carry no admin scope and skip this (`admin_whitelist_config` is also `None`
	// on their routes).
	let is_admin_scoped = claims
		.scope
		.iter()
		.any(|s| matches!(s, AuthScope::AdminAll | AuthScope::AdminRead));
	if is_admin_scoped {
		if let Some(config) = &state.admin_whitelist_config {
			if !crate::apis::auth::is_live_admin_subject(config, &claims.sub).await {
				return (
					StatusCode::UNAUTHORIZED,
					Json(json!({
						"error": "Admin token subject is no longer an authorized admin"
					})),
				)
					.into_response();
			}
		}
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
		create_test_app_with_scope(jwt_service, AuthScope::ReadOrders)
	}

	fn create_test_app_with_scope(
		jwt_service: Arc<JwtService>,
		required_scope: AuthScope,
	) -> Router {
		// No live-whitelist config: existing tests assert pure
		// signature/expiry/scope behavior with admin whitelist gating disabled.
		create_test_app_with_scope_and_config(jwt_service, required_scope, None)
	}

	fn create_test_app_with_scope_and_config(
		jwt_service: Arc<JwtService>,
		required_scope: AuthScope,
		admin_whitelist_config: Option<Arc<RwLock<Config>>>,
	) -> Router {
		let auth_state = AuthState {
			jwt_service,
			required_scope,
			admin_whitelist_config,
		};

		Router::new()
			.route("/protected", get(protected_handler))
			.layer(from_fn_with_state(auth_state, auth_middleware))
	}

	#[tokio::test]
	async fn test_middleware_with_valid_token() {
		let config = AuthConfig {
			orders_auth_enabled: true,
			jwt_secret: SecretString::from("test-secret-key-at-least-32-chars"),
			access_token_expiry_hours: 1,
			refresh_token_expiry_hours: 720,
			issuer: "test".to_string(),
			public_register_enabled: false,
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
			orders_auth_enabled: true,
			jwt_secret: SecretString::from("test-secret-key-at-least-32-chars"),
			access_token_expiry_hours: 1,
			refresh_token_expiry_hours: 720,
			issuer: "test".to_string(),
			public_register_enabled: false,
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
			orders_auth_enabled: true,
			jwt_secret: SecretString::from("test-secret-key-at-least-32-chars"),
			access_token_expiry_hours: 1,
			refresh_token_expiry_hours: 720,
			issuer: "test".to_string(),
			public_register_enabled: false,
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

	#[tokio::test]
	async fn test_admin_all_grants_admin_read_route() {
		let config = AuthConfig {
			orders_auth_enabled: true,
			jwt_secret: SecretString::from("test-secret-key-at-least-32-chars"),
			access_token_expiry_hours: 1,
			refresh_token_expiry_hours: 720,
			issuer: "test".to_string(),
			public_register_enabled: false,
			admin: None,
		};

		let jwt_service = Arc::new(JwtService::new(config).unwrap());
		let token = jwt_service
			.generate_access_token("admin", vec![AuthScope::AdminAll])
			.unwrap();

		let app = create_test_app_with_scope(jwt_service, AuthScope::AdminRead);
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
	async fn test_admin_read_does_not_grant_admin_all_route() {
		let config = AuthConfig {
			orders_auth_enabled: true,
			jwt_secret: SecretString::from("test-secret-key-at-least-32-chars"),
			access_token_expiry_hours: 1,
			refresh_token_expiry_hours: 720,
			issuer: "test".to_string(),
			public_register_enabled: false,
			admin: None,
		};

		let jwt_service = Arc::new(JwtService::new(config).unwrap());
		let token = jwt_service
			.generate_access_token("readonly", vec![AuthScope::AdminRead])
			.unwrap();

		let app = create_test_app_with_scope(jwt_service, AuthScope::AdminAll);
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

	#[tokio::test]
	async fn test_middleware_rejects_refresh_token_as_bearer() {
		// A refresh token carries the same claims shape as an access token —
		// without an explicit `typ` discriminator, a stolen refresh token could
		// be presented in the Authorization header and pass middleware. This
		// test locks in the rejection.
		let config = AuthConfig {
			orders_auth_enabled: true,
			jwt_secret: SecretString::from("test-secret-key-at-least-32-chars"),
			access_token_expiry_hours: 1,
			refresh_token_expiry_hours: 720,
			issuer: "test".to_string(),
			public_register_enabled: false,
			admin: None,
		};

		let jwt_service = Arc::new(JwtService::new(config).unwrap());
		let refresh_token = jwt_service
			.generate_refresh_token("admin", vec![AuthScope::AdminAll])
			.await
			.unwrap();

		let app = create_test_app_with_scope(jwt_service, AuthScope::AdminRead);
		let response = app
			.oneshot(
				Request::builder()
					.uri("/protected")
					.header("Authorization", format!("Bearer {refresh_token}"))
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
	}

	/// Build a live runtime `Config` whose admin whitelist contains exactly the
	/// provided entries (admin auth enabled). This is the live source the
	/// middleware re-checks admin tokens against.
	fn config_with_admin_whitelist(
		whitelist: Vec<solver_types::AdminWhitelistEntry>,
	) -> Arc<RwLock<Config>> {
		use solver_config::{ApiConfig, ApiImplementations, ConfigBuilder};
		use solver_types::AdminConfig;

		let auth_config = AuthConfig {
			orders_auth_enabled: true,
			jwt_secret: SecretString::from("test-secret-key-at-least-32-chars"),
			access_token_expiry_hours: 1,
			refresh_token_expiry_hours: 720,
			issuer: "test".to_string(),
			public_register_enabled: false,
			admin: Some(AdminConfig {
				enabled: true,
				domain: "localhost".to_string(),
				chain_id: Some(1),
				nonce_ttl_seconds: 300,
				whitelist,
			}),
		};

		let mut config = ConfigBuilder::new().build();
		config.api = Some(ApiConfig {
			enabled: true,
			host: "127.0.0.1".to_string(),
			port: 3000,
			timeout_seconds: 30,
			max_request_size: 1024 * 1024,
			implementations: ApiImplementations::default(),
			rate_limiting: None,
			cors: None,
			auth: Some(auth_config),
			quote: None,
		});

		Arc::new(RwLock::new(config))
	}

	/// M-25 (b): An ADMIN access token that was validly issued must stop working
	/// the moment its subject is removed from the live whitelist — without
	/// waiting for the token to expire. The middleware must re-check the live
	/// whitelist for admin-scoped tokens.
	#[tokio::test]
	async fn test_removed_admin_access_token_rejected_by_middleware() {
		use alloy_primitives::Address;

		let config = AuthConfig {
			orders_auth_enabled: true,
			jwt_secret: SecretString::from("test-secret-key-at-least-32-chars"),
			access_token_expiry_hours: 1,
			refresh_token_expiry_hours: 720,
			issuer: "test".to_string(),
			public_register_enabled: false,
			admin: None,
		};
		let jwt_service = Arc::new(JwtService::new(config).unwrap());

		// A still-unexpired admin access token, issued while the admin was valid.
		let admin_address = Address::from([0x11u8; 20]);
		let token = jwt_service
			.generate_access_token(&admin_address.to_string(), vec![AuthScope::AdminAll])
			.unwrap();

		// The live whitelist no longer lists this admin.
		let live_config = config_with_admin_whitelist(vec![]);

		let app = create_test_app_with_scope_and_config(
			jwt_service,
			AuthScope::AdminAll,
			Some(live_config),
		);
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

		assert_eq!(
			response.status(),
			StatusCode::UNAUTHORIZED,
			"a removed admin's still-unexpired access token must be rejected by the middleware"
		);
	}

	/// The legitimate counterpart: an admin still on the live whitelist must
	/// continue to pass the middleware.
	#[tokio::test]
	async fn test_whitelisted_admin_access_token_allowed_by_middleware() {
		use alloy_primitives::Address;
		use solver_types::{AdminRole, AdminWhitelistEntry};

		let config = AuthConfig {
			orders_auth_enabled: true,
			jwt_secret: SecretString::from("test-secret-key-at-least-32-chars"),
			access_token_expiry_hours: 1,
			refresh_token_expiry_hours: 720,
			issuer: "test".to_string(),
			public_register_enabled: false,
			admin: None,
		};
		let jwt_service = Arc::new(JwtService::new(config).unwrap());

		let admin_address = Address::from([0x11u8; 20]);
		let token = jwt_service
			.generate_access_token(&admin_address.to_string(), vec![AuthScope::AdminAll])
			.unwrap();

		let live_config = config_with_admin_whitelist(vec![AdminWhitelistEntry {
			address: admin_address,
			role: AdminRole::Admin,
		}]);

		let app = create_test_app_with_scope_and_config(
			jwt_service,
			AuthScope::AdminAll,
			Some(live_config),
		);
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
}
