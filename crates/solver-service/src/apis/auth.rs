//! Authentication endpoints for JWT token management.
//!
//! This module provides endpoints for client registration, client credentials
//! token issuance, and token refresh operations for API authentication.

use crate::auth::{siwe::verify_siwe_signature, JwtService};
use axum::{
	extract::State,
	http::{HeaderMap, StatusCode},
	response::IntoResponse,
	Json,
};
use base64::Engine;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha3::{Digest, Sha3_256};
use solver_config::Config;
use solver_storage::nonce_store::NonceStore;
use solver_types::AuthScope;
use std::{collections::VecDeque, net::SocketAddr, sync::Arc};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;

const TOKEN_DEFAULT_TTL_SECONDS: u32 = 900;
const TOKEN_MAX_TTL_SECONDS: u32 = 3600;
const TOKEN_RATE_LIMIT_PER_MINUTE: usize = 30;
const TOKEN_RATE_LIMIT_IP_PER_MINUTE: usize = 120;
const RATE_LIMIT_WINDOW_SECONDS: i64 = 60;
const MAX_RATE_LIMIT_KEYS: usize = 10_000;
const MAX_FAILURE_EVENTS_PER_KEY: usize = 256;

static FAILED_AUTH_BY_CLIENT: Lazy<DashMap<String, VecDeque<i64>>> = Lazy::new(DashMap::new);
static FAILED_AUTH_BY_IP: Lazy<DashMap<String, VecDeque<i64>>> = Lazy::new(DashMap::new);

/// Shared state for SIWE auth endpoints.
#[derive(Clone)]
pub struct SiweAuthState {
	/// JWT service used for access token issuance.
	pub jwt_service: Option<Arc<JwtService>>,
	/// Dynamic runtime config containing auth/admin settings.
	pub config: Arc<RwLock<Config>>,
	/// Dedicated nonce store for SIWE flow.
	pub siwe_nonce_store: Option<Arc<NonceStore>>,
}

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

/// Request payload for client credentials token issuance.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenRequest {
	/// OAuth2 grant type (must be "client_credentials")
	pub grant_type: Option<String>,
	/// Optional fallback client id when Authorization: Basic is not provided
	pub client_id: Option<String>,
	/// Optional fallback client secret when Authorization: Basic is not provided
	pub client_secret: Option<String>,
	/// Requested scope (pilot accepts only "admin-all")
	pub scope: Option<String>,
}

/// Response payload for client credentials token issuance.
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
	/// The generated access token
	pub access_token: String,
	/// Token type (always "Bearer")
	pub token_type: String,
	/// Access token lifetime in seconds
	pub expires_in: u32,
	/// Granted scope
	pub scope: String,
}

/// Request payload for SIWE nonce creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiweNonceRequest {
	/// Ethereum address that will sign the SIWE message.
	pub address: String,
}

/// Response payload for SIWE nonce creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiweNonceResponse {
	/// Single-use nonce to include in SIWE message.
	pub nonce: String,
	/// Pre-built SIWE message to sign.
	pub message: String,
	/// Nonce validity in seconds.
	pub expires_in: u64,
	/// Expected SIWE domain.
	pub domain: String,
	/// Expected SIWE chain ID.
	pub chain_id: u64,
}

/// Request payload for SIWE message verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiweVerifyRequest {
	/// Full SIWE message.
	pub message: String,
	/// Ethereum personal_sign signature over the message.
	pub signature: String,
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

	if !jwt_service.config().enabled {
		return (
			StatusCode::SERVICE_UNAVAILABLE,
			Json(json!({
				"error": "Authentication is disabled"
			})),
		)
			.into_response();
	}

	if !jwt_service.config().public_register_enabled {
		return (
			StatusCode::FORBIDDEN,
			Json(json!({
				"error": "Public client registration is disabled"
			})),
		)
			.into_response();
	}

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
	let scopes = match parse_public_scopes(request.scopes) {
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

	if !jwt_service.config().enabled {
		return (
			StatusCode::SERVICE_UNAVAILABLE,
			Json(json!({
				"error": "Authentication is disabled"
			})),
		)
			.into_response();
	}

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

/// Handles POST /api/v1/auth/token requests.
///
/// Issues an access token using client credentials. This endpoint is intended
/// for privileged machine clients and issues access tokens only (no refresh token).
pub async fn issue_client_token(
	State(jwt_service): State<Option<Arc<JwtService>>>,
	headers: HeaderMap,
	Json(request): Json<TokenRequest>,
) -> impl IntoResponse {
	issue_client_token_with_peer(State(jwt_service), headers, None, Json(request)).await
}

/// Handles POST /api/v1/auth/token requests with optional peer address.
///
/// Used by HTTP handlers that can provide trusted socket peer metadata.
pub async fn issue_client_token_with_peer(
	State(jwt_service): State<Option<Arc<JwtService>>>,
	headers: HeaderMap,
	peer_addr: Option<SocketAddr>,
	Json(request): Json<TokenRequest>,
) -> impl IntoResponse {
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

	if !jwt_service.config().enabled {
		return (
			StatusCode::SERVICE_UNAVAILABLE,
			Json(json!({
				"error": "Authentication is disabled"
			})),
		)
			.into_response();
	}

	let configured_secret = match jwt_service.config().token_client_secret.as_ref() {
		Some(secret) => secret,
		None => {
			return (
				StatusCode::SERVICE_UNAVAILABLE,
				Json(json!({
					"error": "Client credentials authentication is not configured"
				})),
			)
				.into_response();
		},
	};

	let grant_type = match request.grant_type.as_deref() {
		Some(grant_type) => grant_type.trim(),
		None => {
			return oauth_error_response(
				StatusCode::BAD_REQUEST,
				"unsupported_grant_type",
				"grant_type must be client_credentials",
			);
		},
	};
	if grant_type != "client_credentials" {
		return oauth_error_response(
			StatusCode::BAD_REQUEST,
			"unsupported_grant_type",
			"grant_type must be client_credentials",
		);
	}

	let requested_scope = request.scope.as_deref().unwrap_or("admin-all").trim();
	if requested_scope != "admin-all" {
		return oauth_error_response(
			StatusCode::BAD_REQUEST,
			"invalid_scope",
			"only admin-all scope is supported by /auth/token",
		);
	}

	let (client_id, client_secret) = match extract_client_credentials(&headers, &request) {
		Some(credentials) => credentials,
		None => {
			return oauth_error_response(
				StatusCode::UNAUTHORIZED,
				"invalid_client",
				"missing client credentials",
			);
		},
	};
	let source_ip = extract_source_ip(&headers, peer_addr);
	let now = chrono::Utc::now().timestamp();

	if is_rate_limited(
		&FAILED_AUTH_BY_CLIENT,
		&client_id,
		TOKEN_RATE_LIMIT_PER_MINUTE,
		now,
	) || is_rate_limited(
		&FAILED_AUTH_BY_IP,
		&source_ip,
		TOKEN_RATE_LIMIT_IP_PER_MINUTE,
		now,
	) {
		return oauth_error_response(
			StatusCode::TOO_MANY_REQUESTS,
			"too_many_requests",
			"too many failed authentication attempts",
		);
	}

	let valid_client_id = client_id == jwt_service.config().token_client_id;
	let valid_secret =
		configured_secret.with_exposed(|expected| secrets_match(&client_secret, expected));
	if !valid_client_id || !valid_secret {
		record_failed_attempt(&FAILED_AUTH_BY_CLIENT, &client_id, now);
		record_failed_attempt(&FAILED_AUTH_BY_IP, &source_ip, now);
		return oauth_error_response(
			StatusCode::UNAUTHORIZED,
			"invalid_client",
			"invalid client credentials",
		);
	}

	let expires_in = TOKEN_DEFAULT_TTL_SECONDS.min(TOKEN_MAX_TTL_SECONDS);
	let access_token = match jwt_service.generate_access_token_with_ttl_seconds(
		&client_id,
		vec![AuthScope::AdminAll],
		expires_in,
	) {
		Ok(token) => token,
		Err(e) => {
			tracing::error!("Failed to generate access token via /auth/token: {}", e);
			return (
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(json!({
					"error": "Failed to generate access token"
				})),
			)
				.into_response();
		},
	};

	let response = TokenResponse {
		access_token,
		token_type: "Bearer".to_string(),
		expires_in,
		scope: "admin-all".to_string(),
	};
	(StatusCode::OK, Json(response)).into_response()
}

/// Handles POST /api/v1/auth/siwe/nonce requests.
///
/// Generates a single-use SIWE nonce and returns a pre-built message to sign.
pub async fn issue_siwe_nonce(
	State(state): State<SiweAuthState>,
	Json(request): Json<SiweNonceRequest>,
) -> impl IntoResponse {
	let (_jwt_service, nonce_store, runtime) = match siwe_dependencies(&state).await {
		Ok(value) => value,
		Err(response) => return response,
	};

	let address = match parse_eth_address(&request.address) {
		Ok(address) => address,
		Err(message) => {
			return (
				StatusCode::BAD_REQUEST,
				Json(json!({
					"error": message
				})),
			)
				.into_response();
		},
	};

	let nonce_id = match nonce_store.generate().await {
		Ok(nonce) => nonce,
		Err(e) => {
			tracing::error!("Failed to generate SIWE nonce: {}", e);
			return (
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(json!({
					"error": "Failed to generate SIWE nonce"
				})),
			)
				.into_response();
		},
	};

	let nonce = format_siwe_nonce(nonce_id);
	let message = build_siwe_message(
		&runtime.domain,
		address,
		runtime.chain_id,
		&nonce,
		runtime.nonce_ttl_seconds,
	);

	let response = SiweNonceResponse {
		nonce,
		message,
		expires_in: runtime.nonce_ttl_seconds,
		domain: runtime.domain,
		chain_id: runtime.chain_id,
	};

	(StatusCode::OK, Json(response)).into_response()
}

/// Handles POST /api/v1/auth/siwe/verify requests.
///
/// Verifies a signed SIWE message and returns an admin JWT access token.
pub async fn verify_siwe_token(
	State(state): State<SiweAuthState>,
	Json(request): Json<SiweVerifyRequest>,
) -> impl IntoResponse {
	let (jwt_service, nonce_store, runtime) = match siwe_dependencies(&state).await {
		Ok(value) => value,
		Err(response) => return response,
	};

	let siwe = match verify_siwe_signature(
		&request.message,
		&request.signature,
		&runtime.domain,
		runtime.chain_id,
	) {
		Ok(siwe) => siwe,
		Err(e) => {
			return (
				StatusCode::UNAUTHORIZED,
				Json(json!({
					"error": e.to_string()
				})),
			)
				.into_response();
		},
	};

	let nonce_id = match parse_siwe_nonce(&siwe.nonce) {
		Ok(nonce) => nonce,
		Err(message) => {
			return (
				StatusCode::BAD_REQUEST,
				Json(json!({
					"error": message
				})),
			)
				.into_response();
		},
	};

	match nonce_store.consume(nonce_id).await {
		Ok(()) => {},
		Err(solver_storage::nonce_store::NonceError::NotFound) => {
			return (
				StatusCode::UNAUTHORIZED,
				Json(json!({
					"error": "Invalid or expired SIWE nonce"
				})),
			)
				.into_response();
		},
		Err(e) => {
			tracing::error!("Failed to consume SIWE nonce: {}", e);
			return (
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(json!({
					"error": "Failed to validate SIWE nonce"
				})),
			)
				.into_response();
		},
	}

	if !runtime.admin_addresses.contains(&siwe.address) {
		return (
			StatusCode::FORBIDDEN,
			Json(json!({
				"error": "SIWE signer is not an authorized admin"
			})),
		)
			.into_response();
	}

	let expires_in = TOKEN_DEFAULT_TTL_SECONDS.min(TOKEN_MAX_TTL_SECONDS);
	let subject = siwe.address.to_string();
	let access_token = match jwt_service.generate_access_token_with_ttl_seconds(
		&subject,
		vec![AuthScope::AdminAll],
		expires_in,
	) {
		Ok(token) => token,
		Err(e) => {
			tracing::error!("Failed to generate SIWE access token: {}", e);
			return (
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(json!({
					"error": "Failed to generate access token"
				})),
			)
				.into_response();
		},
	};

	let response = TokenResponse {
		access_token,
		token_type: "Bearer".to_string(),
		expires_in,
		scope: "admin-all".to_string(),
	};

	(StatusCode::OK, Json(response)).into_response()
}

struct SiweRuntimeConfig {
	domain: String,
	chain_id: u64,
	nonce_ttl_seconds: u64,
	admin_addresses: Vec<alloy_primitives::Address>,
}

async fn siwe_dependencies(
	state: &SiweAuthState,
) -> Result<(Arc<JwtService>, Arc<NonceStore>, SiweRuntimeConfig), axum::response::Response> {
	let jwt_service = match &state.jwt_service {
		Some(service) => service.clone(),
		None => {
			return Err((
				StatusCode::SERVICE_UNAVAILABLE,
				Json(json!({
					"error": "Authentication service is not configured"
				})),
			)
				.into_response());
		},
	};

	if !jwt_service.config().enabled {
		return Err((
			StatusCode::SERVICE_UNAVAILABLE,
			Json(json!({
				"error": "Authentication is disabled"
			})),
		)
			.into_response());
	}

	let nonce_store = match &state.siwe_nonce_store {
		Some(store) => store.clone(),
		None => {
			return Err((
				StatusCode::SERVICE_UNAVAILABLE,
				Json(json!({
					"error": "SIWE authentication is not configured"
				})),
			)
				.into_response());
		},
	};

	let runtime = match resolve_siwe_runtime_config(&state.config).await {
		Ok(runtime) => runtime,
		Err(response) => return Err(response),
	};

	Ok((jwt_service, nonce_store, runtime))
}

async fn resolve_siwe_runtime_config(
	config: &Arc<RwLock<Config>>,
) -> Result<SiweRuntimeConfig, axum::response::Response> {
	let config = config.read().await;
	let api_config = match config.api.as_ref() {
		Some(api) => api,
		None => {
			return Err((
				StatusCode::SERVICE_UNAVAILABLE,
				Json(json!({
					"error": "API authentication is not configured"
				})),
			)
				.into_response());
		},
	};
	let auth = match api_config.auth.as_ref() {
		Some(auth) => auth,
		None => {
			return Err((
				StatusCode::SERVICE_UNAVAILABLE,
				Json(json!({
					"error": "API authentication is not configured"
				})),
			)
				.into_response());
		},
	};
	let admin = match auth.admin.as_ref() {
		Some(admin) if admin.enabled => admin,
		_ => {
			return Err((
				StatusCode::SERVICE_UNAVAILABLE,
				Json(json!({
					"error": "SIWE admin authentication is disabled"
				})),
			)
				.into_response());
		},
	};

	let domain = admin.domain.trim().to_string();
	if domain.is_empty() {
		return Err((
			StatusCode::SERVICE_UNAVAILABLE,
			Json(json!({
				"error": "SIWE domain is not configured"
			})),
		)
			.into_response());
	}

	let chain_id = admin
		.chain_id
		.unwrap_or_else(|| config.networks.keys().next().copied().unwrap_or(1));

	Ok(SiweRuntimeConfig {
		domain,
		chain_id,
		nonce_ttl_seconds: admin.nonce_ttl_seconds,
		admin_addresses: admin.admin_addresses.clone(),
	})
}

fn parse_eth_address(raw: &str) -> Result<alloy_primitives::Address, String> {
	let trimmed = raw.trim();
	if trimmed.is_empty() {
		return Err("Address cannot be empty".to_string());
	}

	let normalized = if let Some(stripped) = trimmed
		.strip_prefix("0x")
		.or_else(|| trimmed.strip_prefix("0X"))
	{
		format!("0x{stripped}")
	} else {
		format!("0x{trimmed}")
	};

	normalized
		.parse::<alloy_primitives::Address>()
		.map_err(|e| format!("Invalid Ethereum address: {e}"))
}

fn format_siwe_nonce(nonce: u64) -> String {
	format!("{nonce:020}")
}

fn parse_siwe_nonce(nonce: &str) -> Result<u64, String> {
	if nonce.len() < 8 {
		return Err("SIWE nonce must be at least 8 characters".to_string());
	}
	if !nonce.chars().all(|c| c.is_ascii_digit()) {
		return Err("SIWE nonce format is invalid".to_string());
	}

	nonce
		.parse::<u64>()
		.map_err(|_| "SIWE nonce format is invalid".to_string())
}

fn build_siwe_message(
	domain: &str,
	address: alloy_primitives::Address,
	chain_id: u64,
	nonce: &str,
	nonce_ttl_seconds: u64,
) -> String {
	let issued_at = chrono::Utc::now();
	let expiration_time = issued_at + chrono::Duration::seconds(nonce_ttl_seconds as i64);
	let uri = if domain.starts_with("http://") || domain.starts_with("https://") {
		domain.to_string()
	} else {
		format!("https://{domain}")
	};

	format!(
		"{domain} wants you to sign in with your Ethereum account:\n\
{address}\n\n\
Sign in to OIF Solver Admin API\n\n\
URI: {uri}\n\
Version: 1\n\
Chain ID: {chain_id}\n\
Nonce: {nonce}\n\
Issued At: {}\n\
Expiration Time: {}\n",
		issued_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
		expiration_time.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
	)
}

fn oauth_error_response(
	status: StatusCode,
	error: &str,
	error_description: &str,
) -> axum::response::Response {
	(
		status,
		Json(json!({
			"error": error,
			"error_description": error_description
		})),
	)
		.into_response()
}

fn extract_client_credentials(
	headers: &HeaderMap,
	request: &TokenRequest,
) -> Option<(String, String)> {
	if let Some(credentials) = extract_basic_credentials(headers) {
		return Some(credentials);
	}

	let client_id = request.client_id.as_deref()?.trim();
	let client_secret = request.client_secret.as_deref()?.trim();
	if client_id.is_empty() || client_secret.is_empty() {
		return None;
	}

	Some((client_id.to_string(), client_secret.to_string()))
}

fn extract_basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
	let header = headers.get("authorization")?.to_str().ok()?;
	let (scheme, encoded) = header.split_once(' ')?;
	if !scheme.eq_ignore_ascii_case("basic") {
		return None;
	}
	let encoded = encoded.trim();
	if encoded.is_empty() {
		return None;
	}
	let decoded = base64::engine::general_purpose::STANDARD
		.decode(encoded)
		.ok()?;
	let decoded = String::from_utf8(decoded).ok()?;
	let (client_id, client_secret) = decoded.split_once(':')?;
	if client_id.trim().is_empty() || client_secret.trim().is_empty() {
		return None;
	}
	Some((client_id.to_string(), client_secret.to_string()))
}

fn extract_source_ip(headers: &HeaderMap, peer_addr: Option<SocketAddr>) -> String {
	if let Some(ip) = headers
		.get("x-forwarded-for")
		.and_then(|v| v.to_str().ok())
		.and_then(|v| v.split(',').next())
		.map(str::trim)
		.filter(|v| !v.is_empty())
	{
		return ip.to_string();
	}

	if let Some(ip) = headers
		.get("x-real-ip")
		.and_then(|v| v.to_str().ok())
		.map(str::trim)
		.filter(|v| !v.is_empty())
	{
		return ip.to_string();
	}

	if let Some(addr) = peer_addr {
		return addr.ip().to_string();
	}

	"unknown".to_string()
}

fn is_rate_limited(
	store: &DashMap<String, VecDeque<i64>>,
	key: &str,
	limit: usize,
	now: i64,
) -> bool {
	let Some(mut attempts) = store.get_mut(key) else {
		return false;
	};

	prune_old_attempts(&mut attempts, now);
	let limited = attempts.len() >= limit;
	let empty = attempts.is_empty();
	drop(attempts);
	if empty {
		store.remove(key);
	}

	limited
}

fn record_failed_attempt(store: &DashMap<String, VecDeque<i64>>, key: &str, now: i64) {
	if !store.contains_key(key) && store.len() >= MAX_RATE_LIMIT_KEYS {
		cleanup_stale_rate_limit_keys(store, now);
	}
	if !store.contains_key(key) && store.len() >= MAX_RATE_LIMIT_KEYS {
		tracing::warn!("Rate limit key capacity reached; skipping failure tracking");
		return;
	}

	let mut attempts = store.entry(key.to_string()).or_default();
	prune_old_attempts(&mut attempts, now);
	attempts.push_back(now);
	while attempts.len() > MAX_FAILURE_EVENTS_PER_KEY {
		attempts.pop_front();
	}
}

fn prune_old_attempts(attempts: &mut VecDeque<i64>, now: i64) {
	while let Some(oldest) = attempts.front().copied() {
		if now - oldest >= RATE_LIMIT_WINDOW_SECONDS {
			attempts.pop_front();
		} else {
			break;
		}
	}
}

fn secrets_match(provided: &str, expected: &str) -> bool {
	let provided_hash = Sha3_256::digest(provided.as_bytes());
	let expected_hash = Sha3_256::digest(expected.as_bytes());
	provided_hash
		.as_slice()
		.ct_eq(expected_hash.as_slice())
		.into()
}

fn cleanup_stale_rate_limit_keys(store: &DashMap<String, VecDeque<i64>>, now: i64) {
	let keys_to_remove: Vec<String> = store
		.iter()
		.filter_map(|entry| {
			let latest = entry.value().back().copied();
			match latest {
				Some(ts) if now - ts < RATE_LIMIT_WINDOW_SECONDS => None,
				_ => Some(entry.key().clone()),
			}
		})
		.collect();
	for key in keys_to_remove {
		store.remove(&key);
	}
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

/// Parse scopes for public self-registration flow (admin scope not allowed).
fn parse_public_scopes(scopes: Option<Vec<String>>) -> Result<Vec<AuthScope>, String> {
	let scopes = parse_scopes(scopes)?;
	if scopes.contains(&AuthScope::AdminAll) {
		return Err("admin-all scope is not allowed on /auth/register".to_string());
	}
	Ok(scopes)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::auth::JwtService;
	use axum::http::{HeaderMap, HeaderValue, StatusCode};
	use serde_json::Value;
	use serial_test::serial;
	use solver_config::{ApiConfig, ApiImplementations, ConfigBuilder};
	use solver_types::{AdminConfig, AuthConfig, SecretString};
	use std::sync::Arc;
	use tokio::sync::RwLock;

	// Helper function to create a test JWT service
	fn create_test_jwt_service_with(
		auth_enabled: bool,
		public_register_enabled: bool,
		token_client_id: &str,
		token_client_secret: Option<&str>,
	) -> Arc<JwtService> {
		let config = AuthConfig {
			enabled: auth_enabled,
			jwt_secret: SecretString::from("test-secret-key-at-least-32-chars-long"),
			access_token_expiry_hours: 1,
			refresh_token_expiry_hours: 720,
			issuer: "test-issuer".to_string(),
			public_register_enabled,
			token_client_id: token_client_id.to_string(),
			token_client_secret: token_client_secret.map(SecretString::from),
			admin: None,
		};
		Arc::new(JwtService::new(config).unwrap())
	}

	fn create_test_jwt_service() -> Arc<JwtService> {
		create_test_jwt_service_with(
			true,
			true,
			"solver-admin",
			Some("test-client-secret-at-least-32-chars"),
		)
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
	fn test_parse_public_scopes_rejects_admin() {
		let input = Some(vec!["admin-all".to_string()]);
		let result = parse_public_scopes(input);
		assert!(result.is_err());
		assert!(result
			.unwrap_err()
			.contains("admin-all scope is not allowed"));
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
	async fn test_register_client_rejects_admin_scope() {
		let jwt_service = create_test_jwt_service();
		let request = RegisterRequest {
			client_id: "test-client".to_string(),
			client_name: None,
			scopes: Some(vec!["admin-all".to_string()]),
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
			.contains("admin-all scope is not allowed"));
	}

	#[tokio::test]
	async fn test_register_client_blocked_when_public_register_disabled() {
		let jwt_service = create_test_jwt_service_with(
			true,
			false,
			"admin-solver-test",
			Some("test-client-secret-at-least-32-chars"),
		);
		let request = RegisterRequest {
			client_id: "test-client".to_string(),
			client_name: None,
			scopes: None,
		};

		let response =
			register_client(axum::extract::State(Some(jwt_service)), Json(request)).await;

		let response_obj = response.into_response();
		let (parts, body) = response_obj.into_parts();
		assert_eq!(parts.status, StatusCode::FORBIDDEN);
		let json_body = extract_json_from_body(body).await;
		assert_eq!(json_body["error"], "Public client registration is disabled");
	}

	#[tokio::test]
	async fn test_register_client_auth_disabled() {
		let jwt_service = create_test_jwt_service_with(
			false,
			true,
			"admin-solver-test",
			Some("test-client-secret-at-least-32-chars"),
		);
		let request = RegisterRequest {
			client_id: "test-client".to_string(),
			client_name: None,
			scopes: None,
		};

		let response =
			register_client(axum::extract::State(Some(jwt_service)), Json(request)).await;

		let response_obj = response.into_response();
		let (parts, body) = response_obj.into_parts();
		assert_eq!(parts.status, StatusCode::SERVICE_UNAVAILABLE);
		let json_body = extract_json_from_body(body).await;
		assert_eq!(json_body["error"], "Authentication is disabled");
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
	async fn test_refresh_token_auth_disabled() {
		let jwt_service = create_test_jwt_service_with(
			false,
			true,
			"admin-solver-test",
			Some("test-client-secret-at-least-32-chars"),
		);
		let request = RefreshRequest {
			refresh_token: "some-token".to_string(),
		};

		let response = refresh_token(axum::extract::State(Some(jwt_service)), Json(request)).await;

		let response_obj = response.into_response();
		let (parts, body) = response_obj.into_parts();
		assert_eq!(parts.status, StatusCode::SERVICE_UNAVAILABLE);
		let json_body = extract_json_from_body(body).await;
		assert_eq!(json_body["error"], "Authentication is disabled");
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

	#[tokio::test]
	#[serial]
	async fn test_issue_client_token_success_with_basic_auth() {
		FAILED_AUTH_BY_CLIENT.clear();
		FAILED_AUTH_BY_IP.clear();

		let jwt_service = create_test_jwt_service_with(
			true,
			false,
			"solver-admin",
			Some("test-client-secret-at-least-32-chars"),
		);

		let mut headers = HeaderMap::new();
		let basic = base64::engine::general_purpose::STANDARD
			.encode("solver-admin:test-client-secret-at-least-32-chars");
		headers.insert(
			"authorization",
			HeaderValue::from_str(&format!("Basic {basic}")).unwrap(),
		);
		headers.insert("x-real-ip", HeaderValue::from_static("127.0.0.1"));

		let request = TokenRequest {
			grant_type: Some("client_credentials".to_string()),
			..Default::default()
		};

		let response = issue_client_token(
			axum::extract::State(Some(jwt_service.clone())),
			headers,
			Json(request),
		)
		.await;

		let response_obj = response.into_response();
		let (parts, body) = response_obj.into_parts();
		assert_eq!(parts.status, StatusCode::OK);

		let json_body = extract_json_from_body(body).await;
		let token_response: TokenResponse = serde_json::from_value(json_body).unwrap();
		assert_eq!(token_response.token_type, "Bearer");
		assert_eq!(token_response.scope, "admin-all");
		assert_eq!(token_response.expires_in, TOKEN_DEFAULT_TTL_SECONDS);

		let claims = jwt_service
			.validate_token(&token_response.access_token)
			.unwrap();
		assert_eq!(claims.sub, "solver-admin");
		assert_eq!(claims.scope, vec![AuthScope::AdminAll]);
	}

	#[tokio::test]
	#[serial]
	async fn test_issue_client_token_success_with_body_credentials() {
		FAILED_AUTH_BY_CLIENT.clear();
		FAILED_AUTH_BY_IP.clear();

		let jwt_service = create_test_jwt_service_with(
			true,
			false,
			"solver-admin",
			Some("test-client-secret-at-least-32-chars"),
		);
		let headers = HeaderMap::new();
		let request = TokenRequest {
			grant_type: Some("client_credentials".to_string()),
			client_id: Some("solver-admin".to_string()),
			client_secret: Some("test-client-secret-at-least-32-chars".to_string()),
			scope: Some("admin-all".to_string()),
		};

		let response = issue_client_token(
			axum::extract::State(Some(jwt_service)),
			headers,
			Json(request),
		)
		.await;

		let response_obj = response.into_response();
		let (parts, _) = response_obj.into_parts();
		assert_eq!(parts.status, StatusCode::OK);
	}

	#[tokio::test]
	#[serial]
	async fn test_issue_client_token_invalid_secret() {
		FAILED_AUTH_BY_CLIENT.clear();
		FAILED_AUTH_BY_IP.clear();

		let jwt_service = create_test_jwt_service_with(
			true,
			false,
			"solver-admin",
			Some("test-client-secret-at-least-32-chars"),
		);
		let headers = HeaderMap::new();
		let request = TokenRequest {
			grant_type: Some("client_credentials".to_string()),
			client_id: Some("solver-admin".to_string()),
			client_secret: Some("wrong-secret".to_string()),
			scope: Some("admin-all".to_string()),
		};

		let response = issue_client_token(
			axum::extract::State(Some(jwt_service)),
			headers,
			Json(request),
		)
		.await;
		let response_obj = response.into_response();
		let (parts, body) = response_obj.into_parts();
		assert_eq!(parts.status, StatusCode::UNAUTHORIZED);

		let json_body = extract_json_from_body(body).await;
		assert_eq!(json_body["error"], "invalid_client");
	}

	#[tokio::test]
	#[serial]
	async fn test_issue_client_token_invalid_scope() {
		FAILED_AUTH_BY_CLIENT.clear();
		FAILED_AUTH_BY_IP.clear();

		let jwt_service = create_test_jwt_service_with(
			true,
			false,
			"solver-admin",
			Some("test-client-secret-at-least-32-chars"),
		);
		let headers = HeaderMap::new();
		let request = TokenRequest {
			grant_type: Some("client_credentials".to_string()),
			client_id: Some("solver-admin".to_string()),
			client_secret: Some("test-client-secret-at-least-32-chars".to_string()),
			scope: Some("read-orders".to_string()),
		};

		let response = issue_client_token(
			axum::extract::State(Some(jwt_service)),
			headers,
			Json(request),
		)
		.await;
		let response_obj = response.into_response();
		let (parts, body) = response_obj.into_parts();
		assert_eq!(parts.status, StatusCode::BAD_REQUEST);

		let json_body = extract_json_from_body(body).await;
		assert_eq!(json_body["error"], "invalid_scope");
	}

	#[tokio::test]
	#[serial]
	async fn test_issue_client_token_rate_limited_after_many_failures() {
		FAILED_AUTH_BY_CLIENT.clear();
		FAILED_AUTH_BY_IP.clear();

		let jwt_service = create_test_jwt_service_with(
			true,
			false,
			"solver-admin-rate-limit",
			Some("test-client-secret-at-least-32-chars"),
		);
		let headers = HeaderMap::new();
		let bad_request = TokenRequest {
			grant_type: Some("client_credentials".to_string()),
			client_id: Some("solver-admin-rate-limit".to_string()),
			client_secret: Some("wrong-secret".to_string()),
			scope: Some("admin-all".to_string()),
		};

		for _ in 0..TOKEN_RATE_LIMIT_PER_MINUTE {
			let response = issue_client_token(
				axum::extract::State(Some(jwt_service.clone())),
				headers.clone(),
				Json(bad_request.clone()),
			)
			.await;
			let status = response.into_response().status();
			assert_eq!(status, StatusCode::UNAUTHORIZED);
		}

		let response = issue_client_token(
			axum::extract::State(Some(jwt_service)),
			headers,
			Json(bad_request),
		)
		.await;
		let response_obj = response.into_response();
		assert_eq!(response_obj.status(), StatusCode::TOO_MANY_REQUESTS);
	}

	#[tokio::test]
	#[serial]
	async fn test_issue_client_token_auth_disabled() {
		FAILED_AUTH_BY_CLIENT.clear();
		FAILED_AUTH_BY_IP.clear();

		let jwt_service = create_test_jwt_service_with(
			false,
			false,
			"solver-admin",
			Some("test-client-secret-at-least-32-chars"),
		);
		let headers = HeaderMap::new();
		let request = TokenRequest {
			grant_type: Some("client_credentials".to_string()),
			client_id: Some("solver-admin".to_string()),
			client_secret: Some("test-client-secret-at-least-32-chars".to_string()),
			scope: Some("admin-all".to_string()),
		};

		let response = issue_client_token(
			axum::extract::State(Some(jwt_service)),
			headers,
			Json(request),
		)
		.await;
		let response_obj = response.into_response();
		let (parts, body) = response_obj.into_parts();
		assert_eq!(parts.status, StatusCode::SERVICE_UNAVAILABLE);

		let json_body = extract_json_from_body(body).await;
		assert_eq!(json_body["error"], "Authentication is disabled");
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

	#[test]
	fn test_token_response_serialization() {
		let response = TokenResponse {
			access_token: "access-token".to_string(),
			token_type: "Bearer".to_string(),
			expires_in: 900,
			scope: "admin-all".to_string(),
		};

		let json = serde_json::to_string(&response).unwrap();
		let deserialized: TokenResponse = serde_json::from_str(&json).unwrap();

		assert_eq!(deserialized.token_type, "Bearer");
		assert_eq!(deserialized.scope, "admin-all");
		assert_eq!(deserialized.expires_in, 900);
	}

	#[test]
	fn test_format_and_parse_siwe_nonce_roundtrip() {
		let nonce = super::format_siwe_nonce(12345);
		assert_eq!(nonce, "00000000000000012345");
		assert_eq!(super::parse_siwe_nonce(&nonce).unwrap(), 12345);
	}

	#[test]
	fn test_parse_siwe_nonce_rejects_short_or_non_numeric() {
		assert!(super::parse_siwe_nonce("1234567").is_err());
		assert!(super::parse_siwe_nonce("abc12345").is_err());
	}

	#[test]
	fn test_build_siwe_message_contains_expected_fields() {
		let address = "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B"
			.parse::<alloy_primitives::Address>()
			.unwrap();
		let message = super::build_siwe_message(
			"solver.example.com",
			address,
			1,
			"00000000000000012345",
			300,
		);

		assert!(message.contains("solver.example.com wants you to sign in"));
		assert!(message.contains("Chain ID: 1"));
		assert!(message.contains("Nonce: 00000000000000012345"));
		assert!(message.contains("URI: https://solver.example.com"));
	}

	#[tokio::test]
	async fn test_resolve_siwe_runtime_config_uses_admin_address_list() {
		let admin_1 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
			.parse::<alloy_primitives::Address>()
			.unwrap();
		let admin_2 = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
			.parse::<alloy_primitives::Address>()
			.unwrap();

		let auth_config = AuthConfig {
			enabled: true,
			jwt_secret: SecretString::from("test-secret-key-at-least-32-chars-long"),
			access_token_expiry_hours: 1,
			refresh_token_expiry_hours: 720,
			issuer: "test-issuer".to_string(),
			public_register_enabled: false,
			token_client_id: "solver-admin".to_string(),
			token_client_secret: Some(SecretString::from("client-secret-at-least-32-chars")),
			admin: Some(AdminConfig {
				enabled: true,
				domain: "localhost".to_string(),
				// Mirrors seed-overrides shape where chain_id can be omitted.
				chain_id: None,
				nonce_ttl_seconds: 300,
				admin_addresses: vec![admin_1, admin_2],
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

		let shared = Arc::new(RwLock::new(config));
		let runtime = super::resolve_siwe_runtime_config(&shared).await.unwrap();

		assert_eq!(runtime.domain, "localhost");
		assert_eq!(runtime.nonce_ttl_seconds, 300);
		assert_eq!(runtime.chain_id, 1); // fallback when chain_id is omitted
		assert_eq!(runtime.admin_addresses, vec![admin_1, admin_2]);
	}

	// Tests for helper functions
	#[test]
	fn test_extract_source_ip_from_x_forwarded_for() {
		let mut headers = HeaderMap::new();
		headers.insert(
			"x-forwarded-for",
			HeaderValue::from_static("192.168.1.1, 10.0.0.1"),
		);
		assert_eq!(super::extract_source_ip(&headers, None), "192.168.1.1");
	}

	#[test]
	fn test_extract_source_ip_from_x_real_ip() {
		let mut headers = HeaderMap::new();
		headers.insert("x-real-ip", HeaderValue::from_static("10.0.0.5"));
		assert_eq!(super::extract_source_ip(&headers, None), "10.0.0.5");
	}

	#[test]
	fn test_extract_source_ip_unknown_when_missing() {
		let headers = HeaderMap::new();
		assert_eq!(super::extract_source_ip(&headers, None), "unknown");
	}

	#[test]
	fn test_extract_source_ip_falls_back_to_peer_addr() {
		let headers = HeaderMap::new();
		let peer_addr: std::net::SocketAddr = "203.0.113.11:3030".parse().unwrap();
		assert_eq!(
			super::extract_source_ip(&headers, Some(peer_addr)),
			"203.0.113.11"
		);
	}

	#[test]
	fn test_extract_basic_credentials_valid() {
		let mut headers = HeaderMap::new();
		let encoded = base64::engine::general_purpose::STANDARD.encode("user:pass");
		headers.insert(
			"authorization",
			HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
		);
		let result = super::extract_basic_credentials(&headers);
		assert_eq!(result, Some(("user".to_string(), "pass".to_string())));
	}

	#[test]
	fn test_extract_basic_credentials_case_insensitive_scheme() {
		let mut headers = HeaderMap::new();
		let encoded = base64::engine::general_purpose::STANDARD.encode("user:pass");
		headers.insert(
			"authorization",
			HeaderValue::from_str(&format!("basic {encoded}")).unwrap(),
		);
		let result = super::extract_basic_credentials(&headers);
		assert_eq!(result, Some(("user".to_string(), "pass".to_string())));
	}

	#[test]
	fn test_extract_basic_credentials_missing_header() {
		let headers = HeaderMap::new();
		assert_eq!(super::extract_basic_credentials(&headers), None);
	}

	#[test]
	fn test_extract_basic_credentials_invalid_base64() {
		let mut headers = HeaderMap::new();
		headers.insert(
			"authorization",
			HeaderValue::from_static("Basic !!!invalid!!!"),
		);
		assert_eq!(super::extract_basic_credentials(&headers), None);
	}

	#[test]
	fn test_extract_basic_credentials_no_colon() {
		let mut headers = HeaderMap::new();
		let encoded = base64::engine::general_purpose::STANDARD.encode("nocolon");
		headers.insert(
			"authorization",
			HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
		);
		assert_eq!(super::extract_basic_credentials(&headers), None);
	}

	#[test]
	fn test_extract_basic_credentials_empty_user() {
		let mut headers = HeaderMap::new();
		let encoded = base64::engine::general_purpose::STANDARD.encode(":password");
		headers.insert(
			"authorization",
			HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
		);
		assert_eq!(super::extract_basic_credentials(&headers), None);
	}

	#[test]
	fn test_secrets_match_equal() {
		assert!(super::secrets_match("secret123", "secret123"));
	}

	#[test]
	fn test_secrets_match_different_length() {
		assert!(!super::secrets_match("short", "longer_secret"));
	}

	#[test]
	fn test_secrets_match_different_content() {
		assert!(!super::secrets_match("secret123", "secret456"));
	}

	#[test]
	fn test_prune_old_attempts_removes_expired() {
		let mut attempts = VecDeque::from([100, 200, 300]);
		super::prune_old_attempts(&mut attempts, 400);
		// All entries older than 400 - 60 = 340 should be removed
		assert_eq!(attempts.len(), 0);
	}

	#[test]
	fn test_prune_old_attempts_keeps_recent() {
		let mut attempts = VecDeque::from([350, 360, 370]);
		super::prune_old_attempts(&mut attempts, 400);
		// All entries are within 60 seconds of now
		assert_eq!(attempts.len(), 3);
	}

	#[tokio::test]
	#[serial]
	async fn test_issue_client_token_missing_credentials() {
		FAILED_AUTH_BY_CLIENT.clear();
		FAILED_AUTH_BY_IP.clear();

		let jwt_service = create_test_jwt_service_with(
			true,
			false,
			"solver-admin",
			Some("test-client-secret-at-least-32-chars"),
		);
		let headers = HeaderMap::new();
		let request = TokenRequest {
			grant_type: Some("client_credentials".to_string()),
			client_id: None,
			client_secret: None,
			scope: Some("admin-all".to_string()),
		};

		let response = issue_client_token(
			axum::extract::State(Some(jwt_service)),
			headers,
			Json(request),
		)
		.await;
		let response_obj = response.into_response();
		let (parts, body) = response_obj.into_parts();
		assert_eq!(parts.status, StatusCode::UNAUTHORIZED);

		let json_body = extract_json_from_body(body).await;
		assert_eq!(json_body["error"], "invalid_client");
	}

	#[tokio::test]
	#[serial]
	async fn test_issue_client_token_unsupported_grant_type() {
		FAILED_AUTH_BY_CLIENT.clear();
		FAILED_AUTH_BY_IP.clear();

		let jwt_service = create_test_jwt_service_with(
			true,
			false,
			"solver-admin",
			Some("test-client-secret-at-least-32-chars"),
		);
		let headers = HeaderMap::new();
		let request = TokenRequest {
			grant_type: Some("password".to_string()),
			client_id: Some("solver-admin".to_string()),
			client_secret: Some("test-client-secret-at-least-32-chars".to_string()),
			scope: Some("admin-all".to_string()),
		};

		let response = issue_client_token(
			axum::extract::State(Some(jwt_service)),
			headers,
			Json(request),
		)
		.await;
		let response_obj = response.into_response();
		let (parts, body) = response_obj.into_parts();
		assert_eq!(parts.status, StatusCode::BAD_REQUEST);

		let json_body = extract_json_from_body(body).await;
		assert_eq!(json_body["error"], "unsupported_grant_type");
	}

	#[tokio::test]
	#[serial]
	async fn test_issue_client_token_missing_grant_type() {
		FAILED_AUTH_BY_CLIENT.clear();
		FAILED_AUTH_BY_IP.clear();

		let jwt_service = create_test_jwt_service_with(
			true,
			false,
			"solver-admin",
			Some("test-client-secret-at-least-32-chars"),
		);
		let headers = HeaderMap::new();
		let request = TokenRequest {
			grant_type: None,
			client_id: Some("solver-admin".to_string()),
			client_secret: Some("test-client-secret-at-least-32-chars".to_string()),
			scope: Some("admin-all".to_string()),
		};

		let response = issue_client_token(
			axum::extract::State(Some(jwt_service)),
			headers,
			Json(request),
		)
		.await;
		let response_obj = response.into_response();
		let (parts, body) = response_obj.into_parts();
		assert_eq!(parts.status, StatusCode::BAD_REQUEST);

		let json_body = extract_json_from_body(body).await;
		assert_eq!(json_body["error"], "unsupported_grant_type");
	}

	#[tokio::test]
	#[serial]
	async fn test_issue_client_token_no_secret_configured() {
		FAILED_AUTH_BY_CLIENT.clear();
		FAILED_AUTH_BY_IP.clear();

		let jwt_service = create_test_jwt_service_with(true, false, "solver-admin", None);
		let headers = HeaderMap::new();
		let request = TokenRequest {
			grant_type: Some("client_credentials".to_string()),
			client_id: Some("solver-admin".to_string()),
			client_secret: Some("some-secret".to_string()),
			scope: Some("admin-all".to_string()),
		};

		let response = issue_client_token(
			axum::extract::State(Some(jwt_service)),
			headers,
			Json(request),
		)
		.await;
		let response_obj = response.into_response();
		let (parts, body) = response_obj.into_parts();
		assert_eq!(parts.status, StatusCode::SERVICE_UNAVAILABLE);

		let json_body = extract_json_from_body(body).await;
		assert_eq!(
			json_body["error"],
			"Client credentials authentication is not configured"
		);
	}

	#[tokio::test]
	#[serial]
	async fn test_issue_client_token_no_jwt_service() {
		let headers = HeaderMap::new();
		let request = TokenRequest::default();

		let response = issue_client_token(axum::extract::State(None), headers, Json(request)).await;
		let response_obj = response.into_response();
		let (parts, body) = response_obj.into_parts();
		assert_eq!(parts.status, StatusCode::SERVICE_UNAVAILABLE);

		let json_body = extract_json_from_body(body).await;
		assert_eq!(
			json_body["error"],
			"Authentication service is not configured"
		);
	}
}
