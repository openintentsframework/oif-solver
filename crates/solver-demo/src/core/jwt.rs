//! JWT authentication and token management
//!
//! This module provides JWT token lifecycle management including client registration,
//! token refresh, validation, and automatic token renewal. Handles secure storage
//! and retrieval of access and refresh tokens with proper expiration checking.

use crate::core::logging;
use crate::types::error::{Error, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Authentication response from JWT token endpoints
///
/// Contains access and refresh tokens along with their expiration times,
/// client identification, and granted scopes for API access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtTokenResponse {
	pub access_token: String,
	pub refresh_token: String,
	pub client_id: String,
	pub access_token_expires_at: i64,
	pub refresh_token_expires_at: i64,
	pub scopes: Vec<String>,
	pub token_type: String,
}

/// Standard JWT claims structure for token validation
///
/// Contains essential JWT claims including expiration time, issued at time,
/// issuer information, client identification, and authorized scopes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
	pub exp: i64,
	pub iat: i64,
	pub iss: String,
	#[serde(rename = "sub")]
	pub client_id: String,
	#[serde(rename = "scope")]
	pub scopes: Vec<String>,
}

/// JWT authentication service with automatic token management
///
/// Provides comprehensive JWT token lifecycle management including client
/// registration, token refresh, validation, and secure storage integration
/// with automatic token renewal and expiration handling
#[derive(Clone)]
pub struct JwtService {
	client: Client,
	base_url: String,
	client_id: String,
}

impl JwtService {
	/// Create new JWT service instance with HTTP client and unique client ID
	///
	/// # Arguments
	/// * `base_url` - Base URL for the authentication API
	///
	/// # Returns
	/// JWT service instance ready for authentication operations
	pub fn new(base_url: String) -> Self {
		let client = Client::builder()
			.timeout(std::time::Duration::from_secs(30))
			.build()
			.expect("Failed to build HTTP client");

		let client_id = Self::generate_client_id();

		Self {
			client,
			base_url,
			client_id,
		}
	}

	/// Retrieve valid access token with automatic refresh and registration
	///
	/// Attempts to use stored valid token first, then refresh if expired,
	/// and finally registers new client if no valid tokens are available
	///
	/// # Arguments
	/// * `session_store` - Session store for token persistence
	///
	/// # Returns
	/// Valid access token ready for API requests
	///
	/// # Errors
	/// Returns Error if all token acquisition methods fail
	#[tracing::instrument(skip(self, session_store))]
	pub async fn get_valid_token(
		&self,
		session_store: &crate::core::session::SessionStore,
	) -> Result<String> {
		// Check if we have a valid stored token
		if let Some(stored_token) = session_store.get_jwt_token("api_client") {
			// Double-check token validity by parsing expiration
			if self.is_token_valid(&stored_token)? {
				use crate::core::logging;
				logging::debug_operation("JWT token", "using valid stored token");
				return Ok(stored_token);
			} else {
				logging::debug_operation("JWT token", "stored token is expired or invalid");
			}
		}

		// Try to refresh token first
		if let Ok(refreshed_token) = self.refresh_token(session_store).await {
			return Ok(refreshed_token);
		}

		// Fall back to full registration
		logging::debug_operation(
			"JWT authentication",
			"registering new client and obtaining token",
		);
		self.register_and_get_token(session_store).await
	}

	/// Register new client and obtain fresh token pair
	///
	/// # Arguments
	/// * `session_store` - Session store for token persistence
	///
	/// # Returns
	/// Fresh access token from new client registration
	///
	/// # Errors
	/// Returns Error if client registration or token storage fails
	async fn register_and_get_token(
		&self,
		session_store: &crate::core::session::SessionStore,
	) -> Result<String> {
		let token_response = self.register_client().await?;

		// Store access token
		session_store.set_jwt_token(
			"api_client".to_string(),
			token_response.access_token.clone(),
			token_response.access_token_expires_at,
		)?;

		// Store refresh token
		if !token_response.refresh_token.is_empty() {
			session_store.set_jwt_token(
				"api_client_refresh".to_string(),
				token_response.refresh_token,
				token_response.refresh_token_expires_at,
			)?;
		}

		use crate::core::logging;
		logging::verbose_success("Stored JWT tokens for client", &token_response.client_id);
		Ok(token_response.access_token)
	}

	/// Register client with authentication API to obtain initial tokens
	///
	/// # Returns
	/// JWT token response containing access and refresh tokens
	///
	/// # Errors
	/// Returns Error if API registration request fails or returns invalid response
	async fn register_client(&self) -> Result<JwtTokenResponse> {
		let url = format!("{}/api/v1/auth/register", self.base_url);

		let scopes = vec![
			solver_types::auth::AuthScope::ReadOrders.to_string(),
			solver_types::auth::AuthScope::CreateOrders.to_string(),
			solver_types::auth::AuthScope::CreateQuotes.to_string(),
			solver_types::auth::AuthScope::ReadQuotes.to_string(),
		];

		let request = json!({
			"client_id": self.client_id,
			"scopes": scopes,
			"expiry_hours": 24,
		});

		let response = self
			.client
			.post(&url)
			.json(&request)
			.send()
			.await
			.map_err(|e| Error::Other(anyhow::anyhow!("Failed to register client: {}", e)))?;

		if !response.status().is_success() {
			let status = response.status();
			let text = response.text().await.unwrap_or_default();
			return Err(Error::Other(anyhow::anyhow!(
				"Client registration failed with status {}: {}",
				status,
				text
			)));
		}

		response.json().await.map_err(|e| {
			Error::Other(anyhow::anyhow!(
				"Failed to parse registration response: {}",
				e
			))
		})
	}

	/// Refresh access token using stored refresh token from session
	///
	/// # Arguments
	/// * `session_store` - Session store containing refresh token
	///
	/// # Returns
	/// New valid access token
	///
	/// # Errors
	/// Returns Error if no refresh token exists or refresh operation fails
	async fn refresh_token(
		&self,
		session_store: &crate::core::session::SessionStore,
	) -> Result<String> {
		if let Some(stored_refresh_token) = session_store.get_jwt_token("api_client_refresh") {
			logging::debug_operation("JWT token", "attempting to refresh access token");

			let token_response = self.refresh_access_token(&stored_refresh_token).await?;

			// Store new access token
			session_store.set_jwt_token(
				"api_client".to_string(),
				token_response.access_token.clone(),
				token_response.access_token_expires_at,
			)?;

			// Store new refresh token if provided
			if !token_response.refresh_token.is_empty() {
				session_store.set_jwt_token(
					"api_client_refresh".to_string(),
					token_response.refresh_token,
					token_response.refresh_token_expires_at,
				)?;
			}

			logging::verbose_success("Successfully refreshed access token", "");
			return Ok(token_response.access_token);
		}

		Err(Error::Other(anyhow::anyhow!(
			"No valid refresh token available"
		)))
	}

	/// Send refresh token request to authentication API
	///
	/// # Arguments
	/// * `refresh_token` - Valid refresh token for token renewal
	///
	/// # Returns
	/// New JWT token response with refreshed tokens
	///
	/// # Errors
	/// Returns Error if refresh API request fails or returns invalid response
	async fn refresh_access_token(&self, refresh_token: &str) -> Result<JwtTokenResponse> {
		let url = format!("{}/api/v1/auth/refresh", self.base_url);

		let request = json!({
			"refresh_token": refresh_token
		});

		let response = self
			.client
			.post(&url)
			.json(&request)
			.send()
			.await
			.map_err(|e| Error::Other(anyhow::anyhow!("Failed to refresh token: {}", e)))?;

		if !response.status().is_success() {
			let status = response.status();
			let text = response.text().await.unwrap_or_default();
			return Err(Error::Other(anyhow::anyhow!(
				"Token refresh failed with status {}: {}",
				status,
				text
			)));
		}

		response
			.json()
			.await
			.map_err(|e| Error::Other(anyhow::anyhow!("Failed to parse refresh response: {}", e)))
	}

	/// Validate token by checking expiration time with safety buffer
	///
	/// # Arguments
	/// * `token` - JWT token to validate
	///
	/// # Returns
	/// True if token is valid and not expiring within 5 minutes
	///
	/// # Errors
	/// Returns Error if token parsing fails
	fn is_token_valid(&self, token: &str) -> Result<bool> {
		match self.parse_token_unsafe(token) {
			Ok(claims) => {
				let exp = DateTime::from_timestamp(claims.exp, 0).unwrap_or_else(Utc::now);
				Ok(exp > Utc::now() + ChronoDuration::minutes(5)) // 5 minute buffer
			},
			Err(_) => Ok(false),
		}
	}

	/// Parse JWT token payload without signature validation for expiration check
	///
	/// # Arguments
	/// * `token` - JWT token string to parse
	///
	/// # Returns
	/// JWT claims extracted from token payload
	///
	/// # Errors
	/// Returns Error if token format is invalid or claims cannot be parsed
	fn parse_token_unsafe(&self, token: &str) -> Result<JwtClaims> {
		let parts: Vec<&str> = token.split('.').collect();
		if parts.len() != 3 {
			return Err(Error::Other(anyhow::anyhow!("Invalid JWT format")));
		}

		// Decode the payload (middle part)
		use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
		let payload = URL_SAFE_NO_PAD
			.decode(parts[1])
			.map_err(|e| Error::Other(anyhow::anyhow!("Failed to decode token payload: {}", e)))?;

		serde_json::from_slice(&payload)
			.map_err(|e| Error::Other(anyhow::anyhow!("Failed to parse token claims: {}", e)))
	}

	/// Generate unique client identifier using hostname, timestamp, and UUID
	///
	/// # Returns
	/// Unique client ID string formatted as oif-demo-v2-{hostname}-{timestamp}-{uuid}
	fn generate_client_id() -> String {
		let hostname = hostname::get()
			.map(|h| h.to_string_lossy().to_string())
			.unwrap_or_else(|_| "unknown".to_string());
		let timestamp = Utc::now().timestamp();
		let uuid = uuid::Uuid::new_v4();
		format!("oif-demo-v2-{}-{}-{}", hostname, timestamp, uuid.simple())
	}

	/// Creates a JWT service for testing with a custom client ID
	#[cfg(test)]
	pub fn new_with_client_id(base_url: String, client_id: String) -> Self {
		let client = Client::builder()
			.timeout(std::time::Duration::from_secs(30))
			.build()
			.expect("Failed to build HTTP client");

		Self {
			client,
			base_url,
			client_id,
		}
	}

	/// Exposes register_client for testing
	#[cfg(test)]
	pub async fn test_register_client(&self) -> Result<JwtTokenResponse> {
		self.register_client().await
	}

	/// Exposes refresh_access_token for testing
	#[cfg(test)]
	pub async fn test_refresh_access_token(&self, refresh_token: &str) -> Result<JwtTokenResponse> {
		self.refresh_access_token(refresh_token).await
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use wiremock::matchers::{method, path};
	use wiremock::{Mock, MockServer, ResponseTemplate};

	#[tokio::test]
	async fn register_client_uses_v1_auth_path() {
		let mock_server = MockServer::start().await;

		let response = JwtTokenResponse {
			access_token: "test-access-token".to_string(),
			refresh_token: "test-refresh-token".to_string(),
			client_id: "test-client".to_string(),
			access_token_expires_at: Utc::now().timestamp() + 3600,
			refresh_token_expires_at: Utc::now().timestamp() + 86400,
			scopes: vec!["read:orders".to_string()],
			token_type: "Bearer".to_string(),
		};

		Mock::given(method("POST"))
			.and(path("/api/v1/auth/register"))
			.respond_with(ResponseTemplate::new(200).set_body_json(&response))
			.expect(1)
			.mount(&mock_server)
			.await;

		let service = JwtService::new_with_client_id(mock_server.uri(), "test-client".to_string());
		let result = service.test_register_client().await;

		assert!(result.is_ok());
		let token_response = result.unwrap();
		assert_eq!(token_response.access_token, "test-access-token");
		assert_eq!(token_response.client_id, "test-client");
	}

	#[tokio::test]
	async fn refresh_access_token_uses_v1_auth_path() {
		let mock_server = MockServer::start().await;

		let response = JwtTokenResponse {
			access_token: "new-access-token".to_string(),
			refresh_token: "new-refresh-token".to_string(),
			client_id: "test-client".to_string(),
			access_token_expires_at: Utc::now().timestamp() + 3600,
			refresh_token_expires_at: Utc::now().timestamp() + 86400,
			scopes: vec!["read:orders".to_string()],
			token_type: "Bearer".to_string(),
		};

		Mock::given(method("POST"))
			.and(path("/api/v1/auth/refresh"))
			.respond_with(ResponseTemplate::new(200).set_body_json(&response))
			.expect(1)
			.mount(&mock_server)
			.await;

		let service = JwtService::new_with_client_id(mock_server.uri(), "test-client".to_string());
		let result = service.test_refresh_access_token("old-refresh-token").await;

		assert!(result.is_ok());
		let token_response = result.unwrap();
		assert_eq!(token_response.access_token, "new-access-token");
	}
}
