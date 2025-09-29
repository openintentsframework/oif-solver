//! JWT authentication service.
//!
//! This module provides functionality for managing JWT tokens,
//! including client registration, token refresh, and validation.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, info};

use crate::core::SessionManager;
use crate::models::JwtTokenEntry;
use solver_types::auth::{AuthScope, JwtClaims};

/// Response from JWT token endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtTokenResponse {
	/// Access token for API authentication.
	pub access_token: String,
	/// Refresh token for obtaining new access tokens.
	pub refresh_token: String,
	/// Client identifier.
	pub client_id: String,
	/// Unix timestamp when access token expires.
	pub access_token_expires_at: i64,
	/// Unix timestamp when refresh token expires.
	pub refresh_token_expires_at: i64,
	/// Authorized scopes for the token.
	pub scopes: Vec<String>,
	/// Token type (usually "Bearer").
	pub token_type: String,
}

/// Service for managing JWT authentication.
#[derive(Clone)]
pub struct JwtService {
	/// HTTP client for API requests.
	client: Client,
	/// Base URL for the authentication server.
	base_url: String,
	/// Session manager for token storage.
	session_manager: Arc<SessionManager>,
	/// Unique client identifier.
	client_id: String,
}

impl JwtService {
	/// Creates a new JWT service instance.
	pub fn new(base_url: String, session_manager: Arc<SessionManager>) -> Self {
		let client = Client::builder()
			.timeout(std::time::Duration::from_secs(30))
			.build()
			.expect("Failed to build HTTP client");

		let client_id = Self::generate_client_id();

		Self {
			client,
			base_url,
			session_manager,
			client_id,
		}
	}

	/// Gets a valid access token, handling registration and refresh automatically.
	pub async fn get_valid_token(&self) -> Result<String> {
		// Check if we have a valid stored token
		if let Some(stored_token) = self.session_manager.get_jwt_token("api_client").await {
			if !stored_token.is_expired() {
				// Double-check token validity by parsing expiration
				if self.is_token_valid(&stored_token.token).await? {
					debug!("Using valid stored JWT token");
					return Ok(stored_token.token);
				}
			} else {
				debug!("Stored JWT token is expired");
			}
		}

		// Try to refresh token first
		if let Ok(refreshed_token) = self.refresh_token().await {
			return Ok(refreshed_token);
		}

		// Fall back to full registration
		debug!("Registering new client and obtaining JWT token");
		self.register_and_get_token().await
	}

	/// Registers client and gets new token pair.
	async fn register_and_get_token(&self) -> Result<String> {
		let token_response = self.register_client().await?;

		// Store access token
		let expires_at = DateTime::from_timestamp(token_response.access_token_expires_at, 0)
			.unwrap_or_else(|| Utc::now() + ChronoDuration::hours(1));

		let token_entry = JwtTokenEntry::new(token_response.access_token.clone(), expires_at);
		self.session_manager
			.set_jwt_token("api_client".to_string(), token_entry)
			.await?;

		// Store refresh token
		if !token_response.refresh_token.is_empty() {
			let refresh_expires_at =
				DateTime::from_timestamp(token_response.refresh_token_expires_at, 0)
					.unwrap_or_else(|| Utc::now() + ChronoDuration::days(7));
			let refresh_entry =
				JwtTokenEntry::new(token_response.refresh_token, refresh_expires_at);
			self.session_manager
				.set_jwt_token("api_client_refresh".to_string(), refresh_entry)
				.await?;
		}

		info!("Stored JWT tokens for client {}", token_response.client_id);
		Ok(token_response.access_token)
	}

	/// Registers client with the API.
	async fn register_client(&self) -> Result<JwtTokenResponse> {
		let url = format!("{}/api/auth/register", self.base_url);

		let scopes = vec![
			AuthScope::ReadOrders.to_string(),
			AuthScope::CreateOrders.to_string(),
			AuthScope::CreateQuotes.to_string(),
			AuthScope::ReadQuotes.to_string(),
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
			.map_err(|e| anyhow!("Failed to register client: {}", e))?;

		if !response.status().is_success() {
			let status = response.status();
			let text = response.text().await.unwrap_or_default();
			return Err(anyhow!(
				"Client registration failed with status {}: {}",
				status,
				text
			));
		}

		response
			.json()
			.await
			.map_err(|e| anyhow!("Failed to parse registration response: {}", e))
	}

	/// Refreshes access token using stored refresh token.
	async fn refresh_token(&self) -> Result<String> {
		if let Some(stored_refresh_token) = self
			.session_manager
			.get_jwt_token("api_client_refresh")
			.await
		{
			if !stored_refresh_token.is_expired() {
				debug!("Attempting to refresh access token");

				let token_response = self
					.refresh_access_token(&stored_refresh_token.token)
					.await?;

				// Store new access token
				let expires_at =
					DateTime::from_timestamp(token_response.access_token_expires_at, 0)
						.unwrap_or_else(|| Utc::now() + ChronoDuration::hours(1));

				let token_entry =
					JwtTokenEntry::new(token_response.access_token.clone(), expires_at);
				self.session_manager
					.set_jwt_token("api_client".to_string(), token_entry)
					.await?;

				// Store new refresh token if provided
				if !token_response.refresh_token.is_empty() {
					let refresh_expires_at =
						DateTime::from_timestamp(token_response.refresh_token_expires_at, 0)
							.unwrap_or_else(|| Utc::now() + ChronoDuration::days(7));
					let refresh_entry =
						JwtTokenEntry::new(token_response.refresh_token, refresh_expires_at);
					self.session_manager
						.set_jwt_token("api_client_refresh".to_string(), refresh_entry)
						.await?;
				}

				info!("Successfully refreshed access token");
				return Ok(token_response.access_token);
			}
		}

		Err(anyhow!("No valid refresh token available"))
	}

	/// Refreshes access token using provided refresh token.
	async fn refresh_access_token(&self, refresh_token: &str) -> Result<JwtTokenResponse> {
		let url = format!("{}/api/auth/refresh", self.base_url);

		let request = json!({
			"refresh_token": refresh_token
		});

		let response = self
			.client
			.post(&url)
			.json(&request)
			.send()
			.await
			.map_err(|e| anyhow!("Failed to refresh token: {}", e))?;

		if !response.status().is_success() {
			let status = response.status();
			let text = response.text().await.unwrap_or_default();
			return Err(anyhow!(
				"Token refresh failed with status {}: {}",
				status,
				text
			));
		}

		response
			.json()
			.await
			.map_err(|e| anyhow!("Failed to parse refresh response: {}", e))
	}

	/// Checks if a token is still valid by parsing its expiration.
	async fn is_token_valid(&self, token: &str) -> Result<bool> {
		match self.parse_token_unsafe(token) {
			Ok(claims) => {
				let exp = DateTime::from_timestamp(claims.exp, 0).unwrap_or_else(Utc::now);
				Ok(exp > Utc::now() + ChronoDuration::minutes(5)) // 5 minute buffer
			},
			Err(_) => Ok(false),
		}
	}

	/// Parses a JWT token without validation (for checking expiration).
	fn parse_token_unsafe(&self, token: &str) -> Result<JwtClaims> {
		let parts: Vec<&str> = token.split('.').collect();
		if parts.len() != 3 {
			return Err(anyhow!("Invalid JWT format"));
		}

		// Decode the payload (middle part)
		use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
		let payload = URL_SAFE_NO_PAD
			.decode(parts[1])
			.map_err(|e| anyhow!("Failed to decode token payload: {}", e))?;

		serde_json::from_slice(&payload).map_err(|e| anyhow!("Failed to parse token claims: {}", e))
	}

	/// Generates a unique client ID.
	fn generate_client_id() -> String {
		let hostname = hostname::get()
			.map(|h| h.to_string_lossy().to_string())
			.unwrap_or_else(|_| "unknown".to_string());
		let timestamp = Utc::now().timestamp();
		let uuid = uuid::Uuid::new_v4();
		format!("oif-demo-{}-{}-{}", hostname, timestamp, uuid.simple())
	}
}
