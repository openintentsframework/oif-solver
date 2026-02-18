//! Authentication module for the OIF solver API service.
//!
//! This module provides JWT-based authentication and authorization
//! functionality for protecting API endpoints.
//!
//! # Admin Authentication
//!
//! The [`admin`] submodule provides wallet-based authentication for admin
//! operations using Ethereum signatures.

pub mod admin;
pub mod middleware;
pub mod siwe;

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use solver_types::{AuthConfig, AuthScope, JwtClaims};
use thiserror::Error;
use uuid::Uuid;

pub use middleware::{auth_middleware, AuthState};

/// Errors that can occur during authentication operations.
#[derive(Error, Debug)]
pub enum AuthError {
	/// Failed to generate a JWT token
	#[error("Failed to generate token: {0}")]
	TokenGeneration(String),

	/// The provided token is invalid
	#[error("Invalid access token: {0}")]
	InvalidAccessToken(String),

	/// The provided refresh token is invalid or expired
	#[error("Invalid refresh token: {0}")]
	InvalidRefreshToken(String),
}

/// Service for handling JWT token generation and validation.
pub struct JwtService {
	config: AuthConfig,
	encoding_key: EncodingKey,
	decoding_key: DecodingKey,
	validation: Validation,
}

impl JwtService {
	/// Creates a new JWT service with the provided configuration.
	///
	/// # Arguments
	/// * `config` - Authentication configuration containing secret and settings
	///
	/// # Returns
	/// A configured JWT service or an error if initialization fails
	pub fn new(config: AuthConfig) -> Result<Self, AuthError> {
		let mut validation = Validation::new(Algorithm::HS256);
		validation.set_issuer(&[config.issuer.clone()]);

		// Extract jwt_secret first to avoid borrowing issues
		let jwt_secret = config.jwt_secret.clone();
		jwt_secret.with_exposed(|secret| {
			let secret_bytes = secret.as_bytes();
			Ok(Self {
				encoding_key: EncodingKey::from_secret(secret_bytes),
				decoding_key: DecodingKey::from_secret(secret_bytes),
				validation,
				config,
			})
		})
	}

	/// Generates a new access token for a client with specified scopes.
	///
	/// # Arguments
	/// * `client_id` - Unique identifier for the client
	/// * `scopes` - List of permissions to grant
	/// * `custom_expiry_hours` - Optional custom expiry time in hours
	///
	/// # Returns
	/// A signed JWT access token string or an error
	pub fn generate_access_token(
		&self,
		client_id: &str,
		scopes: Vec<AuthScope>,
	) -> Result<String, AuthError> {
		let expiry_seconds = self
			.config
			.access_token_expiry_hours
			.saturating_mul(3600)
			.max(1);
		self.generate_access_token_with_ttl_seconds(client_id, scopes, expiry_seconds)
	}

	/// Generates a new access token for a client with custom TTL in seconds.
	pub fn generate_access_token_with_ttl_seconds(
		&self,
		client_id: &str,
		scopes: Vec<AuthScope>,
		ttl_seconds: u32,
	) -> Result<String, AuthError> {
		let ttl_seconds = ttl_seconds.max(1);
		let claims = JwtClaims {
			sub: client_id.to_string(),
			exp: (Utc::now() + Duration::seconds(ttl_seconds as i64)).timestamp(),
			iat: Utc::now().timestamp(),
			iss: self.config.issuer.clone(),
			scope: scopes,
			nonce: None,
		};

		encode(&Header::default(), &claims, &self.encoding_key)
			.map_err(|e| AuthError::TokenGeneration(e.to_string()))
	}

	/// Validates a JWT token and returns the claims if valid.
	///
	/// # Arguments
	/// * `token` - The JWT token string to validate
	///
	/// # Returns
	/// The JWT claims if the token is valid, or an error
	pub fn validate_token(&self, token: &str) -> Result<JwtClaims, AuthError> {
		// Decode and validate the token
		let token_data = decode::<JwtClaims>(token, &self.decoding_key, &self.validation)
			.map_err(|e| AuthError::InvalidAccessToken(e.to_string()))?;

		let claims = token_data.claims;

		// Check if token is expired (jsonwebtoken handles this, but we can double-check)
		let now = Utc::now().timestamp();
		if claims.exp < now {
			return Err(AuthError::InvalidAccessToken("Token expired".to_string()));
		}

		Ok(claims)
	}

	/// Generates a JWT refresh token
	///
	/// # Arguments
	/// * `client_id` - Unique identifier for the client
	/// * `scopes` - List of permissions to grant
	///
	/// # Returns
	/// A JWT refresh token string or an error
	pub async fn generate_refresh_token(
		&self,
		client_id: &str,
		scopes: Vec<AuthScope>,
	) -> Result<String, AuthError> {
		let now = Utc::now().timestamp();
		let expires_at = now + (self.config.refresh_token_expiry_hours as i64 * 3600);

		// Create JWT refresh token with all necessary claims
		let claims = JwtClaims {
			sub: client_id.to_string(),
			exp: expires_at,
			iat: now,
			iss: self.config.issuer.clone(),
			scope: scopes,
			nonce: Some(Uuid::new_v4().to_string()), // Unique nonce for each refresh token
		};

		// Generate and return the JWT refresh token
		encode(&Header::default(), &claims, &self.encoding_key)
			.map_err(|e| AuthError::TokenGeneration(e.to_string()))
	}

	/// Validates a JWT refresh token and returns new access and refresh tokens.
	///
	/// # Arguments
	/// * `refresh_token` - The JWT refresh token to validate
	///
	/// # Returns
	/// A tuple of (access_token, new_refresh_token) or an error
	pub async fn refresh_access_token(
		&self,
		refresh_token: &str,
	) -> Result<(String, String), AuthError> {
		// Decode and validate the JWT refresh token
		let token_data = decode::<JwtClaims>(refresh_token, &self.decoding_key, &self.validation)
			.map_err(|e| AuthError::InvalidRefreshToken(e.to_string()))?;

		let claims = token_data.claims;

		// Check if token is expired
		let now = Utc::now().timestamp();
		if claims.exp <= now {
			return Err(AuthError::InvalidRefreshToken(
				"Refresh token expired".to_string(),
			));
		}

		// Generate new access token using the claims from the refresh token
		let access_token = self.generate_access_token(&claims.sub, claims.scope.clone())?;

		// Generate new refresh token (token rotation for security)
		let new_refresh_token = self
			.generate_refresh_token(&claims.sub, claims.scope)
			.await?;

		Ok((access_token, new_refresh_token))
	}

	/// Returns a reference to the auth configuration.
	pub fn config(&self) -> &AuthConfig {
		&self.config
	}

	/// Checks if the provided claims have the required scope.
	///
	/// # Arguments
	/// * `claims` - JWT claims containing user scopes
	/// * `required` - The required scope for the operation
	///
	/// # Returns
	/// True if the claims contain the required scope or admin permissions
	pub fn check_scope(claims: &JwtClaims, required: &AuthScope) -> bool {
		claims.scope.iter().any(|s| s.grants(required))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use solver_types::SecretString;

	fn test_config() -> AuthConfig {
		AuthConfig {
			enabled: true,
			jwt_secret: SecretString::from("test-secret-key-at-least-32-chars-long"),
			access_token_expiry_hours: 1,
			refresh_token_expiry_hours: 720,
			issuer: "test-issuer".to_string(),
			public_register_enabled: false,
			token_client_id: "solver-admin".to_string(),
			token_client_secret: None,
			admin: None,
		}
	}

	#[test]
	fn test_invalid_token() {
		let service = JwtService::new(test_config()).unwrap();

		let result = service.validate_token("invalid-token");
		assert!(result.is_err());
	}

	#[test]
	fn test_scope_checking() {
		let claims = JwtClaims {
			sub: "test".to_string(),
			exp: 9999999999,
			iat: 0,
			iss: "test".to_string(),
			scope: vec![AuthScope::ReadOrders, AuthScope::AdminAll],
			nonce: None,
		};

		// AdminAll grants everything
		assert!(JwtService::check_scope(&claims, &AuthScope::CreateQuotes));
		assert!(JwtService::check_scope(&claims, &AuthScope::ReadOrders));

		// Regular scope checking
		let limited_claims = JwtClaims {
			scope: vec![AuthScope::ReadOrders],
			..claims
		};
		assert!(JwtService::check_scope(
			&limited_claims,
			&AuthScope::ReadOrders
		));
		assert!(!JwtService::check_scope(
			&limited_claims,
			&AuthScope::CreateQuotes
		));
	}

	#[tokio::test]
	async fn test_refresh_token_generation_and_validation() {
		let service = JwtService::new(test_config()).unwrap();

		// Generate refresh token
		let refresh_token = service
			.generate_refresh_token("test-client", vec![AuthScope::ReadOrders])
			.await
			.unwrap();

		// Verify the refresh token is a valid JWT
		let refresh_claims = service.validate_token(&refresh_token).unwrap();
		assert_eq!(refresh_claims.sub, "test-client");
		assert_eq!(refresh_claims.scope, vec![AuthScope::ReadOrders]);

		// Refresh the access token
		let (access_token, new_refresh_token) =
			service.refresh_access_token(&refresh_token).await.unwrap();

		// Validate the new access token
		let access_claims = service.validate_token(&access_token).unwrap();
		assert_eq!(access_claims.sub, "test-client");
		assert_eq!(access_claims.scope, vec![AuthScope::ReadOrders]);

		// Ensure refresh tokens are different (token rotation)
		assert_ne!(refresh_token, new_refresh_token);

		// Verify old refresh token can still be used (JWT-based, no single-use restriction)
		let result = service.refresh_access_token(&refresh_token).await;
		assert!(result.is_ok());
	}

	#[tokio::test]
	async fn test_refresh_token_expiry() {
		let mut config = test_config();
		config.refresh_token_expiry_hours = 0; // Expired immediately for testing
		let service = JwtService::new(config).unwrap();

		let refresh_token = service
			.generate_refresh_token("test-client", vec![AuthScope::ReadOrders])
			.await
			.unwrap();

		// Wait a moment to ensure expiry
		tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

		let result = service.refresh_access_token(&refresh_token).await;
		assert!(result.is_err());
		assert!(result.unwrap_err().to_string().contains("expired"));
	}

	#[tokio::test]
	async fn test_refresh_token_rotation() {
		let service = JwtService::new(test_config()).unwrap();

		// Generate initial refresh token
		let initial_token = service
			.generate_refresh_token("client1", vec![AuthScope::ReadOrders])
			.await
			.unwrap();

		// First refresh - get new tokens
		let (access_token1, refresh_token1) =
			service.refresh_access_token(&initial_token).await.unwrap();

		// Add small delay to ensure different timestamps
		tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

		// Second refresh - get different tokens (token rotation)
		let (access_token2, refresh_token2) =
			service.refresh_access_token(&refresh_token1).await.unwrap();

		// Verify refresh tokens are different (rotation working)
		assert_ne!(initial_token, refresh_token1);
		assert_ne!(refresh_token1, refresh_token2);

		// Access tokens should also be different due to different timestamps
		assert_ne!(access_token1, access_token2);

		// Verify all refresh tokens still work (JWT-based, stateless)
		assert!(service.refresh_access_token(&initial_token).await.is_ok());
		assert!(service.refresh_access_token(&refresh_token1).await.is_ok());
		assert!(service.refresh_access_token(&refresh_token2).await.is_ok());
	}
}
