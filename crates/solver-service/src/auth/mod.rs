//! Authentication module for the OIF solver API service.
//!
//! This module provides JWT-based authentication and authorization
//! functionality for protecting API endpoints.

pub mod middleware;

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use solver_storage::{StorageIndexes, StorageService};
use solver_types::{AuthConfig, AuthScope, JwtClaims, RefreshTokenData, TokenType};
use std::sync::Arc;
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

	/// Storage error occurred
	#[error("Storage error: {0}")]
	StorageError(String),
}

/// Service for handling JWT token generation and validation.
pub struct JwtService {
	config: AuthConfig,
	encoding_key: EncodingKey,
	decoding_key: DecodingKey,
	validation: Validation,
	storage: Arc<StorageService>,
}

impl JwtService {
	/// Creates a new JWT service with the provided configuration.
	///
	/// # Arguments
	/// * `config` - Authentication configuration containing secret and settings
	/// * `storage` - Storage service for persistent refresh token storage
	///
	/// # Returns
	/// A configured JWT service or an error if initialization fails
	pub fn new(config: AuthConfig, storage: Arc<StorageService>) -> Result<Self, AuthError> {
		let secret = config.jwt_secret.expose_secret().as_bytes();

		let mut validation = Validation::new(Algorithm::HS256);
		validation.set_issuer(&[config.issuer.clone()]);

		Ok(Self {
			encoding_key: EncodingKey::from_secret(secret),
			decoding_key: DecodingKey::from_secret(secret),
			validation,
			config,
			storage,
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
		custom_expiry_hours: Option<u32>,
	) -> Result<String, AuthError> {
		let expiry_hours = custom_expiry_hours.unwrap_or(self.config.access_token_expiry_hours);

		let claims = JwtClaims {
			sub: client_id.to_string(),
			exp: (Utc::now() + Duration::hours(expiry_hours as i64)).timestamp(),
			iat: Utc::now().timestamp(),
			iss: self.config.issuer.clone(),
			scope: scopes,
			nonce: None,
			token_type: TokenType::Access,
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

	/// Generates a refresh token and stores it persistently.
	///
	/// # Arguments
	/// * `client_id` - Unique identifier for the client
	/// * `scopes` - List of permissions to grant
	///
	/// # Returns
	/// A refresh token ID or an error
	pub async fn generate_refresh_token(
		&self,
		client_id: &str,
		scopes: Vec<AuthScope>,
	) -> Result<String, AuthError> {
		let token_id = Uuid::new_v4().to_string();
		let now = Utc::now().timestamp();
		let expires_at = now + (self.config.refresh_token_expiry_hours as i64 * 3600);

		let refresh_data = RefreshTokenData {
			client_id: client_id.to_string(),
			scopes,
			expires_at,
			issued_at: now,
		};

		// Store in persistent storage with TTL
		let ttl =
			std::time::Duration::from_secs(self.config.refresh_token_expiry_hours as u64 * 3600);
		let indexes = Some(
			StorageIndexes::new()
				.with_field("client_id", client_id)
				.with_field("issued_at", now),
		);

		self.storage
			.store_with_ttl(
				"refresh_tokens",
				&token_id,
				&refresh_data,
				indexes,
				Some(ttl),
			)
			.await
			.map_err(|e| AuthError::StorageError(e.to_string()))?;

		Ok(token_id)
	}

	/// Validates a refresh token and returns new access and refresh tokens.
	///
	/// # Arguments
	/// * `refresh_token` - The refresh token to validate
	///
	/// # Returns
	/// A tuple of (access_token, new_refresh_token) or an error
	pub async fn refresh_access_token(
		&self,
		refresh_token: &str,
	) -> Result<(String, String), AuthError> {
		let now = Utc::now().timestamp();

		// Retrieve and remove the refresh token (single use)
		let token_data: RefreshTokenData = self
			.storage
			.retrieve("refresh_tokens", refresh_token)
			.await
			.map_err(|_| {
				AuthError::InvalidRefreshToken("Refresh token not found or expired".to_string())
			})?;

		// Remove the token immediately (single use)
		self.storage
			.remove("refresh_tokens", refresh_token)
			.await
			.map_err(|e| AuthError::StorageError(e.to_string()))?;

		// Check if token is expired
		if token_data.expires_at <= now {
			return Err(AuthError::InvalidRefreshToken(
				"Refresh token expired".to_string(),
			));
		}

		// Generate new access token
		let access_token =
			self.generate_access_token(&token_data.client_id, token_data.scopes.clone(), None)?;

		// Generate new refresh token
		let new_refresh_token = self
			.generate_refresh_token(&token_data.client_id, token_data.scopes)
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
	use solver_storage::implementations::memory::MemoryStorage;
	use solver_types::SecretString;
	use std::sync::Arc;

	fn test_config() -> AuthConfig {
		AuthConfig {
			enabled: true,
			jwt_secret: SecretString::from("test-secret-key-at-least-32-chars-long"),
			access_token_expiry_hours: 1,
			refresh_token_expiry_hours: 720,
			issuer: "test-issuer".to_string(),
		}
	}

	fn test_storage() -> Arc<StorageService> {
		Arc::new(StorageService::new(Box::new(MemoryStorage::new())))
	}

	#[test]
	fn test_invalid_token() {
		let service = JwtService::new(test_config(), test_storage()).unwrap();

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
			token_type: TokenType::Access,
		};

		// AdminAll grants everything
		assert!(JwtService::check_scope(&claims, &AuthScope::CreateQuotes));
		assert!(JwtService::check_scope(&claims, &AuthScope::ReadOrders));

		// Regular scope checking
		let limited_claims = JwtClaims {
			scope: vec![AuthScope::ReadOrders],
			token_type: TokenType::Access,
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
		let service = JwtService::new(test_config(), test_storage()).unwrap();

		// Generate refresh token
		let refresh_token = service
			.generate_refresh_token("test-client", vec![AuthScope::ReadOrders])
			.await
			.unwrap();

		// Refresh the access token
		let (access_token, new_refresh_token) =
			service.refresh_access_token(&refresh_token).await.unwrap();

		// Validate the new access token
		let claims = service.validate_token(&access_token).unwrap();
		assert_eq!(claims.sub, "test-client");
		assert_eq!(claims.scope, vec![AuthScope::ReadOrders]);

		// Ensure refresh tokens are different
		assert_ne!(refresh_token, new_refresh_token);

		// Ensure old refresh token cannot be used again
		let result = service.refresh_access_token(&refresh_token).await;
		assert!(result.is_err());
	}

	#[tokio::test]
	async fn test_refresh_token_expiry() {
		let mut config = test_config();
		config.refresh_token_expiry_hours = 0; // Expired immediately for testing
		let service = JwtService::new(config, test_storage()).unwrap();

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
	async fn test_refresh_token_cleanup() {
		let service = JwtService::new(test_config(), test_storage()).unwrap();

		// Generate multiple refresh tokens
		let token1 = service
			.generate_refresh_token("client1", vec![AuthScope::ReadOrders])
			.await
			.unwrap();
		let token2 = service
			.generate_refresh_token("client2", vec![AuthScope::ReadOrders])
			.await
			.unwrap();

		// Verify both tokens exist and work
		let (_, _) = service.refresh_access_token(&token1).await.unwrap();
		let (_, _) = service.refresh_access_token(&token2).await.unwrap();

		// Now generate a third token which should clean up the used tokens
		let _token3 = service
			.generate_refresh_token("client3", vec![AuthScope::ReadOrders])
			.await
			.unwrap();

		// The first two tokens should no longer work (single use)
		assert!(service.refresh_access_token(&token1).await.is_err());
		assert!(service.refresh_access_token(&token2).await.is_err());
	}
}
