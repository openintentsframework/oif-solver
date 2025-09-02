//! Authentication module for the OIF solver API service.
//!
//! This module provides JWT-based authentication and authorization
//! functionality for protecting API endpoints.

pub mod middleware;

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use solver_types::{AuthConfig, AuthScope, JwtClaims};
use thiserror::Error;

pub use middleware::{auth_middleware, AuthState};

/// Errors that can occur during authentication operations.
#[derive(Error, Debug)]
pub enum AuthError {
	/// Failed to generate a JWT token
	#[error("Failed to generate token: {0}")]
	TokenGeneration(String),

	/// The provided token is invalid
	#[error("Invalid token: {0}")]
	InvalidToken(String),
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
		let secret = config.jwt_secret.expose_secret().as_bytes();

		let mut validation = Validation::new(Algorithm::HS256);
		validation.set_issuer(&[config.issuer.clone()]);

		Ok(Self {
			encoding_key: EncodingKey::from_secret(secret),
			decoding_key: DecodingKey::from_secret(secret),
			validation,
			config,
		})
	}

	/// Generates a new JWT token for a client with specified scopes.
	///
	/// # Arguments
	/// * `client_id` - Unique identifier for the client
	/// * `scopes` - List of permissions to grant
	/// * `custom_expiry_hours` - Optional custom expiry time in hours
	///
	/// # Returns
	/// A signed JWT token string or an error
	pub fn generate_token(
		&self,
		client_id: &str,
		scopes: Vec<AuthScope>,
		custom_expiry_hours: Option<u32>,
	) -> Result<String, AuthError> {
		let expiry_hours = custom_expiry_hours.unwrap_or(self.config.token_expiry_hours);

		let claims = JwtClaims {
			sub: client_id.to_string(),
			exp: (Utc::now() + Duration::hours(expiry_hours as i64)).timestamp(),
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
			.map_err(|e| AuthError::InvalidToken(e.to_string()))?;

		let claims = token_data.claims;

		// Check if token is expired (jsonwebtoken handles this, but we can double-check)
		let now = Utc::now().timestamp();
		if claims.exp < now {
			return Err(AuthError::InvalidToken("Token expired".to_string()));
		}

		Ok(claims)
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
			token_expiry_hours: 24,
			issuer: "test-issuer".to_string(),
		}
	}

	#[test]
	fn test_jwt_generation_and_validation() {
		let service = JwtService::new(test_config()).unwrap();

		// Generate token
		let token = service
			.generate_token(
				"test-client",
				vec![AuthScope::ReadOrders, AuthScope::CreateQuotes],
				None,
			)
			.unwrap();

		// Validate token
		let claims = service.validate_token(&token).unwrap();

		assert_eq!(claims.sub, "test-client");
		assert_eq!(claims.iss, "test-issuer");
		assert_eq!(claims.scope.len(), 2);
		assert!(claims.scope.contains(&AuthScope::ReadOrders));
		assert!(claims.scope.contains(&AuthScope::CreateQuotes));
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

	#[test]
	fn test_expired_token() {
		let service = JwtService::new(test_config()).unwrap();

		// Generate token with 0 hours expiry
		let token = service
			.generate_token(
				"test-client",
				vec![AuthScope::ReadOrders],
				Some(0), // Expires immediately
			)
			.unwrap();

		// Sleep for a moment to ensure expiry
		std::thread::sleep(std::time::Duration::from_secs(2));

		let result = service.validate_token(&token);
		assert!(result.is_err());
		assert!(result.unwrap_err().to_string().contains("expired"));
	}
}
