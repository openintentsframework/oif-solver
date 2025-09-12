//! Authentication and authorization types for the OIF solver API.
//!
//! This module provides types for JWT-based authentication including
//! scopes, claims, and configuration structures.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::SecretString;

/// JWT token scopes defining access permissions
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthScope {
	/// Permission to read order information
	ReadOrders,
	/// Permission to create new orders
	CreateOrders,
	/// Permission to create quotes
	CreateQuotes,
	/// Permission to read quotes
	ReadQuotes,
	/// Admin scope - grants all permissions
	AdminAll,
}

impl AuthScope {
	/// Check if this scope grants access to a specific action
	pub fn grants(&self, required: &AuthScope) -> bool {
		match self {
			AuthScope::AdminAll => true,
			_ => self == required,
		}
	}
}

impl fmt::Display for AuthScope {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let scope_str = match self {
			AuthScope::ReadOrders => "read-orders",
			AuthScope::CreateOrders => "create-orders",
			AuthScope::CreateQuotes => "create-quotes",
			AuthScope::ReadQuotes => "read-quotes",
			AuthScope::AdminAll => "admin-all",
		};
		write!(f, "{}", scope_str)
	}
}

impl FromStr for AuthScope {
	type Err = String;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"read-orders" => Ok(AuthScope::ReadOrders),
			"create-orders" => Ok(AuthScope::CreateOrders),
			"create-quotes" => Ok(AuthScope::CreateQuotes),
			"read-quotes" => Ok(AuthScope::ReadQuotes),
			"admin-all" => Ok(AuthScope::AdminAll),
			_ => Err(format!("Unknown scope: {}", s)),
		}
	}
}

/// JWT claims structure for token validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
	/// Subject (client identifier)
	pub sub: String,
	/// Expiration time (Unix timestamp)
	pub exp: i64,
	/// Issued at (Unix timestamp)
	pub iat: i64,
	/// Issuer
	pub iss: String,
	/// Scopes granted to this token
	pub scope: Vec<AuthScope>,
	/// Optional nonce for one-time tokens
	pub nonce: Option<String>,
	/// Token type (access or refresh)
	pub token_type: TokenType,
}

/// Token type enumeration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenType {
	/// Access token for API calls
	Access,
	/// Refresh token for obtaining new access tokens
	Refresh,
}

/// Refresh token data stored persistently
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenData {
	/// Client identifier
	pub client_id: String,
	/// Granted scopes
	pub scopes: Vec<AuthScope>,
	/// Token expiration timestamp
	pub expires_at: i64,
	/// When the token was issued
	pub issued_at: i64,
}

/// Authentication configuration for the API service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
	/// Enable authentication
	pub enabled: bool,
	/// JWT signing secret
	pub jwt_secret: SecretString,
	/// Access token expiry in hours
	pub access_token_expiry_hours: u32,
	/// Refresh token expiry in hours
	pub refresh_token_expiry_hours: u32,
	/// JWT issuer identifier
	pub issuer: String,
}
