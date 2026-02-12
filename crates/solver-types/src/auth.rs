//! Authentication and authorization types for the OIF solver API.
//!
//! This module provides types for JWT-based authentication including
//! scopes, claims, and configuration structures.

use alloy_primitives::Address;
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
		write!(f, "{scope_str}")
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
			_ => Err(format!("Unknown scope: {s}")),
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
	/// Whether public self-registration endpoint is enabled.
	/// Defaults to false for safer behavior.
	#[serde(default = "default_public_register_enabled")]
	pub public_register_enabled: bool,
	/// Single client ID allowed to request privileged tokens via /auth/token.
	#[serde(default = "default_token_client_id")]
	pub token_client_id: String,
	/// Secret associated with token_client_id.
	/// If absent, /auth/token cannot issue privileged tokens.
	#[serde(default)]
	pub token_client_secret: Option<SecretString>,
	/// Admin authentication configuration (optional)
	/// If not present, admin authentication via wallet signatures is disabled
	#[serde(default)]
	pub admin: Option<AdminConfig>,
}

fn default_public_register_enabled() -> bool {
	false
}

fn default_token_client_id() -> String {
	"solver-admin".to_string()
}

/// Admin authentication configuration for wallet-based admin operations.
///
/// This configuration enables admins to authenticate using their Ethereum
/// wallet signatures. Works for both SIWE session-based and per-action
/// signature approaches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminConfig {
	/// Enable admin authentication
	#[serde(default)]
	pub enabled: bool,

	/// Domain for signature verification (prevents cross-site attacks).
	/// Example: "solver.example.com"
	pub domain: String,

	/// Chain ID for EIP-712 domain separator.
	/// The wallet must be connected to this chain when signing admin actions.
	/// If not set, uses the first network's chain ID from config.
	#[serde(default)]
	pub chain_id: Option<u64>,

	/// Nonce TTL in seconds. Nonces expire after this duration.
	/// Default: 300 seconds (5 minutes)
	#[serde(default = "default_nonce_ttl")]
	pub nonce_ttl_seconds: u64,

	/// List of authorized admin wallet addresses.
	/// Only these addresses can perform admin operations.
	pub admin_addresses: Vec<Address>,
}

fn default_nonce_ttl() -> u64 {
	300
}

impl AdminConfig {
	/// Check if an address is an authorized admin.
	///
	/// Returns `false` if admin auth is disabled (`enabled = false`),
	/// even if the address is in the admin list.
	///
	/// Comparison is done on the raw bytes, which is case-insensitive
	/// and handles checksummed vs non-checksummed addresses correctly.
	pub fn is_admin(&self, address: &Address) -> bool {
		self.enabled && self.admin_addresses.iter().any(|a| a == address)
	}

	/// Get the number of configured admin addresses.
	pub fn admin_count(&self) -> usize {
		self.admin_addresses.len()
	}
}

impl Default for AdminConfig {
	fn default() -> Self {
		Self {
			enabled: false,
			domain: String::new(),
			chain_id: None,
			nonce_ttl_seconds: default_nonce_ttl(),
			admin_addresses: Vec::new(),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::str::FromStr;

	#[test]
	fn test_admin_config_is_admin() {
		let admin_addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();
		let non_admin_addr =
			Address::from_str("0x70997970C51812dc3A010C7d01b50e0d17dc79C8").unwrap();

		let config = AdminConfig {
			enabled: true,
			domain: "solver.example.com".to_string(),
			chain_id: None,
			nonce_ttl_seconds: 300,
			admin_addresses: vec![admin_addr],
		};

		assert!(config.is_admin(&admin_addr));
		assert!(!config.is_admin(&non_admin_addr));
	}

	#[test]
	fn test_admin_config_multiple_admins() {
		let admin1 = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();
		let admin2 = Address::from_str("0x70997970C51812dc3A010C7d01b50e0d17dc79C8").unwrap();
		let non_admin = Address::from_str("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC").unwrap();

		let config = AdminConfig {
			enabled: true,
			domain: "solver.example.com".to_string(),
			chain_id: None,
			nonce_ttl_seconds: 300,
			admin_addresses: vec![admin1, admin2],
		};

		assert!(config.is_admin(&admin1));
		assert!(config.is_admin(&admin2));
		assert!(!config.is_admin(&non_admin));
		assert_eq!(config.admin_count(), 2);
	}

	#[test]
	fn test_admin_config_disabled_rejects_all() {
		// Even if an address is in the admin list, it should be rejected when disabled
		let admin_addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

		let config = AdminConfig {
			enabled: false, // Disabled!
			domain: "solver.example.com".to_string(),
			chain_id: None,
			nonce_ttl_seconds: 300,
			admin_addresses: vec![admin_addr],
		};

		// Should return false because enabled = false
		assert!(!config.is_admin(&admin_addr));
	}

	#[test]
	fn test_admin_config_default() {
		let config = AdminConfig::default();

		assert!(!config.enabled);
		assert!(config.domain.is_empty());
		assert_eq!(config.nonce_ttl_seconds, 300);
		assert!(config.admin_addresses.is_empty());
	}

	#[test]
	fn test_admin_config_serialization() {
		let admin_addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

		let config = AdminConfig {
			enabled: true,
			domain: "solver.example.com".to_string(),
			chain_id: Some(1),
			nonce_ttl_seconds: 600,
			admin_addresses: vec![admin_addr],
		};

		let json = serde_json::to_string(&config).unwrap();
		let parsed: AdminConfig = serde_json::from_str(&json).unwrap();

		assert_eq!(parsed.enabled, config.enabled);
		assert_eq!(parsed.domain, config.domain);
		assert_eq!(parsed.chain_id, config.chain_id);
		assert_eq!(parsed.nonce_ttl_seconds, config.nonce_ttl_seconds);
		assert_eq!(parsed.admin_addresses, config.admin_addresses);
	}

	#[test]
	fn test_admin_config_deserialization_with_defaults() {
		let json = r#"{
			"domain": "solver.example.com",
			"admin_addresses": ["0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"]
		}"#;

		let config: AdminConfig = serde_json::from_str(json).unwrap();

		assert!(!config.enabled); // Default
		assert_eq!(config.nonce_ttl_seconds, 300); // Default
		assert_eq!(config.domain, "solver.example.com");
		assert_eq!(config.admin_count(), 1);
	}

	#[test]
	fn test_auth_config_with_admin() {
		let json = r#"{
			"enabled": true,
			"jwt_secret": "test-secret-at-least-32-characters-long",
			"access_token_expiry_hours": 1,
			"refresh_token_expiry_hours": 720,
			"issuer": "oif-solver",
			"admin": {
				"enabled": true,
				"domain": "solver.example.com",
				"admin_addresses": ["0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"]
			}
		}"#;

		let config: AuthConfig = serde_json::from_str(json).unwrap();

		assert!(config.admin.is_some());
		assert!(!config.public_register_enabled);
		assert_eq!(config.token_client_id, "solver-admin");
		assert!(config.token_client_secret.is_none());
		let admin = config.admin.unwrap();
		assert!(admin.enabled);
		assert_eq!(admin.domain, "solver.example.com");
		assert_eq!(admin.admin_count(), 1);
	}

	#[test]
	fn test_auth_config_without_admin() {
		let json = r#"{
			"enabled": true,
			"jwt_secret": "test-secret-at-least-32-characters-long",
			"access_token_expiry_hours": 1,
			"refresh_token_expiry_hours": 720,
			"issuer": "oif-solver"
		}"#;

		let config: AuthConfig = serde_json::from_str(json).unwrap();

		assert!(config.admin.is_none());
		assert!(!config.public_register_enabled);
		assert_eq!(config.token_client_id, "solver-admin");
		assert!(config.token_client_secret.is_none());
	}

	#[test]
	fn test_auth_config_with_client_credentials_fields() {
		let json = r#"{
			"enabled": true,
			"jwt_secret": "test-secret-at-least-32-characters-long",
			"access_token_expiry_hours": 1,
			"refresh_token_expiry_hours": 720,
			"issuer": "oif-solver",
			"public_register_enabled": true,
			"token_client_id": "solver-admin",
			"token_client_secret": "test-secret-value-at-least-32-chars"
		}"#;

		let config: AuthConfig = serde_json::from_str(json).unwrap();

		assert!(config.public_register_enabled);
		assert_eq!(config.token_client_id, "solver-admin");
		assert_eq!(
			config.token_client_secret.unwrap().expose_secret(),
			"test-secret-value-at-least-32-chars"
		);
	}
}
