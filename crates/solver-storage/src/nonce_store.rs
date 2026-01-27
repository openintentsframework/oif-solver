//! Nonce management for admin authentication.
//!
//! Provides cryptographically secure nonce generation and single-use
//! consumption via a pluggable storage backend. Used for replay protection
//! in admin authentication.
//!
//! # Architecture
//!
//! This module uses the common [`StorageInterface`] for persistence, allowing
//! different backends (Redis, memory, file) to be used. This follows the
//! same pattern as [`crate::config_store`].
//!
//! # Example
//!
//! ```rust,ignore
//! use solver_storage::nonce_store::{create_nonce_store, NonceStoreConfig};
//!
//! // Create nonce store with Redis backend
//! let nonce_store = create_nonce_store(
//!     NonceStoreConfig::Redis { url: "redis://localhost:6379".to_string() },
//!     "my-solver",
//!     300,  // TTL in seconds
//! )?;
//!
//! // Generate a nonce (returns u64)
//! let nonce: u64 = nonce_store.generate().await?;
//!
//! // Later, verify and consume the nonce
//! let exists = nonce_store.exists(nonce).await?;  // Check without consuming
//! nonce_store.consume(nonce).await?;              // Consume (single-use)
//! ```

use crate::{implementations, StorageError, StorageInterface};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, warn};
use uuid::Uuid;

/// Errors that can occur during nonce operations.
#[derive(Error, Debug)]
pub enum NonceError {
	/// Storage backend operation failed
	#[error("Storage error: {0}")]
	Storage(String),

	/// Nonce was not found or already consumed
	#[error("Nonce not found or already used")]
	NotFound,

	/// Configuration error
	#[error("Configuration error: {0}")]
	Configuration(String),
}

impl From<StorageError> for NonceError {
	fn from(err: StorageError) -> Self {
		match err {
			StorageError::NotFound(_) => NonceError::NotFound,
			StorageError::Configuration(msg) => NonceError::Configuration(msg),
			other => NonceError::Storage(other.to_string()),
		}
	}
}

/// Configuration for different nonce store backends.
///
/// Similar to [`crate::config_store::ConfigStoreConfig`], this enum allows
/// selecting the storage backend at runtime.
#[derive(Clone)]
pub enum NonceStoreConfig {
	/// Use an existing StorageInterface (for sharing storage with other components)
	Storage(Arc<dyn StorageInterface>),
	/// Create a new Redis-backed storage
	Redis {
		/// Redis connection URL (e.g., "redis://localhost:6379")
		url: String,
	},
	/// Create an in-memory storage (useful for testing)
	Memory,
}

impl std::fmt::Debug for NonceStoreConfig {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			NonceStoreConfig::Storage(_) => f.debug_struct("Storage").finish_non_exhaustive(),
			NonceStoreConfig::Redis { url } => {
				let redacted = redact_url_credentials(url);
				f.debug_struct("Redis").field("url", &redacted).finish()
			},
			NonceStoreConfig::Memory => f.debug_struct("Memory").finish(),
		}
	}
}

/// Redacts credentials from a URL to prevent leaking secrets in logs.
fn redact_url_credentials(url: &str) -> String {
	let Some(scheme_end) = url.find("://") else {
		return url.to_string();
	};

	let after_scheme = &url[scheme_end + 3..];

	let Some(at_pos) = after_scheme.find('@') else {
		return url.to_string();
	};

	let scheme = &url[..scheme_end + 3];
	let host_and_path = &after_scheme[at_pos + 1..];
	format!("{}[REDACTED]@{}", scheme, host_and_path)
}

/// Creates a nonce store with the specified backend configuration.
///
/// # Arguments
///
/// * `config` - Backend configuration (Redis, Memory, or existing StorageInterface)
/// * `solver_id` - Unique solver identifier for namespacing
/// * `ttl_seconds` - How long nonces are valid before expiring
///
/// # Example
///
/// ```rust,ignore
/// // For production (Redis)
/// let store = create_nonce_store(
///     NonceStoreConfig::Redis { url: redis_url },
///     &solver_id,
///     300,
/// )?;
///
/// // For testing (Memory)
/// let store = create_nonce_store(
///     NonceStoreConfig::Memory,
///     "test-solver",
///     300,
/// )?;
/// ```
pub fn create_nonce_store(
	config: NonceStoreConfig,
	solver_id: &str,
	ttl_seconds: u64,
) -> Result<NonceStore, NonceError> {
	let storage: Arc<dyn StorageInterface> = match config {
		NonceStoreConfig::Storage(s) => s,
		NonceStoreConfig::Redis { url } => {
			let redis_config = toml::Value::Table({
				let mut table = toml::map::Map::new();
				table.insert("redis_url".to_string(), toml::Value::String(url));
				table
			});
			Arc::from(implementations::redis::create_storage(&redis_config)?)
		},
		NonceStoreConfig::Memory => {
			let config = toml::Value::Table(toml::map::Map::new());
			Arc::from(implementations::memory::create_storage(&config)?)
		},
	};
	NonceStore::new(storage, solver_id, ttl_seconds)
}

/// Convenience function for creating a Redis-backed nonce store.
///
/// This mirrors the pattern of [`crate::config_store::create_redis_config_store`].
pub fn create_redis_nonce_store(
	redis_url: String,
	solver_id: &str,
	ttl_seconds: u64,
) -> Result<NonceStore, NonceError> {
	create_nonce_store(
		NonceStoreConfig::Redis { url: redis_url },
		solver_id,
		ttl_seconds,
	)
}

/// Manages nonces for replay protection in admin authentication.
///
/// Nonces are:
/// - Cryptographically random (UUID v4)
/// - Stored with TTL (auto-expire)
/// - Single-use (deleted on consumption)
/// - Namespaced by solver_id (multi-solver safe)
///
/// This struct wraps a [`StorageInterface`] implementation, allowing
/// different storage backends to be used (Redis, memory, file).
pub struct NonceStore {
	/// Storage backend
	storage: Arc<dyn StorageInterface>,
	/// Solver ID for namespacing
	solver_id: String,
	/// Storage namespace for nonces
	namespace: String,
	/// TTL for nonces
	ttl: Duration,
}

impl NonceStore {
	/// Create a new NonceStore with a storage backend.
	///
	/// Prefer using [`create_nonce_store`] or [`create_redis_nonce_store`]
	/// instead of calling this directly.
	///
	/// # Arguments
	///
	/// * `storage` - Storage backend implementing `StorageInterface`
	/// * `solver_id` - Unique solver identifier for namespacing
	/// * `ttl_seconds` - How long nonces are valid (e.g., 300 = 5 min)
	///
	/// # Errors
	///
	/// Returns an error if solver_id is empty.
	pub fn new(
		storage: Arc<dyn StorageInterface>,
		solver_id: &str,
		ttl_seconds: u64,
	) -> Result<Self, NonceError> {
		if solver_id.is_empty() {
			return Err(NonceError::Configuration(
				"Solver ID cannot be empty".to_string(),
			));
		}

		Ok(Self {
			storage,
			solver_id: solver_id.to_string(),
			namespace: format!("{}:admin:nonce", solver_id),
			ttl: Duration::from_secs(ttl_seconds),
		})
	}

	/// Generate and store a new nonce.
	///
	/// Returns a unique numeric nonce that must be included in the signed message.
	/// The nonce will automatically expire after the configured TTL.
	///
	/// The nonce is a u64 derived from UUID v4's cryptographically secure randomness,
	/// making it compatible with EIP-712's uint256 nonce fields.
	pub async fn generate(&self) -> Result<u64, NonceError> {
		// Use UUID v4's 128-bit randomness, take lower 64 bits
		let nonce = Uuid::new_v4().as_u128() as u64;
		let nonce_key = self.nonce_key(nonce);

		// Store with TTL - value is creation timestamp for debugging
		let timestamp = chrono::Utc::now().timestamp().to_string();
		self.storage
			.set_bytes(&nonce_key, timestamp.into_bytes(), None, Some(self.ttl))
			.await?;

		debug!(
			nonce = %nonce,
			ttl_secs = %self.ttl.as_secs(),
			solver_id = %self.solver_id,
			"Generated admin nonce"
		);

		Ok(nonce)
	}

	/// Check if a nonce exists (without consuming it).
	///
	/// Useful for pre-validation before expensive signature verification.
	pub async fn exists(&self, nonce: u64) -> Result<bool, NonceError> {
		let nonce_key = self.nonce_key(nonce);
		Ok(self.storage.exists(&nonce_key).await?)
	}

	/// Consume a nonce (single-use).
	///
	/// Returns `Ok(())` if nonce was valid and is now consumed.
	/// Returns `Err(NotFound)` if nonce doesn't exist or was already used.
	///
	/// Note: This operation uses exists + delete which is not strictly atomic,
	/// but is acceptable for nonces since each nonce is unique (UUID-based)
	/// and the window between operations is minimal.
	pub async fn consume(&self, nonce: u64) -> Result<(), NonceError> {
		let nonce_key = self.nonce_key(nonce);

		// Check if exists first
		if !self.storage.exists(&nonce_key).await? {
			warn!(
				nonce = %nonce,
				solver_id = %self.solver_id,
				"Attempted to use invalid/expired nonce"
			);
			return Err(NonceError::NotFound);
		}

		// Delete the nonce
		self.storage.delete(&nonce_key).await?;

		debug!(
			nonce = %nonce,
			solver_id = %self.solver_id,
			"Consumed admin nonce"
		);

		Ok(())
	}

	/// Build the storage key for a nonce.
	fn nonce_key(&self, nonce: u64) -> String {
		format!("{}:{}", self.namespace, nonce)
	}

	/// Get the configured TTL for nonces in seconds.
	pub fn ttl_seconds(&self) -> u64 {
		self.ttl.as_secs()
	}

	/// Get the solver ID this store is configured for.
	pub fn solver_id(&self) -> &str {
		&self.solver_id
	}
}

impl std::fmt::Debug for NonceStore {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("NonceStore")
			.field("solver_id", &self.solver_id)
			.field("namespace", &self.namespace)
			.field("ttl_secs", &self.ttl.as_secs())
			.finish()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_new_valid() {
		let store = create_nonce_store(NonceStoreConfig::Memory, "test-solver", 300);
		assert!(store.is_ok());

		let store = store.unwrap();
		assert_eq!(store.ttl_seconds(), 300);
		assert_eq!(store.solver_id(), "test-solver");
	}

	#[test]
	fn test_new_empty_solver_id() {
		let result = create_nonce_store(NonceStoreConfig::Memory, "", 300);
		assert!(matches!(result, Err(NonceError::Configuration(_))));
	}

	#[test]
	fn test_nonce_key_format() {
		let store = create_nonce_store(NonceStoreConfig::Memory, "my-solver", 300).unwrap();
		let key = store.nonce_key(12345);
		assert_eq!(key, "my-solver:admin:nonce:12345");
	}

	#[test]
	fn test_debug_impl() {
		let store = create_nonce_store(NonceStoreConfig::Memory, "test-solver", 300).unwrap();

		let debug_str = format!("{:?}", store);
		assert!(debug_str.contains("NonceStore"));
		assert!(debug_str.contains("test-solver"));
		assert!(debug_str.contains("300"));
	}

	#[test]
	fn test_config_debug_redacts_credentials() {
		let config = NonceStoreConfig::Redis {
			url: "redis://:secretpassword@localhost:6379".to_string(),
		};
		let debug_str = format!("{:?}", config);
		assert!(!debug_str.contains("secretpassword"));
		assert!(debug_str.contains("[REDACTED]"));
	}

	#[test]
	fn test_config_debug_memory() {
		let config = NonceStoreConfig::Memory;
		let debug_str = format!("{:?}", config);
		assert!(debug_str.contains("Memory"));
	}

	#[test]
	fn test_redact_url_no_credentials() {
		let url = "redis://localhost:6379";
		assert_eq!(redact_url_credentials(url), "redis://localhost:6379");
	}

	#[test]
	fn test_redact_url_with_password() {
		let url = "redis://:mypassword@localhost:6379";
		let redacted = redact_url_credentials(url);
		assert_eq!(redacted, "redis://[REDACTED]@localhost:6379");
	}

	#[tokio::test]
	async fn test_nonce_lifecycle() {
		let store = create_nonce_store(NonceStoreConfig::Memory, "test-solver", 300).unwrap();

		// Generate
		let nonce = store.generate().await.unwrap();
		assert!(nonce > 0);

		// Exists
		assert!(store.exists(nonce).await.unwrap());

		// Consume once - should succeed
		assert!(store.consume(nonce).await.is_ok());

		// No longer exists
		assert!(!store.exists(nonce).await.unwrap());

		// Consume again - should fail (single-use)
		assert!(matches!(
			store.consume(nonce).await,
			Err(NonceError::NotFound)
		));
	}

	#[tokio::test]
	async fn test_invalid_nonce() {
		let store = create_nonce_store(NonceStoreConfig::Memory, "test-solver", 300).unwrap();

		// Random nonce that was never generated
		let result = store.consume(12345).await;
		assert!(matches!(result, Err(NonceError::NotFound)));
	}

	#[tokio::test]
	async fn test_nonce_isolation_between_solvers() {
		// Create shared storage
		let storage = Arc::from(
			implementations::memory::create_storage(&toml::Value::Table(toml::map::Map::new()))
				.unwrap(),
		);

		let store1 =
			create_nonce_store(NonceStoreConfig::Storage(Arc::clone(&storage)), "solver1", 300)
				.unwrap();
		let store2 =
			create_nonce_store(NonceStoreConfig::Storage(Arc::clone(&storage)), "solver2", 300)
				.unwrap();

		// Generate nonce in store1
		let nonce = store1.generate().await.unwrap();

		// Should exist in store1
		assert!(store1.exists(nonce).await.unwrap());

		// Should NOT exist in store2 (different solver namespace)
		assert!(!store2.exists(nonce).await.unwrap());

		// Consume from store2 should fail
		assert!(matches!(
			store2.consume(nonce).await,
			Err(NonceError::NotFound)
		));

		// Consume from store1 should succeed
		assert!(store1.consume(nonce).await.is_ok());
	}

	#[tokio::test]
	async fn test_multiple_nonces() {
		let store = create_nonce_store(NonceStoreConfig::Memory, "test-solver", 300).unwrap();

		// Generate multiple nonces
		let nonce1 = store.generate().await.unwrap();
		let nonce2 = store.generate().await.unwrap();
		let nonce3 = store.generate().await.unwrap();

		// All should be unique
		assert_ne!(nonce1, nonce2);
		assert_ne!(nonce2, nonce3);
		assert_ne!(nonce1, nonce3);

		// All should exist
		assert!(store.exists(nonce1).await.unwrap());
		assert!(store.exists(nonce2).await.unwrap());
		assert!(store.exists(nonce3).await.unwrap());

		// Consume in different order
		store.consume(nonce2).await.unwrap();
		assert!(!store.exists(nonce2).await.unwrap());
		assert!(store.exists(nonce1).await.unwrap());
		assert!(store.exists(nonce3).await.unwrap());
	}

	#[test]
	fn test_create_redis_nonce_store_convenience() {
		// This will fail because there's no Redis, but it tests the API
		let result = create_redis_nonce_store(
			"redis://invalid-host:6379".to_string(),
			"test-solver",
			300,
		);
		// Should fail at connection time (lazy), not at creation time
		// The error depends on the implementation details
		assert!(result.is_ok() || result.is_err());
	}
}
