//! Nonce management for admin authentication.
//!
//! Provides cryptographically secure nonce generation and single-use
//! consumption via Redis. Used for replay protection in admin authentication.
//!
//! # Example
//!
//! ```rust,ignore
//! use solver_storage::nonce_store::NonceStore;
//!
//! let store = NonceStore::new("redis://localhost:6379", "my-solver", 300)?;
//!
//! // Generate a nonce (returns u64)
//! let nonce: u64 = store.generate().await?;
//!
//! // Later, verify and consume the nonce
//! let exists = store.exists(nonce).await?;  // Check without consuming
//! store.consume(nonce).await?;              // Consume (single-use)
//! ```

use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use thiserror::Error;
use tokio::sync::OnceCell;
use tracing::{debug, warn};
use uuid::Uuid;

/// Errors that can occur during nonce operations.
#[derive(Error, Debug)]
pub enum NonceError {
	/// Redis connection or operation failed
	#[error("Redis error: {0}")]
	Redis(#[from] redis::RedisError),

	/// Nonce was not found or already consumed
	#[error("Nonce not found or already used")]
	NotFound,

	/// Configuration error
	#[error("Configuration error: {0}")]
	Configuration(String),
}

/// Manages nonces for replay protection in admin authentication.
///
/// Nonces are:
/// - Cryptographically random (UUID v4)
/// - Stored in Redis with TTL (auto-expire)
/// - Single-use (atomically deleted on consumption)
/// - Namespaced by solver_id (multi-solver safe)
pub struct NonceStore {
	/// Redis connection manager (lazily initialized)
	connection: OnceCell<ConnectionManager>,
	/// Redis URL for connection
	redis_url: String,
	/// Solver ID for namespacing
	solver_id: String,
	/// Key prefix for nonces
	key_prefix: String,
	/// TTL in seconds for nonces
	ttl_seconds: u64,
}

impl NonceStore {
	/// Create a new NonceStore.
	///
	/// # Arguments
	///
	/// * `redis_url` - Redis connection URL (e.g., "redis://localhost:6379")
	/// * `solver_id` - Unique solver identifier for namespacing
	/// * `ttl_seconds` - How long nonces are valid (default: 300 = 5 min)
	///
	/// # Errors
	///
	/// Returns an error if solver_id or redis_url is empty.
	pub fn new(redis_url: &str, solver_id: &str, ttl_seconds: u64) -> Result<Self, NonceError> {
		if redis_url.is_empty() {
			return Err(NonceError::Configuration(
				"Redis URL cannot be empty".to_string(),
			));
		}
		if solver_id.is_empty() {
			return Err(NonceError::Configuration(
				"Solver ID cannot be empty".to_string(),
			));
		}

		Ok(Self {
			connection: OnceCell::new(),
			redis_url: redis_url.to_string(),
			solver_id: solver_id.to_string(),
			key_prefix: "oif-solver".to_string(),
			ttl_seconds,
		})
	}

	/// Create a NonceStore with a custom key prefix.
	pub fn with_prefix(mut self, prefix: &str) -> Self {
		self.key_prefix = prefix.to_string();
		self
	}

	/// Get or initialize the Redis connection.
	async fn get_connection(&self) -> Result<ConnectionManager, NonceError> {
		self.connection
			.get_or_try_init(|| async {
				let client = redis::Client::open(self.redis_url.as_str())?;
				let manager = ConnectionManager::new(client).await?;
				debug!(
					redis_url = %self.redis_url,
					solver_id = %self.solver_id,
					"Nonce store Redis connection established"
				);
				Ok(manager)
			})
			.await
			.map(Clone::clone)
	}

	/// Build the Redis key for a nonce.
	fn nonce_key(&self, nonce: &str) -> String {
		format!(
			"{}:{}:admin:nonce:{}",
			self.key_prefix, self.solver_id, nonce
		)
	}

	/// Generate and store a new nonce.
	///
	/// Returns a unique numeric nonce that must be included in the signed message.
	/// The nonce will automatically expire after `ttl_seconds`.
	///
	/// The nonce is a u64 derived from UUID v4's cryptographically secure randomness,
	/// making it compatible with EIP-712's uint256 nonce fields.
	pub async fn generate(&self) -> Result<u64, NonceError> {
		// Use UUID v4's 128-bit randomness, take lower 64 bits
		let nonce = Uuid::new_v4().as_u128() as u64;
		let nonce_str = nonce.to_string();
		let key = self.nonce_key(&nonce_str);

		let mut conn = self.get_connection().await?;

		// Store with TTL - value is creation timestamp for debugging
		let timestamp = chrono::Utc::now().timestamp().to_string();
		conn.set_ex::<_, _, ()>(&key, &timestamp, self.ttl_seconds)
			.await?;

		debug!(
			nonce = %nonce,
			ttl = %self.ttl_seconds,
			solver_id = %self.solver_id,
			"Generated admin nonce"
		);

		Ok(nonce)
	}

	/// Check if a nonce exists (without consuming it).
	///
	/// Useful for pre-validation before expensive signature verification.
	pub async fn exists(&self, nonce: u64) -> Result<bool, NonceError> {
		let key = self.nonce_key(&nonce.to_string());

		let mut conn = self.get_connection().await?;
		let exists: bool = conn.exists(&key).await?;
		Ok(exists)
	}

	/// Consume a nonce (single-use).
	///
	/// Returns `Ok(())` if nonce was valid and is now consumed.
	/// Returns `Err(NotFound)` if nonce doesn't exist or was already used.
	///
	/// This operation is atomic - the nonce is deleted in the same
	/// operation that checks for its existence.
	pub async fn consume(&self, nonce: u64) -> Result<(), NonceError> {
		let key = self.nonce_key(&nonce.to_string());

		let mut conn = self.get_connection().await?;

		// DEL returns number of keys deleted (1 if existed, 0 if not)
		let deleted: i64 = conn.del(&key).await?;

		if deleted > 0 {
			debug!(
				nonce = %nonce,
				solver_id = %self.solver_id,
				"Consumed admin nonce"
			);
			Ok(())
		} else {
			warn!(
				nonce = %nonce,
				solver_id = %self.solver_id,
				"Attempted to use invalid/expired nonce"
			);
			Err(NonceError::NotFound)
		}
	}

	/// Get the configured TTL for nonces.
	pub fn ttl_seconds(&self) -> u64 {
		self.ttl_seconds
	}

	/// Get the solver ID this store is configured for.
	pub fn solver_id(&self) -> &str {
		&self.solver_id
	}
}

impl std::fmt::Debug for NonceStore {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("NonceStore")
			.field("redis_url", &self.redis_url)
			.field("solver_id", &self.solver_id)
			.field("key_prefix", &self.key_prefix)
			.field("ttl_seconds", &self.ttl_seconds)
			.finish()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_new_valid() {
		let store = NonceStore::new("redis://localhost:6379", "test-solver", 300);
		assert!(store.is_ok());

		let store = store.unwrap();
		assert_eq!(store.ttl_seconds(), 300);
		assert_eq!(store.solver_id(), "test-solver");
	}

	#[test]
	fn test_new_empty_redis_url() {
		let result = NonceStore::new("", "test-solver", 300);
		assert!(matches!(result, Err(NonceError::Configuration(_))));
	}

	#[test]
	fn test_new_empty_solver_id() {
		let result = NonceStore::new("redis://localhost:6379", "", 300);
		assert!(matches!(result, Err(NonceError::Configuration(_))));
	}

	#[test]
	fn test_nonce_key_format() {
		let store = NonceStore::new("redis://localhost:6379", "my-solver", 300).unwrap();
		let key = store.nonce_key("abc123");
		assert_eq!(key, "oif-solver:my-solver:admin:nonce:abc123");
	}

	#[test]
	fn test_nonce_key_with_custom_prefix() {
		let store = NonceStore::new("redis://localhost:6379", "my-solver", 300)
			.unwrap()
			.with_prefix("custom");
		let key = store.nonce_key("abc123");
		assert_eq!(key, "custom:my-solver:admin:nonce:abc123");
	}

	// Integration tests require Redis - run with: cargo test --features redis-tests
	#[tokio::test]
	#[ignore] // Requires Redis
	async fn test_nonce_lifecycle() {
		let solver_id = format!("test-{}", Uuid::new_v4());
		let store = NonceStore::new("redis://127.0.0.1:6379", &solver_id, 300).unwrap();

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
	#[ignore] // Requires Redis
	async fn test_invalid_nonce() {
		let solver_id = format!("test-{}", Uuid::new_v4());
		let store = NonceStore::new("redis://127.0.0.1:6379", &solver_id, 300).unwrap();

		// Random nonce that was never generated
		let result = store.consume(12345).await;
		assert!(matches!(result, Err(NonceError::NotFound)));
	}

	#[tokio::test]
	#[ignore] // Requires Redis
	async fn test_nonce_isolation_between_solvers() {
		let solver1 = format!("test-solver1-{}", Uuid::new_v4());
		let solver2 = format!("test-solver2-{}", Uuid::new_v4());

		let store1 = NonceStore::new("redis://127.0.0.1:6379", &solver1, 300).unwrap();
		let store2 = NonceStore::new("redis://127.0.0.1:6379", &solver2, 300).unwrap();

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
}
