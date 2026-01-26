//! Redis-based configuration store implementation.

use crate::config_store::{ConfigStore, ConfigStoreError};
use async_trait::async_trait;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use solver_types::Versioned;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OnceCell;
use tokio::time::timeout;
use tracing::{debug, warn};

/// Default connection timeout in milliseconds.
const DEFAULT_CONNECTION_TIMEOUT_MS: u64 = 5000;

/// Key prefix for configuration storage.
const CONFIG_KEY_PREFIX: &str = "config";

/// Redis implementation of the configuration store.
///
/// Stores configuration in Redis using JSON serialization and provides
/// optimistic locking through atomic operations with version checking.
///
/// # Key Structure
///
/// Configuration is stored under the key: `{prefix}:config:{solver_id}`
///
/// # Thread Safety
///
/// This implementation uses lazy connection initialization and is safe
/// for concurrent use from multiple tasks.
pub struct RedisConfigStore<T> {
	/// Redis connection manager (lazily initialized).
	client: OnceCell<Arc<ConnectionManager>>,
	/// Redis URL for connection.
	redis_url: String,
	/// Connection timeout in milliseconds.
	timeout_ms: u64,
	/// Solver ID for key namespacing.
	solver_id: String,
	/// Key prefix for Redis keys.
	key_prefix: String,
	/// Phantom data for type parameter.
	_phantom: std::marker::PhantomData<T>,
}

impl<T> RedisConfigStore<T>
where
	T: Serialize + for<'de> Deserialize<'de> + Send + Sync + Clone,
{
	/// Creates a new RedisConfigStore.
	///
	/// The connection is lazily initialized on first use to ensure it's
	/// created within the correct tokio runtime context.
	///
	/// # Arguments
	///
	/// * `redis_url` - Redis connection URL (e.g., "redis://localhost:6379")
	/// * `solver_id` - Unique identifier for this solver instance
	/// * `key_prefix` - Prefix for all Redis keys (default: "oif-solver")
	///
	/// # Errors
	///
	/// Returns an error if the solver_id or redis_url is empty.
	pub fn new(
		redis_url: String,
		solver_id: String,
		key_prefix: String,
	) -> Result<Self, ConfigStoreError> {
		if solver_id.is_empty() {
			return Err(ConfigStoreError::Configuration(
				"Solver ID cannot be empty".to_string(),
			));
		}

		if redis_url.is_empty() {
			return Err(ConfigStoreError::Configuration(
				"Redis URL cannot be empty".to_string(),
			));
		}

		if key_prefix.is_empty() {
			return Err(ConfigStoreError::Configuration(
				"Key prefix cannot be empty".to_string(),
			));
		}

		Ok(Self {
			client: OnceCell::new(),
			redis_url,
			timeout_ms: DEFAULT_CONNECTION_TIMEOUT_MS,
			solver_id,
			key_prefix,
			_phantom: std::marker::PhantomData,
		})
	}

	/// Creates a new RedisConfigStore with default prefix.
	pub fn with_defaults(redis_url: String, solver_id: String) -> Result<Self, ConfigStoreError> {
		Self::new(redis_url, solver_id, "oif-solver".to_string())
	}

	/// Creates a new RedisConfigStore with custom timeout.
	pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
		self.timeout_ms = timeout_ms;
		self
	}

	/// Generate the Redis key for this solver's configuration.
	fn config_key(&self) -> String {
		format!(
			"{}:{}:{}",
			self.key_prefix, CONFIG_KEY_PREFIX, self.solver_id
		)
	}

	/// Get or create the Redis connection.
	///
	/// This uses lazy initialization to ensure the connection is created
	/// within the correct tokio runtime context.
	async fn get_connection(&self) -> Result<Arc<ConnectionManager>, ConfigStoreError> {
		self.client
			.get_or_try_init(|| async {
				let client = redis::Client::open(self.redis_url.as_ref()).map_err(|e| {
					ConfigStoreError::Backend(format!("Failed to create Redis client: {}", e))
				})?;

				let manager = timeout(
					Duration::from_millis(self.timeout_ms),
					ConnectionManager::new(client),
				)
				.await
				.map_err(|_| {
					ConfigStoreError::Backend(format!(
						"Redis connection timeout ({}ms)",
						self.timeout_ms
					))
				})?
				.map_err(|e| {
					ConfigStoreError::Backend(format!("Failed to connect to Redis: {}", e))
				})?;

				Ok(Arc::new(manager))
			})
			.await
			.cloned()
	}
}

#[async_trait]
impl<T> ConfigStore<T> for RedisConfigStore<T>
where
	T: Serialize + for<'de> Deserialize<'de> + Send + Sync + Clone,
{
	async fn get(&self) -> Result<Versioned<T>, ConfigStoreError> {
		let key = self.config_key();
		let client = self.get_connection().await?;
		let mut conn = client.as_ref().clone();

		let result: Option<String> = conn.get(&key).await.map_err(|e| {
			warn!(key = %key, error = %e, "failed to get config from redis");
			ConfigStoreError::Backend(format!("Redis GET failed: {}", e))
		})?;

		match result {
			Some(json) => {
				let versioned: Versioned<T> = serde_json::from_str(&json).map_err(|e| {
					ConfigStoreError::Serialization(format!("Failed to deserialize config: {}", e))
				})?;
				debug!(key = %key, version = versioned.version, "retrieved config from redis");
				Ok(versioned)
			},
			None => {
				debug!(key = %key, "config not found in redis");
				Err(ConfigStoreError::NotFound(self.solver_id.clone()))
			},
		}
	}

	async fn seed(&self, config: T) -> Result<Versioned<T>, ConfigStoreError> {
		let key = self.config_key();
		let client = self.get_connection().await?;
		let mut conn = client.as_ref().clone();

		// Check if config already exists
		let exists: bool = conn
			.exists(&key)
			.await
			.map_err(|e| ConfigStoreError::Backend(format!("Redis EXISTS failed: {}", e)))?;

		if exists {
			return Err(ConfigStoreError::AlreadyExists(self.solver_id.clone()));
		}

		// Create versioned config
		let versioned = Versioned::new(config);
		let json = serde_json::to_string(&versioned).map_err(|e| {
			ConfigStoreError::Serialization(format!("Failed to serialize config: {}", e))
		})?;

		// Use SETNX to ensure atomicity (only set if not exists)
		let set_result: bool = conn
			.set_nx(&key, &json)
			.await
			.map_err(|e| ConfigStoreError::Backend(format!("Redis SETNX failed: {}", e)))?;

		if !set_result {
			// Race condition: another process seeded the config
			return Err(ConfigStoreError::AlreadyExists(self.solver_id.clone()));
		}

		debug!(key = %key, version = versioned.version, "seeded config to redis");
		Ok(versioned)
	}

	async fn update(
		&self,
		config: T,
		expected_version: u64,
	) -> Result<Versioned<T>, ConfigStoreError> {
		let key = self.config_key();
		let client = self.get_connection().await?;
		let mut conn = client.as_ref().clone();

		// Get current config to check version
		let current_json: Option<String> = conn
			.get(&key)
			.await
			.map_err(|e| ConfigStoreError::Backend(format!("Redis GET failed: {}", e)))?;

		let current = match current_json {
			Some(json) => {
				let versioned: Versioned<T> = serde_json::from_str(&json).map_err(|e| {
					ConfigStoreError::Serialization(format!("Failed to deserialize config: {}", e))
				})?;
				versioned
			},
			None => {
				return Err(ConfigStoreError::NotFound(self.solver_id.clone()));
			},
		};

		// Check version
		if current.version != expected_version {
			return Err(ConfigStoreError::VersionMismatch {
				expected: expected_version,
				found: current.version,
			});
		}

		// Create new versioned config
		let mut new_versioned = Versioned::new(config);
		new_versioned.version = expected_version + 1;

		let new_json = serde_json::to_string(&new_versioned).map_err(|e| {
			ConfigStoreError::Serialization(format!("Failed to serialize config: {}", e))
		})?;

		// Use atomic Lua script for compare-and-swap
		// Returns integer status codes to avoid protocol error handling issues:
		// 1 = success, 0 = version mismatch, -1 = not found
		let script = redis::Script::new(
			r#"
            local key = KEYS[1]
            local expected_version = tonumber(ARGV[1])
            local new_value = ARGV[2]

            local current = redis.call('GET', key)
            if not current then
                return -1
            end

            local current_data = cjson.decode(current)
            if current_data.version ~= expected_version then
                return current_data.version
            end

            redis.call('SET', key, new_value)
            return 1
            "#,
		);

		let result: i64 = script
			.key(&key)
			.arg(expected_version)
			.arg(&new_json)
			.invoke_async(&mut conn)
			.await
			.map_err(|e| ConfigStoreError::Backend(format!("Redis script failed: {}", e)))?;

		match result {
			1 => {
				debug!(
					key = %key,
					old_version = expected_version,
					new_version = new_versioned.version,
					"updated config in redis"
				);
				Ok(new_versioned)
			},
			-1 => Err(ConfigStoreError::NotFound(self.solver_id.clone())),
			found_version => Err(ConfigStoreError::VersionMismatch {
				expected: expected_version,
				found: found_version as u64,
			}),
		}
	}

	async fn exists(&self) -> Result<bool, ConfigStoreError> {
		let key = self.config_key();
		let client = self.get_connection().await?;
		let mut conn = client.as_ref().clone();

		let exists: bool = conn
			.exists(&key)
			.await
			.map_err(|e| ConfigStoreError::Backend(format!("Redis EXISTS failed: {}", e)))?;

		debug!(key = %key, exists, "checked if config exists in redis");
		Ok(exists)
	}

	async fn delete(&self) -> Result<(), ConfigStoreError> {
		let key = self.config_key();
		let client = self.get_connection().await?;
		let mut conn = client.as_ref().clone();

		let _deleted: i32 = conn
			.del(&key)
			.await
			.map_err(|e| ConfigStoreError::Backend(format!("Redis DEL failed: {}", e)))?;

		debug!(key = %key, "deleted config from redis");
		Ok(())
	}
}
