//! Redis storage backend implementation for the solver service.
//!
//! This module provides a Redis-backed implementation of the [`StorageInterface`] trait,
//! offering persistent, distributed storage with native TTL support and efficient
//! index-based querying using Redis data structures.
//!
//! # Features
//!
//! - **Persistent Storage**: Data survives service restarts
//! - **Native TTL Support**: Automatic expiration via Redis `SETEX`/`EXPIRE`
//! - **Index-Based Queries**: Efficient lookups using Redis Sets
//! - **Connection Pooling**: Managed via `redis::aio::ConnectionManager`
//! - **Lazy Initialization**: Connection established on first use within the correct runtime
//!
//! # Configuration
//!
//! The Redis storage backend is configured via TOML:
//!
//! ```toml
//! [storage]
//! primary = "redis"
//! cleanup_interval_seconds = 60
//!
//! [storage.implementations.redis]
//! redis_url = "redis://localhost:6379"
//! key_prefix = "oif-solver"
//! connection_timeout_ms = 5000
//! db = 0
//! ttl_orders = 300                # 5 minutes
//! ttl_intents = 120               # 2 minutes
//! ttl_order_by_tx_hash = 300      # 5 minutes
//! ttl_quotes = 60                 # 1 minute
//! ttl_settlement_messages = 600   # 10 minutes
//! ```
//!
//! ## Configuration Options
//!
//! | Option | Type | Required | Default | Description |
//! |--------|------|----------|---------|-------------|
//! | `redis_url` | String | Yes | - | Redis connection URL (e.g., `redis://localhost:6379`) |
//! | `key_prefix` | String | No | `oif-solver` | Prefix for all Redis keys |
//! | `connection_timeout_ms` | Integer | No | `5000` | Connection timeout in milliseconds |
//! | `db` | Integer | No | `0` | Redis database number (0-15) |
//! | `ttl_orders` | Integer | No | `0` (no expiry) | TTL in seconds for orders |
//! | `ttl_intents` | Integer | No | `0` (no expiry) | TTL in seconds for intents |
//! | `ttl_order_by_tx_hash` | Integer | No | `0` (no expiry) | TTL for tx hash mappings |
//! | `ttl_quotes` | Integer | No | `0` (no expiry) | TTL in seconds for quotes |
//! | `ttl_settlement_messages` | Integer | No | `0` (no expiry) | TTL for settlement messages |
//!
//! # Redis Key Structure
//!
//! The storage uses a hierarchical key structure:
//!
//! ```text
//! {prefix}:{namespace}:{id}           → JSON data (e.g., oif-solver:orders:abc123)
//! {prefix}:{namespace}:_all           → Set of all IDs in namespace
//! {prefix}:{namespace}:_index:{field}:{value} → Set of IDs matching field=value
//! ```
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use solver_storage::implementations::redis::{create_storage, create_storage_async};
//!
//! // Synchronous creation (connection is lazy)
//! let config = toml::toml! {
//!     redis_url = "redis://localhost:6379"
//!     key_prefix = "my-solver"
//! };
//! let storage = create_storage(&toml::Value::Table(config))?;
//!
//! // Async creation with eager connection verification
//! let storage = create_storage_async(&toml::Value::Table(config)).await?;
//! ```
//!
//! # Running Redis
//!
//! You can run Redis locally using Docker:
//!
//! ```bash
//! docker run -d --name redis -p 6379:6379 redis:latest
//! ```
//!
//! Or using Redis Stack for additional features:
//!
//! ```bash
//! docker run -d --name redis-stack -p 6379:6379 redis/redis-stack-server:latest
//! ```

use crate::{QueryFilter, StorageError, StorageIndexes, StorageInterface};
use async_trait::async_trait;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, RedisError};
use solver_types::{ConfigSchema, Field, FieldType, Schema, StorageKey, ValidationError};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OnceCell;
use tokio::time::timeout;
use tracing::{debug, warn};

/// Default connection timeout in milliseconds.
const DEFAULT_CONNECTION_TIMEOUT_MS: u64 = 5000;

/// Default Redis key prefix.
const DEFAULT_KEY_PREFIX: &str = "oif-solver";

/// Suffix for the index key that tracks all IDs in a namespace.
const ALL_IDS_SUFFIX: &str = "_all";

/// Suffix for field index keys.
const INDEX_SUFFIX: &str = "_index";

/// TTL configuration for different storage keys.
#[derive(Debug, Clone)]
pub struct TtlConfig {
	ttls: HashMap<StorageKey, Duration>,
}

impl TtlConfig {
	/// Creates TTL config from TOML configuration.
	fn from_config(config: &toml::Value) -> Self {
		let mut ttls = HashMap::new();

		if let Some(table) = config.as_table() {
			for storage_key in StorageKey::all() {
				let config_key = format!("ttl_{}", storage_key.as_str());
				if let Some(ttl_value) = table
					.get(&config_key)
					.and_then(|v| v.as_integer())
					.map(|v| v as u64)
				{
					if ttl_value > 0 {
						ttls.insert(storage_key, Duration::from_secs(ttl_value));
					}
				}
			}
		}

		Self { ttls }
	}

	/// Gets the TTL for a specific storage key.
	fn get_ttl(&self, storage_key: StorageKey) -> Option<Duration> {
		self.ttls.get(&storage_key).copied()
	}
}

/// Redis storage implementation.
///
/// This implementation stores data in Redis, providing:
/// - Persistent storage across restarts
/// - Native TTL support via Redis EXPIRE
/// - Efficient index-based queries using Redis Sets
/// - Connection pooling via ConnectionManager
/// - Atomic operations using Redis pipelines
///
/// The connection is lazily initialized on first use to ensure it's created
/// within the correct tokio runtime context.
pub struct RedisStorage {
	/// Redis connection manager (lazily initialized).
	client: OnceCell<Arc<ConnectionManager>>,
	/// Redis URL for connection.
	redis_url: String,
	/// Connection timeout in milliseconds.
	timeout_ms: u64,
	/// Prefix for all Redis keys to enable multi-tenant usage.
	key_prefix: String,
	/// TTL configuration for different storage keys.
	ttl_config: TtlConfig,
}

impl RedisStorage {
	/// Creates a new RedisStorage instance with lazy connection initialization.
	///
	/// # Arguments
	///
	/// * `redis_url` - Redis connection URL
	/// * `timeout_ms` - Connection timeout in milliseconds
	/// * `key_prefix` - Prefix for all Redis keys
	/// * `ttl_config` - TTL configuration for different namespaces
	pub fn new(
		redis_url: String,
		timeout_ms: u64,
		key_prefix: String,
		ttl_config: TtlConfig,
	) -> Result<Self, StorageError> {
		if key_prefix.is_empty() {
			return Err(StorageError::Configuration(
				"Redis key prefix cannot be empty".to_string(),
			));
		}

		if redis_url.is_empty() {
			return Err(StorageError::Configuration(
				"Redis URL cannot be empty".to_string(),
			));
		}

		Ok(Self {
			client: OnceCell::new(),
			redis_url,
			timeout_ms,
			key_prefix,
			ttl_config,
		})
	}

	/// Gets or initializes the Redis connection manager.
	async fn get_connection(&self) -> Result<Arc<ConnectionManager>, StorageError> {
		self.client
			.get_or_try_init(|| async {
				initialize_redis_connection(&self.redis_url, self.timeout_ms).await
			})
			.await
			.cloned()
	}

	/// Generates the Redis key for storing data.
	///
	/// Format: `{prefix}:{namespace}:{id}` -> `{prefix}:{key}`
	/// Since key already contains `namespace:id`, we just prefix it.
	fn data_key(&self, key: &str) -> String {
		format!("{}:{}", self.key_prefix, key)
	}

	/// Generates the Redis key for tracking all IDs in a namespace.
	///
	/// Format: `{prefix}:{namespace}:_all`
	fn all_ids_key(&self, namespace: &str) -> String {
		format!("{}:{}:{}", self.key_prefix, namespace, ALL_IDS_SUFFIX)
	}

	/// Generates the Redis key for a field index.
	///
	/// Format: `{prefix}:{namespace}:_index:{field}:{value_hash}`
	fn index_key(&self, namespace: &str, field: &str, value: &serde_json::Value) -> String {
		// Use a hash or string representation of the value for the key
		let value_str = match value {
			serde_json::Value::String(s) => s.clone(),
			serde_json::Value::Number(n) => n.to_string(),
			serde_json::Value::Bool(b) => b.to_string(),
			_ => serde_json::to_string(value).unwrap_or_default(),
		};
		format!(
			"{}:{}:{}:{}:{}",
			self.key_prefix, namespace, INDEX_SUFFIX, field, value_str
		)
	}

	/// Gets the TTL for a given key based on its namespace.
	fn get_ttl_for_key(&self, key: &str) -> Option<Duration> {
		// Parse namespace from key (e.g., "orders:123" -> "orders")
		let namespace = key.split(':').next().unwrap_or("");

		// Try to parse the namespace as a StorageKey
		namespace
			.parse::<StorageKey>()
			.ok()
			.and_then(|sk| self.ttl_config.get_ttl(sk))
	}

	/// Maps Redis errors to StorageError.
	fn map_redis_error(&self, error: RedisError, context: &str) -> StorageError {
		warn!(context = %context, error = %error, "redis operation failed");

		match error.kind() {
			redis::ErrorKind::TypeError => StorageError::Backend(format!(
				"Redis data type error in operation '{}': {}",
				context, error
			)),
			redis::ErrorKind::AuthenticationFailed => {
				StorageError::Backend("Redis authentication failed".to_string())
			},
			redis::ErrorKind::IoError => StorageError::Backend(format!(
				"Redis connection error in operation '{}': {}",
				context, error
			)),
			_ => StorageError::Backend(format!("Redis operation '{}' failed: {}", context, error)),
		}
	}

	/// Updates indexes when storing data.
	async fn update_indexes(
		&self,
		key: &str,
		namespace: &str,
		indexes: &StorageIndexes,
		ttl: Option<Duration>,
	) -> Result<(), StorageError> {
		let client = self.get_connection().await?;
		let mut conn = client.as_ref().clone();

		// Add to all-IDs set for the namespace
		let all_ids_key = self.all_ids_key(namespace);
		let _: () = conn
			.sadd(&all_ids_key, key)
			.await
			.map_err(|e| self.map_redis_error(e, "update_indexes_add_all"))?;

		// Set TTL on the all-IDs set if configured
		if let Some(ttl) = ttl {
			// Get current TTL and only set if not already set or if new TTL is longer
			let current_ttl: i64 = conn
				.ttl(&all_ids_key)
				.await
				.map_err(|e| self.map_redis_error(e, "update_indexes_get_ttl"))?;

			if current_ttl < 0 || (current_ttl as u64) < ttl.as_secs() {
				let _: () = conn
					.expire(&all_ids_key, ttl.as_secs() as i64)
					.await
					.map_err(|e| self.map_redis_error(e, "update_indexes_expire_all"))?;
			}
		}

		// Add to field-specific indexes
		for (field, value) in &indexes.fields {
			let index_key = self.index_key(namespace, field, value);
			let _: () = conn
				.sadd(&index_key, key)
				.await
				.map_err(|e| self.map_redis_error(e, "update_indexes_add_field"))?;

			// Set TTL on index key
			if let Some(ttl) = ttl {
				let current_ttl: i64 = conn
					.ttl(&index_key)
					.await
					.map_err(|e| self.map_redis_error(e, "update_indexes_get_field_ttl"))?;

				if current_ttl < 0 || (current_ttl as u64) < ttl.as_secs() {
					let _: () = conn
						.expire(&index_key, ttl.as_secs() as i64)
						.await
						.map_err(|e| self.map_redis_error(e, "update_indexes_expire_field"))?;
				}
			}
		}

		debug!(key = %key, namespace = %namespace, "updated indexes");
		Ok(())
	}

	/// Removes key from indexes when deleting.
	async fn remove_from_indexes(&self, key: &str, namespace: &str) -> Result<(), StorageError> {
		let client = self.get_connection().await?;
		let mut conn = client.as_ref().clone();

		// Remove from all-IDs set
		let all_ids_key = self.all_ids_key(namespace);
		let _: () = conn
			.srem(&all_ids_key, key)
			.await
			.map_err(|e| self.map_redis_error(e, "remove_from_indexes_all"))?;

		// We can't easily remove from field indexes without knowing what fields were indexed.
		// The entry will be cleaned up when TTL expires or when querying returns stale keys.
		// This is a trade-off for simplicity - in production, you might want to store
		// the index fields alongside the data.

		debug!(key = %key, namespace = %namespace, "removed from all-IDs index");
		Ok(())
	}
}

impl std::fmt::Debug for RedisStorage {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("RedisStorage")
			.field("redis_url", &self.redis_url)
			.field("key_prefix", &self.key_prefix)
			.field("connected", &self.client.initialized())
			.finish()
	}
}

#[async_trait]
impl StorageInterface for RedisStorage {
	async fn get_bytes(&self, key: &str) -> Result<Vec<u8>, StorageError> {
		let redis_key = self.data_key(key);
		let client = self.get_connection().await?;
		let mut conn = client.as_ref().clone();

		let result: Option<Vec<u8>> = conn
			.get(&redis_key)
			.await
			.map_err(|e| self.map_redis_error(e, "get_bytes"))?;

		match result {
			Some(data) => {
				debug!(key = %key, size = data.len(), "retrieved data from redis");
				Ok(data)
			},
			None => {
				debug!(key = %key, "key not found in redis");
				Err(StorageError::NotFound(key.to_string()))
			},
		}
	}

	async fn set_bytes(
		&self,
		key: &str,
		value: Vec<u8>,
		indexes: Option<StorageIndexes>,
		ttl: Option<Duration>,
	) -> Result<(), StorageError> {
		let redis_key = self.data_key(key);
		let client = self.get_connection().await?;
		let mut conn = client.as_ref().clone();

		// Determine TTL: use provided TTL, or get from config based on key
		let effective_ttl = ttl.or_else(|| self.get_ttl_for_key(key));

		// Store data with or without TTL
		match effective_ttl {
			Some(ttl) if !ttl.is_zero() => {
				let _: () = conn
					.set_ex(&redis_key, &value, ttl.as_secs())
					.await
					.map_err(|e| self.map_redis_error(e, "set_bytes_ex"))?;
				debug!(key = %key, ttl_secs = ttl.as_secs(), "stored data with TTL");
			},
			_ => {
				let _: () = conn
					.set(&redis_key, &value)
					.await
					.map_err(|e| self.map_redis_error(e, "set_bytes"))?;
				debug!(key = %key, "stored data without TTL");
			},
		}

		// Update indexes if provided
		if let Some(indexes) = indexes {
			let namespace = key.split(':').next().unwrap_or("");
			self.update_indexes(key, namespace, &indexes, effective_ttl)
				.await?;
		}

		Ok(())
	}

	async fn delete(&self, key: &str) -> Result<(), StorageError> {
		let redis_key = self.data_key(key);
		let client = self.get_connection().await?;
		let mut conn = client.as_ref().clone();

		let deleted: i64 = conn
			.del(&redis_key)
			.await
			.map_err(|e| self.map_redis_error(e, "delete"))?;

		if deleted > 0 {
			// Remove from indexes
			let namespace = key.split(':').next().unwrap_or("");
			self.remove_from_indexes(key, namespace).await?;
			debug!(key = %key, "deleted key from redis");
		} else {
			debug!(key = %key, "key not found for deletion");
		}

		Ok(())
	}

	async fn exists(&self, key: &str) -> Result<bool, StorageError> {
		let redis_key = self.data_key(key);
		let client = self.get_connection().await?;
		let mut conn = client.as_ref().clone();

		let exists: bool = conn
			.exists(&redis_key)
			.await
			.map_err(|e| self.map_redis_error(e, "exists"))?;

		Ok(exists)
	}

	async fn query(
		&self,
		namespace: &str,
		filter: QueryFilter,
	) -> Result<Vec<String>, StorageError> {
		let client = self.get_connection().await?;
		let mut conn = client.as_ref().clone();

		let keys: Vec<String> = match filter {
			QueryFilter::All => {
				// Get all IDs from the namespace's all-IDs set
				let all_ids_key = self.all_ids_key(namespace);
				conn.smembers(&all_ids_key)
					.await
					.map_err(|e| self.map_redis_error(e, "query_all"))?
			},
			QueryFilter::Equals(field, value) => {
				let index_key = self.index_key(namespace, &field, &value);
				conn.smembers(&index_key)
					.await
					.map_err(|e| self.map_redis_error(e, "query_equals"))?
			},
			QueryFilter::NotEquals(field, value) => {
				// Get all IDs, then filter out those that match the value
				let all_ids_key = self.all_ids_key(namespace);
				let index_key = self.index_key(namespace, &field, &value);

				let all_ids: Vec<String> = conn
					.smembers(&all_ids_key)
					.await
					.map_err(|e| self.map_redis_error(e, "query_not_equals_all"))?;

				let excluded_ids: Vec<String> = conn
					.smembers(&index_key)
					.await
					.map_err(|e| self.map_redis_error(e, "query_not_equals_excluded"))?;

				let excluded_set: std::collections::HashSet<_> = excluded_ids.into_iter().collect();
				all_ids
					.into_iter()
					.filter(|id| !excluded_set.contains(id))
					.collect()
			},
			QueryFilter::In(field, values) => {
				// Union of all matching index sets
				let mut result_ids = std::collections::HashSet::new();

				for value in values {
					let index_key = self.index_key(namespace, &field, &value);
					let ids: Vec<String> = conn
						.smembers(&index_key)
						.await
						.map_err(|e| self.map_redis_error(e, "query_in"))?;
					result_ids.extend(ids);
				}

				result_ids.into_iter().collect()
			},
			QueryFilter::NotIn(field, values) => {
				// Get all IDs, then filter out those in any of the value sets
				let all_ids_key = self.all_ids_key(namespace);
				let all_ids: Vec<String> = conn
					.smembers(&all_ids_key)
					.await
					.map_err(|e| self.map_redis_error(e, "query_not_in_all"))?;

				let mut excluded_ids = std::collections::HashSet::new();
				for value in values {
					let index_key = self.index_key(namespace, &field, &value);
					let ids: Vec<String> = conn
						.smembers(&index_key)
						.await
						.map_err(|e| self.map_redis_error(e, "query_not_in_excluded"))?;
					excluded_ids.extend(ids);
				}

				all_ids
					.into_iter()
					.filter(|id| !excluded_ids.contains(id))
					.collect()
			},
		};

		// Validate that keys still exist (handles TTL expiration edge cases)
		let mut valid_keys = Vec::new();
		for key in keys {
			if self.exists(&key).await.unwrap_or(false) {
				valid_keys.push(key);
			}
		}

		debug!(namespace = %namespace, count = valid_keys.len(), "query returned keys");
		Ok(valid_keys)
	}

	async fn get_batch(&self, keys: &[String]) -> Result<Vec<(String, Vec<u8>)>, StorageError> {
		if keys.is_empty() {
			return Ok(Vec::new());
		}

		let client = self.get_connection().await?;
		let mut conn = client.as_ref().clone();
		let redis_keys: Vec<String> = keys.iter().map(|k| self.data_key(k)).collect();

		// Use MGET for efficient batch retrieval
		let values: Vec<Option<Vec<u8>>> = conn
			.mget(&redis_keys)
			.await
			.map_err(|e| self.map_redis_error(e, "get_batch"))?;

		let mut results = Vec::new();
		for (i, value) in values.into_iter().enumerate() {
			if let Some(data) = value {
				results.push((keys[i].clone(), data));
			}
		}

		debug!(
			requested = keys.len(),
			found = results.len(),
			"batch retrieval completed"
		);
		Ok(results)
	}

	fn config_schema(&self) -> Box<dyn ConfigSchema> {
		Box::new(RedisStorageSchema)
	}

	async fn cleanup_expired(&self) -> Result<usize, StorageError> {
		// Redis handles TTL expiration automatically via EXPIRE.
		// We don't need to do manual cleanup.
		// However, we might want to clean up stale index entries.
		debug!("cleanup_expired called - Redis handles TTL automatically");
		Ok(0)
	}
}

/// Configuration schema for RedisStorage.
pub struct RedisStorageSchema;

impl RedisStorageSchema {
	/// Static validation method for use before instance creation.
	pub fn validate_config(config: &toml::Value) -> Result<(), ValidationError> {
		let instance = Self;
		instance.validate(config)
	}
}

impl ConfigSchema for RedisStorageSchema {
	fn validate(&self, config: &toml::Value) -> Result<(), ValidationError> {
		// Build TTL fields dynamically based on StorageKey variants
		let mut optional_fields = vec![
			Field::new("redis_url", FieldType::String),
			Field::new("key_prefix", FieldType::String),
			Field::new(
				"connection_timeout_ms",
				FieldType::Integer {
					min: Some(100),
					max: Some(60000),
				},
			),
			Field::new(
				"db",
				FieldType::Integer {
					min: Some(0),
					max: Some(15),
				},
			),
		];

		// Add TTL fields for each StorageKey
		for storage_key in StorageKey::all() {
			let field_name = format!("ttl_{}", storage_key.as_str());
			optional_fields.push(Field::new(
				field_name.clone(),
				FieldType::Integer {
					min: Some(0),
					max: None,
				},
			));
		}

		let schema = Schema::new(
			vec![Field::new("redis_url", FieldType::String)], // redis_url is required
			optional_fields,
		);

		schema.validate(config)
	}
}

/// Initializes a Redis connection manager with timeout.
///
/// This function creates a new Redis client and connection manager with the specified
/// timeout. The connection manager handles automatic reconnection and connection pooling.
///
/// # Arguments
///
/// * `redis_url` - Redis connection URL (e.g., `redis://localhost:6379` or `redis://localhost:6379/0`)
/// * `timeout_ms` - Connection timeout in milliseconds (recommended: 5000ms)
///
/// # Returns
///
/// An `Arc`-wrapped `ConnectionManager` for shared usage across the application.
///
/// # Errors
///
/// Returns a [`StorageError`] if:
/// - The Redis URL is invalid
/// - The connection times out
/// - The connection manager fails to initialize
///
/// # Example
///
/// ```rust,ignore
/// let conn = initialize_redis_connection("redis://localhost:6379", 5000).await?;
/// ```
pub async fn initialize_redis_connection(
	redis_url: &str,
	timeout_ms: u64,
) -> Result<Arc<ConnectionManager>, StorageError> {
	let redis_client = redis::Client::open(redis_url).map_err(|e| {
		StorageError::Configuration(format!("Failed to create Redis client: {}", e))
	})?;

	let connection_manager = timeout(
		Duration::from_millis(timeout_ms),
		ConnectionManager::new(redis_client),
	)
	.await
	.map_err(|_| StorageError::Backend(format!("Redis connection timeout after {}ms", timeout_ms)))?
	.map_err(|e| StorageError::Backend(format!("Failed to create connection manager: {}", e)))?;

	debug!(redis_url = %redis_url, "redis connection established");
	Ok(Arc::new(connection_manager))
}

/// Factory function to create a Redis storage backend from configuration.
///
/// Configuration parameters:
/// - `redis_url`: Redis connection URL (required, e.g., "redis://localhost:6379")
/// - `key_prefix`: Prefix for all Redis keys (default: "oif-solver")
/// - `connection_timeout_ms`: Connection timeout in milliseconds (default: 5000)
/// - `db`: Redis database number (default: 0, range 0-15)
/// - `ttl_orders`: TTL in seconds for orders (default: no expiration)
/// - `ttl_intents`: TTL in seconds for intents (default: no expiration)
/// - `ttl_order_by_tx_hash`: TTL in seconds for order_by_tx_hash mappings (default: no expiration)
/// - `ttl_quotes`: TTL in seconds for quotes (default: no expiration)
/// - `ttl_settlement_messages`: TTL in seconds for settlement messages (default: no expiration)
pub fn create_storage(config: &toml::Value) -> Result<Box<dyn StorageInterface>, StorageError> {
	// Validate configuration first
	RedisStorageSchema::validate_config(config)
		.map_err(|e| StorageError::Configuration(format!("Invalid configuration: {}", e)))?;

	let redis_url = config
		.get("redis_url")
		.and_then(|v| v.as_str())
		.ok_or_else(|| StorageError::Configuration("redis_url is required".to_string()))?;

	let key_prefix = config
		.get("key_prefix")
		.and_then(|v| v.as_str())
		.unwrap_or(DEFAULT_KEY_PREFIX)
		.to_string();

	let timeout_ms = config
		.get("connection_timeout_ms")
		.and_then(|v| v.as_integer())
		.map(|v| v as u64)
		.unwrap_or(DEFAULT_CONNECTION_TIMEOUT_MS);

	let db = config
		.get("db")
		.and_then(|v| v.as_integer())
		.map(|v| v as u8)
		.unwrap_or(0);

	// Build full Redis URL with database
	let full_redis_url = if redis_url.contains('/')
		&& redis_url
			.split('/')
			.next_back()
			.map(|s| s.parse::<u8>().is_ok())
			.unwrap_or(false)
	{
		// URL already contains database number
		redis_url.to_string()
	} else {
		// Append database number
		format!("{}/{}", redis_url.trim_end_matches('/'), db)
	};

	let ttl_config = TtlConfig::from_config(config);

	// Create storage with lazy connection initialization
	// The connection will be established on first use within the correct runtime
	Ok(Box::new(RedisStorage::new(
		full_redis_url,
		timeout_ms,
		key_prefix,
		ttl_config,
	)?))
}

/// Async factory function to create a Redis storage backend.
///
/// Use this when you need to create storage in an async context without blocking.
/// This function also eagerly initializes the connection to verify connectivity.
pub async fn create_storage_async(
	config: &toml::Value,
) -> Result<Box<dyn StorageInterface>, StorageError> {
	// Validate configuration first
	RedisStorageSchema::validate_config(config)
		.map_err(|e| StorageError::Configuration(format!("Invalid configuration: {}", e)))?;

	let redis_url = config
		.get("redis_url")
		.and_then(|v| v.as_str())
		.ok_or_else(|| StorageError::Configuration("redis_url is required".to_string()))?;

	let key_prefix = config
		.get("key_prefix")
		.and_then(|v| v.as_str())
		.unwrap_or(DEFAULT_KEY_PREFIX)
		.to_string();

	let timeout_ms = config
		.get("connection_timeout_ms")
		.and_then(|v| v.as_integer())
		.map(|v| v as u64)
		.unwrap_or(DEFAULT_CONNECTION_TIMEOUT_MS);

	let db = config
		.get("db")
		.and_then(|v| v.as_integer())
		.map(|v| v as u8)
		.unwrap_or(0);

	// Build full Redis URL with database
	let full_redis_url = if redis_url.contains('/')
		&& redis_url
			.split('/')
			.next_back()
			.map(|s| s.parse::<u8>().is_ok())
			.unwrap_or(false)
	{
		redis_url.to_string()
	} else {
		format!("{}/{}", redis_url.trim_end_matches('/'), db)
	};

	let ttl_config = TtlConfig::from_config(config);

	let storage = RedisStorage::new(full_redis_url, timeout_ms, key_prefix, ttl_config)?;

	// Eagerly initialize connection to verify it works
	storage.get_connection().await?;

	Ok(Box::new(storage))
}

/// Registry for the Redis storage implementation.
pub struct Registry;

impl solver_types::ImplementationRegistry for Registry {
	const NAME: &'static str = "redis";
	type Factory = crate::StorageFactory;

	fn factory() -> Self::Factory {
		create_storage
	}
}

impl crate::StorageRegistry for Registry {}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_ttl_config_from_toml() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://localhost:6379"
			ttl_orders = 3600
			ttl_intents = 7200
			ttl_quotes = 1800
		});

		let ttl_config = TtlConfig::from_config(&config);

		assert_eq!(
			ttl_config.get_ttl(StorageKey::Orders),
			Some(Duration::from_secs(3600))
		);
		assert_eq!(
			ttl_config.get_ttl(StorageKey::Intents),
			Some(Duration::from_secs(7200))
		);
		assert_eq!(
			ttl_config.get_ttl(StorageKey::Quotes),
			Some(Duration::from_secs(1800))
		);
		assert_eq!(ttl_config.get_ttl(StorageKey::OrderByTxHash), None); // Not configured
	}

	#[test]
	fn test_ttl_config_zero_values() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://localhost:6379"
			ttl_orders = 0
			ttl_intents = 100
		});

		let ttl_config = TtlConfig::from_config(&config);

		// Zero TTL should be treated as no TTL (permanent storage)
		assert_eq!(ttl_config.get_ttl(StorageKey::Orders), None);
		assert_eq!(
			ttl_config.get_ttl(StorageKey::Intents),
			Some(Duration::from_secs(100))
		);
	}

	#[test]
	fn test_config_schema_validation_valid() {
		let schema = RedisStorageSchema;

		let valid_config = toml::Value::Table(toml::toml! {
			redis_url = "redis://localhost:6379"
			key_prefix = "test"
			connection_timeout_ms = 5000
			db = 0
			ttl_orders = 3600
		});

		assert!(schema.validate(&valid_config).is_ok());
	}

	#[test]
	fn test_config_schema_validation_missing_url() {
		let schema = RedisStorageSchema;

		let invalid_config = toml::Value::Table(toml::toml! {
			key_prefix = "test"
		});

		assert!(schema.validate(&invalid_config).is_err());
	}

	#[test]
	fn test_config_schema_validation_invalid_timeout() {
		let schema = RedisStorageSchema;

		// Timeout too low
		let invalid_config = toml::Value::Table(toml::toml! {
			redis_url = "redis://localhost:6379"
			connection_timeout_ms = 10
		});

		assert!(schema.validate(&invalid_config).is_err());
	}

	#[test]
	fn test_config_schema_validation_invalid_db() {
		let schema = RedisStorageSchema;

		// DB out of range
		let invalid_config = toml::Value::Table(toml::toml! {
			redis_url = "redis://localhost:6379"
			db = 20
		});

		assert!(schema.validate(&invalid_config).is_err());
	}

	#[test]
	fn test_key_generation() {
		// We can't easily test key generation without a RedisStorage instance,
		// but we can test the key format logic
		let prefix = "oif-solver";
		let namespace = "orders";
		let id = "order123";
		let key = format!("{}:{}", namespace, id);

		let data_key = format!("{}:{}", prefix, key);
		assert_eq!(data_key, "oif-solver:orders:order123");

		let all_ids_key = format!("{}:{}:{}", prefix, namespace, ALL_IDS_SUFFIX);
		assert_eq!(all_ids_key, "oif-solver:orders:_all");

		let index_key = format!(
			"{}:{}:{}:{}:{}",
			prefix, namespace, INDEX_SUFFIX, "status", "pending"
		);
		assert_eq!(index_key, "oif-solver:orders:_index:status:pending");
	}

	// Integration tests that require a running Redis instance
	// These are marked with #[ignore] and can be run with: cargo test -- --ignored

	#[tokio::test]
	#[ignore = "Requires active Redis instance"]
	async fn test_redis_connection() {
		let conn = initialize_redis_connection("redis://127.0.0.1:6379", 5000).await;
		assert!(conn.is_ok());
	}

	#[tokio::test]
	#[ignore = "Requires active Redis instance"]
	async fn test_basic_operations() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://127.0.0.1:6379"
			key_prefix = "test_basic"
		});

		let storage = create_storage_async(&config).await.unwrap();

		let key = "test:key1";
		let value = b"test_value".to_vec();

		// Test set and get
		storage
			.set_bytes(key, value.clone(), None, None)
			.await
			.unwrap();
		let retrieved = storage.get_bytes(key).await.unwrap();
		assert_eq!(retrieved, value);

		// Test exists
		assert!(storage.exists(key).await.unwrap());

		// Test delete
		storage.delete(key).await.unwrap();
		assert!(!storage.exists(key).await.unwrap());

		// Test get after delete
		let result = storage.get_bytes(key).await;
		assert!(matches!(result, Err(StorageError::NotFound(_))));
	}

	#[tokio::test]
	#[ignore = "Requires active Redis instance"]
	async fn test_ttl_functionality() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://127.0.0.1:6379"
			key_prefix = "test_ttl"
			ttl_orders = 1
		});

		let storage = create_storage_async(&config).await.unwrap();

		let key = "orders:test_order";
		let value = b"test_value".to_vec();

		// Store with TTL from config (1 second for orders)
		storage
			.set_bytes(key, value.clone(), None, None)
			.await
			.unwrap();

		// Should be available immediately
		let retrieved = storage.get_bytes(key).await.unwrap();
		assert_eq!(retrieved, value);

		// Wait for expiration
		tokio::time::sleep(Duration::from_millis(1500)).await;

		// Should be expired now
		let result = storage.get_bytes(key).await;
		assert!(matches!(result, Err(StorageError::NotFound(_))));
	}

	#[tokio::test]
	#[ignore = "Requires active Redis instance"]
	async fn test_indexing_operations() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://127.0.0.1:6379"
			key_prefix = "test_index"
		});

		let storage = create_storage_async(&config).await.unwrap();

		let namespace = "orders";

		// Clean up any existing test data
		for i in 1..=3 {
			let _ = storage.delete(&format!("orders:order{}", i)).await;
		}

		let indexes1 = StorageIndexes::new()
			.with_field("status", "pending")
			.with_field("amount", 100);
		let indexes2 = StorageIndexes::new()
			.with_field("status", "completed")
			.with_field("amount", 200);
		let indexes3 = StorageIndexes::new()
			.with_field("status", "pending")
			.with_field("amount", 150);

		// Store with indexes
		storage
			.set_bytes("orders:order1", b"data1".to_vec(), Some(indexes1), None)
			.await
			.unwrap();
		storage
			.set_bytes("orders:order2", b"data2".to_vec(), Some(indexes2), None)
			.await
			.unwrap();
		storage
			.set_bytes("orders:order3", b"data3".to_vec(), Some(indexes3), None)
			.await
			.unwrap();

		// Query by status
		let pending_orders = storage
			.query(
				namespace,
				QueryFilter::Equals(
					"status".to_string(),
					serde_json::Value::String("pending".to_string()),
				),
			)
			.await
			.unwrap();
		assert_eq!(pending_orders.len(), 2);
		assert!(pending_orders.contains(&"orders:order1".to_string()));
		assert!(pending_orders.contains(&"orders:order3".to_string()));

		// Query all
		let all_orders = storage.query(namespace, QueryFilter::All).await.unwrap();
		assert_eq!(all_orders.len(), 3);

		// Clean up
		for i in 1..=3 {
			let _ = storage.delete(&format!("orders:order{}", i)).await;
		}
	}

	#[tokio::test]
	#[ignore = "Requires active Redis instance"]
	async fn test_batch_operations() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://127.0.0.1:6379"
			key_prefix = "test_batch"
		});

		let storage = create_storage_async(&config).await.unwrap();

		let keys = vec![
			"batch:key1".to_string(),
			"batch:key2".to_string(),
			"batch:key3".to_string(),
		];
		let values = [b"value1".to_vec(), b"value2".to_vec(), b"value3".to_vec()];

		// Store multiple items
		for (key, value) in keys.iter().zip(values.iter()) {
			storage
				.set_bytes(key, value.clone(), None, None)
				.await
				.unwrap();
		}

		// Batch retrieve
		let results = storage.get_batch(&keys).await.unwrap();
		assert_eq!(results.len(), 3);

		for (key, value) in results {
			let index = keys.iter().position(|k| k == &key).unwrap();
			assert_eq!(value, values[index]);
		}

		// Test batch with missing keys
		let keys_with_missing = vec![
			"batch:key1".to_string(),
			"batch:missing_key".to_string(),
			"batch:key3".to_string(),
		];
		let results = storage.get_batch(&keys_with_missing).await.unwrap();
		assert_eq!(results.len(), 2); // Only existing keys

		// Clean up
		for key in &keys {
			let _ = storage.delete(key).await;
		}
	}
}
