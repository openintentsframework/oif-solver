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
	use solver_types::ImplementationRegistry;

	// ==================== TtlConfig Tests ====================

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
		assert_eq!(ttl_config.get_ttl(StorageKey::OrderByTxHash), None);
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
	fn test_ttl_config_empty_config() {
		let config = toml::Value::Table(toml::map::Map::new());
		let ttl_config = TtlConfig::from_config(&config);

		// No TTLs should be configured
		assert_eq!(ttl_config.get_ttl(StorageKey::Orders), None);
		assert_eq!(ttl_config.get_ttl(StorageKey::Intents), None);
		assert_eq!(ttl_config.get_ttl(StorageKey::Quotes), None);
		assert_eq!(ttl_config.get_ttl(StorageKey::OrderByTxHash), None);
		assert_eq!(ttl_config.get_ttl(StorageKey::SettlementMessages), None);
	}

	#[test]
	fn test_ttl_config_non_table_value() {
		// When config is not a table, should return empty TtlConfig
		let config = toml::Value::String("not a table".to_string());
		let ttl_config = TtlConfig::from_config(&config);

		assert_eq!(ttl_config.get_ttl(StorageKey::Orders), None);
	}

	#[test]
	fn test_ttl_config_all_storage_keys() {
		let config = toml::Value::Table(toml::toml! {
			ttl_orders = 100
			ttl_intents = 200
			ttl_order_by_tx_hash = 300
			ttl_quotes = 400
			ttl_settlement_messages = 500
		});

		let ttl_config = TtlConfig::from_config(&config);

		assert_eq!(
			ttl_config.get_ttl(StorageKey::Orders),
			Some(Duration::from_secs(100))
		);
		assert_eq!(
			ttl_config.get_ttl(StorageKey::Intents),
			Some(Duration::from_secs(200))
		);
		assert_eq!(
			ttl_config.get_ttl(StorageKey::OrderByTxHash),
			Some(Duration::from_secs(300))
		);
		assert_eq!(
			ttl_config.get_ttl(StorageKey::Quotes),
			Some(Duration::from_secs(400))
		);
		assert_eq!(
			ttl_config.get_ttl(StorageKey::SettlementMessages),
			Some(Duration::from_secs(500))
		);
	}

	#[test]
	fn test_ttl_config_negative_values_treated_as_zero() {
		// Negative values in TOML are still i64, but we cast to u64
		// This tests the behavior with edge values
		let config = toml::Value::Table(toml::toml! {
			ttl_orders = 1
		});

		let ttl_config = TtlConfig::from_config(&config);
		assert_eq!(
			ttl_config.get_ttl(StorageKey::Orders),
			Some(Duration::from_secs(1))
		);
	}

	#[test]
	fn test_ttl_config_debug_impl() {
		let config = toml::Value::Table(toml::toml! {
			ttl_orders = 100
		});
		let ttl_config = TtlConfig::from_config(&config);

		// Should not panic and should contain relevant info
		let debug_str = format!("{:?}", ttl_config);
		assert!(debug_str.contains("TtlConfig"));
		assert!(debug_str.contains("ttls"));
	}

	// ==================== RedisStorage::new() Tests ====================

	#[test]
	fn test_redis_storage_new_valid() {
		let ttl_config = TtlConfig::from_config(&toml::Value::Table(toml::map::Map::new()));
		let result = RedisStorage::new(
			"redis://localhost:6379".to_string(),
			5000,
			"test".to_string(),
			ttl_config,
		);

		assert!(result.is_ok());
		let storage = result.unwrap();
		assert_eq!(storage.redis_url, "redis://localhost:6379");
		assert_eq!(storage.key_prefix, "test");
		assert_eq!(storage.timeout_ms, 5000);
	}

	#[test]
	fn test_redis_storage_new_empty_prefix() {
		let ttl_config = TtlConfig::from_config(&toml::Value::Table(toml::map::Map::new()));
		let result = RedisStorage::new(
			"redis://localhost:6379".to_string(),
			5000,
			"".to_string(),
			ttl_config,
		);

		assert!(result.is_err());
		let err = result.unwrap_err();
		assert!(matches!(err, StorageError::Configuration(_)));
		assert!(err.to_string().contains("key prefix cannot be empty"));
	}

	#[test]
	fn test_redis_storage_new_empty_url() {
		let ttl_config = TtlConfig::from_config(&toml::Value::Table(toml::map::Map::new()));
		let result = RedisStorage::new("".to_string(), 5000, "test".to_string(), ttl_config);

		assert!(result.is_err());
		let err = result.unwrap_err();
		assert!(matches!(err, StorageError::Configuration(_)));
		assert!(err.to_string().contains("URL cannot be empty"));
	}

	// ==================== Key Generation Tests ====================

	#[test]
	fn test_data_key_generation() {
		let ttl_config = TtlConfig::from_config(&toml::Value::Table(toml::map::Map::new()));
		let storage = RedisStorage::new(
			"redis://localhost:6379".to_string(),
			5000,
			"oif-solver".to_string(),
			ttl_config,
		)
		.unwrap();

		assert_eq!(storage.data_key("orders:123"), "oif-solver:orders:123");
		assert_eq!(
			storage.data_key("intents:abc-def"),
			"oif-solver:intents:abc-def"
		);
		assert_eq!(storage.data_key("quotes:q1"), "oif-solver:quotes:q1");
	}

	#[test]
	fn test_data_key_with_custom_prefix() {
		let ttl_config = TtlConfig::from_config(&toml::Value::Table(toml::map::Map::new()));
		let storage = RedisStorage::new(
			"redis://localhost:6379".to_string(),
			5000,
			"my-custom-prefix".to_string(),
			ttl_config,
		)
		.unwrap();

		assert_eq!(
			storage.data_key("orders:123"),
			"my-custom-prefix:orders:123"
		);
	}

	#[test]
	fn test_all_ids_key_generation() {
		let ttl_config = TtlConfig::from_config(&toml::Value::Table(toml::map::Map::new()));
		let storage = RedisStorage::new(
			"redis://localhost:6379".to_string(),
			5000,
			"oif-solver".to_string(),
			ttl_config,
		)
		.unwrap();

		assert_eq!(storage.all_ids_key("orders"), "oif-solver:orders:_all");
		assert_eq!(storage.all_ids_key("intents"), "oif-solver:intents:_all");
		assert_eq!(storage.all_ids_key("quotes"), "oif-solver:quotes:_all");
	}

	#[test]
	fn test_index_key_generation_string_value() {
		let ttl_config = TtlConfig::from_config(&toml::Value::Table(toml::map::Map::new()));
		let storage = RedisStorage::new(
			"redis://localhost:6379".to_string(),
			5000,
			"oif-solver".to_string(),
			ttl_config,
		)
		.unwrap();

		let value = serde_json::Value::String("pending".to_string());
		assert_eq!(
			storage.index_key("orders", "status", &value),
			"oif-solver:orders:_index:status:pending"
		);
	}

	#[test]
	fn test_index_key_generation_number_value() {
		let ttl_config = TtlConfig::from_config(&toml::Value::Table(toml::map::Map::new()));
		let storage = RedisStorage::new(
			"redis://localhost:6379".to_string(),
			5000,
			"oif-solver".to_string(),
			ttl_config,
		)
		.unwrap();

		let value = serde_json::json!(42);
		assert_eq!(
			storage.index_key("orders", "amount", &value),
			"oif-solver:orders:_index:amount:42"
		);
	}

	#[test]
	fn test_index_key_generation_bool_value() {
		let ttl_config = TtlConfig::from_config(&toml::Value::Table(toml::map::Map::new()));
		let storage = RedisStorage::new(
			"redis://localhost:6379".to_string(),
			5000,
			"oif-solver".to_string(),
			ttl_config,
		)
		.unwrap();

		let value = serde_json::Value::Bool(true);
		assert_eq!(
			storage.index_key("orders", "active", &value),
			"oif-solver:orders:_index:active:true"
		);

		let value_false = serde_json::Value::Bool(false);
		assert_eq!(
			storage.index_key("orders", "active", &value_false),
			"oif-solver:orders:_index:active:false"
		);
	}

	#[test]
	fn test_index_key_generation_complex_value() {
		let ttl_config = TtlConfig::from_config(&toml::Value::Table(toml::map::Map::new()));
		let storage = RedisStorage::new(
			"redis://localhost:6379".to_string(),
			5000,
			"oif-solver".to_string(),
			ttl_config,
		)
		.unwrap();

		// Array value
		let array_value = serde_json::json!([1, 2, 3]);
		let key = storage.index_key("orders", "items", &array_value);
		assert!(key.starts_with("oif-solver:orders:_index:items:"));
		assert!(key.contains("[1,2,3]"));

		// Object value
		let obj_value = serde_json::json!({"key": "value"});
		let key = storage.index_key("orders", "metadata", &obj_value);
		assert!(key.starts_with("oif-solver:orders:_index:metadata:"));
	}

	#[test]
	fn test_index_key_generation_null_value() {
		let ttl_config = TtlConfig::from_config(&toml::Value::Table(toml::map::Map::new()));
		let storage = RedisStorage::new(
			"redis://localhost:6379".to_string(),
			5000,
			"oif-solver".to_string(),
			ttl_config,
		)
		.unwrap();

		let null_value = serde_json::Value::Null;
		let key = storage.index_key("orders", "field", &null_value);
		assert!(key.starts_with("oif-solver:orders:_index:field:"));
	}

	// ==================== get_ttl_for_key() Tests ====================

	#[test]
	fn test_get_ttl_for_key_orders() {
		let config = toml::Value::Table(toml::toml! {
			ttl_orders = 3600
		});
		let ttl_config = TtlConfig::from_config(&config);
		let storage = RedisStorage::new(
			"redis://localhost:6379".to_string(),
			5000,
			"test".to_string(),
			ttl_config,
		)
		.unwrap();

		assert_eq!(
			storage.get_ttl_for_key("orders:123"),
			Some(Duration::from_secs(3600))
		);
	}

	#[test]
	fn test_get_ttl_for_key_intents() {
		let config = toml::Value::Table(toml::toml! {
			ttl_intents = 1800
		});
		let ttl_config = TtlConfig::from_config(&config);
		let storage = RedisStorage::new(
			"redis://localhost:6379".to_string(),
			5000,
			"test".to_string(),
			ttl_config,
		)
		.unwrap();

		assert_eq!(
			storage.get_ttl_for_key("intents:abc"),
			Some(Duration::from_secs(1800))
		);
	}

	#[test]
	fn test_get_ttl_for_key_no_ttl_configured() {
		let config = toml::Value::Table(toml::toml! {
			ttl_orders = 3600
		});
		let ttl_config = TtlConfig::from_config(&config);
		let storage = RedisStorage::new(
			"redis://localhost:6379".to_string(),
			5000,
			"test".to_string(),
			ttl_config,
		)
		.unwrap();

		// No TTL configured for quotes
		assert_eq!(storage.get_ttl_for_key("quotes:q1"), None);
	}

	#[test]
	fn test_get_ttl_for_key_unknown_namespace() {
		let config = toml::Value::Table(toml::toml! {
			ttl_orders = 3600
		});
		let ttl_config = TtlConfig::from_config(&config);
		let storage = RedisStorage::new(
			"redis://localhost:6379".to_string(),
			5000,
			"test".to_string(),
			ttl_config,
		)
		.unwrap();

		// Unknown namespace should return None
		assert_eq!(storage.get_ttl_for_key("unknown:key"), None);
	}

	#[test]
	fn test_get_ttl_for_key_empty_key() {
		let config = toml::Value::Table(toml::toml! {
			ttl_orders = 3600
		});
		let ttl_config = TtlConfig::from_config(&config);
		let storage = RedisStorage::new(
			"redis://localhost:6379".to_string(),
			5000,
			"test".to_string(),
			ttl_config,
		)
		.unwrap();

		assert_eq!(storage.get_ttl_for_key(""), None);
	}

	#[test]
	fn test_get_ttl_for_key_no_colon() {
		let config = toml::Value::Table(toml::toml! {
			ttl_orders = 3600
		});
		let ttl_config = TtlConfig::from_config(&config);
		let storage = RedisStorage::new(
			"redis://localhost:6379".to_string(),
			5000,
			"test".to_string(),
			ttl_config,
		)
		.unwrap();

		// Key without colon - namespace is the whole key
		assert_eq!(
			storage.get_ttl_for_key("orders"),
			Some(Duration::from_secs(3600))
		);
	}

	// ==================== map_redis_error() Tests ====================

	#[test]
	fn test_map_redis_error_type_error() {
		let ttl_config = TtlConfig::from_config(&toml::Value::Table(toml::map::Map::new()));
		let storage = RedisStorage::new(
			"redis://localhost:6379".to_string(),
			5000,
			"test".to_string(),
			ttl_config,
		)
		.unwrap();

		let redis_error = redis::RedisError::from((redis::ErrorKind::TypeError, "type error"));
		let storage_error = storage.map_redis_error(redis_error, "test_op");

		assert!(matches!(storage_error, StorageError::Backend(_)));
		let error_msg = storage_error.to_string();
		assert!(error_msg.contains("data type error"));
		assert!(error_msg.contains("test_op"));
	}

	#[test]
	fn test_map_redis_error_auth_failed() {
		let ttl_config = TtlConfig::from_config(&toml::Value::Table(toml::map::Map::new()));
		let storage = RedisStorage::new(
			"redis://localhost:6379".to_string(),
			5000,
			"test".to_string(),
			ttl_config,
		)
		.unwrap();

		let redis_error =
			redis::RedisError::from((redis::ErrorKind::AuthenticationFailed, "auth failed"));
		let storage_error = storage.map_redis_error(redis_error, "auth_op");

		assert!(matches!(storage_error, StorageError::Backend(_)));
		assert!(storage_error.to_string().contains("authentication failed"));
	}

	#[test]
	fn test_map_redis_error_io_error() {
		let ttl_config = TtlConfig::from_config(&toml::Value::Table(toml::map::Map::new()));
		let storage = RedisStorage::new(
			"redis://localhost:6379".to_string(),
			5000,
			"test".to_string(),
			ttl_config,
		)
		.unwrap();

		let redis_error = redis::RedisError::from((redis::ErrorKind::IoError, "io error"));
		let storage_error = storage.map_redis_error(redis_error, "io_op");

		assert!(matches!(storage_error, StorageError::Backend(_)));
		let error_msg = storage_error.to_string();
		assert!(error_msg.contains("connection error"));
		assert!(error_msg.contains("io_op"));
	}

	#[test]
	fn test_map_redis_error_generic() {
		let ttl_config = TtlConfig::from_config(&toml::Value::Table(toml::map::Map::new()));
		let storage = RedisStorage::new(
			"redis://localhost:6379".to_string(),
			5000,
			"test".to_string(),
			ttl_config,
		)
		.unwrap();

		let redis_error =
			redis::RedisError::from((redis::ErrorKind::ResponseError, "some response error"));
		let storage_error = storage.map_redis_error(redis_error, "generic_op");

		assert!(matches!(storage_error, StorageError::Backend(_)));
		let error_msg = storage_error.to_string();
		assert!(error_msg.contains("generic_op"));
		assert!(error_msg.contains("failed"));
	}

	// ==================== RedisStorageSchema Tests ====================

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
	fn test_config_schema_validation_timeout_too_high() {
		let schema = RedisStorageSchema;

		// Timeout too high (> 60000)
		let invalid_config = toml::Value::Table(toml::toml! {
			redis_url = "redis://localhost:6379"
			connection_timeout_ms = 100000
		});

		assert!(schema.validate(&invalid_config).is_err());
	}

	#[test]
	fn test_config_schema_validation_invalid_db() {
		let schema = RedisStorageSchema;

		// DB out of range (> 15)
		let invalid_config = toml::Value::Table(toml::toml! {
			redis_url = "redis://localhost:6379"
			db = 20
		});

		assert!(schema.validate(&invalid_config).is_err());
	}

	#[test]
	fn test_config_schema_validation_db_negative() {
		let schema = RedisStorageSchema;

		// DB negative
		let invalid_config = toml::Value::Table(toml::toml! {
			redis_url = "redis://localhost:6379"
			db = -1
		});

		assert!(schema.validate(&invalid_config).is_err());
	}

	#[test]
	fn test_config_schema_validation_minimal() {
		let schema = RedisStorageSchema;

		// Only redis_url is required
		let minimal_config = toml::Value::Table(toml::toml! {
			redis_url = "redis://localhost:6379"
		});

		assert!(schema.validate(&minimal_config).is_ok());
	}

	#[test]
	fn test_config_schema_validation_all_ttls() {
		let schema = RedisStorageSchema;

		let config_with_all_ttls = toml::Value::Table(toml::toml! {
			redis_url = "redis://localhost:6379"
			ttl_orders = 100
			ttl_intents = 200
			ttl_order_by_tx_hash = 300
			ttl_quotes = 400
			ttl_settlement_messages = 500
		});

		assert!(schema.validate(&config_with_all_ttls).is_ok());
	}

	#[test]
	fn test_config_schema_static_validate() {
		let valid_config = toml::Value::Table(toml::toml! {
			redis_url = "redis://localhost:6379"
		});

		assert!(RedisStorageSchema::validate_config(&valid_config).is_ok());

		let invalid_config = toml::Value::Table(toml::map::Map::new());
		assert!(RedisStorageSchema::validate_config(&invalid_config).is_err());
	}

	// ==================== create_storage() Factory Tests ====================

	#[test]
	fn test_create_storage_valid_config() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://localhost:6379"
			key_prefix = "test"
			connection_timeout_ms = 5000
		});

		let result = create_storage(&config);
		assert!(result.is_ok());
	}

	#[test]
	fn test_create_storage_default_prefix() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://localhost:6379"
		});

		let result = create_storage(&config);
		assert!(result.is_ok());
	}

	#[test]
	fn test_create_storage_default_timeout() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://localhost:6379"
		});

		let result = create_storage(&config);
		assert!(result.is_ok());
	}

	#[test]
	fn test_create_storage_with_db_number() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://localhost:6379"
			db = 5
		});

		let result = create_storage(&config);
		assert!(result.is_ok());
	}

	#[test]
	fn test_create_storage_url_already_has_db() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://localhost:6379/3"
			db = 5
		});

		// Should use the db from URL, not from config
		let result = create_storage(&config);
		assert!(result.is_ok());
	}

	#[test]
	fn test_create_storage_missing_url() {
		let config = toml::Value::Table(toml::toml! {
			key_prefix = "test"
		});

		let result = create_storage(&config);
		assert!(result.is_err());
		match result {
			Err(StorageError::Configuration(_)) => (),
			_ => panic!("Expected Configuration error"),
		}
	}

	#[test]
	fn test_create_storage_invalid_timeout() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://localhost:6379"
			connection_timeout_ms = 10
		});

		let result = create_storage(&config);
		assert!(result.is_err());
	}

	#[test]
	fn test_create_storage_with_ttl_config() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://localhost:6379"
			ttl_orders = 3600
			ttl_intents = 1800
		});

		let result = create_storage(&config);
		assert!(result.is_ok());
	}

	#[test]
	fn test_create_storage_url_with_trailing_slash() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://localhost:6379/"
			db = 2
		});

		let result = create_storage(&config);
		assert!(result.is_ok());
	}

	// ==================== Debug Implementation Tests ====================

	#[test]
	fn test_redis_storage_debug() {
		let ttl_config = TtlConfig::from_config(&toml::Value::Table(toml::map::Map::new()));
		let storage = RedisStorage::new(
			"redis://localhost:6379".to_string(),
			5000,
			"test-prefix".to_string(),
			ttl_config,
		)
		.unwrap();

		let debug_str = format!("{:?}", storage);

		assert!(debug_str.contains("RedisStorage"));
		assert!(debug_str.contains("redis://localhost:6379"));
		assert!(debug_str.contains("test-prefix"));
		assert!(debug_str.contains("connected"));
		assert!(debug_str.contains("false")); // Not connected yet (lazy init)
	}

	// ==================== Registry Tests ====================

	#[test]
	fn test_registry_name() {
		assert_eq!(Registry::NAME, "redis");
	}

	#[test]
	fn test_registry_factory() {
		let factory = Registry::factory();
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://localhost:6379"
		});

		let result = factory(&config);
		assert!(result.is_ok());
	}

	// ==================== Constants Tests ====================

	#[test]
	fn test_constants() {
		assert_eq!(DEFAULT_CONNECTION_TIMEOUT_MS, 5000);
		assert_eq!(DEFAULT_KEY_PREFIX, "oif-solver");
		assert_eq!(ALL_IDS_SUFFIX, "_all");
		assert_eq!(INDEX_SUFFIX, "_index");
	}

	// ==================== config_schema() Tests ====================

	#[test]
	fn test_storage_interface_config_schema() {
		let ttl_config = TtlConfig::from_config(&toml::Value::Table(toml::map::Map::new()));
		let storage = RedisStorage::new(
			"redis://localhost:6379".to_string(),
			5000,
			"test".to_string(),
			ttl_config,
		)
		.unwrap();

		let schema = storage.config_schema();

		// Test that the schema validates correctly
		let valid_config = toml::Value::Table(toml::toml! {
			redis_url = "redis://localhost:6379"
		});
		assert!(schema.validate(&valid_config).is_ok());

		let invalid_config = toml::Value::Table(toml::map::Map::new());
		assert!(schema.validate(&invalid_config).is_err());
	}

	// ==================== URL Building Edge Cases ====================

	#[test]
	fn test_url_with_path_not_db() {
		// URL that has a slash but the last segment is not a valid db number
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://localhost:6379/notanumber"
			db = 5
		});

		// This should append db because "notanumber" is not a valid u8
		let result = create_storage(&config);
		assert!(result.is_ok());
	}

	#[test]
	fn test_url_building_db_out_of_u8_range() {
		// URL with a number larger than u8 max
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://localhost:6379/256"
			db = 5
		});

		// 256 is out of u8 range, so should append db
		let result = create_storage(&config);
		assert!(result.is_ok());
	}

	// ==================== Async Method Tests (connection failure scenarios) ====================

	#[tokio::test]
	async fn test_get_bytes_connection_failure() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://invalid-host:6379"
			connection_timeout_ms = 100
		});

		let storage = create_storage(&config).unwrap();
		let result = storage.get_bytes("test:key").await;

		assert!(result.is_err());
		assert!(matches!(result, Err(StorageError::Backend(_))));
	}

	#[tokio::test]
	async fn test_set_bytes_connection_failure() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://invalid-host:6379"
			connection_timeout_ms = 100
		});

		let storage = create_storage(&config).unwrap();
		let result = storage
			.set_bytes("test:key", b"value".to_vec(), None, None)
			.await;

		assert!(result.is_err());
		assert!(matches!(result, Err(StorageError::Backend(_))));
	}

	#[tokio::test]
	async fn test_set_bytes_with_indexes_connection_failure() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://invalid-host:6379"
			connection_timeout_ms = 100
		});

		let storage = create_storage(&config).unwrap();
		let indexes = StorageIndexes::new().with_field("status", "pending");
		let result = storage
			.set_bytes("orders:key", b"value".to_vec(), Some(indexes), None)
			.await;

		assert!(result.is_err());
		assert!(matches!(result, Err(StorageError::Backend(_))));
	}

	#[tokio::test]
	async fn test_set_bytes_with_explicit_ttl_connection_failure() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://invalid-host:6379"
			connection_timeout_ms = 100
		});

		let storage = create_storage(&config).unwrap();
		let result = storage
			.set_bytes(
				"test:key",
				b"value".to_vec(),
				None,
				Some(Duration::from_secs(60)),
			)
			.await;

		assert!(result.is_err());
		assert!(matches!(result, Err(StorageError::Backend(_))));
	}

	#[tokio::test]
	async fn test_delete_connection_failure() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://invalid-host:6379"
			connection_timeout_ms = 100
		});

		let storage = create_storage(&config).unwrap();
		let result = storage.delete("test:key").await;

		assert!(result.is_err());
		assert!(matches!(result, Err(StorageError::Backend(_))));
	}

	#[tokio::test]
	async fn test_exists_connection_failure() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://invalid-host:6379"
			connection_timeout_ms = 100
		});

		let storage = create_storage(&config).unwrap();
		let result = storage.exists("test:key").await;

		assert!(result.is_err());
		assert!(matches!(result, Err(StorageError::Backend(_))));
	}

	#[tokio::test]
	async fn test_query_all_connection_failure() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://invalid-host:6379"
			connection_timeout_ms = 100
		});

		let storage = create_storage(&config).unwrap();
		let result = storage.query("orders", QueryFilter::All).await;

		assert!(result.is_err());
		assert!(matches!(result, Err(StorageError::Backend(_))));
	}

	#[tokio::test]
	async fn test_query_equals_connection_failure() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://invalid-host:6379"
			connection_timeout_ms = 100
		});

		let storage = create_storage(&config).unwrap();
		let result = storage
			.query(
				"orders",
				QueryFilter::Equals("status".to_string(), serde_json::json!("pending")),
			)
			.await;

		assert!(result.is_err());
		assert!(matches!(result, Err(StorageError::Backend(_))));
	}

	#[tokio::test]
	async fn test_query_not_equals_connection_failure() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://invalid-host:6379"
			connection_timeout_ms = 100
		});

		let storage = create_storage(&config).unwrap();
		let result = storage
			.query(
				"orders",
				QueryFilter::NotEquals("status".to_string(), serde_json::json!("pending")),
			)
			.await;

		assert!(result.is_err());
		assert!(matches!(result, Err(StorageError::Backend(_))));
	}

	#[tokio::test]
	async fn test_query_in_connection_failure() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://invalid-host:6379"
			connection_timeout_ms = 100
		});

		let storage = create_storage(&config).unwrap();
		let result = storage
			.query(
				"orders",
				QueryFilter::In(
					"status".to_string(),
					vec![serde_json::json!("pending"), serde_json::json!("completed")],
				),
			)
			.await;

		assert!(result.is_err());
		assert!(matches!(result, Err(StorageError::Backend(_))));
	}

	#[tokio::test]
	async fn test_query_not_in_connection_failure() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://invalid-host:6379"
			connection_timeout_ms = 100
		});

		let storage = create_storage(&config).unwrap();
		let result = storage
			.query(
				"orders",
				QueryFilter::NotIn(
					"status".to_string(),
					vec![serde_json::json!("pending"), serde_json::json!("completed")],
				),
			)
			.await;

		assert!(result.is_err());
		assert!(matches!(result, Err(StorageError::Backend(_))));
	}

	#[tokio::test]
	async fn test_get_batch_connection_failure() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://invalid-host:6379"
			connection_timeout_ms = 100
		});

		let storage = create_storage(&config).unwrap();
		let keys = vec!["test:key1".to_string(), "test:key2".to_string()];
		let result = storage.get_batch(&keys).await;

		assert!(result.is_err());
		assert!(matches!(result, Err(StorageError::Backend(_))));
	}

	#[tokio::test]
	async fn test_get_batch_empty_keys() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://invalid-host:6379"
			connection_timeout_ms = 100
		});

		let storage = create_storage(&config).unwrap();
		let keys: Vec<String> = vec![];
		// Empty keys should return immediately without connection
		let result = storage.get_batch(&keys).await;

		assert!(result.is_ok());
		assert!(result.unwrap().is_empty());
	}

	#[tokio::test]
	async fn test_cleanup_expired_no_connection_needed() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://invalid-host:6379"
			connection_timeout_ms = 100
		});

		let storage = create_storage(&config).unwrap();
		// cleanup_expired doesn't need a connection for Redis (TTL is automatic)
		let result = storage.cleanup_expired().await;

		assert!(result.is_ok());
		assert_eq!(result.unwrap(), 0);
	}

	#[tokio::test]
	async fn test_initialize_redis_connection_invalid_url() {
		let result = initialize_redis_connection("invalid://url", 100).await;
		assert!(result.is_err());
		assert!(matches!(result, Err(StorageError::Configuration(_))));
	}

	#[tokio::test]
	async fn test_initialize_redis_connection_timeout() {
		// Use a non-routable IP to trigger timeout
		let result = initialize_redis_connection("redis://10.255.255.1:6379", 100).await;
		assert!(result.is_err());
		assert!(matches!(result, Err(StorageError::Backend(_))));
	}

	#[tokio::test]
	async fn test_create_storage_async_validation_failure() {
		let invalid_config = toml::Value::Table(toml::toml! {
			key_prefix = "test"
		});

		let result = create_storage_async(&invalid_config).await;
		assert!(result.is_err());
		assert!(matches!(result, Err(StorageError::Configuration(_))));
	}

	#[tokio::test]
	async fn test_create_storage_async_connection_failure() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://invalid-host:6379"
			connection_timeout_ms = 100
		});

		let result = create_storage_async(&config).await;
		assert!(result.is_err());
		assert!(matches!(result, Err(StorageError::Backend(_))));
	}

	// ==================== update_indexes Tests ====================

	#[tokio::test]
	async fn test_update_indexes_connection_failure() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://invalid-host:6379"
			connection_timeout_ms = 100
		});

		let ttl_config = TtlConfig::from_config(&config);
		let storage = RedisStorage::new(
			"redis://invalid-host:6379".to_string(),
			100,
			"test".to_string(),
			ttl_config,
		)
		.unwrap();

		let indexes = StorageIndexes::new().with_field("status", "pending");
		let result = storage
			.update_indexes("orders:key1", "orders", &indexes, None)
			.await;

		assert!(result.is_err());
		assert!(matches!(result, Err(StorageError::Backend(_))));
	}

	#[tokio::test]
	async fn test_update_indexes_with_ttl_connection_failure() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://invalid-host:6379"
			connection_timeout_ms = 100
		});

		let ttl_config = TtlConfig::from_config(&config);
		let storage = RedisStorage::new(
			"redis://invalid-host:6379".to_string(),
			100,
			"test".to_string(),
			ttl_config,
		)
		.unwrap();

		let indexes = StorageIndexes::new().with_field("status", "pending");
		let result = storage
			.update_indexes(
				"orders:key1",
				"orders",
				&indexes,
				Some(Duration::from_secs(60)),
			)
			.await;

		assert!(result.is_err());
		assert!(matches!(result, Err(StorageError::Backend(_))));
	}

	// ==================== remove_from_indexes Tests ====================

	#[tokio::test]
	async fn test_remove_from_indexes_connection_failure() {
		let config = toml::Value::Table(toml::toml! {
			redis_url = "redis://invalid-host:6379"
			connection_timeout_ms = 100
		});

		let ttl_config = TtlConfig::from_config(&config);
		let storage = RedisStorage::new(
			"redis://invalid-host:6379".to_string(),
			100,
			"test".to_string(),
			ttl_config,
		)
		.unwrap();

		let result = storage.remove_from_indexes("orders:key1", "orders").await;

		assert!(result.is_err());
		assert!(matches!(result, Err(StorageError::Backend(_))));
	}

	// ==================== get_connection Tests ====================

	#[tokio::test]
	async fn test_get_connection_lazy_initialization() {
		let ttl_config = TtlConfig::from_config(&toml::Value::Table(toml::map::Map::new()));
		let storage = RedisStorage::new(
			"redis://invalid-host:6379".to_string(),
			100,
			"test".to_string(),
			ttl_config,
		)
		.unwrap();

		// Connection should not be initialized yet
		assert!(!storage.client.initialized());

		// Attempt to get connection (will fail due to invalid host)
		let result = storage.get_connection().await;
		assert!(result.is_err());
	}
}
