//! Storage module for the OIF solver system.
//!
//! This module provides abstractions for persistent storage of solver data,
//! supporting different backend implementations such as in-memory, file-based,
//! or distributed storage systems.
//!
//! # Configuration Storage
//!
//! The [`config_store`] module provides specialized storage for solver configuration
//! with optimistic locking support via versioning.
//!
//! # Nonce Storage
//!
//! The [`nonce_store`] module provides nonce management for admin authentication
//! with Redis-backed storage and TTL support.

pub mod config_store;
pub mod nonce_store;
pub mod readiness;
pub mod redis_health;

// Re-export redis_health types for convenience
pub use redis_health::{
	check_redis_health, check_redis_health_strict, PersistenceDetectionMethod, RedisHealthError,
	RedisPersistenceInfo,
};

// Re-export readiness types for convenience
pub use readiness::{
	check_storage_readiness, get_readiness_checker, verify_storage_readiness, PersistencePolicy,
	ReadinessCheck, ReadinessConfig, ReadinessError, ReadinessStatus, StorageReadiness,
};

use async_trait::async_trait;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use solver_types::{ConfigSchema, ImplementationRegistry};
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;

/// Re-export implementations
pub mod implementations {
	pub mod file;
	pub mod memory;
	pub mod redis;
}

/// Query filter for storage operations.
///
/// Used to filter items when querying storage backends.
/// Each backend handles indexing differently - databases use native indexes,
/// file storage uses index files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueryFilter {
	/// Match items where field equals value.
	Equals(String, serde_json::Value),
	/// Match items where field does not equal value.
	NotEquals(String, serde_json::Value),
	/// Match items where field is in list of values.
	In(String, Vec<serde_json::Value>),
	/// Match items where field is not in list of values.
	NotIn(String, Vec<serde_json::Value>),
	/// Match all items.
	All,
}

/// Index values for a stored item.
///
/// Provides field values that backends can use for efficient querying.
/// Backends are responsible for maintaining their own index structures.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StorageIndexes {
	/// Field name -> value for indexing.
	pub fields: HashMap<String, serde_json::Value>,
}

impl StorageIndexes {
	/// Creates a new empty StorageIndexes.
	pub fn new() -> Self {
		Self::default()
	}

	/// Adds a field to be indexed.
	pub fn with_field(mut self, name: impl Into<String>, value: impl Serialize) -> Self {
		self.fields.insert(
			name.into(),
			serde_json::to_value(value).unwrap_or(serde_json::Value::Null),
		);
		self
	}
}

/// Errors that can occur during storage operations.
#[derive(Debug, Error)]
pub enum StorageError {
	/// Error that occurs when a requested item is not found.
	#[error("Not found: {0}")]
	NotFound(String),
	/// Error that occurs during serialization/deserialization.
	#[error("Serialization error: {0}")]
	Serialization(String),
	/// Error that occurs in the storage backend.
	#[error("Backend error: {0}")]
	Backend(String),
	/// Error that occurs during configuration validation.
	#[error("Configuration error: {0}")]
	Configuration(String),
	/// Error that occurs when resource is expired.
	#[error("Expired error: {0}")]
	Expired(String),
}

/// Trait defining the low-level interface for storage backends.
///
/// This trait must be implemented by any storage backend that wants to
/// integrate with the solver system. It provides basic key-value operations
/// with optional TTL support and querying capabilities.
///
/// # Atomic Operations
///
/// This trait includes atomic operations for concurrent access patterns:
/// - [`set_nx`](StorageInterface::set_nx): Set if not exists (for initialization)
/// - [`compare_and_swap`](StorageInterface::compare_and_swap): Atomic CAS on raw bytes
/// - [`delete_if_exists`](StorageInterface::delete_if_exists): Atomic delete returning existence
///
/// These are low-level byte operations - higher-level logic (JSON parsing,
/// versioning) should be handled by wrapper stores like `ConfigStore`.
#[async_trait]
#[cfg_attr(feature = "testing", mockall::automock)]
pub trait StorageInterface: Send + Sync {
	/// Retrieves raw bytes for the given key.
	async fn get_bytes(&self, key: &str) -> Result<Vec<u8>, StorageError>;

	/// Stores raw bytes with optional indexes and time-to-live.
	///
	/// The indexes parameter allows backends to optimize queries.
	/// Different backends handle indexing differently:
	/// - Database backends use native indexes
	/// - File storage maintains separate index files
	/// - Memory storage tracks indexes in-memory
	async fn set_bytes(
		&self,
		key: &str,
		value: Vec<u8>,
		indexes: Option<StorageIndexes>,
		ttl: Option<Duration>,
	) -> Result<(), StorageError>;

	/// Deletes the value associated with the given key.
	///
	/// Implementations must also remove the key from any indexes.
	async fn delete(&self, key: &str) -> Result<(), StorageError>;

	/// Checks if a key exists in storage.
	async fn exists(&self, key: &str) -> Result<bool, StorageError>;

	/// Query items in a namespace based on indexed fields.
	///
	/// Returns list of keys matching the filter criteria.
	/// Only returns keys for items that have been indexed.
	async fn query(
		&self,
		namespace: &str,
		filter: QueryFilter,
	) -> Result<Vec<String>, StorageError>;

	/// Batch retrieve multiple values by keys.
	///
	/// Returns a vector of (key, value) pairs for keys that exist.
	/// Missing keys are silently skipped.
	/// Implementations should optimize for bulk retrieval where possible.
	async fn get_batch(&self, keys: &[String]) -> Result<Vec<(String, Vec<u8>)>, StorageError>;

	/// Returns the configuration schema for validation.
	fn config_schema(&self) -> Box<dyn ConfigSchema>;

	/// Removes expired entries from storage (optional operation).
	/// Returns the number of entries removed.
	/// Implementations that don't support expiration can return Ok(0).
	async fn cleanup_expired(&self) -> Result<usize, StorageError> {
		Ok(0) // Default implementation for backends without TTL support
	}

	// ==================== Atomic Operations ====================

	/// Set a value only if the key does not exist.
	///
	/// Returns `Ok(true)` if set successfully, `Ok(false)` if key already exists.
	///
	/// # Atomicity
	///
	/// - **Redis**: Uses native `SETNX` / `SET NX EX` (truly atomic)
	/// - **Memory**: Uses `RwLock` (atomic within process)
	/// - **File**: Best-effort with file locking
	///
	/// # Arguments
	///
	/// * `key` - The key to set
	/// * `value` - The value to store
	/// * `ttl` - Optional time-to-live for the key
	async fn set_nx(
		&self,
		key: &str,
		value: Vec<u8>,
		ttl: Option<Duration>,
	) -> Result<bool, StorageError>;

	/// Atomic compare-and-swap on raw bytes.
	///
	/// Only updates if the current value exactly equals `expected`.
	///
	/// # Returns
	///
	/// - `Ok(true)` if swapped successfully
	/// - `Ok(false)` if current value doesn't match expected
	/// - `Err(NotFound)` if key doesn't exist
	///
	/// # Arguments
	///
	/// * `key` - The key to update
	/// * `expected` - The expected current value (exact byte comparison)
	/// * `new_value` - The new value to set if comparison succeeds
	/// * `ttl` - Optional TTL for the new value (preserves or sets TTL)
	///
	/// # Atomicity
	///
	/// - **Redis**: Uses Lua script for atomic operation
	/// - **Memory**: Uses `RwLock` (atomic within process)
	async fn compare_and_swap(
		&self,
		key: &str,
		expected: &[u8],
		new_value: Vec<u8>,
		ttl: Option<Duration>,
	) -> Result<bool, StorageError>;

	/// Delete a key and return whether it existed.
	///
	/// Useful for single-use tokens like nonces where you need to
	/// atomically check existence and delete in one operation.
	///
	/// # Returns
	///
	/// - `Ok(true)` if key existed and was deleted
	/// - `Ok(false)` if key didn't exist
	///
	/// # Atomicity
	///
	/// - **Redis**: `DEL` returns count of deleted keys (atomic)
	/// - **Memory**: Uses `RwLock` (atomic within process)
	async fn delete_if_exists(&self, key: &str) -> Result<bool, StorageError>;
}

/// Type alias for storage factory functions.
///
/// This is the function signature that all storage implementations must provide
/// to create instances of their storage interface.
pub type StorageFactory = fn(&toml::Value) -> Result<Box<dyn StorageInterface>, StorageError>;

/// Get all registered storage implementations.
///
/// Returns a vector of (name, factory) tuples for all available storage implementations.
/// This is used by the factory registry to automatically register all implementations.
pub fn get_all_implementations() -> Vec<(&'static str, StorageFactory)> {
	use implementations::{file, memory, redis};

	vec![
		(file::Registry::NAME, file::Registry::factory()),
		(memory::Registry::NAME, memory::Registry::factory()),
		(redis::Registry::NAME, redis::Registry::factory()),
	]
}

// =============================================================================
// Shared Store Configuration
// =============================================================================

/// Configuration for storage backends used by specialized stores.
///
/// This enum is shared by [`config_store::ConfigStore`] and [`nonce_store::NonceStore`]
/// to avoid code duplication. All stores use the same backend options.
///
/// # Example
///
/// ```rust,ignore
/// use solver_storage::{StoreConfig, create_storage_backend};
///
/// // For production (Redis)
/// let storage = create_storage_backend(StoreConfig::Redis {
///     url: "redis://localhost:6379".to_string(),
/// })?;
///
/// // For testing (Memory)
/// let storage = create_storage_backend(StoreConfig::Memory)?;
/// ```
#[derive(Clone)]
pub enum StoreConfig {
	/// Use an existing StorageInterface (for sharing storage with other components)
	Storage(std::sync::Arc<dyn StorageInterface>),
	/// Create a new Redis-backed storage
	Redis {
		/// Redis connection URL (e.g., "redis://localhost:6379")
		url: String,
	},
	/// Create a file-based storage (useful for single-instance deployments)
	File {
		/// Base directory path for storing files (e.g., "./data/storage")
		path: String,
	},
	/// Create an in-memory storage (useful for testing)
	Memory,
}

impl std::fmt::Debug for StoreConfig {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			StoreConfig::Storage(_) => f.debug_struct("Storage").finish_non_exhaustive(),
			StoreConfig::Redis { url } => {
				let redacted = redact_url_credentials(url);
				f.debug_struct("Redis").field("url", &redacted).finish()
			},
			StoreConfig::File { path } => f.debug_struct("File").field("path", path).finish(),
			StoreConfig::Memory => f.debug_struct("Memory").finish(),
		}
	}
}

impl StoreConfig {
	/// Build a storage config from environment variables.
	///
	/// Supported backends:
	/// - STORAGE_BACKEND=redis (default) uses REDIS_URL
	/// - STORAGE_BACKEND=file uses STORAGE_PATH (default: "./data/storage")
	/// - STORAGE_BACKEND=memory
	pub fn from_env() -> Result<Self, StorageError> {
		let backend = std::env::var("STORAGE_BACKEND").unwrap_or_else(|_| "redis".to_string());
		match backend.as_str() {
			"redis" => {
				let url = std::env::var("REDIS_URL")
					.unwrap_or_else(|_| "redis://localhost:6379".to_string());
				Ok(StoreConfig::Redis { url })
			},
			"file" => {
				let path =
					std::env::var("STORAGE_PATH").unwrap_or_else(|_| "./data/storage".to_string());
				Ok(StoreConfig::File { path })
			},
			"memory" => Ok(StoreConfig::Memory),
			other => Err(StorageError::Configuration(format!(
				"Unsupported storage backend '{}'. Supported: redis, file, memory",
				other
			))),
		}
	}
}

/// Creates a storage backend from the given configuration.
///
/// This factory function is used by [`config_store`] and [`nonce_store`]
/// to create their underlying storage backends.
///
/// # Arguments
///
/// * `config` - Backend configuration (Redis, Memory, or existing StorageInterface)
///
/// # Returns
///
/// An `Arc<dyn StorageInterface>` ready for use.
///
/// # Errors
///
/// Returns `StorageError` if the backend cannot be created (e.g., invalid Redis URL).
pub fn create_storage_backend(
	config: StoreConfig,
) -> Result<std::sync::Arc<dyn StorageInterface>, StorageError> {
	match config {
		StoreConfig::Storage(s) => Ok(s),
		StoreConfig::Redis { url } => {
			let storage = implementations::redis::RedisStorage::with_url(url)?;
			Ok(std::sync::Arc::new(storage))
		},
		StoreConfig::File { path } => {
			let ttl_config = implementations::file::TtlConfig::default();
			let storage =
				implementations::file::FileStorage::new(std::path::PathBuf::from(path), ttl_config);
			Ok(std::sync::Arc::new(storage))
		},
		StoreConfig::Memory => {
			let storage = implementations::memory::MemoryStorage::new();
			Ok(std::sync::Arc::new(storage))
		},
	}
}

/// Redacts credentials (userinfo) from a URL to prevent leaking secrets in logs.
///
/// Transforms URLs like `redis://:password@host:port` to `redis://[REDACTED]@host:port`
///
/// # Example
///
/// ```rust,ignore
/// let url = "redis://:secret@localhost:6379";
/// let redacted = redact_url_credentials(url);
/// assert_eq!(redacted, "redis://[REDACTED]@localhost:6379");
/// ```
pub fn redact_url_credentials(url: &str) -> String {
	// Find the scheme separator
	let Some(scheme_end) = url.find("://") else {
		return url.to_string();
	};

	let after_scheme = &url[scheme_end + 3..];

	// Find the @ symbol which separates userinfo from host
	let Some(at_pos) = after_scheme.find('@') else {
		// No credentials in URL
		return url.to_string();
	};

	// Reconstruct URL with redacted credentials
	let scheme = &url[..scheme_end + 3];
	let host_and_path = &after_scheme[at_pos + 1..];
	format!("{}[REDACTED]@{}", scheme, host_and_path)
}

// =============================================================================
// Storage Service
// =============================================================================

/// High-level storage service that provides typed operations.
///
/// The StorageService wraps a low-level storage backend and provides
/// convenient methods for storing and retrieving typed data with
/// automatic serialization/deserialization.
pub struct StorageService {
	/// The underlying storage backend implementation.
	backend: Box<dyn StorageInterface>,
}

impl StorageService {
	/// Creates a new StorageService with the specified backend.
	pub fn new(backend: Box<dyn StorageInterface>) -> Self {
		Self { backend }
	}

	/// Stores a serializable value with optional indexes and time-to-live.
	///
	/// The namespace and id are combined to form a unique key.
	/// The data is serialized to JSON before storage.
	pub async fn store_with_ttl<T: Serialize>(
		&self,
		namespace: &str,
		id: &str,
		data: &T,
		indexes: Option<StorageIndexes>,
		ttl: Option<Duration>,
	) -> Result<(), StorageError> {
		let key = format!("{}:{}", namespace, id);
		let bytes =
			serde_json::to_vec(data).map_err(|e| StorageError::Serialization(e.to_string()))?;
		self.backend.set_bytes(&key, bytes, indexes, ttl).await
	}

	/// Stores a serializable value with optional indexes but no TTL.
	pub async fn store<T: Serialize>(
		&self,
		namespace: &str,
		id: &str,
		data: &T,
		indexes: Option<StorageIndexes>,
	) -> Result<(), StorageError> {
		self.store_with_ttl(namespace, id, data, indexes, None)
			.await
	}

	/// Retrieves and deserializes a value from storage.
	///
	/// The namespace and id are combined to form the lookup key.
	/// The retrieved bytes are deserialized from JSON.
	pub async fn retrieve<T: DeserializeOwned>(
		&self,
		namespace: &str,
		id: &str,
	) -> Result<T, StorageError> {
		let key = format!("{}:{}", namespace, id);
		let bytes = self.backend.get_bytes(&key).await?;
		serde_json::from_slice(&bytes).map_err(|e| StorageError::Serialization(e.to_string()))
	}

	/// Removes a value from storage.
	///
	/// The namespace and id are combined to form the key to delete.
	pub async fn remove(&self, namespace: &str, id: &str) -> Result<(), StorageError> {
		let key = format!("{}:{}", namespace, id);
		self.backend.delete(&key).await
	}

	/// Updates an existing value in storage with optional indexes.
	///
	/// This method first checks if the key exists, then updates the value.
	/// Returns an error if the key doesn't exist, making it semantically different
	/// from store() which will create or overwrite.
	pub async fn update<T: Serialize>(
		&self,
		namespace: &str,
		id: &str,
		data: &T,
		indexes: Option<StorageIndexes>,
	) -> Result<(), StorageError> {
		let key = format!("{}:{}", namespace, id);

		// Check if the key exists first
		if !self.backend.exists(&key).await? {
			return Err(StorageError::NotFound(key.to_string()));
		}

		let bytes =
			serde_json::to_vec(data).map_err(|e| StorageError::Serialization(e.to_string()))?;
		self.backend.set_bytes(&key, bytes, indexes, None).await
	}

	/// Checks if a value exists in storage.
	///
	/// The namespace and id are combined to form the lookup key.
	/// Returns true if the key exists, false otherwise.
	pub async fn exists(&self, namespace: &str, id: &str) -> Result<bool, StorageError> {
		let key = format!("{}:{}", namespace, id);
		self.backend.exists(&key).await
	}

	/// Removes expired entries from storage.
	///
	/// Returns the number of entries that were removed.
	/// This is a no-op for backends that don't support TTL.
	pub async fn cleanup_expired(&self) -> Result<usize, StorageError> {
		self.backend.cleanup_expired().await
	}

	/// Updates an existing value in storage with time-to-live and optional indexes.
	///
	/// This method first checks if the key exists, then updates the value with TTL.
	/// Returns an error if the key doesn't exist.
	pub async fn update_with_ttl<T: Serialize>(
		&self,
		namespace: &str,
		id: &str,
		data: &T,
		indexes: Option<StorageIndexes>,
		ttl: Option<Duration>,
	) -> Result<(), StorageError> {
		let key = format!("{}:{}", namespace, id);

		// Check if the key exists first
		if !self.backend.exists(&key).await? {
			return Err(StorageError::NotFound(key.to_string()));
		}

		let bytes =
			serde_json::to_vec(data).map_err(|e| StorageError::Serialization(e.to_string()))?;
		self.backend.set_bytes(&key, bytes, indexes, ttl).await
	}

	/// Query items in a namespace based on a filter.
	///
	/// Returns a list of deserialized items matching the filter criteria.
	pub async fn query<T: DeserializeOwned>(
		&self,
		namespace: &str,
		filter: QueryFilter,
	) -> Result<Vec<(String, T)>, StorageError> {
		let keys = self.backend.query(namespace, filter).await?;

		// Use batch retrieval for efficiency
		let results = self.backend.get_batch(&keys).await?;

		let mut items = Vec::new();
		for (key, bytes) in results {
			// Extract ID from key (format: "namespace:id")
			let id = key.split(':').nth(1).unwrap_or(&key).to_string();
			match serde_json::from_slice::<T>(&bytes) {
				Ok(item) => items.push((id, item)),
				Err(e) => {
					tracing::warn!("Failed to deserialize item {}: {}", key, e);
					// Continue with other items rather than failing entirely
				},
			}
		}

		Ok(items)
	}

	/// Retrieve all items in a namespace.
	///
	/// Uses batch operations for efficiency when loading many items.
	pub async fn retrieve_all<T: DeserializeOwned>(
		&self,
		namespace: &str,
	) -> Result<Vec<(String, T)>, StorageError> {
		self.query(namespace, QueryFilter::All).await
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_store_config_from_env_redis_default() {
		std::env::remove_var("STORAGE_BACKEND");
		std::env::remove_var("REDIS_URL");

		let config = StoreConfig::from_env().unwrap();
		match config {
			StoreConfig::Redis { url } => {
				assert_eq!(url, "redis://localhost:6379");
			},
			_ => panic!("Expected Redis config"),
		}
	}

	#[test]
	fn test_store_config_from_env_redis_custom_url() {
		std::env::set_var("STORAGE_BACKEND", "redis");
		std::env::set_var("REDIS_URL", "redis://custom:6380");

		let config = StoreConfig::from_env().unwrap();
		match config {
			StoreConfig::Redis { url } => {
				assert_eq!(url, "redis://custom:6380");
			},
			_ => panic!("Expected Redis config"),
		}

		std::env::remove_var("STORAGE_BACKEND");
		std::env::remove_var("REDIS_URL");
	}

	#[test]
	fn test_store_config_from_env_file_default_path() {
		std::env::set_var("STORAGE_BACKEND", "file");
		std::env::remove_var("STORAGE_PATH");

		let config = StoreConfig::from_env().unwrap();
		match config {
			StoreConfig::File { path } => {
				assert_eq!(path, "./data/storage");
			},
			_ => panic!("Expected File config"),
		}

		std::env::remove_var("STORAGE_BACKEND");
	}

	#[test]
	fn test_store_config_from_env_file_custom_path() {
		std::env::set_var("STORAGE_BACKEND", "file");
		std::env::set_var("STORAGE_PATH", "/custom/path");

		let config = StoreConfig::from_env().unwrap();
		match config {
			StoreConfig::File { path } => {
				assert_eq!(path, "/custom/path");
			},
			_ => panic!("Expected File config"),
		}

		std::env::remove_var("STORAGE_BACKEND");
		std::env::remove_var("STORAGE_PATH");
	}

	#[test]
	fn test_store_config_from_env_memory() {
		std::env::set_var("STORAGE_BACKEND", "memory");

		let config = StoreConfig::from_env().unwrap();
		assert!(matches!(config, StoreConfig::Memory));

		std::env::remove_var("STORAGE_BACKEND");
	}

	#[test]
	fn test_store_config_from_env_unsupported() {
		std::env::set_var("STORAGE_BACKEND", "unsupported");

		let result = StoreConfig::from_env();
		assert!(result.is_err());
		let err = result.unwrap_err();
		assert!(err.to_string().contains("Unsupported storage backend"));
		assert!(err.to_string().contains("unsupported"));

		std::env::remove_var("STORAGE_BACKEND");
	}

	#[test]
	fn test_store_config_debug_redis() {
		let config = StoreConfig::Redis {
			url: "redis://:secret@localhost:6379".to_string(),
		};
		let debug_str = format!("{:?}", config);
		// Should redact credentials
		assert!(debug_str.contains("[REDACTED]"));
		assert!(!debug_str.contains("secret"));
	}

	#[test]
	fn test_store_config_debug_file() {
		let config = StoreConfig::File {
			path: "/my/storage/path".to_string(),
		};
		let debug_str = format!("{:?}", config);
		assert!(debug_str.contains("File"));
		assert!(debug_str.contains("/my/storage/path"));
	}

	#[test]
	fn test_store_config_debug_memory() {
		let config = StoreConfig::Memory;
		let debug_str = format!("{:?}", config);
		assert!(debug_str.contains("Memory"));
	}

	#[test]
	fn test_create_storage_backend_memory() {
		let config = StoreConfig::Memory;
		let result = create_storage_backend(config);
		assert!(result.is_ok());
	}

	#[test]
	fn test_create_storage_backend_file() {
		let temp_dir = tempfile::TempDir::new().unwrap();
		let config = StoreConfig::File {
			path: temp_dir.path().to_str().unwrap().to_string(),
		};
		let result = create_storage_backend(config);
		assert!(result.is_ok());
	}

	#[test]
	fn test_create_storage_backend_existing_storage() {
		let memory = implementations::memory::MemoryStorage::new();
		let config = StoreConfig::Storage(std::sync::Arc::new(memory));
		let result = create_storage_backend(config);
		assert!(result.is_ok());
	}

	#[test]
	fn test_redact_url_credentials_with_password() {
		let url = "redis://:secret@localhost:6379";
		let redacted = redact_url_credentials(url);
		assert_eq!(redacted, "redis://[REDACTED]@localhost:6379");
	}

	#[test]
	fn test_redact_url_credentials_with_user_and_password() {
		let url = "redis://user:secret@localhost:6379";
		let redacted = redact_url_credentials(url);
		assert_eq!(redacted, "redis://[REDACTED]@localhost:6379");
	}

	#[test]
	fn test_redact_url_credentials_no_credentials() {
		let url = "redis://localhost:6379";
		let redacted = redact_url_credentials(url);
		assert_eq!(redacted, "redis://localhost:6379");
	}

	#[test]
	fn test_redact_url_credentials_no_scheme() {
		let url = "localhost:6379";
		let redacted = redact_url_credentials(url);
		assert_eq!(redacted, "localhost:6379");
	}

	#[test]
	fn test_storage_error_display() {
		let err = StorageError::NotFound("key1".to_string());
		assert_eq!(err.to_string(), "Not found: key1");

		let err = StorageError::Serialization("bad json".to_string());
		assert_eq!(err.to_string(), "Serialization error: bad json");

		let err = StorageError::Backend("connection failed".to_string());
		assert_eq!(err.to_string(), "Backend error: connection failed");

		let err = StorageError::Configuration("invalid config".to_string());
		assert_eq!(err.to_string(), "Configuration error: invalid config");

		let err = StorageError::Expired("key2".to_string());
		assert_eq!(err.to_string(), "Expired error: key2");
	}

	#[test]
	fn test_query_filter_variants() {
		let filter = QueryFilter::All;
		assert!(matches!(filter, QueryFilter::All));

		let filter = QueryFilter::Equals("field".to_string(), serde_json::json!("value"));
		assert!(matches!(filter, QueryFilter::Equals(_, _)));

		let filter = QueryFilter::NotEquals("field".to_string(), serde_json::json!("value"));
		assert!(matches!(filter, QueryFilter::NotEquals(_, _)));

		let filter = QueryFilter::In("field".to_string(), vec![serde_json::json!("a")]);
		assert!(matches!(filter, QueryFilter::In(_, _)));

		let filter = QueryFilter::NotIn("field".to_string(), vec![serde_json::json!("a")]);
		assert!(matches!(filter, QueryFilter::NotIn(_, _)));
	}

	#[test]
	fn test_storage_indexes_builder() {
		let indexes = StorageIndexes::new()
			.with_field("status", "pending")
			.with_field("amount", 100);

		assert_eq!(indexes.fields.len(), 2);
		assert!(indexes.fields.contains_key("status"));
		assert!(indexes.fields.contains_key("amount"));
	}
}
