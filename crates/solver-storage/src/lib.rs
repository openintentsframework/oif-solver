//! Storage module for the OIF solver system.
//!
//! This module provides abstractions for persistent storage of solver data,
//! supporting different backend implementations such as in-memory, file-based,
//! or distributed storage systems.

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
	#[error("Not found")]
	NotFound,
	/// Error that occurs during serialization/deserialization.
	#[error("Serialization error: {0}")]
	Serialization(String),
	/// Error that occurs in the storage backend.
	#[error("Backend error: {0}")]
	Backend(String),
	/// Error that occurs during configuration validation.
	#[error("Configuration error: {0}")]
	Configuration(String),
}

/// Trait defining the low-level interface for storage backends.
///
/// This trait must be implemented by any storage backend that wants to
/// integrate with the solver system. It provides basic key-value operations
/// with optional TTL support and querying capabilities.
#[async_trait]
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
}

/// Type alias for storage factory functions.
///
/// This is the function signature that all storage implementations must provide
/// to create instances of their storage interface.
pub type StorageFactory = fn(&toml::Value) -> Result<Box<dyn StorageInterface>, StorageError>;

/// Registry trait for storage implementations.
///
/// This trait extends the base ImplementationRegistry to specify that
/// storage implementations must provide a StorageFactory.
pub trait StorageRegistry: ImplementationRegistry<Factory = StorageFactory> {}

/// Get all registered storage implementations.
///
/// Returns a vector of (name, factory) tuples for all available storage implementations.
/// This is used by the factory registry to automatically register all implementations.
pub fn get_all_implementations() -> Vec<(&'static str, StorageFactory)> {
	use implementations::{file, memory};

	vec![
		(file::Registry::NAME, file::Registry::factory()),
		(memory::Registry::NAME, memory::Registry::factory()),
	]
}

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
			return Err(StorageError::NotFound);
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
			return Err(StorageError::NotFound);
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
				}
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
