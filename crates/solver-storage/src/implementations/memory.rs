//! In-memory storage backend implementation for the solver service.
//!
//! This module provides a memory-based implementation of the StorageInterface trait,
//! useful for testing and development scenarios where persistence is not required.

use crate::{QueryFilter, StorageError, StorageIndexes, StorageInterface};
use async_trait::async_trait;
use solver_types::{ConfigSchema, Schema, ValidationError};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// In-memory storage implementation.
///
/// This implementation stores data in a HashMap in memory,
/// providing fast access but no persistence across restarts.
/// TTL and indexes are ignored as this is primarily for testing
/// and has no recovery capability.
pub struct MemoryStorage {
	/// The in-memory store protected by a read-write lock.
	store: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl MemoryStorage {
	/// Creates a new MemoryStorage instance.
	pub fn new() -> Self {
		Self {
			store: Arc::new(RwLock::new(HashMap::new())),
		}
	}
}

impl Default for MemoryStorage {
	fn default() -> Self {
		Self::new()
	}
}

#[async_trait]
impl StorageInterface for MemoryStorage {
	async fn get_bytes(&self, key: &str) -> Result<Vec<u8>, StorageError> {
		let store = self.store.read().await;
		store.get(key).cloned().ok_or(StorageError::NotFound)
	}

	async fn set_bytes(
		&self,
		key: &str,
		value: Vec<u8>,
		_indexes: Option<StorageIndexes>,
		_ttl: Option<Duration>,
	) -> Result<(), StorageError> {
		// TTL and indexes are ignored for memory storage
		let mut store = self.store.write().await;
		store.insert(key.to_string(), value);
		Ok(())
	}

	async fn delete(&self, key: &str) -> Result<(), StorageError> {
		let mut store = self.store.write().await;
		store.remove(key);
		Ok(())
	}

	async fn exists(&self, key: &str) -> Result<bool, StorageError> {
		let store = self.store.read().await;
		Ok(store.contains_key(key))
	}

	fn config_schema(&self) -> Box<dyn ConfigSchema> {
		Box::new(MemoryStorageSchema)
	}

	async fn query(
		&self,
		_namespace: &str,
		_filter: QueryFilter,
	) -> Result<Vec<String>, StorageError> {
		// Memory storage doesn't support recovery, so querying is not meaningful.
		// Return empty for compatibility.
		Ok(Vec::new())
	}

	async fn get_batch(&self, keys: &[String]) -> Result<Vec<(String, Vec<u8>)>, StorageError> {
		let store = self.store.read().await;
		let mut results = Vec::new();

		for key in keys {
			if let Some(value) = store.get(key) {
				results.push((key.clone(), value.clone()));
			}
		}

		Ok(results)
	}
}

/// Configuration schema for MemoryStorage.
pub struct MemoryStorageSchema;

impl MemoryStorageSchema {
	/// Static validation method for use before instance creation
	pub fn validate_config(config: &toml::Value) -> Result<(), ValidationError> {
		let instance = Self;
		instance.validate(config)
	}
}

impl ConfigSchema for MemoryStorageSchema {
	fn validate(&self, _config: &toml::Value) -> Result<(), ValidationError> {
		// Memory storage has no required configuration
		let schema = Schema::new(vec![], vec![]);
		schema.validate(_config)
	}
}

/// Factory function to create a memory storage backend from configuration.
///
/// Configuration parameters:
/// - None required for memory storage
pub fn create_storage(config: &toml::Value) -> Result<Box<dyn StorageInterface>, StorageError> {
	// Validate configuration first (even though memory storage has no config)
	MemoryStorageSchema::validate_config(config)
		.map_err(|e| StorageError::Configuration(format!("Invalid configuration: {}", e)))?;

	Ok(Box::new(MemoryStorage::new()))
}

/// Registry for the memory storage implementation.
pub struct Registry;

impl solver_types::ImplementationRegistry for Registry {
	const NAME: &'static str = "memory";
	type Factory = crate::StorageFactory;

	fn factory() -> Self::Factory {
		create_storage
	}
}

impl crate::StorageRegistry for Registry {}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn test_basic_operations() {
		let storage = MemoryStorage::new();

		// Test set and get
		let key = "test_key";
		let value = b"test_value".to_vec();
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
		assert!(matches!(result, Err(StorageError::NotFound)));
	}

	#[tokio::test]
	async fn test_overwrite() {
		let storage = MemoryStorage::new();

		let key = "overwrite_key";
		let value1 = b"value1".to_vec();
		let value2 = b"value2".to_vec();

		// Set initial value
		storage
			.set_bytes(key, value1.clone(), None, None)
			.await
			.unwrap();
		let retrieved = storage.get_bytes(key).await.unwrap();
		assert_eq!(retrieved, value1);

		// Overwrite with new value
		storage
			.set_bytes(key, value2.clone(), None, None)
			.await
			.unwrap();
		let retrieved = storage.get_bytes(key).await.unwrap();
		assert_eq!(retrieved, value2);
	}
}
