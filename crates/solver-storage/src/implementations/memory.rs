//! In-memory storage backend implementation for the solver service.
//!
//! This module provides a memory-based implementation of the StorageInterface trait,
//! useful for testing and development scenarios where persistence is not required.
//!
//! # ⚠️ Test-Only Backend
//!
//! This backend is intended for **testing only**:
//! - TTL is tracked but cleanup is manual (call `cleanup_expired()`)
//! - Atomic operations use `RwLock` (single-process only, not distributed)
//! - Data is lost on restart
//!
//! For production, use Redis or another persistent backend.

use crate::{QueryFilter, StorageError, StorageIndexes, StorageInterface};
use async_trait::async_trait;
use solver_types::{ConfigSchema, Schema, ValidationError};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Entry stored in memory with optional expiration.
#[derive(Clone)]
struct StorageEntry {
	/// The stored value.
	value: Vec<u8>,
	/// When this entry expires (None = never expires).
	expires_at: Option<Instant>,
}

impl StorageEntry {
	/// Check if this entry has expired.
	fn is_expired(&self) -> bool {
		self.expires_at.map(|t| Instant::now() > t).unwrap_or(false)
	}
}

/// In-memory storage implementation.
///
/// # ⚠️ Test-Only Backend
///
/// This implementation stores data in a HashMap in memory:
/// - TTL is tracked but cleanup requires calling `cleanup_expired()`
/// - Atomic operations use `RwLock` (single-process only)
/// - Data is lost on restart
///
/// For production, use Redis or another persistent backend.
pub struct MemoryStorage {
	/// The in-memory store protected by a read-write lock.
	store: Arc<RwLock<HashMap<String, StorageEntry>>>,
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
		match store.get(key) {
			Some(entry) if !entry.is_expired() => Ok(entry.value.clone()),
			Some(_) => Err(StorageError::NotFound(key.to_string())), // Expired
			None => Err(StorageError::NotFound(key.to_string())),
		}
	}

	async fn set_bytes(
		&self,
		key: &str,
		value: Vec<u8>,
		_indexes: Option<StorageIndexes>,
		ttl: Option<Duration>,
	) -> Result<(), StorageError> {
		let mut store = self.store.write().await;
		let entry = StorageEntry {
			value,
			expires_at: ttl.map(|d| Instant::now() + d),
		};
		store.insert(key.to_string(), entry);
		Ok(())
	}

	async fn delete(&self, key: &str) -> Result<(), StorageError> {
		let mut store = self.store.write().await;
		store.remove(key);
		Ok(())
	}

	async fn exists(&self, key: &str) -> Result<bool, StorageError> {
		let store = self.store.read().await;
		match store.get(key) {
			Some(entry) => Ok(!entry.is_expired()),
			None => Ok(false),
		}
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
			if let Some(entry) = store.get(key) {
				if !entry.is_expired() {
					results.push((key.clone(), entry.value.clone()));
				}
			}
		}

		Ok(results)
	}

	async fn cleanup_expired(&self) -> Result<usize, StorageError> {
		let mut store = self.store.write().await;
		let before = store.len();
		store.retain(|_, entry| !entry.is_expired());
		let removed = before - store.len();
		Ok(removed)
	}

	// ==================== Atomic Operations ====================

	async fn set_nx(
		&self,
		key: &str,
		value: Vec<u8>,
		ttl: Option<Duration>,
	) -> Result<bool, StorageError> {
		let mut store = self.store.write().await;

		// Check if key exists and is not expired
		if let Some(entry) = store.get(key) {
			if !entry.is_expired() {
				return Ok(false); // Key exists
			}
			// Key is expired, remove it and continue
		}

		// Set the value
		let entry = StorageEntry {
			value,
			expires_at: ttl.map(|d| Instant::now() + d),
		};
		store.insert(key.to_string(), entry);
		Ok(true)
	}

	async fn compare_and_swap(
		&self,
		key: &str,
		expected: &[u8],
		new_value: Vec<u8>,
		ttl: Option<Duration>,
	) -> Result<bool, StorageError> {
		let mut store = self.store.write().await;

		match store.get(key) {
			Some(entry) if entry.is_expired() => {
				// Treat expired as not found
				Err(StorageError::NotFound(key.to_string()))
			},
			Some(entry) => {
				if entry.value == expected {
					// Match - swap the value
					let new_entry = StorageEntry {
						value: new_value,
						expires_at: ttl.map(|d| Instant::now() + d),
					};
					store.insert(key.to_string(), new_entry);
					Ok(true)
				} else {
					// Mismatch
					Ok(false)
				}
			},
			None => Err(StorageError::NotFound(key.to_string())),
		}
	}

	async fn delete_if_exists(&self, key: &str) -> Result<bool, StorageError> {
		let mut store = self.store.write().await;

		match store.remove(key) {
			Some(entry) if !entry.is_expired() => Ok(true), // Existed and was deleted
			Some(_) => Ok(false),                           // Was expired (treat as not existed)
			None => Ok(false),                              // Didn't exist
		}
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
		assert!(matches!(result, Err(StorageError::NotFound(_))));
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
