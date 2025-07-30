//! In-memory storage backend implementation for the solver service.
//!
//! This module provides a memory-based implementation of the StorageInterface trait,
//! useful for testing and development scenarios where persistence is not required.

use crate::{StorageError, StorageInterface};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Entry in the memory storage with optional expiration.
#[derive(Clone)]
struct MemoryEntry {
	/// The stored data.
	data: Vec<u8>,
	/// Optional expiration time.
	expires_at: Option<Instant>,
}

/// In-memory storage implementation.
///
/// This implementation stores data in a HashMap in memory,
/// providing fast access but no persistence across restarts.
pub struct MemoryStorage {
	/// The in-memory store protected by a read-write lock.
	store: Arc<RwLock<HashMap<String, MemoryEntry>>>,
}

impl MemoryStorage {
	/// Creates a new MemoryStorage instance.
	pub fn new() -> Self {
		Self {
			store: Arc::new(RwLock::new(HashMap::new())),
		}
	}

	/// Removes expired entries from the store.
	///
	/// This is called internally during operations to clean up expired data.
	async fn cleanup_expired(&self) {
		let now = Instant::now();
		let mut store = self.store.write().await;
		store.retain(|_, entry| entry.expires_at.is_none() || entry.expires_at.unwrap() > now);
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
		// Clean up expired entries periodically
		self.cleanup_expired().await;

		let store = self.store.read().await;
		match store.get(key) {
			Some(entry) => {
				// Check if entry has expired
				if let Some(expires_at) = entry.expires_at {
					if expires_at <= Instant::now() {
						return Err(StorageError::NotFound);
					}
				}
				Ok(entry.data.clone())
			}
			None => Err(StorageError::NotFound),
		}
	}

	async fn set_bytes(
		&self,
		key: &str,
		value: Vec<u8>,
		ttl: Option<Duration>,
	) -> Result<(), StorageError> {
		let expires_at = ttl.map(|duration| Instant::now() + duration);
		let entry = MemoryEntry {
			data: value,
			expires_at,
		};

		let mut store = self.store.write().await;
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
			Some(entry) => {
				// Check if entry has expired
				if let Some(expires_at) = entry.expires_at {
					Ok(expires_at > Instant::now())
				} else {
					Ok(true)
				}
			}
			None => Ok(false),
		}
	}
}

/// Factory function to create a memory storage backend from configuration.
///
/// Configuration parameters:
/// - None required for memory storage
pub fn create_storage(_config: &toml::Value) -> Box<dyn StorageInterface> {
	Box::new(MemoryStorage::new())
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::time::Duration;
	use tokio::time::sleep;

	#[tokio::test]
	async fn test_basic_operations() {
		let storage = MemoryStorage::new();

		// Test set and get
		let key = "test_key";
		let value = b"test_value".to_vec();
		storage.set_bytes(key, value.clone(), None).await.unwrap();

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
	async fn test_ttl() {
		let storage = MemoryStorage::new();

		// Set with short TTL
		let key = "ttl_key";
		let value = b"ttl_value".to_vec();
		let ttl = Duration::from_millis(100);
		storage
			.set_bytes(key, value.clone(), Some(ttl))
			.await
			.unwrap();

		// Should exist immediately
		assert!(storage.exists(key).await.unwrap());
		let retrieved = storage.get_bytes(key).await.unwrap();
		assert_eq!(retrieved, value);

		// Wait for expiration
		sleep(Duration::from_millis(150)).await;

		// Should no longer exist
		assert!(!storage.exists(key).await.unwrap());
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
		storage.set_bytes(key, value1.clone(), None).await.unwrap();
		let retrieved = storage.get_bytes(key).await.unwrap();
		assert_eq!(retrieved, value1);

		// Overwrite with new value
		storage.set_bytes(key, value2.clone(), None).await.unwrap();
		let retrieved = storage.get_bytes(key).await.unwrap();
		assert_eq!(retrieved, value2);
	}
}
