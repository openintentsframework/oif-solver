//! Storage module for the OIF solver system.
//!
//! This module provides abstractions for persistent storage of solver data,
//! supporting different backend implementations such as in-memory, file-based,
//! or distributed storage systems.

use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;
use thiserror::Error;

/// Re-export implementations
pub mod implementations {
	pub mod file;
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
}

/// Trait defining the low-level interface for storage backends.
///
/// This trait must be implemented by any storage backend that wants to
/// integrate with the solver system. It provides basic key-value operations
/// with optional TTL support.
#[async_trait]
pub trait StorageInterface: Send + Sync {
	/// Retrieves raw bytes for the given key.
	async fn get_bytes(&self, key: &str) -> Result<Vec<u8>, StorageError>;

	/// Stores raw bytes with optional time-to-live.
	async fn set_bytes(
		&self,
		key: &str,
		value: Vec<u8>,
		ttl: Option<Duration>,
	) -> Result<(), StorageError>;

	/// Deletes the value associated with the given key.
	async fn delete(&self, key: &str) -> Result<(), StorageError>;

	/// Checks if a key exists in storage.
	async fn exists(&self, key: &str) -> Result<bool, StorageError>;
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

	/// Stores a serializable value with optional time-to-live.
	///
	/// The namespace and id are combined to form a unique key.
	/// The data is serialized to JSON before storage.
	pub async fn store_with_ttl<T: Serialize>(
		&self,
		namespace: &str,
		id: &str,
		data: &T,
		ttl: Option<Duration>,
	) -> Result<(), StorageError> {
		let key = format!("{}:{}", namespace, id);
		let bytes =
			serde_json::to_vec(data).map_err(|e| StorageError::Serialization(e.to_string()))?;
		self.backend.set_bytes(&key, bytes, ttl).await
	}

	/// Stores a serializable value without time-to-live.
	///
	/// Convenience method that calls store_with_ttl with None for TTL.
	pub async fn store<T: Serialize>(
		&self,
		namespace: &str,
		id: &str,
		data: &T,
	) -> Result<(), StorageError> {
		let key = format!("{}:{}", namespace, id);
		let bytes =
			serde_json::to_vec(data).map_err(|e| StorageError::Serialization(e.to_string()))?;
		self.backend.set_bytes(&key, bytes, None).await
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
}
