//! Storage backend implementations for the solver service.
//!
//! This module provides concrete implementations of the StorageInterface trait,
//! currently supporting file-based storage for persistence.

use crate::{StorageError, StorageInterface};
use async_trait::async_trait;
use std::path::PathBuf;
use std::time::Duration;
use tokio::fs;

/// File-based storage implementation.
///
/// This implementation stores data as binary files on the filesystem,
/// providing simple persistence without requiring external dependencies.
pub struct FileStorage {
	/// Base directory path for storing files.
	base_path: PathBuf,
}

impl FileStorage {
	/// Creates a new FileStorage instance with the specified base path.
	pub fn new(base_path: PathBuf) -> Self {
		Self { base_path }
	}

	/// Converts a storage key to a filesystem-safe file path.
	///
	/// Sanitizes the key by replacing problematic characters and
	/// appending a .bin extension.
	fn get_file_path(&self, key: &str) -> PathBuf {
		// Sanitize key to be filesystem-safe
		let safe_key = key.replace(['/', ':'], "_");
		self.base_path.join(format!("{}.bin", safe_key))
	}
}

#[async_trait]
impl StorageInterface for FileStorage {
	async fn get_bytes(&self, key: &str) -> Result<Vec<u8>, StorageError> {
		let path = self.get_file_path(key);

		match fs::read(&path).await {
			Ok(data) => Ok(data),
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(StorageError::NotFound),
			Err(e) => Err(StorageError::Backend(e.to_string())),
		}
	}

	async fn set_bytes(
		&self,
		key: &str,
		value: Vec<u8>,
		_ttl: Option<Duration>,
	) -> Result<(), StorageError> {
		let path = self.get_file_path(key);

		// Create parent directory if it doesn't exist
		if let Some(parent) = path.parent() {
			fs::create_dir_all(parent)
				.await
				.map_err(|e| StorageError::Backend(e.to_string()))?;
		}

		// Write atomically by writing to temp file then renaming
		let temp_path = path.with_extension("tmp");
		fs::write(&temp_path, value)
			.await
			.map_err(|e| StorageError::Backend(e.to_string()))?;

		fs::rename(&temp_path, &path)
			.await
			.map_err(|e| StorageError::Backend(e.to_string()))?;

		// TODO: TTL is ignored in this simple implementation

		Ok(())
	}

	async fn delete(&self, key: &str) -> Result<(), StorageError> {
		let path = self.get_file_path(key);

		match fs::remove_file(&path).await {
			Ok(_) => Ok(()),
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
			Err(e) => Err(StorageError::Backend(e.to_string())),
		}
	}

	async fn exists(&self, key: &str) -> Result<bool, StorageError> {
		let path = self.get_file_path(key);
		Ok(path.exists())
	}
}

/// Factory function to create a storage backend from configuration.
///
/// Configuration parameters:
/// - `storage_path`: Base directory for file storage (default: "./data/storage")
pub fn create_storage(config: &toml::Value) -> Box<dyn StorageInterface> {
	let storage_path = config
		.get("storage_path")
		.and_then(|v| v.as_str())
		.unwrap_or("./data/storage")
		.to_string();

	Box::new(FileStorage::new(PathBuf::from(storage_path)))
}
