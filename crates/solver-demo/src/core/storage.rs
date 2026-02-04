//! Persistent JSON-based storage for application data
//!
//! This module provides a simple file-based storage system for persisting
//! application state, session data, and configuration between CLI invocations.
//! Data is stored as JSON files in a designated directory.

use crate::types::error::{Error, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// File-based JSON storage for application data persistence
///
/// Provides a simple key-value storage system using JSON files in a root
/// directory. Supports saving, loading, deleting, and listing stored items.
/// Each key corresponds to a separate JSON file.
#[derive(Debug, Clone)]
pub struct Storage {
	root: Arc<PathBuf>,
}

impl Storage {
	/// Creates a new storage instance with the specified root directory
	///
	/// # Arguments
	/// * `root` - Root directory path for storage files
	///
	/// # Returns
	/// New storage instance
	///
	/// # Errors
	/// Returns error if directory creation fails
	pub fn new(root: &Path) -> Result<Self> {
		if !root.exists() {
			std::fs::create_dir_all(root)
				.map_err(|_| Error::DirectoryCreationFailed(root.to_path_buf()))?;
		}

		Ok(Self {
			root: Arc::new(root.to_path_buf()),
		})
	}

	/// Saves serializable data to a JSON file
	///
	/// # Arguments
	/// * `key` - Storage key used as filename (without .json extension)
	/// * `value` - Data to serialize and save
	///
	/// # Errors
	/// Returns error if file creation fails, directory creation fails, or serialization fails
	pub fn save<T: Serialize>(&self, key: &str, value: &T) -> Result<()> {
		let path = self.path_for(key);

		if let Some(parent) = path.parent() {
			std::fs::create_dir_all(parent)?;
		}

		let file = std::fs::File::create(&path)
			.map_err(|e| Error::StorageError(format!("Failed to create {key}: {e}")))?;

		serde_json::to_writer_pretty(file, value)
			.map_err(|e| Error::StorageError(format!("Failed to write {key}: {e}")))?;

		Ok(())
	}

	/// Loads and deserializes data from a JSON file
	///
	/// # Arguments
	/// * `key` - Storage key to load data from
	///
	/// # Returns
	/// Deserialized data of the specified type
	///
	/// # Errors
	/// Returns error if file not found, file opening fails, or deserialization fails
	pub fn load<T: DeserializeOwned>(&self, key: &str) -> Result<T> {
		let path = self.path_for(key);

		if !path.exists() {
			return Err(Error::StorageError(format!("File not found: {key}")));
		}

		let file = std::fs::File::open(&path)
			.map_err(|e| Error::StorageError(format!("Failed to open {key}: {e}")))?;

		serde_json::from_reader(file)
			.map_err(|e| Error::StorageError(format!("Failed to read {key}: {e}")))
	}

	/// Checks if a storage key exists
	///
	/// # Arguments
	/// * `key` - Storage key to check
	///
	/// # Returns
	/// True if the key exists as a file, false otherwise
	pub fn exists(&self, key: &str) -> bool {
		self.path_for(key).exists()
	}

	/// Deletes a stored item by key
	///
	/// # Arguments
	/// * `key` - Storage key to delete
	///
	/// # Errors
	/// Returns error if file deletion fails
	pub fn delete(&self, key: &str) -> Result<()> {
		let path = self.path_for(key);

		if path.exists() {
			std::fs::remove_file(&path)
				.map_err(|e| Error::StorageError(format!("Failed to delete {key}: {e}")))?;
		}

		Ok(())
	}

	/// Constructs the file path for a given storage key
	///
	/// # Arguments
	/// * `key` - Storage key to get path for
	///
	/// # Returns
	/// Complete file path with .json extension
	fn path_for(&self, key: &str) -> PathBuf {
		self.root.join(format!("{key}.json"))
	}

	/// Creates a new storage instance for a subdirectory
	///
	/// # Arguments
	/// * `name` - Subdirectory name
	///
	/// # Returns
	/// New storage instance rooted in the subdirectory
	///
	/// # Errors
	/// Returns error if subdirectory creation fails
	pub fn subdir(&self, name: &str) -> Result<Storage> {
		let path = self.root.join(name);
		Storage::new(&path)
	}

	/// Lists all storage keys in the root directory
	///
	/// # Returns
	/// Vector of storage keys (filenames without .json extension)
	///
	/// # Errors
	/// Returns error if directory reading fails or I/O errors occur
	pub fn list_keys(&self) -> Result<Vec<String>> {
		let mut keys = Vec::new();

		let entries = std::fs::read_dir(&*self.root)
			.map_err(|e| Error::StorageError(format!("Failed to read directory: {e}")))?;

		for entry in entries {
			let entry = entry?;
			let path = entry.path();

			if path.is_file() {
				if let Some(stem) = path.file_stem() {
					if let Some(ext) = path.extension() {
						if ext == "json" {
							keys.push(stem.to_string_lossy().to_string());
						}
					}
				}
			}
		}

		Ok(keys)
	}

	/// Returns the root directory path for this storage instance
	///
	/// # Returns
	/// Reference to the root directory path
	pub fn root(&self) -> &Path {
		&self.root
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde::Deserialize;
	use tempfile::TempDir;

	#[derive(Debug, Serialize, Deserialize, PartialEq)]
	struct TestData {
		value: String,
	}

	#[test]
	fn test_storage_operations() {
		let temp_dir = TempDir::new().unwrap();
		let storage = Storage::new(temp_dir.path()).unwrap();

		// Test save and load
		let data = TestData {
			value: "test".to_string(),
		};

		storage.save("test", &data).unwrap();
		assert!(storage.exists("test"));

		let loaded: TestData = storage.load("test").unwrap();
		assert_eq!(loaded, data);

		// Test delete
		storage.delete("test").unwrap();
		assert!(!storage.exists("test"));
	}

	#[test]
	fn test_subdir() {
		let temp_dir = TempDir::new().unwrap();
		let storage = Storage::new(temp_dir.path()).unwrap();

		let sub = storage.subdir("contracts").unwrap();

		let data = TestData {
			value: "contract".to_string(),
		};

		sub.save("abi", &data).unwrap();

		// Check the file was created in the subdirectory
		let expected_path = temp_dir.path().join("contracts").join("abi.json");
		assert!(expected_path.exists());
	}
}
