//! Storage backend implementations for the solver service.
//!
//! This module provides concrete implementations of the StorageInterface trait,
//! currently supporting file-based storage for persistence.

use crate::{StorageError, StorageInterface};
use async_trait::async_trait;
use solver_types::{ConfigSchema, Field, FieldType, Schema, StorageKey, ValidationError};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::fs;

#[allow(clippy::doc_nested_refdefs)]
/// Fixed-size file header for TTL support.
///
/// Binary layout (64 bytes total):
/// - [0-3]: Magic bytes "OIFS"
/// - [4-5]: Version (u16, little-endian)
/// - [6-13]: Expiration timestamp (u64, little-endian, Unix seconds, 0 = never)
/// - [14-63]: Reserved/padding for future use
#[derive(Debug, Clone)]
struct FileHeader {
	magic: [u8; 4],
	version: u16,
	expires_at: u64,
	padding: [u8; 50],
}

impl FileHeader {
	const MAGIC: &'static [u8; 4] = b"OIFS";
	const VERSION: u16 = 1;
	const SIZE: usize = 64;

	/// Creates a new header with the given TTL.
	fn new(ttl: Duration) -> Self {
		let expires_at = if ttl.is_zero() {
			0 // Permanent storage
		} else {
			SystemTime::now()
				.duration_since(UNIX_EPOCH)
				.unwrap()
				.as_secs()
				.saturating_add(ttl.as_secs())
		};

		Self {
			magic: *Self::MAGIC,
			version: Self::VERSION,
			expires_at,
			padding: [0; 50],
		}
	}

	/// Serializes the header to bytes.
	fn serialize(&self) -> [u8; Self::SIZE] {
		let mut bytes = [0u8; Self::SIZE];
		bytes[0..4].copy_from_slice(&self.magic);
		bytes[4..6].copy_from_slice(&self.version.to_le_bytes());
		bytes[6..14].copy_from_slice(&self.expires_at.to_le_bytes());
		bytes[14..64].copy_from_slice(&self.padding);
		bytes
	}

	/// Deserializes a header from bytes.
	fn deserialize(bytes: &[u8]) -> Result<Self, StorageError> {
		if bytes.len() < Self::SIZE {
			return Err(StorageError::Backend("File too small for header".into()));
		}

		let mut magic = [0u8; 4];
		magic.copy_from_slice(&bytes[0..4]);

		// Check magic bytes
		if magic != *Self::MAGIC {
			// Not a header, treat as legacy file
			return Err(StorageError::Backend("Legacy file format".into()));
		}

		let version = u16::from_le_bytes([bytes[4], bytes[5]]);
		if version > Self::VERSION {
			return Err(StorageError::Backend(format!(
				"Unsupported file version: {}",
				version
			)));
		}

		let mut expires_bytes = [0u8; 8];
		expires_bytes.copy_from_slice(&bytes[6..14]);
		let expires_at = u64::from_le_bytes(expires_bytes);

		let mut padding = [0u8; 50];
		padding.copy_from_slice(&bytes[14..64]);

		Ok(Self {
			magic,
			version,
			expires_at,
			padding,
		})
	}

	/// Checks if the data has expired.
	fn is_expired(&self) -> bool {
		if self.expires_at == 0 {
			return false; // Permanent storage
		}

		let now = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap()
			.as_secs();

		now >= self.expires_at
	}
}

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
					ttls.insert(storage_key, Duration::from_secs(ttl_value));
				}
			}
		}

		Self { ttls }
	}

	/// Gets the TTL for a specific storage key.
	fn get_ttl(&self, storage_key: StorageKey) -> Duration {
		self.ttls
			.get(&storage_key)
			.copied()
			.unwrap_or(Duration::ZERO)
	}
}

/// File-based storage implementation.
///
/// This implementation stores data as binary files on the filesystem,
/// providing simple persistence without requiring external dependencies.
/// Files include a header with TTL information for automatic expiration.
pub struct FileStorage {
	/// Base directory path for storing files.
	base_path: PathBuf,
	/// TTL configuration for different storage keys.
	ttl_config: TtlConfig,
}

impl FileStorage {
	/// Creates a new FileStorage instance with the specified base path and TTL config.
	pub fn new(base_path: PathBuf, ttl_config: TtlConfig) -> Self {
		Self {
			base_path,
			ttl_config,
		}
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

	/// Gets the TTL for a given key based on its namespace.
	fn get_ttl_for_key(&self, key: &str) -> Duration {
		// Parse namespace from key (e.g., "orders:123" -> "orders")
		let namespace = key.split(':').next().unwrap_or("");

		// Try to parse the namespace as a StorageKey
		namespace
			.parse::<StorageKey>()
			.map(|sk| self.ttl_config.get_ttl(sk))
			.unwrap_or(Duration::ZERO)
	}

	/// Removes all expired files from storage
	async fn cleanup_expired_files(&self) -> Result<usize, StorageError> {
		let mut removed = 0;
		let mut entries = fs::read_dir(&self.base_path)
			.await
			.map_err(|e| StorageError::Backend(e.to_string()))?;

		while let Some(entry) = entries
			.next_entry()
			.await
			.map_err(|e| StorageError::Backend(e.to_string()))?
		{
			let path = entry.path();
			if path.extension() == Some(std::ffi::OsStr::new("bin")) {
				// Read just the header (first 64 bytes)
				match fs::read(&path).await {
					Ok(data) => {
						if data.len() >= FileHeader::SIZE {
							if let Ok(header) = FileHeader::deserialize(&data[..FileHeader::SIZE]) {
								if header.is_expired() {
									if let Err(e) = fs::remove_file(&path).await {
										tracing::warn!(
											"Failed to remove expired file {:?}: {}",
											path,
											e
										);
									} else {
										removed += 1;
									}
								}
							}
						} else {
							tracing::debug!(
								"Skipping file {:?}: too small ({} bytes, expected at least {})",
								path,
								data.len(),
								FileHeader::SIZE
							);
						}
					}
					Err(e) => {
						tracing::debug!("Skipping file {:?}: could not be read: {}", path, e);
					}
				}
			}
		}
		Ok(removed)
	}
}

#[async_trait]
impl StorageInterface for FileStorage {
	async fn get_bytes(&self, key: &str) -> Result<Vec<u8>, StorageError> {
		let path = self.get_file_path(key);

		let data = match fs::read(&path).await {
			Ok(data) => data,
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
				return Err(StorageError::NotFound)
			}
			Err(e) => return Err(StorageError::Backend(e.to_string())),
		};

		// Try to parse header
		match FileHeader::deserialize(&data) {
			Ok(header) => {
				// Check if expired
				if header.is_expired() {
					return Err(StorageError::NotFound);
				}

				// Return data after header
				if data.len() > FileHeader::SIZE {
					Ok(data[FileHeader::SIZE..].to_vec())
				} else {
					Ok(Vec::new())
				}
			}
			Err(_) => {
				// Legacy file without header, return as-is
				Ok(data)
			}
		}
	}

	async fn set_bytes(
		&self,
		key: &str,
		value: Vec<u8>,
		ttl: Option<Duration>,
	) -> Result<(), StorageError> {
		let path = self.get_file_path(key);

		// Create parent directory if it doesn't exist
		if let Some(parent) = path.parent() {
			fs::create_dir_all(parent)
				.await
				.map_err(|e| StorageError::Backend(e.to_string()))?;
		}

		// Determine TTL: use provided TTL, or get from config based on key
		let ttl = ttl.unwrap_or_else(|| self.get_ttl_for_key(key));

		// Create header
		let header = FileHeader::new(ttl);
		let header_bytes = header.serialize();

		// Combine header and data
		let mut file_data = Vec::with_capacity(FileHeader::SIZE + value.len());
		file_data.extend_from_slice(&header_bytes);
		file_data.extend_from_slice(&value);

		// Write atomically by writing to temp file then renaming
		let temp_path = path.with_extension("tmp");
		fs::write(&temp_path, file_data)
			.await
			.map_err(|e| StorageError::Backend(e.to_string()))?;

		fs::rename(&temp_path, &path)
			.await
			.map_err(|e| StorageError::Backend(e.to_string()))?;

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

	fn config_schema(&self) -> Box<dyn ConfigSchema> {
		Box::new(FileStorageSchema)
	}

	async fn cleanup_expired(&self) -> Result<usize, StorageError> {
		self.cleanup_expired_files().await
	}
}

/// Configuration schema for FileStorage.
pub struct FileStorageSchema;

impl ConfigSchema for FileStorageSchema {
	fn validate(&self, config: &toml::Value) -> Result<(), ValidationError> {
		// Build TTL fields dynamically based on StorageKey variants
		let mut optional_fields = vec![Field::new("storage_path", FieldType::String)];

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
			vec![], // No required fields
			optional_fields,
		);

		// First validate against schema
		schema.validate(config)?;

		Ok(())
	}
}

/// Factory function to create a storage backend from configuration.
///
/// Configuration parameters:
/// - `storage_path`: Base directory for file storage (default: "./data/storage")
/// - `ttl_orders`: TTL in seconds for orders (default: 0)
/// - `ttl_intents`: TTL in seconds for intents (default: 0)
/// - `ttl_order_by_tx_hash`: TTL in seconds for order_by_tx_hash (default: 0)
pub fn create_storage(config: &toml::Value) -> Result<Box<dyn StorageInterface>, StorageError> {
	let storage_path = config
		.get("storage_path")
		.and_then(|v| v.as_str())
		.unwrap_or("./data/storage")
		.to_string();

	let ttl_config = TtlConfig::from_config(config);

	Ok(Box::new(FileStorage::new(
		PathBuf::from(storage_path),
		ttl_config,
	)))
}
