//! Configuration storage trait and implementation.
//!
//! This module provides a specialized storage interface for solver configuration
//! with optimistic locking support via versioning. It allows configuration to be
//! stored in any backend implementing [`StorageInterface`](crate::StorageInterface)
//! with concurrent access safety.
//!
//! # Architecture
//!
//! The `ConfigStore` is a thin wrapper around [`StorageInterface`] that adds:
//! - Optimistic locking via version checking
//! - JSON serialization/deserialization
//! - Versioned wrapper for change tracking
//!
//! The atomic operations (`set_nx`, `compare_and_swap`) are provided by
//! the underlying storage backend, while versioning logic stays in this module.
//!
//! # Example
//!
//! ```rust,ignore
//! use solver_storage::{config_store::create_config_store, StoreConfig};
//!
//! // For production (Redis)
//! let store = create_config_store::<MyConfig>(
//!     StoreConfig::Redis { url: "redis://localhost:6379".to_string() },
//!     "my-solver".to_string(),
//! )?;
//!
//! // For testing (Memory)
//! let store = create_config_store::<MyConfig>(
//!     StoreConfig::Memory,
//!     "test-solver".to_string(),
//! )?;
//! ```

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use solver_types::Versioned;
use std::marker::PhantomData;
use std::sync::Arc;
use thiserror::Error;
use tracing::debug;

use crate::{create_storage_backend, StorageError, StorageInterface, StoreConfig};

/// Errors that can occur during configuration storage operations.
#[derive(Debug, Error)]
pub enum ConfigStoreError {
	/// Configuration not found in storage.
	#[error("Configuration not found for solver: {0}")]
	NotFound(String),

	/// Configuration already exists (cannot seed twice).
	#[error("Configuration already exists for solver: {0}")]
	AlreadyExists(String),

	/// Version mismatch during optimistic locking.
	#[error("Version mismatch: expected {expected}, found {found}")]
	VersionMismatch { expected: u64, found: u64 },

	/// Serialization/deserialization error.
	#[error("Serialization error: {0}")]
	Serialization(String),

	/// Backend storage error (Redis connection, file I/O, etc.).
	#[error("Backend error: {0}")]
	Backend(String),

	/// Configuration error (invalid settings).
	#[error("Configuration error: {0}")]
	Configuration(String),
}

/// Trait for configuration storage operations.
///
/// This trait defines the interface for storing and retrieving solver
/// configuration with optimistic locking support. Implementations must
/// ensure thread-safety and handle concurrent access properly.
///
/// The trait is generic over the configuration type T to avoid coupling
/// with specific configuration implementations.
#[async_trait]
#[cfg_attr(feature = "testing", mockall::automock)]
pub trait ConfigStore<T>: Send + Sync
where
	T: Serialize + for<'de> Deserialize<'de> + Send + Sync + Clone,
{
	/// Retrieves the current configuration.
	///
	/// Returns the versioned configuration, including the data, version number,
	/// and last update timestamp.
	///
	/// # Errors
	///
	/// Returns [`ConfigStoreError::NotFound`] if no configuration exists.
	async fn get(&self) -> Result<Versioned<T>, ConfigStoreError>;

	/// Seeds the initial configuration.
	///
	/// This should only be called once when first deploying the solver.
	/// Subsequent updates should use the `update` method.
	///
	/// # Arguments
	///
	/// * `config` - The initial configuration to store
	///
	/// # Returns
	///
	/// The versioned configuration with version 1.
	///
	/// # Errors
	///
	/// Returns [`ConfigStoreError::AlreadyExists`] if configuration already exists.
	async fn seed(&self, config: T) -> Result<Versioned<T>, ConfigStoreError>;

	/// Updates the configuration with optimistic locking.
	///
	/// The update will only succeed if the current version matches
	/// `expected_version`. This prevents lost updates in concurrent scenarios.
	///
	/// # Arguments
	///
	/// * `config` - The new configuration
	/// * `expected_version` - The version number expected to be current
	///
	/// # Returns
	///
	/// The new versioned configuration with incremented version.
	///
	/// # Errors
	///
	/// Returns [`ConfigStoreError::VersionMismatch`] if the expected version
	/// doesn't match the current version.
	async fn update(
		&self,
		config: T,
		expected_version: u64,
	) -> Result<Versioned<T>, ConfigStoreError>;

	/// Checks if a configuration exists.
	///
	/// Useful for determining whether to call `seed` or `get`.
	async fn exists(&self) -> Result<bool, ConfigStoreError>;

	/// Deletes the configuration.
	///
	/// This is primarily useful for testing or cleanup scenarios.
	async fn delete(&self) -> Result<(), ConfigStoreError>;
}

/// Type alias for a boxed ConfigStore that works with JSON values.
/// This provides flexibility for storing any JSON-serializable configuration.
pub type JsonConfigStore = Box<dyn ConfigStore<Value> + Send + Sync>;

/// Creates a config store instance based on the specified configuration.
///
/// This factory function provides an abstraction layer for config store creation,
/// allowing different backend configurations to be used.
///
/// # Arguments
///
/// * `config` - Backend-specific configuration (see [`StoreConfig`](crate::StoreConfig))
/// * `solver_id` - Unique identifier for this solver instance
///
/// # Returns
///
/// A boxed `ConfigStore` trait object.
///
/// # Errors
///
/// Returns `ConfigStoreError::Configuration` if the configuration is invalid.
pub fn create_config_store<T>(
	config: StoreConfig,
	solver_id: String,
) -> Result<Box<dyn ConfigStore<T>>, ConfigStoreError>
where
	T: Serialize + for<'de> Deserialize<'de> + Send + Sync + Clone + 'static,
{
	if solver_id.is_empty() {
		return Err(ConfigStoreError::Configuration(
			"Solver ID cannot be empty".to_string(),
		));
	}

	// Validate Redis URL if provided
	if let StoreConfig::Redis { ref url } = config {
		if url.is_empty() {
			return Err(ConfigStoreError::Configuration(
				"Redis URL cannot be empty".to_string(),
			));
		}
	}

	let storage = create_storage_backend(config)
		.map_err(|e| ConfigStoreError::Configuration(e.to_string()))?;

	let store = StorageConfigStore::<T>::new(storage, solver_id)?;
	Ok(Box::new(store))
}

/// Convenience function to create a Redis config store.
pub fn create_redis_config_store<T>(
	redis_url: String,
	solver_id: String,
) -> Result<Box<dyn ConfigStore<T>>, ConfigStoreError>
where
	T: Serialize + for<'de> Deserialize<'de> + Send + Sync + Clone + 'static,
{
	create_config_store(StoreConfig::Redis { url: redis_url }, solver_id)
}

// =============================================================================
// StorageConfigStore - ConfigStore implementation over StorageInterface
// =============================================================================

/// Key prefix for configuration storage.
const CONFIG_KEY_PREFIX: &str = "config";

/// ConfigStore implementation backed by any [`StorageInterface`].
///
/// This is a thin wrapper that adds:
/// - JSON serialization with [`Versioned<T>`](solver_types::Versioned)
/// - Optimistic locking via `compare_and_swap`
/// - Atomic seeding via `set_nx`
///
/// Version management is handled in this struct, not in the storage layer.
pub struct StorageConfigStore<T> {
	/// Underlying storage backend
	storage: Arc<dyn StorageInterface>,
	/// Solver ID for key namespacing
	solver_id: String,
	/// Storage key for this solver's config
	key: String,
	/// Phantom data for type parameter
	_phantom: PhantomData<T>,
}

impl<T> StorageConfigStore<T>
where
	T: Serialize + for<'de> Deserialize<'de> + Send + Sync + Clone,
{
	/// Creates a new StorageConfigStore.
	///
	/// # Arguments
	///
	/// * `storage` - The underlying storage backend
	/// * `solver_id` - Unique identifier for this solver
	pub fn new(
		storage: Arc<dyn StorageInterface>,
		solver_id: String,
	) -> Result<Self, ConfigStoreError> {
		if solver_id.is_empty() {
			return Err(ConfigStoreError::Configuration(
				"Solver ID cannot be empty".to_string(),
			));
		}

		let key = format!("{CONFIG_KEY_PREFIX}:{solver_id}");

		Ok(Self {
			storage,
			solver_id,
			key,
			_phantom: PhantomData,
		})
	}

	/// Serialize a versioned config to bytes.
	fn serialize(&self, versioned: &Versioned<T>) -> Result<Vec<u8>, ConfigStoreError> {
		serde_json::to_vec(versioned)
			.map_err(|e| ConfigStoreError::Serialization(format!("Failed to serialize: {e}")))
	}

	/// Deserialize bytes to a versioned config.
	fn deserialize(&self, bytes: &[u8]) -> Result<Versioned<T>, ConfigStoreError> {
		serde_json::from_slice(bytes)
			.map_err(|e| ConfigStoreError::Serialization(format!("Failed to deserialize: {e}")))
	}
}

impl<T> std::fmt::Debug for StorageConfigStore<T> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("StorageConfigStore")
			.field("solver_id", &self.solver_id)
			.field("key", &self.key)
			.finish()
	}
}

#[async_trait]
impl<T> ConfigStore<T> for StorageConfigStore<T>
where
	T: Serialize + for<'de> Deserialize<'de> + Send + Sync + Clone,
{
	async fn get(&self) -> Result<Versioned<T>, ConfigStoreError> {
		let bytes = self
			.storage
			.get_bytes(&self.key)
			.await
			.map_err(|e| match e {
				StorageError::NotFound(_) => ConfigStoreError::NotFound(self.solver_id.clone()),
				other => ConfigStoreError::Backend(other.to_string()),
			})?;

		let versioned = self.deserialize(&bytes)?;
		debug!(
			key = %self.key,
			version = versioned.version,
			"retrieved config"
		);
		Ok(versioned)
	}

	async fn seed(&self, config: T) -> Result<Versioned<T>, ConfigStoreError> {
		let versioned = Versioned::new(config);
		let bytes = self.serialize(&versioned)?;

		// Use set_nx for atomic "create if not exists"
		let created = self
			.storage
			.set_nx(&self.key, bytes, None)
			.await
			.map_err(|e| ConfigStoreError::Backend(e.to_string()))?;

		if !created {
			return Err(ConfigStoreError::AlreadyExists(self.solver_id.clone()));
		}

		debug!(
			key = %self.key,
			version = versioned.version,
			"seeded config"
		);
		Ok(versioned)
	}

	async fn update(
		&self,
		config: T,
		expected_version: u64,
	) -> Result<Versioned<T>, ConfigStoreError> {
		// Get current value to compare
		let current_bytes = self
			.storage
			.get_bytes(&self.key)
			.await
			.map_err(|e| match e {
				StorageError::NotFound(_) => ConfigStoreError::NotFound(self.solver_id.clone()),
				other => ConfigStoreError::Backend(other.to_string()),
			})?;

		let current: Versioned<T> = self.deserialize(&current_bytes)?;

		// Check version
		if current.version != expected_version {
			return Err(ConfigStoreError::VersionMismatch {
				expected: expected_version,
				found: current.version,
			});
		}

		// Create new versioned config
		let mut new_versioned = Versioned::new(config);
		new_versioned.version = expected_version + 1;
		let new_bytes = self.serialize(&new_versioned)?;

		// Atomic compare-and-swap
		let swapped = self
			.storage
			.compare_and_swap(&self.key, &current_bytes, new_bytes, None)
			.await
			.map_err(|e| match e {
				StorageError::NotFound(_) => ConfigStoreError::NotFound(self.solver_id.clone()),
				other => ConfigStoreError::Backend(other.to_string()),
			})?;

		if !swapped {
			// Value changed between get and CAS - re-read to get actual version
			let actual_bytes = self
				.storage
				.get_bytes(&self.key)
				.await
				.map_err(|e| ConfigStoreError::Backend(e.to_string()))?;
			let actual: Versioned<T> = self.deserialize(&actual_bytes)?;

			return Err(ConfigStoreError::VersionMismatch {
				expected: expected_version,
				found: actual.version,
			});
		}

		debug!(
			key = %self.key,
			old_version = expected_version,
			new_version = new_versioned.version,
			"updated config"
		);
		Ok(new_versioned)
	}

	async fn exists(&self) -> Result<bool, ConfigStoreError> {
		self.storage
			.exists(&self.key)
			.await
			.map_err(|e| ConfigStoreError::Backend(e.to_string()))
	}

	async fn delete(&self) -> Result<(), ConfigStoreError> {
		self.storage
			.delete(&self.key)
			.await
			.map_err(|e| ConfigStoreError::Backend(e.to_string()))?;

		debug!(key = %self.key, "deleted config");
		Ok(())
	}
}

#[cfg(test)]
mod integration_tests {
	use super::*;
	use std::collections::HashMap;
	use uuid::Uuid;

	/// Test configuration struct for integration tests.
	#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
	pub struct TestConfig {
		pub solver_id: String,
		pub settings: HashMap<String, String>,
		pub version: u32,
	}

	/// Creates a minimal test configuration.
	fn create_test_config(solver_id: &str) -> TestConfig {
		let mut settings = HashMap::new();
		settings.insert("test_setting".to_string(), "test_value".to_string());
		settings.insert("environment".to_string(), "test".to_string());

		TestConfig {
			solver_id: solver_id.to_string(),
			settings,
			version: 1,
		}
	}

	/// Generate a unique solver ID for test isolation.
	fn unique_solver_id() -> String {
		format!("test-solver-{}", Uuid::new_v4())
	}

	// ==================== Factory Function Tests ====================

	#[tokio::test]
	#[ignore] // Requires running Redis
	async fn test_create_config_store_redis() {
		let solver_id = unique_solver_id();
		let store = create_config_store::<TestConfig>(
			StoreConfig::Redis {
				url: "redis://localhost:6379".to_string(),
			},
			solver_id.clone(),
		)
		.unwrap();

		// Verify it implements the ConfigStore trait correctly
		assert!(store.exists().await.is_ok());

		// Test basic operations through the factory-created store
		let config = create_test_config(&solver_id);
		let seeded = store.seed(config.clone()).await.unwrap();
		assert_eq!(seeded.version, 1);
		assert_eq!(seeded.data.solver_id, solver_id);

		// Cleanup
		store.delete().await.unwrap();
	}

	#[tokio::test]
	#[ignore] // Requires running Redis
	async fn test_create_redis_config_store_convenience() {
		let solver_id = unique_solver_id();
		let store = create_redis_config_store::<TestConfig>(
			"redis://localhost:6379".to_string(),
			solver_id.clone(),
		)
		.unwrap();

		// Should work identically to the generic factory
		let config = create_test_config(&solver_id);
		let seeded = store.seed(config.clone()).await.unwrap();
		assert_eq!(seeded.version, 1);
		assert_eq!(seeded.data.solver_id, solver_id);

		// Cleanup
		store.delete().await.unwrap();
	}

	// ==================== Memory Backend Tests (No Redis Required) ====================

	#[tokio::test]
	async fn test_memory_config_store_lifecycle() {
		let solver_id = unique_solver_id();
		let store = create_config_store::<TestConfig>(StoreConfig::Memory, solver_id.clone())
			.expect("Failed to create memory store");

		// 1. Should not exist initially
		assert!(!store.exists().await.unwrap());

		// 2. Seed config
		let config = create_test_config(&solver_id);
		let seeded = store.seed(config.clone()).await.unwrap();
		assert_eq!(seeded.version, 1);
		assert_eq!(seeded.data.solver_id, solver_id);

		// 3. Should exist now
		assert!(store.exists().await.unwrap());

		// 4. Get config
		let retrieved = store.get().await.unwrap();
		assert_eq!(retrieved.version, 1);
		assert_eq!(retrieved.data, config);

		// 5. Update config
		let mut updated_config = config.clone();
		updated_config.version = 42;
		let updated = store.update(updated_config.clone(), 1).await.unwrap();
		assert_eq!(updated.version, 2);
		assert_eq!(updated.data.version, 42);

		// 6. Delete
		store.delete().await.unwrap();
		assert!(!store.exists().await.unwrap());
	}

	#[tokio::test]
	async fn test_memory_seed_already_exists() {
		let solver_id = unique_solver_id();
		let store =
			create_config_store::<TestConfig>(StoreConfig::Memory, solver_id.clone()).unwrap();

		let config = create_test_config(&solver_id);

		// First seed should succeed
		store.seed(config.clone()).await.unwrap();

		// Second seed should fail
		let result = store.seed(config).await;
		assert!(matches!(
			result.unwrap_err(),
			ConfigStoreError::AlreadyExists(_)
		));
	}

	#[tokio::test]
	async fn test_memory_update_version_mismatch() {
		let solver_id = unique_solver_id();
		let store =
			create_config_store::<TestConfig>(StoreConfig::Memory, solver_id.clone()).unwrap();

		let config = create_test_config(&solver_id);
		store.seed(config.clone()).await.unwrap();

		// Update with wrong version
		let mut updated = config.clone();
		updated.version = 999;
		let result = store.update(updated, 5).await; // Wrong version

		assert!(matches!(
			result.unwrap_err(),
			ConfigStoreError::VersionMismatch {
				expected: 5,
				found: 1
			}
		));
	}

	#[tokio::test]
	async fn test_memory_get_not_found() {
		let solver_id = unique_solver_id();
		let store =
			create_config_store::<TestConfig>(StoreConfig::Memory, solver_id.clone()).unwrap();

		let result = store.get().await;
		assert!(matches!(result.unwrap_err(), ConfigStoreError::NotFound(_)));
	}

	#[tokio::test]
	async fn test_memory_update_not_found() {
		let solver_id = unique_solver_id();
		let store =
			create_config_store::<TestConfig>(StoreConfig::Memory, solver_id.clone()).unwrap();

		let config = create_test_config(&solver_id);
		let result = store.update(config, 1).await;
		assert!(matches!(result.unwrap_err(), ConfigStoreError::NotFound(_)));
	}

	// ==================== Unit Tests ====================

	#[test]
	fn test_config_store_error_types() {
		// Test error formatting
		let not_found = ConfigStoreError::NotFound("test-solver".to_string());
		assert_eq!(
			format!("{not_found}"),
			"Configuration not found for solver: test-solver"
		);

		let already_exists = ConfigStoreError::AlreadyExists("test-solver".to_string());
		assert_eq!(
			format!("{already_exists}"),
			"Configuration already exists for solver: test-solver"
		);

		let version_mismatch = ConfigStoreError::VersionMismatch {
			expected: 1,
			found: 2,
		};
		assert_eq!(
			format!("{version_mismatch}"),
			"Version mismatch: expected 1, found 2"
		);

		let serialization = ConfigStoreError::Serialization("invalid JSON".to_string());
		assert_eq!(
			format!("{serialization}"),
			"Serialization error: invalid JSON"
		);

		let backend = ConfigStoreError::Backend("connection failed".to_string());
		assert_eq!(format!("{backend}"), "Backend error: connection failed");

		let config = ConfigStoreError::Configuration("invalid config".to_string());
		assert_eq!(format!("{config}"), "Configuration error: invalid config");
	}

	#[test]
	fn test_store_config_enum() {
		// Test Redis configuration
		let redis_config = StoreConfig::Redis {
			url: "redis://localhost:6379".to_string(),
		};

		// Should be cloneable and debuggable
		let _cloned = redis_config.clone();
		let _debug_str = format!("{redis_config:?}");

		// Test that we can create different configurations
		let redis_config2 = StoreConfig::Redis {
			url: "redis://remote:6379".to_string(),
		};

		assert_ne!(
			format!("{redis_config:?}"),
			format!("{:?}", redis_config2)
		);
	}

	#[test]
	fn test_versioned_type_alias() {
		// Test that JsonConfigStore type alias works
		let _: Option<JsonConfigStore> = None;

		// Test that we can work with the Value type
		use serde_json::json;
		let test_value = json!({
			"solver_id": "test",
			"config": {
				"networks": ["mainnet", "testnet"]
			}
		});

		let versioned = Versioned::new(test_value.clone());
		assert_eq!(versioned.version, 1);
		assert_eq!(versioned.data, test_value);
	}

	// ==================== Error Handling Tests ====================

	#[tokio::test]
	async fn test_redis_config_validation() {
		// Test empty URL
		let result =
			create_redis_config_store::<TestConfig>("".to_string(), "test-solver".to_string());
		assert!(result.is_err());
		if let Err(error) = result {
			assert!(matches!(error, ConfigStoreError::Configuration(_)));
		}

		// Test empty solver ID
		let result = create_redis_config_store::<TestConfig>(
			"redis://localhost:6379".to_string(),
			"".to_string(),
		);
		assert!(result.is_err());
		if let Err(error) = result {
			assert!(matches!(error, ConfigStoreError::Configuration(_)));
		}

		// Test valid configuration
		let result = create_redis_config_store::<TestConfig>(
			"redis://localhost:6379".to_string(),
			"test-solver".to_string(),
		);
		assert!(result.is_ok());
	}

	#[tokio::test]
	#[ignore] // Requires running Redis
	async fn test_config_not_found_error() {
		let solver_id = unique_solver_id();
		let store = create_redis_config_store::<TestConfig>(
			"redis://localhost:6379".to_string(),
			solver_id.clone(),
		)
		.unwrap();

		// Ensure config doesn't exist
		let _ = store.delete().await;

		// Getting non-existent config should return NotFound
		let result = store.get().await;
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), ConfigStoreError::NotFound(_)));

		// Updating non-existent config should return NotFound
		let config = create_test_config(&solver_id);
		let result = store.update(config, 1).await;
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), ConfigStoreError::NotFound(_)));
	}

	#[tokio::test]
	#[ignore] // Requires running Redis
	async fn test_already_exists_error() {
		let solver_id = unique_solver_id();
		let store = create_redis_config_store::<TestConfig>(
			"redis://localhost:6379".to_string(),
			solver_id.clone(),
		)
		.unwrap();

		// Cleanup
		let _ = store.delete().await;

		// Seed initial config
		let config = create_test_config(&solver_id);
		store.seed(config.clone()).await.unwrap();

		// Seeding again should fail
		let result = store.seed(config).await;
		assert!(result.is_err());
		assert!(matches!(
			result.unwrap_err(),
			ConfigStoreError::AlreadyExists(_)
		));

		// Cleanup
		store.delete().await.unwrap();
	}

	// ==================== Concurrent Access Tests ====================

	#[tokio::test]
	#[ignore] // Requires running Redis
	async fn test_concurrent_update_version_conflict() {
		let solver_id = unique_solver_id();

		// Create two separate stores for the same solver
		let store1 = create_redis_config_store::<TestConfig>(
			"redis://localhost:6379".to_string(),
			solver_id.clone(),
		)
		.unwrap();
		let store2 = create_redis_config_store::<TestConfig>(
			"redis://localhost:6379".to_string(),
			solver_id.clone(),
		)
		.unwrap();

		// Cleanup
		let _ = store1.delete().await;

		// Seed initial config
		let config = create_test_config(&solver_id);
		store1.seed(config.clone()).await.unwrap();

		// Both stores get the same version
		let v1 = store1.get().await.unwrap();
		let v2 = store2.get().await.unwrap();
		assert_eq!(v1.version, v2.version);
		assert_eq!(v1.version, 1);

		// Store1 updates successfully
		let mut updated_config1 = v1.data.clone();
		updated_config1.version = 999;
		let result1 = store1.update(updated_config1, v1.version).await;
		assert!(result1.is_ok());
		assert_eq!(result1.unwrap().version, 2);

		// Store2 update should fail with version mismatch (still trying to update version 1)
		let mut updated_config2 = v2.data.clone();
		updated_config2.version = 888;
		let result2 = store2.update(updated_config2, v2.version).await;

		assert!(result2.is_err());
		match result2.unwrap_err() {
			ConfigStoreError::VersionMismatch { expected, found } => {
				assert_eq!(expected, 1);
				assert_eq!(found, 2); // Version was incremented by store1
			},
			_ => panic!("Expected VersionMismatch error"),
		}

		// Store2 can succeed if it gets the updated version first
		let current = store2.get().await.unwrap();
		assert_eq!(current.version, 2);

		let mut final_config = current.data.clone();
		final_config.version = 777;
		let result3 = store2.update(final_config, current.version).await;
		assert!(result3.is_ok());
		assert_eq!(result3.unwrap().version, 3);

		// Cleanup
		store1.delete().await.unwrap();
	}

	#[tokio::test]
	#[ignore] // Requires running Redis
	async fn test_multiple_solvers_isolation() {
		let solver1_id = unique_solver_id();
		let solver2_id = unique_solver_id();

		let store1 = create_redis_config_store::<TestConfig>(
			"redis://localhost:6379".to_string(),
			solver1_id.clone(),
		)
		.unwrap();
		let store2 = create_redis_config_store::<TestConfig>(
			"redis://localhost:6379".to_string(),
			solver2_id.clone(),
		)
		.unwrap();

		// Cleanup both
		let _ = store1.delete().await;
		let _ = store2.delete().await;

		// Each solver should have isolated configuration
		let config1 = create_test_config(&solver1_id);
		let config2 = create_test_config(&solver2_id);

		store1.seed(config1).await.unwrap();
		store2.seed(config2).await.unwrap();

		// Verify isolation
		let retrieved1 = store1.get().await.unwrap();
		let retrieved2 = store2.get().await.unwrap();

		assert_eq!(retrieved1.data.solver_id, solver1_id);
		assert_eq!(retrieved2.data.solver_id, solver2_id);
		assert_ne!(retrieved1.data.solver_id, retrieved2.data.solver_id);

		// Updates should be independent
		let mut updated1 = retrieved1.data.clone();
		updated1.version = 111;
		let result1 = store1.update(updated1, retrieved1.version).await.unwrap();
		assert_eq!(result1.version, 2);

		// Solver2's version should still be 1
		let current2 = store2.get().await.unwrap();
		assert_eq!(current2.version, 1);

		// Cleanup
		store1.delete().await.unwrap();
		store2.delete().await.unwrap();
	}

	// ==================== Integration Tests ====================

	/// Tests the complete seed → get → update flow with Redis.
	#[tokio::test]
	#[ignore] // Requires running Redis
	async fn test_redis_seed_get_update_flow() {
		let solver_id = unique_solver_id();
		let store = create_redis_config_store::<TestConfig>(
			"redis://localhost:6379".to_string(),
			solver_id.clone(),
		)
		.expect("Failed to create store");

		// Cleanup any existing data
		let _ = store.delete().await;

		// 1. Verify config doesn't exist
		let exists = store.exists().await.expect("exists() failed");
		assert!(!exists, "Config should not exist initially");

		// 2. Seed initial config
		let config = create_test_config(&solver_id);
		let seeded = store.seed(config.clone()).await.expect("seed() failed");
		assert_eq!(seeded.version, 1, "Initial version should be 1");
		assert_eq!(seeded.data.solver_id, solver_id);

		// 3. Verify config exists now
		let exists = store.exists().await.expect("exists() failed");
		assert!(exists, "Config should exist after seeding");

		// 4. Get the config
		let retrieved = store.get().await.expect("get() failed");
		assert_eq!(retrieved.version, 1);
		assert_eq!(retrieved.data.solver_id, solver_id);

		// 5. Update the config
		let mut updated_config = retrieved.data.clone();
		updated_config.version = 2;

		let updated = store
			.update(updated_config.clone(), 1)
			.await
			.expect("update() failed");
		assert_eq!(updated.version, 2, "Version should increment");
		assert_eq!(updated.data.version, 2);

		// Cleanup
		store.delete().await.expect("delete() failed");
	}

	#[tokio::test]
	#[ignore] // Requires running Redis
	async fn test_optimistic_locking_version_mismatch() {
		let solver_id = unique_solver_id();
		let store = create_redis_config_store::<TestConfig>(
			"redis://localhost:6379".to_string(),
			solver_id.clone(),
		)
		.unwrap();

		// Cleanup
		let _ = store.delete().await;

		// Seed initial configuration
		let config = create_test_config(&solver_id);
		let seeded = store.seed(config.clone()).await.unwrap();
		assert_eq!(seeded.version, 1);

		// Update with correct version should succeed
		let mut updated_config = config.clone();
		updated_config.version = 999;
		let updated = store.update(updated_config, 1).await.unwrap();
		assert_eq!(updated.version, 2);

		// Update with stale version should fail
		let mut stale_config = config.clone();
		stale_config
			.settings
			.insert("stale_update".to_string(), "should_fail".to_string());

		let result = store.update(stale_config, 1).await; // Using stale version 1
		assert!(result.is_err());
		assert!(matches!(
			result.unwrap_err(),
			ConfigStoreError::VersionMismatch {
				expected: 1,
				found: 2
			}
		));

		// Configuration should be unchanged
		let current = store.get().await.unwrap();
		assert_eq!(current.version, 2);
		assert_eq!(current.data.version, 999); // Should still have the successful update

		// Cleanup
		store.delete().await.unwrap();
	}

	#[tokio::test]
	#[ignore] // Requires running Redis
	async fn test_update_not_found() {
		let solver_id = unique_solver_id();
		let store = create_redis_config_store::<TestConfig>(
			"redis://localhost:6379".to_string(),
			solver_id.clone(),
		)
		.unwrap();

		// Cleanup to ensure clean state
		let _ = store.delete().await;

		// Update on non-existent config should return NotFound
		let config = create_test_config(&solver_id);
		let result = store.update(config, 1).await;
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), ConfigStoreError::NotFound(id) if id == solver_id));
	}

	#[tokio::test]
	#[ignore] // Requires running Redis
	async fn test_delete_idempotent() {
		let solver_id = unique_solver_id();
		let store = create_redis_config_store::<TestConfig>(
			"redis://localhost:6379".to_string(),
			solver_id.clone(),
		)
		.unwrap();

		// Cleanup to ensure clean state
		let _ = store.delete().await;

		// Delete on non-existent config should succeed (idempotent)
		assert!(store.delete().await.is_ok());

		// Seed, then delete, then delete again
		let config = create_test_config(&solver_id);
		store.seed(config).await.unwrap();

		// First delete should succeed
		assert!(store.delete().await.is_ok());
		assert!(!store.exists().await.unwrap());

		// Second delete should still succeed (idempotent)
		assert!(store.delete().await.is_ok());
	}

	#[tokio::test]
	#[ignore] // Requires running Redis
	async fn test_config_persistence_across_connections() {
		let solver_id = unique_solver_id();

		// Create first store instance
		let store1 = create_redis_config_store::<TestConfig>(
			"redis://localhost:6379".to_string(),
			solver_id.clone(),
		)
		.unwrap();

		// Cleanup
		let _ = store1.delete().await;

		// Seed configuration
		let config = create_test_config(&solver_id);
		let seeded = store1.seed(config.clone()).await.unwrap();
		assert_eq!(seeded.version, 1);

		// Drop the first store and create a new one
		drop(store1);
		let store2 = create_redis_config_store::<TestConfig>(
			"redis://localhost:6379".to_string(),
			solver_id.clone(),
		)
		.unwrap();

		// Configuration should persist across connections
		let retrieved = store2.get().await.unwrap();
		assert_eq!(retrieved.version, 1);
		assert_eq!(retrieved.data, config);

		// Should be able to update from new connection
		let mut updated_config = config.clone();
		updated_config.version = 123;
		let updated = store2.update(updated_config.clone(), 1).await.unwrap();
		assert_eq!(updated.version, 2);
		assert_eq!(updated.data, updated_config);

		// Cleanup
		store2.delete().await.unwrap();
	}
}
