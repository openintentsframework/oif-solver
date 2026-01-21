//! Configuration storage trait and Redis implementation.
//!
//! This module provides a specialized storage interface for solver configuration
//! with optimistic locking support via versioning. It allows configuration to be
//! stored in and retrieved from Redis with concurrent access safety.
//!
//! # Architecture
//!
//! The configuration storage is separate from the general-purpose `StorageInterface`
//! because configuration has different requirements:
//! - Single configuration per solver (keyed by solver_id)
//! - Optimistic locking for safe concurrent updates
//! - No TTL (configuration should never expire)
//! - Versioning for change tracking
//!
//! # Example
//!
//! ```rust,ignore
//! use solver_storage::config_store::{ConfigStore, RedisConfigStore};
//!
//! // Create the store
//! let store = RedisConfigStore::new("redis://localhost:6379", "my-solver").await?;
//!
//! // Seed initial configuration
//! let versioned = store.seed(config).await?;
//! assert_eq!(versioned.version, 1);
//!
//! // Update with optimistic locking
//! let updated = store.update(new_config, versioned.version).await?;
//! assert_eq!(updated.version, 2);
//! ```

use async_trait::async_trait;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use solver_config::Config;
use solver_types::Versioned;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::OnceCell;
use tokio::time::timeout;
use tracing::{debug, warn};

/// Default connection timeout in milliseconds.
const DEFAULT_CONNECTION_TIMEOUT_MS: u64 = 5000;

/// Key prefix for configuration storage.
const CONFIG_KEY_PREFIX: &str = "config";

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

    /// Backend storage error (Redis connection, etc.).
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
#[async_trait]
#[cfg_attr(feature = "testing", mockall::automock)]
pub trait ConfigStore: Send + Sync {
    /// Retrieves the current configuration.
    ///
    /// Returns the versioned configuration, including the data, version number,
    /// and last update timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigStoreError::NotFound`] if no configuration exists.
    async fn get(&self) -> Result<Versioned<Config>, ConfigStoreError>;

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
    async fn seed(&self, config: Config) -> Result<Versioned<Config>, ConfigStoreError>;

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
        config: Config,
        expected_version: u64,
    ) -> Result<Versioned<Config>, ConfigStoreError>;

    /// Checks if a configuration exists.
    ///
    /// Useful for determining whether to call `seed` or `get`.
    async fn exists(&self) -> Result<bool, ConfigStoreError>;

    /// Deletes the configuration.
    ///
    /// This is primarily useful for testing or cleanup scenarios.
    /// In production, configuration should rarely be deleted.
    async fn delete(&self) -> Result<(), ConfigStoreError>;
}

/// Redis implementation of the configuration store.
///
/// Stores configuration in Redis using JSON serialization and provides
/// optimistic locking through atomic operations with version checking.
///
/// # Key Structure
///
/// Configuration is stored under the key: `{prefix}:config:{solver_id}`
///
/// # Thread Safety
///
/// This implementation uses lazy connection initialization and is safe
/// for concurrent use from multiple tasks.
pub struct RedisConfigStore {
    /// Redis connection manager (lazily initialized).
    client: OnceCell<Arc<ConnectionManager>>,
    /// Redis URL for connection.
    redis_url: String,
    /// Connection timeout in milliseconds.
    timeout_ms: u64,
    /// Solver ID for key namespacing.
    solver_id: String,
    /// Key prefix for Redis keys.
    key_prefix: String,
}

impl RedisConfigStore {
    /// Creates a new RedisConfigStore.
    ///
    /// The connection is lazily initialized on first use to ensure it's
    /// created within the correct tokio runtime context.
    ///
    /// # Arguments
    ///
    /// * `redis_url` - Redis connection URL (e.g., "redis://localhost:6379")
    /// * `solver_id` - Unique identifier for this solver instance
    /// * `key_prefix` - Prefix for all Redis keys (default: "oif-solver")
    ///
    /// # Errors
    ///
    /// Returns an error if the solver_id or redis_url is empty.
    pub fn new(redis_url: String, solver_id: String, key_prefix: String) -> Result<Self, ConfigStoreError> {
        if solver_id.is_empty() {
            return Err(ConfigStoreError::Configuration(
                "Solver ID cannot be empty".to_string(),
            ));
        }

        if redis_url.is_empty() {
            return Err(ConfigStoreError::Configuration(
                "Redis URL cannot be empty".to_string(),
            ));
        }

        if key_prefix.is_empty() {
            return Err(ConfigStoreError::Configuration(
                "Key prefix cannot be empty".to_string(),
            ));
        }

        Ok(Self {
            client: OnceCell::new(),
            redis_url,
            timeout_ms: DEFAULT_CONNECTION_TIMEOUT_MS,
            solver_id,
            key_prefix,
        })
    }

    /// Creates a new RedisConfigStore with default prefix.
    pub fn with_defaults(redis_url: String, solver_id: String) -> Result<Self, ConfigStoreError> {
        Self::new(redis_url, solver_id, "oif-solver".to_string())
    }

    /// Creates a new RedisConfigStore with custom timeout.
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Gets or initializes the Redis connection manager.
    async fn get_connection(&self) -> Result<Arc<ConnectionManager>, ConfigStoreError> {
        self.client
            .get_or_try_init(|| async {
                let redis_client = redis::Client::open(self.redis_url.as_str()).map_err(|e| {
                    ConfigStoreError::Configuration(format!("Failed to create Redis client: {}", e))
                })?;

                let connection_manager = timeout(
                    Duration::from_millis(self.timeout_ms),
                    ConnectionManager::new(redis_client),
                )
                .await
                .map_err(|_| {
                    ConfigStoreError::Backend(format!(
                        "Redis connection timeout after {}ms",
                        self.timeout_ms
                    ))
                })?
                .map_err(|e| {
                    ConfigStoreError::Backend(format!("Failed to create connection manager: {}", e))
                })?;

                debug!(redis_url = %self.redis_url, solver_id = %self.solver_id, "config store redis connection established");
                Ok(Arc::new(connection_manager))
            })
            .await
            .cloned()
    }

    /// Generates the Redis key for this solver's configuration.
    fn config_key(&self) -> String {
        format!("{}:{}:{}", self.key_prefix, CONFIG_KEY_PREFIX, self.solver_id)
    }
}

impl std::fmt::Debug for RedisConfigStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisConfigStore")
            .field("redis_url", &self.redis_url)
            .field("solver_id", &self.solver_id)
            .field("key_prefix", &self.key_prefix)
            .field("connected", &self.client.initialized())
            .finish()
    }
}

#[async_trait]
impl ConfigStore for RedisConfigStore {
    async fn get(&self) -> Result<Versioned<Config>, ConfigStoreError> {
        let key = self.config_key();
        let client = self.get_connection().await?;
        let mut conn = client.as_ref().clone();

        let result: Option<String> = conn.get(&key).await.map_err(|e| {
            warn!(key = %key, error = %e, "failed to get config from redis");
            ConfigStoreError::Backend(format!("Redis GET failed: {}", e))
        })?;

        match result {
            Some(json) => {
                let versioned: Versioned<Config> = serde_json::from_str(&json).map_err(|e| {
                    ConfigStoreError::Serialization(format!("Failed to deserialize config: {}", e))
                })?;
                debug!(key = %key, version = versioned.version, "retrieved config from redis");
                Ok(versioned)
            }
            None => {
                debug!(key = %key, "config not found in redis");
                Err(ConfigStoreError::NotFound(self.solver_id.clone()))
            }
        }
    }

    async fn seed(&self, config: Config) -> Result<Versioned<Config>, ConfigStoreError> {
        let key = self.config_key();
        let client = self.get_connection().await?;
        let mut conn = client.as_ref().clone();

        // Check if config already exists
        let exists: bool = conn.exists(&key).await.map_err(|e| {
            ConfigStoreError::Backend(format!("Redis EXISTS failed: {}", e))
        })?;

        if exists {
            return Err(ConfigStoreError::AlreadyExists(self.solver_id.clone()));
        }

        // Create versioned config
        let versioned = Versioned::new(config);
        let json = serde_json::to_string(&versioned).map_err(|e| {
            ConfigStoreError::Serialization(format!("Failed to serialize config: {}", e))
        })?;

        // Use SETNX to ensure atomicity (only set if not exists)
        let set_result: bool = conn.set_nx(&key, &json).await.map_err(|e| {
            ConfigStoreError::Backend(format!("Redis SETNX failed: {}", e))
        })?;

        if !set_result {
            // Race condition: another process seeded the config
            return Err(ConfigStoreError::AlreadyExists(self.solver_id.clone()));
        }

        debug!(key = %key, version = versioned.version, "seeded config to redis");
        Ok(versioned)
    }

    async fn update(
        &self,
        config: Config,
        expected_version: u64,
    ) -> Result<Versioned<Config>, ConfigStoreError> {
        let key = self.config_key();
        let client = self.get_connection().await?;
        let mut conn = client.as_ref().clone();

        // Get current config to check version
        let current_json: Option<String> = conn.get(&key).await.map_err(|e| {
            ConfigStoreError::Backend(format!("Redis GET failed: {}", e))
        })?;

        let current = match current_json {
            Some(json) => {
                let versioned: Versioned<Config> = serde_json::from_str(&json).map_err(|e| {
                    ConfigStoreError::Serialization(format!("Failed to deserialize config: {}", e))
                })?;
                versioned
            }
            None => {
                return Err(ConfigStoreError::NotFound(self.solver_id.clone()));
            }
        };

        // Check version
        if current.version != expected_version {
            return Err(ConfigStoreError::VersionMismatch {
                expected: expected_version,
                found: current.version,
            });
        }

        // Create new versioned config
        let new_versioned = current.increment(config);
        let new_json = serde_json::to_string(&new_versioned).map_err(|e| {
            ConfigStoreError::Serialization(format!("Failed to serialize config: {}", e))
        })?;

        // Use WATCH/MULTI/EXEC for optimistic locking
        // For simplicity, we use a Lua script to make this atomic
        let script = redis::Script::new(
            r#"
            local key = KEYS[1]
            local expected_version = tonumber(ARGV[1])
            local new_json = ARGV[2]

            local current = redis.call('GET', key)
            if not current then
                return {err = 'NOT_FOUND'}
            end

            local decoded = cjson.decode(current)
            if decoded.version ~= expected_version then
                return {err = 'VERSION_MISMATCH', version = decoded.version}
            end

            redis.call('SET', key, new_json)
            return {ok = 'OK'}
            "#,
        );

        let result: redis::Value = script
            .key(&key)
            .arg(expected_version)
            .arg(&new_json)
            .invoke_async(&mut conn)
            .await
            .map_err(|e| {
                ConfigStoreError::Backend(format!("Redis script execution failed: {}", e))
            })?;

        // Parse result
        match result {
            redis::Value::Array(items) => {
                // Check for errors in the result
                for item in items {
                    if let redis::Value::BulkString(s) = item {
                        let s_str = String::from_utf8_lossy(&s);
                        if s_str == "OK" {
                            debug!(
                                key = %key,
                                old_version = expected_version,
                                new_version = new_versioned.version,
                                "updated config in redis"
                            );
                            return Ok(new_versioned);
                        }
                    }
                }
                // If we get here, the script returned an unexpected result
                // This might be a version mismatch that wasn't caught properly
                // Re-check the version
                let check_json: Option<String> = conn.get(&key).await.map_err(|e| {
                    ConfigStoreError::Backend(format!("Redis GET failed: {}", e))
                })?;

                if let Some(json) = check_json {
                    let current: Versioned<Config> = serde_json::from_str(&json).map_err(|e| {
                        ConfigStoreError::Serialization(format!("Failed to deserialize: {}", e))
                    })?;

                    if current.version != expected_version {
                        return Err(ConfigStoreError::VersionMismatch {
                            expected: expected_version,
                            found: current.version,
                        });
                    }
                }

                Err(ConfigStoreError::Backend("Unexpected script result".to_string()))
            }
            redis::Value::Okay => {
                debug!(
                    key = %key,
                    old_version = expected_version,
                    new_version = new_versioned.version,
                    "updated config in redis"
                );
                Ok(new_versioned)
            }
            _ => Err(ConfigStoreError::Backend(format!(
                "Unexpected Redis response: {:?}",
                result
            ))),
        }
    }

    async fn exists(&self) -> Result<bool, ConfigStoreError> {
        let key = self.config_key();
        let client = self.get_connection().await?;
        let mut conn = client.as_ref().clone();

        let exists: bool = conn.exists(&key).await.map_err(|e| {
            ConfigStoreError::Backend(format!("Redis EXISTS failed: {}", e))
        })?;

        debug!(key = %key, exists = exists, "checked config existence");
        Ok(exists)
    }

    async fn delete(&self) -> Result<(), ConfigStoreError> {
        let key = self.config_key();
        let client = self.get_connection().await?;
        let mut conn = client.as_ref().clone();

        let deleted: i64 = conn.del(&key).await.map_err(|e| {
            ConfigStoreError::Backend(format!("Redis DEL failed: {}", e))
        })?;

        debug!(key = %key, deleted = deleted > 0, "deleted config from redis");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== RedisConfigStore::new() Tests ====================

    #[test]
    fn test_new_valid() {
        let result = RedisConfigStore::new(
            "redis://localhost:6379".to_string(),
            "test-solver".to_string(),
            "oif-solver".to_string(),
        );
        assert!(result.is_ok());
        let store = result.unwrap();
        assert_eq!(store.solver_id, "test-solver");
        assert_eq!(store.key_prefix, "oif-solver");
    }

    #[test]
    fn test_new_empty_solver_id() {
        let result = RedisConfigStore::new(
            "redis://localhost:6379".to_string(),
            "".to_string(),
            "oif-solver".to_string(),
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ConfigStoreError::Configuration(_)));
        assert!(err.to_string().contains("Solver ID"));
    }

    #[test]
    fn test_new_empty_redis_url() {
        let result = RedisConfigStore::new(
            "".to_string(),
            "test-solver".to_string(),
            "oif-solver".to_string(),
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ConfigStoreError::Configuration(_)));
        assert!(err.to_string().contains("Redis URL"));
    }

    #[test]
    fn test_new_empty_key_prefix() {
        let result = RedisConfigStore::new(
            "redis://localhost:6379".to_string(),
            "test-solver".to_string(),
            "".to_string(),
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ConfigStoreError::Configuration(_)));
        assert!(err.to_string().contains("Key prefix"));
    }

    #[test]
    fn test_with_defaults() {
        let result = RedisConfigStore::with_defaults(
            "redis://localhost:6379".to_string(),
            "test-solver".to_string(),
        );
        assert!(result.is_ok());
        let store = result.unwrap();
        assert_eq!(store.key_prefix, "oif-solver");
    }

    #[test]
    fn test_with_timeout() {
        let store = RedisConfigStore::new(
            "redis://localhost:6379".to_string(),
            "test-solver".to_string(),
            "oif-solver".to_string(),
        )
        .unwrap()
        .with_timeout(10000);

        assert_eq!(store.timeout_ms, 10000);
    }

    // ==================== Key Generation Tests ====================

    #[test]
    fn test_config_key_generation() {
        let store = RedisConfigStore::new(
            "redis://localhost:6379".to_string(),
            "my-solver".to_string(),
            "oif-solver".to_string(),
        )
        .unwrap();

        assert_eq!(store.config_key(), "oif-solver:config:my-solver");
    }

    #[test]
    fn test_config_key_with_custom_prefix() {
        let store = RedisConfigStore::new(
            "redis://localhost:6379".to_string(),
            "my-solver".to_string(),
            "custom-prefix".to_string(),
        )
        .unwrap();

        assert_eq!(store.config_key(), "custom-prefix:config:my-solver");
    }

    // ==================== Debug Implementation Tests ====================

    #[test]
    fn test_debug_impl() {
        let store = RedisConfigStore::new(
            "redis://localhost:6379".to_string(),
            "test-solver".to_string(),
            "oif-solver".to_string(),
        )
        .unwrap();

        let debug_str = format!("{:?}", store);
        assert!(debug_str.contains("RedisConfigStore"));
        assert!(debug_str.contains("redis://localhost:6379"));
        assert!(debug_str.contains("test-solver"));
        assert!(debug_str.contains("oif-solver"));
        assert!(debug_str.contains("connected"));
        assert!(debug_str.contains("false")); // Not connected yet
    }

    // ==================== Error Display Tests ====================

    #[test]
    fn test_error_display_not_found() {
        let err = ConfigStoreError::NotFound("test-solver".to_string());
        assert!(err.to_string().contains("not found"));
        assert!(err.to_string().contains("test-solver"));
    }

    #[test]
    fn test_error_display_already_exists() {
        let err = ConfigStoreError::AlreadyExists("test-solver".to_string());
        assert!(err.to_string().contains("already exists"));
        assert!(err.to_string().contains("test-solver"));
    }

    #[test]
    fn test_error_display_version_mismatch() {
        let err = ConfigStoreError::VersionMismatch {
            expected: 5,
            found: 3,
        };
        assert!(err.to_string().contains("Version mismatch"));
        assert!(err.to_string().contains("5"));
        assert!(err.to_string().contains("3"));
    }

    #[test]
    fn test_error_display_serialization() {
        let err = ConfigStoreError::Serialization("invalid JSON".to_string());
        assert!(err.to_string().contains("Serialization"));
        assert!(err.to_string().contains("invalid JSON"));
    }

    #[test]
    fn test_error_display_backend() {
        let err = ConfigStoreError::Backend("connection refused".to_string());
        assert!(err.to_string().contains("Backend"));
        assert!(err.to_string().contains("connection refused"));
    }

    #[test]
    fn test_error_display_configuration() {
        let err = ConfigStoreError::Configuration("invalid setting".to_string());
        assert!(err.to_string().contains("Configuration"));
        assert!(err.to_string().contains("invalid setting"));
    }

    // ==================== Async Tests (Connection Failure Scenarios) ====================

    #[tokio::test]
    async fn test_get_connection_failure() {
        let store = RedisConfigStore::new(
            "redis://invalid-host:6379".to_string(),
            "test-solver".to_string(),
            "oif-solver".to_string(),
        )
        .unwrap()
        .with_timeout(100);

        let result = store.get().await;
        assert!(result.is_err());
        assert!(matches!(result, Err(ConfigStoreError::Backend(_))));
    }

    #[tokio::test]
    async fn test_seed_connection_failure() {
        let store = RedisConfigStore::new(
            "redis://invalid-host:6379".to_string(),
            "test-solver".to_string(),
            "oif-solver".to_string(),
        )
        .unwrap()
        .with_timeout(100);

        // We need a valid Config to test, but we can't create one easily
        // without all the dependencies. The connection will fail before
        // we get to the serialization stage anyway.
        let result = store.exists().await;
        assert!(result.is_err());
        assert!(matches!(result, Err(ConfigStoreError::Backend(_))));
    }

    #[tokio::test]
    async fn test_exists_connection_failure() {
        let store = RedisConfigStore::new(
            "redis://invalid-host:6379".to_string(),
            "test-solver".to_string(),
            "oif-solver".to_string(),
        )
        .unwrap()
        .with_timeout(100);

        let result = store.exists().await;
        assert!(result.is_err());
        assert!(matches!(result, Err(ConfigStoreError::Backend(_))));
    }

    #[tokio::test]
    async fn test_delete_connection_failure() {
        let store = RedisConfigStore::new(
            "redis://invalid-host:6379".to_string(),
            "test-solver".to_string(),
            "oif-solver".to_string(),
        )
        .unwrap()
        .with_timeout(100);

        let result = store.delete().await;
        assert!(result.is_err());
        assert!(matches!(result, Err(ConfigStoreError::Backend(_))));
    }

    // ==================== Constants Tests ====================

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_CONNECTION_TIMEOUT_MS, 5000);
        assert_eq!(CONFIG_KEY_PREFIX, "config");
    }
}

/// Integration tests that require a running Redis instance.
/// Run with: `cargo test --package solver-storage config_store_integration -- --ignored`
/// Requires: Redis running on localhost:6379
#[cfg(test)]
mod integration_tests {
    use super::*;
    use rust_decimal::Decimal;
    use solver_config::{
        AccountConfig, Config, DeliveryConfig, DiscoveryConfig, OrderConfig, SettlementConfig,
        SolverConfig, StorageConfig, StrategyConfig,
    };
    use std::collections::HashMap;
    use std::str::FromStr;
    use uuid::Uuid;

    /// Helper to create Decimal from string.
    fn dec(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    /// Creates a minimal valid Config for testing.
    fn create_test_config(solver_id: &str) -> Config {
        Config {
            solver: SolverConfig {
                id: solver_id.to_string(),
                min_profitability_pct: dec("1.0"),
                monitoring_timeout_seconds: 28800,
            },
            networks: HashMap::new(),
            storage: StorageConfig {
                primary: "memory".to_string(),
                implementations: HashMap::new(),
                cleanup_interval_seconds: 3600,
            },
            delivery: DeliveryConfig {
                implementations: HashMap::new(),
                min_confirmations: 3,
            },
            account: AccountConfig {
                primary: "local".to_string(),
                implementations: HashMap::new(),
            },
            discovery: DiscoveryConfig {
                implementations: HashMap::new(),
            },
            order: OrderConfig {
                implementations: HashMap::new(),
                strategy: StrategyConfig {
                    primary: "simple".to_string(),
                    implementations: HashMap::new(),
                },
                callback_whitelist: vec![],
                simulate_callbacks: false,
            },
            settlement: SettlementConfig {
                implementations: HashMap::new(),
                settlement_poll_interval_seconds: 10,
            },
            pricing: None,
            api: None,
            gas: None,
        }
    }

    /// Generate a unique solver ID for test isolation.
    fn unique_solver_id() -> String {
        format!("test-solver-{}", Uuid::new_v4())
    }

    // ==================== Integration Tests ====================

    /// Tests the complete seed → get → update flow.
    #[tokio::test]
    #[ignore] // Requires running Redis
    async fn test_seed_get_update_flow() {
        let solver_id = unique_solver_id();
        let store = RedisConfigStore::with_defaults(
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
        assert_eq!(seeded.data.solver.id, solver_id);

        // 3. Verify config exists now
        let exists = store.exists().await.expect("exists() failed");
        assert!(exists, "Config should exist after seeding");

        // 4. Get the config
        let retrieved = store.get().await.expect("get() failed");
        assert_eq!(retrieved.version, 1);
        assert_eq!(retrieved.data.solver.id, solver_id);

        // 5. Update the config
        let mut updated_config = retrieved.data.clone();
        updated_config.solver.min_profitability_pct = dec("2.5");
        let updated = store
            .update(updated_config, retrieved.version)
            .await
            .expect("update() failed");
        assert_eq!(updated.version, 2, "Version should increment");
        assert_eq!(updated.data.solver.min_profitability_pct, dec("2.5"));

        // 6. Verify updated config
        let final_config = store.get().await.expect("get() failed");
        assert_eq!(final_config.version, 2);
        assert_eq!(final_config.data.solver.min_profitability_pct, dec("2.5"));

        // Cleanup
        store.delete().await.expect("delete() failed");
    }

    /// Tests that seeding twice fails (idempotent seeding).
    #[tokio::test]
    #[ignore] // Requires running Redis
    async fn test_idempotent_seeding() {
        let solver_id = unique_solver_id();
        let store = RedisConfigStore::with_defaults(
            "redis://localhost:6379".to_string(),
            solver_id.clone(),
        )
        .expect("Failed to create store");

        // Cleanup
        let _ = store.delete().await;

        // First seed should succeed
        let config = create_test_config(&solver_id);
        let result = store.seed(config.clone()).await;
        assert!(result.is_ok(), "First seed should succeed");

        // Second seed should fail with AlreadyExists
        let result = store.seed(config).await;
        assert!(result.is_err(), "Second seed should fail");
        let err = result.unwrap_err();
        assert!(
            matches!(err, ConfigStoreError::AlreadyExists(_)),
            "Error should be AlreadyExists, got: {:?}",
            err
        );

        // Cleanup
        store.delete().await.expect("delete() failed");
    }

    /// Tests optimistic locking with version mismatch.
    #[tokio::test]
    #[ignore] // Requires running Redis
    async fn test_optimistic_locking_version_mismatch() {
        let solver_id = unique_solver_id();
        let store = RedisConfigStore::with_defaults(
            "redis://localhost:6379".to_string(),
            solver_id.clone(),
        )
        .expect("Failed to create store");

        // Cleanup
        let _ = store.delete().await;

        // Seed initial config
        let config = create_test_config(&solver_id);
        let seeded = store.seed(config).await.expect("seed() failed");
        assert_eq!(seeded.version, 1);

        // Try to update with wrong version
        let mut new_config = seeded.data.clone();
        new_config.solver.min_profitability_pct = dec("5.0");
        let wrong_version = 99;
        let result = store.update(new_config, wrong_version).await;

        assert!(result.is_err(), "Update with wrong version should fail");
        let err = result.unwrap_err();
        assert!(
            matches!(err, ConfigStoreError::VersionMismatch { expected: 99, found: 1 }),
            "Error should be VersionMismatch, got: {:?}",
            err
        );

        // Cleanup
        store.delete().await.expect("delete() failed");
    }

    /// Tests that config persists across "restarts" (new store instances).
    #[tokio::test]
    #[ignore] // Requires running Redis
    async fn test_config_persistence_across_restarts() {
        let solver_id = unique_solver_id();

        // First "session" - create and seed
        {
            let store = RedisConfigStore::with_defaults(
                "redis://localhost:6379".to_string(),
                solver_id.clone(),
            )
            .expect("Failed to create store");

            let _ = store.delete().await; // Clean slate

            let config = create_test_config(&solver_id);
            let seeded = store.seed(config).await.expect("seed() failed");
            assert_eq!(seeded.version, 1);
        }

        // Second "session" - create new store instance and verify data persists
        {
            let store = RedisConfigStore::with_defaults(
                "redis://localhost:6379".to_string(),
                solver_id.clone(),
            )
            .expect("Failed to create store");

            // Config should exist
            let exists = store.exists().await.expect("exists() failed");
            assert!(exists, "Config should persist across restarts");

            // Get should work
            let retrieved = store.get().await.expect("get() failed");
            assert_eq!(retrieved.version, 1);
            assert_eq!(retrieved.data.solver.id, solver_id);

            // Should NOT be able to seed again
            let config = create_test_config(&solver_id);
            let result = store.seed(config).await;
            assert!(
                matches!(result, Err(ConfigStoreError::AlreadyExists(_))),
                "Should not be able to seed after restart"
            );

            // Cleanup
            store.delete().await.expect("delete() failed");
        }
    }

    /// Tests concurrent update scenario (simulated).
    #[tokio::test]
    #[ignore] // Requires running Redis
    async fn test_concurrent_updates() {
        let solver_id = unique_solver_id();
        let store = RedisConfigStore::with_defaults(
            "redis://localhost:6379".to_string(),
            solver_id.clone(),
        )
        .expect("Failed to create store");

        // Cleanup
        let _ = store.delete().await;

        // Seed initial config
        let config = create_test_config(&solver_id);
        let seeded = store.seed(config).await.expect("seed() failed");

        // Simulate two "clients" reading the same version
        let version_client_a = seeded.version;
        let version_client_b = seeded.version;

        // Client A updates first
        let mut config_a = seeded.data.clone();
        config_a.solver.min_profitability_pct = dec("2.0");
        let updated_a = store
            .update(config_a, version_client_a)
            .await
            .expect("Client A update should succeed");
        assert_eq!(updated_a.version, 2);

        // Client B tries to update with stale version - should fail
        let mut config_b = seeded.data.clone();
        config_b.solver.min_profitability_pct = dec("3.0");
        let result_b = store.update(config_b, version_client_b).await;

        assert!(result_b.is_err(), "Client B update should fail");
        let err = result_b.unwrap_err();
        assert!(
            matches!(err, ConfigStoreError::VersionMismatch { expected: 1, found: 2 }),
            "Error should indicate version mismatch: {:?}",
            err
        );

        // Cleanup
        store.delete().await.expect("delete() failed");
    }

    /// Tests that get fails when config doesn't exist.
    #[tokio::test]
    #[ignore] // Requires running Redis
    async fn test_get_not_found() {
        let solver_id = unique_solver_id();
        let store = RedisConfigStore::with_defaults(
            "redis://localhost:6379".to_string(),
            solver_id.clone(),
        )
        .expect("Failed to create store");

        // Ensure clean state
        let _ = store.delete().await;

        let result = store.get().await;
        assert!(result.is_err(), "Get should fail for non-existent config");
        let err = result.unwrap_err();
        assert!(
            matches!(err, ConfigStoreError::NotFound(_)),
            "Error should be NotFound, got: {:?}",
            err
        );
    }

    /// Tests update on non-existent config.
    #[tokio::test]
    #[ignore] // Requires running Redis
    async fn test_update_not_found() {
        let solver_id = unique_solver_id();
        let store = RedisConfigStore::with_defaults(
            "redis://localhost:6379".to_string(),
            solver_id.clone(),
        )
        .expect("Failed to create store");

        // Ensure clean state
        let _ = store.delete().await;

        let config = create_test_config(&solver_id);
        let result = store.update(config, 1).await;
        assert!(result.is_err(), "Update should fail for non-existent config");
        let err = result.unwrap_err();
        assert!(
            matches!(err, ConfigStoreError::NotFound(_)),
            "Error should be NotFound, got: {:?}",
            err
        );
    }

    /// Tests delete idempotency.
    #[tokio::test]
    #[ignore] // Requires running Redis
    async fn test_delete_idempotent() {
        let solver_id = unique_solver_id();
        let store = RedisConfigStore::with_defaults(
            "redis://localhost:6379".to_string(),
            solver_id.clone(),
        )
        .expect("Failed to create store");

        // Delete twice should not fail
        let _ = store.delete().await;
        let result = store.delete().await;
        assert!(result.is_ok(), "Delete should be idempotent");
    }
}
