//! Redis-specific readiness checks.
//!
//! This module implements `StorageReadiness` for Redis, checking:
//! - Connectivity to the Redis server
//! - Persistence configuration (RDB and/or AOF)

use super::{ReadinessCheck, ReadinessConfig, ReadinessError, ReadinessStatus, StorageReadiness};
use crate::redis_health::{check_redis_health, check_redis_health_strict, PersistenceDetectionMethod};
use async_trait::async_trait;

/// Redis readiness checker.
///
/// Performs the following checks:
/// - **Connectivity**: Can we connect to Redis?
/// - **RDB Persistence**: Is RDB (snapshotting) enabled?
/// - **AOF Persistence**: Is AOF (append-only file) enabled?
pub struct RedisReadiness;

impl RedisReadiness {
	/// Create a new Redis readiness checker.
	pub fn new() -> Self {
		Self
	}
}

impl Default for RedisReadiness {
	fn default() -> Self {
		Self::new()
	}
}

#[async_trait]
impl StorageReadiness for RedisReadiness {
	async fn check(
		&self,
		url: &str,
		config: &ReadinessConfig,
	) -> Result<ReadinessStatus, ReadinessError> {
		let timeout = if config.timeout_ms > 0 { config.timeout_ms } else { 5000 };

		// Choose check method based on config
		// strict_checks uses CONFIG GET (more accurate but may be blocked by ACLs)
		// default uses INFO persistence (always works)
		let health_result = if config.strict_checks {
			check_redis_health_strict(url, timeout).await
		} else {
			check_redis_health(url, timeout).await
		};

		match health_result {
			Ok(info) => {
				let checks = vec![
					ReadinessCheck {
						name: "connectivity".to_string(),
						passed: true,
						status: "CONNECTED".to_string(),
						message: None,
					},
					ReadinessCheck {
						name: "rdb_persistence".to_string(),
						passed: info.rdb_enabled,
						status: if info.rdb_enabled { "ENABLED" } else { "disabled" }.to_string(),
						message: if info.rdb_enabled {
							Some(format!("Last save: {}", info.rdb_last_bgsave_status))
						} else {
							None
						},
					},
					ReadinessCheck {
						name: "aof_persistence".to_string(),
						passed: info.aof_enabled,
						status: if info.aof_enabled { "ENABLED" } else { "disabled" }.to_string(),
						message: if info.aof_enabled {
							Some(format!("Last rewrite: {}", info.aof_last_rewrite_status))
						} else {
							None
						},
					},
				];

				let persistence_enabled = info.has_persistence();

				let mut details = std::collections::HashMap::new();
				details.insert(
					"detection_method".to_string(),
					match info.detection_method {
						PersistenceDetectionMethod::InfoCommand => "INFO".to_string(),
						PersistenceDetectionMethod::ConfigCommand => "CONFIG".to_string(),
					},
				);

				// Ready if persistence is enabled OR if we're not in strict mode
				let is_ready = persistence_enabled || !config.strict;

				Ok(ReadinessStatus {
					backend_name: "Redis".to_string(),
					is_ready,
					checks,
					details,
				})
			},
			Err(e) => Err(ReadinessError::ConnectionFailed(e.to_string())),
		}
	}

	fn name(&self) -> &'static str {
		"redis"
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_redis_readiness_name() {
		let checker = RedisReadiness::new();
		assert_eq!(checker.name(), "redis");
	}

	#[test]
	fn test_redis_readiness_has_checks() {
		let checker = RedisReadiness::new();
		assert!(checker.has_checks());
	}

	#[test]
	fn test_readiness_config_default() {
		let config = ReadinessConfig::default();
		assert!(!config.strict);
		assert!(!config.strict_checks);
		assert_eq!(config.timeout_ms, 5000);
	}

	#[tokio::test]
	async fn test_redis_readiness_connection_failure() {
		let checker = RedisReadiness::new();
		let config = ReadinessConfig { timeout_ms: 100, ..Default::default() };

		let result = checker.check("redis://invalid-host:6379", &config).await;

		assert!(result.is_err());
		assert!(matches!(result, Err(ReadinessError::ConnectionFailed(_))));
	}
}
