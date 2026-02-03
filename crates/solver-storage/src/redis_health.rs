//! Redis health and persistence verification.
//!
//! This module provides functions to check Redis connectivity and persistence status.
//! Designed to work with both self-managed Redis and managed services (ElastiCache, Redis Enterprise).
//!
//! # Usage
//!
//! ```rust,ignore
//! use solver_storage::redis_health::{check_redis_health, check_redis_health_strict};
//!
//! // Basic check (uses INFO command, always works)
//! let info = check_redis_health("redis://localhost:6379", 5000).await?;
//! println!("RDB: {}, AOF: {}", info.rdb_enabled, info.aof_enabled);
//!
//! // Strict check (tries CONFIG GET, falls back to INFO if denied)
//! let info = check_redis_health_strict("redis://localhost:6379", 5000).await?;
//! ```

use thiserror::Error;

/// Errors that can occur during Redis health checks.
#[derive(Debug, Error)]
pub enum RedisHealthError {
	/// Redis connection failed (timeout, network error, auth failure)
	#[error("Redis connection failed: {0}")]
	ConnectionFailed(String),

	/// Redis persistence is disabled (neither RDB nor AOF enabled)
	#[error(
		"Redis persistence is disabled. Enable RDB or AOF persistence.\n\n\
         To fix this:\n\
         1. Enable persistence in redis.conf (appendonly yes) or\n\
         2. Set REQUIRE_REDIS_PERSISTENCE=false (not recommended for production)\n\n\
         See docs/redis-persistence.md for detailed instructions."
	)]
	PersistenceDisabled,

	/// Failed to check persistence status
	#[error("Failed to check Redis persistence: {0}")]
	CheckFailed(String),

	/// CONFIG command denied by Redis ACLs (common in managed Redis)
	#[error(
		"CONFIG command denied by Redis ACLs.\n\n\
         This usually means you're using managed Redis (ElastiCache, Redis Enterprise).\n\n\
         Options:\n\
         1. Use the default INFO-based check (recommended for managed Redis)\n\
         2. Grant CONFIG permission to your Redis user\n\n\
         The solver will fall back to INFO-based persistence detection."
	)]
	ConfigDenied,
}

/// Information about Redis persistence configuration.
#[derive(Debug, Clone)]
pub struct RedisPersistenceInfo {
	/// RDB (snapshotting) enabled
	pub rdb_enabled: bool,
	/// AOF (append-only file) enabled
	pub aof_enabled: bool,
	/// Last RDB save status (e.g., "ok", "err")
	pub rdb_last_bgsave_status: String,
	/// AOF last rewrite status
	pub aof_last_rewrite_status: String,
	/// How persistence was detected
	pub detection_method: PersistenceDetectionMethod,
}

/// Method used to detect persistence configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistenceDetectionMethod {
	/// Used INFO persistence command (always available)
	InfoCommand,
	/// Used CONFIG GET command (more accurate but may be blocked by ACLs)
	ConfigCommand,
}

impl RedisPersistenceInfo {
	/// Returns true if at least one persistence method is enabled.
	pub fn has_persistence(&self) -> bool {
		self.rdb_enabled || self.aof_enabled
	}
}

/// Check Redis connectivity and persistence using INFO command (ACL-safe).
///
/// This method works on all Redis deployments including managed services
/// where CONFIG GET may be blocked by ACLs.
///
/// # Arguments
///
/// * `redis_url` - Redis connection URL (e.g., "redis://localhost:6379")
/// * `timeout_ms` - Connection timeout in milliseconds
///
/// # Returns
///
/// * `Ok(RedisPersistenceInfo)` - Redis is reachable, persistence info detected
/// * `Err(RedisHealthError)` - Connection failed or check failed
///
/// # Example
///
/// ```rust,ignore
/// let info = check_redis_health("redis://localhost:6379", 5000).await?;
/// if info.has_persistence() {
///     println!("Persistence is enabled");
/// }
/// ```
pub async fn check_redis_health(
	redis_url: &str,
	timeout_ms: u64,
) -> Result<RedisPersistenceInfo, RedisHealthError> {
	// 1. Establish connection
	let client = redis::Client::open(redis_url)
		.map_err(|e| RedisHealthError::ConnectionFailed(e.to_string()))?;

	let mut conn = tokio::time::timeout(
		std::time::Duration::from_millis(timeout_ms),
		client.get_multiplexed_async_connection(),
	)
	.await
	.map_err(|_| {
		RedisHealthError::ConnectionFailed(format!("Connection timeout after {}ms", timeout_ms))
	})?
	.map_err(|e| RedisHealthError::ConnectionFailed(e.to_string()))?;

	// 2. Get persistence info via INFO command (always allowed)
	let info: String = redis::cmd("INFO")
		.arg("persistence")
		.query_async(&mut conn)
		.await
		.map_err(|e| RedisHealthError::CheckFailed(e.to_string()))?;

	// 3. Parse persistence info from INFO output
	parse_info_persistence(&info)
}

/// Check Redis persistence using CONFIG GET command (stricter but may be blocked).
///
/// This provides more accurate persistence detection but requires CONFIG permission.
/// Falls back to INFO-based detection if CONFIG is denied by ACLs.
///
/// # Arguments
///
/// * `redis_url` - Redis connection URL
/// * `timeout_ms` - Connection timeout in milliseconds
///
/// # Returns
///
/// * `Ok(RedisPersistenceInfo)` - Persistence info (via CONFIG or INFO fallback)
/// * `Err(RedisHealthError)` - Connection failed
///
/// # Note
///
/// When CONFIG GET is denied (common in managed Redis), this function
/// logs a warning and falls back to INFO-based detection rather than failing.
pub async fn check_redis_health_strict(
	redis_url: &str,
	timeout_ms: u64,
) -> Result<RedisPersistenceInfo, RedisHealthError> {
	// 1. Establish connection
	let client = redis::Client::open(redis_url)
		.map_err(|e| RedisHealthError::ConnectionFailed(e.to_string()))?;

	let mut conn = tokio::time::timeout(
		std::time::Duration::from_millis(timeout_ms),
		client.get_multiplexed_async_connection(),
	)
	.await
	.map_err(|_| {
		RedisHealthError::ConnectionFailed(format!("Connection timeout after {}ms", timeout_ms))
	})?
	.map_err(|e| RedisHealthError::ConnectionFailed(e.to_string()))?;

	// 2. Try CONFIG GET first (more accurate)
	let config_result = try_config_get_persistence(&mut conn).await;

	match config_result {
		Ok(info) => Ok(info),
		Err(RedisHealthError::ConfigDenied) => {
			// Fall back to INFO command
			tracing::warn!(
				"CONFIG GET denied by Redis ACLs, falling back to INFO-based detection. \
                 This is normal for managed Redis services."
			);

			let info: String = redis::cmd("INFO")
				.arg("persistence")
				.query_async(&mut conn)
				.await
				.map_err(|e| RedisHealthError::CheckFailed(e.to_string()))?;

			parse_info_persistence(&info)
		},
		Err(e) => Err(e),
	}
}

/// Try to get persistence config via CONFIG GET command.
async fn try_config_get_persistence(
	conn: &mut redis::aio::MultiplexedConnection,
) -> Result<RedisPersistenceInfo, RedisHealthError> {
	// Check RDB save config
	let save_result: Result<Vec<String>, _> = redis::cmd("CONFIG")
		.arg("GET")
		.arg("save")
		.query_async(conn)
		.await;

	let save_config = match save_result {
		Ok(config) => config,
		Err(e) => {
			let err_str = e.to_string().to_lowercase();
			if err_str.contains("noperm")
				|| err_str.contains("no permission")
				|| err_str.contains("acl")
				|| err_str.contains("denied")
				|| err_str.contains("unknown command")
			{
				return Err(RedisHealthError::ConfigDenied);
			}
			return Err(RedisHealthError::CheckFailed(e.to_string()));
		},
	};

	// save_config returns ["save", "<value>"] where value is empty if no saves configured
	let rdb_enabled = save_config
		.get(1)
		.map(|v| !v.is_empty() && v != "\"\"" && v != "''")
		.unwrap_or(false);

	// Check AOF config
	let aof_config: Vec<String> = redis::cmd("CONFIG")
		.arg("GET")
		.arg("appendonly")
		.query_async(conn)
		.await
		.map_err(|e| RedisHealthError::CheckFailed(e.to_string()))?;

	let aof_enabled = aof_config.get(1).map(|v| v == "yes").unwrap_or(false);

	// Get status info for diagnostics
	let info: String = redis::cmd("INFO")
		.arg("persistence")
		.query_async(conn)
		.await
		.unwrap_or_default();

	let (rdb_last_bgsave_status, aof_last_rewrite_status) = parse_status_from_info(&info);

	Ok(RedisPersistenceInfo {
		rdb_enabled,
		aof_enabled,
		rdb_last_bgsave_status,
		aof_last_rewrite_status,
		detection_method: PersistenceDetectionMethod::ConfigCommand,
	})
}

/// Parse persistence info from INFO persistence output.
fn parse_info_persistence(info: &str) -> Result<RedisPersistenceInfo, RedisHealthError> {
	let mut aof_enabled = false;
	let mut rdb_last_bgsave_status = "unknown".to_string();
	let mut aof_last_rewrite_status = "unknown".to_string();
	let mut rdb_last_save_time: Option<i64> = None;

	for line in info.lines() {
		let line = line.trim();
		if line.is_empty() || line.starts_with('#') {
			continue;
		}

		if let Some((key, value)) = line.split_once(':') {
			match key {
				"aof_enabled" => aof_enabled = value == "1",
				"rdb_last_bgsave_status" => rdb_last_bgsave_status = value.to_string(),
				"aof_last_rewrite_status" => aof_last_rewrite_status = value.to_string(),
				"rdb_last_save_time" => {
					rdb_last_save_time = value.parse().ok();
				},
				_ => {},
			}
		}
	}

	// Detect RDB status heuristically from INFO:
	// - If rdb_last_save_time > 0, RDB has saved at least once (likely enabled)
	// - If rdb_last_bgsave_status is "ok", last save succeeded
	//
	// Note: INFO cannot definitively tell if RDB is disabled via "save ''"
	// This is a known limitation; use strict mode for accurate CONFIG-based check
	let rdb_enabled =
		rdb_last_save_time.map(|t| t > 0).unwrap_or(false) || rdb_last_bgsave_status == "ok";

	Ok(RedisPersistenceInfo {
		rdb_enabled,
		aof_enabled,
		rdb_last_bgsave_status,
		aof_last_rewrite_status,
		detection_method: PersistenceDetectionMethod::InfoCommand,
	})
}

/// Extract status fields from INFO persistence output.
fn parse_status_from_info(info: &str) -> (String, String) {
	let mut rdb_last_bgsave_status = "unknown".to_string();
	let mut aof_last_rewrite_status = "unknown".to_string();

	for line in info.lines() {
		if let Some((key, value)) = line.split_once(':') {
			match key.trim() {
				"rdb_last_bgsave_status" => rdb_last_bgsave_status = value.trim().to_string(),
				"aof_last_rewrite_status" => aof_last_rewrite_status = value.trim().to_string(),
				_ => {},
			}
		}
	}

	(rdb_last_bgsave_status, aof_last_rewrite_status)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_error_display_connection_failed() {
		let err = RedisHealthError::ConnectionFailed("timeout".to_string());
		assert!(format!("{}", err).contains("connection failed"));
		assert!(format!("{}", err).contains("timeout"));
	}

	#[test]
	fn test_error_display_persistence_disabled() {
		let err = RedisHealthError::PersistenceDisabled;
		let msg = format!("{}", err);
		assert!(msg.contains("persistence is disabled"));
		assert!(msg.contains("Enable RDB or AOF"));
	}

	#[test]
	fn test_error_display_check_failed() {
		let err = RedisHealthError::CheckFailed("some error".to_string());
		assert!(format!("{}", err).contains("Failed to check"));
		assert!(format!("{}", err).contains("some error"));
	}

	#[test]
	fn test_error_display_config_denied() {
		let err = RedisHealthError::ConfigDenied;
		let msg = format!("{}", err);
		assert!(msg.contains("CONFIG command denied"));
		assert!(msg.contains("managed Redis"));
	}

	#[test]
	fn test_persistence_detection_method_equality() {
		assert_eq!(
			PersistenceDetectionMethod::InfoCommand,
			PersistenceDetectionMethod::InfoCommand
		);
		assert_eq!(
			PersistenceDetectionMethod::ConfigCommand,
			PersistenceDetectionMethod::ConfigCommand
		);
		assert_ne!(
			PersistenceDetectionMethod::InfoCommand,
			PersistenceDetectionMethod::ConfigCommand
		);
	}

	#[test]
	fn test_persistence_detection_method_debug() {
		let info_method = PersistenceDetectionMethod::InfoCommand;
		let config_method = PersistenceDetectionMethod::ConfigCommand;
		assert!(format!("{:?}", info_method).contains("InfoCommand"));
		assert!(format!("{:?}", config_method).contains("ConfigCommand"));
	}

	#[test]
	fn test_redis_persistence_info_debug() {
		let info = RedisPersistenceInfo {
			rdb_enabled: true,
			aof_enabled: false,
			rdb_last_bgsave_status: "ok".to_string(),
			aof_last_rewrite_status: "unknown".to_string(),
			detection_method: PersistenceDetectionMethod::InfoCommand,
		};
		let debug_str = format!("{:?}", info);
		assert!(debug_str.contains("rdb_enabled: true"));
		assert!(debug_str.contains("aof_enabled: false"));
	}

	#[test]
	fn test_redis_persistence_info_clone() {
		let info = RedisPersistenceInfo {
			rdb_enabled: true,
			aof_enabled: true,
			rdb_last_bgsave_status: "ok".to_string(),
			aof_last_rewrite_status: "ok".to_string(),
			detection_method: PersistenceDetectionMethod::ConfigCommand,
		};
		let cloned = info.clone();
		assert_eq!(cloned.rdb_enabled, info.rdb_enabled);
		assert_eq!(cloned.aof_enabled, info.aof_enabled);
		assert_eq!(cloned.detection_method, info.detection_method);
	}

	#[test]
	fn test_parse_status_from_info_complete() {
		let info = r#"
# Persistence
rdb_last_bgsave_status:ok
aof_last_rewrite_status:ok
"#;
		let (rdb_status, aof_status) = parse_status_from_info(info);
		assert_eq!(rdb_status, "ok");
		assert_eq!(aof_status, "ok");
	}

	#[test]
	fn test_parse_status_from_info_partial() {
		let info = "rdb_last_bgsave_status:err";
		let (rdb_status, aof_status) = parse_status_from_info(info);
		assert_eq!(rdb_status, "err");
		assert_eq!(aof_status, "unknown");
	}

	#[test]
	fn test_parse_status_from_info_empty() {
		let (rdb_status, aof_status) = parse_status_from_info("");
		assert_eq!(rdb_status, "unknown");
		assert_eq!(aof_status, "unknown");
	}

	#[test]
	fn test_parse_status_from_info_with_whitespace() {
		let info = "  rdb_last_bgsave_status:  ok  \n  aof_last_rewrite_status:  err  ";
		let (rdb_status, aof_status) = parse_status_from_info(info);
		assert_eq!(rdb_status, "ok");
		assert_eq!(aof_status, "err");
	}

	#[test]
	fn test_parse_info_persistence_with_aof() {
		let info = r#"
# Persistence
loading:0
rdb_changes_since_last_save:0
rdb_bgsave_in_progress:0
rdb_last_save_time:1706500000
rdb_last_bgsave_status:ok
aof_enabled:1
aof_rewrite_in_progress:0
aof_last_rewrite_status:ok
"#;
		let result = parse_info_persistence(info).unwrap();
		assert!(result.aof_enabled);
		assert!(result.rdb_enabled);
		assert_eq!(result.rdb_last_bgsave_status, "ok");
		assert_eq!(result.aof_last_rewrite_status, "ok");
		assert_eq!(
			result.detection_method,
			PersistenceDetectionMethod::InfoCommand
		);
	}

	#[test]
	fn test_parse_info_persistence_rdb_only() {
		let info = r#"
# Persistence
loading:0
rdb_last_save_time:1706500000
rdb_last_bgsave_status:ok
aof_enabled:0
"#;
		let result = parse_info_persistence(info).unwrap();
		assert!(!result.aof_enabled);
		assert!(result.rdb_enabled);
		assert!(result.has_persistence());
	}

	#[test]
	fn test_parse_info_persistence_aof_only() {
		let info = r#"
# Persistence
loading:0
rdb_last_save_time:0
rdb_last_bgsave_status:err
aof_enabled:1
aof_last_rewrite_status:ok
"#;
		let result = parse_info_persistence(info).unwrap();
		assert!(result.aof_enabled);
		assert!(!result.rdb_enabled);
		assert!(result.has_persistence());
	}

	#[test]
	fn test_parse_info_persistence_no_persistence() {
		let info = r#"
# Persistence
loading:0
rdb_last_save_time:0
rdb_last_bgsave_status:err
aof_enabled:0
"#;
		let result = parse_info_persistence(info).unwrap();
		assert!(!result.aof_enabled);
		assert!(!result.rdb_enabled);
		assert!(!result.has_persistence());
	}

	#[test]
	fn test_has_persistence() {
		let info_both = RedisPersistenceInfo {
			rdb_enabled: true,
			aof_enabled: true,
			rdb_last_bgsave_status: "ok".to_string(),
			aof_last_rewrite_status: "ok".to_string(),
			detection_method: PersistenceDetectionMethod::InfoCommand,
		};
		assert!(info_both.has_persistence());

		let info_none = RedisPersistenceInfo {
			rdb_enabled: false,
			aof_enabled: false,
			rdb_last_bgsave_status: "err".to_string(),
			aof_last_rewrite_status: "ok".to_string(),
			detection_method: PersistenceDetectionMethod::InfoCommand,
		};
		assert!(!info_none.has_persistence());
	}

	#[test]
	fn test_has_persistence_rdb_only() {
		let info = RedisPersistenceInfo {
			rdb_enabled: true,
			aof_enabled: false,
			rdb_last_bgsave_status: "ok".to_string(),
			aof_last_rewrite_status: "unknown".to_string(),
			detection_method: PersistenceDetectionMethod::InfoCommand,
		};
		assert!(info.has_persistence());
	}

	#[test]
	fn test_has_persistence_aof_only() {
		let info = RedisPersistenceInfo {
			rdb_enabled: false,
			aof_enabled: true,
			rdb_last_bgsave_status: "err".to_string(),
			aof_last_rewrite_status: "ok".to_string(),
			detection_method: PersistenceDetectionMethod::InfoCommand,
		};
		assert!(info.has_persistence());
	}

	#[test]
	fn test_parse_info_persistence_empty_string() {
		let result = parse_info_persistence("").unwrap();
		assert!(!result.aof_enabled);
		assert!(!result.rdb_enabled);
		assert_eq!(result.rdb_last_bgsave_status, "unknown");
		assert_eq!(result.aof_last_rewrite_status, "unknown");
	}

	#[test]
	fn test_parse_info_persistence_only_comments() {
		let info = r#"
# Persistence
# This is a comment
# Another comment
"#;
		let result = parse_info_persistence(info).unwrap();
		assert!(!result.aof_enabled);
		assert!(!result.rdb_enabled);
	}

	#[test]
	fn test_parse_info_persistence_rdb_via_ok_status() {
		// When rdb_last_save_time is 0 but status is ok, RDB should be enabled
		let info = r#"
rdb_last_save_time:0
rdb_last_bgsave_status:ok
aof_enabled:0
"#;
		let result = parse_info_persistence(info).unwrap();
		assert!(result.rdb_enabled); // Should be true because status is "ok"
		assert!(!result.aof_enabled);
	}

	#[test]
	fn test_parse_info_persistence_rdb_via_save_time() {
		// When rdb_last_save_time > 0, RDB should be detected as enabled
		let info = r#"
rdb_last_save_time:1706500000
rdb_last_bgsave_status:err
aof_enabled:0
"#;
		let result = parse_info_persistence(info).unwrap();
		assert!(result.rdb_enabled); // Should be true because save_time > 0
	}

	#[test]
	fn test_parse_info_persistence_malformed_lines() {
		// Lines without colons should be skipped
		let info = r#"
malformed line without colon
aof_enabled:1
another malformed line
rdb_last_bgsave_status:ok
"#;
		let result = parse_info_persistence(info).unwrap();
		assert!(result.aof_enabled);
		assert_eq!(result.rdb_last_bgsave_status, "ok");
	}

	#[test]
	fn test_parse_info_persistence_unknown_keys() {
		// Unknown keys should be ignored
		let info = r#"
unknown_key:some_value
another_unknown:123
aof_enabled:1
"#;
		let result = parse_info_persistence(info).unwrap();
		assert!(result.aof_enabled);
	}

	#[test]
	fn test_error_debug_implementation() {
		let err = RedisHealthError::ConnectionFailed("test".to_string());
		let debug = format!("{:?}", err);
		assert!(debug.contains("ConnectionFailed"));
		assert!(debug.contains("test"));
	}
}
