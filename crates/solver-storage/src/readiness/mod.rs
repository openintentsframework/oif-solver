//! Storage readiness verification for storage backends.
//!
//! This module provides a trait-based abstraction for verifying
//! backend-specific readiness at startup.
//!
//! # Example
//!
//! ```rust,ignore
//! use solver_storage::readiness::{get_readiness_checker, ReadinessConfig};
//!
//! let checker = get_readiness_checker("redis").unwrap();
//! let config = ReadinessConfig::default();
//! let status = checker.check("redis://localhost:6379", &config).await?;
//!
//! if status.is_ready {
//!     println!("Storage is ready!");
//! }
//! ```

mod redis;

pub use redis::RedisReadiness;

use crate::StoreConfig;
use async_trait::async_trait;
use serde::Serialize;
use std::collections::HashMap;
use thiserror::Error;

/// Errors that can occur during readiness checks.
#[derive(Debug, Error)]
pub enum ReadinessError {
	/// Connection to the storage backend failed
	#[error("Connection failed: {0}")]
	ConnectionFailed(String),

	/// A readiness check failed
	#[error("Readiness check failed: {0}")]
	CheckFailed(String),

	/// Storage is not ready for operation
	#[error("Not ready: {0}")]
	NotReady(String),
}

/// Result of readiness verification.
#[derive(Debug, Clone, Serialize)]
pub struct ReadinessStatus {
	/// Human-readable name of the backend
	pub backend_name: String,
	/// Whether the backend is ready for operation
	pub is_ready: bool,
	/// Individual readiness checks performed
	pub checks: Vec<ReadinessCheck>,
	/// Additional info for logging/debugging
	pub details: HashMap<String, String>,
}

/// Persistence enforcement policy for readiness checks.
///
/// This policy controls whether the solver should fail startup if the
/// storage backend does not have persistence enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistencePolicy {
	/// Do not fail startup if persistence is disabled (warn only).
	/// Use this for development/testing environments.
	WarnIfDisabled,
	/// Fail startup if persistence is disabled.
	/// Use this for production environments where data durability is required.
	RequireEnabled,
}

impl PersistencePolicy {
	/// Build policy from environment variables.
	///
	/// - `REQUIRE_PERSISTENCE=true` => `RequireEnabled`
	/// - Default (not set or false) => `WarnIfDisabled`
	pub fn from_env() -> Self {
		let require = std::env::var("REQUIRE_PERSISTENCE")
			.map(|v| v == "1" || v.to_lowercase() == "true")
			.unwrap_or(false);

		if require {
			Self::RequireEnabled
		} else {
			Self::WarnIfDisabled
		}
	}

	/// Returns true if persistence is required for startup.
	pub fn requires_persistence(self) -> bool {
		matches!(self, Self::RequireEnabled)
	}
}

/// Individual readiness check result.
#[derive(Debug, Clone, Serialize)]
pub struct ReadinessCheck {
	/// Name of the check (e.g., "connectivity", "persistence")
	pub name: String,
	/// Whether the check passed
	pub passed: bool,
	/// Human-readable status (e.g., "CONNECTED", "ENABLED")
	pub status: String,
	/// Optional message with more details
	pub message: Option<String>,
}

/// Configuration for readiness verification.
#[derive(Debug, Clone)]
pub struct ReadinessConfig {
	/// Fail if readiness checks don't pass (default: false = warn only)
	pub require_persistence: bool,
	/// Connection timeout in milliseconds
	pub timeout_ms: u64,
}

impl Default for ReadinessConfig {
	fn default() -> Self {
		Self {
			require_persistence: false,
			timeout_ms: 5000,
		}
	}
}

/// Trait for verifying readiness of a storage backend.
///
/// Each storage backend implements this trait to define what checks
/// must pass for safe operation.
#[async_trait]
pub trait StorageReadiness: Send + Sync {
	/// Check that this backend is ready for operation.
	///
	/// Returns `ReadinessStatus` with details about each check performed.
	/// Does not fail on warnings unless `config.strict` is true.
	async fn check(
		&self,
		url: &str,
		config: &ReadinessConfig,
	) -> Result<ReadinessStatus, ReadinessError>;

	/// Returns the name of this backend (e.g., "redis", "file", "memory").
	fn name(&self) -> &'static str;

	/// Returns true if this backend has readiness checks to perform.
	///
	/// Some backends (like memory) have no meaningful readiness checks.
	fn has_checks(&self) -> bool {
		true
	}
}

/// Run readiness checks for a storage configuration.
///
/// This is storage-agnostic: backend-specific logic lives in each checker.
pub async fn check_storage_readiness(
	config: &StoreConfig,
	policy: PersistencePolicy,
	timeout_ms: u64,
) -> Result<ReadinessStatus, ReadinessError> {
	match config {
		StoreConfig::Redis { url } => {
			let checker = RedisReadiness::new();
			let readiness_config = ReadinessConfig {
				require_persistence: policy.requires_persistence(),
				timeout_ms,
			};
			checker.check(url, &readiness_config).await
		},
		StoreConfig::File { path } => check_file_readiness(path).await,
		StoreConfig::Memory => Ok(ReadinessStatus {
			backend_name: "Memory".to_string(),
			is_ready: true,
			checks: Vec::new(),
			details: HashMap::new(),
		}),
		StoreConfig::Storage(_) => Ok(ReadinessStatus {
			backend_name: "Storage".to_string(),
			is_ready: true,
			checks: Vec::new(),
			details: HashMap::new(),
		}),
	}
}

/// Check file storage readiness.
///
/// Verifies that the storage directory exists (or can be created) and is writable.
async fn check_file_readiness(path: &str) -> Result<ReadinessStatus, ReadinessError> {
	let path = std::path::Path::new(path);
	let mut checks = Vec::new();

	// Check if directory exists or can be created
	let dir_exists = if path.exists() {
		true
	} else {
		// Try to create the directory
		match std::fs::create_dir_all(path) {
			Ok(_) => true,
			Err(e) => {
				return Err(ReadinessError::ConnectionFailed(format!(
					"Cannot create storage directory '{}': {}",
					path.display(),
					e
				)));
			},
		}
	};

	checks.push(ReadinessCheck {
		name: "directory".to_string(),
		passed: dir_exists,
		status: if dir_exists {
			"EXISTS".to_string()
		} else {
			"MISSING".to_string()
		},
		message: Some(format!("Path: {}", path.display())),
	});

	// Check if directory is writable
	let test_file = path.join(".write_test");
	let writable = match std::fs::write(&test_file, b"test") {
		Ok(_) => {
			let _ = std::fs::remove_file(&test_file);
			true
		},
		Err(_) => false,
	};

	checks.push(ReadinessCheck {
		name: "writable".to_string(),
		passed: writable,
		status: if writable {
			"WRITABLE".to_string()
		} else {
			"READ-ONLY".to_string()
		},
		message: None,
	});

	// File storage always has persistence enabled (it writes to disk)
	checks.push(ReadinessCheck {
		name: "persistence".to_string(),
		passed: true,
		status: "ENABLED".to_string(),
		message: Some("File-based storage is always persistent".to_string()),
	});

	let is_ready = dir_exists && writable;

	Ok(ReadinessStatus {
		backend_name: "File".to_string(),
		is_ready,
		checks,
		details: HashMap::new(),
	})
}

/// Verify storage readiness with logging and optional enforcement.
///
/// This helper performs readiness checks, logs details, and enforces persistence
/// based on `PersistencePolicy` derived from environment variables.
pub async fn verify_storage_readiness(store_config: &StoreConfig) -> Result<(), ReadinessError> {
	let backend_label = match store_config {
		StoreConfig::Redis { .. } => "Redis",
		StoreConfig::File { .. } => "File",
		StoreConfig::Memory => "Memory",
		StoreConfig::Storage(_) => "Storage",
	};

	let policy = PersistencePolicy::from_env();
	let timeout_ms = 5000;

	match check_storage_readiness(store_config, policy, timeout_ms).await {
		Ok(status) => {
			tracing::info!("════════════════════════════════════════════════════════════");
			tracing::info!("  {} Storage Readiness", status.backend_name);
			tracing::info!("════════════════════════════════════════════════════════════");

			for check in &status.checks {
				if check.passed {
					tracing::info!("  {}: {}", check.name, check.status);
				} else {
					tracing::warn!("  {}: {}", check.name, check.status);
				}
				if let Some(msg) = &check.message {
					tracing::info!("    └─ {}", msg);
				}
			}

			for (key, value) in &status.details {
				tracing::info!("  {}: {}", key, value);
			}

			tracing::info!("════════════════════════════════════════════════════════════");

			if !status.is_ready {
				tracing::error!("════════════════════════════════════════════════════════════");
				tracing::error!("  STARTUP BLOCKED: Storage not ready");
				tracing::error!("════════════════════════════════════════════════════════════");
				tracing::error!("");
				tracing::error!("  To fix:");
				tracing::error!("  1. Address the failed checks above OR");
				tracing::error!("  2. Set REQUIRE_PERSISTENCE=false (not recommended)");
				tracing::error!("");
				tracing::error!("  See docs/redis-persistence.md for instructions.");
				tracing::error!("════════════════════════════════════════════════════════════");
				return Err(ReadinessError::NotReady(
					"Storage readiness checks failed".to_string(),
				));
			}

			Ok(())
		},
		Err(ReadinessError::ConnectionFailed(msg)) => {
			tracing::error!("════════════════════════════════════════════════════════════");
			tracing::error!("  {} Storage: CONNECTION FAILED", backend_label);
			tracing::error!("════════════════════════════════════════════════════════════");
			tracing::error!("  Error: {}", msg);
			tracing::error!("");
			tracing::error!("  Verify that:");
			tracing::error!("  1. The storage backend is running");
			tracing::error!("  2. Connection URL is correct");
			tracing::error!("  3. Network connectivity is available");
			tracing::error!("════════════════════════════════════════════════════════════");
			Err(ReadinessError::ConnectionFailed(msg))
		},
		Err(e) => {
			tracing::error!("Storage readiness check failed: {}", e);
			Err(e)
		},
	}
}

/// Get the readiness checker for a storage backend by name.
///
/// Returns `None` for unknown backends. Unknown backends can still be used,
/// they just won't have readiness verification at startup.
///
/// # Supported Backends
///
/// - `"redis"` - Redis connectivity and persistence checks
///
/// # Example
///
/// ```rust,ignore
/// if let Some(checker) = get_readiness_checker("redis") {
///     let status = checker.check(url, &config).await?;
/// }
/// ```
pub fn get_readiness_checker(backend_name: &str) -> Option<Box<dyn StorageReadiness>> {
	match backend_name {
		"redis" => Some(Box::new(RedisReadiness::new())),
		_ => None,
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use tempfile::TempDir;

	#[test]
	fn test_persistence_policy_from_env_default() {
		// Clear the env var to test default behavior
		std::env::remove_var("REQUIRE_PERSISTENCE");
		let policy = PersistencePolicy::from_env();
		assert_eq!(policy, PersistencePolicy::WarnIfDisabled);
		assert!(!policy.requires_persistence());
	}

	#[test]
	fn test_persistence_policy_from_env_true() {
		std::env::set_var("REQUIRE_PERSISTENCE", "true");
		let policy = PersistencePolicy::from_env();
		assert_eq!(policy, PersistencePolicy::RequireEnabled);
		assert!(policy.requires_persistence());
		std::env::remove_var("REQUIRE_PERSISTENCE");
	}

	#[test]
	fn test_persistence_policy_from_env_one() {
		std::env::set_var("REQUIRE_PERSISTENCE", "1");
		let policy = PersistencePolicy::from_env();
		assert_eq!(policy, PersistencePolicy::RequireEnabled);
		std::env::remove_var("REQUIRE_PERSISTENCE");
	}

	#[test]
	fn test_persistence_policy_from_env_false() {
		std::env::set_var("REQUIRE_PERSISTENCE", "false");
		let policy = PersistencePolicy::from_env();
		assert_eq!(policy, PersistencePolicy::WarnIfDisabled);
		std::env::remove_var("REQUIRE_PERSISTENCE");
	}

	#[test]
	fn test_readiness_config_default() {
		let config = ReadinessConfig::default();
		assert!(!config.require_persistence);
		assert_eq!(config.timeout_ms, 5000);
	}

	#[test]
	fn test_get_readiness_checker_redis() {
		let checker = get_readiness_checker("redis");
		assert!(checker.is_some());
		assert_eq!(checker.unwrap().name(), "redis");
	}

	#[test]
	fn test_get_readiness_checker_unknown() {
		let checker = get_readiness_checker("unknown");
		assert!(checker.is_none());
	}

	#[test]
	fn test_get_readiness_checker_file() {
		// File doesn't have a trait-based checker, returns None
		let checker = get_readiness_checker("file");
		assert!(checker.is_none());
	}

	#[tokio::test]
	async fn test_check_file_readiness_new_directory() {
		let temp_dir = TempDir::new().unwrap();
		let new_path = temp_dir.path().join("new_storage_dir");

		let result = check_file_readiness(new_path.to_str().unwrap()).await;
		assert!(result.is_ok());

		let status = result.unwrap();
		assert_eq!(status.backend_name, "File");
		assert!(status.is_ready);
		assert_eq!(status.checks.len(), 3);

		// Check directory exists
		let dir_check = status
			.checks
			.iter()
			.find(|c| c.name == "directory")
			.unwrap();
		assert!(dir_check.passed);
		assert_eq!(dir_check.status, "EXISTS");

		// Check writable
		let write_check = status.checks.iter().find(|c| c.name == "writable").unwrap();
		assert!(write_check.passed);
		assert_eq!(write_check.status, "WRITABLE");

		// Check persistence
		let persist_check = status
			.checks
			.iter()
			.find(|c| c.name == "persistence")
			.unwrap();
		assert!(persist_check.passed);
		assert_eq!(persist_check.status, "ENABLED");
	}

	#[tokio::test]
	async fn test_check_file_readiness_existing_directory() {
		let temp_dir = TempDir::new().unwrap();

		let result = check_file_readiness(temp_dir.path().to_str().unwrap()).await;
		assert!(result.is_ok());

		let status = result.unwrap();
		assert!(status.is_ready);
	}

	#[tokio::test]
	async fn test_check_storage_readiness_memory() {
		let config = StoreConfig::Memory;
		let result =
			check_storage_readiness(&config, PersistencePolicy::WarnIfDisabled, 1000).await;

		assert!(result.is_ok());
		let status = result.unwrap();
		assert_eq!(status.backend_name, "Memory");
		assert!(status.is_ready);
		assert!(status.checks.is_empty());
	}

	#[tokio::test]
	async fn test_check_storage_readiness_file() {
		let temp_dir = TempDir::new().unwrap();
		let config = StoreConfig::File {
			path: temp_dir.path().to_str().unwrap().to_string(),
		};

		let result =
			check_storage_readiness(&config, PersistencePolicy::WarnIfDisabled, 1000).await;

		assert!(result.is_ok());
		let status = result.unwrap();
		assert_eq!(status.backend_name, "File");
		assert!(status.is_ready);
	}

	#[tokio::test]
	async fn test_check_storage_readiness_with_storage_interface() {
		let memory = crate::implementations::memory::MemoryStorage::new();
		let config = StoreConfig::Storage(std::sync::Arc::new(memory));

		let result =
			check_storage_readiness(&config, PersistencePolicy::WarnIfDisabled, 1000).await;

		assert!(result.is_ok());
		let status = result.unwrap();
		assert_eq!(status.backend_name, "Storage");
		assert!(status.is_ready);
	}

	#[test]
	fn test_readiness_error_display() {
		let err = ReadinessError::ConnectionFailed("timeout".to_string());
		assert_eq!(err.to_string(), "Connection failed: timeout");

		let err = ReadinessError::CheckFailed("persistence disabled".to_string());
		assert_eq!(
			err.to_string(),
			"Readiness check failed: persistence disabled"
		);

		let err = ReadinessError::NotReady("storage not ready".to_string());
		assert_eq!(err.to_string(), "Not ready: storage not ready");
	}

	#[test]
	fn test_readiness_status_serialization() {
		let status = ReadinessStatus {
			backend_name: "Test".to_string(),
			is_ready: true,
			checks: vec![ReadinessCheck {
				name: "test_check".to_string(),
				passed: true,
				status: "OK".to_string(),
				message: Some("All good".to_string()),
			}],
			details: HashMap::new(),
		};

		let json = serde_json::to_string(&status).unwrap();
		assert!(json.contains("\"backend_name\":\"Test\""));
		assert!(json.contains("\"is_ready\":true"));
		assert!(json.contains("\"test_check\""));
	}

	#[test]
	fn test_readiness_check_serialization() {
		let check = ReadinessCheck {
			name: "connectivity".to_string(),
			passed: true,
			status: "CONNECTED".to_string(),
			message: None,
		};

		let json = serde_json::to_string(&check).unwrap();
		assert!(json.contains("\"name\":\"connectivity\""));
		assert!(json.contains("\"passed\":true"));
	}

	#[tokio::test]
	async fn test_verify_storage_readiness_memory() {
		std::env::remove_var("REQUIRE_PERSISTENCE");
		let config = StoreConfig::Memory;
		let result = verify_storage_readiness(&config).await;
		assert!(result.is_ok());
	}

	#[tokio::test]
	async fn test_verify_storage_readiness_file() {
		std::env::remove_var("REQUIRE_PERSISTENCE");
		let temp_dir = TempDir::new().unwrap();
		let config = StoreConfig::File {
			path: temp_dir.path().to_str().unwrap().to_string(),
		};
		let result = verify_storage_readiness(&config).await;
		assert!(result.is_ok());
	}

	#[tokio::test]
	async fn test_verify_storage_readiness_storage_interface() {
		std::env::remove_var("REQUIRE_PERSISTENCE");
		let memory = crate::implementations::memory::MemoryStorage::new();
		let config = StoreConfig::Storage(std::sync::Arc::new(memory));
		let result = verify_storage_readiness(&config).await;
		assert!(result.is_ok());
	}

	#[tokio::test]
	async fn test_check_file_readiness_cannot_create_directory() {
		// Try to create a directory in a path that doesn't exist and can't be created
		// On most systems, /proc is read-only
		#[cfg(target_os = "linux")]
		{
			let result = check_file_readiness("/proc/impossible_path/storage").await;
			assert!(result.is_err());
			assert!(matches!(result, Err(ReadinessError::ConnectionFailed(_))));
		}

		// On macOS, use a similar approach with /System which is read-only
		#[cfg(target_os = "macos")]
		{
			let result = check_file_readiness("/System/impossible_path/storage").await;
			assert!(result.is_err());
			assert!(matches!(result, Err(ReadinessError::ConnectionFailed(_))));
		}
	}

	#[test]
	fn test_readiness_check_with_message() {
		let check = ReadinessCheck {
			name: "persistence".to_string(),
			passed: true,
			status: "ENABLED".to_string(),
			message: Some("Last save: ok".to_string()),
		};

		let json = serde_json::to_string(&check).unwrap();
		assert!(json.contains("\"message\":\"Last save: ok\""));
	}

	#[test]
	fn test_readiness_status_not_ready() {
		let status = ReadinessStatus {
			backend_name: "Redis".to_string(),
			is_ready: false,
			checks: vec![ReadinessCheck {
				name: "persistence".to_string(),
				passed: false,
				status: "DISABLED".to_string(),
				message: Some("Neither RDB nor AOF enabled".to_string()),
			}],
			details: HashMap::new(),
		};

		assert!(!status.is_ready);
		assert_eq!(status.checks.len(), 1);
		assert!(!status.checks[0].passed);
	}

	#[test]
	fn test_readiness_status_with_details() {
		let mut details = HashMap::new();
		details.insert("redis_version".to_string(), "7.0.0".to_string());

		let status = ReadinessStatus {
			backend_name: "Redis".to_string(),
			is_ready: true,
			checks: Vec::new(),
			details,
		};

		let json = serde_json::to_string(&status).unwrap();
		assert!(json.contains("\"redis_version\":\"7.0.0\""));
	}
}
