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
#[derive(Debug, Clone, Copy)]
pub enum PersistencePolicy {
	/// Do not fail startup if persistence is disabled (warn only).
	WarnIfDisabled,
	/// Fail startup if persistence is disabled.
	RequireEnabled,
	/// Fail startup if persistence is disabled and use strict checks (CONFIG GET).
	RequireEnabledStrict,
}

impl PersistencePolicy {
	/// Build policy from environment variables.
	///
	/// - REQUIRE_PERSISTENCE=true => RequireEnabled
	/// - REQUIRE_PERSISTENCE_STRICT=true => RequireEnabledStrict
	pub fn from_env() -> Self {
		let require = std::env::var("REQUIRE_PERSISTENCE")
			.map(|v| v == "1" || v.to_lowercase() == "true")
			.unwrap_or(false);
		let strict = std::env::var("REQUIRE_PERSISTENCE_STRICT")
			.map(|v| v == "1" || v.to_lowercase() == "true")
			.unwrap_or(false);

		if strict {
			Self::RequireEnabledStrict
		} else if require {
			Self::RequireEnabled
		} else {
			Self::WarnIfDisabled
		}
	}

	fn is_strict(self) -> bool {
		matches!(self, Self::RequireEnabled | Self::RequireEnabledStrict)
	}

	fn use_strict_checks(self) -> bool {
		matches!(self, Self::RequireEnabledStrict)
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
	pub strict: bool,
	/// Use more accurate but potentially restricted checks (default: false)
	/// For Redis, this uses CONFIG GET which may be blocked by ACLs
	pub strict_checks: bool,
	/// Connection timeout in milliseconds
	pub timeout_ms: u64,
}

impl Default for ReadinessConfig {
	fn default() -> Self {
		Self {
			strict: false,
			strict_checks: false,
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
			let config = ReadinessConfig {
				strict: policy.is_strict(),
				strict_checks: policy.use_strict_checks(),
				timeout_ms,
			};
			checker.check(url, &config).await
		},
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

/// Verify storage readiness with logging and optional enforcement.
///
/// This helper performs readiness checks, logs details, and enforces persistence
/// based on `PersistencePolicy` derived from environment variables.
pub async fn verify_storage_readiness(store_config: &StoreConfig) -> Result<(), ReadinessError> {
	let backend_label = match store_config {
		StoreConfig::Redis { .. } => "Redis",
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
