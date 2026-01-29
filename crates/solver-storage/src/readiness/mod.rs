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

use async_trait::async_trait;
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
#[derive(Debug, Clone)]
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

/// Individual readiness check result.
#[derive(Debug, Clone)]
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
