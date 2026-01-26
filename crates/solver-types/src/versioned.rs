//! Versioned wrapper for optimistic locking in Redis storage.
//!
//! This module provides a generic `Versioned<T>` wrapper that adds version
//! tracking to any serializable type. This enables optimistic concurrency
//! control when storing configuration in Redis.
//!
//! # Example
//!
//! ```rust,ignore
//! use solver_types::versioned::Versioned;
//!
//! let config = MyConfig { /* ... */ };
//! let versioned = Versioned::new(config);
//! assert_eq!(versioned.version, 1);
//!
//! // After updating
//! let updated = versioned.increment(new_config);
//! assert_eq!(updated.version, 2);
//! ```

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// A wrapper that adds version tracking to any type.
///
/// Used for optimistic locking when updating configuration in Redis.
/// The version is incremented on each update, and updates will fail
/// if the expected version doesn't match the current version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Versioned<T> {
	/// The wrapped data.
	pub data: T,
	/// Version number, starts at 1 and increments on each update.
	pub version: u64,
	/// Unix timestamp of when this version was created/updated.
	pub updated_at: u64,
}

impl<T> Versioned<T> {
	/// Create a new versioned wrapper with version 1.
	pub fn new(data: T) -> Self {
		Self {
			data,
			version: 1,
			updated_at: current_timestamp(),
		}
	}

	/// Create a new version with incremented version number.
	///
	/// Consumes self and returns a new Versioned with version + 1.
	pub fn increment(self, new_data: T) -> Self {
		Self {
			data: new_data,
			version: self.version + 1,
			updated_at: current_timestamp(),
		}
	}

	/// Get a reference to the inner data.
	pub fn inner(&self) -> &T {
		&self.data
	}

	/// Consume self and return the inner data.
	pub fn into_inner(self) -> T {
		self.data
	}
}

/// Get current Unix timestamp in seconds.
fn current_timestamp() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.expect("Time went backwards")
		.as_secs()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
	struct TestData {
		value: String,
	}

	#[test]
	fn test_new_versioned_has_version_1() {
		let data = TestData {
			value: "test".to_string(),
		};
		let versioned = Versioned::new(data);

		assert_eq!(versioned.version, 1);
		assert_eq!(versioned.data.value, "test");
		assert!(versioned.updated_at > 0);
	}

	#[test]
	fn test_increment_increases_version() {
		let data = TestData {
			value: "v1".to_string(),
		};
		let v1 = Versioned::new(data);
		assert_eq!(v1.version, 1);

		let new_data = TestData {
			value: "v2".to_string(),
		};
		let v2 = v1.increment(new_data);

		assert_eq!(v2.version, 2);
		assert_eq!(v2.data.value, "v2");
	}

	#[test]
	fn test_inner_returns_reference() {
		let data = TestData {
			value: "test".to_string(),
		};
		let versioned = Versioned::new(data);

		assert_eq!(versioned.inner().value, "test");
	}

	#[test]
	fn test_into_inner_consumes() {
		let data = TestData {
			value: "test".to_string(),
		};
		let versioned = Versioned::new(data);
		let inner = versioned.into_inner();

		assert_eq!(inner.value, "test");
	}

	#[test]
	fn test_json_serialization_roundtrip() {
		let data = TestData {
			value: "test".to_string(),
		};
		let versioned = Versioned::new(data);

		let json = serde_json::to_string(&versioned).unwrap();
		let deserialized: Versioned<TestData> = serde_json::from_str(&json).unwrap();

		assert_eq!(deserialized.version, versioned.version);
		assert_eq!(deserialized.data.value, "test");
		assert_eq!(deserialized.updated_at, versioned.updated_at);
	}
}
