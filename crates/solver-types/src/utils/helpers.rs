//! Helper utilities for common operations.
//!
//! This module provides utility functions used throughout the solver system
//! for common operations like timestamp retrieval.

/// Helper function to get current timestamp, returns 0 if system time is before UNIX epoch.
///
/// This function safely retrieves the current UNIX timestamp in seconds,
/// returning 0 if the system time is somehow before the UNIX epoch.
pub fn current_timestamp() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}
