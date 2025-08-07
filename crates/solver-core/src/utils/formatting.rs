//! String formatting utilities.
//!
//! Provides functions for formatting strings for display, particularly for
//! truncating long hex strings to make logs more readable.

/// Utility function to truncate a hex string for display purposes.
///
/// Shows only the first 8 characters followed by ".." for longer strings.
pub fn truncate_id(id: &str) -> String {
	if id.len() <= 8 {
		id.to_string()
	} else {
		format!("{}..", &id[..8])
	}
}
