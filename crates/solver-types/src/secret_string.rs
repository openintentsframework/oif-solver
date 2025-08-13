//! Secure string type for handling sensitive data like private keys.
//!
//! This module provides `SecretString`, a wrapper around sensitive string data
//! that ensures the data is zeroed out when dropped and is never accidentally
//! exposed in logs or debug output.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use zeroize::Zeroizing;

/// A secure string type that automatically zeros memory on drop and
/// prevents accidental exposure in logs.
///
/// This type should be used for any sensitive string data like private keys,
/// passwords, or API tokens.
#[derive(Clone)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
	/// Creates a new SecretString from a regular string.
	pub fn new(s: String) -> Self {
		Self(Zeroizing::new(s))
	}

	/// Creates a new SecretString from a string slice.
	pub fn from(s: &str) -> Self {
		Self::new(s.to_string())
	}

	/// Exposes the secret string as a string slice.
	///
	/// # Security Warning
	/// This method exposes the actual secret. Use it only when absolutely necessary
	/// and ensure the exposed value is not logged or stored insecurely.
	pub fn expose_secret(&self) -> &str {
		&self.0
	}

	/// Exposes the secret string to a closure for processing.
	///
	/// This is a safer way to access the secret as it limits the scope
	/// where the secret is exposed.
	pub fn with_exposed<F, R>(&self, f: F) -> R
	where
		F: FnOnce(&str) -> R,
	{
		f(&self.0)
	}

	/// Returns the length of the secret string.
	pub fn len(&self) -> usize {
		self.0.len()
	}

	/// Returns true if the secret string is empty.
	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}
}

impl fmt::Debug for SecretString {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "SecretString(***REDACTED***)")
	}
}

impl fmt::Display for SecretString {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "***REDACTED***")
	}
}

impl From<String> for SecretString {
	fn from(s: String) -> Self {
		Self::new(s)
	}
}

impl From<&str> for SecretString {
	fn from(s: &str) -> Self {
		Self::from(s)
	}
}

impl PartialEq for SecretString {
	fn eq(&self, other: &Self) -> bool {
		self.0.as_str() == other.0.as_str()
	}
}

impl Eq for SecretString {}

// Custom serialization that redacts the value
impl Serialize for SecretString {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		// When serializing for logs or debug, always redact
		// For actual config serialization, we'd need a different approach
		serializer.serialize_str("***REDACTED***")
	}
}

// Custom deserialization
impl<'de> Deserialize<'de> for SecretString {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		Ok(SecretString::new(s))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_secret_string_debug() {
		let secret = SecretString::from("my-secret-key");
		let debug_str = format!("{:?}", secret);
		assert_eq!(debug_str, "SecretString(***REDACTED***)");
		assert!(!debug_str.contains("my-secret-key"));
	}

	#[test]
	fn test_secret_string_display() {
		let secret = SecretString::from("my-secret-key");
		let display_str = format!("{}", secret);
		assert_eq!(display_str, "***REDACTED***");
		assert!(!display_str.contains("my-secret-key"));
	}

	#[test]
	fn test_secret_string_expose() {
		let secret = SecretString::from("my-secret-key");
		assert_eq!(secret.expose_secret(), "my-secret-key");
	}

	#[test]
	fn test_secret_string_eq() {
		let secret1 = SecretString::from("key1");
		let secret2 = SecretString::from("key1");
		let secret3 = SecretString::from("key2");

		assert_eq!(secret1, secret2);
		assert_ne!(secret1, secret3);
	}

	#[test]
	fn test_with_exposed() {
		let secret = SecretString::from("my-secret-value");

		// Test that the closure receives the correct value
		let result = secret.with_exposed(|s| {
			assert_eq!(s, "my-secret-value");
			s.len()
		});
		assert_eq!(result, 15);

		// Test that it can return different types
		let uppercase = secret.with_exposed(|s| s.to_uppercase());
		assert_eq!(uppercase, "MY-SECRET-VALUE");

		// Test that the secret is not exposed outside the closure
		let debug_str = format!("{:?}", secret);
		assert!(!debug_str.contains("my-secret-value"));
	}
}
