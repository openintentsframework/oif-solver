//! Intent builder utilities for creating test and production Intent instances.

use crate::{Intent, IntentMetadata};
use alloy_primitives::Bytes;

/// Builder for creating Intent instances with sensible defaults.
///
/// This builder provides a fluent interface for constructing Intent objects,
/// particularly useful for testing and creating intents with common patterns.
#[derive(Debug, Clone)]
pub struct IntentBuilder {
	id: String,
	source: String,
	standard: String,
	metadata: IntentMetadata,
	data: serde_json::Value,
	order_bytes: Bytes,
	quote_id: Option<String>,
	lock_type: String,
}

impl Default for IntentBuilder {
	fn default() -> Self {
		let timestamp = crate::current_timestamp();
		Self {
			id: "test_intent_123".to_string(),
			source: "test".to_string(),
			standard: "eip7683".to_string(),
			metadata: IntentMetadata {
				requires_auction: false,
				exclusive_until: None,
				discovered_at: timestamp,
			},
			data: serde_json::json!({
				"origin_chain_id": 1,
				"outputs": [
					{
						"chain_id": 137,
						"token": "0x0000000000000000000000000000000000000000",
						"amount": "950000000000000000"
					}
				]
			}),
			order_bytes: Bytes::default(), // Empty bytes for test data
			quote_id: None,
			lock_type: "permit2_escrow".to_string(),
		}
	}
}

impl IntentBuilder {
	/// Creates a new IntentBuilder with default values.
	pub fn new() -> Self {
		Self::default()
	}

	/// Sets the intent ID.
	pub fn with_id<S: Into<String>>(mut self, id: S) -> Self {
		self.id = id.into();
		self
	}

	/// Sets the source.
	pub fn with_source<S: Into<String>>(mut self, source: S) -> Self {
		self.source = source.into();
		self
	}

	/// Sets the standard.
	pub fn with_standard<S: Into<String>>(mut self, standard: S) -> Self {
		self.standard = standard.into();
		self
	}

	/// Sets the metadata.
	pub fn with_metadata(mut self, metadata: IntentMetadata) -> Self {
		self.metadata = metadata;
		self
	}

	/// Sets whether the intent requires auction.
	pub fn with_requires_auction(mut self, requires_auction: bool) -> Self {
		self.metadata.requires_auction = requires_auction;
		self
	}

	/// Sets the exclusive until timestamp.
	pub fn with_exclusive_until(mut self, exclusive_until: Option<u64>) -> Self {
		self.metadata.exclusive_until = exclusive_until;
		self
	}

	/// Sets the discovered at timestamp.
	pub fn with_discovered_at(mut self, discovered_at: u64) -> Self {
		self.metadata.discovered_at = discovered_at;
		self
	}

	/// Sets the intent data.
	pub fn with_data(mut self, data: serde_json::Value) -> Self {
		self.data = data;
		self
	}

	/// Sets the origin chain ID in the data.
	pub fn with_origin_chain_id(mut self, chain_id: u64) -> Self {
		if let Some(obj) = self.data.as_object_mut() {
			obj.insert(
				"origin_chain_id".to_string(),
				serde_json::Value::Number(chain_id.into()),
			);
		}
		self
	}

	/// Adds an output to the intent data.
	pub fn with_output(mut self, chain_id: u64, token: &str, amount: &str) -> Self {
		if let Some(obj) = self.data.as_object_mut() {
			let outputs = obj
				.entry("outputs")
				.or_insert_with(|| serde_json::Value::Array(vec![]));
			if let Some(outputs_array) = outputs.as_array_mut() {
				outputs_array.push(serde_json::json!({
					"chain_id": chain_id,
					"token": token,
					"amount": amount
				}));
			}
		}
		self
	}

	/// Sets the outputs in the intent data.
	pub fn with_outputs(mut self, outputs: Vec<serde_json::Value>) -> Self {
		if let Some(obj) = self.data.as_object_mut() {
			obj.insert("outputs".to_string(), serde_json::Value::Array(outputs));
		}
		self
	}

	/// Sets the quote ID.
	pub fn with_quote_id<S: Into<String>>(mut self, quote_id: Option<S>) -> Self {
		self.quote_id = quote_id.map(|s| s.into());
		self
	}

	/// Sets the lock type.
	pub fn with_lock_type<S: Into<String>>(mut self, lock_type: S) -> Self {
		self.lock_type = lock_type.into();
		self
	}

	/// Sets the order bytes.
	pub fn with_order_bytes(mut self, bytes: Bytes) -> Self {
		self.order_bytes = bytes;
		self
	}

	/// Builds the Intent instance.
	pub fn build(self) -> Intent {
		Intent {
			id: self.id,
			source: self.source,
			standard: self.standard,
			metadata: self.metadata,
			data: self.data,
			order_bytes: self.order_bytes,
			quote_id: self.quote_id,
			lock_type: self.lock_type,
		}
	}
}
