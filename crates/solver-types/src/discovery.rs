//! Intent discovery types for the solver system.
//!
//! This module defines types related to discovering and representing
//! cross-chain intents before they are validated into orders.

use serde::{Deserialize, Serialize};

/// Represents a discovered cross-chain intent.
///
/// An intent is a raw expression of desire to perform a cross-chain operation,
/// discovered from various sources like on-chain events or off-chain APIs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Intent {
	/// Unique identifier for this intent.
	pub id: String,
	/// Source from which this intent was discovered (e.g., "on-chain").
	pub source: String,
	/// Standard this intent conforms to (e.g., "eip7683").
	pub standard: String,
	/// Metadata about the intent discovery and requirements.
	pub metadata: IntentMetadata,
	/// Raw intent data in JSON format, structure depends on the standard.
	pub data: serde_json::Value,
	/// Quote ID associated with this intent.
	pub quote_id: Option<String>,
}

/// Metadata associated with a discovered intent.
///
/// Contains information about how the intent was discovered and any
/// special requirements for processing it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IntentMetadata {
	/// Whether this intent requires an auction process.
	pub requires_auction: bool,
	/// Timestamp until which this intent is exclusive to a specific solver.
	pub exclusive_until: Option<u64>,
	/// Timestamp when this intent was discovered.
	pub discovered_at: u64,
}
