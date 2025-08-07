//! Storage-related types for the solver system.

/// Storage keys for different data collections.
///
/// This enum provides type safety for storage operations by replacing
/// string literals with strongly typed variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StorageKey {
	/// Key for storing order data
	Orders,
	/// Key for storing intent data  
	Intents,
	/// Key for mapping transaction hashes to order IDs
	OrderByTxHash,
}

impl StorageKey {
	/// Returns the string representation of the storage key.
	pub fn as_str(&self) -> &'static str {
		match self {
			StorageKey::Orders => "orders",
			StorageKey::Intents => "intents",
			StorageKey::OrderByTxHash => "order_by_tx_hash",
		}
	}
}
