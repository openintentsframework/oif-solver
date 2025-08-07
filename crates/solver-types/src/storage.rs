//! Storage-related types for the solver system.

/// Table names for storage operations.
///
/// This enum provides type safety for storage operations by replacing
/// string literals with strongly typed variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StorageTable {
	/// Table for storing order data
	Orders,
	/// Table for storing intent data  
	Intents,
	/// Table for mapping transaction hashes to order IDs
	TxToOrder,
}

impl StorageTable {
	/// Returns the string representation of the table name.
	pub fn as_str(&self) -> &'static str {
		match self {
			StorageTable::Orders => "orders",
			StorageTable::Intents => "intents",
			StorageTable::TxToOrder => "tx_to_order",
		}
	}
}
