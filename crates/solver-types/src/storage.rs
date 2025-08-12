//! Storage-related types for the solver system.

use std::str::FromStr;

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
	/// Key for storing quote data
	Quotes,
}

impl StorageKey {
	/// Returns the string representation of the storage key.
	pub fn as_str(&self) -> &'static str {
		match self {
			StorageKey::Orders => "orders",
			StorageKey::Intents => "intents",
			StorageKey::OrderByTxHash => "order_by_tx_hash",
			StorageKey::Quotes => "quotes",
		}
	}

	/// Returns an iterator over all StorageKey variants.
	pub fn all() -> impl Iterator<Item = Self> {
		[
			Self::Orders,
			Self::Intents,
			Self::OrderByTxHash,
			Self::Quotes,
		]
		.into_iter()
	}
}

impl FromStr for StorageKey {
	type Err = ();

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"orders" => Ok(Self::Orders),
			"intents" => Ok(Self::Intents),
			"order_by_tx_hash" => Ok(Self::OrderByTxHash),
			"quotes" => Ok(Self::Quotes),
			_ => Err(()),
		}
	}
}

impl From<StorageKey> for &'static str {
	fn from(key: StorageKey) -> Self {
		key.as_str()
	}
}
