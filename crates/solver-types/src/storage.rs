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
	/// Key for storing settlement message data (per implementation)
	SettlementMessages,
}

impl StorageKey {
	/// Returns the string representation of the storage key.
	pub fn as_str(&self) -> &'static str {
		match self {
			StorageKey::Orders => "orders",
			StorageKey::Intents => "intents",
			StorageKey::OrderByTxHash => "order_by_tx_hash",
			StorageKey::Quotes => "quotes",
			StorageKey::SettlementMessages => "settlement_messages",
		}
	}

	/// Returns an iterator over all StorageKey variants.
	pub fn all() -> impl Iterator<Item = Self> {
		[
			Self::Orders,
			Self::Intents,
			Self::OrderByTxHash,
			Self::Quotes,
			Self::SettlementMessages,
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
			"settlement_messages" => Ok(Self::SettlementMessages),
			_ => Err(()),
		}
	}
}

impl From<StorageKey> for &'static str {
	fn from(key: StorageKey) -> Self {
		key.as_str()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_storage_key_as_str() {
		assert_eq!(StorageKey::Orders.as_str(), "orders");
		assert_eq!(StorageKey::Intents.as_str(), "intents");
		assert_eq!(StorageKey::OrderByTxHash.as_str(), "order_by_tx_hash");
		assert_eq!(StorageKey::Quotes.as_str(), "quotes");
		assert_eq!(
			StorageKey::SettlementMessages.as_str(),
			"settlement_messages"
		);
	}

	#[test]
	fn test_storage_key_from_str() {
		// Valid cases
		assert_eq!("orders".parse::<StorageKey>().unwrap(), StorageKey::Orders);
		assert_eq!(
			"intents".parse::<StorageKey>().unwrap(),
			StorageKey::Intents
		);
		assert_eq!(
			"order_by_tx_hash".parse::<StorageKey>().unwrap(),
			StorageKey::OrderByTxHash
		);
		assert_eq!("quotes".parse::<StorageKey>().unwrap(), StorageKey::Quotes);
		assert_eq!(
			"settlement_messages".parse::<StorageKey>().unwrap(),
			StorageKey::SettlementMessages
		);

		// Invalid cases
		assert!("invalid".parse::<StorageKey>().is_err());
		assert!("".parse::<StorageKey>().is_err());
		assert!("Orders".parse::<StorageKey>().is_err()); // Case sensitive
		assert!(" orders ".parse::<StorageKey>().is_err()); // Whitespace
	}

	#[test]
	fn test_storage_key_all_iterator() {
		let all_keys: Vec<StorageKey> = StorageKey::all().collect();
		let expected = vec![
			StorageKey::Orders,
			StorageKey::Intents,
			StorageKey::OrderByTxHash,
			StorageKey::Quotes,
			StorageKey::SettlementMessages,
		];

		assert_eq!(all_keys, expected);
	}

	#[test]
	fn test_from_storage_key_to_str() {
		// Test all variants
		let orders_str: &'static str = StorageKey::Orders.into();
		assert_eq!(orders_str, "orders");

		let intents_str: &'static str = StorageKey::Intents.into();
		assert_eq!(intents_str, "intents");

		let order_by_tx_str: &'static str = StorageKey::OrderByTxHash.into();
		assert_eq!(order_by_tx_str, "order_by_tx_hash");

		let quotes_str: &'static str = StorageKey::Quotes.into();
		assert_eq!(quotes_str, "quotes");

		let settlement_str: &'static str = StorageKey::SettlementMessages.into();
		assert_eq!(settlement_str, "settlement_messages");
	}

	#[test]
	fn test_round_trip_conversion() {
		for key in StorageKey::all() {
			let str_repr = key.as_str();
			let parsed_key = str_repr.parse::<StorageKey>().unwrap();
			assert_eq!(key, parsed_key);
		}
	}

	#[test]
	fn test_string_uniqueness() {
		use std::collections::HashSet;

		let strings: HashSet<&str> = StorageKey::all().map(|k| k.as_str()).collect();
		assert_eq!(strings.len(), 4, "String representations should be unique");
	}

	#[test]
	fn test_hash_and_equality() {
		use std::collections::HashSet;

		let mut set = HashSet::new();
		for key in StorageKey::all() {
			assert!(set.insert(key)); // Should be unique
		}
		assert_eq!(set.len(), 4);

		// Test equality
		assert_eq!(StorageKey::Orders, StorageKey::Orders);
		assert_ne!(StorageKey::Orders, StorageKey::Intents);
	}
}
