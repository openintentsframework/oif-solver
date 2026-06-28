use crate::{
	current_timestamp, Address, Transaction, TransactionHash, TransactionReceipt, TransactionType,
};
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TransactionAttemptStatus {
	Planned,
	Broadcast,
	Confirmed,
	SubmitRejected,
	Reverted,
	Indeterminate,
	Replaced,
}

impl TransactionAttemptStatus {
	pub fn is_terminal(self) -> bool {
		matches!(
			self,
			Self::Confirmed | Self::SubmitRejected | Self::Reverted | Self::Replaced
		)
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum TransactionAttemptScope {
	Order { order_id: String },
	System { scope_id: String },
}

impl TransactionAttemptScope {
	pub fn order(order_id: impl Into<String>) -> Self {
		Self::Order {
			order_id: order_id.into(),
		}
	}

	pub fn system(scope_id: impl Into<String>) -> Self {
		Self::System {
			scope_id: scope_id.into(),
		}
	}

	pub fn scope_id(&self) -> &str {
		match self {
			Self::Order { order_id } => order_id,
			Self::System { scope_id } => scope_id,
		}
	}

	pub fn order_id(&self) -> Option<&str> {
		match self {
			Self::Order { order_id } => Some(order_id),
			Self::System { .. } => None,
		}
	}

	pub fn is_system(&self) -> bool {
		matches!(self, Self::System { .. })
	}
}

#[derive(Debug, Clone, Serialize)]
pub struct TransactionAttempt {
	pub id: String,
	pub scope: TransactionAttemptScope,
	pub signer: Option<Address>,
	pub tx_type: TransactionType,
	pub chain_id: u64,
	pub nonce: Option<u64>,
	pub tx_hash: Option<TransactionHash>,
	pub receipt: Option<TransactionReceipt>,
	pub tx: Transaction,
	pub status: TransactionAttemptStatus,
	pub error: Option<String>,
	pub created_at: u64,
	pub updated_at: u64,
	/// Parent attempt id when this row is a same-nonce replacement.
	/// Set at creation by the sweeper; never mutated afterwards.
	#[serde(default)]
	pub replacement_of: Option<String>,
	/// Child attempt id when this row has been superseded by a bump.
	/// Best-effort hint; lineage traversal MUST NOT depend on this field.
	#[serde(default)]
	pub replaced_by: Option<String>,
}

impl<'de> Deserialize<'de> for TransactionAttempt {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		#[derive(Deserialize)]
		struct TransactionAttemptWire {
			id: String,
			scope: Option<TransactionAttemptScope>,
			order_id: Option<String>,
			signer: Option<Address>,
			tx_type: TransactionType,
			chain_id: u64,
			nonce: Option<u64>,
			tx_hash: Option<TransactionHash>,
			receipt: Option<TransactionReceipt>,
			tx: Transaction,
			status: TransactionAttemptStatus,
			error: Option<String>,
			created_at: u64,
			updated_at: u64,
			#[serde(default)]
			replacement_of: Option<String>,
			#[serde(default)]
			replaced_by: Option<String>,
		}

		let wire = TransactionAttemptWire::deserialize(deserializer)?;
		let scope = match (wire.scope, wire.order_id) {
			(Some(scope), _) => scope,
			(None, Some(order_id)) => TransactionAttemptScope::order(order_id),
			(None, None) => {
				return Err(serde::de::Error::missing_field("scope"));
			},
		};

		Ok(Self {
			id: wire.id,
			scope,
			signer: wire.signer,
			tx_type: wire.tx_type,
			chain_id: wire.chain_id,
			nonce: wire.nonce,
			tx_hash: wire.tx_hash,
			receipt: wire.receipt,
			tx: wire.tx,
			status: wire.status,
			error: wire.error,
			created_at: wire.created_at,
			updated_at: wire.updated_at,
			replacement_of: wire.replacement_of,
			replaced_by: wire.replaced_by,
		})
	}
}

impl TransactionAttempt {
	pub fn planned(
		id: String,
		scope: TransactionAttemptScope,
		signer: Option<Address>,
		tx_type: TransactionType,
		tx: Transaction,
	) -> Self {
		let now = current_timestamp();
		Self {
			id,
			scope,
			signer,
			tx_type,
			chain_id: tx.chain_id,
			nonce: tx.nonce,
			tx_hash: None,
			receipt: None,
			tx,
			status: TransactionAttemptStatus::Planned,
			error: None,
			created_at: now,
			updated_at: now,
			replacement_of: None,
			replaced_by: None,
		}
	}

	pub fn is_terminal(&self) -> bool {
		self.status.is_terminal()
	}

	pub fn order_id(&self) -> Option<&str> {
		self.scope.order_id()
	}

	pub fn scope_id(&self) -> &str {
		self.scope.scope_id()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{Address, Log, TransactionHash, TransactionReceipt};
	use alloy_primitives::U256;

	fn sample_tx() -> Transaction {
		Transaction {
			to: Some(Address(vec![1; 20])),
			data: vec![0xab, 0xcd],
			value: U256::from(5u64),
			chain_id: 10,
			nonce: Some(7),
			gas_limit: Some(21000),
			gas_price: None,
			max_fee_per_gas: Some(100),
			max_priority_fee_per_gas: Some(2),
		}
	}

	#[test]
	fn planned_attempt_copies_tx_metadata() {
		let attempt = TransactionAttempt::planned(
			"attempt-1".to_string(),
			TransactionAttemptScope::order("order-1"),
			Some(Address(vec![9; 20])),
			TransactionType::Fill,
			sample_tx(),
		);

		assert_eq!(attempt.id, "attempt-1");
		assert_eq!(attempt.order_id(), Some("order-1"));
		assert_eq!(attempt.signer, Some(Address(vec![9; 20])));
		assert_eq!(attempt.tx_type, TransactionType::Fill);
		assert_eq!(attempt.chain_id, 10);
		assert_eq!(attempt.nonce, Some(7));
		assert_eq!(attempt.tx_hash, None);
		assert_eq!(attempt.receipt, None);
		assert_eq!(attempt.status, TransactionAttemptStatus::Planned);
		assert_eq!(attempt.error, None);
		assert!(!attempt.is_terminal());
		assert!(attempt.created_at > 0);
		assert_eq!(attempt.created_at, attempt.updated_at);
	}

	#[test]
	fn terminal_statuses_are_explicit() {
		assert!(!TransactionAttemptStatus::Planned.is_terminal());
		assert!(!TransactionAttemptStatus::Broadcast.is_terminal());
		assert!(!TransactionAttemptStatus::Indeterminate.is_terminal());
		assert!(TransactionAttemptStatus::Confirmed.is_terminal());
		assert!(TransactionAttemptStatus::SubmitRejected.is_terminal());
		assert!(TransactionAttemptStatus::Reverted.is_terminal());
		assert!(TransactionAttemptStatus::Replaced.is_terminal());
	}

	#[test]
	fn status_serializes_as_camel_case() {
		let json = serde_json::to_string(&TransactionAttemptStatus::SubmitRejected).unwrap();
		assert_eq!(json, "\"submitRejected\"");
	}

	#[test]
	fn attempt_round_trips_through_json() {
		let mut attempt = TransactionAttempt::planned(
			"attempt-1".to_string(),
			TransactionAttemptScope::order("order-1"),
			Some(Address(vec![9; 20])),
			TransactionType::Fill,
			sample_tx(),
		);
		attempt.tx_hash = Some(TransactionHash(vec![4; 32]));
		attempt.receipt = Some(TransactionReceipt {
			hash: TransactionHash(vec![4; 32]),
			block_number: 123,
			success: true,
			logs: vec![Log {
				address: Address(vec![8; 20]),
				topics: vec![],
				data: vec![0xaa],
				..Default::default()
			}],
			block_timestamp: Some(456),
		});
		attempt.status = TransactionAttemptStatus::Broadcast;
		attempt.error = Some("temporary rpc timeout".to_string());

		let json = serde_json::to_string(&attempt).unwrap();
		let decoded: TransactionAttempt = serde_json::from_str(&json).unwrap();

		assert_eq!(decoded.id, attempt.id);
		assert_eq!(decoded.scope, attempt.scope);
		assert_eq!(decoded.signer, attempt.signer);
		assert_eq!(decoded.tx_type, attempt.tx_type);
		assert_eq!(decoded.chain_id, attempt.chain_id);
		assert_eq!(decoded.nonce, attempt.nonce);
		assert_eq!(decoded.tx_hash.as_ref().unwrap().0, vec![4; 32]);
		assert_eq!(decoded.receipt.as_ref().unwrap().block_number, 123);
		assert!(decoded.receipt.as_ref().unwrap().success);
		assert_eq!(decoded.status, attempt.status);
		assert_eq!(decoded.error, attempt.error);
		assert_eq!(decoded.tx.data, attempt.tx.data);
		assert_eq!(decoded.tx.chain_id, attempt.tx.chain_id);
	}

	#[test]
	fn replaced_status_is_terminal() {
		assert!(TransactionAttemptStatus::Replaced.is_terminal());
	}

	#[test]
	fn replaced_attempt_is_terminal() {
		let mut a = TransactionAttempt::planned(
			"x".into(),
			TransactionAttemptScope::order("order-1"),
			Some(Address(vec![9; 20])),
			TransactionType::Fill,
			sample_tx(),
		);
		a.status = TransactionAttemptStatus::Replaced;
		assert!(a.is_terminal());
	}

	#[test]
	fn lineage_fields_default_to_none_on_planned() {
		let a = TransactionAttempt::planned(
			"x".into(),
			TransactionAttemptScope::order("order-1"),
			Some(Address(vec![9; 20])),
			TransactionType::Fill,
			sample_tx(),
		);
		assert!(a.replacement_of.is_none());
		assert!(a.replaced_by.is_none());
	}

	#[test]
	fn old_serialized_row_without_lineage_fields_deserializes() {
		// Pre-PR-06 row JSON: no replacement_of, no replaced_by.
		// tx_type uses PascalCase (no rename_all on TransactionType).
		// status uses camelCase (rename_all = "camelCase" on TransactionAttemptStatus).
		let json = r#"{
			"id": "x",
			"order_id": "o",
			"signer": null,
			"tx_type": "Fill",
			"chain_id": 1,
			"nonce": null,
			"tx_hash": null,
			"receipt": null,
			"tx": {
				"to": null, "data": [], "value": "0",
				"chain_id": 1, "nonce": null, "gas_limit": null,
				"gas_price": null, "max_fee_per_gas": null,
				"max_priority_fee_per_gas": null
			},
			"status": "planned",
			"error": null,
			"created_at": 0,
			"updated_at": 0
		}"#;
		let a: TransactionAttempt = serde_json::from_str(json).unwrap();
		assert_eq!(a.scope, TransactionAttemptScope::order("o"));
		assert_eq!(a.order_id(), Some("o"));
		assert!(a.replacement_of.is_none());
		assert!(a.replaced_by.is_none());
	}
}
