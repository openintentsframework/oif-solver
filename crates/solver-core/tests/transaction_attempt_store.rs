use std::sync::Arc;

use alloy_primitives::U256;
use solver_core::state::transaction_attempt::TransactionAttemptStore;
use solver_delivery::TransactionAttemptRecorder;
use solver_storage::{
	implementations::file::{FileStorage, TtlConfig},
	StorageService,
};
use solver_types::{
	Address, Transaction, TransactionAttemptStatus, TransactionHash, TransactionReceipt,
	TransactionType,
};
use tempfile::TempDir;

fn make_store() -> (TransactionAttemptStore, TempDir) {
	let temp_dir = tempfile::tempdir().unwrap();
	let path = temp_dir.path().to_path_buf();
	let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
		path,
		TtlConfig::default(),
	))));
	(TransactionAttemptStore::new(storage), temp_dir)
}

fn sample_tx(chain_id: u64, nonce: Option<u64>) -> Transaction {
	Transaction {
		to: Some(Address(vec![3; 20])),
		data: vec![0xde, 0xad, 0xbe, 0xef],
		value: U256::ZERO,
		chain_id,
		nonce,
		gas_limit: Some(120000),
		gas_price: None,
		max_fee_per_gas: Some(2000),
		max_priority_fee_per_gas: Some(20),
	}
}

fn sample_hash(byte: u8) -> TransactionHash {
	TransactionHash(vec![byte; 32])
}

fn sample_receipt(hash: TransactionHash, success: bool) -> TransactionReceipt {
	TransactionReceipt {
		hash,
		block_number: 123,
		success,
		logs: vec![],
		block_timestamp: Some(456),
	}
}

#[tokio::test]
async fn create_planned_attempt_persists_with_v4_id() {
	let (store, _temp_dir) = make_store();

	let attempt = store
		.create_planned_attempt(
			"order-1",
			Some(Address(vec![9; 20])),
			TransactionType::Fill,
			sample_tx(10, Some(7)),
		)
		.await
		.unwrap();

	let parsed_id = uuid::Uuid::parse_str(&attempt.id).unwrap();
	assert_eq!(parsed_id.get_version_num(), 4);
	assert_eq!(attempt.order_id, "order-1");
	assert_eq!(attempt.signer, Some(Address(vec![9; 20])));
	assert_eq!(attempt.tx_type, TransactionType::Fill);
	assert_eq!(attempt.chain_id, 10);
	assert_eq!(attempt.nonce, Some(7));
	assert_eq!(attempt.status, TransactionAttemptStatus::Planned);

	let loaded = store.get_attempt(&attempt.id).await.unwrap();
	assert_eq!(loaded.id, attempt.id);
	assert_eq!(loaded.order_id, attempt.order_id);
	assert_eq!(loaded.signer, attempt.signer);
	assert_eq!(loaded.tx_type, attempt.tx_type);
	assert_eq!(loaded.chain_id, attempt.chain_id);
	assert_eq!(loaded.nonce, attempt.nonce);
	assert_eq!(loaded.tx_hash, attempt.tx_hash);
	assert_eq!(loaded.receipt, attempt.receipt);
	assert_eq!(loaded.status, attempt.status);
	assert_eq!(loaded.error, attempt.error);
	assert_eq!(loaded.created_at, attempt.created_at);
	assert_eq!(loaded.updated_at, attempt.updated_at);
	assert_eq!(loaded.tx.chain_id, attempt.tx.chain_id);
	assert_eq!(loaded.tx.nonce, attempt.tx.nonce);
	assert_eq!(loaded.tx.data, attempt.tx.data);
}

#[tokio::test]
async fn attempts_for_order_returns_only_matching_order_attempts() {
	let (store, _temp_dir) = make_store();

	let first = store
		.create_planned_attempt(
			"order-1",
			Some(Address(vec![9; 20])),
			TransactionType::Fill,
			sample_tx(10, Some(1)),
		)
		.await
		.unwrap();
	let second = store
		.create_planned_attempt(
			"order-2",
			Some(Address(vec![8; 20])),
			TransactionType::Fill,
			sample_tx(10, Some(2)),
		)
		.await
		.unwrap();

	let order_one_attempts = store.attempts_for_order("order-1").await.unwrap();

	assert_eq!(order_one_attempts.len(), 1);
	assert_eq!(order_one_attempts[0].id, first.id);
	assert_ne!(order_one_attempts[0].id, second.id);
}

#[tokio::test]
async fn update_attempt_status_sets_hash_and_hash_lookup_finds_it() {
	let (store, _temp_dir) = make_store();
	let attempt = store
		.create_planned_attempt(
			"order-1",
			Some(Address(vec![9; 20])),
			TransactionType::Fill,
			sample_tx(10, Some(7)),
		)
		.await
		.unwrap();
	let tx_hash = sample_hash(9);

	let updated = store
		.update_attempt_status(
			&attempt.id,
			TransactionAttemptStatus::Broadcast,
			None,
			|attempt| {
				attempt.tx_hash = Some(tx_hash.clone());
			},
		)
		.await
		.unwrap();

	assert_eq!(updated.status, TransactionAttemptStatus::Broadcast);
	assert_eq!(updated.tx_hash, Some(tx_hash.clone()));
	assert!(updated.updated_at >= updated.created_at);

	let by_hash = store.attempt_by_hash(&tx_hash).await.unwrap().unwrap();
	assert_eq!(by_hash.id, attempt.id);
}

#[tokio::test]
async fn recorder_update_persists_broadcast_hash_index() {
	let (store, _temp_dir) = make_store();
	let tx_hash = sample_hash(7);
	let attempt = store
		.create_planned_attempt(
			"order-1",
			Some(Address(vec![9; 20])),
			TransactionType::Fill,
			sample_tx(10, Some(7)),
		)
		.await
		.unwrap();

	store
		.record_attempt_update(
			&attempt.id,
			TransactionAttemptStatus::Broadcast,
			Some(tx_hash.clone()),
			None,
			None,
		)
		.await
		.unwrap();

	let stored = store.get_attempt(&attempt.id).await.unwrap();
	assert_eq!(stored.status, TransactionAttemptStatus::Broadcast);
	assert_eq!(stored.tx_hash, Some(tx_hash.clone()));
	assert_eq!(stored.receipt, None);
	assert_eq!(stored.error, None);

	let by_hash = store.attempt_by_hash(&tx_hash).await.unwrap().unwrap();
	assert_eq!(by_hash.id, attempt.id);
}

#[tokio::test]
async fn recorder_update_persists_confirmed_receipt() {
	let (store, _temp_dir) = make_store();
	let tx_hash = sample_hash(8);
	let receipt = sample_receipt(tx_hash.clone(), true);
	let attempt = store
		.create_planned_attempt(
			"order-1",
			Some(Address(vec![9; 20])),
			TransactionType::Claim,
			sample_tx(10, Some(7)),
		)
		.await
		.unwrap();

	store
		.record_attempt_update(
			&attempt.id,
			TransactionAttemptStatus::Confirmed,
			Some(tx_hash.clone()),
			Some(receipt.clone()),
			None,
		)
		.await
		.unwrap();

	let stored = store.get_attempt(&attempt.id).await.unwrap();
	assert_eq!(stored.status, TransactionAttemptStatus::Confirmed);
	assert_eq!(stored.tx_hash, Some(tx_hash));
	assert_eq!(
		stored.receipt.as_ref().unwrap().block_number,
		receipt.block_number
	);
	assert_eq!(stored.receipt.as_ref().unwrap().success, true);
	assert!(stored.is_terminal());
}

#[tokio::test]
async fn terminal_attempt_cannot_be_mutated() {
	let (store, _temp_dir) = make_store();
	let attempt = store
		.create_planned_attempt(
			"order-1",
			Some(Address(vec![9; 20])),
			TransactionType::Fill,
			sample_tx(10, Some(7)),
		)
		.await
		.unwrap();

	store
		.update_attempt_status(
			&attempt.id,
			TransactionAttemptStatus::Confirmed,
			None,
			|attempt| {
				attempt.tx_hash = Some(sample_hash(1));
			},
		)
		.await
		.unwrap();

	let err = store
		.update_attempt_status(
			&attempt.id,
			TransactionAttemptStatus::Reverted,
			Some("late revert".to_string()),
			|_| {},
		)
		.await
		.unwrap_err();

	assert!(err.to_string().contains("terminal"));
	let loaded = store.get_attempt(&attempt.id).await.unwrap();
	assert_eq!(loaded.status, TransactionAttemptStatus::Confirmed);
	assert_eq!(loaded.error, None);
}
