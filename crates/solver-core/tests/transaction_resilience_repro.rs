use std::{collections::HashMap, sync::Arc};

use alloy_primitives::U256;
use solver_core::{
	handlers::TransactionHandler,
	recovery::RecoveryService,
	state::{transaction_attempt::TransactionAttemptStore, OrderStateMachine},
	EventBus,
};
use solver_delivery::{DeliveryService, MockDeliveryInterface};
use solver_settlement::{MockSettlementInterface, SettlementService};
use solver_storage::{
	implementations::file::{FileStorage, TtlConfig},
	StorageService,
};
use solver_types::{
	utils::tests::builders::OrderBuilder, Address, OrderStatus, Transaction,
	TransactionAttemptStatus, TransactionHash, TransactionReceipt, TransactionType,
};

fn file_storage() -> (Arc<StorageService>, tempfile::TempDir) {
	let temp_dir = tempfile::tempdir().unwrap();
	let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
		temp_dir.path().to_path_buf(),
		TtlConfig::default(),
	))));
	(storage, temp_dir)
}

fn sample_tx(chain_id: u64) -> Transaction {
	Transaction {
		to: Some(Address(vec![3; 20])),
		data: vec![0xde, 0xad, 0xbe, 0xef],
		value: U256::ZERO,
		chain_id,
		nonce: Some(7),
		gas_limit: Some(120000),
		gas_price: None,
		max_fee_per_gas: Some(2000),
		max_priority_fee_per_gas: Some(20),
	}
}

fn receipt(hash: TransactionHash, success: bool) -> TransactionReceipt {
	TransactionReceipt {
		hash,
		block_number: 12345,
		success,
		block_timestamp: Some(456),
		logs: vec![],
	}
}

#[tokio::test]
async fn transaction_resilience_reproves_atomic_fill_write_and_recovery_attempt_writeback() {
	// C1: confirmation handler writes status and fill hash in one state-machine transition.
	let (storage, _temp_dir) = file_storage();
	let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
	let order = OrderBuilder::new()
		.with_id("atomic-fill-order".to_string())
		.with_status(OrderStatus::Executing)
		.build();
	state_machine.store_order(&order).await.unwrap();

	let settlement = Arc::new(SettlementService::new(HashMap::new(), String::new(), 20));
	let handler = TransactionHandler::new(
		storage.clone(),
		state_machine.clone(),
		settlement,
		EventBus::new(100),
	);
	let fill_hash = TransactionHash(vec![0x11; 32]);
	handler
		.handle_confirmed(
			order.id.clone(),
			fill_hash.clone(),
			TransactionType::Fill,
			receipt(fill_hash.clone(), true),
		)
		.await
		.unwrap();

	let stored = state_machine.get_order(&order.id).await.unwrap();
	assert_eq!(stored.status, OrderStatus::Executed);
	assert_eq!(stored.fill_tx_hash, Some(fill_hash));

	// C3: startup recovery writes chain-proven confirmation back to the attempt ledger.
	let (storage, _temp_dir) = file_storage();
	let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
	let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));
	let mut order = OrderBuilder::new()
		.with_id("recovery-writeback-order".to_string())
		.with_status(OrderStatus::Executed)
		.build();
	order.fill_tx_hash = None;
	order.post_fill_tx_hash = None;
	order.settlement_name = Some("eip7683".to_string());
	state_machine.store_order(&order).await.unwrap();

	let recovered_hash = TransactionHash(vec![0x22; 32]);
	let attempt = attempt_store
		.create_planned_attempt(
			&order.id,
			Some(Address(vec![9; 20])),
			TransactionType::Fill,
			sample_tx(137),
		)
		.await
		.unwrap();
	attempt_store
		.update_attempt_status(
			&attempt.id,
			TransactionAttemptStatus::Broadcast,
			None,
			|attempt| {
				attempt.tx_hash = Some(recovered_hash.clone());
			},
		)
		.await
		.unwrap();

	let mut mock_delivery = MockDeliveryInterface::new();
	mock_delivery
		.expect_get_receipt()
		.with(
			mockall::predicate::eq(recovered_hash.clone()),
			mockall::predicate::eq(137u64),
		)
		.times(1)
		.returning(move |hash, _| {
			let hash = hash.clone();
			Box::pin(async move { Ok(receipt(hash, true)) })
		});
	let delivery = Arc::new(DeliveryService::new(
		HashMap::from([(
			137u64,
			Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
		)]),
		1,
		20,
		60,
	));

	let mut mock_settlement = MockSettlementInterface::new();
	mock_settlement
		.expect_recover_post_fill_state()
		.times(1)
		.returning(|_| Box::pin(async move { Ok(false) }));
	let settlement = Arc::new(SettlementService::new(
		HashMap::from([(
			"eip7683".to_string(),
			Box::new(mock_settlement) as Box<dyn solver_settlement::SettlementInterface>,
		)]),
		String::new(),
		20,
	));
	let recovery = RecoveryService::new(
		storage.clone(),
		state_machine.clone(),
		delivery,
		settlement,
		EventBus::new(100),
		attempt_store.clone(),
		Arc::new(HashMap::new()),
	);

	let (report, _orphaned) = recovery.recover_state().await.unwrap();
	assert_eq!(report.total_orders, 1);
	assert_eq!(report.reconciled_orders, 1);

	let stored = state_machine.get_order(&order.id).await.unwrap();
	assert_eq!(stored.fill_tx_hash, Some(recovered_hash.clone()));
	let attempt = attempt_store.get_attempt(&attempt.id).await.unwrap();
	assert_eq!(attempt.status, TransactionAttemptStatus::Confirmed);
	assert_eq!(attempt.tx_hash, Some(recovered_hash));
	assert!(attempt.receipt.is_some());
}
