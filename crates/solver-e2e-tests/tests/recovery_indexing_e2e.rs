//! Recovery indexing regression tests.
//!
//! This test intentionally avoids Anvil. It exercises the same production
//! recovery path against the real file storage backend, which is enough to
//! catch mismatches between indexes written by `OrderStateMachine` and indexes
//! queried by `RecoveryService`.

use solver_core::{
	recovery::RecoveryService,
	state::{transaction_attempt::TransactionAttemptStore, OrderStateMachine},
	EventBus,
};
use solver_delivery::DeliveryService;
use solver_settlement::SettlementService;
use solver_storage::{
	implementations::file::{FileStorage, TtlConfig},
	StorageService,
};
use solver_types::{
	utils::tests::builders::OrderBuilder, OrderStatus, StorageKey, TransactionType,
};
use std::{collections::HashMap, sync::Arc};

fn file_storage() -> (Arc<StorageService>, tempfile::TempDir) {
	let tempdir = tempfile::TempDir::new().expect("create temp storage dir");
	let backend = FileStorage::new(tempdir.path().to_path_buf(), TtlConfig::default());
	(Arc::new(StorageService::new(Box::new(backend))), tempdir)
}

fn recovery_service(storage: Arc<StorageService>) -> RecoveryService {
	let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
	let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20, 60));
	let settlement = Arc::new(SettlementService::new(HashMap::new(), String::new(), 20));
	let event_bus = EventBus::new(100);
	let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));
	let networks_config = Arc::new(solver_types::NetworksConfig::new());

	RecoveryService::new(
		storage,
		state_machine,
		delivery,
		settlement,
		event_bus,
		attempt_store,
		networks_config,
	)
}

#[tokio::test]
async fn recovery_counts_only_non_terminal_orders_from_real_storage_indexes() -> anyhow::Result<()>
{
	let (storage, _tempdir) = file_storage();
	let state_machine = OrderStateMachine::new(storage.clone());

	let active = OrderBuilder::new()
		.with_id("active-created-order")
		.with_status(OrderStatus::Created)
		.build();
	let finalized = OrderBuilder::new()
		.with_id("terminal-finalized-order")
		.with_status(OrderStatus::Finalized)
		.build();
	let failed = OrderBuilder::new()
		.with_id("terminal-failed-order")
		.with_status(OrderStatus::Failed(
			TransactionType::Fill,
			"intentional terminal failure".to_string(),
		))
		.build();

	state_machine.store_order(&active).await?;
	state_machine.store_order(&finalized).await?;
	state_machine.store_order(&failed).await?;

	let stored_orders = storage
		.retrieve_all::<solver_types::Order>(StorageKey::Orders.as_str())
		.await?;
	assert_eq!(
		stored_orders.len(),
		3,
		"test setup should persist active and terminal orders"
	);

	let recovery = recovery_service(storage);
	let (report, _orphaned_intents) = recovery.recover_state().await?;

	assert_eq!(
		report.total_orders, 1,
		"recovery should load only non-terminal orders from storage indexes"
	);
	assert_eq!(report.reconciled_orders, 1);

	Ok(())
}
