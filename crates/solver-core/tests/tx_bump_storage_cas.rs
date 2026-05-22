use std::sync::{
	atomic::{AtomicBool, Ordering},
	Arc, Barrier,
};
use std::time::Duration;

use solver_core::state::order::OrderStateMachine;
use solver_storage::{
	implementations::{
		file::{FileStorage, TtlConfig as FileTtlConfig},
		memory::MemoryStorage,
		redis::{RedisStorage, TtlConfig as RedisTtlConfig},
	},
	StorageService,
};
use solver_types::{
	utils::tests::builders::OrderBuilder, Order, OrderStatus, StorageKey, TransactionHash,
	TransactionType,
};

fn redis_url_or_skip() -> Option<String> {
	match std::env::var("REDIS_URL") {
		Ok(url) => Some(url),
		Err(_) if std::env::var("CI").as_deref() == Ok("true") => {
			panic!("REDIS_URL required in CI for tx_bump_storage_cas");
		},
		Err(_) => None,
	}
}

fn sample_order(order_id: &str) -> Order {
	OrderBuilder::new()
		.with_id(order_id)
		.with_status(OrderStatus::Executing)
		.build()
}

async fn run_cas_race(storage: Arc<StorageService>) {
	let state = Arc::new(OrderStateMachine::new(storage.clone()));
	let order_id = "tx-bump-cas-order";
	let fill_hash = TransactionHash(vec![0x44; 32]);
	let quote_id = "quote-preserved-after-race".to_string();

	state.store_order(&sample_order(order_id)).await.unwrap();

	let barrier = Arc::new(Barrier::new(2));
	let fill_first_invocation = Arc::new(AtomicBool::new(true));
	let quote_first_invocation = Arc::new(AtomicBool::new(true));

	let fill_state = state.clone();
	let fill_barrier = barrier.clone();
	let fill_once = fill_first_invocation.clone();
	let fill_hash_for_task = fill_hash.clone();
	let fill_task = tokio::spawn(async move {
		fill_state
			.update_order_with(order_id, move |order| {
				if fill_once.swap(false, Ordering::SeqCst) {
					fill_barrier.wait();
					std::thread::sleep(Duration::from_millis(50));
				}
				order.status = OrderStatus::Executed;
				order.fill_tx_hash = Some(fill_hash_for_task.clone());
			})
			.await
	});

	let quote_state = state.clone();
	let quote_barrier = barrier.clone();
	let quote_once = quote_first_invocation.clone();
	let quote_id_for_task = quote_id.clone();
	let quote_task = tokio::spawn(async move {
		quote_state
			.update_order_with(order_id, move |order| {
				if quote_once.swap(false, Ordering::SeqCst) {
					quote_barrier.wait();
				}
				order.quote_id = Some(quote_id_for_task.clone());
			})
			.await
	});

	fill_task.await.unwrap().unwrap();
	quote_task.await.unwrap().unwrap();

	let final_order: Order = storage
		.retrieve(StorageKey::Orders.as_str(), order_id)
		.await
		.unwrap();

	assert_eq!(final_order.status, OrderStatus::Executed);
	assert_eq!(final_order.fill_tx_hash, Some(fill_hash));
	assert_eq!(final_order.quote_id, Some(quote_id));

	state
		.transition_order_status(order_id, OrderStatus::Settled)
		.await
		.unwrap();
	state
		.transition_order_status(order_id, OrderStatus::Finalized)
		.await
		.unwrap();
	let invalid = state
		.transition_order_status(
			order_id,
			OrderStatus::Failed(TransactionType::Fill, "terminal invariant".to_string()),
		)
		.await;
	assert!(
		invalid.is_err(),
		"terminal/backward transition must stay rejected"
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn memory_storage_cas_preserves_canonical_hash_under_concurrent_writes() {
	let storage = Arc::new(StorageService::new(Box::new(MemoryStorage::new())));
	run_cas_race(storage).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn file_storage_cas_preserves_canonical_hash_under_concurrent_writes() {
	let temp = tempfile::tempdir().unwrap();
	let storage = Arc::new(StorageService::new(Box::new(FileStorage::new(
		temp.path().to_path_buf(),
		FileTtlConfig::default(),
	))));
	run_cas_race(storage).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redis_storage_cas_preserves_canonical_hash_under_concurrent_writes() {
	let Some(redis_url) = redis_url_or_skip() else {
		eprintln!("skipping Redis CAS test because REDIS_URL is not set");
		return;
	};

	let storage = Arc::new(StorageService::new(Box::new(
		RedisStorage::new(
			redis_url,
			5000,
			format!("tx-bump-cas-{}", uuid::Uuid::new_v4()),
			RedisTtlConfig::default(),
			false,
		)
		.unwrap(),
	)));
	run_cas_race(storage).await;
}
