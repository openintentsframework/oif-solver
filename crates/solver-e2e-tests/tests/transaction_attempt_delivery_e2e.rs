use std::{collections::HashMap, sync::Arc};

use alloy_primitives::{Bytes, U256};
use async_trait::async_trait;
use solver_core::state::transaction_attempt::TransactionAttemptStore;
use solver_delivery::{
	DeliveryError, DeliveryInterface, DeliveryService, FeeParams, PlannedAttemptInit,
	TransactionAttemptRecorder, TransactionTracking,
};
use solver_storage::{
	implementations::file::{FileStorage, TtlConfig},
	StorageService,
};
use solver_types::validation::{ConfigSchema, ValidationError};
use solver_types::{
	Address, Log, LogFilter, Transaction, TransactionAttemptStatus, TransactionHash,
	TransactionReceipt, TransactionType,
};
use tempfile::TempDir;

struct EmptyConfigSchema;

impl ConfigSchema for EmptyConfigSchema {
	fn validate(&self, _config: &serde_json::Value) -> Result<(), ValidationError> {
		Ok(())
	}
}

#[derive(Clone)]
struct RecordingDelivery {
	tx_hash: TransactionHash,
	signer: Address,
}

#[async_trait]
impl DeliveryInterface for RecordingDelivery {
	fn config_schema(&self) -> Box<dyn ConfigSchema> {
		Box::new(EmptyConfigSchema)
	}

	async fn submit(
		&self,
		tx: Transaction,
		tracking: Option<solver_delivery::TransactionTrackingWithConfig>,
	) -> Result<TransactionHash, DeliveryError> {
		let tracking = tracking.expect("test must pass tracking");
		let attempt = tracking
			.tracking
			.attempt_recorder
			.record_planned_attempt(PlannedAttemptInit {
				scope: match tracking.tracking.tx_type {
					TransactionType::Approval
					| TransactionType::Withdrawal
					| TransactionType::Bridge
					| TransactionType::Pusher => {
						solver_types::TransactionAttemptScope::system(tracking.tracking.id.clone())
					},
					_ => solver_types::TransactionAttemptScope::order(tracking.tracking.id.clone()),
				},
				signer: Some(self.signer.clone()),
				tx_type: tracking.tracking.tx_type,
				tx,
				attempt_id_override: None,
				replacement_of: None,
			})
			.await
			.map_err(|e| DeliveryError::Network(e.to_string()))?;

		tracking
			.tracking
			.attempt_recorder
			.record_attempt_update(
				&attempt.id,
				TransactionAttemptStatus::Broadcast,
				Some(self.tx_hash.clone()),
				None,
				None,
			)
			.await
			.map_err(|e| DeliveryError::Network(e.to_string()))?;

		Ok(self.tx_hash.clone())
	}

	async fn get_receipt(
		&self,
		_hash: &TransactionHash,
		_chain_id: u64,
	) -> Result<TransactionReceipt, DeliveryError> {
		unimplemented!()
	}

	async fn get_fee_params(&self, chain_id: u64) -> Result<FeeParams, DeliveryError> {
		Ok(FeeParams::legacy(chain_id, 1))
	}

	async fn get_balance(
		&self,
		_address: &str,
		_token: Option<&str>,
		_chain_id: u64,
	) -> Result<String, DeliveryError> {
		unimplemented!()
	}

	async fn get_allowance(
		&self,
		_owner: &str,
		_spender: &str,
		_token_address: &str,
		_chain_id: u64,
	) -> Result<String, DeliveryError> {
		unimplemented!()
	}

	async fn get_nonce(&self, _address: &str, _chain_id: u64) -> Result<u64, DeliveryError> {
		unimplemented!()
	}

	async fn get_block_number(&self, _chain_id: u64) -> Result<u64, DeliveryError> {
		unimplemented!()
	}

	async fn estimate_gas(&self, _tx: Transaction) -> Result<u64, DeliveryError> {
		unimplemented!()
	}

	async fn estimate_gas_with_overrides(
		&self,
		_tx: Transaction,
		_state_override: alloy_rpc_types::state::StateOverride,
	) -> Result<u64, DeliveryError> {
		unimplemented!()
	}

	async fn eth_call(&self, _tx: Transaction) -> Result<Bytes, DeliveryError> {
		unimplemented!()
	}

	async fn tx_exists(
		&self,
		_hash: &TransactionHash,
		_chain_id: u64,
	) -> Result<bool, DeliveryError> {
		unimplemented!()
	}

	async fn get_logs(
		&self,
		_chain_id: u64,
		_filter: LogFilter,
	) -> Result<Vec<Log>, DeliveryError> {
		unimplemented!()
	}
}

fn make_storage() -> (Arc<StorageService>, TempDir) {
	let temp_dir = TempDir::new().unwrap();
	let file_storage = FileStorage::new(temp_dir.path().to_path_buf(), TtlConfig::default());
	(
		Arc::new(StorageService::new(Box::new(file_storage))),
		temp_dir,
	)
}

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

#[ignore]
#[tokio::test]
async fn delivery_service_persists_attempt_ledger_through_tracking() {
	let (storage, _temp_dir) = make_storage();
	let attempt_store = Arc::new(TransactionAttemptStore::new(storage));
	let tx_hash = TransactionHash(vec![3; 32]);
	let signer = Address(vec![9; 20]);

	let mut implementations: HashMap<u64, Arc<dyn DeliveryInterface>> = HashMap::new();
	implementations.insert(
		10,
		Arc::new(RecordingDelivery {
			tx_hash: tx_hash.clone(),
			signer: signer.clone(),
		}),
	);

	let service = DeliveryService::new(implementations, 1, 60, 60);

	let tracking = TransactionTracking {
		id: "order-delivery-e2e".to_string(),
		tx_type: TransactionType::Fill,
		attempt_recorder: attempt_store.clone() as Arc<dyn TransactionAttemptRecorder>,
		callback: Box::new(|_| {}),
		attempt_id: None,
		replacement_of: None,
	};

	let returned_hash = service.deliver(sample_tx(), Some(tracking)).await.unwrap();
	assert_eq!(returned_hash, tx_hash);

	let attempts = attempt_store
		.attempts_for_order("order-delivery-e2e")
		.await
		.unwrap();
	assert_eq!(attempts.len(), 1);

	let attempt = &attempts[0];
	assert_eq!(attempt.order_id(), Some("order-delivery-e2e"));
	assert_eq!(attempt.signer, Some(signer));
	assert_eq!(attempt.tx_type, TransactionType::Fill);
	assert_eq!(attempt.chain_id, 10);
	assert_eq!(attempt.nonce, Some(7));
	assert_eq!(attempt.status, TransactionAttemptStatus::Broadcast);
	assert_eq!(attempt.tx_hash, Some(tx_hash.clone()));
	assert_eq!(attempt.receipt, None);

	let by_hash = attempt_store
		.attempt_by_hash(&tx_hash)
		.await
		.unwrap()
		.unwrap();
	assert_eq!(by_hash.id, attempt.id);
}
