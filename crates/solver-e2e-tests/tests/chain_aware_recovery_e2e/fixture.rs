//! Recovery-service fixture for chain-aware recovery e2e tests.
//!
//! Lives here (not in `solver-e2e-tests/src/lib.rs`) because `solver-core`,
//! `solver-delivery`, `solver-settlement`, and `solver-storage` are
//! dev-dependencies of this crate. A library can't return their types; an
//! integration test can.

use std::{collections::HashMap, sync::Arc};

use alloy_primitives::{Address as AlloyAddress, B256};
use alloy_provider::{DynProvider, Provider};
use anyhow::{anyhow, Context as _, Result};
use async_trait::async_trait;
use solver_core::{
	recovery::RecoveryService,
	state::{transaction_attempt::TransactionAttemptStore, OrderStateMachine},
	EventBus,
};
use solver_delivery::{DeliveryError, DeliveryInterface, DeliveryService, FeeParams};
use solver_settlement::{MockSettlementInterface, SettlementInterface, SettlementService};
use solver_storage::{
	implementations::file::{FileStorage, TtlConfig},
	StorageService,
};
use solver_types::{
	networks::RpcEndpoint, utils::tests::builders::OrderBuilder, validation::ValidationError,
	with_0x_prefix, Address, ChainSettlerInfo, ConfigSchema, NetworkConfig, NetworkType,
	NetworksConfig, Order, OrderStatus, TransactionHash, TransactionReceipt,
};

use solver_e2e_tests::{Harness, DEST_CHAIN_ID, ORIGIN_CHAIN_ID};

#[derive(Default, Clone)]
pub struct OrderStageHashes {
	pub prepare: Option<TransactionHash>,
	pub fill: Option<TransactionHash>,
	pub post_fill: Option<TransactionHash>,
	pub pre_claim: Option<TransactionHash>,
	pub claim: Option<TransactionHash>,
}

pub struct RecoveryServiceFixture {
	pub service: RecoveryService,
	pub state_machine: Arc<OrderStateMachine>,
	// Keep alive for the test's lifetime — TempDir removes the dir on Drop.
	pub _tempdir: tempfile::TempDir,
}

pub async fn build_recovery_service(h: &Harness) -> Result<RecoveryServiceFixture> {
	// Storage stack.
	let tempdir = tempfile::TempDir::new().context("create storage tempdir")?;
	let backend = FileStorage::new(tempdir.path().to_path_buf(), TtlConfig::default());
	let storage = Arc::new(StorageService::new(Box::new(backend)));
	let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
	let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));

	// NetworksConfig with origin + destination entries. Only settler addresses
	// matter for the chain probe — other fields can be defaults.
	let mut networks: NetworksConfig = HashMap::new();
	networks.insert(
		ORIGIN_CHAIN_ID,
		network_config(h.origin.input_settler, h.origin.output_settler),
	);
	networks.insert(
		DEST_CHAIN_ID,
		network_config(h.destination.input_settler, h.destination.output_settler),
	);

	// Delivery: a test-only impl that wraps the harness's alloy providers and
	// exposes only the three methods recovery's chain probe needs.
	let mut delivery_impls: HashMap<u64, Arc<dyn DeliveryInterface>> = HashMap::new();
	delivery_impls.insert(
		ORIGIN_CHAIN_ID,
		Arc::new(RpcOnlyDelivery::new(h.origin_provider.clone())),
	);
	delivery_impls.insert(
		DEST_CHAIN_ID,
		Arc::new(RpcOnlyDelivery::new(h.destination_provider.clone())),
	);
	let delivery = Arc::new(DeliveryService::new(delivery_impls, 1, 20, 60));

	// Settlement: register a mock under "eip7683". Production orders persist
	// settlement_name = Some("eip7683"); reconciliation dispatches by that key.
	let mut mock = MockSettlementInterface::new();
	mock.expect_recover_post_fill_state()
		.returning(|_| Box::pin(async move { Ok(false) }));
	let mut settlements: HashMap<String, Box<dyn SettlementInterface>> = HashMap::new();
	settlements.insert("eip7683".to_string(), Box::new(mock));
	let settlement = Arc::new(SettlementService::new(
		settlements,
		"eip7683".to_string(),
		20,
	));

	let event_bus = EventBus::new(100);

	let service = RecoveryService::new(
		storage,
		state_machine.clone(),
		delivery,
		settlement,
		event_bus,
		attempt_store,
		Arc::new(networks),
	);

	Ok(RecoveryServiceFixture {
		service,
		state_machine,
		_tempdir: tempdir,
	})
}

fn network_config(input_settler: AlloyAddress, output_settler: AlloyAddress) -> NetworkConfig {
	NetworkConfig {
		name: None,
		network_type: NetworkType::default(),
		rpc_urls: Vec::<RpcEndpoint>::new(),
		input_settler_address: Address(input_settler.as_slice().to_vec()),
		output_settler_address: Address(output_settler.as_slice().to_vec()),
		tokens: Vec::new(),
		input_settler_compact_address: None,
		the_compact_address: None,
		allocator_address: None,
	}
}

/// Persist a `solver_types::Order` so `RecoveryService::recover_state()`
/// picks it up. Caller controls which tx-hash fields are `None` (simulating
/// crash-window data loss) and the order's initial status.
pub async fn persist_order_for_recovery(
	fixture: &RecoveryServiceFixture,
	order_id: B256,
	initial_status: OrderStatus,
	stage_hashes: OrderStageHashes,
	fill_proof: Option<solver_types::FillProof>,
) -> Result<Order> {
	let id_string = with_0x_prefix(&hex::encode(order_id.0));

	let order = OrderBuilder::new()
		.with_id(id_string)
		.with_standard("eip7683")
		.with_status(initial_status)
		.with_input_chains(vec![ChainSettlerInfo {
			chain_id: ORIGIN_CHAIN_ID,
			settler_address: Address(vec![0; 20]),
		}])
		.with_output_chains(vec![ChainSettlerInfo {
			chain_id: DEST_CHAIN_ID,
			settler_address: Address(vec![0; 20]),
		}])
		.with_prepare_tx_hash(stage_hashes.prepare)
		.with_fill_tx_hash(stage_hashes.fill)
		.with_post_fill_tx_hash(stage_hashes.post_fill)
		.with_pre_claim_tx_hash(stage_hashes.pre_claim)
		.with_claim_tx_hash(stage_hashes.claim)
		.with_fill_proof(fill_proof)
		.with_settlement_name(Some("eip7683"))
		.build();

	fixture
		.state_machine
		.store_order(&order)
		.await
		.map_err(|e| anyhow!("store_order: {e}"))?;
	Ok(order)
}

// =============================================================================
// Test-only DeliveryInterface
//
// The chain probe in PR 04 calls `get_block_number`, `get_receipt`, and
// `get_logs`. Plus `get_status` (which is just `get_receipt(...).success`).
// Everything else panics — these tests never exercise other paths.
// =============================================================================

struct RpcOnlyDelivery {
	provider: DynProvider,
}

impl RpcOnlyDelivery {
	fn new(provider: DynProvider) -> Self {
		Self { provider }
	}
}

struct EmptySchema;
impl ConfigSchema for EmptySchema {
	fn validate(&self, _config: &serde_json::Value) -> std::result::Result<(), ValidationError> {
		Ok(())
	}
}

#[async_trait]
impl DeliveryInterface for RpcOnlyDelivery {
	fn config_schema(&self) -> Box<dyn ConfigSchema> {
		Box::new(EmptySchema)
	}

	async fn submit(
		&self,
		_tx: solver_types::Transaction,
		_tracking: Option<solver_delivery::TransactionTrackingWithConfig>,
	) -> std::result::Result<TransactionHash, DeliveryError> {
		unimplemented!("RpcOnlyDelivery::submit not used by recovery")
	}

	async fn get_receipt(
		&self,
		hash: &TransactionHash,
		chain_id: u64,
	) -> std::result::Result<TransactionReceipt, DeliveryError> {
		let tx_hash = alloy_primitives::FixedBytes::<32>::from_slice(&hash.0);
		match self.provider.get_transaction_receipt(tx_hash).await {
			Ok(Some(receipt)) => Ok(TransactionReceipt::from(&receipt)),
			Ok(None) => Err(DeliveryError::Network(format!(
				"Transaction not found on chain {chain_id}"
			))),
			Err(e) => Err(DeliveryError::Network(format!(
				"Failed to get receipt on chain {chain_id}: {e}"
			))),
		}
	}

	async fn get_fee_params(
		&self,
		_chain_id: u64,
	) -> std::result::Result<FeeParams, DeliveryError> {
		unimplemented!("RpcOnlyDelivery::get_fee_params not used by recovery")
	}

	async fn get_balance(
		&self,
		_address: &str,
		_token: Option<&str>,
		_chain_id: u64,
	) -> std::result::Result<String, DeliveryError> {
		unimplemented!("RpcOnlyDelivery::get_balance not used by recovery")
	}

	async fn get_allowance(
		&self,
		_owner: &str,
		_spender: &str,
		_token_address: &str,
		_chain_id: u64,
	) -> std::result::Result<String, DeliveryError> {
		unimplemented!("RpcOnlyDelivery::get_allowance not used by recovery")
	}

	async fn get_nonce(
		&self,
		_address: &str,
		_chain_id: u64,
	) -> std::result::Result<u64, DeliveryError> {
		unimplemented!("RpcOnlyDelivery::get_nonce not used by recovery")
	}

	async fn get_block_number(&self, _chain_id: u64) -> std::result::Result<u64, DeliveryError> {
		self.provider
			.get_block_number()
			.await
			.map_err(|e| DeliveryError::Network(format!("get_block_number: {e}")))
	}

	async fn estimate_gas(
		&self,
		_tx: solver_types::Transaction,
	) -> std::result::Result<u64, DeliveryError> {
		unimplemented!("RpcOnlyDelivery::estimate_gas not used by recovery")
	}

	async fn estimate_gas_with_overrides(
		&self,
		_tx: solver_types::Transaction,
		_state_override: alloy_rpc_types::state::StateOverride,
	) -> std::result::Result<u64, DeliveryError> {
		unimplemented!("RpcOnlyDelivery::estimate_gas_with_overrides not used by recovery")
	}

	async fn eth_call(
		&self,
		_tx: solver_types::Transaction,
	) -> std::result::Result<alloy_primitives::Bytes, DeliveryError> {
		unimplemented!("RpcOnlyDelivery::eth_call not used by recovery")
	}

	async fn tx_exists(
		&self,
		_hash: &TransactionHash,
		_chain_id: u64,
	) -> std::result::Result<bool, DeliveryError> {
		unimplemented!("RpcOnlyDelivery::tx_exists not used by recovery")
	}

	async fn get_logs(
		&self,
		_chain_id: u64,
		filter: solver_types::LogFilter,
	) -> std::result::Result<Vec<solver_types::Log>, DeliveryError> {
		let mut alloy_filter = alloy_rpc_types::Filter::new()
			.address(AlloyAddress::from_slice(&filter.address.0))
			.from_block(filter.from_block);
		if let Some(to) = filter.to_block {
			alloy_filter = alloy_filter.to_block(to);
		}
		for (i, topic) in filter.topics().iter().enumerate() {
			if let Some(t) = topic {
				let topic_hash = alloy_primitives::FixedBytes::<32>::from(t.0);
				match i {
					0 => alloy_filter = alloy_filter.event_signature(topic_hash),
					1 => alloy_filter = alloy_filter.topic1(topic_hash),
					2 => alloy_filter = alloy_filter.topic2(topic_hash),
					3 => alloy_filter = alloy_filter.topic3(topic_hash),
					_ => {},
				}
			}
		}
		let logs = self
			.provider
			.get_logs(&alloy_filter)
			.await
			.map_err(|e| DeliveryError::Network(format!("get_logs: {e}")))?;
		Ok(logs
			.into_iter()
			.map(|l| solver_types::Log {
				address: Address(l.address().as_slice().to_vec()),
				topics: l.topics().iter().map(|t| solver_types::H256(t.0)).collect(),
				data: l.data().data.to_vec(),
				transaction_hash: l.transaction_hash.map(|h| TransactionHash(h.0.to_vec())),
				block_number: l.block_number,
			})
			.collect())
	}
}
