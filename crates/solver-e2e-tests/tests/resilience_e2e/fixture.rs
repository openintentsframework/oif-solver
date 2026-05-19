//! Phase A-specific recovery fixture helpers.
//!
//! This mirrors `chain_aware_recovery_e2e/fixture.rs`, but exposes the storage,
//! event bus, and attempt ledger handles needed by resilience scenarios. It
//! stays in the e2e test crate so Phase A does not add production accessors.

use std::{collections::HashMap, sync::Arc};

use alloy_network::TransactionBuilder;
use alloy_primitives::{Address as AlloyAddress, Bytes, B256};
use alloy_provider::{DynProvider, Provider};
use alloy_rpc_types::{BlockNumberOrTag, TransactionInput, TransactionRequest};
use alloy_sol_types::SolCall;
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

use solver_e2e_tests::{
	Harness, IInputSettlerEscrow, SolveParams, StandardOrder, DEST_CHAIN_ID, ORIGIN_CHAIN_ID,
};

#[derive(Default, Clone)]
pub struct OrderStageHashes {
	pub prepare: Option<TransactionHash>,
	pub fill: Option<TransactionHash>,
	pub post_fill: Option<TransactionHash>,
	pub pre_claim: Option<TransactionHash>,
	pub claim: Option<TransactionHash>,
}

pub struct ResilienceRecoveryFixture {
	pub service: RecoveryService,
	pub state_machine: Arc<OrderStateMachine>,
	pub attempt_store: Arc<TransactionAttemptStore>,
	pub event_bus: EventBus,
	pub _tempdir: tempfile::TempDir,
}

pub async fn build_resilience_recovery_service(h: &Harness) -> Result<ResilienceRecoveryFixture> {
	let tempdir = tempfile::TempDir::new().context("create storage tempdir")?;
	let backend = FileStorage::new(tempdir.path().to_path_buf(), TtlConfig::default());
	let storage = Arc::new(StorageService::new(Box::new(backend)));
	let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
	let attempt_store = Arc::new(TransactionAttemptStore::new(storage.clone()));

	let mut networks: NetworksConfig = HashMap::new();
	networks.insert(
		ORIGIN_CHAIN_ID,
		network_config(h.origin.input_settler, h.origin.output_settler),
	);
	networks.insert(
		DEST_CHAIN_ID,
		network_config(h.destination.input_settler, h.destination.output_settler),
	);

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
		storage.clone(),
		state_machine.clone(),
		delivery,
		settlement,
		event_bus.clone(),
		attempt_store.clone(),
		Arc::new(networks),
	);

	Ok(ResilienceRecoveryFixture {
		service,
		state_machine,
		attempt_store,
		event_bus,
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

pub async fn persist_order_for_recovery(
	fixture: &ResilienceRecoveryFixture,
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
		.with_execution_params(Some(solver_types::ExecutionParams {
			gas_price: alloy_primitives::U256::from(1_000_000_000u64),
			priority_fee: Some(alloy_primitives::U256::from(1_000_000u64)),
		}))
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

pub async fn seed_planned_attempt(
	fixture: &ResilienceRecoveryFixture,
	order_id: &str,
	tx_type: solver_types::TransactionType,
) -> Result<solver_types::TransactionAttempt> {
	let tx = solver_types::Transaction {
		to: None,
		data: Vec::new(),
		value: alloy_primitives::U256::ZERO,
		chain_id: DEST_CHAIN_ID,
		nonce: None,
		gas_limit: None,
		gas_price: None,
		max_fee_per_gas: None,
		max_priority_fee_per_gas: None,
	};
	Ok(fixture
		.attempt_store
		.create_planned_attempt(order_id, Some(Address(vec![0u8; 20])), tx_type, tx)
		.await?)
}

pub async fn seed_broadcast_attempt(
	fixture: &ResilienceRecoveryFixture,
	order_id: &str,
	tx_type: solver_types::TransactionType,
	tx_hash: TransactionHash,
) -> Result<solver_types::TransactionAttempt> {
	let attempt = seed_planned_attempt(fixture, order_id, tx_type).await?;
	Ok(fixture
		.attempt_store
		.update_attempt_status(
			&attempt.id,
			solver_types::TransactionAttemptStatus::Broadcast,
			None,
			|attempt| {
				attempt.tx_hash = Some(tx_hash);
			},
		)
		.await?)
}

pub struct RevertedClaimTx {
	pub tx_hash: TransactionHash,
	pub tx: solver_types::Transaction,
	pub signer: Address,
}

pub async fn direct_reverted_claim_after_finalised(
	h: &Harness,
	order: StandardOrder,
	fill_timestamp: u32,
) -> Result<RevertedClaimTx> {
	let solver_word = h.solver_address().into_word();
	let solve_params = vec![SolveParams {
		timestamp: fill_timestamp,
		solver: solver_word,
	}];
	let call = IInputSettlerEscrow::finaliseCall {
		order: order.clone(),
		solveParams: solve_params.clone(),
		destination: solver_word,
		call: Bytes::new(),
	};
	let request = TransactionRequest::default()
		.to(h.origin.input_settler)
		.with_chain_id(ORIGIN_CHAIN_ID)
		.with_gas_limit(2_000_000)
		.input(TransactionInput::new(call.abi_encode().into()));
	let tx: solver_types::Transaction = request.clone().into();

	let pending = h
		.origin_provider
		.send_transaction(request)
		.await
		.context("send reverted finalise transaction")?;
	let receipt = pending
		.get_receipt()
		.await
		.context("reverted finalise receipt")?;
	if receipt.status() {
		return Err(anyhow!(
			"second finalise unexpectedly succeeded (tx {:?})",
			receipt.transaction_hash
		));
	}

	Ok(RevertedClaimTx {
		tx_hash: TransactionHash(receipt.transaction_hash.0.to_vec()),
		tx,
		signer: Address(h.solver_address().as_slice().to_vec()),
	})
}

pub async fn seed_reverted_claim_attempt(
	fixture: &ResilienceRecoveryFixture,
	order_id: &str,
	reverted: RevertedClaimTx,
) -> Result<solver_types::TransactionAttempt> {
	let attempt = fixture
		.attempt_store
		.create_planned_attempt(
			order_id,
			Some(reverted.signer),
			solver_types::TransactionType::Claim,
			reverted.tx,
		)
		.await?;
	Ok(fixture
		.attempt_store
		.update_attempt_status(
			&attempt.id,
			solver_types::TransactionAttemptStatus::Reverted,
			Some("AlreadyClaimed".to_string()),
			|attempt| {
				attempt.tx_hash = Some(reverted.tx_hash);
			},
		)
		.await?)
}

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

	async fn get_revert_data(
		&self,
		_chain_id: u64,
		tx: solver_types::Transaction,
		from: Option<Address>,
		block: u64,
	) -> std::result::Result<Option<Vec<u8>>, DeliveryError> {
		let mut request: TransactionRequest = tx.into();
		if let Some(addr) = from {
			if addr.0.len() == 20 {
				request = request.from(AlloyAddress::from_slice(&addr.0));
			}
		}
		let block_id = BlockNumberOrTag::Number(block).into();
		match self.provider.call(request).block(block_id).await {
			Ok(_) => Ok(None),
			Err(err) => Ok(err
				.as_error_resp()
				.and_then(|payload| payload.as_revert_data())
				.map(|bytes| bytes.to_vec())),
		}
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
