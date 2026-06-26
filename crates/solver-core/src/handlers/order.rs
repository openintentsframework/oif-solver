//! Order handler for processing order preparation and execution.
//!
//! Manages the generation and submission of prepare transactions (for off-chain orders)
//! and fill transactions, updating order state and publishing appropriate events.

use crate::engine::event_bus::EventBus;
use crate::handlers::forced_withdrawal::ensure_resource_locks_claimable;
use crate::order_preparation::order_requires_preparation;
use crate::state::transaction_attempt::TransactionAttemptStore;
use crate::state::OrderStateMachine;
use alloy_primitives::{hex, B256, U256};
use alloy_sol_types::SolCall;
use solver_config::Config;
use solver_delivery::{
	DeliveryService, RevertClassification, TransactionAttemptRecorder, TransactionMonitoringEvent,
	TransactionTracking,
};
use solver_order::OrderService;
use solver_storage::StorageService;
use solver_types::{
	standards::eip7683::{interfaces::IInputSettlerEscrow, LockType},
	truncate_id,
	utils::conversion::hex_to_alloy_address,
	Address, DeliveryEvent, Eip7683OrderData, ExecutionParams, Order, OrderEvent, OrderStatus,
	SolverEvent, StorageKey, Transaction, TransactionType,
};
use std::{sync::Arc, time::Duration};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::instrument;

const ESCROW_ORDER_STATUS_DEPOSITED: u8 = 1;
const ESCROW_ORDER_STATUS_NONE: u8 = 0;
const DEFAULT_SOURCE_FINALITY_BLOCKS: u64 = 20;
const SOURCE_FINALITY_RETRY_AFTER: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EscrowDepositReadiness {
	Ready,
	Defer(Duration),
}

fn view_tx(to: &Address, chain_id: u64, data: Vec<u8>) -> Transaction {
	Transaction {
		to: Some(to.clone()),
		data,
		value: U256::ZERO,
		chain_id,
		nonce: None,
		gas_limit: None,
		gas_price: None,
		max_fee_per_gas: None,
		max_priority_fee_per_gas: None,
	}
}

fn finality_blocks_from_value(value: &serde_json::Value, chain_id: u64) -> Option<u64> {
	if let Some(depth) = value
		.get("finality_blocks")
		.and_then(|value| value.as_object())
		.and_then(|object| object.get(&chain_id.to_string()))
		.and_then(|value| value.as_u64())
	{
		return Some(depth);
	}

	value
		.get("default_finality_blocks")
		.and_then(|value| value.as_u64())
}

fn source_finality_blocks_for_config(config: &Config, chain_id: u64) -> u64 {
	if let Some(depth) = config
		.settlement
		.implementations
		.get("broadcaster")
		.and_then(|broadcaster| finality_blocks_from_value(broadcaster, chain_id))
	{
		return depth;
	}

	if let Some(depth) = config
		.discovery
		.implementations
		.get("onchain_eip7683")
		.and_then(|onchain| finality_blocks_from_value(onchain, chain_id))
	{
		return depth;
	}

	DEFAULT_SOURCE_FINALITY_BLOCKS
}

/// Errors that can occur during order processing.
///
/// These errors represent failures in service operations,
/// storage operations, or state transitions during order handling.
#[derive(Debug, Error)]
pub enum OrderError {
	#[error("Service error: {0}")]
	Service(String),
	#[error("Storage error: {0}")]
	Storage(String),
	#[error("State error: {0}")]
	State(String),
}

/// Handler for processing order preparation and execution.
///
/// The OrderHandler manages the generation and submission of prepare
/// transactions for off-chain orders and fill transactions for all orders,
/// while updating order state and publishing relevant events.
pub struct OrderHandler {
	order_service: Arc<OrderService>,
	delivery: Arc<DeliveryService>,
	storage: Arc<StorageService>,
	state_machine: Arc<OrderStateMachine>,
	event_bus: EventBus,
	/// Dynamic config, read just-in-time so Admin API hot-reloads
	/// (e.g. toggling `resource_lock_enabled`) take effect on the next fill.
	dynamic_config: Arc<RwLock<Config>>,
}

impl OrderHandler {
	pub fn new(
		order_service: Arc<OrderService>,
		delivery: Arc<DeliveryService>,
		storage: Arc<StorageService>,
		state_machine: Arc<OrderStateMachine>,
		event_bus: EventBus,
		dynamic_config: Arc<RwLock<Config>>,
	) -> Self {
		Self {
			order_service,
			delivery,
			storage,
			state_machine,
			event_bus,
			dynamic_config,
		}
	}

	fn transaction_attempt_recorder(&self) -> Arc<dyn TransactionAttemptRecorder> {
		Arc::new(TransactionAttemptStore::new(self.storage.clone()))
	}

	/// Handles order preparation for off-chain orders.
	#[instrument(skip_all, fields(order_id = %truncate_id(&order.id)))]
	pub async fn handle_preparation(
		&self,
		source: String,
		order: Order,
		params: ExecutionParams,
	) -> Result<(), OrderError> {
		// Generate prepare transaction
		if let Some(prepare_tx) = self
			.order_service
			.generate_prepare_transaction(&source, &order, &params)
			.await
			.map_err(|e| OrderError::Service(e.to_string()))?
		{
			// Submit prepare transaction with monitoring
			let event_bus = self.event_bus.clone();
			let callback = Box::new(move |event: TransactionMonitoringEvent| match event {
				TransactionMonitoringEvent::Confirmed {
					id,
					tx_hash,
					tx_type,
					receipt,
				} => {
					event_bus
						.publish(SolverEvent::Delivery(DeliveryEvent::TransactionConfirmed {
							order_id: id,
							tx_hash,
							tx_type,
							receipt,
						}))
						.ok();
				},
				TransactionMonitoringEvent::Failed {
					id,
					tx_hash,
					tx_type,
					error,
					classification,
				} => match classification {
					RevertClassification::StageComplete { reason } => {
						tracing::info!(
							order_id = %id,
							?tx_type,
							?reason,
							?tx_hash,
							"Revert classified as stage-complete; deferring to recovery for chain confirmation"
						);
					},
					RevertClassification::Terminal { .. } | RevertClassification::Unknown => {
						event_bus
							.publish(SolverEvent::Delivery(DeliveryEvent::TransactionFailed {
								order_id: id,
								tx_hash,
								tx_type,
								error,
							}))
							.ok();
					},
				},
				TransactionMonitoringEvent::Indeterminate {
					id: order_id,
					tx_hash,
					tx_type,
					reason,
				} => {
					// Live tx watcher could not determine on-chain state within
					// the confirmation deadline. Order is left in its current
					// status; startup recovery will reconcile via direct chain
					// query. Do NOT publish a `TransactionFailed` event — that
					// would terminally fail the order.
					tracing::warn!(
						%order_id,
						?tx_hash,
						?tx_type,
						%reason,
						"Live tx monitor indeterminate; order left in current status"
					);
				},
				TransactionMonitoringEvent::AttemptLedgerConflict {
					id,
					attempt_id,
					tx_type,
					tx_hash,
					attempted_status,
					error,
					context,
				} => {
					event_bus
						.publish(SolverEvent::Delivery(
							DeliveryEvent::TransactionAttemptLedgerConflict {
								order_id: id,
								attempt_id,
								tx_type,
								tx_hash,
								attempted_status,
								error,
								context: context.to_string(),
							},
						))
						.ok();
				},
			});

			let tracking = TransactionTracking {
				id: order.id.clone(),
				tx_type: TransactionType::Prepare,
				attempt_recorder: self.transaction_attempt_recorder(),
				callback,
				attempt_id: None,
				replacement_of: None,
			};

			let prepare_tx_hash = self
				.delivery
				.deliver(prepare_tx.clone(), Some(tracking))
				.await
				.map_err(|e| OrderError::Service(e.to_string()))?;

			self.event_bus
				.publish(SolverEvent::Delivery(DeliveryEvent::TransactionPending {
					order_id: order.id.clone(),
					tx_hash: prepare_tx_hash.clone(),
					tx_type: TransactionType::Prepare,
					tx_chain_id: prepare_tx.chain_id,
				}))
				.ok();

			// Store tx_hash -> order_id mapping
			self.storage
				.store(
					StorageKey::OrderByTxHash.as_str(),
					&hex::encode(&prepare_tx_hash.0),
					&order.id,
					None,
				)
				.await
				.map_err(|e| OrderError::Storage(e.to_string()))?;

			// `execution_params` are already persisted on the order by the time
			// this event fires; only the prepare tx hash and status need updating here.
			self.state_machine
				.update_order_with(&order.id, |o| {
					o.status = OrderStatus::Pending;
					o.prepare_tx_hash = Some(prepare_tx_hash.clone());
				})
				.await
				.map_err(|e| OrderError::State(e.to_string()))?;
		} else {
			// No preparation needed (on-chain intent), go directly to Executing.
			// `execution_params` are already persisted on the order at this point.
			self.state_machine
				.update_order_with(&order.id, |o| {
					o.status = OrderStatus::Executing;
				})
				.await
				.map_err(|e| OrderError::State(e.to_string()))?;

			self.event_bus
				.publish(SolverEvent::Order(OrderEvent::Executing {
					order: order.clone(),
					params,
				}))
				.ok();
		}

		Ok(())
	}

	/// (C-03) Reject ResourceLock fills whose input locks have a pending or enabled
	/// forced withdrawal on TheCompact, checked just before the fill is released.
	///
	/// No-op for non-ResourceLock orders. When ResourceLock support is disabled this
	/// path should not be reached (intake gates it), but we still treat a ResourceLock
	/// order arriving here as in-scope and fail closed if its compact address is
	/// missing or the on-chain query fails.
	async fn check_forced_withdrawal_before_fill(&self, order: &Order) -> Result<(), OrderError> {
		let order_data: Eip7683OrderData = match serde_json::from_value(order.data.clone()) {
			Ok(data) => data,
			Err(e) if order.standard == "eip7683" => {
				return Err(OrderError::Service(format!(
					"Failed to parse EIP-7683 order data before ResourceLock guard: {e}"
				)));
			},
			// Non-7683 orders carry no resource lock; nothing to guard.
			Err(_) => return Ok(()),
		};

		if !matches!(order_data.lock_type, Some(LockType::ResourceLock)) {
			return Ok(());
		}

		let origin_chain_id = u64::try_from(order_data.origin_chain_id)
			.map_err(|_| OrderError::Service("Invalid origin chain ID".to_string()))?;

		// Resolve TheCompact on the origin chain from current (hot-reloadable) config.
		let the_compact_address = {
			let config = self.dynamic_config.read().await;
			config
				.networks
				.get(&origin_chain_id)
				.and_then(|n| n.the_compact_address.clone())
				.ok_or_else(|| {
					OrderError::Service(format!(
						"ResourceLock fill aborted: TheCompact address not configured for origin chain {origin_chain_id}"
					))
				})?
		};

		let sponsor = hex_to_alloy_address(&order_data.user)
			.map_err(|e| OrderError::Service(format!("Invalid sponsor address: {e}")))?;

		ensure_resource_locks_claimable(
			&self.delivery,
			&the_compact_address,
			origin_chain_id,
			sponsor,
			&order_data.inputs,
		)
		.await
		.map_err(|e| OrderError::Service(e.to_string()))
	}

	/// (M-01) For escrow-origin orders, confirm the source-chain deposit still
	/// exists at the configured finality depth immediately before releasing the
	/// destination fill.
	async fn check_escrow_deposit_before_fill(
		&self,
		order: &Order,
	) -> Result<EscrowDepositReadiness, OrderError> {
		let order_data: Eip7683OrderData = match serde_json::from_value(order.data.clone()) {
			Ok(data) => data,
			Err(e) if order.standard == "eip7683" => {
				return Err(OrderError::Service(format!(
					"Failed to parse EIP-7683 order data before source deposit guard: {e}"
				)));
			},
			Err(_) => return Ok(EscrowDepositReadiness::Ready),
		};

		let Some(lock_type) = order_data.lock_type else {
			return Ok(EscrowDepositReadiness::Ready);
		};
		if !lock_type.is_escrow() {
			return Ok(EscrowDepositReadiness::Ready);
		}

		let origin_chain_id = u64::try_from(order_data.origin_chain_id)
			.map_err(|_| OrderError::Service("Invalid origin chain ID".to_string()))?;
		let (input_settler_address, finality_blocks) = {
			let config = self.dynamic_config.read().await;
			let input_settler_address = config
				.networks
				.get(&origin_chain_id)
				.map(|network| network.input_settler_address.clone())
				.ok_or_else(|| {
					OrderError::Service(format!(
						"Escrow fill aborted: input settler not configured for origin chain {origin_chain_id}"
					))
				})?;
			let finality_blocks = source_finality_blocks_for_config(&config, origin_chain_id);
			(input_settler_address, finality_blocks)
		};

		let latest_block = self
			.delivery
			.get_block_number(origin_chain_id)
			.await
			.map_err(|e| {
				OrderError::Service(format!(
					"Escrow fill aborted: failed to get origin chain {origin_chain_id} head: {e}"
				))
			})?;
		let Some(confirmed_block) = latest_block.checked_sub(finality_blocks) else {
			tracing::info!(
				order_id = %order.id,
				origin_chain_id,
				latest_block,
				finality_blocks,
				"Escrow fill deferred: origin chain {origin_chain_id} has not reached configured finality depth {finality_blocks}"
			);
			return Ok(EscrowDepositReadiness::Defer(SOURCE_FINALITY_RETRY_AFTER));
		};

		let order_id = B256::from(order_data.order_id);
		let call = IInputSettlerEscrow::orderStatusCall { orderId: order_id };
		let tx = view_tx(&input_settler_address, origin_chain_id, call.abi_encode());
		let result = self
			.delivery
			.contract_call_at_block(origin_chain_id, tx.clone(), confirmed_block)
			.await
			.map_err(|e| {
				OrderError::Service(format!(
					"Escrow fill aborted: failed to query source orderStatus at block {confirmed_block}: {e}"
				))
			})?;
		if result.is_empty() {
			let latest_result = self
				.delivery
				.contract_call(origin_chain_id, tx)
				.await
				.map_err(|e| {
					OrderError::Service(format!(
						"Escrow fill aborted: failed to query latest source orderStatus after empty confirmed read at block {confirmed_block}: {e}"
					))
				})?;
			if latest_result.is_empty() {
				return Err(OrderError::Service(format!(
					"Escrow fill aborted: source orderStatus returned empty data at latest; check input settler address and orderStatus ABI for origin chain {origin_chain_id}"
				)));
			}
			let latest_status = IInputSettlerEscrow::orderStatusCall::abi_decode_returns_validate(
				&latest_result,
			)
			.map_err(|e| {
				OrderError::Service(format!(
					"Escrow fill aborted: failed to decode latest source orderStatus after empty confirmed read at block {confirmed_block}: {e}"
				))
			})?;
			if latest_status != ESCROW_ORDER_STATUS_DEPOSITED
				&& latest_status != ESCROW_ORDER_STATUS_NONE
			{
				let expected = ESCROW_ORDER_STATUS_DEPOSITED;
				return Err(OrderError::Service(format!(
					"Escrow fill aborted: latest source orderStatus is {latest_status}, expected Deposited ({expected})"
				)));
			}

			tracing::info!(
				order_id = %order.id,
				origin_chain_id,
				confirmed_block,
				"Escrow fill deferred: source orderStatus read returned empty data"
			);
			return Ok(EscrowDepositReadiness::Defer(SOURCE_FINALITY_RETRY_AFTER));
		}

		let status = IInputSettlerEscrow::orderStatusCall::abi_decode_returns_validate(&result)
			.map_err(|e| {
				OrderError::Service(format!(
					"Escrow fill aborted: failed to decode source orderStatus: {e}"
				))
			})?;

		if status != ESCROW_ORDER_STATUS_DEPOSITED {
			if status == ESCROW_ORDER_STATUS_NONE {
				tracing::info!(
					order_id = %order.id,
					origin_chain_id,
					confirmed_block,
					"Escrow fill deferred: source order deposit is not final yet"
				);
				return Ok(EscrowDepositReadiness::Defer(SOURCE_FINALITY_RETRY_AFTER));
			}

			let expected = ESCROW_ORDER_STATUS_DEPOSITED;
			return Err(OrderError::Service(format!(
				"Escrow fill aborted: source orderStatus is {status}, expected Deposited ({expected})"
			)));
		}

		Ok(EscrowDepositReadiness::Ready)
	}

	/// Handles order execution by generating and submitting a fill transaction.
	#[instrument(skip_all, fields(order_id = %truncate_id(&order.id)))]
	pub async fn handle_execution(
		&self,
		order: Order,
		params: ExecutionParams,
	) -> Result<(), OrderError> {
		if order_requires_preparation(&order) && order.prepare_tx_hash.is_none() {
			return Err(OrderError::Service(format!(
				"Order {} requires preparation before fill, but prepare_tx_hash is missing",
				order.id
			)));
		}

		// (C-03) Just-in-time forced-withdrawal guard for ResourceLock orders. This is
		// the last solver-controlled point before the destination fill is released, so
		// it catches a sponsor who enabled (or began) a forced withdrawal before the
		// order was submitted — a case the intake-time reset-period floor cannot see.
		self.check_forced_withdrawal_before_fill(&order).await?;

		match self.check_escrow_deposit_before_fill(&order).await? {
			EscrowDepositReadiness::Ready => {},
			EscrowDepositReadiness::Defer(retry_after) => {
				self.event_bus
					.publish(SolverEvent::Order(OrderEvent::Deferred {
						order_id: order.id,
						retry_after,
					}))
					.ok();
				return Ok(());
			},
		}

		// Generate fill transaction
		let tx = self
			.order_service
			.generate_fill_transaction(&order, &params)
			.await
			.map_err(|e| OrderError::Service(e.to_string()))?;

		// Submit transaction with monitoring
		let event_bus = self.event_bus.clone();
		let callback = Box::new(move |event: TransactionMonitoringEvent| match event {
			TransactionMonitoringEvent::Confirmed {
				id,
				tx_hash,
				tx_type,
				receipt,
			} => {
				event_bus
					.publish(SolverEvent::Delivery(DeliveryEvent::TransactionConfirmed {
						order_id: id,
						tx_hash,
						tx_type,
						receipt,
					}))
					.ok();
			},
			TransactionMonitoringEvent::Failed {
				id,
				tx_hash,
				tx_type,
				error,
				classification,
			} => match classification {
				RevertClassification::StageComplete { reason } => {
					tracing::info!(
						order_id = %id,
						?tx_type,
						?reason,
						?tx_hash,
						"Revert classified as stage-complete; deferring to recovery for chain confirmation"
					);
				},
				RevertClassification::Terminal { .. } | RevertClassification::Unknown => {
					event_bus
						.publish(SolverEvent::Delivery(DeliveryEvent::TransactionFailed {
							order_id: id,
							tx_hash,
							tx_type,
							error,
						}))
						.ok();
				},
			},
			TransactionMonitoringEvent::Indeterminate {
				id: order_id,
				tx_hash,
				tx_type,
				reason,
			} => {
				tracing::warn!(
					%order_id,
					?tx_hash,
					?tx_type,
					%reason,
					"Live tx monitor indeterminate; order left in current status"
				);
			},
			TransactionMonitoringEvent::AttemptLedgerConflict {
				id,
				attempt_id,
				tx_type,
				tx_hash,
				attempted_status,
				error,
				context,
			} => {
				event_bus
					.publish(SolverEvent::Delivery(
						DeliveryEvent::TransactionAttemptLedgerConflict {
							order_id: id,
							attempt_id,
							tx_type,
							tx_hash,
							attempted_status,
							error,
							context: context.to_string(),
						},
					))
					.ok();
			},
		});

		let tracking = TransactionTracking {
			id: order.id.clone(),
			tx_type: TransactionType::Fill,
			attempt_recorder: self.transaction_attempt_recorder(),
			callback,
			attempt_id: None,
			replacement_of: None,
		};

		let tx_hash = self
			.delivery
			.deliver(tx.clone(), Some(tracking))
			.await
			.map_err(|e| OrderError::Service(e.to_string()))?;

		self.event_bus
			.publish(SolverEvent::Delivery(DeliveryEvent::TransactionPending {
				order_id: order.id.clone(),
				tx_hash: tx_hash.clone(),
				tx_type: TransactionType::Fill,
				tx_chain_id: tx.chain_id,
			}))
			.ok();

		// Store fill transaction
		self.state_machine
			.set_transaction_hash(&order.id, tx_hash.clone(), TransactionType::Fill)
			.await
			.map_err(|e| OrderError::State(e.to_string()))?;

		// Store reverse mapping: tx_hash -> order_id
		self.storage
			.store(
				StorageKey::OrderByTxHash.as_str(),
				&hex::encode(&tx_hash.0),
				&order.id,
				None,
			)
			.await
			.map_err(|e| OrderError::Storage(e.to_string()))?;

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::engine::event_bus::EventBus;
	use crate::state::OrderStateMachine;
	use alloy_primitives::U256;
	use solver_delivery::{DeliveryService, MockDeliveryInterface};
	use solver_order::{MockOrderInterface, OrderService};
	use solver_storage::{MockStorageInterface, StorageService};
	use solver_types::networks::{NetworkConfig, NetworkType, RpcEndpoint};
	use solver_types::utils::tests::builders::{
		Eip7683OrderDataBuilder, OrderBuilder, TransactionBuilder,
	};
	use solver_types::{
		ExecutionParams, Order, SolverEvent, Transaction, TransactionHash, TransactionType,
	};
	use std::collections::HashMap;
	use std::sync::Arc;
	use tokio::sync::broadcast;

	fn create_test_order() -> Order {
		OrderBuilder::new().build()
	}

	fn create_test_execution_params() -> ExecutionParams {
		ExecutionParams {
			gas_price: U256::from(20_000_000_000u64),         // 20 gwei
			priority_fee: Some(U256::from(1_000_000_000u64)), // 1 gwei
		}
	}

	fn create_test_transaction() -> Transaction {
		TransactionBuilder::new()
			.chain_id(137)
			.gas_limit(21000)
			.gas_price(20_000_000_000u128) // Add gas price (20 gwei)
			.build()
	}

	fn create_test_tx_hash() -> TransactionHash {
		TransactionHash(vec![0xab; 32])
	}

	fn test_input_settler_address() -> solver_types::Address {
		solver_types::Address(vec![0x11u8; 20])
	}

	fn create_test_config() -> solver_config::Config {
		let network = NetworkConfig {
			name: None,
			network_type: NetworkType::default(),
			rpc_urls: vec![RpcEndpoint::http_only("http://localhost:8545".to_string())],
			input_settler_address: test_input_settler_address(),
			output_settler_address: solver_types::Address(vec![0x22u8; 20]),
			tokens: vec![],
			input_settler_compact_address: Some(solver_types::Address(vec![0x44u8; 20])),
			the_compact_address: Some(solver_types::Address(vec![0x88u8; 20])),
			allocator_address: Some(solver_types::Address(vec![0xA1u8; 20])),
		};

		solver_config::ConfigBuilder::new()
			.networks(HashMap::from([(137, network)]))
			.build()
	}

	fn create_test_config_with_broadcaster_finality(
		default_finality_blocks: u64,
		chain_137_finality_blocks: u64,
	) -> solver_config::Config {
		let settlement = solver_config::SettlementConfig {
			implementations: HashMap::from([(
				"broadcaster".to_string(),
				serde_json::json!({
					"default_finality_blocks": default_finality_blocks,
					"finality_blocks": {
						"137": chain_137_finality_blocks
					}
				}),
			)]),
			primary: "broadcaster".to_string(),
			settlement_poll_interval_seconds: 3,
		};

		let mut config = create_test_config();
		config.settlement = settlement;
		config
	}

	fn create_test_config_with_discovery_finality(
		default_finality_blocks: u64,
		chain_137_finality_blocks: u64,
	) -> solver_config::Config {
		let mut config = create_test_config();
		config.discovery.implementations.insert(
			"onchain_eip7683".to_string(),
			serde_json::json!({
				"default_finality_blocks": default_finality_blocks,
				"finality_blocks": {
					"137": chain_137_finality_blocks
				}
			}),
		);
		config
	}

	#[test]
	fn source_finality_falls_back_to_discovery_config_when_broadcaster_settlement_is_absent() {
		let config = create_test_config_with_discovery_finality(0, 7);

		assert_eq!(source_finality_blocks_for_config(&config, 137), 7);
		assert_eq!(source_finality_blocks_for_config(&config, 1), 0);
	}

	fn deposited_status_return() -> alloy_primitives::Bytes {
		let mut encoded = vec![0u8; 32];
		encoded[31] = ESCROW_ORDER_STATUS_DEPOSITED;
		alloy_primitives::Bytes::from(encoded)
	}

	fn escrow_status_return(status: u8) -> alloy_primitives::Bytes {
		let mut encoded = vec![0u8; 32];
		encoded[31] = status;
		alloy_primitives::Bytes::from(encoded)
	}

	fn is_expected_escrow_status_call(tx: &Transaction, order: &Order) -> bool {
		let Ok(order_data) = serde_json::from_value::<Eip7683OrderData>(order.data.clone()) else {
			return false;
		};
		let expected_call = IInputSettlerEscrow::orderStatusCall {
			orderId: B256::from(order_data.order_id),
		}
		.abi_encode();

		tx.to.as_ref() == Some(&test_input_settler_address()) && tx.data == expected_call
	}

	fn eip7683_order_with_lock(
		lock_type: LockType,
		offchain_fields: bool,
		prepare_tx_hash: Option<TransactionHash>,
	) -> Order {
		let mut order_data = Eip7683OrderDataBuilder::new()
			.origin_chain_id(U256::from(137))
			.lock_type(lock_type)
			.raw_order_data("0x1234");

		if offchain_fields {
			order_data = order_data
				.sponsor("0x1111111111111111111111111111111111111111")
				.signature("0xabcdef");
		}

		OrderBuilder::new()
			.with_data(serde_json::to_value(order_data.build()).unwrap())
			.with_prepare_tx_hash(prepare_tx_hash)
			.build()
	}

	async fn assert_handle_execution_succeeds(order: Order) {
		let params = create_test_execution_params();
		let fill_tx = create_test_transaction();
		let fill_tx_hash = create_test_tx_hash();
		let order_clone = order.clone();
		let fill_tx_clone = fill_tx.clone();
		let fill_tx_hash_clone = fill_tx_hash.clone();
		let status_order = order.clone();
		let needs_escrow_guard = serde_json::from_value::<Eip7683OrderData>(order.data.clone())
			.ok()
			.and_then(|data| data.lock_type)
			.is_some_and(|lock_type| lock_type.is_escrow());

		let (handler, mut event_rx) = create_test_handler_with_config(
			|mock_order| {
				let fill_tx_clone = fill_tx_clone.clone();
				mock_order
					.expect_generate_fill_transaction()
					.times(1)
					.returning(move |_, _| {
						let tx = fill_tx_clone.clone();
						Box::pin(async move { Ok(tx) })
					});
			},
			|mock_delivery| {
				let fill_tx_hash_clone = fill_tx_hash_clone.clone();
				if needs_escrow_guard {
					mock_delivery
						.expect_get_block_number()
						.times(1)
						.withf(|chain_id| *chain_id == 137)
						.returning(|_| Box::pin(async { Ok(100) }));
					mock_delivery
						.expect_eth_call_at_block()
						.times(1)
						.withf(move |tx, block| {
							tx.chain_id == 137
								&& *block == 80 && is_expected_escrow_status_call(tx, &status_order)
						})
						.returning(|_, _| Box::pin(async { Ok(deposited_status_return()) }));
				}
				mock_delivery
					.expect_submit()
					.times(1)
					.returning(move |_tx, _tracking| {
						let hash = fill_tx_hash_clone.clone();
						Box::pin(async move { Ok(hash) })
					});
			},
			|mock_storage| {
				let order_clone = order_clone.clone();
				mock_storage
					.expect_set_bytes()
					.times(1)
					.returning(|_, _, _, _| Box::pin(async { Ok(()) }));

				mock_storage
					.expect_exists()
					.returning(|_| Box::pin(async { Ok(true) }));

				mock_storage.expect_get_bytes().returning(move |_| {
					let order = order_clone.clone();
					Box::pin(async move { Ok(serde_json::to_vec(&order).unwrap()) })
				});

				mock_storage
					.expect_compare_and_swap_with_indexes()
					.times(1)
					.returning(|_, _, _, _, _| Box::pin(async { Ok(true) }));
			},
			create_test_config(),
		)
		.await;

		let result = handler.handle_execution(order.clone(), params).await;
		assert!(result.is_ok());

		let event = tokio::time::timeout(std::time::Duration::from_millis(100), event_rx.recv())
			.await
			.expect("Should receive event")
			.expect("Event should be valid");

		match event {
			SolverEvent::Delivery(DeliveryEvent::TransactionPending {
				order_id,
				tx_hash,
				tx_type,
				tx_chain_id,
			}) => {
				assert_eq!(order_id, order.id);
				assert_eq!(tx_hash, fill_tx_hash);
				assert_eq!(tx_type, TransactionType::Fill);
				assert_eq!(tx_chain_id, fill_tx.chain_id);
			},
			_ => panic!("Expected TransactionPending event"),
		}
	}

	async fn create_test_handler_with_mocks<F1, F2, F3>(
		setup_order: F1,
		setup_delivery: F2,
		setup_storage: F3,
	) -> (OrderHandler, broadcast::Receiver<SolverEvent>)
	where
		F1: FnOnce(&mut MockOrderInterface),
		F2: FnOnce(&mut MockDeliveryInterface),
		F3: FnOnce(&mut MockStorageInterface),
	{
		create_test_handler_with_config(
			setup_order,
			setup_delivery,
			setup_storage,
			create_test_config(),
		)
		.await
	}

	async fn create_test_handler_with_config<F1, F2, F3>(
		setup_order: F1,
		setup_delivery: F2,
		setup_storage: F3,
		config: solver_config::Config,
	) -> (OrderHandler, broadcast::Receiver<SolverEvent>)
	where
		F1: FnOnce(&mut MockOrderInterface),
		F2: FnOnce(&mut MockDeliveryInterface),
		F3: FnOnce(&mut MockStorageInterface),
	{
		let mut mock_order = MockOrderInterface::new();
		let mut mock_delivery = MockDeliveryInterface::new();
		let mut mock_storage = MockStorageInterface::new();

		// Set up expectations using the provided closures
		setup_order(&mut mock_order);
		setup_delivery(&mut mock_delivery);
		setup_storage(&mut mock_storage);
		mock_storage
			.expect_compare_and_swap_with_indexes()
			.returning(|_, _, _, _, _| Box::pin(async { Ok(true) }));

		// Create services with configured mocks
		let order_service = Arc::new(OrderService::new(
			HashMap::from([(
				"eip7683".to_string(),
				Box::new(mock_order) as Box<dyn solver_order::OrderInterface>,
			)]),
			Box::new(solver_order::MockExecutionStrategy::new()),
		));

		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				137u64,
				Arc::new(mock_delivery) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			1,
			20,
			60,
		));

		let storage = Arc::new(StorageService::new(Box::new(mock_storage)));
		let state_machine = Arc::new(OrderStateMachine::new(storage.clone()));
		let event_bus = EventBus::new(100);
		let event_rx = event_bus.subscribe();

		let handler = OrderHandler::new(
			order_service,
			delivery,
			storage,
			state_machine,
			event_bus,
			Arc::new(RwLock::new(config)),
		);

		(handler, event_rx)
	}

	#[tokio::test]
	async fn test_handle_preparation_with_prepare_transaction_success() {
		let order = create_test_order();
		let params = create_test_execution_params();
		let prepare_tx = create_test_transaction();
		let prepare_tx_hash = create_test_tx_hash();

		// Clone variables for use in closures and assertions
		let prepare_tx_clone = prepare_tx.clone();
		let prepare_tx_hash_clone = prepare_tx_hash.clone();
		let order_clone = order.clone();

		let (handler, mut event_rx) = create_test_handler_with_mocks(
			|mock_order| {
				let prepare_tx_clone = prepare_tx_clone.clone();
				mock_order
					.expect_generate_prepare_transaction()
					.times(1)
					.returning(move |_, _, _| {
						let tx = prepare_tx_clone.clone();
						Box::pin(async move { Ok(Some(tx)) })
					});
			},
			|mock_delivery| {
				let hash_clone = prepare_tx_hash_clone.clone();
				mock_delivery
					.expect_submit()
					.times(1)
					.returning(move |_tx, _tracking| {
						let hash = hash_clone.clone();
						Box::pin(async move { Ok(hash) })
					});
			},
			|mock_storage| {
				let order_clone = order_clone.clone();
				mock_storage
					.expect_set_bytes()
					.times(1)
					.returning(|_, _, _, _| Box::pin(async { Ok(()) }));

				// Mock for state machine storage operations
				mock_storage
					.expect_exists()
					.returning(|_| Box::pin(async { Ok(true) }));

				mock_storage.expect_get_bytes().returning(move |_| {
					let order = order_clone.clone();
					Box::pin(async move { Ok(serde_json::to_vec(&order).unwrap()) })
				});

				mock_storage
					.expect_compare_and_swap_with_indexes()
					.times(1)
					.returning(|_, _, _, _, _| Box::pin(async { Ok(true) }));
			},
		)
		.await;

		let result = handler
			.handle_preparation("test_source".to_string(), order.clone(), params.clone())
			.await;

		assert!(result.is_ok());

		// Verify event was published
		let event = tokio::time::timeout(std::time::Duration::from_millis(100), event_rx.recv())
			.await
			.expect("Should receive event")
			.expect("Event should be valid");

		match event {
			SolverEvent::Delivery(DeliveryEvent::TransactionPending {
				order_id,
				tx_hash,
				tx_type,
				tx_chain_id,
			}) => {
				assert_eq!(order_id, order.id);
				assert_eq!(tx_hash, prepare_tx_hash);
				assert_eq!(tx_type, TransactionType::Prepare);
				assert_eq!(tx_chain_id, prepare_tx.chain_id);
			},
			_ => panic!("Expected TransactionPending event"),
		}
	}

	#[tokio::test]
	async fn test_handle_preparation_without_prepare_transaction() {
		let order = create_test_order();
		let params = create_test_execution_params();

		// Clone for closure
		let order_clone = order.clone();

		let (handler, mut event_rx) = create_test_handler_with_mocks(
			|mock_order| {
				mock_order
					.expect_generate_prepare_transaction()
					.times(1)
					.returning(|_, _, _| Box::pin(async { Ok(None) }));
			},
			|_mock_delivery| {
				// No delivery expectations since no prepare transaction
			},
			|mock_storage| {
				let order_clone = order_clone.clone();
				// Mock for state machine storage operations
				mock_storage
					.expect_exists()
					.returning(|_| Box::pin(async { Ok(true) }));

				mock_storage.expect_get_bytes().returning(move |_| {
					let order = order_clone.clone();
					Box::pin(async move { Ok(serde_json::to_vec(&order).unwrap()) })
				});

				mock_storage
					.expect_compare_and_swap_with_indexes()
					.times(1)
					.returning(|_, _, _, _, _| Box::pin(async { Ok(true) }));
			},
		)
		.await;

		let result = handler
			.handle_preparation("test_source".to_string(), order.clone(), params.clone())
			.await;

		assert!(result.is_ok());

		// Verify OrderEvent::Executing was published
		let event = tokio::time::timeout(std::time::Duration::from_millis(100), event_rx.recv())
			.await
			.expect("Should receive event")
			.expect("Event should be valid");

		match event {
			SolverEvent::Order(OrderEvent::Executing {
				order: event_order,
				params: _,
			}) => {
				assert_eq!(event_order.id, order.id);
			},
			_ => panic!("Expected OrderEvent::Executing event"),
		}
	}

	#[tokio::test]
	async fn test_handle_preparation_order_service_error() {
		let order = create_test_order();
		let params = create_test_execution_params();

		let (handler, _event_rx) = create_test_handler_with_mocks(
			|mock_order| {
				mock_order
					.expect_generate_prepare_transaction()
					.times(1)
					.returning(|_, _, _| {
						Box::pin(async {
							Err(solver_order::OrderError::ValidationFailed(
								"Test error".to_string(),
							))
						})
					});
			},
			|_mock_delivery| {},
			|_mock_storage| {},
		)
		.await;

		let result = handler
			.handle_preparation("test_source".to_string(), order, params)
			.await;

		assert!(result.is_err());
		match result.unwrap_err() {
			OrderError::Service(msg) => assert!(msg.contains("Test error")),
			_ => panic!("Expected Service error"),
		}
	}

	#[tokio::test]
	async fn test_handle_preparation_delivery_error() {
		let order = create_test_order();
		let params = create_test_execution_params();
		let prepare_tx = create_test_transaction();

		let (handler, _event_rx) = create_test_handler_with_mocks(
			|mock_order| {
				mock_order
					.expect_generate_prepare_transaction()
					.times(1)
					.returning(move |_, _, _| {
						let tx = prepare_tx.clone();
						Box::pin(async move { Ok(Some(tx)) })
					});
			},
			|mock_delivery| {
				mock_delivery
					.expect_submit()
					.times(1)
					.returning(|_tx, _tracking| {
						Box::pin(async {
							Err(solver_delivery::DeliveryError::Network(
								"Delivery failed".to_string(),
							))
						})
					});
			},
			|_mock_storage| {},
		)
		.await;

		let result = handler
			.handle_preparation("test_source".to_string(), order, params)
			.await;

		assert!(result.is_err());
		match result.unwrap_err() {
			OrderError::Service(msg) => assert!(msg.contains("Delivery failed")),
			_ => panic!("Expected Service error"),
		}
	}

	#[tokio::test]
	async fn test_handle_preparation_storage_error() {
		let order = create_test_order();
		let params = create_test_execution_params();
		let prepare_tx = create_test_transaction();
		let prepare_tx_hash = create_test_tx_hash();

		let (handler, _event_rx) = create_test_handler_with_mocks(
			|mock_order| {
				mock_order
					.expect_generate_prepare_transaction()
					.times(1)
					.returning(move |_, _, _| {
						let tx = prepare_tx.clone();
						Box::pin(async move { Ok(Some(tx)) })
					});
			},
			|mock_delivery| {
				mock_delivery
					.expect_submit()
					.times(1)
					.returning(move |_tx, _tracking| {
						let hash = prepare_tx_hash.clone();
						Box::pin(async move { Ok(hash) })
					});
			},
			|mock_storage| {
				mock_storage
					.expect_set_bytes()
					.times(1)
					.returning(|_, _, _, _| {
						Box::pin(async {
							Err(solver_storage::StorageError::Backend(
								"Storage failed".to_string(),
							))
						})
					});
			},
		)
		.await;

		let result = handler
			.handle_preparation("test_source".to_string(), order, params)
			.await;

		assert!(result.is_err());
		match result.unwrap_err() {
			OrderError::Storage(msg) => assert!(msg.contains("Storage failed")),
			_ => panic!("Expected Storage error"),
		}
	}

	#[tokio::test]
	async fn test_handle_execution_success() {
		let order = create_test_order();
		let params = create_test_execution_params();
		let fill_tx = create_test_transaction();
		let fill_tx_hash = create_test_tx_hash();

		// Clone for closure
		let order_clone = order.clone();
		let fill_tx_clone = fill_tx.clone();
		let fill_tx_hash_clone = fill_tx_hash.clone();

		let (handler, mut event_rx) = create_test_handler_with_mocks(
			|mock_order| {
				let fill_tx_clone = fill_tx_clone.clone();
				mock_order
					.expect_generate_fill_transaction()
					.times(1)
					.returning(move |_, _| {
						let tx = fill_tx_clone.clone();
						Box::pin(async move { Ok(tx) })
					});
			},
			|mock_delivery| {
				let fill_tx_hash_clone = fill_tx_hash_clone.clone();
				mock_delivery
					.expect_submit()
					.times(1)
					.returning(move |_tx, _tracking| {
						let hash = fill_tx_hash_clone.clone();
						Box::pin(async move { Ok(hash) })
					});
			},
			|mock_storage| {
				let order_clone = order_clone.clone();
				mock_storage
					.expect_set_bytes()
					.times(1)
					.returning(|_, _, _, _| Box::pin(async { Ok(()) }));

				// Mock for state machine storage operations
				mock_storage
					.expect_exists()
					.returning(|_| Box::pin(async { Ok(true) }));

				mock_storage.expect_get_bytes().returning(move |_| {
					let order = order_clone.clone();
					Box::pin(async move { Ok(serde_json::to_vec(&order).unwrap()) })
				});

				mock_storage
					.expect_compare_and_swap_with_indexes()
					.times(1)
					.returning(|_, _, _, _, _| Box::pin(async { Ok(true) }));
			},
		)
		.await;

		let result = handler.handle_execution(order.clone(), params).await;

		assert!(result.is_ok());

		// Verify event was published
		let event = tokio::time::timeout(std::time::Duration::from_millis(100), event_rx.recv())
			.await
			.expect("Should receive event")
			.expect("Event should be valid");

		match event {
			SolverEvent::Delivery(DeliveryEvent::TransactionPending {
				order_id,
				tx_hash,
				tx_type,
				tx_chain_id,
			}) => {
				assert_eq!(order_id, order.id);
				assert_eq!(tx_hash, fill_tx_hash);
				assert_eq!(tx_type, TransactionType::Fill);
				assert_eq!(tx_chain_id, fill_tx.chain_id);
			},
			_ => panic!("Expected TransactionPending event"),
		}
	}

	#[tokio::test]
	async fn test_handle_execution_order_service_error() {
		let order = create_test_order();
		let params = create_test_execution_params();

		let (handler, _event_rx) = create_test_handler_with_mocks(
			|mock_order| {
				mock_order
					.expect_generate_fill_transaction()
					.times(1)
					.returning(|_, _| {
						Box::pin(async {
							Err(solver_order::OrderError::ValidationFailed(
								"Fill error".to_string(),
							))
						})
					});
			},
			|_mock_delivery| {},
			|_mock_storage| {},
		)
		.await;

		let result = handler.handle_execution(order, params).await;

		assert!(result.is_err());
		match result.unwrap_err() {
			OrderError::Service(msg) => assert!(msg.contains("Fill error")),
			_ => panic!("Expected Service error"),
		}
	}

	#[tokio::test]
	async fn handle_execution_rejects_offchain_escrow_without_prepare_hash() {
		let order = eip7683_order_with_lock(LockType::Permit2Escrow, true, None);
		let params = create_test_execution_params();

		let (handler, _event_rx) = create_test_handler_with_mocks(
			|mock_order| {
				mock_order.expect_generate_fill_transaction().times(0);
			},
			|mock_delivery| {
				mock_delivery.expect_submit().times(0);
			},
			|_mock_storage| {},
		)
		.await;

		let err = handler
			.handle_execution(order, params)
			.await
			.expect_err("off-chain escrow order without prepare hash must not fill");

		assert!(matches!(
			err,
			OrderError::Service(msg)
				if msg.contains("requires preparation") && msg.contains("prepare_tx_hash")
		));
	}

	#[tokio::test]
	async fn handle_execution_allows_offchain_escrow_with_prepare_hash() {
		let order = eip7683_order_with_lock(
			LockType::Permit2Escrow,
			true,
			Some(TransactionHash(vec![0xcd; 32])),
		);

		assert_handle_execution_succeeds(order).await;
	}

	#[tokio::test]
	async fn handle_execution_allows_onchain_escrow_without_prepare_hash() {
		let order = eip7683_order_with_lock(LockType::Permit2Escrow, false, None);

		assert_handle_execution_succeeds(order).await;
	}

	#[tokio::test]
	async fn handle_execution_rejects_escrow_when_source_status_not_deposited() {
		let order = eip7683_order_with_lock(LockType::Permit2Escrow, false, None);
		let params = create_test_execution_params();
		let status_order = order.clone();

		let (handler, _event_rx) = create_test_handler_with_config(
			|mock_order| {
				mock_order.expect_generate_fill_transaction().times(0);
			},
			|mock_delivery| {
				mock_delivery
					.expect_get_block_number()
					.times(1)
					.withf(|chain_id| *chain_id == 137)
					.returning(|_| Box::pin(async { Ok(100) }));
				mock_delivery
					.expect_eth_call_at_block()
					.times(1)
					.withf(move |tx, block| {
						tx.chain_id == 137
							&& *block == 80 && is_expected_escrow_status_call(tx, &status_order)
					})
					.returning(|_, _| Box::pin(async { Ok(escrow_status_return(2)) }));
				mock_delivery.expect_submit().times(0);
			},
			|_mock_storage| {},
			create_test_config(),
		)
		.await;

		let err = handler
			.handle_execution(order, params)
			.await
			.expect_err("source status guard should refuse fill");
		assert!(
			err.to_string().contains("expected Deposited"),
			"unexpected error: {err}"
		);
	}

	#[tokio::test]
	async fn handle_execution_defers_escrow_when_source_finality_depth_not_reached() {
		let order = eip7683_order_with_lock(LockType::Permit2Escrow, false, None);
		let params = create_test_execution_params();

		let (handler, mut event_rx) = create_test_handler_with_config(
			|mock_order| {
				mock_order.expect_generate_fill_transaction().times(0);
			},
			|mock_delivery| {
				mock_delivery
					.expect_get_block_number()
					.times(1)
					.withf(|chain_id| *chain_id == 137)
					.returning(|_| Box::pin(async { Ok(10) }));
				mock_delivery.expect_eth_call_at_block().times(0);
				mock_delivery.expect_submit().times(0);
			},
			|_mock_storage| {},
			create_test_config(),
		)
		.await;

		let result = handler.handle_execution(order.clone(), params).await;
		assert!(result.is_ok(), "finality wait should defer, got {result:?}");

		let event = tokio::time::timeout(std::time::Duration::from_millis(100), event_rx.recv())
			.await
			.expect("Should receive deferred event")
			.expect("Event should be valid");
		match event {
			SolverEvent::Order(OrderEvent::Deferred {
				order_id,
				retry_after,
			}) => {
				assert_eq!(order_id, order.id);
				assert_eq!(retry_after, std::time::Duration::from_secs(5));
			},
			other => panic!("Expected deferred event, got {other:?}"),
		}
	}

	#[tokio::test]
	async fn handle_execution_defers_offchain_escrow_when_source_status_not_final_yet() {
		let order = eip7683_order_with_lock(
			LockType::Permit2Escrow,
			true,
			Some(TransactionHash(vec![0xcd; 32])),
		);
		let params = create_test_execution_params();
		let status_order = order.clone();

		let (handler, mut event_rx) = create_test_handler_with_config(
			|mock_order| {
				mock_order.expect_generate_fill_transaction().times(0);
			},
			|mock_delivery| {
				mock_delivery
					.expect_get_block_number()
					.times(1)
					.withf(|chain_id| *chain_id == 137)
					.returning(|_| Box::pin(async { Ok(100) }));
				mock_delivery
					.expect_eth_call_at_block()
					.times(1)
					.withf(move |tx, block| {
						tx.chain_id == 137
							&& *block == 80 && is_expected_escrow_status_call(tx, &status_order)
					})
					.returning(|_, _| Box::pin(async { Ok(escrow_status_return(0)) }));
				mock_delivery.expect_submit().times(0);
			},
			|_mock_storage| {},
			create_test_config(),
		)
		.await;

		let result = handler.handle_execution(order.clone(), params).await;
		assert!(
			result.is_ok(),
			"unfinalized deposit should defer, got {result:?}"
		);

		let event = tokio::time::timeout(std::time::Duration::from_millis(100), event_rx.recv())
			.await
			.expect("Should receive deferred event")
			.expect("Event should be valid");
		match event {
			SolverEvent::Order(OrderEvent::Deferred {
				order_id,
				retry_after,
			}) => {
				assert_eq!(order_id, order.id);
				assert_eq!(retry_after, std::time::Duration::from_secs(5));
			},
			other => panic!("Expected deferred event, got {other:?}"),
		}
	}

	#[tokio::test]
	async fn handle_execution_defers_onchain_escrow_when_source_status_not_final_yet() {
		let order = eip7683_order_with_lock(LockType::Permit2Escrow, false, None);
		let params = create_test_execution_params();
		let status_order = order.clone();

		let (handler, mut event_rx) = create_test_handler_with_config(
			|mock_order| {
				mock_order.expect_generate_fill_transaction().times(0);
			},
			|mock_delivery| {
				mock_delivery
					.expect_get_block_number()
					.times(1)
					.withf(|chain_id| *chain_id == 137)
					.returning(|_| Box::pin(async { Ok(100) }));
				mock_delivery
					.expect_eth_call_at_block()
					.times(1)
					.withf(move |tx, block| {
						tx.chain_id == 137
							&& *block == 80 && is_expected_escrow_status_call(tx, &status_order)
					})
					.returning(|_, _| Box::pin(async { Ok(escrow_status_return(0)) }));
				mock_delivery.expect_submit().times(0);
			},
			|_mock_storage| {},
			create_test_config(),
		)
		.await;

		let result = handler.handle_execution(order.clone(), params).await;
		assert!(
			result.is_ok(),
			"unfinalized on-chain deposit should defer, got {result:?}"
		);

		let event = tokio::time::timeout(std::time::Duration::from_millis(100), event_rx.recv())
			.await
			.expect("Should receive deferred event")
			.expect("Event should be valid");
		match event {
			SolverEvent::Order(OrderEvent::Deferred {
				order_id,
				retry_after,
			}) => {
				assert_eq!(order_id, order.id);
				assert_eq!(retry_after, std::time::Duration::from_secs(5));
			},
			other => panic!("Expected deferred event, got {other:?}"),
		}
	}

	#[tokio::test]
	async fn handle_execution_defers_escrow_when_source_status_read_is_empty() {
		let order = eip7683_order_with_lock(
			LockType::Permit2Escrow,
			true,
			Some(TransactionHash(vec![0xcd; 32])),
		);
		let params = create_test_execution_params();
		let status_order = order.clone();
		let latest_order = order.clone();

		let (handler, mut event_rx) = create_test_handler_with_config(
			|mock_order| {
				mock_order.expect_generate_fill_transaction().times(0);
			},
			|mock_delivery| {
				mock_delivery
					.expect_get_block_number()
					.times(1)
					.withf(|chain_id| *chain_id == 137)
					.returning(|_| Box::pin(async { Ok(100) }));
				mock_delivery
					.expect_eth_call_at_block()
					.times(1)
					.withf(move |tx, block| {
						tx.chain_id == 137
							&& *block == 80 && is_expected_escrow_status_call(tx, &status_order)
					})
					.returning(|_, _| Box::pin(async { Ok(alloy_primitives::Bytes::new()) }));
				mock_delivery
					.expect_eth_call()
					.times(1)
					.withf(move |tx| {
						tx.chain_id == 137 && is_expected_escrow_status_call(tx, &latest_order)
					})
					.returning(|_| Box::pin(async { Ok(deposited_status_return()) }));
				mock_delivery.expect_submit().times(0);
			},
			|_mock_storage| {},
			create_test_config(),
		)
		.await;

		let result = handler.handle_execution(order.clone(), params).await;
		assert!(
			result.is_ok(),
			"empty status read should defer, got {result:?}"
		);

		let event = tokio::time::timeout(std::time::Duration::from_millis(100), event_rx.recv())
			.await
			.expect("Should receive deferred event")
			.expect("Event should be valid");
		match event {
			SolverEvent::Order(OrderEvent::Deferred {
				order_id,
				retry_after,
			}) => {
				assert_eq!(order_id, order.id);
				assert_eq!(retry_after, std::time::Duration::from_secs(5));
			},
			other => panic!("Expected deferred event, got {other:?}"),
		}
	}

	#[tokio::test]
	async fn handle_execution_rejects_escrow_when_status_read_is_empty_at_latest() {
		let order = eip7683_order_with_lock(
			LockType::Permit2Escrow,
			true,
			Some(TransactionHash(vec![0xcd; 32])),
		);
		let params = create_test_execution_params();
		let status_order = order.clone();
		let latest_order = order.clone();

		let (handler, _event_rx) = create_test_handler_with_config(
			|mock_order| {
				mock_order.expect_generate_fill_transaction().times(0);
			},
			|mock_delivery| {
				mock_delivery
					.expect_get_block_number()
					.times(1)
					.withf(|chain_id| *chain_id == 137)
					.returning(|_| Box::pin(async { Ok(100) }));
				mock_delivery
					.expect_eth_call_at_block()
					.times(1)
					.withf(move |tx, block| {
						tx.chain_id == 137
							&& *block == 80 && is_expected_escrow_status_call(tx, &status_order)
					})
					.returning(|_, _| Box::pin(async { Ok(alloy_primitives::Bytes::new()) }));
				mock_delivery
					.expect_eth_call()
					.times(1)
					.withf(move |tx| {
						tx.chain_id == 137 && is_expected_escrow_status_call(tx, &latest_order)
					})
					.returning(|_| Box::pin(async { Ok(alloy_primitives::Bytes::new()) }));
				mock_delivery.expect_submit().times(0);
			},
			|_mock_storage| {},
			create_test_config(),
		)
		.await;

		let err = handler
			.handle_execution(order, params)
			.await
			.expect_err("empty latest status read should fail closed");
		assert!(
			err.to_string().contains("returned empty data at latest"),
			"unexpected error: {err}"
		);
	}

	#[tokio::test]
	async fn handle_execution_uses_configured_broadcaster_finality_for_escrow_status_check() {
		let order = eip7683_order_with_lock(LockType::Permit2Escrow, false, None);
		let params = create_test_execution_params();
		let status_order = order.clone();
		let config = create_test_config_with_broadcaster_finality(42, 7);

		let (handler, _event_rx) = create_test_handler_with_config(
			|mock_order| {
				mock_order.expect_generate_fill_transaction().times(0);
			},
			|mock_delivery| {
				mock_delivery
					.expect_get_block_number()
					.times(1)
					.withf(|chain_id| *chain_id == 137)
					.returning(|_| Box::pin(async { Ok(100) }));
				mock_delivery
					.expect_eth_call_at_block()
					.times(1)
					.withf(move |tx, block| {
						tx.chain_id == 137
							&& *block == 93 && is_expected_escrow_status_call(tx, &status_order)
					})
					.returning(|_, _| Box::pin(async { Ok(escrow_status_return(2)) }));
				mock_delivery.expect_submit().times(0);
			},
			|_mock_storage| {},
			config,
		)
		.await;

		let err = handler
			.handle_execution(order, params)
			.await
			.expect_err("source status guard should refuse fill");
		assert!(
			err.to_string().contains("expected Deposited"),
			"unexpected error: {err}"
		);
	}

	#[tokio::test]
	async fn handle_execution_allows_resource_lock_without_prepare_hash() {
		use solver_types::networks::{NetworkConfig, NetworkType, RpcEndpoint};
		use solver_types::Address;

		let order_data = Eip7683OrderDataBuilder::new()
			.origin_chain_id(U256::from(137))
			.inputs(vec![[U256::from(1000), U256::ZERO]])
			.lock_type(LockType::ResourceLock)
			.raw_order_data("0x1234")
			.sponsor("0x1111111111111111111111111111111111111111")
			.signature("0xabcdef")
			.build();
		let order = OrderBuilder::new()
			.with_data(serde_json::to_value(order_data).unwrap())
			.with_prepare_tx_hash(None)
			.build();
		let params = create_test_execution_params();
		let fill_tx = create_test_transaction();
		let fill_tx_hash = create_test_tx_hash();
		let order_clone = order.clone();
		let fill_tx_clone = fill_tx.clone();
		let fill_tx_hash_clone = fill_tx_hash.clone();

		let network = NetworkConfig {
			name: None,
			network_type: NetworkType::default(),
			rpc_urls: vec![RpcEndpoint::http_only("http://localhost:8545".to_string())],
			input_settler_address: Address(vec![0x11u8; 20]),
			output_settler_address: Address(vec![0x22u8; 20]),
			tokens: vec![],
			input_settler_compact_address: Some(Address(vec![0x44u8; 20])),
			the_compact_address: Some(Address(vec![0x88u8; 20])),
			allocator_address: Some(Address(vec![0xA1u8; 20])),
		};
		let config = solver_config::ConfigBuilder::new()
			.networks(HashMap::from([(137, network)]))
			.build();

		let (handler, mut event_rx) = create_test_handler_with_config(
			|mock_order| {
				let fill_tx_clone = fill_tx_clone.clone();
				mock_order
					.expect_generate_fill_transaction()
					.times(1)
					.returning(move |_, _| {
						let tx = fill_tx_clone.clone();
						Box::pin(async move { Ok(tx) })
					});
			},
			|mock_delivery| {
				let fill_tx_hash_clone = fill_tx_hash_clone.clone();
				mock_delivery.expect_eth_call().times(1).returning(|_| {
					Box::pin(async { Ok(alloy_primitives::Bytes::from(vec![0u8; 64])) })
				});
				mock_delivery
					.expect_submit()
					.times(1)
					.returning(move |_tx, _tracking| {
						let hash = fill_tx_hash_clone.clone();
						Box::pin(async move { Ok(hash) })
					});
			},
			|mock_storage| {
				let order_clone = order_clone.clone();
				mock_storage
					.expect_set_bytes()
					.times(1)
					.returning(|_, _, _, _| Box::pin(async { Ok(()) }));

				mock_storage
					.expect_exists()
					.returning(|_| Box::pin(async { Ok(true) }));

				mock_storage.expect_get_bytes().returning(move |_| {
					let order = order_clone.clone();
					Box::pin(async move { Ok(serde_json::to_vec(&order).unwrap()) })
				});

				mock_storage
					.expect_compare_and_swap_with_indexes()
					.times(1)
					.returning(|_, _, _, _, _| Box::pin(async { Ok(true) }));
			},
			config,
		)
		.await;

		let result = handler.handle_execution(order.clone(), params).await;
		assert!(result.is_ok());

		let event = tokio::time::timeout(std::time::Duration::from_millis(100), event_rx.recv())
			.await
			.expect("Should receive event")
			.expect("Event should be valid");

		match event {
			SolverEvent::Delivery(DeliveryEvent::TransactionPending {
				order_id,
				tx_hash,
				tx_type,
				tx_chain_id,
			}) => {
				assert_eq!(order_id, order.id);
				assert_eq!(tx_hash, fill_tx_hash);
				assert_eq!(tx_type, TransactionType::Fill);
				assert_eq!(tx_chain_id, fill_tx.chain_id);
			},
			_ => panic!("Expected TransactionPending event"),
		}
	}

	#[tokio::test]
	async fn malformed_eip7683_order_data_rejected_before_fill_generation() {
		let order = OrderBuilder::new()
			.with_standard("eip7683")
			.with_data(serde_json::json!({
				"lock_type": "resource_lock",
				"origin_chain_id": "137"
			}))
			.build();
		let params = create_test_execution_params();

		let (handler, _event_rx) = create_test_handler_with_mocks(
			|mock_order| {
				mock_order.expect_generate_fill_transaction().times(0);
			},
			|mock_delivery| {
				mock_delivery.expect_submit().times(0);
			},
			|_mock_storage| {},
		)
		.await;

		let err = handler
			.handle_execution(order, params)
			.await
			.expect_err("malformed EIP-7683 data must fail before fill generation");

		assert!(matches!(
			err,
			OrderError::Service(msg) if msg.contains("Failed to parse EIP-7683 order data")
		));
	}

	/// (C-03) A ResourceLock order whose input lock has an *enabled* forced
	/// withdrawal must be rejected before the destination fill is released: the
	/// sponsor can pull the locked input out from under the solver's claim.
	///
	/// The guard runs before `generate_fill_transaction`, so neither fill
	/// generation nor delivery is exercised (`.times(0)`).
	#[tokio::test]
	async fn forced_withdrawal_enabled_resource_lock_rejected_before_fill() {
		use alloy_sol_types::SolCall;
		use solver_types::networks::{NetworkConfig, NetworkType, RpcEndpoint};
		use solver_types::standards::eip7683::interfaces::ITheCompact;
		use solver_types::standards::eip7683::LockType;
		use solver_types::Address;

		const ORIGIN_CHAIN: u64 = 137;
		let the_compact = Address(vec![0x88u8; 20]);

		// ResourceLock order with a single input lock; sponsor is `user`.
		let lock_id = U256::from(0xABCDu64);
		let order_data = serde_json::json!({
			"user": "0x2222222222222222222222222222222222222222",
			"nonce": "1",
			"origin_chain_id": ORIGIN_CHAIN.to_string(),
			"expires": 1_700_000_600u32,
			"fill_deadline": 1_700_000_000u32,
			"input_oracle": "0x3333333333333333333333333333333333333333",
			"inputs": [[lock_id.to_string(), "1000"]],
			"order_id": vec![0u8; 32],
			"gas_limit_overrides": {},
			"outputs": [],
			"lock_type": LockType::ResourceLock,
		});
		let order = OrderBuilder::new().with_data(order_data).build();

		// Config: origin chain network advertises TheCompact.
		let network = NetworkConfig {
			name: None,
			network_type: NetworkType::default(),
			rpc_urls: vec![RpcEndpoint::http_only("http://localhost:8545".to_string())],
			input_settler_address: Address(vec![0x11u8; 20]),
			output_settler_address: Address(vec![0x22u8; 20]),
			tokens: vec![],
			input_settler_compact_address: Some(Address(vec![0x44u8; 20])),
			the_compact_address: Some(the_compact),
			allocator_address: Some(Address(vec![0xA1u8; 20])),
		};
		let config = solver_config::ConfigBuilder::new()
			.networks(HashMap::from([(ORIGIN_CHAIN, network)]))
			.build();

		let params = create_test_execution_params();

		let (handler, _event_rx) = create_test_handler_with_config(
			|mock_order| {
				// Fill generation must NOT run — the guard aborts first.
				mock_order.expect_generate_fill_transaction().times(0);
			},
			|mock_delivery| {
				// `getForcedWithdrawalStatus` reports Enabled (status 2).
				mock_delivery.expect_eth_call().returning(|tx| {
					let selector = tx.data.get(0..4).map(|s| [s[0], s[1], s[2], s[3]]);
					let resp = match selector {
						Some(s) if s == ITheCompact::getForcedWithdrawalStatusCall::SELECTOR => {
							let mut out = vec![0u8; 64];
							out[31] = 2; // ForcedWithdrawalStatus::Enabled
							alloy_primitives::Bytes::from(out)
						},
						_ => alloy_primitives::Bytes::from(vec![0u8; 64]),
					};
					Box::pin(async move { Ok(resp) })
				});
				// No fill is submitted.
				mock_delivery.expect_submit().times(0);
			},
			|_mock_storage| {},
			config,
		)
		.await;

		let result = handler.handle_execution(order, params).await;

		let err = result.expect_err("enabled forced withdrawal must abort the fill");
		match err {
			OrderError::Service(msg) => {
				assert!(
					msg.contains("forced withdrawal"),
					"unexpected error message: {msg}"
				);
			},
			other => panic!("expected Service error, got {other:?}"),
		}
	}

	#[tokio::test]
	async fn test_handle_execution_delivery_error() {
		let order = create_test_order();
		let params = create_test_execution_params();
		let fill_tx = create_test_transaction();

		let (handler, _event_rx) = create_test_handler_with_mocks(
			|mock_order| {
				mock_order
					.expect_generate_fill_transaction()
					.times(1)
					.returning(move |_, _| {
						let tx = fill_tx.clone();
						Box::pin(async move { Ok(tx) })
					});
			},
			|mock_delivery| {
				mock_delivery
					.expect_submit()
					.times(1)
					.returning(|_tx, _tracking| {
						Box::pin(async {
							Err(solver_delivery::DeliveryError::Network(
								"Execution delivery failed".to_string(),
							))
						})
					});
			},
			|_mock_storage| {},
		)
		.await;

		let result = handler.handle_execution(order, params).await;

		assert!(result.is_err());
		match result.unwrap_err() {
			OrderError::Service(msg) => assert!(msg.contains("Execution delivery failed")),
			_ => panic!("Expected Service error"),
		}
	}

	#[tokio::test]
	async fn test_handle_execution_state_machine_error() {
		let order = create_test_order();
		let params = create_test_execution_params();
		let fill_tx = create_test_transaction();
		let fill_tx_hash = create_test_tx_hash();

		let (handler, _event_rx) = create_test_handler_with_mocks(
			|mock_order| {
				mock_order
					.expect_generate_fill_transaction()
					.times(1)
					.returning(move |_, _| {
						let tx = fill_tx.clone();
						Box::pin(async move { Ok(tx) })
					});
			},
			|mock_delivery| {
				let fill_tx_hash_clone = fill_tx_hash.clone();
				mock_delivery
					.expect_submit()
					.times(1)
					.returning(move |_tx, _tracking| {
						let hash = fill_tx_hash_clone.clone();
						Box::pin(async move { Ok(hash) })
					});
			},
			|mock_storage| {
				// Mock for state machine storage operations - simulate error
				mock_storage.expect_get_bytes().returning(|_| {
					Box::pin(async {
						Err(solver_storage::StorageError::Backend(
							"State machine error".to_string(),
						))
					})
				});
			},
		)
		.await;

		let result = handler.handle_execution(order, params).await;

		assert!(result.is_err());
		match result.unwrap_err() {
			OrderError::State(msg) => assert!(msg.contains("State machine error")),
			_ => panic!("Expected State error"),
		}
	}
}
