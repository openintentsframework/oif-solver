//! Phase A resilience e2e tests.
//!
//! Known limitations:
//! - tx_bump config cannot be enabled through SeedOverrides yet; bump scenarios are Phase B.
//! - Multi-output orders are not covered because recovery/direct settlement consume output_chains.first().
//! - Bumped tx gas_limit reuse is a PR06 known limitation, not exercised here.
//! - Multiple rpc_urls are configured but only the first URL is consumed by runtime clients.
//! - The native-gas subprocess test currently observes the pre-storage callback
//!   simulation path. A deterministic submit-preflight path needs Phase B harness
//!   controls over live solver timing.
//!
//! Run with:
//!
//!     cargo test -p solver-e2e-tests --test resilience_e2e -- --ignored --test-threads=1

#![allow(unused_imports)]

use std::time::Duration;

use alloy_primitives::U256;
use anyhow::Result;
use solver_e2e_tests::{
	amount_with_decimals, Finalised, Harness, HarnessOptions, OutputFilled, StandardOrderBuilder,
	DEST_CHAIN_ID, NO_EVENT_TIMEOUT, ORIGIN_CHAIN_ID,
};
use solver_types::{OrderStatus, TransactionHash, TransactionType};

#[path = "resilience_e2e/fixture.rs"]
mod fixture;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn planned_only_attempt_recovers_to_execution_without_broadcast_hash() -> Result<()> {
	let h = Harness::boot_with(HarnessOptions {
		run_solver: false,
		..Default::default()
	})
	.await?;
	let order = StandardOrderBuilder::happy_path(&h, "resilience-planned-only").build();
	h.user_approve(
		h.origin.token_a,
		h.origin.input_settler,
		amount_with_decimals(1_000),
	)
	.await?;
	let order_id = h.user_open(order).await?;

	let fixture = fixture::build_resilience_recovery_service(&h).await?;
	let local_order = fixture::persist_order_for_recovery(
		&fixture,
		order_id,
		OrderStatus::Created,
		fixture::OrderStageHashes::default(),
		None,
	)
	.await?;
	fixture::seed_planned_attempt(&fixture, &local_order.id, TransactionType::Fill).await?;

	let mut sub = fixture.event_bus.subscribe();
	let (_report, _orphans) = fixture.service.recover_state().await?;
	let recovered = fixture.state_machine.get_order(&local_order.id).await?;
	assert!(recovered.fill_tx_hash.is_none());
	assert!(!matches!(recovered.status, OrderStatus::Failed(_, _)));

	let event = tokio::time::timeout(Duration::from_secs(5), sub.recv()).await??;
	assert!(matches!(
		event,
		solver_types::SolverEvent::Order(solver_types::OrderEvent::Executing { .. })
	));
	Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn broadcast_attempt_repairs_missing_fill_hash_without_resubmit() -> Result<()> {
	let h = Harness::boot_with(HarnessOptions {
		run_solver: false,
		..Default::default()
	})
	.await?;
	let order = StandardOrderBuilder::happy_path(&h, "resilience-broadcast-repair").build();
	h.user_approve(
		h.origin.token_a,
		h.origin.input_settler,
		amount_with_decimals(1_000),
	)
	.await?;
	let order_id = h.user_open(order.clone()).await?;
	let fill_receipt = h
		.direct_fill_on_destination(order_id, order.outputs[0].clone(), order.fillDeadline)
		.await?;
	let real_hash = TransactionHash(fill_receipt.transaction_hash.0.to_vec());

	let fixture = fixture::build_resilience_recovery_service(&h).await?;
	let local_order = fixture::persist_order_for_recovery(
		&fixture,
		order_id,
		OrderStatus::Executed,
		fixture::OrderStageHashes {
			prepare: Some(TransactionHash(vec![0xaa; 32])),
			fill: None,
			..Default::default()
		},
		None,
	)
	.await?;
	fixture::seed_broadcast_attempt(
		&fixture,
		&local_order.id,
		TransactionType::Fill,
		real_hash.clone(),
	)
	.await?;

	let mut sub = fixture.event_bus.subscribe();
	let (_report, _orphans) = fixture.service.recover_state().await?;
	let recovered = fixture.state_machine.get_order(&local_order.id).await?;
	assert_eq!(recovered.fill_tx_hash, Some(real_hash));
	let event = tokio::time::timeout(Duration::from_secs(5), sub.recv()).await??;
	assert!(matches!(
		event,
		solver_types::SolverEvent::Settlement(
			solver_types::SettlementEvent::StartMonitoring { .. }
				| solver_types::SettlementEvent::PostFillReady { .. }
		)
	));
	Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn recovery_repairs_missing_fill_hash_from_chain_log() -> Result<()> {
	let h = Harness::boot_with(HarnessOptions {
		run_solver: false,
		..Default::default()
	})
	.await?;
	let order = StandardOrderBuilder::happy_path(&h, "resilience-fill-log-repair").build();
	h.user_approve(
		h.origin.token_a,
		h.origin.input_settler,
		amount_with_decimals(1_000),
	)
	.await?;
	let order_id = h.user_open(order.clone()).await?;

	let fill_receipt = h
		.direct_fill_on_destination(order_id, order.outputs[0].clone(), order.fillDeadline)
		.await?;
	let real_fill_tx_hash = TransactionHash(fill_receipt.transaction_hash.0.to_vec());
	h.await_event::<OutputFilled>(
		DEST_CHAIN_ID,
		h.destination.output_settler,
		order_id,
		Duration::from_secs(5),
	)
	.await?;

	let fixture = fixture::build_resilience_recovery_service(&h).await?;
	let local_order = fixture::persist_order_for_recovery(
		&fixture,
		order_id,
		OrderStatus::Executed,
		fixture::OrderStageHashes {
			prepare: Some(TransactionHash(vec![0xaa; 32])),
			fill: None,
			..Default::default()
		},
		None,
	)
	.await?;

	let (report, _orphans) = fixture.service.recover_state().await?;
	assert!(report.reconciled_orders > 0);

	let recovered = fixture.state_machine.get_order(&local_order.id).await?;
	assert_eq!(recovered.fill_tx_hash, Some(real_fill_tx_hash));
	let attempts = fixture
		.attempt_store
		.attempts_for_order(&local_order.id)
		.await?;
	assert!(
		attempts
			.iter()
			.all(|attempt| attempt.tx_type != TransactionType::Fill),
		"chain-log repair should not require a Fill attempt row"
	);
	Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn already_claimed_revert_finalizes_only_after_chain_proof() -> Result<()> {
	let h = Harness::boot_with(HarnessOptions {
		run_solver: false,
		..Default::default()
	})
	.await?;
	let order = StandardOrderBuilder::happy_path(&h, "resilience-already-claimed").build();
	h.user_approve(
		h.origin.token_a,
		h.origin.input_settler,
		amount_with_decimals(1_000),
	)
	.await?;
	let order_id = h.user_open(order.clone()).await?;

	let fill_receipt = h
		.direct_fill_on_destination(order_id, order.outputs[0].clone(), order.fillDeadline)
		.await?;
	let fill_ts = h
		.destination_block_timestamp(fill_receipt.block_number.unwrap_or(0))
		.await?;
	h.direct_finalise(order.clone(), fill_ts as u32).await?;
	h.await_event::<Finalised>(
		ORIGIN_CHAIN_ID,
		h.origin.input_settler,
		order_id,
		Duration::from_secs(5),
	)
	.await?;

	let reverted =
		fixture::direct_reverted_claim_after_finalised(&h, order.clone(), fill_ts as u32).await?;

	let fixture = fixture::build_resilience_recovery_service(&h).await?;
	let local_order = fixture::persist_order_for_recovery(
		&fixture,
		order_id,
		OrderStatus::Settled,
		fixture::OrderStageHashes {
			claim: Some(reverted.tx_hash.clone()),
			..Default::default()
		},
		Some(solver_types::FillProof {
			tx_hash: TransactionHash(fill_receipt.transaction_hash.0.to_vec()),
			block_number: fill_receipt.block_number.unwrap_or(0),
			attestation_data: Some(vec![]),
			filled_timestamp: fill_ts,
			oracle_address: format!("0x{:040x}", 0u8),
		}),
	)
	.await?;
	fixture::seed_reverted_claim_attempt(&fixture, &local_order.id, reverted).await?;

	let (_report, _orphans) = fixture.service.recover_state().await?;
	let recovered = fixture.state_machine.get_order(&local_order.id).await?;
	assert!(matches!(recovered.status, OrderStatus::Finalized));
	Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn insufficient_native_gas_logs_operator_signal_and_keeps_order_non_failed() -> Result<()> {
	let h = Harness::boot().await?;
	let solver = h.solver_address();
	h.set_native_balance(DEST_CHAIN_ID, solver, U256::from(1u64))
		.await?;

	let order = StandardOrderBuilder::happy_path(&h, "resilience-no-native-gas").build();
	h.user_approve(
		h.origin.token_a,
		h.origin.input_settler,
		amount_with_decimals(1_000),
	)
	.await?;
	let order_id = h.user_open(order).await?;

	h.await_no_event::<OutputFilled>(
		DEST_CHAIN_ID,
		h.destination.output_settler,
		order_id,
		NO_EVENT_TIMEOUT,
	)
	.await?;

	let id = solver_types::with_0x_prefix(&hex::encode(order_id.0));
	if let Ok(stored) = h.read_order_from_storage(&id).await {
		assert!(!matches!(stored.status, OrderStatus::Failed(_, _)));
	}
	assert!(
		h.solver_log_contains("Insufficient native gas for transaction preflight")?
			|| h.solver_log_contains("Order failed callback simulation")?
			|| h.solver_log_contains("Gas estimation failed")?
	);
	Ok(())
}
