//! Chain-aware recovery e2e tests.
//!
//! Boot anvil with `run_solver: false` (the live solver loop would race
//! against direct contract calls), deploy the OIF contracts, emit real PR 04
//! events on-chain, and run `RecoveryService::recover_state()` against
//! persisted orders that simulate crash-window data loss. Proves that our
//! `sol!`-computed event signature hashes (topic0) match what the deployed
//! contracts emit — something mockall tests cannot verify.
//!
//! Run with:
//!
//!     cargo test -p solver-e2e-tests --test chain_aware_recovery_e2e -- --ignored

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_primitives::U256;
use anyhow::Result;
use solver_e2e_tests::{
	amount_with_decimals, Finalised, Harness, HarnessOptions, OutputFilled, Refunded,
	StandardOrderBuilder, DEST_CHAIN_ID, ORIGIN_CHAIN_ID,
};

use crate::fixture::{build_recovery_service, persist_order_for_recovery, OrderStageHashes};

// Integration tests are single-file binary crates; resolve the submodule
// explicitly from a co-located subdirectory.
#[path = "chain_aware_recovery_e2e/fixture.rs"]
mod fixture;

/// Must match `StandardOrderBuilder::happy_path` default `amount_in`
/// (`crates/solver-e2e-tests/src/lib.rs` → `amount_with_decimals(1_000)`).
fn input_amount() -> U256 {
	amount_with_decimals(1_000)
}

fn unix_now() -> u32 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.expect("system time before unix epoch")
		.as_secs() as u32
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn chain_aware_recovery_repairs_fill_hash_from_real_output_filled() -> Result<()> {
	let h = Harness::boot_with(HarnessOptions {
		run_solver: false,
		..Default::default()
	})
	.await?;

	// 1. User approves origin TOKA -> InputSettlerEscrow, then opens.
	let order = StandardOrderBuilder::happy_path(&h, "e2e-pr04-fill-repair").build();
	h.user_approve(h.origin.token_a, h.origin.input_settler, input_amount())
		.await?;
	let order_id = h.user_open(order.clone()).await?;

	// 2. Solver fills on destination — emits OutputFilled.
	let fill_receipt = h
		.direct_fill_on_destination(order_id, order.outputs[0].clone(), order.fillDeadline)
		.await?;
	let real_fill_tx_hash = fill_receipt.transaction_hash;

	// 3. Sanity: OutputFilled fired on destination's OutputSettler.
	h.await_event::<OutputFilled>(
		DEST_CHAIN_ID,
		h.destination.output_settler,
		order_id,
		Duration::from_secs(5),
	)
	.await?;

	// 4. Build recovery service + persist a crash-window order
	//    (fill happened on chain but fill_tx_hash is None locally).
	let fixture = build_recovery_service(&h).await?;
	let local_order = persist_order_for_recovery(
		&fixture,
		order_id,
		solver_types::OrderStatus::Executed,
		OrderStageHashes {
			prepare: Some(solver_types::TransactionHash(vec![0xaa; 32])),
			fill: None,
			..Default::default()
		},
		None,
	)
	.await?;

	// 5. Run public recovery.
	let (_report, _orphans) = fixture
		.service
		.recover_state()
		.await
		.expect("recover_state");

	// 6. Assert: PR 04 repaired fill_tx_hash from the chain log.
	let recovered = fixture
		.state_machine
		.get_order(&local_order.id)
		.await
		.expect("get_order");
	let repaired = recovered.fill_tx_hash.expect(
		"PR 04 chain probe must repair fill_tx_hash from the OutputFilled event. \
         If this fails, OutputFilled::SIGNATURE_HASH likely does not match the \
         deployed contract's emitted topic0.",
	);
	assert_eq!(
		repaired.0.as_slice(),
		real_fill_tx_hash.0.as_slice(),
		"Repaired fill tx hash must match the real on-chain tx hash"
	);

	Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn chain_aware_recovery_repairs_claim_hash_from_real_finalised() -> Result<()> {
	let h = Harness::boot_with(HarnessOptions {
		run_solver: false,
		..Default::default()
	})
	.await?;

	let order = StandardOrderBuilder::happy_path(&h, "e2e-pr04-claim-repair").build();
	h.user_approve(h.origin.token_a, h.origin.input_settler, input_amount())
		.await?;
	let order_id = h.user_open(order.clone()).await?;

	// Fill on destination — prerequisite for finalise.
	let fill_receipt = h
		.direct_fill_on_destination(order_id, order.outputs[0].clone(), order.fillDeadline)
		.await?;
	let fill_block_timestamp = h
		.destination_block_timestamp(fill_receipt.block_number.unwrap_or(0))
		.await?;

	// Finalise on origin — emits Finalised. Default AlwaysYesOracle no-ops
	// the proof check, so no Hyperlane setup is required.
	let finalise_receipt = h
		.direct_finalise(order.clone(), fill_block_timestamp as u32)
		.await?;
	let real_claim_tx_hash = finalise_receipt.transaction_hash;

	// Sanity: Finalised fired on origin's InputSettlerEscrow.
	h.await_event::<Finalised>(
		ORIGIN_CHAIN_ID,
		h.origin.input_settler,
		order_id,
		Duration::from_secs(5),
	)
	.await?;

	// Persist crash-window order: claim_tx_hash = None.
	let fixture = build_recovery_service(&h).await?;
	let local_order = persist_order_for_recovery(
		&fixture,
		order_id,
		solver_types::OrderStatus::Settled,
		OrderStageHashes {
			fill: Some(solver_types::TransactionHash(vec![0xbb; 32])),
			claim: None,
			..Default::default()
		},
		// Synthetic fill_proof so the order looks ready for claim.
		Some(solver_types::FillProof {
			tx_hash: solver_types::TransactionHash(vec![0xbb; 32]),
			block_number: 0,
			attestation_data: Some(vec![]),
			filled_timestamp: 0,
			oracle_address: format!("0x{:040x}", 0u8),
		}),
	)
	.await?;

	let (_report, _orphans) = fixture
		.service
		.recover_state()
		.await
		.expect("recover_state");

	let recovered = fixture
		.state_machine
		.get_order(&local_order.id)
		.await
		.expect("get_order");
	let repaired_claim_hash = recovered
		.claim_tx_hash
		.expect("PR 04 chain probe must repair claim_tx_hash from the Finalised event");
	assert_eq!(
		repaired_claim_hash.0.as_slice(),
		real_claim_tx_hash.0.as_slice(),
	);
	assert!(matches!(
		recovered.status,
		solver_types::OrderStatus::Finalized
	));
	Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn chain_aware_recovery_terminates_on_real_refunded_event() -> Result<()> {
	let h = Harness::boot_with(HarnessOptions {
		run_solver: false,
		..Default::default()
	})
	.await?;

	// Build order with FUTURE-but-near expires so `open()` validates,
	// and direct_refund advances Anvil past expires before calling refund.
	let now = unix_now();
	let order = StandardOrderBuilder::happy_path(&h, "e2e-pr04-refund")
		.fill_deadline(now + 30)
		.expires(now + 60)
		.build();
	h.user_approve(h.origin.token_a, h.origin.input_settler, input_amount())
		.await?;
	let order_id = h.user_open(order.clone()).await?;

	// direct_refund advances Anvil past order.expires, then calls refund.
	h.direct_refund(order.clone()).await?;
	h.await_event::<Refunded>(
		ORIGIN_CHAIN_ID,
		h.origin.input_settler,
		order_id,
		Duration::from_secs(5),
	)
	.await?;

	// Persist crash-window order: no fill, no claim hash.
	let fixture = build_recovery_service(&h).await?;
	let local_order = persist_order_for_recovery(
		&fixture,
		order_id,
		solver_types::OrderStatus::Settled,
		OrderStageHashes::default(),
		None,
	)
	.await?;

	let (_report, _orphans) = fixture
		.service
		.recover_state()
		.await
		.expect("recover_state");

	let recovered = fixture
		.state_machine
		.get_order(&local_order.id)
		.await
		.expect("get_order");
	assert!(
		matches!(recovered.status, solver_types::OrderStatus::Failed(_, _)),
		"Refunded event must terminate the order as Failed, got: {:?}",
		recovered.status
	);
	assert_eq!(recovered.claim_tx_hash, None);
	Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn chain_aware_recovery_falls_through_when_no_events_on_chain() -> Result<()> {
	let h = Harness::boot_with(HarnessOptions {
		run_solver: false,
		..Default::default()
	})
	.await?;

	// Open an order but DO nothing else: no fill, no claim, no refund.
	let order = StandardOrderBuilder::happy_path(&h, "e2e-pr04-empty-chain").build();
	h.user_approve(h.origin.token_a, h.origin.input_settler, input_amount())
		.await?;
	let order_id = h.user_open(order.clone()).await?;

	// Sanity: confirm no Finalised / Refunded on origin and no OutputFilled
	// on destination, all keyed by this order_id.
	h.await_no_event::<Finalised>(
		ORIGIN_CHAIN_ID,
		h.origin.input_settler,
		order_id,
		Duration::from_secs(2),
	)
	.await?;
	h.await_no_event::<Refunded>(
		ORIGIN_CHAIN_ID,
		h.origin.input_settler,
		order_id,
		Duration::from_secs(2),
	)
	.await?;
	h.await_no_event::<OutputFilled>(
		DEST_CHAIN_ID,
		h.destination.output_settler,
		order_id,
		Duration::from_secs(2),
	)
	.await?;

	let fixture = build_recovery_service(&h).await?;
	let local_order = persist_order_for_recovery(
		&fixture,
		order_id,
		solver_types::OrderStatus::Created,
		OrderStageHashes::default(),
		None,
	)
	.await?;

	let (_report, _orphans) = fixture
		.service
		.recover_state()
		.await
		.expect("recover_state");

	let recovered = fixture
		.state_machine
		.get_order(&local_order.id)
		.await
		.expect("get_order");
	assert_eq!(recovered.fill_tx_hash, None);
	assert_eq!(recovered.claim_tx_hash, None);
	assert!(!matches!(
		recovered.status,
		solver_types::OrderStatus::Finalized
	));
	assert!(!matches!(
		recovered.status,
		solver_types::OrderStatus::Failed(_, _)
	));
	Ok(())
}
