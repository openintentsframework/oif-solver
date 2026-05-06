//! Hyperlane settlement variant of the happy path. Asserts the solver called
//! `HyperlaneOracle.submit()` during PostFill by reading
//! `MockMailboxV2.dispatchCounter` — the only durable trace tied to the call,
//! since the oracle emits no orderId-bearing event we could correlate.
//!
//! Run with:
//!   cargo test -p solver-e2e-tests --test submit_e2e_hyperlane \
//!       -- --ignored --nocapture

use alloy_primitives::{B256, U256};
use solver_e2e_tests::{
	amount_with_decimals, Finalised, Harness, HarnessOptions, OutputFilled, StandardOrderBuilder,
	DEST_CHAIN_ID, FILL_TIMEOUT, ORIGIN_CHAIN_ID,
};
use std::time::Duration;

// Hyperlane needs more headroom than the standard SETTLE_TIMEOUT — PostFill
// dispatch + finalise involves an extra cross-chain hop.
const HYPERLANE_SETTLE_TIMEOUT: Duration = Duration::from_secs(180);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn solver_submits_via_hyperlane_oracle() -> anyhow::Result<()> {
	let h = Harness::boot_with(HarnessOptions {
		use_hyperlane_settlement: true,
		..Default::default()
	})
	.await?;

	let user = h.user_address();
	let recipient = h.recipient_address();
	let amount_in = amount_with_decimals(1_000);
	let amount_out = amount_with_decimals(990);

	// Sanity: dispatchCounter starts at 0 — also confirms the mock mailbox deployed.
	let dispatch_before = h.destination_mailbox_dispatch_count().await?;
	assert_eq!(dispatch_before, U256::ZERO);

	let order = StandardOrderBuilder::happy_path(&h, "e2e-hyperlane-submit")
		.amount_in(amount_in)
		.amount_out(amount_out)
		.build();
	h.user_approve(h.origin.token_a, h.origin.input_settler, amount_in)
		.await?;
	let order_id: B256 = h.user_open(order).await?;
	tracing::info!(%order_id, "open submitted");

	let (filled, _) = h
		.await_event::<OutputFilled>(
			DEST_CHAIN_ID,
			h.destination.output_settler,
			order_id,
			FILL_TIMEOUT,
		)
		.await?;
	assert_eq!(filled.orderId, order_id);
	assert_eq!(filled.finalAmount, amount_out);

	// Finalised is load-bearing: the solver gates it on PostFill confirmation,
	// so when it fires, submit() has already run.
	let (finalised, _) = h
		.await_event::<Finalised>(
			ORIGIN_CHAIN_ID,
			h.origin.input_settler,
			order_id,
			HYPERLANE_SETTLE_TIMEOUT,
		)
		.await?;
	assert_eq!(finalised.orderId, order_id);

	let dispatch_after = h.destination_mailbox_dispatch_count().await?;
	assert!(
		dispatch_after >= U256::from(1u64),
		"solver did not call HyperlaneOracle.submit() — dispatchCounter is {dispatch_after}"
	);

	let recipient_after = h
		.balance(DEST_CHAIN_ID, h.destination.token_b, recipient)
		.await?;
	let user_after = h.balance(ORIGIN_CHAIN_ID, h.origin.token_a, user).await?;
	assert!(user_after < amount_with_decimals(1_000_000));
	assert!(recipient_after >= amount_out);

	Ok(())
}
