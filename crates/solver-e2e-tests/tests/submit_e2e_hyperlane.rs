//! Live E2E that exercises the solver's PostFill submit() path.
//!
//! Same shape as `happy_e2e_open_fill_settle` but with `settlement.type =
//! hyperlane`: the solver fills on destination, then dispatches a real
//! `HyperlaneOracle.submit(...)` against a `MockMailboxV2` we deploy on the
//! destination chain. We assert this happened by reading the mock mailbox's
//! `dispatchCounter`. The cross-chain message is never relayed — we don't
//! care about the bridge protocol itself, only that the solver actually
//! exercises its post-fill submit code path.
//!
//! Origin still uses `AlwaysYesOracle` for its input role so `finalise()`
//! succeeds without needing a real proof to land.
//!
//! Run with:
//!   cargo test -p solver-e2e-tests --test submit_e2e_hyperlane \
//!       -- --ignored --nocapture

use alloy_primitives::{B256, U256};
use solver_e2e_tests::{
	amount_with_decimals_helper, Finalised, Harness, HarnessOptions, OutputFilled,
	StandardOrderBuilder, DEST_CHAIN_ID, ORIGIN_CHAIN_ID,
};
use std::time::{Duration, Instant};

const FILL_TIMEOUT: Duration = Duration::from_secs(60);
const SETTLE_TIMEOUT: Duration = Duration::from_secs(180);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn solver_submits_via_hyperlane_oracle() -> anyhow::Result<()> {
	let h = Harness::boot_with(HarnessOptions {
		use_hyperlane_settlement: true,
		..Default::default()
	})
	.await?;
	let started = Instant::now();
	eprintln!("\n--- STEP 0: Harness booted (Hyperlane settlement) ---");

	let user = h.user_address();
	let recipient = h.recipient_address();

	let amount_in = amount_with_decimals_helper(1_000);
	let amount_out = amount_with_decimals_helper(990);

	// Pre-flight: dispatchCounter must start at 0. This is also a sanity
	// check that the mock mailbox actually deployed.
	let dispatch_before = h.destination_mailbox_dispatch_count().await?;
	assert_eq!(
		dispatch_before,
		U256::ZERO,
		"MockMailboxV2.dispatchCounter must start at 0"
	);

	// (1) User opens the order.
	let order = StandardOrderBuilder::happy_path(&h, "e2e-hyperlane-submit")
		.amount_in(amount_in)
		.amount_out(amount_out)
		.build();
	h.user_approve(h.origin.token_a, h.origin.input_settler, amount_in)
		.await?;
	let order_id: B256 = h.user_open(order).await?;
	eprintln!("--- STEP 1: open() submitted, orderId = {order_id} ---");

	// (2) Solver fills on destination.
	let (filled, fill_log) = h
		.await_event::<OutputFilled>(
			DEST_CHAIN_ID,
			h.destination.output_settler,
			order_id,
			FILL_TIMEOUT,
		)
		.await?;
	assert_eq!(filled.orderId, order_id);
	assert_eq!(filled.finalAmount, amount_out);
	eprintln!("--- STEP 2: OutputFilled (tx={:?}) ---", fill_log.transaction_hash);

	// (3) Solver finalises on origin. This is the load-bearing wait — by the
	// time Finalised fires, the PostFill submit() must have completed (the
	// solver gates Finalise on PostFill confirmation).
	let (finalised, finalise_log) = h
		.await_event::<Finalised>(
			ORIGIN_CHAIN_ID,
			h.origin.input_settler,
			order_id,
			SETTLE_TIMEOUT,
		)
		.await?;
	assert_eq!(finalised.orderId, order_id);
	eprintln!(
		"--- STEP 3: Finalised (tx={:?}) ---",
		finalise_log.transaction_hash
	);

	// (4) The actual reason this test exists: prove the solver called
	// HyperlaneOracle.submit() during PostFill. The mock mailbox's
	// dispatchCounter is the durable on-chain trace of that call — there's
	// no oracle-local event that carries the orderId we could correlate
	// against, so this counter check is the cleanest assertion available.
	let dispatch_after = h.destination_mailbox_dispatch_count().await?;
	eprintln!(
		"--- STEP 4: MockMailboxV2.dispatchCounter = {dispatch_after} (was {dispatch_before}) ---"
	);
	assert!(
		dispatch_after >= U256::from(1u64),
		"solver did not call HyperlaneOracle.submit() — \
		 dispatchCounter is {dispatch_after}"
	);

	// (5) Sanity bound: balances moved correctly. Same checks as the Direct
	// happy path; switching settlement type shouldn't change the user-facing
	// outcome.
	let recipient_after = h
		.balance(DEST_CHAIN_ID, h.destination.token_b, recipient)
		.await?;
	let user_after = h.balance(ORIGIN_CHAIN_ID, h.origin.token_a, user).await?;
	assert!(
		user_after < amount_with_decimals_helper(1_000_000),
		"user TOKA on origin should have decreased"
	);
	assert!(
		recipient_after >= amount_out,
		"recipient TOKB on destination should have received at least amount_out"
	);

	eprintln!(
		"\n=== solver_submits_via_hyperlane_oracle PASSED in {:.1}s ===\n",
		started.elapsed().as_secs_f32()
	);
	Ok(())
}
