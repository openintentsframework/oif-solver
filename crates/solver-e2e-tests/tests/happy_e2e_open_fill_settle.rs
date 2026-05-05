//! Live happy-path E2E with step-by-step verification:
//!   STEP 1  user opens an escrow order on origin chain via `open()`.
//!   STEP 2  solver discovers, decides to execute, fills on destination
//!           via `OutputSettler.fill()`.
//!   STEP 3  solver finalises on origin via `InputSettlerEscrow.finalise()`.
//!   STEP 4  balances on both chains match the expected deltas.
//!
//! Each step verifies:
//!   - The expected event was emitted with the right orderId.
//!   - The transaction that emitted it didn't revert (receipt.status == 1).
//!   - For events carrying decoded fields, the fields match what we sent.
//!
//! Run with:
//!   cargo test -p solver-e2e-tests --test happy_e2e_open_fill_settle \
//!       -- --ignored --nocapture
//!
//! Marked `#[ignore]` because plain `cargo test` shouldn't try to spawn Anvil
//! on every dev machine.

use alloy_primitives::{B256, U256};
use solver_e2e_tests::{
	addr_to_bytes32, addr_to_u256, amount_with_decimals_helper, nonce_from_seed, unix_now_plus,
	Finalised, Harness, MandateOutput, OutputFilled, StandardOrder, DEST_CHAIN_ID,
	ORIGIN_CHAIN_ID,
};
use std::time::{Duration, Instant};

const FILL_TIMEOUT: Duration = Duration::from_secs(60);
const SETTLE_TIMEOUT: Duration = Duration::from_secs(120);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn happy_e2e_open_fill_settle() -> anyhow::Result<()> {
	let h = Harness::boot().await?;
	let started = Instant::now();
	step_header(0, "Harness booted (anvils + contracts + solver)");

	let user = h.user_address();
	let recipient = h.recipient_address();
	let solver = h.solver_address();

	let amount_in = amount_with_decimals_helper(1_000);
	let amount_out = amount_with_decimals_helper(990); // 10 TOKB spread for solver

	let user_in_before = h
		.balance(ORIGIN_CHAIN_ID, h.origin.token_a, user)
		.await?;
	let recipient_out_before = h
		.balance(DEST_CHAIN_ID, h.destination.token_b, recipient)
		.await?;
	let solver_out_before = h
		.balance(DEST_CHAIN_ID, h.destination.token_b, solver)
		.await?;

	eprintln!(
		"  user TOKA on {ORIGIN_CHAIN_ID} = {user_in_before}\n  \
		 recipient TOKB on {DEST_CHAIN_ID} = {recipient_out_before}\n  \
		 solver TOKB on {DEST_CHAIN_ID} = {solver_out_before}"
	);

	// (1) User approves the input settler to spend TOKA.
	let approve_receipt = h
		.user_approve(h.origin.token_a, h.origin.input_settler, amount_in)
		.await?;
	eprintln!(
		"  ERC20 approve tx = {:?} (status={}, gas={})",
		approve_receipt.transaction_hash,
		approve_receipt.status(),
		approve_receipt.gas_used,
	);

	// (1) User submits open() — this is the on-chain signal the solver's
	// discovery service is waiting for.
	let order = StandardOrder {
		user,
		nonce: nonce_from_seed("e2e-happy-1"),
		originChainId: U256::from(ORIGIN_CHAIN_ID),
		expires: unix_now_plus(60 * 60),
		fillDeadline: unix_now_plus(30 * 60),
		inputOracle: h.origin.input_oracle,
		inputs: vec![[addr_to_u256(h.origin.token_a), amount_in]],
		outputs: vec![MandateOutput {
			oracle: addr_to_bytes32(h.destination.output_oracle),
			settler: addr_to_bytes32(h.destination.output_settler),
			chainId: U256::from(DEST_CHAIN_ID),
			token: addr_to_bytes32(h.destination.token_b),
			amount: amount_out,
			recipient: addr_to_bytes32(recipient),
			callbackData: Default::default(),
			context: Default::default(),
		}],
	};

	let (order_id, open_receipt): (B256, _) = h.user_open(order).await?;
	step_header(1, "User Open() on origin");
	eprintln!(
		"  ✓ tx        = {:?}\n  \
		 ✓ status    = {}\n  \
		 ✓ gas_used  = {}\n  \
		 ✓ orderId   = {order_id}",
		open_receipt.transaction_hash,
		open_receipt.status(),
		open_receipt.gas_used,
	);

	// (2) Wait for the solver's destination-side fill. OutputFilled is emitted
	// by OutputSettler.fill(); receipt status verifies the fill tx didn't
	// revert and gives us the gas + tx hash for the diagnostic line.
	let (filled, _filled_log, filled_receipt) = h
		.await_event::<OutputFilled>(
			DEST_CHAIN_ID,
			h.destination.output_settler,
			order_id,
			FILL_TIMEOUT,
		)
		.await?;
	step_header(2, "Solver Fill() on destination");
	eprintln!(
		"  ✓ tx          = {:?}\n  \
		 ✓ status      = {}\n  \
		 ✓ gas_used    = {}\n  \
		 ✓ orderId     = {} (matches Open)\n  \
		 ✓ solver      = {}\n  \
		 ✓ finalAmount = {}",
		filled_receipt.transaction_hash,
		filled_receipt.status(),
		filled_receipt.gas_used,
		filled.orderId,
		filled.solver,
		filled.finalAmount,
	);
	assert_eq!(filled.orderId, order_id, "OutputFilled.orderId mismatch");
	assert_eq!(
		filled.finalAmount, amount_out,
		"OutputFilled.finalAmount mismatch"
	);

	// (3) Wait for the solver's origin-side claim. Finalised is emitted by
	// InputSettlerEscrow.finalise(). The same receipt-status invariant.
	let (finalised, _final_log, finalise_receipt) = h
		.await_event::<Finalised>(
			ORIGIN_CHAIN_ID,
			h.origin.input_settler,
			order_id,
			SETTLE_TIMEOUT,
		)
		.await?;
	step_header(3, "Solver Finalise() on origin");
	eprintln!(
		"  ✓ tx          = {:?}\n  \
		 ✓ status      = {}\n  \
		 ✓ gas_used    = {}\n  \
		 ✓ orderId     = {} (matches Open)\n  \
		 ✓ solver      = {}\n  \
		 ✓ destination = {}",
		finalise_receipt.transaction_hash,
		finalise_receipt.status(),
		finalise_receipt.gas_used,
		finalised.orderId,
		finalised.solver,
		finalised.destination,
	);
	assert_eq!(finalised.orderId, order_id, "Finalised.orderId mismatch");

	// (4) Now that the whole flow has completed, verify the solver actually
	// exercised `HyperlaneOracle.submit()` somewhere between Fill and
	// Finalise. We can't watch a clean event for this — the solver's
	// submit() lands on `MailboxMock.dispatch()` which returns a dummy
	// messageId without emitting an event of its own. Instead we read the
	// mock's `dispatchCounter`: it starts at 0 and increments per dispatch.
	// A non-zero value here is proof the solver called submit() at least
	// once.
	let dispatch_count = h.destination_mailbox_dispatch_count().await?;
	step_header(4, "Solver Submit() on destination output oracle (HyperlaneOracle)");
	eprintln!(
		"  ✓ MailboxMock.dispatchCounter = {dispatch_count} (expected ≥ 1)"
	);
	assert!(
		dispatch_count >= U256::from(1u64),
		"solver did not call HyperlaneOracle.submit() — MailboxMock.dispatchCounter is {dispatch_count}"
	);

	// (5) Balance deltas. These cross-check the event-based assertions: even
	// if all three events fire with the right orderIds, balance moves prove
	// the actual token flow happened.
	let user_in_after = h
		.balance(ORIGIN_CHAIN_ID, h.origin.token_a, user)
		.await?;
	let recipient_out_after = h
		.balance(DEST_CHAIN_ID, h.destination.token_b, recipient)
		.await?;
	let solver_out_after = h
		.balance(DEST_CHAIN_ID, h.destination.token_b, solver)
		.await?;

	step_header(5, "Balance deltas");
	eprintln!(
		"  user TOKA on {ORIGIN_CHAIN_ID}:        -{}\n  \
		 recipient TOKB on {DEST_CHAIN_ID}: +{}\n  \
		 solver TOKB on {DEST_CHAIN_ID}:    -{}",
		user_in_before - user_in_after,
		recipient_out_after - recipient_out_before,
		solver_out_before - solver_out_after,
	);

	assert_eq!(
		user_in_before - user_in_after,
		amount_in,
		"user TOKA delta should equal amount_in"
	);
	assert_eq!(
		recipient_out_after - recipient_out_before,
		amount_out,
		"recipient TOKB delta should equal amount_out"
	);
	assert_eq!(
		solver_out_before - solver_out_after,
		amount_out,
		"solver TOKB delta (the fill) should equal amount_out"
	);

	eprintln!(
		"\n=== happy_e2e_open_fill_settle PASSED in {:.1}s ===\n",
		started.elapsed().as_secs_f32()
	);
	Ok(())
}

fn step_header(n: u32, title: &str) {
	eprintln!("\n--- STEP {n}: {title} ---");
}
