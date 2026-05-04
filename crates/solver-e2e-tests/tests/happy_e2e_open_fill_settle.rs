//! Live happy-path E2E:
//!   1. Spawn two Anvils (31337 = origin, 31338 = destination).
//!   2. Deploy MockERC20 × 2 + AlwaysYesOracle + InputSettlerEscrow +
//!      OutputSettlerSimple on each chain.
//!   3. Spawn the `solver` binary against the freshly-deployed addresses.
//!   4. As the user: approve + call `open(StandardOrder)` on origin.
//!   5. Assert the solver fills on destination (`OutputFilled` event with
//!      matching orderId).
//!   6. Assert the solver settles on origin (`Finalised` event with matching
//!      orderId).
//!   7. Assert balances moved consistently.
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
use std::time::Duration;

const FILL_TIMEOUT: Duration = Duration::from_secs(60);
const SETTLE_TIMEOUT: Duration = Duration::from_secs(120);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn happy_e2e_open_fill_settle() -> anyhow::Result<()> {
	let h = Harness::boot().await?;

	let user = h.user_address();
	let recipient = h.recipient_address();
	let solver = h.solver_address();

	let amount_in = amount_with_decimals_helper(1_000);
	let amount_out = amount_with_decimals_helper(990); // small spread for solver profit

	// (a) Snapshot balances before. We assert against these at the end.
	let user_in_before = h
		.balance(ORIGIN_CHAIN_ID, h.origin.token_a, user)
		.await?;
	let recipient_out_before = h
		.balance(DEST_CHAIN_ID, h.destination.token_b, recipient)
		.await?;
	let solver_out_before = h
		.balance(DEST_CHAIN_ID, h.destination.token_b, solver)
		.await?;

	// (b) User approves InputSettlerEscrow on origin chain. Standard ERC20
	// approve — no Permit2, no signature off-chain.
	h.user_approve(h.origin.token_a, h.origin.input_settler, amount_in)
		.await?;

	// (c) Build the StandardOrder. orderId is deterministic from these fields,
	// so we'll match it against the Open event the call emits.
	let order = StandardOrder {
		user,
		nonce: nonce_from_seed("e2e-happy-1"),
		originChainId: U256::from(ORIGIN_CHAIN_ID),
		expires: unix_now_plus(60 * 60),       // 1h
		fillDeadline: unix_now_plus(30 * 60),  // 30m
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

	// (d) Submit open(). The receipt's Open event yields the orderId we'll
	// chase across the next two events.
	let order_id: B256 = h.user_open(order).await?;
	eprintln!("Open submitted; orderId = {order_id}");

	// (e) Wait for the destination fill. OutputFilled is the cross-chain
	// signal that the solver picked up the intent and executed it.
	let (filled, _filled_log) = h
		.await_event::<OutputFilled>(
			DEST_CHAIN_ID,
			h.destination.output_settler,
			order_id,
			FILL_TIMEOUT,
		)
		.await?;
	assert_eq!(
		filled.orderId, order_id,
		"OutputFilled.orderId must match our Open"
	);
	assert_eq!(
		filled.finalAmount, amount_out,
		"OutputFilled.finalAmount must match the order's MandateOutput.amount"
	);
	eprintln!(
		"OutputFilled observed on chain {DEST_CHAIN_ID} (final={}, solver={})",
		filled.finalAmount, filled.solver
	);

	// (f) Wait for the origin claim. Finalised is the signal that the solver
	// completed the round trip and was paid the input asset.
	let (finalised, _final_log) = h
		.await_event::<Finalised>(
			ORIGIN_CHAIN_ID,
			h.origin.input_settler,
			order_id,
			SETTLE_TIMEOUT,
		)
		.await?;
	assert_eq!(
		finalised.orderId, order_id,
		"Finalised.orderId must match our Open"
	);
	eprintln!("Finalised observed on chain {ORIGIN_CHAIN_ID}");

	// (g) Balance assertions — sanity bound on the event-based assertion.
	let user_in_after = h
		.balance(ORIGIN_CHAIN_ID, h.origin.token_a, user)
		.await?;
	let recipient_out_after = h
		.balance(DEST_CHAIN_ID, h.destination.token_b, recipient)
		.await?;
	let solver_out_after = h
		.balance(DEST_CHAIN_ID, h.destination.token_b, solver)
		.await?;

	assert_eq!(
		user_in_before - user_in_after,
		amount_in,
		"user TOKA on origin should have decreased by exactly amount_in"
	);
	assert_eq!(
		recipient_out_after - recipient_out_before,
		amount_out,
		"recipient TOKB on destination should have increased by exactly amount_out"
	);
	assert_eq!(
		solver_out_before - solver_out_after,
		amount_out,
		"solver TOKB on destination should have decreased by exactly amount_out (the fill)"
	);

	Ok(())
}
