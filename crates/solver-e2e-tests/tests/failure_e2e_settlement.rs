//! Live settlement/fill failure E2E tests.

use alloy_primitives::U256;
use solver_e2e_tests::{
	amount_with_decimals_helper, Finalised, Harness, HarnessOptions, OutputFilled,
	StandardOrderBuilder, DEST_CHAIN_ID, ORIGIN_CHAIN_ID,
};
use std::time::Duration;

const FILL_TIMEOUT: Duration = Duration::from_secs(60);
const NO_EVENT_TIMEOUT: Duration = Duration::from_secs(15);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn oracle_not_proven_does_not_finalise() -> anyhow::Result<()> {
	let h = Harness::boot_with(HarnessOptions {
		use_false_oracle: true,
		..Default::default()
	})
	.await?;

	let amount_in = amount_with_decimals_helper(1_000);
	let order = StandardOrderBuilder::happy_path(&h, "e2e-false-oracle")
		.amount_in(amount_in)
		.build();

	h.user_approve(h.origin.token_a, h.origin.input_settler, amount_in)
		.await?;
	let order_id = h.user_open(order).await?;

	h.await_event::<OutputFilled>(
		DEST_CHAIN_ID,
		h.destination.output_settler,
		order_id,
		FILL_TIMEOUT,
	)
	.await?;
	h.await_no_event::<Finalised>(
		ORIGIN_CHAIN_ID,
		h.origin.input_settler,
		order_id,
		NO_EVENT_TIMEOUT,
	)
	.await?;

	Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn destination_fill_revert_does_not_emit_output_filled() -> anyhow::Result<()> {
	let h = Harness::boot_with(HarnessOptions {
		use_reverting_output_settler: true,
		..Default::default()
	})
	.await?;

	let amount_in = amount_with_decimals_helper(1_000);
	let recipient = h.recipient_address();
	let before = h
		.balance(DEST_CHAIN_ID, h.destination.token_b, recipient)
		.await?;
	let order = StandardOrderBuilder::happy_path(&h, "e2e-fill-revert")
		.amount_in(amount_in)
		.build();

	h.user_approve(h.origin.token_a, h.origin.input_settler, amount_in)
		.await?;
	let order_id = h.user_open(order).await?;

	h.await_no_event::<OutputFilled>(
		DEST_CHAIN_ID,
		h.destination.output_settler,
		order_id,
		NO_EVENT_TIMEOUT,
	)
	.await?;
	h.await_no_event::<Finalised>(
		ORIGIN_CHAIN_ID,
		h.origin.input_settler,
		order_id,
		NO_EVENT_TIMEOUT,
	)
	.await?;

	let after = h
		.balance(DEST_CHAIN_ID, h.destination.token_b, recipient)
		.await?;
	assert_eq!(
		after, before,
		"recipient balance must not change when fill reverts"
	);

	Ok(())
}

/// Solver runs out of native gas (ETH) on the destination chain → fill never
/// broadcasts → no `OutputFilled`, recipient balance unchanged.
///
/// Exercises `AlloyDelivery::submit`'s `InsufficientNativeGas` preflight from
/// PR #319. We let the harness boot normally (so the bootstrap token
/// approvals on destination succeed using the default 10000 ETH balance),
/// then drain the solver's destination ETH via `anvil_setBalance` to a value
/// way below `gas_limit * fee_per_gas + value`. When the user's Open lands,
/// the solver's strategy will decide to execute and the delivery layer will
/// reject the submission before consuming a nonce.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn solver_native_gas_exhaustion_blocks_fill() -> anyhow::Result<()> {
	let h = Harness::boot().await?;

	let solver = h.solver_address();
	let before = h.native_balance(DEST_CHAIN_ID, solver).await?;
	eprintln!("solver destination ETH before drain: {before}");

	// One wei: enough to be a valid balance but nowhere near a fill's
	// `gas_limit * fee + value`. Anvil's default fee schedule means even a
	// trivial tx requires a few hundred thousand wei minimum.
	h.set_native_balance(DEST_CHAIN_ID, solver, U256::from(1u64))
		.await?;
	let after = h.native_balance(DEST_CHAIN_ID, solver).await?;
	assert_eq!(after, U256::from(1u64), "anvil_setBalance must take effect");

	let amount_in = amount_with_decimals_helper(1_000);
	let amount_out = amount_with_decimals_helper(990);
	let recipient = h.recipient_address();
	let recipient_before = h
		.balance(DEST_CHAIN_ID, h.destination.token_b, recipient)
		.await?;

	let order = StandardOrderBuilder::happy_path(&h, "e2e-no-gas")
		.amount_in(amount_in)
		.amount_out(amount_out)
		.build();
	h.user_approve(h.origin.token_a, h.origin.input_settler, amount_in)
		.await?;
	let order_id = h.user_open(order).await?;
	eprintln!("Open submitted; orderId = {order_id}");

	// Solver must not have filled. The InsufficientNativeGas error path
	// returns before consuming a nonce, so no tx broadcasts. We give a
	// generous window because the solver may re-evaluate the order.
	h.await_no_event::<OutputFilled>(
		DEST_CHAIN_ID,
		h.destination.output_settler,
		order_id,
		NO_EVENT_TIMEOUT,
	)
	.await?;

	let recipient_after = h
		.balance(DEST_CHAIN_ID, h.destination.token_b, recipient)
		.await?;
	assert_eq!(
		recipient_after, recipient_before,
		"recipient TOKB on destination must not change when solver can't pay gas"
	);

	// Symmetric: no claim either.
	h.await_no_event::<Finalised>(
		ORIGIN_CHAIN_ID,
		h.origin.input_settler,
		order_id,
		NO_EVENT_TIMEOUT,
	)
	.await?;

	Ok(())
}
