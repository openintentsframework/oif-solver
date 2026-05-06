//! Settlement / fill failure paths.

use alloy_primitives::U256;
use solver_e2e_tests::{
	amount_with_decimals, Finalised, Harness, HarnessOptions, OutputFilled, StandardOrderBuilder,
	DEST_CHAIN_ID, FILL_TIMEOUT, NO_EVENT_TIMEOUT, ORIGIN_CHAIN_ID,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn oracle_not_proven_does_not_finalise() -> anyhow::Result<()> {
	let h = Harness::boot_with(HarnessOptions {
		use_false_oracle: true,
		..Default::default()
	})
	.await?;

	let amount_in = amount_with_decimals(1_000);
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

	let amount_in = amount_with_decimals(1_000);
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
	assert_eq!(after, before);

	Ok(())
}

/// Drains solver's destination ETH after bootstrap so PR #319's
/// `InsufficientNativeGas` preflight fires. The preflight returns before
/// consuming a nonce, so no tx broadcasts and `OutputFilled` never appears.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn solver_native_gas_exhaustion_blocks_fill() -> anyhow::Result<()> {
	let h = Harness::boot().await?;

	let solver = h.solver_address();

	// 1 wei is a valid balance but nowhere near `gas_limit * fee + value`.
	h.set_native_balance(DEST_CHAIN_ID, solver, U256::from(1u64))
		.await?;
	assert_eq!(
		h.native_balance(DEST_CHAIN_ID, solver).await?,
		U256::from(1u64)
	);

	let amount_in = amount_with_decimals(1_000);
	let amount_out = amount_with_decimals(990);
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
	assert_eq!(recipient_after, recipient_before);

	h.await_no_event::<Finalised>(
		ORIGIN_CHAIN_ID,
		h.origin.input_settler,
		order_id,
		NO_EVENT_TIMEOUT,
	)
	.await?;

	Ok(())
}
