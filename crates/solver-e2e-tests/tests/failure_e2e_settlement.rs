//! Live settlement/fill failure E2E tests.

use solver_e2e_tests::{
	amount_with_decimals_helper, Finalised, Harness, HarnessOptions, OutputFilled,
	StandardOrderBuilder, DEST_CHAIN_ID, ORIGIN_CHAIN_ID,
};
use std::time::Duration;

const FILL_TIMEOUT: Duration = Duration::from_secs(60);
const NO_EVENT_TIMEOUT: Duration = Duration::from_secs(10);

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
