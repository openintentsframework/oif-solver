//! Live on-chain failure E2E tests.
//!
//! These scenarios exercise failures that should be externally observable
//! without depending on solver-internal state.

use solver_e2e_tests::{
	amount_with_decimals_helper, assert_open_failed, unix_now_plus, Harness, HarnessOptions,
	OutputFilled, StandardOrderBuilder, DEST_CHAIN_ID,
};
use std::time::Duration;

const NO_FILL_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn insufficient_solver_destination_balance_does_not_fill() -> anyhow::Result<()> {
	let h = Harness::boot_with(HarnessOptions {
		solver_token_b_mint: amount_with_decimals_helper(1),
		..Default::default()
	})
	.await?;

	let amount_in = amount_with_decimals_helper(1_000);
	let amount_out = amount_with_decimals_helper(990);
	let order = StandardOrderBuilder::happy_path(&h, "e2e-no-solver-liquidity")
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
		NO_FILL_TIMEOUT,
	)
	.await?;

	Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn expired_order_open_fails() -> anyhow::Result<()> {
	let h = Harness::boot().await?;

	let amount_in = amount_with_decimals_helper(1_000);
	let order = StandardOrderBuilder::happy_path(&h, "e2e-expired-order")
		.amount_in(amount_in)
		.expires(unix_now_plus(0).saturating_sub(10))
		.fill_deadline(unix_now_plus(0).saturating_sub(10))
		.build();

	h.user_approve(h.origin.token_a, h.origin.input_settler, amount_in)
		.await?;
	assert_open_failed(h.user_open_result(order).await, "expired order open");

	Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn insufficient_allowance_open_fails() -> anyhow::Result<()> {
	let h = Harness::boot().await?;

	let order = StandardOrderBuilder::happy_path(&h, "e2e-insufficient-allowance").build();

	assert_open_failed(
		h.user_open_result(order).await,
		"insufficient allowance open",
	);

	Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn insufficient_user_balance_open_fails() -> anyhow::Result<()> {
	let h = Harness::boot_with(HarnessOptions {
		user_token_a_mint: amount_with_decimals_helper(1),
		..Default::default()
	})
	.await?;

	let amount_in = amount_with_decimals_helper(1_000);
	let order = StandardOrderBuilder::happy_path(&h, "e2e-insufficient-user-balance")
		.amount_in(amount_in)
		.build();

	h.user_approve(h.origin.token_a, h.origin.input_settler, amount_in)
		.await?;
	assert_open_failed(
		h.user_open_result(order).await,
		"insufficient user balance open",
	);

	Ok(())
}
