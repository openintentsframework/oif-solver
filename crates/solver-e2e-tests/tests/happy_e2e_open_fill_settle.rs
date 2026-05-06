//! Direct on-chain happy path: user calls `open()`, solver fills, solver claims.
//!
//! Run with:
//!   cargo test -p solver-e2e-tests --test happy_e2e_open_fill_settle \
//!       -- --ignored --nocapture

use alloy_primitives::B256;
use solver_e2e_tests::{
	amount_with_decimals, Finalised, Harness, OutputFilled, StandardOrderBuilder, DEST_CHAIN_ID,
	FILL_TIMEOUT, ORIGIN_CHAIN_ID, SETTLE_TIMEOUT,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn happy_e2e_open_fill_settle() -> anyhow::Result<()> {
	let h = Harness::boot().await?;

	let user = h.user_address();
	let recipient = h.recipient_address();
	let solver = h.solver_address();

	let amount_in = amount_with_decimals(1_000);
	let amount_out = amount_with_decimals(990); // small spread for solver profit

	let user_in_before = h.balance(ORIGIN_CHAIN_ID, h.origin.token_a, user).await?;
	let recipient_out_before = h
		.balance(DEST_CHAIN_ID, h.destination.token_b, recipient)
		.await?;
	let solver_out_before = h
		.balance(DEST_CHAIN_ID, h.destination.token_b, solver)
		.await?;

	h.user_approve(h.origin.token_a, h.origin.input_settler, amount_in)
		.await?;

	let order = StandardOrderBuilder::happy_path(&h, "e2e-happy-1").build();
	let order_id: B256 = h.user_open(order).await?;
	tracing::info!(%order_id, "Open submitted");

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

	let (finalised, _) = h
		.await_event::<Finalised>(
			ORIGIN_CHAIN_ID,
			h.origin.input_settler,
			order_id,
			SETTLE_TIMEOUT,
		)
		.await?;
	assert_eq!(finalised.orderId, order_id);

	let user_in_after = h.balance(ORIGIN_CHAIN_ID, h.origin.token_a, user).await?;
	let recipient_out_after = h
		.balance(DEST_CHAIN_ID, h.destination.token_b, recipient)
		.await?;
	let solver_out_after = h
		.balance(DEST_CHAIN_ID, h.destination.token_b, solver)
		.await?;

	assert_eq!(user_in_before - user_in_after, amount_in);
	assert_eq!(recipient_out_after - recipient_out_before, amount_out);
	assert_eq!(solver_out_before - solver_out_after, amount_out);

	Ok(())
}
