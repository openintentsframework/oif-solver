//! Deny list E2E (PR #308 / `IntentHandler::load_deny_list`). The solver
//! lowercases the list at load time, then rejects any intent whose
//! `order.user` or any output `recipient` matches. Rejected intents reach
//! `Open` on-chain but never `OutputFilled`.
//!
//! Run with:
//!   cargo test -p solver-e2e-tests --test deny_list_e2e -- --ignored --nocapture

use solver_e2e_tests::{
	amount_with_decimals, Harness, HarnessOptions, OutputFilled, StandardOrderBuilder,
	DEST_CHAIN_ID, NO_EVENT_TIMEOUT, RECIPIENT_ADDRESS, USER_ADDRESS,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn sender_on_deny_list_intent_rejected() -> anyhow::Result<()> {
	let h = Harness::boot_with(HarnessOptions {
		deny_list_addresses: Some(vec![USER_ADDRESS.to_string()]),
		..Default::default()
	})
	.await?;

	let amount_in = amount_with_decimals(1_000);
	let order = StandardOrderBuilder::happy_path(&h, "e2e-deny-sender")
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
	Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn recipient_on_deny_list_intent_rejected() -> anyhow::Result<()> {
	let h = Harness::boot_with(HarnessOptions {
		deny_list_addresses: Some(vec![RECIPIENT_ADDRESS.to_string()]),
		..Default::default()
	})
	.await?;

	let amount_in = amount_with_decimals(1_000);
	let order = StandardOrderBuilder::happy_path(&h, "e2e-deny-recipient")
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
	Ok(())
}

/// Regression: deny list lowercases at load, so an uppercase entry must still
/// match a lowercase user address.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn deny_list_matches_case_insensitively() -> anyhow::Result<()> {
	let h = Harness::boot_with(HarnessOptions {
		deny_list_addresses: Some(vec![USER_ADDRESS.to_uppercase()]),
		..Default::default()
	})
	.await?;

	let amount_in = amount_with_decimals(1_000);
	let order = StandardOrderBuilder::happy_path(&h, "e2e-deny-case")
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
	Ok(())
}
