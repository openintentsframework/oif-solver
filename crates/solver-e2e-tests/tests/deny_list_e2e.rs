//! Deny list E2E (PR #308 / `IntentHandler::load_deny_list`).
//!
//! The deny list is a local JSON array of address strings. The solver loads
//! it at startup, lowercases everything, and rejects any intent whose
//! `order.user` or any output `recipient` matches. Rejected intents never
//! reach the fill / settle path — the on-chain `Open` event still appears
//! (the user's tx, not solver-controlled), but the solver does nothing.
//!
//! These tests write a per-test deny list file in the harness's tempdir and
//! assert the rejection happens by waiting for the absence of `OutputFilled`
//! within a short window. Same pattern as `failure_e2e_settlement::*`.
//!
//! Run with:
//!   cargo test -p solver-e2e-tests --test deny_list_e2e -- --ignored --nocapture

use solver_e2e_tests::{
	amount_with_decimals_helper, Harness, HarnessOptions, OutputFilled, StandardOrderBuilder,
	DEST_CHAIN_ID, RECIPIENT_ADDRESS, USER_ADDRESS,
};
use std::time::Duration;

const NO_FILL_TIMEOUT: Duration = Duration::from_secs(10);

/// Sender on deny list → solver rejects the intent before storing/processing.
/// `Open` still fires on-chain because the user's tx already broadcast; the
/// observable signal is the *absence* of `OutputFilled` on destination.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn sender_on_deny_list_intent_rejected() -> anyhow::Result<()> {
	let h = Harness::boot_with(HarnessOptions {
		deny_list_addresses: Some(vec![USER_ADDRESS.to_string()]),
		..Default::default()
	})
	.await?;

	let amount_in = amount_with_decimals_helper(1_000);
	let order = StandardOrderBuilder::happy_path(&h, "e2e-deny-sender")
		.amount_in(amount_in)
		.build();

	h.user_approve(h.origin.token_a, h.origin.input_settler, amount_in)
		.await?;
	let order_id = h.user_open(order).await?;
	eprintln!("Open submitted with denied sender; orderId = {order_id}");

	h.await_no_event::<OutputFilled>(
		DEST_CHAIN_ID,
		h.destination.output_settler,
		order_id,
		NO_FILL_TIMEOUT,
	)
	.await?;
	Ok(())
}

/// Recipient on deny list → solver rejects. Same shape as above; only the
/// matched field differs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn recipient_on_deny_list_intent_rejected() -> anyhow::Result<()> {
	let h = Harness::boot_with(HarnessOptions {
		deny_list_addresses: Some(vec![RECIPIENT_ADDRESS.to_string()]),
		..Default::default()
	})
	.await?;

	let amount_in = amount_with_decimals_helper(1_000);
	let order = StandardOrderBuilder::happy_path(&h, "e2e-deny-recipient")
		.amount_in(amount_in)
		.build();

	h.user_approve(h.origin.token_a, h.origin.input_settler, amount_in)
		.await?;
	let order_id = h.user_open(order).await?;
	eprintln!("Open submitted with denied recipient; orderId = {order_id}");

	h.await_no_event::<OutputFilled>(
		DEST_CHAIN_ID,
		h.destination.output_settler,
		order_id,
		NO_FILL_TIMEOUT,
	)
	.await?;
	Ok(())
}

/// Mixed-case (checksummed) addresses in the deny list still match a
/// lowercase user address. Regression test against any future "preserve
/// case" refactor of `load_deny_list` (which currently lowercases on load).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn deny_list_matches_case_insensitively() -> anyhow::Result<()> {
	// USER_ADDRESS is already mixed-case (checksummed). Pass uppercase to
	// also exercise the upper→lower path explicitly.
	let h = Harness::boot_with(HarnessOptions {
		deny_list_addresses: Some(vec![USER_ADDRESS.to_uppercase()]),
		..Default::default()
	})
	.await?;

	let amount_in = amount_with_decimals_helper(1_000);
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
		NO_FILL_TIMEOUT,
	)
	.await?;
	Ok(())
}
