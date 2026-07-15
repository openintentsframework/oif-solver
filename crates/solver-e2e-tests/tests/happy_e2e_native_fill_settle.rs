//! Native-ETH output happy path: user calls `open()` with an ERC20 (TOKA)
//! input, the solver fills a NATIVE ETH output (token = zero address) with
//! attached `msg.value`, then settles/claims on origin.
//!
//! This is the native-output counterpart to `happy_e2e_open_fill_settle`:
//! the input leg is unchanged (ERC20 TOKA, user approve + on-chain `open()`),
//! only the destination OUTPUT switches to native. The all-zero `bytes32`
//! `MandateOutput.token` is the sentinel the contract's `OutputSettlerBase._fill`
//! treats as native (`tokenIdentifier == bytes32(0)` -> `Address.sendValue`).
//!
//! Run with:
//!   cargo test -p solver-e2e-tests --test happy_e2e_native_fill_settle \
//!       -- --ignored --nocapture

use alloy_primitives::{Address, B256};
use solver_e2e_tests::{
	amount_with_decimals, Finalised, Harness, OutputFilled, StandardOrderBuilder, DEST_CHAIN_ID,
	FILL_TIMEOUT, ORIGIN_CHAIN_ID, SETTLE_TIMEOUT,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn happy_e2e_native_fill_settle() -> anyhow::Result<()> {
	let h = Harness::boot().await?;

	let user = h.user_address();
	let recipient = h.recipient_address();
	let solver = h.solver_address();

	// Input leg stays ERC20 TOKA (mock price $20 -> $20,000 of input value).
	// Output leg is NATIVE ETH: at the mock ETH price ($4,615.16), 1 ETH is
	// ~$4,615, leaving a very wide (~77%) spread so the fill clears the
	// profitability gate comfortably (the ERC20 template runs at ~50%).
	let amount_in = amount_with_decimals(1_000);
	let amount_out = amount_with_decimals(1); // 1 ETH, native output

	let user_in_before = h.balance(ORIGIN_CHAIN_ID, h.origin.token_a, user).await?;
	let recipient_native_before = h.native_balance(DEST_CHAIN_ID, recipient).await?;
	let solver_native_before = h.native_balance(DEST_CHAIN_ID, solver).await?;

	h.user_approve(h.origin.token_a, h.origin.input_settler, amount_in)
		.await?;

	// Only the OUTPUT changes vs the ERC20 template: token = zero address
	// (native sentinel) and a smaller amount to keep the trade profitable.
	let order = StandardOrderBuilder::happy_path(&h, "e2e-native-1")
		.amount_out(amount_out)
		.output_token(Address::ZERO)
		.build();
	let order_id: B256 = h.user_open(order).await?;
	tracing::info!(%order_id, "Open submitted (native output)");

	// OutputFilled is token-agnostic; assert it fired for our order with the
	// requested amount.
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
	let recipient_native_after = h.native_balance(DEST_CHAIN_ID, recipient).await?;
	let solver_native_after = h.native_balance(DEST_CHAIN_ID, solver).await?;

	// User paid the full ERC20 input on origin.
	assert_eq!(user_in_before - user_in_after, amount_in);

	// Recipient received EXACTLY amount_out in native ETH: the recipient is a
	// passive account that submits no transaction, so it pays no gas -> the
	// delta is a clean equality.
	assert_eq!(
		recipient_native_after - recipient_native_before,
		amount_out,
		"recipient native delta must equal amount_out"
	);

	// The solver funded the native output (plus gas) out of its own balance.
	// We do NOT assert an exact solver delta: the solver pays destination gas
	// and the settler refunds any excess `msg.value`, so only a lower bound is
	// meaningful.
	assert!(
		solver_native_before - solver_native_after >= amount_out,
		"solver must have spent at least amount_out in native ETH"
	);

	Ok(())
}
