//! C-06 compact-deposit reservation accounting E2E.
//!
//! Validates the engine-side `CompactReservationStore` admission gate: at
//! intent acceptance the engine reserves each input's deposit, and a second
//! order that oversubscribes the same `(chain, owner, token_id)` deposit is
//! rejected inside the engine (via `DiscoveryEvent::IntentRejected` with an
//! "oversubscribed" reason) — even though the stateless HTTP advisory
//! balance check passes for it.
//!
//! ## Why the assertions are on-chain/behavioral, not HTTP-status
//!
//! The reservation gate lives in the ENGINE (`IntentHandler`), NOT the HTTP
//! `/orders` path. The HTTP validator only does a stateless advisory
//! `balanceOf(owner, token_id)` check, which PASSES for an oversubscribing
//! second order: the on-chain Compact deposit balance is unchanged until the
//! origin claim lands, so the balance still looks sufficient. The second
//! order therefore gets an HTTP success ("received") and is rejected
//! ASYNCHRONOUSLY inside the engine, before the order is ever stored.
//!
//! We assert the rejection two ways, both observable from outside the engine:
//!   1. The oversubscribing order is NEVER filled on the destination chain —
//!      `OutputFilled` never appears for its order id, and the shared
//!      recipient's token-B balance only ever increases by the FIRST order's
//!      `amount_out`.
//!   2. The oversubscribing order is never persisted — `GET /orders/{id}`
//!      reports the order is absent (HTTP 400 with `error == "ORDER_NOT_FOUND"`;
//!      the endpoint maps a storage miss to that, not a 404), because the engine
//!      rejects the intent before `store_order` is reached (see
//!      `IntentHandler::process_intent`: the `Err(reason) => IntentRejected` arm
//!      runs before the `should_execute`/`store_order` block).
//!
//! Run with:
//!   cargo test -p solver-e2e-tests --test compact_reservation_e2e -- --ignored --test-threads=1 --nocapture

use alloy_primitives::{keccak256, Bytes, B256, U256};
use alloy_signer::SignerSync;
use solver_e2e_tests::{
	addr_to_bytes32, amount_with_decimals, unix_now_plus, Harness, HarnessOptions, MandateOutput,
	OifOrder, OrderPayload, OutputFilled, PostOrderRequest, PostOrderResponseStatus, SignatureType,
	StandardOrder, DEST_CHAIN_ID, FILL_TIMEOUT, ORIGIN_CHAIN_ID, SOLVER_PRIVATE_KEY,
	USER_PRIVATE_KEY,
};
use solver_types::standards::eip7683::compact_claims::compute_batch_compact_claim_hash;

/// How long to wait while asserting the oversubscribing order is NEVER filled.
/// Generous relative to the happy-path fill latency (a valid order fills well
/// inside `FILL_TIMEOUT`), but bounded so the test still terminates.
const NO_FILL_WINDOW: std::time::Duration = std::time::Duration::from_secs(25);

/// Test 1 — a single Compact deposit admits only ONE of two orders that each
/// draw more than half of it.
///
/// Deposit 1000 once (one token_id). Order 1 draws 600 and must fully fill on
/// the destination chain. Order 2 draws another 600 from the SAME deposit:
/// 600 + 600 = 1200 > 1000, so the engine reservation gate must reject it. We
/// assert order 2 is HTTP-accepted (advisory check passes) but never fills and
/// is never persisted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out with Compact artifacts; opt-in via --ignored"]
async fn compact_deposit_oversubscription_admits_only_one_order() -> anyhow::Result<()> {
	let h = Harness::boot_with(HarnessOptions {
		enable_compact_simple_allocator: true,
		..Default::default()
	})
	.await?;

	// One deposit of 1000 → one token_id. Both orders below draw on it.
	let deposit_amount = amount_with_decimals(1_000);
	let lock_tag = h.compact_lock_tag()?;
	let token_id = h.compact_deposit_user_token_a(deposit_amount).await?;

	let order1_in = amount_with_decimals(600);
	let order1_out = amount_with_decimals(594); // small spread for solver profit
	let order2_in = amount_with_decimals(600);
	let order2_out = amount_with_decimals(594);

	let recipient = h.recipient_address();
	let recipient_before = h
		.balance(DEST_CHAIN_ID, h.destination.token_b, recipient)
		.await?;

	// --- Order 1: fits the deposit (600 ≤ 1000). Must fill. ---
	let order1 = compact_order(&h, token_id, order1_in, order1_out, 1);
	let request1 = build_compact_request(&h, &order1, lock_tag).await?;
	let resp1 = h.submit_post_order(&request1).await?;
	assert_eq!(
		resp1.status,
		PostOrderResponseStatus::Received,
		"order 1 should be accepted at HTTP intake: {resp1:?}"
	);
	let order1_id = order_id_b256(&resp1)?;

	// Wait for order 1's destination fill (the engine reserved 600 of the
	// 1000 deposit at acceptance, then filled on the destination chain).
	let (filled1, _) = h
		.await_event::<OutputFilled>(
			DEST_CHAIN_ID,
			h.destination.output_settler,
			order1_id,
			FILL_TIMEOUT,
		)
		.await?;
	assert_eq!(filled1.orderId, order1_id);
	assert_eq!(filled1.finalAmount, order1_out);

	let recipient_after_order1 = h
		.balance(DEST_CHAIN_ID, h.destination.token_b, recipient)
		.await?;
	assert_eq!(
		recipient_after_order1 - recipient_before,
		order1_out,
		"recipient must receive exactly order 1's amount_out"
	);

	// --- Order 2: same deposit, distinct nonce. 600 + 600 > 1000 deposit. ---
	// The HTTP advisory balanceOf check PASSES for order 2: the on-chain
	// Compact balance is still 1000 (order 1 has not claimed it yet), so the
	// stateless check sees enough. The rejection happens later, in the engine.
	let order2 = compact_order(&h, token_id, order2_in, order2_out, 2);
	let request2 = build_compact_request(&h, &order2, lock_tag).await?;
	let resp2 = h.submit_post_order(&request2).await?;
	assert_eq!(
		resp2.status,
		PostOrderResponseStatus::Received,
		"order 2 should ALSO pass HTTP intake — the advisory balanceOf check \
		 cannot see in-flight reservations, so it admits the oversubscribing \
		 order; the engine rejects it asynchronously: {resp2:?}"
	);
	let order2_id = order_id_b256(&resp2)?;

	// Assert the engine rejected order 2: it never fills on the destination
	// chain within a generous-but-bounded window.
	h.await_no_event::<OutputFilled>(
		DEST_CHAIN_ID,
		h.destination.output_settler,
		order2_id,
		NO_FILL_WINDOW,
	)
	.await?;

	// And the shared recipient's balance has NOT moved beyond order 1's fill —
	// no second fill landed under any order id.
	let recipient_final = h
		.balance(DEST_CHAIN_ID, h.destination.token_b, recipient)
		.await?;
	assert_eq!(
		recipient_final, recipient_after_order1,
		"recipient balance must not increase beyond order 1's fill — the \
		 oversubscribing order must never be filled"
	);

	// The rejected intent is never persisted: the engine emits IntentRejected
	// before `store_order`, so GET /orders/{id} 404s for order 2.
	assert_order_not_found(&h, order2_id).await?;
	// Sanity: order 1 IS retrievable (it was stored and executed), proving the
	// 404 above is specific to the rejected order, not a broken endpoint.
	assert_order_found(&h, order1_id).await?;

	Ok(())
}

/// Test 2 (positive control) — two orders that TOGETHER fit one deposit must
/// BOTH fill. Proves the reservation ledger does not over-reject.
///
/// Deposit 1000; order A draws 400, order B draws 400 (400 + 400 = 800 ≤
/// 1000), distinct nonces. Both reservations must coexist and both orders must
/// fill on the destination chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out with Compact artifacts; opt-in via --ignored"]
async fn compact_deposit_partial_reservations_coexist() -> anyhow::Result<()> {
	let h = Harness::boot_with(HarnessOptions {
		enable_compact_simple_allocator: true,
		..Default::default()
	})
	.await?;

	let deposit_amount = amount_with_decimals(1_000);
	let lock_tag = h.compact_lock_tag()?;
	let token_id = h.compact_deposit_user_token_a(deposit_amount).await?;

	let a_in = amount_with_decimals(400);
	let a_out = amount_with_decimals(396);
	let b_in = amount_with_decimals(400);
	let b_out = amount_with_decimals(396);

	let recipient = h.recipient_address();
	let recipient_before = h
		.balance(DEST_CHAIN_ID, h.destination.token_b, recipient)
		.await?;

	// Submit both before waiting on either, so their reservations are taken
	// against the same live deposit (400 + 400 = 800 ≤ 1000 must both fit).
	let order_a = compact_order(&h, token_id, a_in, a_out, 11);
	let request_a = build_compact_request(&h, &order_a, lock_tag).await?;
	let resp_a = h.submit_post_order(&request_a).await?;
	assert_eq!(resp_a.status, PostOrderResponseStatus::Received);
	let order_a_id = order_id_b256(&resp_a)?;

	let order_b = compact_order(&h, token_id, b_in, b_out, 12);
	let request_b = build_compact_request(&h, &order_b, lock_tag).await?;
	let resp_b = h.submit_post_order(&request_b).await?;
	assert_eq!(resp_b.status, PostOrderResponseStatus::Received);
	let order_b_id = order_id_b256(&resp_b)?;

	// Both must fill — the reservation ledger does not reject non-oversubscribing
	// orders that share a deposit.
	let (filled_a, _) = h
		.await_event::<OutputFilled>(
			DEST_CHAIN_ID,
			h.destination.output_settler,
			order_a_id,
			FILL_TIMEOUT,
		)
		.await?;
	assert_eq!(filled_a.finalAmount, a_out);

	let (filled_b, _) = h
		.await_event::<OutputFilled>(
			DEST_CHAIN_ID,
			h.destination.output_settler,
			order_b_id,
			FILL_TIMEOUT,
		)
		.await?;
	assert_eq!(filled_b.finalAmount, b_out);

	let recipient_after = h
		.balance(DEST_CHAIN_ID, h.destination.token_b, recipient)
		.await?;
	assert_eq!(
		recipient_after - recipient_before,
		a_out + b_out,
		"recipient must receive BOTH orders' amount_out (proves no over-rejection)"
	);

	Ok(())
}

// =============================================================================
// Helpers
//
// Copied (and lightly parameterized for recipient/amounts/nonce) from
// `compact_allocator_e2e.rs`. The e2e crate's pattern is self-contained test
// binaries: each `tests/*.rs` file owns the request-building glue it needs
// (the shared surface is the `Harness` in `src/lib.rs`). These helpers build a
// signed BatchCompact order with VALID allocator data so the order is admitted
// at HTTP intake and the engine reservation gate is the only thing that can
// reject it.
// =============================================================================

fn compact_order(
	h: &Harness,
	token_id: U256,
	amount_in: U256,
	amount_out: U256,
	nonce: u64,
) -> StandardOrder {
	StandardOrder {
		user: h.user_address(),
		nonce: U256::from(nonce),
		originChainId: U256::from(ORIGIN_CHAIN_ID),
		expires: unix_now_plus(60 * 60),
		fillDeadline: unix_now_plus(30 * 60),
		inputOracle: h.origin.input_oracle,
		inputs: vec![[token_id, amount_in]],
		outputs: vec![MandateOutput {
			oracle: addr_to_bytes32(h.destination.output_oracle),
			settler: addr_to_bytes32(h.destination.output_settler),
			chainId: U256::from(DEST_CHAIN_ID),
			token: addr_to_bytes32(h.destination.token_b),
			amount: amount_out,
			recipient: addr_to_bytes32(h.recipient_address()),
			callbackData: Default::default(),
			context: Default::default(),
		}],
	}
}

/// Parse the engine/on-chain order id out of a `PostOrderResponse`.
///
/// For resource-lock orders the discovery service computes the order id via
/// `IInputSettlerCompact.orderIdentifier(order)` and uses `hex::encode` of it
/// as the engine intent id, which it echoes back as `orderId`. That same 32-byte
/// value is the `OutputFilled` topic on the destination chain, so a single
/// parse gives us the key for both event polling and `GET /orders/{id}`.
fn order_id_b256(resp: &solver_e2e_tests::PostOrderResponse) -> anyhow::Result<B256> {
	let raw = resp
		.order_id
		.as_ref()
		.ok_or_else(|| anyhow::anyhow!("response missing orderId: {resp:?}"))?;
	let hex = raw.trim_start_matches("0x");
	let bytes = alloy_primitives::hex::decode(hex)
		.map_err(|e| anyhow::anyhow!("decode orderId {raw}: {e}"))?;
	if bytes.len() != 32 {
		anyhow::bail!("orderId {raw} is {} bytes, expected 32", bytes.len());
	}
	Ok(B256::from_slice(&bytes))
}

/// Assert `GET /orders/{id}` reports the order was never persisted.
///
/// The endpoint maps a storage miss to `GetOrderError::NotFound`, which the API
/// surfaces as HTTP 400 with `error == "ORDER_NOT_FOUND"` (not 404 — see
/// `solver_types::api`'s `From<GetOrderError> for APIError`). We assert on the
/// error type, the load-bearing signal that the order is absent from storage.
async fn assert_order_not_found(h: &Harness, order_id: B256) -> anyhow::Result<()> {
	let (status, body) = get_order(h, order_id).await?;
	assert_eq!(
		status,
		reqwest::StatusCode::BAD_REQUEST,
		"a not-persisted order returns 400 ORDER_NOT_FOUND: GET /orders/{order_id} → {status}, {body}"
	);
	assert_eq!(
		body.get("error").and_then(|v| v.as_str()),
		Some("ORDER_NOT_FOUND"),
		"oversubscribed order must not be persisted: GET /orders/{order_id} body {body}"
	);
	Ok(())
}

/// Assert `GET /orders/{id}` returns 200 — the order was persisted.
async fn assert_order_found(h: &Harness, order_id: B256) -> anyhow::Result<()> {
	let (status, body) = get_order(h, order_id).await?;
	assert_eq!(
		status,
		reqwest::StatusCode::OK,
		"admitted order must be retrievable: GET /orders/{order_id} → {status}, {body}"
	);
	Ok(())
}

async fn get_order(
	h: &Harness,
	order_id: B256,
) -> anyhow::Result<(reqwest::StatusCode, serde_json::Value)> {
	let client = reqwest::Client::builder()
		.no_proxy()
		.timeout(std::time::Duration::from_secs(15))
		.build()?;
	let url = format!("{}/orders/0x{}", h.api_base_url(), hex::encode(order_id));
	let resp = client.get(&url).send().await?;
	let status = resp.status();
	let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
	Ok((status, body))
}

async fn build_compact_request(
	h: &Harness,
	order: &StandardOrder,
	lock_tag: alloy_primitives::FixedBytes<12>,
) -> anyhow::Result<PostOrderRequest> {
	let compact_settler = h
		.origin
		.input_settler_compact
		.ok_or_else(|| anyhow::anyhow!("Compact settler not deployed"))?;
	let claim_hash = compute_batch_compact_claim_hash(order, compact_settler)
		.map_err(|e| anyhow::anyhow!("claim hash: {e}"))?;
	let domain_separator = h.compact_domain_separator().await?;
	let digest = keccak256(
		[
			&[0x19, 0x01][..],
			domain_separator.as_slice(),
			claim_hash.as_slice(),
		]
		.concat(),
	);
	let user_signer = USER_PRIVATE_KEY
		.parse::<alloy_signer_local::PrivateKeySigner>()
		.expect("static key parses");
	let sponsor_signature = user_signer
		.sign_hash_sync(&B256::from(digest))
		.map_err(|e| anyhow::anyhow!("sign sponsor: {e}"))?;

	// Valid allocator data: the harness deploys `SimpleAllocator(signer = SOLVER)`,
	// whose `isClaimAuthorized` verifies `allocatorData` as a `signer` signature
	// over the SAME `0x1901 || domainSeparator || claimHash` digest the sponsor
	// signs. Signing it with the solver key makes the order pass HTTP intake
	// (allocator authorization + advisory balanceOf), leaving the ENGINE
	// reservation gate as the only admission control left to exercise.
	let allocator_signer = SOLVER_PRIVATE_KEY
		.parse::<alloy_signer_local::PrivateKeySigner>()
		.expect("static key parses");
	let allocator_signature = allocator_signer
		.sign_hash_sync(&B256::from(digest))
		.map_err(|e| anyhow::anyhow!("sign allocator: {e}"))?;

	Ok(PostOrderRequest {
		order: OifOrder::OifResourceLockV0 {
			payload: build_compact_payload(h, order, lock_tag)?,
		},
		signature: compact_signature(
			&sponsor_signature.as_bytes(),
			&allocator_signature.as_bytes(),
		),
		quote_id: None,
		origin_submission: None,
	})
}

fn build_compact_payload(
	h: &Harness,
	order: &StandardOrder,
	lock_tag: alloy_primitives::FixedBytes<12>,
) -> anyhow::Result<OrderPayload> {
	Ok(OrderPayload {
		signature_type: SignatureType::Eip712,
		domain: serde_json::json!({
			"name": "BatchCompact",
			"version": "1",
			"chainId": ORIGIN_CHAIN_ID.to_string(),
			"verifyingContract": h.origin.the_compact.expect("TheCompact deployed").to_string(),
		}),
		primary_type: "BatchCompact".to_string(),
		message: serde_json::json!({
			"sponsor": order.user.to_string(),
			"nonce": order.nonce.to_string(),
			"expires": order.expires.to_string(),
			"mandate": {
				"fillDeadline": order.fillDeadline.to_string(),
				"inputOracle": order.inputOracle.to_string(),
				"outputs": [{
					"oracle": format!("0x{}", hex::encode(order.outputs[0].oracle)),
					"settler": format!("0x{}", hex::encode(order.outputs[0].settler)),
					"chainId": order.outputs[0].chainId.to_string(),
					"token": format!("0x{}", hex::encode(order.outputs[0].token)),
					"amount": order.outputs[0].amount.to_string(),
					"recipient": format!("0x{}", hex::encode(order.outputs[0].recipient)),
					"callbackData": "0x",
					"context": "0x"
				}]
			},
			"commitments": [{
				"lockTag": format!("0x{}", hex::encode(lock_tag)),
				"token": h.origin.token_a.to_string(),
				"amount": order.inputs[0][1].to_string()
			}]
		}),
		types: None,
	})
}

fn compact_signature(sponsor_sig: &[u8], allocator_data: &[u8]) -> Bytes {
	let sponsor_tail = padded_bytes(sponsor_sig);
	let allocator_offset = 64 + sponsor_tail.len();

	let mut signature = Vec::new();
	signature.extend_from_slice(&abi_word(64));
	signature.extend_from_slice(&abi_word(allocator_offset));
	signature.extend_from_slice(&sponsor_tail);
	signature.extend_from_slice(&padded_bytes(allocator_data));
	Bytes::from(signature)
}

fn padded_bytes(bytes: &[u8]) -> Vec<u8> {
	let mut encoded = Vec::new();
	encoded.extend_from_slice(&abi_word(bytes.len()));
	encoded.extend_from_slice(bytes);
	let padding = (32 - (bytes.len() % 32)) % 32;
	encoded.extend(std::iter::repeat_n(0u8, padding));
	encoded
}

fn abi_word(value: usize) -> [u8; 32] {
	let mut word = [0u8; 32];
	word[24..32].copy_from_slice(&(value as u64).to_be_bytes());
	word
}
