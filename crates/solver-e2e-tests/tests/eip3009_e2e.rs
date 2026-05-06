//! Live E2E for the off-chain EIP-3009 `openFor()` flow.
//!
//! Same shape as `permit2_e2e` but using the token's own EIP-3009
//! `ReceiveWithAuthorization` typed-data instead of Permit2:
//!
//! - **Domain** = the input token's EIP-712 domain (`name: "Token A"`,
//!   `version: "1"`, the token's address as `verifyingContract`). MockERC20
//!   in oif-contracts already implements EIP-3009.
//! - **Primary type** = `ReceiveWithAuthorization`.
//! - **Signature scheme byte** = `0x01` (vs Permit2's `0x00`).
//! - **Metadata** carries the `StandardOrder` reconstruction data — user,
//!   nonce, expires, fillDeadline, inputOracle, inputs, outputs. Tokens,
//!   user, and recipient are encoded as **InteropAddress** (EIP-7930) hex,
//!   not plain `0x...` addresses.
//!
//! The signed authorization's `nonce` field MUST equal the `StandardOrder`
//! orderId — `_openForWithAuthorization` calls
//! `receiveWithAuthorization(..., nonce: orderId, validBefore:
//! fillDeadline, ...)` and the token recovers the signer over those exact
//! fields. To get the orderId before signing, we build a local
//! `StandardOrder` mirroring what the solver's `from_eip3009` parser
//! produces from our metadata, then call the input settler's
//! `orderIdentifier()` view via the harness.
//!
//! Run with:
//!   cargo test -p solver-e2e-tests --test eip3009_e2e -- --ignored --nocapture

use alloy_primitives::{Bytes, B256, U256};
use alloy_signer::SignerSync;
use solver_e2e_tests::{
	addr_to_bytes32, addr_to_u256, amount_with_decimals_helper, reconstruct_eip3009_digest,
	Finalised, Harness, MandateOutput, OifOrder, OrderPayload, OutputFilled, PostOrderRequest,
	PostOrderResponseStatus, SignatureType, StandardOrder, DEST_CHAIN_ID, ORIGIN_CHAIN_ID,
	USER_PRIVATE_KEY,
};
use solver_e2e_tests::InteropAddress;
use std::time::{Duration, Instant};

const FILL_TIMEOUT: Duration = Duration::from_secs(60);
const SETTLE_TIMEOUT: Duration = Duration::from_secs(120);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn eip3009_offchain_open_fill_settle() -> anyhow::Result<()> {
	let h = Harness::boot().await?;
	let started = Instant::now();
	eprintln!("\n--- STEP 0: Harness booted ---");

	let user = h.user_address();
	let recipient = h.recipient_address();
	let amount_in = amount_with_decimals_helper(1_000);
	let amount_out = amount_with_decimals_helper(990);

	// (1) Build the StandardOrder locally with the exact shape the solver's
	// `from_eip3009` parser will reconstruct from our metadata. The orderId
	// is deterministic from these fields, so a local computation matches
	// the solver's. We'll feed it as the EIP-3009 `nonce`.
	let now_secs = unix_secs_now();
	let expires = (now_secs + 60 * 60) as u32;
	let fill_deadline = (now_secs + 30 * 60) as u32;
	let nonce_u64 = now_secs;

	let order = StandardOrder {
		user,
		nonce: U256::from(nonce_u64),
		originChainId: U256::from(ORIGIN_CHAIN_ID),
		expires,
		fillDeadline: fill_deadline,
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
	let order_id = h.compute_order_id(order.clone()).await?;
	eprintln!("--- STEP 1: Local orderId computed = {order_id} ---");

	// (2) Build the EIP-3009 ReceiveWithAuthorization typed-data. Domain is
	// the input TOKEN's domain (MockERC20 uses `EIP712(name, "1")`), not
	// Permit2's. The signed values must match what the input settler will
	// pass to the token in `_openForWithAuthorization`:
	//   from = user (the signer)
	//   to = address(this) = input_settler
	//   value = inputs[0][1] = amount_in
	//   validAfter = 0
	//   validBefore = fillDeadline
	//   nonce = orderId  (NOT a random bytes32 — see contract:296-303)
	let domain = serde_json::json!({
		"name": "Token A",
		"version": "1",
		"chainId": ORIGIN_CHAIN_ID,
		"verifyingContract": format!("0x{}", hex::encode(h.origin.token_a.as_slice())),
	});
	let message = serde_json::json!({
		"from": format!("0x{}", hex::encode(user.as_slice())),
		"to": format!("0x{}", hex::encode(h.origin.input_settler.as_slice())),
		"value": amount_in.to_string(),
		"validAfter": 0u64,
		"validBefore": fill_deadline as u64,
		"nonce": format!("0x{}", hex::encode(order_id.as_slice())),
	});
	let payload = OrderPayload {
		signature_type: SignatureType::Eip712,
		domain,
		primary_type: "ReceiveWithAuthorization".to_string(),
		message,
		types: None,
	};

	// (3) Sign the typed-data digest. EIP-3009 uses the `0x01` scheme prefix.
	let user_signer = USER_PRIVATE_KEY
		.parse::<alloy_signer_local::PrivateKeySigner>()
		.expect("static key parses");
	let digest_bytes = reconstruct_eip3009_digest(&payload, None)
		.map_err(|e| anyhow::anyhow!("digest: {e}"))?;
	let signature = user_signer
		.sign_hash_sync(&B256::from(digest_bytes))
		.map_err(|e| anyhow::anyhow!("sign: {e}"))?;
	let mut sig_bytes = vec![0x01u8];
	sig_bytes.extend_from_slice(&signature.as_bytes());
	eprintln!(
		"--- STEP 2: EIP-3009 ReceiveWithAuthorization signed ({} bytes) ---",
		sig_bytes.len()
	);

	// (4) Build the metadata — the solver's `from_eip3009` parser will use
	// these exact fields to rebuild the StandardOrder. They must match the
	// local `order` above so the on-chain orderId matches what we signed.
	let metadata = serde_json::json!({
		"user": InteropAddress::new_ethereum(ORIGIN_CHAIN_ID, user).to_hex(),
		"nonce": nonce_u64,
		"expires": expires as u64,
		"fillDeadline": fill_deadline as u64,
		"inputOracle": format!("0x{}", hex::encode(h.origin.input_oracle.as_slice())),
		"inputs": [{
			"chainId": ORIGIN_CHAIN_ID,
			"asset": InteropAddress::new_ethereum(ORIGIN_CHAIN_ID, h.origin.token_a).to_hex(),
			"amount": amount_in.to_string(),
		}],
		"outputs": [{
			"chainId": DEST_CHAIN_ID,
			"asset": InteropAddress::new_ethereum(DEST_CHAIN_ID, h.destination.token_b).to_hex(),
			"amount": amount_out.to_string(),
			"receiver": InteropAddress::new_ethereum(DEST_CHAIN_ID, recipient).to_hex(),
			"oracle": format!("0x{}", hex::encode(h.destination.output_oracle.as_slice())),
			"settler": format!("0x{}", hex::encode(h.destination.output_settler.as_slice())),
		}],
	});

	// (5) POST. Solver verifies the EIP-3009 signature against the token's
	// domain, then reconstructs the StandardOrder from metadata and calls
	// `openFor(order, sponsor=user, signature)`. The InputSettlerEscrow's
	// EIP-3009 path consumes the sig to pull the user's tokens via
	// `receiveWithAuthorization`.
	let request = PostOrderRequest {
		order: OifOrder::Oif3009V0 { payload, metadata },
		signature: Bytes::from(sig_bytes),
		quote_id: None,
		origin_submission: None,
	};
	let response = h.submit_post_order(&request).await?;
	assert_eq!(
		response.status,
		PostOrderResponseStatus::Received,
		"solver must accept the order; got {:?}: {:?}",
		response.status,
		response.message
	);
	eprintln!(
		"--- STEP 3: POST /orders accepted ({:?}) ---",
		response.status
	);

	// (6) Watch the chain — same assertions as the Permit2 path.
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
	eprintln!("--- STEP 4: OutputFilled observed ---");

	let (finalised, _) = h
		.await_event::<Finalised>(
			ORIGIN_CHAIN_ID,
			h.origin.input_settler,
			order_id,
			SETTLE_TIMEOUT,
		)
		.await?;
	assert_eq!(finalised.orderId, order_id);
	eprintln!("--- STEP 5: Finalised observed ---");

	let user_after = h.balance(ORIGIN_CHAIN_ID, h.origin.token_a, user).await?;
	let recipient_after = h
		.balance(DEST_CHAIN_ID, h.destination.token_b, recipient)
		.await?;
	assert!(
		user_after < amount_with_decimals_helper(1_000_000),
		"user TOKA on origin should have decreased"
	);
	assert!(
		recipient_after >= amount_out,
		"recipient TOKB on destination should have received at least amount_out"
	);

	eprintln!(
		"\n=== eip3009_offchain_open_fill_settle PASSED in {:.1}s ===\n",
		started.elapsed().as_secs_f32()
	);
	Ok(())
}

fn unix_secs_now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.expect("clock before unix epoch")
		.as_secs()
}
