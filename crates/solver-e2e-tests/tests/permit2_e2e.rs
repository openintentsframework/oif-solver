//! Live E2E for the off-chain Permit2 `openFor()` flow.
//!
//! Differs from `happy_e2e_open_fill_settle` only at the order-entry layer:
//! instead of the user calling `InputSettlerEscrow.open()` directly on chain,
//! the user signs an EIP-712 Permit2 message off-chain and POSTs it to the
//! solver's `/api/v1/orders` HTTP endpoint. The solver then calls
//! `openFor(order, sponsor, signature)` on the input settler, which uses
//! Permit2 to pull the user's tokens. The same `Open(orderId, order)` event
//! fires and the rest of the flow is identical.
//!
//! Run with:
//!   cargo test -p solver-e2e-tests --test permit2_e2e -- --ignored --nocapture

use alloy_primitives::{Bytes, B256, U256};
use alloy_signer::SignerSync;
use solver_e2e_tests::{
	amount_with_decimals_helper, reconstruct_permit2_digest, Finalised, Harness, HarnessOptions,
	OifOrder, OrderPayload, OutputFilled, PostOrderRequest, PostOrderResponseStatus, SignatureType,
	StandardOrderBuilder, DEST_CHAIN_ID, ORIGIN_CHAIN_ID, PERMIT2_ADDRESS, USER_PRIVATE_KEY,
};
use std::str::FromStr;
use std::time::{Duration, Instant};

const FILL_TIMEOUT: Duration = Duration::from_secs(60);
const SETTLE_TIMEOUT: Duration = Duration::from_secs(120);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn permit2_offchain_open_fill_settle() -> anyhow::Result<()> {
	let h = Harness::boot_with(HarnessOptions {
		enable_permit2: true,
		..Default::default()
	})
	.await?;
	let started = Instant::now();
	eprintln!("\n--- STEP 0: Harness booted (Permit2 enabled) ---");

	let user = h.user_address();
	let recipient = h.recipient_address();
	let amount_in = amount_with_decimals_helper(1_000);
	let amount_out = amount_with_decimals_helper(990);

	// (1) Build the same StandardOrder we'd use for a direct `open()` —
	// nothing special about Permit2 at this layer, only how authorization
	// is conveyed.
	let order = StandardOrderBuilder::happy_path(&h, "e2e-permit2")
		.amount_in(amount_in)
		.amount_out(amount_out)
		.build();
	eprintln!("--- STEP 1: StandardOrder built ---");

	// (2) Build the EIP-712 OrderPayload. Field types matter:
	//   - chainId: u64 number
	//   - nonce / deadline / amount: decimal STRINGS (parsed via str::parse)
	//   - expires: u64 number
	//   - addresses: 0x-prefixed strings
	//   - bytes32 (oracle/settler/token/recipient inside MandateOutput): 32-byte
	//     hex strings (left-padded)
	//   - callbackData / context: hex bytes ("0x" for empty)
	// solver-types' `reconstruct_permit2_digest` parses this exact shape
	// — see crates/solver-types/src/utils/eip712.rs:128.
	let nonce_now = unix_millis_now();
	let payload = build_permit2_payload(
		&order,
		nonce_now,
		PERMIT2_ADDRESS,
		amount_in,
		amount_out,
		&h,
		recipient,
	);

	// (3) Compute the EIP-712 digest using the same code the solver server
	// uses on the receiving end. Sign it with the user's key, then prepend
	// the Permit2 scheme byte (0x00) — the solver demuxes signature types
	// off this prefix.
	let user_signer = USER_PRIVATE_KEY
		.parse::<alloy_signer_local::PrivateKeySigner>()
		.expect("static key parses");
	let digest_bytes =
		reconstruct_permit2_digest(&payload).map_err(|e| anyhow::anyhow!("digest: {e}"))?;
	let signature = user_signer
		.sign_hash_sync(&B256::from(digest_bytes))
		.map_err(|e| anyhow::anyhow!("sign: {e}"))?;
	let mut sig_bytes = vec![0x00u8];
	sig_bytes.extend_from_slice(&signature.as_bytes());
	eprintln!(
		"--- STEP 2: Permit2 typed-data signed ({} bytes) ---",
		sig_bytes.len()
	);

	// (4) POST the signed order. The solver receives, validates the
	// signature, forwards through its discovery layer to the intent
	// handler, which eventually calls openFor() on the input settler.
	let request = PostOrderRequest {
		order: OifOrder::OifEscrowV0 { payload },
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

	// The API echoes the orderId the solver reconstructed from our typed-data
	// payload. We use it (rather than computing locally) because `from_permit2`
	// rebuilds the `StandardOrder` with the Permit2 `message.nonce` as the
	// order nonce — different from any value the local
	// `StandardOrderBuilder::happy_path` chooses, so a local
	// `orderIdentifier()` would mismatch the on-chain hash.
	let order_id_str = response
		.order_id
		.as_deref()
		.ok_or_else(|| anyhow::anyhow!("API response missing order_id"))?;
	let order_id = B256::from_str(order_id_str.trim_start_matches("0x"))
		.map_err(|e| anyhow::anyhow!("parse order_id {:?}: {e}", order_id_str))?;
	eprintln!(
		"--- STEP 3: POST /orders accepted ({:?}) — orderId = {order_id} ---",
		response.status
	);

	// (5) Same assertions as the direct happy path. The off-chain entry
	// must produce identical on-chain effects.
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

	// (6) Balances moved correctly.
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
		"\n=== permit2_offchain_open_fill_settle PASSED in {:.1}s ===\n",
		started.elapsed().as_secs_f32()
	);
	Ok(())
}

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

fn unix_millis_now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.expect("clock before unix epoch")
		.as_millis() as u64
}

fn addr_hex(a: alloy_primitives::Address) -> String {
	format!("0x{}", hex::encode(a.as_slice()))
}

fn addr_bytes32_hex(a: alloy_primitives::Address) -> String {
	let mut buf = [0u8; 32];
	buf[12..].copy_from_slice(a.as_slice());
	format!("0x{}", hex::encode(buf))
}

/// Build the `OrderPayload` JSON exactly as `reconstruct_permit2_digest`
/// expects (see solver-types/src/utils/eip712.rs:128 for the parser).
fn build_permit2_payload(
	order: &solver_e2e_tests::StandardOrder,
	nonce_ms: u64,
	permit2_address: &str,
	amount_in: U256,
	amount_out: U256,
	h: &Harness,
	recipient: alloy_primitives::Address,
) -> OrderPayload {
	let domain = serde_json::json!({
		"name": "Permit2",
		"chainId": ORIGIN_CHAIN_ID,
		"verifyingContract": permit2_address,
	});

	let permitted = serde_json::json!([{
		"token": addr_hex(h.origin.token_a),
		"amount": amount_in.to_string(),
	}]);

	let outputs = serde_json::json!([{
		"oracle": addr_bytes32_hex(h.destination.output_oracle),
		"settler": addr_bytes32_hex(h.destination.output_settler),
		"chainId": DEST_CHAIN_ID,
		"token": addr_bytes32_hex(h.destination.token_b),
		"amount": amount_out.to_string(),
		"recipient": addr_bytes32_hex(recipient),
		"callbackData": "0x",
		"context": "0x",
	}]);

	let witness = serde_json::json!({
		"user": addr_hex(h.user_address()),
		"expires": order.expires,
		"inputOracle": addr_hex(h.origin.input_oracle),
		"outputs": outputs,
	});

	let message = serde_json::json!({
		"permitted": permitted,
		"spender": addr_hex(h.origin.input_settler),
		"nonce": nonce_ms.to_string(),
		"deadline": (order.fillDeadline as u64).to_string(),
		"witness": witness,
	});

	OrderPayload {
		signature_type: SignatureType::Eip712,
		domain,
		primary_type: "PermitBatchWitnessTransferFrom".to_string(),
		message,
		types: None,
	}
}
