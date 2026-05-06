//! Off-chain Permit2 `openFor()` flow. The user signs a Permit2 EIP-712
//! `PermitBatchWitnessTransferFrom` and POSTs to `/api/v1/orders`; the solver
//! calls `openFor(order, sponsor, signature)` with scheme byte `0x00`.
//!
//! Run with:
//!   cargo test -p solver-e2e-tests --test permit2_e2e -- --ignored --nocapture

use alloy_primitives::{Bytes, B256, U256};
use alloy_signer::SignerSync;
use solver_e2e_tests::{
	amount_with_decimals, reconstruct_permit2_digest, unix_now_millis, Finalised, Harness,
	HarnessOptions, OifOrder, OrderPayload, OutputFilled, PostOrderRequest,
	PostOrderResponseStatus, SignatureType, StandardOrderBuilder, DEST_CHAIN_ID, FILL_TIMEOUT,
	ORIGIN_CHAIN_ID, PERMIT2_ADDRESS, SETTLE_TIMEOUT, USER_PRIVATE_KEY,
};
use std::str::FromStr;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn permit2_offchain_open_fill_settle() -> anyhow::Result<()> {
	let h = Harness::boot_with(HarnessOptions {
		enable_permit2: true,
		..Default::default()
	})
	.await?;

	let user = h.user_address();
	let recipient = h.recipient_address();
	let amount_in = amount_with_decimals(1_000);
	let amount_out = amount_with_decimals(990);

	let order = StandardOrderBuilder::happy_path(&h, "e2e-permit2")
		.amount_in(amount_in)
		.amount_out(amount_out)
		.build();

	let payload = build_permit2_payload(
		&order,
		unix_now_millis(),
		PERMIT2_ADDRESS,
		amount_in,
		amount_out,
		&h,
		recipient,
	);

	let user_signer = USER_PRIVATE_KEY
		.parse::<alloy_signer_local::PrivateKeySigner>()
		.expect("static key parses");
	let digest_bytes =
		reconstruct_permit2_digest(&payload).map_err(|e| anyhow::anyhow!("digest: {e}"))?;
	let signature = user_signer
		.sign_hash_sync(&B256::from(digest_bytes))
		.map_err(|e| anyhow::anyhow!("sign: {e}"))?;
	let mut sig_bytes = vec![0x00u8]; // Permit2 scheme prefix
	sig_bytes.extend_from_slice(&signature.as_bytes());

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

	// Use the API-echoed orderId: `from_permit2` rebuilds StandardOrder with
	// the Permit2 message.nonce as the order nonce, which differs from any
	// value StandardOrderBuilder picks — local `orderIdentifier()` would
	// mismatch the on-chain hash.
	let order_id_str = response
		.order_id
		.as_deref()
		.ok_or_else(|| anyhow::anyhow!("API response missing order_id"))?;
	let order_id = B256::from_str(order_id_str.trim_start_matches("0x"))
		.map_err(|e| anyhow::anyhow!("parse order_id {order_id_str:?}: {e}"))?;

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

	let user_after = h.balance(ORIGIN_CHAIN_ID, h.origin.token_a, user).await?;
	let recipient_after = h
		.balance(DEST_CHAIN_ID, h.destination.token_b, recipient)
		.await?;
	assert!(user_after < amount_with_decimals(1_000_000));
	assert!(recipient_after >= amount_out);

	Ok(())
}

fn addr_hex(a: alloy_primitives::Address) -> String {
	format!("0x{}", hex::encode(a.as_slice()))
}

fn addr_bytes32_hex(a: alloy_primitives::Address) -> String {
	let mut buf = [0u8; 32];
	buf[12..].copy_from_slice(a.as_slice());
	format!("0x{}", hex::encode(buf))
}

/// Build the `OrderPayload` JSON expected by `reconstruct_permit2_digest`. See
/// `solver-types/src/utils/eip712.rs:128` for the exact field-type contract.
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
