//! Off-chain EIP-3009 `openFor()` flow. Differs from `permit2_e2e` in:
//!   - signed under the input token's EIP-712 domain (not Permit2's)
//!   - primary type `ReceiveWithAuthorization`
//!   - signature scheme byte `0x01`
//!   - StandardOrder fields live in `metadata`, parsed by `from_eip3009`
//!
//! Run with:
//!   cargo test -p solver-e2e-tests --test eip3009_e2e -- --ignored --nocapture

use alloy_primitives::{Bytes, B256, U256};
use alloy_signer::SignerSync;
use solver_e2e_tests::{
	addr_to_bytes32, addr_to_u256, amount_with_decimals, reconstruct_eip3009_digest, unix_now_secs,
	Finalised, Harness, InteropAddress, MandateOutput, OifOrder, OrderPayload, OutputFilled,
	PostOrderRequest, PostOrderResponseStatus, SignatureType, StandardOrder, DEST_CHAIN_ID,
	FILL_TIMEOUT, ORIGIN_CHAIN_ID, SETTLE_TIMEOUT, USER_PRIVATE_KEY,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn eip3009_offchain_open_fill_settle() -> anyhow::Result<()> {
	let h = Harness::boot().await?;

	let user = h.user_address();
	let recipient = h.recipient_address();
	let amount_in = amount_with_decimals(1_000);
	let amount_out = amount_with_decimals(990);

	// Build a local StandardOrder matching what `from_eip3009` reconstructs
	// from our metadata. orderId is deterministic over these fields, and we
	// need it before signing because `_openForWithAuthorization` calls
	// `receiveWithAuthorization(..., nonce: orderId, validBefore: fillDeadline,
	// ...)` — see oif-contracts InputSettlerEscrow.sol:296-303.
	let now_secs = unix_now_secs();
	let expires = (now_secs + 60 * 60) as u32;
	let fill_deadline = (now_secs + 30 * 60) as u32;

	let order = StandardOrder {
		user,
		nonce: U256::from(now_secs),
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

	// MockERC20 uses `EIP712(name, "1")`. The signed values must match what
	// the input settler will pass to the token in
	// `_openForWithAuthorization`; `nonce` is the orderId, NOT a random
	// bytes32.
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

	let user_signer = USER_PRIVATE_KEY
		.parse::<alloy_signer_local::PrivateKeySigner>()
		.expect("static key parses");
	let digest_bytes = reconstruct_eip3009_digest(&payload, None)
		.map_err(|e| anyhow::anyhow!("digest: {e}"))?;
	let signature = user_signer
		.sign_hash_sync(&B256::from(digest_bytes))
		.map_err(|e| anyhow::anyhow!("sign: {e}"))?;
	let mut sig_bytes = vec![0x01u8]; // EIP-3009 scheme prefix
	sig_bytes.extend_from_slice(&signature.as_bytes());

	let metadata = serde_json::json!({
		"user": InteropAddress::new_ethereum(ORIGIN_CHAIN_ID, user).to_hex(),
		"nonce": now_secs,
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
