//! Compact allocator intake E2E.
//!
//! Run with:
//!   cargo test -p solver-e2e-tests --test compact_allocator_e2e -- --ignored --test-threads=1 --nocapture

use alloy_primitives::{keccak256, Bytes, B256, U256};
use alloy_signer::SignerSync;
use solver_e2e_tests::{
	addr_to_bytes32, amount_with_decimals, unix_now_plus, CompactResetPeriod, Harness,
	HarnessOptions, MandateOutput, OifOrder, OrderPayload, PostOrderRequest, SignatureType,
	StandardOrder, DEST_CHAIN_ID, ORIGIN_CHAIN_ID, USER_PRIVATE_KEY,
};
use solver_types::standards::eip7683::compact_claims::compute_batch_compact_claim_hash;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out with Compact artifacts; opt-in via --ignored"]
async fn compact_order_with_unauthorized_allocator_data_is_rejected_at_intake() -> anyhow::Result<()>
{
	let h = Harness::boot_with(HarnessOptions {
		enable_compact_simple_allocator: true,
		..Default::default()
	})
	.await?;

	let amount_in = amount_with_decimals(1_000);
	let lock_tag = h.compact_lock_tag()?;
	let token_id = h.compact_deposit_user_token_a(amount_in).await?;
	let amount_out = amount_with_decimals(990);

	let order = compact_order(&h, token_id, amount_in, amount_out, 1);
	let request = build_compact_request(&h, &order, lock_tag, b"garbage allocator data").await?;

	let client = reqwest::Client::builder()
		.no_proxy()
		.timeout(std::time::Duration::from_secs(15))
		.build()?;
	let response = client
		.post(format!("{}/orders", h.api_base_url()))
		.json(&request)
		.send()
		.await?;
	assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
	let body: serde_json::Value = response.json().await?;
	assert_eq!(
		body.get("error").and_then(|v| v.as_str()),
		Some("ORDER_VALIDATION_FAILED")
	);
	assert!(
		body.get("message")
			.and_then(|v| v.as_str())
			.unwrap_or_default()
			.contains("did not authorize"),
		"response body should mention allocator rejection: {body}"
	);

	Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out with Compact artifacts; opt-in via --ignored"]
async fn compact_order_with_short_reset_period_is_rejected_at_intake() -> anyhow::Result<()> {
	let h = Harness::boot_with(HarnessOptions {
		enable_compact_simple_allocator: true,
		..Default::default()
	})
	.await?;

	let amount_in = amount_with_decimals(1_000);
	let lock_tag = h.compact_lock_tag_with_reset_period(CompactResetPeriod::OneSecond)?;
	let token_id = h
		.compact_deposit_user_token_a_with_reset_period(amount_in, CompactResetPeriod::OneSecond)
		.await?;
	let amount_out = amount_with_decimals(990);
	let order = compact_order(&h, token_id, amount_in, amount_out, 2);
	let request = build_compact_request(&h, &order, lock_tag, &[]).await?;

	let recipient_balance_before = h
		.balance(DEST_CHAIN_ID, h.destination.token_b, h.recipient_address())
		.await?;
	let response = reqwest::Client::builder()
		.no_proxy()
		.timeout(std::time::Duration::from_secs(15))
		.build()?
		.post(format!("{}/orders", h.api_base_url()))
		.json(&request)
		.send()
		.await?;
	assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
	let body: serde_json::Value = response.json().await?;
	assert!(
		body.get("message")
			.and_then(|v| v.as_str())
			.unwrap_or_default()
			.contains("reset period"),
		"response body should mention reset-period rejection: {body}"
	);
	let recipient_balance_after = h
		.balance(DEST_CHAIN_ID, h.destination.token_b, h.recipient_address())
		.await?;
	assert_eq!(
		recipient_balance_after, recipient_balance_before,
		"short-reset ResourceLock order must be rejected before destination fill"
	);

	Ok(())
}

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

async fn build_compact_request(
	h: &Harness,
	order: &StandardOrder,
	lock_tag: alloy_primitives::FixedBytes<12>,
	allocator_data: &[u8],
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

	Ok(PostOrderRequest {
		order: OifOrder::OifResourceLockV0 {
			payload: build_compact_payload(h, order, lock_tag)?,
		},
		signature: compact_signature(&sponsor_signature.as_bytes(), allocator_data),
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
