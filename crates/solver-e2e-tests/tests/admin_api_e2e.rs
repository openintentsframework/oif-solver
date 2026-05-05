//! Live admin API E2E tests.

use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use serde::Deserialize;
use serde_json::json;
use solver_e2e_tests::{
	redis_url_or_skip, Harness, HarnessOptions, SOLVER_ADDRESS, SOLVER_PRIVATE_KEY,
};

#[derive(Debug, Deserialize)]
struct SiweNonceResponse {
	message: String,
	domain: String,
	chain_id: u64,
}

#[derive(Debug, Deserialize)]
struct AuthTokenResponse {
	access_token: String,
	refresh_token: String,
	scopes: Vec<String>,
	token_type: String,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out + REDIS_URL; opt-in via --ignored"]
async fn admin_api_accepts_siwe_authenticated_admin() -> anyhow::Result<()> {
	let Some(redis_url) = redis_url_or_skip() else {
		eprintln!("skipping admin E2E because REDIS_URL is not set");
		return Ok(());
	};

	let h = Harness::boot_with(HarnessOptions {
		enable_admin_api: true,
		admin_redis_url: Some(redis_url),
		..Default::default()
	})
	.await?;

	let client = reqwest::Client::new();
	let base_url = h.api_base_url();

	let response = client
		.get(format!("{base_url}/admin/rebalance/config"))
		.send()
		.await?;
	assert!(
		response.status().as_u16() == 401 || response.status().as_u16() == 403,
		"admin route should exist and reject unauthenticated requests, got {}",
		response.status()
	);

	let nonce = client
		.post(format!("{base_url}/auth/siwe/nonce"))
		.json(&json!({ "address": SOLVER_ADDRESS }))
		.send()
		.await?;
	assert!(
		nonce.status().is_success(),
		"SIWE nonce request failed with {}: {}",
		nonce.status(),
		nonce.text().await?
	);
	let nonce: SiweNonceResponse = nonce.json().await?;
	assert_eq!(nonce.domain, "localhost");
	assert_eq!(nonce.chain_id, solver_e2e_tests::ORIGIN_CHAIN_ID);

	let signer: PrivateKeySigner = SOLVER_PRIVATE_KEY.parse()?;
	let signature = signer.sign_message_sync(nonce.message.as_bytes())?;
	let signature = format!("0x{}", hex::encode(signature.as_bytes()));

	let verify = client
		.post(format!("{base_url}/auth/siwe/verify"))
		.json(&json!({
			"message": nonce.message,
			"signature": signature,
		}))
		.send()
		.await?;
	assert!(
		verify.status().is_success(),
		"SIWE verify failed with {}: {}",
		verify.status(),
		verify.text().await?
	);
	let tokens: AuthTokenResponse = verify.json().await?;
	assert_eq!(tokens.token_type, "Bearer");
	assert!(!tokens.access_token.is_empty());
	assert!(!tokens.refresh_token.is_empty());
	assert!(
		tokens.scopes.iter().any(|scope| scope == "admin-all"),
		"SIWE token should include admin-all scope, got {:?}",
		tokens.scopes
	);

	let protected = client
		.get(format!("{base_url}/admin/rebalance/config"))
		.bearer_auth(&tokens.access_token)
		.send()
		.await?;
	assert!(
		protected.status().is_success(),
		"authenticated admin request failed with {}: {}",
		protected.status(),
		protected.text().await?
	);
	let body: serde_json::Value = protected.json().await?;
	assert_eq!(body["enabled"], false);
	assert_eq!(body["pairs"].as_array().map(Vec::len), Some(0));

	Ok(())
}
