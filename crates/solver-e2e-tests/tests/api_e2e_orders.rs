//! Live public API E2E tests.

use solver_e2e_tests::Harness;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn public_assets_api_returns_seeded_test_tokens() -> anyhow::Result<()> {
	let h = Harness::boot().await?;

	let response = reqwest::get(format!("{}/assets", h.api_base_url())).await?;
	assert!(
		response.status().is_success(),
		"assets status should be success, got {}",
		response.status()
	);
	let body: serde_json::Value = response.json().await?;
	let body_text = body.to_string();

	assert!(
		body_text.contains("TOKA"),
		"assets response should include TOKA: {body_text}"
	);
	assert!(
		body_text.contains("TOKB"),
		"assets response should include TOKB: {body_text}"
	);

	Ok(())
}
