//! Live public API E2E tests.

use solver_e2e_tests::Harness;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out; opt-in via --ignored"]
async fn public_assets_api_returns_seeded_test_tokens() -> anyhow::Result<()> {
	let h = Harness::boot().await?;

	// Bound the request so a hung solver subprocess can't pin this test
	// indefinitely. The harness already health-probes the API before tests
	// run, so a successful response should land well under this budget.
	let client = reqwest::Client::builder()
		.timeout(Duration::from_secs(15))
		.build()?;
	let response = client
		.get(format!("{}/assets", h.api_base_url()))
		.send()
		.await?;
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
