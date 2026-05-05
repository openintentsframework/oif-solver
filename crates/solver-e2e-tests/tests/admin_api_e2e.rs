//! Live admin API E2E smoke tests.

use solver_e2e_tests::{redis_url_or_skip, Harness, HarnessOptions};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Anvil + oif-contracts/out + REDIS_URL; opt-in via --ignored"]
async fn admin_api_is_registered_when_redis_is_available() -> anyhow::Result<()> {
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

	let response = reqwest::get(format!("{}/admin/rebalance/config", h.api_base_url())).await?;
	assert!(
		response.status().as_u16() == 401 || response.status().as_u16() == 403,
		"admin route should exist and reject unauthenticated requests, got {}",
		response.status()
	);

	Ok(())
}
