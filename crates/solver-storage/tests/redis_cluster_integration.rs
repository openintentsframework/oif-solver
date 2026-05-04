//! Integration tests for cluster-mode Redis storage.
//!
//! Run against the local single-shard cluster from `docker-compose.cluster.yml`:
//! ```sh
//!   docker compose -f docker-compose.cluster.yml up -d
//!   cargo test -p solver-storage --features cluster-tests --test redis_cluster_integration
//! ```
//!
//! The default seed URL is `redis://127.0.0.1:7100` — port 7000 conflicts
//! with macOS AirPlay Receiver, hence the 7100 default. Override with
//! `REDIS_CLUSTER_TEST_URL` if your harness uses a different port.
//!
//! These tests are gated behind the `cluster-tests` feature so that default
//! `cargo test` runs (without Docker) skip them.
//!
//! The local harness is intentionally single-shard; production uses AWS
//! MemoryDB. These tests verify the cluster client path and the single-slot
//! key-tag invariant. They do not prove CROSSSLOT behavior: a multi-shard
//! Redis Cluster is needed to enforce that class of failures locally.

#![cfg(feature = "cluster-tests")]

use solver_storage::implementations::redis::{RedisStorage, TtlConfig};
use solver_storage::{QueryFilter, StorageIndexes, StorageInterface};
use std::sync::Arc;
use std::time::Duration;

/// Seed node URL. Override via `REDIS_CLUSTER_TEST_URL` env var.
fn cluster_url() -> String {
	std::env::var("REDIS_CLUSTER_TEST_URL").unwrap_or_else(|_| "redis://127.0.0.1:7100".to_string())
}

fn make_storage(prefix: &str) -> Arc<RedisStorage> {
	Arc::new(
		RedisStorage::new(
			cluster_url(),
			5000,
			prefix.to_string(),
			TtlConfig::default(),
			true, // cluster_mode
		)
		.expect("construct cluster RedisStorage"),
	)
}

fn unique_prefix(suffix: &str) -> String {
	format!("oif-test-{}-{}", uuid::Uuid::new_v4(), suffix)
}

#[test]
#[serial_test::serial(cluster_test_url_env)]
fn cluster_url_defaults_to_7100() {
	let original = std::env::var_os("REDIS_CLUSTER_TEST_URL");
	std::env::remove_var("REDIS_CLUSTER_TEST_URL");
	assert_eq!(cluster_url(), "redis://127.0.0.1:7100");
	match original {
		Some(value) => std::env::set_var("REDIS_CLUSTER_TEST_URL", value),
		None => std::env::remove_var("REDIS_CLUSTER_TEST_URL"),
	}
}

#[test]
#[serial_test::serial(cluster_test_url_env)]
fn cluster_url_honors_env_override() {
	let original = std::env::var_os("REDIS_CLUSTER_TEST_URL");
	std::env::set_var("REDIS_CLUSTER_TEST_URL", "redis://127.0.0.1:7200");
	assert_eq!(cluster_url(), "redis://127.0.0.1:7200");
	match original {
		Some(value) => std::env::set_var("REDIS_CLUSTER_TEST_URL", value),
		None => std::env::remove_var("REDIS_CLUSTER_TEST_URL"),
	}
}

#[tokio::test]
async fn cluster_set_get_roundtrip() {
	let storage = make_storage(&unique_prefix("setget"));
	storage
		.set_bytes("k1", b"v1".to_vec(), None, None)
		.await
		.unwrap();
	let got = storage.get_bytes("k1").await.unwrap();
	assert_eq!(got, b"v1".to_vec());
	assert!(storage.exists("k1").await.unwrap());
}

#[tokio::test]
async fn cluster_get_batch_mget_works() {
	// Smoke-tests `MGET` through the cluster client end-to-end. This runs
	// against a single-shard cluster, so CROSSSLOT is not reachable locally.
	let storage = make_storage(&unique_prefix("mget"));
	for i in 0..5_u8 {
		storage
			.set_bytes(&format!("k{i}"), vec![i], None, None)
			.await
			.unwrap();
	}
	let keys: Vec<String> = (0..5).map(|i| format!("k{i}")).collect();
	let batch = storage.get_batch(&keys).await.unwrap();
	assert_eq!(
		batch.len(),
		5,
		"MGET across 5 keys must succeed in cluster mode"
	);
}

#[tokio::test]
async fn cluster_compare_and_swap_atomic() {
	// `compare_and_swap` is a `StorageInterface` trait method (lib.rs:229),
	// dispatched through the cluster client end-to-end.
	let storage = make_storage(&unique_prefix("cas"));
	storage
		.set_bytes("counter", b"1".to_vec(), None, None)
		.await
		.unwrap();
	let ok = storage
		.compare_and_swap("counter", b"1", b"2".to_vec(), None)
		.await
		.unwrap();
	assert!(ok);
	assert_eq!(storage.get_bytes("counter").await.unwrap(), b"2".to_vec());
}

#[tokio::test]
async fn cluster_query_with_indexes_round_trip() {
	let storage = make_storage(&unique_prefix("idx"));
	let indexes = StorageIndexes::new().with_field("status", serde_json::json!("pending"));
	storage
		.set_bytes(
			"orders:order-1",
			b"data".to_vec(),
			Some(indexes),
			Some(Duration::from_secs(60)),
		)
		.await
		.unwrap();

	let results = storage
		.query(
			"orders",
			QueryFilter::Equals("status".to_string(), serde_json::json!("pending")),
		)
		.await
		.unwrap();
	assert!(
		results.iter().any(|k| k == "orders:order-1"),
		"indexed query did not return the inserted key; got {results:?}"
	);
}

#[tokio::test]
async fn cluster_set_nx_atomicity() {
	let storage = make_storage(&unique_prefix("setnx"));
	let first = storage.set_nx("k", b"v1".to_vec(), None).await.unwrap();
	let second = storage.set_nx("k", b"v2".to_vec(), None).await.unwrap();
	assert!(first);
	assert!(!second);
	assert_eq!(storage.get_bytes("k").await.unwrap(), b"v1".to_vec());
}

// --- Readiness / health: prove the cluster INFO path works end-to-end ---
//
// Startup calls readiness BEFORE the rest of the storage layer is exercised.
// If the cluster client routing for `INFO persistence` is broken, the solver
// fails health-check before it ever issues an `EXISTS` — and that masks the
// fix from manifesting in the original `MOVED` error. This test exercises
// that path locally, before staging.

#[tokio::test]
async fn cluster_check_redis_health_succeeds() {
	use solver_storage::redis_health::check_redis_health;
	let info = check_redis_health(&cluster_url(), 5000, true)
		.await
		.expect("cluster INFO must succeed against the local single-shard cluster");
	// The local Docker harness enables AOF (`--appendonly yes`); persistence
	// is reported via INFO regardless of whether RDB or AOF is on, so just
	// assert we got a parseable response.
	let _ = info.has_persistence();
}

#[tokio::test]
async fn cluster_redis_readiness_check_reports_connected() {
	use solver_storage::readiness::{ReadinessConfig, RedisReadiness, StorageReadiness};
	let checker = RedisReadiness::new();
	let config = ReadinessConfig {
		require_persistence: false,
		timeout_ms: 5000,
		cluster_mode: true,
	};
	let status = checker
		.check(&cluster_url(), &config)
		.await
		.expect("cluster readiness check must succeed");
	assert!(status.is_ready, "expected ready=true, got {status:?}");
	assert!(
		status
			.checks
			.iter()
			.any(|c| c.name == "connectivity" && c.passed),
		"expected a passing connectivity check, got {:?}",
		status.checks
	);
}
