# M-04 Redis Query Bounds Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close M-04 by removing unbounded Redis active-order scans, preventing unsafe generic Redis negative scans, and adding index-hygiene coverage.

**Architecture:** The hot liveness paths should stop using negative status filters and instead query the existing `is_terminal=false` index. Redis `NotEquals` and `NotIn` must either be bounded/rejected or run through a cursor/budgeted path; plain `SDIFF` reduces solver memory but is not a complete Redis blocking fix by itself. Retention must not expire active orders or shared index keys unexpectedly, so this plan keeps terminal retention as a documented follow-up unless an index-safe deletion sweeper is implemented.

**Tech Stack:** Rust workspace, `solver-storage` Redis backend, `solver-core` recovery/tx-bump orchestration, optional `solver-service` config defaults/docs. Use alloy ecosystem only. Per-crate tests first, then `cargo check --all-targets --all-features`, `cargo fmt --all -- --check`, and `cargo clippy --all-features --all-targets -- -D warnings --allow deprecated`.

**Audit Source:** M-04 from the local audit export at `/Users/nahimdhaney/openzeppelin/oif-solver/docs/oif-audit-findings.md:348`. The live audit page is auth-gated in this environment, so implementation should cite the local export or the platform issue only after the assignee can access it.

**M-04 Excerpt:** "Unbounded Redis SMEMBERS Scans In Storage Query Can Block Redis And Exhaust Solver Memory" (Medium, open). The finding states that `RedisStorage::query` resolves `NotIn` and `NotEquals` by `SMEMBERS` over `:_all` and excluded index sets, then performs client-side set difference. Because `ttl_orders` defaults to `0`, terminal orders are retained indefinitely, and recovery/tx-bump automatically call the `NotIn` path through active-order loading.

**Live Verification Notes:** A fresh grep on this worktree found `cleanup_expired` is scheduled by `SolverEngine::run` through a spawned cleanup task using `storage.cleanup_interval_seconds` (`crates/solver-core/src/engine/mod.rs:415-433`), with the operator-derived/default interval set to 3600 seconds (`crates/solver-service/src/config_merge.rs:1352`, `crates/solver-service/src/seeds/types.rs:178`). A fresh `QueryFilter::NotIn`/`NotEquals` constructor inventory found only two production negative-filter constructors: recovery `load_active_orders` and tx-bump `load_active_order_ids`. Other checked production query paths use positive `Equals` filters.

**Base Worktree:** `/Users/nahimdhaney/openzeppelin/oif-solver/.worktrees/m04-plan`

**Branch:** `audit/m04-redis-query-bounds`.

**Implementation Status:** Implemented in this worktree. Active recovery and
tx-bump queries use `is_terminal=false`; Redis `NotEquals`/`NotIn` filters fail
fast; Redis cleanup uses `SSCAN` over known namespace/index sets and prunes
stale order index members with an atomic data-key absence recheck; file-backed
index lookup now matches persisted boolean/numeric index values for parity with
the canonical `is_terminal` index. The cluster-gated cleanup integration test
compiles, but the local Docker cluster runtime test could not be completed
because the Redis image pull/startup stalled before containers were created.

---

## Scope

In scope:
- Recovery startup active-order query.
- Transaction bump active-order query.
- Redis `QueryFilter::NotEquals` and `QueryFilter::NotIn` safety behavior.
- Redis cluster same-slot behavior for any multi-key cursor/budget helper.
- Index hygiene for expired/deleted order records.
- Documentation for retention follow-up and operational verification.

Out of scope:
- Reworking all storage APIs around pagination in this PR.
- Silently limiting recovery or tx-bump results. Missing active orders is a correctness bug.
- Deleting terminal order history without a documented retention policy.

## Key Facts

- `RedisStorage::query` currently resolves `NotEquals` and `NotIn` by calling `SMEMBERS` on namespace `_all`, calling `SMEMBERS` on excluded index sets, and diffing client-side in `Vec`/`HashSet`.
- `RecoveryService::load_active_orders` and tx-bump `load_active_order_ids` both query `status_kind NOT IN ["finalized", "failed"]`.
- Orders already store an `is_terminal` boolean index, so active liveness queries can be exact positive index lookups.
- The cleanup scheduler already exists in `SolverEngine::run`; the Redis backend work must make `cleanup_expired` useful, not add a new scheduler.
- Rejecting Redis negative filters is viable only after Task 1 because the current production negative-filter constructors are the two M-04 liveness callers. Keep this inventory testable with grep/find-references during implementation.
- Redis cluster mode key builders already hash-tag the prefix. Any cursor/budget implementation that touches multiple keys must preserve that same-slot invariant.
- `ttl_orders = 0` in operator-derived config, Redis TTL only applies when greater than zero, and `cleanup_expired` currently does not prune stale index members.

## File Structure

| File | Responsibility |
|---|---|
| `crates/solver-core/src/recovery/mod.rs` | Replace active recovery query with `is_terminal=false`; update query-shape tests. |
| `crates/solver-core/src/bump/service.rs` | Replace tx-bump active ID query with `is_terminal=false`; add query-shape test. |
| `crates/solver-storage/src/implementations/redis.rs` | Reject or bound Redis negative filters; add stale-index cleanup helpers. |
| `crates/solver-storage/tests/redis_cluster_integration.rs` | Verify negative-filter query path works in cluster mode with hash-tagged keys. |
| `crates/solver-core/src/state/order.rs` | Preserve canonical `is_terminal` indexing; do not add data TTL here unless shared-index TTL semantics are refactored first. |
| `crates/solver-service/src/config_merge.rs` | If config defaults change, wire/order-retention defaults and tests here. |
| `docs/config-storage.md` | Document active-order indexing, Redis negative-filter safety policy, retention follow-up, and operator checks. |

---

### Task 1: Switch Active-Order Callers To `is_terminal=false`

**Files:**
- Modify: `crates/solver-core/src/recovery/mod.rs`
- Modify: `crates/solver-core/src/bump/service.rs`
- Test: `crates/solver-core/src/recovery/mod.rs`
- Test: `crates/solver-core/src/bump/service.rs`

- [ ] **Step 1: Rename and update the recovery RED test**

Rename `load_active_orders_queries_canonical_status_kind_index` to `load_active_orders_queries_is_terminal_index`, then update it to expect:

```rust
QueryFilter::Equals(
	"is_terminal".to_string(),
	serde_json::json!(false),
)
```

Run:

```bash
cargo test -p solver-core load_active_orders_queries_is_terminal_index 2>&1 | tee /tmp/m04-recovery-red.log
```

Expected: FAIL because `load_active_orders` still sends `NotIn("status_kind", ["finalized", "failed"])`.

- [ ] **Step 2: Add the tx-bump RED test**

Add a focused test near `load_active_order_ids` that uses `MockStorageInterface` and asserts the function queries:

```rust
QueryFilter::Equals(
	"is_terminal".to_string(),
	serde_json::json!(false),
)
```

Run:

```bash
cargo test -p solver-core load_active_order_ids 2>&1 | tee /tmp/m04-bump-red.log
```

Expected: FAIL because tx bump still duplicates the `status_kind NotIn` query.

- [ ] **Step 3: Implement the minimal caller change**

Change both callers to import/use `IS_TERMINAL_INDEX_FIELD` and query:

```rust
QueryFilter::Equals(IS_TERMINAL_INDEX_FIELD.to_string(), serde_json::json!(false))
```

Do not add any result limit to these callers.

Also update the stale tx-bump comment above `load_active_order_ids`; it should say it mirrors recovery by querying the canonical `is_terminal` index.

- [ ] **Step 4: Verify caller behavior**

Run:

```bash
cargo test -p solver-core load_active_orders_queries_is_terminal_index 2>&1 | tee /tmp/m04-recovery-green.log
cargo test -p solver-core load_active_order_ids 2>&1 | tee /tmp/m04-bump-green.log
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/solver-core/src/recovery/mod.rs crates/solver-core/src/bump/service.rs
git commit -m "fix(M-04): query active orders by terminal index"
```

---

### Task 2: Make Redis Negative Filters Safe

**Files:**
- Modify: `crates/solver-storage/src/implementations/redis.rs`
- Test: `crates/solver-storage/src/implementations/redis.rs`
- Test: `crates/solver-storage/tests/redis_cluster_integration.rs`

- [ ] **Step 1: Add RED coverage proving hot paths no longer need Redis negative filters**

Add or update tests that fail if recovery or tx-bump uses `QueryFilter::NotIn`/`NotEquals` for active orders:
- `load_active_orders_queries_is_terminal_index`
- a new `load_active_order_ids_queries_is_terminal_index`

Run:

```bash
cargo test -p solver-core is_terminal_index 2>&1 | tee /tmp/m04-hot-path-red.log
```

Expected before Task 1 implementation: FAIL. Expected after Task 1: PASS.

- [ ] **Step 2: Decide Redis negative-filter policy**

Recommended policy: reject Redis `NotEquals` and `NotIn` when they would require scanning namespace `_all`, unless a small explicit candidate budget is configured for non-liveness/admin use.

Rationale:
- Plain `SDIFF _all ...` still blocks Redis over `_all`; it only avoids transferring/materializing excluded sets in the solver.
- After Task 1, production liveness paths do not require Redis negative filters.
- A fresh constructor inventory found no other production `QueryFilter::NotIn` or `QueryFilter::NotEquals` users outside recovery and tx bump; bridge history/active-transfer queries and transaction-attempt queries use positive `Equals` filters.
- Failing fast on Redis negative filters is safer than leaving a latent DoS primitive in the generic storage API.

Acceptable alternative: implement an `SSCAN`-based negative filter with a strict scanned-candidate budget and return `StorageError::Backend` once the budget is exceeded. Do not implement unbounded `SDIFF` and call the finding closed.

- [ ] **Step 3: Add RED storage tests for the chosen policy**

For reject-by-default:
- Add tests that `RedisStorage::query("orders", QueryFilter::NotIn(...))` and `NotEquals(...)` return a clear `StorageError::Backend` without issuing `SMEMBERS _all`.
- Existing connection-failure tests for negative filters should be updated so they assert the new policy error when no connection is needed.
- Add an implementation note/test assertion that memory and file backends keep their existing negative-filter semantics; the rejection is Redis-specific because the audit finding is Redis-specific.
- Re-run `rg -n "QueryFilter::(NotIn|NotEquals)|NotIn\\(|NotEquals\\(" crates` before committing. If a new production caller appears, either migrate it to a positive index or document why Redis rejection will not affect it.

For bounded cursor:
- Add tests for the helper that proves it scans in bounded batches and errors when the configured candidate budget is exceeded.

Run:

```bash
cargo test -p solver-storage redis_negative_filter 2>&1 | tee /tmp/m04-redis-negative-red.log
```

Expected: FAIL because Redis negative filters still use client-side `SMEMBERS`.

- [ ] **Step 4: Implement the Redis policy**

Reject-by-default implementation sketch:

```rust
QueryFilter::NotEquals(_, _) | QueryFilter::NotIn(_, _) => {
	return Err(StorageError::Backend(
		"Redis negative index queries are disabled; use a positive index such as is_terminal=false".to_string(),
	));
}
```

If the cursor alternative is selected, use `SSCAN` over `_all` with `COUNT`, batched `SMISMEMBER` checks against excluded sets, a strict candidate budget, and no unbounded `SMEMBERS _all`.

Keep memory/file backends unchanged unless the shared trait changes.

- [ ] **Step 5: Add cluster integration coverage**

If rejecting negative filters, add a cluster test that verifies the same clear error in cluster mode.

If implementing cursor-bounded filters, extend `crates/solver-storage/tests/redis_cluster_integration.rs` with a test that inserts active/terminal-like rows and proves the negative query works with hash-tagged keys.

Run only when the local cluster harness is available:

```bash
docker compose -f docker-compose.cluster.yml up -d
cargo test -p solver-storage --features cluster-tests --test redis_cluster_integration cluster_query_negative_filter 2>&1 | tee /tmp/m04-redis-cluster.log
```

Expected after implementation: PASS. If Docker/Redis is unavailable, record that this integration test was not run.

- [ ] **Step 6: Verify storage tests**

Run:

```bash
cargo test -p solver-storage query 2>&1 | tee /tmp/m04-storage-query.log
cargo test -p solver-storage redis 2>&1 | tee /tmp/m04-storage-redis.log
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/solver-storage/src/implementations/redis.rs crates/solver-storage/tests/redis_cluster_integration.rs
git commit -m "fix(M-04): disable unsafe Redis negative scans"
```

If cluster tests are unchanged, omit `crates/solver-storage/tests/redis_cluster_integration.rs`.

---

### Task 3: Add Redis Index-Hygiene Safeguards

**Files:**
- Modify: `crates/solver-storage/src/implementations/redis.rs`
- Test: `crates/solver-storage/src/implementations/redis.rs`

- [ ] **Step 1: Do not add order TTL in this task**

Do not pass TTL through order writes in `OrderStateMachine` in this PR. Redis currently applies configured data TTL to shared `_all`, field-index, and `_idx_meta` keys inside `update_indexes`; blindly adding terminal TTL would risk expiring shared indexes or metadata before cleanup can prune stale members.

Terminal retention should be a follow-up using an index-safe deletion sweeper, not data-key TTL attached to normal order writes.

- [ ] **Step 2: Add RED tests for stale index cleanup**

Add a Redis backend test that creates:
- data key `orders:active` with indexes,
- data key `orders:terminal` with indexes,
- then simulates data-key expiry/deletion while leaving stale index members.

The test should prove `cleanup_expired` removes stale members from:
- `{prefix}:orders:_all`,
- `{prefix}:orders:_index:<field>:<value>`,
- `{prefix}:orders:<id>:_idx_meta` when present.

Also update existing `test_cleanup_expired_no_connection_needed`: after this change, Redis cleanup is connection-backed. It should expect a backend error for an unavailable Redis connection or be replaced by a test for the cleanup helper that does not require a network.

Run:

```bash
cargo test -p solver-storage cleanup_expired 2>&1 | tee /tmp/m04-cleanup-red.log
```

Expected: FAIL because Redis `cleanup_expired` currently returns `Ok(0)` and does no pruning.

- [ ] **Step 3: Implement Redis index hygiene**

Implement `cleanup_expired` so it walks known indexed sets and removes members whose data key no longer exists.

Implementation constraints:
- Do not add a new scheduler; `SolverEngine::run` already spawns one cleanup loop using `storage.cleanup_interval_seconds`.
- Do not use `KEYS`.
- In cluster mode, do not issue default keyspace `SCAN` through `ClusterConnection`; with the current Redis crate, routing can hit the wrong primary and miss keys.
- Prefer `SSCAN` over known keyed sets such as `{prefix}:orders:_all` and selected field-index sets. Those keys are built from the tagged prefix and stay in the expected hash slot.
- If keyspace `SCAN` is still needed, route it explicitly to the relevant primary/all primaries with the Redis crate's routing API and document why `SSCAN` is insufficient.
- Use bounded batches, e.g. `COUNT 1000`.
- For each stale member discovered from `_all` or a field-index set, derive the logical storage key, check `EXISTS data_key`, and if absent call a no-fetch cleanup helper that removes the member from `_all`, known index sets, and `_idx_meta` when present.
- Cleanup must handle stale `_all` members whose `_idx_meta` key is already absent.
- Return the number of logical records pruned.

- [ ] **Step 4: Verify index hygiene**

Run:

```bash
cargo test -p solver-storage cleanup_expired 2>&1 | tee /tmp/m04-cleanup-green.log
```

Expected: PASS.

Add one of these cluster-safety checks before considering the task complete:
- a cluster-mode cleanup test proving the cleanup path works without unrouted keyspace `SCAN`, or
- an implementation-level test proving the cleanup path uses `SSCAN` over known tagged keys or explicit cluster routing.

The existing single-node cluster harness is not enough by itself to catch random-node `SCAN` routing issues.

Also verify the scheduler path remains wired:

```bash
rg -n "cleanup_expired\\(|cleanup_interval_seconds|Storage cleanup" crates/solver-core crates/solver-service 2>&1 | tee /tmp/m04-cleanup-callers.log
```

Expected: `SolverEngine::run` spawns the cleanup loop and config defaults set a positive interval.

- [ ] **Step 5: Commit**

```bash
git add crates/solver-storage/src/implementations/redis.rs
git commit -m "fix(M-04): prune stale Redis order indexes"
```

---

### Task 4: Update Storage Documentation

**Files:**
- Modify: `docs/config-storage.md`
- Optionally modify: `docs/tx-bump-operations.md`

- [ ] **Step 1: Document the active-order query invariant**

Add a short Redis storage section explaining:
- active-order recovery and tx bumping use `is_terminal=false`,
- Redis negative filters are rejected or cursor/budgeted; they are not used for liveness,
- cleanup runs through the existing solver-engine cleanup task at `storage.cleanup_interval_seconds`,
- result limits are intentionally not applied to recovery/bump queries.

- [ ] **Step 2: Document retention and cleanup**

Document that terminal retention is a follow-up unless this PR implements an index-safe deletion sweeper. Warn that `ttl_orders` is unsafe as a short blanket value because Redis currently applies TTL to shared index keys during index updates.

Include a warning that active orders must not expire before the maximum settlement/recovery window.

- [ ] **Step 3: Document operational probes**

Add commands:

```bash
redis-cli SCARD '<prefix>:orders:_all'
redis-cli SCARD '<prefix>:orders:_index:is_terminal:false'
redis-cli SCARD '<prefix>:orders:_index:is_terminal:true'
```

For cluster mode, document that keys include the hash-tagged prefix, e.g. `{solver-id}:orders:_all`.

- [ ] **Step 4: Commit**

```bash
git add docs/config-storage.md docs/tx-bump-operations.md
git commit -m "docs(M-04): document Redis active-order query and retention"
```

Omit `docs/tx-bump-operations.md` if unchanged.

---

### Task 5: Full Verification And Review Package

**Files:**
- No source files unless fixing verification failures.

- [ ] **Step 1: Focused tests**

Run:

```bash
cargo test -p solver-storage query 2>&1 | tee /tmp/m04-storage-query-final.log
cargo test -p solver-storage redis 2>&1 | tee /tmp/m04-storage-redis-final.log
cargo test -p solver-core load_active_orders_queries_is_terminal_index 2>&1 | tee /tmp/m04-core-recovery-final.log
cargo test -p solver-core load_active_order_ids_queries_is_terminal_index 2>&1 | tee /tmp/m04-core-bump-final.log
```

Expected: PASS.

- [ ] **Step 2: Crate checks**

Run:

```bash
cargo check -p solver-storage --all-targets --all-features 2>&1 | tee /tmp/m04-storage-check.log
cargo check -p solver-core --all-targets --all-features 2>&1 | tee /tmp/m04-core-check.log
```

If config types changed, also run:

```bash
cargo check -p solver-service --all-targets --all-features 2>&1 | tee /tmp/m04-service-check.log
cargo test -p solver-service build_storage_config_from_operator 2>&1 | tee /tmp/m04-service-config.log
```

Expected: PASS.

- [ ] **Step 3: Workspace gates**

Run:

```bash
cargo fmt --all -- --check 2>&1 | tee /tmp/m04-fmt.log
cargo check --all-targets --all-features 2>&1 | tee /tmp/m04-all-check.log
cargo clippy --all-features --all-targets -- -D warnings --allow deprecated 2>&1 | tee /tmp/m04-clippy.log
```

Expected: PASS.

- [ ] **Step 4: Optional Redis cluster gate**

If Docker is available:

```bash
docker compose -f docker-compose.cluster.yml up -d
cargo test -p solver-storage --features cluster-tests --test redis_cluster_integration 2>&1 | tee /tmp/m04-cluster-tests.log
```

Expected: PASS. If unavailable, report it explicitly.

- [ ] **Step 5: PR summary**

Prepare a PR summary that says:
- M-04 active liveness queries no longer touch `orders:_all`;
- generic negative Redis filters are rejected or cursor/budgeted;
- stale index cleanup prevents `_all` from accumulating dead members after data expiry/deletion;
- cleanup uses the existing scheduled storage cleanup loop;
- verification commands and any skipped cluster test.

Use `gh-work` for work remotes. Keep branch names, commit messages, PR title, and PR body task-specific.
