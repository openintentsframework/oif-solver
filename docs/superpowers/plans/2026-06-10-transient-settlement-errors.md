# Transient Settlement Errors Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent transient settlement/post-fill/pre-claim infrastructure failures from terminally marking already-filled orders as `Failed`, so recovery can retry and solver funds are not stranded.

**Architecture:** Preserve typed error information at the settlement-handler boundary, classify retryable infrastructure failures in one shared helper, and have engine settlement arms leave orders in their current retryable status for transient errors. Confirmed on-chain transaction handlers must advance status first and run settlement callback post-processing as retryable/idempotent work; only confirmed reverts and explicit permanent settlement errors should write terminal `Failed`.

**Tech Stack:** Rust 2021, `solver-core`, existing `solver-delivery` and `solver-settlement` error enums, Tokio tests, `mockall`, file-backed storage test helpers.

---

## Investigation Summary

Current `origin/main` at `9e6668dbe311b2dcbcf2e38db24ddf250253fcab` does not fully fix Group 1.

- `crates/solver-core/src/engine/mod.rs`: `is_transient_postfill_error` only treats `SettlementError::InsufficientNativeGas` as transient. `PostFillReady` still fails all other errors, `PreClaimReady` fails every error, and `ClaimReady` has the same latent terminalization pattern.
- `crates/solver-core/src/handlers/settlement.rs`: post-fill preserves `DeliveryError::InsufficientNativeGas`, but collapses other delivery errors to `Service(String)`. Pre-claim and claim collapse all delivery errors to `Service(String)`.
- `crates/solver-core/src/handlers/transaction.rs`: `handle_confirmed` calls settlement `handle_transaction_confirmed` for `PostFill` and `PreClaim` before advancing order status. Any callback error becomes `TransactionError::Service`, and the engine marks the order `Failed(tx_type, ...)`.
- `crates/solver-core/src/recovery/mod.rs` and `crates/solver-core/src/bump/service.rs`: both exclude `Failed` orders from automated processing. Leaving `Executed` or `Settled` unchanged is safe because recovery already re-emits `PostFillReady` and `PreClaimReady` from those statuses.
- `crates/solver-core/src/handlers/settlement.rs`: claim batch error handling is already broken in a separate way. `process_claim_batch` drains the batch, and `CLAIM_BATCH` is currently `1`, so the engine's later `for order_id in batch` failure loop is dead code. This plan's claim-batch work primarily restores per-order error observability and policy application.
- Startup recovery is startup-only. `RetryLater` means the order remains eligible for startup recovery and live bump/retry components where they apply; it is not a new in-process backoff loop.

Baseline verification before plan: `cargo test -p solver-core 2>&1 | tee /tmp/oif-solver-core-baseline-h02-h06-m24.log` passed with `333 passed; 0 failed; 1 ignored` for unit tests, plus all solver-core integration/doc tests passing.

## File Structure

- Modify `crates/solver-core/src/handlers/settlement.rs`
  - Add typed core `SettlementError::Delivery(solver_delivery::DeliveryError)` and `SettlementError::SettlementService(solver_settlement::SettlementError)` variants.
  - Add `map_delivery_error` for every fallible delivery call, including `get_receipt` and all `deliver` calls.
  - Add `map_settlement_service_error` for `recover_post_fill_state`, `generate_post_fill_transaction`, and `generate_pre_claim_transaction`.
  - Preserve `solver_settlement::SettlementError` from settlement-service calls so `FinalityNotReached`, `ProverUnavailable`, `InvalidProof`, and `FillMismatch` can be classified without string matching.
- Modify `crates/solver-core/src/handlers/transaction.rs`
  - Add typed `TransactionError::SettlementCallback(...)` for settlement callback failures.
  - Reorder `PostFill` and `PreClaim` confirmation processing so the order status/hash transition happens before settlement callback post-processing.
  - Return typed callback errors after status advance so the engine can avoid terminalizing transient callback work.
- Modify `crates/solver-core/src/recovery/mod.rs`
  - Re-drive missing settlement callback side effects when recovery sees an already-confirmed `PostFill` or `PreClaim` receipt.
  - Gate `PostFill` callback replay through existing post-fill state recovery so broadcaster orders with already-tracked submissions do not reset proof state on every restart.
- Modify `crates/solver-core/src/engine/mod.rs`
  - Replace `is_transient_postfill_error` with one shared policy helper, for example `settlement_failure_policy(stage, &error)`.
  - Use the policy from `PostFillReady`, `PreClaimReady`, `ClaimReady`, and `TransactionConfirmed` callback-error handling.
- Modify tests in:
  - `crates/solver-core/src/handlers/settlement.rs`
  - `crates/solver-core/src/handlers/transaction.rs`
  - `crates/solver-core/tests/transaction_resilience_repro.rs` for recovery-loop regression coverage.

## Data Shape and Call Sites

Order state uses `OrderStatus` plus per-stage hashes: `fill_tx_hash`, `post_fill_tx_hash`, `pre_claim_tx_hash`, and `claim_tx_hash`. Reverse lookup storage uses `StorageKey::OrderByTxHash` keyed by encoded transaction hash.

Call sites that exercise this path:

- Live monitor callbacks publish `DeliveryEvent::TransactionConfirmed` from settlement handler callbacks.
- Engine `TransactionConfirmed` arm calls `TransactionHandler::handle_confirmed`.
- Engine `PostFillReady` arm calls `SettlementHandler::handle_post_fill_ready`.
- Engine `PreClaimReady` arm calls `SettlementHandler::handle_pre_claim_ready`.
- Engine `ClaimReady` arm calls `SettlementHandler::process_claim_batch`.
- Startup recovery publishes `PostFillReady`, `StartMonitoring`, `PreClaimReady`, or `ClaimReady` for non-terminal orders.

## Error Classification Design

Add a local policy enum in `engine/mod.rs` or a small helper module under `crates/solver-core/src/engine/`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SettlementFailurePolicy {
	RetryLater,
	FailOrder,
}
```

Classify as `RetryLater`:

- `DeliveryError::Network`
- `DeliveryError::NonceTooLow`
- `DeliveryError::ReplacementUnderpriced`
- `DeliveryError::InsufficientNativeGas`
- `DeliveryError::NoImplementationAvailable`
- `solver_settlement::SettlementError::FinalityNotReached`
- `solver_settlement::SettlementError::ProverUnavailable`
- `solver_settlement::SettlementError::ProofGenerationFailed { .. }`
- typed transaction callback storage/state errors only when the error variant proves the on-chain stage has already been persisted and the remaining failure is post-confirmation callback/storage work

Classify as `FailOrder`:

- confirmed receipt `success == false`, which already flows through `TransactionFailed`
- explicit permanent settlement errors: `ValidationFailed`, `InvalidProof`, `FillMismatch`, `SlotDerivationMismatch`
- `DeliveryError::TransactionFailed` unless a narrower typed classification proves it is retryable
- missing invariant data that cannot be recovered by retry alone, such as no fill hash when handling post-fill or no fill proof when handling pre-claim
- generic `SettlementError::Storage`, `SettlementError::State`, and `SettlementError::Service` unless they are replaced by typed/contextual variants proving retry is safe

Do not broaden `RevertClassification::Unknown` in this PR unless tests prove it is necessary. Current delivery callbacks intentionally publish `TransactionFailed` for `Unknown`; changing that is adjacent but riskier than fixing transient infrastructure errors.

## Task 1: Preserve Typed Settlement Handler Errors

**Files:**
- Modify: `crates/solver-core/src/handlers/settlement.rs`

- [ ] **Step 1: Write failing tests for pre-claim delivery classification**

Add tests near `test_handle_pre_claim_ready_missing_fill_proof`:

```rust
#[tokio::test]
async fn pre_claim_ready_preserves_insufficient_native_gas_as_transient() {
	// Arrange a settled order with fill_proof and a generated pre-claim tx.
	// Mock delivery.submit to return DeliveryError::InsufficientNativeGas.
	// Assert handle_pre_claim_ready returns SettlementError::InsufficientNativeGas.
}

#[tokio::test]
async fn post_fill_ready_preserves_receipt_network_error_as_delivery_error() {
	// Arrange an Executed order with fill_tx_hash.
	// Mock delivery.get_receipt to return DeliveryError::Network.
	// Assert handle_post_fill_ready returns SettlementError::Delivery.
}

#[tokio::test]
async fn pre_claim_ready_preserves_settlement_service_error() {
	// Arrange a Settled order with fill_proof.
	// Mock generate_pre_claim_transaction to return solver_settlement::SettlementError::ProverUnavailable.
	// Assert handle_pre_claim_ready returns SettlementError::SettlementService.
}
```

- [ ] **Step 2: Run RED**

Run:

```bash
cargo test -p solver-core ready_preserves_ 2>&1 | tee /tmp/oif-red-settlement-preserve.log
```

Expected: FAIL. The pre-claim native-gas test should fail by assertion because the error is currently `Service`; the receipt and settlement-service preservation tests may initially fail to compile because the new typed variants do not exist yet. Treat that compile failure as the expected RED for new API surface.

- [ ] **Step 3: Add shared mapping helper**

Implement one helper:

```rust
fn map_delivery_error(error: solver_delivery::DeliveryError) -> SettlementError {
	match error {
		solver_delivery::DeliveryError::InsufficientNativeGas(info) => {
			SettlementError::InsufficientNativeGas(info)
		},
		other => SettlementError::Delivery(other),
	}
}
```

Add `SettlementError::Delivery(solver_delivery::DeliveryError)`. Also add:

```rust
fn map_settlement_service_error(error: solver_settlement::SettlementError) -> SettlementError {
	SettlementError::SettlementService(error)
}
```

- [ ] **Step 4: Replace delivery and settlement-service mappings**

Use `map_delivery_error` for:

- `delivery.get_receipt` in `handle_post_fill_ready`
- `delivery.deliver` in `handle_post_fill_ready`
- `delivery.deliver` in `handle_pre_claim_ready`
- `delivery.deliver` in `process_claim_batch`

Use `map_settlement_service_error` for:

- `settlement.recover_post_fill_state`
- `settlement.generate_post_fill_transaction`
- `settlement.generate_pre_claim_transaction`

- [ ] **Step 5: Run GREEN**

Run:

```bash
cargo test -p solver-core ready_preserves_ 2>&1 | tee /tmp/oif-green-settlement-preserve.log
```

Expected: PASS.

## Task 2: Add One Shared Settlement Failure Policy

**Files:**
- Modify: `crates/solver-core/src/engine/mod.rs`

- [ ] **Step 1: Write unit tests for policy**

Add tests under `engine::tests`:

```rust
#[test]
fn settlement_policy_retries_transient_delivery_errors() {
	// Build core SettlementError values wrapping DeliveryError::Network,
	// NonceTooLow, ReplacementUnderpriced, and InsufficientNativeGas.
	// Assert RetryLater for PostFill, PreClaim, and Claim.
}

#[test]
fn settlement_policy_fails_permanent_settlement_errors() {
	// Build core SettlementError values wrapping InvalidProof/FillMismatch.
	// Assert FailOrder.
}
```

- [ ] **Step 2: Run RED**

Run:

```bash
cargo test -p solver-core settlement_policy 2>&1 | tee /tmp/oif-red-policy.log
```

Expected: FAIL, likely as a compile failure because the policy function and new typed variants do not exist yet. This filter should match only policy tests.

- [ ] **Step 3: Implement policy**

Replace `is_transient_postfill_error` with:

```rust
fn settlement_failure_policy(
	stage: solver_types::TransactionType,
	error: &crate::handlers::settlement::SettlementError,
) -> SettlementFailurePolicy {
	// Match typed variants, not strings.
}
```

Keep the implementation local and exhaustive over current core `SettlementError` variants.

Classify every wrapped `DeliveryError` and `solver_settlement::SettlementError` variant explicitly. Do not leave a wildcard arm for these source enums; adding a new upstream variant should force a policy decision.

- [ ] **Step 4: Run GREEN**

Run:

```bash
cargo test -p solver-core settlement_policy 2>&1 | tee /tmp/oif-green-policy.log
```

Expected: PASS.

## Task 3: Apply Policy to Event Arms

**Files:**
- Modify: `crates/solver-core/src/engine/mod.rs`

- [ ] **Step 1: Extract DRY helper for settlement arm errors**

Create a helper used by `PostFillReady`, `PreClaimReady`, and `ClaimReady`:

```rust
async fn handle_settlement_stage_error(
	engine: &SolverEngine,
	order_id: &str,
	tx_type: TransactionType,
	context: &str,
	error: crate::handlers::settlement::SettlementError,
) -> Result<(), EngineError> {
	// RetryLater: warn and return EngineError without transitioning.
	// FailOrder: transition to OrderStatus::Failed(tx_type, message).
}
```

If borrowing makes an async helper noisy, keep it as a small private method on `SolverEngine`.

- [ ] **Step 2: Update PostFillReady**

Replace the existing `is_transient_postfill_error` branch with the shared helper.

- [ ] **Step 3: Update PreClaimReady**

Use the same helper so transient delivery/RPC/signer errors leave the order in `Settled`. Generic `SettlementError::Storage` and `SettlementError::State` still fail unless replaced by a typed/contextual variant proving retry is safe after on-chain success.

- [ ] **Step 4: Update ClaimReady**

Use the same helper for claim processing, but first fix the batch error shape. Current `process_claim_batch` drains `batch`, while the engine error branch iterates the same drained vector.

Implement one concrete design: make `process_claim_batch` return `Result<(), ClaimBatchError>` where `ClaimBatchError` includes the affected `order_id` and typed `SettlementError`. Preserve the input order IDs before draining or iterate without consuming them until each order succeeds, so the engine can apply the shared policy to exactly the affected order.

Then transient claim submission errors and typed/contextual retry-safe post-submission storage/state errors leave that order in `Settled`/`PreClaimed` for recovery, while permanent failures transition only the affected order to `Failed(Claim, ...)`. Generic `SettlementError::Storage` and `SettlementError::State` remain `FailOrder` unless the implementation replaces them with a variant proving the chain stage already succeeded and only retryable off-chain bookkeeping failed.

- [ ] **Step 5: Add and run focused engine error-path tests**

Add tests for the shared helper or engine arm wrapper:

```rust
#[tokio::test]
async fn post_fill_ready_transient_error_leaves_order_executed() {
	// Assert RetryLater path does not call transition_order_status to Failed.
}

#[tokio::test]
async fn pre_claim_ready_transient_error_leaves_order_settled() {
	// Assert RetryLater path does not call transition_order_status to Failed.
}

#[tokio::test]
async fn claim_ready_transient_error_leaves_order_retryable() {
	// Assert transient claim error does not terminalize order.
}

#[tokio::test]
async fn claim_ready_permanent_error_fails_only_affected_order() {
	// Assert permanent claim error writes Failed(Claim) for the affected order.
}
```

Run:

```bash
cargo test -p solver-core transient_error_leaves 2>&1 | tee /tmp/oif-engine-transient-arms.log
cargo test -p solver-core claim_ready_permanent 2>&1 | tee /tmp/oif-engine-claim-ready.log
```

Expected: PASS.

## Task 4: Make Confirmed Callback Post-Processing Retryable

**Files:**
- Modify: `crates/solver-core/src/handlers/transaction.rs`
- Modify: `crates/solver-core/src/engine/mod.rs`
- Modify: `crates/solver-core/src/recovery/mod.rs`

- [ ] **Step 1: Write failing transaction-handler test**

Add a test proving a successful `PostFill` receipt advances to `PostFilled` and emits `StartMonitoring` even if settlement callback post-processing returns a transient error.

```rust
#[tokio::test]
async fn post_fill_confirmed_advances_status_before_transient_callback_error() {
	// Stored order starts Executed with fill_tx_hash.
	// Mock settlement handle_transaction_confirmed returns ProverUnavailable or equivalent transient.
	// Call handle_confirmed(PostFill, success receipt).
	// Assert stored status is PostFilled and post_fill_tx_hash is recorded.
	// Assert returned error preserves callback context for engine logging/classification.
}
```

Add an equivalent `PreClaim` test for `Settled -> PreClaimed` and `ClaimReady`.

The test must bind the order to the mocked settlement implementation. `TransactionHandler::handle_confirmed` skips the callback when `SettlementService::find_settlement_for_order` returns `Err`, so set `order.settlement_name` to the registered mock key or configure that key as the settlement service primary name.

- [ ] **Step 2: Run RED**

Run:

```bash
cargo test -p solver-core transient_callback_error 2>&1 | tee /tmp/oif-red-confirmed-callback.log
```

Expected: FAIL because current code runs callback before transition. Name both tests with the shared `transient_callback_error` phrase so this single filter matches them.

- [ ] **Step 3: Reorder confirmed handling**

For `PostFill` and `PreClaim`:

1. Retrieve order.
2. Run the stage-specific status/hash transition.
3. Run settlement `handle_transaction_confirmed` afterward.
4. If callback fails, return `TransactionError::SettlementCallback { stage, source }` without rolling back status.

Keep receipt `success == false` behavior unchanged.

- [ ] **Step 4: Apply engine policy to callback errors**

In the `TransactionConfirmed` event arm, distinguish `TransactionError::SettlementCallback`. If policy is `RetryLater`, log and leave status unchanged. If policy is `FailOrder`, transition to `Failed(tx_type, ...)`.

- [ ] **Step 5: Write failing recovery replay test**

Add a test in `crates/solver-core/tests/transaction_resilience_repro.rs` where an order has a successful `PostFill` receipt already on chain but settlement callback state is missing. `RecoveryService::recover_state()` should call settlement `handle_transaction_confirmed` or an equivalent recovery path before moving on to monitoring/pre-claim. This test protects the broadcaster `NoSubmissionState` case.

Also include the gate case: when post-fill state already exists, recovery should not replay `PostFill` callback side effects again. This avoids repeatedly calling broadcaster `track_submission`, which resets proof state to `None`.

Run:

```bash
cargo test -p solver-core --test transaction_resilience_repro recovery_replays_missing_confirmed_post_fill_callback 2>&1 | tee /tmp/oif-red-recovery-callback-replay.log
```

Expected: FAIL because confirmed receipts currently bypass settlement callback replay.

- [ ] **Step 6: Add recovery callback replay**

Add a recovery helper that re-runs settlement callback side effects only when recovery sees a confirmed receipt and the callback state is missing or safely idempotent:

```rust
async fn replay_confirmed_settlement_callback_if_needed(
	&self,
	order: &Order,
	tx_type: TransactionType,
	receipt: &TransactionReceipt,
) -> Result<(), RecoveryError> {
	// PostFill: first call recover_post_fill_state(order). If it returns false,
	// call settlement.handle_transaction_confirmed(order, PostFill, receipt).
	// This avoids repeatedly calling broadcaster track_submission after state
	// already exists, because track_submission resets proof to None.
	// PreClaim: call settlement.handle_transaction_confirmed(order, PreClaim, receipt);
	// mark_verified-style callbacks are idempotent and do not clear proofs.
}
```

Call this helper in `reconcile_with_blockchain` successful receipt branches for `PostFill` and `PreClaim`, after `mark_recovered_attempt_confirmed` and before returning `NeedsMonitoring`, `NeedsPreClaim`, or `NeedsClaim`. On transient callback replay errors, log the retryable error and continue with the normal evidence-based `ReconcileResult`; do not return `Unknown` and do not write `Failed`.

- [ ] **Step 7: Run GREEN**

Run:

```bash
cargo test -p solver-core transient_callback_error 2>&1 | tee /tmp/oif-green-confirmed-callback.log
cargo test -p solver-core --test transaction_resilience_repro recovery_replays_missing_confirmed_post_fill_callback 2>&1 | tee /tmp/oif-green-recovery-callback-replay.log
```

Expected: PASS.

## Task 5: Add Recovery Regression Coverage Inside solver-core Tests

**Files:**
- Modify: `crates/solver-core/tests/transaction_resilience_repro.rs`

- [ ] **Step 1: Add recovery re-drive regression for post-fill**

Add a test where an `Executed` order has a confirmed fill hash. `RecoveryService::recover_state()` should reconcile the fill receipt and publish `SettlementEvent::PostFillReady`. This proves the actual safety property for Tasks 1-3: leaving an order in `Executed` after a transient post-fill error lets startup recovery re-drive the post-fill path.

- [ ] **Step 2: Add recovery re-drive regression for pre-claim**

Add a test where a `Settled` order has `fill_proof`, `post_fill_tx_hash`, a mocked successful post-fill receipt from `delivery.get_receipt`, and settlement readiness is `Ready`. `RecoveryService::recover_state()` should publish `SettlementEvent::PreClaimReady`. This proves leaving an order in `Settled` after a transient pre-claim error lets startup recovery re-drive pre-claim.

- [ ] **Step 3: Run RED/GREEN as tests are added**

For each test:

```bash
cargo test -p solver-core --test transaction_resilience_repro <test_name> 2>&1 | tee /tmp/oif-<test-name>.log
```

Expected before implementation: the recovery re-drive tests should pass if current recovery already publishes the event. Expected after implementation: PASS.

## Task 6: Full Verification

**Files:**
- No new files unless implementation adds a small helper module.

- [ ] **Step 1: Format**

Run:

```bash
cargo fmt --all -- --check 2>&1 | tee /tmp/oif-fmt-check.log
```

Expected: PASS. If it fails, run `cargo fmt` and then re-run the check.

- [ ] **Step 2: Test solver-core**

Run:

```bash
cargo test -p solver-core 2>&1 | tee /tmp/oif-solver-core-final.log
```

Expected: PASS with the new regression tests included.

- [ ] **Step 3: Check broader target if shared APIs changed**

If `solver-delivery`, `solver-settlement`, or `solver-types` public APIs were changed, run:

```bash
cargo check --all-targets --all-features 2>&1 | tee /tmp/oif-all-targets-check.log
```

Expected: PASS.

- [ ] **Step 4: Lint**

Run:

```bash
cargo clippy --all-features --all-targets -- -D warnings --allow deprecated 2>&1 | tee /tmp/oif-clippy.log
```

Expected: PASS.

## Risk Notes

- Do not add backwards-compatible status shims. The safer behavior is to avoid writing `Failed` for retryable post-fill/pre-claim/claim work.
- Do not classify all `Service(String)` as transient. Preserve typed sources so permanent order/proof/config faults still fail fast.
- Do not change on-chain idempotency assumptions. Retrying post-fill/pre-claim/claim is acceptable because OIF contracts enforce single fill/claim/settle; the off-chain risk is stranded funds.
- Be conservative with `DeliveryError::TransactionFailed` and `RevertClassification::Unknown`. Treat them as permanent unless a narrower typed signal proves transient.
- Generic `SettlementError::Storage` and `SettlementError::State` remain terminal in this plan unless replaced by typed contextual variants. A storage blip after successful submission can still be a residual risk; handle that only with a variant proving on-chain progress already happened.
- `RetryLater` does not introduce an in-process retry loop. It prevents terminal `Failed` writes so startup recovery, existing monitoring, or a later explicitly-designed retry loop can re-drive the stage.
