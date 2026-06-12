# Hyperlane Output Context Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Hyperlane and Broadcaster post-fill settlement encode the same context-bearing `FillDescription` that was filled and attested on-chain.

**Architecture:** Introduce one shared `solver-settlement` helper that validates an `OutputFilled` log against the signed `MandateOutput` and returns a verified fill record containing solver, timestamp, and the full output including context. Reuse that record anywhere settlement builds a payload hash or post-fill submission payload.

**Tech Stack:** Rust 2021, Alloy sol types, existing `solver-types` EIP-7683 types, `sha3::Keccak256`, `cargo test -p solver-settlement`.

---

## Current Evidence

- Worktree: `/Users/nahimdhaney/openzeppelin/oif-solver/.worktrees/fix-hyperlane-output-context`
- Branch: `fix/hyperlane-output-context`
- Baseline build: `cargo build` passed.
- Baseline settlement tests: `cargo test -p solver-settlement` passed with `157 passed; 0 failed`.
- Independent `gpt-5.5` investigators confirmed the bug is not already fixed and identified the same lossy flow in Hyperlane and Broadcaster.

## File Map

- Create: `crates/solver-settlement/src/implementations/fill_description.rs`
  - New internal helper module for verified fill extraction, `FillDescription` encoding, and payload hashing.
- Modify: `crates/solver-settlement/src/lib.rs`
  - Wire the helper module inside the inline `pub mod implementations` block.
- Modify: `crates/solver-settlement/src/implementations/hyperlane.rs`
  - Replace local output extraction / log extraction / encoding duplication with the shared helper.
  - Update payload hash and post-fill submission paths.
  - Add Hyperlane regression tests.
- Modify: `crates/solver-settlement/src/implementations/broadcaster.rs`
  - Replace duplicated lossy output extraction / log extraction / encoding with the shared helper.
  - Add Broadcaster regression tests.
- Optional modify: `crates/solver-e2e-tests/src/lib.rs`
  - Add context support to `StandardOrderBuilder`.
- Optional modify: `crates/solver-e2e-tests/tests/submit_e2e_hyperlane.rs`
  - Exercise Hyperlane e2e with `context: vec![0x00]`.

## Task 1: Write the Hyperlane RED Test

**Files:**
- Modify: `crates/solver-settlement/src/implementations/hyperlane.rs`

- [ ] **Step 1: Add the failing test**

Add a unit test near the existing Hyperlane payload/hash tests:

```rust
#[test]
fn hyperlane_payload_hash_includes_output_context() {
	let settlement = test_hyperlane_settlement_with_oracles(1, 137);
	let solver = [0x11; 32];
	let timestamp = 1_700_000_000;
	let order_id = [0x22; 32];
	let mut settler = [0u8; 32];
	settler[12..].copy_from_slice(&[0x44; 20]);
	let mut token = [0u8; 32];
	token[12..].copy_from_slice(&[0x33; 20]);
	let mut recipient = [0u8; 32];
	recipient[12..].copy_from_slice(&[0x55; 20]);
	let mut output = make_mandate_output(
		[0x22; 32],
		settler,
		137,
		token,
		U256::from(42u64),
		recipient,
	);
	output.context = vec![0x00];
	let order = build_test_order_for_emitter_tests(order_id, 1, 137, output.clone());

	let actual = settlement
		.compute_payload_hash(&order, solver, timestamp)
		.expect("payload hash should encode");

	let expected_payload = encode_fill_description(
		solver,
		order_id,
		timestamp,
		output.token,
		output.amount,
		output.recipient,
		output.call,
		output.context,
	)
	.expect("expected payload should encode");
	let mut hasher = Keccak256::new();
	hasher.update(&expected_payload);
	let expected = hasher.finalize();
	let mut expected_hash = [0u8; 32];
	expected_hash.copy_from_slice(&expected);

	assert_eq!(actual, expected_hash);
}
```

- [ ] **Step 2: Run the test and confirm RED**

Run:

```bash
cargo test -p solver-settlement hyperlane_payload_hash_includes_output_context 2>&1 | tee /tmp/hyperlane-context-red.log
```

Expected before fix: FAIL because the actual hash uses empty context.

- [ ] **Step 3: Commit the RED test if using TDD commits**

```bash
git add crates/solver-settlement/src/implementations/hyperlane.rs
git commit -m "test: expose Hyperlane context payload hash regression"
```

## Task 2: Create Shared Verified Fill Helper

**Files:**
- Create: `crates/solver-settlement/src/implementations/fill_description.rs`
- Modify: `crates/solver-settlement/src/lib.rs`

- [ ] **Step 1: Move shared shapes and helpers**

Create an internal module with:

```rust
pub(crate) struct VerifiedFill {
	pub(crate) solver_identifier: [u8; 32],
	pub(crate) timestamp: u32,
	pub(crate) output: solver_types::standards::eip7683::MandateOutput,
}

pub(crate) fn extract_verified_fill_from_logs(
	logs: &[solver_types::Log],
	order: &solver_types::Order,
	order_id: &[u8; 32],
	dest_chain: u64,
) -> Result<VerifiedFill, SettlementError> {
	// Port the existing log filtering and full MandateOutput equality checks
	// from Hyperlane/Broadcaster. Return the decoded output after validation.
}

pub(crate) fn encode_fill_description(
	fill: &VerifiedFill,
	order_id: [u8; 32],
) -> Result<Vec<u8>, SettlementError> {
	// Same byte layout as the existing encoders, using fill.output.context.
}

pub(crate) fn payload_hash(
	fill: &VerifiedFill,
	order_id: [u8; 32],
) -> Result<[u8; 32], SettlementError> {
	// Keccak256 over encode_fill_description(fill, order_id).
}
```

- [ ] **Step 2: Keep validation identical**

Preserve these existing guards:

- expected output must exist for destination chain
- multiple outputs on destination chain are unsupported
- expected settler must be left-padded EVM address
- log emitter must equal expected settler
- topic0 must be `OutputFilled::SIGNATURE_HASH`
- topic1 must equal order id
- decoded oracle, settler, chain id, token, amount, recipient, callback data, and context must match the signed order
- `finalAmount` must equal decoded output amount

- [ ] **Step 3: Wire the module**

Add to the inline `pub mod implementations` block in `crates/solver-settlement/src/lib.rs`:

```rust
mod fill_description;
```

- [ ] **Step 4: Run compile check for the new module**

Run:

```bash
cargo check -p solver-settlement 2>&1 | tee /tmp/solver-settlement-fill-description-check.log
```

Expected: PASS. Treat compile errors as real blockers; unused `pub(crate)` helpers should only warn.

## Task 3: Migrate Hyperlane to Verified Fill

**Files:**
- Modify: `crates/solver-settlement/src/implementations/hyperlane.rs`

- [ ] **Step 1: Replace lossy post-fill transaction construction**

In `HyperlaneSettlement::generate_post_fill_transaction`, replace:

- `extract_output_details(order)?`
- `extract_fill_details_from_logs(...) -> (solver_identifier, fill_timestamp)`
- manual `encode_fill_description(...)`

with:

```rust
let verified_fill = extract_verified_fill_from_logs(
	&fill_receipt.logs,
	order,
	&order_id_bytes,
	dest_chain,
)?;
let fill_description = encode_fill_description(&verified_fill, order_id_bytes)?;
```

- [ ] **Step 2: Replace lossy payload hash computation**

Change `compute_payload_hash` so it accepts or receives a verified fill rather than reconstructing from `OrderOutput`.

Preferred minimal shape:

```rust
fn compute_payload_hash_from_fill(
	&self,
	order_id: [u8; 32],
	fill: &VerifiedFill,
) -> Result<[u8; 32], SettlementError>
```

Then in `handle_transaction_confirmed`, decode the verified fill from the fill receipt logs once and pass it into the hash helper.

- [ ] **Step 3: Update Hyperlane tests for the new helper API**

Move or update existing Hyperlane tests that directly call local helpers so they exercise the shared helpers instead:

- `extract_fill_details_from_logs` tests should assert `VerifiedFill.solver_identifier`, `VerifiedFill.timestamp`, and `VerifiedFill.output.context`.
- `encode_fill_description` tests should call the shared encoder.
- Payload-hash tests should call `compute_payload_hash_from_fill(order_id, &verified_fill)` or shared `payload_hash(&verified_fill, order_id)`.

If the RED test from Task 1 no longer compiles after the API migration, update it to build a `VerifiedFill` from a matching `OutputFilled` log and assert the shared payload hash includes `output.context`.

- [ ] **Step 4: Remove obsolete lossy helpers**

Remove `HyperlaneOutput`, `order_output_to_hyperlane`, and `extract_output_details` from Hyperlane if no longer used.

- [ ] **Step 5: Run the RED test again and confirm GREEN**

Run:

```bash
cargo test -p solver-settlement hyperlane_payload_hash_includes_output_context 2>&1 | tee /tmp/hyperlane-context-green.log
```

Expected: PASS.

## Task 4: Add Broadcaster Regression And Migrate

**Files:**
- Modify: `crates/solver-settlement/src/implementations/broadcaster.rs`

- [ ] **Step 1: Add failing Broadcaster payload test**

Add a unit test proving `parse_fill_payload_from_logs` preserves non-empty context. Build a matching `OutputFilled` log with `output.context = vec![0x00]`, call `parse_fill_payload_from_logs`, and compare against shared `encode_fill_description`.

While the local Broadcaster encoder still exists, avoid name ambiguity by importing the shared helper with an alias:

```rust
use super::fill_description::encode_fill_description as encode_verified_fill_description;
```

- [ ] **Step 2: Confirm RED**

Run:

```bash
cargo test -p solver-settlement broadcaster_payload_includes_output_context 2>&1 | tee /tmp/broadcaster-context-red.log
```

Expected before migration: FAIL because `order_output_to_encoded` hardcodes empty context.

- [ ] **Step 3: Replace Broadcaster lossy construction**

In `BroadcasterSettlement::parse_fill_payload_from_logs`, replace `extract_output_details` plus `(solver, timestamp)` extraction with the shared verified fill helper:

```rust
let verified_fill = extract_verified_fill_from_logs(
	logs,
	order,
	&order_id_bytes,
	destination_chain,
)?;
encode_fill_description(&verified_fill, order_id_bytes)
```

- [ ] **Step 4: Update Broadcaster helper tests**

Move or update existing Broadcaster tests that directly call local helpers so they exercise the shared helpers instead:

- `extract_fill_details_from_logs` tests should assert `VerifiedFill.solver_identifier`, `VerifiedFill.timestamp`, and `VerifiedFill.output.context`.
- `encode_fill_description` tests should call the shared encoder.
- Payload parsing tests should compare against the aliased shared encoder.

- [ ] **Step 5: Remove obsolete duplicated Broadcaster helpers**

Remove Broadcaster-local `EncodedOutput`, `order_output_to_encoded`, `extract_output_details`, and duplicated `extract_fill_details_from_logs` / `encode_fill_description` only after all call sites have moved.

- [ ] **Step 6: Confirm GREEN**

Run:

```bash
cargo test -p solver-settlement broadcaster_payload_includes_output_context 2>&1 | tee /tmp/broadcaster-context-green.log
```

Expected: PASS.

## Task 5: Run Focused Settlement Verification

**Files:**
- No edits.

- [ ] **Step 1: Run all settlement tests once**

Run:

```bash
cargo test -p solver-settlement 2>&1 | tee /tmp/solver-settlement-context.log
```

Expected: PASS, including the new Hyperlane and Broadcaster context tests.

- [ ] **Step 2: Run format check**

Run:

```bash
cargo fmt --all -- --check 2>&1 | tee /tmp/hyperlane-context-fmt.log
```

Expected: PASS. If it fails only due to formatting, run `cargo fmt` and re-run the check.

- [ ] **Step 3: Run CI lint**

Run:

```bash
cargo clippy --all-features --all-targets -- -D warnings --allow deprecated 2>&1 | tee /tmp/hyperlane-context-clippy.log
```

Expected: PASS. This is the CI lint command from `AGENTS.md`.

## Task 6: Optional E2E Regression

**Files:**
- Modify: `crates/solver-e2e-tests/src/lib.rs`
- Modify: `crates/solver-e2e-tests/tests/submit_e2e_hyperlane.rs`

- [ ] **Step 1: Add context to the e2e builder**

Add `context: Vec<u8>` to `StandardOrderBuilder`, default it to `Vec::new()`, add `.context(Vec<u8>)`, and emit it into the built `MandateOutput.context`.

- [ ] **Step 2: Use non-empty context in Hyperlane e2e**

In `solver_submits_via_hyperlane_oracle`, add:

```rust
.context(vec![0x00])
```

- [ ] **Step 3: Run only when environment is available**

Run:

```bash
cargo test -p solver-e2e-tests --test submit_e2e_hyperlane -- --ignored --test-threads=1 --nocapture 2>&1 | tee /tmp/hyperlane-context-e2e.log
```

Expected after fix: PASS. If Foundry, `oif-contracts`, Redis, or fixed ports are unavailable, record that the e2e was not run and why.

## Task 7: Final Cross-Crate Check

**Files:**
- No edits.

- [ ] **Step 1: Run all-target check if shared helper signatures touch public APIs**

Run:

```bash
cargo check --all-targets --all-features 2>&1 | tee /tmp/hyperlane-context-all-targets.log
```

Expected: PASS.

- [ ] **Step 2: Summarize verification**

Report exact commands and relevant pass/fail lines. If e2e was skipped, state the missing prerequisite explicitly.
