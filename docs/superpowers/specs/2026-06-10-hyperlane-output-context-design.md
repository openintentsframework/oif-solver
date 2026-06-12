# Hyperlane Output Context Settlement Design

## Problem

Hyperlane settlement currently rebuilds `FillDescription` from `OrderOutput`, which is a generic API shape that does not carry EIP-7683 `MandateOutput.context`. The fill transaction preserves context when it builds `SolMandateOutput`, and `OutputFilled` logs also include the filled `MandateOutput`. As a result, any accepted context-bearing output can be filled with one payload and later proven or submitted with another.

The issue is present on the new `fix/hyperlane-output-context` branch:

- `MandateOutput.context` exists in `crates/solver-types/src/standards/eip7683.rs`.
- `OrderOutput` in `crates/solver-types/src/api.rs` has no context field.
- `parse_requested_outputs` drops `MandateOutput.context`.
- `crates/solver-settlement/src/implementations/hyperlane.rs` reconstructs context as `vec![]`.
- `crates/solver-settlement/src/implementations/broadcaster.rs` has the same lossy pattern.

## Root Cause

The root cause is not the `FillDescription` encoder. It already appends callback length/data and context length/data. The root cause is that settlement code uses a lossy projection (`OrderOutput`) as the source of truth after a fill.

The `OutputFilled` log decode path already has the correct data:

1. It filters by expected settler emitter.
2. It filters by order id.
3. It decodes `SolMandateOutput`.
4. It compares oracle, settler, chain id, token, amount, recipient, callback data, and context against the signed order output.

After this validation, the decoded output is safe to use as the construction source for `FillDescription`.

## Design

Add an internal settlement helper that returns a verified filled output instead of only `(solver, timestamp)`.

Suggested shape:

```rust
struct VerifiedFill {
	solver_identifier: [u8; 32],
	timestamp: u32,
	output: MandateOutput,
}
```

The helper should parse the signed order output, decode the matching `OutputFilled` event, validate every decoded output field against the signed `MandateOutput`, reject divergent `finalAmount`, and return the validated decoded output.

Use this helper in both Hyperlane and Broadcaster settlement paths:

- `HyperlaneSettlement::generate_post_fill_transaction`
- `HyperlaneSettlement::handle_transaction_confirmed` / payload hash tracking
- `BroadcasterSettlement::parse_fill_payload_from_logs`

Then encode `FillDescription` from:

- `verified_fill.solver_identifier`
- `order_id`
- `verified_fill.timestamp`
- `verified_fill.output.token`
- `verified_fill.output.amount`
- `verified_fill.output.recipient`
- `verified_fill.output.call`
- `verified_fill.output.context`

This keeps the signed order as the validation authority and the verified event as the post-fill construction authority. It also removes duplication between Hyperlane and Broadcaster instead of fixing only one copy.

## Non-Goals

- Do not add a second EVM library.
- Do not change external order APIs as part of the core fix.
- Do not add backwards-compat shims for old lossy payload hashes.
- Do not run the full workspace test suite unless explicitly requested.

## Optional Follow-Up

`PostFillFeeParams` quote-time paths currently estimate with empty context. That does not cause the stranded-proof failure, but it can underquote message gas for context-bearing outputs. If quote accuracy is in scope, add output context to fee quote inputs or derive it from order data before quoting.

## Verification

Primary unit regression:

- Add a Hyperlane unit test proving `compute_payload_hash` includes non-empty `MandateOutput.context`.
- Add a Broadcaster unit test proving parsed fill payload includes non-empty context.

Optional e2e regression:

- Extend `StandardOrderBuilder` in `crates/solver-e2e-tests` to set context.
- Run the ignored Hyperlane e2e with `context: vec![0x00]`.

