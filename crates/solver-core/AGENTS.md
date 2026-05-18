# solver-core — Agent Guide

The orchestration engine. Coordinates the full lifecycle: discovery → order processing → delivery → settlement.

## Where new functionality belongs

New lifecycle stages or behaviors usually do **not** belong directly in this crate. The pattern is:

1. Add the trait to `solver-types`.
2. Add the implementation to the specialized crate (`solver-settlement`, `solver-delivery`, `solver-storage`, etc.).
3. Wire it through `solver-core` only as orchestration glue.

If you're tempted to add business logic directly to `solver-core`, first check whether it should live as a trait in `solver-types` plus an impl elsewhere.

## Test helpers

The `test-helpers` feature exposes seams for integration tests in other crates. Enable with `--features test-helpers`. Do not gate production code paths behind this feature.

## Invariant: OIF contracts enforce on-chain idempotency

A single intent can be filled, claimed, and settled exactly once on-chain. The contract enforces this regardless of how many transactions the solver submits. The failure mode this crate guards against is **stranded funds** — a transaction succeeds on-chain but the solver loses track of it — not double-execution. Any retry, replacement, or recovery design must preserve this framing.
