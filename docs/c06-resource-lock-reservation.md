# C-06 — Resource-Lock In-Flight Reservation Accounting (design note)

Status: **design note only.** Part A (reject client-supplied `lock.params`) is
implemented. Part B (reservation accounting) is deferred — see "Why deferred"
below — and specified here so it can be implemented as a focused follow-up PR
without re-deriving the scheme.

## Problem

`ensure_user_capacity_for_order`
(`crates/solver-service/src/validators/order.rs`) admits a resource-lock order
after a single **stateless** `balanceOf(owner, id)` read against TheCompact via
`validate_compact_deposit_for_order`. There is no escrow and no reservation:

- For Permit2/EIP-3009 escrow orders, `openFor` (prepare) pulls funds on the
  origin chain, so a double-spend of the same allowance reverts on-chain.
- For **resource-lock** orders, prepare/escrow is **skipped** — the solver fills
  on the destination chain and only later claims against the compact deposit on
  the origin chain. The OIF/TheCompact contract enforces single-claim
  idempotency per intent, but it does **not** prevent two *distinct* intents
  from both being backed by the *same* deposit.

Result: N concurrent or sequential resource-lock orders, each `<= balanceOf`
individually but `> balanceOf` in aggregate, all pass intake and all get
filled. Only one claim can succeed; the remaining fills are unrecoverable
solver losses (funds already sent on the destination chain, nothing to claim on
the origin chain).

Today this is mitigated **only** by the default-off kill switch
`solver.resource_lock_enabled` (PR #382) — a feature gate, not a fix.

## Why this is deferred (not half-implemented)

Fund-critical accounting must be correct and exactly-once. A safe
implementation spans two crates and several engine transitions:

1. The **reserve** happens at HTTP intake (`solver-service`), but
   `solver-service`'s own `AGENTS.md` is explicit that orchestration/business
   logic does not belong there — only the HTTP shell does.
2. The **release** must fire on every terminal order transition inside the
   `solver-core` engine lifecycle (`OrderStatus::Finalized` and every
   `OrderStatus::Failed(..)` path, including recovery/abandonment), and must be
   idempotent so a ret* or crash-replay never double-releases.
3. There is no existing reservation namespace/schema; introducing one is a
   storage schema addition that, per repo convention, is a clean break with
   migration rather than a coexistence shim.

Per `AGENTS.md` ("Don't half-implement fund-critical accounting"; "minimal,
focused implementations win"), this is delivered as a precise spec plus a
tracked `TODO(C-06, part B)` at the exact insertion point in
`crates/solver-service/src/validators/order.rs`, rather than a partial
implementation that could itself strand funds.

## Reservation model

A reservation tracks the sum of in-flight reserved amounts per deposit:

```
key:   reservation:{chain_id}:{owner_lowercase_hex}:{token_id_decimal}
value: U256 (decimal or 32-byte big-endian) = sum of reserved amounts
```

`token_id` is the full 32-byte TheCompact id (allocator lock tag ‖ token
address), i.e. `input[0]` in `StandardOrder::inputs` — NOT the bare ERC-20
address. Two orders against the same ERC-20 but different allocator lock tags
are distinct deposits and must key separately.

Admission rule (atomic):

```
available = balanceOf(owner, token_id)            // on-chain read, TheCompact
reserved  = current reservation counter           // storage read
admit iff  available >= reserved + order_amount
on admit:  reserved += order_amount               // same atomic step
```

The `balanceOf` read is not part of the atomic section (it is an RPC call); the
**counter mutation** is. Because `reserved` only ever grows on admit and shrinks
on release, comparing `available >= reserved + amount` with an atomically
incremented `reserved` is conservative: concurrent admits cannot both observe a
stale low `reserved` and both succeed, as long as the increment is a
compare-and-swap / atomic add.

### Atomic primitive

Use the existing storage abstraction; do not add a second mechanism:

- **Preferred:** add an atomic `increment_by(key, delta, ttl) -> new_value`
  (and `decrement_by`/`release`) to `StorageInterface`
  (`crates/solver-storage/src/lib.rs`). Redis backend → native `INCRBY`/`DECRBY`
  (or a small Lua script that also enforces a floor of 0 and the
  `reserved + amount <= available` admission check in one round trip, passing
  `available` in as an argument). Memory/file backends → `RwLock` as the other
  atomic ops already do (`set_nx`, `compare_and_swap`).
- **Without touching the trait:** a CAS loop on the existing
  `StorageInterface::compare_and_swap(key, expected, new_value, ttl)`:
  read counter → compute `new = old + amount` → `compare_and_swap`; retry on
  `Ok(false)`. Correct but more round-trips; acceptable for the expected
  contention level. The single-Lua approach is preferred because it folds the
  admission check and the increment into one atomic step and avoids a
  TOCTOU window between the `balanceOf` read and the reserve.

U256 amounts exceed Redis INCRBY's 64-bit range in the general case. Either (a)
store the counter as a decimal string and do the add in a Lua script using
string/bignum handling, or (b) gate on the practical invariant that a single
deposit's reserved sum fits in i64 for supported tokens and reject otherwise.
Option (a) is the robust choice.

### TTL / leak protection

Set a TTL on the reservation key equal to (or slightly above) the order's
`expires` / `fillDeadline` horizon, so an order that is admitted but never
reaches a terminal release (process crash between reserve and the engine
recording the order) cannot leak reserved capacity forever. The release path
still decrements explicitly; TTL is the backstop, not the primary mechanism.

## Lifecycle hooks (release)

Reservations are created at intake and released by `solver-core` on terminal
transitions. The order already carries the `(chain_id, owner, token_id, amount)`
tuple needed to compute the key (it is in the persisted `StandardOrder`
inputs), so the release path can reconstruct keys without extra state.

Release on:

- `OrderStatus::Finalized` — claim confirmed on the origin chain. The deposit
  was consumed on-chain, so `balanceOf` has already dropped by `amount`;
  decrement the reservation by `amount` so the now-smaller on-chain balance is
  matched by a correspondingly smaller `reserved`. (Net effect on
  `available - reserved` is zero, which is correct: that capacity is gone.)
- `OrderStatus::Failed(..)` — definitive failure before claim. Funds were
  *not* claimed, so the deposit is still on-chain and free; decrement the
  reservation by `amount` to return the capacity to other orders.

Both releases MUST be idempotent (guard with a per-order
`reservation_released` flag persisted on the order, or a single-use marker key),
because the engine can re-enter terminal handling on retry/replay. A double
release would corrupt the counter and re-introduce oversubscription.

Wiring: per `crates/solver-core/AGENTS.md`, add a `ReservationStore` trait to
`solver-types`, implement it in `solver-storage`, and call it from `solver-core`
as orchestration glue at the terminal transition points in
`crates/solver-core/src/state/order.rs` /
`crates/solver-core/src/engine/lifecycle.rs`. Do not embed the accounting logic
directly in `solver-core` or in the HTTP handler.

## Failure modes to handle explicitly

1. **Crash after reserve, before order persisted:** TTL backstop reclaims the
   reservation; no permanent leak.
2. **Crash after fill, before `Finalized`/`Failed` recorded:** recovery path
   must re-derive and converge the reservation (e.g. on startup, rebuild
   reservations from non-terminal persisted orders rather than trusting the
   counter). Simplest correct approach: on startup, **rebuild** the reservation
   counters from the set of non-terminal resource-lock orders (clean-break
   reconcile), consistent with the repo's "clean break with migration" rule.
3. **Concurrent admits of the same deposit:** prevented by the atomic
   increment + admission check (single Lua or CAS loop). Never compare against a
   non-atomically-read counter.
4. **Partial fills:** if partial fills are enabled, reserve/release must use the
   actually-committed input amount, not the quoted maximum. Confirm against the
   partial-fill amount semantics before implementing.
5. **Multi-input orders:** reserve per input `(token_id)`; release all on
   terminal transition. A failure to reserve any one input must roll back the
   already-reserved inputs for that order (reserve all-or-nothing per order).

## Test plan for the follow-up PR (RED first)

- Two orders against the same deposit: first reserves `0.7 * balance`, second
  requests `0.5 * balance` → second is rejected (`balanceOf` unchanged in the
  mock; reservation makes the aggregate exceed balance). This is the core RED
  test for part B.
- Release on `Failed` frees capacity: after the first order fails, a new order
  for `0.6 * balance` is admitted.
- Idempotent release: invoking release twice for the same order does not drive
  the counter negative and does not free capacity twice.
- Concurrency: spawn N tasks admitting against one deposit whose balance allows
  exactly K < N; exactly K succeed.

## Scope delivered in this PR

- **Part A (done):** `generate_resource_lock_order` now rejects any non-empty
  `lock.params` instead of silently dropping them (the signed message is built
  entirely server-side). The unused `_params` argument was removed from
  `build_compact_message` / `build_rhinestone_message`.
- **Part B (this note + `TODO(C-06, part B)`):** specified, not implemented, for
  the reasons in "Why deferred". The kill switch `resource_lock_enabled`
  remains the operational mitigation until part B lands.
