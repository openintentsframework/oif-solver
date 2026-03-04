# Pusher Direction Setup Guide

This guide walks through configuring a `pusher_directions` entry for a new L1→L2 direction
in the broadcaster solver config. It assumes the chain pair already has a working broadcaster
settlement (oracles, routes, broadcaster/receiver addresses) and that you only need to add
proactive block hash pushing.

See `block-hash-pusher-service-plan.md` for the full design rationale.

---

## When do you need a pusher direction?

Only directions where proof generation depends on a buffer of L1 block hashes on L2 require
a pusher entry. The pattern is: **L1 fill → prove L1 block on L2**.

| Direction | Needs pusher? | Reason |
|---|---|---|
| ETH→ARB | Yes (¹) | Proof requires ETH block hash in ARB buffer |
| ETH→OP | Yes | Proof requires ETH block hash in OP buffer |
| ETH→Linea | Yes | Proof requires ETH block hash in Linea buffer |
| ARB→ETH | No | Proof uses Arbitrum Outbox sendRoot on ETH |
| OP→ETH | No | Proof uses OP AnchorStateRegistry on ETH |

(¹) ETH→ARB uses the `IArbitrumPusher` ABI (inbox-based) rather than the generic `IPusher`
interface. Configure it with `"l2_params": {"type": "arbitrum", ...}` — the solver dispatches
to the correct ABI automatically based on the variant. See Step 2 for the full field reference.

---

## Step 1: Confirm contracts are deployed

You need two contracts deployed and paired:

- **IPusher** on L1 — builds block hash arrays and sends them cross-chain
- **IBuffer** on L2 — stores the received hashes and answers `newestBlockNumber()` / `parentChainBlockHash()`

The pusher and buffer must be paired: the buffer's `pusher()` must return the L1 pusher
address (or its aliased form for ARB/ZkSync).

Verify with:

```bash
# Check the buffer knows its paired pusher
cast call $BUFFER_ADDRESS "pusher()(address)" --rpc-url $L2_RPC

# Check the buffer's current newest block
cast call $BUFFER_ADDRESS "newestBlockNumber()(uint256)" --rpc-url $L2_RPC | awk '{print $1}'

# Check current L1 head to see the lag
cast block-number --rpc-url $L1_RPC
```

The buffer's `pusher()` return value must match the deployed `IPusher` address (for OP/Linea/Scroll)
or its Arbitrum-aliased address (for ARB/ZkSync).

---

## Step 2: Configure `l2_params`

`l2_params` is a typed JSON object that tells the solver how to call the pusher contract.
Choose the variant that matches your L2 chain:

### Optimism / Base / OP Stack

```json
"l2_params": {
  "type": "op_stack",
  "gas_limit": 200000
}
```

`msg.value = 0` (enforced by the contract). `gas_limit` is the L2 gas budget for the
`receiveHashes` call. A 256-slot batch costs roughly 5–10M gas on OP; start with 200k
for small batches and profile from there.

### Arbitrum

```json
"l2_params": {
  "type": "arbitrum",
  "inbox": "0x<RetryableTx inbox address on ARB>",
  "gas_price_bid": 100000000,
  "gas_limit": 16000000,
  "submission_cost": 1000000000000000,
  "is_erc20_inbox": false
}
```

`msg.value = gas_limit * gas_price_bid + submission_cost`. All numeric fields are in wei.
`is_erc20_inbox` defaults to `false` if omitted.

### Linea

```json
"l2_params": {
  "type": "linea",
  "fee": 1000000000000000
}
```

`msg.value = fee`. The fee goes to the Linea postman that relays the message on L2.
Query the current Linea fee from the rollup contract or use a conservative fixed value.

### Other / unknown chains (Raw fallback)

For chains not yet typed (Scroll, ZkSync, etc.), use the `raw` variant with the exact
hex-encoded `l2TransactionData` bytes. Compute it with `cast abi-encode` as needed:

```json
"l2_params": {
  "type": "raw",
  "data": "0x<hex-encoded l2TransactionData>",
  "value_wei": 0
}
```

`value_wei` defaults to `0` if omitted. Set it to the required `msg.value` in wei.

**Migration note:** Configs with a legacy `l2_transaction_data` hex string still work
(the solver falls back to chain-ID-based inference), but `l2_params` is preferred and
`l2_transaction_data` will be removed in a future release.

---

## Step 3: Choose `push_cooldown_seconds`

This is the minimum time between push transactions for a given direction. It must exceed the
expected cross-chain message execution time on L2:

| L2 Chain | Typical execution time | Recommended `push_cooldown_seconds` |
|---|---|---|
| OP / Base | ~2–5 min | 600 |
| Linea | ~5–15 min (postman dependent) | 900 |
| Scroll | ~5–15 min | 900 |
| ZkSync Era | ~5–15 min | 900 |
| ARB Sepolia | ~10–15 min (auto-redeem); 30+ min if OOG | 900–1800 |

Too low: risks duplicate pushes while the first one is still in flight.
Too high: buffer lag grows before the next push fires.

---

## Step 4: Add the config entry

Add to the `pusher_directions` array in `settlement.broadcaster`. Example for OP Stack:

```json
{
  "settlement": {
    "type": "broadcaster",
    "broadcaster": {
      "pusher_directions": [
        {
          "pusher_address": "0x<IPusher on L1>",
          "buffer_address": "0x<IBuffer on L2>",
          "push_cooldown_seconds": 900,
          "l2_params": {
            "type": "op_stack",
            "gas_limit": 200000
          }
        }
      ]
    }
  }
}
```

Optional fields with defaults — only set these if you need to override:

```json
{
  "l1_chain_id": 11155111,
  "l2_chain_id": 11155420,
  "batch_size": 256,
  "label": "eth-to-op-sepolia"
}
```

---

## Step 5: Verify the setup

After starting the solver, confirm the pusher task is working:

**Check buffer lag in logs:**
```text
buffer_lag_blocks direction=eth-to-arb-sepolia lag=45
```

**Manually check buffer state:**
```bash
# Buffer newest block on L2
NEWEST=$(cast call $BUFFER_ADDRESS "newestBlockNumber()(uint256)" --rpc-url $L2_RPC | awk '{print $1}')
# Current L1 head
L1_HEAD=$(cast block-number --rpc-url $L1_RPC)
echo "Buffer lag: $((L1_HEAD - NEWEST)) blocks"
```

**After a push fires, confirm the buffer advances:**
```bash
# Wait push_cooldown_seconds, then re-check newestBlockNumber
cast call $BUFFER_ADDRESS "newestBlockNumber()(uint256)" --rpc-url $L2_RPC | awk '{print $1}'
```

If the buffer does not advance within `push_cooldown_seconds`, the solver will emit a
`RETRYABLE_NOT_EXECUTED` alert. For ARB, this means the retryable ticket needs a manual redeem
(see `eth-arb-sepolia-solver-improvement-plan.md` runbook step 6).

---

## Known deployed contracts (Sepolia testnets)

| Direction | L1 Pusher | L2 Buffer | `l2_params` type | Status |
|---|---|---|---|---|
| ETH→ARB Sepolia | `0x5a5c4f3d...` (`IArbitrumPusher`) | `0x0000000048C4Ed10...` | `arbitrum` | Config-driven via `pusher_directions` |
| ETH→OP Sepolia | TBD | TBD | `op_stack` | Not yet deployed |
| ETH→Base Sepolia | TBD | TBD | `op_stack` | Not yet deployed |

---

## References

- `block-hash-pusher-service-plan.md` — full design and architecture
- `eth-arb-sepolia-solver-improvement-plan.md` — ETH/ARB operational runbook
- `broadcaster/src/contracts/block-hash-pusher/` — all pusher and buffer contracts
