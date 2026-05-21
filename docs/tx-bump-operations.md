# Transaction Bump Operations

The transaction bump sweeper is the solver's same-nonce replacement loop for stale in-flight attempts. It is useful for unattended operation during fee spikes, but it also automates gas spending. Treat `tx_bump.enabled = true` as an operational decision, not only a code switch.

## What It Guarantees

- CAS-protected order status and transaction-hash updates for order-stage transitions.
- Same-nonce replacement only for non-terminal attempt lineages that pass the configured age, cap, signer, deadline, and profitability checks.
- Receipt preflight before replacement so a mined lineage tip is reconciled instead of blindly replaced.
- Attempt-ledger writeback during recovery when chain evidence proves a previously broadcast attempt confirmed during downtime.
- Operator-visible events for canonical hash conflicts, attempt-ledger conflicts, receipt preflight failures, missing nonces, missing submission signers, skipped balance checks, and submit failures.

## What It Does Not Guarantee

- Deep reorg recovery after a transaction has passed the configured confirmation depth.
- Protection from unsafe fee caps, overly aggressive sweep intervals, or underfunded signer wallets.
- Uniform behavior across RPC providers or mempools. Same-nonce replacement rules are chain/provider dependent.
- Automatic rollback when `TransactionCanonicalHashConflict` fires. That event is an alert that an operator must investigate.
- Automatic recovery when receipt preflight repeatedly fails and the chain is configured to fail closed.

## Configuration Checklist

Before enabling the sweeper on a chain:

- Keep `tx_bump.enabled = false` until the chain-specific caps, signer funding, and alerts are configured.
- Add only the chains you intend to bump under `tx_bump.chains`.
- Set `default_max_fee_per_gas_cap_wei` and/or per-chain `max_fee_per_gas_cap_wei`.
- Set `default_max_priority_fee_per_gas_cap_wei` and/or per-chain `max_priority_fee_per_gas_cap_wei`.
- Keep `default_receipt_preflight_fail_closed = true` unless you explicitly accept submitting replacements when the receipt check is unavailable.
- Prefer `profitability_gate_fail_closed = true` for chains where strict cost control is more important than liveness.
- Choose `pending_threshold_secs` above normal confirmation time for the chain.
- Keep `sweep_interval_secs` high enough that one bad condition does not cause noisy repeated attempts.
- Set `max_replacements_per_stage` to a small number until you have enough bump telemetry to tune it.
- Configure low native-balance alerts for every signer used by delivery.

Example:

```json
{
  "tx_bump": {
    "enabled": false,
    "sweep_interval_secs": 15,
    "default_pending_threshold_secs": 60,
    "default_bump_percent": 15,
    "default_max_replacements_per_stage": 3,
    "default_max_fee_per_gas_cap_wei": "150000000000",
    "default_max_priority_fee_per_gas_cap_wei": "5000000000",
    "default_profitability_gate_fail_closed": false,
    "default_receipt_preflight_fail_closed": true,
    "chains": {
      "8453": {
        "pending_threshold_secs": 60,
        "bump_percent": 15,
        "max_replacements_per_stage": 3,
        "max_fee_per_gas_cap_wei": "50000000000",
        "max_priority_fee_per_gas_cap_wei": "2000000000",
        "profitability_gate_fail_closed": true,
        "receipt_preflight_fail_closed": true
      }
    }
  }
}
```

## Required Alerts

Alert on these events before enabling bumping:

| Event | Meaning | Action |
|---|---|---|
| `TransactionCanonicalHashConflict` | A duplicate confirmation observed a different hash from the stored canonical stage hash. | Investigate chain receipts, reorg risk, and settlement proof inputs before continuing the order manually. |
| `TransactionAttemptLedgerConflict` | A chain-truth update could not be written to the attempt ledger, usually because another path terminalized the attempt. | Inspect the attempt lineage and confirm the terminal row matches chain truth. |
| `BumpReceiptPreflightSkipped` | The sweeper could not check whether the tip already mined. | Check RPC health. If `fail_closed = true`, bumping stops for that attempt until the preflight can run. |
| `BumpTipAlreadyMined` | Receipt preflight found the lineage tip mined and skipped replacement. | Usually informational. Alert if high volume indicates monitor lag. |
| `BumpMissingNonce` | The lineage tip has no nonce, so same-nonce replacement is impossible. | Inspect attempt recording and delivery metadata. |
| `BumpSubmissionSignerUnavailable` | No submission signer is configured for the chain. | Fix delivery/account configuration before enabling the chain. |
| `BumpBalanceCheckSkipped` | The signer balance check could not be trusted. | Check RPC/balance parsing and signer funding. |
| `BumpSubmitFailed` | Replacement submission failed outside the known recoverable paths. | Inspect delivery error, nonce state, caps, and RPC health. |

Also alert on:

- CAS retry exhaustion in order state updates.
- Signer native balance below the configured reserve.
- Repeated `BumpCapReached`.
- Repeated `BumpMaxReplacementsReached`.

## Enablement Procedure

1. Start with `tx_bump.enabled = false`.
2. Configure only the chains that should be bumped under `tx_bump.chains`.
3. Wire alerts for `TransactionCanonicalHashConflict`, `TransactionAttemptLedgerConflict`, `BumpReceiptPreflightSkipped`, and CAS retry exhaustion.
4. Confirm signer balances and fee caps during a simulated or natural fee spike.
5. Enable one chain at a time.
6. Keep initial caps conservative and raise them only with operator approval.
7. Review bump events regularly after enabling.

## Incident Playbook

### Canonical Hash Conflict

1. Do not assume the latest observed hash is safe to settle with.
2. Compare stored order hash, attempt ledger rows, and on-chain receipts.
3. Check whether a reorg or split-brain monitor path can explain the conflict.
4. Continue settlement only after choosing the canonical receipt manually.

### Receipt Preflight Skipped

1. Check RPC health and receipt availability for the affected chain.
2. If `fail_closed = true`, the sweeper intentionally skips replacement.
3. If the chain must keep moving, temporarily choose a healthier RPC endpoint before considering fail-open behavior.

### Bump Cap Reached

1. Check whether gas is temporarily spiking or caps are too low for the chain.
2. Confirm the order remains profitable before raising caps.
3. Prefer per-chain cap changes over raising global defaults.

### Signer Balance Low Or Balance Check Skipped

1. Top up the chain-specific signer balance.
2. Check whether balance RPCs are failing or returning unparsable values.
3. Do not enable additional chains until signer funding alerts are reliable.

## Related Docs

- [Fee Policy](fee-policy.md)
- [Configuration Storage](config-storage.md)
- [Same-Nonce Gas Bumping Design](superpowers/tx-hardening/06-same-nonce-gas-bumping.md)
