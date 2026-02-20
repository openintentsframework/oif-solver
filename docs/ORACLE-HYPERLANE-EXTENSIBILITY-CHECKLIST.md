# Oracle and Hyperlane Checklist

Date: February 19, 2026

Purpose:
- Explain how Hyperlane works in this solver.
- Clarify what you need to deploy on a brand new chain.
- Provide a checklist for adding a different oracle/settlement type later.

## 1) Hyperlane In General (Short Version)

Hyperlane is a cross-chain messaging protocol with chain-local contracts and off-chain relayer/validator components.

Core concepts:

- `Mailbox` on each chain:
  - Source chain app dispatches a message through Mailbox.
  - Destination Mailbox receives and delivers message to recipient app.
- Security module and validators:
  - Validators attest messages/checkpoints.
  - Destination verifies according to configured security model.
- `IGP` (Interchain Gas Paymaster):
  - Lets source-side transaction prepay destination execution gas.

## 2) How This Solver Uses Hyperlane

Current seeded runtime uses `settlement.implementations.hyperlane`.

Flow in this repo:

1. Fill happens on destination/output chain.
2. Solver submits a post-fill message via `hyperlane_oracle.submit(...)`.
3. Message targets the input-side oracle on origin chain.
4. Solver checks message delivery/readiness before claim finalization.

Required config for Hyperlane settlement in this repo:

- `oracles.input`
- `oracles.output`
- `routes`
- `mailboxes`
- `igp_addresses`
- `default_gas_limit`

## 3) Do You Need To Deploy Hyperlane Contracts On A New Network?

Usually, yes for a truly new chain integration.

Checklist:

- [ ] Verify whether Hyperlane core is already deployed on target chain.
- [ ] If not present, deploy/enable Hyperlane core stack for that chain.
- [ ] Obtain canonical `mailbox` and `igp` addresses for that chain.
- [ ] Deploy or configure the OIF-compatible `hyperlane_oracle` contract on that chain.
- [ ] Configure oracle routing between new chain and paired chain.

Practical note:
- Even if Mailbox/IGP already exist, you still need oracle contracts and route/oracle config aligned with your app.

## 4) Oracle Configuration Validation Rules You Must Satisfy

- [ ] Each chain in `oracles.input` has at least one address.
- [ ] Each chain in `oracles.output` has at least one address.
- [ ] Each route source exists in input oracle map.
- [ ] Each route destination exists in output oracle map.
- [ ] Routes are explicit (or generated intentionally as full mesh).

## 5) Recommended Onboarding Route Pattern (New + Pair)

If you run only two networks, start with explicit bidirectional routes:

```toml
[routes]
NEW_CHAIN_ID = [PAIR_CHAIN_ID]
PAIR_CHAIN_ID = [NEW_CHAIN_ID]
```

If you later add more chains, review whether full mesh is intended. Do not assume full mesh is always desirable.

## 6) If You Want To Support Another Oracle Type

In this architecture, oracle behavior is tied to settlement implementation. To support a new oracle protocol, add a new settlement implementation.

Implementation checklist:

- [ ] Create new file under `crates/solver-settlement/src/implementations/<name>.rs`.
- [ ] Implement `SettlementInterface`.
- [ ] Define config schema validation (`ConfigSchema`) for your oracle inputs.
- [ ] Implement factory function `create_settlement(...)`.
- [ ] Register implementation in `crates/solver-settlement/src/lib.rs` via `get_all_implementations()`.
- [ ] Ensure it is auto-registered in service factory registry (`crates/solver-service/src/factory_registry.rs`).
- [ ] Add config generation/extraction support in merge paths if needed.
- [ ] Add unit tests for schema validation and runtime behavior.
- [ ] Add integration smoke test with seeded config and at least 2 chains.

## 7) Configuration Model Recommendation For Multi-Oracle Future

To support multiple oracle backends cleanly:

- Keep per-network contract addresses in operator config, not only static seeds.
- Keep oracle routes in operator config and expose admin API for route edits.
- Add `settlement.primary` selection and optional fallback semantics.
- Add dry-run validator endpoint for settlement config before persistence.

## 8) Pre-Production Oracle Go/No-Go

- [ ] Oracle contracts deployed and verified on all participating chains.
- [ ] Mailbox + IGP addresses validated per chain.
- [ ] Route table validated against oracle tables.
- [ ] Post-fill message dispatch confirmed in staging.
- [ ] Claim readiness path confirmed in staging.
- [ ] Failure path tested (message not delivered, wrong route, wrong oracle).

## 9) Key Code References

- Hyperlane settlement implementation: `crates/solver-settlement/src/implementations/hyperlane.rs`
- Oracle parsing and route validation utilities: `crates/solver-settlement/src/utils.rs`
- Settlement interface and registry list: `crates/solver-settlement/src/lib.rs`
- Dynamic factory auto-registration: `crates/solver-service/src/factory_registry.rs`
- Settlement timing guide (all implementations): `docs/oracles/settlement-timing-configuration.md`
