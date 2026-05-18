//! Same-nonce gas bumping for stuck pending transactions.
//!
//! PR 06 of the transaction-hardening series. See
//! `docs/superpowers/specs/2026-05-16-tx-bump-design.md`.

pub mod lineage;
pub mod policy;
pub mod service;

pub use policy::{apply_bump_percent, bumped_fees_exceed_cap, BumpFees};
pub use service::TransactionBumpService;
