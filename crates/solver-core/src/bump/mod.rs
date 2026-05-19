//! Same-nonce gas bumping for stuck pending transactions.

pub mod lineage;
pub mod policy;
pub mod service;

pub use policy::{apply_bump_percent, bumped_fees_exceed_cap, BumpFees};
pub use service::TransactionBumpService;
