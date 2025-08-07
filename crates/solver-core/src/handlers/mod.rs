//! Event handlers for processing solver events.
//!
//! This module contains specialized handlers for different aspects of the order
//! lifecycle: intent discovery, order preparation and execution, transaction
//! monitoring, and settlement claiming.

pub mod intent;
pub mod order;
pub mod settlement;
pub mod transaction;

pub use intent::IntentHandler;
pub use order::OrderHandler;
pub use settlement::SettlementHandler;
pub use transaction::TransactionHandler;
