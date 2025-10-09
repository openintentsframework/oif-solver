//! Builder patterns for solver types
//!
//! This module provides fluent builder APIs for constructing various types
//! with sensible defaults and validation.

pub mod asset_amount;
pub mod eip7683_order_data;
pub mod intent;
pub mod mandate_output;
pub mod networks;
pub mod order;
pub mod transaction;
pub mod transaction_receipt;

// Re-export builders for convenience
pub use asset_amount::{AssetAmountBuilder, AssetAmountBuilderError};
pub use eip7683_order_data::{Eip7683OrderDataBuilder, Eip7683OrderDataBuilderError};
pub use intent::IntentBuilder;
pub use mandate_output::{MandateOutputBuilder, MandateOutputBuilderError};
pub use networks::{
	NetworkConfigBuilder, NetworkConfigBuilderError, NetworksConfigBuilder,
	NetworksConfigBuilderError, TokenConfigBuilder, TokenConfigBuilderError,
};
pub use order::OrderBuilder;
pub use transaction::{TransactionBuilder, TransactionBuilderError};
pub use transaction_receipt::TransactionReceiptBuilder;
