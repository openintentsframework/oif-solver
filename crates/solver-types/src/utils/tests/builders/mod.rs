//! Builder patterns for solver types
//!
//! This module provides fluent builder APIs for constructing various types
//! with sensible defaults and validation.

pub mod asset_amount;
pub mod available_input;
pub mod eip7683_order_data;
pub mod get_quote_request;
pub mod intent;
pub mod mandate_output;
pub mod networks;
pub mod order;
pub mod requested_output;
pub mod transaction;
pub mod transaction_receipt;

// Re-export builders for convenience
pub use asset_amount::{AssetAmountBuilder, AssetAmountBuilderError};
pub use available_input::{AvailableInputBuilder, AvailableInputBuilderError};
pub use eip7683_order_data::{Eip7683OrderDataBuilder, Eip7683OrderDataBuilderError};
pub use get_quote_request::{GetQuoteRequestBuilder, GetQuoteRequestBuilderError};
pub use intent::IntentBuilder;
pub use mandate_output::{MandateOutputBuilder, MandateOutputBuilderError};
pub use networks::{
	NetworkConfigBuilder, NetworkConfigBuilderError, NetworksConfigBuilder,
	NetworksConfigBuilderError, RpcEndpointBuilder, RpcEndpointBuilderError, TokenConfigBuilder,
	TokenConfigBuilderError,
};
pub use order::OrderBuilder;
pub use requested_output::{RequestedOutputBuilder, RequestedOutputBuilderError};
pub use transaction::{TransactionBuilder, TransactionBuilderError};
pub use transaction_receipt::TransactionReceiptBuilder;
