//! Order processing types for the solver system.
//!
//! This module defines types related to validated orders, execution decisions,
//! and fill proofs used throughout the order lifecycle.

use alloy_primitives::U256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;

use crate::{
	Address, AssetAmount, ChainData, OrderInput, OrderOutput, SettlementType, TransactionHash,
	TransactionType,
};

#[cfg(feature = "oif-interfaces")]
use crate::Eip7683OrderData;

/// Information about a chain and its associated settler contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainSettlerInfo {
	/// The chain ID
	pub chain_id: u64,
	/// The settler contract address on this chain
	pub settler_address: Address,
}

/// Trait for parsing order data from different standards into common structures.
///
/// This trait provides a unified interface for extracting order information
/// from various cross-chain order standards (e.g., EIP-7683, etc.). It enables
/// the solver to work with different order formats through a consistent API,
/// abstracting away the implementation details of each standard.
///
/// # Purpose
///
/// Different cross-chain protocols may represent orders in various formats, but
/// they all share common concepts like inputs (what the user provides) and outputs
/// (what the user receives). This trait standardizes access to these common elements,
/// allowing the solver's core logic to remain agnostic to the specific order standard.
///
/// # Implementation Guidelines
///
/// When implementing this trait for a new order standard:
/// - Ensure all conversions are deterministic and consistent
/// - Handle missing or invalid data gracefully with sensible defaults
/// - Preserve all precision when converting amounts (use U256)
/// - Use InteropAddress for cross-chain compatible addressing
pub trait OrderParsable: Send + Sync {
	/// Extract available inputs from the order data.
	///
	/// Available inputs represent the assets that the order maker is willing
	/// to provide as part of the transaction. Each input includes:
	/// - The user who owns the assets
	/// - The asset details (token address and chain)
	/// - The amount being offered
	/// - Optional lock information if assets are pre-locked
	///
	/// # Returns
	///
	/// A vector of `OrderInput` instances. May be empty for orders
	/// that don't require specific inputs (e.g., native currency payments).
	///
	/// # Implementation Note
	///
	/// Implementations should handle token address formats appropriate to
	/// their standard and convert them to InteropAddress format.
	fn parse_available_inputs(&self) -> Vec<OrderInput>;

	/// Extract requested outputs from the order data.
	///
	/// Requested outputs represent the assets that the order maker expects
	/// to receive upon successful execution. Each output includes:
	/// - The receiver address (who gets the assets)
	/// - The asset details (token address and chain)
	/// - The amount to be received
	/// - Optional calldata for contract interactions
	///
	/// # Returns
	///
	/// A vector of `OrderOutput` instances. May be empty for orders
	/// that don't specify explicit outputs (though this is unusual).
	///
	/// # Implementation Note
	///
	/// Implementations should ensure that recipient addresses are properly
	/// formatted as InteropAddress instances with correct chain IDs.
	fn parse_requested_outputs(&self) -> Vec<OrderOutput>;

	/// Extract the lock type from the order data, if applicable.
	///
	/// The lock type indicates the mechanism used to secure user funds
	/// during order execution. Common lock types include:
	/// - `"permit2_escrow"` - Uses Permit2 for gasless approvals
	/// - `"eip3009_escrow"` - Uses EIP-3009 for gasless transfers
	/// - `"resource_lock"` - Uses resource locking (e.g., The Compact)
	///
	/// # Returns
	///
	/// - `Some(String)` - The lock type identifier if the order specifies one
	/// - `None` - If the order doesn't specify a lock type or the standard
	///   doesn't support lock types
	///
	/// # Usage
	///
	/// The lock type is primarily used for:
	/// - Determining gas costs (different lock types have different gas requirements)
	/// - Selecting the appropriate settlement contract
	/// - Configuring transaction parameters
	fn parse_lock_type(&self) -> Option<String>;

	/// Get the input oracle address from the order data.
	///
	/// The input oracle is responsible for attesting to order fills on the origin chain.
	/// This oracle validates that the solver has properly filled the order according
	/// to its requirements.
	///
	/// # Returns
	///
	/// The oracle address as a string. For standards that don't use oracles,
	/// this should return a zero address or empty string.
	fn input_oracle(&self) -> String;

	/// Get the origin chain ID where the order originates.
	///
	/// This represents the primary chain where the order was created and
	/// where the input assets are typically located. For single-chain orders,
	/// this is simply the chain of execution. For cross-chain orders, this
	/// is the source chain.
	///
	/// # Returns
	///
	/// The chain ID as a `u64`. Common values include:
	/// - 1 for Ethereum Mainnet
	/// - 137 for Polygon
	/// - 42161 for Arbitrum One
	/// - etc.
	///
	/// # Default Behavior
	///
	/// If the chain ID cannot be determined, implementations should return
	/// a sensible default (typically 1 for Ethereum Mainnet) rather than panic.
	fn origin_chain_id(&self) -> u64;

	/// Get the destination chain IDs where outputs will be delivered.
	///
	/// For cross-chain orders, outputs may be delivered to multiple chains.
	/// This method returns all unique chain IDs where the order expects to
	/// receive assets.
	///
	/// # Returns
	///
	/// A vector of chain IDs. May contain duplicates if multiple outputs
	/// go to the same chain. May be empty if no outputs are specified.
	///
	/// # Usage
	///
	/// This information is used for:
	/// - Calculating cross-chain routing costs
	/// - Determining which bridges/protocols to use
	/// - Estimating gas costs on destination chains
	/// - Validating order feasibility
	fn destination_chain_ids(&self) -> Vec<u64>;
}

/// Callback function type for computing order IDs.
/// Takes chain_id and transaction data (settler_address + calldata), returns the order ID bytes.
pub type OrderIdCallback = Box<
	dyn Fn(u64, Vec<u8>) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send>>
		+ Send
		+ Sync,
>;

/// Represents a validated cross-chain order with execution state.
///
/// An order is created from a validated intent and contains all information
/// necessary for execution, settlement, and tracking throughout its lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
	/// Unique identifier for this order.
	pub id: String,
	/// The standard this order conforms to (e.g., "eip7683").
	pub standard: String,
	/// Timestamp when this order was created.
	pub created_at: u64,
	/// Timestamp when this order was last updated.
	pub updated_at: u64,
	/// Current status of the order.
	pub status: OrderStatus,
	/// Standard-specific order data in JSON format.
	pub data: serde_json::Value,
	/// The solver's address for this order (for reward attribution).
	pub solver_address: Address,
	/// Quote ID associated with this order.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub quote_id: Option<String>,
	/// Input chains with their associated settler contracts.
	/// For most orders this will be a single chain, but could be multiple for complex orders.
	#[serde(default)]
	pub input_chains: Vec<ChainSettlerInfo>,
	/// Output chains with their associated settler contracts.
	/// Can be multiple chains for orders that split outputs across chains.
	#[serde(default)]
	pub output_chains: Vec<ChainSettlerInfo>,
	/// Execution parameters when order is ready for execution.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub execution_params: Option<ExecutionParams>,
	/// Transaction hash of the prepare transaction (if applicable).
	#[serde(skip_serializing_if = "Option::is_none")]
	pub prepare_tx_hash: Option<TransactionHash>,
	/// Transaction hash of the fill transaction.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub fill_tx_hash: Option<TransactionHash>,
	/// Transaction hash of the post-fill transaction (if applicable).
	#[serde(skip_serializing_if = "Option::is_none")]
	pub post_fill_tx_hash: Option<TransactionHash>,
	/// Transaction hash of the pre-claim transaction (if applicable).
	#[serde(skip_serializing_if = "Option::is_none")]
	pub pre_claim_tx_hash: Option<TransactionHash>,
	/// Transaction hash of the claim transaction.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub claim_tx_hash: Option<TransactionHash>,
	/// Fill proof data when available.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub fill_proof: Option<FillProof>,
}

impl Order {
	/// Parse the order data based on its standard
	#[cfg(feature = "oif-interfaces")]
	pub fn parse_order_data(&self) -> Result<Box<dyn OrderParsable>, Box<dyn std::error::Error>> {
		match self.standard.as_str() {
			"eip7683" => {
				let order_data: Eip7683OrderData = serde_json::from_value(self.data.clone())
					.map_err(|e| format!("Failed to parse EIP-7683 order data: {}", e))?;
				Ok(Box::new(order_data))
			},
			_ => Err(format!("Unsupported order standard: {}", self.standard).into()),
		}
	}
}

/// Parameters for executing an order.
///
/// Contains gas-related parameters determined by the execution strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionParams {
	/// Gas price to use for the transaction.
	pub gas_price: U256,
	/// Optional priority fee for EIP-1559 transactions.
	pub priority_fee: Option<U256>,
}

/// Context information for making execution decisions.
///
/// Provides chain-specific market conditions and solver state to execution strategies.
/// This context is built specifically for each intent, containing only relevant chain data.
#[derive(Debug, Clone)]
pub struct ExecutionContext {
	/// Chain-specific data indexed by chain ID.
	/// Contains gas prices, block numbers, and timestamps for each involved chain.
	pub chain_data: HashMap<u64, ChainData>,
	/// Solver's balance per chain and token.
	/// Key format: (chain_id, token_address) where token_address is None for native tokens.
	/// Value is balance as decimal string.
	pub solver_balances: HashMap<(u64, Option<String>), String>,
	/// Timestamp when this context was built.
	pub timestamp: u64,
}

/// Decision made by an execution strategy.
///
/// Determines whether and how an order should be executed.
#[derive(Debug)]
pub enum ExecutionDecision {
	/// Execute the order with the specified parameters.
	Execute(ExecutionParams),
	/// Skip the order with a reason.
	Skip(String),
	/// Defer execution for the specified duration.
	Defer(std::time::Duration),
}

/// Proof that an order has been filled.
///
/// Contains all information needed to claim rewards for filling an order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FillProof {
	/// Transaction hash of the fill.
	pub tx_hash: TransactionHash,
	/// Block number where the fill was included.
	pub block_number: u64,
	/// Optional attestation data from an oracle.
	pub attestation_data: Option<Vec<u8>>,
	/// Timestamp when the order was filled.
	pub filled_timestamp: u64,
	/// Address of the oracle that attested to the fill.
	pub oracle_address: String,
}

/// Settlement information for an order
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settlement {
	/// Settlement mechanism type
	#[serde(rename = "type")]
	pub settlement_type: SettlementType,
	/// Settlement-specific data
	pub data: serde_json::Value,
}

/// Order response for API endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderResponse {
	/// Unique identifier for this order
	pub id: String,
	/// Current order status
	pub status: OrderStatus,
	/// Timestamp when this order was created
	#[serde(rename = "createdAt")]
	pub created_at: u64,
	/// Timestamp when this order was last updated
	#[serde(rename = "updatedAt")]
	pub updated_at: u64,
	/// Associated quote ID if available
	#[serde(rename = "quoteId")]
	pub quote_id: Option<String>,
	/// Input asset and amount
	#[serde(rename = "inputAmounts")]
	pub input_amounts: Vec<AssetAmount>,
	/// Output asset and amount
	#[serde(rename = "outputAmounts")]
	pub output_amounts: Vec<AssetAmount>,
	/// Settlement information
	pub settlement: Settlement,
	/// Transaction details if order has been executed
	#[serde(rename = "fillTransaction")]
	pub fill_transaction: Option<serde_json::Value>,
}

/// Status of an order in the solver system.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum OrderStatus {
	/// Order has been created but not yet prepared.
	/// Next: Prepare transaction will be sent, moving to Pending.
	Created,
	/// Order has a pending prepare transaction.
	/// Next: When prepare confirms, moves to Executing.
	Pending,
	/// Order is currently executing - prepare confirmed, fill transaction in progress.
	/// Next: When fill confirms, moves to Executed.
	Executing,
	/// Order has been executed - fill transaction confirmed.
	/// Next: Either PostFilled (if post-fill tx needed) or Settled (if no post-fill).
	Executed,
	/// Post-fill transaction completed (optional state).
	/// Next: Moves to Settled when ready for claiming.
	PostFilled,
	/// Pre-claim transaction completed (optional state).
	/// Next: Moves to Finalized after claim confirms.
	PreClaimed,
	/// Order has been settled and is ready to be claimed.
	/// Next: Either PreClaimed (if pre-claim tx needed) or Finalized (after claim).
	Settled,
	/// Order is finalized and complete - claim transaction confirmed.
	/// Terminal state: No further transitions.
	Finalized,
	/// Order execution failed with specific transaction type.
	/// Terminal state: No further transitions.
	Failed(TransactionType),
}

impl fmt::Display for OrderStatus {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			OrderStatus::Created => write!(f, "Created"),
			OrderStatus::Pending => write!(f, "Pending"),
			OrderStatus::Executing => write!(f, "Executing"),
			OrderStatus::Executed => write!(f, "Executed"),
			OrderStatus::PostFilled => write!(f, "PostFilled"),
			OrderStatus::PreClaimed => write!(f, "PreClaimed"),
			OrderStatus::Settled => write!(f, "Settled"),
			OrderStatus::Finalized => write!(f, "Finalized"),
			OrderStatus::Failed(_) => write!(f, "Failed"),
		}
	}
}
