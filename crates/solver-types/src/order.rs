//! Order processing types for the solver system.
//!
//! This module defines types related to validated orders, execution decisions,
//! and fill proofs used throughout the order lifecycle.

use alloy_primitives::U256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use crate::{Address, AssetAmount, ChainData, SettlementType, TransactionHash, TransactionType};

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
	/// Chain IDs where input assets are located.
	/// For most orders this will be a single chain, but could be multiple for complex orders.
	#[serde(default)]
	pub input_chain_ids: Vec<u64>,
	/// Chain IDs where output assets will be delivered.
	/// Can be multiple chains for orders that split outputs across chains.
	#[serde(default)]
	pub output_chain_ids: Vec<u64>,
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
	#[serde(rename = "inputAmount")]
	pub input_amount: AssetAmount,
	/// Output asset and amount
	#[serde(rename = "outputAmount")]
	pub output_amount: AssetAmount,
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
