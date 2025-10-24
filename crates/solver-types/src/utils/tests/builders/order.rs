//! Order builder utilities for creating test and production Order instances.

use crate::order::ChainSettlerInfo;
use crate::{Address, FillProof, Order, OrderStatus, TransactionHash};

/// Builder for creating Order instances with sensible defaults.
///
/// This builder provides a fluent interface for constructing Order objects,
/// particularly useful for testing and creating orders with common patterns.
#[derive(Debug, Clone)]
pub struct OrderBuilder {
	id: String,
	standard: String,
	status: OrderStatus,
	solver_address: Address,
	created_at: u64,
	updated_at: u64,
	data: serde_json::Value,
	quote_id: Option<String>,
	input_chains: Vec<ChainSettlerInfo>,
	output_chains: Vec<ChainSettlerInfo>,
	execution_params: Option<crate::ExecutionParams>,
	prepare_tx_hash: Option<TransactionHash>,
	fill_tx_hash: Option<TransactionHash>,
	post_fill_tx_hash: Option<TransactionHash>,
	pre_claim_tx_hash: Option<TransactionHash>,
	claim_tx_hash: Option<TransactionHash>,
	fill_proof: Option<FillProof>,
}

impl Default for OrderBuilder {
	fn default() -> Self {
		let timestamp = crate::current_timestamp();
		Self {
			id: "test_order_123".to_string(),
			standard: "eip7683".to_string(),
			status: OrderStatus::Created,
			solver_address: Address(vec![0x12; 20]),
			created_at: timestamp,
			updated_at: timestamp,
			// Create minimal data with just the fields needed for the test
			data: serde_json::json!({
				"order_id": vec![0u8; 32],
				"user": "0x1234567890123456789012345678901234567890",
				"nonce": "123456789",
				"origin_chain_id": "1",
				"expires": timestamp + 3600,
				"fill_deadline": timestamp + 1800,
				"input_oracle": "0x1234567890123456789012345678901234567890",
				"inputs": [],
				"outputs": [],
				"gas_limit_overrides": {}
			}),
			quote_id: None,
			input_chains: vec![ChainSettlerInfo {
				chain_id: 1,
				settler_address: Address(vec![0x00; 20]),
			}],
			output_chains: vec![ChainSettlerInfo {
				chain_id: 137,
				settler_address: Address(vec![0x00; 20]),
			}],
			execution_params: None,
			prepare_tx_hash: None,
			fill_tx_hash: None,
			post_fill_tx_hash: None,
			pre_claim_tx_hash: None,
			claim_tx_hash: None,
			fill_proof: None,
		}
	}
}

impl OrderBuilder {
	/// Creates a new OrderBuilder with default values.
	pub fn new() -> Self {
		Self::default()
	}

	/// Sets the order ID.
	pub fn with_id<S: Into<String>>(mut self, id: S) -> Self {
		self.id = id.into();
		self
	}

	/// Sets the standard.
	pub fn with_standard<S: Into<String>>(mut self, standard: S) -> Self {
		self.standard = standard.into();
		self
	}

	/// Sets the order status.
	pub fn with_status(mut self, status: OrderStatus) -> Self {
		self.status = status;
		self
	}

	/// Sets the solver address.
	pub fn with_solver_address(mut self, address: Address) -> Self {
		self.solver_address = address;
		self
	}

	/// Sets the created_at timestamp.
	pub fn with_created_at(mut self, timestamp: u64) -> Self {
		self.created_at = timestamp;
		self
	}

	/// Sets the updated_at timestamp.
	pub fn with_updated_at(mut self, timestamp: u64) -> Self {
		self.updated_at = timestamp;
		self
	}

	/// Sets both created_at and updated_at to the same timestamp.
	pub fn with_timestamps(mut self, timestamp: u64) -> Self {
		self.created_at = timestamp;
		self.updated_at = timestamp;
		self
	}

	/// Sets the order data.
	pub fn with_data(mut self, data: serde_json::Value) -> Self {
		self.data = data;
		self
	}

	/// Sets the quote ID.
	pub fn with_quote_id<S: Into<String>>(mut self, quote_id: Option<S>) -> Self {
		self.quote_id = quote_id.map(|s| s.into());
		self
	}

	/// Sets the input chains with settler info.
	pub fn with_input_chains(mut self, chains: Vec<ChainSettlerInfo>) -> Self {
		self.input_chains = chains;
		self
	}

	/// Sets the output chains with settler info.
	pub fn with_output_chains(mut self, chains: Vec<ChainSettlerInfo>) -> Self {
		self.output_chains = chains;
		self
	}

	/// Convenience method to set input chain IDs with dummy settler addresses.
	pub fn with_input_chain_ids(mut self, chain_ids: Vec<u64>) -> Self {
		self.input_chains = chain_ids
			.into_iter()
			.map(|chain_id| ChainSettlerInfo {
				chain_id,
				settler_address: Address(vec![0x11; 20]), // Default input settler address
			})
			.collect();
		self
	}

	/// Convenience method to set output chain IDs with dummy settler addresses.
	pub fn with_output_chain_ids(mut self, chain_ids: Vec<u64>) -> Self {
		self.output_chains = chain_ids
			.into_iter()
			.map(|chain_id| ChainSettlerInfo {
				chain_id,
				settler_address: Address(vec![0x22; 20]), // Default output settler address
			})
			.collect();
		self
	}

	/// Sets the execution parameters.
	pub fn with_execution_params(mut self, params: Option<crate::ExecutionParams>) -> Self {
		self.execution_params = params;
		self
	}

	/// Sets the prepare transaction hash.
	pub fn with_prepare_tx_hash(mut self, tx_hash: Option<TransactionHash>) -> Self {
		self.prepare_tx_hash = tx_hash;
		self
	}

	/// Sets the fill transaction hash.
	pub fn with_fill_tx_hash(mut self, tx_hash: Option<TransactionHash>) -> Self {
		self.fill_tx_hash = tx_hash;
		self
	}

	/// Sets the post-fill transaction hash.
	pub fn with_post_fill_tx_hash(mut self, tx_hash: Option<TransactionHash>) -> Self {
		self.post_fill_tx_hash = tx_hash;
		self
	}

	/// Sets the pre-claim transaction hash.
	pub fn with_pre_claim_tx_hash(mut self, tx_hash: Option<TransactionHash>) -> Self {
		self.pre_claim_tx_hash = tx_hash;
		self
	}

	/// Sets the claim transaction hash.
	pub fn with_claim_tx_hash(mut self, tx_hash: Option<TransactionHash>) -> Self {
		self.claim_tx_hash = tx_hash;
		self
	}

	/// Sets the fill proof.
	pub fn with_fill_proof(mut self, fill_proof: Option<FillProof>) -> Self {
		self.fill_proof = fill_proof;
		self
	}

	/// Convenience method to create an executed order with fill transaction and proof.
	pub fn executed_with_fill(mut self, tx_hash: TransactionHash, block_number: u64) -> Self {
		let timestamp = self.updated_at;
		self.status = OrderStatus::Executed;
		self.fill_tx_hash = Some(tx_hash.clone());
		self.fill_proof = Some(FillProof {
			tx_hash,
			block_number,
			attestation_data: None,
			filled_timestamp: timestamp,
			oracle_address: "0x1234567890123456789012345678901234567890".to_string(),
		});
		self
	}

	/// Convenience method to create a failed order.
	pub fn failed_with_transaction_type(mut self, tx_type: crate::TransactionType) -> Self {
		self.status = OrderStatus::Failed(tx_type, "Test failure".to_string());
		self
	}

	/// Builds the Order instance.
	pub fn build(self) -> Order {
		Order {
			id: self.id,
			standard: self.standard,
			created_at: self.created_at,
			updated_at: self.updated_at,
			status: self.status,
			data: self.data,
			solver_address: self.solver_address,
			quote_id: self.quote_id,
			input_chains: self.input_chains,
			output_chains: self.output_chains,
			execution_params: self.execution_params,
			prepare_tx_hash: self.prepare_tx_hash,
			fill_tx_hash: self.fill_tx_hash,
			post_fill_tx_hash: self.post_fill_tx_hash,
			pre_claim_tx_hash: self.pre_claim_tx_hash,
			claim_tx_hash: self.claim_tx_hash,
			fill_proof: self.fill_proof,
		}
	}
}
