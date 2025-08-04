//! Direct settlement implementation for testing purposes.
//!
//! This module provides a basic implementation of the SettlementInterface trait
//! intended for testing and development. It handles fill validation and claim
//! readiness checks using simple transaction receipt verification without
//! complex attestation mechanisms.

use crate::{SettlementError, SettlementInterface};
use alloy_primitives::{Address as AlloyAddress, FixedBytes};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types::BlockTransactionsKind;
use alloy_transport_http::Http;
use async_trait::async_trait;
use solver_types::{
	ConfigSchema, Eip7683OrderData, Field, FieldType, FillProof, Order, Schema, TransactionHash,
};

/// Direct settlement implementation.
///
/// This implementation validates fills by checking transaction receipts
/// and manages dispute periods before allowing claims.
pub struct DirectSettlement {
	/// The Alloy provider for blockchain interaction.
	provider: RootProvider<Http<reqwest::Client>>,
	/// Oracle address for attestation verification.
	oracle_address: String,
	/// Dispute period duration in seconds.
	dispute_period_seconds: u64,
}

impl DirectSettlement {
	/// Creates a new DirectSettlement instance.
	///
	/// Configures settlement validation with the specified oracle address
	/// and dispute period.
	pub async fn new(
		rpc_url: &str,
		oracle_address: String,
		dispute_period_seconds: u64,
	) -> Result<Self, SettlementError> {
		// Create provider
		let provider =
			RootProvider::new_http(rpc_url.parse().map_err(|e| {
				SettlementError::ValidationFailed(format!("Invalid RPC URL: {}", e))
			})?);

		// Parse oracle address
		let oracle = oracle_address.parse::<AlloyAddress>().map_err(|e| {
			SettlementError::ValidationFailed(format!("Invalid oracle address: {}", e))
		})?;

		Ok(Self {
			provider,
			oracle_address: oracle.to_string(),
			dispute_period_seconds,
		})
	}
}

/// Configuration schema for DirectSettlement.
pub struct DirectSettlementSchema;

impl ConfigSchema for DirectSettlementSchema {
	fn validate(&self, config: &toml::Value) -> Result<(), solver_types::ValidationError> {
		let schema = Schema::new(
			// Required fields
			vec![
				Field::new("rpc_url", FieldType::String).with_validator(|value| {
					match value.as_str() {
						Some(url) => {
							if url.starts_with("http://") || url.starts_with("https://") {
								Ok(())
							} else {
								Err("RPC URL must start with http:// or https://".to_string())
							}
						}
						None => Err("Expected string value for rpc_url".to_string()),
					}
				}),
				Field::new("oracle_address", FieldType::String).with_validator(|value| match value
					.as_str()
				{
					Some(addr) => {
						if addr.len() != 42 || !addr.starts_with("0x") {
							return Err(
								"oracle_address must be a valid Ethereum address".to_string()
							);
						}
						Ok(())
					}
					None => Err("Expected string value for oracle_address".to_string()),
				}),
			],
			// Optional fields
			vec![Field::new(
				"dispute_period_seconds",
				FieldType::Integer {
					min: Some(0),
					max: Some(86400),
				},
			)],
		);

		schema.validate(config)
	}
}

#[async_trait]
impl SettlementInterface for DirectSettlement {
	fn config_schema(&self) -> Box<dyn ConfigSchema> {
		Box::new(DirectSettlementSchema)
	}

	/// Gets attestation data for a filled order and generates a fill proof.
	///
	/// Since the transaction is already confirmed by the delivery service,
	/// this method just extracts necessary data for claim generation.
	async fn get_attestation(
		&self,
		order: &Order,
		tx_hash: &TransactionHash,
	) -> Result<FillProof, SettlementError> {
		// Convert tx hash
		let hash = FixedBytes::<32>::from_slice(&tx_hash.0);

		// Get transaction receipt
		let receipt = self
			.provider
			.get_transaction_receipt(hash)
			.await
			.map_err(|e| {
				SettlementError::ValidationFailed(format!("Failed to get receipt: {}", e))
			})?
			.ok_or_else(|| {
				SettlementError::ValidationFailed("Transaction not found".to_string())
			})?;

		// Check if transaction was successful
		if !receipt.status() {
			return Err(SettlementError::ValidationFailed(
				"Transaction failed".to_string(),
			));
		}

		let tx_block = receipt.block_number.unwrap_or(0);

		// Parse order data to get order ID
		let order_data: Eip7683OrderData =
			serde_json::from_value(order.data.clone()).map_err(|e| {
				SettlementError::ValidationFailed(format!("Failed to parse order data: {}", e))
			})?;

		// Get the block timestamp
		let block = self
			.provider
			.get_block_by_number(
				alloy_rpc_types::BlockNumberOrTag::Number(tx_block),
				BlockTransactionsKind::Hashes,
			)
			.await
			.map_err(|e| {
				SettlementError::ValidationFailed(format!("Failed to get block: {}", e))
			})?;

		let block_timestamp = block
			.ok_or_else(|| SettlementError::ValidationFailed("Block not found".to_string()))?
			.header
			.timestamp;

		Ok(FillProof {
			tx_hash: tx_hash.clone(),
			block_number: tx_block,
			oracle_address: self.oracle_address.to_string(),
			attestation_data: Some(order_data.order_id.to_vec()),
			filled_timestamp: block_timestamp,
		})
	}

	/// Checks if an order is ready to be claimed.
	///
	/// Verifies that the dispute period has passed and all claim
	/// requirements are met.
	async fn can_claim(&self, _order: &Order, fill_proof: &FillProof) -> bool {
		// Get current block to check timestamp
		let current_block = match self.provider.get_block_number().await {
			Ok(block_num) => match self
				.provider
				.get_block_by_number(block_num.into(), BlockTransactionsKind::Hashes)
				.await
			{
				Ok(Some(block)) => block,
				Ok(None) => return false,
				Err(_) => return false,
			},
			Err(_) => return false,
		};

		// Check if dispute period has passed using timestamps
		let current_timestamp = current_block.header.timestamp;
		let dispute_end_timestamp = fill_proof.filled_timestamp + self.dispute_period_seconds;

		if current_timestamp < dispute_end_timestamp {
			return false; // Still in dispute period
		}

		// TODO check:
		// 1. Oracle attestation exists
		// 2. No disputes were raised
		// 3. Claim window hasn't expired
		// 4. Rewards haven't been claimed yet

		// For now, return true if dispute period passed
		true
	}
}

/// Factory function to create a settlement provider from configuration.
///
/// Required configuration parameters:
/// - `rpc_url`: The HTTP RPC endpoint URL
/// - `oracle_address`: Address of the attestation oracle
///
/// Optional configuration parameters:
/// - `dispute_period_seconds`: Dispute period duration (default: 300)
pub fn create_settlement(
	config: &toml::Value,
) -> Result<Box<dyn SettlementInterface>, SettlementError> {
	let rpc_url = config
		.get("rpc_url")
		.and_then(|v| v.as_str())
		.ok_or_else(|| SettlementError::ValidationFailed("rpc_url is required".to_string()))?;

	let oracle_address = config
		.get("oracle_address")
		.and_then(|v| v.as_str())
		.ok_or_else(|| {
			SettlementError::ValidationFailed("oracle_address is required".to_string())
		})?;

	let dispute_period_seconds = config
		.get("dispute_period_seconds")
		.and_then(|v| v.as_integer())
		.unwrap_or(300) as u64; // 5 minutes default

	// Create settlement service synchronously
	let settlement = tokio::task::block_in_place(|| {
		tokio::runtime::Handle::current().block_on(async {
			DirectSettlement::new(rpc_url, oracle_address.to_string(), dispute_period_seconds).await
		})
	})?;

	Ok(Box::new(settlement))
}
