//! Order processing implementations for the solver service.
//!
//! This module provides concrete implementations of the OrderInterface trait
//! for EIP-7683 cross-chain orders, including transaction generation for
//! filling and claiming orders.

use crate::{OrderError, OrderInterface};
use alloy_primitives::{Address as AlloyAddress, FixedBytes, U256};
use alloy_sol_types::{sol, SolCall, SolValue};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use solver_types::{
	Address, ConfigSchema, ExecutionParams, Field, FieldType, FillProof, Intent, Order, Schema,
	Transaction,
};

// Solidity type definitions for EIP-7683 contract interactions.
sol! {
	/// MandateOutput structure used in fill operations.
	struct MandateOutput {
		bytes32 oracle;
		bytes32 settler;
		uint256 chainId;
		bytes32 token;
		uint256 amount;
		bytes32 recipient;
		bytes call;
		bytes context;
	}

	/// IDestinationSettler interface for filling orders.
	interface IDestinationSettler {
		function fill(bytes32 orderId, bytes originData, bytes fillerData) external;
	}

	/// Order structure for finaliseSelf.
	struct OrderStruct {
		address user;
		uint256 nonce;
		uint256 originChainId;
		uint32 expires;
		uint32 fillDeadline;
		address oracle;
		uint256[2][] inputs;
		MandateOutput[] outputs;
	}

	/// IInputSettler interface for finalizing orders.
	interface IInputSettler {
		function finaliseSelf(OrderStruct order, uint32[] timestamps, bytes32 solver) external;
	}
}

/// EIP-7683 specific order data structure.
///
/// Contains all the necessary information for processing a cross-chain order
/// according to the EIP-7683 standard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip7683OrderData {
	pub user: String,
	pub nonce: u64,
	pub origin_chain_id: u64,
	pub destination_chain_id: u64,
	pub expires: u32, // Changed from open_deadline to match contract
	pub fill_deadline: u32,
	pub local_oracle: String,   // Added oracle address
	pub inputs: Vec<[U256; 2]>, // Added inputs array [token, amount]
	pub order_id: [u8; 32],
	pub settle_gas_limit: u64,
	pub fill_gas_limit: u64,
	pub outputs: Vec<Output>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Output {
	pub token: String,
	pub amount: U256,
	pub recipient: String,
	pub chain_id: u64,
}

/// EIP-7683 order implementation.
///
/// Handles validation and transaction generation for EIP-7683 cross-chain orders.
/// Manages interactions with both input and output settler contracts.
pub struct Eip7683OrderImpl {
	/// Address of the output settler contract on destination chains.
	output_settler_address: Address,
	/// Address of the input settler contract on origin chains.
	input_settler_address: Address,
	/// Address of the solver for claiming rewards.
	solver_address: Address,
}

impl Eip7683OrderImpl {
	/// Creates a new EIP-7683 order implementation.
	pub fn new(output_settler: String, input_settler: String, solver: String) -> Self {
		Self {
			output_settler_address: Address(
				hex::decode(output_settler.trim_start_matches("0x"))
					.expect("Invalid output settler address"),
			),
			input_settler_address: Address(
				hex::decode(input_settler.trim_start_matches("0x"))
					.expect("Invalid input settler address"),
			),
			solver_address: Address(
				hex::decode(solver.trim_start_matches("0x")).expect("Invalid solver address"),
			),
		}
	}
}

/// Configuration schema for EIP-7683 order implementation.
pub struct Eip7683OrderSchema;

impl ConfigSchema for Eip7683OrderSchema {
	fn validate(&self, config: &toml::Value) -> Result<(), solver_types::ValidationError> {
		let schema = Schema::new(
			// Required fields
			vec![
				Field::new("output_settler_address", FieldType::String).with_validator(|value| {
					let addr = value.as_str().unwrap();
					if addr.len() != 42 || !addr.starts_with("0x") {
						return Err(
							"output_settler_address must be a valid Ethereum address".to_string()
						);
					}
					Ok(())
				}),
				Field::new("input_settler_address", FieldType::String).with_validator(|value| {
					let addr = value.as_str().unwrap();
					if addr.len() != 42 || !addr.starts_with("0x") {
						return Err(
							"input_settler_address must be a valid Ethereum address".to_string()
						);
					}
					Ok(())
				}),
				Field::new("solver_address", FieldType::String).with_validator(|value| {
					let addr = value.as_str().unwrap();
					if addr.len() != 42 || !addr.starts_with("0x") {
						return Err("solver_address must be a valid Ethereum address".to_string());
					}
					Ok(())
				}),
			],
			// Optional fields
			vec![],
		);

		schema.validate(config)
	}
}

#[async_trait]
impl OrderInterface for Eip7683OrderImpl {
	fn config_schema(&self) -> Box<dyn ConfigSchema> {
		Box::new(Eip7683OrderSchema)
	}

	/// Validates an EIP-7683 intent and converts it to an order.
	async fn validate_intent(&self, intent: &Intent) -> Result<Order, OrderError> {
		if intent.standard != "eip7683" {
			return Err(OrderError::ValidationFailed(
				"Not an EIP-7683 order".to_string(),
			));
		}

		// Parse order data
		let order_data: Eip7683OrderData =
			serde_json::from_value(intent.data.clone()).map_err(|e| {
				OrderError::ValidationFailed(format!("Failed to parse order data: {}", e))
			})?;

		// Validate deadlines
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap()
			.as_secs() as u32;

		if now > order_data.expires {
			return Err(OrderError::ValidationFailed("Order expired".to_string()));
		}

		// Create order
		Ok(Order {
			id: intent.id.clone(),
			standard: intent.standard.clone(),
			created_at: intent.metadata.discovered_at,
			data: serde_json::to_value(&order_data)
				.map_err(|e| OrderError::ValidationFailed(format!("Failed to serialize: {}", e)))?,
		})
	}

	/// Generates a transaction to fill an EIP-7683 order on the destination chain.
	async fn generate_fill_transaction(
		&self,
		order: &Order,
		_params: &ExecutionParams,
	) -> Result<Transaction, OrderError> {
		let order_data: Eip7683OrderData =
			serde_json::from_value(order.data.clone()).map_err(|e| {
				OrderError::ValidationFailed(format!("Failed to parse order data: {}", e))
			})?;

		// Check if this is a same-chain order
		if order_data.origin_chain_id == order_data.destination_chain_id {
			return Err(OrderError::ValidationFailed(
				"Same-chain orders are not supported".to_string(),
			));
		}

		// Get the output for the destination chain
		let output = order_data
			.outputs
			.iter()
			.find(|o| o.chain_id == order_data.destination_chain_id)
			.ok_or_else(|| {
				OrderError::ValidationFailed("No output found for destination chain".to_string())
			})?;

		// Create the MandateOutput struct for the fill operation
		let mandate_output = MandateOutput {
			oracle: FixedBytes::<32>::from([0u8; 32]), // No oracle for direct fills
			settler: {
				let mut bytes32 = [0u8; 32];
				bytes32[12..32].copy_from_slice(&self.output_settler_address.0);
				FixedBytes::<32>::from(bytes32)
			},
			chainId: U256::from(output.chain_id),
			token: {
				let token_hex = output.token.trim_start_matches("0x");
				let token_bytes = hex::decode(token_hex).map_err(|e| {
					OrderError::ValidationFailed(format!("Invalid token address: {}", e))
				})?;
				let mut bytes32 = [0u8; 32];
				bytes32[12..32].copy_from_slice(&token_bytes);
				FixedBytes::<32>::from(bytes32)
			},
			amount: output.amount,
			recipient: {
				let recipient_hex = output.recipient.trim_start_matches("0x");
				let recipient_bytes = hex::decode(recipient_hex).map_err(|e| {
					OrderError::ValidationFailed(format!("Invalid recipient address: {}", e))
				})?;
				let mut bytes32 = [0u8; 32];
				bytes32[12..32].copy_from_slice(&recipient_bytes);
				FixedBytes::<32>::from(bytes32)
			},
			call: vec![].into(),    // Empty for direct transfers
			context: vec![].into(), // Empty context
		};

		// Encode fill data
		let fill_data = IDestinationSettler::fillCall {
			orderId: FixedBytes::<32>::from(order_data.order_id),
			originData: mandate_output.abi_encode().into(),
			fillerData: {
				// FillerData should contain the solver address as bytes32
				let mut solver_bytes32 = [0u8; 32];
				solver_bytes32[12..32].copy_from_slice(&self.solver_address.0);
				solver_bytes32.to_vec().into()
			},
		}
		.abi_encode();

		Ok(Transaction {
			to: Some(self.output_settler_address.clone()),
			data: fill_data,
			value: U256::ZERO,
			chain_id: order_data.destination_chain_id,
			nonce: None,
			gas_limit: Some(order_data.fill_gas_limit),
			gas_price: None,
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
		})
	}

	/// Generates a transaction to claim rewards for a filled order on the origin chain.
	async fn generate_claim_transaction(
		&self,
		order: &Order,
		fill_proof: &FillProof,
	) -> Result<Transaction, OrderError> {
		let order_data: Eip7683OrderData =
			serde_json::from_value(order.data.clone()).map_err(|e| {
				OrderError::ValidationFailed(format!("Failed to parse order data: {}", e))
			})?;

		// Check if this is a same-chain order
		if order_data.origin_chain_id == order_data.destination_chain_id {
			return Err(OrderError::ValidationFailed(
				"Same-chain orders are not supported".to_string(),
			));
		}

		// Parse addresses
		let user_hex = order_data.user.trim_start_matches("0x");
		let user_bytes = hex::decode(user_hex)
			.map_err(|e| OrderError::ValidationFailed(format!("Invalid user address: {}", e)))?;
		let user_address = AlloyAddress::from_slice(&user_bytes);

		// Parse oracle address
		let oracle_hex = fill_proof.oracle_address.trim_start_matches("0x");
		let oracle_bytes = hex::decode(oracle_hex)
			.map_err(|e| OrderError::ValidationFailed(format!("Invalid oracle address: {}", e)))?;
		let oracle_address = AlloyAddress::from_slice(&oracle_bytes);

		// Create inputs array from order data
		let inputs: Vec<[U256; 2]> = order_data.inputs.clone();

		// Create outputs array (MandateOutput structs)
		let outputs: Vec<MandateOutput> = order_data
			.outputs
			.iter()
			.map(|output| {
				// Convert addresses to bytes32
				let oracle_bytes32 = FixedBytes::<32>::from([0u8; 32]); // No oracle

				let settler_bytes32 = {
					let mut bytes32 = [0u8; 32];
					if output.chain_id == order_data.origin_chain_id {
						// Use input settler for origin chain
						bytes32[12..32].copy_from_slice(&self.input_settler_address.0);
					} else {
						// Use output settler for other chains
						bytes32[12..32].copy_from_slice(&self.output_settler_address.0);
					}
					FixedBytes::<32>::from(bytes32)
				};

				let token_bytes32 = {
					let token_hex = output.token.trim_start_matches("0x");
					let token_bytes = hex::decode(token_hex).unwrap_or_else(|_| vec![0; 20]);
					let mut bytes32 = [0u8; 32];
					bytes32[12..32].copy_from_slice(&token_bytes);
					FixedBytes::<32>::from(bytes32)
				};

				let recipient_bytes32 = {
					let recipient_hex = output.recipient.trim_start_matches("0x");
					let recipient_bytes =
						hex::decode(recipient_hex).unwrap_or_else(|_| vec![0; 20]);
					let mut bytes32 = [0u8; 32];
					bytes32[12..32].copy_from_slice(&recipient_bytes);
					FixedBytes::<32>::from(bytes32)
				};

				MandateOutput {
					oracle: oracle_bytes32,
					settler: settler_bytes32,
					chainId: U256::from(output.chain_id),
					token: token_bytes32,
					amount: output.amount,
					recipient: recipient_bytes32,
					call: vec![].into(),
					context: vec![].into(),
				}
			})
			.collect();

		// Build the order struct
		let order_struct = OrderStruct {
			user: user_address,
			nonce: U256::from(order_data.nonce),
			originChainId: U256::from(order_data.origin_chain_id),
			expires: order_data.expires,
			fillDeadline: order_data.fill_deadline,
			oracle: oracle_address,
			inputs,
			outputs,
		};

		// Create timestamps array - use timestamp from fill proof
		let timestamps = vec![fill_proof.filled_timestamp as u32];

		// Create solver bytes32
		let mut solver_bytes32 = [0u8; 32];
		solver_bytes32[12..32].copy_from_slice(&self.solver_address.0);
		let solver = FixedBytes::<32>::from(solver_bytes32);

		// Encode the finaliseSelf call
		let call_data = IInputSettler::finaliseSelfCall {
			order: order_struct,
			timestamps,
			solver,
		}
		.abi_encode();

		Ok(Transaction {
			to: Some(self.input_settler_address.clone()),
			data: call_data,
			value: U256::ZERO,
			chain_id: order_data.origin_chain_id,
			nonce: None,
			gas_limit: Some(order_data.settle_gas_limit),
			gas_price: None,
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
		})
	}
}

/// Factory function to create an EIP-7683 order implementation from configuration.
///
/// Required configuration parameters:
/// - `output_settler_address`: Address of the output settler contract
/// - `input_settler_address`: Address of the input settler contract
/// - `solver_address`: Address of the solver for claiming rewards
pub fn create_order_impl(config: &toml::Value) -> Box<dyn OrderInterface> {
	let output_settler = config
		.get("output_settler_address")
		.and_then(|v| v.as_str())
		.expect("output_settler_address is required");

	let input_settler = config
		.get("input_settler_address")
		.and_then(|v| v.as_str())
		.expect("input_settler_address is required");

	let solver_address = config
		.get("solver_address")
		.and_then(|v| v.as_str())
		.expect("solver_address is required");

	Box::new(Eip7683OrderImpl::new(
		output_settler.to_string(),
		input_settler.to_string(),
		solver_address.to_string(),
	))
}
