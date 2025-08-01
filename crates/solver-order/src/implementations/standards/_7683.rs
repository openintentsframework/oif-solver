//! Order processing implementations for the solver service.
//!
//! This module provides concrete implementations of the OrderInterface trait
//! for EIP-7683 cross-chain orders, including transaction generation for
//! filling and claiming orders.

use crate::{OrderError, OrderInterface};
use alloy_primitives::{Address as AlloyAddress, FixedBytes, U256};
use alloy_sol_types::{sol, SolCall, SolValue};
use async_trait::async_trait;
use solver_types::{
	Address, ConfigSchema, Eip7683OrderData, ExecutionParams, Field, FieldType, FillProof,
	Intent, Order, Schema, Transaction,
};

// Solidity type definitions for EIP-7683 contract interactions.
sol! {
	/// OnchainCrossChainOrder for open() call
	struct OnchainCrossChainOrder {
		uint32 fillDeadline;
		bytes32 orderDataType;
		bytes orderData;
	}

	/// GaslessCrossChainOrder for openFor() call
	struct GaslessCrossChainOrder {
		address originSettler;
		address user;
		uint256 nonce;
		uint256 originChainId;
		uint32 openDeadline;
		uint32 fillDeadline;
		bytes32 orderDataType;
		bytes orderData;
	}

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
		function open(OnchainCrossChainOrder calldata order) external;
		function openFor(GaslessCrossChainOrder calldata order, bytes calldata signature, bytes calldata originFillerData) external;
	}
}

/// EIP-7683 order implementation.
///
/// This struct implements the `OrderInterface` trait for EIP-7683 cross-chain orders.
/// It handles validation and transaction generation for filling orders across chains,
/// managing interactions with both input (origin chain) and output (destination chain)
/// settler contracts.
///
/// # Architecture
///
/// The implementation supports three main operations:
/// 1. **Prepare** - For off-chain orders, creates on-chain order via `openFor()`
/// 2. **Fill** - Executes order on destination chain via settler's `fill()`
/// 3. **Claim** - Claims rewards on origin chain via `finaliseSelf()`
///
/// # Fields
///
/// * `output_settler_address` - Settler contract on destination chains for fills
/// * `input_settler_address` - Settler contract on origin chain for claims
/// * `solver_address` - Solver address for reward attribution
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
	///
	/// # Arguments
	///
	/// * `output_settler` - Hex-encoded address of the output settler contract
	/// * `input_settler` - Hex-encoded address of the input settler contract
	/// * `solver` - Hex-encoded address of the solver
	///
	/// # Panics
	///
	/// Panics if any of the provided addresses are invalid hex strings.
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
///
/// Validates configuration parameters required for the EIP-7683 order processor.
/// Ensures all addresses are valid Ethereum addresses in hex format.
///
/// # Required Configuration
///
/// ```toml
/// output_settler_address = "0x..."  # 42-char hex address
/// input_settler_address = "0x..."   # 42-char hex address
/// solver_address = "0x..."          # 42-char hex address
/// ```
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
	///
	/// Performs validation checks to ensure the intent is a valid EIP-7683 order
	/// that hasn't expired. Extracts and validates the order data structure.
	///
	/// # Arguments
	///
	/// * `intent` - The intent to validate
	///
	/// # Returns
	///
	/// Returns a validated `Order` ready for processing.
	///
	/// # Errors
	///
	/// Returns `OrderError::ValidationFailed` if:
	/// - The intent is not an EIP-7683 order
	/// - The order data cannot be parsed
	/// - The order has expired
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

	/// Generates a transaction to prepare an order for filling (if needed).
	///
	/// For off-chain orders, this calls `openFor()` to create the order on-chain.
	/// On-chain orders don't require preparation and return `None`.
	///
	/// # Arguments
	///
	/// * `intent` - The original intent (used to check if off-chain)
	/// * `order` - The validated order
	/// * `_params` - Execution parameters (currently unused)
	///
	/// # Returns
	///
	/// Returns `Some(Transaction)` for off-chain orders that need to be opened,
	/// or `None` for on-chain orders.
	///
	/// # Errors
	///
	/// Returns `OrderError::ValidationFailed` if:
	/// - Order data is missing required fields for off-chain orders
	/// - Address parsing fails
	/// - Hex decoding fails
	async fn generate_prepare_transaction(
		&self,
		intent: &Intent,
		order: &Order,
		_params: &ExecutionParams,
	) -> Result<Option<Transaction>, OrderError> {
		// Only off-chain orders need preparation
		if intent.source != "off-chain" {
			return Ok(None);
		}

		let order_data: Eip7683OrderData =
			serde_json::from_value(order.data.clone()).map_err(|e| {
				OrderError::ValidationFailed(format!("Failed to parse order data: {}", e))
			})?;

		let origin_settler = self.input_settler_address.clone();

		let raw_order_data = order_data.raw_order_data.as_ref().ok_or_else(|| {
			OrderError::ValidationFailed("Missing raw order data for off-chain order".to_string())
		})?;

		let order_data_type = order_data.order_data_type.ok_or_else(|| {
			OrderError::ValidationFailed("Missing order data type for off-chain order".to_string())
		})?;

		let signature = order_data.signature.as_ref().ok_or_else(|| {
			OrderError::ValidationFailed("Missing signature for off-chain order".to_string())
		})?;

		// Create GaslessCrossChainOrder for openFor
		let gasless_order = GaslessCrossChainOrder {
			originSettler: AlloyAddress::from_slice(&origin_settler.0),
			user: AlloyAddress::from_slice(
				&hex::decode(order_data.user.trim_start_matches("0x")).map_err(|e| {
					OrderError::ValidationFailed(format!("Invalid user address: {}", e))
				})?,
			),
			nonce: U256::from(order_data.nonce),
			originChainId: U256::from(order_data.origin_chain_id),
			openDeadline: order_data.expires,
			fillDeadline: order_data.fill_deadline,
			orderDataType: FixedBytes::<32>::from(order_data_type),
			orderData: hex::decode(raw_order_data.trim_start_matches("0x"))
				.map_err(|e| OrderError::ValidationFailed(format!("Invalid order data: {}", e)))?
				.into(),
		};

		// Encode openFor call
		let open_for_data = IInputSettler::openForCall {
			order: gasless_order,
			signature: hex::decode(signature.trim_start_matches("0x"))
				.map_err(|e| OrderError::ValidationFailed(format!("Invalid signature: {}", e)))?
				.into(),
			originFillerData: vec![].into(), // Empty filler data
		}
		.abi_encode();

		Ok(Some(Transaction {
			to: Some(self.input_settler_address.clone()),
			data: open_for_data,
			value: U256::ZERO,
			chain_id: order_data.origin_chain_id,
			nonce: None,
			gas_limit: Some(300_000), // TODO: Determine gas limit here
			gas_price: None,
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
		}))
	}

	/// Generates a transaction to fill an EIP-7683 order on the destination chain.
	///
	/// Creates a transaction that calls the destination settler's `fill()` function
	/// with the appropriate order data and solver information.
	///
	/// # Arguments
	///
	/// * `order` - The order to fill
	/// * `_params` - Execution parameters (currently unused)
	///
	/// # Returns
	///
	/// Returns a transaction ready to be signed and submitted.
	///
	/// # Errors
	///
	/// Returns `OrderError::ValidationFailed` if:
	/// - Order data cannot be parsed
	/// - Order is a same-chain order (not supported)
	/// - No output exists for the destination chain
	/// - Address parsing fails
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
	///
	/// Creates a transaction that calls the origin settler's `finaliseSelf()` function
	/// to claim solver rewards after successfully filling an order.
	///
	/// # Arguments
	///
	/// * `order` - The filled order
	/// * `fill_proof` - Proof of fill containing oracle attestation
	///
	/// # Returns
	///
	/// Returns a transaction to claim rewards on the origin chain.
	///
	/// # Errors
	///
	/// Returns `OrderError::ValidationFailed` if:
	/// - Order data cannot be parsed
	/// - Order is a same-chain order (not supported)
	/// - Address parsing fails
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
/// This function is called by the order module factory system to instantiate
/// a new EIP-7683 order processor with the provided configuration.
///
/// # Arguments
///
/// * `config` - TOML configuration value containing required parameters
///
/// # Returns
///
/// Returns a boxed `OrderInterface` implementation for EIP-7683 orders.
///
/// # Configuration
///
/// Required configuration parameters:
/// ```toml
/// output_settler_address = "0x..."  # Output settler contract address
/// input_settler_address = "0x..."   # Input settler contract address
/// solver_address = "0x..."          # Solver address for rewards
/// ```
///
/// # Panics
///
/// Panics if any required configuration parameter is missing.
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
