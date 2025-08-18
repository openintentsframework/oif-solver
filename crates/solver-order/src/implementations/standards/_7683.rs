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
	Address, ConfigSchema, Eip7683OrderData, ExecutionParams, FillProof, Intent, NetworksConfig,
	Order, OrderStatus, Schema, Transaction,
};

// Solidity type definitions for EIP-7683 contract interactions.
sol! {
	/// StandardOrder for the OIF contracts (used in openFor)
	struct StandardOrder {
		address user;
		uint256 nonce;
		uint256 originChainId;
		uint32 expires;
		uint32 fillDeadline;
		address inputOracle;
		uint256[2][] inputs;
		MandateOutput[] outputs;
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

	/// IInputSettlerEscrow interface for the OIF contracts.
	interface IInputSettlerEscrow {
		function finalise(OrderStruct order, uint32[] timestamps, bytes32[] solvers, bytes32 destination, bytes call) external;
		function finaliseWithSignature(OrderStruct order, uint32[] timestamps, bytes32[] solvers, bytes32 destination, bytes call, bytes signature) external;
		function open(bytes calldata order) external;
		function openFor(bytes calldata order, address sponsor, bytes calldata signature) external;
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
/// * `networks` - Networks configuration containing settler addresses for each chain
pub struct Eip7683OrderImpl {
	/// Networks configuration for dynamic settler address lookups.
	networks: NetworksConfig,
}

impl Eip7683OrderImpl {
	/// Creates a new EIP-7683 order implementation.
	///
	/// # Arguments
	///
	/// * `networks` - Networks configuration with settler addresses
	pub fn new(networks: NetworksConfig) -> Result<Self, OrderError> {
		// Validate that networks config has at least 2 networks
		if networks.len() < 2 {
			return Err(OrderError::ValidationFailed(
				"At least 2 networks must be configured".to_string(),
			));
		}

		Ok(Self { networks })
	}
}

/// Configuration schema for EIP-7683 order implementation.
///
/// Validates configuration parameters required for the EIP-7683 order processor.
/// Ensures all addresses are valid Ethereum addresses in hex format.
///
/// Configuration schema for EIP-7683 order implementation.
///
/// This schema validates the configuration for the EIP-7683 order processor,
/// ensuring all required addresses are present and properly formatted.
///
/// # Required Configuration
///
/// ```toml
/// output_settler_address = "0x..."  # 42-char hex address
/// input_settler_address = "0x..."   # 42-char hex address
/// ```
pub struct Eip7683OrderSchema;

impl Eip7683OrderSchema {
	/// Static validation method for use before instance creation
	pub fn validate_config(config: &toml::Value) -> Result<(), solver_types::ValidationError> {
		let instance = Self;
		instance.validate(config)
	}
}

impl ConfigSchema for Eip7683OrderSchema {
	fn validate(&self, config: &toml::Value) -> Result<(), solver_types::ValidationError> {
		let schema = Schema::new(
			// Required fields
			vec![],
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
	/// * `solver_address` - The solver's address for reward attribution
	///
	/// # Returns
	///
	/// Returns a validated `Order` ready for processing with the solver address included.
	///
	/// # Errors
	///
	/// Returns `OrderError::ValidationFailed` if:
	/// - The intent is not an EIP-7683 order
	/// - The order data cannot be parsed
	/// - The order has expired
	async fn validate_intent(
		&self,
		intent: &Intent,
		solver_address: &Address,
	) -> Result<Order, OrderError> {
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
			.map(|d| d.as_secs() as u32)
			.unwrap_or(0);

		if now > order_data.expires {
			return Err(OrderError::ValidationFailed("Order expired".to_string()));
		}

		// Extract chain IDs
		let input_chain_ids = vec![order_data.origin_chain_id.to::<u64>()];
		let output_chain_ids = order_data
			.outputs
			.iter()
			.map(|output| output.chain_id.to::<u64>())
			.collect::<Vec<_>>();

		// Create order
		Ok(Order {
			id: intent.id.clone(),
			standard: intent.standard.clone(),
			created_at: intent.metadata.discovered_at,
			data: serde_json::to_value(&order_data)
				.map_err(|e| OrderError::ValidationFailed(format!("Failed to serialize: {}", e)))?,
			solver_address: solver_address.clone(),
			quote_id: intent.quote_id.clone(),
			input_chain_ids,
			output_chain_ids,
			updated_at: std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.map(|d| d.as_secs())
				.unwrap_or(0),
			status: OrderStatus::Created,
			execution_params: None,
			prepare_tx_hash: None,
			fill_tx_hash: None,
			claim_tx_hash: None,
			fill_proof: None,
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

		let raw_order_data = order_data.raw_order_data.as_ref().ok_or_else(|| {
			OrderError::ValidationFailed("Missing raw order data for off-chain order".to_string())
		})?;

		let sponsor = order_data.sponsor.as_ref().ok_or_else(|| {
			OrderError::ValidationFailed("Missing sponsor for off-chain order".to_string())
		})?;

		let signature = order_data.signature.as_ref().ok_or_else(|| {
			OrderError::ValidationFailed("Missing signature for off-chain order".to_string())
		})?;

		// For the OIF contracts, we need to use the StandardOrder openFor
		// The raw_order_data contains the encoded StandardOrder
		// We just need to pass the order bytes, sponsor, and signature
		let sponsor_address =
			AlloyAddress::from_slice(&hex::decode(sponsor.trim_start_matches("0x")).map_err(
				|e| OrderError::ValidationFailed(format!("Invalid sponsor address: {}", e)),
			)?);

		// Use the InputSettlerEscrow openFor call
		let open_for_data = IInputSettlerEscrow::openForCall {
			order: hex::decode(raw_order_data.trim_start_matches("0x"))
				.map_err(|e| OrderError::ValidationFailed(format!("Invalid order data: {}", e)))?
				.into(),
			sponsor: sponsor_address,
			signature: hex::decode(signature.trim_start_matches("0x"))
				.map_err(|e| OrderError::ValidationFailed(format!("Invalid signature: {}", e)))?
				.into(),
		}
		.abi_encode();

		// Get the input settler address for the order's origin chain
		let origin_chain_id = *order
			.input_chain_ids
			.first()
			.ok_or_else(|| OrderError::ValidationFailed("No input chains in order".into()))?;
		let input_settler_address = self
			.networks
			.get(&origin_chain_id)
			.ok_or_else(|| {
				OrderError::ValidationFailed(format!(
					"Chain ID {} not found in networks configuration",
					order_data.origin_chain_id
				))
			})?
			.input_settler_address
			.clone();

		Ok(Some(Transaction {
			to: Some(input_settler_address),
			data: open_for_data,
			value: U256::ZERO,
			chain_id: origin_chain_id,
			nonce: None,
			gas_limit: order_data.gas_limit_overrides.prepare_gas_limit,
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

		// For multi-output orders, we need to handle each output separately
		// This implementation fills the first cross-chain output found
		// TODO: Implement logic to select the most profitable output
		let output = order_data
			.outputs
			.iter()
			.find(|o| o.chain_id != order_data.origin_chain_id)
			.ok_or_else(|| {
				OrderError::ValidationFailed("No cross-chain output found".to_string())
			})?;

		// Get the output settler address for the destination chain
		let dest_chain_id = output.chain_id.to::<u64>();
		let output_settler_address = self
			.networks
			.get(&dest_chain_id)
			.ok_or_else(|| {
				OrderError::ValidationFailed(format!(
					"Chain ID {} not found in networks configuration",
					dest_chain_id
				))
			})?
			.output_settler_address
			.clone();

		// Create the MandateOutput struct for the fill operation
		let mandate_output = MandateOutput {
			oracle: FixedBytes::<32>::from([0u8; 32]), // No oracle for direct fills
			settler: {
				let mut bytes32 = [0u8; 32];
				bytes32[12..32].copy_from_slice(&output_settler_address.0);
				FixedBytes::<32>::from(bytes32)
			},
			chainId: output.chain_id,
			token: FixedBytes::<32>::from(output.token),
			amount: output.amount,
			recipient: FixedBytes::<32>::from(output.recipient),
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
				solver_bytes32[12..32].copy_from_slice(&order.solver_address.0);
				solver_bytes32.to_vec().into()
			},
		}
		.abi_encode();

		Ok(Transaction {
			to: Some(output_settler_address),
			data: fill_data,
			value: U256::ZERO,
			chain_id: dest_chain_id,
			nonce: None,
			gas_limit: order_data.gas_limit_overrides.fill_gas_limit,
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

		// Check if all outputs are on the origin chain (same-chain order)
		let has_cross_chain = order_data
			.outputs
			.iter()
			.any(|o| o.chain_id != order_data.origin_chain_id);
		if !has_cross_chain {
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
			.map(|output| -> Result<MandateOutput, OrderError> {
				// Use the oracle value from the original order
				let oracle_bytes32 = FixedBytes::<32>::from(output.oracle);

				let settler_bytes32 = {
					let mut bytes32 = [0u8; 32];
					let output_chain_id = output.chain_id.to::<u64>();
					let network = self.networks.get(&output_chain_id).ok_or_else(|| {
						OrderError::ValidationFailed(format!(
							"Chain ID {} not found in networks configuration",
							output.chain_id
						))
					})?;

					let settler_address = if output.chain_id == order_data.origin_chain_id {
						// Use input settler for origin chain
						&network.input_settler_address
					} else {
						// Use output settler for other chains
						&network.output_settler_address
					};

					bytes32[12..32].copy_from_slice(&settler_address.0);
					FixedBytes::<32>::from(bytes32)
				};

				let token_bytes32 = FixedBytes::<32>::from(output.token);

				let recipient_bytes32 = FixedBytes::<32>::from(output.recipient);

				Ok(MandateOutput {
					oracle: oracle_bytes32,
					settler: settler_bytes32,
					chainId: output.chain_id,
					token: token_bytes32,
					amount: output.amount,
					recipient: recipient_bytes32,
					call: vec![].into(),
					context: vec![].into(),
				})
			})
			.collect::<Result<Vec<_>, _>>()?;

		// Build the order struct
		let order_struct = OrderStruct {
			user: user_address,
			nonce: order_data.nonce,
			originChainId: order_data.origin_chain_id,
			expires: order_data.expires,
			fillDeadline: order_data.fill_deadline,
			oracle: oracle_address,
			inputs,
			outputs,
		};

		// Create timestamps array - use timestamp from fill proof
		let timestamps = vec![fill_proof.filled_timestamp as u32];

		// Create solver bytes32 array (single solver in this case)
		let mut solver_bytes32 = [0u8; 32];
		solver_bytes32[12..32].copy_from_slice(&order.solver_address.0);
		let solvers = vec![FixedBytes::<32>::from(solver_bytes32)];

		// Create destination bytes32 (solver address for self-finalisation)
		let mut destination_bytes32 = [0u8; 32];
		destination_bytes32[12..32].copy_from_slice(&order.solver_address.0);
		let destination = FixedBytes::<32>::from(destination_bytes32);

		// Empty call data for simple finalisation
		let call = vec![];

		// Encode the finalise call
		let call_data = IInputSettlerEscrow::finaliseCall {
			order: order_struct,
			timestamps,
			solvers,
			destination,
			call: call.into(),
		}
		.abi_encode();

		// Get the input settler address for the order's origin chain
		let origin_chain_id = *order
			.input_chain_ids
			.first()
			.ok_or_else(|| OrderError::ValidationFailed("No input chains in order".into()))?;
		let input_settler_address = self
			.networks
			.get(&origin_chain_id)
			.ok_or_else(|| {
				OrderError::ValidationFailed(format!(
					"Chain ID {} not found in networks configuration",
					order_data.origin_chain_id
				))
			})?
			.input_settler_address
			.clone();

		Ok(Transaction {
			to: Some(input_settler_address),
			data: call_data,
			value: U256::ZERO,
			chain_id: origin_chain_id,
			nonce: None,
			gas_limit: order_data.gas_limit_overrides.settle_gas_limit,
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
/// * `config` - TOML configuration value (may be empty)
/// * `networks` - Networks configuration with settler addresses
///
/// # Returns
///
/// Returns a boxed `OrderInterface` implementation for EIP-7683 orders.
///
/// # Configuration
///
/// No specific configuration required - networks config is passed separately.
///
/// # Errors
///
/// Returns an error if networks configuration is invalid.
pub fn create_order_impl(
	config: &toml::Value,
	networks: &NetworksConfig,
) -> Result<Box<dyn OrderInterface>, OrderError> {
	// Validate configuration first
	Eip7683OrderSchema::validate_config(config)
		.map_err(|e| OrderError::InvalidOrder(format!("Invalid configuration: {}", e)))?;

	let order_impl = Eip7683OrderImpl::new(networks.clone())?;
	Ok(Box::new(order_impl))
}

/// Registry for the EIP-7683 order implementation.
pub struct Registry;

impl solver_types::ImplementationRegistry for Registry {
	const NAME: &'static str = "eip7683";
	type Factory = crate::OrderFactory;

	fn factory() -> Self::Factory {
		create_order_impl
	}
}

impl crate::OrderRegistry for Registry {}
