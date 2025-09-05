//! Order processing implementations for the solver service.
//!
//! This module provides concrete implementations of the OrderInterface trait
//! for EIP-7683 cross-chain orders, including transaction generation for
//! filling and claiming orders.

use crate::{OrderError, OrderInterface};
use alloy_primitives::{Address as AlloyAddress, FixedBytes, U256};
use alloy_sol_types::{sol, SolCall};
use async_trait::async_trait;
use solver_types::{
	oracle::OracleRoutes, standards::eip7683::LockType, Address, ConfigSchema, Eip7683OrderData,
	ExecutionParams, FillProof, Intent, NetworksConfig, Order, OrderStatus, Schema, Transaction,
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

	/// Structure that matches OutputFillLib's expected packed encoding format.
	/// This struct represents the exact byte layout expected by OutputSettlerSimple.
	struct PackedMandateOutput {
		uint48 fillDeadline;    // 6 bytes at offset 0
		bytes32 oracle;          // 32 bytes at offset 6
		bytes32 settler;         // 32 bytes at offset 38
		uint256 chainId;         // 32 bytes at offset 70
		bytes32 token;           // 32 bytes at offset 102
		uint256 amount;          // 32 bytes at offset 134
		bytes32 recipient;       // 32 bytes at offset 166
		// Note: call and context need special handling due to their variable length
		// and 2-byte length prefixes which ABI encoding doesn't naturally provide
	}

	/// OutputSettlerSimple interface for filling orders.
	interface IOutputSettlerSimple {
		function fill(bytes32 orderId, bytes originData, bytes fillerData) external returns (bytes32);
		function fillOrderOutputs(bytes32 orderId, bytes[] outputs, bytes fillerData) external;
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

	/// IInputSettlerCompact interface for Compact-based settlement.
	interface IInputSettlerCompact {
		function finalise(OrderStruct order, bytes signatures, uint32[] timestamps, bytes32[] solvers, bytes32 destination, bytes call) external;
		function finaliseWithSignature(OrderStruct order, bytes signatures, uint32[] timestamps, bytes32[] solvers, bytes32 destination, bytes call, bytes signature) external;
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
/// * `oracle_routes` - Oracle routes for validation of input/output oracle compatibility
#[derive(Debug)]
pub struct Eip7683OrderImpl {
	/// Networks configuration for dynamic settler address lookups.
	networks: NetworksConfig,
	/// Oracle routes for validation of input/output oracle compatibility.
	oracle_routes: OracleRoutes,
}

impl Eip7683OrderImpl {
	/// Creates a new EIP-7683 order implementation.
	///
	/// # Arguments
	///
	/// * `networks` - Networks configuration with settler addresses
	/// * `oracle_routes` - Oracle routes for validation
	pub fn new(networks: NetworksConfig, oracle_routes: OracleRoutes) -> Result<Self, OrderError> {
		// Validate that networks config has at least 2 networks
		if networks.len() < 2 {
			return Err(OrderError::ValidationFailed(
				"At least 2 networks must be configured".to_string(),
			));
		}

		Ok(Self {
			networks,
			oracle_routes,
		})
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

		// Validate oracle routes
		let origin_chain = order_data.origin_chain_id.to::<u64>();
		let input_oracle = solver_types::utils::parse_address(&order_data.input_oracle)
			.map_err(|e| OrderError::ValidationFailed(format!("Invalid input oracle: {}", e)))?;

		let input_info = solver_types::oracle::OracleInfo {
			chain_id: origin_chain,
			oracle: input_oracle,
		};

		// Check if the input oracle is supported
		if !self
			.oracle_routes
			.supported_routes
			.contains_key(&input_info)
		{
			return Err(OrderError::ValidationFailed(format!(
				"Input oracle {} on chain {} is not supported",
				order_data.input_oracle, origin_chain
			)));
		}

		// Get supported output oracles for this input oracle
		let supported_outputs = self
			.oracle_routes
			.supported_routes
			.get(&input_info)
			.ok_or_else(|| {
				OrderError::ValidationFailed(format!(
					"No routes configured for input oracle {} on chain {}",
					order_data.input_oracle, origin_chain
				))
			})?;

		// Early validation: Check if the specific routes exist
		let supported_destinations: std::collections::HashSet<u64> =
			supported_outputs.iter().map(|info| info.chain_id).collect();

		for output in &order_data.outputs {
			let dest_chain = output.chain_id.to::<u64>();

			// Skip same-chain outputs as they don't need cross-chain routes
			if dest_chain == origin_chain {
				continue;
			}

			if !supported_destinations.contains(&dest_chain) {
				return Err(OrderError::ValidationFailed(format!(
					"Route from chain {} to chain {} is not supported (oracle {} has no route to destination)",
					origin_chain, dest_chain, order_data.input_oracle
				)));
			}
		}

		// Validate each output oracle
		for output in &order_data.outputs {
			let dest_chain = output.chain_id.to::<u64>();

			// If output oracle is zero (0x00...), it means use any compatible oracle
			// Otherwise, validate the specific oracle
			if output.oracle != [0u8; 32] {
				// Parse the oracle address from bytes32 (take first 20 bytes)
				let output_oracle_bytes = &output.oracle[12..32]; // Last 20 bytes for address
				let output_oracle = Address(output_oracle_bytes.into());

				let output_info = solver_types::oracle::OracleInfo {
					chain_id: dest_chain,
					oracle: output_oracle,
				};

				// Check if this output oracle is in the supported list
				if !supported_outputs.contains(&output_info) {
					return Err(OrderError::ValidationFailed(format!(
						"Output oracle {:?} on chain {} is not compatible with input oracle {} on chain {}",
						output.oracle, dest_chain, order_data.input_oracle, origin_chain
					)));
				}
			} else {
				// Zero oracle means any oracle on the destination chain is acceptable
				// Just verify that there's at least one oracle for this destination
				let has_route_to_dest = supported_outputs
					.iter()
					.any(|info| info.chain_id == dest_chain);

				if !has_route_to_dest {
					return Err(OrderError::ValidationFailed(format!(
						"No route available from chain {} to chain {}",
						origin_chain, dest_chain
					)));
				}
			}
		}

		// Extract chain IDs
		let input_chain_ids = vec![origin_chain];
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
			post_fill_tx_hash: None,
			pre_claim_tx_hash: None,
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
			tracing::debug!(
				order_id = %order.id,
				source = %intent.source,
				"Skipping preparation: not an off-chain order"
			);
			return Ok(None);
		}

		let order_data: Eip7683OrderData =
			serde_json::from_value(order.data.clone()).map_err(|e| {
				OrderError::ValidationFailed(format!("Failed to parse order data: {}", e))
			})?;
		
		tracing::debug!(
			order_id = %order.id,
			lock_type = ?order_data.lock_type,
			"Checking lock type for preparation decision"
		);
		
		// Skip prepare for Compact (resource lock) flows
		if matches!(order_data.lock_type, Some(LockType::ResourceLock)) {
			tracing::info!(
				order_id = %order.id,
				"Skipping preparation: ResourceLock order detected"
			);
			return Ok(None);
		}

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

		// Encode fill data for OutputSettlerSimple using packed encoding
		let fill_data = IOutputSettlerSimple::fillCall {
			orderId: FixedBytes::<32>::from(order_data.order_id),
			originData: {
				// Use abi.encodePacked equivalent for the exact byte layout expected by OutputFillLib
				let packed_output = PackedMandateOutput {
					fillDeadline: alloy_primitives::Uint::<48, 1>::from(
						order_data.fill_deadline as u64,
					),
					oracle: FixedBytes::<32>::from(output.oracle),
					settler: {
						let mut bytes32 = [0u8; 32];
						bytes32[12..32].copy_from_slice(&output_settler_address.0);
						FixedBytes::<32>::from(bytes32)
					},
					chainId: output.chain_id,
					token: FixedBytes::<32>::from(output.token),
					amount: output.amount,
					recipient: FixedBytes::<32>::from(output.recipient),
				};

				// Build the packed bytes manually since we need special handling for call/context
				let mut origin_data = Vec::new();

				// Add the fixed-size fields using packed encoding (no offsets/padding)
				// fillDeadline as 6 bytes
				let fill_deadline_bytes = packed_output.fillDeadline.to_be_bytes_vec();
				// The Uint<48, 1> will produce exactly 6 bytes
				origin_data.extend_from_slice(&fill_deadline_bytes);

				// oracle, settler, chainId, token, amount, recipient as 32 bytes each
				origin_data.extend_from_slice(packed_output.oracle.as_slice());
				origin_data.extend_from_slice(packed_output.settler.as_slice());
				origin_data.extend_from_slice(&packed_output.chainId.to_be_bytes_vec());
				origin_data.extend_from_slice(packed_output.token.as_slice());
				origin_data.extend_from_slice(&packed_output.amount.to_be_bytes_vec());
				origin_data.extend_from_slice(packed_output.recipient.as_slice());

				// Add call length (2 bytes) and call data
				let call_data = vec![]; // Empty for direct transfers
				origin_data.extend_from_slice(&(call_data.len() as u16).to_be_bytes());
				origin_data.extend_from_slice(&call_data);

				// Add context length (2 bytes) and context data
				let context_data = vec![]; // Empty context
				origin_data.extend_from_slice(&(context_data.len() as u16).to_be_bytes());
				origin_data.extend_from_slice(&context_data);

				origin_data.into()
			},
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

		// Encode the finalise call. If Compact flow, include signatures argument.
		let call_data = {
			let parsed =
				serde_json::from_value::<Eip7683OrderData>(order.data.clone()).map_err(|e| {
					OrderError::ValidationFailed(format!("Failed to parse order data: {}", e))
				})?;
			match parsed.lock_type {
				Some(LockType::ResourceLock) => {
					let sig_hex = parsed.signature.as_deref().ok_or_else(|| {
						OrderError::ValidationFailed(
							"Missing signatures for compact flow".to_string(),
						)
					})?;

					// Expect full signature payload already without any type prefix
					let sig_str = sig_hex.trim_start_matches("0x");
					let compact_sig_bytes = hex::decode(sig_str).map_err(|e| {
						OrderError::ValidationFailed(format!("Invalid compact signatures: {}", e))
					})?;

					IInputSettlerCompact::finaliseCall {
						order: order_struct,
						signatures: compact_sig_bytes.into(),
						timestamps,
						solvers,
						destination,
						call: call.into(),
					}
					.abi_encode()
				},
				_ => IInputSettlerEscrow::finaliseCall {
					order: order_struct,
					timestamps,
					solvers,
					destination,
					call: call.into(),
				}
				.abi_encode(),
			}
		};

		// Get the input settler address for the order's origin chain
		let origin_chain_id = *order
			.input_chain_ids
			.first()
			.ok_or_else(|| OrderError::ValidationFailed("No input chains in order".into()))?;
		let network_cfg = self.networks.get(&origin_chain_id).ok_or_else(|| {
			OrderError::ValidationFailed(format!(
				"Chain ID {} not found in networks configuration",
				order_data.origin_chain_id
			))
		})?;
		let is_compact = serde_json::from_value::<Eip7683OrderData>(order.data.clone())
			.ok()
			.and_then(|d| d.lock_type)
			.map(|lt| lt == LockType::ResourceLock)
			.unwrap_or(false);
		let input_settler_address = if is_compact {
			// Prefer compact-specific address if provided
			network_cfg
				.input_settler_compact_address
				.clone()
				.unwrap_or_else(|| network_cfg.input_settler_address.clone())
		} else {
			network_cfg.input_settler_address.clone()
		};

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
	oracle_routes: &solver_types::oracle::OracleRoutes,
) -> Result<Box<dyn OrderInterface>, OrderError> {
	// Validate configuration first
	Eip7683OrderSchema::validate_config(config)
		.map_err(|e| OrderError::InvalidOrder(format!("Invalid configuration: {}", e)))?;

	let order_impl = Eip7683OrderImpl::new(networks.clone(), oracle_routes.clone())?;
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

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::U256;
	use solver_types::{
		oracle::{OracleInfo, OracleRoutes},
		standards::eip7683::{Eip7683OrderData, LockType},
		utils::tests::builders::{
			Eip7683OrderDataBuilder, IntentBuilder, NetworkConfigBuilder, NetworksConfigBuilder,
			OrderBuilder,
		},
		Address, ExecutionParams, FillProof, Intent, NetworksConfig, OrderStatus, TransactionHash,
	};
	use std::collections::HashMap;

	fn create_test_networks() -> NetworksConfig {
		NetworksConfigBuilder::new()
			.add_network(1, NetworkConfigBuilder::new().build())
			.add_network(137, NetworkConfigBuilder::new().build())
			.build()
	}

	fn create_test_oracle_routes() -> OracleRoutes {
		let mut supported_routes = HashMap::new();

		let input_oracle = OracleInfo {
			chain_id: 1,
			oracle: Address(vec![10u8; 20]),
		};

		let output_oracle = OracleInfo {
			chain_id: 137,
			oracle: Address(vec![11u8; 20]),
		};

		supported_routes.insert(input_oracle, vec![output_oracle]);

		OracleRoutes { supported_routes }
	}

	fn create_test_order_data() -> Eip7683OrderData {
		Eip7683OrderDataBuilder::new().build()
	}

	fn create_test_intent(order_data: Eip7683OrderData, source: &str) -> Intent {
		IntentBuilder::new()
			.with_id("test-intent-id".to_string())
			.with_source(source.to_string())
			.with_data(serde_json::to_value(&order_data).unwrap())
			.with_quote_id(Some("test-quote-id".to_string()))
			.build()
	}

	#[test]
	fn test_new_eip7683_order_impl() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();

		let result = Eip7683OrderImpl::new(networks, oracle_routes);
		assert!(result.is_ok());
	}

	#[test]
	fn test_new_with_insufficient_networks() {
		let networks = NetworksConfigBuilder::new()
			.add_network(1, NetworkConfigBuilder::new().build())
			.build();

		let oracle_routes = create_test_oracle_routes();

		let result = Eip7683OrderImpl::new(networks, oracle_routes);
		assert!(result.is_err());
		assert!(result
			.unwrap_err()
			.to_string()
			.contains("At least 2 networks"));
	}

	#[tokio::test]
	async fn test_validate_intent_success() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		let order_data = create_test_order_data();
		let intent = create_test_intent(order_data, "on-chain");
		let solver_address = Address(vec![99u8; 20]);

		let result = order_impl.validate_intent(&intent, &solver_address).await;
		assert!(result.is_ok());

		let order = result.unwrap();
		assert_eq!(order.id, "test-intent-id");
		assert_eq!(order.standard, "eip7683");
		assert_eq!(order.solver_address, solver_address);
		assert_eq!(order.status, OrderStatus::Created);
	}

	#[tokio::test]
	async fn test_validate_intent_wrong_standard() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		let mut intent = create_test_intent(create_test_order_data(), "on-chain");
		intent.standard = "eip7230".to_string();
		let solver_address = Address(vec![99u8; 20]);

		let result = order_impl.validate_intent(&intent, &solver_address).await;
		assert!(result.is_err());
		assert!(result
			.unwrap_err()
			.to_string()
			.contains("Not an EIP-7683 order"));
	}

	#[tokio::test]
	async fn test_validate_intent_expired_order() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		let mut order_data = create_test_order_data();
		order_data.expires = 100; // Set to past timestamp
		let intent = create_test_intent(order_data, "on-chain");
		let solver_address = Address(vec![99u8; 20]);

		let result = order_impl.validate_intent(&intent, &solver_address).await;
		assert!(result.is_err());
		assert!(result.unwrap_err().to_string().contains("Order expired"));
	}

	#[tokio::test]
	async fn test_validate_intent_unsupported_oracle() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		let mut order_data = create_test_order_data();
		order_data.input_oracle = "0x9999999999999999999999999999999999999999".to_string();
		let intent = create_test_intent(order_data, "on-chain");
		let solver_address = Address(vec![99u8; 20]);

		let result = order_impl.validate_intent(&intent, &solver_address).await;
		assert!(result.is_err());
		assert!(result.unwrap_err().to_string().contains("is not supported"));
	}

	#[tokio::test]
	async fn test_generate_prepare_transaction_onchain_order() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		let order_data = create_test_order_data();
		let intent = create_test_intent(order_data.clone(), "on-chain");
		let order = OrderBuilder::new()
			.with_data(serde_json::to_value(&order_data).unwrap())
			.with_solver_address(Address(vec![99u8; 20]))
			.with_quote_id(Some("test-quote".to_string()))
			.with_input_chain_ids(vec![1])
			.with_output_chain_ids(vec![137])
			.build();
		let params = ExecutionParams {
			gas_price: U256::ZERO,
			priority_fee: None,
		};

		let result = order_impl
			.generate_prepare_transaction(&intent, &order, &params)
			.await;
		assert!(result.is_ok());
		assert!(result.unwrap().is_none()); // On-chain orders don't need preparation
	}

	#[tokio::test]
	async fn test_generate_prepare_transaction_offchain_order() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		let mut order_data = create_test_order_data();
		order_data.raw_order_data = Some("0xabcdef".to_string());
		order_data.sponsor = Some("0x1111111111111111111111111111111111111111".to_string());
		order_data.signature = Some("0x22222222".to_string());

		let intent = create_test_intent(order_data.clone(), "off-chain");
		let order = OrderBuilder::new()
			.with_data(serde_json::to_value(&order_data).unwrap())
			.with_solver_address(Address(vec![99u8; 20]))
			.with_quote_id(Some("test-quote".to_string()))
			.with_input_chain_ids(vec![1])
			.with_output_chain_ids(vec![137])
			.build();
		let params = ExecutionParams {
			gas_price: U256::ZERO,
			priority_fee: None,
		};

		let result = order_impl
			.generate_prepare_transaction(&intent, &order, &params)
			.await;
		assert!(result.is_ok());

		let tx = result.unwrap().unwrap();
		assert_eq!(tx.chain_id, 1);
		assert_eq!(
			tx.to,
			Some(Address(
				hex::decode("7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9").unwrap()
			))
		); // input_settler_address for chain 1
		assert!(!tx.data.is_empty());
	}

	#[tokio::test]
	async fn test_generate_fill_transaction() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		let order_data = create_test_order_data();
		let order = OrderBuilder::new()
			.with_data(serde_json::to_value(&order_data).unwrap())
			.with_solver_address(Address(vec![99u8; 20]))
			.with_quote_id(Some("test-quote".to_string()))
			.with_input_chain_ids(vec![1])
			.with_output_chain_ids(vec![137])
			.build();
		let params = ExecutionParams {
			gas_price: U256::ZERO,
			priority_fee: None,
		};

		let result = order_impl.generate_fill_transaction(&order, &params).await;
		assert!(result.is_ok());

		let tx = result.unwrap();
		assert_eq!(tx.chain_id, 137); // destination chain
		assert_eq!(
			tx.to,
			Some(Address(
				hex::decode("5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f").unwrap()
			))
		); // output_settler_address for chain 137
		assert!(!tx.data.is_empty());
	}

	#[tokio::test]
	async fn test_generate_claim_transaction_escrow() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		let order_data = create_test_order_data();
		let order = OrderBuilder::new()
			.with_data(serde_json::to_value(&order_data).unwrap())
			.with_solver_address(Address(vec![99u8; 20]))
			.with_quote_id(Some("test-quote".to_string()))
			.with_input_chain_ids(vec![1])
			.with_output_chain_ids(vec![137])
			.build();
		let fill_proof = FillProof {
			tx_hash: TransactionHash(hex::decode("abcd").unwrap()),
			block_number: 12345,
			attestation_data: Some(b"proof".to_vec()),
			filled_timestamp: 123456789,
			oracle_address: "0x0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B".to_string(),
		};

		let result = order_impl
			.generate_claim_transaction(&order, &fill_proof)
			.await;
		assert!(result.is_ok());

		let tx = result.unwrap();
		assert_eq!(tx.chain_id, 1); // origin chain
		assert_eq!(
			tx.to,
			Some(Address(
				hex::decode("7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9").unwrap()
			))
		); // input_settler_address for chain 1
		assert!(!tx.data.is_empty());
	}

	#[tokio::test]
	async fn test_generate_claim_transaction_compact() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		let mut order_data = create_test_order_data();
		order_data.lock_type = Some(LockType::ResourceLock);
		order_data.signature = Some("0x123456789abcdef0".to_string());

		let order = OrderBuilder::new()
			.with_id("test-order".to_string())
			.with_data(serde_json::to_value(&order_data).unwrap())
			.with_solver_address(Address(vec![99u8; 20]))
			.with_quote_id(Some("test-quote".to_string()))
			.with_input_chain_ids(vec![1])
			.with_output_chain_ids(vec![137])
			.build();

		let fill_proof = FillProof {
			tx_hash: TransactionHash(hex::decode("abcd").unwrap()),
			block_number: 12345,
			attestation_data: Some(b"proof".to_vec()),
			filled_timestamp: 123456789,
			oracle_address: "0x0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B".to_string(),
		};

		let result = order_impl
			.generate_claim_transaction(&order, &fill_proof)
			.await;
		assert!(result.is_ok());

		let tx = result.unwrap();
		assert_eq!(tx.chain_id, 1); // origin chain
		assert_eq!(
			tx.to,
			Some(Address(
				hex::decode("00000000000c2e074ec69a0dfb2997ba6c7d2e1e").unwrap()
			))
		); // compact address for chain 1
		assert!(!tx.data.is_empty());
	}

	#[test]
	fn test_config_schema_validation() {
		let schema = Eip7683OrderSchema;
		let valid_config = toml::Value::Table(toml::map::Map::new());

		let result = schema.validate(&valid_config);
		assert!(result.is_ok());
	}

	#[test]
	fn test_create_order_impl_factory() {
		let config = toml::Value::Table(toml::map::Map::new());
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();

		let result = create_order_impl(&config, &networks, &oracle_routes);
		assert!(result.is_ok());
	}

	#[test]
	fn test_lock_type_enum() {
		assert_eq!(LockType::from_u8(1), Some(LockType::Permit2Escrow));
		assert_eq!(LockType::from_u8(2), Some(LockType::Eip3009Escrow));
		assert_eq!(LockType::from_u8(3), Some(LockType::ResourceLock));
		assert_eq!(LockType::from_u8(99), None);

		assert_eq!(LockType::Permit2Escrow.to_u8(), 1);
		assert_eq!(LockType::ResourceLock.to_u8(), 3);

		assert!(LockType::ResourceLock.is_compact());
		assert!(!LockType::Permit2Escrow.is_compact());

		assert!(LockType::Permit2Escrow.is_escrow());
		assert!(!LockType::ResourceLock.is_escrow());
	}

	#[tokio::test]
	async fn test_generate_fill_transaction_no_cross_chain_output() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		let mut order_data = create_test_order_data();
		// Make the output same-chain
		order_data.outputs[0].chain_id = U256::from(1);
		let order = OrderBuilder::new()
			.with_data(serde_json::to_value(&order_data).unwrap())
			.with_solver_address(Address(vec![99u8; 20]))
			.with_quote_id(Some("test-quote".to_string()))
			.with_input_chain_ids(vec![1])
			.with_output_chain_ids(vec![1])
			.build();
		let params = ExecutionParams {
			gas_price: U256::ZERO,
			priority_fee: None,
		};

		let result = order_impl.generate_fill_transaction(&order, &params).await;
		assert!(result.is_err());
		assert!(result
			.unwrap_err()
			.to_string()
			.contains("No cross-chain output found"));
	}
}
