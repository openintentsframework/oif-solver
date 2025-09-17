//! Order processing implementations for the solver service.
//!
//! This module provides concrete implementations of the OrderInterface trait
//! for EIP-7683 cross-chain orders, including transaction generation for
//! filling and claiming orders.

use crate::{OrderError, OrderInterface};
use alloy_primitives::{Address as AlloyAddress, Bytes, FixedBytes, U256};
use alloy_sol_types::{SolCall, SolType};
use async_trait::async_trait;
use solver_delivery::DeliveryService;
use solver_types::{
	current_timestamp,
	oracle::OracleRoutes,
	standards::eip7683::{
		interfaces::{
			IInputSettlerCompact, IInputSettlerEscrow, IOutputSettlerSimple,
			SolMandateOutput as MandateOutput, SolveParams, StandardOrder as OifStandardOrder,
		},
		LockType,
	},
	Address, ConfigSchema, Eip7683OrderData, ExecutionParams, FillProof, Intent, NetworksConfig,
	Order, OrderStatus, Schema, Transaction,
};
use std::sync::Arc;

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
pub struct Eip7683OrderImpl {
	/// Networks configuration for dynamic settler address lookups.
	networks: NetworksConfig,
	/// Oracle routes for validation of input/output oracle compatibility.
	oracle_routes: OracleRoutes,
}

impl Eip7683OrderImpl {
	/// Build contract call for order ID based on lock type
	pub fn build_order_id_call(
		&self,
		order_bytes: &Bytes,
		lock_type: LockType,
	) -> Result<Bytes, OrderError> {
		match lock_type {
			LockType::ResourceLock => {
				// Decode to StandardOrder for Compact
				let std_order = OifStandardOrder::abi_decode(order_bytes, true).map_err(|e| {
					OrderError::ValidationFailed(format!("Failed to decode StandardOrder: {}", e))
				})?;

				let call = IInputSettlerCompact::orderIdentifierCall { order: std_order };
				Ok(Bytes::from(call.abi_encode()))
			},
			LockType::Permit2Escrow | LockType::Eip3009Escrow => {
				// Decode to StandardOrder for Escrow contracts
				let std_order = OifStandardOrder::abi_decode(order_bytes, true).map_err(|e| {
					OrderError::ValidationFailed(format!("Failed to decode StandardOrder: {}", e))
				})?;

				let call = IInputSettlerEscrow::orderIdentifierCall { order: std_order };
				Ok(Bytes::from(call.abi_encode()))
			},
		}
	}

	/// Get settler address for a specific chain and lock type
	pub fn get_settler_address(
		&self,
		chain_id: u64,
		lock_type: LockType,
	) -> Result<Address, OrderError> {
		let network = self.networks.get(&chain_id).ok_or_else(|| {
			OrderError::InvalidOrder(format!("No network config for chain {}", chain_id))
		})?;

		match lock_type {
			LockType::ResourceLock => {
				network
					.input_settler_compact_address
					.clone()
					.ok_or_else(|| {
						OrderError::InvalidOrder(format!(
							"No compact settler configured for chain {}",
							chain_id
						))
					})
			},
			LockType::Permit2Escrow | LockType::Eip3009Escrow => {
				Ok(network.input_settler_address.clone())
			},
		}
	}

	/// Creates a new EIP-7683 order implementation.
	///
	/// # Arguments
	///
	/// * `networks` - Networks configuration with settler addresses
	/// * `oracle_routes` - Oracle routes for validation
	/// * `delivery` - Delivery service for blockchain interactions
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

	/// Decode raw order bytes into StandardOrder struct.
	fn decode_standard_order(order_bytes: &str) -> Result<OifStandardOrder, OrderError> {
		let bytes = hex::decode(order_bytes.trim_start_matches("0x"))
			.map_err(|e| OrderError::ValidationFailed(format!("Invalid hex: {}", e)))?;

		// Decode using alloy's ABI decoder
		OifStandardOrder::abi_decode(&bytes, true).map_err(|e| {
			OrderError::ValidationFailed(format!("Failed to decode StandardOrder: {}", e))
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
			return Ok(None);
		}

		let order_data: Eip7683OrderData =
			serde_json::from_value(order.data.clone()).map_err(|e| {
				OrderError::ValidationFailed(format!("Failed to parse order data: {}", e))
			})?;
		// Skip prepare for Compact (resource lock) flows
		if matches!(order_data.lock_type, Some(LockType::ResourceLock)) {
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

		// Decode the raw order bytes into StandardOrder struct
		let order_struct = Self::decode_standard_order(raw_order_data)?;

		// Use the InputSettlerEscrow openFor call with StandardOrder struct
		let open_for_data = IInputSettlerEscrow::openForCall {
			order: order_struct,
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
	/// For ResourceLock orders, validates the signature before generating the fill transaction.
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
	/// - Signature validation fails for ResourceLock orders
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

		// Create the MandateOutput struct for the fill call
		let output_struct = MandateOutput {
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
			// For direct transfers, no additional call data is required, so this field is left empty.
			// If the output settlement requires invoking a contract with specific calldata, populate this field accordingly.
			call: vec![].into(),
			// Context is also left empty for direct transfers, as no extra execution context is needed.
			// This field may be populated for advanced settlement scenarios (e.g., meta-transactions, custom logic).
			context: vec![].into(),
		};

		// Encode fill data for OutputSettlerSimple using the new signature
		let fill_data = IOutputSettlerSimple::fillCall {
			orderId: FixedBytes::<32>::from(order_data.order_id),
			output: output_struct,
			fillDeadline: alloy_primitives::Uint::<48, 1>::from(order_data.fill_deadline as u64),
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
		let order_struct = OifStandardOrder {
			user: user_address,
			nonce: order_data.nonce,
			originChainId: order_data.origin_chain_id,
			expires: order_data.expires,
			fillDeadline: order_data.fill_deadline,
			inputOracle: oracle_address,
			inputs,
			outputs,
		};

		// Create SolveParams struct with timestamp and solver
		let mut solver_bytes32 = [0u8; 32];
		solver_bytes32[12..32].copy_from_slice(&order.solver_address.0);

		let solve_params = vec![SolveParams {
			timestamp: fill_proof.filled_timestamp as u32,
			solver: FixedBytes::<32>::from(solver_bytes32),
		}];

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
						order: order_struct.clone(),
						signatures: compact_sig_bytes.into(),
						solveParams: solve_params.clone(),
						destination,
						call: call.into(),
					}
					.abi_encode()
				},
				_ => IInputSettlerEscrow::finaliseCall {
					order: order_struct,
					solveParams: solve_params,
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

	/// Validates EIP-7683 order bytes by decoding to StandardOrder and validating.
	async fn validate_order(&self, order_bytes: &Bytes) -> Result<OifStandardOrder, OrderError> {
		// Decode using the StandardOrder from types module
		let standard_order = OifStandardOrder::abi_decode(order_bytes, true).map_err(|e| {
			OrderError::ValidationFailed(format!("Failed to decode StandardOrder: {}", e))
		})?;

		let current_time = current_timestamp() as u32;

		if standard_order.expires < current_time {
			return Err(OrderError::ValidationFailed(
				"Order has expired".to_string(),
			));
		}

		if standard_order.fillDeadline < current_time {
			return Err(OrderError::ValidationFailed(
				"Order fill deadline has passed".to_string(),
			));
		}

		// TODO: validate oracle routes and signatures

		// Return the decoded StandardOrder directly since it's already the right type
		Ok(standard_order)
	}

	/// Validates order bytes and creates a generic Order with computed order ID.
	///
	/// This override ensures the standard name is correctly set to "eip7683".
	async fn validate_and_create_order(
		&self,
		order_bytes: &Bytes,
		lock_type: &str,
		order_id_callback: solver_types::OrderIdCallback,
		solver_address: &Address,
	) -> Result<Order, OrderError> {
		// First validate the order
		let standard_order = self.validate_order(order_bytes).await?;

		// Build tx_data for order ID computation
		let chain_id = standard_order.originChainId.to::<u64>();

		// Parse lock type
		let lock_type = lock_type
			.parse::<LockType>()
			.map_err(|e| OrderError::ValidationFailed(format!("Invalid lock type: {}", e)))?;

		// Get settler address and build calldata
		let settler_address = self.get_settler_address(chain_id, lock_type).map_err(|e| {
			OrderError::ValidationFailed(format!("Failed to get settler address: {}", e))
		})?;

		let calldata = self.build_order_id_call(order_bytes, lock_type)?;

		// Build tx_data as [settler_address][calldata]
		let mut tx_data = Vec::with_capacity(20 + calldata.len());
		tx_data.extend_from_slice(&settler_address.0);
		tx_data.extend_from_slice(&calldata);

		// Compute order ID using the callback
		let order_id_bytes = order_id_callback(chain_id, tx_data).await.map_err(|e| {
			OrderError::ValidationFailed(format!("Failed to compute order ID: {}", e))
		})?;

		// Ensure order ID is exactly 32 bytes
		if order_id_bytes.len() != 32 {
			return Err(OrderError::ValidationFailed(format!(
				"Invalid order ID length: expected 32 bytes, got {}",
				order_id_bytes.len()
			)));
		}

		// Convert order ID bytes to fixed array
		let mut order_id_array = [0u8; 32];
		order_id_array.copy_from_slice(&order_id_bytes);

		// Convert order ID bytes to hex string
		let order_id = alloy_primitives::hex::encode_prefixed(&order_id_bytes);

		// Extract chain IDs from the order
		let input_chain_ids = vec![standard_order.originChainId.to::<u64>()];
		let output_chain_ids: Vec<u64> = standard_order
			.outputs
			.iter()
			.map(|output| output.chainId.to::<u64>())
			.collect();

		// Convert StandardOrder to Eip7683OrderData for serialization
		let mut order_data = Eip7683OrderData::from(standard_order.clone());
		order_data.order_id = order_id_array;
		order_data.lock_type = Some(lock_type);

		// Create generic Order
		Ok(Order {
			id: order_id,
			standard: "eip7683".to_string(),
			created_at: current_timestamp(),
			updated_at: current_timestamp(),
			status: OrderStatus::Pending,
			data: serde_json::to_value(&order_data).map_err(|e| {
				OrderError::ValidationFailed(format!("Failed to serialize order: {}", e))
			})?,
			solver_address: solver_address.clone(),
			quote_id: None,
			input_chain_ids,
			output_chain_ids,
			execution_params: None,
			prepare_tx_hash: None,
			fill_tx_hash: None,
			claim_tx_hash: None,
			post_fill_tx_hash: None,
			pre_claim_tx_hash: None,
			fill_proof: None,
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
/// * `oracle_routes` - Oracle routes for validation
/// * `delivery` - Delivery service for blockchain interactions
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
		standards::eip7683::{interfaces, Eip7683OrderData, LockType},
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

	fn create_test_delivery_service() -> Arc<DeliveryService> {
		// Create a mock delivery implementation for testing
		struct MockDeliveryImpl;

		#[async_trait::async_trait]
		impl solver_delivery::DeliveryInterface for MockDeliveryImpl {
			fn config_schema(&self) -> Box<dyn solver_types::ConfigSchema> {
				// Create a simple schema implementation for testing
				struct MockSchema;
				impl solver_types::ConfigSchema for MockSchema {
					fn validate(
						&self,
						_config: &toml::Value,
					) -> Result<(), solver_types::ValidationError> {
						Ok(())
					}
				}
				Box::new(MockSchema)
			}

			async fn submit(
				&self,
				_tx: solver_types::Transaction,
			) -> Result<solver_types::TransactionHash, solver_delivery::DeliveryError> {
				Ok(solver_types::TransactionHash(vec![0; 32]))
			}

			async fn wait_for_confirmation(
				&self,
				_hash: &solver_types::TransactionHash,
				_chain_id: u64,
				_confirmations: u64,
			) -> Result<solver_types::TransactionReceipt, solver_delivery::DeliveryError> {
				Ok(solver_types::TransactionReceipt {
					hash: solver_types::TransactionHash(vec![0; 32]),
					block_number: 1,
					success: true,
				})
			}

			async fn get_receipt(
				&self,
				_hash: &solver_types::TransactionHash,
				_chain_id: u64,
			) -> Result<solver_types::TransactionReceipt, solver_delivery::DeliveryError> {
				Ok(solver_types::TransactionReceipt {
					hash: solver_types::TransactionHash(vec![0; 32]),
					block_number: 1,
					success: true,
				})
			}

			async fn get_balance(
				&self,
				_address: &str,
				_token: Option<&str>,
				_chain_id: u64,
			) -> Result<String, solver_delivery::DeliveryError> {
				Ok("1000000000000000000".to_string())
			}

			async fn get_nonce(
				&self,
				_address: &str,
				_chain_id: u64,
			) -> Result<u64, solver_delivery::DeliveryError> {
				Ok(0)
			}

			async fn get_gas_price(
				&self,
				_chain_id: u64,
			) -> Result<String, solver_delivery::DeliveryError> {
				Ok("20000000000".to_string())
			}

			async fn get_allowance(
				&self,
				_owner: &str,
				_spender: &str,
				_token_address: &str,
				_chain_id: u64,
			) -> Result<String, solver_delivery::DeliveryError> {
				Ok("1000000000000000000".to_string())
			}

			async fn get_block_number(
				&self,
				_chain_id: u64,
			) -> Result<u64, solver_delivery::DeliveryError> {
				Ok(12345)
			}

			async fn estimate_gas(
				&self,
				_tx: solver_types::Transaction,
			) -> Result<u64, solver_delivery::DeliveryError> {
				Ok(21000)
			}

			async fn eth_call(
				&self,
				_tx: solver_types::Transaction,
			) -> Result<alloy_primitives::Bytes, solver_delivery::DeliveryError> {
				// Mock response for DOMAIN_SEPARATOR() call - return the expected hardcoded domain separator
				let domain_separator =
					hex::decode("330989378c39c177ab3877ced96ca0cdb60d7a6489567b993185beff161d80d7")
						.expect("Invalid hardcoded domain separator hex");
				Ok(alloy_primitives::Bytes::from(domain_separator))
			}
		}

		let mut delivery_impls = std::collections::HashMap::new();
		delivery_impls.insert(
			1u64,
			Arc::new(MockDeliveryImpl) as Arc<dyn solver_delivery::DeliveryInterface>,
		);
		delivery_impls.insert(
			137u64,
			Arc::new(MockDeliveryImpl) as Arc<dyn solver_delivery::DeliveryInterface>,
		);

		Arc::new(DeliveryService::new(delivery_impls, 1))
	}

	#[test]
	fn test_new_eip7683_order_impl() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let _delivery = create_test_delivery_service();

		let result = Eip7683OrderImpl::new(networks, oracle_routes);
		assert!(result.is_ok());
	}

	#[test]
	fn test_new_with_insufficient_networks() {
		let networks = NetworksConfigBuilder::new()
			.add_network(1, NetworkConfigBuilder::new().build())
			.build();

		let oracle_routes = create_test_oracle_routes();

		let _delivery = create_test_delivery_service();
		let result = Eip7683OrderImpl::new(networks, oracle_routes);
		assert!(result.is_err());
		if let Err(e) = result {
			assert!(e.to_string().contains("At least 2 networks"));
		}
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
		let _delivery = create_test_delivery_service();
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
		// Create a valid StandardOrder and encode it for raw_order_data
		use alloy_primitives::{Address as AlloyAddress, B256};
		use alloy_sol_types::SolValue;
		let test_order = interfaces::StandardOrder {
			user: AlloyAddress::from([0x11; 20]),
			nonce: U256::from(123),
			originChainId: U256::from(1),
			expires: 1000000000,
			fillDeadline: 1000000100,
			inputOracle: AlloyAddress::from([0x22; 20]),
			inputs: vec![[U256::from(100), U256::from(200)]],
			outputs: vec![interfaces::SolMandateOutput {
				oracle: B256::from([0x33; 32]),
				settler: B256::from([0x44; 32]),
				chainId: U256::from(137),
				token: B256::from([0x55; 32]),
				amount: U256::from(1000),
				recipient: B256::from([0x66; 32]),
				call: vec![].into(),
				context: vec![].into(),
			}],
		};
		order_data.raw_order_data = Some(format!("0x{}", hex::encode(test_order.abi_encode())));
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
		let _delivery = create_test_delivery_service();
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
}
