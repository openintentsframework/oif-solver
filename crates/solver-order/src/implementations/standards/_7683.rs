//! Order processing implementations for the solver service.
//!
//! This module provides concrete implementations of the OrderInterface trait
//! for EIP-7683 cross-chain orders, including transaction generation for
//! filling and claiming orders.

use crate::{OrderError, OrderInterface};
use alloy_primitives::{Bytes, FixedBytes, U256};
use alloy_sol_types::{SolCall, SolType};
use async_trait::async_trait;
use solver_types::{
	current_timestamp,
	oracle::OracleRoutes,
	standards::eip7683::{
		interfaces::{
			IInputSettlerCompact, IInputSettlerEscrow, IOutputSettlerSimple, SolMandateOutput,
			SolveParams, StandardOrder,
		},
		LockType,
	},
	utils::conversion::hex_to_alloy_address,
	Address, ConfigSchema, Eip7683OrderData, ExecutionParams, FillProof, NetworksConfig, Order,
	OrderStatus, Schema, Transaction,
};

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
	/// Build contract call for order ID based on lock type
	pub fn build_order_id_call(
		&self,
		order_bytes: &Bytes,
		lock_type: LockType,
	) -> Result<Bytes, OrderError> {
		match lock_type {
			LockType::ResourceLock => {
				// Decode to StandardOrder for Compact
				let std_order = StandardOrder::abi_decode_validate(order_bytes).map_err(|e| {
					OrderError::ValidationFailed(format!("Failed to decode StandardOrder: {}", e))
				})?;

				let call = IInputSettlerCompact::orderIdentifierCall { order: std_order };
				Ok(Bytes::from(call.abi_encode()))
			},
			LockType::Permit2Escrow | LockType::Eip3009Escrow => {
				// Decode to StandardOrder for Escrow contracts
				let std_order = StandardOrder::abi_decode_validate(order_bytes).map_err(|e| {
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
	fn decode_standard_order(order_bytes: &str) -> Result<StandardOrder, OrderError> {
		let bytes = hex::decode(order_bytes.trim_start_matches("0x"))
			.map_err(|e| OrderError::ValidationFailed(format!("Invalid hex: {}", e)))?;

		// Decode using alloy's ABI decoder
		StandardOrder::abi_decode_validate(&bytes).map_err(|e| {
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

	/// Generates a transaction to prepare an order for filling (if needed).
	///
	/// For off-chain orders, this calls `openFor()` to create the order on-chain.
	/// On-chain orders don't require preparation and return `None`.
	///
	/// # Arguments
	///
	/// * `source` - The original intent source (used to check if off-chain)
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
		source: &str,
		order: &Order,
		_params: &ExecutionParams,
	) -> Result<Option<Transaction>, OrderError> {
		// Only off-chain orders need preparation
		if source != "off-chain" {
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
		let sponsor_address = hex_to_alloy_address(sponsor)
			.map_err(|e| OrderError::ValidationFailed(format!("Invalid sponsor address: {}", e)))?;

		// Decode the raw order bytes into StandardOrder struct
		let order_struct = Self::decode_standard_order(raw_order_data)?;

		let signature_bytes = hex::decode(signature.trim_start_matches("0x"))
			.map_err(|e| OrderError::ValidationFailed(format!("Invalid signature: {}", e)))?;

		let open_for_data = IInputSettlerEscrow::openForCall {
			order: order_struct,
			sponsor: sponsor_address,
			signature: signature_bytes.into(),
		}
		.abi_encode();

		let input_chain = order
			.input_chains
			.first()
			.ok_or_else(|| OrderError::ValidationFailed("No input chains in order".into()))?;

		Ok(Some(Transaction {
			to: Some(input_chain.settler_address.clone()),
			data: open_for_data,
			value: U256::ZERO,
			chain_id: input_chain.chain_id,
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

		// Get the output settler address from the order
		let dest_chain_id = output.chain_id.to::<u64>();
		let output_chain = order
			.output_chains
			.iter()
			.find(|c| c.chain_id == dest_chain_id)
			.ok_or_else(|| {
				OrderError::ValidationFailed(format!(
					"Chain ID {} not found in order output chains",
					dest_chain_id
				))
			})?;
		let output_settler_address = output_chain.settler_address.clone();

		// Create the SolMandateOutput struct for the fill call
		let output_struct = SolMandateOutput {
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
			callbackData: vec![].into(),
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
		let user_address = hex_to_alloy_address(&order_data.user)
			.map_err(|e| OrderError::ValidationFailed(format!("Invalid user address: {}", e)))?;

		// Parse oracle address
		let oracle_address = hex_to_alloy_address(&fill_proof.oracle_address)
			.map_err(|e| OrderError::ValidationFailed(format!("Invalid oracle address: {}", e)))?;

		// Create inputs array from order data
		let inputs: Vec<[U256; 2]> = order_data.inputs.clone();

		// Create outputs array (SolMandateOutput structs)
		let outputs: Vec<SolMandateOutput> = order_data
			.outputs
			.iter()
			.map(|output| -> Result<SolMandateOutput, OrderError> {
				// Use the oracle value from the original order
				let oracle_bytes32 = FixedBytes::<32>::from(output.oracle);

				let settler_bytes32 = {
					let mut bytes32 = [0u8; 32];
					let output_chain_id = output.chain_id.to::<u64>();

					// Get settler address from the order
					let settler_address = if output.chain_id == order_data.origin_chain_id {
						// Use input settler for origin chain
						order
							.input_chains
							.first()
							.map(|c| &c.settler_address)
							.ok_or_else(|| {
								OrderError::ValidationFailed("No input chains in order".to_string())
							})?
					} else {
						// Use output settler for the specific output chain
						order
							.output_chains
							.iter()
							.find(|c| c.chain_id == output_chain_id)
							.map(|c| &c.settler_address)
							.ok_or_else(|| {
								OrderError::ValidationFailed(format!(
									"Chain ID {} not found in order output chains",
									output_chain_id
								))
							})?
					};

					bytes32[12..32].copy_from_slice(&settler_address.0);
					FixedBytes::<32>::from(bytes32)
				};

				let token_bytes32 = FixedBytes::<32>::from(output.token);

				let recipient_bytes32 = FixedBytes::<32>::from(output.recipient);

				Ok(SolMandateOutput {
					oracle: oracle_bytes32,
					settler: settler_bytes32,
					chainId: output.chain_id,
					token: token_bytes32,
					amount: output.amount,
					recipient: recipient_bytes32,
					callbackData: vec![].into(),
					context: vec![].into(),
				})
			})
			.collect::<Result<Vec<_>, _>>()?;

		// Build the order struct
		let order_struct = StandardOrder {
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

		// Get the input chain info directly from the order
		let input_chain = order
			.input_chains
			.first()
			.ok_or_else(|| OrderError::ValidationFailed("No input chains in order".into()))?;

		Ok(Transaction {
			to: Some(input_chain.settler_address.clone()),
			data: call_data,
			value: U256::ZERO,
			chain_id: input_chain.chain_id,
			nonce: None,
			gas_limit: order_data.gas_limit_overrides.settle_gas_limit,
			gas_price: None,
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
		})
	}

	/// Validates EIP-7683 order bytes by decoding to StandardOrder and validating.
	async fn validate_order(&self, order_bytes: &Bytes) -> Result<StandardOrder, OrderError> {
		// Decode using the StandardOrder from types module
		let standard_order = StandardOrder::abi_decode_validate(order_bytes).map_err(|e| {
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

		// Validate oracle routes
		let origin_chain = standard_order.originChainId.to::<u64>();
		let input_oracle = standard_order.inputOracle;
		let input_oracle_address = input_oracle.into();

		let input_info = solver_types::oracle::OracleInfo {
			chain_id: origin_chain,
			oracle: input_oracle_address,
		};

		// Get supported output oracles for this input oracle
		let supported_outputs = self
			.oracle_routes
			.supported_routes
			.get(&input_info)
			.ok_or_else(|| {
				OrderError::ValidationFailed(format!(
					"Input oracle {:?} on chain {} is not supported",
					input_oracle, origin_chain
				))
			})?;

		// Build a set of supported destinations for efficient lookups
		let supported_destinations: std::collections::HashSet<u64> =
			supported_outputs.iter().map(|info| info.chain_id).collect();

		// Single pass validation for all outputs
		for output in &standard_order.outputs {
			let dest_chain = output.chainId.to::<u64>();

			// Skip same-chain outputs as they don't need cross-chain routes
			if dest_chain == origin_chain {
				continue;
			}

			// First check if destination chain is supported at all
			if !supported_destinations.contains(&dest_chain) {
				return Err(OrderError::ValidationFailed(format!(
					"Route from chain {} to chain {} is not supported (oracle {:?} has no route to destination)",
					origin_chain, dest_chain, input_oracle
				)));
			}

			// If a specific output oracle is specified, validate it
			if output.oracle != [0u8; 32] {
				// Check if this specific output oracle is compatible with input oracle
				// Use address normalization to compare regardless of padding format
				let mut found_compatible = false;
				for supported in supported_outputs.iter() {
					if supported.chain_id == dest_chain {
						let addresses_match = solver_types::utils::conversion::addresses_equal(
							&supported.oracle.0,
							output.oracle.as_slice(),
						);
						if addresses_match {
							found_compatible = true;
							break;
						}
					}
				}
				let is_compatible = found_compatible;

				if !is_compatible {
					return Err(OrderError::ValidationFailed(format!(
						"Output oracle {:?} on chain {} is not compatible with input oracle {:?} on chain {}",
						output.oracle, dest_chain, input_oracle, origin_chain
					)));
				}
			}
		}

		// Return the decoded StandardOrder directly since it's already the right type
		Ok(standard_order)
	}

	/// Validates order bytes and creates a generic Order with computed order ID.
	///
	/// This override ensures the standard name is correctly set to "eip7683".
	async fn validate_and_create_order(
		&self,
		order_bytes: &Bytes,
		intent_data: &Option<serde_json::Value>,
		lock_type: &str,
		order_id_callback: solver_types::OrderIdCallback,
		solver_address: &Address,
		quote_id: Option<String>,
	) -> Result<Order, OrderError> {
		// First validate the order
		let standard_order = self.validate_order(order_bytes).await?;

		// Extract chain info from the order
		let origin_chain_id = standard_order.originChainId.to::<u64>();

		// Parse lock type
		let lock_type = lock_type
			.parse::<LockType>()
			.map_err(|e| OrderError::ValidationFailed(format!("Invalid lock type: {}", e)))?;

		// Get settler address and build calldata
		let settler_address = self
			.get_settler_address(origin_chain_id, lock_type)
			.map_err(|e| {
				OrderError::ValidationFailed(format!("Failed to get settler address: {}", e))
			})?;

		let calldata = self.build_order_id_call(order_bytes, lock_type)?;

		// Build tx_data as [settler_address][calldata]
		let mut tx_data = Vec::with_capacity(20 + calldata.len());
		tx_data.extend_from_slice(&settler_address.0);
		tx_data.extend_from_slice(&calldata);

		let order_id_bytes = order_id_callback(origin_chain_id, tx_data)
			.await
			.map_err(|e| {
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

		let input_chains = vec![solver_types::order::ChainSettlerInfo {
			chain_id: origin_chain_id,
			settler_address,
		}];

		// Build output chains with settler addresses
		let mut output_chains = Vec::new();
		for output in &standard_order.outputs {
			let output_chain_id = output.chainId.to::<u64>();
			let output_network = self.networks.get(&output_chain_id).ok_or_else(|| {
				OrderError::ValidationFailed(format!("Chain {} not configured", output_chain_id))
			})?;

			output_chains.push(solver_types::order::ChainSettlerInfo {
				chain_id: output_chain_id,
				settler_address: output_network.output_settler_address.clone(),
			});
		}

		// Try to use existing Eip7683OrderData from intent_data if available,
		// otherwise create from StandardOrder
		use std::convert::TryFrom;
		let mut order_data = match intent_data {
			Some(data) => {
				// Try to parse the intent data as Eip7683OrderData
				match Eip7683OrderData::try_from(data) {
					Ok(parsed_data) => {
						// Successfully parsed - use the existing data (preserves sponsor/signature)
						parsed_data
					},
					Err(_) => {
						// Failed to parse - create fresh from StandardOrder
						Eip7683OrderData::from(standard_order.clone())
					},
				}
			},
			None => {
				// No intent data provided - create fresh from StandardOrder
				Eip7683OrderData::from(standard_order.clone())
			},
		};

		order_data.order_id = order_id_array;
		order_data.lock_type = Some(lock_type);
		order_data.raw_order_data = Some(alloy_primitives::hex::encode_prefixed(order_bytes));

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
			quote_id,
			input_chains,
			output_chains,
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
		Address, ExecutionParams, FillProof, Intent, NetworksConfig, TransactionHash,
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

	// Helper function to create a valid StandardOrder for testing
	fn create_valid_standard_order() -> interfaces::StandardOrder {
		use alloy_primitives::{Address as AlloyAddress, B256};
		use solver_types::current_timestamp;

		let current_time = current_timestamp() as u32;
		interfaces::StandardOrder {
			user: AlloyAddress::from([0x11; 20]),
			nonce: U256::from(123),
			originChainId: U256::from(1),
			expires: current_time + 3600,                // 1 hour from now
			fillDeadline: current_time + 1800,           // 30 minutes from now
			inputOracle: AlloyAddress::from([10u8; 20]), // Matches test oracle routes
			inputs: vec![[U256::from(100), U256::from(200)]],
			outputs: vec![interfaces::SolMandateOutput {
				oracle: B256::from([11u8; 32]), // Matches test oracle routes
				settler: B256::from([0x44; 32]),
				chainId: U256::from(137), // Cross-chain output
				token: B256::from([0x55; 32]),
				amount: U256::from(1000),
				recipient: B256::from([0x66; 32]),
				callbackData: vec![].into(),
				context: vec![].into(),
			}],
		}
	}

	// Helper function to encode StandardOrder to bytes
	fn encode_standard_order(order: &interfaces::StandardOrder) -> Bytes {
		use alloy_sol_types::SolValue;
		Bytes::from(order.abi_encode())
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
			.generate_prepare_transaction(&intent.source, &order, &params)
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
				callbackData: vec![].into(),
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
			.generate_prepare_transaction(&intent.source, &order, &params)
			.await;
		assert!(result.is_ok());

		let tx = result.unwrap().unwrap();
		assert_eq!(tx.chain_id, 1);
		assert_eq!(tx.to, Some(Address(vec![0x11; 20])));
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
		assert_eq!(tx.to, Some(Address(vec![0x22; 20])));
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
		assert_eq!(tx.to, Some(Address(vec![0x11; 20])));
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
		assert_eq!(tx.to, Some(Address(vec![0x11; 20])));
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

	#[tokio::test]
	async fn test_validate_order_success() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		let standard_order = create_valid_standard_order();
		let order_bytes = encode_standard_order(&standard_order);

		let result = order_impl.validate_order(&order_bytes).await;
		assert!(result.is_ok());

		let validated_order = result.unwrap();
		assert_eq!(validated_order.user, standard_order.user);
		assert_eq!(validated_order.nonce, standard_order.nonce);
		assert_eq!(validated_order.originChainId, standard_order.originChainId);
	}

	#[tokio::test]
	async fn test_validate_order_invalid_bytes() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		// Invalid bytes that cannot be decoded
		let invalid_bytes = Bytes::from(vec![0x00, 0x01, 0x02]);

		let result = order_impl.validate_order(&invalid_bytes).await;
		assert!(result.is_err());
		assert!(result
			.unwrap_err()
			.to_string()
			.contains("Failed to decode StandardOrder"));
	}

	#[tokio::test]
	async fn test_validate_order_expired() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		let mut standard_order = create_valid_standard_order();
		// Set expiry to past timestamp
		standard_order.expires = (solver_types::current_timestamp() as u32) - 3600; // 1 hour ago
		let order_bytes = encode_standard_order(&standard_order);

		let result = order_impl.validate_order(&order_bytes).await;
		assert!(result.is_err());
		assert!(result
			.unwrap_err()
			.to_string()
			.contains("Order has expired"));
	}

	#[tokio::test]
	async fn test_validate_order_fill_deadline_passed() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		let mut standard_order = create_valid_standard_order();
		// Set fill deadline to past timestamp
		standard_order.fillDeadline = (solver_types::current_timestamp() as u32) - 1800; // 30 minutes ago
		let order_bytes = encode_standard_order(&standard_order);

		let result = order_impl.validate_order(&order_bytes).await;
		assert!(result.is_err());
		assert!(result
			.unwrap_err()
			.to_string()
			.contains("Order fill deadline has passed"));
	}

	#[tokio::test]
	async fn test_validate_order_unsupported_input_oracle() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		let mut standard_order = create_valid_standard_order();
		// Use unsupported input oracle
		standard_order.inputOracle = alloy_primitives::Address::from([0x99; 20]);
		let order_bytes = encode_standard_order(&standard_order);

		let result = order_impl.validate_order(&order_bytes).await;
		assert!(result.is_err());
		let error_msg = result.unwrap_err().to_string();
		assert!(error_msg.contains("Input oracle"));
		assert!(error_msg.contains("is not supported"));
	}

	#[tokio::test]
	async fn test_validate_order_unsupported_destination_chain() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		let mut standard_order = create_valid_standard_order();
		// Use unsupported destination chain
		standard_order.outputs[0].chainId = U256::from(999); // Unsupported chain
		let order_bytes = encode_standard_order(&standard_order);

		let result = order_impl.validate_order(&order_bytes).await;
		assert!(result.is_err());
		assert!(result
			.unwrap_err()
			.to_string()
			.contains("Route from chain 1 to chain 999 is not supported"));
	}

	#[tokio::test]
	async fn test_validate_order_incompatible_output_oracle() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		let mut standard_order = create_valid_standard_order();
		// Use incompatible output oracle (different from what's supported)
		standard_order.outputs[0].oracle = alloy_primitives::B256::from([0x99; 32]);
		let order_bytes = encode_standard_order(&standard_order);

		let result = order_impl.validate_order(&order_bytes).await;
		assert!(result.is_err());
		let error_msg = result.unwrap_err().to_string();
		assert!(error_msg.contains("Output oracle"));
		assert!(error_msg.contains("is not compatible with input oracle"));
	}

	#[tokio::test]
	async fn test_validate_order_zero_output_oracle_allowed() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		let mut standard_order = create_valid_standard_order();
		// Use zero oracle (should be allowed - means any compatible oracle can be used)
		standard_order.outputs[0].oracle = alloy_primitives::B256::from([0x00; 32]);
		let order_bytes = encode_standard_order(&standard_order);

		let result = order_impl.validate_order(&order_bytes).await;
		assert!(result.is_ok());
	}

	#[tokio::test]
	async fn test_validate_order_multiple_outputs_mixed_validity() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		let mut standard_order = create_valid_standard_order();
		// Add a second output with unsupported chain
		standard_order.outputs.push(interfaces::SolMandateOutput {
			oracle: alloy_primitives::B256::from([11u8; 32]),
			settler: alloy_primitives::B256::from([0x44; 32]),
			chainId: U256::from(999), // Unsupported chain
			token: alloy_primitives::B256::from([0x55; 32]),
			amount: U256::from(500),
			recipient: alloy_primitives::B256::from([0x77; 32]),
			callbackData: vec![].into(),
			context: vec![].into(),
		});
		let order_bytes = encode_standard_order(&standard_order);

		let result = order_impl.validate_order(&order_bytes).await;
		assert!(result.is_err());
		assert!(result
			.unwrap_err()
			.to_string()
			.contains("Route from chain 1 to chain 999 is not supported"));
	}

	// Helper function to create a mock order ID callback
	fn mock_order_id_callback(
		_chain_id: u64,
		_tx_data: Vec<u8>,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send>> {
		Box::pin(async move {
			Ok(vec![0x42; 32]) // Return a fixed 32-byte order ID
		})
	}

	#[tokio::test]
	async fn test_validate_and_create_order_success() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		let standard_order = create_valid_standard_order();
		let order_bytes = encode_standard_order(&standard_order);
		let solver_address = Address(vec![0x99; 20]);
		let quote_id = Some("test-quote-123".to_string());

		let result = order_impl
			.validate_and_create_order(
				&order_bytes,
				&None,
				"permit2_escrow",
				Box::new(mock_order_id_callback),
				&solver_address,
				quote_id.clone(),
			)
			.await;

		assert!(result.is_ok());
		let order = result.unwrap();

		// Verify order properties
		assert_eq!(order.standard, "eip7683");
		assert_eq!(order.solver_address, solver_address);
		assert_eq!(order.quote_id, quote_id);
		assert_eq!(order.status, OrderStatus::Pending);
		assert_eq!(order.input_chains.len(), 1);
		assert_eq!(order.input_chains[0].chain_id, 1);
		assert_eq!(order.output_chains.len(), 1);
		assert_eq!(order.output_chains[0].chain_id, 137);

		// Verify order data
		let order_data: Eip7683OrderData = serde_json::from_value(order.data).unwrap();
		assert_eq!(order_data.lock_type, Some(LockType::Permit2Escrow));
		assert!(order_data.raw_order_data.is_some());
		assert_eq!(order_data.order_id, [0x42; 32]);
	}

	#[tokio::test]
	async fn test_validate_and_create_order_with_resource_lock() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		let standard_order = create_valid_standard_order();
		let order_bytes = encode_standard_order(&standard_order);
		let solver_address = Address(vec![0x99; 20]);

		let result = order_impl
			.validate_and_create_order(
				&order_bytes,
				&None,
				"resource_lock",
				Box::new(mock_order_id_callback),
				&solver_address,
				None,
			)
			.await;

		assert!(result.is_ok());
		let order = result.unwrap();

		let order_data: Eip7683OrderData = serde_json::from_value(order.data).unwrap();
		assert_eq!(order_data.lock_type, Some(LockType::ResourceLock));
	}

	#[tokio::test]
	async fn test_validate_and_create_order_with_existing_intent_data() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		let standard_order = create_valid_standard_order();
		let order_bytes = encode_standard_order(&standard_order);
		let solver_address = Address(vec![0x99; 20]);

		// Create intent data with sponsor and signature
		let mut existing_order_data = Eip7683OrderData::from(standard_order.clone());
		existing_order_data.sponsor =
			Some("0x1111111111111111111111111111111111111111".to_string());
		existing_order_data.signature = Some("0x123456789abcdef".to_string());
		let intent_data = Some(serde_json::to_value(&existing_order_data).unwrap());

		let result = order_impl
			.validate_and_create_order(
				&order_bytes,
				&intent_data,
				"permit2_escrow",
				Box::new(mock_order_id_callback),
				&solver_address,
				None,
			)
			.await;

		assert!(result.is_ok());
		let order = result.unwrap();

		let order_data: Eip7683OrderData = serde_json::from_value(order.data).unwrap();
		assert_eq!(
			order_data.sponsor,
			Some("0x1111111111111111111111111111111111111111".to_string())
		);
		assert_eq!(order_data.signature, Some("0x123456789abcdef".to_string()));
	}

	#[tokio::test]
	async fn test_validate_and_create_order_invalid_order_bytes() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		// Invalid bytes that cannot be decoded
		let invalid_bytes = Bytes::from(vec![0x00, 0x01, 0x02]);
		let solver_address = Address(vec![0x99; 20]);

		let result = order_impl
			.validate_and_create_order(
				&invalid_bytes,
				&None,
				"permit2_escrow",
				Box::new(mock_order_id_callback),
				&solver_address,
				None,
			)
			.await;

		assert!(result.is_err());
		assert!(result
			.unwrap_err()
			.to_string()
			.contains("Failed to decode StandardOrder"));
	}

	#[tokio::test]
	async fn test_validate_and_create_order_expired_order() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		let mut standard_order = create_valid_standard_order();
		// Set expiry to past timestamp
		standard_order.expires = (solver_types::current_timestamp() as u32) - 3600; // 1 hour ago
		let order_bytes = encode_standard_order(&standard_order);
		let solver_address = Address(vec![0x99; 20]);

		let result = order_impl
			.validate_and_create_order(
				&order_bytes,
				&None,
				"permit2_escrow",
				Box::new(mock_order_id_callback),
				&solver_address,
				None,
			)
			.await;

		assert!(result.is_err());
		assert!(result
			.unwrap_err()
			.to_string()
			.contains("Order has expired"));
	}

	#[tokio::test]
	async fn test_validate_and_create_order_invalid_lock_type() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		let standard_order = create_valid_standard_order();
		let order_bytes = encode_standard_order(&standard_order);
		let solver_address = Address(vec![0x99; 20]);

		let result = order_impl
			.validate_and_create_order(
				&order_bytes,
				&None,
				"invalid_lock_type",
				Box::new(mock_order_id_callback),
				&solver_address,
				None,
			)
			.await;

		assert!(result.is_err());
		assert!(result
			.unwrap_err()
			.to_string()
			.contains("Invalid lock type"));
	}

	#[tokio::test]
	async fn test_validate_and_create_order_unsupported_chain() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		let mut standard_order = create_valid_standard_order();
		// Use unsupported origin chain
		standard_order.originChainId = U256::from(999);
		let order_bytes = encode_standard_order(&standard_order);
		let solver_address = Address(vec![0x99; 20]);

		let result = order_impl
			.validate_and_create_order(
				&order_bytes,
				&None,
				"permit2_escrow",
				Box::new(mock_order_id_callback),
				&solver_address,
				None,
			)
			.await;
		assert!(result.is_err());
		let error_msg = result.unwrap_err().to_string();
		assert!(error_msg.contains("Input oracle"));
		assert!(error_msg.contains("is not supported"));
	}

	#[tokio::test]
	async fn test_validate_and_create_order_order_id_callback_failure() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		let standard_order = create_valid_standard_order();
		let order_bytes = encode_standard_order(&standard_order);
		let solver_address = Address(vec![0x99; 20]);

		// Mock callback that fails
		let failing_callback = |_chain_id: u64, _tx_data: Vec<u8>| {
			Box::pin(async move { Err("Order ID computation failed".to_string()) })
				as std::pin::Pin<
					Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send>,
				>
		};

		let result = order_impl
			.validate_and_create_order(
				&order_bytes,
				&None,
				"permit2_escrow",
				Box::new(failing_callback),
				&solver_address,
				None,
			)
			.await;

		assert!(result.is_err());
		assert!(result
			.unwrap_err()
			.to_string()
			.contains("Failed to compute order ID"));
	}

	#[tokio::test]
	async fn test_validate_and_create_order_invalid_order_id_length() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		let standard_order = create_valid_standard_order();
		let order_bytes = encode_standard_order(&standard_order);
		let solver_address = Address(vec![0x99; 20]);

		// Mock callback that returns wrong length
		let invalid_length_callback = |_chain_id: u64, _tx_data: Vec<u8>| {
			Box::pin(async move {
				Ok(vec![0x42u8; 16]) // Wrong length (16 instead of 32)
			})
				as std::pin::Pin<
					Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send>,
				>
		};

		let result = order_impl
			.validate_and_create_order(
				&order_bytes,
				&None,
				"permit2_escrow",
				Box::new(invalid_length_callback),
				&solver_address,
				None,
			)
			.await;

		assert!(result.is_err());
		assert!(result
			.unwrap_err()
			.to_string()
			.contains("Invalid order ID length: expected 32 bytes, got 16"));
	}

	#[tokio::test]
	async fn test_validate_and_create_order_with_malformed_intent_data() {
		let networks = create_test_networks();
		let oracle_routes = create_test_oracle_routes();
		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		let standard_order = create_valid_standard_order();
		let order_bytes = encode_standard_order(&standard_order);
		let solver_address = Address(vec![0x99; 20]);

		// Create malformed intent data that can't be parsed as Eip7683OrderData
		let malformed_intent_data = Some(serde_json::json!({
			"invalid_field": "invalid_value"
		}));

		let result = order_impl
			.validate_and_create_order(
				&order_bytes,
				&malformed_intent_data,
				"permit2_escrow",
				Box::new(mock_order_id_callback),
				&solver_address,
				None,
			)
			.await;

		// Should succeed by falling back to creating fresh order data from StandardOrder
		assert!(result.is_ok());
		let order = result.unwrap();

		let order_data: Eip7683OrderData = serde_json::from_value(order.data).unwrap();
		// Should have fresh data without sponsor/signature
		assert!(order_data.sponsor.is_none());
		assert!(order_data.signature.is_none());
	}

	#[tokio::test]
	async fn test_validate_and_create_order_multiple_outputs() {
		// Create networks with an additional chain (42161 for Arbitrum)
		let networks = NetworksConfigBuilder::new()
        .add_network(1, NetworkConfigBuilder::new().build())
        .add_network(137, NetworkConfigBuilder::new().build())
        .add_network(42161, NetworkConfigBuilder::new().build()) // Add Arbitrum
        .build();

		// Create oracle routes that support the additional chain
		let mut supported_routes = HashMap::new();
		let input_oracle = OracleInfo {
			chain_id: 1,
			oracle: Address(vec![10u8; 20]),
		};
		let output_oracle_polygon = OracleInfo {
			chain_id: 137,
			oracle: Address(vec![11u8; 20]),
		};
		let output_oracle_arbitrum = OracleInfo {
			chain_id: 42161,
			oracle: Address(vec![12u8; 20]), // Different oracle for Arbitrum
		};
		supported_routes.insert(
			input_oracle,
			vec![output_oracle_polygon, output_oracle_arbitrum],
		);
		let oracle_routes = OracleRoutes { supported_routes };

		let order_impl = Eip7683OrderImpl::new(networks, oracle_routes).unwrap();

		let mut standard_order = create_valid_standard_order();
		// Add a second output on a different destination chain (Arbitrum)
		standard_order.outputs.push(interfaces::SolMandateOutput {
			oracle: alloy_primitives::B256::from([12u8; 32]), // Different oracle for Arbitrum
			settler: alloy_primitives::B256::from([0x44; 32]),
			chainId: U256::from(42161), // Arbitrum chain ID (different from first output)
			token: alloy_primitives::B256::from([0x77; 32]),
			amount: U256::from(500),
			recipient: alloy_primitives::B256::from([0x88; 32]),
			callbackData: vec![].into(),
			context: vec![].into(),
		});
		let order_bytes = encode_standard_order(&standard_order);
		let solver_address = Address(vec![0x99; 20]);

		let result = order_impl
			.validate_and_create_order(
				&order_bytes,
				&None,
				"permit2_escrow",
				Box::new(mock_order_id_callback),
				&solver_address,
				None,
			)
			.await;

		assert!(result.is_ok());
		let order = result.unwrap();

		// Should have two output chains (137 and 42161) with multiple outputs
		assert_eq!(order.output_chains.len(), 2);
		let chain_ids: Vec<u64> = order.output_chains.iter().map(|oc| oc.chain_id).collect();
		assert!(chain_ids.contains(&137));
		assert!(chain_ids.contains(&42161));

		let order_data: Eip7683OrderData = serde_json::from_value(order.data).unwrap();
		assert_eq!(order_data.outputs.len(), 2);
	}
}
