//! Quote generation engine for cross-chain intent execution.
//!
//! This module orchestrates the creation of executable quotes for cross-chain token transfers.
//! It combines custody decisions, settlement mechanisms, and signature requirements to produce
//! complete quote objects that users can sign and submit for execution.
//!
//! ## Overview
//!
//! The quote generator:
//! - Analyzes available inputs and requested outputs
//! - Determines optimal custody and settlement strategies
//! - Generates appropriate signature payloads
//! - Calculates execution timelines and expiry
//! - Produces multiple quote options when available
//!
//! ## Quote Structure
//!
//! Each generated quote contains:
//! - **Orders**: Signature requirements (EIP-712, EIP-3009, etc.)
//! - **Details**: Input/output specifications
//! - **Validity**: Expiry times and execution windows
//! - **ETA**: Estimated completion time based on chain characteristics
//! - **Provider**: Solver identification
//!
//! ## Generation Process
//!
//! 1. **Input Analysis**: Evaluate each available input for capabilities
//! 2. **Custody Decision**: Determine optimal token custody mechanism
//! 3. **Order Creation**: Generate appropriate signature payloads
//! 4. **Quote Assembly**: Combine all components into executable quotes
//! 5. **Preference Sorting**: Order quotes based on user preferences
//!
//! ## Supported Order Types
//!
//! ### Resource Locks
//! - TheCompact orders with allocation proofs
//! - Custom protocol-specific lock orders
//!
//! ### Escrow Orders
//! - Permit2 batch witness transfers
//! - EIP-3009 authorization transfers
//!
//! ## Optimization Strategies
//!
//! The generator optimizes for:
//! - **Speed**: Minimal execution time across chains
//! - **Cost**: Lowest gas fees and protocol costs
//! - **Trust**: Minimal trust assumptions
//! - **Input Priority**: Preference for specific input tokens

use super::custody::{CustodyDecision, CustodyStrategy};
use crate::eip712::{compact, get_domain_separator};
use alloy_primitives::U256;
use solver_config::{Config, QuoteConfig};
use solver_delivery::DeliveryService;
use solver_settlement::{SettlementInterface, SettlementService};
use solver_types::standards::eip7683::LockType;
use solver_types::{
	with_0x_prefix, CostContext, FailureHandlingMode, GetQuoteRequest, InteropAddress, OifOrder,
	OrderInput, OrderPayload, Quote, QuoteError, QuotePreference, SignatureType, SwapType,
	ValidatedQuoteContext,
};
use std::sync::Arc;
use uuid::Uuid;

/// Quote generation engine with settlement service integration.
pub struct QuoteGenerator {
	custody_strategy: CustodyStrategy,
	/// Reference to settlement service for implementation lookup.
	settlement_service: Arc<SettlementService>,
	/// Reference to delivery service for contract calls.
	delivery_service: Arc<DeliveryService>,
}

impl QuoteGenerator {
	/// Creates a new quote generator.
	///
	/// # Arguments
	/// * `settlement_service` - Service managing settlement implementations
	/// * `delivery_service` - Service for making contract calls
	pub fn new(
		settlement_service: Arc<SettlementService>,
		delivery_service: Arc<DeliveryService>,
	) -> Self {
		Self {
			custody_strategy: CustodyStrategy::new(),
			settlement_service,
			delivery_service,
		}
	}

	pub async fn generate_quotes(
		&self,
		request: &GetQuoteRequest,
		config: &Config,
	) -> Result<Vec<Quote>, QuoteError> {
		let mut quotes = Vec::new();
		for input in &request.intent.inputs {
			let order_input: OrderInput = input.try_into()?;
			let custody_decision = self
				.custody_strategy
				.decide_custody(&order_input, request.intent.origin_submission.as_ref())
				.await?;
			if let Ok(quote) = self
				.generate_quote_for_settlement(request, config, &custody_decision)
				.await
			{
				quotes.push(quote);
			}
		}
		if quotes.is_empty() {
			return Err(QuoteError::InsufficientLiquidity);
		}
		self.sort_quotes_by_preference(&mut quotes, &request.intent.preference);
		Ok(quotes)
	}

	/// Generate quotes with costs already embedded in the amounts.
	pub async fn generate_quotes_with_costs(
		&self,
		request: &GetQuoteRequest,
		context: &ValidatedQuoteContext,
		cost_context: &CostContext,
		config: &Config,
	) -> Result<Vec<Quote>, QuoteError> {
		// Build a new request with swap amounts and cost adjustments from CostContext
		let adjusted_request = self.build_cost_adjusted_request(request, context, cost_context)?;

		// Validate no zero amounts after adjustment
		self.validate_no_zero_amounts(&adjusted_request, context)?;

		// Validate constraints on the adjusted amounts
		self.validate_swap_amount_constraints(&adjusted_request, context)?;

		// Generate quotes using the adjusted request
		let quotes = self.generate_quotes(&adjusted_request, config).await?;

		Ok(quotes)
	}

	/// Build a new request with swap amounts and cost adjustments based on swap type
	fn build_cost_adjusted_request(
		&self,
		request: &GetQuoteRequest,
		context: &ValidatedQuoteContext,
		cost_context: &CostContext,
	) -> Result<GetQuoteRequest, QuoteError> {
		let mut adjusted = request.clone();

		match context.swap_type {
			SwapType::ExactInput => {
				// For ExactInput: Use swap amounts for outputs, then subtract costs
				// Input amounts are already known from the request

				// Determine first output asset before the loop to avoid borrow issues
				let first_output_asset = adjusted.intent.outputs.first().map(|o| o.asset.clone());

				for output in adjusted.intent.outputs.iter_mut() {
					// First set the base swap amount from our calculation
					if let Some(base_amount) = cost_context.swap_amounts.get(&output.asset) {
						// Get cost for this specific token
						let cost_in_token = cost_context
							.cost_amounts_in_tokens
							.get(&output.asset)
							.copied()
							.unwrap_or(U256::ZERO);

						// Apply full cost to first output, others get their base amount
						let is_first_output = first_output_asset
							.as_ref()
							.map(|first| first == &output.asset)
							.unwrap_or(false);

						let adjusted_amount = if is_first_output {
							// First output bears the full cost
							base_amount.saturating_sub(cost_in_token)
						} else {
							// Other outputs get their base amount
							*base_amount
						};

						output.amount = Some(adjusted_amount.to_string());
					}
				}
			},
			SwapType::ExactOutput => {
				// For ExactOutput: Use swap amounts for inputs, then add costs
				// Output amounts are already known from the request

				// Determine first input asset before the loop to avoid borrow issues
				let first_input_asset = adjusted.intent.inputs.first().map(|i| i.asset.clone());

				for input in adjusted.intent.inputs.iter_mut() {
					// First set the base swap amount from our calculation
					if let Some(base_amount) = cost_context.swap_amounts.get(&input.asset) {
						// Get cost for this specific token
						let cost_in_token = cost_context
							.cost_amounts_in_tokens
							.get(&input.asset)
							.copied()
							.unwrap_or(U256::ZERO);

						// Apply full cost to first input, others get their base amount
						let is_first_input = first_input_asset
							.as_ref()
							.map(|first| first == &input.asset)
							.unwrap_or(false);

						let adjusted_amount = if is_first_input {
							// First input bears the full cost
							base_amount + cost_in_token
						} else {
							// Other inputs get their base amount
							*base_amount
						};

						input.amount = Some(adjusted_amount.to_string());
					}
				}
			},
		}

		Ok(adjusted)
	}

	/// Validate that adjusted amounts meet the constraints
	fn validate_swap_amount_constraints(
		&self,
		adjusted_request: &GetQuoteRequest,
		context: &ValidatedQuoteContext,
	) -> Result<(), QuoteError> {
		use alloy_primitives::U256;
		use std::str::FromStr;

		match context.swap_type {
			SwapType::ExactInput => {
				// For exact-input: check that output amounts meet minimums
				if let Some(constraints) = &context.constraint_outputs {
					for (output, constraint_amount_opt) in constraints {
						if let Some(constraint_amount) = constraint_amount_opt {
							// Find the adjusted output amount
							let adjusted_output = adjusted_request
								.intent
								.outputs
								.iter()
								.find(|o| o.asset == output.asset)
								.and_then(|o| o.amount.as_ref())
								.and_then(|amt| U256::from_str(amt).ok())
								.unwrap_or(U256::ZERO);

							if adjusted_output < *constraint_amount {
								return Err(QuoteError::InvalidRequest(format!(
									"Output amount for {} ({}) below minimum required ({})",
									output.asset, adjusted_output, constraint_amount
								)));
							}
						}
					}
				}
			},
			SwapType::ExactOutput => {
				// For exact-output: check that input amounts don't exceed maximums
				// When a user provides input constraints for exact-output swaps,
				// they're specifying the maximum they're willing to provide
				if let Some(constraints) = &context.constraint_inputs {
					for (input, constraint_amount_opt) in constraints {
						if let Some(constraint_amount) = constraint_amount_opt {
							// Find the adjusted input amount
							let adjusted_input = adjusted_request
								.intent
								.inputs
								.iter()
								.find(|i| i.asset == input.asset)
								.and_then(|i| i.amount.as_ref())
								.and_then(|amt| U256::from_str(amt).ok())
								.unwrap_or(U256::ZERO);

							if adjusted_input > *constraint_amount {
								return Err(QuoteError::InvalidRequest(format!(
									"Input amount for {} ({}) exceeds maximum allowed ({})",
									input.asset, adjusted_input, constraint_amount
								)));
							}
						}
					}
				}
			},
		}

		Ok(())
	}

	/// Validate that no amounts are zero after adjustment
	fn validate_no_zero_amounts(
		&self,
		adjusted_request: &GetQuoteRequest,
		context: &ValidatedQuoteContext,
	) -> Result<(), QuoteError> {
		use alloy_primitives::U256;
		use std::str::FromStr;

		match context.swap_type {
			SwapType::ExactInput => {
				// For exact-input, check that all outputs are non-zero
				for output in &adjusted_request.intent.outputs {
					let amount = output
						.amount
						.as_ref()
						.and_then(|amt| U256::from_str(amt).ok())
						.unwrap_or(U256::ZERO);

					if amount.is_zero() {
						return Err(QuoteError::InvalidRequest(format!(
							"Output amount for {} cannot be zero after cost adjustment",
							output.asset
						)));
					}
				}
			},
			SwapType::ExactOutput => {
				// For exact-output, check that all inputs are non-zero
				for input in &adjusted_request.intent.inputs {
					let amount = input
						.amount
						.as_ref()
						.and_then(|amt| U256::from_str(amt).ok())
						.unwrap_or(U256::ZERO);

					if amount.is_zero() {
						return Err(QuoteError::InvalidRequest(format!(
							"Input amount for {} cannot be zero after cost adjustment",
							input.asset
						)));
					}
				}
			},
		}

		Ok(())
	}

	async fn generate_quote_for_settlement(
		&self,
		request: &GetQuoteRequest,
		config: &Config,
		custody_decision: &CustodyDecision,
	) -> Result<Quote, QuoteError> {
		let quote_id = Uuid::new_v4().to_string();
		let order = match custody_decision {
			CustodyDecision::ResourceLock { lock } => {
				self.generate_resource_lock_order(request, config, lock)
					.await?
			},
			CustodyDecision::Escrow { lock_type } => {
				self.generate_escrow_order(request, config, lock_type)
					.await?
			},
		};

		let eta = self.calculate_eta(&request.intent.preference);
		let validity_seconds = self.get_quote_validity_seconds(config);

		// Get failure handling from request or use default
		let failure_handling = request
			.intent
			.failure_handling
			.as_ref()
			.and_then(|modes| modes.first())
			.cloned()
			.unwrap_or(FailureHandlingMode::RefundAutomatic);

		// Get partial fill preference from request or default to false
		let partial_fill = request.intent.partial_fill.unwrap_or(false);

		Ok(Quote {
			order,
			failure_handling,
			partial_fill,
			valid_until: chrono::Utc::now().timestamp() as u64 + validity_seconds,
			eta: Some(eta),
			quote_id,
			provider: Some("oif-solver".to_string()),
		})
	}

	async fn generate_resource_lock_order(
		&self,
		request: &GetQuoteRequest,
		config: &Config,
		lock: &solver_types::AssetLockReference,
	) -> Result<OifOrder, QuoteError> {
		use solver_types::LockKind;

		let domain_address = self.get_lock_domain_address(config, lock)?;
		let default_params = serde_json::json!({});
		let params = lock.params.as_ref().unwrap_or(&default_params);
		let (primary_type, message) = match &lock.kind {
			LockKind::TheCompact => Ok((
				"BatchCompact".to_string(),
				self.build_compact_message(request, config, params).await?,
			)),
			LockKind::Rhinestone => Ok((
				"RhinestoneLock".to_string(),
				self.build_rhinestone_message(request, config, params)
					.await?,
			)),
		}?;

		// Create OifOrder based on lock kind
		let order = match &lock.kind {
			LockKind::TheCompact => {
				// Build structured domain object for TheCompact (similar to Permit2)
				let input_chain_id =
					request.intent.inputs[0]
						.asset
						.ethereum_chain_id()
						.map_err(|e| {
							QuoteError::InvalidRequest(format!(
								"Invalid chain ID in asset address: {}",
								e
							))
						})?;
				let domain_object = self
					.build_compact_domain_object(config, input_chain_id)
					.await?;

				OifOrder::OifResourceLockV0 {
					payload: OrderPayload {
						signature_type: SignatureType::Eip712,
						domain: serde_json::to_value(domain_object)
							.unwrap_or(serde_json::Value::Null),
						primary_type,
						message,
						types: Some(self.build_compact_eip712_types()),
					},
				}
			},
			_ => {
				OifOrder::OifResourceLockV0 {
					payload: OrderPayload {
						signature_type: SignatureType::Eip712,
						domain: serde_json::to_value(domain_address)
							.unwrap_or(serde_json::Value::Null),
						primary_type,
						message,
						types: None, // Other resource locks don't need EIP-712 types yet
					},
				}
			},
		};

		Ok(order)
	}

	async fn generate_escrow_order(
		&self,
		request: &GetQuoteRequest,
		config: &Config,
		lock_type: &LockType,
	) -> Result<OifOrder, QuoteError> {
		// Extract chain from first output to find appropriate settlement
		// TODO: Implement support for multiple destination chains
		let chain_id = request
			.intent
			.outputs
			.first()
			.ok_or_else(|| QuoteError::InvalidRequest("No requested outputs".to_string()))?
			.asset
			.ethereum_chain_id()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid chain ID: {}", e)))?;

		// For escrow orders, prefer Direct settlement over other implementations
		let (settlement, selected_oracle) = self
			.get_preferred_settlement_for_escrow(chain_id)
			.ok_or_else(|| {
				QuoteError::InvalidRequest(format!(
					"No suitable settlement available for escrow on chain {}",
					chain_id
				))
			})?;

		match lock_type {
			LockType::Permit2Escrow => {
				self.generate_permit2_order(request, config, settlement, selected_oracle)
					.await
			},
			LockType::Eip3009Escrow => {
				self.generate_eip3009_order(request, config, settlement, selected_oracle)
					.await
			},
			_ => Err(QuoteError::UnsupportedSettlement(format!(
				"Unsupported escrow type: {:?}",
				lock_type
			))),
		}
	}

	async fn generate_permit2_order(
		&self,
		request: &GetQuoteRequest,
		config: &Config,
		settlement: &dyn SettlementInterface,
		selected_oracle: solver_types::Address,
	) -> Result<OifOrder, QuoteError> {
		let chain_id = request.intent.inputs[0]
			.asset
			.ethereum_chain_id()
			.map_err(|e| {
				QuoteError::InvalidRequest(format!("Invalid chain ID in asset address: {}", e))
			})?;

		// Build structured domain object for Permit2
		let domain_object = self.build_permit2_domain_object(config, chain_id).await?;

		// Generate the message object without pre-computed digest
		let message_obj =
			self.build_permit2_message_object(request, config, settlement, selected_oracle)?;

		let order = OifOrder::OifEscrowV0 {
			payload: OrderPayload {
				signature_type: SignatureType::Eip712,
				domain: serde_json::to_value(domain_object).unwrap_or(serde_json::Value::Null),
				primary_type: "PermitBatchWitnessTransferFrom".to_string(),
				message: message_obj,
				types: Some(self.build_permit2_eip712_types()),
			},
		};

		Ok(order)
	}

	async fn generate_eip3009_order(
		&self,
		request: &GetQuoteRequest,
		config: &Config,
		_settlement: &dyn SettlementInterface,
		selected_oracle: solver_types::Address,
	) -> Result<OifOrder, QuoteError> {
		// Use minValidUntil from request if provided, otherwise use configured validity
		let intent_validity_seconds = request
			.intent
			.min_valid_until
			.unwrap_or_else(|| self.get_quote_validity_seconds(config));

		// Get input chain to find the input settler address (the 'to' field)
		let first_input = &request.intent.inputs[0];
		let input_chain_id = first_input
			.asset
			.ethereum_chain_id()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid input chain ID: {}", e)))?;
		let network = config.networks.get(&input_chain_id).ok_or_else(|| {
			QuoteError::InvalidRequest(format!("Network {} not found in config", input_chain_id))
		})?;
		let input_settler = network.input_settler_address.clone();
		let input_settler_address = format!(
			"0x{:040x}",
			alloy_primitives::Address::from_slice(&input_settler.0)
		);
		let output_settler = network.output_settler_address.clone();

		// Calculate fillDeadline (should match fillDeadline in StandardOrder)
		let fill_deadline = chrono::Utc::now().timestamp() as u32 + intent_validity_seconds as u32;

		// Calculate the correct orderIdentifier using the contract (same method as intents script)
		let (nonce_u64, order_identifier) = self.compute_eip3009_order_identifier(
			request,
			config,
			&selected_oracle,
			fill_deadline,
		)?;

		// Get token address for domain information
		let token_address = first_input
			.asset
			.ethereum_address()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid token address: {}", e)))?;

		// Build structured domain object for EIP-3009 token
		let domain_object = self
			.build_eip3009_domain_object(&token_address, input_chain_id)
			.await?;

		// For EIP-3009, we need to generate signature templates for each input
		// since the contract expects one signature per input
		let mut signatures_array = Vec::new();
		for input in &request.intent.inputs {
			let input_message = serde_json::json!({
				"from": input.user.ethereum_address().map_err(|e| QuoteError::InvalidRequest(format!("Invalid Ethereum address: {}", e)))?,
				"to": input_settler_address,
				"value": input.amount,
				"validAfter": 0,
				"validBefore": fill_deadline,
				"nonce": order_identifier,  // Use order_identifier for signature
				"realNonce": format!("0x{:x}", nonce_u64),  // Include real nonce for StandardOrder
				"inputOracle": format!("0x{:040x}", alloy_primitives::Address::from_slice(&selected_oracle.0))
			});
			signatures_array.push(input_message);
		}

		let message = if signatures_array.len() == 1 {
			// Single input - return the message directly
			signatures_array.into_iter().next().unwrap()
		} else {
			// Multiple inputs - return array of messages for multiple signatures
			serde_json::json!({
				"signatures": signatures_array
			})
		};

		// Build metadata with full intent information AND StandardOrder reconstruction data
		// This is needed for conversion back to StandardOrder from limited EIP-3009 signature
		let metadata = serde_json::json!({
			"user": request.user.to_string(),
			"nonce": nonce_u64,
			"originChainId": input_chain_id,
			"expires": fill_deadline, // Use fillDeadline for both expires and fillDeadline
			"fillDeadline": fill_deadline,
			"inputOracle": format!("0x{:040x}", alloy_primitives::Address::from_slice(&selected_oracle.0)),
			"inputs": request.intent.inputs.iter().map(|input| {
				serde_json::json!({
					"chainId": input.asset.ethereum_chain_id().unwrap_or(1),
					"asset": input.asset.to_string(),
					// TODO: Handle swap-type properly - for now use "0" if amount is None
					"amount": input.amount.as_ref().unwrap_or(&"0".to_string()).clone(),
					"user": input.user.to_string()
				})
			}).collect::<Vec<_>>(),
			"outputs": request.intent.outputs.iter().map(|output| {
				serde_json::json!({
					"chainId": output.asset.ethereum_chain_id().unwrap_or(1),
					"asset": output.asset.to_string(),
					// TODO: Handle swap-type properly - for now use "0" if amount is None
					"amount": output.amount.as_ref().unwrap_or(&"0".to_string()).clone(),
					"receiver": output.receiver.to_string(),
					"oracle": format!("0x{:040x}", alloy_primitives::Address::from_slice(&selected_oracle.0)),
					"settler": format!("0x{:040x}", alloy_primitives::Address::from_slice(&output_settler.0)),
				})
			}).collect::<Vec<_>>()
		});

		let order = OifOrder::Oif3009V0 {
			payload: OrderPayload {
				signature_type: SignatureType::Eip712,
				domain: serde_json::to_value(domain_object).unwrap_or(serde_json::Value::Null),
				primary_type: "ReceiveWithAuthorization".to_string(),
				message,
				types: Some(self.build_eip3009_eip712_types()),
			},
			metadata,
		};

		Ok(order)
	}

	/// Compute the orderIdentifier for an EIP-3009 order by building a StandardOrder
	/// and calling the contract's orderIdentifier function - same as the intents script
	/// Returns (nonce, order_identifier)
	fn compute_eip3009_order_identifier(
		&self,
		request: &GetQuoteRequest,
		config: &Config,
		selected_oracle: &solver_types::Address,
		fill_deadline: u32,
	) -> Result<(u64, String), QuoteError> {
		let input = &request.intent.inputs[0];

		// Get input chain info
		let input_chain_id = input
			.asset
			.ethereum_chain_id()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid input chain ID: {}", e)))?;
		let input_network = config.networks.get(&input_chain_id).ok_or_else(|| {
			QuoteError::InvalidRequest(format!("Network {} not found", input_chain_id))
		})?;

		// Note: We don't need output network info for orderIdentifier calculation

		// Build StandardOrder struct (same approach as intents script)
		let user_addr = input
			.user
			.ethereum_address()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid user address: {}", e)))?;
		// Generate incremental nonce like direct intent (current timestamp in microseconds)
		let nonce = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_micros() as u64)
			.unwrap_or(0u64);
		let expiry = fill_deadline; // Use same value
		let input_oracle = format!(
			"0x{:040x}",
			alloy_primitives::Address::from_slice(&selected_oracle.0)
		);

		// Build input tokens array: [[token, amount]]
		let input_token = input
			.asset
			.ethereum_address()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid input token: {}", e)))?;
		// Input amount should be set after cost adjustment
		let input_amount = input
			.amount
			.as_ref()
			.ok_or_else(|| {
				QuoteError::InvalidRequest("Input amount not set after cost adjustment".to_string())
			})?
			.clone();

		// TODO: All this needs to all be removed!

		// Use std::process::Command to call cast (same as scripts)
		let rpc_url = if input_chain_id == 31337 {
			"http://localhost:8545"
		} else {
			"http://localhost:8546"
		};

		let input_settler_address = format!(
			"0x{:040x}",
			alloy_primitives::Address::from_slice(&input_network.input_settler_address.0)
		);

		// Get output information for the outputs array (same as direct intent)
		let output_info =
			request.intent.outputs.first().ok_or_else(|| {
				QuoteError::InvalidRequest("No requested outputs found".to_string())
			})?;

		// Extract output chain and token from InteropAddress
		let output_interop = output_info.asset.clone();
		let output_chain_id = output_interop
			.ethereum_chain_id()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid output chain ID: {}", e)))?;
		let output_token = output_interop
			.ethereum_address()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid output token: {}", e)))?;
		// Output amount should be set after cost adjustment
		let output_amount = output_info
			.amount
			.as_ref()
			.ok_or_else(|| {
				QuoteError::InvalidRequest(
					"Output amount not set after cost adjustment".to_string(),
				)
			})?
			.clone();

		// Extract recipient from InteropAddress
		let recipient_interop = output_info.receiver.clone();
		let recipient_addr = recipient_interop
			.ethereum_address()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid recipient address: {}", e)))?;

		// Get output settler from config (same as direct intent)
		let output_network = config.networks.get(&output_chain_id).ok_or_else(|| {
			QuoteError::InvalidRequest(format!(
				"Output network {} not found in config",
				output_chain_id
			))
		})?;
		let output_settler = output_network.output_settler_address.clone();
		let output_settler_address = alloy_primitives::Address::from_slice(&output_settler.0);

		// Build outputs array (same format as direct intent)
		let zero_bytes32 = "0x0000000000000000000000000000000000000000000000000000000000000000";
		let output_settler_bytes32 =
			format!("0x000000000000000000000000{:040x}", output_settler_address);
		let output_token_bytes32 = format!("0x000000000000000000000000{:040x}", output_token);
		let recipient_bytes32 = format!("0x000000000000000000000000{:040x}", recipient_addr);

		let outputs_array = format!(
			"[({},{},{},{},{},{},0x,0x)]",
			zero_bytes32,
			output_settler_bytes32,
			output_chain_id,
			output_token_bytes32,
			output_amount,
			recipient_bytes32
		);

		// Build the order struct string (same format as intents script with real outputs)
		let order_struct = format!(
			"({},{},{},{},{},{},[[{},{}]],{})",
			user_addr,      // user
			nonce,          // nonce (microseconds)
			input_chain_id, // originChainId
			expiry,         // expires
			fill_deadline,  // fillDeadline
			input_oracle,   // inputOracle
			input_token,    // input token
			input_amount,   // input amount
			outputs_array   // outputs (with real data)
		);

		// Call contract orderIdentifier function (same as intents script)
		let order_identifier_sig = "orderIdentifier((address,uint256,uint256,uint32,uint32,address,uint256[2][],(bytes32,bytes32,uint256,bytes32,uint256,bytes32,bytes,bytes)[]))";

		// Execute cast call in a clean environment without RUST_LOG to avoid contamination
		let output = std::process::Command::new("cast")
			.arg("call")
			.arg(&input_settler_address)
			.arg(order_identifier_sig)
			.arg(&order_struct)
			.arg("--rpc-url")
			.arg(rpc_url)
			.env_remove("RUST_LOG")  // Explicitly remove RUST_LOG for this process
			.output()
			.map_err(|e| QuoteError::InvalidRequest(format!("Failed to call cast: {}", e)))?;

		if !output.status.success() {
			let stderr = String::from_utf8_lossy(&output.stderr);
			return Err(QuoteError::InvalidRequest(format!(
				"Cast call failed: {}",
				stderr
			)));
		}

		let raw_output = String::from_utf8_lossy(&output.stdout);

		// Extract only the 64-character hex string (order ID), filtering out any debug logs
		let order_id = raw_output
			.lines()
			.find_map(|line| {
				// Look for a line that contains a 66-character hex string (0x + 64 hex chars)
				if let Some(start) = line.find("0x") {
					let hex_part = &line[start..];
					if hex_part.len() >= 66 {
						let candidate = &hex_part[..66];
						// Validate it's actually a hex string
						if candidate.chars().skip(2).all(|c| c.is_ascii_hexdigit()) {
							return Some(candidate.to_string());
						}
					}
				}
				None
			})
			.unwrap_or_else(|| raw_output.trim().to_string());

		if order_id.is_empty()
			|| order_id == "0x0000000000000000000000000000000000000000000000000000000000000000"
		{
			tracing::warn!(
				"Failed to extract valid order ID from cast output: {}",
				raw_output
			);
			return Err(QuoteError::InvalidRequest(
				"Failed to compute order ID from contract".to_string(),
			));
		}

		tracing::debug!("Successfully extracted clean order ID: {}", order_id);

		Ok((nonce, order_id))
	}

	async fn build_compact_message(
		&self,
		request: &GetQuoteRequest,
		config: &Config,
		_params: &serde_json::Value,
	) -> Result<serde_json::Value, QuoteError> {
		use alloy_primitives::{hex, U256};
		use solver_types::utils::bytes20_to_alloy_address;
		use std::str::FromStr;

		// Use minValidUntil from request if provided, otherwise use configured validity
		let intent_validity_seconds = request
			.intent
			.min_valid_until
			.unwrap_or_else(|| self.get_quote_validity_seconds(config));
		let current_time = chrono::Utc::now().timestamp() as u64;
		let expires = current_time + intent_validity_seconds;
		let nonce = chrono::Utc::now().timestamp_millis() as u64; // Use milliseconds timestamp as nonce for uniqueness (matching direct intent flow)

		// Get user address
		let user_address = request
			.user
			.ethereum_address()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid user address: {}", e)))?;

		// Get TheCompact domain address (arbiter)
		let the_compact_lock = solver_types::AssetLockReference {
			kind: solver_types::LockKind::TheCompact,
			params: Some(serde_json::json!({})),
		};
		let domain_address = self.get_lock_domain_address(config, &the_compact_lock)?;
		let _arbiter_address = domain_address
			.ethereum_address()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid domain address: {}", e)))?;

		// Get input chain ID from first available input
		let first_input = request
			.intent
			.inputs
			.first()
			.ok_or_else(|| QuoteError::InvalidRequest("No available inputs".to_string()))?;
		let input_chain_id = first_input
			.asset
			.ethereum_chain_id()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid input chain ID: {}", e)))?;

		// Get addresses from network configuration
		let network = config.networks.get(&input_chain_id).ok_or_else(|| {
			QuoteError::InvalidRequest(format!("Network {} not found in config", input_chain_id))
		})?;

		// Get preferred settlement for TheCompact (prioritizes Direct settlement like escrow)
		let (_input_settlement, input_selected_oracle) = self
			.get_preferred_settlement_for_escrow(input_chain_id)
			.ok_or_else(|| {
				QuoteError::InvalidRequest(format!(
					"No suitable settlement available for TheCompact on chain {}",
					input_chain_id
				))
			})?;

		// Convert inputs to the format expected by TheCompact
		// For ResourceLock orders, we need to build the proper token IDs and amounts
		let mut inputs_array = Vec::new();
		for input in &request.intent.inputs {
			let token_address = input.asset.ethereum_address().map_err(|e| {
				QuoteError::InvalidRequest(format!("Invalid input token address: {}", e))
			})?;

			// Generate allocator lock tag from address (0x00 + last 11 bytes of address)
			// If allocator address is not configured, fall back to zeroed tag for tests/back-compat
			let allocator_tag = if let Some(allocator_address) = network.allocator_address.as_ref()
			{
				let address_hex = hex::encode(&allocator_address.0);
				format!("0x00{}", &address_hex[address_hex.len() - 22..])
			} else {
				// 12 bytes zero value prefixed with 0x
				"0x000000000000000000000000".to_string()
			};

			// Build token ID by concatenating allocator tag (12 bytes) + token address (20 bytes)
			let token_address_hex = hex::encode(token_address.0);
			let token_id_hex = format!("{}{}", allocator_tag, token_address_hex);
			let token_id = U256::from_str(&token_id_hex).map_err(|e| {
				QuoteError::InvalidRequest(format!("Failed to create token ID: {}", e))
			})?;

			let amount = input.amount.as_ref().ok_or_else(|| {
				QuoteError::InvalidRequest("Input amount not set after cost adjustment".to_string())
			})?;
			inputs_array.push(serde_json::json!([token_id.to_string(), amount.clone(),]));
		}

		// Convert outputs to MandateOutput format
		let mut outputs_array = Vec::new();
		for output in &request.intent.outputs {
			let output_token_address = output.asset.ethereum_address().map_err(|e| {
				QuoteError::InvalidRequest(format!("Invalid output token address: {}", e))
			})?;
			let recipient_address = output.receiver.ethereum_address().map_err(|e| {
				QuoteError::InvalidRequest(format!("Invalid recipient address: {}", e))
			})?;
			let output_chain_id = output.asset.ethereum_chain_id().map_err(|e| {
				QuoteError::InvalidRequest(format!("Invalid output chain ID: {}", e))
			})?;

			// Get preferred settlement for the output chain (prioritizes Direct settlement like escrow)
			let (_output_settlement, output_selected_oracle) = self
				.get_preferred_settlement_for_escrow(output_chain_id)
				.ok_or_else(|| {
					QuoteError::InvalidRequest(format!(
						"No suitable settlement available for output chain {}",
						output_chain_id
					))
				})?;

			// Get output settler from config (like permit2 flow)
			let dest_net = config.networks.get(&output_chain_id).ok_or_else(|| {
				QuoteError::InvalidRequest(format!(
					"Destination chain {} missing from networks config",
					output_chain_id
				))
			})?;
			let output_settler = bytes20_to_alloy_address(&dest_net.output_settler_address.0)
				.map_err(QuoteError::InvalidRequest)?;

			// Convert oracle address (like permit2 flow)
			let output_oracle =
				bytes20_to_alloy_address(&output_selected_oracle.0).map_err(|e| {
					QuoteError::InvalidRequest(format!("Invalid output oracle address: {}", e))
				})?;

			// Build MandateOutput with proper oracle and settler addresses
			let amount = output.amount.as_ref().ok_or_else(|| {
				QuoteError::InvalidRequest(
					"Output amount not set after cost adjustment".to_string(),
				)
			})?;
			outputs_array.push(serde_json::json!({
				"oracle": format!("0x000000000000000000000000{:040x}", output_oracle),
				"settler": format!("0x000000000000000000000000{:040x}", output_settler),
				"chainId": output_chain_id.to_string(),
				"token": format!("0x000000000000000000000000{:040x}", output_token_address),
				"amount": amount.clone(),
				"recipient": format!("0x000000000000000000000000{:040x}", recipient_address),
				"call": output.calldata.clone(),
				"context": "0x" // Context is typically empty for standard flows
			}));
		}

		// Use the selected oracle for input chain as the inputOracle (like permit2 flow)
		let input_oracle = bytes20_to_alloy_address(&input_selected_oracle.0).map_err(|e| {
			QuoteError::InvalidRequest(format!("Invalid input oracle address: {}", e))
		})?;

		// Build the EIP-712 message structure (like permit2 flow)
		// The scripts will compute the digest from this data
		let eip712_message = serde_json::json!({
			"types": {
				"EIP712Domain": [
					{"name": "name", "type": "string"},
					{"name": "version", "type": "string"},
					{"name": "chainId", "type": "uint256"},
					{"name": "verifyingContract", "type": "address"}
				],
				"BatchCompact": [
					{"name": "arbiter", "type": "address"},
					{"name": "sponsor", "type": "address"},
					{"name": "nonce", "type": "uint256"},
					{"name": "expires", "type": "uint256"},
					{"name": "commitments", "type": "Lock[]"},
					{"name": "mandate", "type": "Mandate"}
				],
				"Lock": [
					{"name": "lockTag", "type": "bytes12"},
					{"name": "token", "type": "address"},
					{"name": "amount", "type": "uint256"}
				],
				"Mandate": [
					{"name": "fillDeadline", "type": "uint32"},
					{"name": "inputOracle", "type": "address"},
					{"name": "outputs", "type": "MandateOutput[]"}
				],
				"MandateOutput": [
					{"name": "oracle", "type": "bytes32"},
					{"name": "settler", "type": "bytes32"},
					{"name": "chainId", "type": "uint256"},
					{"name": "token", "type": "bytes32"},
					{"name": "amount", "type": "uint256"},
					{"name": "recipient", "type": "bytes32"},
					{"name": "call", "type": "bytes"},
					{"name": "context", "type": "bytes"}
				]
			},
			"domain": {
				"name": "TheCompact",
				"version": "1",
				"chainId": input_chain_id.to_string(),
				"verifyingContract": format!("0x{:040x}", alloy_primitives::Address::from_slice(&network.the_compact_address.as_ref().unwrap().0))
			},
			"primaryType": "BatchCompact",
			"message": {
				"arbiter": format!("0x{:040x}", alloy_primitives::Address::from_slice(&network.input_settler_compact_address.as_ref().unwrap_or(&network.input_settler_address).0)),
				"sponsor": format!("0x{:040x}", user_address),
				"nonce": nonce.to_string(),
				"expires": expires.to_string(),
				"commitments": inputs_array.iter().map(|input| {
					let input_array = input.as_array().unwrap();
					let token_id_str = input_array[0].as_str().unwrap();
					let amount_str = input_array[1].as_str().unwrap();

					// Extract allocator tag (first 12 bytes) and token address (last 20 bytes) from token ID
					let token_id = U256::from_str(token_id_str).unwrap();
					let token_id_bytes = token_id.to_be_bytes::<32>();
					let lock_tag_hex = format!("0x{}", hex::encode(&token_id_bytes[0..12]));
					let token_addr_hex = format!("0x{}", hex::encode(&token_id_bytes[12..32]));

					serde_json::json!({
						"lockTag": lock_tag_hex,
						"token": token_addr_hex,
						"amount": amount_str
					})
				}).collect::<Vec<_>>(),
				"mandate": {
					"fillDeadline": (current_time + intent_validity_seconds).to_string(),
					"inputOracle": format!("0x{:040x}", input_oracle),
					"outputs": outputs_array
				}
			}
		});

		// Extract just the message part for the new flat structure
		// The domain and types are now handled at the OrderPayload level
		let message_part = eip712_message
			.get("message")
			.cloned()
			.unwrap_or(serde_json::Value::Null);

		// Return only the message part (flat structure like Permit2)
		Ok(message_part)
	}

	async fn build_rhinestone_message(
		&self,
		_request: &GetQuoteRequest,
		_config: &Config,
		_params: &serde_json::Value,
	) -> Result<serde_json::Value, QuoteError> {
		Err(QuoteError::UnsupportedSettlement(
			"Rhinestone resource locks are not yet supported".to_string(),
		))
	}

	/// Build structured domain object for EIP-3009 token
	async fn build_eip3009_domain_object(
		&self,
		token_address: &[u8; 20],
		chain_id: u64,
	) -> Result<serde_json::Value, QuoteError> {
		let alloy_token_address = alloy_primitives::Address::from_slice(token_address);

		// Try to get token name
		let token_name = self
			.get_token_name(&alloy_token_address, chain_id)
			.await
			.unwrap_or_else(|_| "Unknown Token".to_string());

		// Build domain object similar to TheCompact structure (without pre-computed domainSeparator)
		// The client will compute the domainSeparator using these fields
		Ok(serde_json::json!({
			"name": token_name,
			"chainId": chain_id.to_string(),
			"verifyingContract": format!("0x{:040x}", alloy_token_address)
		}))
	}

	/// Get token name from contract
	async fn get_token_name(
		&self,
		token_address: &alloy_primitives::Address,
		chain_id: u64,
	) -> Result<String, QuoteError> {
		use alloy_sol_types::{sol, SolCall};

		// Define the name() function call
		sol! {
			function name() external view returns (string);
		}

		let call = nameCall {};
		let encoded = call.abi_encode();

		let tx = solver_types::Transaction {
			to: Some(solver_types::Address(token_address.0.to_vec())),
			data: encoded,
			value: alloy_primitives::U256::ZERO,
			chain_id,
			nonce: None,
			gas_limit: None,
			gas_price: None,
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
		};

		let result = self
			.delivery_service
			.contract_call(chain_id, tx)
			.await
			.map_err(|e| QuoteError::InvalidRequest(format!("Failed to get token name: {}", e)))?;

		let name = nameCall::abi_decode_returns(&result, false)
			.map_err(|e| QuoteError::InvalidRequest(format!("Failed to decode token name: {}", e)))?
			._0;

		Ok(name)
	}

	/// Get preferred settlement for escrow orders (prioritizes Direct settlement)
	fn get_preferred_settlement_for_escrow(
		&self,
		chain_id: u64,
	) -> Option<(&dyn SettlementInterface, solver_types::Address)> {
		// First, try to get Direct settlement specifically
		if let Some(direct_settlement) = self.settlement_service.get("direct") {
			if let Some(oracles) = direct_settlement
				.oracle_config()
				.input_oracles
				.get(&chain_id)
			{
				if !oracles.is_empty() {
					let selected_oracle = direct_settlement.select_oracle(oracles, None)?;
					return Some((direct_settlement, selected_oracle));
				}
			}
		}

		// Fallback to any available settlement if Direct is not available
		self.settlement_service
			.get_any_settlement_for_chain(chain_id)
	}

	/// Build structured domain object for Permit2
	async fn build_permit2_domain_object(
		&self,
		_config: &Config,
		chain_id: u64,
	) -> Result<serde_json::Value, QuoteError> {
		use crate::apis::quote::registry::PROTOCOL_REGISTRY;

		// Get Permit2 contract address for this chain
		let permit2_address = PROTOCOL_REGISTRY
			.get_permit2_address(chain_id)
			.ok_or_else(|| {
				QuoteError::InvalidRequest(format!("Permit2 not deployed on chain {}", chain_id))
			})?;

		// Get the actual name from Permit2 contract (like we do for EIP-3009 tokens)
		let permit2_name = self
			.get_token_name(&permit2_address, chain_id)
			.await
			.unwrap_or_else(|_| "Permit2".to_string()); // Fallback to constant if contract call fails

		// Build domain object similar to TheCompact and EIP-3009 structure
		Ok(serde_json::json!({
			"name": permit2_name,
			"chainId": chain_id.to_string(),
			"verifyingContract": format!("0x{:040x}", permit2_address)
		}))
	}

	/// Build Permit2 message object
	fn build_permit2_message_object(
		&self,
		request: &GetQuoteRequest,
		config: &Config,
		settlement: &dyn SettlementInterface,
		selected_oracle: solver_types::Address,
	) -> Result<serde_json::Value, QuoteError> {
		use crate::apis::quote::permit2::build_permit2_batch_witness_digest;

		// Generate the complete message structure
		let (_final_digest, message_obj) =
			build_permit2_batch_witness_digest(request, config, settlement, selected_oracle)?;

		// Extract only the EIP-712 message fields (no metadata like "signing", "digest")
		let permitted = message_obj
			.get("permitted")
			.cloned()
			.unwrap_or(serde_json::Value::Null);
		let spender = message_obj
			.get("spender")
			.cloned()
			.unwrap_or(serde_json::Value::Null);
		let nonce = message_obj
			.get("nonce")
			.cloned()
			.unwrap_or(serde_json::Value::Null);
		let deadline = message_obj
			.get("deadline")
			.cloned()
			.unwrap_or(serde_json::Value::Null);
		let witness = message_obj
			.get("witness")
			.cloned()
			.unwrap_or(serde_json::Value::Null);

		// Return clean message with only EIP-712 fields (no wrapper)
		Ok(serde_json::json!({
			"permitted": permitted,
			"spender": spender,
			"nonce": nonce,
			"deadline": deadline,
			"witness": witness
		}))
	}

	/// Try to compute the digest using the existing eip712/compact module
	async fn try_compute_server_digest(
		&self,
		eip712_message: &serde_json::Value,
		_request: &GetQuoteRequest,
		network: &solver_types::NetworkConfig,
		input_chain_id: u64,
	) -> Result<[u8; 32], QuoteError> {
		use alloy_primitives::{keccak256, Address as AlloyAddress, FixedBytes, Uint};
		use alloy_sol_types::SolType;
		use solver_types::standards::eip7683::interfaces::StandardOrder as OifStandardOrder;
		use std::str::FromStr;

		// Build a StandardOrder from the EIP-712 message to use with the compact module
		let message = eip712_message.get("message").ok_or_else(|| {
			QuoteError::InvalidRequest("Missing message in EIP-712 structure".to_string())
		})?;

		// Extract basic fields
		let sponsor_str = message
			.get("sponsor")
			.and_then(|v| v.as_str())
			.ok_or_else(|| QuoteError::InvalidRequest("Missing sponsor in message".to_string()))?;
		let sponsor = AlloyAddress::from_str(&sponsor_str[2..])
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid sponsor address: {}", e)))?;

		let nonce_str = message
			.get("nonce")
			.and_then(|v| v.as_str())
			.ok_or_else(|| QuoteError::InvalidRequest("Missing nonce in message".to_string()))?;
		let nonce = Uint::<256, 4>::from_str(nonce_str)
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid nonce: {}", e)))?;

		let expires_str = message
			.get("expires")
			.and_then(|v| v.as_str())
			.ok_or_else(|| QuoteError::InvalidRequest("Missing expires in message".to_string()))?;
		let expires = u32::from_str(expires_str)
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid expires: {}", e)))?;

		// Extract mandate fields
		let mandate = message
			.get("mandate")
			.ok_or_else(|| QuoteError::InvalidRequest("Missing mandate in message".to_string()))?;
		let fill_deadline_str = mandate
			.get("fillDeadline")
			.and_then(|v| v.as_str())
			.ok_or_else(|| {
				QuoteError::InvalidRequest("Missing fillDeadline in mandate".to_string())
			})?;
		let fill_deadline = u32::from_str(fill_deadline_str)
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid fillDeadline: {}", e)))?;

		let input_oracle_str = mandate
			.get("inputOracle")
			.and_then(|v| v.as_str())
			.ok_or_else(|| {
				QuoteError::InvalidRequest("Missing inputOracle in mandate".to_string())
			})?;
		let input_oracle = AlloyAddress::from_str(&input_oracle_str[2..])
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid inputOracle: {}", e)))?;

		// Extract inputs from commitments
		let commitments = message
			.get("commitments")
			.and_then(|v| v.as_array())
			.ok_or_else(|| {
				QuoteError::InvalidRequest("Missing commitments in message".to_string())
			})?;

		let mut inputs = Vec::new();
		for commitment in commitments {
			let lock_tag_str = commitment
				.get("lockTag")
				.and_then(|v| v.as_str())
				.ok_or_else(|| {
					QuoteError::InvalidRequest("Missing lockTag in commitment".to_string())
				})?;
			let token_str = commitment
				.get("token")
				.and_then(|v| v.as_str())
				.ok_or_else(|| {
					QuoteError::InvalidRequest("Missing token in commitment".to_string())
				})?;
			let amount_str = commitment
				.get("amount")
				.and_then(|v| v.as_str())
				.ok_or_else(|| {
					QuoteError::InvalidRequest("Missing amount in commitment".to_string())
				})?;

			// Reconstruct token ID from lock_tag + token_address
			let lock_tag_bytes = alloy_primitives::hex::decode(&lock_tag_str[2..])
				.map_err(|e| QuoteError::InvalidRequest(format!("Invalid lockTag hex: {}", e)))?;
			let token_bytes = alloy_primitives::hex::decode(&token_str[2..])
				.map_err(|e| QuoteError::InvalidRequest(format!("Invalid token hex: {}", e)))?;

			// Combine lock_tag (12 bytes) + token_address (20 bytes) to form token_id (32 bytes)
			let mut token_id_bytes = [0u8; 32];
			token_id_bytes[0..12].copy_from_slice(&lock_tag_bytes);
			token_id_bytes[12..32].copy_from_slice(&token_bytes);
			let token_id = Uint::<256, 4>::from_be_bytes(token_id_bytes);

			let amount = Uint::<256, 4>::from_str(amount_str)
				.map_err(|e| QuoteError::InvalidRequest(format!("Invalid amount: {}", e)))?;

			inputs.push([token_id, amount]);
		}

		// Extract outputs
		let outputs_array = mandate
			.get("outputs")
			.and_then(|v| v.as_array())
			.ok_or_else(|| QuoteError::InvalidRequest("Missing outputs in mandate".to_string()))?;

		use solver_types::standards::eip7683::interfaces::SolMandateOutput as MandateOutput;
		let mut outputs = Vec::new();
		for output in outputs_array {
			let oracle_str = output
				.get("oracle")
				.and_then(|v| v.as_str())
				.ok_or_else(|| {
					QuoteError::InvalidRequest("Missing oracle in output".to_string())
				})?;
			let oracle = FixedBytes::<32>::from_str(oracle_str)
				.map_err(|e| QuoteError::InvalidRequest(format!("Invalid oracle: {}", e)))?;

			let settler_str = output
				.get("settler")
				.and_then(|v| v.as_str())
				.ok_or_else(|| {
					QuoteError::InvalidRequest("Missing settler in output".to_string())
				})?;
			let settler = FixedBytes::<32>::from_str(settler_str)
				.map_err(|e| QuoteError::InvalidRequest(format!("Invalid settler: {}", e)))?;

			let chain_id_str = output
				.get("chainId")
				.and_then(|v| v.as_str())
				.ok_or_else(|| {
					QuoteError::InvalidRequest("Missing chainId in output".to_string())
				})?;
			let chain_id = Uint::<256, 4>::from_str(chain_id_str)
				.map_err(|e| QuoteError::InvalidRequest(format!("Invalid chainId: {}", e)))?;

			let token_str = output
				.get("token")
				.and_then(|v| v.as_str())
				.ok_or_else(|| QuoteError::InvalidRequest("Missing token in output".to_string()))?;
			let token = FixedBytes::<32>::from_str(token_str)
				.map_err(|e| QuoteError::InvalidRequest(format!("Invalid token: {}", e)))?;

			let amount_str = output
				.get("amount")
				.and_then(|v| v.as_str())
				.ok_or_else(|| {
					QuoteError::InvalidRequest("Missing amount in output".to_string())
				})?;
			let amount = Uint::<256, 4>::from_str(amount_str)
				.map_err(|e| QuoteError::InvalidRequest(format!("Invalid amount: {}", e)))?;

			let recipient_str = output
				.get("recipient")
				.and_then(|v| v.as_str())
				.ok_or_else(|| {
					QuoteError::InvalidRequest("Missing recipient in output".to_string())
				})?;
			let recipient = FixedBytes::<32>::from_str(recipient_str)
				.map_err(|e| QuoteError::InvalidRequest(format!("Invalid recipient: {}", e)))?;

			let call_str = output.get("call").and_then(|v| v.as_str()).unwrap_or("0x");
			let call = if call_str == "0x" {
				alloy_primitives::Bytes::new()
			} else {
				alloy_primitives::Bytes::from(
					alloy_primitives::hex::decode(&call_str[2..]).map_err(|e| {
						QuoteError::InvalidRequest(format!("Invalid call data: {}", e))
					})?,
				)
			};

			let context_str = output
				.get("context")
				.and_then(|v| v.as_str())
				.unwrap_or("0x");
			let context = if context_str == "0x" {
				alloy_primitives::Bytes::new()
			} else {
				alloy_primitives::Bytes::from(
					alloy_primitives::hex::decode(&context_str[2..]).map_err(|e| {
						QuoteError::InvalidRequest(format!("Invalid context data: {}", e))
					})?,
				)
			};

			outputs.push(MandateOutput {
				oracle,
				settler,
				chainId: chain_id,
				token,
				amount,
				recipient,
				call,
				context,
			});
		}

		// Build the StandardOrder
		let standard_order = OifStandardOrder {
			user: sponsor,
			nonce,
			originChainId: Uint::<256, 4>::from(input_chain_id),
			expires,
			fillDeadline: fill_deadline,
			inputOracle: input_oracle,
			inputs,
			outputs,
		};

		// Encode the order to use with the compact module
		let order_bytes = OifStandardOrder::abi_encode(&standard_order);

		// Use the same contract address logic as the signature validator
		let contract_address = {
			let addr = network
				.input_settler_compact_address
				.clone()
				.unwrap_or_else(|| network.input_settler_address.clone());
			AlloyAddress::from_slice(&addr.0)
		};

		// Use the existing compact module to compute the message hash
		let struct_hash = compact::compute_batch_compact_hash(&order_bytes, contract_address)
			.map_err(|e| {
				QuoteError::InvalidRequest(format!("Failed to compute batch compact hash: {}", e))
			})?;

		// Get domain separator from TheCompact contract
		let the_compact_address = network.the_compact_address.as_ref().ok_or_else(|| {
			QuoteError::InvalidRequest("TheCompact address not configured".to_string())
		})?;
		let domain_separator =
			get_domain_separator(&self.delivery_service, the_compact_address, input_chain_id)
				.await
				.map_err(|e| {
					QuoteError::InvalidRequest(format!("Failed to get domain separator: {}", e))
				})?;

		// Compute final EIP-712 digest
		let digest_data = [&[0x19, 0x01][..], &domain_separator[..], &struct_hash[..]].concat();
		let final_digest = keccak256(&digest_data);

		Ok(final_digest.into())
	}

	fn get_lock_domain_address(
		&self,
		config: &Config,
		lock: &solver_types::AssetLockReference,
	) -> Result<InteropAddress, QuoteError> {
		match &config.settlement.domain {
			Some(domain_config) => {
				let address = domain_config.address.parse().map_err(|e| {
					QuoteError::InvalidRequest(format!("Invalid domain address in config: {}", e))
				})?;
				Ok(InteropAddress::new_ethereum(
					domain_config.chain_id,
					address,
				))
			},
			None => Err(QuoteError::InvalidRequest(format!(
				"Domain configuration required for lock type: {:?}",
				lock.kind
			))),
		}
	}

	fn calculate_eta(&self, preference: &Option<QuotePreference>) -> u64 {
		let base_eta = 120u64;
		match preference {
			Some(QuotePreference::Speed) => (base_eta as f64 * 0.8) as u64,
			Some(QuotePreference::Price) => (base_eta as f64 * 1.2) as u64,
			Some(QuotePreference::TrustMinimization) => (base_eta as f64 * 1.5) as u64,
			_ => base_eta,
		}
	}

	fn sort_quotes_by_preference(
		&self,
		quotes: &mut [Quote],
		preference: &Option<QuotePreference>,
	) {
		match preference {
			Some(QuotePreference::Speed) => quotes.sort_by(|a, b| match (a.eta, b.eta) {
				(Some(eta_a), Some(eta_b)) => eta_a.cmp(&eta_b),
				(Some(_), None) => std::cmp::Ordering::Less,
				(None, Some(_)) => std::cmp::Ordering::Greater,
				(None, None) => std::cmp::Ordering::Equal,
			}),
			Some(QuotePreference::InputPriority) => {},
			Some(QuotePreference::Price) | Some(QuotePreference::TrustMinimization) | None => {},
		}
	}

	/// Gets the quote validity duration from configuration.
	///
	/// Returns the configured validity seconds from api.quote config or default.
	fn get_quote_validity_seconds(&self, config: &Config) -> u64 {
		config
			.api
			.as_ref()
			.and_then(|api| api.quote.as_ref())
			.map(|quote| quote.validity_seconds)
			.unwrap_or_else(|| QuoteConfig::default().validity_seconds)
	}

	/// Generates EIP-712 types definition for Permit2 orders
	fn build_permit2_eip712_types(&self) -> serde_json::Value {
		serde_json::json!({
			"EIP712Domain": [
				{"name": "name", "type": "string"},
				{"name": "chainId", "type": "uint256"},
				{"name": "verifyingContract", "type": "address"}
			],
			"PermitBatchWitnessTransferFrom": [
				{"name": "permitted", "type": "TokenPermissions[]"},
				{"name": "spender", "type": "address"},
				{"name": "nonce", "type": "uint256"},
				{"name": "deadline", "type": "uint256"},
				{"name": "witness", "type": "Permit2Witness"}
			],
			"TokenPermissions": [
				{"name": "token", "type": "address"},
				{"name": "amount", "type": "uint256"}
			],
			"Permit2Witness": [
				{"name": "expires", "type": "uint32"},
				{"name": "inputOracle", "type": "address"},
				{"name": "outputs", "type": "MandateOutput[]"}
			],
			"MandateOutput": [
				{"name": "oracle", "type": "bytes32"},
				{"name": "settler", "type": "bytes32"},
				{"name": "chainId", "type": "uint256"},
				{"name": "token", "type": "bytes32"},
				{"name": "amount", "type": "uint256"},
				{"name": "recipient", "type": "bytes32"},
				{"name": "call", "type": "bytes"},
				{"name": "context", "type": "bytes"}
			]
		})
	}

	/// Generates EIP-712 types definition for TheCompact BatchCompact orders
	fn build_compact_eip712_types(&self) -> serde_json::Value {
		serde_json::json!({
			"EIP712Domain": [
				{"name": "name", "type": "string"},
				{"name": "version", "type": "string"},
				{"name": "chainId", "type": "uint256"},
				{"name": "verifyingContract", "type": "address"}
			],
			"BatchCompact": [
				{"name": "arbiter", "type": "address"},
				{"name": "sponsor", "type": "address"},
				{"name": "nonce", "type": "uint256"},
				{"name": "expires", "type": "uint256"},
				{"name": "commitments", "type": "Lock[]"},
				{"name": "mandate", "type": "Mandate"}
			],
			"Lock": [
				{"name": "lockTag", "type": "bytes12"},
				{"name": "token", "type": "address"},
				{"name": "amount", "type": "uint256"}
			],
			"Mandate": [
				{"name": "fillDeadline", "type": "uint32"},
				{"name": "inputOracle", "type": "address"},
				{"name": "outputs", "type": "MandateOutput[]"}
			],
			"MandateOutput": [
				{"name": "oracle", "type": "bytes32"},
				{"name": "settler", "type": "bytes32"},
				{"name": "chainId", "type": "uint256"},
				{"name": "token", "type": "bytes32"},
				{"name": "amount", "type": "uint256"},
				{"name": "recipient", "type": "bytes32"},
				{"name": "call", "type": "bytes"},
				{"name": "context", "type": "bytes"}
			]
		})
	}

	/// Generates EIP-712 types definition for EIP-3009 ReceiveWithAuthorization orders
	fn build_eip3009_eip712_types(&self) -> serde_json::Value {
		serde_json::json!({
			"EIP712Domain": [
				{"name": "name", "type": "string"},
				{"name": "chainId", "type": "uint256"},
				{"name": "verifyingContract", "type": "address"}
			],
			"ReceiveWithAuthorization": [
				{"name": "from", "type": "address"},
				{"name": "to", "type": "address"},
				{"name": "value", "type": "uint256"},
				{"name": "validAfter", "type": "uint256"},
				{"name": "validBefore", "type": "uint256"},
				{"name": "nonce", "type": "bytes32"}
			]
		})
	}

	/// Build structured domain object for TheCompact
	async fn build_compact_domain_object(
		&self,
		config: &Config,
		chain_id: u64,
	) -> Result<serde_json::Value, QuoteError> {
		// Get TheCompact contract address from network config
		let network = config.networks.get(&chain_id).ok_or_else(|| {
			QuoteError::InvalidRequest(format!("Network {} not found in config", chain_id))
		})?;

		let the_compact_address = network.the_compact_address.as_ref().ok_or_else(|| {
			QuoteError::InvalidRequest("TheCompact address not configured".to_string())
		})?;

		let contract_address = alloy_primitives::Address::from_slice(&the_compact_address.0);

		// Build domain object similar to Permit2 structure
		Ok(serde_json::json!({
			"name": "TheCompact",
			"version": "1",
			"chainId": chain_id.to_string(),
			"verifyingContract": format!("0x{:040x}", contract_address)
		}))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::apis::quote::custody::CustodyDecision;
	use alloy_primitives::address;
	use alloy_primitives::U256;
	use solver_config::{
		ApiConfig, Config, ConfigBuilder, DomainConfig, QuoteConfig, SettlementConfig,
	};
	use solver_settlement::{MockSettlementInterface, SettlementInterface};
	use solver_types::{
		oif_versions, parse_address,
		utils::tests::builders::{NetworkConfigBuilder, NetworksConfigBuilder},
		FailureHandlingMode, GetQuoteRequest, IntentRequest, IntentType, InteropAddress, OifOrder,
		OrderPayload, QuoteInput, QuoteOutput, QuotePreference, SignatureType, SwapType,
	};
	use std::collections::HashMap;

	fn create_test_config() -> Config {
		// Create API configuration with quote settings
		let api_config = ApiConfig {
			enabled: true,
			host: "127.0.0.1".to_string(),
			port: 8080,
			timeout_seconds: 30,
			max_request_size: 1048576,
			implementations: Default::default(),
			rate_limiting: None,
			cors: None,
			auth: None,
			quote: Some(QuoteConfig {
				validity_seconds: 300,
			}),
		};

		// Create settlement configuration with domain
		let settlement_config = SettlementConfig {
			implementations: HashMap::new(),
			domain: Some(DomainConfig {
				chain_id: 1,
				address: "0x1234567890123456789012345678901234567890".to_string(),
			}),
			settlement_poll_interval_seconds: 3,
		};

		// Build network configurations using builder pattern
		let networks = NetworksConfigBuilder::new()
			.add_network(1, NetworkConfigBuilder::new().build())
			.add_network(137, NetworkConfigBuilder::new().build())
			.build();

		// Create config using ConfigBuilder with complete fluent API
		ConfigBuilder::new()
			.api(Some(api_config))
			.settlement(settlement_config)
			.networks(networks)
			.build()
	}

	fn create_test_request() -> GetQuoteRequest {
		GetQuoteRequest {
			user: InteropAddress::new_ethereum(
				1,
				address!("1111111111111111111111111111111111111111"),
			),
			intent: IntentRequest {
				intent_type: IntentType::OifSwap,
				inputs: vec![QuoteInput {
					user: InteropAddress::new_ethereum(
						1,
						address!("1111111111111111111111111111111111111111"),
					),
					asset: InteropAddress::new_ethereum(
						1,
						address!("A0b86a33E6441b8C6A7f4C5C1C5C5C5C5C5C5C5C"),
					),
					amount: Some(U256::from(1000).to_string()),
					lock: None,
				}],
				outputs: vec![QuoteOutput {
					receiver: InteropAddress::new_ethereum(
						137,
						address!("2222222222222222222222222222222222222222"),
					),
					asset: InteropAddress::new_ethereum(
						137,
						address!("B0b86a33E6441b8C6A7f4C5C1C5C5C5C5C5C5C5C"),
					),
					amount: Some(U256::from(950).to_string()),
					calldata: None,
				}],
				swap_type: None,
				min_valid_until: None,
				preference: Some(QuotePreference::Speed),
				origin_submission: None,
				failure_handling: None,
				partial_fill: None,
				metadata: None,
			},
			supported_types: vec![oif_versions::escrow_order_type("v0")],
		}
	}

	fn create_test_settlement_service(with_oracles: bool) -> Arc<SettlementService> {
		use solver_types::Address;

		let mut input_oracles = HashMap::new();
		let mut output_oracles = HashMap::new();
		let mut routes = HashMap::new();

		if with_oracles {
			// Add input oracles for both chains (since get_any_settlement_for_chain looks for input oracles)
			input_oracles.insert(1, vec![Address(vec![0xaa; 20])]);
			input_oracles.insert(137, vec![Address(vec![0xcc; 20])]);
			// Add output oracles for both chains
			output_oracles.insert(1, vec![Address(vec![0xbb; 20])]);
			output_oracles.insert(137, vec![Address(vec![0xdd; 20])]);
			// Add routes between chains
			routes.insert(1, vec![137]);
			routes.insert(137, vec![1]);
		}

		let mut mock_settlement = MockSettlementInterface::new();
		mock_settlement
			.expect_oracle_config()
			.return_const(solver_settlement::OracleConfig {
				input_oracles,
				output_oracles,
				routes,
				selection_strategy: solver_settlement::OracleSelectionStrategy::First,
			});

		if with_oracles {
			// Mock the select_oracle method to return the first oracle
			mock_settlement
				.expect_select_oracle()
				.returning(|oracles, _context| oracles.first().cloned());
		}

		let mut implementations: HashMap<String, Box<dyn SettlementInterface>> = HashMap::new();
		implementations.insert("test".to_string(), Box::new(mock_settlement));

		Arc::new(SettlementService::new(implementations, 3))
	}

	#[tokio::test]
	async fn test_generate_quotes_success() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service =
			Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1, 60));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);
		let config = create_test_config();
		let request = create_test_request();

		let result = generator.generate_quotes(&request, &config).await;

		// Should succeed since we have properly configured oracles
		assert!(result.is_ok());
		let quotes = result.unwrap();
		assert!(!quotes.is_empty());

		let quote = &quotes[0];
		assert_eq!(quote.provider, Some("oif-solver".to_string()));
		assert!(quote.valid_until > 0);
		assert!(quote.eta.is_some());
		assert_eq!(quote.eta.unwrap(), 96); // Speed preference: 120 * 0.8
		assert!(!quote.quote_id.is_empty());

		// Verify quote has a single order
		match &quote.order {
			OifOrder::OifEscrowV0 { payload } => {
				assert_eq!(payload.signature_type, SignatureType::Eip712);
			},
			_ => panic!("Expected escrow order type"),
		}

		// Verify failure handling and partial fill fields
		assert_eq!(quote.failure_handling, FailureHandlingMode::RefundAutomatic);
		assert!(!quote.partial_fill);
	}

	#[tokio::test]
	async fn test_generate_quotes_no_oracles_configured() {
		let settlement_service = create_test_settlement_service(false);
		let delivery_service =
			Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1, 60));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);
		let config = create_test_config();
		let request = create_test_request();

		let result = generator.generate_quotes(&request, &config).await;

		// Should fail with insufficient liquidity since our mock settlement has no oracles configured
		assert!(matches!(result, Err(QuoteError::InsufficientLiquidity)));
	}

	#[tokio::test]
	async fn test_generate_quotes_insufficient_liquidity() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service =
			Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1, 60));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);
		let config = create_test_config();

		// Create request with no available inputs
		let request = GetQuoteRequest {
			user: InteropAddress::new_ethereum(
				1,
				address!("1111111111111111111111111111111111111111"),
			),
			intent: IntentRequest {
				intent_type: IntentType::OifSwap,
				inputs: vec![],
				outputs: vec![QuoteOutput {
					receiver: InteropAddress::new_ethereum(
						137,
						address!("2222222222222222222222222222222222222222"),
					),
					asset: InteropAddress::new_ethereum(
						137,
						address!("B0b86a33E6441b8C6A7f4C5C1C5C5C5C5C5C5C5C"),
					),
					amount: Some(U256::from(950).to_string()),
					calldata: None,
				}],
				swap_type: None,
				min_valid_until: None,
				preference: Some(QuotePreference::Speed),
				origin_submission: None,
				failure_handling: None,
				partial_fill: None,
				metadata: None,
			},
			supported_types: vec![oif_versions::escrow_order_type("v0")],
		};

		let result = generator.generate_quotes(&request, &config).await;
		assert!(matches!(result, Err(QuoteError::InsufficientLiquidity)));
	}

	#[tokio::test]
	async fn test_generate_resource_lock_order_the_compact() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service =
			Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1, 60));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);
		let config = create_test_config();
		let request = create_test_request();

		let lock = solver_types::AssetLockReference {
			kind: solver_types::LockKind::TheCompact,
			params: Some(serde_json::json!({"test": "value"})),
		};

		let result = generator
			.generate_resource_lock_order(&request, &config, &lock)
			.await;

		match result {
			Ok(order) => match order {
				OifOrder::OifResourceLockV0 { payload } => {
					assert_eq!(payload.signature_type, SignatureType::Eip712);
					assert_eq!(payload.primary_type, "CompactLock");
					assert!(payload.message.is_object());
				},
				_ => panic!("Expected OifResourceLockV0 order"),
			},
			Err(e) => {
				// Expected if domain configuration is missing
				assert!(matches!(e, QuoteError::InvalidRequest(_)));
			},
		}
	}

	#[tokio::test]
	async fn test_generate_eip3009_order() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service =
			Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1, 60));

		// Get settlement and oracle like in real usage
		let (settlement, selected_oracle) = settlement_service
			.get_any_settlement_for_chain(137)
			.expect("Should have settlement for test chain");

		let generator = QuoteGenerator::new(settlement_service.clone(), delivery_service);
		let config = create_test_config();
		let request = create_test_request();

		let result = generator
			.generate_eip3009_order(&request, &config, settlement, selected_oracle)
			.await;

		match result {
			Ok(order) => {
				match order {
					OifOrder::Oif3009V0 { payload, .. } => {
						assert_eq!(payload.signature_type, SignatureType::Eip712);
						assert_eq!(payload.primary_type, "ReceiveWithAuthorization");
						assert!(payload.message.is_object());

						// Verify domain is at the order level (new structure)
						assert!(payload.domain.is_object());
						let domain = payload.domain.as_object().unwrap();
						assert!(domain.contains_key("name"));
						assert!(domain.contains_key("chainId"));
						assert!(domain.contains_key("verifyingContract"));

						// Verify message structure (EIP-3009 fields)
						let message_obj = payload.message.as_object().unwrap();
						assert!(message_obj["from"].is_string());
						assert!(message_obj["to"].is_string());
						assert!(message_obj["value"].is_string());
						assert!(message_obj["validAfter"].is_number());
						assert!(message_obj["validBefore"].is_number());
						assert!(message_obj["nonce"].is_string());
						assert!(message_obj["inputOracle"].is_string());
					},
					_ => panic!("Expected Oif3009V0 order"),
				}
			},
			Err(e) => {
				// Expected if token contract calls fail or configuration is missing
				assert!(matches!(e, QuoteError::InvalidRequest(_)));
			},
		}
	}

	#[tokio::test]
	async fn test_build_compact_message() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service =
			Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1, 60));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);
		let request = create_test_request();
		let params = serde_json::json!({"test": "value"});
		let mut config = create_test_config();
		let bsc_network = NetworkConfigBuilder::new()
			.input_settler_address(
				parse_address("0x5555555555555555555555555555555555555555").unwrap(),
			)
			.output_settler_address(
				parse_address("0x6666666666666666666666666666666666666666").unwrap(),
			)
			.allocator_address(parse_address("0x7777777777777777777777777777777777777777").unwrap())
			.build();

		config.networks.insert(56, bsc_network);

		let result = generator
			.build_compact_message(&request, &config, &params)
			.await;

		assert!(result.is_ok());
		let result_obj = result.unwrap();
		assert!(result_obj.is_object());

		let result_map = result_obj.as_object().unwrap();
		// Should contain either digest+eip712 or just eip712
		assert!(result_map.contains_key("eip712"));

		// Check the EIP-712 structure
		let eip712_structure = result_map.get("eip712").unwrap();
		let eip712_obj = eip712_structure.as_object().unwrap();
		assert!(eip712_obj.contains_key("types"));
		assert!(eip712_obj.contains_key("domain"));
		assert!(eip712_obj.contains_key("primaryType"));
		assert!(eip712_obj.contains_key("message"));

		// Check the actual message fields
		let message = eip712_obj.get("message").unwrap();
		let message_obj = message.as_object().unwrap();
		assert!(message_obj.contains_key("sponsor"));
		assert!(message_obj.contains_key("commitments"));
		assert!(message_obj.contains_key("mandate"));
		assert!(message_obj.contains_key("nonce"));
		assert!(message_obj.contains_key("expires"));
	}

	#[test]
	fn test_calculate_eta_with_preferences() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service =
			Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1, 60));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);

		// Test speed preference
		let speed_eta = generator.calculate_eta(&Some(QuotePreference::Speed));
		assert_eq!(speed_eta, 96); // 120 * 0.8

		// Test price preference
		let price_eta = generator.calculate_eta(&Some(QuotePreference::Price));
		assert_eq!(price_eta, 144); // 120 * 1.2

		// Test trust minimization preference
		let trust_eta = generator.calculate_eta(&Some(QuotePreference::TrustMinimization));
		assert_eq!(trust_eta, 180); // 120 * 1.5

		// Test no preference
		let default_eta = generator.calculate_eta(&None);
		assert_eq!(default_eta, 120);

		// Test input priority (should use default)
		let input_eta = generator.calculate_eta(&Some(QuotePreference::InputPriority));
		assert_eq!(input_eta, 120);
	}

	#[test]
	fn test_sort_quotes_by_preference_speed() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service =
			Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1, 60));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);

		let mut quotes = vec![
			Quote {
				order: OifOrder::OifEscrowV0 {
					payload: OrderPayload {
						signature_type: SignatureType::Eip712,
						domain: serde_json::json!({}),
						primary_type: "TestType".to_string(),
						message: serde_json::json!({}),
						types: None,
					},
				},
				failure_handling: FailureHandlingMode::RefundAutomatic,
				partial_fill: false,
				valid_until: 1234567890,
				eta: Some(200),
				quote_id: "quote1".to_string(),
				provider: Some("test".to_string()),
			},
			Quote {
				order: OifOrder::OifEscrowV0 {
					payload: OrderPayload {
						signature_type: SignatureType::Eip712,
						domain: serde_json::json!({}),
						primary_type: "TestType".to_string(),
						message: serde_json::json!({}),
						types: None,
					},
				},
				failure_handling: FailureHandlingMode::RefundAutomatic,
				partial_fill: false,
				valid_until: 1234567890,
				eta: Some(100),
				quote_id: "quote2".to_string(),
				provider: Some("test".to_string()),
			},
			Quote {
				order: OifOrder::OifEscrowV0 {
					payload: OrderPayload {
						signature_type: SignatureType::Eip712,
						domain: serde_json::json!({}),
						primary_type: "TestType".to_string(),
						message: serde_json::json!({}),
						types: None,
					},
				},
				failure_handling: FailureHandlingMode::RefundAutomatic,
				partial_fill: false,
				valid_until: 1234567890,
				eta: None,
				quote_id: "quote3".to_string(),
				provider: Some("test".to_string()),
			},
		];

		generator.sort_quotes_by_preference(&mut quotes, &Some(QuotePreference::Speed));

		// Should be sorted by ETA ascending (fastest first)
		assert_eq!(quotes[0].eta, Some(100));
		assert_eq!(quotes[1].eta, Some(200));
		assert_eq!(quotes[2].eta, None); // None should be last
	}

	#[test]
	fn test_sort_quotes_by_preference_other() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service =
			Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1, 60));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);

		let mut quotes = vec![
			Quote {
				order: OifOrder::OifEscrowV0 {
					payload: OrderPayload {
						signature_type: SignatureType::Eip712,
						domain: serde_json::json!({}),
						primary_type: "TestType".to_string(),
						message: serde_json::json!({}),
						types: None,
					},
				},
				failure_handling: FailureHandlingMode::RefundAutomatic,
				partial_fill: false,
				valid_until: 1234567890,
				eta: Some(200),
				quote_id: "quote1".to_string(),
				provider: Some("test".to_string()),
			},
			Quote {
				order: OifOrder::OifEscrowV0 {
					payload: OrderPayload {
						signature_type: SignatureType::Eip712,
						domain: serde_json::json!({}),
						primary_type: "TestType".to_string(),
						message: serde_json::json!({}),
						types: None,
					},
				},
				failure_handling: FailureHandlingMode::RefundAutomatic,
				partial_fill: false,
				valid_until: 1234567890,
				eta: Some(100),
				quote_id: "quote2".to_string(),
				provider: Some("test".to_string()),
			},
		];

		let original_order = quotes.clone();

		// Test that other preferences don't change order
		generator.sort_quotes_by_preference(&mut quotes, &Some(QuotePreference::Price));
		assert_eq!(quotes[0].quote_id, original_order[0].quote_id);
		assert_eq!(quotes[1].quote_id, original_order[1].quote_id);

		generator.sort_quotes_by_preference(&mut quotes, &Some(QuotePreference::TrustMinimization));
		assert_eq!(quotes[0].quote_id, original_order[0].quote_id);
		assert_eq!(quotes[1].quote_id, original_order[1].quote_id);

		generator.sort_quotes_by_preference(&mut quotes, &Some(QuotePreference::InputPriority));
		assert_eq!(quotes[0].quote_id, original_order[0].quote_id);
		assert_eq!(quotes[1].quote_id, original_order[1].quote_id);

		generator.sort_quotes_by_preference(&mut quotes, &None);
		assert_eq!(quotes[0].quote_id, original_order[0].quote_id);
		assert_eq!(quotes[1].quote_id, original_order[1].quote_id);
	}

	#[test]
	fn test_get_quote_validity_seconds() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service =
			Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1, 60));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);

		// Test with configured validity
		let config = create_test_config();
		let validity = generator.get_quote_validity_seconds(&config);
		assert_eq!(validity, 300);

		// Test with no API config (should use default)
		let config_no_api = ConfigBuilder::new().build();
		let validity_default = generator.get_quote_validity_seconds(&config_no_api);
		assert_eq!(validity_default, 20); // if API none, use default 20
	}

	#[test]
	fn test_get_lock_domain_address_success() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service =
			Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1, 60));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);
		let config = create_test_config();
		let lock = solver_types::AssetLockReference {
			kind: solver_types::LockKind::TheCompact,
			params: Some(serde_json::json!({})),
		};

		let result = generator.get_lock_domain_address(&config, &lock);
		assert!(result.is_ok());

		let domain = result.unwrap();
		assert_eq!(domain.ethereum_chain_id().unwrap(), 1);
	}

	#[test]
	fn test_get_lock_domain_address_missing_config() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service =
			Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1, 60));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);
		let mut config = create_test_config();
		config.settlement.domain = None;

		let lock = solver_types::AssetLockReference {
			kind: solver_types::LockKind::TheCompact,
			params: Some(serde_json::json!({})),
		};

		let result = generator.get_lock_domain_address(&config, &lock);
		assert!(matches!(result, Err(QuoteError::InvalidRequest(_))));
	}

	#[tokio::test]
	async fn test_generate_quote_for_settlement_resource_lock() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service =
			Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1, 60));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);
		let config = create_test_config();
		let request = create_test_request();

		let custody_decision = CustodyDecision::ResourceLock {
			lock: solver_types::AssetLockReference {
				kind: solver_types::LockKind::TheCompact,
				params: Some(serde_json::json!({})),
			},
		};

		let result = generator
			.generate_quote_for_settlement(&request, &config, &custody_decision)
			.await;

		match result {
			Ok(quote) => {
				assert!(!quote.quote_id.is_empty());
				assert_eq!(quote.provider, Some("oif-solver".to_string()));
				assert!(quote.valid_until > 0);
				assert!(quote.eta.is_some());
				// Check that the order is ResourceLock based on the custody decision
				match &quote.order {
					OifOrder::OifResourceLockV0 { payload } => {
						assert_eq!(payload.signature_type, SignatureType::Eip712);
					},
					_ => panic!("Expected OifResourceLockV0 order"),
				}
			},
			Err(e) => {
				// Expected if domain configuration is incomplete
				assert!(matches!(e, QuoteError::InvalidRequest(_)));
			},
		}
	}

	#[tokio::test]
	async fn test_generate_quote_for_settlement_escrow() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service =
			Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1, 60));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);
		let config = create_test_config();
		let request = create_test_request();

		let custody_decision = CustodyDecision::Escrow {
			lock_type: solver_types::standards::eip7683::LockType::Eip3009Escrow,
		};

		let result = generator
			.generate_quote_for_settlement(&request, &config, &custody_decision)
			.await;

		match result {
			Ok(quote) => {
				assert!(!quote.quote_id.is_empty());
				assert_eq!(quote.provider, Some("oif-solver".to_string()));
				assert!(quote.valid_until > 0);
				assert!(quote.eta.is_some());
				// Check that the order is EIP-3009 based on the custody decision
				match &quote.order {
					OifOrder::Oif3009V0 { payload, .. } => {
						assert_eq!(payload.signature_type, SignatureType::Eip712);
					},
					_ => panic!("Expected Oif3009V0 order"),
				}
			},
			Err(e) => {
				// Expected due to missing settlement service setup or invalid request
				assert!(matches!(
					e,
					QuoteError::InvalidRequest(_) | QuoteError::UnsupportedSettlement(_)
				));
			},
		}
	}

	#[tokio::test]
	async fn test_exact_input_no_output_constraint_succeeds() {
		let generator = create_test_generator();
		let request = create_exact_input_request(
			Some("1000000000000000000"), // 1 TOKA input
			None,                        // No output constraint
		);

		let config = create_test_config();
		let result = generator.generate_quotes(&request, &config).await;

		// Should not fail with InvalidRequest for missing constraint
		// May fail with other errors (e.g., InsufficientLiquidity) but that's ok
		assert!(
			!matches!(result, Err(QuoteError::InvalidRequest(msg)) if msg.contains("constraint")),
			"Should accept exact-input without output constraint"
		);
	}

	#[tokio::test]
	async fn test_exact_output_no_input_constraint_succeeds() {
		let generator = create_test_generator();
		let request = create_exact_output_request(
			None,                        // No input constraint
			Some("1000000000000000000"), // 1 TOKB output
		);

		let config = create_test_config();
		let result = generator.generate_quotes(&request, &config).await;

		// Should not fail with InvalidRequest for missing constraint
		assert!(
			!matches!(result, Err(QuoteError::InvalidRequest(msg)) if msg.contains("constraint")),
			"Should accept exact-output without input constraint"
		);
	}

	fn create_test_generator() -> QuoteGenerator {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service =
			Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1, 60));
		QuoteGenerator::new(settlement_service, delivery_service)
	}

	fn create_exact_input_request(
		input_amount: Option<&str>,
		output_amount: Option<&str>,
	) -> GetQuoteRequest {
		GetQuoteRequest {
			user: InteropAddress::new_ethereum(
				1,
				address!("1111111111111111111111111111111111111111"),
			),
			intent: IntentRequest {
				intent_type: IntentType::OifSwap,
				inputs: vec![QuoteInput {
					user: InteropAddress::new_ethereum(
						1,
						address!("1111111111111111111111111111111111111111"),
					),
					asset: InteropAddress::new_ethereum(
						1,
						address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
					),
					amount: input_amount.map(|s| s.to_string()),
					lock: None,
				}],
				outputs: vec![QuoteOutput {
					receiver: InteropAddress::new_ethereum(
						137,
						address!("2222222222222222222222222222222222222222"),
					),
					asset: InteropAddress::new_ethereum(
						137,
						address!("2791Bca1f2de4661ED88A30C99A7a9449Aa84174"),
					),
					amount: output_amount.map(|s| s.to_string()),
					calldata: None,
				}],
				swap_type: Some(SwapType::ExactInput),
				preference: Some(QuotePreference::Speed),
				min_valid_until: Some(600),
				origin_submission: Some(solver_types::OriginSubmission {
					mode: solver_types::OriginMode::User,
					schemes: Some(vec![solver_types::AuthScheme::Permit2]),
				}),
				failure_handling: None,
				partial_fill: Some(false),
				metadata: None,
			},
			supported_types: vec!["oif-escrow-v0".to_string()],
		}
	}

	fn create_exact_output_request(
		input_amount: Option<&str>,
		output_amount: Option<&str>,
	) -> GetQuoteRequest {
		GetQuoteRequest {
			user: InteropAddress::new_ethereum(
				1,
				address!("1111111111111111111111111111111111111111"),
			),
			intent: IntentRequest {
				intent_type: IntentType::OifSwap,
				inputs: vec![QuoteInput {
					user: InteropAddress::new_ethereum(
						1,
						address!("1111111111111111111111111111111111111111"),
					),
					asset: InteropAddress::new_ethereum(
						1,
						address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
					),
					amount: input_amount.map(|s| s.to_string()),
					lock: None,
				}],
				outputs: vec![QuoteOutput {
					receiver: InteropAddress::new_ethereum(
						137,
						address!("2222222222222222222222222222222222222222"),
					),
					asset: InteropAddress::new_ethereum(
						137,
						address!("2791Bca1f2de4661ED88A30C99A7a9449Aa84174"),
					),
					amount: output_amount.map(|s| s.to_string()),
					calldata: None,
				}],
				swap_type: Some(SwapType::ExactOutput),
				preference: Some(QuotePreference::Speed),
				min_valid_until: Some(600),
				origin_submission: Some(solver_types::OriginSubmission {
					mode: solver_types::OriginMode::User,
					schemes: Some(vec![solver_types::AuthScheme::Permit2]),
				}),
				failure_handling: None,
				partial_fill: Some(false),
				metadata: None,
			},
			supported_types: vec!["oif-escrow-v0".to_string()],
		}
	}
}
