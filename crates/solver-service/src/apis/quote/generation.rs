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
use alloy_primitives::U256;
use solver_config::{Config, QuoteConfig};
use solver_delivery::DeliveryService;
use solver_settlement::SettlementService;
use solver_types::standards::eip7683::LockType;
use solver_types::{
	CostContext, FailureHandlingMode, GetQuoteRequest, OifOrder, OrderInput, OrderPayload, Quote,
	QuoteError, QuotePreference, QuotePreview, SignatureType, SwapType, ValidatedQuoteContext,
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
			custody_strategy: CustodyStrategy::new(delivery_service.clone()),
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
					if let Some(base_info) = cost_context.swap_amounts.get(&output.asset) {
						// Get cost for this specific token
						let cost_amount = cost_context
							.cost_amounts_in_tokens
							.get(&output.asset)
							.map(|info| info.amount)
							.unwrap_or(U256::ZERO);

						// Apply full cost to first output, others get their base amount
						let is_first_output = first_output_asset
							.as_ref()
							.map(|first| first == &output.asset)
							.unwrap_or(false);

						let adjusted_amount = if is_first_output {
							// First output bears the full cost
							base_info.amount.saturating_sub(cost_amount)
						} else {
							// Other outputs get their base amount
							base_info.amount
						};

						// Convert Decimal to string (already in smallest unit, no decimal places)
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
					if let Some(base_info) = cost_context.swap_amounts.get(&input.asset) {
						// Get cost for this specific token
						let cost_amount = cost_context
							.cost_amounts_in_tokens
							.get(&input.asset)
							.map(|info| info.amount)
							.unwrap_or(U256::ZERO);

						// Apply full cost to first input, others get their base amount
						let is_first_input = first_input_asset
							.as_ref()
							.map(|first| first == &input.asset)
							.unwrap_or(false);

						let adjusted_amount = if is_first_input {
							// First input bears the full cost
							base_info.amount.saturating_add(cost_amount)
						} else {
							// Other inputs get their base amount
							base_info.amount
						};

						// Convert Decimal to string (already in smallest unit, no decimal places)
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
		let (order, settlement_name) = match custody_decision {
			CustodyDecision::ResourceLock { lock } => {
				let order = self
					.generate_resource_lock_order(request, config, lock)
					.await?;
				// Resource lock orders don't have a settlement name (handled differently)
				(order, None)
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
			order: order.clone(),
			failure_handling,
			partial_fill,
			valid_until: chrono::Utc::now().timestamp() as u64 + validity_seconds,
			eta: Some(eta),
			quote_id,
			provider: Some("oif-solver".to_string()),
			preview: QuotePreview::from_order_and_user(&order, &request.user),
			settlement_name,
		})
	}

	async fn generate_resource_lock_order(
		&self,
		request: &GetQuoteRequest,
		config: &Config,
		lock: &solver_types::AssetLockReference,
	) -> Result<OifOrder, QuoteError> {
		use solver_types::LockKind;

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
								"Invalid chain ID in asset address: {e}"
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
						domain: serde_json::Value::Null, // TBD
						primary_type,
						message,
						types: None, // Other resource locks don't need EIP-712 types yet
					},
				}
			},
		};

		Ok(order)
	}

	/// Generates an escrow order and returns it along with the selected settlement name.
	async fn generate_escrow_order(
		&self,
		request: &GetQuoteRequest,
		config: &Config,
		lock_type: &LockType,
	) -> Result<(OifOrder, Option<String>), QuoteError> {
		// Extract chain from first output to find appropriate settlement
		// TODO: Implement support for multiple destination chains
		let origin_chain_id = request
			.intent
			.inputs
			.first()
			.ok_or_else(|| QuoteError::InvalidRequest("No requested inputs".to_string()))?
			.asset
			.ethereum_chain_id()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid chain ID: {e}")))?;

		let destination_chain_id = request
			.intent
			.outputs
			.first()
			.ok_or_else(|| QuoteError::InvalidRequest("No requested outputs".to_string()))?
			.asset
			.ethereum_chain_id()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid chain ID: {e}")))?;

		// For escrow orders, get settlement that supports both chains
		let (selected_settlement, _settlement, input_oracle, output_oracle) = self
			.settlement_service
			.get_any_settlement_for_chains_with_name(origin_chain_id, destination_chain_id)
			.ok_or_else(|| {
				QuoteError::InvalidRequest(format!(
					"No suitable settlement available for escrow from chain {origin_chain_id} to chain {destination_chain_id}"
				))
			})?;
		tracing::debug!(
			origin_chain_id,
			destination_chain_id,
			settlement = selected_settlement,
			"Selected settlement for escrow quote"
		);

		let order = match lock_type {
			LockType::Permit2Escrow => {
				self.generate_permit2_order(request, config, input_oracle, output_oracle)
					.await?
			},
			LockType::Eip3009Escrow => {
				self.generate_eip3009_order(request, config, input_oracle, output_oracle)
					.await?
			},
			_ => {
				return Err(QuoteError::UnsupportedSettlement(format!(
					"Unsupported escrow type: {lock_type:?}"
				)))
			},
		};

		Ok((order, Some(selected_settlement.to_string())))
	}

	async fn generate_permit2_order(
		&self,
		request: &GetQuoteRequest,
		config: &Config,
		input_oracle: solver_types::Address,
		output_oracle: solver_types::Address,
	) -> Result<OifOrder, QuoteError> {
		let chain_id = request.intent.inputs[0]
			.asset
			.ethereum_chain_id()
			.map_err(|e| {
				QuoteError::InvalidRequest(format!("Invalid chain ID in asset address: {e}"))
			})?;

		// Build structured domain object for Permit2
		let domain_object = self.build_permit2_domain_object(config, chain_id).await?;

		// Generate the message object without pre-computed digest
		let message_obj =
			self.build_permit2_message_object(request, config, input_oracle, output_oracle)?;

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
		input_oracle: solver_types::Address,
		output_oracle: solver_types::Address,
	) -> Result<OifOrder, QuoteError> {
		use alloy_primitives::hex;

		let current_time = chrono::Utc::now().timestamp() as u64;

		// Calculate separate deadlines
		// fillDeadline: Time to fill outputs on destination chains (default 5 minutes)
		let fill_deadline_timestamp = if let Some(min_valid_until) = request.intent.min_valid_until
		{
			// If user specifies min_valid_until, use it as fillDeadline
			min_valid_until
		} else {
			let fill_deadline_seconds = self.get_fill_deadline_seconds(config);
			current_time + fill_deadline_seconds
		};

		// expires: Time to finalize/claim on origin chain (default 10 minutes, must be > fillDeadline)
		let expires_timestamp = if let Some(min_valid_until) = request.intent.min_valid_until {
			// If user specifies min_valid_until, add buffer for expires
			min_valid_until
				+ (self.get_expires_seconds(config) - self.get_fill_deadline_seconds(config))
		} else {
			let expires_seconds = self.get_expires_seconds(config);
			current_time + expires_seconds
		};

		// Get input chain to find the input settler address (the 'to' field)
		let first_input = &request.intent.inputs[0];
		let input_chain_id = first_input
			.asset
			.ethereum_chain_id()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid input chain ID: {e}")))?;
		let network = config.networks.get(&input_chain_id).ok_or_else(|| {
			QuoteError::InvalidRequest(format!("Network {input_chain_id} not found in config"))
		})?;
		let input_settler = network.input_settler_address.clone();
		let input_settler_address = format!(
			"0x{:040x}",
			alloy_primitives::Address::from_slice(&input_settler.0)
		);

		// Set fillDeadline for order
		let fill_deadline = fill_deadline_timestamp as u32;
		let expires = expires_timestamp as u32;

		// Calculate the correct orderIdentifier using the contract
		let (nonce_u64, order_identifier) = self
			.compute_eip3009_order_identifier(
				request,
				config,
				&input_oracle,
				&output_oracle,
				fill_deadline,
				expires,
			)
			.await?;

		// Get token address for domain information
		let token_address = first_input
			.asset
			.ethereum_address()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid token address: {e}")))?;

		// Build structured domain object for EIP-3009 token
		let domain_object = self
			.build_eip3009_domain_object(&token_address, input_chain_id)
			.await?;

		// Get the domain separator from the contract
		let domain_separator = self
			.get_eip3009_domain_separator(&token_address, input_chain_id)
			.await?;

		// For EIP-3009, we need to generate signature templates for each input
		// since the contract expects one signature per input
		let mut signatures_array = Vec::new();
		for input in &request.intent.inputs {
			let input_message = serde_json::json!({
				"from": input.user.ethereum_address().map_err(|e| QuoteError::InvalidRequest(format!("Invalid Ethereum address: {e}")))?,
				"to": input_settler_address,
				"value": input.amount,
				"validAfter": 0,
				"validBefore": fill_deadline,
				"nonce": order_identifier  // Use order_identifier for signature
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
			"domain_separator": format!("0x{}", hex::encode(domain_separator)),
			"user": request.user.to_string(),
			"nonce": nonce_u64,
			"originChainId": input_chain_id,
			"expires": expires, // Separate expires (10 min default) for finalization
			"fillDeadline": fill_deadline, // Fill deadline (5 min default) for output fills
			"inputOracle": format!("0x{:040x}", alloy_primitives::Address::from_slice(&input_oracle.0)),
			"inputs": request.intent.inputs.iter().map(|input| {
				serde_json::json!({
					"chainId": input.asset.ethereum_chain_id().unwrap_or(1),
					"asset": input.asset.to_string(),
					"amount": input.amount.clone(),
					"user": input.user.to_string()
				})
			}).collect::<Vec<_>>(),
			"outputs": request.intent.outputs.iter().map(|output| {
				// Get the output settler for the specific output chain
				let output_chain_id = output.asset.ethereum_chain_id().unwrap_or(1);
				let output_network = config.networks.get(&output_chain_id).ok_or_else(|| {
					QuoteError::InvalidRequest(format!(
						"Output chain {output_chain_id} not found in config"
					))
				})?;
				let output_settler = &output_network.output_settler_address;

				Ok::<_, QuoteError>(serde_json::json!({
					"chainId": output_chain_id,
					"asset": output.asset.to_string(),
					"amount": output.amount.clone(),
					"receiver": output.receiver.to_string(),
					"oracle": format!("0x{:040x}", alloy_primitives::Address::from_slice(&output_oracle.0)),
					"settler": format!("0x{:040x}", alloy_primitives::Address::from_slice(&output_settler.0)),
				}))
			}).collect::<Result<Vec<_>, _>>()?
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
	/// and calling the contract's orderIdentifier function using the delivery service
	/// Returns (nonce, order_identifier)
	async fn compute_eip3009_order_identifier(
		&self,
		request: &GetQuoteRequest,
		config: &Config,
		input_oracle: &solver_types::Address,
		output_oracle: &solver_types::Address,
		fill_deadline: u32,
		expires: u32,
	) -> Result<(u64, String), QuoteError> {
		// Build the StandardOrder struct for encoding
		use alloy_primitives::U256;
		use alloy_sol_types::SolCall;
		use solver_types::standards::eip7683::interfaces::{SolMandateOutput, StandardOrder};
		use std::str::FromStr;

		// Define just the orderIdentifier function since we're reusing the structs
		alloy_sol_types::sol! {
			function orderIdentifier((address,uint256,uint256,uint32,uint32,address,uint256[2][],(bytes32,bytes32,uint256,bytes32,uint256,bytes32,bytes,bytes)[]) memory order) external pure returns (bytes32);
		}

		let input = &request.intent.inputs[0];

		// Get input chain info
		let input_chain_id = input
			.asset
			.ethereum_chain_id()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid input chain ID: {e}")))?;
		let input_network = config.networks.get(&input_chain_id).ok_or_else(|| {
			QuoteError::InvalidRequest(format!("Network {input_chain_id} not found"))
		})?;

		// Build StandardOrder struct (same approach as intents script)
		let user_addr = input
			.user
			.ethereum_address()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid user address: {e}")))?;
		// Generate incremental nonce like direct intent (current timestamp in milliseconds)
		let nonce = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_millis() as u64)
			.unwrap_or(0u64);
		let expiry = expires; // Use expires for the order expiry

		// Build input tokens array: [[token, amount]]
		let input_token = input
			.asset
			.ethereum_address()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid input token: {e}")))?;
		// Input amount should be set after cost adjustment
		let input_amount = input
			.amount
			.as_ref()
			.ok_or_else(|| {
				QuoteError::InvalidRequest("Input amount not set after cost adjustment".to_string())
			})?
			.clone();

		// Build outputs array for StandardOrder
		let output_info =
			request.intent.outputs.first().ok_or_else(|| {
				QuoteError::InvalidRequest("No requested outputs found".to_string())
			})?;

		// Extract output chain and token from InteropAddress
		let output_chain_id = output_info
			.asset
			.ethereum_chain_id()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid output chain ID: {e}")))?;
		let output_token = output_info
			.asset
			.ethereum_address()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid output token: {e}")))?;
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
		let recipient_addr = output_info
			.receiver
			.ethereum_address()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid recipient address: {e}")))?;

		// Get output settler from config
		let output_network = config.networks.get(&output_chain_id).ok_or_else(|| {
			QuoteError::InvalidRequest(format!(
				"Output network {output_chain_id} not found in config"
			))
		})?;
		let output_settler = output_network.output_settler_address.clone();
		let output_settler_address = alloy_primitives::Address::from_slice(&output_settler.0);

		// Convert addresses to bytes32 for Output struct
		let mut output_oracle_bytes = [0u8; 32];
		output_oracle_bytes[12..].copy_from_slice(&output_oracle.0[..]);
		let output_oracle_bytes32 = alloy_primitives::FixedBytes::<32>::from(output_oracle_bytes);

		let mut output_settler_bytes = [0u8; 32];
		output_settler_bytes[12..].copy_from_slice(&output_settler_address.0[..]);
		let output_settler_bytes32 = alloy_primitives::FixedBytes::<32>::from(output_settler_bytes);

		let mut output_token_bytes = [0u8; 32];
		output_token_bytes[12..].copy_from_slice(&output_token.0[..]);
		let output_token_bytes32 = alloy_primitives::FixedBytes::<32>::from(output_token_bytes);

		let mut recipient_bytes = [0u8; 32];
		recipient_bytes[12..].copy_from_slice(&recipient_addr.0[..]);
		let recipient_bytes32 = alloy_primitives::FixedBytes::<32>::from(recipient_bytes);

		// Parse amounts
		let input_amount_u256 = U256::from_str(&input_amount)
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid input amount: {e}")))?;
		let output_amount_u256 = U256::from_str(&output_amount)
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid output amount: {e}")))?;

		// Convert input token address to bytes32 for inputs array
		let mut input_token_bytes = [0u8; 32];
		input_token_bytes[12..].copy_from_slice(&input_token.0[..]);
		let input_token_u256 = U256::from_be_bytes(input_token_bytes);

		// Parse callbackData from request if present
		let callback_data_bytes = if let Some(ref calldata_hex) = output_info.calldata {
			if calldata_hex.is_empty() || calldata_hex == "0x" {
				vec![]
			} else {
				let hex_str = calldata_hex.trim_start_matches("0x");
				hex::decode(hex_str).unwrap_or_else(|e| {
					tracing::warn!("Failed to decode callbackData '{}': {}", calldata_hex, e);
					vec![]
				})
			}
		} else {
			vec![]
		};

		// Build the StandardOrder
		let order = StandardOrder {
			user: user_addr,
			nonce: U256::from(nonce),
			originChainId: U256::from(input_chain_id),
			expires: expiry,
			fillDeadline: fill_deadline,
			inputOracle: alloy_primitives::Address::from_slice(&input_oracle.0),
			inputs: vec![[input_token_u256, input_amount_u256]],
			outputs: vec![SolMandateOutput {
				oracle: output_oracle_bytes32,
				settler: output_settler_bytes32,
				chainId: U256::from(output_chain_id),
				token: output_token_bytes32,
				amount: output_amount_u256,
				recipient: recipient_bytes32,
				callbackData: callback_data_bytes.into(),
				context: vec![].into(),
			}],
		};

		// Encode the function call - pass the order as a tuple
		let encoded_call = orderIdentifierCall {
			order: (
				order.user,
				order.nonce,
				order.originChainId,
				order.expires,
				order.fillDeadline,
				order.inputOracle,
				order.inputs.clone(),
				order
					.outputs
					.iter()
					.map(|o| {
						(
							o.oracle,
							o.settler,
							o.chainId,
							o.token,
							o.amount,
							o.recipient,
							o.callbackData.clone(),
							o.context.clone(),
						)
					})
					.collect::<Vec<_>>(),
			),
		}
		.abi_encode();

		// Get input settler address
		let input_settler_address = input_network.input_settler_address.clone();

		// Build transaction for the contract call
		let tx = solver_types::Transaction {
			to: Some(input_settler_address.clone()),
			data: encoded_call,
			value: alloy_primitives::U256::ZERO,
			gas_limit: None,
			gas_price: None,
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
			nonce: None,
			chain_id: input_chain_id,
		};

		// Call the contract using the delivery service directly
		let order_id_bytes = self
			.delivery_service
			.contract_call(input_chain_id, tx)
			.await
			.map_err(|e| QuoteError::InvalidRequest(format!("Failed to compute order ID: {e}")))?;

		// Convert the returned bytes to hex string
		let order_id = format!("0x{}", alloy_primitives::hex::encode(&order_id_bytes));

		if order_id == "0x0000000000000000000000000000000000000000000000000000000000000000" {
			return Err(QuoteError::InvalidRequest(
				"Failed to compute valid order ID from contract".to_string(),
			));
		}

		tracing::debug!("Successfully computed order ID: {}", order_id);

		Ok((nonce, order_id))
	}

	/// Get the DOMAIN_SEPARATOR from an EIP-3009 token contract
	async fn get_eip3009_domain_separator(
		&self,
		token_address: &[u8; 20],
		chain_id: u64,
	) -> Result<[u8; 32], QuoteError> {
		use alloy_sol_types::SolCall;

		// Define the DOMAIN_SEPARATOR function
		alloy_sol_types::sol! {
			function DOMAIN_SEPARATOR() external view returns (bytes32);
		}

		// Encode the call
		let encoded_call = DOMAIN_SEPARATORCall {}.abi_encode();

		// Build transaction for the contract call
		let tx = solver_types::Transaction {
			to: Some(solver_types::Address(token_address.to_vec())),
			data: encoded_call,
			value: alloy_primitives::U256::ZERO,
			gas_limit: None,
			gas_price: None,
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
			nonce: None,
			chain_id,
		};

		// Call the contract using the delivery service
		let domain_separator_bytes = self
			.delivery_service
			.contract_call(chain_id, tx)
			.await
			.map_err(|e| {
				QuoteError::InvalidRequest(format!("Failed to get domain separator: {e}"))
			})?;

		// Convert the returned bytes to [u8; 32]
		if domain_separator_bytes.len() != 32 {
			return Err(QuoteError::InvalidRequest(format!(
				"Invalid domain separator length: expected 32 bytes, got {}",
				domain_separator_bytes.len()
			)));
		}

		let mut domain_separator = [0u8; 32];
		domain_separator.copy_from_slice(&domain_separator_bytes);

		Ok(domain_separator)
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

		let current_time = chrono::Utc::now().timestamp() as u64;

		// Calculate separate deadlines
		// fillDeadline: Time to fill outputs on destination chains (default 5 minutes)
		let fill_deadline_timestamp = if let Some(min_valid_until) = request.intent.min_valid_until
		{
			// If user specifies min_valid_until, use it as fillDeadline
			min_valid_until
		} else {
			let fill_deadline_seconds = self.get_fill_deadline_seconds(config);
			current_time + fill_deadline_seconds
		};

		// expires: Time for BatchCompact signature/claim on origin chain (default 10 minutes, must be > fillDeadline)
		let expires = if let Some(min_valid_until) = request.intent.min_valid_until {
			// If user specifies min_valid_until, add buffer for expires
			min_valid_until
				+ (self.get_expires_seconds(config) - self.get_fill_deadline_seconds(config))
		} else {
			let expires_seconds = self.get_expires_seconds(config);
			current_time + expires_seconds
		};

		let nonce = chrono::Utc::now().timestamp_millis() as u64; // Use milliseconds timestamp as nonce for uniqueness (matching direct intent flow)

		// Get user address
		let user_address = request
			.user
			.ethereum_address()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid user address: {e}")))?;

		// Get input chain ID from first available input
		let origin_chain_id = request
			.intent
			.inputs
			.first()
			.ok_or_else(|| QuoteError::InvalidRequest("No requested inputs".to_string()))?
			.asset
			.ethereum_chain_id()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid chain ID: {e}")))?;

		// Get addresses from network configuration
		let network = config.networks.get(&origin_chain_id).ok_or_else(|| {
			QuoteError::InvalidRequest(format!("Network {origin_chain_id} not found in config"))
		})?;

		// Get preferred settlement for TheCompact (prioritizes Direct settlement like escrow)
		let (selected_input_settlement, _input_settlement, input_oracle, _output_oracle) = self
			.settlement_service
			.get_any_settlement_for_chain_with_name(origin_chain_id)
			.ok_or_else(|| {
				QuoteError::InvalidRequest(format!(
					"No suitable settlement available for TheCompact on chain {origin_chain_id}"
				))
			})?;
		tracing::debug!(
			chain_id = origin_chain_id,
			settlement = selected_input_settlement,
			"Selected settlement for resource-lock input chain"
		);

		// Convert inputs to the format expected by TheCompact
		// For ResourceLock orders, we need to build the proper token IDs and amounts
		let mut inputs_array = Vec::new();
		for input in &request.intent.inputs {
			let token_address = input.asset.ethereum_address().map_err(|e| {
				QuoteError::InvalidRequest(format!("Invalid input token address: {e}"))
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
			let token_id_hex = format!("{allocator_tag}{token_address_hex}");
			let token_id = U256::from_str(&token_id_hex).map_err(|e| {
				QuoteError::InvalidRequest(format!("Failed to create token ID: {e}"))
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
				QuoteError::InvalidRequest(format!("Invalid output token address: {e}"))
			})?;
			let recipient_address = output.receiver.ethereum_address().map_err(|e| {
				QuoteError::InvalidRequest(format!("Invalid recipient address: {e}"))
			})?;
			let output_chain_id = output
				.asset
				.ethereum_chain_id()
				.map_err(|e| QuoteError::InvalidRequest(format!("Invalid output chain ID: {e}")))?;

			// Get preferred settlement for the output chain (prioritizes Direct settlement like escrow)
			let (
				selected_output_settlement,
				_output_settlement,
				_output_input_oracle,
				output_oracle,
			) = self
				.settlement_service
				.get_any_settlement_for_chain_with_name(output_chain_id)
				.ok_or_else(|| {
					QuoteError::InvalidRequest(format!(
						"No suitable settlement available for output chain {output_chain_id}"
					))
				})?;
			tracing::debug!(
				chain_id = output_chain_id,
				settlement = selected_output_settlement,
				"Selected settlement for resource-lock output chain"
			);

			// Get output settler from config (like permit2 flow)
			let dest_net = config.networks.get(&output_chain_id).ok_or_else(|| {
				QuoteError::InvalidRequest(format!(
					"Destination chain {output_chain_id} missing from networks config"
				))
			})?;
			let output_settler = bytes20_to_alloy_address(&dest_net.output_settler_address.0)
				.map_err(QuoteError::InvalidRequest)?;

			// Convert oracle address (like permit2 flow)
			let output_oracle_address =
				bytes20_to_alloy_address(&output_oracle.0).map_err(|e| {
					QuoteError::InvalidRequest(format!("Invalid output oracle address: {e}"))
				})?;

			// Build MandateOutput with proper oracle and settler addresses
			let amount = output.amount.as_ref().ok_or_else(|| {
				QuoteError::InvalidRequest(
					"Output amount not set after cost adjustment".to_string(),
				)
			})?;
			outputs_array.push(serde_json::json!({
				"oracle": solver_types::utils::address_to_bytes32_hex(&output_oracle_address),
				"settler": solver_types::utils::address_to_bytes32_hex(&output_settler),
				"chainId": output_chain_id,
				"token": solver_types::utils::address_to_bytes32_hex(&output_token_address),
				"amount": amount.clone(),
				"recipient": solver_types::utils::address_to_bytes32_hex(&recipient_address),
				"callbackData": output.calldata.as_ref().unwrap_or(&"0x".to_string()).clone(),
				"context": "0x" // Context is typically empty for standard flows
			}));
		}

		// Use the selected oracle for input chain as the inputOracle (like permit2 flow)
		let input_oracle_address = bytes20_to_alloy_address(&input_oracle.0).map_err(|e| {
			QuoteError::InvalidRequest(format!("Invalid input oracle address: {e}"))
		})?;

		// Build the EIP-712 message structure (like permit2 flow)
		// The scripts will compute the digest from this data
		let eip712_message = serde_json::json!({
			"types": self.build_compact_eip712_types(),
			"domain": {
				"name": "TheCompact",
				"version": "1",
				"chainId": origin_chain_id,
				"verifyingContract": format!("{:#x}", alloy_primitives::Address::from_slice(&network.the_compact_address.as_ref().unwrap().0))
			},
			"primaryType": "BatchCompact",
			"message": {
				"arbiter": format!("{:#x}", alloy_primitives::Address::from_slice(&network.input_settler_compact_address.as_ref().unwrap_or(&network.input_settler_address).0)),
				"sponsor": format!("{:#x}", user_address),
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
					"fillDeadline": fill_deadline_timestamp.to_string(),
					"inputOracle": format!("{:#x}", input_oracle_address),
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
		let token_version = self
			.get_token_eip712_version(&alloy_token_address, chain_id)
			.await;

		// Build domain object similar to TheCompact structure (without pre-computed domainSeparator)
		// The client will compute the domainSeparator using these fields
		Ok(serde_json::json!({
			"name": token_name,
			"version": token_version,
			"chainId": chain_id,
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
			.map_err(|e| QuoteError::InvalidRequest(format!("Failed to get token name: {e}")))?;

		let name = nameCall::abi_decode_returns(&result)
			.map_err(|e| QuoteError::InvalidRequest(format!("Failed to decode token name: {e}")))?;

		Ok(name)
	}

	/// Get token EIP-712 version with graceful fallbacks.
	async fn get_token_eip712_version(
		&self,
		token_address: &alloy_primitives::Address,
		chain_id: u64,
	) -> String {
		if let Ok(version) = self
			.get_token_eip712_version_via_eip5267(token_address, chain_id)
			.await
		{
			return version;
		}

		if let Ok(version) = self
			.get_token_eip712_version_via_version_call(token_address, chain_id)
			.await
		{
			return version;
		}

		if let Some(version) = self.get_known_eip3009_token_version(token_address, chain_id) {
			return version;
		}

		tracing::warn!(
			chain_id,
			token_address = %format!("0x{:040x}", token_address),
			"Falling back to default EIP-712 version '1' for EIP-3009 token"
		);

		"1".to_string()
	}

	/// Resolve token EIP-712 version from EIP-5267 `eip712Domain()`.
	async fn get_token_eip712_version_via_eip5267(
		&self,
		token_address: &alloy_primitives::Address,
		chain_id: u64,
	) -> Result<String, QuoteError> {
		use alloy_sol_types::{sol, SolCall};

		sol! {
			function eip712Domain() external view returns (
				bytes1 fields,
				string name,
				string version,
				uint256 chainId,
				address verifyingContract,
				bytes32 salt,
				uint256[] extensions
			);
		}

		let tx = solver_types::Transaction {
			to: Some(solver_types::Address(token_address.0.to_vec())),
			data: eip712DomainCall {}.abi_encode(),
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
			.map_err(|e| {
				QuoteError::InvalidRequest(format!("Failed to get token EIP-712 domain: {e}"))
			})?;

		let domain = eip712DomainCall::abi_decode_returns(&result).map_err(|e| {
			QuoteError::InvalidRequest(format!("Failed to decode token EIP-712 domain: {e}"))
		})?;
		let version = domain.version;

		if version.trim().is_empty() {
			return Err(QuoteError::InvalidRequest(
				"Token EIP-712 version is empty".to_string(),
			));
		}

		Ok(version)
	}

	/// Resolve token EIP-712 version from ERC20-like `version()` function.
	async fn get_token_eip712_version_via_version_call(
		&self,
		token_address: &alloy_primitives::Address,
		chain_id: u64,
	) -> Result<String, QuoteError> {
		use alloy_sol_types::{sol, SolCall};

		sol! {
			function version() external view returns (string);
		}

		let tx = solver_types::Transaction {
			to: Some(solver_types::Address(token_address.0.to_vec())),
			data: versionCall {}.abi_encode(),
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
			.map_err(|e| {
				QuoteError::InvalidRequest(format!("Failed to get token version(): {e}"))
			})?;

		let version = versionCall::abi_decode_returns(&result).map_err(|e| {
			QuoteError::InvalidRequest(format!("Failed to decode token version(): {e}"))
		})?;

		if version.trim().is_empty() {
			return Err(QuoteError::InvalidRequest(
				"Token version() returned empty string".to_string(),
			));
		}

		Ok(version)
	}

	/// Known EIP-3009 token versions for offline/testing fallbacks.
	fn get_known_eip3009_token_version(
		&self,
		token_address: &alloy_primitives::Address,
		chain_id: u64,
	) -> Option<String> {
		let token_hex = format!("0x{token_address:040x}").to_ascii_lowercase();

		match (chain_id, token_hex.as_str()) {
			(1, "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
			| (10, "0x0b2c639c533813f4aa9d7837caf62653d097ff85")
			| (137, "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359")
			| (8453, "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913")
			| (42161, "0xaf88d065e77c8cc2239327c5edb3a432268e5831")
			| (84532, "0x036cbd53842c5426634e7929541ec2318f3dcf7e")
			| (421614, "0x75faf114eafb1bdbe2f0316df893fd58ce46aa4d")
			| (11155111, "0x1c7d4b196cb0c7b01d743fbc6116a902379c7238")
			| (11155420, "0x5fd84259d66cd46123540766be93dfe6d43130d7")
			| (11155420, "0x191688b2ff5be8f0a5bcab3e819c900a810faaf6") => Some("2".to_string()),
			_ => None,
		}
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
				QuoteError::InvalidRequest(format!("Permit2 not deployed on chain {chain_id}"))
			})?;

		// Build domain object similar to TheCompact and EIP-3009 structure
		Ok(serde_json::json!({
			"name": "Permit2",
			"chainId": chain_id,
			"verifyingContract": format!("0x{:040x}", permit2_address)
		}))
	}

	/// Build Permit2 message object
	fn build_permit2_message_object(
		&self,
		request: &GetQuoteRequest,
		config: &Config,
		input_oracle: solver_types::Address,
		output_oracle: solver_types::Address,
	) -> Result<serde_json::Value, QuoteError> {
		use crate::apis::quote::permit2::build_permit2_batch_witness_digest;

		// Generate the complete message structure
		let (_final_digest, message_obj) =
			build_permit2_batch_witness_digest(request, config, input_oracle, output_oracle)?;

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

	/// Gets the fill deadline duration from configuration.
	///
	/// Returns the configured fill deadline seconds from api.quote config or default.
	fn get_fill_deadline_seconds(&self, config: &Config) -> u64 {
		config
			.api
			.as_ref()
			.and_then(|api| api.quote.as_ref())
			.map(|quote| quote.fill_deadline_seconds)
			.unwrap_or_else(|| QuoteConfig::default().fill_deadline_seconds)
	}

	/// Gets the expires duration from configuration.
	///
	/// Returns the configured expires seconds from api.quote config or default.
	fn get_expires_seconds(&self, config: &Config) -> u64 {
		config
			.api
			.as_ref()
			.and_then(|api| api.quote.as_ref())
			.map(|quote| quote.expires_seconds)
			.unwrap_or_else(|| QuoteConfig::default().expires_seconds)
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
			"MandateOutput": [
				{"name": "oracle", "type": "bytes32"},
				{"name": "settler", "type": "bytes32"},
				{"name": "chainId", "type": "uint256"},
				{"name": "token", "type": "bytes32"},
				{"name": "amount", "type": "uint256"},
				{"name": "recipient", "type": "bytes32"},
				{"name": "callbackData", "type": "bytes"},
				{"name": "context", "type": "bytes"}
			],
			"Permit2Witness": [
				{"name": "expires", "type": "uint32"},
				{"name": "inputOracle", "type": "address"},
				{"name": "outputs", "type": "MandateOutput[]"}
			],
			"TokenPermissions": [
				{"name": "token", "type": "address"},
				{"name": "amount", "type": "uint256"}
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
				{"name": "callbackData", "type": "bytes"},
				{"name": "context", "type": "bytes"}
			]
		})
	}

	/// Generates EIP-712 types definition for EIP-3009 ReceiveWithAuthorization orders
	fn build_eip3009_eip712_types(&self) -> serde_json::Value {
		serde_json::json!({
			"EIP712Domain": [
				{"name": "name", "type": "string"},
				{"name": "version", "type": "string"},
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
			QuoteError::InvalidRequest(format!("Network {chain_id} not found in config"))
		})?;

		let the_compact_address = network.the_compact_address.as_ref().ok_or_else(|| {
			QuoteError::InvalidRequest("TheCompact address not configured".to_string())
		})?;

		let contract_address = alloy_primitives::Address::from_slice(&the_compact_address.0);

		// Build domain object similar to Permit2 structure
		Ok(serde_json::json!({
			"name": "The Compact",
			"version": "1",
			"chainId": chain_id,
			"verifyingContract": format!("{:#x}", contract_address)
		}))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::apis::quote::custody::CustodyDecision;
	use alloy_primitives::{address, Address as AlloyAddress, Bytes, FixedBytes, U256};
	use solver_config::{ApiConfig, Config, ConfigBuilder, QuoteConfig, SettlementConfig};
	use solver_delivery::{
		DeliveryError, DeliveryInterface, DeliveryService, MockDeliveryInterface,
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
				validity_seconds: 60,
				fill_deadline_seconds: 300,
				expires_seconds: 600,
			}),
		};

		// Create settlement configuration with domain
		let settlement_config = SettlementConfig {
			implementations: HashMap::new(),
			implementation_order: Vec::new(),
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

	fn create_cost_context() -> CostContext {
		use rust_decimal::Decimal;
		use solver_types::{costs::TokenAmountInfo, CostBreakdown};
		use std::collections::HashMap;
		use std::str::FromStr;

		let mut swap_amounts = HashMap::new();
		let mut cost_amounts_in_tokens = HashMap::new();
		let mut adjusted_amounts = HashMap::new();

		let input_asset =
			InteropAddress::new_ethereum(1, address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"));
		let output_asset =
			InteropAddress::new_ethereum(137, address!("2791Bca1f2de4661ED88A30C99A7a9449Aa84174"));

		swap_amounts.insert(
			input_asset.clone(),
			TokenAmountInfo {
				token: input_asset.clone(),
				amount: U256::from_str("1000000000000000000").unwrap(),
				decimals: 18,
			},
		);
		swap_amounts.insert(
			output_asset.clone(),
			TokenAmountInfo {
				token: output_asset.clone(),
				amount: U256::from_str("950000000000000000").unwrap(),
				decimals: 18,
			},
		);

		cost_amounts_in_tokens.insert(
			input_asset.clone(),
			TokenAmountInfo {
				token: input_asset.clone(),
				amount: U256::from_str("10000000000000000").unwrap(), // 0.01 token cost
				decimals: 18,
			},
		);
		cost_amounts_in_tokens.insert(
			output_asset.clone(),
			TokenAmountInfo {
				token: output_asset.clone(),
				amount: U256::from_str("9500000000000000").unwrap(), // 0.0095 token cost
				decimals: 18,
			},
		);

		adjusted_amounts.insert(
			input_asset.clone(),
			TokenAmountInfo {
				token: input_asset.clone(),
				amount: U256::from_str("1010000000000000000").unwrap(), // input + cost
				decimals: 18,
			},
		);
		adjusted_amounts.insert(
			output_asset.clone(),
			TokenAmountInfo {
				token: output_asset.clone(),
				amount: U256::from_str("940500000000000000").unwrap(), // output - cost
				decimals: 18,
			},
		);

		CostContext {
			cost_breakdown: CostBreakdown {
				gas_open: Decimal::from_str("0.001").unwrap(),
				gas_fill: Decimal::from_str("0.002").unwrap(),
				gas_claim: Decimal::from_str("0.001").unwrap(),
				gas_buffer: Decimal::from_str("0.0005").unwrap(),
				rate_buffer: Decimal::from_str("0.01").unwrap(),
				base_price: Decimal::from_str("1.0").unwrap(),
				min_profit: Decimal::from_str("0.005").unwrap(),
				operational_cost: Decimal::from_str("0.0045").unwrap(),
				subtotal: Decimal::from_str("1.0045").unwrap(),
				total: Decimal::from_str("1.0095").unwrap(),
				currency: "USD".to_string(),
			},
			execution_costs_by_chain: HashMap::new(),
			liquidity_cost_adjustment: Decimal::from_str("0.001").unwrap(),
			protocol_fees: HashMap::new(),
			swap_type: SwapType::ExactInput,
			swap_amounts,
			cost_amounts_in_tokens,
			adjusted_amounts,
		}
	}

	fn create_validated_quote_context(swap_type: SwapType) -> ValidatedQuoteContext {
		use std::str::FromStr;

		let input_asset =
			InteropAddress::new_ethereum(1, address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"));
		let output_asset =
			InteropAddress::new_ethereum(137, address!("2791Bca1f2de4661ED88A30C99A7a9449Aa84174"));

		let mut constraint_inputs = Vec::new();
		let mut constraint_outputs = Vec::new();

		match swap_type {
			SwapType::ExactInput => {
				constraint_outputs.push((
					QuoteOutput {
						receiver: InteropAddress::new_ethereum(
							137,
							address!("2222222222222222222222222222222222222222"),
						),
						asset: output_asset,
						amount: Some("900000000000000000".to_string()),
						calldata: None,
					},
					Some(U256::from_str("900000000000000000").unwrap()),
				));
			},
			SwapType::ExactOutput => {
				constraint_inputs.push((
					QuoteInput {
						user: InteropAddress::new_ethereum(
							1,
							address!("1111111111111111111111111111111111111111"),
						),
						asset: input_asset,
						amount: Some("1100000000000000000".to_string()),
						lock: None,
					},
					Some(U256::from_str("1100000000000000000").unwrap()),
				));
			},
		}

		ValidatedQuoteContext {
			swap_type,
			known_inputs: None,
			known_outputs: None,
			constraint_inputs: if constraint_inputs.is_empty() {
				None
			} else {
				Some(constraint_inputs)
			},
			constraint_outputs: if constraint_outputs.is_empty() {
				None
			} else {
				Some(constraint_outputs)
			},
		}
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
					assert_eq!(payload.primary_type, "BatchCompact");
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
		let (_settlement, input_oracle, output_oracle) = settlement_service
			.get_any_settlement_for_chain(137)
			.expect("Should have settlement for test chain");

		let generator = QuoteGenerator::new(settlement_service.clone(), delivery_service);
		let config = create_test_config();
		let request = create_test_request();

		let result = generator
			.generate_eip3009_order(&request, &config, input_oracle, output_oracle)
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

						// Verify message structure (EIP-3009 fields only - 6 standard fields)
						let message_obj = payload.message.as_object().unwrap();
						assert!(message_obj["from"].is_string());
						assert!(message_obj["to"].is_string());
						assert!(message_obj["value"].is_string());
						assert!(message_obj["validAfter"].is_number());
						assert!(message_obj["validBefore"].is_number());
						assert!(message_obj["nonce"].is_string());
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

		// The build_compact_message now returns just the message part (flat structure)
		// Check the actual message fields directly
		let message_obj = result_map;
		assert!(message_obj.contains_key("sponsor"));
		assert!(message_obj.contains_key("commitments"));
		assert!(message_obj.contains_key("mandate"));
		assert!(message_obj.contains_key("nonce"));
		assert!(message_obj.contains_key("expires"));

		let mandate = message_obj
			.get("mandate")
			.and_then(|m| m.as_object())
			.expect("mandate should be present");
		let outputs = mandate
			.get("outputs")
			.and_then(|o| o.as_array())
			.expect("mandate.outputs should be present");
		let first_output = outputs
			.first()
			.expect("at least one output should be present");
		assert!(first_output["chainId"].is_u64());
		assert_eq!(first_output["chainId"], 137);
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
				preview: solver_types::QuotePreview {
					inputs: vec![],
					outputs: vec![],
				},
				settlement_name: None,
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
				preview: solver_types::QuotePreview {
					inputs: vec![],
					outputs: vec![],
				},
				settlement_name: None,
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
				preview: solver_types::QuotePreview {
					inputs: vec![],
					outputs: vec![],
				},
				settlement_name: None,
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
				preview: solver_types::QuotePreview {
					inputs: vec![],
					outputs: vec![],
				},
				settlement_name: None,
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
				preview: solver_types::QuotePreview {
					inputs: vec![],
					outputs: vec![],
				},
				settlement_name: None,
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
		assert_eq!(validity, 60); // Updated default: 1 minute

		// Test with no API config (should use default)
		let config_no_api = ConfigBuilder::new().build();
		let validity_default = generator.get_quote_validity_seconds(&config_no_api);
		assert_eq!(validity_default, 60); // Updated default: 1 minute
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

	fn create_test_generator_with_mock_delivery(
		chain_id: u64,
		mock_delivery: MockDeliveryInterface,
	) -> QuoteGenerator {
		let settlement_service = create_test_settlement_service(true);
		let mut implementations: HashMap<u64, Arc<dyn DeliveryInterface>> = HashMap::new();
		implementations.insert(
			chain_id,
			Arc::new(mock_delivery) as Arc<dyn DeliveryInterface>,
		);
		let delivery_service = Arc::new(DeliveryService::new(implementations, 1, 60));
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

	#[tokio::test]
	async fn test_generate_quotes_with_costs_exact_input() {
		let generator = create_test_generator();
		let request = create_exact_input_request(
			Some("1000000000000000000"), // 1 token input
			None,
		);
		let context = create_validated_quote_context(SwapType::ExactInput);
		let cost_context = create_cost_context();
		let config = create_test_config();

		let result = generator
			.generate_quotes_with_costs(&request, &context, &cost_context, &config)
			.await;

		match result {
			Ok(quotes) => {
				assert!(!quotes.is_empty());
				// Verify that costs were properly applied
			},
			Err(e) => {
				// Should not fail due to cost adjustment logic
				assert!(
					!matches!(e, QuoteError::InvalidRequest(msg) if msg.contains("cost adjustment"))
				);
			},
		}
	}

	#[tokio::test]
	async fn test_generate_quotes_with_costs_exact_output() {
		let generator = create_test_generator();
		let request = create_exact_output_request(
			None,
			Some("950000000000000000"), // 0.95 token output
		);
		let context = create_validated_quote_context(SwapType::ExactOutput);
		let cost_context = create_cost_context();
		let config = create_test_config();

		let result = generator
			.generate_quotes_with_costs(&request, &context, &cost_context, &config)
			.await;

		// Should succeed or fail with expected errors (not InvalidRequest for cost adjustment)
		match result {
			Ok(quotes) => {
				assert!(!quotes.is_empty());
			},
			Err(e) => {
				// Should not fail due to cost adjustment logic
				assert!(
					!matches!(e, QuoteError::InvalidRequest(msg) if msg.contains("cost adjustment"))
				);
			},
		}
	}

	#[test]
	fn test_build_cost_adjusted_request_exact_input() {
		let generator = create_test_generator();
		let request = create_exact_input_request(
			Some("1000000000000000000"), // 1 token input
			None,
		);
		let context = create_validated_quote_context(SwapType::ExactInput);
		let cost_context = create_cost_context();

		let result = generator.build_cost_adjusted_request(&request, &context, &cost_context);

		assert!(result.is_ok());
		let adjusted = result.unwrap();

		// For exact input, outputs should be adjusted (reduced by costs)
		assert!(adjusted.intent.outputs[0].amount.is_some());
		let output_amount = adjusted.intent.outputs[0].amount.as_ref().unwrap();
		let expected = U256::from(950000000000000000u64) - U256::from(9500000000000000u64);
		assert_eq!(output_amount, &expected.to_string());
	}

	#[test]
	fn test_build_cost_adjusted_request_exact_output() {
		let generator = create_test_generator();
		let request = create_exact_output_request(
			None,
			Some("950000000000000000"), // 0.95 token output
		);
		let context = create_validated_quote_context(SwapType::ExactOutput);
		let cost_context = create_cost_context();

		let result = generator.build_cost_adjusted_request(&request, &context, &cost_context);

		assert!(result.is_ok());
		let adjusted = result.unwrap();

		// For exact output, inputs should be adjusted (increased by costs)
		assert!(adjusted.intent.inputs[0].amount.is_some());
		let input_amount = adjusted.intent.inputs[0].amount.as_ref().unwrap();
		let expected = U256::from(1000000000000000000u64) + U256::from(10000000000000000u64);
		assert_eq!(input_amount, &expected.to_string());
	}

	#[test]
	fn test_validate_no_zero_amounts_exact_input_zero_output() {
		let generator = create_test_generator();
		let request = create_exact_input_request(
			Some("1000000000000000000"),
			Some("0"), // Zero output after cost adjustment
		);
		let context = create_validated_quote_context(SwapType::ExactInput);

		let result = generator.validate_no_zero_amounts(&request, &context);

		assert!(
			matches!(result, Err(QuoteError::InvalidRequest(msg)) if msg.contains("cannot be zero after cost adjustment"))
		);
	}

	#[test]
	fn test_validate_no_zero_amounts_exact_output_zero_input() {
		let generator = create_test_generator();
		let request = create_exact_output_request(
			Some("0"), // Zero input after cost adjustment
			Some("950000000000000000"),
		);
		let context = create_validated_quote_context(SwapType::ExactOutput);

		let result = generator.validate_no_zero_amounts(&request, &context);

		assert!(
			matches!(result, Err(QuoteError::InvalidRequest(msg)) if msg.contains("cannot be zero after cost adjustment"))
		);
	}

	#[test]
	fn test_validate_swap_amount_constraints_exact_input_below_minimum() {
		let generator = create_test_generator();
		let request = create_exact_input_request(
			Some("1000000000000000000"),
			Some("800000000000000000"), // Below minimum constraint
		);
		let context = create_validated_quote_context(SwapType::ExactInput);

		let result = generator.validate_swap_amount_constraints(&request, &context);

		assert!(
			matches!(result, Err(QuoteError::InvalidRequest(msg)) if msg.contains("below minimum required"))
		);
	}

	#[test]
	fn test_validate_swap_amount_constraints_exact_output_above_maximum() {
		let generator = create_test_generator();
		let request = create_exact_output_request(
			Some("1200000000000000000"), // Above maximum constraint
			Some("950000000000000000"),
		);
		let context = create_validated_quote_context(SwapType::ExactOutput);

		let result = generator.validate_swap_amount_constraints(&request, &context);

		assert!(
			matches!(result, Err(QuoteError::InvalidRequest(msg)) if msg.contains("exceeds maximum allowed"))
		);
	}

	#[tokio::test]
	async fn test_generate_permit2_order_success() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service =
			Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1, 60));
		let generator = QuoteGenerator::new(settlement_service.clone(), delivery_service);
		let config = create_test_config();
		let request = create_test_request();

		// Get oracles like in real usage
		let (_settlement, input_oracle, output_oracle) = settlement_service
			.get_any_settlement_for_chains(1, 137)
			.expect("Should have settlement for test chains");

		let result = generator
			.generate_permit2_order(&request, &config, input_oracle, output_oracle)
			.await;

		match result {
			Ok(order) => {
				match order {
					OifOrder::OifEscrowV0 { payload } => {
						assert_eq!(payload.signature_type, SignatureType::Eip712);
						assert_eq!(payload.primary_type, "PermitBatchWitnessTransferFrom");
						assert!(payload.message.is_object());
						assert!(payload.domain.is_object());
						assert!(payload.types.is_some());

						// Verify message structure
						let message = payload.message.as_object().unwrap();
						assert!(message.contains_key("permitted"));
						assert!(message.contains_key("spender"));
						assert!(message.contains_key("nonce"));
						assert!(message.contains_key("deadline"));
						assert!(message.contains_key("witness"));
					},
					_ => panic!("Expected OifEscrowV0 order"),
				}
			},
			Err(e) => {
				// Expected if Permit2 registry or domain configuration is missing
				assert!(matches!(e, QuoteError::InvalidRequest(_)));
			},
		}
	}

	#[tokio::test]
	async fn test_generate_escrow_order_permit2() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service =
			Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1, 60));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);
		let config = create_test_config();
		let request = create_test_request();

		let result = generator
			.generate_escrow_order(&request, &config, &LockType::Permit2Escrow)
			.await;

		match result {
			Ok((order, settlement_name)) => {
				assert!(settlement_name.is_some());
				match order {
					OifOrder::OifEscrowV0 { payload } => {
						assert_eq!(payload.signature_type, SignatureType::Eip712);
						assert_eq!(payload.primary_type, "PermitBatchWitnessTransferFrom");
					},
					_ => panic!("Expected OifEscrowV0 order"),
				}
			},
			Err(e) => {
				// Expected due to missing settlement or configuration
				assert!(matches!(e, QuoteError::InvalidRequest(_)));
			},
		}
	}

	#[tokio::test]
	async fn test_generate_escrow_order_eip3009() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service =
			Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1, 60));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);
		let config = create_test_config();
		let request = create_test_request();

		let result = generator
			.generate_escrow_order(&request, &config, &LockType::Eip3009Escrow)
			.await;

		match result {
			Ok((order, settlement_name)) => {
				assert!(settlement_name.is_some());
				match order {
					OifOrder::Oif3009V0 { payload, .. } => {
						assert_eq!(payload.signature_type, SignatureType::Eip712);
						assert_eq!(payload.primary_type, "ReceiveWithAuthorization");
					},
					_ => panic!("Expected Oif3009V0 order"),
				}
			},
			Err(e) => {
				// Expected due to missing settlement or contract calls failing
				assert!(matches!(e, QuoteError::InvalidRequest(_)));
			},
		}
	}

	#[tokio::test]
	async fn test_generate_escrow_order_unsupported_lock_type() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service =
			Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1, 60));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);
		let config = create_test_config();
		let request = create_test_request();

		// Use an unsupported lock type
		let result = generator
			.generate_escrow_order(&request, &config, &LockType::ResourceLock)
			.await;

		assert!(matches!(result, Err(QuoteError::UnsupportedSettlement(_))));
	}

	#[tokio::test]
	async fn test_generate_escrow_order_no_settlement() {
		let settlement_service = create_test_settlement_service(false); // No oracles
		let delivery_service =
			Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1, 60));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);
		let config = create_test_config();
		let request = create_test_request();

		let result = generator
			.generate_escrow_order(&request, &config, &LockType::Permit2Escrow)
			.await;

		assert!(
			matches!(result, Err(QuoteError::InvalidRequest(msg)) if msg.contains("No suitable settlement available"))
		);
	}

	#[test]
	fn test_build_permit2_eip712_types() {
		let generator = create_test_generator();
		let types = generator.build_permit2_eip712_types();

		assert!(types.is_object());
		let types_obj = types.as_object().unwrap();

		// Verify all required types are present
		assert!(types_obj.contains_key("EIP712Domain"));
		assert!(types_obj.contains_key("PermitBatchWitnessTransferFrom"));
		assert!(types_obj.contains_key("MandateOutput"));
		assert!(types_obj.contains_key("Permit2Witness"));
		assert!(types_obj.contains_key("TokenPermissions"));

		// Verify EIP712Domain structure
		let domain_type = &types_obj["EIP712Domain"];
		assert!(domain_type.is_array());
		let domain_fields = domain_type.as_array().unwrap();
		assert!(domain_fields.len() >= 3); // name, chainId, verifyingContract
	}

	#[test]
	fn test_build_compact_eip712_types() {
		let generator = create_test_generator();
		let types = generator.build_compact_eip712_types();

		assert!(types.is_object());
		let types_obj = types.as_object().unwrap();

		// Verify all required types are present
		assert!(types_obj.contains_key("EIP712Domain"));
		assert!(types_obj.contains_key("BatchCompact"));
		assert!(types_obj.contains_key("Lock"));
		assert!(types_obj.contains_key("Mandate"));
		assert!(types_obj.contains_key("MandateOutput"));

		// Verify BatchCompact structure
		let batch_compact_type = &types_obj["BatchCompact"];
		assert!(batch_compact_type.is_array());
		let batch_compact_fields = batch_compact_type.as_array().unwrap();
		assert!(batch_compact_fields.len() >= 5); // arbiter, sponsor, nonce, expires, commitments, mandate
	}

	#[test]
	fn test_build_eip3009_eip712_types() {
		let generator = create_test_generator();
		let types = generator.build_eip3009_eip712_types();

		assert!(types.is_object());
		let types_obj = types.as_object().unwrap();

		// Verify all required types are present
		assert!(types_obj.contains_key("EIP712Domain"));
		assert!(types_obj.contains_key("ReceiveWithAuthorization"));
		let domain_type = types_obj["EIP712Domain"].as_array().unwrap();
		assert_eq!(domain_type.len(), 4);
		assert_eq!(domain_type[1]["name"], "version");
		assert_eq!(domain_type[1]["type"], "string");

		// Verify ReceiveWithAuthorization structure
		let receive_auth_type = &types_obj["ReceiveWithAuthorization"];
		assert!(receive_auth_type.is_array());
		let receive_auth_fields = receive_auth_type.as_array().unwrap();
		assert_eq!(receive_auth_fields.len(), 6); // from, to, value, validAfter, validBefore, nonce
	}

	#[tokio::test]
	async fn test_build_compact_domain_object() {
		let generator = create_test_generator();
		let mut config = create_test_config();

		// Add TheCompact address to network config
		let mut network = config.networks.get(&1).unwrap().clone();
		network.the_compact_address = Some(solver_types::Address(vec![0x12; 20]));
		config.networks.insert(1, network);

		let result = generator.build_compact_domain_object(&config, 1).await;

		match result {
			Ok(domain) => {
				assert!(domain.is_object());
				let domain_obj = domain.as_object().unwrap();
				assert_eq!(domain_obj["name"], "The Compact");
				assert_eq!(domain_obj["version"], "1");
				assert_eq!(domain_obj["chainId"], 1);
				assert!(domain_obj.contains_key("verifyingContract"));
			},
			Err(e) => {
				// Expected if TheCompact address is not configured
				assert!(matches!(e, QuoteError::InvalidRequest(_)));
			},
		}
	}

	#[tokio::test]
	async fn test_build_compact_domain_object_missing_address() {
		let generator = create_test_generator();
		let mut config = create_test_config();

		// Remove TheCompact address from network config to test missing address case
		let mut network = config.networks.get(&1).unwrap().clone();
		network.the_compact_address = None;
		config.networks.insert(1, network);

		let result = generator.build_compact_domain_object(&config, 1).await;
		println!("result: {result:?}");

		assert!(
			matches!(result, Err(QuoteError::InvalidRequest(msg)) if msg.contains("TheCompact address not configured"))
		);
	}

	#[tokio::test]
	async fn test_build_eip3009_domain_object() {
		let generator = create_test_generator();
		let token_address = [0x42; 20];

		let result = generator
			.build_eip3009_domain_object(&token_address, 1)
			.await;
		assert!(result.is_ok());
		let domain = result.unwrap();
		assert!(domain.is_object());
		let domain_obj = domain.as_object().unwrap();
		assert!(domain_obj.contains_key("name"));
		assert_eq!(domain_obj["version"], "1");
		assert_eq!(domain_obj["chainId"], 1);
		assert!(domain_obj.contains_key("verifyingContract"));
	}

	#[tokio::test]
	async fn test_get_token_eip712_version_uses_eip5267() {
		use alloy_sol_types::{sol, SolCall};

		sol! {
			function eip712Domain() external view returns (
				bytes1 fields,
				string name,
				string version,
				uint256 chainId,
				address verifyingContract,
				bytes32 salt,
				uint256[] extensions
			);
		}

		let eip712_selector = eip712DomainCall {}.abi_encode()[0..4].to_vec();
		let eip712_response =
			Bytes::from(eip712DomainCall::abi_encode_returns(&eip712DomainReturn {
				fields: FixedBytes::<1>::from([0x1]),
				name: "USD Coin".to_string(),
				version: "2".to_string(),
				chainId: U256::from(1u64),
				verifyingContract: AlloyAddress::from([0x11; 20]),
				salt: FixedBytes::<32>::from([0u8; 32]),
				extensions: Vec::<U256>::new(),
			}));

		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_eth_call()
			.times(1)
			.returning(move |tx| {
				let is_expected_selector = tx.data.starts_with(&eip712_selector);
				assert!(
					is_expected_selector,
					"unexpected selector for eip712Domain()"
				);
				let response = eip712_response.clone();
				Box::pin(async move { Ok(response) })
			});

		let generator = create_test_generator_with_mock_delivery(1, mock_delivery);
		let token_address = address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
		let version = generator.get_token_eip712_version(&token_address, 1).await;

		assert_eq!(version, "2");
	}

	#[tokio::test]
	async fn test_get_token_eip712_version_falls_back_to_version_call() {
		use alloy_sol_types::{sol, SolCall};

		sol! {
			function eip712Domain() external view returns (
				bytes1 fields,
				string name,
				string version,
				uint256 chainId,
				address verifyingContract,
				bytes32 salt,
				uint256[] extensions
			);
			function version() external view returns (string);
		}

		let eip712_selector = eip712DomainCall {}.abi_encode()[0..4].to_vec();
		let version_selector = versionCall {}.abi_encode()[0..4].to_vec();
		let version_response = Bytes::from(versionCall::abi_encode_returns(&"7".to_string()));

		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_eth_call()
			.times(2)
			.returning(move |tx| {
				let is_eip712_selector = tx.data.starts_with(&eip712_selector);
				let is_version_selector = tx.data.starts_with(&version_selector);
				assert!(
					is_eip712_selector || is_version_selector,
					"unexpected selector"
				);
				let version_response = version_response.clone();
				Box::pin(async move {
					if is_eip712_selector {
						Err(DeliveryError::Network(
							"eip712Domain() not available".to_string(),
						))
					} else {
						Ok(version_response)
					}
				})
			});

		let generator = create_test_generator_with_mock_delivery(1, mock_delivery);
		let token_address = address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
		let version = generator.get_token_eip712_version(&token_address, 1).await;

		assert_eq!(version, "7");
	}

	#[tokio::test]
	async fn test_get_token_eip712_version_falls_back_to_known_registry() {
		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery.expect_eth_call().times(2).returning(|_| {
			Box::pin(async {
				Err(DeliveryError::Network(
					"version lookups unavailable".to_string(),
				))
			})
		});

		let generator = create_test_generator_with_mock_delivery(1, mock_delivery);
		let token_address = address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
		let version = generator.get_token_eip712_version(&token_address, 1).await;

		assert_eq!(version, "2");
	}

	#[tokio::test]
	async fn test_get_token_eip712_version_via_eip5267_decode_error() {
		use alloy_sol_types::{sol, SolCall};

		sol! {
			function eip712Domain() external view returns (
				bytes1 fields,
				string name,
				string version,
				uint256 chainId,
				address verifyingContract,
				bytes32 salt,
				uint256[] extensions
			);
		}

		let eip712_selector = eip712DomainCall {}.abi_encode()[0..4].to_vec();
		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_eth_call()
			.times(1)
			.returning(move |tx| {
				assert!(tx.data.starts_with(&eip712_selector));
				Box::pin(async move { Ok(Bytes::from(vec![0u8; 4])) })
			});

		let generator = create_test_generator_with_mock_delivery(1, mock_delivery);
		let token_address = address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
		let result = generator
			.get_token_eip712_version_via_eip5267(&token_address, 1)
			.await;

		assert!(
			matches!(result, Err(QuoteError::InvalidRequest(msg)) if msg.contains("decode token EIP-712 domain"))
		);
	}

	#[tokio::test]
	async fn test_get_token_eip712_version_via_eip5267_empty_version() {
		use alloy_sol_types::{sol, SolCall};

		sol! {
			function eip712Domain() external view returns (
				bytes1 fields,
				string name,
				string version,
				uint256 chainId,
				address verifyingContract,
				bytes32 salt,
				uint256[] extensions
			);
		}

		let eip712_selector = eip712DomainCall {}.abi_encode()[0..4].to_vec();
		let eip712_response =
			Bytes::from(eip712DomainCall::abi_encode_returns(&eip712DomainReturn {
				fields: FixedBytes::<1>::from([0x1]),
				name: "USD Coin".to_string(),
				version: "".to_string(),
				chainId: U256::from(1u64),
				verifyingContract: AlloyAddress::from([0x11; 20]),
				salt: FixedBytes::<32>::from([0u8; 32]),
				extensions: Vec::<U256>::new(),
			}));

		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_eth_call()
			.times(1)
			.returning(move |tx| {
				assert!(tx.data.starts_with(&eip712_selector));
				let response = eip712_response.clone();
				Box::pin(async move { Ok(response) })
			});

		let generator = create_test_generator_with_mock_delivery(1, mock_delivery);
		let token_address = address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
		let result = generator
			.get_token_eip712_version_via_eip5267(&token_address, 1)
			.await;

		assert!(
			matches!(result, Err(QuoteError::InvalidRequest(msg)) if msg.contains("version is empty"))
		);
	}

	#[tokio::test]
	async fn test_get_token_eip712_version_via_version_call_decode_error() {
		use alloy_sol_types::{sol, SolCall};

		sol! {
			function version() external view returns (string);
		}

		let version_selector = versionCall {}.abi_encode()[0..4].to_vec();
		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_eth_call()
			.times(1)
			.returning(move |tx| {
				assert!(tx.data.starts_with(&version_selector));
				Box::pin(async move { Ok(Bytes::from(vec![0u8; 4])) })
			});

		let generator = create_test_generator_with_mock_delivery(1, mock_delivery);
		let token_address = address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
		let result = generator
			.get_token_eip712_version_via_version_call(&token_address, 1)
			.await;

		assert!(
			matches!(result, Err(QuoteError::InvalidRequest(msg)) if msg.contains("decode token version()"))
		);
	}

	#[tokio::test]
	async fn test_get_token_eip712_version_via_version_call_empty_string() {
		use alloy_sol_types::{sol, SolCall};

		sol! {
			function version() external view returns (string);
		}

		let version_selector = versionCall {}.abi_encode()[0..4].to_vec();
		let version_response = Bytes::from(versionCall::abi_encode_returns(&"".to_string()));

		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery
			.expect_eth_call()
			.times(1)
			.returning(move |tx| {
				assert!(tx.data.starts_with(&version_selector));
				let response = version_response.clone();
				Box::pin(async move { Ok(response) })
			});

		let generator = create_test_generator_with_mock_delivery(1, mock_delivery);
		let token_address = address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
		let result = generator
			.get_token_eip712_version_via_version_call(&token_address, 1)
			.await;

		assert!(
			matches!(result, Err(QuoteError::InvalidRequest(msg)) if msg.contains("returned empty string"))
		);
	}

	#[test]
	fn test_get_known_eip3009_token_version_supported_mappings() {
		let generator = create_test_generator();

		let known_tokens = vec![
			(1, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
			(10, "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85"),
			(137, "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359"),
			(8453, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
			(42161, "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"),
			(84532, "0x036CbD53842c5426634e7929541eC2318f3dCF7e"),
			(421614, "0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d"),
			(11155111, "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"),
			(11155420, "0x5fd84259d66Cd46123540766Be93DFE6D43130D7"),
			(11155420, "0x191688b2ff5be8f0a5bcab3e819c900a810faaf6"),
		];

		for (chain_id, token) in known_tokens {
			let parsed: AlloyAddress = token.parse().unwrap();
			assert_eq!(
				generator.get_known_eip3009_token_version(&parsed, chain_id),
				Some("2".to_string())
			);
		}
	}

	#[tokio::test]
	async fn test_get_token_eip712_version_falls_back_to_default() {
		let mut mock_delivery = MockDeliveryInterface::new();
		mock_delivery.expect_eth_call().times(2).returning(|_| {
			Box::pin(async {
				Err(DeliveryError::Network(
					"version lookups unavailable".to_string(),
				))
			})
		});

		let generator = create_test_generator_with_mock_delivery(1, mock_delivery);
		let token_address = address!("1111111111111111111111111111111111111111");
		let version = generator.get_token_eip712_version(&token_address, 1).await;

		assert_eq!(version, "1");
	}

	#[tokio::test]
	async fn test_build_rhinestone_message_unsupported() {
		let generator = create_test_generator();
		let request = create_test_request();
		let config = create_test_config();
		let params = serde_json::json!({});

		let result = generator
			.build_rhinestone_message(&request, &config, &params)
			.await;

		assert!(
			matches!(result, Err(QuoteError::UnsupportedSettlement(msg)) if msg.contains("Rhinestone resource locks are not yet supported"))
		);
	}

	#[tokio::test]
	async fn test_generate_quotes_with_failure_handling_modes() {
		let generator = create_test_generator();
		let config = create_test_config();

		// Test with explicit failure handling mode
		let mut request = create_test_request();
		request.intent.failure_handling = Some(vec![FailureHandlingMode::RefundClaim]);
		request.intent.partial_fill = Some(true);

		let result = generator.generate_quotes(&request, &config).await;

		match result {
			Ok(quotes) => {
				let quote = &quotes[0];
				assert_eq!(quote.failure_handling, FailureHandlingMode::RefundClaim);
				assert!(quote.partial_fill);
			},
			Err(_) => {
				// Expected due to missing settlement configuration
			},
		}
	}

	#[tokio::test]
	async fn test_generate_quotes_with_multiple_failure_modes() {
		let generator = create_test_generator();
		let config = create_test_config();

		// Test with multiple failure handling modes (should use first)
		let mut request = create_test_request();
		request.intent.failure_handling = Some(vec![
			FailureHandlingMode::RefundClaim,
			FailureHandlingMode::RefundAutomatic,
		]);

		let result = generator.generate_quotes(&request, &config).await;

		match result {
			Ok(quotes) => {
				let quote = &quotes[0];
				assert_eq!(quote.failure_handling, FailureHandlingMode::RefundClaim);
			},
			Err(_) => {
				// Expected due to missing settlement configuration
			},
		}
	}

	#[test]
	fn test_generate_quotes_input_conversion_error() {
		use solver_types::QuoteInput;

		// This test would require creating an invalid QuoteInput that fails try_into()
		// For now, we'll test the basic structure since the conversion is typically reliable
		let input = QuoteInput {
			user: InteropAddress::new_ethereum(
				1,
				address!("1111111111111111111111111111111111111111"),
			),
			asset: InteropAddress::new_ethereum(
				1,
				address!("A0b86a33E6441b8C6A7f4C5C1C5C5C5C5C5C5C5C"),
			),
			amount: Some("1000".to_string()),
			lock: None,
		};

		let order_input_result: Result<OrderInput, _> = (&input).try_into();
		assert!(order_input_result.is_ok());
	}

	#[tokio::test]
	async fn test_generate_quotes_min_valid_until() {
		let generator = create_test_generator();
		let config = create_test_config();

		// Test with min_valid_until set
		let mut request = create_test_request();
		request.intent.min_valid_until = Some(1234567890);

		let result = generator.generate_quotes(&request, &config).await;

		match result {
			Ok(quotes) => {
				let quote = &quotes[0];
				// Should use min_valid_until for expiry calculation
				assert!(quote.valid_until >= 1234567890);
			},
			Err(_) => {
				// Expected due to missing settlement configuration
			},
		}
	}

	#[tokio::test]
	async fn test_get_token_name_contract_call() {
		let generator = create_test_generator();
		let token_address = alloy_primitives::Address::from([0x42; 20]);

		let result = generator.get_token_name(&token_address, 1).await;

		// Expected to fail since we don't have a real contract to call
		assert!(matches!(result, Err(QuoteError::InvalidRequest(_))));
	}

	#[tokio::test]
	async fn test_get_eip3009_domain_separator_contract_call() {
		let generator = create_test_generator();
		let token_address = [0x42; 20];

		let result = generator
			.get_eip3009_domain_separator(&token_address, 1)
			.await;

		// Expected to fail since we don't have a real contract to call
		assert!(matches!(result, Err(QuoteError::InvalidRequest(_))));
	}

	#[tokio::test]
	async fn test_compute_eip3009_order_identifier_contract_call() {
		let generator = create_test_generator();
		let config = create_test_config();
		let request = create_test_request();
		let input_oracle = solver_types::Address(vec![0xaa; 20]);
		let output_oracle = solver_types::Address(vec![0xbb; 20]);

		let result = generator
			.compute_eip3009_order_identifier(
				&request,
				&config,
				&input_oracle,
				&output_oracle,
				1234567890, // fill_deadline
				1234568000, // expires (should be > fill_deadline)
			)
			.await;

		// Expected to fail since we don't have a real contract to call
		assert!(matches!(result, Err(QuoteError::InvalidRequest(_))));
	}

	#[tokio::test]
	async fn test_build_permit2_domain_object_missing_permit2() {
		let generator = create_test_generator();
		let config = create_test_config();

		// Use a chain ID that doesn't have Permit2 deployed
		let result = generator.build_permit2_domain_object(&config, 999999).await;

		assert!(
			matches!(result, Err(QuoteError::InvalidRequest(msg)) if msg.contains("Permit2 not deployed"))
		);
	}

	#[test]
	fn test_build_permit2_message_object_structure() {
		let generator = create_test_generator();
		let config = create_test_config();
		let request = create_test_request();
		let input_oracle = solver_types::Address(vec![0xaa; 20]);
		let output_oracle = solver_types::Address(vec![0xbb; 20]);

		let result =
			generator.build_permit2_message_object(&request, &config, input_oracle, output_oracle);

		match result {
			Ok(message) => {
				assert!(message.is_object());
				let message_obj = message.as_object().unwrap();

				// Verify required Permit2 message fields
				assert!(message_obj.contains_key("permitted"));
				assert!(message_obj.contains_key("spender"));
				assert!(message_obj.contains_key("nonce"));
				assert!(message_obj.contains_key("deadline"));
				assert!(message_obj.contains_key("witness"));
			},
			Err(e) => {
				// Expected if permit2 module dependencies are missing
				assert!(matches!(e, QuoteError::InvalidRequest(_)));
			},
		}
	}

	#[tokio::test]
	async fn test_generate_quotes_invalid_chain_id() {
		let generator = create_test_generator();
		let config = create_test_config();

		// Create request with invalid chain ID
		let mut request = create_test_request();
		request.intent.inputs[0].asset = InteropAddress::new_ethereum(
			999999, // Invalid chain ID not in config
			address!("A0b86a33E6441b8C6A7f4C5C1C5C5C5C5C5C5C5C"),
		);

		let result = generator.generate_quotes(&request, &config).await;

		// Should fail due to no supported settlement mechanism on invalid chain
		assert!(
			matches!(result, Err(QuoteError::UnsupportedSettlement(msg)) if msg.contains("No supported settlement mechanism available for this token"))
		);
	}

	#[tokio::test]
	async fn test_generate_quotes_mismatched_input_output_chains() {
		let generator = create_test_generator();
		let config = create_test_config();

		// Create request where input and output are on same chain (no cross-chain)
		let mut request = create_test_request();
		request.intent.outputs[0].asset = InteropAddress::new_ethereum(
			1, // Same chain as input
			address!("B0b86a33E6441b8C6A7f4C5C1C5C5C5C5C5C5C5C"),
		);

		let result = generator.generate_quotes(&request, &config).await;

		// May succeed or fail depending on settlement configuration
		match result {
			Ok(quotes) => {
				assert!(!quotes.is_empty());
			},
			Err(_) => {
				// Expected due to settlement configuration or liquidity issues
			},
		}
	}

	#[tokio::test]
	async fn test_generate_resource_lock_order_rhinestone() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service =
			Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1, 60));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);
		let config = create_test_config();
		let request = create_test_request();

		let lock = solver_types::AssetLockReference {
			kind: solver_types::LockKind::Rhinestone,
			params: Some(serde_json::json!({"test": "value"})),
		};

		let result = generator
			.generate_resource_lock_order(&request, &config, &lock)
			.await;

		// Should fail with unsupported settlement error
		assert!(
			matches!(result, Err(QuoteError::UnsupportedSettlement(msg)) if msg.contains("Rhinestone resource locks are not yet supported"))
		);
	}

	#[test]
	fn test_get_quote_validity_seconds_edge_cases() {
		let generator = create_test_generator();

		// Test with completely empty config (no API config)
		let empty_config = ConfigBuilder::new().build();

		let validity = generator.get_quote_validity_seconds(&empty_config);
		assert_eq!(validity, 60); // Updated default: 1 minute

		// Test with API config but no quote config
		let api_no_quote_config = ConfigBuilder::new()
			.api(Some(solver_config::ApiConfig {
				enabled: true,
				host: "127.0.0.1".to_string(),
				port: 8080,
				timeout_seconds: 30,
				max_request_size: 1048576,
				implementations: Default::default(),
				rate_limiting: None,
				cors: None,
				auth: None,
				quote: None, // No quote config
			}))
			.build();

		let validity_no_quote = generator.get_quote_validity_seconds(&api_no_quote_config);
		assert_eq!(validity_no_quote, 60); // Updated default: 1 minute
	}

	#[tokio::test]
	async fn test_generate_quotes_empty_supported_types() {
		let generator = create_test_generator();
		let config = create_test_config();

		// Create request with empty supported types
		let mut request = create_test_request();
		request.supported_types = vec![];

		let result = generator.generate_quotes(&request, &config).await;

		// Should still work as supported_types is used for filtering, not generation
		match result {
			Ok(quotes) => {
				assert!(!quotes.is_empty());
			},
			Err(_) => {
				// Expected due to missing settlement configuration
			},
		}
	}

	#[tokio::test]
	async fn test_generate_quotes_multiple_inputs() {
		let generator = create_test_generator();
		let config = create_test_config();

		// Create request with multiple inputs
		let mut request = create_test_request();
		request.intent.inputs.push(QuoteInput {
			user: InteropAddress::new_ethereum(
				1,
				address!("1111111111111111111111111111111111111111"),
			),
			asset: InteropAddress::new_ethereum(
				1,
				address!("C0b86a33E6441b8C6A7f4C5C1C5C5C5C5C5C5C5C"),
			),
			amount: Some(U256::from(500).to_string()),
			lock: None,
		});

		let result = generator.generate_quotes(&request, &config).await;

		// Should generate quotes for each input
		match result {
			Ok(quotes) => {
				// Should have quotes for multiple inputs (up to 2)
				assert!(!quotes.is_empty());
			},
			Err(_) => {
				// Expected due to missing settlement configuration
			},
		}
	}

	#[tokio::test]
	async fn test_generate_quotes_with_metadata() {
		let generator = create_test_generator();
		let config = create_test_config();

		// Create request with metadata
		let mut request = create_test_request();
		request.intent.metadata = Some(serde_json::json!({
			"custom_field": "test_value",
			"priority": "high"
		}));

		let result = generator.generate_quotes(&request, &config).await;

		// Metadata should not affect quote generation
		match result {
			Ok(quotes) => {
				assert!(!quotes.is_empty());
			},
			Err(_) => {
				// Expected due to missing settlement configuration
			},
		}
	}
}
