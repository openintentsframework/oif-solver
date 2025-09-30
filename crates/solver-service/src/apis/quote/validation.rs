//! Quote Request Validation Module
//!
//! This module provides comprehensive validation for incoming quote requests in the OIF solver system.
//! It ensures all parameters meet the required constraints and that the solver has the necessary
//! capabilities to fulfill the requested quotes.
//!
//! # Validation Pipeline
//!
//! The validation process consists of several stages:
//! 1. **Basic Structure** - Ensures required fields are present and non-empty
//! 2. **Address Validation** - Validates ERC-7930 interoperable addresses
//! 3. **Network Support** - Verifies chains are configured with appropriate settlers
//! 4. **Token Support** - Confirms tokens are supported on their respective chains
//! 5. **Balance Checks** - Ensures solver has sufficient liquidity

use alloy_primitives::{Address as AlloyAddress, U256};
use futures::future::try_join_all;
use solver_core::SolverEngine;
use solver_types::{
	AuthScheme, CostContext, GetQuoteRequest, IntentRequest, IntentType, InteropAddress,
	QuoteError, SwapType, ValidatedQuoteContext,
};

/// Main validator for quote requests.
///
/// This struct provides static methods for validating various aspects of quote requests,
/// from basic structure validation to complex capability checks.
pub struct QuoteValidator;

/// Represents a validated asset that has been confirmed to be supported by the solver.
///
/// This struct is created after successful validation and contains only the
/// necessary information for subsequent processing stages.
#[derive(Debug, Clone)]
pub struct SupportedAsset {
	pub asset: InteropAddress,
	pub amount: U256,
}

impl QuoteValidator {
	pub fn validate_quote_request(
		request: &GetQuoteRequest,
		solver: &SolverEngine,
	) -> Result<ValidatedQuoteContext, QuoteError> {
		// 1. Intent structure validation
		Self::validate_intent_structure(&request.intent)?;

		// 2. supportedTypes validation
		Self::validate_supported_types(&request.supported_types, solver)?;

		// 3. SwapType-aware input/output validation
		let context = Self::validate_swap_type_logic(&request.intent)?;

		// 4. Lock and auth scheme validation
		Self::validate_capabilities(request, solver, &context)?;

		Ok(context)
	}

	fn validate_intent_structure(intent: &IntentRequest) -> Result<(), QuoteError> {
		// Validate intentType
		if intent.intent_type != IntentType::OifSwap {
			return Err(QuoteError::UnsupportedIntentType(format!(
				"Unsupported intent type: {:?}",
				intent.intent_type
			)));
		}

		// Validate required arrays
		if intent.inputs.is_empty() || intent.outputs.is_empty() {
			return Err(QuoteError::InvalidRequest(
				"inputs and outputs are required".to_string(),
			));
		}

		for input in &intent.inputs {
			Self::validate_interop_address(&input.user)?;
			Self::validate_interop_address(&input.asset)?;
		}

		for output in &intent.outputs {
			Self::validate_interop_address(&output.receiver)?;
			Self::validate_interop_address(&output.asset)?;
		}

		Ok(())
	}

	fn validate_supported_types(
		supported_types: &[String],
		_solver: &SolverEngine,
	) -> Result<(), QuoteError> {
		if supported_types.is_empty() {
			return Err(QuoteError::InvalidRequest(
				"supportedTypes cannot be empty".to_string(),
			));
		}

		// Validate that order types follow the OIF versioning pattern
		for order_type in supported_types {
			if !order_type.starts_with("oif-") || !order_type.contains("-v") {
				return Err(QuoteError::InvalidRequest(format!(
					"Invalid order type format: {}",
					order_type
				)));
			}
		}

		Ok(())
	}

	fn validate_swap_type_logic(
		intent: &IntentRequest,
	) -> Result<ValidatedQuoteContext, QuoteError> {
		let swap_type = intent.swap_type.as_ref().unwrap_or(&SwapType::ExactInput);

		match swap_type {
			SwapType::ExactInput => {
				// Input amounts must be provided
				let mut known_inputs = Vec::new();
				for input in &intent.inputs {
					let amount_u256 = input.amount_as_u256().map_err(|e| {
						QuoteError::InvalidRequest(format!("Invalid amount: {}", e))
					})?;

					if amount_u256.is_none() {
						return Err(QuoteError::MissingInputAmount);
					}

					let amount = amount_u256.unwrap();
					if amount.is_zero() {
						return Err(QuoteError::InvalidRequest(
							"Input amount cannot be zero for exact-input swaps".to_string(),
						));
					}

					known_inputs.push((input.clone(), amount));
				}

				// Output amounts are optional constraints
				let mut constraint_outputs = Vec::new();
				for output in &intent.outputs {
					let amount_u256 = output.amount_as_u256().map_err(|e| {
						QuoteError::InvalidRequest(format!("Invalid amount: {}", e))
					})?;
					constraint_outputs.push((output.clone(), amount_u256));
				}

				Ok(ValidatedQuoteContext {
					swap_type: SwapType::ExactInput,
					known_inputs: Some(known_inputs),
					known_outputs: None,
					constraint_inputs: None,
					constraint_outputs: Some(constraint_outputs),
				})
			},
			SwapType::ExactOutput => {
				// Output amounts must be provided
				let mut known_outputs = Vec::new();
				for output in &intent.outputs {
					let amount_u256 = output.amount_as_u256().map_err(|e| {
						QuoteError::InvalidRequest(format!("Invalid amount: {}", e))
					})?;

					if amount_u256.is_none() {
						return Err(QuoteError::MissingOutputAmount);
					}

					let amount = amount_u256.unwrap();
					if amount.is_zero() {
						return Err(QuoteError::InvalidRequest(
							"Output amount cannot be zero for exact-output swaps".to_string(),
						));
					}

					known_outputs.push((output.clone(), amount));
				}

				// Input amounts are optional constraints
				let mut constraint_inputs = Vec::new();
				for input in &intent.inputs {
					let amount_u256 = input.amount_as_u256().map_err(|e| {
						QuoteError::InvalidRequest(format!("Invalid amount: {}", e))
					})?;
					constraint_inputs.push((input.clone(), amount_u256));
				}

				Ok(ValidatedQuoteContext {
					swap_type: SwapType::ExactOutput,
					known_inputs: None,
					known_outputs: Some(known_outputs),
					constraint_inputs: Some(constraint_inputs),
					constraint_outputs: None,
				})
			},
		}
	}

	fn validate_capabilities(
		request: &GetQuoteRequest,
		_solver: &SolverEngine,
		context: &ValidatedQuoteContext,
	) -> Result<(), QuoteError> {
		// Validate inferred order types match supported types
		Self::validate_order_type_compatibility(request, context)?;

		// Validate auth schemes if specified
		if let Some(origin) = &request.intent.origin_submission {
			Self::validate_auth_schemes(&origin.schemes)?;
		}

		Ok(())
	}

	fn validate_order_type_compatibility(
		request: &GetQuoteRequest,
		_context: &ValidatedQuoteContext,
	) -> Result<(), QuoteError> {
		use solver_types::oif_versions;

		// Check that each input's inferred order type is compatible with supportedTypes
		for input in &request.intent.inputs {
			// Infer the order type with the current version, considering origin submission schemes
			let inferred_order_type = input.infer_order_type_with_origin(
				oif_versions::CURRENT,
				request.intent.origin_submission.as_ref(),
			);

			// Check if the inferred type (with version) is in the supported types list
			if !request.supported_types.contains(&inferred_order_type) {
				return Err(QuoteError::NoMatchingOrderType(format!(
					"Inferred order type '{}' not found in supported types: {:?}",
					inferred_order_type, request.supported_types
				)));
			}
		}

		Ok(())
	}

	fn validate_auth_schemes(schemes: &Option<Vec<AuthScheme>>) -> Result<(), QuoteError> {
		if let Some(schemes) = schemes {
			if schemes.is_empty() {
				return Err(QuoteError::InvalidRequest(
					"Auth schemes cannot be empty if specified".to_string(),
				));
			}
			// Note: We don't validate specific auth schemes here.
			// The solver should attempt to work with whatever auth schemes the user prefers.
			// Actual capability checking happens in custody_strategy.decide_custody()
		}
		Ok(())
	}

	/// Validates that the chains referenced in the request are supported by the solver.
	///
	/// # Validation Policy
	///
	/// - **Available Inputs**: Must be on chains with configured `input_settler_address` (origin chains)
	/// - **Requested Outputs**: Must be on chains with configured `output_settler_address` (destination chains)
	///
	/// At least one input must be on a supported origin chain, while ALL outputs must be
	/// on supported destination chains.
	///
	/// # Arguments
	///
	/// * `request` - The quote request containing chain references
	/// * `solver` - The solver engine with network configuration
	///
	/// # Errors
	///
	/// Returns `QuoteError::UnsupportedAsset` if unsupported chains are detected
	pub fn validate_supported_networks(
		request: &GetQuoteRequest,
		solver: &SolverEngine,
	) -> Result<(), QuoteError> {
		let networks = solver.token_manager().get_networks();

		// Check if any input is on a supported origin chain
		let has_valid_input = request.intent.inputs.iter().any(|input| {
			Self::chain_id_from_interop(&input.asset)
				.ok()
				.and_then(|id| {
					tracing::debug!("Checking input chain ID: {}", id);
					networks.get(&id)
				})
				.is_some_and(|net| !net.input_settler_address.0.is_empty())
		});

		if !has_valid_input {
			return Err(QuoteError::UnsupportedAsset(
				"No supported origin chains in inputs".into(),
			));
		}

		// Validate all outputs are on supported destination chains
		for output in &request.intent.outputs {
			let chain_id = Self::chain_id_from_interop(&output.asset)?;
			let is_dest = networks
				.get(&chain_id)
				.is_some_and(|net| !net.output_settler_address.0.is_empty());

			if !is_dest {
				return Err(QuoteError::UnsupportedAsset(format!(
					"Chain {} not supported as destination",
					chain_id
				)));
			}
		}

		Ok(())
	}

	/// Checks if a specific token is supported by the solver on a given chain.
	///
	/// This method queries the TokenManager to determine if the solver has
	/// configuration for the specified token.
	///
	/// # Arguments
	///
	/// * `solver` - The solver engine containing token configuration
	/// * `chain_id` - The blockchain network ID
	/// * `address` - The token contract address
	fn is_token_supported(solver: &SolverEngine, chain_id: u64, address: &AlloyAddress) -> bool {
		let solver_address = solver_types::Address(address.as_slice().to_vec());
		solver
			.token_manager()
			.is_supported(chain_id, &solver_address)
	}

	/// Validates an ERC-7930 interoperable address.
	///
	/// Ensures the address conforms to the ERC-7930 standard format which
	/// encodes both chain information and the address itself.
	///
	/// # Future Enhancements
	///
	/// Additional validation could include:
	/// - Chain-specific address validation
	/// - Token contract existence checks
	/// - Supported chain verification
	fn validate_interop_address(address: &InteropAddress) -> Result<(), QuoteError> {
		// Validate the interoperable address format
		address.validate().map_err(|e| {
			QuoteError::InvalidRequest(format!("Invalid interoperable address: {}", e))
		})?;

		Ok(())
	}

	fn chain_id_from_interop(addr: &InteropAddress) -> Result<u64, QuoteError> {
		addr.ethereum_chain_id().map_err(|e| {
			QuoteError::InvalidRequest(format!("Invalid chain in interoperable address: {}", e))
		})
	}

	/// Extracts chain ID and EVM address components from an InteropAddress.
	///
	/// Decomposes an ERC-7930 interoperable address into its constituent parts
	/// for use in chain-specific operations.
	///
	/// # Returns
	///
	/// A tuple of (chain_id, evm_address) on success
	fn extract_chain_and_address(addr: &InteropAddress) -> Result<(u64, AlloyAddress), QuoteError> {
		let chain_id = Self::chain_id_from_interop(addr)?;
		let evm_addr = addr
			.ethereum_address()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid asset address: {}", e)))?;
		Ok((chain_id, evm_addr))
	}

	/// Validates and collects input assets using calculated swap amounts from cost context.
	///
	/// Uses the pre-calculated swap amounts from the cost context which represent the
	/// actual amounts needed for the swap. ALL input assets must be supported for
	/// pricing and execution.
	///
	/// # Arguments
	///
	/// * `request` - The quote request containing inputs
	/// * `solver` - The solver engine with token configuration  
	/// * `cost_context` - Contains calculated swap amounts for each asset
	///
	/// # Returns
	///
	/// A vector of `SupportedAsset` with amounts from cost_context.swap_amounts
	///
	/// # Errors
	///
	/// Returns `QuoteError::UnsupportedAsset` if ANY input is not supported
	pub fn validate_and_collect_inputs_with_costs(
		request: &GetQuoteRequest,
		solver: &SolverEngine,
		cost_context: &CostContext,
	) -> Result<Vec<SupportedAsset>, QuoteError> {
		let mut supported_assets = Vec::new();

		for asset_info in &request.intent.inputs {
			let asset_addr = &asset_info.asset;
			let (chain_id, evm_addr) = Self::extract_chain_and_address(asset_addr)?;

			// ALL assets must be supported for proper pricing
			if !Self::is_token_supported(solver, chain_id, &evm_addr) {
				return Err(QuoteError::UnsupportedAsset(format!(
					"Input token not supported on chain {}: {}",
					chain_id,
					alloy_primitives::hex::encode(evm_addr.as_slice())
				)));
			}

			// Use the swap amount from cost context (the calculated base amount)
			let amount = cost_context
				.swap_amounts
				.get(asset_addr)
				.map(|info| info.amount)
				.unwrap_or_else(|| {
					// Fallback to request amount if not in cost context
					asset_info
						.amount_as_u256()
						.map_err(|e| QuoteError::InvalidRequest(format!("Invalid amount: {}", e)))
						.ok()
						.flatten()
						.unwrap_or_default()
				});

			supported_assets.push(SupportedAsset {
				asset: asset_addr.clone(),
				amount,
			});
		}

		Ok(supported_assets)
	}

	/// Validates and collects output assets using calculated swap amounts from cost context.
	///
	/// Uses the pre-calculated swap amounts from the cost context which represent the
	/// actual amounts needed for the swap. ALL output assets must be supported for
	/// pricing and execution.
	///
	/// # Arguments
	///
	/// * `request` - The quote request containing outputs
	/// * `solver` - The solver engine with token configuration
	/// * `cost_context` - Contains calculated swap amounts for each asset
	///
	/// # Returns
	///
	/// A vector of `SupportedAsset` with amounts from cost_context.swap_amounts
	///
	/// # Errors
	///
	/// Returns `QuoteError::UnsupportedAsset` if ANY output is not supported
	pub fn validate_and_collect_outputs_with_costs(
		request: &GetQuoteRequest,
		solver: &SolverEngine,
		cost_context: &CostContext,
	) -> Result<Vec<SupportedAsset>, QuoteError> {
		let mut supported_assets = Vec::new();

		for asset_info in &request.intent.outputs {
			let asset_addr = &asset_info.asset;
			let (chain_id, evm_addr) = Self::extract_chain_and_address(asset_addr)?;

			// ALL assets must be supported for proper pricing
			if !Self::is_token_supported(solver, chain_id, &evm_addr) {
				return Err(QuoteError::UnsupportedAsset(format!(
					"Output token not supported on chain {}: {}",
					chain_id,
					alloy_primitives::hex::encode(evm_addr.as_slice())
				)));
			}

			// Use the swap amount from cost context (the calculated base amount)
			let amount = cost_context
				.swap_amounts
				.get(asset_addr)
				.map(|info| info.amount)
				.unwrap_or_else(|| {
					// Fallback to request amount if not in cost context
					asset_info
						.amount_as_u256()
						.map_err(|e| QuoteError::InvalidRequest(format!("Invalid amount: {}", e)))
						.ok()
						.flatten()
						.unwrap_or_default()
				});

			supported_assets.push(SupportedAsset {
				asset: asset_addr.clone(),
				amount,
			});
		}

		Ok(supported_assets)
	}

	/// Ensures the solver has sufficient balance for all requested destination outputs.
	///
	/// Performs parallel balance checks for all output tokens to verify the solver
	/// has enough liquidity to fulfill the quote. For ExactInput swaps, this should
	/// be called with cost-adjusted output amounts. For ExactOutput swaps, the amounts
	/// remain unchanged.
	///
	/// # Performance
	///
	/// Balance checks are executed in parallel using `futures::try_join_all` for
	/// optimal performance when checking multiple outputs.
	///
	/// # Arguments
	///
	/// * `solver` - The solver engine with token manager
	/// * `outputs` - The validated output assets with cost-adjusted amounts
	/// * `context` - The validated quote context to determine swap type
	/// * `cost_context` - Contains cost amounts for adjusting output requirements
	///
	/// # Errors
	///
	/// Returns `QuoteError::InsufficientLiquidity` if any balance is insufficient.
	/// Returns `QuoteError::Internal` if balance checks fail or parsing errors occur.
	pub async fn ensure_destination_balances_with_costs(
		solver: &SolverEngine,
		outputs: &[SupportedAsset],
		context: &ValidatedQuoteContext,
		cost_context: &CostContext,
	) -> Result<(), QuoteError> {
		let token_manager = solver.token_manager();

		// Create futures for parallel balance checks
		let balance_checks = outputs.iter().map(|output| {
			let output = output.clone();
			async move {
				let (chain_id, evm_addr) = Self::extract_chain_and_address(&output.asset)?;
				let token_addr = solver_types::Address(evm_addr.as_slice().to_vec());

				let balance_str = token_manager
					.check_balance(chain_id, &token_addr)
					.await
					.map_err(|e| QuoteError::Internal(format!("Balance check failed: {}", e)))?;

				let balance = U256::from_str_radix(&balance_str, 10)
					.map_err(|e| QuoteError::Internal(format!("Failed to parse balance: {}", e)))?;

				// For ExactInput swaps, adjust the required amount by subtracting costs
				let required_amount = if matches!(context.swap_type, SwapType::ExactInput) {
					// Check if this is the first output (which bears the cost)
					let is_first = outputs
						.first()
						.map(|first| first.asset == output.asset)
						.unwrap_or(false);

					if is_first {
						// First output: subtract costs from the base amount
						let cost_in_token = cost_context
							.cost_amounts_in_tokens
							.get(&output.asset)
							.map(|info| info.amount)
							.unwrap_or(U256::ZERO);
						output.amount.saturating_sub(cost_in_token)
					} else {
						output.amount
					}
				} else {
					// For ExactOutput, amounts remain unchanged
					output.amount
				};

				if balance < required_amount {
					let token_hex = alloy_primitives::hex::encode(evm_addr.as_slice());
					tracing::error!(
						chain_id = chain_id,
						required = %required_amount,
						available = %balance,
						token = %token_hex,
						"Insufficient destination balance",
					);
					return Err(QuoteError::InsufficientLiquidity);
				} else {
					tracing::debug!(
						chain_id = chain_id,
						required = %required_amount,
						available = %balance,
						token = %alloy_primitives::hex::encode(evm_addr.as_slice()),
						"Sufficient destination balance"
					);
				}

				Ok::<(), QuoteError>(())
			}
		});

		// Execute all balance checks in parallel
		try_join_all(balance_checks).await?;

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::address;
	use solver_types::{IntentType, QuoteInput, QuoteOutput};

	fn create_exact_input_request(
		input_amount: Option<&str>,
		output_amount: Option<&str>,
	) -> IntentRequest {
		IntentRequest {
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
					address!("2b2C76e42a8a6dDA8dF24ecCc6C8a9D3f5506bF1"),
				),
				amount: output_amount.map(|s| s.to_string()),
				calldata: None,
			}],
			swap_type: Some(SwapType::ExactInput),
			min_valid_until: None,
			preference: None,
			origin_submission: None,
			failure_handling: None,
			partial_fill: None,
			metadata: None,
		}
	}

	fn create_exact_output_request(
		input_amount: Option<&str>,
		output_amount: Option<&str>,
	) -> IntentRequest {
		IntentRequest {
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
					address!("2b2C76e42a8a6dDA8dF24ecCc6C8a9D3f5506bF1"),
				),
				amount: output_amount.map(|s| s.to_string()),
				calldata: None,
			}],
			swap_type: Some(SwapType::ExactOutput),
			min_valid_until: None,
			preference: None,
			origin_submission: None,
			failure_handling: None,
			partial_fill: None,
			metadata: None,
		}
	}

	#[test]
	fn test_exact_input_missing_input_amount_fails() {
		// Test: Exact-input missing required input amount
		let intent = create_exact_input_request(
			None, // Missing required input amount
			None,
		);

		let result = QuoteValidator::validate_swap_type_logic(&intent);
		assert!(
			matches!(result, Err(QuoteError::MissingInputAmount)),
			"Should reject missing input amount: {:?}",
			result
		);
	}

	#[test]
	fn test_exact_output_missing_output_amount_fails() {
		// Test: Exact-output missing required output amount
		let intent = create_exact_output_request(
			None, None, // Missing required output amount
		);

		let result = QuoteValidator::validate_swap_type_logic(&intent);
		assert!(
			matches!(result, Err(QuoteError::MissingOutputAmount)),
			"Should reject missing output amount: {:?}",
			result
		);
	}

	#[test]
	fn test_exact_input_zero_input_amount_fails() {
		// Test: Exact-input with zero input amount
		let intent = create_exact_input_request(
			Some("0"), // Zero input amount
			None,
		);

		let result = QuoteValidator::validate_swap_type_logic(&intent);
		assert!(
			matches!(result, Err(QuoteError::InvalidRequest(ref msg)) if msg.contains("cannot be zero")),
			"Should reject zero input amount for exact-input: {:?}",
			result
		);
	}

	#[test]
	fn test_exact_output_zero_output_amount_fails() {
		// Test: Exact-output with zero output amount
		let intent = create_exact_output_request(
			None,
			Some("0"), // Zero output amount
		);

		let result = QuoteValidator::validate_swap_type_logic(&intent);
		assert!(
			matches!(result, Err(QuoteError::InvalidRequest(ref msg)) if msg.contains("cannot be zero")),
			"Should reject zero output amount for exact-output: {:?}",
			result
		);
	}

	#[test]
	fn test_exact_input_with_valid_amounts_succeeds() {
		// Test: Exact-input with valid input amount should succeed
		let intent = create_exact_input_request(
			Some("1000000000000000000"), // 1 token
			None,
		);

		let result = QuoteValidator::validate_swap_type_logic(&intent);
		assert!(
			result.is_ok(),
			"Should accept valid exact-input: {:?}",
			result
		);

		let context = result.unwrap();
		assert!(matches!(context.swap_type, SwapType::ExactInput));
		assert!(context.known_inputs.is_some());
		assert_eq!(context.known_inputs.unwrap().len(), 1);
	}

	#[test]
	fn test_exact_output_with_valid_amounts_succeeds() {
		// Test: Exact-output with valid output amount should succeed
		let intent = create_exact_output_request(
			None,
			Some("1000000000000000000"), // 1 token
		);

		let result = QuoteValidator::validate_swap_type_logic(&intent);
		assert!(
			result.is_ok(),
			"Should accept valid exact-output: {:?}",
			result
		);

		let context = result.unwrap();
		assert!(matches!(context.swap_type, SwapType::ExactOutput));
		assert!(context.known_outputs.is_some());
		assert_eq!(context.known_outputs.unwrap().len(), 1);
	}
}
