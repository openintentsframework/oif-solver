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
	AuthScheme, GetQuoteRequest, IntentRequest, IntentType, InteropAddress, QuoteError, QuoteInput,
	QuoteOutput, SwapType,
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

/// Rich validation context that replaces simple SupportedAsset lists
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ValidatedQuoteContext {
	pub swap_type: SwapType,
	pub known_inputs: Option<Vec<(QuoteInput, U256)>>,
	pub known_outputs: Option<Vec<(QuoteOutput, U256)>>,
	pub constraint_inputs: Option<Vec<(QuoteInput, Option<U256>)>>,
	pub constraint_outputs: Option<Vec<(QuoteOutput, Option<U256>)>>,
	pub inferred_order_types: Vec<String>,
	pub compatible_auth_schemes: Vec<AuthScheme>,
	pub inputs_for_balance_check: Vec<QuoteInput>,
	pub outputs_for_balance_check: Vec<QuoteOutput>,
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

					known_inputs.push((input.clone(), amount_u256.unwrap()));
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
					inferred_order_types: Vec::new(),
					compatible_auth_schemes: Vec::new(),
					inputs_for_balance_check: intent.inputs.clone(),
					outputs_for_balance_check: vec![], // Can't pre-validate - amounts unknown
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

					known_outputs.push((output.clone(), amount_u256.unwrap()));
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
					inferred_order_types: Vec::new(),
					compatible_auth_schemes: Vec::new(),
					inputs_for_balance_check: vec![], // Can't pre-validate - amounts unknown
					outputs_for_balance_check: intent.outputs.clone(),
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
			// TODO: Check if solver supports these auth schemes
		}
		Ok(())
	}

	// Keep old validation methods for V1 compatibility
	/// Validates the basic structure and content of a quote request.
	///
	/// This performs initial validation including:
	/// - Checking for required fields
	/// - Validating address formats
	/// - Ensuring amounts are positive
	///
	/// # Arguments
	///
	/// * `request` - The quote request to validate
	///
	/// # Errors
	///
	/// Returns `QuoteError::InvalidRequest` if validation fails
	pub fn validate_request(request: &GetQuoteRequest) -> Result<(), QuoteError> {
		Self::validate_basic_structure(request)?;
		Self::validate_user_address(request)?;
		Self::validate_inputs(request)?;
		Self::validate_outputs(request)?;
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

	/// Validates the basic structure of a quote request.
	///
	/// Ensures that the request contains at least one input and one output,
	/// which are fundamental requirements for any quote.
	///
	/// # Errors
	///
	/// Returns `QuoteError::InvalidRequest` if inputs or outputs are empty
	fn validate_basic_structure(request: &GetQuoteRequest) -> Result<(), QuoteError> {
		// Check that we have at least one input
		if request.intent.inputs.is_empty() {
			return Err(QuoteError::InvalidRequest(
				"At least one input is required".to_string(),
			));
		}

		// Check that we have at least one requested output
		if request.intent.outputs.is_empty() {
			return Err(QuoteError::InvalidRequest(
				"At least one output is required".to_string(),
			));
		}

		Ok(())
	}

	/// Validates the user's interoperable address.
	///
	/// Ensures the user address follows the ERC-7930 format and is valid.
	fn validate_user_address(request: &GetQuoteRequest) -> Result<(), QuoteError> {
		Self::validate_interop_address(&request.user)?;
		Ok(())
	}

	/// Validates all input specifications in the request.
	///
	/// Checks each available input for:
	/// - Valid user address format
	/// - Valid asset address format
	/// - Positive amount (non-zero)
	///
	/// # Errors
	///
	/// Returns `QuoteError::InvalidRequest` if any input is invalid
	fn validate_inputs(request: &GetQuoteRequest) -> Result<(), QuoteError> {
		for input in &request.intent.inputs {
			Self::validate_interop_address(&input.user)?;
			Self::validate_interop_address(&input.asset)?;

			// Check that amount is positive if provided
			if let Ok(Some(amount)) = input.amount_as_u256() {
				if amount == U256::ZERO {
					return Err(QuoteError::InvalidRequest(
						"Input amount must be greater than zero".to_string(),
					));
				}
			}
		}
		Ok(())
	}

	/// Validates all output specifications in the request.
	///
	/// Checks each requested output for:
	/// - Valid receiver address format
	/// - Valid asset address format
	/// - Positive amount (non-zero)
	///
	/// # Errors
	///
	/// Returns `QuoteError::InvalidRequest` if any output is invalid
	fn validate_outputs(request: &GetQuoteRequest) -> Result<(), QuoteError> {
		for output in &request.intent.outputs {
			Self::validate_interop_address(&output.receiver)?;
			Self::validate_interop_address(&output.asset)?;

			// Check that amount is positive if provided
			if let Ok(Some(amount)) = output.amount_as_u256() {
				if amount == U256::ZERO {
					return Err(QuoteError::InvalidRequest(
						"Output amount must be greater than zero".to_string(),
					));
				}
			}
		}
		Ok(())
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

	/// Collects and validates supported input assets from the request.
	///
	/// Filters the provided available inputs to include only those tokens that are
	/// configured and supported by the solver. This creates a validated subset
	/// for use in subsequent processing stages.
	///
	/// # Arguments
	///
	/// * `request` - The quote request containing available inputs
	/// * `solver` - The solver engine with token configuration
	///
	/// # Returns
	///
	/// A vector of `SupportedAsset` containing only supported inputs.
	///
	/// # Errors
	///
	/// Returns `QuoteError::UnsupportedAsset` if no inputs are supported
	pub fn collect_supported_available_inputs(
		request: &GetQuoteRequest,
		solver: &SolverEngine,
	) -> Result<Vec<SupportedAsset>, QuoteError> {
		let mut supported_assets = Vec::new();

		for input in &request.intent.inputs {
			let (chain_id, evm_addr) = Self::extract_chain_and_address(&input.asset)?;

			let amount_u256 = input
				.amount_as_u256()
				.map_err(|e| QuoteError::InvalidRequest(format!("Invalid amount: {}", e)))?;

			if Self::is_token_supported(solver, chain_id, &evm_addr) {
				supported_assets.push(SupportedAsset {
					asset: input.asset.clone(),
					amount: amount_u256.unwrap_or_default(),
				});
			}
		}

		if supported_assets.is_empty() {
			return Err(QuoteError::UnsupportedAsset(
				"None of the provided inputs are supported".to_string(),
			));
		}

		Ok(supported_assets)
	}

	/// Validates and collects all requested output assets.
	///
	/// Unlike input validation which allows partial support, this method requires
	/// ALL requested outputs to be supported by the solver. This ensures the solver
	/// can fulfill the complete quote request.
	///
	/// # Arguments
	///
	/// * `request` - The quote request containing requested outputs
	/// * `solver` - The solver engine with token configuration
	///
	/// # Returns
	///
	/// A vector of `SupportedAsset` containing all validated outputs.
	///
	/// # Errors
	///
	/// Returns `QuoteError::UnsupportedAsset` if any output is not supported
	pub fn validate_and_collect_requested_outputs(
		request: &GetQuoteRequest,
		solver: &SolverEngine,
	) -> Result<Vec<SupportedAsset>, QuoteError> {
		let mut supported_outputs = Vec::new();

		for output in &request.intent.outputs {
			let (chain_id, evm_addr) = Self::extract_chain_and_address(&output.asset)?;

			if !Self::is_token_supported(solver, chain_id, &evm_addr) {
				return Err(QuoteError::UnsupportedAsset(format!(
					"Requested output token not supported on chain {}",
					chain_id
				)));
			}

			let amount_u256 = output
				.amount_as_u256()
				.map_err(|e| QuoteError::InvalidRequest(format!("Invalid amount: {}", e)))?;

			supported_outputs.push(SupportedAsset {
				asset: output.asset.clone(),
				amount: amount_u256.unwrap_or_default(),
			});
		}

		Ok(supported_outputs)
	}

	/// Ensures the solver has sufficient balance for all requested destination outputs.
	///
	/// Performs parallel balance checks for all output tokens to verify the solver
	/// has enough liquidity to fulfill the quote. This is a critical pre-flight
	/// check to prevent quote generation for unfulfillable requests.
	///
	/// # Performance
	///
	/// Balance checks are executed in parallel using `futures::try_join_all` for
	/// optimal performance when checking multiple outputs.
	///
	/// # Arguments
	///
	/// * `solver` - The solver engine with token manager
	/// * `outputs` - The validated output assets to check
	///
	/// # Errors
	///
	/// Returns `QuoteError::InsufficientLiquidity` if any balance is insufficient.
	/// Returns `QuoteError::Internal` if balance checks fail or parsing errors occur.
	pub async fn ensure_destination_balances(
		solver: &SolverEngine,
		outputs: &[SupportedAsset],
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

				if balance < output.amount {
					let token_hex = alloy_primitives::hex::encode(evm_addr.as_slice());
					tracing::error!(
						chain_id = chain_id,
						required = %output.amount,
						available = %balance,
						token = %token_hex,
						"Insufficient destination balance",
					);
					return Err(QuoteError::InsufficientLiquidity);
				} else {
					tracing::debug!(
						chain_id = chain_id,
						required = %output.amount,
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
