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
use solver_types::{GetQuoteRequest, InteropAddress, QuoteError};
use solver_config::Config;

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
		let has_valid_input = request.available_inputs.iter().any(|input| {
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
		for output in &request.requested_outputs {
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
		if request.available_inputs.is_empty() {
			return Err(QuoteError::InvalidRequest(
				"At least one available input is required".to_string(),
			));
		}

		// Check that we have at least one requested output
		if request.requested_outputs.is_empty() {
			return Err(QuoteError::InvalidRequest(
				"At least one requested output is required".to_string(),
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
		for input in &request.available_inputs {
			Self::validate_interop_address(&input.user)?;
			Self::validate_interop_address(&input.asset)?;

			// Check that amount is positive
			if input.amount == U256::ZERO {
				return Err(QuoteError::InvalidRequest(
					"Input amount must be greater than zero".to_string(),
				));
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
		for output in &request.requested_outputs {
			Self::validate_interop_address(&output.receiver)?;
			Self::validate_interop_address(&output.asset)?;

			if output.amount == U256::ZERO {
				return Err(QuoteError::InvalidRequest(
					"Output amount must be greater than zero".to_string(),
				));
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

		// Additional validation could include:
		// - Chain-specific address validation
		// - Token contract existence checks
		// - Supported chain verification

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
        config: &Config,
    ) -> Result<Vec<SupportedAsset>, QuoteError> {
		let mut supported_assets = Vec::new();

		for input in &request.available_inputs {
			let (chain_id, evm_addr) = Self::extract_chain_and_address(&input.asset)?;
            let allow_unknown = config
                .api
                .as_ref()
                .and_then(|api| api.quote.as_ref())
                .map(|q| q.allow_unknown_tokens)
                .unwrap_or(false);

            if allow_unknown || Self::is_token_supported(solver, chain_id, &evm_addr) {
				supported_assets.push(SupportedAsset {
					asset: input.asset.clone(),
					amount: input.amount,
				});
			}
		}

		if supported_assets.is_empty() {
			return Err(QuoteError::UnsupportedAsset(
				"None of the provided availableInputs are supported".to_string(),
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
        config: &Config,
    ) -> Result<Vec<SupportedAsset>, QuoteError> {
		let mut supported_outputs = Vec::new();

		for output in &request.requested_outputs {
			let (chain_id, evm_addr) = Self::extract_chain_and_address(&output.asset)?;
            let allow_unknown = config
                .api
                .as_ref()
                .and_then(|api| api.quote.as_ref())
                .map(|q| q.allow_unknown_tokens)
                .unwrap_or(false);

            if !allow_unknown && !Self::is_token_supported(solver, chain_id, &evm_addr) {
				return Err(QuoteError::UnsupportedAsset(format!(
					"Requested output token not supported on chain {}",
					chain_id
				)));
			}

			supported_outputs.push(SupportedAsset {
				asset: output.asset.clone(),
				amount: output.amount,
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
