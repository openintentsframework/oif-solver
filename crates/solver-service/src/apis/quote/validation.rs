//! Quote Request Validation
//!
//! This module handles validation of incoming quote requests,
//! ensuring all parameters are valid before processing.

use alloy_primitives::U256;
use solver_types::{GetQuoteRequest, InteropAddress, QuoteError};

/// Handles validation of quote requests
pub struct QuoteValidator;

impl QuoteValidator {
	/// Validates the incoming quote request
	pub fn validate_request(request: &GetQuoteRequest) -> Result<(), QuoteError> {
		Self::validate_basic_structure(request)?;
		Self::validate_user_address(request)?;
		Self::validate_inputs(request)?;
		Self::validate_outputs(request)?;
		Ok(())
	}

	/// Validates basic request structure
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

	/// Validates user address
	fn validate_user_address(request: &GetQuoteRequest) -> Result<(), QuoteError> {
		Self::validate_interop_address(&request.user)?;
		Ok(())
	}

	/// Validates input specifications
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

	/// Validates output specifications
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

	/// Validates an ERC-7930 interoperable address
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
}
