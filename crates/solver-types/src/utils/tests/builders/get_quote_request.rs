//! Builder for GetQuoteRequest
//!
//! Provides a fluent API for constructing GetQuoteRequest instances with
//! proper validation and sensible defaults.

use crate::api::{AvailableInput, GetQuoteRequest, QuotePreference, RequestedOutput};
use crate::standards::eip7930::InteropAddress;
use alloy_primitives::Address as AlloyAddress;

/// Builder for creating `GetQuoteRequest` instances with a fluent API.
///
/// Provides an easy way to construct quote requests with proper validation
/// and sensible defaults for API requests.
///
/// # Examples
///
/// ```
/// use solver_types::utils::builders::GetQuoteRequestBuilder;
/// use solver_types::api::QuotePreference;
///
/// let request = GetQuoteRequestBuilder::new()
///     .user_ethereum(1, address!("1111111111111111111111111111111111111111"))
///     .preference(QuotePreference::Price)
///     .min_valid_until(1234567890)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct GetQuoteRequestBuilder {
	user: Option<InteropAddress>,
	available_inputs: Vec<AvailableInput>,
	requested_outputs: Vec<RequestedOutput>,
	min_valid_until: Option<u64>,
	preference: Option<QuotePreference>,
}

impl Default for GetQuoteRequestBuilder {
	fn default() -> Self {
		Self::new()
	}
}

impl GetQuoteRequestBuilder {
	/// Creates a new `GetQuoteRequestBuilder` with default values.
	pub fn new() -> Self {
		Self {
			user: None,
			available_inputs: Vec::new(),
			requested_outputs: Vec::new(),
			min_valid_until: None,
			preference: None,
		}
	}

	/// Sets the user address using an InteropAddress.
	pub fn user(mut self, user: InteropAddress) -> Self {
		self.user = Some(user);
		self
	}

	/// Sets the user address for Ethereum.
	pub fn user_ethereum(mut self, chain_id: u64, address: AlloyAddress) -> Self {
		self.user = Some(InteropAddress::new_ethereum(chain_id, address));
		self
	}

	/// Sets the user address from a hex string for Ethereum.
	pub fn user_ethereum_hex(
		mut self,
		chain_id: u64,
		hex: &str,
	) -> Result<Self, GetQuoteRequestBuilderError> {
		let hex = hex.strip_prefix("0x").unwrap_or(hex);
		let bytes = hex::decode(hex)
			.map_err(|_| GetQuoteRequestBuilderError::InvalidAddress(hex.to_string()))?;
		if bytes.len() != 20 {
			return Err(GetQuoteRequestBuilderError::InvalidAddress(hex.to_string()));
		}
		let mut addr_bytes = [0u8; 20];
		addr_bytes.copy_from_slice(&bytes);
		let address = AlloyAddress::from(addr_bytes);
		self.user = Some(InteropAddress::new_ethereum(chain_id, address));
		Ok(self)
	}

	/// Adds an available input.
	pub fn add_available_input(mut self, input: AvailableInput) -> Self {
		self.available_inputs.push(input);
		self
	}

	/// Sets all available inputs, replacing any existing ones.
	pub fn available_inputs(mut self, inputs: Vec<AvailableInput>) -> Self {
		self.available_inputs = inputs;
		self
	}

	/// Clears all available inputs.
	pub fn clear_available_inputs(mut self) -> Self {
		self.available_inputs.clear();
		self
	}

	/// Adds a requested output.
	pub fn add_requested_output(mut self, output: RequestedOutput) -> Self {
		self.requested_outputs.push(output);
		self
	}

	/// Sets all requested outputs, replacing any existing ones.
	pub fn requested_outputs(mut self, outputs: Vec<RequestedOutput>) -> Self {
		self.requested_outputs = outputs;
		self
	}

	/// Clears all requested outputs.
	pub fn clear_requested_outputs(mut self) -> Self {
		self.requested_outputs.clear();
		self
	}

	/// Sets the minimum validity duration.
	pub fn min_valid_until(mut self, timestamp: u64) -> Self {
		self.min_valid_until = Some(timestamp);
		self
	}

	/// Clears the minimum validity duration.
	pub fn no_min_valid_until(mut self) -> Self {
		self.min_valid_until = None;
		self
	}

	/// Sets the quote preference.
	pub fn preference(mut self, preference: QuotePreference) -> Self {
		self.preference = Some(preference);
		self
	}

	/// Clears the quote preference.
	pub fn no_preference(mut self) -> Self {
		self.preference = None;
		self
	}

	/// Validates the builder state and returns an error if required fields are missing.
	pub fn validate(&self) -> Result<(), GetQuoteRequestBuilderError> {
		if self.user.is_none() {
			return Err(GetQuoteRequestBuilderError::MissingField("user"));
		}
		Ok(())
	}

	/// Builds the `GetQuoteRequest` with the configured values.
	///
	/// # Panics
	///
	/// Panics if required fields are not set.
	/// Use `try_build()` for error handling instead of panicking.
	pub fn build(self) -> GetQuoteRequest {
		self.try_build()
			.expect("Missing required fields or invalid configuration")
	}

	/// Tries to build the `GetQuoteRequest` with the configured values.
	///
	/// Returns an error if required fields are missing.
	pub fn try_build(self) -> Result<GetQuoteRequest, GetQuoteRequestBuilderError> {
		self.validate()?;

		Ok(GetQuoteRequest {
			user: self.user.unwrap(),
			available_inputs: self.available_inputs,
			requested_outputs: self.requested_outputs,
			min_valid_until: self.min_valid_until,
			preference: self.preference,
		})
	}
}

/// Errors that can occur when building a GetQuoteRequest.
#[derive(Debug, thiserror::Error)]
pub enum GetQuoteRequestBuilderError {
	#[error("Missing required field: {0}")]
	MissingField(&'static str),
	#[error("Invalid address: {0}")]
	InvalidAddress(String),
}
