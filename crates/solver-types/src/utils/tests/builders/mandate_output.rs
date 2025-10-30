//! Builder for MandateOutput
//!
//! Provides a fluent API for constructing MandateOutput instances with
//! proper validation and sensible defaults.

use crate::standards::eip7683::MandateOutput;
use alloy_primitives::U256;

/// Builder for creating `MandateOutput` instances with a fluent API.
///
/// Provides an easy way to construct mandate outputs with proper validation
/// and sensible defaults for cross-chain order outputs.
///
/// # Examples
///
/// ```text
/// use solver_types::standards::eip7683::builders::MandateOutputBuilder;
/// use alloy_primitives::U256;
///
/// let output = MandateOutputBuilder::new()
///     .chain_id(U256::from(1))
///     .token([1u8; 32])
///     .amount(U256::from(1000))
///     .recipient([2u8; 32])
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct MandateOutputBuilder {
	oracle: [u8; 32],
	settler: [u8; 32],
	chain_id: Option<U256>,
	token: Option<[u8; 32]>,
	amount: Option<U256>,
	recipient: Option<[u8; 32]>,
	call: Vec<u8>,
	context: Vec<u8>,
}

impl Default for MandateOutputBuilder {
	fn default() -> Self {
		Self::new()
	}
}

impl MandateOutputBuilder {
	/// Creates a new `MandateOutputBuilder` with default values.
	pub fn new() -> Self {
		Self {
			oracle: [0u8; 32],
			settler: [0u8; 32],
			chain_id: None,
			token: None,
			amount: None,
			recipient: None,
			call: Vec::new(),
			context: Vec::new(),
		}
	}

	/// Sets the oracle address (bytes32).
	pub fn oracle(mut self, oracle: [u8; 32]) -> Self {
		self.oracle = oracle;
		self
	}

	/// Sets the settler address (bytes32).
	pub fn settler(mut self, settler: [u8; 32]) -> Self {
		self.settler = settler;
		self
	}

	/// Sets the chain ID where the output should be delivered.
	pub fn chain_id(mut self, chain_id: U256) -> Self {
		self.chain_id = Some(chain_id);
		self
	}

	/// Sets the token address (bytes32).
	pub fn token(mut self, token: [u8; 32]) -> Self {
		self.token = Some(token);
		self
	}

	/// Sets the amount of tokens to be received.
	pub fn amount(mut self, amount: U256) -> Self {
		self.amount = Some(amount);
		self
	}

	/// Sets the recipient address (bytes32).
	pub fn recipient(mut self, recipient: [u8; 32]) -> Self {
		self.recipient = Some(recipient);
		self
	}

	/// Sets the call data for settlement callback.
	pub fn call(mut self, call: Vec<u8>) -> Self {
		self.call = call;
		self
	}

	/// Sets the call data from a hex string (with or without 0x prefix).
	pub fn call_hex(mut self, hex: &str) -> Result<Self, hex::FromHexError> {
		let hex = hex.strip_prefix("0x").unwrap_or(hex);
		self.call = hex::decode(hex)?;
		Ok(self)
	}

	/// Sets the context data for settlement.
	pub fn context(mut self, context: Vec<u8>) -> Self {
		self.context = context;
		self
	}

	/// Sets the context data from a hex string (with or without 0x prefix).
	pub fn context_hex(mut self, hex: &str) -> Result<Self, hex::FromHexError> {
		let hex = hex.strip_prefix("0x").unwrap_or(hex);
		self.context = hex::decode(hex)?;
		Ok(self)
	}

	/// Validates the builder state and returns an error if required fields are missing.
	pub fn validate(&self) -> Result<(), MandateOutputBuilderError> {
		if self.chain_id.is_none() {
			return Err(MandateOutputBuilderError::MissingField("chain_id"));
		}
		if self.token.is_none() {
			return Err(MandateOutputBuilderError::MissingField("token"));
		}
		if self.amount.is_none() {
			return Err(MandateOutputBuilderError::MissingField("amount"));
		}
		if self.recipient.is_none() {
			return Err(MandateOutputBuilderError::MissingField("recipient"));
		}
		Ok(())
	}

	/// Builds the `MandateOutput` with the configured values.
	///
	/// # Panics
	///
	/// Panics if required fields (chain_id, token, amount, recipient) are not set.
	/// Use `try_build()` for error handling instead of panicking.
	pub fn build(self) -> MandateOutput {
		self.try_build().expect("Missing required fields")
	}

	/// Tries to build the `MandateOutput` with the configured values.
	///
	/// Returns an error if required fields are missing.
	pub fn try_build(self) -> Result<MandateOutput, MandateOutputBuilderError> {
		self.validate()?;

		Ok(MandateOutput {
			oracle: self.oracle,
			settler: self.settler,
			chain_id: self.chain_id.unwrap(),
			token: self.token.unwrap(),
			amount: self.amount.unwrap(),
			recipient: self.recipient.unwrap(),
			call: self.call,
			context: self.context,
		})
	}
}

/// Errors that can occur when building a MandateOutput.
#[derive(Debug, thiserror::Error)]
pub enum MandateOutputBuilderError {
	#[error("Missing required field: {0}")]
	MissingField(&'static str),
}
