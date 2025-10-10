//! Builder for Eip7683OrderData
//!
//! Provides a fluent API for constructing Eip7683OrderData instances with
//! proper validation and sensible defaults.

use crate::standards::eip7683::{Eip7683OrderData, GasLimitOverrides, LockType, MandateOutput};
use alloy_primitives::U256;

// Constants for token amounts with 18 decimals
const TOKENS_18_DECIMALS: u128 = 1_000_000_000_000_000_000;
const DEFAULT_INPUT_AMOUNT_TOKENS: u128 = 100;
const DEFAULT_OUTPUT_AMOUNT_TOKENS: u128 = 95;

/// Builder for creating `Eip7683OrderData` instances with a fluent API.
///
/// Provides an easy way to construct EIP-7683 order data with proper validation
/// and sensible defaults for cross-chain orders.
///
/// # Examples
///
/// ```text
/// use solver_types::standards::eip7683::builders::Eip7683OrderDataBuilder;
/// use alloy_primitives::U256;
///
/// let order = Eip7683OrderDataBuilder::new()
///     .user("0x1234567890123456789012345678901234567890")
///     .nonce(U256::from(123))
///     .origin_chain_id(U256::from(1))
///     .expires(1234567890)
///     .fill_deadline(1234567900)
///     .input_oracle("0xoracle123")
///     .add_input(U256::from(1), U256::from(1000))
///     .order_id([5u8; 32])
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct Eip7683OrderDataBuilder {
	user: Option<String>,
	nonce: Option<U256>,
	origin_chain_id: Option<U256>,
	expires: Option<u32>,
	fill_deadline: Option<u32>,
	input_oracle: Option<String>,
	inputs: Vec<[U256; 2]>,
	order_id: Option<[u8; 32]>,
	gas_limit_overrides: GasLimitOverrides,
	outputs: Vec<MandateOutput>,
	raw_order_data: Option<String>,
	signature: Option<String>,
	sponsor: Option<String>,
	lock_type: Option<LockType>,
}

impl Default for Eip7683OrderDataBuilder {
	fn default() -> Self {
		Self::new()
	}
}

impl Eip7683OrderDataBuilder {
	/// Creates a new `Eip7683OrderDataBuilder` with default values.
	pub fn new() -> Self {
		Self {
			user: Some("0x1234567890123456789012345678901234567890".to_string()),
			nonce: Some(U256::from(1)),
			origin_chain_id: Some(U256::from(1)),
			expires: Some(
				(std::time::SystemTime::now()
					.duration_since(std::time::UNIX_EPOCH)
					.unwrap()
					.as_secs() + 3600) as u32,
			),
			fill_deadline: Some(
				(std::time::SystemTime::now()
					.duration_since(std::time::UNIX_EPOCH)
					.unwrap()
					.as_secs() + 1800) as u32,
			),
			input_oracle: Some("0x0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A".to_string()),
			inputs: vec![[
				U256::from(1000),
				U256::from(DEFAULT_INPUT_AMOUNT_TOKENS * TOKENS_18_DECIMALS),
			]],
			order_id: Some([1u8; 32]),
			gas_limit_overrides: GasLimitOverrides::default(),
			outputs: vec![MandateOutput {
				oracle: [0u8; 32],
				settler: [0u8; 32],
				chain_id: U256::from(137),
				token: [0u8; 32],
				amount: U256::from(DEFAULT_OUTPUT_AMOUNT_TOKENS * TOKENS_18_DECIMALS),
				recipient: [0u8; 32],
				call: vec![],
				context: vec![],
			}],
			raw_order_data: None,
			signature: None,
			sponsor: None,
			lock_type: None,
		}
	}

	/// Sets the user address initiating the cross-chain order.
	pub fn user<S: Into<String>>(mut self, user: S) -> Self {
		self.user = Some(user.into());
		self
	}

	/// Sets the unique nonce to prevent order replay attacks.
	pub fn nonce(mut self, nonce: U256) -> Self {
		self.nonce = Some(nonce);
		self
	}

	/// Sets the chain ID where the order originates.
	pub fn origin_chain_id(mut self, chain_id: U256) -> Self {
		self.origin_chain_id = Some(chain_id);
		self
	}

	/// Sets the Unix timestamp when the order expires.
	pub fn expires(mut self, expires: u32) -> Self {
		self.expires = Some(expires);
		self
	}

	/// Sets the deadline by which the order must be filled.
	pub fn fill_deadline(mut self, deadline: u32) -> Self {
		self.fill_deadline = Some(deadline);
		self
	}

	/// Sets the address of the oracle responsible for validating fills.
	pub fn input_oracle<S: Into<String>>(mut self, oracle: S) -> Self {
		self.input_oracle = Some(oracle.into());
		self
	}

	/// Adds an input token and amount pair.
	pub fn add_input(mut self, token: U256, amount: U256) -> Self {
		self.inputs.push([token, amount]);
		self
	}

	/// Sets all input tokens and amounts at once.
	pub fn inputs(mut self, inputs: Vec<[U256; 2]>) -> Self {
		self.inputs = inputs;
		self
	}

	/// Clears all inputs.
	pub fn clear_inputs(mut self) -> Self {
		self.inputs.clear();
		self
	}

	/// Sets the unique 32-byte identifier for the order.
	pub fn order_id(mut self, order_id: [u8; 32]) -> Self {
		self.order_id = Some(order_id);
		self
	}

	/// Sets the gas limit overrides for transaction execution.
	pub fn gas_limit_overrides(mut self, overrides: GasLimitOverrides) -> Self {
		self.gas_limit_overrides = overrides;
		self
	}

	/// Adds an output to the order.
	pub fn add_output(mut self, output: MandateOutput) -> Self {
		self.outputs.push(output);
		self
	}

	/// Sets all outputs at once.
	pub fn outputs(mut self, outputs: Vec<MandateOutput>) -> Self {
		self.outputs = outputs;
		self
	}

	/// Clears all outputs.
	pub fn clear_outputs(mut self) -> Self {
		self.outputs.clear();
		self
	}

	/// Sets the raw order data (StandardOrder encoded as bytes).
	pub fn raw_order_data<S: Into<String>>(mut self, data: S) -> Self {
		self.raw_order_data = Some(data.into());
		self
	}

	/// Clears the raw order data.
	pub fn clear_raw_order_data(mut self) -> Self {
		self.raw_order_data = None;
		self
	}

	/// Sets the signature for off-chain order validation.
	pub fn signature<S: Into<String>>(mut self, signature: S) -> Self {
		self.signature = Some(signature.into());
		self
	}

	/// Clears the signature.
	pub fn clear_signature(mut self) -> Self {
		self.signature = None;
		self
	}

	/// Sets the sponsor address for off-chain orders.
	pub fn sponsor<S: Into<String>>(mut self, sponsor: S) -> Self {
		self.sponsor = Some(sponsor.into());
		self
	}

	/// Clears the sponsor.
	pub fn clear_sponsor(mut self) -> Self {
		self.sponsor = None;
		self
	}

	/// Sets the lock type determining the custody mechanism.
	pub fn lock_type(mut self, lock_type: LockType) -> Self {
		self.lock_type = Some(lock_type);
		self
	}

	/// Clears the lock type.
	pub fn clear_lock_type(mut self) -> Self {
		self.lock_type = None;
		self
	}

	/// Validates the builder state and returns an error if required fields are missing.
	pub fn validate(&self) -> Result<(), Eip7683OrderDataBuilderError> {
		if self.user.is_none() {
			return Err(Eip7683OrderDataBuilderError::MissingField("user"));
		}
		if self.nonce.is_none() {
			return Err(Eip7683OrderDataBuilderError::MissingField("nonce"));
		}
		if self.origin_chain_id.is_none() {
			return Err(Eip7683OrderDataBuilderError::MissingField(
				"origin_chain_id",
			));
		}
		if self.expires.is_none() {
			return Err(Eip7683OrderDataBuilderError::MissingField("expires"));
		}
		if self.fill_deadline.is_none() {
			return Err(Eip7683OrderDataBuilderError::MissingField("fill_deadline"));
		}
		if self.input_oracle.is_none() {
			return Err(Eip7683OrderDataBuilderError::MissingField("input_oracle"));
		}
		if self.order_id.is_none() {
			return Err(Eip7683OrderDataBuilderError::MissingField("order_id"));
		}
		if self.inputs.is_empty() {
			return Err(Eip7683OrderDataBuilderError::EmptyInputs);
		}
		if self.outputs.is_empty() {
			return Err(Eip7683OrderDataBuilderError::EmptyOutputs);
		}
		Ok(())
	}

	/// Builds the `Eip7683OrderData` with the configured values.
	///
	/// # Panics
	///
	/// Panics if required fields are not set or if inputs/outputs are empty.
	/// Use `try_build()` for error handling instead of panicking.
	pub fn build(self) -> Eip7683OrderData {
		self.try_build()
			.expect("Missing required fields or empty inputs/outputs")
	}

	/// Tries to build the `Eip7683OrderData` with the configured values.
	///
	/// Returns an error if required fields are missing or if inputs/outputs are empty.
	pub fn try_build(self) -> Result<Eip7683OrderData, Eip7683OrderDataBuilderError> {
		self.validate()?;

		Ok(Eip7683OrderData {
			user: self.user.unwrap(),
			nonce: self.nonce.unwrap(),
			origin_chain_id: self.origin_chain_id.unwrap(),
			expires: self.expires.unwrap(),
			fill_deadline: self.fill_deadline.unwrap(),
			input_oracle: self.input_oracle.unwrap(),
			inputs: self.inputs,
			order_id: self.order_id.unwrap(),
			gas_limit_overrides: self.gas_limit_overrides,
			outputs: self.outputs,
			raw_order_data: self.raw_order_data,
			signature: self.signature,
			sponsor: self.sponsor,
			lock_type: self.lock_type,
		})
	}
}

/// Errors that can occur when building an Eip7683OrderData.
#[derive(Debug, thiserror::Error)]
pub enum Eip7683OrderDataBuilderError {
	#[error("Missing required field: {0}")]
	MissingField(&'static str),
	#[error("Inputs cannot be empty")]
	EmptyInputs,
	#[error("Outputs cannot be empty")]
	EmptyOutputs,
}
