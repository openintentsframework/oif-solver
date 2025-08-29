//! Builder for RequestedOutput
//!
//! Provides a fluent API for constructing RequestedOutput instances with
//! proper validation and sensible defaults.

use crate::api::RequestedOutput;
use crate::standards::eip7930::InteropAddress;
use alloy_primitives::{Address as AlloyAddress, U256};

/// Builder for creating `RequestedOutput` instances with a fluent API.
///
/// Provides an easy way to construct requested outputs with proper validation
/// and sensible defaults for API requests.
///
/// # Examples
///
/// ```
/// use solver_types::utils::builders::RequestedOutputBuilder;
///
/// let output = RequestedOutputBuilder::new()
///     .receiver_ethereum(1, address!("3333333333333333333333333333333333333333"))
///     .asset_ethereum(1, address!("4444444444444444444444444444444444444444"))
///     .amount_u64(2000)
///     .calldata("0xdeadbeef")
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct RequestedOutputBuilder {
	receiver: Option<InteropAddress>,
	asset: Option<InteropAddress>,
	amount: U256,
	calldata: Option<String>,
}

impl Default for RequestedOutputBuilder {
	fn default() -> Self {
		Self::new()
	}
}

impl RequestedOutputBuilder {
	/// Creates a new `RequestedOutputBuilder` with default values.
	pub fn new() -> Self {
		Self {
			receiver: None,
			asset: None,
			amount: U256::ZERO,
			calldata: None,
		}
	}

	/// Sets the receiver address using an InteropAddress.
	pub fn receiver(mut self, receiver: InteropAddress) -> Self {
		self.receiver = Some(receiver);
		self
	}

	/// Sets the receiver address for Ethereum.
	pub fn receiver_ethereum(mut self, chain_id: u64, address: AlloyAddress) -> Self {
		self.receiver = Some(InteropAddress::new_ethereum(chain_id, address));
		self
	}

	/// Sets the receiver address from a hex string for Ethereum.
	pub fn receiver_ethereum_hex(
		mut self,
		chain_id: u64,
		hex: &str,
	) -> Result<Self, RequestedOutputBuilderError> {
		let hex = hex.strip_prefix("0x").unwrap_or(hex);
		let bytes = hex::decode(hex)
			.map_err(|_| RequestedOutputBuilderError::InvalidAddress(hex.to_string()))?;
		if bytes.len() != 20 {
			return Err(RequestedOutputBuilderError::InvalidAddress(hex.to_string()));
		}
		let mut addr_bytes = [0u8; 20];
		addr_bytes.copy_from_slice(&bytes);
		let address = AlloyAddress::from(addr_bytes);
		self.receiver = Some(InteropAddress::new_ethereum(chain_id, address));
		Ok(self)
	}

	/// Sets the asset address using an InteropAddress.
	pub fn asset(mut self, asset: InteropAddress) -> Self {
		self.asset = Some(asset);
		self
	}

	/// Sets the asset address for Ethereum.
	pub fn asset_ethereum(mut self, chain_id: u64, address: AlloyAddress) -> Self {
		self.asset = Some(InteropAddress::new_ethereum(chain_id, address));
		self
	}

	/// Sets the asset address from a hex string for Ethereum.
	pub fn asset_ethereum_hex(
		mut self,
		chain_id: u64,
		hex: &str,
	) -> Result<Self, RequestedOutputBuilderError> {
		let hex = hex.strip_prefix("0x").unwrap_or(hex);
		let bytes = hex::decode(hex)
			.map_err(|_| RequestedOutputBuilderError::InvalidAddress(hex.to_string()))?;
		if bytes.len() != 20 {
			return Err(RequestedOutputBuilderError::InvalidAddress(hex.to_string()));
		}
		let mut addr_bytes = [0u8; 20];
		addr_bytes.copy_from_slice(&bytes);
		let address = AlloyAddress::from(addr_bytes);
		self.asset = Some(InteropAddress::new_ethereum(chain_id, address));
		Ok(self)
	}

	/// Sets the amount.
	pub fn amount(mut self, amount: U256) -> Self {
		self.amount = amount;
		self
	}

	/// Sets the amount from a u64.
	pub fn amount_u64(mut self, amount: u64) -> Self {
		self.amount = U256::from(amount);
		self
	}

	/// Sets the amount from a string (decimal).
	pub fn amount_str(mut self, amount: &str) -> Result<Self, RequestedOutputBuilderError> {
		let parsed = U256::from_str_radix(amount, 10)
			.map_err(|_| RequestedOutputBuilderError::InvalidAmount(amount.to_string()))?;
		self.amount = parsed;
		Ok(self)
	}

	/// Sets the calldata.
	pub fn calldata<S: Into<String>>(mut self, calldata: S) -> Self {
		self.calldata = Some(calldata.into());
		self
	}

	/// Sets the calldata from hex bytes.
	pub fn calldata_hex(mut self, hex: &str) -> Self {
		let hex = if hex.starts_with("0x") {
			hex
		} else {
			&format!("0x{}", hex)
		};
		self.calldata = Some(hex.to_string());
		self
	}

	/// Clears the calldata.
	pub fn no_calldata(mut self) -> Self {
		self.calldata = None;
		self
	}

	/// Validates the builder state and returns an error if required fields are missing.
	pub fn validate(&self) -> Result<(), RequestedOutputBuilderError> {
		if self.receiver.is_none() {
			return Err(RequestedOutputBuilderError::MissingField("receiver"));
		}
		if self.asset.is_none() {
			return Err(RequestedOutputBuilderError::MissingField("asset"));
		}
		Ok(())
	}

	/// Builds the `RequestedOutput` with the configured values.
	///
	/// # Panics
	///
	/// Panics if required fields are not set.
	/// Use `try_build()` for error handling instead of panicking.
	pub fn build(self) -> RequestedOutput {
		self.try_build()
			.expect("Missing required fields or invalid configuration")
	}

	/// Tries to build the `RequestedOutput` with the configured values.
	///
	/// Returns an error if required fields are missing.
	pub fn try_build(self) -> Result<RequestedOutput, RequestedOutputBuilderError> {
		self.validate()?;

		Ok(RequestedOutput {
			receiver: self.receiver.unwrap(),
			asset: self.asset.unwrap(),
			amount: self.amount,
			calldata: self.calldata,
		})
	}
}

/// Errors that can occur when building a RequestedOutput.
#[derive(Debug, thiserror::Error)]
pub enum RequestedOutputBuilderError {
	#[error("Missing required field: {0}")]
	MissingField(&'static str),
	#[error("Invalid amount: {0}")]
	InvalidAmount(String),
	#[error("Invalid address: {0}")]
	InvalidAddress(String),
}
