//! Builder for AvailableInput
//!
//! Provides a fluent API for constructing AvailableInput instances with
//! proper validation and sensible defaults.

use crate::api::{AvailableInput, Lock};
use crate::standards::eip7930::InteropAddress;
use alloy_primitives::{Address as AlloyAddress, U256};

/// Builder for creating `AvailableInput` instances with a fluent API.
///
/// Provides an easy way to construct available inputs with proper validation
/// and sensible defaults for API requests.
///
/// # Examples
///
/// ```
/// use solver_types::utils::builders::AvailableInputBuilder;
///
/// let input = AvailableInputBuilder::new()
///     .user_ethereum(1, address!("1111111111111111111111111111111111111111"))
///     .asset_ethereum(1, address!("2222222222222222222222222222222222222222"))
///     .amount_u64(1000)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct AvailableInputBuilder {
	user: Option<InteropAddress>,
	asset: Option<InteropAddress>,
	amount: U256,
	lock: Option<Lock>,
}

impl Default for AvailableInputBuilder {
	fn default() -> Self {
		Self::new()
	}
}

impl AvailableInputBuilder {
	/// Creates a new `AvailableInputBuilder` with default values.
	pub fn new() -> Self {
		Self {
			user: None,
			asset: None,
			amount: U256::ZERO,
			lock: None,
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
	) -> Result<Self, AvailableInputBuilderError> {
		let hex = hex.strip_prefix("0x").unwrap_or(hex);
		let bytes = hex::decode(hex)
			.map_err(|_| AvailableInputBuilderError::InvalidAddress(hex.to_string()))?;
		if bytes.len() != 20 {
			return Err(AvailableInputBuilderError::InvalidAddress(hex.to_string()));
		}
		let mut addr_bytes = [0u8; 20];
		addr_bytes.copy_from_slice(&bytes);
		let address = AlloyAddress::from(addr_bytes);
		self.user = Some(InteropAddress::new_ethereum(chain_id, address));
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
	) -> Result<Self, AvailableInputBuilderError> {
		let hex = hex.strip_prefix("0x").unwrap_or(hex);
		let bytes = hex::decode(hex)
			.map_err(|_| AvailableInputBuilderError::InvalidAddress(hex.to_string()))?;
		if bytes.len() != 20 {
			return Err(AvailableInputBuilderError::InvalidAddress(hex.to_string()));
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
	pub fn amount_str(mut self, amount: &str) -> Result<Self, AvailableInputBuilderError> {
		let parsed = U256::from_str_radix(amount, 10)
			.map_err(|_| AvailableInputBuilderError::InvalidAmount(amount.to_string()))?;
		self.amount = parsed;
		Ok(self)
	}

	/// Sets the lock information.
	pub fn lock(mut self, lock: Lock) -> Self {
		self.lock = Some(lock);
		self
	}

	/// Clears the lock information.
	pub fn no_lock(mut self) -> Self {
		self.lock = None;
		self
	}

	/// Validates the builder state and returns an error if required fields are missing.
	pub fn validate(&self) -> Result<(), AvailableInputBuilderError> {
		if self.user.is_none() {
			return Err(AvailableInputBuilderError::MissingField("user"));
		}
		if self.asset.is_none() {
			return Err(AvailableInputBuilderError::MissingField("asset"));
		}
		Ok(())
	}

	/// Builds the `AvailableInput` with the configured values.
	///
	/// # Panics
	///
	/// Panics if required fields are not set.
	/// Use `try_build()` for error handling instead of panicking.
	pub fn build(self) -> AvailableInput {
		self.try_build()
			.expect("Missing required fields or invalid configuration")
	}

	/// Tries to build the `AvailableInput` with the configured values.
	///
	/// Returns an error if required fields are missing.
	pub fn try_build(self) -> Result<AvailableInput, AvailableInputBuilderError> {
		self.validate()?;

		Ok(AvailableInput {
			user: self.user.unwrap(),
			asset: self.asset.unwrap(),
			amount: self.amount,
			lock: self.lock,
		})
	}
}

/// Errors that can occur when building an AvailableInput.
#[derive(Debug, thiserror::Error)]
pub enum AvailableInputBuilderError {
	#[error("Missing required field: {0}")]
	MissingField(&'static str),
	#[error("Invalid amount: {0}")]
	InvalidAmount(String),
	#[error("Invalid address: {0}")]
	InvalidAddress(String),
}
