//! Builder for AssetAmount
//!
//! Provides a fluent API for constructing AssetAmount instances with
//! proper validation and sensible defaults.

use crate::api::AssetAmount;
use alloy_primitives::U256;

/// Builder for creating `AssetAmount` instances with a fluent API.
///
/// Provides an easy way to construct asset amounts with proper validation
/// and sensible defaults for API requests.
///
/// # Examples
///
/// ```text
/// use solver_types::utils::builders::AssetAmountBuilder;
/// use alloy_primitives::U256;
///
/// let asset_amount = AssetAmountBuilder::new()
///     .asset("0x1234567890123456789012345678901234567890")
///     .amount(U256::from(1000))
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct AssetAmountBuilder {
	asset: Option<String>,
	amount: U256,
}

impl Default for AssetAmountBuilder {
	fn default() -> Self {
		Self::new()
	}
}

impl AssetAmountBuilder {
	/// Creates a new `AssetAmountBuilder` with default values.
	pub fn new() -> Self {
		Self {
			asset: None,
			amount: U256::ZERO,
		}
	}

	/// Sets the asset address.
	pub fn asset<S: Into<String>>(mut self, asset: S) -> Self {
		self.asset = Some(asset.into());
		self
	}

	/// Sets the asset address from a hex string (with or without 0x prefix).
	pub fn asset_hex(mut self, hex: &str) -> Self {
		let hex = if hex.starts_with("0x") {
			hex
		} else {
			&format!("0x{}", hex)
		};
		self.asset = Some(hex.to_string());
		self
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
	pub fn amount_str(mut self, amount: &str) -> Result<Self, AssetAmountBuilderError> {
		let parsed = U256::from_str_radix(amount, 10)
			.map_err(|_| AssetAmountBuilderError::InvalidAmount(amount.to_string()))?;
		self.amount = parsed;
		Ok(self)
	}

	/// Validates the builder state and returns an error if required fields are missing.
	pub fn validate(&self) -> Result<(), AssetAmountBuilderError> {
		if self.asset.is_none() {
			return Err(AssetAmountBuilderError::MissingField("asset"));
		}
		Ok(())
	}

	/// Builds the `AssetAmount` with the configured values.
	///
	/// # Panics
	///
	/// Panics if required fields are not set.
	/// Use `try_build()` for error handling instead of panicking.
	pub fn build(self) -> AssetAmount {
		self.try_build()
			.expect("Missing required fields or invalid configuration")
	}

	/// Tries to build the `AssetAmount` with the configured values.
	///
	/// Returns an error if required fields are missing.
	pub fn try_build(self) -> Result<AssetAmount, AssetAmountBuilderError> {
		self.validate()?;

		Ok(AssetAmount {
			asset: self.asset.unwrap(),
			amount: self.amount,
		})
	}
}

/// Errors that can occur when building an AssetAmount.
#[derive(Debug, thiserror::Error)]
pub enum AssetAmountBuilderError {
	#[error("Missing required field: {0}")]
	MissingField(&'static str),
	#[error("Invalid amount: {0}")]
	InvalidAmount(String),
}
