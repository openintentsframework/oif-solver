//! Builder for AssetAmount
//!
//! Provides a fluent API for constructing AssetAmount instances with
//! proper validation and sensible defaults.

use crate::{api::AssetAmount, InteropAddress};
use alloy_primitives::{Address, U256};

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
/// // Using InteropAddress directly
/// let asset_amount = AssetAmountBuilder::new()
///     .asset(interop_address)
///     .amount(U256::from(1000))
///     .build();
///
/// // Or from hex string
/// let asset_amount = AssetAmountBuilder::new()
///     .asset_from_hex("0x00010000010114D8DA6BF26964AF9D7EED9E03E53415D37AA96045")
///     .amount(U256::from(1000))
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct AssetAmountBuilder {
	asset: Option<InteropAddress>,
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

	/// Sets the asset as an InteropAddress.
	pub fn asset(mut self, asset: InteropAddress) -> Self {
		self.asset = Some(asset);
		self
	}

	/// Sets the asset from an InteropAddress hex string.
	pub fn asset_from_hex(mut self, hex: &str) -> Result<Self, AssetAmountBuilderError> {
		let interop_address = InteropAddress::from_hex(hex).map_err(|e| {
			AssetAmountBuilderError::InvalidAsset(format!("Invalid InteropAddress: {e}"))
		})?;
		self.asset = Some(interop_address);
		Ok(self)
	}

	/// Sets the asset from chain ID and Ethereum address.
	pub fn asset_from_chain_and_address(
		mut self,
		chain_id: u64,
		address_str: &str,
	) -> Result<Self, AssetAmountBuilderError> {
		let address_str = if address_str.starts_with("0x") {
			address_str
		} else {
			&format!("0x{address_str}")
		};
		let address = address_str.parse::<Address>().map_err(|e| {
			AssetAmountBuilderError::InvalidAsset(format!("Invalid address: {e}"))
		})?;
		let interop_address = InteropAddress::new_ethereum(chain_id, address);
		self.asset = Some(interop_address);
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
	#[error("Invalid asset: {0}")]
	InvalidAsset(String),
}
