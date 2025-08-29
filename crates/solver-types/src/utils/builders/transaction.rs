//! Builder for Transaction
//!
//! Provides a fluent API for constructing Transaction instances with
//! proper validation and sensible defaults.

use crate::account::{Address, Transaction};
use alloy_primitives::U256;

/// Builder for creating `Transaction` instances with a fluent API.
///
/// Provides an easy way to construct transactions with proper validation
/// and sensible defaults for blockchain transactions.
///
/// # Examples
///
/// ```
/// use solver_types::utils::builders::TransactionBuilder;
/// use solver_types::account::Address;
/// use alloy_primitives::U256;
///
/// let tx = TransactionBuilder::new()
///     .to(Address(vec![0x12; 20]))
///     .value(U256::from(1000))
///     .chain_id(1)
///     .gas_limit(21000)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct TransactionBuilder {
	to: Option<Address>,
	data: Vec<u8>,
	value: U256,
	chain_id: Option<u64>,
	nonce: Option<u64>,
	gas_limit: Option<u64>,
	gas_price: Option<u128>,
	max_fee_per_gas: Option<u128>,
	max_priority_fee_per_gas: Option<u128>,
}

impl Default for TransactionBuilder {
	fn default() -> Self {
		Self::new()
	}
}

impl TransactionBuilder {
	/// Creates a new `TransactionBuilder` with default values.
	pub fn new() -> Self {
		Self {
			to: None,
			data: Vec::new(),
			value: U256::ZERO,
			chain_id: None,
			nonce: None,
			gas_limit: None,
			gas_price: None,
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
		}
	}

	/// Sets the recipient address (None for contract creation).
	pub fn to(mut self, to: Address) -> Self {
		self.to = Some(to);
		self
	}

	/// Sets the recipient address from bytes.
	pub fn to_bytes(mut self, bytes: Vec<u8>) -> Self {
		self.to = Some(Address(bytes));
		self
	}

	/// Sets the recipient address from a hex string.
	pub fn to_hex(mut self, hex: &str) -> Result<Self, hex::FromHexError> {
		let hex = hex.strip_prefix("0x").unwrap_or(hex);
		let bytes = hex::decode(hex)?;
		self.to = Some(Address(bytes));
		Ok(self)
	}

	/// Clears the recipient address (for contract creation).
	pub fn clear_to(mut self) -> Self {
		self.to = None;
		self
	}

	/// Sets the transaction data/calldata.
	pub fn data(mut self, data: Vec<u8>) -> Self {
		self.data = data;
		self
	}

	/// Sets the transaction data from a hex string.
	pub fn data_hex(mut self, hex: &str) -> Result<Self, hex::FromHexError> {
		let hex = hex.strip_prefix("0x").unwrap_or(hex);
		self.data = hex::decode(hex)?;
		Ok(self)
	}

	/// Clears the transaction data.
	pub fn clear_data(mut self) -> Self {
		self.data.clear();
		self
	}

	/// Sets the value to transfer in native currency.
	pub fn value(mut self, value: U256) -> Self {
		self.value = value;
		self
	}

	/// Sets the value from a u64.
	pub fn value_u64(mut self, value: u64) -> Self {
		self.value = U256::from(value);
		self
	}

	/// Sets the chain ID for replay protection.
	pub fn chain_id(mut self, chain_id: u64) -> Self {
		self.chain_id = Some(chain_id);
		self
	}

	/// Sets the transaction nonce.
	pub fn nonce(mut self, nonce: u64) -> Self {
		self.nonce = Some(nonce);
		self
	}

	/// Clears the transaction nonce (to be filled by provider).
	pub fn clear_nonce(mut self) -> Self {
		self.nonce = None;
		self
	}

	/// Sets the gas limit for transaction execution.
	pub fn gas_limit(mut self, gas_limit: u64) -> Self {
		self.gas_limit = Some(gas_limit);
		self
	}

	/// Clears the gas limit.
	pub fn clear_gas_limit(mut self) -> Self {
		self.gas_limit = None;
		self
	}

	/// Sets the legacy gas price (for non-EIP-1559 transactions).
	pub fn gas_price(mut self, gas_price: u128) -> Self {
		self.gas_price = Some(gas_price);
		self
	}

	/// Sets the gas price in gwei.
	pub fn gas_price_gwei(mut self, gwei: u64) -> Self {
		self.gas_price = Some(gwei as u128 * 1_000_000_000);
		self
	}

	/// Clears the gas price.
	pub fn clear_gas_price(mut self) -> Self {
		self.gas_price = None;
		self
	}

	/// Sets the maximum fee per gas (EIP-1559).
	pub fn max_fee_per_gas(mut self, max_fee: u128) -> Self {
		self.max_fee_per_gas = Some(max_fee);
		self
	}

	/// Sets the maximum fee per gas in gwei.
	pub fn max_fee_per_gas_gwei(mut self, gwei: u64) -> Self {
		self.max_fee_per_gas = Some(gwei as u128 * 1_000_000_000);
		self
	}

	/// Clears the maximum fee per gas.
	pub fn clear_max_fee_per_gas(mut self) -> Self {
		self.max_fee_per_gas = None;
		self
	}

	/// Sets the maximum priority fee per gas (EIP-1559).
	pub fn max_priority_fee_per_gas(mut self, max_priority_fee: u128) -> Self {
		self.max_priority_fee_per_gas = Some(max_priority_fee);
		self
	}

	/// Sets the maximum priority fee per gas in gwei.
	pub fn max_priority_fee_per_gas_gwei(mut self, gwei: u64) -> Self {
		self.max_priority_fee_per_gas = Some(gwei as u128 * 1_000_000_000);
		self
	}

	/// Clears the maximum priority fee per gas.
	pub fn clear_max_priority_fee_per_gas(mut self) -> Self {
		self.max_priority_fee_per_gas = None;
		self
	}

	/// Sets up EIP-1559 transaction with max fee and priority fee.
	pub fn eip1559(mut self, max_fee_gwei: u64, priority_fee_gwei: u64) -> Self {
		self.max_fee_per_gas = Some(max_fee_gwei as u128 * 1_000_000_000);
		self.max_priority_fee_per_gas = Some(priority_fee_gwei as u128 * 1_000_000_000);
		self.gas_price = None; // Clear legacy gas price
		self
	}

	/// Sets up legacy transaction with gas price.
	pub fn legacy(mut self, gas_price_gwei: u64) -> Self {
		self.gas_price = Some(gas_price_gwei as u128 * 1_000_000_000);
		self.max_fee_per_gas = None;
		self.max_priority_fee_per_gas = None;
		self
	}

	/// Validates the builder state and returns an error if required fields are missing.
	pub fn validate(&self) -> Result<(), TransactionBuilderError> {
		if self.chain_id.is_none() {
			return Err(TransactionBuilderError::MissingField("chain_id"));
		}

		// Validate that we have either legacy gas pricing or EIP-1559 pricing
		let has_legacy = self.gas_price.is_some();
		let has_eip1559 = self.max_fee_per_gas.is_some() || self.max_priority_fee_per_gas.is_some();

		if !has_legacy && !has_eip1559 {
			return Err(TransactionBuilderError::MissingGasPricing);
		}

		// Validate EIP-1559 pricing consistency
		if has_eip1559 {
			if let (Some(max_fee), Some(priority_fee)) =
				(self.max_fee_per_gas, self.max_priority_fee_per_gas)
			{
				if priority_fee > max_fee {
					return Err(TransactionBuilderError::InvalidGasPricing(
						"Priority fee cannot exceed max fee".to_string(),
					));
				}
			}
		}

		Ok(())
	}

	/// Builds the `Transaction` with the configured values.
	///
	/// # Panics
	///
	/// Panics if required fields are not set or if gas pricing is invalid.
	/// Use `try_build()` for error handling instead of panicking.
	pub fn build(self) -> Transaction {
		self.try_build()
			.expect("Missing required fields or invalid configuration")
	}

	/// Tries to build the `Transaction` with the configured values.
	///
	/// Returns an error if required fields are missing or configuration is invalid.
	pub fn try_build(self) -> Result<Transaction, TransactionBuilderError> {
		self.validate()?;

		Ok(Transaction {
			to: self.to,
			data: self.data,
			value: self.value,
			chain_id: self.chain_id.unwrap(),
			nonce: self.nonce,
			gas_limit: self.gas_limit,
			gas_price: self.gas_price,
			max_fee_per_gas: self.max_fee_per_gas,
			max_priority_fee_per_gas: self.max_priority_fee_per_gas,
		})
	}
}

/// Errors that can occur when building a Transaction.
#[derive(Debug, thiserror::Error)]
pub enum TransactionBuilderError {
	#[error("Missing required field: {0}")]
	MissingField(&'static str),
	#[error("Missing gas pricing: must set either gas_price or EIP-1559 fees")]
	MissingGasPricing,
	#[error("Invalid gas pricing: {0}")]
	InvalidGasPricing(String),
}
