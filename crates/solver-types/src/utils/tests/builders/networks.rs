//! Builders for Network Configuration Types
//!
//! Provides fluent APIs for constructing network configuration instances with
//! proper validation and sensible defaults.

use crate::networks::{NetworkConfig, NetworksConfig, RpcEndpoint, TokenConfig};
use crate::{parse_address, Address};
use std::collections::HashMap;

/// Builder for creating `TokenConfig` instances with a fluent API.
///
/// Provides an easy way to construct token configurations with proper validation
/// and sensible defaults for blockchain tokens.
///
/// # Examples
///
/// ```
/// use solver_types::utils::builders::TokenConfigBuilder;
/// use solver_types::Address;
///
/// let token = TokenConfigBuilder::new()
///     .address_hex("A0b86a33E6776Fb78B3e1E6B2D0d2E8F0C1D2A3B")
///     .symbol("USDC")
///     .decimals(6)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct TokenConfigBuilder {
	address: Option<Address>,
	symbol: Option<String>,
	decimals: Option<u8>,
}

impl Default for TokenConfigBuilder {
	fn default() -> Self {
		Self::new()
	}
}

impl TokenConfigBuilder {
	/// Creates a new `TokenConfigBuilder` with default values.
	pub fn new() -> Self {
		Self {
			address: Some(
				parse_address("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
					.expect("Invalid USDC address"),
			),
			symbol: Some("USDC".to_string()),
			decimals: Some(6),
		}
	}

	/// Sets the token address.
	pub fn address(mut self, address: Address) -> Self {
		self.address = Some(address);
		self
	}

	/// Sets the token address from a hex string (with or without 0x prefix).
	pub fn address_hex(mut self, hex: &str) -> Result<Self, TokenConfigBuilderError> {
		let hex_str = hex.trim_start_matches("0x");
		let bytes = hex::decode(hex_str)
			.map_err(|_| TokenConfigBuilderError::InvalidAddress(hex.to_string()))?;
		self.address = Some(Address(bytes));
		Ok(self)
	}

	/// Sets the token symbol.
	pub fn symbol<S: Into<String>>(mut self, symbol: S) -> Self {
		self.symbol = Some(symbol.into());
		self
	}

	/// Sets the token decimals.
	pub fn decimals(mut self, decimals: u8) -> Self {
		self.decimals = Some(decimals);
		self
	}

	/// Validates the builder state and returns an error if required fields are missing.
	pub fn validate(&self) -> Result<(), TokenConfigBuilderError> {
		if self.address.is_none() {
			return Err(TokenConfigBuilderError::MissingField("address"));
		}
		if self.symbol.is_none() {
			return Err(TokenConfigBuilderError::MissingField("symbol"));
		}
		if self.decimals.is_none() {
			return Err(TokenConfigBuilderError::MissingField("decimals"));
		}
		Ok(())
	}

	/// Builds the `TokenConfig` with the configured values.
	///
	/// # Panics
	///
	/// Panics if required fields are not set.
	/// Use `try_build()` for error handling instead of panicking.
	pub fn build(self) -> TokenConfig {
		self.try_build()
			.expect("Missing required fields or invalid configuration")
	}

	/// Tries to build the `TokenConfig` with the configured values.
	///
	/// Returns an error if required fields are missing.
	pub fn try_build(self) -> Result<TokenConfig, TokenConfigBuilderError> {
		self.validate()?;

		Ok(TokenConfig {
			address: self.address.unwrap(),
			symbol: self.symbol.unwrap(),
			decimals: self.decimals.unwrap(),
		})
	}
}

/// Builder for creating `NetworkConfig` instances with a fluent API.
///
/// Provides an easy way to construct network configurations with proper validation
/// and sensible defaults for blockchain networks.
///
/// # Examples
///
/// ```
/// use solver_types::utils::builders::{NetworkConfigBuilder, RpcEndpointBuilder};
/// use solver_types::Address;
///
/// let network = NetworkConfigBuilder::new()
///     .input_settler_address_hex("7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9")
///     .output_settler_address_hex("5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f")
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct NetworkConfigBuilder {
	rpc_urls: Vec<RpcEndpoint>,
	input_settler_address: Option<Address>,
	output_settler_address: Option<Address>,
	tokens: Vec<TokenConfig>,
	input_settler_compact_address: Option<Address>,
	the_compact_address: Option<Address>,
}

impl Default for NetworkConfigBuilder {
	fn default() -> Self {
		Self::new()
	}
}

impl NetworkConfigBuilder {
	/// Creates a new `NetworkConfigBuilder` with default values.
	pub fn new() -> Self {
		Self {
			rpc_urls: vec![RpcEndpoint::both(
				"https://eth.llamarpc.com".to_string(),
				"wss://eth.llamarpc.com".to_string(),
			)],
			input_settler_address: Some(
				parse_address("0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9")
					.expect("Invalid mock address"),
			),
			output_settler_address: Some(
				parse_address("0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f")
					.expect("Invalid mock address"),
			),
			tokens: vec![TokenConfigBuilder::new().build()],
			input_settler_compact_address: Some(
				parse_address("0x00000000000c2e074ec69a0dfb2997ba6c7d2e1e")
					.expect("Invalid mock address"),
			),
			the_compact_address: Some(
				parse_address("0x00000000000c2e074ec69a0dfb2997ba6c7d2e1f")
					.expect("Invalid mock address"),
			),
		}
	}

	/// Adds an RPC endpoint.
	pub fn add_rpc_endpoint(mut self, endpoint: RpcEndpoint) -> Self {
		self.rpc_urls.push(endpoint);
		self
	}

	/// Adds multiple RPC endpoints.
	pub fn rpc_endpoints(mut self, endpoints: Vec<RpcEndpoint>) -> Self {
		self.rpc_urls.extend(endpoints);
		self
	}

	/// Sets the input settler address.
	pub fn input_settler_address(mut self, address: Address) -> Self {
		self.input_settler_address = Some(address);
		self
	}

	/// Sets the input settler address from a hex string (with or without 0x prefix).
	pub fn input_settler_address_hex(
		mut self,
		hex: &str,
	) -> Result<Self, NetworkConfigBuilderError> {
		let hex_str = hex.trim_start_matches("0x");
		let bytes = hex::decode(hex_str)
			.map_err(|_| NetworkConfigBuilderError::InvalidAddress(hex.to_string()))?;
		self.input_settler_address = Some(Address(bytes));
		Ok(self)
	}

	/// Sets the output settler address.
	pub fn output_settler_address(mut self, address: Address) -> Self {
		self.output_settler_address = Some(address);
		self
	}

	/// Sets the output settler address from a hex string (with or without 0x prefix).
	pub fn output_settler_address_hex(
		mut self,
		hex: &str,
	) -> Result<Self, NetworkConfigBuilderError> {
		let hex_str = hex.trim_start_matches("0x");
		let bytes = hex::decode(hex_str)
			.map_err(|_| NetworkConfigBuilderError::InvalidAddress(hex.to_string()))?;
		self.output_settler_address = Some(Address(bytes));
		Ok(self)
	}

	/// Adds a token configuration.
	pub fn add_token(mut self, token: TokenConfig) -> Self {
		self.tokens.push(token);
		self
	}

	/// Adds multiple token configurations.
	pub fn tokens(mut self, tokens: Vec<TokenConfig>) -> Self {
		self.tokens.extend(tokens);
		self
	}

	/// Sets the optional input settler compact address.
	pub fn input_settler_compact_address(mut self, address: Address) -> Self {
		self.input_settler_compact_address = Some(address);
		self
	}

	/// Sets the optional input settler compact address from a hex string.
	pub fn input_settler_compact_address_hex(
		mut self,
		hex: &str,
	) -> Result<Self, NetworkConfigBuilderError> {
		let hex_str = hex.trim_start_matches("0x");
		let bytes = hex::decode(hex_str)
			.map_err(|_| NetworkConfigBuilderError::InvalidAddress(hex.to_string()))?;
		self.input_settler_compact_address = Some(Address(bytes));
		Ok(self)
	}

	/// Sets the optional TheCompact contract address.
	pub fn the_compact_address(mut self, address: Address) -> Self {
		self.the_compact_address = Some(address);
		self
	}

	/// Sets the optional TheCompact contract address from a hex string.
	pub fn the_compact_address_hex(mut self, hex: &str) -> Result<Self, NetworkConfigBuilderError> {
		let hex_str = hex.trim_start_matches("0x");
		let bytes = hex::decode(hex_str)
			.map_err(|_| NetworkConfigBuilderError::InvalidAddress(hex.to_string()))?;
		self.the_compact_address = Some(Address(bytes));
		Ok(self)
	}

	/// Validates the builder state and returns an error if required fields are missing.
	pub fn validate(&self) -> Result<(), NetworkConfigBuilderError> {
		if self.rpc_urls.is_empty() {
			return Err(NetworkConfigBuilderError::MissingField("rpc_urls"));
		}
		if self.input_settler_address.is_none() {
			return Err(NetworkConfigBuilderError::MissingField(
				"input_settler_address",
			));
		}
		if self.output_settler_address.is_none() {
			return Err(NetworkConfigBuilderError::MissingField(
				"output_settler_address",
			));
		}
		Ok(())
	}

	/// Builds the `NetworkConfig` with the configured values.
	///
	/// # Panics
	///
	/// Panics if required fields are not set.
	/// Use `try_build()` for error handling instead of panicking.
	pub fn build(self) -> NetworkConfig {
		self.try_build()
			.expect("Missing required fields or invalid configuration")
	}

	/// Tries to build the `NetworkConfig` with the configured values.
	///
	/// Returns an error if required fields are missing.
	pub fn try_build(self) -> Result<NetworkConfig, NetworkConfigBuilderError> {
		self.validate()?;

		Ok(NetworkConfig {
			rpc_urls: self.rpc_urls,
			input_settler_address: self.input_settler_address.unwrap(),
			output_settler_address: self.output_settler_address.unwrap(),
			tokens: self.tokens,
			input_settler_compact_address: self.input_settler_compact_address,
			the_compact_address: self.the_compact_address,
		})
	}
}

/// Builder for creating `NetworksConfig` instances with a fluent API.
///
/// Provides an easy way to construct networks configuration mappings with proper validation
/// and sensible defaults for multi-chain configurations.
///
/// # Examples
///
/// ```
/// use solver_types::utils::builders::{NetworksConfigBuilder, NetworkConfigBuilder};
///
/// let networks = NetworksConfigBuilder::new()
///     .add_network(1, NetworkConfigBuilder::new()
///         .input_settler_address_hex("7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9")
///         .output_settler_address_hex("5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f")
///         .build())
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct NetworksConfigBuilder {
	networks: HashMap<u64, NetworkConfig>,
}

impl Default for NetworksConfigBuilder {
	fn default() -> Self {
		Self::new()
	}
}

impl NetworksConfigBuilder {
	/// Creates a new `NetworksConfigBuilder` with default values.
	pub fn new() -> Self {
		Self {
			networks: HashMap::new(),
		}
	}

	/// Adds a network configuration for the given chain ID.
	pub fn add_network(mut self, chain_id: u64, config: NetworkConfig) -> Self {
		self.networks.insert(chain_id, config);
		self
	}

	/// Adds multiple network configurations.
	pub fn networks(mut self, networks: HashMap<u64, NetworkConfig>) -> Self {
		self.networks.extend(networks);
		self
	}

	/// Builds the `NetworksConfig` with the configured values.
	///
	/// # Panics
	///
	/// Panics if no networks are configured.
	/// Use `try_build()` for error handling instead of panicking.
	pub fn build(self) -> NetworksConfig {
		self.try_build()
			.expect("At least one network must be configured")
	}

	/// Tries to build the `NetworksConfig` with the configured values.
	///
	/// Returns an error if no networks are configured.
	pub fn try_build(self) -> Result<NetworksConfig, NetworksConfigBuilderError> {
		Ok(self.networks)
	}
}

/// Errors that can occur when building a TokenConfig.
#[derive(Debug, thiserror::Error)]
pub enum TokenConfigBuilderError {
	#[error("Missing required field: {0}")]
	MissingField(&'static str),
	#[error("Invalid address: {0}")]
	InvalidAddress(String),
}

/// Errors that can occur when building a NetworkConfig.
#[derive(Debug, thiserror::Error)]
pub enum NetworkConfigBuilderError {
	#[error("Missing required field: {0}")]
	MissingField(&'static str),
	#[error("Invalid address: {0}")]
	InvalidAddress(String),
}

/// Errors that can occur when building a NetworksConfig.
#[derive(Debug, thiserror::Error)]
pub enum NetworksConfigBuilderError {
	#[error("At least one network must be configured")]
	NoNetworksConfigured,
}
