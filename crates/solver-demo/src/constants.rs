//! Constants and configuration values used throughout the solver demo
//!
//! Contains hardcoded addresses, private keys, environment variable names,
//! and other configuration constants for development and testing. Includes
//! Anvil account details, contract addresses, and application defaults.

/// Canonical Permit2 contract address deployed on all supported networks
///
/// This is the standard Permit2 contract address that enables gasless approvals
/// and is deployed at the same address across all EVM-compatible networks.
pub const PERMIT2_ADDRESS: &str = "0x000000000022D473030F116dDEE9F6B43aC78BA3";

/// Default decimal places for ERC20 tokens
///
/// Standard number of decimal places used by most ERC20 tokens, following
/// the Ethereum convention where 1 token = 10^18 wei.
pub const DEFAULT_TOKEN_DECIMALS: u8 = 18;

/// Default Anvil account addresses and private keys for local development
///
/// Contains the standard Anvil accounts used for testing and development.
/// These are well-known test accounts and should never be used in production.
pub mod anvil_accounts {
	/// User account address for transaction signing and testing
	///
	/// Corresponds to Anvil account #2 in the default mnemonic
	pub const USER_ADDRESS: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

	/// Private key for the user account
	///
	/// Used for signing user transactions in local development environments
	pub const USER_PRIVATE_KEY: &str =
		"0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

	/// Solver account address for executing solver operations
	///
	/// Corresponds to Anvil account #1 in the default mnemonic
	pub const SOLVER_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

	/// Private key for the solver account
	///
	/// Used for signing solver transactions and contract deployments
	pub const SOLVER_PRIVATE_KEY: &str =
		"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

	/// Recipient account address for receiving tokens and payments
	///
	/// Corresponds to Anvil account #3 in the default mnemonic
	pub const RECIPIENT_ADDRESS: &str = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
}

/// Environment variable names
pub mod env_vars {
	pub const USER_ADDRESS: &str = "USER_ADDRESS";
	pub const USER_PRIVATE_KEY: &str = "USER_PRIVATE_KEY";
	pub const SOLVER_ADDRESS: &str = "SOLVER_ADDRESS";
	pub const SOLVER_PRIVATE_KEY: &str = "SOLVER_PRIVATE_KEY";
	pub const RECIPIENT_ADDRESS: &str = "RECIPIENT_ADDRESS";
}

/// Contract placeholder keys for TOML configuration generation and replacement
///
/// These constants define the placeholder patterns used in generated TOML files
/// that get replaced with actual deployed contract addresses during environment setup.
pub mod placeholders {
	/// Placeholder prefixes for different contract types
	pub const PLACEHOLDER_INPUT_SETTLER_PREFIX: &str = "PLACEHOLDER_INPUT_SETTLER_";
	pub const PLACEHOLDER_OUTPUT_SETTLER_PREFIX: &str = "PLACEHOLDER_OUTPUT_SETTLER_";
	pub const PLACEHOLDER_COMPACT_PREFIX: &str = "PLACEHOLDER_COMPACT_";
	pub const PLACEHOLDER_INPUT_SETTLER_COMPACT_PREFIX: &str = "PLACEHOLDER_INPUT_SETTLER_COMPACT_";
	pub const PLACEHOLDER_ALLOCATOR_PREFIX: &str = "PLACEHOLDER_ALLOCATOR_";
	pub const PLACEHOLDER_TOKEN_A_PREFIX: &str = "PLACEHOLDER_TOKEN_A_";
	pub const PLACEHOLDER_TOKEN_B_PREFIX: &str = "PLACEHOLDER_TOKEN_B_";
	pub const ORACLE_PLACEHOLDER_INPUT_PREFIX: &str = "ORACLE_PLACEHOLDER_INPUT_";
	pub const ORACLE_PLACEHOLDER_OUTPUT_PREFIX: &str = "ORACLE_PLACEHOLDER_OUTPUT_";

	/// Starting counter for placeholder addresses
	pub const PLACEHOLDER_START_COUNTER: u64 = 1000; // 0x3e8
}
