//! Smart contract interaction and ABI management
//!
//! This module provides comprehensive smart contract interaction capabilities
//! including ABI loading, method encoding, contract calls, and address management.
//! Supports ERC20 tokens, TheCompact protocol, and custom contract interactions
//! with automatic encoding and decoding of function calls and responses.

use crate::types::{
	chain::ChainId,
	error::{Error, Result},
	hex::Hex,
	session::ContractSet,
};
use alloy_dyn_abi::{DynSolValue, JsonAbiExt};
use alloy_json_abi::JsonAbi;
use alloy_primitives::{Address, Bytes, U256};
use alloy_provider::Provider as AlloyProvider;
use alloy_rpc_types::TransactionRequest;
use std::collections::HashMap;
use std::sync::Arc;

use super::blockchain::Provider;

/// Contract management system with ABI handling and address resolution
///
/// Provides centralized management of smart contract ABIs and addresses
/// across multiple blockchain networks with support for dynamic contract
/// interaction, method encoding, and automated function calling
#[derive(Debug, Clone, Default)]
pub struct Contracts {
	abis: Arc<HashMap<String, JsonAbi>>,
	addresses: Arc<HashMap<ChainId, ContractAddresses>>,
}

impl Contracts {
	/// Create new contract management instance
	///
	/// # Returns
	/// Empty Contracts instance ready for ABI loading and address configuration
	pub fn new() -> Self {
		Self {
			abis: Arc::new(HashMap::new()),
			addresses: Arc::new(HashMap::new()),
		}
	}

	/// Load contract ABIs for supported protocols
	///
	/// Loads standard ABIs for ERC20 tokens and TheCompact protocol
	/// into the contract manager for future method encoding and calling
	///
	/// # Arguments
	/// * `_dir` - Directory path for ABI files (currently unused)
	///
	/// # Returns
	/// Success if all ABIs are loaded successfully
	///
	/// # Errors
	/// Returns Error if ABI loading fails
	pub fn load_abis(&mut self, _dir: &std::path::Path) -> Result<()> {
		let mut abis = HashMap::new();

		// Load standard ERC20 ABI
		abis.insert("ERC20".to_string(), self.erc20_abi());

		// Load TheCompact ABI
		abis.insert("TheCompact".to_string(), self.thecompact_abi());

		self.abis = Arc::new(abis);
		Ok(())
	}

	/// Configure contract addresses for specific blockchain network
	///
	/// # Arguments
	/// * `chain` - Target blockchain network identifier
	/// * `addresses` - Contract addresses for the specified chain
	pub fn set_addresses(&mut self, chain: ChainId, addresses: ContractAddresses) {
		Arc::make_mut(&mut self.addresses).insert(chain, addresses);
	}

	/// Retrieve contract addresses for specific blockchain network
	///
	/// # Arguments
	/// * `chain` - Target blockchain network identifier
	///
	/// # Returns
	/// Optional reference to ContractAddresses if configured for the chain
	pub fn addresses(&self, chain: ChainId) -> Option<&ContractAddresses> {
		self.addresses.get(&chain)
	}

	/// Execute ERC20 contract method call
	///
	/// # Arguments
	/// * `provider` - Blockchain provider for contract interaction
	/// * `token` - ERC20 token contract address
	/// * `method` - Method name to call
	/// * `args` - Method arguments as DynSolValue array
	///
	/// # Returns
	/// Raw bytes returned from contract call
	///
	/// # Errors
	/// Returns Error if ABI not loaded, method not found, or contract call fails
	pub async fn erc20_call(
		&self,
		provider: &Provider,
		token: Address,
		method: &str,
		args: Vec<DynSolValue>,
	) -> Result<Bytes> {
		let abi = self
			.abis
			.get("ERC20")
			.ok_or_else(|| Error::InvalidAbi("ERC20 ABI not loaded".to_string()))?;

		let functions = abi
			.function(method)
			.ok_or_else(|| Error::InvalidAbi(format!("Function {} not found", method)))?;

		let function = functions.first().ok_or_else(|| {
			Error::InvalidAbi(format!("No implementation for function {}", method))
		})?;

		// Encode the call data
		let data = function.abi_encode_input(&args).map_err(|e| {
			Error::ContractCallFailed(format!("Failed to encode {}: {}", method, e))
		})?;

		// Make the call
		let call = TransactionRequest::default().to(token).input(data.into());

		let result =
			provider.inner().call(&call).await.map_err(|e| {
				Error::ContractCallFailed(format!("Call to {} failed: {}", method, e))
			})?;

		Ok(result)
	}

	/// Retrieve ERC20 token balance for specific owner address
	///
	/// # Arguments
	/// * `provider` - Blockchain provider for contract interaction
	/// * `token` - ERC20 token contract address
	/// * `owner` - Address to query balance for
	///
	/// # Returns
	/// Token balance as U256
	///
	/// # Errors
	/// Returns Error if contract call or balance decoding fails
	pub async fn erc20_balance(
		&self,
		provider: &Provider,
		token: Address,
		owner: Address,
	) -> Result<U256> {
		let result = self
			.erc20_call(
				provider,
				token,
				"balanceOf",
				vec![DynSolValue::Address(owner)],
			)
			.await?;

		// Decode the result
		let balance = U256::from_be_slice(&result);
		Ok(balance)
	}

	/// Encode ERC20 approve transaction data for spending authorization
	///
	/// # Arguments
	/// * `spender` - Address authorized to spend tokens
	/// * `amount` - Maximum amount of tokens to authorize
	///
	/// # Returns
	/// Encoded transaction data for approve call
	///
	/// # Errors
	/// Returns Error if ABI not loaded or encoding fails
	pub fn erc20_approve(&self, spender: Address, amount: U256) -> Result<Bytes> {
		let abi = self
			.abis
			.get("ERC20")
			.ok_or_else(|| Error::InvalidAbi("ERC20 ABI not loaded".to_string()))?;

		let functions = abi
			.function("approve")
			.ok_or_else(|| Error::InvalidAbi("Function approve not found".to_string()))?;

		let function = functions.first().ok_or_else(|| {
			Error::InvalidAbi("No implementation for function approve".to_string())
		})?;

		// Encode the call data
		let args = vec![
			DynSolValue::Address(spender),
			DynSolValue::Uint(amount, 256),
		];

		let data = function
			.abi_encode_input(&args)
			.map_err(|e| Error::ContractCallFailed(format!("Failed to encode approve: {}", e)))?;

		Ok(data.into())
	}

	/// Encode ERC20 mint transaction data for token creation
	///
	/// # Arguments
	/// * `recipient` - Address to receive newly minted tokens
	/// * `amount` - Amount of tokens to mint
	///
	/// # Returns
	/// Encoded transaction data for mint call
	///
	/// # Errors
	/// Returns Error if ABI not loaded or encoding fails
	pub fn erc20_mint(&self, recipient: Address, amount: U256) -> Result<Bytes> {
		let abi = self
			.abis
			.get("ERC20")
			.ok_or_else(|| Error::InvalidAbi("ERC20 ABI not loaded".to_string()))?;

		let functions = abi
			.function("mint")
			.ok_or_else(|| Error::InvalidAbi("Function mint not found".to_string()))?;

		let function = functions
			.first()
			.ok_or_else(|| Error::InvalidAbi("No implementation for function mint".to_string()))?;

		// Encode the call data
		let args = vec![
			DynSolValue::Address(recipient),
			DynSolValue::Uint(amount, 256),
		];

		let data = function
			.abi_encode_input(&args)
			.map_err(|e| Error::ContractCallFailed(format!("Failed to encode mint: {}", e)))?;

		Ok(data.into())
	}

	/// Execute TheCompact protocol contract method call
	///
	/// # Arguments
	/// * `provider` - Blockchain provider for contract interaction
	/// * `compact` - TheCompact contract address
	/// * `method` - Method name to call
	/// * `args` - Method arguments as DynSolValue array
	///
	/// # Returns
	/// Raw bytes returned from contract call
	///
	/// # Errors
	/// Returns Error if ABI not loaded, method not found, or contract call fails
	pub async fn thecompact_call(
		&self,
		provider: &Provider,
		compact: Address,
		method: &str,
		args: Vec<DynSolValue>,
	) -> Result<Bytes> {
		let abi = self
			.abis
			.get("TheCompact")
			.ok_or_else(|| Error::InvalidAbi("TheCompact ABI not loaded".to_string()))?;

		let functions = abi
			.function(method)
			.ok_or_else(|| Error::InvalidAbi(format!("Function {} not found", method)))?;

		let function = functions.first().ok_or_else(|| {
			Error::InvalidAbi(format!("No implementation for function {}", method))
		})?;

		// Encode the call data
		let data = function.abi_encode_input(&args).map_err(|e| {
			Error::ContractCallFailed(format!("Failed to encode {}: {}", method, e))
		})?;

		// Make the call
		let call = TransactionRequest::default().to(compact).input(data.into());

		let result =
			provider.inner().call(&call).await.map_err(|e| {
				Error::ContractCallFailed(format!("Call to {} failed: {}", method, e))
			})?;

		Ok(result)
	}

	/// Encode TheCompact depositERC20 transaction data for token deposits
	///
	/// # Arguments
	/// * `token` - ERC20 token contract address
	/// * `allocator_lock_tag` - 12-byte allocator lock identifier
	/// * `amount` - Amount of tokens to deposit
	/// * `recipient` - Address to receive deposit allocation
	///
	/// # Returns
	/// Encoded transaction data for depositERC20 call
	///
	/// # Errors
	/// Returns Error if ABI not loaded or encoding fails
	pub fn thecompact_deposit(
		&self,
		token: Address,
		allocator_lock_tag: [u8; 12],
		amount: U256,
		recipient: Address,
	) -> Result<Bytes> {
		let abi = self
			.abis
			.get("TheCompact")
			.ok_or_else(|| Error::InvalidAbi("TheCompact ABI not loaded".to_string()))?;

		let functions = abi
			.function("depositERC20")
			.ok_or_else(|| Error::InvalidAbi("Function depositERC20 not found".to_string()))?;

		let function = functions.first().ok_or_else(|| {
			Error::InvalidAbi("No implementation for function depositERC20".to_string())
		})?;

		// Prepare 12-byte lock tag as FixedBytes<32> for ABI encoding
		let mut lock_tag_32 = [0u8; 32];
		lock_tag_32[0..12].copy_from_slice(&allocator_lock_tag);
		let lock_tag_word = alloy_primitives::FixedBytes::<32>::from(lock_tag_32);

		let args = vec![
			DynSolValue::Address(token),
			DynSolValue::FixedBytes(lock_tag_word, 12),
			DynSolValue::Uint(amount, 256),
			DynSolValue::Address(recipient),
		];

		let data = function.abi_encode_input(&args).map_err(|e| {
			Error::ContractCallFailed(format!("Failed to encode depositERC20: {}", e))
		})?;

		Ok(data.into())
	}

	/// Encode TheCompact allocator registration transaction data
	///
	/// # Arguments
	/// * `allocator` - Allocator contract address to register
	/// * `proof` - Registration proof bytes
	///
	/// # Returns
	/// Encoded transaction data for __registerAllocator call
	///
	/// # Errors
	/// Returns Error if ABI not loaded or encoding fails
	pub fn thecompact_register_allocator(
		&self,
		allocator: Address,
		proof: Vec<u8>,
	) -> Result<Bytes> {
		let abi = self
			.abis
			.get("TheCompact")
			.ok_or_else(|| Error::InvalidAbi("TheCompact ABI not loaded".to_string()))?;

		let functions = abi.function("__registerAllocator").ok_or_else(|| {
			Error::InvalidAbi("Function __registerAllocator not found".to_string())
		})?;

		let function = functions.first().ok_or_else(|| {
			Error::InvalidAbi("No implementation for function __registerAllocator".to_string())
		})?;

		let args = vec![DynSolValue::Address(allocator), DynSolValue::Bytes(proof)];

		let data = function.abi_encode_input(&args).map_err(|e| {
			Error::ContractCallFailed(format!("Failed to encode __registerAllocator: {}", e))
		})?;

		Ok(data.into())
	}

	/// Retrieve ERC20 token symbol string
	///
	/// # Arguments
	/// * `provider` - Blockchain provider for contract interaction
	/// * `token` - ERC20 token contract address
	///
	/// # Returns
	/// Token symbol as String
	///
	/// # Errors
	/// Returns Error if contract call fails or symbol decoding fails
	pub async fn erc20_symbol(&self, provider: &Provider, token: Address) -> Result<String> {
		let result = self.erc20_call(provider, token, "symbol", vec![]).await?;

		// Decode string result - for strings, we need to decode the ABI-encoded data
		// The result contains: [offset][length][data...]
		if result.len() < 64 {
			return Err(Error::ContractCallFailed(
				"Invalid symbol response length".to_string(),
			));
		}

		// Skip the first 32 bytes (offset, usually 0x20), get length from next 32 bytes
		let length_bytes = &result[32..64];
		let length = U256::from_be_slice(length_bytes).to::<usize>();

		if result.len() < 64 + length {
			return Err(Error::ContractCallFailed(
				"Symbol response too short".to_string(),
			));
		}

		let symbol_bytes = &result[64..64 + length];
		let symbol = String::from_utf8(symbol_bytes.to_vec())
			.map_err(|e| Error::ContractCallFailed(format!("Invalid UTF-8 in symbol: {}", e)))?;

		Ok(symbol)
	}

	/// Generate standard ERC20 contract ABI
	///
	/// # Returns
	/// JsonAbi containing standard ERC20 function definitions
	fn erc20_abi(&self) -> JsonAbi {
		// Minimal ERC20 ABI including mint function for test tokens
		serde_json::from_str(
			r#"[
            {
                "type": "function",
                "name": "balanceOf",
                "inputs": [{"name": "owner", "type": "address"}],
                "outputs": [{"name": "", "type": "uint256"}],
                "stateMutability": "view"
            },
            {
                "type": "function",
                "name": "approve",
                "inputs": [
                    {"name": "spender", "type": "address"},
                    {"name": "amount", "type": "uint256"}
                ],
                "outputs": [{"name": "", "type": "bool"}],
                "stateMutability": "nonpayable"
            },
            {
                "type": "function",
                "name": "allowance",
                "inputs": [
                    {"name": "owner", "type": "address"},
                    {"name": "spender", "type": "address"}
                ],
                "outputs": [{"name": "", "type": "uint256"}],
                "stateMutability": "view"
            },
            {
                "type": "function",
                "name": "transfer",
                "inputs": [
                    {"name": "to", "type": "address"},
                    {"name": "amount", "type": "uint256"}
                ],
                "outputs": [{"name": "", "type": "bool"}],
                "stateMutability": "nonpayable"
            },
            {
                "type": "function",
                "name": "mint",
                "inputs": [
                    {"name": "to", "type": "address"},
                    {"name": "amount", "type": "uint256"}
                ],
                "outputs": [{"name": "", "type": "bool"}],
                "stateMutability": "nonpayable"
            },
            {
                "type": "function",
                "name": "decimals",
                "inputs": [],
                "outputs": [{"name": "", "type": "uint8"}],
                "stateMutability": "view"
            },
            {
                "type": "function",
                "name": "symbol",
                "inputs": [],
                "outputs": [{"name": "", "type": "string"}],
                "stateMutability": "view"
            }
        ]"#,
		)
		.expect("Invalid ERC20 ABI")
	}

	/// Generate TheCompact protocol contract ABI
	///
	/// # Returns
	/// JsonAbi containing TheCompact function definitions
	fn thecompact_abi(&self) -> JsonAbi {
		// TheCompact ABI with the functions we need
		serde_json::from_str(
			r#"[
            {
                "type": "function",
                "name": "depositERC20",
                "inputs": [
                    {"name": "token", "type": "address"},
                    {"name": "lockTag", "type": "bytes12"},
                    {"name": "amount", "type": "uint256"},
                    {"name": "recipient", "type": "address"}
                ],
                "outputs": [{"name": "id", "type": "uint256"}],
                "stateMutability": "nonpayable"
            },
            {
                "type": "function",
                "name": "__registerAllocator",
                "inputs": [
                    {"name": "allocator", "type": "address"},
                    {"name": "proof", "type": "bytes"}
                ],
                "outputs": [{"name": "", "type": "uint96"}],
                "stateMutability": "nonpayable"
            },
            {
                "type": "function",
                "name": "depositNative",
                "inputs": [
                    {"name": "lockTag", "type": "bytes12"},
                    {"name": "recipient", "type": "address"}
                ],
                "outputs": [{"name": "", "type": "uint256"}],
                "stateMutability": "payable"
            }
        ]"#,
		)
		.expect("Invalid TheCompact ABI")
	}
}

/// Contract address collection for specific blockchain network
///
/// Contains addresses for all deployed contracts on a particular chain
/// including settlers, permit2, compact, allocator, oracle, and token contracts
#[derive(Debug, Clone, Default)]
pub struct ContractAddresses {
	pub input_settler: Option<Address>,
	pub output_settler: Option<Address>,
	pub permit2: Option<Address>,
	pub compact: Option<Address>,
	pub allocator: Option<Address>,
	pub oracle: Option<Address>,
	pub tokens: HashMap<String, Address>,
}

impl ContractAddresses {
	/// Create empty contract addresses collection
	///
	/// # Returns
	/// Empty ContractAddresses with no configured addresses
	pub fn new() -> Self {
		Self {
			input_settler: None,
			output_settler: None,
			permit2: None,
			compact: None,
			allocator: None,
			oracle: None,
			tokens: HashMap::new(),
		}
	}

	/// Convert session ContractSet to ContractAddresses with parsed addresses
	///
	/// # Arguments
	/// * `deployed` - ContractSet from session storage
	///
	/// # Returns
	/// ContractAddresses with parsed address values
	///
	/// # Errors
	/// Returns Error if any address string cannot be parsed
	pub fn from_session_contract_set(deployed: ContractSet) -> Result<Self> {
		use crate::types::hex::Hex;

		let mut addresses = Self::new();

		// Parse addresses from strings to Address types
		if let Some(allocator_str) = &deployed.allocator {
			addresses.allocator = Some(Hex::to_address(allocator_str)?);
		}
		if let Some(compact_str) = &deployed.compact {
			addresses.compact = Some(Hex::to_address(compact_str)?);
		}
		if let Some(input_settler_str) = &deployed.input_settler {
			addresses.input_settler = Some(Hex::to_address(input_settler_str)?);
		}
		if let Some(output_settler_str) = &deployed.output_settler {
			addresses.output_settler = Some(Hex::to_address(output_settler_str)?);
		}
		if let Some(permit2_str) = &deployed.permit2 {
			addresses.permit2 = Some(Hex::to_address(permit2_str)?);
		}

		// Add token addresses
		for (symbol, token_info) in &deployed.tokens {
			let addr = Hex::to_address(&token_info.address)?;
			addresses.tokens.insert(symbol.clone(), addr);
		}

		Ok(addresses)
	}

	/// Create ContractAddresses from individual address strings
	///
	/// # Arguments
	/// * `input_settler` - Optional input settler address string
	/// * `output_settler` - Optional output settler address string
	/// * `permit2` - Optional permit2 contract address string
	/// * `compact` - Optional compact contract address string
	/// * `allocator` - Optional allocator contract address string
	/// * `oracle` - Optional oracle contract address string
	///
	/// # Returns
	/// ContractAddresses with parsed address values
	///
	/// # Errors
	/// Returns Error if any address string cannot be parsed
	pub fn from_strings(
		input_settler: Option<String>,
		output_settler: Option<String>,
		permit2: Option<String>,
		compact: Option<String>,
		allocator: Option<String>,
		oracle: Option<String>,
	) -> Result<Self> {
		Ok(Self {
			input_settler: input_settler.map(|s| Hex::to_address(&s)).transpose()?,
			output_settler: output_settler.map(|s| Hex::to_address(&s)).transpose()?,
			permit2: permit2.map(|s| Hex::to_address(&s)).transpose()?,
			compact: compact.map(|s| Hex::to_address(&s)).transpose()?,
			allocator: allocator.map(|s| Hex::to_address(&s)).transpose()?,
			oracle: oracle.map(|s| Hex::to_address(&s)).transpose()?,
			tokens: HashMap::new(),
		})
	}

	/// Add token contract address to the collection
	///
	/// # Arguments
	/// * `symbol` - Token symbol identifier
	/// * `address` - Token contract address
	pub fn add_token(&mut self, symbol: String, address: Address) {
		self.tokens.insert(symbol, address);
	}
}
