//! Contract deployment operations
//!
//! Provides functionality for deploying OIF contracts to blockchain networks.
//! Handles contract compilation artifacts, deployment transactions, and address
//! management for settler contracts, oracles, and token contracts with
//! comprehensive error handling and transaction verification.

use crate::{
	constants,
	core::{
		blockchain::{Provider, TxBuilder},
		logging,
	},
	types::{
		chain::ChainId,
		error::{Error, Result},
		session::ContractAddresses,
	},
	Context,
};
use alloy_dyn_abi::DynSolValue;
use alloy_network::TransactionBuilder;
use alloy_primitives::{hex, Address, Bytes, U256};
use alloy_rpc_types::TransactionRequest;
use alloy_signer_local::PrivateKeySigner;
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

/// Contract deployment operations handler
///
/// Manages the deployment of OIF contracts to blockchain networks including
/// settler contracts, oracles, and ERC20 tokens. Handles contract compilation
/// artifacts, transaction building, and address resolution with automatic
/// dependency management and verification.
#[derive(Clone)]
pub struct ContractDeployer {
	ctx: Arc<Context>,
	contracts_path: PathBuf,
}

impl ContractDeployer {
	/// Creates a new contract deployer with default contract path
	///
	/// # Arguments
	/// * `ctx` - Shared application context containing configuration and services
	///
	/// # Returns
	/// New contract deployer instance using default contracts directory
	pub fn new(ctx: Arc<Context>) -> Self {
		Self {
			ctx,
			contracts_path: PathBuf::from("oif-contracts/out"),
		}
	}

	/// Creates a new contract deployer with custom contract path
	///
	/// # Arguments
	/// * `ctx` - Shared application context containing configuration and services
	/// * `contracts_path` - Path to compiled contract artifacts directory
	///
	/// # Returns
	/// New contract deployer instance using specified contracts directory
	pub fn with_path(ctx: Arc<Context>, contracts_path: PathBuf) -> Self {
		Self {
			ctx,
			contracts_path,
		}
	}

	/// Deploys all required contracts to a specific blockchain network
	///
	/// # Arguments
	/// * `chain` - Target blockchain network identifier
	///
	/// # Returns
	/// Contract addresses structure containing all deployed contract addresses
	///
	/// # Errors
	/// Returns error if deployment fails, transaction verification fails,
	/// or contract artifacts are missing
	pub async fn deploy_to_chain(&self, chain: ChainId) -> Result<ContractAddresses> {
		use crate::core::logging;
		logging::verbose_operation("Starting contract deployment", &format!("chain {chain}"));

		// Create provider for this chain
		let provider = self.ctx.provider(chain).await?;

		// Deploy Permit2 first (canonical address)
		let permit2 = self.deploy_permit2(&provider).await?;

		// Deploy test tokens early if in local environment
		let tokens = if self.ctx.is_local() {
			self.deploy_test_tokens(&provider).await?
		} else {
			HashMap::new()
		};

		// Deploy core contracts in dependency order
		let input_settler = self.deploy_input_settler(&provider).await?;
		let output_settler = self.deploy_output_settler(&provider).await?;
		let the_compact = self.deploy_the_compact(&provider).await?;
		let input_settler_compact = self
			.deploy_input_settler_compact(&provider, the_compact)
			.await?;
		let allocator = self.deploy_allocator(&provider).await?;

		// Deploy oracles
		let input_oracle = self.deploy_input_oracle(&provider).await?;
		let output_oracle = self.deploy_output_oracle(&provider).await?;

		// Build contract addresses
		let addresses = ContractAddresses {
			chain,
			permit2: Some(permit2),
			input_settler: Some(input_settler),
			input_settler_compact: Some(input_settler_compact),
			output_settler: Some(output_settler),
			the_compact: Some(the_compact),
			allocator: Some(allocator),
			input_oracle: Some(input_oracle),
			output_oracle: Some(output_oracle),
			tokens,
		};

		logging::verbose_success("Contract deployment completed", &format!("chain {chain}"));
		Ok(addresses)
	}

	/// Deploy a contract from its compiled JSON
	async fn deploy_contract(
		&self,
		provider: &Provider,
		contract_name: &str,
		constructor_args: Option<Bytes>,
	) -> Result<Address> {
		// Find and load contract JSON
		let contract_json = self.load_contract_json(contract_name)?;

		// Extract bytecode
		let bytecode = self.extract_bytecode(&contract_json)?;

		// Create transaction request
		let mut data = bytecode;
		if let Some(args) = constructor_args {
			let mut combined = data.to_vec();
			combined.extend_from_slice(&args);
			data = Bytes::from(combined);
		}

		// Create signer for deployment
		let signer = self.get_solver_signer()?;

		let tx = TransactionRequest::default()
			.with_kind(alloy_primitives::TxKind::Create)
			.input(data.into())
			.value(U256::ZERO);

		// Send transaction
		let tx_builder = TxBuilder::new(provider.clone()).with_signer(signer);
		let receipt = tx_builder.send_and_wait(tx).await?;

		// Extract contract address from receipt
		let address = receipt
			.contract_address
			.ok_or_else(|| Error::DeploymentFailed("No contract address in receipt".to_string()))?;

		logging::verbose_success(
			"Contract deployed",
			&format!("{contract_name} at {address}"),
		);
		Ok(address)
	}

	/// Load contract JSON from the contracts directory
	fn load_contract_json(&self, contract_name: &str) -> Result<Value> {
		// Look for the contract in the expected paths
		let possible_paths = vec![
			self.contracts_path
				.join(format!("{contract_name}.sol"))
				.join(format!("{contract_name}.json")),
			self.contracts_path
				.join(format!("{contract_name}.sol/{contract_name}.json")),
		];

		for path in &possible_paths {
			if path.exists() {
				let content = std::fs::read_to_string(path).map_err(|e| {
					Error::InvalidConfig(format!("Failed to read {}: {}", path.display(), e))
				})?;

				let json: Value = serde_json::from_str(&content).map_err(|e| {
					Error::InvalidConfig(format!("Invalid JSON in {}: {}", path.display(), e))
				})?;

				return Ok(json);
			}
		}

		Err(Error::InvalidConfig(format!(
			"Contract {} not found in {}",
			contract_name,
			self.contracts_path.display()
		)))
	}

	/// Extract bytecode from contract JSON
	fn extract_bytecode(&self, contract_json: &Value) -> Result<Bytes> {
		let bytecode_obj = contract_json
			.get("bytecode")
			.and_then(|b| b.get("object"))
			.and_then(|o| o.as_str())
			.ok_or_else(|| {
				Error::InvalidConfig("No bytecode found in contract JSON".to_string())
			})?;

		// Remove 0x prefix if present
		let hex_str = bytecode_obj.strip_prefix("0x").unwrap_or(bytecode_obj);

		hex::decode(hex_str)
			.map_err(|e| Error::InvalidConfig(format!("Invalid bytecode hex: {e}")))
			.map(Bytes::from)
	}

	/// Helper function to encode constructor arguments
	fn encode_constructor_args(&self, constructor_args: Vec<DynSolValue>) -> Bytes {
		let tuple_value = DynSolValue::Tuple(constructor_args);
		let encoded_args = tuple_value.abi_encode_sequence().unwrap_or_default();
		Bytes::from(encoded_args)
	}

	/// Deploy Permit2 contract
	async fn deploy_permit2(&self, provider: &Provider) -> Result<Address> {
		// Check if we should use canonical Permit2 address
		if !self.ctx.is_local() {
			// Use canonical Permit2 address on mainnet/testnets
			let address: Address = constants::PERMIT2_ADDRESS
				.parse()
				.map_err(|e| Error::InvalidConfig(format!("Invalid Permit2 address: {e}")))?;
			logging::verbose_tech("Using canonical Permit2", &address.to_string());
			return Ok(address);
		}

		// Deploy locally using embedded bytecode
		match self.deploy_permit2_from_bytecode(provider).await {
			Ok(address) => {
				logging::verbose_success("Permit2 deployed", &address.to_string());
				Ok(address)
			},
			Err(e) => {
				use crate::core::logging;
				logging::warning(&format!("Permit2 deployment failed: {e}"));
				Err(Error::DeploymentFailed(format!(
					"Failed to deploy permit2 from bytecode: {e}"
				)))
			},
		}
	}

	/// Deploy Permit2 from embedded bytecode using anvil_setCode
	async fn deploy_permit2_from_bytecode(&self, provider: &Provider) -> Result<Address> {
		// Read Permit2 bytecode from file
		let bytecode_path =
			std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("data/permit2_bytecode.hex");

		let bytecode_hex = std::fs::read_to_string(&bytecode_path)
			.map_err(|e| Error::InvalidConfig(format!("Failed to read Permit2 bytecode: {e}")))?;

		// Prepare bytecode with 0x prefix
		let bytecode_hex = bytecode_hex.trim();
		let bytecode_with_prefix = if bytecode_hex.starts_with("0x") {
			bytecode_hex.to_string()
		} else {
			format!("0x{bytecode_hex}")
		};

		// Use anvil_setCode to set the bytecode at canonical address
		let canonical_address = constants::PERMIT2_ADDRESS;

		provider
			.set_code(canonical_address, &bytecode_with_prefix)
			.await
			.map_err(|e| Error::DeploymentFailed(format!("Failed to set Permit2 code: {e}")))?;

		// Parse the canonical address as Address
		let address = canonical_address
			.parse::<Address>()
			.map_err(|e| Error::InvalidConfig(format!("Invalid canonical address: {e}")))?;

		Ok(address)
	}

	/// Deploy Input Settler contract
	async fn deploy_input_settler(&self, provider: &Provider) -> Result<Address> {
		self.deploy_contract(provider, "InputSettlerEscrow", None)
			.await
	}

	/// Deploy Output Settler contract
	async fn deploy_output_settler(&self, provider: &Provider) -> Result<Address> {
		self.deploy_contract(provider, "OutputSettlerSimple", None)
			.await
	}

	/// Deploy The Compact contract
	async fn deploy_the_compact(&self, provider: &Provider) -> Result<Address> {
		self.deploy_contract(provider, "TheCompact", None).await
	}

	/// Deploy Allocator contract
	async fn deploy_allocator(&self, provider: &Provider) -> Result<Address> {
		self.deploy_contract(provider, "AlwaysOKAllocator", None)
			.await
	}

	/// Deploy InputSettlerCompact contract
	async fn deploy_input_settler_compact(
		&self,
		provider: &Provider,
		the_compact_address: Address,
	) -> Result<Address> {
		// Encode constructor arguments (takes TheCompact address)
		let constructor_args = self.encode_constructor_args(vec![the_compact_address.into()]);
		self.deploy_contract(provider, "InputSettlerCompact", Some(constructor_args))
			.await
	}

	/// Deploy AlwaysYesOracle contract for input oracle
	async fn deploy_input_oracle(&self, provider: &Provider) -> Result<Address> {
		self.deploy_contract(provider, "AlwaysYesOracle", None)
			.await
	}

	/// Deploy AlwaysYesOracle contract for output oracle
	async fn deploy_output_oracle(&self, provider: &Provider) -> Result<Address> {
		self.deploy_contract(provider, "AlwaysYesOracle", None)
			.await
	}

	/// Deploy test tokens for local environment
	async fn deploy_test_tokens(
		&self,
		provider: &Provider,
	) -> Result<HashMap<String, (Address, u8)>> {
		let mut tokens = HashMap::new();

		// Deploy standard test tokens
		let toka = self
			.deploy_test_token(
				provider,
				"TOKA",
				"USD Coin",
				constants::DEFAULT_TOKEN_DECIMALS,
			)
			.await?;
		let tokb = self
			.deploy_test_token(
				provider,
				"TOKB",
				"Tether USD",
				constants::DEFAULT_TOKEN_DECIMALS,
			)
			.await?;

		tokens.insert(
			"TOKA".to_string(),
			(toka, constants::DEFAULT_TOKEN_DECIMALS),
		);
		tokens.insert(
			"TOKB".to_string(),
			(tokb, constants::DEFAULT_TOKEN_DECIMALS),
		);

		logging::verbose_success("Test tokens deployment", "completed");
		Ok(tokens)
	}

	/// Deploy a single test token
	async fn deploy_test_token(
		&self,
		provider: &Provider,
		symbol: &str,
		name: &str,
		decimals: u8,
	) -> Result<Address> {
		// Encode constructor arguments for MockERC20(string name, string symbol, uint8 decimals)
		let constructor_args = vec![
			DynSolValue::String(name.to_string()),
			DynSolValue::String(symbol.to_string()),
			DynSolValue::Uint(U256::from(decimals), 8),
		];

		let encoded_args = self.encode_constructor_args(constructor_args);
		let address = self
			.deploy_contract(provider, "MockERC20", Some(encoded_args))
			.await?;
		logging::verbose_success(
			"Test token deployed",
			&format!("{symbol} ({name}) at {address}"),
		);
		Ok(address)
	}

	/// Fund an account with test ETH (local only)
	pub async fn fund_account(&self, chain: ChainId, account: Address, amount: U256) -> Result<()> {
		if !self.ctx.is_local() {
			return Err(Error::NotLocalChain(chain));
		}

		let provider = self.ctx.provider(chain).await?;

		// Create a transaction to send ETH from the default funded account
		let signer = PrivateKeySigner::from_str(constants::anvil_accounts::SOLVER_PRIVATE_KEY)
			.map_err(|e| Error::InvalidConfig(format!("Invalid private key: {e}")))?;

		let tx = TransactionRequest::default()
			.to(account)
			.value(amount)
			.input(Bytes::new().into());

		let tx_builder = TxBuilder::new(provider).with_signer(signer);
		let _receipt = tx_builder.send_and_wait(tx).await?;

		logging::verbose_success("Account funded", &format!("{account} with {amount} ETH"));
		Ok(())
	}

	/// Deploy a single contract by name to a specific chain
	pub async fn deploy_single_contract(
		&self,
		contract_name: &str,
		chain: ChainId,
	) -> Result<Address> {
		logging::verbose_operation(
			"Starting single contract deployment",
			&format!("{contract_name} on chain {chain}"),
		);

		// Create provider for this chain
		let provider = self.ctx.provider(chain).await?;

		// Deploy the specific contract
		let address = self.deploy_contract(&provider, contract_name, None).await?;

		Ok(address)
	}

	/// List available contracts in the contracts directory
	pub fn list_available_contracts(&self) -> Result<Vec<String>> {
		let mut contracts = Vec::new();

		if !self.contracts_path.exists() {
			return Ok(contracts);
		}

		for entry in std::fs::read_dir(&self.contracts_path)
			.map_err(|e| Error::InvalidConfig(format!("Failed to read contracts directory: {e}")))?
		{
			let entry = entry.map_err(|e| {
				Error::InvalidConfig(format!("Failed to read directory entry: {e}"))
			})?;

			if entry
				.file_type()
				.map_err(|e| Error::InvalidConfig(format!("Failed to get file type: {e}")))?
				.is_dir()
			{
				let dir_name = entry.file_name();
				if let Some(name) = dir_name.to_str() {
					if name.ends_with(".sol") {
						// Look for contract JSON files in this directory
						let sol_dir = entry.path();
						if let Ok(entries) = std::fs::read_dir(&sol_dir) {
							for json_entry in entries.flatten() {
								if let Some(json_name) = json_entry.file_name().to_str() {
									if json_name.ends_with(".json") && !json_name.contains("Test") {
										let contract_name =
											json_name.strip_suffix(".json").unwrap_or(json_name);
										if !contracts.contains(&contract_name.to_string()) {
											contracts.push(contract_name.to_string());
										}
									}
								}
							}
						}
					}
				}
			}
		}

		contracts.sort();
		Ok(contracts)
	}

	/// Get user signer for transactions
	fn get_solver_signer(&self) -> Result<alloy_signer_local::PrivateKeySigner> {
		let private_key = self
			.ctx
			.config
			.accounts()
			.solver
			.private_key
			.as_ref()
			.ok_or_else(|| {
				crate::types::error::Error::InvalidConfig("No private key configured".to_string())
			})?;

		private_key.with_exposed(|key| {
			key.parse().map_err(|_| {
				crate::types::error::Error::InvalidConfig("Invalid private key format".to_string())
			})
		})
	}
}
