//! Smart contract interaction and management module.
//!
//! This module provides comprehensive smart contract interaction capabilities for the OIF Solver
//! demonstration system. It orchestrates contract deployments, function calls, transaction
//! sending, and state queries across multiple blockchain networks. The ContractManager serves
//! as the primary interface for all contract-related operations, abstracting away the
//! complexities of multi-chain interaction while providing detailed logging and error handling.
//!
//! The module integrates closely with the AbiManager for contract interface management and
//! the DeployerManager for deployment operations. It maintains provider connections for
//! efficient network communication and supports both read-only calls and state-changing
//! transactions with proper transaction confirmation monitoring.

use alloy_primitives::{Address, U256};
use alloy_sol_types::SolCall;
use anyhow::{anyhow, Result};
use ethers::{
	abi::Token,
	contract::Contract,
	core::types::{TransactionReceipt, H256},
	middleware::SignerMiddleware,
	providers::{Http, Middleware, Provider},
	signers::{LocalWallet, Signer},
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::core::{AbiManager, DeployerManager};

/// Manager for smart contract interactions across multiple blockchain networks.
///
/// The ContractManager coordinates all contract-related operations including deployment,
/// function calls, transaction submission, and state queries. It maintains provider
/// connections for each supported network and integrates with the AbiManager and
/// DeployerManager to provide a unified interface for contract operations. The manager
/// handles transaction confirmation, error reporting, and provider lifecycle management.
pub struct ContractManager {
	/// Reference to the ABI manager for contract interface operations.
	///
	/// Provides access to contract ABIs and bytecode for deployment and
	/// interaction operations across all supported contracts.
	abi_manager: Arc<AbiManager>,

	/// Reference to the deployer manager for contract deployment operations.
	///
	/// Enables access to signing capabilities and deployment coordination
	/// for new contract instances across multiple networks.
	deployer_manager: Arc<DeployerManager>,

	/// Thread-safe cache of blockchain network providers.
	///
	/// Maintains HTTP provider instances for each configured chain to
	/// optimize network communication and reduce connection overhead.
	providers: Arc<RwLock<HashMap<u64, Arc<Provider<Http>>>>>,
}

impl ContractManager {
	/// Creates a new ContractManager with the specified dependencies.
	///
	/// Initializes the contract manager with references to the ABI manager
	/// and deployer manager, setting up the foundation for contract operations.
	/// The provider cache is initialized empty and will be populated on-demand
	/// as networks are accessed.
	pub fn new(abi_manager: Arc<AbiManager>, deployer_manager: Arc<DeployerManager>) -> Self {
		Self {
			abi_manager,
			deployer_manager,
			providers: Arc::new(RwLock::new(HashMap::new())),
		}
	}

	/// Deploys a smart contract to the specified blockchain network.
	///
	/// Orchestrates the complete contract deployment process by retrieving the
	/// contract ABI and bytecode from the ABI manager, then coordinating with
	/// the deployer manager to execute the deployment transaction. Returns the
	/// deployed contract address upon successful completion.
	pub async fn deploy_contract(
		&self,
		chain_id: u64,
		contract_name: &str,
		constructor_args: Vec<Token>,
	) -> Result<Address> {
		info!("Deploying contract {} to chain {}", contract_name, chain_id);

		let abi = self.abi_manager.get_abi(contract_name).await?;
		let bytecode = self.abi_manager.get_bytecode(contract_name).await?;

		let result = self
			.deployer_manager
			.deploy(chain_id, bytecode, &abi, constructor_args)
			.await?;

		info!(
			"Contract {} deployed at {} (tx: {})",
			contract_name, result.address, result.tx_hash
		);

		Ok(result.address)
	}

	/// Executes a read-only function call on a deployed smart contract.
	///
	/// Performs a view or pure function call that doesn't modify blockchain state.
	/// The method encodes the function call with provided arguments, executes it
	/// against the specified contract, and decodes the returned data. This is
	/// used for querying contract state without incurring transaction costs.
	pub async fn call_contract(
		&self,
		chain_id: u64,
		address: Address,
		abi_name: &str,
		function: &str,
		args: Vec<Token>,
	) -> Result<Vec<Token>> {
		debug!(
			"Calling {}::{} on chain {} at {}",
			abi_name, function, chain_id, address
		);

		let abi = self.abi_manager.get_abi(abi_name).await?;

		let provider = self.get_provider(chain_id).await?;

		let func = abi
			.function(function)
			.map_err(|e| anyhow!("Function '{}' not found in ABI: {}", function, e))?;

		let encoded = func
			.encode_input(&args)
			.map_err(|e| anyhow!("Failed to encode call for {}: {}", function, e))?;

		let tx = ethers::types::transaction::eip2718::TypedTransaction::Legacy(
			ethers::types::TransactionRequest::new()
				.to(ethers::types::H160::from_slice(address.as_slice()))
				.data(encoded),
		);

		let result = provider
			.call(&tx, None)
			.await
			.map_err(|e| anyhow!("Contract call failed: {}", e))?;

		let tokens = func
			.decode_output(&result)
			.map_err(|e| anyhow!("Failed to decode output: {}", e))?;

		Ok(tokens)
	}

	/// Sends a state-changing transaction to a smart contract.
	///
	/// Executes a function call that modifies blockchain state by creating,
	/// signing, and submitting a transaction. The method handles transaction
	/// encoding, gas estimation, signing with the appropriate wallet, and
	/// confirmation monitoring. Returns the transaction receipt upon successful
	/// execution and confirmation.
	pub async fn send_transaction(
		&self,
		chain_id: u64,
		address: Address,
		abi_name: &str,
		function: &str,
		args: Vec<Token>,
	) -> Result<TransactionReceipt> {
		info!(
			"Sending transaction {}::{} on chain {} to {}",
			abi_name, function, chain_id, address
		);

		debug!("Transaction args: {:?}", args);

		let abi = self.abi_manager.get_abi(abi_name).await?;
		debug!("Loaded ABI for {}", abi_name);

		let provider = self.get_provider(chain_id).await?;
		let signer = self.deployer_manager.get_signer(chain_id)?;

		let client = Arc::new(SignerMiddleware::new(provider.clone(), signer.clone()));

		let contract = Contract::new(
			ethers::types::H160::from_slice(address.as_slice()),
			abi,
			client.clone(),
		);

		debug!("Building method call for function: {}", function);
		debug!("Contract address: {:?}", contract.address());

		let func = contract
			.abi()
			.function(function)
			.map_err(|e| anyhow!("Function '{}' not found in ABI: {}", function, e))?;

		let encoded = func.encode_input(&args).map_err(|e| {
			debug!("Encoding failed: {:?}", e);
			debug!("Function name: {}", function);
			debug!("Args passed: {:?}", args);
			anyhow!("Failed to encode call for {}: {}", function, e)
		})?;

		let tx = ethers::types::TransactionRequest::new()
			.to(contract.address())
			.data(encoded);

		let pending_tx = client
			.send_transaction(tx, None)
			.await
			.map_err(|e| anyhow!("Failed to send transaction: {}", e))?;

		debug!("Transaction sent: {:?}", pending_tx);

		let receipt = pending_tx
			.await?
			.ok_or_else(|| anyhow!("Transaction receipt not found"))?;

		info!(
			"Transaction confirmed in block {} with status {}",
			receipt
				.block_number
				.map_or("pending".to_string(), |n| n.to_string()),
			receipt
				.status
				.map_or("unknown".to_string(), |s| s.to_string())
		);

		Ok(receipt)
	}

	/// Retrieves the native token balance for a specific address.
	///
	/// Queries the blockchain network to obtain the current native token
	/// balance (such as ETH) for the specified address. Returns the balance
	/// in the smallest denomination (wei for Ethereum).
	pub async fn get_balance(&self, chain_id: u64, address: Address) -> Result<U256> {
		let provider = self.get_provider(chain_id).await?;
		let balance = provider
			.get_balance(ethers::types::H160::from_slice(address.as_slice()), None)
			.await
			.map_err(|e| anyhow!("Failed to get balance: {}", e))?;

		Ok(U256::from(balance.as_u128()))
	}

	/// Retrieves the transaction receipt for a specific transaction hash.
	///
	/// Queries the blockchain network to obtain the transaction receipt,
	/// which contains execution details including gas usage, status, and
	/// emitted events. Returns None if the transaction is not yet confirmed.
	pub async fn get_transaction_receipt(
		&self,
		chain_id: u64,
		tx_hash: H256,
	) -> Result<Option<TransactionReceipt>> {
		let provider = self.get_provider(chain_id).await?;
		let receipt = provider
			.get_transaction_receipt(tx_hash)
			.await
			.map_err(|e| anyhow!("Failed to get transaction receipt: {}", e))?;

		Ok(receipt)
	}

	/// Waits for a transaction to receive the specified number of confirmations.
	///
	/// Monitors the blockchain network until the specified transaction has been
	/// confirmed with the requested number of block confirmations. This provides
	/// security against chain reorganizations by waiting for additional blocks
	/// to be mined after the transaction's inclusion.
	pub async fn wait_for_confirmation(
		&self,
		chain_id: u64,
		tx_hash: H256,
		confirmations: usize,
	) -> Result<TransactionReceipt> {
		let provider = self.get_provider(chain_id).await?;

		let mut attempts = 0;
		let max_attempts = 60; // Wait up to 60 seconds

		loop {
			if let Some(receipt) = provider.get_transaction_receipt(tx_hash).await? {
				if confirmations == 0 {
					return Ok(receipt);
				}

				if let Some(block_number) = receipt.block_number {
					let current_block = provider.get_block_number().await?;
					let confirms = current_block.saturating_sub(block_number).as_u64();
					if confirms >= confirmations as u64 {
						return Ok(receipt);
					}
				}
			}

			attempts += 1;
			if attempts >= max_attempts {
				return Err(anyhow!(
					"Transaction not found after {} attempts: {:?}",
					max_attempts,
					tx_hash
				));
			}

			tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
		}
	}

	/// Retrieves or creates a blockchain provider for the specified chain.
	///
	/// Returns a cached provider instance for the chain if available, otherwise
	/// creates a new provider using the RPC URL from the session manager.
	/// The provider is cached for future use to optimize network operations.
	async fn get_provider(&self, chain_id: u64) -> Result<Arc<Provider<Http>>> {
		let mut providers = self.providers.write().await;

		if let Some(provider) = providers.get(&chain_id) {
			return Ok(provider.clone());
		}

		let session_manager = &self.deployer_manager.session_manager;
		let rpc_url = session_manager
			.get_rpc_url(chain_id)
			.await
			.ok_or_else(|| anyhow!("No RPC URL for chain {}", chain_id))?;

		let provider = Arc::new(Provider::<Http>::try_from(rpc_url)?);
		providers.insert(chain_id, provider.clone());

		Ok(provider)
	}

	/// Removes the cached provider for a specific chain.
	///
	/// Clears the provider instance from the cache, forcing the next
	/// operation on this chain to create a fresh provider connection.
	/// Useful for handling network connectivity issues or configuration changes.
	pub async fn clear_provider(&self, chain_id: u64) {
		let mut providers = self.providers.write().await;
		providers.remove(&chain_id);
	}

	/// Clears all cached provider instances.
	///
	/// Removes all provider connections from the cache, forcing fresh
	/// connections for all subsequent operations. Useful for resetting
	/// network state or handling widespread connectivity issues.
	pub async fn clear_all_providers(&self) {
		let mut providers = self.providers.write().await;
		providers.clear();
	}

	/// Approves tokens for a spender contract.
	///
	/// Sends an ERC20 approve transaction to allow the spender contract
	/// to transfer tokens on behalf of the signer.
	pub async fn approve_tokens(
		&self,
		token_address: Address,
		spender: Address,
		amount: U256,
		private_key: &str,
		rpc_url: &str,
	) -> Result<String> {
		info!(
			"Approving {} to spend {} tokens from {}",
			spender, amount, token_address
		);

		// Create provider and wallet
		let provider = Provider::<Http>::try_from(rpc_url)?;
		let wallet: LocalWallet = private_key
			.parse()
			.map_err(|e| anyhow!("Failed to parse private key: {}", e))?;
		let chain_id = provider.get_chainid().await?.as_u64();
		let wallet = wallet.with_chain_id(chain_id);

		let client = Arc::new(SignerMiddleware::new(provider, wallet));

		// Create ERC20 contract instance
		let erc20_abi = self.abi_manager.get_abi("MockERC20").await?;
		let contract = Contract::new(
			ethers::types::H160::from_slice(token_address.as_slice()),
			erc20_abi,
			client.clone(),
		);

		// Call approve function
		let method_call = contract
			.method::<_, H256>(
				"approve",
				(
					ethers::types::H160::from_slice(spender.as_slice()),
					ethers::types::U256::from_big_endian(&amount.to_be_bytes::<32>()),
				),
			)
			.map_err(|e| anyhow!("Failed to build approve transaction: {}", e))?;

		let pending_tx = method_call
			.send()
			.await
			.map_err(|e| anyhow!("Failed to send approve transaction: {}", e))?;

		let tx_hash = pending_tx.tx_hash();
		info!("Token approval transaction sent: {:?}", tx_hash);

		// Wait for confirmation
		let receipt = pending_tx
			.await
			.map_err(|e| anyhow!("Failed to wait for transaction: {}", e))?
			.ok_or_else(|| anyhow!("Transaction receipt not found"))?;

		if receipt.status != Some(1.into()) {
			return Err(anyhow!("Token approval transaction failed"));
		}

		Ok(format!("{:?}", tx_hash))
	}

	/// Submits an intent onchain to the InputSettler contract.
	///
	/// Calls the open() function on the InputSettler contract with the
	/// StandardOrder struct to submit an intent directly to the blockchain.
	pub async fn submit_intent_onchain(
		&self,
		input_settler: Address,
		order: &solver_types::standards::eip7683::interfaces::StandardOrder,
		private_key: &str,
		rpc_url: &str,
		contract_type: &str,
	) -> Result<String> {
		info!(
			"Submitting intent onchain to InputSettler at {}",
			input_settler
		);

		// Create provider and wallet
		let provider = Provider::<Http>::try_from(rpc_url)?;
		let wallet: LocalWallet = private_key
			.parse()
			.map_err(|e| anyhow!("Failed to parse private key: {}", e))?;
		let chain_id = provider.get_chainid().await?.as_u64();
		let wallet = wallet.with_chain_id(chain_id);

		let client = Arc::new(SignerMiddleware::new(provider, wallet));

		// Get the appropriate settler ABI based on the order type
		let settler_abi = self
			.abi_manager
			.get_abi(contract_type)
			.await
			.map_err(|e| anyhow!("Failed to get ABI for {}: {}", contract_type, e))?;
		let contract = Contract::new(
			ethers::types::H160::from_slice(input_settler.as_slice()),
			settler_abi,
			client.clone(),
		);

		// Use alloy's ABI encoding to encode the StandardOrder, then manually build the call
		// The encoding depends on the contract type (escrow vs compact)
		let call_data = match contract_type {
			"InputSettlerEscrow" => {
				use solver_types::standards::eip7683::interfaces::IInputSettlerEscrow;

				// Build the open call using alloy for escrow
				let open_call = IInputSettlerEscrow::openCall {
					order: order.clone(),
				};

				// Encode the call data
				open_call.abi_encode()
			},
			"InputSettlerCompact" => {
				// Compact settler doesn't have an open function
				// It requires the compact signature and uses a different flow
				// For onchain submission of compact orders, we would need to call
				// TheCompact contract first to deposit/lock resources, then submit
				// This is not currently supported in the demo
				return Err(anyhow!("Onchain submission for InputSettlerCompact is not yet implemented. Compact orders require depositing to TheCompact first."));
			},
			_ => {
				return Err(anyhow!("Unsupported contract type: {}", contract_type));
			},
		};

		debug!(
			"Encoded call data for {}: 0x{}",
			contract_type,
			hex::encode(&call_data)
		);

		// Send the transaction using raw call data
		let client = contract.client().clone();
		let tx = ethers::core::types::TransactionRequest::new()
			.to(ethers::types::H160::from_slice(input_settler.as_slice()))
			.data(call_data.to_vec());
		let pending_tx = client
			.send_transaction(tx, None)
			.await
			.map_err(|e| anyhow!("Failed to send open transaction: {}", e))?;

		let tx_hash = pending_tx.tx_hash();
		info!("Intent submission transaction sent: {:?}", tx_hash);

		// Wait for confirmation
		let receipt = pending_tx
			.await
			.map_err(|e| anyhow!("Failed to wait for transaction: {}", e))?
			.ok_or_else(|| anyhow!("Transaction receipt not found"))?;

		if receipt.status != Some(1.into()) {
			return Err(anyhow!("Intent submission transaction failed"));
		}

		Ok(format!("{:?}", tx_hash))
	}
}
