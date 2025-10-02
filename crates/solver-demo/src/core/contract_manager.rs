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

use alloy_dyn_abi::{DynSolType, DynSolValue};
use alloy_network::EthereumWallet;
use alloy_primitives::{Address, B256, U256};
use alloy_provider::{Provider, ProviderBuilder, RootProvider};
use alloy_rpc_types::{TransactionReceipt, TransactionRequest};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use alloy_transport_http::Http;
use anyhow::{anyhow, Result};
use reqwest::Client;
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
	#[allow(clippy::type_complexity)]
	providers: Arc<RwLock<HashMap<u64, Arc<RootProvider<Http<Client>>>>>>,
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
		constructor_args: Vec<DynSolValue>,
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
		args: Vec<DynSolValue>,
	) -> Result<Vec<DynSolValue>> {
		debug!(
			"Calling {}::{} on chain {} at {}",
			abi_name, function, chain_id, address
		);

		let abi = self.abi_manager.get_abi(abi_name).await?;

		let provider = self.get_provider(chain_id).await?;

		let func = abi
			.function(function)
			.ok_or_else(|| anyhow!("Function '{}' not found in ABI", function))?
			.first()
			.ok_or_else(|| anyhow!("Function '{}' has no implementations", function))?;

		// Encode using dynamic ABI encoding
		let mut encoded = func.selector().to_vec();

		// Encode the inputs using dynamic ABI types
		if !args.is_empty() {
			// Use alloy's dynamic ABI encoder
			let tuple_value = DynSolValue::Tuple(args);
			let encoded_inputs = tuple_value
				.abi_encode_sequence()
				.ok_or_else(|| anyhow!("Failed to encode function arguments"))?;
			encoded.extend(encoded_inputs);
		}

		let tx = TransactionRequest::default()
			.to(address)
			.input(encoded.into());

		let result = provider
			.call(&tx)
			.await
			.map_err(|e| anyhow!("Contract call failed: {}", e))?;

		// Decode the output
		let output_types: Vec<DynSolType> = func
			.outputs
			.iter()
			.map(|param| param.ty.parse().unwrap())
			.collect();

		let tokens = if output_types.is_empty() {
			vec![]
		} else {
			let tuple_type = DynSolType::Tuple(output_types);
			let decoded = tuple_type
				.abi_decode(&result)
				.map_err(|e| anyhow!("Failed to decode output: {}", e))?;
			if let DynSolValue::Tuple(values) = decoded {
				values
			} else {
				vec![decoded]
			}
		};

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
		args: Vec<DynSolValue>,
	) -> Result<TransactionReceipt> {
		self.send_transaction_with_key(chain_id, address, abi_name, function, args, None)
			.await
	}

	/// Executes a function call that modifies blockchain state with an optional private key.
	///
	/// If private_key is provided, uses that key for signing. Otherwise uses the default
	/// deployer signer for the chain.
	pub async fn send_transaction_with_key(
		&self,
		chain_id: u64,
		address: Address,
		abi_name: &str,
		function: &str,
		args: Vec<DynSolValue>,
		private_key: Option<PrivateKeySigner>,
	) -> Result<TransactionReceipt> {
		info!(
			"Sending transaction {}::{} on chain {} to {}",
			abi_name, function, chain_id, address
		);

		info!("Transaction args: {:?}", args);

		let abi = self.abi_manager.get_abi(abi_name).await?;
		info!("Loaded ABI for {}", abi_name);

		let provider = self.get_provider(chain_id).await?;
		let signer = if let Some(wallet) = private_key {
			wallet
		} else {
			self.deployer_manager.get_signer(chain_id)?.clone()
		};

		let wallet = EthereumWallet::from(signer);
		let rpc_url = provider.client().transport().url();
		let provider_with_signer = ProviderBuilder::new()
			.with_recommended_fillers()
			.wallet(wallet)
			.on_http(rpc_url.parse()?);

		debug!("Building method call for function: {}", function);
		debug!("Contract address: {:?}", address);

		let func = abi
			.function(function)
			.ok_or_else(|| anyhow!("Function '{}' not found in ABI", function))?
			.first()
			.ok_or_else(|| anyhow!("Function '{}' has no implementations", function))?;

		// Encode using dynamic ABI encoding
		let mut encoded = func.selector().to_vec();
		info!(
			"Function selector for {}: 0x{}",
			function,
			hex::encode(func.selector())
		);

		// Encode the inputs using dynamic ABI types
		if !args.is_empty() {
			info!("Encoding {} arguments", args.len());
			for (i, arg) in args.iter().enumerate() {
				info!("  Arg[{}]: {:?}", i, arg);
			}

			// Use alloy's dynamic ABI encoder
			let tuple_value = DynSolValue::Tuple(args);
			let encoded_inputs = tuple_value
				.abi_encode_sequence()
				.ok_or_else(|| anyhow!("Failed to encode function arguments"))?;
			info!("Encoded inputs: 0x{}", hex::encode(&encoded_inputs));
			encoded.extend(encoded_inputs);
		}

		info!("Full calldata: 0x{}", hex::encode(&encoded));

		let tx = TransactionRequest::default()
			.to(address)
			.input(encoded.into());

		let pending_tx = provider_with_signer
			.send_transaction(tx)
			.await
			.map_err(|e| anyhow!("Failed to send transaction: {}", e))?;

		debug!("Transaction sent: {:?}", pending_tx.tx_hash());

		let receipt = pending_tx
			.get_receipt()
			.await
			.map_err(|e| anyhow!("Failed to get transaction receipt: {}", e))?;

		info!(
			"Transaction confirmed in block {} with status {}",
			receipt
				.block_number
				.map_or("pending".to_string(), |n| n.to_string()),
			receipt.status()
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
			.get_balance(address)
			.await
			.map_err(|e| anyhow!("Failed to get balance: {}", e))?;

		Ok(balance)
	}

	/// Retrieves the transaction receipt for a specific transaction hash.
	///
	/// Queries the blockchain network to obtain the transaction receipt,
	/// which contains execution details including gas usage, status, and
	/// emitted events. Returns None if the transaction is not yet confirmed.
	pub async fn get_transaction_receipt(
		&self,
		chain_id: u64,
		tx_hash: B256,
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
		tx_hash: B256,
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
					let confirms = current_block.saturating_sub(block_number);
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
	pub async fn get_provider(&self, chain_id: u64) -> Result<Arc<RootProvider<Http<Client>>>> {
		let mut providers = self.providers.write().await;

		if let Some(provider) = providers.get(&chain_id) {
			return Ok(provider.clone());
		}

		let session_manager = &self.deployer_manager.session_manager;
		let rpc_url = session_manager
			.get_rpc_url(chain_id)
			.await
			.ok_or_else(|| anyhow!("No RPC URL for chain {}", chain_id))?;

		let provider = Arc::new(ProviderBuilder::new().on_http(rpc_url.parse()?));
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
		let wallet: PrivateKeySigner = private_key
			.parse()
			.map_err(|e| anyhow!("Failed to parse private key: {}", e))?;
		let eth_wallet = EthereumWallet::from(wallet);
		let provider_with_signer = ProviderBuilder::new()
			.with_recommended_fillers()
			.wallet(eth_wallet)
			.on_http(rpc_url.parse()?);

		// Create ERC20 contract instance
		let erc20_abi = self.abi_manager.get_abi("MockERC20").await?;

		// Build approve function call
		let func = erc20_abi
			.function("approve")
			.ok_or_else(|| anyhow!("Function 'approve' not found in ABI"))?
			.first()
			.ok_or_else(|| anyhow!("Function 'approve' has no implementations"))?;

		// Encode using dynamic ABI encoding
		let mut encoded = func.selector().to_vec();

		let args = vec![
			DynSolValue::Address(spender),
			DynSolValue::Uint(amount, 256),
		];

		// Encode the inputs using dynamic ABI types
		if !args.is_empty() {
			// Use alloy's dynamic ABI encoder
			let tuple_value = DynSolValue::Tuple(args);
			let encoded_inputs = tuple_value
				.abi_encode_sequence()
				.ok_or_else(|| anyhow!("Failed to encode function arguments"))?;
			encoded.extend(encoded_inputs);
		}

		let tx = TransactionRequest::default()
			.to(token_address)
			.input(encoded.into());

		let pending_tx = provider_with_signer
			.send_transaction(tx)
			.await
			.map_err(|e| anyhow!("Failed to send approve transaction: {}", e))?;

		let tx_hash = *pending_tx.tx_hash();
		info!("Token approval transaction sent: {:?}", tx_hash);

		// Wait for confirmation
		let receipt = pending_tx
			.get_receipt()
			.await
			.map_err(|e| anyhow!("Failed to wait for transaction: {}", e))?;

		if !receipt.status() {
			return Err(anyhow!("Token approval transaction failed"));
		}

		Ok(format!("{:?}", tx_hash))
	}

	/// Computes the order identifier from an InputSettler contract.
	///
	/// Calls the orderIdentifier() function on the InputSettler contract with the
	/// StandardOrder struct to get the proper order identifier bytes32 value.
	pub async fn compute_order_identifier(
		&self,
		chain_id: u64,
		input_settler_address: Address,
		order: &solver_types::standards::eip7683::interfaces::StandardOrder,
	) -> Result<[u8; 32]> {
		use alloy_sol_types::SolCall;
		use solver_types::standards::eip7683::interfaces::IInputSettlerEscrow;

		println!("📞 [CONTRACT] Calling orderIdentifier on InputSettler");
		println!("📞 [CONTRACT] Chain ID: {}", chain_id);
		println!(
			"📞 [CONTRACT] InputSettler: {}",
			crate::utils::address::to_checksum_address(&input_settler_address, Some(chain_id))
		);

		// Build the orderIdentifier call using alloy (same ABI for compact or escrow)
		let order_id_call = IInputSettlerEscrow::orderIdentifierCall {
			order: order.clone(),
		};

		// Encode the call data
		let call_data = order_id_call.abi_encode();
		println!("📞 [CONTRACT] Call data length: {} bytes", call_data.len());
		println!("📞 [CONTRACT] Call data: 0x{}", hex::encode(&call_data));

		let provider = self.get_provider(chain_id).await?;

		// Make the call
		let tx = TransactionRequest::default()
			.to(input_settler_address)
			.input(call_data.into());

		println!("📞 [CONTRACT] Making RPC call to orderIdentifier...");
		let result = provider.call(&tx).await.map_err(|e| {
			println!("❌ [CONTRACT] RPC call failed: {}", e);
			anyhow!("Failed to call orderIdentifier: {}", e)
		})?;

		println!(
			"📞 [CONTRACT] RPC call successful, result length: {}",
			result.len()
		);
		println!("📞 [CONTRACT] Raw result: 0x{}", hex::encode(&result));

		if result.len() != 32 {
			return Err(anyhow!(
				"Invalid orderIdentifier result length: {}",
				result.len()
			));
		}

		let mut order_id = [0u8; 32];
		order_id.copy_from_slice(&result);
		println!("📞 [CONTRACT] Parsed order ID: 0x{}", hex::encode(order_id));
		Ok(order_id)
	}

	/// Deposits ERC20 tokens to TheCompact contract.
	///
	/// Calls the depositERC20() function on TheCompact contract to lock tokens
	/// with a specified allocator lock tag. This is required before submitting
	/// compact/resource lock intents.
	#[allow(clippy::too_many_arguments)]
	pub async fn deposit_to_compact(
		&self,
		the_compact_address: Address,
		token_address: Address,
		allocator_lock_tag: [u8; 12],
		amount: U256,
		recipient: Address,
		private_key: &str,
		rpc_url: &str,
	) -> Result<String> {
		info!(
			"Depositing {} tokens to TheCompact for recipient {}",
			amount, recipient
		);

		// Create provider and wallet
		let wallet: PrivateKeySigner = private_key
			.parse()
			.map_err(|e| anyhow!("Failed to parse private key: {}", e))?;
		let eth_wallet = EthereumWallet::from(wallet);
		let provider_with_signer = ProviderBuilder::new()
			.with_recommended_fillers()
			.wallet(eth_wallet)
			.on_http(rpc_url.parse()?);

		// Get TheCompact ABI
		let compact_abi = self.abi_manager.get_abi("TheCompact").await?;

		// Build depositERC20 function call
		// function depositERC20(address token, bytes12 allocatorLockTag, uint256 amount, address recipient)
		let func = compact_abi
			.function("depositERC20")
			.ok_or_else(|| anyhow!("Function 'depositERC20' not found in ABI"))?
			.first()
			.ok_or_else(|| anyhow!("Function 'depositERC20' has no implementations"))?;

		// Encode using dynamic ABI encoding
		let mut encoded = func.selector().to_vec();

		// Convert the 12-byte allocator_lock_tag to a 32-byte Word for FixedBytes
		let mut word_bytes = [0u8; 32];
		word_bytes[0..12].copy_from_slice(&allocator_lock_tag);
		let word = alloy_primitives::FixedBytes::<32>::from(word_bytes);

		let args = vec![
			DynSolValue::Address(token_address),
			DynSolValue::FixedBytes(word, 12),
			DynSolValue::Uint(amount, 256),
			DynSolValue::Address(recipient),
		];

		// Encode the inputs
		if !args.is_empty() {
			let tuple_value = DynSolValue::Tuple(args);
			let encoded_inputs = tuple_value
				.abi_encode_sequence()
				.ok_or_else(|| anyhow!("Failed to encode function arguments"))?;
			encoded.extend(encoded_inputs);
		}

		let tx = TransactionRequest::default()
			.to(the_compact_address)
			.input(encoded.into());

		let pending_tx = provider_with_signer
			.send_transaction(tx)
			.await
			.map_err(|e| anyhow!("Failed to send deposit transaction: {}", e))?;

		let tx_hash = *pending_tx.tx_hash();
		info!("Deposit transaction sent: {:?}", tx_hash);

		// Wait for confirmation
		let receipt = pending_tx
			.get_receipt()
			.await
			.map_err(|e| anyhow!("Failed to wait for deposit transaction: {}", e))?;

		if !receipt.status() {
			return Err(anyhow!("Deposit transaction failed"));
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
		let wallet: PrivateKeySigner = private_key
			.parse()
			.map_err(|e| anyhow!("Failed to parse private key: {}", e))?;
		let eth_wallet = EthereumWallet::from(wallet);
		let provider_with_signer = ProviderBuilder::new()
			.with_recommended_fillers()
			.wallet(eth_wallet)
			.on_http(rpc_url.parse()?);

		// Get the appropriate settler ABI based on the order type
		let _settler_abi = self
			.abi_manager
			.get_abi(contract_type)
			.await
			.map_err(|e| anyhow!("Failed to get ABI for {}: {}", contract_type, e))?;

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
				SolCall::abi_encode(&open_call)
			},
			"InputSettlerCompact" => {
				// Compact settler doesn't have an open function
				// It requires the compact signature and uses a different flow
				// For onchain submission of compact orders, we would need to call
				// TheCompact contract first to deposit/lock resources, then submit
				// This is not currently supported in the demo
				return Err(anyhow!(
					"Onchain submission for InputSettlerCompact is not yet implemented. Compact orders require depositing to TheCompact first."
				));
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
		let tx = TransactionRequest::default()
			.to(input_settler)
			.input(call_data.into());
		let pending_tx = provider_with_signer
			.send_transaction(tx)
			.await
			.map_err(|e| anyhow!("Failed to send open transaction: {}", e))?;

		let tx_hash = *pending_tx.tx_hash();
		info!("Intent submission transaction sent: {:?}", tx_hash);

		// Wait for confirmation
		let receipt = pending_tx
			.get_receipt()
			.await
			.map_err(|e| anyhow!("Failed to wait for transaction: {}", e))?;

		if !receipt.status() {
			return Err(anyhow!("Intent submission transaction failed"));
		}

		Ok(format!("{:?}", tx_hash))
	}
}
