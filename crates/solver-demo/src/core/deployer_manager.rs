//! Contract deployment orchestration and management module.
//!
//! This module provides comprehensive smart contract deployment capabilities across multiple
//! blockchain networks. It handles the complex orchestration of deployment operations including
//! transaction signing, nonce management, gas estimation, and deployment verification. The
//! DeployerManager maintains per-chain signers and coordinates with the SessionManager to
//! ensure deployments are executed with correct network configurations and account settings.
//!
//! The module supports both local development environments with configured private keys and
//! production environments with external signing mechanisms. It provides detailed logging
//! and error handling to ensure reliable deployment operations across different network
//! conditions and configurations.

use alloy_dyn_abi::DynSolValue;
use alloy_json_abi::JsonAbi;
use alloy_network::{EthereumWallet, TransactionBuilder};
use alloy_primitives::U256;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types::TransactionRequest;
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

use crate::core::SessionManager;
use crate::models::DeploymentResult;

/// Manager for orchestrating smart contract deployments across multiple chains.
///
/// The DeployerManager coordinates contract deployment operations, managing signers for
/// each supported blockchain network and handling the complexities of cross-chain deployment.
/// It maintains transaction state, provides nonce management, and ensures that deployments
/// are executed with appropriate gas settings and security parameters. The manager integrates
/// closely with the SessionManager to access network configurations and account information.
pub struct DeployerManager {
	/// Reference to the session manager for accessing network and account configuration.
	///
	/// Provides access to RPC endpoints, chain configurations, account information,
	/// and other session-specific settings required for deployment operations.
	pub session_manager: Arc<SessionManager>,

	/// Collection of signing wallets keyed by chain ID.
	///
	/// Maintains per-chain PrivateKeySigner instances configured with appropriate chain IDs
	/// for signing deployment transactions. Only populated in local development mode
	/// where private keys are available.
	signers: HashMap<u64, PrivateKeySigner>,
}

impl DeployerManager {
	/// Creates a new DeployerManager with the provided session manager.
	///
	/// Initializes the deployer manager and configures signers for each chain if
	/// operating in local mode with available private keys. In production mode,
	/// signers must be added separately using external key management systems.
	/// The initialization process sets up per-chain wallet instances with correct
	/// chain IDs for transaction signing.
	pub async fn new(session_manager: Arc<SessionManager>) -> Result<Self> {
		let mut signers = HashMap::new();

		if session_manager.is_local().await {
			let solver_account = session_manager.get_solver_account().await;

			if let Some(private_key) = solver_account.private_key {
				let key = private_key.trim_start_matches("0x");
				let signer = PrivateKeySigner::from_slice(&hex::decode(key)?)
					.map_err(|e| anyhow!("Failed to parse private key: {}", e))?;

				for chain_id in session_manager.get_chain_ids().await {
					let signer_with_chain = signer.clone().with_chain_id(Some(chain_id));
					signers.insert(chain_id, signer_with_chain);
				}
			}
		}

		Ok(Self {
			session_manager,
			signers,
		})
	}

	/// Retrieves the configured signer for a specific chain.
	///
	/// Returns a reference to the PrivateKeySigner configured for the specified
	/// chain ID, which can be used for signing deployment transactions.
	/// Returns an error if no signer is configured for the chain.
	pub fn get_signer(&self, chain_id: u64) -> Result<&PrivateKeySigner> {
		self.signers
			.get(&chain_id)
			.ok_or_else(|| anyhow!("No signer available for chain {}", chain_id))
	}

	/// Deploys a smart contract to the specified blockchain network.
	///
	/// Orchestrates the complete deployment process including transaction creation,
	/// signing, submission, and confirmation. The method handles constructor argument
	/// encoding, gas estimation, and transaction receipt verification. Returns detailed
	/// deployment information including the deployed contract address and transaction hash.
	///
	/// The deployment process validates bytecode availability, establishes network
	/// connections, configures signing middleware, and monitors transaction execution
	/// to ensure successful contract deployment.
	pub async fn deploy(
		&self,
		chain_id: u64,
		bytecode: Vec<u8>,
		abi: &JsonAbi,
		constructor_args: Vec<DynSolValue>,
	) -> Result<DeploymentResult> {
		info!("Deploying contract to chain {}", chain_id);
		debug!("Bytecode length: {} bytes", bytecode.len());
		debug!("Constructor args: {:?}", constructor_args);

		if bytecode.is_empty() {
			return Err(anyhow!("Empty bytecode provided for deployment"));
		}

		let rpc_url = self
			.session_manager
			.get_rpc_url(chain_id)
			.await
			.ok_or_else(|| anyhow!("No RPC URL for chain {}", chain_id))?;

		let signer = self.get_signer(chain_id)?.clone();
		debug!("Using signer address: {}", signer.address());

		let wallet = EthereumWallet::from(signer);
		let provider = ProviderBuilder::new()
			.with_recommended_fillers()
			.wallet(wallet)
			.on_http(rpc_url.parse()?);

		// Encode constructor arguments if any
		let mut deployment_data = bytecode.clone();
		if !constructor_args.is_empty() {
			// Find the constructor in the ABI
			if let Some(_constructor) = abi.constructor() {
				// Debug: Print what we're about to encode
				println!("🔧 [DEPLOY] Constructor arguments to encode:");
				for (i, arg) in constructor_args.iter().enumerate() {
					println!("  [{}]: {:?}", i, arg);
				}

				// Encode constructor arguments properly - they should be encoded as individual arguments, not a tuple
				use alloy_dyn_abi::DynSolValue;
				let tuple_value = DynSolValue::Tuple(constructor_args.clone());
				let encoded_args = tuple_value.abi_encode_sequence().unwrap_or_default();

				println!(
					"🔧 [DEPLOY] Encoded constructor args length: {} bytes",
					encoded_args.len()
				);
				println!(
					"🔧 [DEPLOY] Encoded constructor args (hex): 0x{}",
					hex::encode(&encoded_args)
				);

				deployment_data.extend(encoded_args);
			}
		}

		// Create deployment transaction using alloy's deployment method
		let tx = TransactionRequest::default().with_deploy_code(deployment_data);

		// Send deployment transaction
		let pending_tx = provider
			.send_transaction(tx)
			.await
			.map_err(|e| anyhow!("Failed to send deployment transaction: {}", e))?;

		let receipt = pending_tx
			.get_receipt()
			.await
			.map_err(|e| anyhow!("Failed to get deployment receipt: {}", e))?;

		let address = receipt
			.contract_address
			.ok_or_else(|| anyhow!("No contract address in deployment receipt"))?;
		let tx_hash = format!("{:?}", receipt.transaction_hash);

		debug!(
			"Contract deployed at {} with tx {}",
			address.to_checksum(Some(chain_id)),
			tx_hash
		);

		Ok(DeploymentResult {
			address,
			tx_hash,
			gas_used: Some(receipt.gas_used.try_into().unwrap_or(0)),
		})
	}

	/// Retrieves the current transaction nonce for the signer on a specific chain.
	///
	/// Queries the blockchain network to obtain the current transaction count for
	/// the configured signer address, which serves as the nonce for the next
	/// transaction. This ensures proper transaction ordering and prevents replay attacks.
	pub async fn get_nonce(&self, chain_id: u64) -> Result<U256> {
		let rpc_url = self
			.session_manager
			.get_rpc_url(chain_id)
			.await
			.ok_or_else(|| anyhow!("No RPC URL for chain {}", chain_id))?;

		let provider = ProviderBuilder::new().on_http(rpc_url.parse()?);
		let signer = self.get_signer(chain_id)?;
		let address = signer.address();

		let nonce = provider
			.get_transaction_count(address)
			.await
			.map_err(|e| anyhow!("Failed to get nonce: {}", e))?;

		Ok(U256::from(nonce))
	}

	/// Adds a signer wallet for a specific chain.
	///
	/// Registers a PrivateKeySigner instance for the specified chain ID, enabling
	/// deployment operations on that network. Typically used in production
	/// environments where signers are managed externally.
	pub fn add_signer(&mut self, chain_id: u64, signer: PrivateKeySigner) {
		self.signers.insert(chain_id, signer);
	}

	/// Checks if a signer is configured for the specified chain.
	///
	/// Returns true if a PrivateKeySigner is available for the given chain ID,
	/// indicating that deployment operations can be performed on that network.
	pub fn has_signer(&self, chain_id: u64) -> bool {
		self.signers.contains_key(&chain_id)
	}
}
