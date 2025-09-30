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

use alloy_primitives::{Address, U256};
use anyhow::{anyhow, Result};
use ethers::{
	abi::Abi,
	contract::ContractFactory,
	core::types::Bytes,
	middleware::SignerMiddleware,
	prelude::LocalWallet,
	providers::{Http, Middleware, Provider},
	signers::Signer,
};
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
	/// Maintains per-chain LocalWallet instances configured with appropriate chain IDs
	/// for signing deployment transactions. Only populated in local development mode
	/// where private keys are available.
	signers: HashMap<u64, LocalWallet>,
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
				let wallet = key
					.parse::<LocalWallet>()
					.map_err(|e| anyhow!("Failed to parse private key: {}", e))?;

				for chain_id in session_manager.get_chain_ids().await {
					let wallet_with_chain = wallet.clone().with_chain_id(chain_id);
					signers.insert(chain_id, wallet_with_chain);
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
	/// Returns a reference to the LocalWallet configured for the specified
	/// chain ID, which can be used for signing deployment transactions.
	/// Returns an error if no signer is configured for the chain.
	pub fn get_signer(&self, chain_id: u64) -> Result<&LocalWallet> {
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
		abi: &Abi,
		constructor_args: Vec<ethers::abi::Token>,
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

		let provider = Provider::<Http>::try_from(rpc_url.clone())
			.map_err(|e| anyhow!("Failed to create provider for {}: {}", rpc_url, e))?;

		let signer = self.get_signer(chain_id)?;
		debug!("Using signer address: {}", signer.address());

		let client = Arc::new(SignerMiddleware::new(provider.clone(), signer.clone()));

		let factory = ContractFactory::new(abi.clone(), Bytes::from(bytecode), client.clone());

		let deployer = factory
			.deploy_tokens(constructor_args.clone())
			.map_err(|e| anyhow!("Failed to create deployment transaction: {}", e))?;
		let (contract, receipt) = deployer
			.send_with_receipt()
			.await
			.map_err(|e| anyhow!("Failed to deploy contract: {}", e))?;

		let address = contract.address();
		let tx_hash = format!("{:?}", receipt.transaction_hash);

		debug!("Contract deployed at {} with tx {}", address, tx_hash);

		Ok(DeploymentResult {
			address: Address::from_slice(address.as_bytes()),
			tx_hash,
			gas_used: None,
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

		let provider = Provider::<Http>::try_from(rpc_url)?;
		let signer = self.get_signer(chain_id)?;
		let address = signer.address();

		let nonce = provider
			.get_transaction_count(address, None)
			.await
			.map_err(|e| anyhow!("Failed to get nonce: {}", e))?;

		Ok(U256::from(nonce.as_u64()))
	}

	/// Adds a signer wallet for a specific chain.
	///
	/// Registers a LocalWallet instance for the specified chain ID, enabling
	/// deployment operations on that network. Typically used in production
	/// environments where signers are managed externally.
	pub fn add_signer(&mut self, chain_id: u64, signer: LocalWallet) {
		self.signers.insert(chain_id, signer);
	}

	/// Checks if a signer is configured for the specified chain.
	///
	/// Returns true if a LocalWallet is available for the given chain ID,
	/// indicating that deployment operations can be performed on that network.
	pub fn has_signer(&self, chain_id: u64) -> bool {
		self.signers.contains_key(&chain_id)
	}
}
