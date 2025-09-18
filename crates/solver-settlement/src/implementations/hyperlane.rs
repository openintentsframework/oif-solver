//! Hyperlane oracle settlement implementation.
//!
//! This module provides a settlement implementation using Hyperlane's cross-chain
//! messaging protocol for oracle attestations.

use crate::{utils::parse_oracle_config, OracleConfig, SettlementError, SettlementInterface};
use alloy_primitives::{hex, FixedBytes, U256};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types::BlockTransactionsKind;
use alloy_sol_types::{sol, SolCall};
use alloy_transport_http::Http;
use async_trait::async_trait;
use sha3::{Digest, Keccak256};
use solver_types::{
	with_0x_prefix, ConfigSchema, Field, FieldType, FillProof, NetworksConfig, Order, Schema,
	Transaction, TransactionHash, TransactionReceipt, TransactionType,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Helper to compute keccak256 hash
fn keccak256(data: &str) -> FixedBytes<32> {
	let mut hasher = Keccak256::new();
	hasher.update(data.as_bytes());
	let result = hasher.finalize();
	FixedBytes::<32>::from_slice(&result)
}

sol! {
	interface IHyperlaneOracle {
		// Submit cross-chain message with gas payment
		function submit(
			uint32 destinationDomain,
			address recipientOracle,
			uint256 gasLimit,
			bytes calldata customMetadata,
			address source,
			bytes[] calldata payloads
		) external payable;

		// Submit with custom hook
		function submit(
			uint32 destinationDomain,
			address recipientOracle,
			uint256 gasLimit,
			bytes calldata customMetadata,
			address customHook,
			address source,
			bytes[] calldata payloads
		) external payable;

		// Quote gas payment for message
		function quoteGasPayment(
			uint32 destinationDomain,
			address recipientOracle,
			uint256 gasLimit,
			bytes calldata customMetadata,
			address source,
			bytes[] calldata payloads
		) external view returns (uint256);

		// Quote with custom hook
		function quoteGasPayment(
			uint32 destinationDomain,
			address recipientOracle,
			uint256 gasLimit,
			bytes calldata customMetadata,
			address customHook,
			address source,
			bytes[] calldata payloads
		) external view returns (uint256);

		// Check if finalization is required for a message
		function requiresFinalization(
			bytes32 messageId
		) external view returns (bool);

		// Finalize a delivered message
		function finalize(
			bytes32 messageId
		) external;
	}

	// Event emitted when output is proven
	event OutputProven(
		uint32 indexed messageOrigin,
		bytes32 indexed messageSender,
		bytes32 indexed application,
		bytes32 payloadHash
	);

	// Event emitted by Mailbox when message is dispatched
	event Dispatch(
		address indexed sender,
		uint32 indexed destination,
		bytes32 indexed recipient,
		bytes32 messageId
	);

	// Alternative dispatch event format
	event DispatchId(bytes32 indexed messageId);
}

/// Message tracker for managing Hyperlane messages
#[derive(Debug, Clone, Default)]
pub struct MessageTracker {
	submitted_messages: HashMap<String, SubmittedMessage>,
	delivered_messages: HashMap<String, DeliveredMessage>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SubmittedMessage {
	message_id: [u8; 32],
	origin_chain: u64,
	destination_chain: u64,
	submission_tx_hash: TransactionHash,
	submission_timestamp: u64,
	gas_payment: U256,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct DeliveredMessage {
	message_id: [u8; 32],
	delivery_tx_hash: TransactionHash,
	delivery_timestamp: u64,
}

impl MessageTracker {
	pub fn new() -> Self {
		Self {
			submitted_messages: HashMap::new(),
			delivered_messages: HashMap::new(),
		}
	}

	pub fn track_submission(
		&mut self,
		order_id: String,
		message_id: [u8; 32],
		origin_chain: u64,
		destination_chain: u64,
		tx_hash: TransactionHash,
		gas_payment: U256,
	) {
		let submission = SubmittedMessage {
			message_id,
			origin_chain,
			destination_chain,
			submission_tx_hash: tx_hash,
			submission_timestamp: std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.unwrap()
				.as_secs(),
			gas_payment,
		};
		self.submitted_messages.insert(order_id, submission);
	}

	pub async fn check_finalization_required(
		&self,
		order_id: &str,
		oracle_address: solver_types::Address,
		provider: &RootProvider<Http<reqwest::Client>>,
	) -> Result<bool, SettlementError> {
		println!("Checking for finalization...");
		// Get the submitted message
		let message = self.submitted_messages.get(order_id).ok_or_else(|| {
			SettlementError::ValidationFailed("Message not found in tracker".to_string())
		})?;

		// Build requiresFinalization call
		let call_data = IHyperlaneOracle::requiresFinalizationCall {
			messageId: FixedBytes::<32>::from_slice(&message.message_id),
		};

		let call_request = alloy_rpc_types::eth::transaction::TransactionRequest {
			to: Some(alloy_primitives::TxKind::Call(
				alloy_primitives::Address::from_slice(&oracle_address.0),
			)),
			input: call_data.abi_encode().into(),
			..Default::default()
		};

		// Make the call
		let result = provider.call(&call_request).await.map_err(|e| {
			SettlementError::ValidationFailed(format!(
				"Failed to check finalization requirement: {}",
				e
			))
		})?;

		// Decode bool result
		Ok(!result.is_empty() && result[31] == 1)
	}

	pub fn mark_delivered(&mut self, order_id: String, delivery_tx_hash: TransactionHash) {
		println!("Marking as delivered...");

		if let Some(submission) = self.submitted_messages.get(&order_id) {
			let delivery = DeliveredMessage {
				message_id: submission.message_id,
				delivery_tx_hash,
				delivery_timestamp: std::time::SystemTime::now()
					.duration_since(std::time::UNIX_EPOCH)
					.unwrap()
					.as_secs(),
			};
			self.delivered_messages.insert(order_id, delivery);
		}
	}

	pub fn get_message_id(&self, order_id: &str) -> Option<[u8; 32]> {
		self.submitted_messages.get(order_id).map(|m| m.message_id)
	}
}

/// Hyperlane settlement implementation
#[allow(dead_code)]
pub struct HyperlaneSettlement {
	providers: HashMap<u64, RootProvider<Http<reqwest::Client>>>,
	oracle_config: OracleConfig,
	mailbox_addresses: HashMap<u64, solver_types::Address>,
	igp_addresses: HashMap<u64, solver_types::Address>,
	message_tracker: Arc<RwLock<MessageTracker>>,
	default_gas_limit: u64,
}

impl HyperlaneSettlement {
	/// Creates a new HyperlaneSettlement instance
	pub async fn new(
		networks: &NetworksConfig,
		oracle_config: OracleConfig,
		mailbox_addresses: HashMap<u64, solver_types::Address>,
		igp_addresses: HashMap<u64, solver_types::Address>,
		default_gas_limit: u64,
	) -> Result<Self, SettlementError> {
		// Create RPC providers for each network that has oracles configured
		let mut providers = HashMap::new();

		// Collect unique network IDs from input and output oracles
		let mut all_network_ids: Vec<u64> = oracle_config
			.input_oracles
			.keys()
			.chain(oracle_config.output_oracles.keys())
			.copied()
			.collect();
		all_network_ids.sort_unstable();
		all_network_ids.dedup();

		for network_id in &all_network_ids {
			let network = networks.get(network_id).ok_or_else(|| {
				SettlementError::ValidationFailed(format!(
					"Network {} not found in configuration",
					network_id
				))
			})?;

			let http_url = network.get_http_url().ok_or_else(|| {
				SettlementError::ValidationFailed(format!(
					"No HTTP RPC URL configured for network {}",
					network_id
				))
			})?;

			let provider = RootProvider::new_http(http_url.parse().map_err(|e| {
				SettlementError::ValidationFailed(format!(
					"Invalid RPC URL for network {}: {}",
					network_id, e
				))
			})?);

			providers.insert(*network_id, provider);
		}

		// Validate mailbox addresses are configured for all oracle chains
		for chain_id in &all_network_ids {
			if !mailbox_addresses.contains_key(chain_id) {
				return Err(SettlementError::ValidationFailed(format!(
					"Mailbox address not configured for chain {}",
					chain_id
				)));
			}
		}

		Ok(Self {
			providers,
			oracle_config,
			mailbox_addresses,
			igp_addresses,
			message_tracker: Arc::new(RwLock::new(MessageTracker::new())),
			default_gas_limit,
		})
	}

	/// Calculate gas limit for a Hyperlane message
	fn calculate_message_gas_limit(&self, payload_size: usize) -> U256 {
		// Base gas for message handling
		let base_gas = 200000;

		// Additional gas per byte of payload
		let gas_per_byte = 16;

		// Buffer for oracle processing
		let buffer = 100000;

		U256::from(base_gas + (payload_size * gas_per_byte) + buffer)
	}

	/// Estimate gas payment for a Hyperlane message
	#[allow(clippy::too_many_arguments)]
	async fn estimate_gas_payment(
		&self,
		origin_chain: u64,
		destination_chain: u32,
		recipient_oracle: solver_types::Address,
		gas_limit: U256,
		custom_metadata: Vec<u8>,
		source: solver_types::Address,
		payloads: Vec<Vec<u8>>,
	) -> Result<U256, SettlementError> {
		println!("Estimating gas payment...");

		// Get the output oracle address for the origin chain
		let oracle_addresses = self.get_output_oracles(origin_chain);
		if oracle_addresses.is_empty() {
			return Err(SettlementError::ValidationFailed(format!(
				"No output oracle configured for chain {}",
				origin_chain
			)));
		}

		// Select oracle using strategy
		let oracle_address = self.select_oracle(&oracle_addresses, None).ok_or_else(|| {
			SettlementError::ValidationFailed("Failed to select oracle".to_string())
		})?;

		// Get provider for the origin chain
		let provider = self.providers.get(&origin_chain).ok_or_else(|| {
			SettlementError::ValidationFailed(format!("No provider for chain {}", origin_chain))
		})?;

		// Build the quoteGasPayment call
		let call_data = IHyperlaneOracle::quoteGasPayment_0Call {
			destinationDomain: destination_chain,
			recipientOracle: alloy_primitives::Address::from_slice(&recipient_oracle.0),
			gasLimit: gas_limit,
			customMetadata: custom_metadata.into(),
			source: alloy_primitives::Address::from_slice(&source.0),
			payloads: payloads.into_iter().map(Into::into).collect(),
		};

		// Create call request
		let call_request = alloy_rpc_types::eth::transaction::TransactionRequest {
			to: Some(alloy_primitives::TxKind::Call(
				alloy_primitives::Address::from_slice(&oracle_address.0),
			)),
			input: call_data.abi_encode().into(),
			..Default::default()
		};

		// Make the eth_call to get the quote
		let result = provider.call(&call_request).await.map_err(|e| {
			SettlementError::ValidationFailed(format!("Failed to quote gas payment: {}", e))
		})?;

		// Decode the result
		let quote = U256::from_be_slice(&result);

		// TODO: Estimate is quite high here (e.g. 24656950763914024 wei (0.02 ETH))
		// 		 we should make sure this calculation is included in our initial acceptance criteria
		println!("QUOTE: {}", quote);
		Ok(quote)
	}
}

/// Configuration schema for HyperlaneSettlement
pub struct HyperlaneSettlementSchema;

impl HyperlaneSettlementSchema {
	/// Static validation method for use before instance creation
	pub fn validate_config(config: &toml::Value) -> Result<(), solver_types::ValidationError> {
		let instance = Self;
		instance.validate(config)
	}
}

impl ConfigSchema for HyperlaneSettlementSchema {
	fn validate(&self, config: &toml::Value) -> Result<(), solver_types::ValidationError> {
		let schema = Schema::new(
			// Required fields
			vec![
				Field::new(
					"oracles",
					FieldType::Table(Schema::new(
						vec![
							Field::new("input", FieldType::Table(Schema::new(vec![], vec![]))),
							Field::new("output", FieldType::Table(Schema::new(vec![], vec![]))),
						],
						vec![],
					)),
				),
				Field::new("routes", FieldType::Table(Schema::new(vec![], vec![]))),
				Field::new("mailboxes", FieldType::Table(Schema::new(vec![], vec![]))),
				Field::new(
					"igp_addresses",
					FieldType::Table(Schema::new(vec![], vec![])),
				),
				Field::new(
					"default_gas_limit",
					FieldType::Integer {
						min: Some(100000),
						max: Some(10000000),
					},
				),
			],
			// Optional fields
			vec![
				Field::new("oracle_selection_strategy", FieldType::String),
				Field::new(
					"message_timeout_seconds",
					FieldType::Integer {
						min: Some(60),
						max: Some(3600),
					},
				),
				Field::new("finalization_required", FieldType::Boolean),
			],
		);
		schema.validate(config)
	}
}

#[async_trait]
impl SettlementInterface for HyperlaneSettlement {
	fn oracle_config(&self) -> &OracleConfig {
		&self.oracle_config
	}

	fn config_schema(&self) -> Box<dyn ConfigSchema> {
		Box::new(HyperlaneSettlementSchema)
	}

	async fn get_attestation(
		&self,
		order: &Order,
		tx_hash: &TransactionHash,
	) -> Result<FillProof, SettlementError> {
		println!("Getting attestation...");

		let origin_chain_id = order
			.input_chains
			.first()
			.map(|c| c.chain_id)
			.ok_or_else(|| {
				SettlementError::ValidationFailed("No input chains in order".to_string())
			})?;

		let destination_chain_id =
			order
				.output_chains
				.first()
				.map(|c| c.chain_id)
				.ok_or_else(|| {
					SettlementError::ValidationFailed("No output chains in order".to_string())
				})?;

		// Get the appropriate provider for destination chain
		let provider = self.providers.get(&destination_chain_id).ok_or_else(|| {
			SettlementError::ValidationFailed(format!(
				"No provider configured for chain {}",
				destination_chain_id
			))
		})?;

		// Get the oracle address using selection strategy
		let oracle_addresses = self.get_input_oracles(origin_chain_id);
		if oracle_addresses.is_empty() {
			return Err(SettlementError::ValidationFailed(format!(
				"No input oracle configured for chain {}",
				origin_chain_id
			)));
		}

		// Use order ID hash for deterministic oracle selection
		let order_id_hash = keccak256(&order.id);
		let selection_context = u64::from_be_bytes(order_id_hash[0..8].try_into().unwrap());
		let oracle_address = self
			.select_oracle(&oracle_addresses, Some(selection_context))
			.ok_or_else(|| {
				SettlementError::ValidationFailed(format!(
					"Failed to select oracle for chain {}",
					origin_chain_id
				))
			})?;

		// Get transaction receipt
		let hash = FixedBytes::<32>::from_slice(&tx_hash.0);
		let receipt = provider
			.get_transaction_receipt(hash)
			.await
			.map_err(|e| {
				SettlementError::ValidationFailed(format!("Failed to get receipt: {}", e))
			})?
			.ok_or_else(|| {
				SettlementError::ValidationFailed("Transaction not found".to_string())
			})?;

		if !receipt.status() {
			return Err(SettlementError::ValidationFailed(
				"Transaction failed".to_string(),
			));
		}

		let tx_block = receipt.block_number.unwrap_or(0);

		// Get the block timestamp
		let block = provider
			.get_block_by_number(
				alloy_rpc_types::BlockNumberOrTag::Number(tx_block),
				BlockTransactionsKind::Hashes,
			)
			.await
			.map_err(|e| {
				SettlementError::ValidationFailed(format!("Failed to get block: {}", e))
			})?;

		let block_timestamp = block
			.ok_or_else(|| SettlementError::ValidationFailed("Block not found".to_string()))?
			.header
			.timestamp;

		// Check if we have a tracked message for this order
		let message_id = self
			.message_tracker
			.read()
			.await
			.get_message_id(&order.id)
			.map(hex::encode);

		Ok(FillProof {
			tx_hash: tx_hash.clone(),
			block_number: tx_block,
			oracle_address: with_0x_prefix(&hex::encode(&oracle_address.0)),
			attestation_data: message_id.map(|id| id.into_bytes()),
			filled_timestamp: block_timestamp,
		})
	}

	async fn can_claim(&self, order: &Order, fill_proof: &FillProof) -> bool {
		println!("Checking if can_claim...");

		let origin_chain_id = match order.input_chains.first() {
			Some(chain) => chain.chain_id,
			None => return false,
		};

		// Get the input oracle for checking finalization
		let oracle_addresses = self.get_input_oracles(origin_chain_id);
		if oracle_addresses.is_empty() {
			return false;
		}

		let oracle_address = match self.select_oracle(&oracle_addresses, None) {
			Some(addr) => addr,
			None => return false,
		};

		let provider = match self.providers.get(&origin_chain_id) {
			Some(p) => p,
			None => return false,
		};

		// Check if we have a message ID in the attestation data
		let message_id = match &fill_proof.attestation_data {
			Some(data) if data.len() == 64 => {
				// Hex encoded 32 bytes
				let mut id = [0u8; 32];
				if hex::decode_to_slice(data, &mut id).is_ok() {
					Some(id)
				} else {
					None
				}
			},
			_ => None,
		};

		if message_id.is_none() {
			// No Hyperlane message was submitted, can claim immediately
			return true;
		}

		// Check if finalization is required
		let tracker = self.message_tracker.read().await;
		match tracker
			.check_finalization_required(&order.id, oracle_address, provider)
			.await
		{
			Ok(false) => true, // No finalization required, can claim
			Ok(true) => {
				// Check if already finalized by querying the oracle
				// This would require another contract call to check finalization status
				false
			},
			Err(_) => false,
		}
	}

	async fn generate_post_fill_transaction(
		&self,
		order: &Order,
		fill_receipt: &TransactionReceipt,
	) -> Result<Option<Transaction>, SettlementError> {
		println!("Generating post_fill transaction...");

		// Get chains
		let dest_chain = order
			.output_chains
			.first()
			.map(|c| c.chain_id)
			.ok_or_else(|| SettlementError::ValidationFailed("No output chains".into()))?;
		let origin_chain = order
			.input_chains
			.first()
			.map(|c| c.chain_id)
			.ok_or_else(|| SettlementError::ValidationFailed("No input chains".into()))?;

		// Get output oracle on destination chain
		let output_oracles = self.get_output_oracles(dest_chain);
		if output_oracles.is_empty() {
			return Ok(None); // No oracle configured
		}

		let oracle_address = self
			.select_oracle(&output_oracles, None)
			.ok_or_else(|| SettlementError::ValidationFailed("Failed to select oracle".into()))?;

		// Get input oracle on origin chain (recipient)
		let input_oracles = self.get_input_oracles(origin_chain);
		if input_oracles.is_empty() {
			return Ok(None);
		}

		let recipient_oracle = self.select_oracle(&input_oracles, None).ok_or_else(|| {
			SettlementError::ValidationFailed("Failed to select recipient".into())
		})?;

		// Calculate gas limit for message
		let payload_size = 256; // Estimate for order attestation
		let gas_limit = self.calculate_message_gas_limit(payload_size);

		// Build attestation payload using order ID and fill transaction hash
		let attestation_payload = vec![
			order.id.as_bytes().to_vec(), // Use order.id directly
			fill_receipt.hash.0.to_vec(),
		];

		// Get the OutputSettler address from the order
		// The OutputSettler is the contract that attested the payloads during fill
		let output_chain = order.input_chains.first().ok_or_else(|| {
			SettlementError::ValidationFailed("No output settler in order".into())
		})?;

		// Quote gas payment - use OutputSettler as source
		let gas_payment = self
			.estimate_gas_payment(
				dest_chain,
				origin_chain as u32,
				recipient_oracle.clone(),
				gas_limit,
				vec![],                               // No custom metadata
				output_chain.settler_address.clone(), // Use OutputSettler address as source
				attestation_payload.clone(),
			)
			.await?;

		// Build submit call - use OutputSettler as source
		let call_data = IHyperlaneOracle::submit_0Call {
			destinationDomain: origin_chain as u32,
			recipientOracle: alloy_primitives::Address::from_slice(&recipient_oracle.0),
			gasLimit: gas_limit,
			customMetadata: vec![].into(),
			source: alloy_primitives::Address::from_slice(&output_chain.settler_address.0), // Use OutputSettler address as source
			payloads: attestation_payload.into_iter().map(Into::into).collect(),
		};

		Ok(Some(Transaction {
			to: Some(oracle_address),
			data: call_data.abi_encode(),
			value: gas_payment,
			chain_id: dest_chain,
			nonce: None,
			gas_limit: Some(300000),
			gas_price: None,
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
		}))
	}

	async fn generate_pre_claim_transaction(
		&self,
		order: &Order,
		fill_proof: &FillProof,
	) -> Result<Option<Transaction>, SettlementError> {
		println!("Generating pre_claim transaction...");

		let origin_chain = order
			.input_chains
			.first()
			.map(|c| c.chain_id)
			.ok_or_else(|| SettlementError::ValidationFailed("No input chains".into()))?;

		// Get input oracle on origin chain
		let oracle_addresses = self.get_input_oracles(origin_chain);
		if oracle_addresses.is_empty() {
			return Ok(None);
		}

		let oracle_address = self
			.select_oracle(&oracle_addresses, None)
			.ok_or_else(|| SettlementError::ValidationFailed("Failed to select oracle".into()))?;

		// Get message ID from attestation data
		let message_id = match &fill_proof.attestation_data {
			Some(data) if data.len() == 64 => {
				let mut id = [0u8; 32];
				hex::decode_to_slice(data, &mut id)
					.map_err(|_| SettlementError::ValidationFailed("Invalid message ID".into()))?;
				FixedBytes::<32>::from_slice(&id)
			},
			_ => return Ok(None), // No message to finalize
		};

		// Check if finalization is required
		let provider = self
			.providers
			.get(&origin_chain)
			.ok_or_else(|| SettlementError::ValidationFailed("No provider".into()))?;

		let tracker = self.message_tracker.read().await;
		if !tracker
			.check_finalization_required(&order.id, oracle_address.clone(), provider)
			.await?
		{
			return Ok(None); // No finalization needed
		}

		// Build finalize call
		let call_data = IHyperlaneOracle::finalizeCall {
			messageId: message_id,
		};

		Ok(Some(Transaction {
			to: Some(oracle_address),
			data: call_data.abi_encode(),
			value: U256::ZERO,
			chain_id: origin_chain,
			nonce: None,
			gas_limit: Some(100000),
			gas_price: None,
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
		}))
	}

	async fn handle_transaction_confirmed(
		&self,
		order: &Order,
		tx_type: TransactionType,
		receipt: &TransactionReceipt,
	) -> Result<(), SettlementError> {
		println!("Checking transaction status...");

		// Only handle PostFill transactions for Hyperlane message tracking
		if matches!(tx_type, TransactionType::PostFill) {
			let origin_chain = order
				.input_chains
				.first()
				.map(|c| c.chain_id)
				.ok_or_else(|| SettlementError::ValidationFailed("No input chains".into()))?;
			let dest_chain = order
				.output_chains
				.first()
				.map(|c| c.chain_id)
				.ok_or_else(|| SettlementError::ValidationFailed("No output chains".into()))?;

			// Create a deterministic message ID from the transaction hash
			// TODO: this would be extracted from Dispatch event logs
			let mut message_id = [0u8; 32];
			if receipt.hash.0.len() >= 32 {
				message_id.copy_from_slice(&receipt.hash.0[0..32]);
			} else {
				// Pad with zeros if hash is shorter
				message_id[..receipt.hash.0.len()].copy_from_slice(&receipt.hash.0);
			}

			// Store in message tracker for later use in can_claim and pre_claim
			self.message_tracker.write().await.track_submission(
				order.id.clone(),
				message_id,
				dest_chain,
				origin_chain,
				receipt.hash.clone(),
				U256::ZERO, // Gas payment would be calculated from actual receipt
			);

			tracing::info!(
				"Hyperlane message tracked for order {} with message_id {}",
				order.id,
				hex::encode(message_id)
			);
		}
		Ok(())
	}
}

/// Helper function to parse address tables from config
fn parse_address_table(
	table: &toml::Value,
) -> Result<HashMap<u64, solver_types::Address>, SettlementError> {
	let mut result = HashMap::new();

	if let Some(table) = table.as_table() {
		for (chain_id_str, address_value) in table {
			let chain_id = chain_id_str.parse::<u64>().map_err(|e| {
				SettlementError::ValidationFailed(format!(
					"Invalid chain ID '{}': {}",
					chain_id_str, e
				))
			})?;

			let address_str = address_value.as_str().ok_or_else(|| {
				SettlementError::ValidationFailed(format!(
					"Address must be string for chain {}",
					chain_id
				))
			})?;

			let address = solver_types::utils::parse_address(address_str).map_err(|e| {
				SettlementError::ValidationFailed(format!(
					"Invalid address for chain {}: {}",
					chain_id, e
				))
			})?;

			result.insert(chain_id, address);
		}
	}

	Ok(result)
}

/// Factory function to create a Hyperlane settlement provider from configuration
pub fn create_settlement(
	config: &toml::Value,
	networks: &NetworksConfig,
) -> Result<Box<dyn SettlementInterface>, SettlementError> {
	// Validate configuration first
	HyperlaneSettlementSchema::validate_config(config)
		.map_err(|e| SettlementError::ValidationFailed(format!("Invalid configuration: {}", e)))?;

	// Parse oracle configuration using common utilities
	let oracle_config = parse_oracle_config(config)?;

	// Parse mailbox addresses
	let mailbox_addresses = parse_address_table(
		config
			.get("mailboxes")
			.ok_or_else(|| SettlementError::ValidationFailed("Missing mailboxes".to_string()))?,
	)?;

	// Parse IGP addresses
	let igp_addresses =
		parse_address_table(config.get("igp_addresses").ok_or_else(|| {
			SettlementError::ValidationFailed("Missing IGP addresses".to_string())
		})?)?;

	let default_gas_limit = config
		.get("default_gas_limit")
		.and_then(|v| v.as_integer())
		.unwrap_or(500000) as u64;

	// Create settlement service synchronously
	let settlement = tokio::task::block_in_place(|| {
		tokio::runtime::Handle::current().block_on(async {
			HyperlaneSettlement::new(
				networks,
				oracle_config,
				mailbox_addresses,
				igp_addresses,
				default_gas_limit,
			)
			.await
		})
	})?;

	Ok(Box::new(settlement))
}

/// Registry for the Hyperlane settlement implementation
pub struct Registry;

impl solver_types::ImplementationRegistry for Registry {
	const NAME: &'static str = "hyperlane";
	type Factory = crate::SettlementFactory;

	fn factory() -> Self::Factory {
		create_settlement
	}
}

impl crate::SettlementRegistry for Registry {}
