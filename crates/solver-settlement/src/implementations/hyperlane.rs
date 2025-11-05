//! Hyperlane oracle settlement implementation.
//!
//! This module provides a settlement implementation using Hyperlane's cross-chain
//! messaging protocol for oracle attestations.

use crate::{utils::parse_oracle_config, OracleConfig, SettlementError, SettlementInterface};
use alloy_primitives::{hex, FixedBytes, U256};
use alloy_provider::{DynProvider, Provider};
use alloy_rpc_types::{BlockId, BlockNumberOrTag};
use alloy_sol_types::{sol, SolCall};
use alloy_transport::TransportError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use solver_storage::StorageService;
use solver_types::{
	create_http_provider, with_0x_prefix, ConfigSchema, Field, FieldType, FillProof,
	InteropAddress, NetworksConfig, Order, OrderOutput, ProviderError, Schema, StorageKey,
	Transaction, TransactionHash, TransactionReceipt, TransactionType,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Custom serialization for U256
mod u256_serde {
	use alloy_primitives::U256;
	use serde::{Deserialize, Deserializer, Serializer};

	pub fn serialize<S>(value: &U256, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&value.to_string())
	}

	pub fn deserialize<'de, D>(deserializer: D) -> Result<U256, D::Error>
	where
		D: Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		s.parse::<U256>()
			.map_err(|_| serde::de::Error::custom("Failed to parse U256"))
	}
}

/// Helper to compute keccak256 hash
fn keccak256(data: &str) -> FixedBytes<32> {
	let mut hasher = Keccak256::new();
	hasher.update(data.as_bytes());
	let result = hasher.finalize();
	FixedBytes::<32>::from_slice(&result)
}

/// Convert order ID string to bytes32
fn order_id_to_bytes32(order_id: &str) -> [u8; 32] {
	// If order_id starts with 0x, treat as hex
	if let Some(hex_str) = order_id.strip_prefix("0x") {
		let mut bytes = [0u8; 32];
		if let Ok(decoded) = hex::decode(hex_str) {
			let len = decoded.len().min(32);
			bytes[32 - len..].copy_from_slice(&decoded[..len]);
		}
		bytes
	} else {
		// Otherwise, encode as UTF-8 bytes, right-align and left-pad with zeros
		let raw = order_id.as_bytes();
		let mut bytes = [0u8; 32];
		let len = raw.len().min(32);
		bytes[32 - len..].copy_from_slice(&raw[..len]);
		bytes
	}
}

/// Hyperlane-compatible output representation
struct HyperlaneOutput {
	token: [u8; 32],
	amount: U256,
	recipient: [u8; 32],
	call: Vec<u8>,
	context: Vec<u8>,
}

/// Convert InteropAddress to bytes32 for Hyperlane
fn interop_address_to_bytes32(addr: &InteropAddress) -> [u8; 32] {
	let mut bytes32 = [0u8; 32];

	// Get the raw bytes from the InteropAddress
	let raw_bytes = addr.to_bytes();

	// For Ethereum addresses (20 bytes), right-align in 32 bytes
	if let Ok(eth_addr) = addr.ethereum_address() {
		// Put the 20-byte Ethereum address in the last 20 bytes of the 32-byte array
		bytes32[12..].copy_from_slice(eth_addr.as_slice());
	} else {
		// For other address formats, use the raw bytes right-aligned
		let len = raw_bytes.len().min(32);
		bytes32[32 - len..].copy_from_slice(&raw_bytes[..len]);
	}

	bytes32
}

/// Convert an OrderOutput to Hyperlane-compatible format
fn order_output_to_hyperlane(output: &OrderOutput) -> HyperlaneOutput {
	let asset = &output.asset;
	let receiver = &output.receiver;
	let amount = output.amount;

	HyperlaneOutput {
		token: interop_address_to_bytes32(asset),
		amount,
		recipient: interop_address_to_bytes32(receiver),
		call: output
			.calldata
			.as_ref()
			.and_then(|s| hex::decode(s.trim_start_matches("0x")).ok())
			.unwrap_or_default(),
		context: vec![], // Empty context for generic orders
	}
}

/// Extract output details from order data using OrderParsable
fn extract_output_details(order: &Order) -> Result<HyperlaneOutput, SettlementError> {
	// Parse order data using the OrderParsable trait
	let parsed_order = order.parse_order_data().map_err(|e| {
		SettlementError::ValidationFailed(format!("Failed to parse order data: {}", e))
	})?;

	// Get requested outputs
	let outputs = parsed_order.parse_requested_outputs();

	// Get the first output
	let first_output = outputs
		.first()
		.ok_or_else(|| SettlementError::ValidationFailed("No outputs found in order".into()))?;

	// Convert to Hyperlane format
	Ok(order_output_to_hyperlane(first_output))
}

/// Extract fill details from OutputFilled event in logs
fn extract_fill_details_from_logs(
	logs: &[solver_types::Log],
	order_id: &[u8; 32],
) -> Result<(Vec<u8>, u32), SettlementError> {
	// OutputFilled event signature: OutputFilled(bytes32,bytes32,uint32,MandateOutput,uint256)
	let output_filled_signature = keccak256("OutputFilled(bytes32,bytes32,uint32,(bytes32,bytes32,uint256,bytes32,uint256,bytes32,bytes,bytes),uint256)");

	for log in logs {
		// Check if this is an OutputFilled event
		if log.topics.len() >= 2 && log.topics[0].0 == output_filled_signature.0 {
			// Topic[1] is indexed orderId
			if log.topics[1].0 == *order_id {
				// The data contains: solver (bytes32), timestamp (uint32), MandateOutput, finalAmount
				// First 32 bytes: solver
				// Next 32 bytes: timestamp (padded)
				if log.data.len() >= 64 {
					let solver = log.data[0..32].to_vec();
					let timestamp_bytes = &log.data[32..64];
					// Timestamp is uint32, stored in the last 4 bytes of the 32-byte slot
					let timestamp = u32::from_be_bytes([
						timestamp_bytes[28],
						timestamp_bytes[29],
						timestamp_bytes[30],
						timestamp_bytes[31],
					]);

					return Ok((solver, timestamp));
				}
			}
		}
	}

	Err(SettlementError::ValidationFailed(
		"No OutputFilled event detected in logs. The output may have already been completed by another solver".into(),
	))
}

/// Encode FillDescription according to MandateOutputEncodingLib
/// Layout:
/// - solver (32 bytes)
/// - orderId (32 bytes)
/// - timestamp (4 bytes)
/// - token (32 bytes)
/// - amount (32 bytes)
/// - recipient (32 bytes)
/// - call length (2 bytes) + call data
/// - context length (2 bytes) + context data
#[allow(clippy::too_many_arguments)]
fn encode_fill_description(
	solver_identifier: [u8; 32],
	order_id: [u8; 32],
	timestamp: u32,
	token: [u8; 32],
	amount: U256,
	recipient: [u8; 32],
	call_data: Vec<u8>,
	context: Vec<u8>,
) -> Result<Vec<u8>, SettlementError> {
	// Check length constraints
	if call_data.len() > u16::MAX as usize {
		return Err(SettlementError::ValidationFailed(
			"Call data too large".into(),
		));
	}
	if context.len() > u16::MAX as usize {
		return Err(SettlementError::ValidationFailed(
			"Context data too large".into(),
		));
	}

	let mut payload =
		Vec::with_capacity(32 + 32 + 4 + 32 + 32 + 32 + 2 + call_data.len() + 2 + context.len());

	// Solver identifier (32 bytes)
	payload.extend_from_slice(&solver_identifier);

	// Order ID (32 bytes)
	payload.extend_from_slice(&order_id);

	// Timestamp (4 bytes) - uint32 big endian
	payload.extend_from_slice(&timestamp.to_be_bytes());

	// Token (32 bytes)
	payload.extend_from_slice(&token);

	// Amount (32 bytes) - big endian
	let amount_bytes = amount.to_be_bytes::<32>();
	payload.extend_from_slice(&amount_bytes);

	// Recipient (32 bytes)
	payload.extend_from_slice(&recipient);

	// Call length (2 bytes) and call data
	payload.extend_from_slice(&(call_data.len() as u16).to_be_bytes());
	payload.extend_from_slice(&call_data);

	// Context length (2 bytes) and context
	payload.extend_from_slice(&(context.len() as u16).to_be_bytes());
	payload.extend_from_slice(&context);

	Ok(payload)
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

		// Check if data has been proven (from BaseInputOracle)
		function isProven(
			uint256 remoteChainId,
			bytes32 remoteOracle,
			bytes32 application,
			bytes32 dataHash
		) external view returns (bool);

		// Efficiently check multiple proofs (from BaseInputOracle)
		function efficientRequireProven(
			bytes calldata proofSeries
		) external view;
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

/// Message state for a single order
#[derive(Debug, Clone, Serialize, Deserialize)]
struct HyperlaneMessageState {
	submitted: Option<SubmittedMessage>,
	delivered: Option<DeliveredMessage>,
}

/// Message tracker for managing Hyperlane messages with automatic persistence
#[derive(Clone)]
pub struct MessageTracker {
	storage: Arc<StorageService>,
	/// Cache of recently accessed messages (order_id -> state)
	cache: Arc<RwLock<HashMap<String, HyperlaneMessageState>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
struct SubmittedMessage {
	#[serde(with = "hex::serde")]
	message_id: [u8; 32],
	origin_chain: u64,
	destination_chain: u64,
	submission_tx_hash: TransactionHash,
	submission_timestamp: u64,
	#[serde(with = "u256_serde")]
	gas_payment: U256,
	// Store computed payload hash to avoid recomputing
	#[serde(with = "hex::serde")]
	payload_hash: [u8; 32],
	// Store fill details for later use
	#[serde(with = "hex::serde")]
	solver_identifier: [u8; 32],
	fill_timestamp: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
struct DeliveredMessage {
	#[serde(with = "hex::serde")]
	message_id: [u8; 32],
	delivery_timestamp: u64,
	#[serde(with = "hex::serde")]
	payload_hash: [u8; 32],
}

impl MessageTracker {
	/// Create a new MessageTracker with storage support
	pub async fn new(storage: Arc<StorageService>) -> Self {
		Self {
			storage,
			cache: Arc::new(RwLock::new(HashMap::new())),
		}
	}

	/// Generate storage key for a specific order
	fn storage_key(order_id: &str) -> String {
		format!("hyperlane:{}", order_id)
	}

	/// Load message state for a specific order
	async fn load_message(&self, order_id: &str) -> Option<HyperlaneMessageState> {
		// Check cache first
		{
			let cache = self.cache.read().await;
			if let Some(state) = cache.get(order_id) {
				return Some(state.clone());
			}
		}

		// Try to load from storage
		let key = Self::storage_key(order_id);
		match self
			.storage
			.retrieve::<HyperlaneMessageState>(StorageKey::SettlementMessages.as_str(), &key)
			.await
		{
			Ok(state) => {
				// Update cache
				let mut cache = self.cache.write().await;
				cache.insert(order_id.to_string(), state.clone());
				Some(state)
			},
			Err(_) => None,
		}
	}

	/// Save message state for a specific order
	async fn save_message(
		&self,
		order_id: &str,
		state: &HyperlaneMessageState,
	) -> Result<(), SettlementError> {
		let key = Self::storage_key(order_id);

		// Save to storage with TTL (7 days after message is delivered)
		let ttl = if state.delivered.is_some() {
			Some(std::time::Duration::from_secs(7 * 24 * 60 * 60))
		} else {
			None // No TTL for pending messages
		};

		self.storage
			.store_with_ttl(
				StorageKey::SettlementMessages.as_str(),
				&key,
				state,
				None, // No indexes needed
				ttl,
			)
			.await
			.map_err(|e| {
				SettlementError::ValidationFailed(format!("Failed to persist message state: {}", e))
			})?;

		// Update cache
		let mut cache = self.cache.write().await;
		cache.insert(order_id.to_string(), state.clone());

		Ok(())
	}

	#[allow(clippy::too_many_arguments)]
	pub async fn track_submission(
		&self,
		order_id: String,
		message_id: [u8; 32],
		origin_chain: u64,
		destination_chain: u64,
		tx_hash: TransactionHash,
		gas_payment: U256,
		payload_hash: [u8; 32],
		solver_identifier: [u8; 32],
		fill_timestamp: u32,
	) -> Result<(), SettlementError> {
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
			payload_hash,
			solver_identifier,
			fill_timestamp,
		};

		// Load existing state or create new
		let mut state = self
			.load_message(&order_id)
			.await
			.unwrap_or(HyperlaneMessageState {
				submitted: None,
				delivered: None,
			});

		state.submitted = Some(submission);

		// Save to storage
		self.save_message(&order_id, &state).await
	}

	pub async fn check_finalization_required(
		&self,
		_order_id: &str,
		_oracle_address: solver_types::Address,
		_provider: &DynProvider,
	) -> Result<bool, SettlementError> {
		// Hyperlane doesn't require explicit finalization
		// Messages are automatically processed when they arrive at the destination
		// The oracle will automatically attest to the message when it's received
		Ok(false)
	}

	pub async fn mark_delivered(
		&self,
		order_id: String,
		payload_hash: [u8; 32],
	) -> Result<(), SettlementError> {
		// Load existing state
		let mut state = self.load_message(&order_id).await.ok_or_else(|| {
			SettlementError::ValidationFailed("Message not found in tracker".to_string())
		})?;

		if let Some(submission) = &state.submitted {
			let delivery = DeliveredMessage {
				message_id: submission.message_id,
				delivery_timestamp: std::time::SystemTime::now()
					.duration_since(std::time::UNIX_EPOCH)
					.unwrap()
					.as_secs(),
				payload_hash,
			};
			state.delivered = Some(delivery);

			// Save updated state with TTL
			self.save_message(&order_id, &state).await?
		}

		Ok(())
	}

	pub async fn get_message_id(&self, order_id: &str) -> Option<[u8; 32]> {
		let state = self.load_message(order_id).await?;
		state.submitted.map(|m| m.message_id)
	}
}

/// Hyperlane settlement implementation
#[allow(dead_code)]
pub struct HyperlaneSettlement {
	providers: HashMap<u64, DynProvider>,
	oracle_config: OracleConfig,
	mailbox_addresses: HashMap<u64, solver_types::Address>,
	igp_addresses: HashMap<u64, solver_types::Address>,
	message_tracker: Arc<MessageTracker>,
	default_gas_limit: u64,
}

impl HyperlaneSettlement {
	/// Compute the payload hash that will be checked with isProven
	fn compute_payload_hash(
		&self,
		order: &Order,
		solver_identifier: [u8; 32],
		timestamp: u32,
	) -> Result<[u8; 32], SettlementError> {
		// Extract output details from order
		let output = extract_output_details(order)?;
		let order_id_bytes = order_id_to_bytes32(&order.id);

		// Encode the FillDescription payload
		let payload = encode_fill_description(
			solver_identifier,
			order_id_bytes,
			timestamp,
			output.token,
			output.amount,
			output.recipient,
			output.call,
			output.context,
		)?;

		// Hash the payload (matches oracle's storage)
		let mut hasher = Keccak256::new();
		hasher.update(&payload);
		let hash = hasher.finalize();

		let mut result = [0u8; 32];
		result.copy_from_slice(&hash);
		Ok(result)
	}

	/// Check if a payload has been proven on the oracle
	async fn is_payload_proven(
		&self,
		oracle_chain: u64,
		oracle_address: solver_types::Address,
		remote_chain: u64,
		remote_oracle: [u8; 32],
		application: [u8; 32],
		payload_hash: [u8; 32],
	) -> Result<bool, SettlementError> {
		let provider = self.providers.get(&oracle_chain).ok_or_else(|| {
			SettlementError::ValidationFailed(format!("No provider for chain {}", oracle_chain))
		})?;

		// Build the call
		let call_data = IHyperlaneOracle::isProvenCall {
			remoteChainId: U256::from(remote_chain),
			remoteOracle: FixedBytes::<32>::from(remote_oracle),
			application: FixedBytes::<32>::from(application),
			dataHash: FixedBytes::<32>::from(payload_hash),
		};

		// Execute eth_call
		let request = alloy_rpc_types::eth::transaction::TransactionRequest {
			to: Some(alloy_primitives::TxKind::Call(
				alloy_primitives::Address::from_slice(&oracle_address.0),
			)),
			input: call_data.abi_encode().into(),
			..Default::default()
		};

		let result = provider.call(request).await.map_err(|e| {
			SettlementError::ValidationFailed(format!("Failed to call isProven: {}", e))
		})?;

		// Decode boolean (last byte of 32-byte result)
		let is_proven = result.len() >= 32 && result[31] != 0;
		Ok(is_proven)
	}

	/// Check if a Hyperlane message has been delivered
	async fn check_delivery(
		&self,
		order: &Order,
		message_id: [u8; 32],
	) -> Result<bool, SettlementError> {
		let order_id = &order.id;

		// Load message state
		let mut state =
			self.message_tracker
				.load_message(order_id)
				.await
				.unwrap_or(HyperlaneMessageState {
					submitted: None,
					delivered: None,
				});

		// Already delivered?
		if state.delivered.is_some() {
			return Ok(true);
		}

		// Get submission info with pre-computed payload hash
		let submission = match state.submitted.as_ref() {
			Some(s) => s,
			None => {
				return Err(SettlementError::ValidationFailed(
					"No submission info".to_string(),
				));
			},
		};

		// Use stored chains and payload hash
		let origin_chain = submission.origin_chain;
		let dest_chain = submission.destination_chain;
		let payload_hash = submission.payload_hash;

		// Select oracles
		// We need the input oracle on the destination chain (where we check isProven)
		let input_oracle = self
			.select_oracle(&self.get_input_oracles(dest_chain), None)
			.ok_or_else(|| SettlementError::ValidationFailed("No input oracle".to_string()))?;

		// We need the output oracle on the origin chain (the remote oracle)
		let output_oracle = self
			.select_oracle(&self.get_output_oracles(origin_chain), None)
			.ok_or_else(|| SettlementError::ValidationFailed("No output oracle".to_string()))?;

		// Get application address (OutputSettler)
		let application = order
			.output_chains
			.first()
			.ok_or_else(|| SettlementError::ValidationFailed("No output settler".into()))?
			.settler_address
			.clone();

		// Convert to bytes32 format
		let mut remote_oracle_bytes = [0u8; 32];
		remote_oracle_bytes[12..].copy_from_slice(&output_oracle.0);

		let mut application_bytes = [0u8; 32];
		application_bytes[12..].copy_from_slice(&application.0);

		let is_proven = self
			.is_payload_proven(
				dest_chain,          // Chain where we call isProven (destination of message)
				input_oracle,        // Input oracle on destination chain
				origin_chain,        // Remote chain (origin of message)
				remote_oracle_bytes, // Output oracle on origin chain
				application_bytes,
				payload_hash,
			)
			.await?;

		if is_proven {
			let now = std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.unwrap()
				.as_secs();

			state.delivered = Some(DeliveredMessage {
				message_id,
				delivery_timestamp: now,
				payload_hash,
			});

			self.message_tracker.save_message(order_id, &state).await?;

			tracing::debug!(
				order_id = %solver_types::utils::formatting::truncate_id(order_id),
				message_id = %hex::encode(message_id),
				"Hyperlane message proven"
			);
		}

		Ok(is_proven)
	}

	/// Extract message ID from Dispatch event logs
	fn extract_message_id_from_logs(
		&self,
		logs: &[solver_types::Log],
	) -> Result<[u8; 32], SettlementError> {
		// Dispatch event signature: Dispatch(address,uint32,bytes32,bytes32)
		// Topic0 is the event signature hash
		let dispatch_signature = keccak256("Dispatch(address,uint32,bytes32,bytes32)");

		// DispatchId event signature: DispatchId(bytes32)
		let dispatch_id_signature = keccak256("DispatchId(bytes32)");

		// First try to find Dispatch event
		for log in logs {
			if log.topics.is_empty() {
				continue;
			}

			// Check for Dispatch event
			if log.topics[0].0 == dispatch_signature.0 {
				// Message ID is the 4th indexed parameter (topics[3])
				if log.topics.len() > 3 {
					return Ok(log.topics[3].0);
				}
			}

			// Check for DispatchId event
			if log.topics[0].0 == dispatch_id_signature.0 {
				// Message ID is the 1st indexed parameter (topics[1])
				if log.topics.len() > 1 {
					return Ok(log.topics[1].0);
				}
			}
		}

		Err(SettlementError::ValidationFailed(
			"No Dispatch or DispatchId event found in transaction logs".to_string(),
		))
	}

	/// Creates a new HyperlaneSettlement instance
	pub async fn new(
		networks: &NetworksConfig,
		oracle_config: OracleConfig,
		mailbox_addresses: HashMap<u64, solver_types::Address>,
		igp_addresses: HashMap<u64, solver_types::Address>,
		default_gas_limit: u64,
		storage: Arc<StorageService>,
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
			let provider = create_http_provider(*network_id, networks).map_err(|e| match e {
				ProviderError::NetworkConfig(msg) => SettlementError::ValidationFailed(msg),
				ProviderError::Connection(msg) => SettlementError::ValidationFailed(msg),
				ProviderError::InvalidUrl(msg) => SettlementError::ValidationFailed(msg),
			})?;

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

		// Create message tracker with storage
		let message_tracker = MessageTracker::new(storage).await;

		Ok(Self {
			providers,
			oracle_config,
			mailbox_addresses,
			igp_addresses,
			message_tracker: Arc::new(message_tracker),
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

	#[allow(clippy::too_many_arguments)]
	/// Estimate gas payment for a Hyperlane message
	async fn estimate_gas_payment(
		&self,
		oracle_chain: u64, // Chain where the oracle is deployed (where we're calling from)
		destination_chain: u32, // Chain where the message is going
		recipient_oracle: solver_types::Address,
		gas_limit: U256,
		custom_metadata: Vec<u8>,
		source: solver_types::Address,
		payloads: Vec<Vec<u8>>,
		from: solver_types::Address,
		block_id: Option<u64>,
	) -> Result<U256, SettlementError> {
		// Get the output oracle address for the oracle chain (where we're calling from)
		let oracle_addresses = self.get_output_oracles(oracle_chain);
		if oracle_addresses.is_empty() {
			return Err(SettlementError::ValidationFailed(format!(
				"No output oracle configured for chain {}",
				oracle_chain
			)));
		}

		// Select oracle using strategy
		let oracle_address = self.select_oracle(&oracle_addresses, None).ok_or_else(|| {
			SettlementError::ValidationFailed("Failed to select oracle".to_string())
		})?;

		// Get provider for the oracle chain
		let provider = self.providers.get(&oracle_chain).ok_or_else(|| {
			SettlementError::ValidationFailed(format!("No provider for chain {}", oracle_chain))
		})?;

		let payload_sizes: Vec<usize> = payloads.iter().map(Vec::len).collect();
		let total_payload_len: usize = payload_sizes.iter().sum();
		let custom_metadata_len = custom_metadata.len();

		// Build the quoteGasPayment call
		let call_data = IHyperlaneOracle::quoteGasPayment_0Call {
			destinationDomain: destination_chain,
			recipientOracle: alloy_primitives::Address::from_slice(&recipient_oracle.0),
			gasLimit: gas_limit,
			customMetadata: custom_metadata.into(),
			source: alloy_primitives::Address::from_slice(&source.0),
			payloads: payloads.into_iter().map(Into::into).collect(),
		};

		let encoded_call = call_data.abi_encode();
		let call_data_hex = solver_types::with_0x_prefix(&hex::encode(&encoded_call));
		let call_data_len = encoded_call.len();

		let call_block_id = if let Some(block_number) = block_id {
			BlockId::Number(BlockNumberOrTag::Number(block_number))
		} else {
			Self::resolve_call_block_id(provider, oracle_chain, destination_chain).await
		};
		let block_source = if block_id.is_some() {
			"provided"
		} else {
			"resolved_latest"
		};
		// Create call request with from address to ensure correct msg.sender in the call
		let call_request = alloy_rpc_types::eth::transaction::TransactionRequest {
			from: Some(alloy_primitives::Address::from_slice(&from.0)),
			to: Some(alloy_primitives::TxKind::Call(
				alloy_primitives::Address::from_slice(&oracle_address.0),
			)),
			input: encoded_call.clone().into(),
			..Default::default()
		};

		tracing::info!(
			oracle_chain,
			destination_chain,
			block_id = %Self::format_block_id(call_block_id.clone()),
			block_source,
			gas_limit = %gas_limit,
			recipient_oracle = %solver_types::with_0x_prefix(&hex::encode(&recipient_oracle.0)),
			source = %solver_types::with_0x_prefix(&hex::encode(&source.0)),
			caller = %solver_types::with_0x_prefix(&hex::encode(&from.0)),
			payload_count = payload_sizes.len(),
			payload_sizes = ?payload_sizes,
			total_payload_len,
			custom_metadata_len,
			call_data_len,
			"Hyperlane gas quote request"
		);

		// Make the eth_call to get the quote with timing
		let call_data_hex_for_error = call_data_hex.clone();
		let call_result = provider
			.call(call_request.clone())
			.block(call_block_id.clone())
			.await;

		if let Err(ref e) = call_result {
			let (rpc_code, rpc_message, rpc_data) = match &e {
				TransportError::ErrorResp(payload) => (
					Some(payload.code),
					Some(payload.message.clone()),
					payload.data.as_ref().map(|data| format!("{:?}", data)),
				),
				_ => (None, None, None),
			};
			tracing::info!(
				oracle_chain,
				destination_chain,
				error = %e,
				rpc_code = ?rpc_code,
				rpc_message = ?rpc_message,
				rpc_data = ?rpc_data,
				block_id = %Self::format_block_id(call_block_id.clone()),
				call_data_len,
				call_data = %call_data_hex_for_error,
				"Hyperlane gas quote failed"
			);
		}
		match Self::fetch_debug_trace(provider, &call_request, call_block_id.clone()).await {
			Ok(trace) => tracing::info!(
				oracle_chain,
				destination_chain,
				block_id = %Self::format_block_id(call_block_id.clone()),
				trace = ?trace,
				"Hyperlane debug_traceCall response"
			),
			Err(trace_err) => tracing::info!(
				oracle_chain,
				destination_chain,
				block_id = %Self::format_block_id(call_block_id),
				error = ?trace_err,
				"Hyperlane debug_traceCall failed"
			),
		}
		let result = call_result.map_err(|e| {
			SettlementError::ValidationFailed(format!("Failed to quote gas payment: {}", e))
		})?;

		// Decode the result
		let quote = U256::from_be_slice(&result);

		// Return quote without buffer - the quote already includes IGP overhead
		Ok(quote)
	}

	async fn resolve_call_block_id(
		provider: &DynProvider,
		oracle_chain: u64,
		destination_chain: u32,
	) -> BlockId {
		match provider.get_block_by_number(BlockNumberOrTag::Latest).await {
			Ok(Some(block)) => BlockId::hash(block.header.hash),
			Ok(None) => {
				tracing::warn!(
					oracle_chain,
					destination_chain,
					"Latest block query returned None; defaulting to tag:latest"
				);
				BlockId::Number(BlockNumberOrTag::Latest)
			},
			Err(error) => {
				tracing::warn!(
					oracle_chain,
					destination_chain,
					error = %error,
					"Failed to fetch latest block; defaulting to tag:latest"
				);
				BlockId::Number(BlockNumberOrTag::Latest)
			},
		}
	}

	async fn fetch_debug_trace(
		provider: &DynProvider,
		call_request: &alloy_rpc_types::eth::transaction::TransactionRequest,
		block_id: BlockId,
	) -> Result<Value, TransportError> {
		let params = (
			call_request.clone(),
			block_id,
			json!({ "tracer": "callTracer" }),
		);
		let client = provider.client();
		client.request::<_, Value>("debug_traceCall", params).await
	}

	fn format_block_id(block_id: BlockId) -> String {
		match block_id {
			BlockId::Hash(hash) => format!("hash:0x{}", hex::encode(hash.block_hash)),
			BlockId::Number(BlockNumberOrTag::Number(num)) => format!("number:{}", num),
			BlockId::Number(BlockNumberOrTag::Latest) => "tag:latest".to_string(),
			BlockId::Number(BlockNumberOrTag::Finalized) => "tag:finalized".to_string(),
			BlockId::Number(BlockNumberOrTag::Safe) => "tag:safe".to_string(),
			BlockId::Number(BlockNumberOrTag::Earliest) => "tag:earliest".to_string(),
			BlockId::Number(BlockNumberOrTag::Pending) => "tag:pending".to_string(),
		}
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
		let selection_context =
			u64::from_be_bytes(order_id_hash[0..8].try_into().map_err(|_| {
				SettlementError::ValidationFailed("Failed to convert hash bytes".to_string())
			})?);
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
			.get_block_by_number(alloy_rpc_types::BlockNumberOrTag::Number(tx_block))
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
			.get_message_id(&order.id)
			.await
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
		tracing::debug!(
			order_id = %solver_types::utils::formatting::truncate_id(&order.id),
			"Checking Hyperlane claim readiness"
		);

		// Extract message ID from attestation data
		let message_id = match &fill_proof.attestation_data {
			Some(data) if data.len() == 64 => {
				let mut id = [0u8; 32];
				if hex::decode_to_slice(data, &mut id).is_ok() {
					Some(id)
				} else {
					None
				}
			},
			_ => None,
		};

		// No message = can claim immediately
		if message_id.is_none() {
			tracing::debug!(
				order_id = %solver_types::utils::formatting::truncate_id(&order.id),
				"No Hyperlane message, claim ready"
			);
			return true;
		}

		// Check if message has been delivered
		match self.check_delivery(order, message_id.unwrap()).await {
			Ok(delivered) => {
				if delivered {
					tracing::debug!(
						order_id = %solver_types::utils::formatting::truncate_id(&order.id),
						"Hyperlane message delivered, claim ready"
					);
				}
				delivered
			},
			Err(e) => {
				tracing::error!(
					order_id = %solver_types::utils::formatting::truncate_id(&order.id),
					error = %e,
					"Error checking Hyperlane delivery"
				);
				false
			},
		}
	}

	async fn generate_post_fill_transaction(
		&self,
		order: &Order,
		fill_receipt: &TransactionReceipt,
		block_number: Option<u64>,
	) -> Result<Option<Transaction>, SettlementError> {
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

		// Extract fill details from order
		let output = extract_output_details(order)?;

		// Convert order ID to bytes32
		let order_id_bytes = order_id_to_bytes32(&order.id);

		// Extract solver and timestamp from OutputFilled event
		let (solver_bytes, fill_timestamp) =
			extract_fill_details_from_logs(&fill_receipt.logs, &order_id_bytes)?;

		// Convert solver bytes to bytes32 array
		let mut solver_identifier = [0u8; 32];
		solver_identifier.copy_from_slice(&solver_bytes);

		// Create FillDescription payload
		// Note: The oracle and settler are NOT part of the FillDescription.
		// They are reconstructed by the contract from msg.sender and address(this)
		let fill_description = encode_fill_description(
			solver_identifier,
			order_id_bytes,
			fill_timestamp, // Using timestamp from OutputFilled event
			output.token,
			output.amount,
			output.recipient,
			output.call,
			output.context,
		)?;

		// Create payloads array with single FillDescription
		let payloads = vec![fill_description];

		// Get OutputSettler address (source that can attest)
		let output_settler = order
			.output_chains
			.first()
			.ok_or_else(|| SettlementError::ValidationFailed("No output chain".into()))?;

		// Calculate gas limit based on actual payload size
		let total_payload_size: usize = payloads.iter().map(|p| p.len()).sum();
		let gas_limit = self.calculate_message_gas_limit(total_payload_size);

		// Estimate gas payment with correct payloads
		// Pass solver address to ensure correct msg.sender in eth_call
		let gas_payment = self
			.estimate_gas_payment(
				dest_chain,
				origin_chain as u32,
				recipient_oracle.clone(),
				gas_limit,
				vec![], // No custom metadata
				output_settler.settler_address.clone(),
				payloads.clone(),
				order.solver_address.clone(), // Solver address for msg.sender
				block_number,
			)
			.await?;

		// Build submit call with correct payloads
		let call_data = IHyperlaneOracle::submit_0Call {
			destinationDomain: origin_chain as u32,
			recipientOracle: alloy_primitives::Address::from_slice(&recipient_oracle.0),
			gasLimit: gas_limit,
			customMetadata: vec![].into(),
			source: alloy_primitives::Address::from_slice(&output_settler.settler_address.0),
			payloads: payloads.into_iter().map(Into::into).collect(),
		};

		Ok(Some(Transaction {
			to: Some(oracle_address),
			data: call_data.abi_encode(),
			value: gas_payment,
			chain_id: dest_chain,
			nonce: None,
			gas_limit: None,
			gas_price: None,
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
		}))
	}

	async fn generate_pre_claim_transaction(
		&self,
		_order: &Order,
		_fill_proof: &FillProof,
	) -> Result<Option<Transaction>, SettlementError> {
		// Hyperlane doesn't require finalization
		// Messages are automatically processed when they arrive
		Ok(None)
	}

	async fn handle_transaction_confirmed(
		&self,
		order: &Order,
		tx_type: TransactionType,
		receipt: &TransactionReceipt,
	) -> Result<(), SettlementError> {
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

			// Extract message ID from Dispatch event logs
			let message_id = self.extract_message_id_from_logs(&receipt.logs)?;

			// Need to get the fill transaction to extract solver and timestamp
			let dest_provider = self.providers.get(&dest_chain).ok_or_else(|| {
				SettlementError::ValidationFailed(format!("No provider for chain {}", dest_chain))
			})?;

			let fill_receipt = dest_provider
				.get_transaction_receipt(FixedBytes::<32>::from_slice(
					&order.fill_tx_hash.as_ref().unwrap().0,
				))
				.await
				.map_err(|e| {
					SettlementError::ValidationFailed(format!("Failed to get fill receipt: {}", e))
				})?
				.ok_or_else(|| {
					SettlementError::ValidationFailed("Fill transaction not found".to_string())
				})?;

			// Extract solver and timestamp from fill logs
			let logs: Vec<solver_types::Log> = fill_receipt
				.inner
				.logs()
				.iter()
				.map(|log| solver_types::Log {
					address: solver_types::Address(log.address().0 .0.to_vec()),
					topics: log
						.topics()
						.iter()
						.map(|t| solver_types::H256(t.0))
						.collect(),
					data: log.data().data.to_vec(),
				})
				.collect();

			let order_id_bytes = order_id_to_bytes32(&order.id);
			let (solver_bytes, timestamp) = extract_fill_details_from_logs(&logs, &order_id_bytes)?;

			let mut solver_id = [0u8; 32];
			solver_id.copy_from_slice(&solver_bytes);

			// Compute payload hash once and store it
			let payload_hash = self.compute_payload_hash(order, solver_id, timestamp)?;

			// Store in message tracker with all details for later use
			// PostFill happens on dest_chain, message goes from dest_chain to origin_chain
			self.message_tracker
				.track_submission(
					order.id.clone(),
					message_id,
					dest_chain,   // origin_chain in submission = where message originates from
					origin_chain, // destination_chain in submission = where message goes to
					receipt.hash.clone(),
					U256::ZERO, // TODO: Gas payment would be calculated from actual receipt
					payload_hash,
					solver_id,
					timestamp,
				)
				.await?;

			tracing::info!(
				message_id = %hex::encode(message_id),
				"Hyperlane message tracked"
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
	storage: Arc<StorageService>,
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
				storage,
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
