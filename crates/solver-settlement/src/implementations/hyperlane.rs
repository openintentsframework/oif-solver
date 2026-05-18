//! Hyperlane oracle settlement implementation.
//!
//! This module provides a settlement implementation using Hyperlane's cross-chain
//! messaging protocol for oracle attestations.

use crate::{
	utils::{
		address_to_bytes32, check_is_proven, create_providers_for_chains, parse_address_table,
		parse_oracle_config, SettlementMessageTracker,
	},
	OracleConfig, SettlementError, SettlementInterface,
};
use alloy_primitives::{hex, FixedBytes, U256};
use alloy_provider::{DynProvider, Provider};
use alloy_sol_types::{sol, SolCall};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use solver_storage::StorageService;
use solver_types::{
	order_id_to_bytes32, with_0x_prefix, ConfigSchema, Field, FieldType, FillProof, InteropAddress,
	NetworksConfig, Order, OrderOutput, Schema, Transaction, TransactionHash, TransactionReceipt,
	TransactionType,
};
use std::collections::HashMap;
use std::sync::Arc;

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
		SettlementError::ValidationFailed(format!("Failed to parse order data: {e}"))
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

/// Extract (solver, timestamp) from OutputFilled logs.
///
/// Verifies that the log was emitted by the order's expected output settler for the
/// destination chain AND that the decoded MandateOutput matches the order's output.
/// Rejects forged logs emitted by malicious contracts in the same fill transaction.
fn extract_fill_details_from_logs(
	logs: &[solver_types::Log],
	order: &solver_types::Order,
	order_id: &[u8; 32],
	dest_chain: u64,
) -> Result<([u8; 32], u32), SettlementError> {
	use alloy_sol_types::SolEvent;
	use solver_types::standards::eip7683::interfaces::OutputFilled;

	// 1. Resolve the expected output and emitter from the order.
	let order_data: solver_types::standards::eip7683::Eip7683OrderData =
		serde_json::from_value(order.data.clone()).map_err(|e| {
			SettlementError::ValidationFailed(format!("Failed to parse order_data: {e}"))
		})?;

	let matched: Vec<&_> = order_data
		.outputs
		.iter()
		.filter(|o| o.chain_id == alloy_primitives::U256::from(dest_chain))
		.collect();
	if matched.is_empty() {
		return Err(SettlementError::ValidationFailed(format!(
			"Order has no output on destination chain {dest_chain}"
		)));
	}
	if matched.len() > 1 {
		return Err(SettlementError::ValidationFailed(format!(
			"Order has multiple outputs on destination chain {dest_chain}; unsupported"
		)));
	}
	let expected_output = matched[0];

	// 2. Convert the signed bytes32 settler to a 20-byte EVM address.
	if expected_output.settler[0..12].iter().any(|b| *b != 0) {
		return Err(SettlementError::ValidationFailed(
			"Order output settler is not a left-padded EVM address".to_string(),
		));
	}
	let mut expected_addr = [0u8; 20];
	expected_addr.copy_from_slice(&expected_output.settler[12..32]);
	let expected_emitter = solver_types::Address(expected_addr.to_vec());

	// 3. Filter logs by emitter AND topic match, then decode and compare MandateOutput.
	for log in logs {
		if log.address != expected_emitter {
			continue;
		}
		if log.topics.len() < 2 {
			continue;
		}
		if log.topics[0].0 != OutputFilled::SIGNATURE_HASH.0 {
			continue;
		}
		if log.topics[1].0 != *order_id {
			continue;
		}

		// Decode the non-indexed payload via the sol!-generated event type.
		// In alloy-sol-types 1.x, `abi_decode_data_validate(data)` performs the
		// validated decode and returns a tuple matching the event's non-indexed
		// params: (solver, timestamp, output, finalAmount).
		match <OutputFilled as SolEvent>::abi_decode_data_validate(&log.data) {
			Ok((solver_b32, timestamp, sol_output, _final_amount)) => {
				// Compare the decoded SolMandateOutput against the order's MandateOutput.
				let oracle_match = sol_output.oracle.0 == expected_output.oracle;
				let settler_match = sol_output.settler.0 == expected_output.settler;
				let chain_match = sol_output.chainId == expected_output.chain_id;
				let token_match = sol_output.token.0 == expected_output.token;
				let amount_match = sol_output.amount == expected_output.amount;
				let recipient_match = sol_output.recipient.0 == expected_output.recipient;
				let call_match =
					sol_output.callbackData.as_ref() == expected_output.call.as_slice();
				let context_match =
					sol_output.context.as_ref() == expected_output.context.as_slice();

				if oracle_match
					&& settler_match
					&& chain_match && token_match
					&& amount_match && recipient_match
					&& call_match && context_match
				{
					return Ok((solver_b32.0, timestamp));
				}
				// Mismatched payload — keep looking; another log might match.
				continue;
			},
			Err(_) => continue, // undecodable data — skip
		}
	}

	Err(SettlementError::ValidationFailed(
		"no matching OutputFilled log emitted by expected settler".to_string(),
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
	tracker: SettlementMessageTracker<HyperlaneMessageState>,
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
	pub fn new(storage: Arc<StorageService>) -> Self {
		Self {
			tracker: SettlementMessageTracker::new(storage, "hyperlane"),
		}
	}

	/// Load message state for a specific order
	async fn load_message(
		&self,
		order_id: &str,
	) -> Result<Option<HyperlaneMessageState>, SettlementError> {
		self.tracker.load(order_id).await
	}

	/// Save message state for a specific order
	async fn save_message(
		&self,
		order_id: &str,
		state: &HyperlaneMessageState,
	) -> Result<(), SettlementError> {
		// Save to storage with TTL (7 days after message is delivered)
		let ttl = if state.delivered.is_some() {
			Some(std::time::Duration::from_secs(7 * 24 * 60 * 60))
		} else {
			None // No TTL for pending messages
		};

		self.tracker.save(order_id, state, ttl).await
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
			.map_err(|e| {
				SettlementError::ValidationFailed(format!(
					"Failed to load hyperlane submission state for order {order_id}: {e}"
				))
			})?
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
		let mut state = self.load_message(&order_id).await?.ok_or_else(|| {
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
		let state = self.load_message(order_id).await.ok()??;
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
		let order_id_bytes =
			order_id_to_bytes32(&order.id).map_err(SettlementError::ValidationFailed)?;

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
			SettlementError::ValidationFailed(format!("No provider for chain {oracle_chain}"))
		})?;
		check_is_proven(
			provider,
			&oracle_address,
			remote_chain,
			remote_oracle,
			application,
			payload_hash,
		)
		.await
	}

	/// Check if a Hyperlane message has been delivered
	async fn check_delivery(
		&self,
		order: &Order,
		message_id: [u8; 32],
	) -> Result<bool, SettlementError> {
		let order_id = &order.id;

		// Load message state
		let mut state = self
			.message_tracker
			.load_message(order_id)
			.await
			.map_err(|e| {
				SettlementError::ValidationFailed(format!(
					"Failed to load hyperlane message state for order {order_id}: {e}"
				))
			})?
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
		let remote_oracle_bytes = address_to_bytes32(&output_oracle);
		let application_bytes = address_to_bytes32(&application);

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
		// Collect unique network IDs from input and output oracles
		let all_network_ids: Vec<u64> = oracle_config
			.input_oracles
			.keys()
			.chain(oracle_config.output_oracles.keys())
			.copied()
			.collect();
		let providers = create_providers_for_chains(&all_network_ids, networks)?;

		// Validate mailbox addresses are configured for all oracle chains
		for chain_id in &all_network_ids {
			if !mailbox_addresses.contains_key(chain_id) {
				return Err(SettlementError::ValidationFailed(format!(
					"Mailbox address not configured for chain {chain_id}"
				)));
			}
		}

		// Create message tracker with storage
		let message_tracker = MessageTracker::new(storage);

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

	/// Estimate gas payment for a Hyperlane message
	#[allow(clippy::too_many_arguments)]
	async fn estimate_gas_payment(
		&self,
		oracle_chain: u64, // Chain where the oracle is deployed (where we're calling from)
		destination_chain: u32, // Chain where the message is going
		recipient_oracle: solver_types::Address,
		gas_limit: U256,
		custom_metadata: Vec<u8>,
		source: solver_types::Address,
		payloads: Vec<Vec<u8>>,
	) -> Result<U256, SettlementError> {
		// Get the output oracle address for the oracle chain (where we're calling from)
		let oracle_addresses = self.get_output_oracles(oracle_chain);
		if oracle_addresses.is_empty() {
			return Err(SettlementError::ValidationFailed(format!(
				"No output oracle configured for chain {oracle_chain}"
			)));
		}

		// Select oracle using strategy
		let oracle_address = self.select_oracle(&oracle_addresses, None).ok_or_else(|| {
			SettlementError::ValidationFailed("Failed to select oracle".to_string())
		})?;

		// Get provider for the oracle chain
		let provider = self.providers.get(&oracle_chain).ok_or_else(|| {
			SettlementError::ValidationFailed(format!("No provider for chain {oracle_chain}"))
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
		let result = provider
			.call(call_request)
			.block(alloy_rpc_types::eth::BlockId::latest())
			.await
			.map_err(|e| {
				SettlementError::ValidationFailed(format!("Failed to quote gas payment: {e}"))
			})?;

		// Decode the result
		let quote = U256::from_be_slice(&result);

		// Return quote without buffer for now - the quote already includes IGP overhead
		Ok(quote)
	}
}

/// Configuration schema for HyperlaneSettlement
pub struct HyperlaneSettlementSchema;

impl HyperlaneSettlementSchema {
	/// Static validation method for use before instance creation
	pub fn validate_config(
		config: &serde_json::Value,
	) -> Result<(), solver_types::ValidationError> {
		let instance = Self;
		instance.validate(config)
	}
}

impl ConfigSchema for HyperlaneSettlementSchema {
	fn validate(&self, config: &serde_json::Value) -> Result<(), solver_types::ValidationError> {
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
				"No provider configured for chain {destination_chain_id}"
			))
		})?;

		// Get the oracle address using selection strategy
		let oracle_addresses = self.get_input_oracles(origin_chain_id);
		if oracle_addresses.is_empty() {
			return Err(SettlementError::ValidationFailed(format!(
				"No input oracle configured for chain {origin_chain_id}"
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
					"Failed to select oracle for chain {origin_chain_id}"
				))
			})?;

		// Get transaction receipt
		let hash = FixedBytes::<32>::from_slice(&tx_hash.0);
		let receipt = provider
			.get_transaction_receipt(hash)
			.await
			.map_err(|e| SettlementError::ValidationFailed(format!("Failed to get receipt: {e}")))?
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
			.map_err(|e| SettlementError::ValidationFailed(format!("Failed to get block: {e}")))?;

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
		let order_id_bytes =
			order_id_to_bytes32(&order.id).map_err(SettlementError::ValidationFailed)?;

		// Extract solver and timestamp from OutputFilled event
		let (solver_identifier, fill_timestamp) =
			extract_fill_details_from_logs(&fill_receipt.logs, order, &order_id_bytes, dest_chain)?;

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
		let gas_payment = self
			.estimate_gas_payment(
				dest_chain,
				origin_chain as u32,
				recipient_oracle.clone(),
				gas_limit,
				vec![], // No custom metadata
				output_settler.settler_address.clone(),
				payloads.clone(),
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

		// Set explicit gas limit for the submit transaction
		let submit_gas_limit = self.default_gas_limit;

		Ok(Some(Transaction {
			to: Some(oracle_address),
			data: call_data.abi_encode(),
			value: gas_payment,
			chain_id: dest_chain,
			nonce: None,
			gas_limit: Some(submit_gas_limit),
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
				SettlementError::ValidationFailed(format!("No provider for chain {dest_chain}"))
			})?;

			let fill_receipt = dest_provider
				.get_transaction_receipt(FixedBytes::<32>::from_slice(
					&order.fill_tx_hash.as_ref().unwrap().0,
				))
				.await
				.map_err(|e| {
					SettlementError::ValidationFailed(format!("Failed to get fill receipt: {e}"))
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
					transaction_hash: log
						.transaction_hash
						.map(|h| solver_types::TransactionHash(h.0.to_vec())),
					block_number: log.block_number,
				})
				.collect();

			let order_id_bytes =
				order_id_to_bytes32(&order.id).map_err(SettlementError::ValidationFailed)?;
			let (solver_id, timestamp) =
				extract_fill_details_from_logs(&logs, order, &order_id_bytes, dest_chain)?;

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

/// Factory function to create a Hyperlane settlement provider from configuration
pub fn create_settlement(
	config: &serde_json::Value,
	networks: &NetworksConfig,
	storage: Arc<StorageService>,
) -> Result<Box<dyn SettlementInterface>, SettlementError> {
	// Validate configuration first
	HyperlaneSettlementSchema::validate_config(config)
		.map_err(|e| SettlementError::ValidationFailed(format!("Invalid configuration: {e}")))?;

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
		.and_then(|v| v.as_i64())
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

#[cfg(test)]
mod tests {
	use super::*;

	// === Shared helpers for OutputFilled emitter-filter tests ===
	// Duplicated from `broadcaster.rs` — extracting to a shared test helper
	// module is a follow-up tracked in the Fix 2 plan (acceptable per spec).
	fn build_test_order_for_emitter_tests(
		order_id: [u8; 32],
		origin_chain: u64,
		dest_chain: u64,
		output: solver_types::standards::eip7683::MandateOutput,
	) -> solver_types::Order {
		use solver_types::standards::eip7683::{Eip7683OrderData, GasLimitOverrides};

		let order_data = Eip7683OrderData {
			user: format!("0x{}", alloy_primitives::hex::encode([0x22u8; 20])),
			nonce: alloy_primitives::U256::from(1u64),
			origin_chain_id: alloy_primitives::U256::from(origin_chain),
			expires: (solver_types::current_timestamp() as u32) + 3600,
			fill_deadline: (solver_types::current_timestamp() as u32) + 1800,
			input_oracle: format!("0x{}", alloy_primitives::hex::encode([0x11u8; 20])),
			inputs: vec![],
			order_id,
			gas_limit_overrides: GasLimitOverrides::default(),
			outputs: vec![output.clone()],
			raw_order_data: None,
			signature: None,
			sponsor: None,
			lock_type: None,
		};

		let mut settler_addr = [0u8; 20];
		settler_addr.copy_from_slice(&output.settler[12..32]);

		solver_types::Order {
			id: format!("0x{}", alloy_primitives::hex::encode(order_id)),
			standard: "eip7683".to_string(),
			created_at: 0,
			updated_at: 0,
			status: solver_types::OrderStatus::Pending,
			data: serde_json::to_value(&order_data).unwrap(),
			solver_address: solver_types::Address(vec![0x99; 20]),
			quote_id: None,
			input_chains: vec![solver_types::order::ChainSettlerInfo {
				chain_id: origin_chain,
				settler_address: solver_types::Address(vec![0xCC; 20]),
			}],
			output_chains: vec![solver_types::order::ChainSettlerInfo {
				chain_id: dest_chain,
				settler_address: solver_types::Address(settler_addr.to_vec()),
			}],
			execution_params: None,
			prepare_tx_hash: None,
			fill_tx_hash: None,
			claim_tx_hash: None,
			post_fill_tx_hash: None,
			pre_claim_tx_hash: None,
			fill_proof: None,
			settlement_name: None,
		}
	}

	fn make_mandate_output(
		oracle: [u8; 32],
		settler: [u8; 32],
		chain_id: u64,
		token: [u8; 32],
		amount: alloy_primitives::U256,
		recipient: [u8; 32],
	) -> solver_types::standards::eip7683::MandateOutput {
		solver_types::standards::eip7683::MandateOutput {
			oracle,
			settler,
			chain_id: alloy_primitives::U256::from(chain_id),
			token,
			amount,
			recipient,
			call: vec![],
			context: vec![],
		}
	}

	fn encode_output_filled_data(
		order_id: [u8; 32],
		solver: [u8; 32],
		timestamp: u32,
		output: &solver_types::standards::eip7683::MandateOutput,
		final_amount: alloy_primitives::U256,
	) -> Vec<u8> {
		use alloy_sol_types::SolEvent;
		use solver_types::standards::eip7683::interfaces::{OutputFilled, SolMandateOutput};

		let sol_output = SolMandateOutput {
			oracle: alloy_primitives::FixedBytes::from(output.oracle),
			settler: alloy_primitives::FixedBytes::from(output.settler),
			chainId: output.chain_id,
			token: alloy_primitives::FixedBytes::from(output.token),
			amount: output.amount,
			recipient: alloy_primitives::FixedBytes::from(output.recipient),
			callbackData: output.call.clone().into(),
			context: output.context.clone().into(),
		};

		let event = OutputFilled {
			orderId: alloy_primitives::FixedBytes::from(order_id),
			solver: alloy_primitives::FixedBytes::from(solver),
			timestamp,
			output: sol_output,
			finalAmount: final_amount,
		};

		event.encode_data()
	}
	// === End shared helpers ===

	#[test]
	fn test_extract_fill_details_rejects_log_from_wrong_emitter() {
		let order_id: [u8; 32] = [0x42; 32];
		let expected_settler_addr: [u8; 20] = [0xAA; 20];
		let attacker_addr: [u8; 20] = [0xBB; 20];

		let mut settler_bytes32 = [0u8; 32];
		settler_bytes32[12..32].copy_from_slice(&expected_settler_addr);

		let output = make_mandate_output(
			[0x11; 32],
			settler_bytes32,
			137,
			[0x22; 32],
			alloy_primitives::U256::from(1000u64),
			[0x33; 32],
		);
		let order = build_test_order_for_emitter_tests(order_id, 1, 137, output.clone());

		let log_data = encode_output_filled_data(
			order_id,
			[0x77; 32],
			1_700_000_000u32,
			&output,
			alloy_primitives::U256::from(1000u64),
		);

		let forged_log = solver_types::Log {
			address: solver_types::Address(attacker_addr.to_vec()),
			topics: vec![
				solver_types::H256(
					<solver_types::standards::eip7683::interfaces::OutputFilled
						as alloy_sol_types::SolEvent>::SIGNATURE_HASH.0,
				),
				solver_types::H256(order_id),
			],
			data: log_data,
			..Default::default()
		};

		let result = extract_fill_details_from_logs(&[forged_log], &order, &order_id, 137);
		assert!(
			result.is_err(),
			"forged log from wrong emitter should be rejected"
		);
	}

	#[test]
	fn test_extract_fill_details_rejects_mismatched_mandate_output() {
		let order_id: [u8; 32] = [0x42; 32];
		let expected_settler_addr: [u8; 20] = [0xAA; 20];
		let mut settler_bytes32 = [0u8; 32];
		settler_bytes32[12..32].copy_from_slice(&expected_settler_addr);

		let order_output = make_mandate_output(
			[0x11; 32],
			settler_bytes32,
			137,
			[0x22; 32],
			alloy_primitives::U256::from(1000u64),
			[0x33; 32],
		);
		let order = build_test_order_for_emitter_tests(order_id, 1, 137, order_output.clone());

		let tampered_output = make_mandate_output(
			[0x11; 32],
			settler_bytes32,
			137,
			[0x22; 32],
			alloy_primitives::U256::from(9999u64),
			[0x33; 32],
		);
		let log_data = encode_output_filled_data(
			order_id,
			[0x77; 32],
			1_700_000_000u32,
			&tampered_output,
			alloy_primitives::U256::from(9999u64),
		);

		let log = solver_types::Log {
			address: solver_types::Address(expected_settler_addr.to_vec()),
			topics: vec![
				solver_types::H256(
					<solver_types::standards::eip7683::interfaces::OutputFilled
						as alloy_sol_types::SolEvent>::SIGNATURE_HASH.0,
				),
				solver_types::H256(order_id),
			],
			data: log_data,
			..Default::default()
		};

		let result = extract_fill_details_from_logs(&[log], &order, &order_id, 137);
		assert!(
			result.is_err(),
			"log with mismatched MandateOutput should be rejected"
		);
	}

	#[test]
	fn test_extract_fill_details_accepts_matching_log() {
		let order_id: [u8; 32] = [0x42; 32];
		let expected_settler_addr: [u8; 20] = [0xAA; 20];
		let mut settler_bytes32 = [0u8; 32];
		settler_bytes32[12..32].copy_from_slice(&expected_settler_addr);

		let output = make_mandate_output(
			[0x11; 32],
			settler_bytes32,
			137,
			[0x22; 32],
			alloy_primitives::U256::from(1000u64),
			[0x33; 32],
		);
		let order = build_test_order_for_emitter_tests(order_id, 1, 137, output.clone());

		let expected_solver = [0x77u8; 32];
		let expected_timestamp = 1_700_000_000u32;

		let log_data = encode_output_filled_data(
			order_id,
			expected_solver,
			expected_timestamp,
			&output,
			alloy_primitives::U256::from(1000u64),
		);

		let log = solver_types::Log {
			address: solver_types::Address(expected_settler_addr.to_vec()),
			topics: vec![
				solver_types::H256(
					<solver_types::standards::eip7683::interfaces::OutputFilled
						as alloy_sol_types::SolEvent>::SIGNATURE_HASH.0,
				),
				solver_types::H256(order_id),
			],
			data: log_data,
			..Default::default()
		};

		let (solver, ts) = extract_fill_details_from_logs(&[log], &order, &order_id, 137)
			.expect("matching log should be accepted");
		assert_eq!(solver, expected_solver);
		assert_eq!(ts, expected_timestamp);
	}
}
