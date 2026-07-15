//! Hyperlane oracle settlement implementation.
//!
//! This module provides a settlement implementation using Hyperlane's cross-chain
//! messaging protocol for oracle attestations.

use crate::{
	implementations::fill_description::{
		encode_fill_description, extract_verified_fill_from_logs,
		payload_hash as verified_payload_hash, VerifiedFill,
	},
	utils::{
		address_to_bytes32, check_is_proven, create_providers_for_chains, parse_address_table,
		parse_oracle_config, SettlementMessageTracker,
	},
	OracleConfig, PostFillFeeParams, SettlementError, SettlementFeeQuote, SettlementInterface,
};
use alloy_primitives::{hex, FixedBytes, U256};
use alloy_provider::{DynProvider, Provider};
use alloy_sol_types::{sol, SolCall};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use solver_storage::StorageService;
use solver_types::{
	order_id_to_bytes32, with_0x_prefix, ConfigSchema, Field, FieldType, FillProof, NetworksConfig,
	Order, Schema, Transaction, TransactionHash, TransactionReceipt, TransactionType,
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

/// Encode a placeholder FillDescription for post-fill fee quotes.
///
/// This preserves the pre-existing quote-time behavior: callers only have a
/// PostFillFeeParams projection, not a verified fill receipt with full output
/// context.
#[allow(clippy::too_many_arguments)]
fn encode_quote_fill_description(
	solver_identifier: [u8; 32],
	order_id: [u8; 32],
	timestamp: u32,
	token: [u8; 32],
	amount: U256,
	recipient: [u8; 32],
	call_data: Vec<u8>,
	context: Vec<u8>,
) -> Result<Vec<u8>, SettlementError> {
	encode_fill_description(
		&VerifiedFill {
			solver_identifier,
			timestamp,
			output: solver_types::standards::eip7683::MandateOutput {
				oracle: [0u8; 32],
				settler: [0u8; 32],
				chain_id: U256::ZERO,
				token,
				amount,
				recipient,
				call: call_data,
				context,
			},
		},
		order_id,
	)
}

fn transaction_receipt_from_alloy(
	receipt: &alloy_rpc_types::TransactionReceipt,
) -> TransactionReceipt {
	TransactionReceipt::from(receipt)
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
		// Propagate the typed error (StorageUnavailable is retryable); do not
		// collapse a transient storage fault into terminal ValidationFailed.
		let mut state = self
			.load_message(&order_id)
			.await?
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
	domains: HashMap<u64, u32>,
	message_tracker: Arc<MessageTracker>,
	default_gas_limit: u64,
}

impl HyperlaneSettlement {
	fn resolve_domain(&self, chain_id: u64) -> Result<u32, SettlementError> {
		self.domains.get(&chain_id).copied().ok_or_else(|| {
			SettlementError::ValidationFailed(format!(
				"Hyperlane domain not configured for chain {chain_id}"
			))
		})
	}

	fn build_resolved_domains(
		domains: HashMap<u64, u32>,
		chain_ids: &[u64],
	) -> Result<HashMap<u64, u32>, SettlementError> {
		let mut resolved = HashMap::new();
		for chain_id in chain_ids {
			let domain = domains.get(chain_id).copied().ok_or_else(|| {
				SettlementError::ValidationFailed(format!(
					"Hyperlane domain not configured for chain {chain_id}"
				))
			})?;
			if domain == 0 {
				return Err(SettlementError::ValidationFailed(format!(
					"Hyperlane domain for chain {chain_id} cannot be zero"
				)));
			}
			resolved.insert(*chain_id, domain);
		}
		Ok(resolved)
	}

	/// Validate that the order-bound input oracle is configured for the given
	/// source chain. Returns the parsed order-bound input oracle on success.
	fn validate_bound_input_oracle(
		&self,
		order: &Order,
		source_chain: u64,
	) -> Result<solver_types::Address, SettlementError> {
		let input_oracle = crate::parse_bound_input_oracle(order)?;
		if !self.is_input_oracle_supported(source_chain, &input_oracle) {
			return Err(SettlementError::ValidationFailed(format!(
				"Order-bound input oracle is not configured for source chain {source_chain}"
			)));
		}
		Ok(input_oracle)
	}

	/// Validate that the order-bound output oracle is configured for the given
	/// destination chain. Returns the parsed order-bound output oracle on success.
	fn validate_bound_output_oracle(
		&self,
		order: &Order,
		destination_chain: u64,
	) -> Result<solver_types::Address, SettlementError> {
		let output_oracle = crate::parse_bound_output_oracle(order, destination_chain)?;
		if !self.is_output_oracle_supported(destination_chain, &output_oracle) {
			return Err(SettlementError::ValidationFailed(format!(
				"Order-bound output oracle is not configured for destination chain {destination_chain}"
			)));
		}
		Ok(output_oracle)
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
		// Propagate the typed error (StorageUnavailable is retryable); do not
		// collapse a transient storage fault into terminal ValidationFailed.
		let mut state = self
			.message_tracker
			.load_message(order_id)
			.await?
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
		// Security: bind to the order's signed input oracle on the destination chain
		// (where we check isProven) and the order's signed output oracle on the
		// origin chain. Reject any divergence from the order-bound oracles.
		let input_oracle = self.validate_bound_input_oracle(order, dest_chain)?;
		let output_oracle = self.validate_bound_output_oracle(order, origin_chain)?;

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
		} else {
			tracing::info!(
				order_id = %solver_types::utils::formatting::truncate_id(order_id),
				message_id = %hex::encode(message_id),
				origin_chain,
				dest_chain,
				"Hyperlane message not proven yet; claim readiness blocked on delivery"
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
		domains: HashMap<u64, u32>,
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
		let domains = Self::build_resolved_domains(domains, &all_network_ids)?;

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
			domains,
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
				SettlementError::BackendUnavailable(format!("Failed to quote gas payment: {e}"))
			})?;

		// Decode the result
		let quote = U256::from_be_slice(&result);

		// Return quote without buffer for now - the quote already includes IGP overhead
		Ok(quote)
	}

	/// Returns true when this order's route actually uses Hyperlane PostFill.
	/// Mirrors the early-return logic in `generate_post_fill_transaction`:
	/// when EITHER side has no configured oracles, the orchestrator skips
	/// PostFill, and a claim never needs a Hyperlane message to prove fill.
	fn post_fill_required(&self, order: &Order) -> bool {
		let dest_chain = match order.output_chains.first() {
			Some(c) => c.chain_id,
			None => return false,
		};
		let origin_chain = match order.input_chains.first() {
			Some(c) => c.chain_id,
			None => return false,
		};
		!self.get_output_oracles(dest_chain).is_empty()
			&& !self.get_input_oracles(origin_chain).is_empty()
	}

	async fn track_post_fill_submission_from_receipt(
		&self,
		order: &Order,
		receipt: &TransactionReceipt,
	) -> Result<(), SettlementError> {
		if self
			.message_tracker
			.get_message_id(&order.id)
			.await
			.is_some()
		{
			return Ok(());
		}

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

		let fill_tx_hash = order.fill_tx_hash.as_ref().ok_or_else(|| {
			SettlementError::ValidationFailed(
				"Missing fill transaction hash: required for Hyperlane post-fill processing"
					.to_string(),
			)
		})?;

		let fill_receipt = dest_provider
			.get_transaction_receipt(FixedBytes::<32>::from_slice(&fill_tx_hash.0))
			.await
			.map_err(|e| {
				SettlementError::BackendUnavailable(format!("Failed to get fill receipt: {e}"))
			})?
			.ok_or_else(|| {
				SettlementError::ValidationFailed("Fill transaction not found".to_string())
			})?;
		let fill_receipt = transaction_receipt_from_alloy(&fill_receipt);

		let order_id_bytes =
			order_id_to_bytes32(&order.id).map_err(SettlementError::ValidationFailed)?;
		let verified_fill =
			extract_verified_fill_from_logs(&fill_receipt.logs, order, order_id_bytes, dest_chain)?;

		// Compute payload hash once and store it
		let payload_hash = verified_payload_hash(&verified_fill, order_id_bytes)?;

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
				verified_fill.solver_identifier,
				verified_fill.timestamp,
			)
			.await?;

		tracing::info!(
			message_id = %hex::encode(message_id),
			"Hyperlane message tracked"
		);

		Ok(())
	}
}

fn parse_domain_table(table: &serde_json::Value) -> Result<HashMap<u64, u32>, SettlementError> {
	let table = table.as_object().ok_or_else(|| {
		SettlementError::ValidationFailed("Hyperlane domains must be an object".to_string())
	})?;
	let mut result = HashMap::new();

	for (chain_id_str, domain_value) in table {
		let chain_id = chain_id_str.parse::<u64>().map_err(|e| {
			SettlementError::ValidationFailed(format!("Invalid chain ID '{chain_id_str}': {e}"))
		})?;
		let domain = domain_value.as_u64().ok_or_else(|| {
			SettlementError::ValidationFailed(format!(
				"Hyperlane domain must be an unsigned integer for chain {chain_id}"
			))
		})?;
		if domain == 0 {
			return Err(SettlementError::ValidationFailed(format!(
				"Hyperlane domain for chain {chain_id} cannot be zero"
			)));
		}
		if domain > u32::MAX as u64 {
			return Err(SettlementError::ValidationFailed(format!(
				"Hyperlane domain for chain {chain_id} exceeds u32::MAX"
			)));
		}
		result.insert(chain_id, domain as u32);
	}

	Ok(result)
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
				Field::new("domains", FieldType::Table(Schema::new(vec![], vec![]))),
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

	async fn quote_post_fill_fee(
		&self,
		params: &PostFillFeeParams,
	) -> Result<Option<SettlementFeeQuote>, SettlementError> {
		if self.get_output_oracles(params.dest_chain_id).is_empty()
			|| self.get_input_oracles(params.origin_chain_id).is_empty()
		{
			return Ok(None);
		}

		let recipient_oracle = self
			.select_oracle(&self.get_input_oracles(params.origin_chain_id), None)
			.ok_or_else(|| SettlementError::ValidationFailed("No input oracle".into()))?;

		let fill_description = encode_quote_fill_description(
			[0u8; 32],
			[0u8; 32],
			0,
			params.output_token,
			params.output_amount,
			params.output_recipient,
			params.output_call.clone(),
			vec![],
		)?;
		let payloads = vec![fill_description];
		let total_payload_size: usize = payloads.iter().map(|p| p.len()).sum();
		let gas_limit = self.calculate_message_gas_limit(total_payload_size);
		let origin_domain = self.resolve_domain(params.origin_chain_id)?;

		let fee_wei = self
			.estimate_gas_payment(
				params.dest_chain_id,
				origin_domain,
				recipient_oracle,
				gas_limit,
				vec![],
				params.source_settler.clone(),
				payloads,
			)
			.await?;

		Ok(Some(SettlementFeeQuote {
			fee_wei,
			chain_id: params.dest_chain_id,
		}))
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

		// Security: use the order-bound input oracle from canonical order_data.
		// Any mismatch with the configured input oracle set for the source chain
		// is a security event and surfaces as ValidationFailed.
		let oracle_address = self.validate_bound_input_oracle(order, origin_chain_id)?;

		// Get transaction receipt
		let hash = FixedBytes::<32>::from_slice(&tx_hash.0);
		let receipt = provider
			.get_transaction_receipt(hash)
			.await
			.map_err(|e| {
				SettlementError::BackendUnavailable(format!("Failed to get receipt: {e}"))
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
				SettlementError::BackendUnavailable(format!("Failed to get block: {e}"))
			})?;

		let block_timestamp = block
			.ok_or_else(|| SettlementError::ValidationFailed("Block not found".to_string()))?
			.header
			.timestamp;

		// Check if we have a tracked message for this order. If the solver
		// restarted after PostFill confirmed, rebuild the tracker from receipts
		// before returning proof data.
		let mut message_id = self.message_tracker.get_message_id(&order.id).await;
		if message_id.is_none() && order.post_fill_tx_hash.is_some() {
			self.recover_post_fill_state(order).await?;
			message_id = self.message_tracker.get_message_id(&order.id).await;
		}

		Ok(FillProof {
			tx_hash: tx_hash.clone(),
			block_number: tx_block,
			oracle_address: with_0x_prefix(&hex::encode(&oracle_address.0)),
			attestation_data: message_id.map(|id| hex::encode(id).into_bytes()),
			filled_timestamp: block_timestamp,
		})
	}

	async fn recover_post_fill_state(&self, order: &Order) -> Result<bool, SettlementError> {
		if self
			.message_tracker
			.get_message_id(&order.id)
			.await
			.is_some()
		{
			return Ok(true);
		}

		let post_fill_tx_hash = match order.post_fill_tx_hash.as_ref() {
			Some(tx_hash) => tx_hash,
			None => return Ok(false),
		};
		let dest_chain = order
			.output_chains
			.first()
			.map(|c| c.chain_id)
			.ok_or_else(|| SettlementError::ValidationFailed("No output chains".into()))?;
		let provider = self.providers.get(&dest_chain).ok_or_else(|| {
			SettlementError::ValidationFailed(format!("No provider for chain {dest_chain}"))
		})?;

		let receipt = provider
			.get_transaction_receipt(FixedBytes::<32>::from_slice(&post_fill_tx_hash.0))
			.await
			.map_err(|e| {
				SettlementError::BackendUnavailable(format!("Failed to get post-fill receipt: {e}"))
			})?
			.ok_or_else(|| {
				SettlementError::ValidationFailed("Post-fill transaction not found".to_string())
			})?;

		if !receipt.status() {
			return Ok(false);
		}

		let receipt = transaction_receipt_from_alloy(&receipt);
		self.track_post_fill_submission_from_receipt(order, &receipt)
			.await?;

		Ok(self
			.message_tracker
			.get_message_id(&order.id)
			.await
			.is_some())
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

		if message_id.is_none() {
			if self.post_fill_required(order) {
				tracing::warn!(
					order_id = %solver_types::utils::formatting::truncate_id(&order.id),
					attestation_data = ?fill_proof.attestation_data,
					"Hyperlane message_id missing from attestation; deferring claim readiness"
				);
				return false;
			}
			// Route does not use Hyperlane PostFill: no message is expected,
			// so missing message_id means claim is ready.
			tracing::debug!(
				order_id = %solver_types::utils::formatting::truncate_id(&order.id),
				"No Hyperlane PostFill required for this route, claim ready"
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

		// Preserve legitimate "no oracle configured for this chain = skip post-fill"
		// semantics. Any mismatch between the order-bound oracle and the configured
		// supported set MUST surface as ValidationFailed below, not as Ok(None).
		if self.get_output_oracles(dest_chain).is_empty() {
			return Ok(None);
		}
		if self.get_input_oracles(origin_chain).is_empty() {
			return Ok(None);
		}
		// Security: bind to the order's signed output oracle (destination) and
		// signed input oracle (origin / recipient).
		let oracle_address = self.validate_bound_output_oracle(order, dest_chain)?;
		let recipient_oracle = self.validate_bound_input_oracle(order, origin_chain)?;

		// Convert order ID to bytes32
		let order_id_bytes =
			order_id_to_bytes32(&order.id).map_err(SettlementError::ValidationFailed)?;

		let verified_fill =
			extract_verified_fill_from_logs(&fill_receipt.logs, order, order_id_bytes, dest_chain)?;

		// Create FillDescription payload
		// Note: The oracle and settler are NOT part of the FillDescription.
		// They are reconstructed by the contract from msg.sender and address(this)
		let fill_description = encode_fill_description(&verified_fill, order_id_bytes)?;

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
		let origin_domain = self.resolve_domain(origin_chain)?;

		// Estimate gas payment with correct payloads
		let gas_payment = self
			.estimate_gas_payment(
				dest_chain,
				origin_domain,
				recipient_oracle.clone(),
				gas_limit,
				vec![], // No custom metadata
				output_settler.settler_address.clone(),
				payloads.clone(),
			)
			.await?;

		// Build submit call with correct payloads
		let call_data = IHyperlaneOracle::submit_0Call {
			destinationDomain: origin_domain,
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
			self.track_post_fill_submission_from_receipt(order, receipt)
				.await?;
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

	let domains = parse_domain_table(config.get("domains").ok_or_else(|| {
		SettlementError::ValidationFailed("Missing Hyperlane domains".to_string())
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
				domains,
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
	use crate::OracleSelectionStrategy;
	use alloy_provider::ProviderBuilder;
	use solver_types::standards::eip7683::MandateOutput;
	use solver_types::utils::tests::builders::{
		Eip7683OrderDataBuilder, MandateOutputBuilder, OrderBuilder,
	};
	use wiremock::matchers::{body_string_contains, method};
	use wiremock::{Mock, MockServer, ResponseTemplate};

	fn test_storage() -> Arc<StorageService> {
		Arc::new(StorageService::new(Box::new(
			solver_storage::implementations::memory::MemoryStorage::new(),
		)))
	}

	fn test_hyperlane_settlement(oracle_config: OracleConfig) -> HyperlaneSettlement {
		HyperlaneSettlement {
			providers: HashMap::new(),
			oracle_config,
			mailbox_addresses: HashMap::new(),
			igp_addresses: HashMap::new(),
			domains: HashMap::new(),
			message_tracker: Arc::new(MessageTracker::new(test_storage())),
			default_gas_limit: 500_000,
		}
	}

	fn test_hyperlane_settlement_with_providers(
		oracle_config: OracleConfig,
		providers: HashMap<u64, DynProvider>,
		domains: HashMap<u64, u32>,
	) -> HyperlaneSettlement {
		HyperlaneSettlement {
			providers,
			oracle_config,
			mailbox_addresses: HashMap::new(),
			igp_addresses: HashMap::new(),
			domains,
			message_tracker: Arc::new(MessageTracker::new(test_storage())),
			default_gas_limit: 500_000,
		}
	}

	fn make_eip7683_order_data_for_binding(
		input_oracle: &solver_types::Address,
		outputs: Vec<MandateOutput>,
	) -> serde_json::Value {
		let data = Eip7683OrderDataBuilder::new()
			.origin_chain_id(U256::from(1u64))
			.input_oracle(with_0x_prefix(&hex::encode(&input_oracle.0)))
			.outputs(outputs)
			.build();
		serde_json::to_value(data).unwrap()
	}

	fn make_output_for_binding(destination_chain: u64, output_oracle: [u8; 32]) -> MandateOutput {
		MandateOutputBuilder::new()
			.oracle(output_oracle)
			.chain_id(U256::from(destination_chain))
			.token([0x11; 32])
			.amount(U256::from(42u64))
			.recipient([0x22; 32])
			.build()
	}

	#[test]
	fn hyperlane_domain_table_rejects_zero_domain() {
		let err = parse_domain_table(&serde_json::json!({ "1": 0 })).unwrap_err();
		assert!(
			err.to_string().contains("cannot be zero"),
			"unexpected error: {err}"
		);
	}

	#[test]
	fn hyperlane_domain_table_rejects_non_object() {
		let err = parse_domain_table(&serde_json::json!([])).unwrap_err();
		assert!(
			err.to_string().contains("must be an object"),
			"unexpected error: {err}"
		);
	}

	#[test]
	fn hyperlane_domain_table_rejects_non_integer_domain() {
		let err = parse_domain_table(&serde_json::json!({ "1": "10" })).unwrap_err();
		assert!(
			err.to_string().contains("must be an unsigned integer"),
			"unexpected error: {err}"
		);
	}

	#[test]
	fn hyperlane_domain_table_rejects_oversized_domain() {
		let err = parse_domain_table(&serde_json::json!({ "1": u32::MAX as u64 + 1 })).unwrap_err();
		assert!(
			err.to_string().contains("exceeds u32::MAX"),
			"unexpected error: {err}"
		);
	}

	#[test]
	fn hyperlane_resolved_domains_require_every_network() {
		let err = HyperlaneSettlement::build_resolved_domains(HashMap::from([(1, 10)]), &[1, 2])
			.unwrap_err();
		assert!(
			err.to_string().contains("not configured for chain 2"),
			"unexpected error: {err}"
		);
	}

	#[test]
	fn hyperlane_resolved_domains_reject_zero_domain() {
		let err =
			HyperlaneSettlement::build_resolved_domains(HashMap::from([(1, 0)]), &[1]).unwrap_err();
		assert!(
			err.to_string().contains("cannot be zero"),
			"unexpected error: {err}"
		);
	}

	#[test]
	fn hyperlane_create_settlement_requires_domains() {
		let config = serde_json::json!({
			"oracles": {
				"input": {},
				"output": {}
			},
			"routes": {},
			"mailboxes": {},
			"igp_addresses": {},
			"default_gas_limit": 500000
		});

		let err = match create_settlement(&config, &NetworksConfig::new(), test_storage()) {
			Ok(_) => panic!("missing domains must fail validation"),
			Err(err) => err,
		};

		assert!(
			err.to_string().contains("Missing required field: domains"),
			"unexpected error: {err}"
		);
	}

	// Shared helpers for OutputFilled emitter-filter tests.
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

	fn hex_hash(bytes: &[u8]) -> String {
		format!("0x{}", hex::encode(bytes))
	}

	fn make_dispatch_id_log(message_id: [u8; 32]) -> solver_types::Log {
		solver_types::Log {
			address: solver_types::Address(vec![0x44; 20]),
			topics: vec![
				solver_types::H256(keccak256("DispatchId(bytes32)").0),
				solver_types::H256(message_id),
			],
			data: vec![],
			..Default::default()
		}
	}

	fn make_output_filled_log(
		emitter: &[u8; 20],
		order_id: [u8; 32],
		solver: [u8; 32],
		timestamp: u32,
		output: &MandateOutput,
	) -> solver_types::Log {
		solver_types::Log {
			address: solver_types::Address(emitter.to_vec()),
			topics: vec![
				solver_types::H256(
					<solver_types::standards::eip7683::interfaces::OutputFilled
						as alloy_sol_types::SolEvent>::SIGNATURE_HASH.0,
				),
				solver_types::H256(order_id),
			],
			data: encode_output_filled_data(order_id, solver, timestamp, output, output.amount),
			..Default::default()
		}
	}

	fn make_hyperlane_recovery_order(
		order_id: [u8; 32],
		origin_chain: u64,
		dest_chain: u64,
		fill_tx_hash: TransactionHash,
		post_fill_tx_hash: TransactionHash,
	) -> (Order, MandateOutput, [u8; 20]) {
		let output_settler = [0xAA; 20];
		let mut settler_bytes32 = [0u8; 32];
		settler_bytes32[12..32].copy_from_slice(&output_settler);

		let output = make_mandate_output(
			[0x44; 32],
			settler_bytes32,
			dest_chain,
			[0x22; 32],
			U256::from(1000u64),
			[0x33; 32],
		);
		let order = OrderBuilder::new()
			.with_id(format!("0x{}", hex::encode(order_id)))
			.with_input_chain_ids(vec![origin_chain])
			.with_output_chains(vec![solver_types::order::ChainSettlerInfo {
				chain_id: dest_chain,
				settler_address: solver_types::Address(output_settler.to_vec()),
			}])
			.with_data(make_eip7683_order_data_for_binding(
				&solver_types::Address(vec![0x33; 20]),
				vec![output.clone()],
			))
			.with_fill_tx_hash(Some(fill_tx_hash))
			.with_post_fill_tx_hash(Some(post_fill_tx_hash))
			.build();

		(order, output, output_settler)
	}

	fn make_receipt_json(
		tx_hash: &TransactionHash,
		block_number: u64,
		success: bool,
		logs: &[solver_types::Log],
	) -> serde_json::Value {
		let status_hex = if success { "0x1" } else { "0x0" };
		serde_json::json!({
			"transactionHash": hex_hash(&tx_hash.0),
			"transactionIndex": "0x0",
			"blockHash": "0x0000000000000000000000000000000000000000000000000000000000000002",
			"blockNumber": format!("0x{block_number:x}"),
			"from": "0x0000000000000000000000000000000000000003",
			"to": "0x0000000000000000000000000000000000000004",
			"cumulativeGasUsed": "0x0",
			"gasUsed": "0x0",
			"effectiveGasPrice": "0x0",
			"logs": logs.iter().enumerate().map(|(idx, log)| serde_json::json!({
				"address": with_0x_prefix(&hex::encode(&log.address.0)),
				"topics": log.topics.iter().map(|topic| hex_hash(&topic.0)).collect::<Vec<_>>(),
				"data": with_0x_prefix(&hex::encode(&log.data)),
				"blockHash": "0x0000000000000000000000000000000000000000000000000000000000000002",
				"blockNumber": format!("0x{block_number:x}"),
				"transactionHash": hex_hash(&tx_hash.0),
				"transactionIndex": "0x0",
				"logIndex": format!("0x{idx:x}"),
				"removed": false,
			})).collect::<Vec<_>>(),
			"logsBloom": format!("0x{}", "0".repeat(512)),
			"status": status_hex,
			"type": "0x2",
		})
	}

	fn make_block_json(block_number: u64, timestamp: u64) -> serde_json::Value {
		serde_json::json!({
			"number": format!("0x{block_number:x}"),
			"hash": "0x0000000000000000000000000000000000000000000000000000000000000002",
			"parentHash": "0x0000000000000000000000000000000000000000000000000000000000000001",
			"sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
			"miner": "0x0000000000000000000000000000000000000003",
			"stateRoot": "0x0000000000000000000000000000000000000000000000000000000000000004",
			"transactionsRoot": "0x0000000000000000000000000000000000000000000000000000000000000005",
			"receiptsRoot": "0x0000000000000000000000000000000000000000000000000000000000000006",
			"logsBloom": format!("0x{}", "0".repeat(512)),
			"difficulty": "0x0",
			"totalDifficulty": "0x0",
			"extraData": "0x",
			"size": "0x0",
			"gasLimit": "0x1c9c380",
			"gasUsed": "0x0",
			"timestamp": format!("0x{timestamp:x}"),
			"transactions": [],
			"uncles": [],
			"baseFeePerGas": "0x0",
			"mixHash": "0x0000000000000000000000000000000000000000000000000000000000000007",
			"nonce": "0x0000000000000000",
		})
	}

	async fn mount_receipt_mock(
		server: &MockServer,
		tx_hash: &TransactionHash,
		receipt: serde_json::Value,
	) {
		Mock::given(method("POST"))
			.and(body_string_contains(
				"\"method\":\"eth_getTransactionReceipt\"",
			))
			.and(body_string_contains(hex_hash(&tx_hash.0)))
			.respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
				"jsonrpc": "2.0",
				"id": 1,
				"result": receipt,
			})))
			.mount(server)
			.await;
	}

	async fn mount_block_mock(server: &MockServer, block_number: u64, block: serde_json::Value) {
		Mock::given(method("POST"))
			.and(body_string_contains("\"method\":\"eth_getBlockByNumber\""))
			.and(body_string_contains(format!("0x{block_number:x}")))
			.respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
				"jsonrpc": "2.0",
				"id": 1,
				"result": block,
			})))
			.mount(server)
			.await;
	}

	#[test]
	fn hyperlane_payload_hash_includes_output_context() {
		let order_id: [u8; 32] = [0x42; 32];
		let solver = [0x77u8; 32];
		let timestamp = 1_700_000_000u32;
		let amount = alloy_primitives::U256::from(1000u64);

		let mut settler = [0u8; 32];
		settler[12..32].copy_from_slice(&[0xAA; 20]);
		let mut token = [0u8; 32];
		token[12..32].copy_from_slice(&[0xBB; 20]);
		let mut recipient = [0u8; 32];
		recipient[12..32].copy_from_slice(&[0xCC; 20]);

		let mut output = make_mandate_output([0x11; 32], settler, 137, token, amount, recipient);
		output.context = vec![0x00];
		let order = build_test_order_for_emitter_tests(order_id, 1, 137, output.clone());

		let verified_fill = VerifiedFill {
			solver_identifier: solver,
			timestamp,
			output: output.clone(),
		};
		let expected_payload = encode_fill_description(&verified_fill, order_id).unwrap();
		let expected_hash = verified_payload_hash(&verified_fill, order_id).unwrap();
		let omitted_context_fill = VerifiedFill {
			output: make_mandate_output([0x11; 32], settler, 137, token, amount, recipient),
			..verified_fill.clone()
		};
		let omitted_context_hash = verified_payload_hash(&omitted_context_fill, order_id).unwrap();

		let log_data = encode_output_filled_data(order_id, solver, timestamp, &output, amount);
		let log = solver_types::Log {
			address: solver_types::Address(vec![0xAA; 20]),
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
		let extracted_fill =
			extract_verified_fill_from_logs(&[log], &order, order_id, 137).unwrap();
		let actual_payload = encode_fill_description(&extracted_fill, order_id).unwrap();
		let actual_hash = verified_payload_hash(&extracted_fill, order_id).unwrap();

		assert_eq!(actual_payload, expected_payload);
		assert_ne!(
			expected_hash, omitted_context_hash,
			"test setup must make non-empty context change the payload hash"
		);

		assert_eq!(
			actual_hash, expected_hash,
			"Hyperlane payload hash must include non-empty MandateOutput context; actual matches the empty-context hash"
		);
	}

	#[test]
	fn test_validate_bound_input_oracle_success() {
		let input_oracle = solver_types::Address(vec![0x33; 20]);
		let order = OrderBuilder::new()
			.with_data(make_eip7683_order_data_for_binding(
				&input_oracle,
				vec![make_output_for_binding(137, [0u8; 32])],
			))
			.build();
		let oracle_config = OracleConfig {
			input_oracles: HashMap::from([(1u64, vec![input_oracle.clone()])]),
			output_oracles: HashMap::new(),
			routes: HashMap::new(),
			selection_strategy: OracleSelectionStrategy::First,
		};
		let settlement = test_hyperlane_settlement(oracle_config);

		assert_eq!(
			settlement.validate_bound_input_oracle(&order, 1).unwrap(),
			input_oracle
		);
	}

	#[test]
	fn test_validate_bound_input_oracle_rejects_unsupported() {
		let signed_oracle = solver_types::Address(vec![0x33; 20]);
		let configured_oracle = solver_types::Address(vec![0x44; 20]);
		let order = OrderBuilder::new()
			.with_data(make_eip7683_order_data_for_binding(
				&signed_oracle,
				vec![make_output_for_binding(137, [0u8; 32])],
			))
			.build();
		let oracle_config = OracleConfig {
			input_oracles: HashMap::from([(1u64, vec![configured_oracle])]),
			output_oracles: HashMap::new(),
			routes: HashMap::new(),
			selection_strategy: OracleSelectionStrategy::First,
		};
		let settlement = test_hyperlane_settlement(oracle_config);

		let err = settlement
			.validate_bound_input_oracle(&order, 1)
			.unwrap_err();
		assert!(
			err.to_string()
				.contains("not configured for source chain 1"),
			"unexpected error: {err}"
		);
	}

	#[test]
	fn test_validate_bound_output_oracle_success() {
		let input_oracle = solver_types::Address(vec![0x33; 20]);
		let output_oracle = solver_types::Address(vec![0x44; 20]);
		let order = OrderBuilder::new()
			.with_data(make_eip7683_order_data_for_binding(
				&input_oracle,
				vec![make_output_for_binding(
					137,
					address_to_bytes32(&output_oracle),
				)],
			))
			.build();
		let oracle_config = OracleConfig {
			input_oracles: HashMap::new(),
			output_oracles: HashMap::from([(137u64, vec![output_oracle.clone()])]),
			routes: HashMap::new(),
			selection_strategy: OracleSelectionStrategy::First,
		};
		let settlement = test_hyperlane_settlement(oracle_config);

		assert_eq!(
			settlement
				.validate_bound_output_oracle(&order, 137)
				.unwrap(),
			output_oracle
		);
	}

	#[test]
	fn test_validate_bound_output_oracle_rejects_unsupported() {
		let input_oracle = solver_types::Address(vec![0x33; 20]);
		let signed_output_oracle = solver_types::Address(vec![0x44; 20]);
		let configured_output_oracle = solver_types::Address(vec![0x55; 20]);
		let order = OrderBuilder::new()
			.with_data(make_eip7683_order_data_for_binding(
				&input_oracle,
				vec![make_output_for_binding(
					137,
					address_to_bytes32(&signed_output_oracle),
				)],
			))
			.build();
		let oracle_config = OracleConfig {
			input_oracles: HashMap::new(),
			output_oracles: HashMap::from([(137u64, vec![configured_output_oracle])]),
			routes: HashMap::new(),
			selection_strategy: OracleSelectionStrategy::First,
		};
		let settlement = test_hyperlane_settlement(oracle_config);

		let err = settlement
			.validate_bound_output_oracle(&order, 137)
			.unwrap_err();
		assert!(
			err.to_string()
				.contains("not configured for destination chain 137"),
			"unexpected error: {err}"
		);
	}

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

		let result = extract_verified_fill_from_logs(&[forged_log], &order, order_id, 137);
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

		let result = extract_verified_fill_from_logs(&[log], &order, order_id, 137);
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

		let fill = extract_verified_fill_from_logs(&[log], &order, order_id, 137)
			.expect("matching log should be accepted");
		assert_eq!(fill.solver_identifier, expected_solver);
		assert_eq!(fill.timestamp, expected_timestamp);
		assert_eq!(fill.output.amount, output.amount);
	}

	// ── can_claim route-awareness helpers ─────────────────────────────────────

	/// Build a settlement with oracles configured for both origin and dest chains
	/// so that `post_fill_required` returns true.
	fn test_hyperlane_settlement_with_oracles(origin: u64, dest: u64) -> HyperlaneSettlement {
		let oracle_config = OracleConfig {
			input_oracles: HashMap::from([(origin, vec![solver_types::Address(vec![0x11; 20])])]),
			output_oracles: HashMap::from([(dest, vec![solver_types::Address(vec![0x22; 20])])]),
			routes: HashMap::new(),
			selection_strategy: OracleSelectionStrategy::First,
		};
		test_hyperlane_settlement(oracle_config)
	}

	/// Build a settlement with NO oracles configured so that `post_fill_required`
	/// returns false (PostFill is skipped for every route).
	fn test_hyperlane_settlement_no_oracles() -> HyperlaneSettlement {
		let oracle_config = OracleConfig {
			input_oracles: HashMap::new(),
			output_oracles: HashMap::new(),
			routes: HashMap::new(),
			selection_strategy: OracleSelectionStrategy::First,
		};
		test_hyperlane_settlement(oracle_config)
	}

	/// Minimal order with `input_chains` on `origin` and `output_chains` on `dest`.
	fn test_order_with_chains(origin: u64, dest: u64) -> solver_types::Order {
		solver_types::Order {
			id: "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".to_string(),
			standard: "eip7683".to_string(),
			created_at: 0,
			updated_at: 0,
			status: solver_types::OrderStatus::Pending,
			data: serde_json::Value::Null,
			solver_address: solver_types::Address(vec![0x99; 20]),
			quote_id: None,
			input_chains: vec![solver_types::order::ChainSettlerInfo {
				chain_id: origin,
				settler_address: solver_types::Address(vec![0xCC; 20]),
			}],
			output_chains: vec![solver_types::order::ChainSettlerInfo {
				chain_id: dest,
				settler_address: solver_types::Address(vec![0xDD; 20]),
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

	/// Minimal FillProof skeleton with no attestation data.
	fn fill_proof_skeleton() -> FillProof {
		FillProof {
			tx_hash: solver_types::TransactionHash(vec![0u8; 32]),
			block_number: 0,
			attestation_data: None,
			filled_timestamp: 0,
			oracle_address: "0x0000000000000000000000000000000000000000".to_string(),
		}
	}

	#[tokio::test]
	async fn can_claim_returns_false_when_message_id_missing_and_post_fill_required() {
		let settlement = test_hyperlane_settlement_with_oracles(1, 137);
		let order = test_order_with_chains(1, 137);
		let fill_proof = FillProof {
			attestation_data: None,
			..fill_proof_skeleton()
		};
		let ready = settlement.can_claim(&order, &fill_proof).await;
		assert!(
			!ready,
			"can_claim must return false when PostFill is required and message_id is missing"
		);
	}

	#[tokio::test]
	async fn can_claim_returns_true_when_message_id_missing_but_post_fill_skipped() {
		let settlement = test_hyperlane_settlement_no_oracles();
		let order = test_order_with_chains(1, 137);
		let fill_proof = FillProof {
			attestation_data: None,
			..fill_proof_skeleton()
		};
		let ready = settlement.can_claim(&order, &fill_proof).await;
		assert!(
			ready,
			"can_claim must return true when PostFill is not required and message_id is missing"
		);
	}

	#[tokio::test]
	async fn hyperlane_quotes_post_fill_fee_using_real_message_gas_limit() {
		let server = MockServer::start().await;
		let quoted_fee = U256::from(1_000_000_000_000_000_000u128);
		Mock::given(method("POST"))
			.respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
				"jsonrpc": "2.0",
				"id": 1,
				"result": format!("0x{}", hex::encode(quoted_fee.to_be_bytes::<32>()))
			})))
			.mount(&server)
			.await;

		let origin_chain = 1u64;
		let origin_domain = 10u32;
		let dest_chain = 2u64;
		let dest_domain = 20u32;
		let input_oracle = solver_types::Address(vec![0x33; 20]);
		let output_oracle = solver_types::Address(vec![0x44; 20]);
		let provider = ProviderBuilder::new()
			.connect_http(server.uri().parse().expect("valid RPC URL"))
			.erased();
		let settlement = test_hyperlane_settlement_with_providers(
			OracleConfig {
				input_oracles: HashMap::from([(origin_chain, vec![input_oracle.clone()])]),
				output_oracles: HashMap::from([(dest_chain, vec![output_oracle])]),
				routes: HashMap::from([(origin_chain, vec![dest_chain])]),
				selection_strategy: OracleSelectionStrategy::First,
			},
			HashMap::from([(dest_chain, provider)]),
			HashMap::from([(origin_chain, origin_domain), (dest_chain, dest_domain)]),
		);
		let params = PostFillFeeParams {
			origin_chain_id: origin_chain,
			dest_chain_id: dest_chain,
			output_token: [0x11; 32],
			output_amount: U256::from(1000u64),
			output_recipient: [0x22; 32],
			output_call: vec![0xab, 0xcd],
			source_settler: solver_types::Address(vec![0x55; 20]),
		};
		let expected_payload = encode_quote_fill_description(
			[0u8; 32],
			[0u8; 32],
			0,
			params.output_token,
			params.output_amount,
			params.output_recipient,
			params.output_call.clone(),
			vec![],
		)
		.unwrap();
		let expected_gas_limit = settlement.calculate_message_gas_limit(expected_payload.len());

		let quote = settlement
			.quote_post_fill_fee(&params)
			.await
			.unwrap()
			.expect("hyperlane route has a fee");
		assert_eq!(quote.fee_wei, quoted_fee);
		assert_eq!(quote.chain_id, dest_chain);

		let requests = server.received_requests().await.unwrap();
		assert_eq!(requests.len(), 1);
		let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
		let input_hex = body["params"][0]["input"].as_str().unwrap();
		let input = hex::decode(input_hex.trim_start_matches("0x")).unwrap();
		let decoded = IHyperlaneOracle::quoteGasPayment_0Call::abi_decode(&input).unwrap();
		assert_eq!(decoded.destinationDomain, origin_domain);
		assert_eq!(
			decoded.recipientOracle,
			alloy_primitives::Address::from_slice(&input_oracle.0)
		);
		assert_eq!(decoded.gasLimit, expected_gas_limit);
		assert_eq!(
			decoded.source,
			alloy_primitives::Address::from_slice(&params.source_settler.0)
		);
		assert_eq!(decoded.payloads.len(), 1);
		assert_eq!(decoded.payloads[0].as_ref(), expected_payload.as_slice());
	}

	#[tokio::test]
	async fn hyperlane_recover_post_fill_state_rebuilds_tracker_from_post_fill_receipt() {
		let server = MockServer::start().await;
		let origin_chain = 1u64;
		let dest_chain = 2u64;
		let fill_tx_hash = TransactionHash(vec![0xfa; 32]);
		let post_fill_tx_hash = TransactionHash(vec![0xfb; 32]);
		let order_id = [0x42; 32];
		let (order, output, output_settler) = make_hyperlane_recovery_order(
			order_id,
			origin_chain,
			dest_chain,
			fill_tx_hash.clone(),
			post_fill_tx_hash.clone(),
		);
		let expected_message_id = [0x66; 32];
		let fill_log =
			make_output_filled_log(&output_settler, order_id, [0x77; 32], 123u32, &output);
		let post_fill_log = make_dispatch_id_log(expected_message_id);
		mount_receipt_mock(
			&server,
			&fill_tx_hash,
			make_receipt_json(&fill_tx_hash, 7, true, &[fill_log]),
		)
		.await;
		mount_receipt_mock(
			&server,
			&post_fill_tx_hash,
			make_receipt_json(&post_fill_tx_hash, 8, true, &[post_fill_log]),
		)
		.await;

		let provider = ProviderBuilder::new()
			.connect_http(server.uri().parse().expect("valid RPC URL"))
			.erased();
		let domains = HashMap::from([
			(origin_chain, origin_chain as u32),
			(dest_chain, dest_chain as u32),
		]);
		let settlement = test_hyperlane_settlement_with_providers(
			OracleConfig {
				input_oracles: HashMap::from([(
					origin_chain,
					vec![solver_types::Address(vec![0x33; 20])],
				)]),
				output_oracles: HashMap::from([(
					dest_chain,
					vec![solver_types::Address(vec![0x44; 20])],
				)]),
				routes: HashMap::from([(origin_chain, vec![dest_chain])]),
				selection_strategy: OracleSelectionStrategy::First,
			},
			HashMap::from([(dest_chain, provider)]),
			domains,
		);

		assert!(settlement.recover_post_fill_state(&order).await.unwrap());
		assert_eq!(
			settlement.message_tracker.get_message_id(&order.id).await,
			Some(expected_message_id)
		);
	}

	#[tokio::test]
	async fn hyperlane_recover_post_fill_state_maps_rpc_transport_error_to_backend_unavailable() {
		let server = MockServer::start().await;
		let origin_chain = 1u64;
		let dest_chain = 2u64;
		let fill_tx_hash = TransactionHash(vec![0xfa; 32]);
		let post_fill_tx_hash = TransactionHash(vec![0xfb; 32]);
		let order_id = [0x42; 32];
		let (order, _output, _output_settler) = make_hyperlane_recovery_order(
			order_id,
			origin_chain,
			dest_chain,
			fill_tx_hash.clone(),
			post_fill_tx_hash.clone(),
		);

		// The destination RPC is unreachable/erroring: every eth_getTransactionReceipt
		// returns HTTP 500, which alloy surfaces as a transport error. This must be
		// classified as a retryable backend failure, not a terminal validation error.
		Mock::given(method("POST"))
			.respond_with(ResponseTemplate::new(500))
			.mount(&server)
			.await;

		let provider = ProviderBuilder::new()
			.connect_http(server.uri().parse().expect("valid RPC URL"))
			.erased();
		let domains = HashMap::from([
			(origin_chain, origin_chain as u32),
			(dest_chain, dest_chain as u32),
		]);
		let settlement = test_hyperlane_settlement_with_providers(
			OracleConfig {
				input_oracles: HashMap::from([(
					origin_chain,
					vec![solver_types::Address(vec![0x33; 20])],
				)]),
				output_oracles: HashMap::from([(
					dest_chain,
					vec![solver_types::Address(vec![0x44; 20])],
				)]),
				routes: HashMap::from([(origin_chain, vec![dest_chain])]),
				selection_strategy: OracleSelectionStrategy::First,
			},
			HashMap::from([(dest_chain, provider)]),
			domains,
		);

		let err = settlement
			.recover_post_fill_state(&order)
			.await
			.expect_err("RPC transport failure must surface as an error");
		assert!(
			matches!(err, SettlementError::BackendUnavailable(_)),
			"expected BackendUnavailable, got {err:?}"
		);
	}

	#[tokio::test]
	async fn hyperlane_get_attestation_recovers_missing_message_tracker() {
		let server = MockServer::start().await;
		let origin_chain = 1u64;
		let dest_chain = 2u64;
		let fill_tx_hash = TransactionHash(vec![0xfa; 32]);
		let post_fill_tx_hash = TransactionHash(vec![0xfb; 32]);
		let order_id = [0x43; 32];
		let (order, output, output_settler) = make_hyperlane_recovery_order(
			order_id,
			origin_chain,
			dest_chain,
			fill_tx_hash.clone(),
			post_fill_tx_hash.clone(),
		);
		let expected_message_id = [0x67; 32];
		let fill_log =
			make_output_filled_log(&output_settler, order_id, [0x78; 32], 124u32, &output);
		let post_fill_log = make_dispatch_id_log(expected_message_id);
		mount_receipt_mock(
			&server,
			&fill_tx_hash,
			make_receipt_json(&fill_tx_hash, 7, true, &[fill_log]),
		)
		.await;
		mount_receipt_mock(
			&server,
			&post_fill_tx_hash,
			make_receipt_json(&post_fill_tx_hash, 8, true, &[post_fill_log]),
		)
		.await;
		mount_block_mock(&server, 7, make_block_json(7, 1_700_000_000)).await;

		let provider = ProviderBuilder::new()
			.connect_http(server.uri().parse().expect("valid RPC URL"))
			.erased();
		let domains = HashMap::from([
			(origin_chain, origin_chain as u32),
			(dest_chain, dest_chain as u32),
		]);
		let settlement = test_hyperlane_settlement_with_providers(
			OracleConfig {
				input_oracles: HashMap::from([(
					origin_chain,
					vec![solver_types::Address(vec![0x33; 20])],
				)]),
				output_oracles: HashMap::from([(
					dest_chain,
					vec![solver_types::Address(vec![0x44; 20])],
				)]),
				routes: HashMap::from([(origin_chain, vec![dest_chain])]),
				selection_strategy: OracleSelectionStrategy::First,
			},
			HashMap::from([(dest_chain, provider)]),
			domains,
		);

		let proof = settlement
			.get_attestation(&order, &fill_tx_hash)
			.await
			.unwrap();

		assert_eq!(
			proof.attestation_data,
			Some(hex::encode(expected_message_id).into_bytes())
		);
		assert_eq!(
			settlement.message_tracker.get_message_id(&order.id).await,
			Some(expected_message_id)
		);
	}

	#[tokio::test]
	async fn hyperlane_post_fill_callback_is_noop_when_tracker_already_populated() {
		let origin_chain = 1u64;
		let dest_chain = 2u64;
		let order = test_order_with_chains(origin_chain, dest_chain);
		let expected_message_id = [0x68; 32];
		let settlement = test_hyperlane_settlement_with_providers(
			OracleConfig {
				input_oracles: HashMap::new(),
				output_oracles: HashMap::new(),
				routes: HashMap::new(),
				selection_strategy: OracleSelectionStrategy::First,
			},
			HashMap::new(),
			HashMap::new(),
		);
		settlement
			.message_tracker
			.track_submission(
				order.id.clone(),
				expected_message_id,
				dest_chain,
				origin_chain,
				TransactionHash(vec![0xfb; 32]),
				U256::ZERO,
				[0x55; 32],
				[0x77; 32],
				123u32,
			)
			.await
			.unwrap();
		let receipt = TransactionReceipt {
			hash: TransactionHash(vec![0xfb; 32]),
			block_number: 8,
			success: true,
			logs: vec![make_dispatch_id_log([0x99; 32])],
			block_timestamp: None,
		};

		settlement
			.handle_transaction_confirmed(&order, TransactionType::PostFill, &receipt)
			.await
			.unwrap();

		assert_eq!(
			settlement.message_tracker.get_message_id(&order.id).await,
			Some(expected_message_id)
		);
	}

	#[tokio::test]
	async fn track_submission_preserves_transient_storage_error() {
		use solver_storage::{MockStorageInterface, StorageError};

		// A storage backend that fails every read with a transient backend fault
		// (the shape produced by a momentary Redis outage).
		let mut backend = MockStorageInterface::new();
		backend.expect_get_bytes().returning(|_| {
			Box::pin(async { Err(StorageError::Backend("simulated redis outage".to_string())) })
		});
		let storage = Arc::new(StorageService::new(Box::new(backend)));
		let tracker = MessageTracker::new(storage);

		let err = tracker
			.track_submission(
				"order-transient".to_string(),
				[0u8; 32], // message_id
				1,         // origin_chain
				2,         // destination_chain
				TransactionHash(vec![0u8; 32]),
				U256::ZERO, // gas_payment
				[0u8; 32],  // payload_hash
				[0u8; 32],  // solver_identifier
				0,          // fill_timestamp
			)
			.await
			.expect_err("a transient storage fault must surface as an error");

		assert!(
			matches!(err, SettlementError::StorageUnavailable(_)),
			"transient storage fault must stay retryable (StorageUnavailable), got: {err:?}"
		);
	}

	#[tokio::test]
	async fn check_delivery_preserves_transient_storage_error() {
		use solver_storage::{MockStorageInterface, StorageError};

		// HyperlaneSettlement whose message tracker fails every read with a
		// transient backend fault (the shape of a momentary Redis outage).
		let mut backend = MockStorageInterface::new();
		backend.expect_get_bytes().returning(|_| {
			Box::pin(async { Err(StorageError::Backend("simulated redis outage".to_string())) })
		});
		let settlement = HyperlaneSettlement {
			providers: HashMap::new(),
			oracle_config: OracleConfig {
				input_oracles: HashMap::new(),
				output_oracles: HashMap::new(),
				routes: HashMap::new(),
				selection_strategy: OracleSelectionStrategy::First,
			},
			mailbox_addresses: HashMap::new(),
			igp_addresses: HashMap::new(),
			domains: HashMap::new(),
			message_tracker: Arc::new(MessageTracker::new(Arc::new(StorageService::new(
				Box::new(backend),
			)))),
			default_gas_limit: 500_000,
		};
		let order = test_order_with_chains(1, 137);

		let err = settlement
			.check_delivery(&order, [0u8; 32])
			.await
			.expect_err("a transient storage fault must surface as an error");

		assert!(
			matches!(err, SettlementError::StorageUnavailable(_)),
			"check_delivery must stay retryable (StorageUnavailable), got: {err:?}"
		);
	}

	#[tokio::test]
	async fn can_claim_returns_false_when_attestation_invalid_hex_and_post_fill_required() {
		let settlement = test_hyperlane_settlement_with_oracles(1, 137);
		let order = test_order_with_chains(1, 137);
		let fill_proof = FillProof {
			attestation_data: Some("zz".repeat(32).into_bytes()), // 64 bytes, not valid hex
			..fill_proof_skeleton()
		};
		let ready = settlement.can_claim(&order, &fill_proof).await;
		assert!(
			!ready,
			"invalid hex must defer claim when PostFill required"
		);
	}

	#[tokio::test]
	async fn can_claim_returns_false_when_attestation_wrong_length_and_post_fill_required() {
		let settlement = test_hyperlane_settlement_with_oracles(1, 137);
		let order = test_order_with_chains(1, 137);
		let fill_proof = FillProof {
			attestation_data: Some("aa".repeat(16).into_bytes()), // 32 bytes, not 64
			..fill_proof_skeleton()
		};
		let ready = settlement.can_claim(&order, &fill_proof).await;
		assert!(
			!ready,
			"wrong-length attestation must defer claim when PostFill required"
		);
	}

	#[test]
	fn test_extract_fill_details_rejects_diverged_final_amount() {
		// Mirror of broadcaster.rs::test_extract_fill_details_rejects_diverged_final_amount.
		// An OutputFilled log emitted by the expected settler, whose MandateOutput
		// matches the order in every field, but whose `finalAmount` differs from
		// `MandateOutput.amount`. Today no shipped settler emits divergent values,
		// but a future partial-fill / fee-deducting settler could; if so, the
		// solver must NOT silently build an on-chain attestation payload from the
		// order-requested amount while the chain settled a different amount.
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

		// MandateOutput.amount = 1000, but finalAmount = 999 (e.g. fee deducted).
		let log_data = encode_output_filled_data(
			order_id,
			[0x77; 32],
			1_700_000_000u32,
			&output,
			alloy_primitives::U256::from(999u64),
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

		let result = extract_verified_fill_from_logs(&[log], &order, order_id, 137);
		assert!(
			result.is_err(),
			"log with finalAmount != MandateOutput.amount must be rejected",
		);
	}
}
