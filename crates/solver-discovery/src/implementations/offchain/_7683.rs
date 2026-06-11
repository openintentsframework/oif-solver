//! ERC-7683 Off-chain Intent Discovery Implementation
//!
//! This module accepts ERC-7683 cross-chain intents in-process via `submit_order`,
//! which is called by solver-service's `POST /api/v1/orders` handler AFTER it runs
//! full intake validation (sponsor signature, allocator authorization, capacity).
//! There is no separately bindable HTTP server or port; off-chain intake shares the
//! solver's public API surface.
//!
//! ## Overview
//!
//! `submit_order`:
//! - Parses an already-validated EIP-7683 order into a `StandardOrder`
//! - Computes the order ID by calling the settler contract
//! - Converts the order to the internal Intent format
//! - Enqueues the intent to the solver engine via the monitoring channel
//!
//! ## Trust boundary
//!
//! `submit_order` does NOT re-validate signatures, allocator authorization, or
//! balances — callers must validate first (see the `DiscoveryInterface::submit_order`
//! doc). The only sanctioned caller is `POST /api/v1/orders`.
//!
//! ## Configuration
//!
//! - `network_ids` - List of chain IDs this discovery source supports
//! - RPC URLs are resolved from the global networks configuration
//!
//! ## Order Flow
//!
//! 1. solver-service validates the order and calls `submit_order` in-process
//! 2. Order ID is computed by calling the settler contract
//! 3. Order data is parsed to extract inputs/outputs
//! 4. The order is converted to an Intent and enqueued to the solver engine

use crate::{DiscoveryError, DiscoveryInterface, IntentSubmission, IntentSubmissionError};
use alloy_primitives::{Address as AlloyAddress, Bytes, U256};
use alloy_provider::DynProvider;
use alloy_sol_types::SolType;
use async_trait::async_trait;
use hex;
use serde::{Deserialize, Serialize};
use serde_json;
use solver_types::{
	account::Address,
	api::PostOrderRequest,
	bytes32_to_address, create_http_provider, current_timestamp, normalize_bytes32_address,
	standards::eip7683::{
		interfaces::{IInputSettlerCompact, IInputSettlerEscrow, SolMandateOutput, StandardOrder},
		GasLimitOverrides, LockType, MandateOutput,
	},
	with_0x_prefix, ConfigSchema, Eip7683OrderData, Field, FieldType, ImplementationRegistry,
	Intent, IntentMetadata, NetworksConfig, ProviderError, Schema,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

/// API representation of StandardOrder for JSON deserialization.
///
/// This struct represents the order format for the OIF contracts.
/// The order is sent as encoded bytes along with sponsor and signature.
///
/// # Fields
///
/// * `user` - Address of the user creating the order
/// * `nonce` - Unique nonce to prevent replay attacks
/// * `origin_chain_id` - Chain ID where the order originates
/// * `expires` - Unix timestamp when the order expires
/// * `fill_deadline` - Unix timestamp by which the order must be filled
/// * `input_oracle` - Address of the oracle responsible for validating fills
/// * `inputs` - Array of [token, amount] pairs as U256
/// * `outputs` - Array of MandateOutput structs
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiStandardOrder {
	user: AlloyAddress,
	nonce: U256,
	origin_chain_id: U256,
	expires: u32,
	fill_deadline: u32,
	input_oracle: AlloyAddress,
	inputs: Vec<[U256; 2]>,
	outputs: Vec<ApiMandateOutput>,
}

/// API representation of MandateOutput
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiMandateOutput {
	#[serde(
		deserialize_with = "deserialize_bytes32",
		serialize_with = "serialize_bytes32"
	)]
	oracle: [u8; 32],
	#[serde(
		deserialize_with = "deserialize_bytes32",
		serialize_with = "serialize_bytes32"
	)]
	settler: [u8; 32],
	chain_id: U256,
	#[serde(
		deserialize_with = "deserialize_bytes32",
		serialize_with = "serialize_bytes32"
	)]
	token: [u8; 32],
	amount: U256,
	#[serde(
		deserialize_with = "deserialize_bytes32",
		serialize_with = "serialize_bytes32"
	)]
	recipient: [u8; 32],
	#[serde(rename = "callbackData")]
	call: Bytes,
	context: Bytes,
}

/// Custom serializer for bytes32 to hex strings
/// Converts to address format (20 bytes) when it's an address, otherwise full bytes32
fn serialize_bytes32<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
where
	S: serde::Serializer,
{
	// Use the bytes32_to_address helper which extracts last 20 bytes
	// and returns them as a hex string without 0x prefix
	let address = bytes32_to_address(bytes);
	serializer.serialize_str(&with_0x_prefix(&address))
}

impl From<&SolMandateOutput> for ApiMandateOutput {
	fn from(output: &SolMandateOutput) -> Self {
		Self {
			oracle: output.oracle.0,
			settler: output.settler.0,
			chain_id: output.chainId,
			token: output.token.0,
			amount: output.amount,
			recipient: output.recipient.0,
			call: output.callbackData.clone(),
			context: output.context.clone(),
		}
	}
}

impl From<&StandardOrder> for ApiStandardOrder {
	fn from(order: &StandardOrder) -> Self {
		Self {
			user: order.user,
			nonce: order.nonce,
			origin_chain_id: order.originChainId,
			expires: order.expires,
			fill_deadline: order.fillDeadline,
			input_oracle: order.inputOracle,
			inputs: order.inputs.clone(),
			outputs: order.outputs.iter().map(ApiMandateOutput::from).collect(),
		}
	}
}

/// Custom deserializer for bytes32 that accepts hex strings.
///
/// Converts hex strings (with or without "0x" prefix) to fixed 32-byte arrays.
/// Used for deserializing order_data_type and other bytes32 fields from JSON.
///
/// # Errors
///
/// Returns an error if:
/// - The hex string is not exactly 64 characters (32 bytes)
/// - The string contains invalid hex characters
fn deserialize_bytes32<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
	D: serde::Deserializer<'de>,
{
	use serde::de::Error;

	let s = String::deserialize(deserializer)?;
	let s = s.strip_prefix("0x").unwrap_or(&s);

	if s.len() != 64 {
		return Err(Error::custom(format!(
			"Invalid bytes32: expected 64 hex chars, got {}",
			s.len()
		)));
	}

	let mut bytes = [0u8; 32];
	hex::decode_to_slice(s, &mut bytes).map_err(|e| Error::custom(format!("Invalid hex: {e}")))?;

	Ok(bytes)
}

/// EIP-7683 offchain discovery implementation.
///
/// This struct implements the `DiscoveryInterface` trait to provide off-chain
/// intent discovery. Orders are submitted in-process via `submit_order` (called
/// by solver-service's `/api/v1/orders` after validation) and converted to the
/// internal Intent format for processing by the solver system.
#[derive(Debug)]
pub struct Eip7683OffchainDiscovery {
	/// RPC providers for each supported network
	providers: HashMap<u64, DynProvider>,
	/// Networks configuration for settler lookups
	networks: NetworksConfig,
	/// Flag indicating if the implementation is active
	is_running: Arc<AtomicBool>,
	/// In-process intent submission channel, set while monitoring is active.
	intent_sender: Arc<Mutex<Option<mpsc::Sender<Intent>>>>,
}

impl Eip7683OffchainDiscovery {
	/// Creates a new EIP-7683 offchain discovery instance.
	///
	/// # Arguments
	///
	/// * `network_ids` - List of network IDs this discovery source supports
	/// * `networks` - Networks configuration with RPC URLs
	///
	/// # Returns
	///
	/// Returns a new discovery instance or an error if any RPC URL is invalid.
	///
	/// # Errors
	///
	/// Returns `DiscoveryError::Connection` if any RPC URL cannot be parsed.
	/// Returns `DiscoveryError::ValidationError` if networks config is invalid.
	pub fn new(network_ids: Vec<u64>, networks: &NetworksConfig) -> Result<Self, DiscoveryError> {
		// Validate networks config has at least one network
		if networks.is_empty() {
			return Err(DiscoveryError::ValidationError(
				"Networks configuration cannot be empty".to_string(),
			));
		}

		// Create RPC providers for each supported network
		let mut providers = HashMap::new();
		for network_id in &network_ids {
			match create_http_provider(*network_id, networks) {
				Ok(provider) => {
					providers.insert(*network_id, provider);
				},
				Err(e) => match e {
					ProviderError::NetworkConfig(_) => {
						tracing::warn!(
							"Network {} in supported_networks not found in networks config",
							network_id
						);
					},
					ProviderError::Connection(msg) => {
						return Err(DiscoveryError::Connection(msg));
					},
					ProviderError::InvalidUrl(msg) => {
						return Err(DiscoveryError::Connection(msg));
					},
				},
			}
		}

		if providers.is_empty() {
			return Err(DiscoveryError::ValidationError(
				"No valid RPC providers could be created for supported networks".to_string(),
			));
		}

		Ok(Self {
			providers,
			networks: networks.clone(),
			is_running: Arc::new(AtomicBool::new(false)),
			intent_sender: Arc::new(Mutex::new(None)),
		})
	}

	/// Converts StandardOrder to Intent.
	///
	/// Transforms a parsed StandardOrder into the internal Intent format used by
	/// the solver system. This includes:
	/// - Computing the order ID via the settler contract
	/// - Extracting inputs/outputs from the parsed order
	/// - Creating metadata for the intent
	///
	/// # Arguments
	///
	/// * `order` - The parsed StandardOrder to convert
	/// * `order_bytes` - The raw encoded order bytes (needed for order ID computation)
	/// * `sponsor` - The address sponsoring the order
	/// * `signature` - The Permit2Witness signature
	/// * `lock_type` - The custody mechanism type (Permit2Escrow, Eip3009Escrow, or ResourceLock)
	/// * `providers` - RPC providers for each supported network
	/// * `networks` - Networks configuration for settler lookups
	///
	/// # Returns
	///
	/// Returns an Intent ready for processing by the solver system.
	///
	/// # Errors
	///
	/// Returns an error if:
	/// - Order ID computation fails
	/// - No outputs are present in the order
	/// - Network configuration is missing for the origin chain
	async fn order_to_intent(
		order: &StandardOrder,
		sponsor: &Address,
		signature: &Bytes,
		lock_type: LockType,
		providers: &HashMap<u64, DynProvider>,
		networks: &NetworksConfig,
		quote_id: Option<String>,
	) -> Result<Intent, DiscoveryError> {
		// Encode StandardOrder to bytes for order_to_intent
		let order_bytes = Bytes::from(StandardOrder::abi_encode(order));

		// Get the input settler address for the order's origin chain
		let origin_chain_id = order.originChainId.to::<u64>();
		let network = networks.get(&origin_chain_id).ok_or_else(|| {
			DiscoveryError::ValidationError(format!(
				"Chain ID {} not found in networks configuration",
				order.originChainId
			))
		})?;

		if network.input_settler_address.0.len() != 20 {
			return Err(DiscoveryError::ValidationError(
				"Invalid settler address length".to_string(),
			));
		}
		// Choose settler based on lock_type
		let settler_address = match lock_type {
			LockType::ResourceLock => {
				let addr = network
					.input_settler_compact_address
					.clone()
					.ok_or_else(|| {
						DiscoveryError::ValidationError(format!(
							"No input settler compact address found for chain ID {origin_chain_id}"
						))
					})?;
				AlloyAddress::from_slice(&addr.0)
			},
			LockType::Permit2Escrow | LockType::Eip3009Escrow => {
				AlloyAddress::from_slice(&network.input_settler_address.0)
			},
		};

		// Get provider for the origin chain
		let provider = providers.get(&origin_chain_id).ok_or_else(|| {
			DiscoveryError::ValidationError(format!(
				"No RPC provider configured for chain ID {origin_chain_id}"
			))
		})?;

		// Generate order ID from order data
		let order_id =
			Self::compute_order_id(&order_bytes, provider, settler_address, lock_type).await?;

		// Validate that order has outputs
		if order.outputs.is_empty() {
			return Err(DiscoveryError::ValidationError(
				"Order must have at least one output".to_string(),
			));
		}

		// Convert to intent format
		let order_data = Eip7683OrderData {
			user: with_0x_prefix(&hex::encode(order.user)),
			nonce: order.nonce,
			origin_chain_id: order.originChainId,
			expires: order.expires,
			fill_deadline: order.fillDeadline,
			input_oracle: with_0x_prefix(&hex::encode(order.inputOracle)),
			inputs: order.inputs.clone(),
			order_id,
			gas_limit_overrides: GasLimitOverrides::default(),
			outputs: order
				.outputs
				.iter()
				.map(|output| {
					let settler = normalize_bytes32_address(output.settler.0);
					let token = normalize_bytes32_address(output.token.0);
					let recipient = normalize_bytes32_address(output.recipient.0);
					MandateOutput {
						oracle: output.oracle.0,
						settler,
						chain_id: output.chainId,
						token,
						amount: output.amount,
						recipient,
						call: output.callbackData.clone().into(),
						context: output.context.clone().into(),
					}
				})
				.collect(),
			// Include raw order data for openFor
			raw_order_data: Some(with_0x_prefix(&hex::encode(&order_bytes))),
			// Include signature and sponsor
			signature: Some(with_0x_prefix(&hex::encode(signature))),
			sponsor: Some(sponsor.to_string()),
			lock_type: Some(lock_type),
		};

		Ok(Intent {
			id: hex::encode(order_id),
			source: "off-chain".to_string(),
			standard: "eip7683".to_string(),
			metadata: IntentMetadata {
				requires_auction: false,
				exclusive_until: None,
				discovered_at: current_timestamp(),
			},
			data: serde_json::to_value(&order_data).map_err(|e| {
				DiscoveryError::ParseError(format!("Failed to serialize order data: {e}"))
			})?,
			order_bytes,
			quote_id,
			lock_type: lock_type.to_string(),
		})
	}

	/// Computes order ID from order data.
	///
	/// Determines which settler interface to use based on the lock_type and calls
	/// the appropriate `orderIdentifier` function to compute the canonical order ID.
	///
	/// # Lock Types
	///
	/// * 1 = permit2-escrow (uses IInputSettlerEscrow)
	/// * 2 = 3009-escrow (uses IInputSettlerEscrow)
	/// * 3 = resource-lock/TheCompact (uses IInputSettlerCompact)
	/// * Other values default to IInputSettlerEscrow
	///
	/// # Arguments
	///
	/// * `order_bytes` - The encoded order bytes to compute ID for
	/// * `provider` - RPC provider for calling the settler contract
	/// * `settler_address` - Address of the appropriate settler contract
	/// * `lock_type` - The custody/lock type determining which interface to use
	///
	/// # Returns
	///
	/// Returns the 32-byte order ID.
	///
	/// # Errors
	///
	/// Returns `DiscoveryError::Connection` if the contract call fails or
	/// `DiscoveryError::ParseError` if order decoding fails for compact orders.
	async fn compute_order_id(
		order_bytes: &Bytes,
		provider: &DynProvider,
		settler_address: AlloyAddress,
		lock_type: LockType,
	) -> Result<[u8; 32], DiscoveryError> {
		match lock_type {
			LockType::ResourceLock => {
				// Resource Lock (TheCompact) - use IInputSettlerCompact
				let std_order = StandardOrder::abi_decode_validate(order_bytes).map_err(|e| {
					DiscoveryError::ParseError(format!("Failed to decode StandardOrder: {e}"))
				})?;
				let compact = IInputSettlerCompact::new(settler_address, provider);
				let resp = compact
					.orderIdentifier(std_order)
					.call()
					.await
					.map_err(|e| {
						DiscoveryError::Connection(format!(
							"Failed to get order ID from compact contract: {e}"
						))
					})?;
				Ok(resp.0)
			},
			LockType::Permit2Escrow | LockType::Eip3009Escrow => {
				// Escrow types - use IInputSettlerEscrow
				// Decode the order bytes to StandardOrder
				let std_order = StandardOrder::abi_decode_validate(order_bytes).map_err(|e| {
					DiscoveryError::ParseError(format!("Failed to decode StandardOrder: {e}"))
				})?;
				let escrow = IInputSettlerEscrow::new(settler_address, provider);
				let resp = escrow
					.orderIdentifier(std_order)
					.call()
					.await
					.map_err(|e| {
						DiscoveryError::Connection(format!(
							"Failed to get order ID from escrow contract: {e}"
						))
					})?;
				Ok(resp.0)
			},
		}
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnqueueIntentError {
	Full,
	Closed,
}

impl std::fmt::Display for EnqueueIntentError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Full => write!(f, "intent queue is full"),
			Self::Closed => write!(f, "intent queue is closed"),
		}
	}
}

fn enqueue_intent(
	intent_sender: &mpsc::Sender<Intent>,
	intent: Intent,
) -> Result<(), EnqueueIntentError> {
	intent_sender.try_send(intent).map_err(|e| match e {
		mpsc::error::TrySendError::Full(_) => EnqueueIntentError::Full,
		mpsc::error::TrySendError::Closed(_) => EnqueueIntentError::Closed,
	})
}

/// Configuration schema for EIP-7683 off-chain discovery.
///
/// This schema validates the configuration for the off-chain discovery source,
/// ensuring all required fields are present and have valid values.
///
/// # Required Fields
///
/// - `network_ids` - List of network IDs this discovery source monitors
pub struct Eip7683OffchainDiscoverySchema;

impl Eip7683OffchainDiscoverySchema {
	/// Static validation method for use before instance creation
	pub fn validate_config(
		config: &serde_json::Value,
	) -> Result<(), solver_types::ValidationError> {
		let instance = Self;
		instance.validate(config)
	}
}

impl ConfigSchema for Eip7683OffchainDiscoverySchema {
	fn validate(&self, config: &serde_json::Value) -> Result<(), solver_types::ValidationError> {
		let schema = Schema::new(
			// Required fields
			vec![Field::new(
				"network_ids",
				FieldType::Array(Box::new(FieldType::Integer {
					min: Some(1),
					max: None,
				})),
			)],
			vec![],
		);

		schema.validate(config)
	}
}

#[async_trait]
impl DiscoveryInterface for Eip7683OffchainDiscovery {
	fn config_schema(&self) -> Box<dyn ConfigSchema> {
		Box::new(Eip7683OffchainDiscoverySchema)
	}

	async fn start_monitoring(&self, sender: mpsc::Sender<Intent>) -> Result<(), DiscoveryError> {
		if self.is_running.load(Ordering::SeqCst) {
			return Err(DiscoveryError::AlreadyMonitoring);
		}

		// Stash the sender so in-process submit_order can enqueue intents.
		// There is no HTTP server to spawn; off-chain intake is in-process.
		*self.intent_sender.lock().await = Some(sender);

		self.is_running.store(true, Ordering::SeqCst);
		Ok(())
	}

	async fn stop_monitoring(&self) -> Result<(), DiscoveryError> {
		if !self.is_running.load(Ordering::SeqCst) {
			return Ok(());
		}

		*self.intent_sender.lock().await = None;
		self.is_running.store(false, Ordering::SeqCst);
		Ok(())
	}

	async fn submit_order(
		&self,
		request: &PostOrderRequest,
	) -> Result<IntentSubmission, IntentSubmissionError> {
		let order = StandardOrder::try_from(&request.order).map_err(|e| {
			tracing::warn!(error = %e, "Failed to convert OifOrder to StandardOrder");
			IntentSubmissionError::Rejected {
				message: format!("Failed to convert order: {e}"),
				order: None,
			}
		})?;

		// Serialize the parsed order once so every outcome can echo it.
		let order_json = match serde_json::to_value(ApiStandardOrder::from(&order)) {
			Ok(json) => Some(json),
			Err(e) => {
				tracing::warn!(error = %e, "Failed to serialize order");
				None
			},
		};

		let signature = &request.signature;

		let sponsor = request
			.order
			.extract_sponsor(Some(signature))
			.map_err(|e| {
				tracing::warn!(error = %e, "Failed to extract sponsor from order");
				IntentSubmissionError::Rejected {
					message: format!("Failed to extract sponsor: {e}"),
					order: order_json.clone(),
				}
			})?;

		let lock_type = LockType::from(&request.order);

		// NOTE: no allocator-authorization or compact-signature decode here —
		// solver-service's validate_intent_request ran them before this call
		// (see the TRUST BOUNDARY doc on the trait method). compact_allocator.rs
		// is the single allocator-auth implementation.

		let intent = Self::order_to_intent(
			&order,
			&sponsor,
			signature,
			lock_type,
			&self.providers,
			&self.networks,
			request.quote_id.clone(),
		)
		.await
		.map_err(|e| {
			tracing::warn!(error = %e, "Failed to convert order to intent");
			IntentSubmissionError::Rejected {
				message: e.to_string(),
				order: order_json.clone(),
			}
		})?;

		let order_id = intent.id.clone();

		let sender = self.intent_sender.lock().await.clone();
		let sender = sender.ok_or_else(|| IntentSubmissionError::Unavailable {
			message: "Intent submission is not running".to_string(),
			order_id: Some(order_id.clone()),
			order: order_json.clone(),
		})?;

		enqueue_intent(&sender, intent).map_err(|e| {
			tracing::warn!(error = %e, "Failed to send intent to solver channel");
			IntentSubmissionError::Unavailable {
				message: format!("Failed to process intent: {e}"),
				order_id: Some(order_id.clone()),
				order: order_json.clone(),
			}
		})?;

		Ok(IntentSubmission {
			order_id,
			order: order_json,
			message:
				"Basic validation passed, pending profitability validation and oracle route validation"
					.to_string(),
		})
	}
}

/// Factory function to create an EIP-7683 offchain discovery provider.
///
/// This function is called by the discovery module factory system
/// to instantiate a new off-chain discovery service with the provided
/// configuration.
///
/// # Arguments
///
/// * `config` - JSON configuration value containing service parameters
/// * `networks` - Global networks configuration with RPC URLs and settler addresses
///
/// # Returns
///
/// Returns a boxed discovery interface implementation.
///
/// # Configuration
///
/// Expected configuration format:
/// ```json
/// {
///   "network_ids": [1, 10, 137]
/// }
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The networks configuration is invalid
/// - The discovery service cannot be created
pub fn create_discovery(
	config: &serde_json::Value,
	networks: &NetworksConfig,
) -> Result<Box<dyn DiscoveryInterface>, DiscoveryError> {
	// Validate configuration first
	Eip7683OffchainDiscoverySchema::validate_config(config)
		.map_err(|e| DiscoveryError::ValidationError(format!("Invalid configuration: {e}")))?;

	// Get network_ids from config, or default to all networks
	let network_ids = config
		.get("network_ids")
		.and_then(|v| v.as_array())
		.map(|arr| {
			arr.iter()
				.filter_map(|v| v.as_i64().map(|i| i as u64))
				.collect::<Vec<_>>()
		})
		.unwrap_or_else(|| networks.keys().cloned().collect());

	let discovery = Eip7683OffchainDiscovery::new(network_ids, networks).map_err(|e| {
		DiscoveryError::Connection(format!("Failed to create offchain discovery service: {e}"))
	})?;

	Ok(Box::new(discovery))
}

/// Registry for the offchain EIP-7683 discovery implementation.
pub struct Registry;

impl ImplementationRegistry for Registry {
	const NAME: &'static str = "offchain_eip7683";
	type Factory = crate::DiscoveryFactory;

	fn factory() -> Self::Factory {
		create_discovery
	}
}

impl crate::DiscoveryRegistry for Registry {}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::{Address as AlloyAddress, Bytes, U256};
	use alloy_provider::{mock::Asserter, Provider, ProviderBuilder};
	use serde_json::json;
	use solver_types::api::{OifOrder, OrderPayload, PostOrderRequest, SignatureType};
	use solver_types::{
		utils::tests::builders::{NetworkConfigBuilder, NetworksConfigBuilder},
		Intent, IntentMetadata, NetworksConfig,
	};
	use std::collections::HashMap;
	use tokio::sync::mpsc;

	fn create_test_networks_config() -> NetworksConfig {
		NetworksConfigBuilder::new()
			.add_network(1, NetworkConfigBuilder::new().build())
			.build()
	}

	fn create_test_standard_order() -> StandardOrder {
		StandardOrder {
			user: AlloyAddress::from_slice(&[0x12u8; 20]),
			nonce: U256::from(1),
			originChainId: U256::from(1),
			expires: (current_timestamp() + 3600) as u32, // 1 hour from now
			fillDeadline: (current_timestamp() + 1800) as u32, // 30 min from now
			inputOracle: AlloyAddress::from_slice(&[0x34u8; 20]),
			inputs: vec![[U256::from(1000), U256::from(100)]],
			outputs: vec![create_test_mandate_output()],
		}
	}

	fn create_test_mandate_output() -> SolMandateOutput {
		SolMandateOutput {
			oracle: alloy_primitives::FixedBytes::from([0x56u8; 32]),
			settler: alloy_primitives::FixedBytes::from([0x78u8; 32]),
			chainId: U256::from(137),
			token: alloy_primitives::FixedBytes::from([0x9au8; 32]),
			amount: U256::from(500),
			recipient: alloy_primitives::FixedBytes::from([0xbcu8; 32]),
			callbackData: Bytes::new(),
			context: Bytes::new(),
		}
	}

	fn abi_word(value: usize) -> [u8; 32] {
		let mut word = [0u8; 32];
		word[24..32].copy_from_slice(&(value as u64).to_be_bytes());
		word
	}

	fn padded_bytes(bytes: &[u8]) -> Vec<u8> {
		let mut encoded = Vec::new();
		encoded.extend_from_slice(&abi_word(bytes.len()));
		encoded.extend_from_slice(bytes);
		let padding = (32 - (bytes.len() % 32)) % 32;
		encoded.extend(std::iter::repeat_n(0u8, padding));
		encoded
	}

	fn compact_signature(sponsor_sig: &[u8], allocator_data: &[u8]) -> Bytes {
		let sponsor_tail = padded_bytes(sponsor_sig);
		let allocator_offset = 64 + sponsor_tail.len();

		let mut signature = Vec::new();
		signature.extend_from_slice(&abi_word(64));
		signature.extend_from_slice(&abi_word(allocator_offset));
		signature.extend_from_slice(&sponsor_tail);
		signature.extend_from_slice(&padded_bytes(allocator_data));
		Bytes::from(signature)
	}

	fn resource_lock_request(signature: Bytes) -> PostOrderRequest {
		let payload = OrderPayload {
			signature_type: SignatureType::Eip712,
			domain: json!({
				"name": "BatchCompact",
				"version": "1",
				"chainId": "1",
				"verifyingContract": "0x8888888888888888888888888888888888888888",
			}),
			primary_type: "BatchCompact".to_string(),
			message: json!({
				"sponsor": "0x1111111111111111111111111111111111111111",
				"nonce": "1",
				"expires": "1700000600",
				"mandate": {
					"fillDeadline": "1700000000",
					"inputOracle": "0x2222222222222222222222222222222222222222",
					"outputs": [{
						"oracle": "0x6666666666666666666666666666666666666666666666666666666666666666",
						"settler": "0x7777777777777777777777777777777777777777777777777777777777777777",
						"chainId": "137",
						"token": "0x4444444444444444444444444444444444444444444444444444444444444444",
						"amount": "500",
						"recipient": "0x5555555555555555555555555555555555555555555555555555555555555555",
						"callbackData": "0x",
						"context": "0x"
					}]
				},
				"commitments": [{
					"lockTag": "0xaaaaaaaaaaaaaaaaaaaaaaaa",
					"token": "0x3333333333333333333333333333333333333333",
					"amount": "1000"
				}]
			}),
			types: None,
		};

		PostOrderRequest {
			order: OifOrder::OifResourceLockV0 { payload },
			signature,
			quote_id: None,
			origin_submission: None,
		}
	}

	/// Provider that answers the single `orderIdentifier` call `order_to_intent`
	/// makes (returns a bytes32). This is the only on-chain call left in the
	/// lean `submit_order` path now that allocator-auth moved out.
	fn mocked_provider_with_order_id(order_id: [u8; 32]) -> DynProvider {
		let asserter = Asserter::new();
		asserter.push_success(&Bytes::from(order_id.to_vec()));
		ProviderBuilder::new()
			.connect_mocked_client(asserter)
			.erased()
	}

	/// Constructs an `Eip7683OffchainDiscovery` directly (test-only) with the
	/// given providers and optional intent sender.
	fn test_discovery_with_providers(
		providers: HashMap<u64, DynProvider>,
		intent_sender: Option<mpsc::Sender<Intent>>,
	) -> Eip7683OffchainDiscovery {
		Eip7683OffchainDiscovery {
			providers,
			networks: create_test_networks_config(),
			is_running: Arc::new(AtomicBool::new(false)),
			intent_sender: Arc::new(Mutex::new(intent_sender)),
		}
	}

	/// (request, providers) that clear submit_order's lean pipeline, so any
	/// failure after this point is a sender-stage (Unavailable) failure, not
	/// Rejected. Mocks ONLY the orderIdentifier call.
	fn fully_admittable_request_and_providers() -> (PostOrderRequest, HashMap<u64, DynProvider>) {
		let request = resource_lock_request(compact_signature(&[0x11u8; 65], b""));
		let mut providers = HashMap::new();
		providers.insert(1u64, mocked_provider_with_order_id([0xABu8; 32]));
		(request, providers)
	}

	#[tokio::test]
	async fn submit_order_succeeds_and_enqueues_when_pipeline_valid() {
		// Positive control: proves the fixture really clears the pipeline, so
		// the two failure tests below fail at the sender stage and nowhere else.
		let (request, providers) = fully_admittable_request_and_providers();
		let (tx, mut rx) = mpsc::channel(16);
		let discovery = test_discovery_with_providers(providers, Some(tx));

		let submission = discovery
			.submit_order(&request)
			.await
			.expect("should be admitted");

		assert!(!submission.order_id.is_empty());
		let intent = rx.try_recv().expect("intent must be enqueued");
		assert_eq!(intent.id, submission.order_id);
	}

	#[tokio::test]
	async fn submit_order_unavailable_when_monitoring_not_started() {
		let (request, providers) = fully_admittable_request_and_providers();
		let discovery = test_discovery_with_providers(providers, None);

		let result = discovery.submit_order(&request).await;

		match result {
			Err(IntentSubmissionError::Unavailable {
				message, order_id, ..
			}) => {
				assert!(
					message.contains("not running"),
					"unexpected message: {message}"
				);
				assert!(order_id.is_some(), "order id is known by the sender stage");
			},
			other => panic!("expected Unavailable (missing sender), got {other:?}"),
		}
	}

	#[tokio::test]
	async fn submit_order_unavailable_when_queue_full() {
		let (request, providers) = fully_admittable_request_and_providers();
		// Capacity-1 channel, pre-filled: enqueue_intent must hit TrySendError::Full.
		let (tx, _rx) = mpsc::channel(1);
		tx.try_send(Intent {
			id: "already-queued".to_string(),
			source: "test".to_string(),
			standard: "eip7683".to_string(),
			metadata: IntentMetadata {
				requires_auction: false,
				exclusive_until: None,
				discovered_at: current_timestamp(),
			},
			data: json!({}),
			order_bytes: Bytes::new(),
			quote_id: None,
			lock_type: "permit2_escrow".to_string(),
		})
		.expect("first intent should fill queue");
		let discovery = test_discovery_with_providers(providers, Some(tx));

		let result = discovery.submit_order(&request).await;

		match result {
			Err(IntentSubmissionError::Unavailable { message, .. }) => {
				assert!(
					message.contains("Failed to process intent"),
					"unexpected message: {message}"
				);
			},
			other => panic!("expected Unavailable (queue full), got {other:?}"),
		}
	}

	#[test]
	fn test_new_discovery_service() {
		let networks = create_test_networks_config();
		let network_ids = vec![1];

		let discovery = Eip7683OffchainDiscovery::new(network_ids, &networks);

		assert!(discovery.is_ok());
	}

	#[test]
	fn test_new_discovery_service_invalid_networks() {
		let networks = HashMap::new(); // Empty networks
		let network_ids = vec![1];

		let result = Eip7683OffchainDiscovery::new(network_ids, &networks);

		assert!(result.is_err());
		matches!(result.unwrap_err(), DiscoveryError::ValidationError(_));
	}

	#[test]
	fn test_deserialize_bytes32_valid() {
		let json_data = json!({
			"oracle": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			"settler": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			"chainId": "137",
			"token": "9999999999999999999999999999999999999999999999999999999999999999",
			"amount": "500",
			"recipient": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			"callbackData": "0x",
			"context": "0x"
		});
		let result: Result<ApiMandateOutput, _> = serde_json::from_value(json_data);
		assert!(result.is_ok());

		let output = result.unwrap();
		assert_eq!(output.oracle[0], 0x12);
		assert_eq!(output.oracle[31], 0xef);
	}

	#[test]
	fn test_deserialize_bytes32_no_prefix() {
		let json_data = json!({
			"oracle": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			"settler": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			"chainId": "137",
			"token": "9999999999999999999999999999999999999999999999999999999999999999",
			"amount": "500",
			"recipient": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			"callbackData": "0x",
			"context": "0x"
		});
		let result: Result<ApiMandateOutput, _> = serde_json::from_value(json_data);
		assert!(result.is_ok());
	}

	#[test]
	fn test_deserialize_bytes32_invalid_length() {
		let json_data = json!("0x1234"); // Too short
		let result: Result<[u8; 32], _> = serde_json::from_value(json_data);
		assert!(result.is_err());
	}

	#[test]
	fn test_api_standard_order_conversion() {
		let sol_order = create_test_standard_order();
		let api_order = ApiStandardOrder::from(&sol_order);

		assert_eq!(api_order.user, sol_order.user);
		assert_eq!(api_order.nonce, sol_order.nonce);
		assert_eq!(api_order.origin_chain_id, sol_order.originChainId);
		assert_eq!(api_order.expires, sol_order.expires);
		assert_eq!(api_order.fill_deadline, sol_order.fillDeadline);
		assert_eq!(api_order.inputs, sol_order.inputs);
		assert_eq!(api_order.outputs.len(), sol_order.outputs.len());
	}

	#[test]
	fn test_mandate_output_conversion() {
		let sol_output = create_test_mandate_output();
		let api_output = ApiMandateOutput::from(&sol_output);

		assert_eq!(api_output.oracle, sol_output.oracle.0);
		assert_eq!(api_output.settler, sol_output.settler.0);
		assert_eq!(api_output.chain_id, sol_output.chainId);
		assert_eq!(api_output.token, sol_output.token.0);
		assert_eq!(api_output.amount, sol_output.amount);
		assert_eq!(api_output.recipient, sol_output.recipient.0);
	}

	#[test]
	fn test_config_schema_validation_success() {
		let config = serde_json::Value::Object({
			let mut table = serde_json::Map::new();
			table.insert(
				"api_host".to_string(),
				serde_json::Value::String("127.0.0.1".to_string()),
			);
			table.insert("api_port".to_string(), serde_json::Value::from(8080));
			table.insert(
				"network_ids".to_string(),
				serde_json::Value::Array(vec![serde_json::Value::from(1)]),
			);
			table
		});

		let result = Eip7683OffchainDiscoverySchema::validate_config(&config);
		assert!(result.is_ok());
	}

	#[test]
	fn test_config_schema_validation_missing_required() {
		let config = serde_json::Value::Object({
			let mut table = serde_json::Map::new();
			table.insert(
				"api_host".to_string(),
				serde_json::Value::String("127.0.0.1".to_string()),
			);
			// Missing api_port and network_ids
			table
		});

		let result = Eip7683OffchainDiscoverySchema::validate_config(&config);
		assert!(result.is_err());
	}

	#[test]
	fn test_create_discovery_factory_success() {
		let config = serde_json::Value::Object({
			let mut table = serde_json::Map::new();
			table.insert(
				"api_host".to_string(),
				serde_json::Value::String("127.0.0.1".to_string()),
			);
			table.insert("api_port".to_string(), serde_json::Value::from(8080));
			table.insert(
				"network_ids".to_string(),
				serde_json::Value::Array(vec![serde_json::Value::from(1)]),
			);
			table
		});

		let networks = create_test_networks_config();
		let result = create_discovery(&config, &networks);
		assert!(result.is_ok());
	}

	#[test]
	fn test_create_discovery_factory_defaults() {
		let config = serde_json::Value::Object({
			let mut table = serde_json::Map::new();
			// Provide required fields but use values that will trigger defaults
			table.insert(
				"api_host".to_string(),
				serde_json::Value::String("0.0.0.0".to_string()),
			);
			table.insert("api_port".to_string(), serde_json::Value::from(8081));
			table.insert(
				"network_ids".to_string(),
				serde_json::Value::Array(vec![serde_json::Value::from(1)]),
			);
			// Don't include auth_token to test that default (None) works
			table
		});

		let networks = create_test_networks_config();
		let result = create_discovery(&config, &networks);
		assert!(result.is_ok());
	}

	#[tokio::test]
	async fn test_discovery_interface_start_stop() {
		let networks = create_test_networks_config();
		let discovery = Eip7683OffchainDiscovery::new(vec![1], &networks).unwrap();

		let (tx, _rx) = mpsc::channel(16);

		// Test start monitoring
		let start_result = discovery.start_monitoring(tx).await;
		assert!(start_result.is_ok());
		assert!(discovery.is_running.load(Ordering::SeqCst));

		// Test stop monitoring
		let stop_result = discovery.stop_monitoring().await;
		assert!(stop_result.is_ok());
		assert!(!discovery.is_running.load(Ordering::SeqCst));
	}

	#[tokio::test]
	async fn test_discovery_interface_already_monitoring() {
		let networks = create_test_networks_config();
		let discovery = Eip7683OffchainDiscovery::new(vec![1], &networks).unwrap();

		let (tx1, _rx1) = mpsc::channel(16);
		let (tx2, _rx2) = mpsc::channel(16);

		// Start monitoring
		discovery.start_monitoring(tx1).await.unwrap();

		// Try to start again - should fail
		let result = discovery.start_monitoring(tx2).await;
		assert!(result.is_err());
		matches!(result.unwrap_err(), DiscoveryError::AlreadyMonitoring);

		// Cleanup
		discovery.stop_monitoring().await.unwrap();
	}

	#[tokio::test]
	async fn test_enqueue_intent_returns_service_unavailable_when_queue_full() {
		let (tx, _rx) = mpsc::channel(1);
		tx.try_send(Intent {
			id: "already-queued".to_string(),
			source: "test".to_string(),
			standard: "eip7683".to_string(),
			metadata: IntentMetadata {
				requires_auction: false,
				exclusive_until: None,
				discovered_at: current_timestamp(),
			},
			data: json!({}),
			order_bytes: Bytes::new(),
			quote_id: None,
			lock_type: "permit2_escrow".to_string(),
		})
		.expect("first intent should fill queue");

		let error = enqueue_intent(
			&tx,
			Intent {
				id: "backpressured".to_string(),
				source: "test".to_string(),
				standard: "eip7683".to_string(),
				metadata: IntentMetadata {
					requires_auction: false,
					exclusive_until: None,
					discovered_at: current_timestamp(),
				},
				data: json!({}),
				order_bytes: Bytes::new(),
				quote_id: None,
				lock_type: "permit2_escrow".to_string(),
			},
		)
		.expect_err("full queue should reject the intent immediately");

		assert_eq!(error, EnqueueIntentError::Full);
	}
}
