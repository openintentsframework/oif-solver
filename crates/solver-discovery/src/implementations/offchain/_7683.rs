//! ERC-7683 Off-chain Intent Discovery API Implementation
//!
//! This module implements an HTTP API server that accepts ERC-7683 cross-chain intents
//! directly from users or other systems. It provides an endpoint for receiving
//! gasless cross-chain orders that follow the ERC-7683 standard.
//!
//! The API is exposed directly from the discovery module rather than solver-service for several key reasons:
//!
//! 1. **Consistency**: Discovery is the entry point for ALL intents - both on-chain and off-chain
//! 2. **Single Responsibility**: Each module has a clear purpose:
//!    - solver-discovery: Intent ingestion and lifecycle management
//!    - solver-service: Solver orchestration, health, metrics, quotes
//! 3. **Extensibility**: Provides a pattern for custom discovery implementations (e.g., webhooks, other APIs)
//! 4. **Independence**: Discovery can be deployed/scaled separately from the solver service
//! 5. **Source of Truth**: Discovery owns the intent lifecycle and should expose intent-related endpoints
//!
//! ## Overview
//!
//! The off-chain discovery service runs an HTTP API server that:
//! - Accepts EIP-7683 gasless cross-chain orders via POST requests
//! - Validates order parameters and signatures
//! - Converts orders to the internal Intent format
//! - Broadcasts discovered intents to the solver system
//!
//! ## API Endpoint
//!
//! - `POST /intent` - Submit a new cross-chain order
//!
//! ## Configuration
//!
//! The service requires the following configuration:
//! - `api_host` - The host address to bind the API server (default: "0.0.0.0")
//! - `api_port` - The port to listen on (default: 8080)
//! - `rpc_url` - Ethereum RPC URL for calling settler contracts
//!
//! ## Order Flow
//!
//! 1. User submits a `GaslessCrossChainOrder` to the API endpoint
//! 2. The service validates the order deadlines and signature
//! 3. Order ID is computed by calling the settler contract
//! 4. Order data is parsed to extract inputs/outputs
//! 5. The order is converted to an Intent and broadcast to solvers

use crate::{DiscoveryError, DiscoveryInterface};
use alloy_primitives::{Address as AlloyAddress, Bytes, U256};
use alloy_provider::DynProvider;
use alloy_sol_types::SolType;
use async_trait::async_trait;
use axum::{
	extract::State,
	http::StatusCode,
	response::{IntoResponse, Json},
	routing::post,
	Router,
};
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
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tower_http::cors::CorsLayer;

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
	hex::decode_to_slice(s, &mut bytes)
		.map_err(|e| Error::custom(format!("Invalid hex: {}", e)))?;

	Ok(bytes)
}

/// Status enum for intent submission responses.
///
/// Distinguishes between successful receipt and validation failures at the discovery stage.
/// Note: Full validation (oracle routes, etc.) happens asynchronously after receipt.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum IntentResponseStatus {
	/// Intent received and passed basic validation, queued for full validation
	Received,
	/// Intent rejected due to validation failure
	Rejected,
	/// Intent processing encountered an error
	Error,
}

/// API response for intent submission.
///
/// Returned by the POST /intent endpoint to indicate submission status.
///
/// # Fields
///
/// * `order_id` - The assigned order identifier if received (optional)
/// * `status` - Status enum indicating if intent was received or rejected
/// * `message` - Optional message for additional details on status
/// * `order` - The submitted EIP-712 typed data order (parsed StandardOrder as JSON)
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct IntentResponse {
	#[serde(rename = "orderId")]
	order_id: Option<String>,
	status: IntentResponseStatus,
	message: Option<String>,
	order: Option<serde_json::Value>,
}

/// Shared state for the API server.
///
/// Contains all the dependencies needed by API request handlers.
/// This state is cloned for each request (all fields are cheaply cloneable).
///
/// # Fields
///
/// * `intent_sender` - Channel to broadcast discovered intents to the solver system
/// * `providers` - RPC providers for interacting with on-chain contracts
/// * `networks` - Networks configuration for settler lookups
#[derive(Clone)]
struct ApiState {
	/// Channel to send discovered intents
	intent_sender: mpsc::UnboundedSender<Intent>,
	/// RPC providers for each supported network
	providers: HashMap<u64, DynProvider>,
	/// Networks configuration for settler lookups
	networks: NetworksConfig,
}

/// EIP-7683 offchain discovery implementation.
///
/// This struct implements the `DiscoveryInterface` trait to provide
/// off-chain intent discovery through an HTTP API server. It listens
/// for incoming EIP-7683 orders and converts them to the internal
/// Intent format for processing by the solver system.
#[derive(Debug)]
pub struct Eip7683OffchainDiscovery {
	/// API server configuration
	api_host: String,
	api_port: u16,
	/// RPC providers for each supported network
	providers: HashMap<u64, DynProvider>,
	/// Networks configuration for settler lookups
	networks: NetworksConfig,
	/// Flag indicating if the server is running
	is_running: Arc<AtomicBool>,
	/// Channel for signaling server shutdown
	shutdown_signal: Arc<Mutex<Option<mpsc::Sender<()>>>>,
}

impl Eip7683OffchainDiscovery {
	/// Creates a new EIP-7683 offchain discovery instance.
	///
	/// # Arguments
	///
	/// * `api_host` - The host address to bind the API server
	/// * `api_port` - The port number to listen on
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
	pub fn new(
		api_host: String,
		api_port: u16,
		network_ids: Vec<u64>,
		networks: &NetworksConfig,
	) -> Result<Self, DiscoveryError> {
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
			api_host,
			api_port,
			providers,
			networks: networks.clone(),
			is_running: Arc::new(AtomicBool::new(false)),
			shutdown_signal: Arc::new(Mutex::new(None)),
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
							"No input settler compact address found for chain ID {}",
							origin_chain_id
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
				"No RPC provider configured for chain ID {}",
				origin_chain_id
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
				DiscoveryError::ParseError(format!("Failed to serialize order data: {}", e))
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
					DiscoveryError::ParseError(format!("Failed to decode StandardOrder: {}", e))
				})?;
				let compact = IInputSettlerCompact::new(settler_address, provider);
				let resp = compact
					.orderIdentifier(std_order)
					.call()
					.await
					.map_err(|e| {
						DiscoveryError::Connection(format!(
							"Failed to get order ID from compact contract: {}",
							e
						))
					})?;
				Ok(resp.0)
			},
			LockType::Permit2Escrow | LockType::Eip3009Escrow => {
				// Escrow types - use IInputSettlerEscrow
				// Decode the order bytes to StandardOrder
				let std_order = StandardOrder::abi_decode_validate(order_bytes).map_err(|e| {
					DiscoveryError::ParseError(format!("Failed to decode StandardOrder: {}", e))
				})?;
				let escrow = IInputSettlerEscrow::new(settler_address, provider);
				let resp = escrow
					.orderIdentifier(std_order)
					.call()
					.await
					.map_err(|e| {
						DiscoveryError::Connection(format!(
							"Failed to get order ID from escrow contract: {}",
							e
						))
					})?;
				Ok(resp.0)
			},
		}
	}

	/// Main API server task.
	///
	/// Runs the HTTP server that listens for intent submissions.
	/// The server supports graceful shutdown via the shutdown channel.
	///
	/// # Arguments
	///
	/// * `api_host` - Host address to bind to
	/// * `api_port` - Port number to listen on
	/// * `intent_sender` - Channel to send discovered intents
	/// * `providers` - RPC providers for contract calls
	/// * `networks` - Networks configuration for settler lookups
	/// * `shutdown_rx` - Channel to receive shutdown signal
	///
	/// # Errors
	///
	/// Returns an error if:
	/// - The address cannot be parsed
	/// - The TCP listener cannot bind to the address
	/// - The server encounters a fatal error
	async fn run_server(
		api_host: String,
		api_port: u16,
		intent_sender: mpsc::UnboundedSender<Intent>,
		providers: HashMap<u64, DynProvider>,
		networks: NetworksConfig,
		mut shutdown_rx: mpsc::Receiver<()>,
	) -> Result<(), String> {
		let state = ApiState {
			intent_sender,
			providers,
			networks,
		};

		let app = Router::new()
			.route("/intent", post(handle_intent_submission))
			.layer(CorsLayer::permissive())
			.with_state(state);

		let addr = format!("{}:{}", api_host, api_port)
			.parse::<SocketAddr>()
			.map_err(|e| format!("Invalid address '{}:{}': {}", api_host, api_port, e))?;

		let listener = tokio::net::TcpListener::bind(addr)
			.await
			.map_err(|e| format!("Failed to bind address {}: {}", addr, e))?;

		tracing::info!("EIP-7683 offchain discovery API listening on {}", addr);

		axum::serve(listener, app)
			.with_graceful_shutdown(async move {
				let _ = shutdown_rx.recv().await;
				tracing::info!("Shutting down API server");
			})
			.await
			.map_err(|e| format!("Server error: {}", e))?;

		Ok(())
	}
}
/// Handles intent submission requests.
///
/// This is the main request handler for the POST /intent endpoint.
/// It validates the incoming order, converts it to an Intent, and
/// broadcasts it to the solver system.
///
/// # Arguments
///
/// * `state` - Shared API state containing dependencies
/// * `request` - The intent submission request
///
/// # Returns
///
/// Returns an HTTP response with:
/// - 200 OK with order_id on success
/// - 400 Bad Request if validation fails
/// - 500 Internal Server Error if processing fails
///
/// # Response Format
///
/// ```json
/// {
///   "order_id": "0x...",
///   "status": "success" | "error",
///   "message": "optional error message"
/// }
/// ```
async fn handle_intent_submission(
	State(state): State<ApiState>,
	Json(request): Json<PostOrderRequest>,
) -> impl IntoResponse {
	// Convert OifOrder to StandardOrder
	let order = match StandardOrder::try_from(&request.order) {
		Ok(order) => order,
		Err(e) => {
			tracing::warn!(error = %e, "Failed to convert OifOrder to StandardOrder");
			return (
				StatusCode::BAD_REQUEST,
				Json(IntentResponse {
					order_id: None,
					status: IntentResponseStatus::Rejected,
					message: Some(format!("Failed to convert order: {}", e)),
					order: None,
				}),
			)
				.into_response();
		},
	};

	// Serialize the parsed order once for all responses
	let order_json = match serde_json::to_value(ApiStandardOrder::from(&order)) {
		Ok(json) => Some(json),
		Err(e) => {
			tracing::warn!(error = %e, "Failed to serialize order");
			None
		},
	};

	let signature = request.signature;

	// Extract sponsor from the order using our new helper
	let sponsor = match request.order.extract_sponsor(Some(&signature)) {
		Ok(sponsor) => sponsor,
		Err(e) => {
			tracing::warn!(error = %e, "Failed to extract sponsor from order");
			return (
				StatusCode::BAD_REQUEST,
				Json(IntentResponse {
					order_id: None,
					status: IntentResponseStatus::Rejected,
					message: Some(format!("Failed to extract sponsor: {}", e)),
					order: order_json,
				}),
			)
				.into_response();
		},
	};

	// Derive lock type from the order
	let lock_type = LockType::from(&request.order);

	// Convert to intent
	match Eip7683OffchainDiscovery::order_to_intent(
		&order,
		&sponsor,
		&signature,
		lock_type,
		&state.providers,
		&state.networks,
		request.quote_id,
	)
	.await
	{
		Ok(intent) => {
			let order_id = intent.id.clone();

			// Send intent through channel
			if let Err(e) = state.intent_sender.send(intent) {
				tracing::warn!(error = %e, "Failed to send intent to solver channel");
				return (
					StatusCode::INTERNAL_SERVER_ERROR,
					Json(IntentResponse {
						order_id: Some(order_id),
						status: IntentResponseStatus::Error,
						message: Some(format!("Failed to process intent: {}", e)),
						order: order_json.clone(),
					}),
				)
					.into_response();
			}

			(
				StatusCode::ACCEPTED,
				Json(IntentResponse {
					order_id: Some(order_id),
					status: IntentResponseStatus::Received,
					message: Some(
						"Basic validation passed, pending profitability validation and oracle route validation".to_string(),
					),
					order: order_json,
				}),
			)
				.into_response()
		},
		Err(e) => {
			tracing::warn!(error = %e, "Failed to convert order to intent");
			(
				StatusCode::BAD_REQUEST,
				Json(IntentResponse {
					order_id: None,
					status: IntentResponseStatus::Rejected,
					message: Some(e.to_string()),
					order: order_json,
				}),
			)
				.into_response()
		},
	}
}

/// Configuration schema for EIP-7683 off-chain discovery service.
///
/// This schema validates the configuration for the off-chain discovery API,
/// ensuring all required fields are present and have valid values.
///
/// # Required Fields
///
/// - `api_host` - Host address for the API server (e.g., "127.0.0.1" or "0.0.0.0")
/// - `api_port` - Port number for the API server (1-65535)
/// - `network_ids` - List of network IDs this discovery service monitors
pub struct Eip7683OffchainDiscoverySchema;

impl Eip7683OffchainDiscoverySchema {
	/// Static validation method for use before instance creation
	pub fn validate_config(config: &toml::Value) -> Result<(), solver_types::ValidationError> {
		let instance = Self;
		instance.validate(config)
	}
}

impl ConfigSchema for Eip7683OffchainDiscoverySchema {
	fn validate(&self, config: &toml::Value) -> Result<(), solver_types::ValidationError> {
		let schema = Schema::new(
			// Required fields
			vec![
				Field::new("api_host", FieldType::String),
				Field::new(
					"api_port",
					FieldType::Integer {
						min: Some(1),
						max: Some(65535),
					},
				),
				Field::new(
					"network_ids",
					FieldType::Array(Box::new(FieldType::Integer {
						min: Some(1),
						max: None,
					})),
				),
			],
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

	async fn start_monitoring(
		&self,
		sender: mpsc::UnboundedSender<Intent>,
	) -> Result<(), DiscoveryError> {
		if self.is_running.load(Ordering::SeqCst) {
			return Err(DiscoveryError::AlreadyMonitoring);
		}

		let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
		*self.shutdown_signal.lock().await = Some(shutdown_tx);

		// Spawn API server task
		let api_host = self.api_host.clone();
		let api_port = self.api_port;
		let providers = self.providers.clone();
		let networks = self.networks.clone();

		tokio::spawn(async move {
			if let Err(e) =
				Self::run_server(api_host, api_port, sender, providers, networks, shutdown_rx).await
			{
				tracing::error!("API server error: {}", e);
			}
		});

		self.is_running.store(true, Ordering::SeqCst);
		Ok(())
	}

	async fn stop_monitoring(&self) -> Result<(), DiscoveryError> {
		if !self.is_running.load(Ordering::SeqCst) {
			return Ok(());
		}

		if let Some(shutdown_tx) = self.shutdown_signal.lock().await.take() {
			let _ = shutdown_tx.send(()).await;
		}

		self.is_running.store(false, Ordering::SeqCst);
		Ok(())
	}

	fn get_url(&self) -> Option<String> {
		Some(format!("{}:{}", self.api_host, self.api_port))
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
/// * `config` - TOML configuration value containing service parameters
/// * `networks` - Global networks configuration with RPC URLs and settler addresses
///
/// # Returns
///
/// Returns a boxed discovery interface implementation.
///
/// # Configuration
///
/// Expected configuration format:
/// ```toml
/// api_host = "0.0.0.0"         # optional, defaults to "0.0.0.0"
/// api_port = 8081              # optional, defaults to 8081
/// network_ids = [1, 10, 137]  # optional, defaults to all networks
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The networks configuration is invalid
/// - The discovery service cannot be created
pub fn create_discovery(
	config: &toml::Value,
	networks: &NetworksConfig,
) -> Result<Box<dyn DiscoveryInterface>, DiscoveryError> {
	// Validate configuration first
	Eip7683OffchainDiscoverySchema::validate_config(config)
		.map_err(|e| DiscoveryError::ValidationError(format!("Invalid configuration: {}", e)))?;

	let api_host = config
		.get("api_host")
		.and_then(|v| v.as_str())
		.unwrap_or("0.0.0.0")
		.to_string();

	let api_port = config
		.get("api_port")
		.and_then(|v| v.as_integer())
		.unwrap_or(8081) as u16;

	// Get network_ids from config, or default to all networks
	let network_ids = config
		.get("network_ids")
		.and_then(|v| v.as_array())
		.map(|arr| {
			arr.iter()
				.filter_map(|v| v.as_integer().map(|i| i as u64))
				.collect::<Vec<_>>()
		})
		.unwrap_or_else(|| networks.keys().cloned().collect());

	let discovery = Eip7683OffchainDiscovery::new(api_host, api_port, network_ids, networks)
		.map_err(|e| {
			DiscoveryError::Connection(format!(
				"Failed to create offchain discovery service: {}",
				e
			))
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
	use serde_json::json;
	use solver_types::{
		utils::tests::builders::{NetworkConfigBuilder, NetworksConfigBuilder},
		NetworksConfig,
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

	#[test]
	fn test_new_discovery_service() {
		let networks = create_test_networks_config();
		let network_ids = vec![1];

		let discovery =
			Eip7683OffchainDiscovery::new("127.0.0.1".to_string(), 8080, network_ids, &networks);

		assert!(discovery.is_ok());
		let discovery = discovery.unwrap();
		assert_eq!(discovery.api_host, "127.0.0.1");
		assert_eq!(discovery.api_port, 8080);
	}

	#[test]
	fn test_new_discovery_service_invalid_networks() {
		let networks = HashMap::new(); // Empty networks
		let network_ids = vec![1];

		let result =
			Eip7683OffchainDiscovery::new("127.0.0.1".to_string(), 8080, network_ids, &networks);

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
			"call": "0x",
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
			"call": "0x",
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
	fn test_intent_response_serialization() {
		let response = IntentResponse {
			order_id: Some("0x123".to_string()),
			status: IntentResponseStatus::Received,
			message: Some("Success".to_string()),
			order: Some(json!({"test": "data"})),
		};

		let serialized = serde_json::to_string(&response);
		assert!(serialized.is_ok());

		let json_str = serialized.unwrap();
		assert!(json_str.contains("orderId"));
		assert!(json_str.contains("received"));
	}

	#[test]
	fn test_config_schema_validation_success() {
		let config = toml::Value::Table({
			let mut table = toml::value::Table::new();
			table.insert(
				"api_host".to_string(),
				toml::Value::String("127.0.0.1".to_string()),
			);
			table.insert("api_port".to_string(), toml::Value::Integer(8080));
			table.insert(
				"network_ids".to_string(),
				toml::Value::Array(vec![toml::Value::Integer(1)]),
			);
			table
		});

		let result = Eip7683OffchainDiscoverySchema::validate_config(&config);
		assert!(result.is_ok());
	}

	#[test]
	fn test_config_schema_validation_missing_required() {
		let config = toml::Value::Table({
			let mut table = toml::value::Table::new();
			table.insert(
				"api_host".to_string(),
				toml::Value::String("127.0.0.1".to_string()),
			);
			// Missing api_port and network_ids
			table
		});

		let result = Eip7683OffchainDiscoverySchema::validate_config(&config);
		assert!(result.is_err());
	}

	#[test]
	fn test_config_schema_validation_invalid_port() {
		let config = toml::Value::Table({
			let mut table = toml::value::Table::new();
			table.insert(
				"api_host".to_string(),
				toml::Value::String("127.0.0.1".to_string()),
			);
			table.insert("api_port".to_string(), toml::Value::Integer(70000)); // Invalid port > 65535
			table.insert(
				"network_ids".to_string(),
				toml::Value::Array(vec![toml::Value::Integer(1)]),
			);
			table
		});

		let result = Eip7683OffchainDiscoverySchema::validate_config(&config);
		assert!(result.is_err());
	}

	#[test]
	fn test_create_discovery_factory_success() {
		let config = toml::Value::Table({
			let mut table = toml::value::Table::new();
			table.insert(
				"api_host".to_string(),
				toml::Value::String("127.0.0.1".to_string()),
			);
			table.insert("api_port".to_string(), toml::Value::Integer(8080));
			table.insert(
				"network_ids".to_string(),
				toml::Value::Array(vec![toml::Value::Integer(1)]),
			);
			table
		});

		let networks = create_test_networks_config();
		let result = create_discovery(&config, &networks);
		assert!(result.is_ok());
	}

	#[test]
	fn test_create_discovery_factory_defaults() {
		let config = toml::Value::Table({
			let mut table = toml::value::Table::new();
			// Provide required fields but use values that will trigger defaults
			table.insert(
				"api_host".to_string(),
				toml::Value::String("0.0.0.0".to_string()),
			);
			table.insert("api_port".to_string(), toml::Value::Integer(8081));
			table.insert(
				"network_ids".to_string(),
				toml::Value::Array(vec![toml::Value::Integer(1)]),
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
		let discovery = Eip7683OffchainDiscovery::new(
			"127.0.0.1".to_string(),
			0, // Use port 0 to let OS assign a free port
			vec![1],
			&networks,
		)
		.unwrap();

		let (tx, _rx) = mpsc::unbounded_channel();

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
		let discovery =
			Eip7683OffchainDiscovery::new("127.0.0.1".to_string(), 0, vec![1], &networks).unwrap();

		let (tx1, _rx1) = mpsc::unbounded_channel();
		let (tx2, _rx2) = mpsc::unbounded_channel();

		// Start monitoring
		discovery.start_monitoring(tx1).await.unwrap();

		// Try to start again - should fail
		let result = discovery.start_monitoring(tx2).await;
		assert!(result.is_err());
		matches!(result.unwrap_err(), DiscoveryError::AlreadyMonitoring);

		// Cleanup
		discovery.stop_monitoring().await.unwrap();
	}

	#[test]
	fn test_get_url() {
		let networks = create_test_networks_config();
		let discovery =
			Eip7683OffchainDiscovery::new("127.0.0.1".to_string(), 8080, vec![1], &networks)
				.unwrap();

		let url = discovery.get_url();
		assert_eq!(url, Some("127.0.0.1:8080".to_string()));
	}

	#[tokio::test]
	async fn test_handle_intent_submission_invalid_order() {
		use axum::extract::State;
		use axum::Json;
		use solver_types::api::OifOrder;

		let (tx, _rx) = mpsc::unbounded_channel();
		let state = ApiState {
			intent_sender: tx,
			providers: HashMap::new(),
			networks: create_test_networks_config(),
		};

		// Create invalid request with malformed OifOrder
		// Using OifGenericV0 with invalid data that will fail StandardOrder conversion
		let invalid_request = PostOrderRequest {
			order: OifOrder::OifGenericV0 {
				payload: serde_json::json!({
					"invalid": "data_that_cannot_be_converted_to_standard_order"
				}),
			},
			signature: Bytes::from_static(b"signature"),
			quote_id: None,
			origin_submission: None,
		};

		let response = handle_intent_submission(State(state), Json(invalid_request)).await;

		// Should return BAD_REQUEST status due to parsing failure
		assert_eq!(response.into_response().status(), StatusCode::BAD_REQUEST);
	}
}
