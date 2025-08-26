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
//! - `auth_token` - Optional authentication token for API access
//!
//! ## Order Flow
//!
//! 1. User submits a `GaslessCrossChainOrder` to the API endpoint
//! 2. The service validates the order deadlines and signature
//! 3. Order ID is computed by calling the settler contract
//! 4. Order data is parsed to extract inputs/outputs
//! 5. The order is converted to an Intent and broadcast to solvers

use crate::{DiscoveryError, DiscoveryInterface};
use alloy_primitives::{Address, Bytes, U256};
use alloy_provider::RootProvider;
use alloy_sol_types::sol;
use alloy_transport_http::Http;
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
	current_timestamp, normalize_bytes32_address,
	standards::eip7683::{GasLimitOverrides, LockType, MandateOutput},
	with_0x_prefix, ConfigSchema, Eip7683OrderData, Field, FieldType, ImplementationRegistry,
	Intent, IntentMetadata, NetworksConfig, Schema,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tower_http::cors::CorsLayer;

// Import the Solidity types for the OIF contracts
sol! {
	#[sol(rpc)]
	interface IInputSettlerEscrow {
		function orderIdentifier(bytes calldata order) external view returns (bytes32);
		function openFor(bytes calldata order, address sponsor, bytes calldata signature) external;
	}

	#[sol(rpc)]
	interface IInputSettlerCompact {
		function orderIdentifier(StandardOrder calldata order) external view returns (bytes32);
	}

	struct StandardOrder {
		address user;
		uint256 nonce;
		uint256 originChainId;
		uint32 expires;
		uint32 fillDeadline;
		address inputOracle;
		uint256[2][] inputs;
		SolMandateOutput[] outputs;
	}

	struct SolMandateOutput {
		bytes32 oracle;
		bytes32 settler;
		uint256 chainId;
		bytes32 token;
		uint256 amount;
		bytes32 recipient;
		bytes call;
		bytes context;
	}
}

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
	user: Address,
	nonce: U256,
	origin_chain_id: U256,
	expires: u32,
	fill_deadline: u32,
	input_oracle: Address,
	inputs: Vec<[U256; 2]>,
	outputs: Vec<ApiMandateOutput>,
}

/// API representation of MandateOutput
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiMandateOutput {
	#[serde(deserialize_with = "deserialize_bytes32")]
	oracle: [u8; 32],
	#[serde(deserialize_with = "deserialize_bytes32")]
	settler: [u8; 32],
	chain_id: U256,
	#[serde(deserialize_with = "deserialize_bytes32")]
	token: [u8; 32],
	amount: U256,
	#[serde(deserialize_with = "deserialize_bytes32")]
	recipient: [u8; 32],
	call: Bytes,
	context: Bytes,
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

/// Flexible deserializer for LockType that accepts numbers, strings, or enum names.
fn deserialize_lock_type_flexible<'de, D>(deserializer: D) -> Result<LockType, D::Error>
where
	D: serde::Deserializer<'de>,
{
	use serde::de::Error;
	let v = serde_json::Value::deserialize(deserializer)?;
	match v {
		serde_json::Value::Number(n) => {
			let num = n
				.as_u64()
				.ok_or_else(|| Error::custom("Invalid number for LockType"))?;
			if num <= u8::MAX as u64 {
				LockType::from_u8(num as u8).ok_or_else(|| Error::custom("Invalid LockType value"))
			} else {
				Err(Error::custom("LockType value out of range"))
			}
		},
		serde_json::Value::String(s) => {
			// Try parsing as number first, then as enum name
			if let Ok(num) = s.parse::<u8>() {
				LockType::from_u8(num).ok_or_else(|| Error::custom("Invalid LockType value"))
			} else {
				// Try parsing as enum variant name
				match s.as_str() {
					"permit2_escrow" | "Permit2Escrow" => Ok(LockType::Permit2Escrow),
					"eip3009_escrow" | "Eip3009Escrow" => Ok(LockType::Eip3009Escrow),
					"resource_lock" | "ResourceLock" => Ok(LockType::ResourceLock),
					_ => Err(Error::custom("Invalid LockType string")),
				}
			}
		},
		serde_json::Value::Null => Ok(default_lock_type()),
		_ => Err(Error::custom(
			"expected number, string, or null for LockType",
		)),
	}
}

/// API request wrapper for intent submission.
///
/// This is the top-level structure for POST /intent requests with the OIF format.
///
/// # Fields
///
/// * `order` - The StandardOrder encoded as hex bytes
/// * `sponsor` - The address sponsoring the order (usually the user)
/// * `signature` - The Permit2Witness signature
/// * `lock_type` - The custody mechanism type
#[derive(Debug, Deserialize)]
struct IntentRequest {
	order: Bytes,
	sponsor: Address,
	signature: Bytes,
	#[serde(
		default = "default_lock_type",
		deserialize_with = "deserialize_lock_type_flexible"
	)]
	lock_type: LockType,
}

fn default_lock_type() -> LockType {
	LockType::Permit2Escrow
}

/// API response for intent submission.
///
/// Returned by the POST /intent endpoint to indicate submission status.
///
/// # Fields
///
/// * `order_id` - The assigned order identifier if accepted (optional)
/// * `status` - Human/machine readable status string
/// * `message` - Optional message for additional details on status
/// * `order` - The submitted EIP-712 typed data order (optional)
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct IntentResponse {
	#[serde(rename = "orderId")]
	order_id: Option<String>,
	status: String,
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
/// * `auth_token` - Optional authentication token for API access control
/// * `provider` - RPC provider for interacting with on-chain contracts
/// * `networks` - Networks configuration for settler lookups
#[derive(Clone)]
struct ApiState {
	/// Channel to send discovered intents
	intent_sender: mpsc::UnboundedSender<Intent>,
	/// Optional authentication token
	#[allow(dead_code)]
	auth_token: Option<String>,
	/// RPC providers for each supported network
	providers: HashMap<u64, RootProvider<Http<reqwest::Client>>>,
	/// Networks configuration for settler lookups
	networks: NetworksConfig,
}

/// EIP-7683 offchain discovery implementation.
///
/// This struct implements the `DiscoveryInterface` trait to provide
/// off-chain intent discovery through an HTTP API server. It listens
/// for incoming EIP-7683 orders and converts them to the internal
/// Intent format for processing by the solver system.
pub struct Eip7683OffchainDiscovery {
	/// API server configuration
	api_host: String,
	api_port: u16,
	auth_token: Option<String>,
	/// RPC providers for each supported network
	providers: HashMap<u64, RootProvider<Http<reqwest::Client>>>,
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
	/// * `auth_token` - Optional authentication token for API access
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
		auth_token: Option<String>,
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
			if let Some(network) = networks.get(network_id) {
				let http_url = network.get_http_url().ok_or_else(|| {
					DiscoveryError::Connection(format!(
						"No HTTP RPC URL configured for network {}",
						network_id
					))
				})?;
				let provider = RootProvider::new_http(http_url.parse().map_err(|e| {
					DiscoveryError::Connection(format!(
						"Invalid RPC URL for network {}: {}",
						network_id, e
					))
				})?);
				providers.insert(*network_id, provider);
			} else {
				tracing::warn!(
					"Network {} in supported_networks not found in networks config",
					network_id
				);
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
			auth_token,
			providers,
			networks: networks.clone(),
			is_running: Arc::new(AtomicBool::new(false)),
			shutdown_signal: Arc::new(Mutex::new(None)),
		})
	}

	/// Parses StandardOrder data from raw bytes.
	///
	/// Decodes the StandardOrder struct from the raw order data bytes
	/// and extracts all necessary fields.
	///
	/// # Arguments
	///
	/// * `order_bytes` - The encoded StandardOrder bytes
	///
	/// # Returns
	///
	/// Returns the decoded StandardOrder struct.
	///
	/// # Errors
	///
	/// Returns `DiscoveryError::ParseError` if the order data cannot be decoded.
	fn parse_standard_order(order_bytes: &Bytes) -> Result<StandardOrder, DiscoveryError> {
		use alloy_sol_types::SolValue;

		// Decode the StandardOrder struct from the order data
		let order = StandardOrder::abi_decode(order_bytes, true).map_err(|e| {
			DiscoveryError::ParseError(format!("Failed to decode StandardOrder: {}", e))
		})?;

		Ok(order)
	}

	/// Validates the incoming StandardOrder.
	///
	/// Performs validation checks on order deadlines to ensure
	/// the order is still valid and can be processed.
	///
	/// # Arguments
	///
	/// * `order` - The StandardOrder to validate
	/// * `sponsor` - The sponsor address
	/// * `signature` - The Permit2Witness signature
	///
	/// # Returns
	///
	/// Returns `Ok(())` if the order is valid.
	///
	/// # Errors
	///
	/// Returns `DiscoveryError::ValidationError` if:
	/// - The expiry has passed
	/// - The fill deadline has passed
	///
	/// # TODO
	///
	/// - Implement Permit2Witness signature validation
	async fn validate_order(
		order: &StandardOrder,
		_sponsor: &Address,
		_signature: &Bytes,
	) -> Result<(), DiscoveryError> {
		// Check if deadlines are still valid
		let current_time = current_timestamp() as u32;

		if order.expires < current_time {
			return Err(DiscoveryError::ValidationError(
				"Order has expired".to_string(),
			));
		}

		if order.fillDeadline < current_time {
			return Err(DiscoveryError::ValidationError(
				"Order fill deadline has passed".to_string(),
			));
		}

		// TODO: Implement Permit2Witness signature validation
		// The signature should be validated against the Permit2 contract

		Ok(())
	}

	/// Converts GaslessCrossChainOrder to Intent.
	///
	/// Transforms an API order into the internal Intent format used by
	/// the solver system. This includes:
	/// - Computing the order ID via the settler contract
	/// - Parsing order data to extract inputs/outputs
	/// - Creating metadata for the intent
	///
	/// # Arguments
	///
	/// * `order` - The API order to convert
	/// * `provider` - RPC provider for calling contracts
	/// * `signature` - Optional order signature
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
	/// - Order data parsing fails
	/// - No outputs are present in the order
	async fn order_to_intent(
		order_bytes: &Bytes,
		sponsor: &Address,
		signature: &Bytes,
		lock_type: LockType,
		providers: &HashMap<u64, RootProvider<Http<reqwest::Client>>>,
		networks: &NetworksConfig,
	) -> Result<Intent, DiscoveryError> {
		// Parse the StandardOrder
		let order = Self::parse_standard_order(order_bytes)?;

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
					.unwrap_or_else(|| {
						panic!("No input settler compact address found for chain ID {}", origin_chain_id);
					});
				Address::from_slice(&addr.0)
			},
			LockType::Permit2Escrow | LockType::Eip3009Escrow => {
				Address::from_slice(&network.input_settler_address.0)
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
			Self::compute_order_id(order_bytes, provider, settler_address, lock_type).await?;

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
						call: output.call.clone().into(),
						context: output.context.clone().into(),
					}
				})
				.collect(),
			// Include raw order data for openFor
			raw_order_data: Some(with_0x_prefix(&hex::encode(order_bytes))),
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
			quote_id: None, // TODO: add quote id to the intent
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
		provider: &RootProvider<Http<reqwest::Client>>,
		settler_address: Address,
		lock_type: LockType,
	) -> Result<[u8; 32], DiscoveryError> {
		use alloy_sol_types::SolValue;

		match lock_type {
			LockType::ResourceLock => {
				// Resource Lock (TheCompact) - use IInputSettlerCompact
				let std_order = StandardOrder::abi_decode(order_bytes, true).map_err(|e| {
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
				Ok(resp._0.0)
			},
			LockType::Permit2Escrow | LockType::Eip3009Escrow => {
				// Escrow types - use IInputSettlerEscrow
				let escrow = IInputSettlerEscrow::new(settler_address, provider);
				let resp = escrow
					.orderIdentifier(order_bytes.clone())
					.call()
					.await
					.map_err(|e| {
						DiscoveryError::Connection(format!(
							"Failed to get order ID from escrow contract: {}",
							e
						))
					})?;
				Ok(resp._0.0)
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
	/// * `auth_token` - Optional authentication token
	/// * `provider` - RPC provider for contract calls
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
		auth_token: Option<String>,
		providers: HashMap<u64, RootProvider<Http<reqwest::Client>>>,
		networks: NetworksConfig,
		mut shutdown_rx: mpsc::Receiver<()>,
	) -> Result<(), String> {
		let state = ApiState {
			intent_sender,
			auth_token,
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
	Json(request): Json<IntentRequest>,
) -> impl IntoResponse {
	// TODO: Implement authentication
	// if let Some(token) = &state.auth_token {
	//     // Check Authorization header
	// }

	// Parse the StandardOrder from bytes
	let order = match Eip7683OffchainDiscovery::parse_standard_order(&request.order) {
		Ok(order) => order,
		Err(e) => {
			tracing::warn!(error = %e, "Failed to parse StandardOrder from request");
			return (
				StatusCode::BAD_REQUEST,
				Json(IntentResponse {
					order_id: None,
					status: "error".to_string(),
					message: Some(format!("Failed to parse order: {}", e)),
					order: Some(serde_json::Value::String(format!(
						"0x{}",
						hex::encode(&request.order)
					))),
				}),
			)
				.into_response();
		},
	};

	// Validate order
	if let Err(e) =
		Eip7683OffchainDiscovery::validate_order(&order, &request.sponsor, &request.signature).await
	{
		tracing::warn!(error = %e, "Order validation failed");
		return (
			StatusCode::BAD_REQUEST,
			Json(IntentResponse {
				order_id: None,
				status: "error".to_string(),
				message: Some(e.to_string()),
				order: Some(serde_json::Value::String(format!(
					"0x{}",
					hex::encode(&request.order)
				))),
			}),
		)
			.into_response();
	}

	// Convert to intent
	match Eip7683OffchainDiscovery::order_to_intent(
		&request.order,
		&request.sponsor,
		&request.signature,
		request.lock_type,
		&state.providers,
		&state.networks,
	)
	.await
	{
		Ok(intent) => {
			let order_id = intent.id.clone();
			let intent_data = intent.data.clone();

			// Send intent through channel
			if let Err(e) = state.intent_sender.send(intent) {
				tracing::warn!(error = %e, "Failed to send intent to solver channel");
				return (
					StatusCode::INTERNAL_SERVER_ERROR,
					Json(IntentResponse {
						order_id: Some(order_id),
						status: "error".to_string(),
						message: Some(format!("Failed to process intent: {}", e)),
						order: Some(serde_json::Value::String(format!(
							"0x{}",
							hex::encode(&request.order)
						))),
					}),
				)
					.into_response();
			}

			tracing::info!(%order_id, "Intent accepted and forwarded to solver");
			(
				StatusCode::OK,
				Json(IntentResponse {
					order_id: Some(order_id),
					status: "success".to_string(),
					message: None,
					order: Some(serde_json::Value::String(format!(
						"0x{}",
						hex::encode(&request.order)
					))),
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
					status: "error".to_string(),
					message: Some(e.to_string()),
					order: Some(serde_json::Value::String(format!(
						"0x{}",
						hex::encode(&request.order)
					))),
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
///
/// # Optional Fields
///
/// - `auth_token` - Authentication token string for API access
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
			// Optional fields
			vec![
				Field::new("auth_token", FieldType::String),
				Field::new(
					"rate_limit",
					FieldType::Integer {
						min: Some(1),
						max: Some(10000),
					},
				),
			],
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
		let auth_token = self.auth_token.clone();
		let providers = self.providers.clone();
		let networks = self.networks.clone();

		tokio::spawn(async move {
			if let Err(e) = Self::run_server(
				api_host,
				api_port,
				sender,
				auth_token,
				providers,
				networks,
				shutdown_rx,
			)
			.await
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
/// auth_token = "secret"        # optional
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

	let auth_token = config
		.get("auth_token")
		.and_then(|v| v.as_str())
		.map(String::from);

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

	let discovery =
		Eip7683OffchainDiscovery::new(api_host, api_port, auth_token, network_ids, networks)
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
