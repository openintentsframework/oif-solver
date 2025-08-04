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
use serde::{Deserialize, Serialize};
use solver_types::{
	standards::eip7683::MandateOutput, ConfigSchema, Eip7683OrderData, Field, FieldType, Intent,
	IntentMetadata, Schema,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tower_http::cors::CorsLayer;

/// Helper function to get current timestamp, returns 0 if system time is before UNIX epoch
fn current_timestamp() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

// Import the Solidity types for the OIF contracts
sol! {
	#[sol(rpc)]
	interface IInputSettlerEscrow {
		function orderIdentifier(bytes calldata order) external view returns (bytes32);
		function openFor(bytes calldata order, address sponsor, bytes calldata signature) external;
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

/// API request wrapper for intent submission.
///
/// This is the top-level structure for POST /intent requests with the OIF format.
///
/// # Fields
///
/// * `order` - The StandardOrder encoded as hex bytes
/// * `sponsor` - The address sponsoring the order (usually the user)
/// * `signature` - The Permit2Witness signature
#[derive(Debug, Deserialize)]
struct IntentRequest {
	order: Bytes,
	sponsor: Address,
	signature: Bytes,
}

/// API response for intent submission.
///
/// Returned by the POST /intent endpoint to indicate submission status.
///
/// # Fields
///
/// * `order_id` - The computed order ID (hex encoded)
/// * `status` - Either "success" or "error"
/// * `message` - Optional error message when status is "error"
#[derive(Debug, Serialize)]
struct IntentResponse {
	order_id: String,
	status: String, // error | success
	message: Option<String>,
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
/// * `settler_address` - Address of the settler contract
#[derive(Clone)]
struct ApiState {
	/// Channel to send discovered intents
	intent_sender: mpsc::UnboundedSender<Intent>,
	/// Optional authentication token
	#[allow(dead_code)]
	auth_token: Option<String>,
	/// RPC provider for calling settler contracts
	provider: RootProvider<Http<reqwest::Client>>,
	/// Settler contract address
	settler_address: Address,
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
	/// RPC provider for calling settler contracts
	provider: RootProvider<Http<reqwest::Client>>,
	/// Settler contract address
	settler_address: Address,
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
	/// * `rpc_url` - Ethereum RPC URL for calling settler contracts
	/// * `settler_address` - Address of the settler contract
	///
	/// # Returns
	///
	/// Returns a new discovery instance or an error if the RPC URL is invalid.
	///
	/// # Errors
	///
	/// Returns `DiscoveryError::Connection` if the RPC URL cannot be parsed.
	/// Returns `DiscoveryError::ValidationError` if the settler address is invalid.
	pub fn new(
		api_host: String,
		api_port: u16,
		auth_token: Option<String>,
		rpc_url: String,
		settler_address: String,
	) -> Result<Self, DiscoveryError> {
		let provider = RootProvider::new_http(
			rpc_url
				.parse()
				.map_err(|e| DiscoveryError::Connection(format!("Invalid RPC URL: {}", e)))?,
		);

		let settler_address = settler_address.parse::<Address>().map_err(|e| {
			DiscoveryError::ValidationError(format!("Invalid settler address: {}", e))
		})?;

		Ok(Self {
			api_host,
			api_port,
			auth_token,
			provider,
			settler_address,
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
		provider: &RootProvider<Http<reqwest::Client>>,
		settler_address: Address,
	) -> Result<Intent, DiscoveryError> {
		// Parse the StandardOrder
		let order = Self::parse_standard_order(order_bytes)?;

		// Generate order ID from order data
		let order_id = Self::compute_order_id(order_bytes, provider, settler_address).await?;

		// Validate that order has outputs
		if order.outputs.is_empty() {
			return Err(DiscoveryError::ValidationError(
				"Order must have at least one output".to_string(),
			));
		}

		// Convert to intent format
		let order_data = Eip7683OrderData {
			user: format!("0x{}", hex::encode(order.user)),
			nonce: order.nonce,
			origin_chain_id: order.originChainId,
			expires: order.expires,
			fill_deadline: order.fillDeadline,
			input_oracle: format!("0x{}", hex::encode(order.inputOracle)),
			inputs: order.inputs.clone(),
			order_id,
			settle_gas_limit: 200_000u64, // TODO: calculate exactly
			fill_gas_limit: 200_000u64,   // TODO: calculate exactly
			outputs: order
				.outputs
				.iter()
				.map(|output| MandateOutput {
					oracle: output.oracle.0,
					settler: output.settler.0,
					chain_id: output.chainId,
					token: output.token.0,
					amount: output.amount,
					recipient: output.recipient.0,
					call: output.call.clone().into(),
					context: output.context.clone().into(),
				})
				.collect(),
			// Include raw order data for openFor
			raw_order_data: Some(format!("0x{}", hex::encode(order_bytes))),
			// Include signature and sponsor
			signature: Some(format!("0x{}", hex::encode(signature))),
			sponsor: Some(sponsor.to_string()),
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
		})
	}

	/// Computes order ID from order data.
	///
	/// Calls the `orderIdentifier` function on the origin settler contract
	/// to compute the canonical order ID for the given order.
	///
	/// # Arguments
	///
	/// * `order` - The order to compute ID for
	/// * `provider` - RPC provider for calling the settler contract
	///
	/// # Returns
	///
	/// Returns the 32-byte order ID.
	///
	/// # Errors
	///
	/// Returns `DiscoveryError::Connection` if the contract call fails.
	async fn compute_order_id(
		order_bytes: &Bytes,
		provider: &RootProvider<Http<reqwest::Client>>,
		settler_address: Address,
	) -> Result<[u8; 32], DiscoveryError> {
		let settler = IInputSettlerEscrow::new(settler_address, provider);

		let order_id = settler
			.orderIdentifier(order_bytes.clone())
			.call()
			.await
			.map_err(|e| {
				DiscoveryError::Connection(format!("Failed to get order ID from contract: {}", e))
			})?;

		Ok(order_id._0.0)
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
	/// * `settler_address` - Address of the settler contract
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
		provider: RootProvider<Http<reqwest::Client>>,
		settler_address: Address,
		mut shutdown_rx: mpsc::Receiver<()>,
	) -> Result<(), String> {
		let state = ApiState {
			intent_sender,
			auth_token,
			provider,
			settler_address,
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
			return (
				StatusCode::BAD_REQUEST,
				Json(IntentResponse {
					order_id: String::new(),
					status: "error".to_string(),
					message: Some(format!("Failed to parse order: {}", e)),
				}),
			)
				.into_response();
		}
	};

	// Validate order
	if let Err(e) =
		Eip7683OffchainDiscovery::validate_order(&order, &request.sponsor, &request.signature).await
	{
		return (
			StatusCode::BAD_REQUEST,
			Json(IntentResponse {
				order_id: String::new(),
				status: "error".to_string(),
				message: Some(e.to_string()),
			}),
		)
			.into_response();
	}

	// Get settler address from the API state
	let settler_address = state.settler_address;

	// Convert to intent
	match Eip7683OffchainDiscovery::order_to_intent(
		&request.order,
		&request.sponsor,
		&request.signature,
		&state.provider,
		settler_address,
	)
	.await
	{
		Ok(intent) => {
			let order_id = intent.id.clone();

			// Send intent through channel
			if let Err(e) = state.intent_sender.send(intent) {
				return (
					StatusCode::INTERNAL_SERVER_ERROR,
					Json(IntentResponse {
						order_id,
						status: "error".to_string(),
						message: Some(format!("Failed to process intent: {}", e)),
					}),
				)
					.into_response();
			}

			(
				StatusCode::OK,
				Json(IntentResponse {
					order_id,
					status: "success".to_string(),
					message: None,
				}),
			)
				.into_response()
		}
		Err(e) => (
			StatusCode::BAD_REQUEST,
			Json(IntentResponse {
				order_id: String::new(),
				status: "error".to_string(),
				message: Some(e.to_string()),
			}),
		)
			.into_response(),
	}
}

/// Configuration schema for EIP-7683 offchain discovery.
///
/// Defines and validates the configuration parameters required
/// for the off-chain discovery service. This schema ensures
/// all required fields are present and have valid values.
///
/// # Required Fields
///
/// - `api_port` - Port number (1-65535)
/// - `api_host` - Host address string
/// - `rpc_url` - HTTP(S) URL for Ethereum RPC
///
/// # Optional Fields
///
/// - `auth_token` - Authentication token string
/// - `rate_limit` - Request rate limit (1-10000)
pub struct Eip7683OffchainDiscoverySchema;

impl ConfigSchema for Eip7683OffchainDiscoverySchema {
	fn validate(&self, config: &toml::Value) -> Result<(), solver_types::ValidationError> {
		let schema = Schema::new(
			// Required fields
			vec![
				Field::new(
					"api_port",
					FieldType::Integer {
						min: Some(1),
						max: Some(65535),
					},
				),
				Field::new("api_host", FieldType::String),
				Field::new("rpc_url", FieldType::String).with_validator(|value| {
					match value.as_str() {
						Some(url) => {
							if url.starts_with("http://") || url.starts_with("https://") {
								Ok(())
							} else {
								Err("RPC URL must start with http:// or https://".to_string())
							}
						}
						None => Err("Expected string value for rpc_url".to_string()),
					}
				}),
				Field::new("settler_address", FieldType::String).with_validator(
					|value| match value.as_str() {
						Some(addr) => {
							if addr.len() != 42 || !addr.starts_with("0x") {
								Err("settler_address must be a valid Ethereum address".to_string())
							} else {
								Ok(())
							}
						}
						None => Err("Expected string value for settler_address".to_string()),
					},
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
		let provider = self.provider.clone();
		let settler_address = self.settler_address;

		tokio::spawn(async move {
			if let Err(e) = Self::run_server(
				api_host,
				api_port,
				sender,
				auth_token,
				provider,
				settler_address,
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
/// rpc_url = "https://..."      # required
/// settler_address = "0x..."    # required
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - `rpc_url` is not provided in the configuration
/// - `settler_address` is not provided in the configuration
/// - The discovery service cannot be created
pub fn create_discovery(
	config: &toml::Value,
) -> Result<Box<dyn DiscoveryInterface>, DiscoveryError> {
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

	let rpc_url = config
		.get("rpc_url")
		.and_then(|v| v.as_str())
		.ok_or_else(|| DiscoveryError::ValidationError("rpc_url is required".to_string()))?
		.to_string();

	let settler_address = config
		.get("settler_address")
		.and_then(|v| v.as_str())
		.ok_or_else(|| DiscoveryError::ValidationError("settler_address is required".to_string()))?
		.to_string();

	let discovery =
		Eip7683OffchainDiscovery::new(api_host, api_port, auth_token, rpc_url, settler_address)
			.map_err(|e| {
				DiscoveryError::Connection(format!(
					"Failed to create offchain discovery service: {}",
					e
				))
			})?;

	Ok(Box::new(discovery))
}
