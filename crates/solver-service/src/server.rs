//! HTTP server for the OIF Solver API.
//!
//! This module provides a minimal HTTP server infrastructure
//! for the OIF Solver API.

use axum::{
	extract::{Path, State},
	http::StatusCode,
	response::{IntoResponse, Json},
	routing::{get, post},
	Router, ServiceExt,
};
use serde_json::Value;
use solver_config::{ApiConfig, Config};
use solver_core::SolverEngine;
use solver_types::{APIError, GetOrderResponse, GetQuoteRequest, GetQuoteResponse};
use std::sync::Arc;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use tower_http::normalize_path::NormalizePath;

/// Shared application state for the API server.
#[derive(Clone)]
pub struct AppState {
	/// Reference to the solver engine for processing requests.
	pub solver: Arc<SolverEngine>,
	/// Complete configuration.
	pub config: Config,
	/// HTTP client for forwarding requests.
	pub http_client: reqwest::Client,
	/// Discovery service URL for forwarding orders (if configured).
	pub discovery_url: Option<String>,
}

/// Starts the HTTP server for the API.
///
/// This function creates and configures the HTTP server with routing,
/// middleware, and error handling for the endpoint.
pub async fn start_server(
	api_config: ApiConfig,
	solver: Arc<SolverEngine>,
) -> Result<(), Box<dyn std::error::Error>> {
	// Get the full config from the solver engine
	let config = solver.config().clone();

	// Create a reusable HTTP client with connection pooling
	let http_client = reqwest::Client::builder()
		.pool_idle_timeout(std::time::Duration::from_secs(90))
		.pool_max_idle_per_host(10)
		.timeout(std::time::Duration::from_secs(30))
		.build()?;

	// Extract discovery service URL once during startup
	let discovery_url = api_config
		.implementations
		.discovery
		.as_ref()
		.and_then(|discovery_impl| {
			solver.discovery().get_url(discovery_impl).map(|url| {
				// Format as complete URL with /intent endpoint
				format!("http://{}/intent", url)
			})
		});

	if let Some(ref url) = discovery_url {
		tracing::info!("Orders will be forwarded to discovery service at: {}", url);
	} else {
		tracing::warn!("No offchain_eip7683 discovery source configured - /orders endpoint will not be available");
	}

	let app_state = AppState {
		solver,
		config,
		http_client,
		discovery_url,
	};

	// Build the router with /api base path and quote endpoint
	let app = Router::new()
		.nest(
			"/api",
			Router::new()
				.route("/quotes", post(handle_quote))
				.route("/orders", post(handle_order))
				.route("/orders/{id}", get(handle_get_order_by_id))
				.route("/tokens", get(handle_get_tokens))
				.route("/tokens/{chain_id}", get(handle_get_tokens_for_chain)),
		)
		.layer(ServiceBuilder::new().layer(CorsLayer::permissive()))
		.with_state(app_state);

	let bind_address = format!("{}:{}", api_config.host, api_config.port);
	let listener = TcpListener::bind(&bind_address).await?;

	tracing::info!("OIF Solver API server starting on {}", bind_address);

	// Wrap the entire app with NormalizePath to handle trailing slashes
	let app = NormalizePath::trim_trailing_slash(app);
	let service = ServiceExt::<axum::http::Request<axum::body::Body>>::into_make_service(app);

	axum::serve(listener, service).await?;

	Ok(())
}

/// Handles POST /api/quotes requests.
///
/// This endpoint processes quote requests and returns price estimates
/// for cross-chain intents following the ERC-7683 standard.
async fn handle_quote(
	State(state): State<AppState>,
	Json(request): Json<GetQuoteRequest>,
) -> Result<Json<GetQuoteResponse>, APIError> {
	match crate::apis::quote::process_quote_request(request, &state.solver, &state.config).await {
		Ok(response) => Ok(Json(response)),
		Err(e) => {
			tracing::warn!("Quote request failed: {}", e);
			Err(APIError::from(e))
		},
	}
}

/// Handles GET /api/orders/{id} requests.
///
/// This endpoint retrieves order details by ID, providing status information
/// and execution details for cross-chain intent orders.
async fn handle_get_order_by_id(
	Path(id): Path<String>,
	State(state): State<AppState>,
) -> Result<Json<GetOrderResponse>, APIError> {
	match crate::apis::order::get_order_by_id(Path(id), &state.solver).await {
		Ok(response) => Ok(Json(response)),
		Err(e) => {
			tracing::warn!("Order retrieval failed: {}", e);
			Err(APIError::from(e))
		},
	}
}

/// Handles GET /api/tokens requests.
///
/// Returns all supported tokens across all configured networks.
async fn handle_get_tokens(
	State(state): State<AppState>,
) -> Json<crate::apis::tokens::TokensResponse> {
	crate::apis::tokens::get_tokens(State(state.solver)).await
}

/// Handles GET /api/tokens/{chain_id} requests.
///
/// Returns supported tokens for a specific chain.
async fn handle_get_tokens_for_chain(
	Path(chain_id): Path<u64>,
	State(state): State<AppState>,
) -> Result<Json<crate::apis::tokens::NetworkTokens>, StatusCode> {
	crate::apis::tokens::get_tokens_for_chain(Path(chain_id), State(state.solver)).await
}

/// Handles POST /api/orders requests.
///
/// This endpoint forwards intent submission requests to the 7683 discovery API.
/// It acts as a proxy to maintain a consistent API surface where /orders
/// is the standard endpoint for intent submission across different solver implementations.
async fn handle_order(
	State(state): State<AppState>,
	Json(payload): Json<Value>,
) -> axum::response::Response {
	// Check if this is a committed order (quote acceptance)
	if let Some(response) = handle_committed_order(payload.clone(), &state).await {
		return response.into_response();
	}

	// Check if discovery URL is configured
	let forward_url = match &state.discovery_url {
		Some(url) => url,
		None => {
			tracing::warn!("offchain_eip7683 discovery source not configured");
			return (
				StatusCode::SERVICE_UNAVAILABLE,
				Json(serde_json::json!({
					"error": "Intent submission service not configured"
				})),
			)
				.into_response();
		},
	};

	tracing::debug!("Forwarding order submission to: {}", forward_url);

	// Use the shared HTTP client from app state
	// Forward the request
	match state
		.http_client
		.post(forward_url)
		.json(&payload)
		.send()
		.await
	{
		Ok(response) => {
			let status = response.status();
			match response.json::<Value>().await {
				Ok(body) => {
					// Convert reqwest status to axum status
					let axum_status = StatusCode::from_u16(status.as_u16())
						.unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
					(axum_status, Json(body)).into_response()
				},
				Err(e) => {
					tracing::warn!("Failed to parse response from discovery API: {}", e);
					(
						StatusCode::BAD_GATEWAY,
						Json(serde_json::json!({
							"error": "Failed to read response from discovery service"
						})),
					)
						.into_response()
				},
			}
		},
		Err(e) => {
			tracing::warn!("Failed to forward request to discovery API: {}", e);
			(
				StatusCode::BAD_GATEWAY,
				Json(serde_json::json!({
					"error": format!("Failed to submit intent: {}", e)
				})),
			)
				.into_response()
		},
	}
}

async fn handle_committed_order(payload: Value, state: &AppState) -> Option<impl IntoResponse> {
	// Check if this is a quote acceptance submission (contains quoteId)
	if let Some(quote_id) = payload.get("quoteId").and_then(|v| v.as_str()) {
		tracing::info!("Received quote acceptance for quote ID: {}", quote_id);

		// Extract signature if present
		let signature = payload.get("signature").and_then(|v| v.as_str());

		if let Some(sig) = signature {
			tracing::debug!(
				"Quote acceptance detected, retrieving quote from storage and converting to intent"
			);

			// Retrieve the quote from storage using the existing get_quote_by_id function
			match crate::apis::quote::get_quote_by_id(quote_id, &state.solver).await {
				Ok(quote) => {
					// Submit quote to the discovery service for processing
					// This is much simpler than ABI encoding and avoids duplication
					match submit_quote_acceptance(&quote, sig, &state).await {
						Ok(()) => {
							tracing::info!("Quote acceptance processed successfully, intent sent to solver pipeline");
							return Some(
								(
									StatusCode::OK,
									Json(serde_json::json!({
										"message": "Quote accepted and intent submitted to solver pipeline",
										"quoteId": quote_id,
										"status": "received"
									})),
								)
									.into_response(),
							);
						},
						Err(e) => {
							tracing::warn!("Failed to submit quote to discovery service: {}", e);
							return Some(
								(
									StatusCode::INTERNAL_SERVER_ERROR,
									Json(serde_json::json!({
										"error": format!("Failed to process quote: {}", e),
										"quoteId": quote_id
									})),
								)
									.into_response(),
							);
						},
					}
				},
				Err(e) => {
					tracing::warn!("Failed to retrieve quote {}: {}", quote_id, e);
					return Some(
						(
							StatusCode::NOT_FOUND,
							Json(serde_json::json!({
								"error": format!("Quote not found: {}", e),
								"quoteId": quote_id
							})),
						)
							.into_response(),
					);
				},
			}
		} else {
			tracing::warn!("Quote acceptance missing signature");
			return Some(
				(
					StatusCode::BAD_REQUEST,
					Json(serde_json::json!({
						"error": "Signature required for quote acceptance",
						"quoteId": quote_id
					})),
				)
					.into_response(),
			);
		}
	}
	None
}

/// Submit quote acceptance to the discovery service via HTTP request
async fn submit_quote_acceptance(
	quote: &solver_types::api::Quote,
	signature: &str,
	state: &AppState,
) -> Result<(), Box<dyn std::error::Error>> {
	// Get the discovery service URL (should already point to /intent endpoint)
	let intent_url = state
		.discovery_url
		.as_ref()
		.ok_or("Discovery service URL not configured")?;

	// Convert quote to IntentRequest format with encoded StandardOrder
	let intent_request = quote_to_intent_request(quote, signature)?;

	// Submit to discovery service using the shared HTTP client
	let response = state
		.http_client
		.post(intent_url)
		.json(&intent_request)
		.send()
		.await?;

	if response.status().is_success() {
		Ok(())
	} else {
		let error_text = response
			.text()
			.await
			.unwrap_or_else(|_| "Unknown error".to_string());
		Err(format!("Discovery service returned error: {}", error_text).into())
	}
}

/// Convert quote and signature to IntentRequest format
fn quote_to_intent_request(
	quote: &solver_types::api::Quote,
	signature: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
	use alloy_primitives::{Address, U256};
	use alloy_sol_types::SolType;
	use solver_types::standards::eip7930::InteropAddress;

	// Extract user address from the first available input
	let user_str = &quote
		.details
		.available_inputs
		.first()
		.ok_or("Quote must have at least one available input")?
		.user;
	let interop_address = InteropAddress::from_hex(&user_str.to_string())?;
	let user_address = interop_address.ethereum_address()?;

	// Extract order data from quote
	let quote_order = quote
		.orders
		.first()
		.ok_or("Quote must contain at least one order")?;
	let message_data = quote_order
		.message
		.as_object()
		.ok_or("Invalid EIP-712 message structure")?;
	let eip712_data = message_data
		.get("eip712")
		.and_then(|e| e.as_object())
		.ok_or("Missing 'eip712' object in message")?;

	// Extract nonce
	let nonce_str = eip712_data
		.get("nonce")
		.and_then(|n| n.as_str())
		.ok_or("Missing nonce in EIP-712 data")?;
	let nonce = U256::from_str_radix(nonce_str, 10)?;

	// Extract witness data
	let witness = eip712_data
		.get("witness")
		.and_then(|w| w.as_object())
		.ok_or("Missing 'witness' object in EIP-712 message")?;

	// Get origin chain ID
	let origin_chain_id = U256::from(interop_address.ethereum_chain_id()?);

	// Extract timing data
	let expires = witness
		.get("expires")
		.and_then(|e| e.as_u64())
		.unwrap_or(quote.valid_until.unwrap_or(0)) as u32;
	let fill_deadline = expires;

	// Extract input oracle
	let input_oracle_str = witness
		.get("inputOracle")
		.and_then(|o| o.as_str())
		.unwrap_or("0x0000000000000000000000000000000000000000");
	let input_oracle =
		Address::from_slice(&hex::decode(input_oracle_str.trim_start_matches("0x"))?);

	// Extract input data from permitted array
	let permitted = eip712_data
		.get("permitted")
		.and_then(|p| p.as_array())
		.ok_or("Missing permitted array in EIP-712 data")?;
	let first_permitted = permitted
		.first()
		.ok_or("Empty permitted array in EIP-712 data")?;

	let input_amount_str = first_permitted
		.get("amount")
		.and_then(|a| a.as_str())
		.ok_or("Missing amount in permitted token")?;
	let input_amount = U256::from_str_radix(input_amount_str, 10)?;

	let input_token_str = first_permitted
		.get("token")
		.and_then(|t| t.as_str())
		.ok_or("Missing token in permitted array")?;
	let input_token = Address::from_slice(&hex::decode(input_token_str.trim_start_matches("0x"))?);

	// Convert input token address to U256
	let mut token_bytes = [0u8; 32];
	token_bytes[12..32].copy_from_slice(&input_token.0 .0);
	let input_token_u256 = U256::from_be_bytes(token_bytes);
	let inputs = vec![[input_token_u256, input_amount]];

	// Extract outputs from witness
	let default_outputs = Vec::new();
	let witness_outputs = witness
		.get("outputs")
		.and_then(|o| o.as_array())
		.unwrap_or(&default_outputs);

	// Parse outputs with proper helper function for hex parsing
	fn parse_bytes32_from_hex(hex_str: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
		let hex_clean = hex_str.trim_start_matches("0x");
		if hex_clean.len() != 64 {
			return Err("Hex string must be exactly 64 characters (32 bytes)".into());
		}
		let mut bytes = [0u8; 32];
		hex::decode_to_slice(hex_clean, &mut bytes)?;
		Ok(bytes)
	}

	let mut sol_outputs = Vec::new();
	for output_item in witness_outputs {
		if let Some(output_obj) = output_item.as_object() {
			let chain_id = output_obj
				.get("chainId")
				.and_then(|c| c.as_u64())
				.unwrap_or(0);
			let amount_str = output_obj
				.get("amount")
				.and_then(|a| a.as_str())
				.unwrap_or("0");
			let token_str = output_obj
				.get("token")
				.and_then(|t| t.as_str())
				.unwrap_or("0x0000000000000000000000000000000000000000000000000000000000000000");
			let recipient_str = output_obj
				.get("recipient")
				.and_then(|r| r.as_str())
				.unwrap_or("0x0000000000000000000000000000000000000000000000000000000000000000");
			let oracle_str = output_obj
				.get("oracle")
				.and_then(|o| o.as_str())
				.unwrap_or("0x0000000000000000000000000000000000000000000000000000000000000000");
			let settler_str = output_obj
				.get("settler")
				.and_then(|s| s.as_str())
				.unwrap_or("0x0000000000000000000000000000000000000000000000000000000000000000");

			if let Ok(amount) = U256::from_str_radix(amount_str, 10) {
				let token_bytes = parse_bytes32_from_hex(token_str).unwrap_or([0u8; 32]);
				let recipient_bytes = parse_bytes32_from_hex(recipient_str).unwrap_or([0u8; 32]);
				let oracle_bytes = parse_bytes32_from_hex(oracle_str).unwrap_or([0u8; 32]);
				let settler_bytes = parse_bytes32_from_hex(settler_str).unwrap_or([0u8; 32]);

				// Import the SolMandateOutput type from the discovery module
				use solver_discovery::implementations::offchain::_7683::SolMandateOutput;

				sol_outputs.push(SolMandateOutput {
					oracle: oracle_bytes.into(),
					settler: settler_bytes.into(),
					chainId: U256::from(chain_id),
					token: token_bytes.into(),
					amount,
					recipient: recipient_bytes.into(),
					call: Vec::new().into(),
					context: Vec::new().into(),
				});
			}
		}
	}

	// Create and encode the StandardOrder
	use solver_discovery::implementations::offchain::_7683::StandardOrder;
	let sol_order = StandardOrder {
		user: user_address,
		nonce,
		originChainId: origin_chain_id,
		expires,
		fillDeadline: fill_deadline,
		inputOracle: input_oracle,
		inputs,
		outputs: sol_outputs,
	};

	// ABI encode the StandardOrder
	let encoded_order = StandardOrder::abi_encode(&sol_order);

	// Parse signature to bytes
	// let signature_bytes = Bytes::from_hex(signature)?;

	// Extract lock type from quote data or default to permit2_escrow
	let lock_type = extract_lock_type_from_quote(quote).unwrap_or("permit2_escrow".to_string());

	// Create IntentRequest
	let intent_request = serde_json::json!({
		"order": format!("0x{}", hex::encode(&encoded_order)),
		"sponsor": format!("{:#x}", user_address),
		"signature": signature,
		"lockType": lock_type
	});

	Ok(intent_request)
}

/// Extract lock type from quote data
fn extract_lock_type_from_quote(quote: &solver_types::api::Quote) -> Option<String> {
	// First check the direct lock_type field on the quote
	if !quote.lock_type.is_empty() {
		return Some(quote.lock_type.clone());
	}

	// Check if the quote contains lock type information in order data or witness data
	if let Some(quote_order) = quote.orders.first() {
		if let Some(message_data) = quote_order.message.as_object() {
			// Check for lock type in the main message data
			if let Some(lock_type) = message_data.get("lockType").and_then(|v| v.as_str()) {
				return Some(lock_type.to_string());
			}

			// Check for lock type in EIP-712 data
			if let Some(eip712_data) = message_data.get("eip712").and_then(|e| e.as_object()) {
				if let Some(lock_type) = eip712_data.get("lockType").and_then(|v| v.as_str()) {
					return Some(lock_type.to_string());
				}

				// Check witness data for lock type
				if let Some(witness) = eip712_data.get("witness").and_then(|w| w.as_object()) {
					if let Some(lock_type) = witness.get("lockType").and_then(|v| v.as_str()) {
						return Some(lock_type.to_string());
					}
				}
			}
		}
	}

	None
}
