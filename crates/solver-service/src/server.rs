//! HTTP server for the OIF Solver API.
//!
//! This module provides a minimal HTTP server infrastructure
//! for the OIF Solver API.

use crate::{
	apis::{order::get_order_by_id, quote::cost::engine::CostEngine},
	auth::{auth_middleware, AuthState, JwtService},
};
use axum::{
	extract::{Extension, Path, State},
	http::StatusCode,
	middleware,
	response::{IntoResponse, Json},
	routing::{get, post},
	Router, ServiceExt,
};
use serde_json::Value;
use solver_config::{ApiConfig, Config};
use solver_core::SolverEngine;
use solver_types::{
	standards::eip7683::interfaces::StandardOrder, APIError, GetOrderResponse, GetQuoteRequest,
	GetQuoteResponse,
};
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
	/// JWT service for authentication (if configured).
	pub jwt_service: Option<Arc<JwtService>>,
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

	// Initialize JWT service if auth is enabled
	let jwt_service = match &api_config.auth {
		Some(auth_config) if auth_config.enabled => match JwtService::new(auth_config.clone()) {
			Ok(service) => {
				tracing::info!(
					"API authentication enabled with issuer: {}",
					auth_config.issuer
				);
				Some(Arc::new(service))
			},
			Err(e) => {
				tracing::error!("Failed to initialize JWT service: {}", e);
				return Err(e.into());
			},
		},
		_ => {
			tracing::info!("API authentication disabled");
			None
		},
	};

	let app_state = AppState {
		solver,
		config,
		http_client,
		discovery_url,
		jwt_service: jwt_service.clone(),
	};

	// Build the router with /api base path and quote endpoint
	let mut api_routes = Router::new()
		.route("/register", post(handle_register))
		.route("/quotes", post(handle_quote))
		.route("/tokens", get(handle_get_tokens))
		.route("/tokens/{chain_id}", get(handle_get_tokens_for_chain));

	// Create order routes with optional auth
	let mut order_routes = Router::new()
		.route("/orders", post(handle_order))
		.route("/orders/{id}", get(handle_get_order_by_id));

	// Apply auth middleware to order routes if enabled
	if let Some(jwt) = &jwt_service {
		// POST /orders requires CreateOrders scope
		let order_post_route = Router::new().route("/orders", post(handle_order)).layer(
			middleware::from_fn_with_state(
				AuthState {
					jwt_service: jwt.clone(),
					required_scope: solver_types::AuthScope::CreateOrders,
				},
				auth_middleware,
			),
		);

		// GET /orders/{id} requires ReadOrders scope
		let order_get_route = Router::new()
			.route("/orders/{id}", get(handle_get_order_by_id))
			.layer(middleware::from_fn_with_state(
				AuthState {
					jwt_service: jwt.clone(),
					required_scope: solver_types::AuthScope::ReadOrders,
				},
				auth_middleware,
			));

		order_routes = order_post_route.merge(order_get_route);
	}

	// Combine all routes
	api_routes = api_routes.merge(order_routes);

	let app = Router::new()
		.nest("/api", api_routes)
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
	claims: Option<Extension<solver_types::JwtClaims>>,
) -> Result<Json<GetOrderResponse>, APIError> {
	// Log authenticated access if JWT claims are present
	if let Some(Extension(claims)) = &claims {
		tracing::info!(
			client_id = %claims.sub,
			order_id = %id,
			"Authenticated order retrieval"
		);
	}
	match get_order_by_id(Path(id), &state.solver, claims).await {
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

/// Handles POST /api/register requests.
///
/// This endpoint allows clients to self-register and receive JWT tokens
/// for API authentication.
async fn handle_register(
	State(state): State<AppState>,
	Json(payload): Json<crate::apis::register::RegisterRequest>,
) -> impl IntoResponse {
	crate::apis::register::register_client(State(state.jwt_service), Json(payload)).await
}

/// Handles POST /api/orders requests.
///
/// This endpoint forwards intent submission requests to the 7683 discovery API.
/// It acts as a proxy to maintain a consistent API surface where /orders
/// is the standard endpoint for intent submission across different solver implementations.
async fn handle_order(
	State(state): State<AppState>,
	claims: Option<Extension<solver_types::JwtClaims>>,
	Json(payload): Json<Value>,
) -> axum::response::Response {
	// Log authenticated access if JWT claims are present
	if let Some(Extension(claims)) = &claims {
		tracing::info!(
			client_id = %claims.sub,
			"Authenticated order submission"
		);
	}

	// Check if this is a committed order (quote acceptance)
	if let Some(result) = handle_committed_order(payload.clone(), &state).await {
		return match result {
			Ok(result) => result.into_response(),
			Err(api_error) => api_error.into_response(),
		};
	}

	// Validate order before forwarding
	let validated_order = match validate_order_submission(&payload, &state).await {
		Ok(order) => order,
		Err(validation_error) => {
			return validation_error.into_response();
		},
	};

	let lock_type = payload
		.get("lock_type")
		.and_then(|b| b.as_str())
		.and_then(|s| match s {
			"1" => Some("permit2_escrow"),
			"2" => Some("eip3009_escrow"),
			"3" => Some("resource_lock"),
			_ => None,
		})
		.unwrap_or("permit2_escrow"); // TODO: should we default to permit2_escrow?

	// Use CostEngine for order cost estimation
	let cost_engine = CostEngine::new();
	let _order_cost = cost_engine
		.estimate_order_cost(&validated_order, lock_type, &state.solver, &state.config)
		.await;

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

	// Forward the request (existing logic)
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

/// Validates order submission and estimates cost
async fn validate_order_submission(
	payload: &Value,
	state: &AppState,
) -> Result<StandardOrder, APIError> {
	// Extract order bytes from payload
	let order_bytes_hex = payload
		.get("order")
		.and_then(|b| b.as_str())
		.ok_or_else(|| APIError::BadRequest {
			error_type: "MISSING_ORDER_BYTES".to_string(),
			message: "Missing order field in request".to_string(),
			details: None,
		})?;

	// Decode hex to bytes
	let order_bytes = hex::decode(order_bytes_hex.trim_start_matches("0x")).map_err(|_| {
		APIError::BadRequest {
			error_type: "INVALID_HEX_ENCODING".to_string(),
			message: "Invalid hex encoding in orderBytes".to_string(),
			details: None,
		}
	})?;

	// Validate order using OrderService
	let standard = "eip7683"; // Default to EIP-7683
	let order = state
		.solver
		.order()
		.validate_order(standard, &order_bytes.into())
		.await
		.map_err(|e| APIError::BadRequest {
			error_type: "ORDER_VALIDATION_FAILED".to_string(),
			message: format!("Order validation failed: {}", e),
			details: None,
		})?;

	Ok(order)
}

async fn handle_committed_order(
	payload: Value,
	state: &AppState,
) -> Option<Result<impl IntoResponse, APIError>> {
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
			let quote = match crate::apis::quote::get_quote_by_id(quote_id, &state.solver).await {
				Ok(quote) => quote,
				Err(e) => {
					tracing::warn!("Failed to retrieve quote {}: {}", quote_id, e);
					return Some(Err(APIError::BadRequest {
						error_type: "QUOTE_NOT_FOUND".to_string(),
						message: format!("Quote not found: {}", e),
						details: Some(serde_json::json!({"quoteId": quote_id})),
					}));
				},
			};

			// Submit quote to the discovery service for processing
			if let Err(e) = submit_quote_acceptance(&quote, sig, state).await {
				tracing::warn!("Failed to submit quote to discovery service: {}", e);
				return Some(Err(APIError::InternalServerError {
					error_type: "QUOTE_PROCESSING_FAILED".to_string(),
					message: format!("Failed to process quote: {}", e),
				}));
			}

			tracing::info!(
				"Quote acceptance processed successfully, intent sent to solver pipeline"
			);
			Some(Ok(Json(serde_json::json!({
				"message": "Quote accepted and intent submitted to solver pipeline",
				"quoteId": quote_id,
				"status": "received"
			}))
			.into_response()))
		} else {
			tracing::warn!("Quote acceptance missing signature");
			Some(Err(APIError::BadRequest {
				error_type: "MISSING_SIGNATURE".to_string(),
				message: "Signature required for quote acceptance".to_string(),
				details: Some(serde_json::json!({"quoteId": quote_id})),
			}))
		}
	} else {
		// Not a committed order, return None to indicate no handling needed
		None
	}
}

/// Submit quote acceptance to the discovery service via HTTP request
async fn submit_quote_acceptance(
	quote: &solver_types::api::Quote,
	signature: &str,
	state: &AppState,
) -> Result<(), APIError> {
	// Get the discovery service URL (should already point to /intent endpoint)
	let intent_url = state
		.discovery_url
		.as_ref()
		.ok_or_else(|| APIError::InternalServerError {
			error_type: "DISCOVERY_SERVICE_NOT_CONFIGURED".to_string(),
			message: "Discovery service URL not configured".to_string(),
		})?;

	// Convert quote to IntentRequest format with encoded StandardOrder
	let intent_request: serde_json::Value =
		solver_types::api::QuoteWithSignature::from((quote, signature))
			.try_into()
			.map_err(|e| APIError::InternalServerError {
				error_type: "QUOTE_CONVERSION_FAILED".to_string(),
				message: format!("Failed to convert quote to intent format: {}", e),
			})?;

	// Submit to discovery service using the shared HTTP client
	let response = state
		.http_client
		.post(intent_url)
		.json(&intent_request)
		.send()
		.await
		.map_err(|e| APIError::ServiceUnavailable {
			error_type: "DISCOVERY_SERVICE_UNAVAILABLE".to_string(),
			message: format!("Failed to submit to discovery service: {}", e),
			retry_after: Some(30),
		})?;

	if response.status().is_success() {
		Ok(())
	} else {
		let error_text = response
			.text()
			.await
			.unwrap_or_else(|_| "Unknown error".to_string());
		Err(APIError::ServiceUnavailable {
			error_type: "DISCOVERY_SERVICE_ERROR".to_string(),
			message: format!("Discovery service returned error: {}", error_text),
			retry_after: Some(30),
		})
	}
}
