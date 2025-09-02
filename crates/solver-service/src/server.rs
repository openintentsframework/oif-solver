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
	// Get the discovery service base URL and construct the quote acceptance endpoint
	let discovery_base_url = state
		.discovery_url
		.as_ref()
		.ok_or("Discovery service URL not configured")?
		.trim_end_matches("/intent"); // Remove /intent to get base URL

	let quote_accept_url = format!("{}/quote/accept", discovery_base_url);

	// Create the quote acceptance request
	let quote_request = serde_json::json!({
		"quote": quote,
		"signature": signature
	});

	// Submit to discovery service using the shared HTTP client
	let response = state
		.http_client
		.post(&quote_accept_url)
		.json(&quote_request)
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
