//! HTTP server for the OIF Solver API.
//!
//! This module provides a minimal HTTP server infrastructure
//! for the OIF Solver API.

use axum::{
	extract::{Path, State},
	http::StatusCode,
	response::{IntoResponse, Json},
	routing::{get, post},
	Router,
};
use serde_json::Value;
use solver_config::{ApiConfig, Config};
use solver_core::SolverEngine;
use solver_types::{APIError, GetOrderResponse, GetQuoteRequest, GetQuoteResponse};
use std::sync::Arc;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;

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
	let discovery_url = config
		.discovery
		.sources
		.get("offchain_eip7683")
		.map(|discovery_config| {
			let api_host = discovery_config
				.get("api_host")
				.and_then(|v| v.as_str())
				.unwrap_or("127.0.0.1");
			let api_port = discovery_config
				.get("api_port")
				.and_then(|v| v.as_integer())
				.unwrap_or(8081) as u16;
			format!("http://{}:{}/intent", api_host, api_port)
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
				.route("/orders/{id}", get(handle_get_order_by_id)),
		)
		.layer(ServiceBuilder::new().layer(CorsLayer::permissive()))
		.with_state(app_state);

	let bind_address = format!("{}:{}", api_config.host, api_config.port);
	let listener = TcpListener::bind(&bind_address).await?;

	tracing::info!("OIF Solver API server starting on {}", bind_address);

	axum::serve(listener, app).await?;

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
		}
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
		}
	}
}

/// Handles POST /api/orders requests.
///
/// This endpoint forwards intent submission requests to the 7683 discovery API.
/// It acts as a proxy to maintain a consistent API surface where /orders
/// is the standard endpoint for intent submission across different solver implementations.
async fn handle_order(
	State(state): State<AppState>,
	Json(payload): Json<Value>,
) -> impl IntoResponse {
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
		}
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
				}
				Err(e) => {
					tracing::warn!("Failed to parse response from discovery API: {}", e);
					(
						StatusCode::BAD_GATEWAY,
						Json(serde_json::json!({
							"error": "Invalid response from discovery service"
						})),
					)
						.into_response()
				}
			}
		}
		Err(e) => {
			tracing::warn!("Failed to forward request to discovery API: {}", e);
			(
				StatusCode::BAD_GATEWAY,
				Json(serde_json::json!({
					"error": format!("Failed to submit intent: {}", e)
				})),
			)
				.into_response()
		}
	}
}
