//! HTTP server for the OIF Solver API.
//!
//! This module provides a minimal HTTP server infrastructure
//! for the OIF Solver API.

use crate::{
	apis::order::get_order_by_id,
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
	if let Some(response) = handle_committed_order(payload.clone()).await {
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

async fn handle_committed_order(payload: Value) -> Option<impl IntoResponse> {
	// Check if this is a quote acceptance submission (contains quoteId)
	if let Some(quote_id) = payload.get("quoteId").and_then(|v| v.as_str()) {
		tracing::info!("Received quote acceptance for quote ID: {}", quote_id);

		// Extract signature if present
		let signature = payload.get("signature").and_then(|v| v.as_str());

		if let Some(sig) = signature {
			tracing::debug!("Quote acceptance signature: {}", sig);
		}

		// Return placeholder response for quote acceptance
		// TODO: Implement actual quote acceptance logic once quote storage is in place
		return Some(
			(
				StatusCode::NOT_IMPLEMENTED,
				Json(serde_json::json!({
					"error": "Quote acceptance not yet implemented",
					"message": "Quote ID submission is recognized but not yet supported",
					"quoteId": quote_id,
					"status": "pending_implementation"
				})),
			)
				.into_response(),
		);
	}
	None
}
