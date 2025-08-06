//! HTTP server for the OIF Solver API.
//!
//! This module provides a minimal HTTP server infrastructure
//! for the OIF Solver API.

use axum::{
	extract::{Path, State},
	response::Json,
	routing::{get, post},
	Router,
};
use solver_config::{ApiConfig, Config};
use solver_core::SolverEngine;
use solver_types::{APIError, GetOrderResponse, GetQuoteRequest, GetQuoteResponse};
use std::sync::Arc;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use tracing::{info, warn};

/// Shared application state for the API server.
#[derive(Clone)]
pub struct AppState {
	/// Reference to the solver engine for processing requests.
	pub solver: Arc<SolverEngine>,
	/// Complete configuration.
	pub config: Config,
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

	let app_state = AppState { solver, config };

	// Build the router with /api base path and quote endpoint
	let app = Router::new()
		.nest(
			"/api",
			Router::new()
				.route("/quote", post(handle_quote))
				.route("/order/{id}", get(handle_get_order_by_id)),
		)
		.layer(ServiceBuilder::new().layer(CorsLayer::permissive()))
		.with_state(app_state);

	let bind_address = format!("{}:{}", api_config.host, api_config.port);
	let listener = TcpListener::bind(&bind_address).await?;

	info!("OIF Solver API server starting on {}", bind_address);

	axum::serve(listener, app).await?;

	Ok(())
}

/// Handles POST /api/quote requests.
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
			warn!("Quote request failed: {}", e);
			Err(APIError::from(e))
		}
	}
}

/// Handles GET /api/order/{id} requests.
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
			warn!("Order retrieval failed: {}", e);
			Err(APIError::from(e))
		}
	}
}
