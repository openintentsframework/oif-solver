//! HTTP server for the OIF Solver API.
//!
//! This module provides a minimal HTTP server infrastructure 
//! for the OIF Solver API.

use axum::{
    extract::State,
    response::Json,
    routing::post,
    Router,
};
use solver_config::ApiConfig;
use solver_core::SolverEngine;
use solver_types::{APIError, GetQuoteRequest, GetQuoteResponse};
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
}

/// Starts the HTTP server for the API.
///
/// This function creates and configures the HTTP server with routing,
/// middleware, and error handling for the endpoint.
pub async fn start_server(
    config: ApiConfig,
    solver: Arc<SolverEngine>,
) -> Result<(), Box<dyn std::error::Error>> {
    let app_state = AppState { solver };

    // Build the router with /api base path and quote endpoint
    let app = Router::new()
        .nest("/api", Router::new()
            .route("/quote", post(handle_quote))
        )
        .layer(
            ServiceBuilder::new()
                .layer(CorsLayer::permissive()),
        )
        .with_state(app_state);

    let bind_address = format!("{}:{}", config.host, config.port);
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
    match crate::apis::quote::process_quote_request(request, &state.solver).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => {
            warn!("Quote request failed: {}", e);
            Err(APIError::from(e))
        }
    }
} 



/// Convert QuoteError to APIError with appropriate HTTP status codes.
impl From<crate::apis::quote::QuoteError> for APIError {
    fn from(quote_error: crate::apis::quote::QuoteError) -> Self {
        use crate::apis::quote::QuoteError;
        
        match quote_error {
            QuoteError::InvalidRequest(msg) => APIError::BadRequest {
                error_type: "INVALID_REQUEST".to_string(),
                message: msg,
                details: None,
            },
            QuoteError::UnsupportedAsset(asset) => APIError::UnprocessableEntity {
                error_type: "UNSUPPORTED_ASSET".to_string(),
                message: format!("Asset not supported by solver: {}", asset),
                details: Some(serde_json::json!({ "asset": asset })),
            },
            QuoteError::InsufficientLiquidity => APIError::UnprocessableEntity {
                error_type: "INSUFFICIENT_LIQUIDITY".to_string(),
                message: "Insufficient liquidity available for the requested amount".to_string(),
                details: None,
            },
            QuoteError::SolverCapacityExceeded => APIError::ServiceUnavailable {
                error_type: "SOLVER_CAPACITY_EXCEEDED".to_string(),
                message: "Solver capacity exceeded, please try again later".to_string(),
                retry_after: Some(60), // Suggest retry after 60 seconds
            },
            QuoteError::Internal(msg) => APIError::InternalServerError {
                error_type: "INTERNAL_ERROR".to_string(),
                message: format!("An internal error occurred: {}", msg),
            },
        }
    }
}