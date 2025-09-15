//! HTTP server for the OIF Solver API.
//!
//! This module provides a minimal HTTP server infrastructure
//! for the OIF Solver API.

use crate::{
	apis::{order::get_order_by_id, quote::cost::CostEngine},
	auth::{auth_middleware, AuthState, JwtService},
};
use alloy_primitives::U256;
use axum::{
	extract::{Extension, Path, State},
	http::StatusCode,
	middleware,
	response::{IntoResponse, Json},
	routing::{get, post},
	Router, ServiceExt,
};
use rust_decimal::Decimal;
use serde_json::Value;
use solver_config::{ApiConfig, Config};
use solver_core::SolverEngine;
use solver_pricing;
use solver_types::{
	api::IntentRequest, APIError, Address, ApiErrorType, CostEstimate, GetOrderResponse,
	GetQuoteRequest, GetQuoteResponse, Order, OrderIdCallback, Transaction,
};
use std::str::FromStr;
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
/// This endpoint processes both quote acceptances and direct order submissions
/// through a unified validation pipeline before forwarding to the discovery service.
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

	// Extract standard, default to eip7683
	let standard = payload
		.get("standard")
		.and_then(|s| s.as_str())
		.unwrap_or("eip7683");

	// Convert payload to IntentRequest
	let intent_request = match extract_intent_request(payload.clone(), &state, standard).await {
		Ok(intent) => intent,
		Err(api_error) => return api_error.into_response(),
	};

	// Validate the IntentRequest
	let validated_order = match validate_intent_request(&intent_request, &state, standard).await {
		Ok(order) => order,
		Err(api_error) => return api_error.into_response(),
	};

	// Estimate costs
	let cost_engine = CostEngine::new();
	let order_cost = cost_engine
		.estimate_cost(&validated_order, &state.solver, &state.config)
		.await;

	// Check profitability if cost estimation succeeded
	if let Ok(cost_estimate) = &order_cost {
		match calculate_order_profitability(&validated_order, cost_estimate, &state.solver).await {
			Ok(profit_margin) => {
				if profit_margin < state.config.solver.min_profitability_pct {
					return APIError::UnprocessableEntity {
						error_type: ApiErrorType::InsufficientProfitability,
						message: format!(
							"Order profit margin {:.2}% below minimum required {:.2}%",
							profit_margin, state.config.solver.min_profitability_pct
						),
						details: Some(serde_json::json!({
							"profit_margin": profit_margin,
							"min_required": state.config.solver.min_profitability_pct,
							"total_cost": cost_estimate.total
						})),
					}
					.into_response();
				}
			},
			Err(e) => {
				tracing::warn!("Failed to calculate profitability: {}", e);
				return APIError::InternalServerError {
					error_type: ApiErrorType::InternalError,
					message: format!("Failed to calculate profitability: {}", e),
				}
				.into_response();
			},
		}
	}

	forward_to_discovery_service(&state, &intent_request).await
}

/// Extracts an IntentRequest from the incoming payload.
/// Handles both quote acceptances (with quoteId) and direct submissions.
async fn extract_intent_request(
	payload: Value,
	state: &AppState,
	standard: &str,
) -> Result<IntentRequest, APIError> {
	// Check if this is a quote acceptance (has quoteId)
	if payload.get("quoteId").and_then(|v| v.as_str()).is_some() {
		// Quote acceptance path
		create_intent_from_quote(payload, state, standard).await
	} else {
		// Direct submission path
		create_intent_from_payload(payload)
	}
}

/// Creates an IntentRequest from a quote acceptance.
async fn create_intent_from_quote(
	payload: Value,
	state: &AppState,
	standard: &str,
) -> Result<IntentRequest, APIError> {
	// Extract required fields
	let quote_id = payload
		.get("quoteId")
		.and_then(|v| v.as_str())
		.ok_or_else(|| APIError::BadRequest {
			error_type: ApiErrorType::MissingSignature,
			message: "Missing quoteId in request".to_string(),
			details: None,
		})?;

	let signature = payload
		.get("signature")
		.and_then(|v| v.as_str())
		.ok_or_else(|| APIError::BadRequest {
			error_type: ApiErrorType::MissingSignature,
			message: "Missing signature for quote acceptance".to_string(),
			details: None,
		})?;

	tracing::info!(
		"Quote acceptance for quote_id: {}, standard: {}",
		quote_id,
		standard
	);

	// Retrieve the quote from storage
	let quote = crate::apis::quote::get_quote_by_id(quote_id, &state.solver)
		.await
		.map_err(|e| {
			tracing::warn!("Failed to retrieve quote {}: {}", quote_id, e);
			APIError::BadRequest {
				error_type: ApiErrorType::QuoteNotFound,
				message: format!("Quote not found: {}", e),
				details: Some(serde_json::json!({"quoteId": quote_id})),
			}
		})?;

	// Convert Quote to IntentRequest using the TryFrom implementation
	(&quote, signature, standard)
		.try_into()
		.map_err(|e| APIError::InternalServerError {
			error_type: ApiErrorType::QuoteConversionFailed,
			message: format!("Failed to convert quote to intent format: {}", e),
		})
}

/// Creates an IntentRequest from a direct payload submission.
fn create_intent_from_payload(payload: Value) -> Result<IntentRequest, APIError> {
	// The payload should already be in IntentRequest format
	// {order: Bytes, sponsor: Address, signature: Bytes, lock_type: LockType}
	serde_json::from_value::<IntentRequest>(payload).map_err(|e| APIError::BadRequest {
		error_type: ApiErrorType::InvalidRequest,
		message: format!("Invalid intent request format: {}", e),
		details: None,
	})
}

/// Validates an IntentRequest and creates an Order.
async fn validate_intent_request(
	intent: &IntentRequest,
	state: &AppState,
	standard: &str,
) -> Result<Order, APIError> {
	// Get the order bytes (already in Bytes format from IntentRequest)
	let order_bytes = &intent.order;

	// Get lock_type as string
	let lock_type = intent.lock_type.as_str();

	// Get solver address from primary account
	let solver_address =
		state
			.solver
			.account()
			.get_address()
			.await
			.map_err(|e| APIError::InternalServerError {
				error_type: ApiErrorType::SolverAddressError,
				message: format!("Failed to get solver address: {}", e),
			})?;

	// Create callback that captures DeliveryService
	let delivery = state.solver.delivery().clone();
	let compute_order_id: OrderIdCallback = Box::new(move |chain_id, tx_data| {
		let delivery = delivery.clone();
		Box::pin(async move {
			// Extract settler address and calldata from tx_data
			if tx_data.len() < 20 {
				return Err("Invalid transaction data: too short".to_string());
			}

			let settler_address = Address(tx_data[0..20].to_vec());
			let calldata = &tx_data[20..];

			let tx = Transaction {
				to: Some(settler_address),
				data: calldata.to_vec(),
				value: U256::ZERO,
				gas_limit: None, // Will be estimated
				gas_price: None, // Will be set by delivery
				max_fee_per_gas: None,
				max_priority_fee_per_gas: None,
				nonce: None, // Will be set by delivery
				chain_id,
			};

			// Execute via DeliveryService
			delivery
				.contract_call(chain_id, tx)
				.await
				.map(|bytes| bytes.to_vec())
				.map_err(|e| format!("Contract call failed: {}", e))
		})
	});

	// Process the order through the OrderService
	// This validates the order based on the standard and returns a validated Order
	state
		.solver
		.order()
		.validate_and_create_order(
			standard,
			order_bytes,
			lock_type,
			compute_order_id,
			&solver_address,
		)
		.await
		.map_err(|e| APIError::BadRequest {
			error_type: ApiErrorType::OrderValidationFailed,
			message: format!("Order validation failed: {}", e),
			details: None,
		})
}

async fn forward_to_discovery_service(
	state: &AppState,
	intent: &IntentRequest,
) -> axum::response::Response {
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

	// Forward the request
	match state
		.http_client
		.post(forward_url)
		.json(intent)
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

/// Calculates the profit margin percentage for an order.
///
/// The profit margin is calculated as:
/// Profit = Total Input Amount (USD) - Total Output Amount (USD) - Execution Costs (USD)
/// Profit Margin = (Profit / Total Input Amount (USD)) * 100
///
/// This represents the percentage profit the solver makes on the input amount.
/// All amounts are converted to USD using the pricing service for accurate comparison.
async fn calculate_order_profitability(
	order: &Order,
	cost_estimate: &CostEstimate,
	solver: &SolverEngine,
) -> Result<Decimal, Box<dyn std::error::Error>> {
	// Parse the order data as Eip7683OrderData
	let order_data: solver_types::Eip7683OrderData = serde_json::from_value(order.data.clone())
		.map_err(|e| format!("Failed to parse order data: {}", e))?;

	let token_manager = solver.token_manager();
	let pricing_service = solver.pricing();

	// Calculate total input amount in USD (sum of all inputs converted to USD)
	let mut total_input_amount_usd = Decimal::ZERO;
	for input in &order_data.inputs {
		// input is [token_address, amount] - extract both
		let token_address_u256 = input[0];
		let amount_u256 = input[1];

		// Convert token address from U256 to Address
		// Token address is stored in the last 20 bytes of the U256
		let mut token_bytes = [0u8; 20];
		let token_u256_bytes = token_address_u256.to_be_bytes::<32>();
		token_bytes.copy_from_slice(&token_u256_bytes[12..32]);
		let token_address = solver_types::Address(token_bytes.to_vec());

		// Get token info
		let token_info = token_manager
			.get_token_info(order_data.origin_chain_id.to::<u64>(), &token_address)
			.map_err(|e| format!("Failed to get token info: {}", e))?;

		// Convert raw amount to USD using pricing service, then normalize
		let usd_amount = convert_raw_token_to_usd(
			&amount_u256,
			&token_info.symbol,
			token_info.decimals,
			pricing_service,
		)
		.await?;

		total_input_amount_usd += Decimal::from_str(&usd_amount)
			.map_err(|e| format!("Failed to parse input USD amount: {}", e))?;
	}

	// Calculate total output amount in USD (sum of all outputs converted to USD)
	let mut total_output_amount_usd = Decimal::ZERO;
	for output in &order_data.outputs {
		// Extract token address from the last 20 bytes of the bytes32 token field
		let mut token_bytes = [0u8; 20];
		token_bytes.copy_from_slice(&output.token[12..32]);
		let token_address = solver_types::Address(token_bytes.to_vec());

		// Get token info
		let token_info = token_manager
			.get_token_info(output.chain_id.to::<u64>(), &token_address)
			.map_err(|e| format!("Failed to get token info: {}", e))?;

		// Convert raw amount to USD using pricing service, then normalize
		let usd_amount = convert_raw_token_to_usd(
			&output.amount,
			&token_info.symbol,
			token_info.decimals,
			pricing_service,
		)
		.await?;

		total_output_amount_usd += Decimal::from_str(&usd_amount)
			.map_err(|e| format!("Failed to parse output USD amount: {}", e))?;
	}

	// Parse execution costs from cost estimate (already in USD)
	let execution_cost_usd = Decimal::from_str(&cost_estimate.total)
		.map_err(|e| format!("Failed to parse execution cost: {}", e))?;

	// Calculate profit: Input (USD) - Output (USD) - Costs (USD)
	let profit_usd = total_input_amount_usd - total_output_amount_usd - execution_cost_usd;

	let hundred = Decimal::new(100_i64, 0);
	let profit_margin_decimal = (profit_usd / total_input_amount_usd) * hundred;

	tracing::debug!(
		"Profitability calculation: input=${} (USD), output=${} (USD), cost=${} (USD), profit=${} (USD), margin={}%",
		total_input_amount_usd,
		total_output_amount_usd,
		execution_cost_usd,
		profit_usd,
		profit_margin_decimal
	);

	Ok(profit_margin_decimal)
}

/// Converts a raw token amount to USD, handling decimals normalization.
async fn convert_raw_token_to_usd(
	raw_amount: &U256,
	token_symbol: &str,
	token_decimals: u8,
	pricing_service: &solver_pricing::PricingService,
) -> Result<String, Box<dyn std::error::Error>> {
	// First normalize the token amount by dividing by 10^decimals
	let raw_amount_str = raw_amount.to_string();
	let raw_amount_decimal = Decimal::from_str(&raw_amount_str)
		.map_err(|e| format!("Failed to parse raw amount: {}", e))?;

	let divisor = Decimal::new(10_i64.pow(token_decimals as u32), 0);
	let normalized_amount = raw_amount_decimal / divisor;

	// Then convert the normalized token amount to USD using the pricing service
	pricing_service
		.convert_asset(token_symbol, "USD", &normalized_amount.to_string())
		.await
		.map_err(|e| format!("Failed to convert {} to USD: {}", token_symbol, e).into())
}
