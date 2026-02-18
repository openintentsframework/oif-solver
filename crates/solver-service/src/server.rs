//! HTTP server for the OIF Solver API.
//!
//! This module provides a minimal HTTP server infrastructure
//! for the OIF Solver API.

use crate::{
	apis::admin::{
		handle_add_admin, handle_add_token, handle_approve_tokens, handle_get_balances,
		handle_get_config, handle_get_fees, handle_get_gas, handle_get_nonce, handle_get_types,
		handle_remove_admin, handle_remove_token, handle_update_fees, handle_update_gas,
		handle_withdrawal, AdminApiState,
	},
	apis::health::handle_health,
	apis::order::get_order_by_id,
	auth::{admin::AdminActionVerifier, auth_middleware, AuthState, JwtService},
	config_merge::config_to_operator_config,
	validators::order::ensure_user_capacity_for_order,
	validators::signature::SignatureValidationService,
};
use alloy_primitives::U256;
use axum::{
	extract::{ConnectInfo, Extension, Path, State},
	http::{HeaderMap, StatusCode},
	middleware,
	response::{IntoResponse, Json},
	routing::{delete, get, post, put},
	Router, ServiceExt,
};
use serde_json::Value;
use solver_config::{ApiConfig, Config};
use solver_core::SolverEngine;
use solver_storage::{
	config_store::create_config_store,
	nonce_store::{create_nonce_store, create_nonce_store_with_namespace, NonceStore},
	StoreConfig,
};
use solver_types::{
	api::PostOrderRequest, standards::eip7683::interfaces::StandardOrder, APIError, Address,
	ApiErrorType, GetOrderResponse, GetQuoteRequest, GetQuoteResponse, OperatorConfig, Order,
	OrderIdCallback, Transaction,
};
use std::{convert::TryInto, net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use tower_http::normalize_path::NormalizePath;

/// Shared application state for the API server.
#[derive(Clone)]
pub struct AppState {
	/// Reference to the solver engine for processing requests.
	pub solver: Arc<SolverEngine>,
	/// Shared runtime config that gets hot-reloaded by admin API.
	/// Always use this for reading current config (tokens, networks, etc.).
	pub config: Arc<RwLock<Config>>,
	/// HTTP client for forwarding requests.
	pub http_client: reqwest::Client,
	/// Discovery service URL for forwarding orders (if configured).
	pub discovery_url: Option<String>,
	/// JWT service for authentication (if configured).
	pub jwt_service: Option<Arc<JwtService>>,
	/// Dedicated nonce store for SIWE authentication (if configured).
	pub siwe_nonce_store: Option<Arc<NonceStore>>,
	/// Signature validation service for different order standards.
	pub signature_validation: Arc<SignatureValidationService>,
}

/// Starts the HTTP server for the API.
///
/// This function creates and configures the HTTP server with routing,
/// middleware, and error handling for the endpoint.
pub async fn start_server(
	api_config: ApiConfig,
	solver: Arc<SolverEngine>,
) -> Result<(), Box<dyn std::error::Error>> {
	// Get the dynamic config from the solver engine for hot-reload support.
	// This is the SAME Arc used by the solver - admin API updates will propagate immediately.
	let dynamic_config = solver.dynamic_config().clone();
	// Get a snapshot for reading config values during setup
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
				format!("http://{url}/intent")
			})
		});

	if let Some(ref url) = discovery_url {
		tracing::info!("Orders will be forwarded to discovery service at: {}", url);
	} else {
		tracing::warn!("No offchain_eip7683 discovery source configured - /orders endpoint will not be available");
	}

	// Initialize JWT service if auth config exists (needed for admin endpoints even if orders auth is disabled)
	let jwt_service = match &api_config.auth {
		Some(auth_config) => match JwtService::new(auth_config.clone()) {
			Ok(service) => {
				if auth_config.enabled {
					tracing::info!(
						"API authentication enabled for orders with issuer: {}",
						auth_config.issuer
					);
				} else {
					tracing::info!("JWT service initialized for admin auth (orders auth disabled)");
				}
				Some(Arc::new(service))
			},
			Err(e) => {
				tracing::error!("Failed to initialize JWT service: {}", e);
				return Err(e.into());
			},
		},
		None => {
			tracing::info!("API authentication disabled");
			None
		},
	};

	// Track whether orders should require auth
	let orders_require_auth = api_config.auth.as_ref().map(|a| a.enabled).unwrap_or(false);

	// Initialize signature validation service
	let signature_validation = Arc::new(SignatureValidationService::new());
	let mut siwe_nonce_store: Option<Arc<NonceStore>> = None;

	// Initialize admin API if enabled in config
	let admin_state = if let Some(auth_config) = &api_config.auth {
		if let Some(admin_config) = &auth_config.admin {
			if admin_config.enabled {
				let redis_url = std::env::var("REDIS_URL")
					.unwrap_or_else(|_| "redis://localhost:6379".to_string());
				let solver_id = config.solver.id.clone();
				// Use explicit chain_id from admin config, or fall back to first network
				let chain_id = admin_config
					.chain_id
					.unwrap_or_else(|| config.networks.keys().next().copied().unwrap_or(1));

				match create_nonce_store_with_namespace(
					StoreConfig::Redis {
						url: redis_url.clone(),
					},
					&solver_id,
					"siwe",
					admin_config.nonce_ttl_seconds,
				) {
					Ok(store) => {
						siwe_nonce_store = Some(Arc::new(store));
						tracing::info!("SIWE nonce store initialized");
					},
					Err(e) => {
						tracing::error!("Failed to initialize SIWE nonce store: {}", e);
					},
				}

				// Use the solver's dynamic_config for hot reload (same Arc!)
				// This ensures admin API updates propagate to the solver engine.

				// Convert Config to OperatorConfig for persistence
				let operator_config = match config_to_operator_config(&config) {
					Ok(oc) => oc,
					Err(e) => {
						tracing::error!("Failed to convert config to OperatorConfig: {}", e);
						return Err(Box::new(std::io::Error::new(
							std::io::ErrorKind::InvalidData,
							format!("Config conversion error: {e}"),
						)));
					},
				};

				// Create ConfigStore for OperatorConfig
				let config_store: Arc<
					dyn solver_storage::config_store::ConfigStore<OperatorConfig>,
				> = match create_config_store::<OperatorConfig>(
					StoreConfig::Redis {
						url: redis_url.clone(),
					},
					format!("{solver_id}-operator"),
				) {
					Ok(store) => Arc::from(store),
					Err(e) => {
						tracing::error!("Failed to create operator config store: {}", e);
						return Err(Box::new(std::io::Error::other(format!(
							"Config store error: {e}"
						))));
					},
				};

				// Seed OperatorConfig if it doesn't exist
				match config_store.exists().await {
					Ok(false) => {
						if let Err(e) = config_store.seed(operator_config).await {
							tracing::error!("Failed to seed operator config: {}", e);
							return Err(Box::new(std::io::Error::other(format!(
								"Config seed error: {e}"
							))));
						}
						tracing::info!("Seeded operator config for admin API persistence");
					},
					Ok(true) => {
						tracing::info!("Operator config already exists, using existing");
					},
					Err(e) => {
						tracing::error!("Failed to check operator config existence: {}", e);
						return Err(Box::new(std::io::Error::other(format!(
							"Config check error: {e}"
						))));
					},
				}

				// Create nonce store (concrete NonceStore type, not a trait)
				match create_nonce_store(
					StoreConfig::Redis { url: redis_url },
					&solver_id,
					admin_config.nonce_ttl_seconds,
				) {
					Ok(nonce_store) => {
						// Keep nonce_store as Arc for sharing with verifier and AdminApiState
						let nonce_store: Arc<solver_storage::nonce_store::NonceStore> =
							Arc::new(nonce_store);
						let verifier = AdminActionVerifier::new(
							nonce_store.clone(),
							admin_config.clone(),
							chain_id,
						);
						tracing::info!(
							"Admin API enabled for {} admin(s) with config persistence",
							admin_config.admin_count()
						);
						Some(AdminApiState {
							// Wrap verifier in RwLock for hot reload of admin list
							verifier: Arc::new(RwLock::new(verifier)),
							config_store,
							dynamic_config: dynamic_config.clone(),
							// Store nonce_store for rebuilding verifier later
							nonce_store,
							// Token manager for hot-reloading token configurations
							token_manager: solver.token_manager().clone(),
						})
					},
					Err(e) => {
						tracing::error!("Failed to initialize admin nonce store: {}", e);
						None
					},
				}
			} else {
				None
			}
		} else {
			None
		}
	} else {
		None
	};

	// Note: dynamic_config is already defined at function start from solver.dynamic_config()
	// This ensures AppState and AdminApiState use the same Arc as the solver engine.

	let app_state = AppState {
		solver,
		config: dynamic_config,
		http_client,
		discovery_url,
		jwt_service: jwt_service.clone(),
		siwe_nonce_store,
		signature_validation,
	};

	// Build the router with /api/v1 base path and quote endpoint
	let mut api_routes = Router::new()
		.route("/quotes", post(handle_quote))
		.route("/tokens", get(handle_get_tokens))
		.route("/tokens/{chain_id}", get(handle_get_tokens_for_chain));

	// Add auth subroutes
	let auth_routes = Router::new()
		.route("/register", post(handle_auth_register))
		.route("/token", post(handle_auth_token))
		.route("/refresh", post(handle_auth_refresh))
		.route("/siwe/nonce", post(handle_auth_siwe_nonce))
		.route("/siwe/verify", post(handle_auth_siwe_verify));

	api_routes = api_routes.nest("/auth", auth_routes);

	// Add admin routes if enabled
	if let Some(admin_state) = admin_state {
		let mut admin_protected_routes = Router::new()
			.route("/config", get(handle_get_config))
			.route("/balances", get(handle_get_balances))
			.route("/nonce", get(handle_get_nonce).post(handle_get_nonce))
			.route("/types", get(handle_get_types))
			.route("/whitelist", post(handle_add_admin))
			.route("/whitelist", delete(handle_remove_admin))
			.route("/tokens", post(handle_add_token))
			.route("/tokens", delete(handle_remove_token))
			.route("/tokens/approve", post(handle_approve_tokens))
			.route("/withdrawals", post(handle_withdrawal))
			.route("/fees", get(handle_get_fees))
			.route("/fees", put(handle_update_fees))
			.route("/gas", get(handle_get_gas))
			.route("/gas", put(handle_update_gas));

		// Only apply JWT auth to protected admin routes if orders_require_auth is true
		// (i.e., auth.enabled in config). Admin routes also have their own
		// EIP-712 signature auth for admin actions.
		if orders_require_auth {
			if let Some(jwt) = &jwt_service {
				admin_protected_routes =
					admin_protected_routes.layer(middleware::from_fn_with_state(
						AuthState {
							jwt_service: jwt.clone(),
							required_scope: solver_types::AuthScope::AdminAll,
						},
						auth_middleware,
					));
			}
		}

		let admin_routes = admin_protected_routes.with_state(admin_state);

		api_routes = api_routes.nest("/admin", admin_routes);
		tracing::info!("Admin routes registered at /api/v1/admin/*");
	}

	// Create order routes with optional auth
	let mut order_routes = Router::new()
		.route("/orders", post(handle_order))
		.route("/orders/{id}", get(handle_get_order_by_id));

	// Apply auth middleware to order routes only if orders_require_auth is true
	if orders_require_auth {
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
	}

	// Combine all routes
	api_routes = api_routes.merge(order_routes);

	// Health check route at root level (no auth required)
	let health_routes = Router::new()
		.route("/health", get(handle_health))
		.with_state(app_state.clone());

	let app = Router::new()
		.merge(health_routes) // Health endpoints at root level
		.nest("/api/v1", api_routes)
		.layer(ServiceBuilder::new().layer(CorsLayer::permissive()))
		.with_state(app_state);

	let bind_address = format!("{}:{}", api_config.host, api_config.port);
	let listener = TcpListener::bind(&bind_address).await?;

	tracing::info!("OIF Solver API server starting on {}", bind_address);

	// Wrap the entire app with NormalizePath to handle trailing slashes
	let app = NormalizePath::trim_trailing_slash(app);
	let service =
		ServiceExt::<axum::http::Request<axum::body::Body>>::into_make_service_with_connect_info::<
			SocketAddr,
		>(app);

	axum::serve(listener, service).await?;

	Ok(())
}

/// Handles POST /api/v1/quotes requests.
///
/// This endpoint processes quote requests and returns price estimates
/// for cross-chain intents following the ERC-7683 standard.
async fn handle_quote(
	State(state): State<AppState>,
	Json(request): Json<GetQuoteRequest>,
) -> Result<Json<GetQuoteResponse>, APIError> {
	let config = state.config.read().await;
	match crate::apis::quote::process_quote_request(request, &state.solver, &config).await {
		Ok(response) => Ok(Json(response)),
		Err(e) => {
			tracing::warn!("Quote request failed: {}", e);
			Err(APIError::from(e))
		},
	}
}

/// Handles GET /api/v1/orders/{id} requests.
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

/// Handles GET /api/v1/tokens requests.
///
/// Returns all supported tokens across all configured networks.
async fn handle_get_tokens(
	State(state): State<AppState>,
) -> Json<crate::apis::tokens::TokensResponse> {
	// Use shared config to support hot reload from admin API
	crate::apis::tokens::get_tokens_from_config(State(state.config)).await
}

/// Handles GET /api/v1/tokens/{chain_id} requests.
///
/// Returns supported tokens for a specific chain.
async fn handle_get_tokens_for_chain(
	Path(chain_id): Path<u64>,
	State(state): State<AppState>,
) -> Result<Json<crate::apis::tokens::NetworkTokens>, StatusCode> {
	// Use shared config to support hot reload from admin API
	crate::apis::tokens::get_tokens_for_chain_from_config(
		Path(chain_id),
		State(state.config.clone()),
	)
	.await
}

/// Handles POST /api/v1/auth/register requests.
///
/// Auth endpoint that provides both access and refresh tokens.
async fn handle_auth_register(
	State(state): State<AppState>,
	Json(payload): Json<crate::apis::auth::RegisterRequest>,
) -> impl IntoResponse {
	crate::apis::auth::register_client(State(state.jwt_service), Json(payload)).await
}

/// Handles POST /api/v1/auth/refresh requests.
///
/// Endpoint exchanges refresh tokens for new access and refresh tokens.
async fn handle_auth_refresh(
	State(state): State<AppState>,
	Json(payload): Json<crate::apis::auth::RefreshRequest>,
) -> impl IntoResponse {
	crate::apis::auth::refresh_token(State(state.jwt_service), Json(payload)).await
}

/// Handles POST /api/v1/auth/token requests.
///
/// Endpoint issues access tokens via client credentials.
async fn handle_auth_token(
	State(state): State<AppState>,
	headers: HeaderMap,
	ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
	Json(payload): Json<crate::apis::auth::TokenRequest>,
) -> impl IntoResponse {
	crate::apis::auth::issue_client_token_with_peer(
		State(state.jwt_service),
		headers,
		Some(peer_addr),
		Json(payload),
	)
	.await
}

/// Handles POST /api/v1/auth/siwe/nonce requests.
///
/// Generates a SIWE nonce and canonical SIWE message for admin login.
async fn handle_auth_siwe_nonce(
	State(state): State<AppState>,
	Json(payload): Json<crate::apis::auth::SiweNonceRequest>,
) -> impl IntoResponse {
	let siwe_state = crate::apis::auth::SiweAuthState {
		jwt_service: state.jwt_service,
		config: state.config,
		siwe_nonce_store: state.siwe_nonce_store,
	};

	crate::apis::auth::issue_siwe_nonce(State(siwe_state), Json(payload)).await
}

/// Handles POST /api/v1/auth/siwe/verify requests.
///
/// Verifies SIWE signatures and returns admin-scoped JWT access token.
async fn handle_auth_siwe_verify(
	State(state): State<AppState>,
	Json(payload): Json<crate::apis::auth::SiweVerifyRequest>,
) -> impl IntoResponse {
	let siwe_state = crate::apis::auth::SiweAuthState {
		jwt_service: state.jwt_service,
		config: state.config,
		siwe_nonce_store: state.siwe_nonce_store,
	};

	crate::apis::auth::verify_siwe_token(State(siwe_state), Json(payload)).await
}

/// Handles POST /api/v1/orders requests.
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
	let standard = "eip7683";

	// Convert payload to PostOrderRequest
	let intent_request = match extract_intent_request(payload.clone(), &state, standard).await {
		Ok(intent) => intent,
		Err(api_error) => return api_error.into_response(),
	};

	// Validate the PostOrderRequest
	match validate_intent_request(&intent_request, &state, standard).await {
		Ok(order) => order,
		Err(api_error) => return api_error.into_response(),
	};

	forward_to_discovery_service(&state, &intent_request).await
}

/// Extracts a PostOrderRequest from the incoming payload.
/// Handles both quote acceptances (with quoteId) and direct submissions.
/// Also injects the recovered user address for Permit2 orders that require ecrecover.
async fn extract_intent_request(
	payload: Value,
	state: &AppState,
	standard: &str,
) -> Result<PostOrderRequest, APIError> {
	// Check if this is a quote acceptance (has quoteId)
	let mut intent = if payload.get("quoteId").and_then(|v| v.as_str()).is_some() {
		// Quote acceptance path
		create_intent_from_quote(payload, state, standard).await?
	} else {
		// Direct submission path
		create_intent_from_payload(payload)?
	};

	// If this order requires ecrecover, we need to inject the recovered user
	// into the order message so the discovery service can process it correctly
	if intent.order.requires_ecrecover() {
		// Extract sponsor address from the order
		let sponsor = intent
			.order
			.extract_sponsor(Some(&intent.signature))
			.map_err(|e| APIError::BadRequest {
				error_type: ApiErrorType::OrderValidationFailed,
				message: format!("Failed to extract sponsor: {e}"),
				details: None,
			})?;

		// Inject the recovered user into Permit2 orders
		if let solver_types::OifOrder::OifEscrowV0 { payload } = &mut intent.order {
			// Permit2 orders need 'user' field injected after signature recovery
			if let Some(message_obj) = payload.message.as_object_mut() {
				message_obj.insert(
					"user".to_string(),
					serde_json::Value::String(sponsor.to_string()),
				);
			}
		}
	}

	Ok(intent)
}

/// Creates a PostOrderRequest from a quote acceptance.
async fn create_intent_from_quote(
	payload: Value,
	state: &AppState,
	standard: &str,
) -> Result<PostOrderRequest, APIError> {
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
				message: format!("Quote not found: {e}"),
				details: Some(serde_json::json!({"quoteId": quote_id})),
			}
		})?;

	// Convert Quote to PostOrderRequest using the TryFrom implementation
	(&quote, signature, standard)
		.try_into()
		.map_err(|e| APIError::InternalServerError {
			error_type: ApiErrorType::QuoteConversionFailed,
			message: format!("Failed to convert quote to intent format: {e}"),
		})
}

/// Creates a PostOrderRequest from a direct payload submission.
fn create_intent_from_payload(payload: Value) -> Result<PostOrderRequest, APIError> {
	// The payload should already be in PostOrderRequest format
	// {order: Bytes, sponsor: Address, signature: Bytes, lock_type: LockType}
	serde_json::from_value::<PostOrderRequest>(payload).map_err(|e| APIError::BadRequest {
		error_type: ApiErrorType::InvalidRequest,
		message: format!("Invalid intent request format: {e}"),
		details: None,
	})
}

/// Validates a PostOrderRequest and creates an Order.
async fn validate_intent_request(
	intent: &PostOrderRequest,
	state: &AppState,
	standard: &str,
) -> Result<Order, APIError> {
	use alloy_sol_types::SolType;

	// Get lock_type from the order
	let lock_type = intent.order.get_lock_type();
	let lock_type_str = lock_type.as_str();

	// Convert to StandardOrder and encode
	// Note: The user injection for Permit2 orders is already done in extract_intent_request
	let standard_order =
		StandardOrder::try_from(&intent.order).map_err(|e| APIError::BadRequest {
			error_type: ApiErrorType::OrderValidationFailed,
			message: format!("Failed to convert order to standard format: {e}"),
			details: None,
		})?;

	{
		let config = state.config.read().await;
		ensure_user_capacity_for_order(state.solver.as_ref(), &config, lock_type, &standard_order)
			.await?;
	}

	let order_bytes = alloy_primitives::Bytes::from(StandardOrder::abi_encode(&standard_order));

	// Get solver address from primary account
	let solver_address =
		state
			.solver
			.account()
			.get_address()
			.await
			.map_err(|e| APIError::InternalServerError {
				error_type: ApiErrorType::SolverAddressError,
				message: format!("Failed to get solver address: {e}"),
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
				.map_err(|e| format!("Contract call failed: {e}"))
		})
	});

	// EIP-712 signature validation for ResourceLock orders
	let requires_validation = state
		.signature_validation
		.requires_signature_validation(standard, &lock_type);

	if requires_validation {
		let config = state.config.read().await;
		state
			.signature_validation
			.validate_signature(standard, intent, &config.networks, state.solver.delivery())
			.await?;
	}

	// Process the order through the OrderService
	// This validates the order based on the standard and returns a validated Order
	let result = state
		.solver
		.order()
		.validate_and_create_order(
			standard,
			&order_bytes,
			&None,
			lock_type_str,
			compute_order_id,
			&solver_address,
			None, // No quote_id for direct order submissions
		)
		.await
		.map_err(|e| {
			tracing::error!("Order validation failed with error: {}", e);
			APIError::BadRequest {
				error_type: ApiErrorType::OrderValidationFailed,
				message: format!("Order validation failed: {e}"),
				details: None,
			}
		});

	match &result {
		Ok(_) => tracing::debug!("Order validation completed successfully"),
		Err(e) => tracing::error!("Order validation failed: {:?}", e),
	}

	result
}

async fn forward_to_discovery_service(
	state: &AppState,
	intent: &PostOrderRequest,
) -> axum::response::Response {
	use solver_types::{PostOrderResponse, PostOrderResponseStatus};

	// Check if discovery URL is configured
	let forward_url = match &state.discovery_url {
		Some(url) => url,
		None => {
			tracing::warn!("offchain_eip7683 discovery source not configured");
			let response = PostOrderResponse {
				order_id: None,
				status: PostOrderResponseStatus::Error,
				message: Some("Intent submission service not configured".to_string()),
				order: None,
			};
			return (StatusCode::SERVICE_UNAVAILABLE, Json(response)).into_response();
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

			// Try to parse as PostOrderResponse first
			match response.json::<PostOrderResponse>().await {
				Ok(post_order_response) => {
					// Convert reqwest status to axum status
					let axum_status = if status.is_success() {
						StatusCode::OK
					} else if status.is_client_error() {
						StatusCode::BAD_REQUEST
					} else {
						StatusCode::from_u16(status.as_u16())
							.unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
					};
					(axum_status, Json(post_order_response)).into_response()
				},
				Err(e) => {
					tracing::warn!(
						"Failed to parse response from discovery API as PostOrderResponse: {}",
						e
					);
					// Return an error response
					let response = PostOrderResponse {
						order_id: None,
						status: PostOrderResponseStatus::Error,
						message: Some(
							"Failed to parse response from discovery service".to_string(),
						),
						order: None,
					};
					(StatusCode::BAD_GATEWAY, Json(response)).into_response()
				},
			}
		},
		Err(e) => {
			tracing::warn!("Failed to forward request to discovery API: {}", e);
			let response = PostOrderResponse {
				order_id: None,
				status: PostOrderResponseStatus::Error,
				message: Some(format!("Failed to submit intent: {e}")),
				order: None,
			};
			(StatusCode::BAD_GATEWAY, Json(response)).into_response()
		},
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use axum::body;
	use axum::http::StatusCode;
	use reqwest::Client;
	use serde_json::{json, to_value};
	use solver_account::AccountService;
	use solver_config::Config;
	use solver_core::engine::event_bus::EventBus;
	use solver_core::engine::token_manager::TokenManager;
	use solver_delivery::DeliveryService;
	use solver_discovery::DiscoveryService;
	use solver_order::OrderService;
	use solver_pricing::implementations::mock::create_mock_pricing;
	use solver_pricing::PricingService;
	use solver_settlement::SettlementService;
	use solver_storage::implementations::memory::MemoryStorage;
	use solver_storage::StorageService;
	use solver_types::api::{
		OifOrder, OrderPayload, PostOrderRequest, PostOrderResponse, PostOrderResponseStatus,
		SignatureType,
	};
	use solver_types::{APIError, Address, ApiErrorType};
	use std::collections::HashMap;
	use std::sync::Arc;
	use wiremock::matchers::{method, path};
	use wiremock::{Mock, MockServer, ResponseTemplate};

	async fn build_test_solver_engine() -> Arc<SolverEngine> {
		let config_toml = r#"
			[solver]
			id = "test-solver"
			monitoring_timeout_seconds = 30
			min_profitability_pct = 1.0

			[storage]
			primary = "memory"
			cleanup_interval_seconds = 60
			[storage.implementations.memory]

			[delivery]
			min_confirmations = 1
			[delivery.implementations]

			[account]
			primary = "local"
			[account.implementations.local]
			private_key = "0x1234567890123456789012345678901234567890123456789012345678901234"

			[discovery]
			[discovery.implementations]

			[order]
			[order.implementations]
			[order.strategy]
			primary = "simple"
			[order.strategy.implementations.simple]

			[settlement]
			[settlement.implementations]

			[networks.1]
			chain_id = 1
			input_settler_address = "0x0000000000000000000000000000000000000011"
			output_settler_address = "0x0000000000000000000000000000000000000022"
			[[networks.1.rpc_urls]]
			http = "http://localhost:8545"
			[[networks.1.tokens]]
			symbol = "TEST"
			address = "0x0000000000000000000000000000000000000033"
			decimals = 18
		"#;

		let config: Config = toml::from_str(config_toml).expect("failed to parse test config");

		let storage = Arc::new(StorageService::new(Box::new(MemoryStorage::new())));

		let account_config: toml::Value = toml::from_str(
			r#"private_key = "0x1234567890123456789012345678901234567890123456789012345678901234""#,
		)
		.expect("failed to parse account config");
		let account_impl = solver_account::implementations::local::create_account(&account_config)
			.await
			.expect("failed to create account impl");
		let account = Arc::new(AccountService::new(account_impl));

		let solver_address = Address(vec![0x11; 20]);

		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 10));
		let discovery = Arc::new(DiscoveryService::new(HashMap::new()));

		let strategy_config = toml::Value::Table(toml::value::Table::new());
		let strategy =
			solver_order::implementations::strategies::simple::create_strategy(&strategy_config)
				.expect("failed to create order strategy");
		let order = Arc::new(OrderService::new(HashMap::new(), strategy));

		let settlement = Arc::new(SettlementService::new(HashMap::new(), 10));

		let pricing_impl = create_mock_pricing(&toml::Value::Table(toml::value::Table::new()))
			.expect("failed to create mock pricing");
		let pricing = Arc::new(PricingService::new(pricing_impl, Vec::new()));

		let event_bus = EventBus::new(10);

		let token_manager = Arc::new(TokenManager::new(
			HashMap::new(),
			delivery.clone(),
			account.clone(),
		));

		let dynamic_config = Arc::new(RwLock::new(config.clone()));
		let engine = SolverEngine::new(
			dynamic_config,
			config.clone(),
			storage,
			account,
			solver_address,
			delivery,
			discovery,
			order,
			settlement,
			pricing,
			event_bus,
			token_manager,
		);

		Arc::new(engine)
	}

	async fn build_test_app_state(discovery_url: Option<String>) -> AppState {
		let solver = build_test_solver_engine().await;
		let config = solver.config().clone();
		let dynamic_config = Arc::new(RwLock::new(config));

		let http_client = Client::builder()
			.no_proxy()
			.build()
			.expect("failed to build client");

		AppState {
			solver,
			config: dynamic_config,
			http_client,
			discovery_url,
			jwt_service: None,
			siwe_nonce_store: None,
			signature_validation: Arc::new(SignatureValidationService::new()),
		}
	}

	fn sample_post_order_request() -> PostOrderRequest {
		let payload = OrderPayload {
			signature_type: SignatureType::Eip712,
			domain: json!({
				"name": "TestDomain",
				"version": "1",
				"chainId": "1",
				"verifyingContract": "0x0000000000000000000000000000000000000000"
			}),
			primary_type: "PermitBatchTransferFrom".to_string(),
			message: json!({
				"permitted": [{
					"token": "0x0000000000000000000000000000000000000000",
					"amount": "1"
				}],
				"spender": "0x0000000000000000000000000000000000000001",
				"nonce": "1",
				"deadline": "1",
				"witness": {}
			}),
			types: None,
		};

		PostOrderRequest {
			order: OifOrder::OifEscrowV0 { payload },
			signature: alloy_primitives::Bytes::from(vec![0u8; 65]),
			quote_id: None,
			origin_submission: None,
		}
	}

	#[test]
	fn create_intent_from_payload_rejects_invalid_json() {
		let payload = json!({"unexpected": true});
		let result = super::create_intent_from_payload(payload);
		assert!(matches!(
			result,
			Err(APIError::BadRequest {
				error_type: ApiErrorType::InvalidRequest,
				..
			})
		));
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn forward_to_discovery_service_returns_service_unavailable_when_missing_url() {
		let state = build_test_app_state(None).await;
		let response =
			super::forward_to_discovery_service(&state, &sample_post_order_request()).await;

		assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

		let body_bytes = body::to_bytes(response.into_body(), usize::MAX)
			.await
			.expect("body");
		let parsed: PostOrderResponse = serde_json::from_slice(&body_bytes).expect("parse body");
		assert_eq!(parsed.status, PostOrderResponseStatus::Error);
		assert!(parsed
			.message
			.as_deref()
			.unwrap_or_default()
			.contains("Intent submission service not configured"));
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn forward_to_discovery_service_succeeds_with_valid_backend() {
		let mock_server = MockServer::start().await;

		let expected_response = PostOrderResponse {
			order_id: Some("order-123".to_string()),
			status: PostOrderResponseStatus::Received,
			message: Some("ok".to_string()),
			order: None,
		};

		Mock::given(method("POST"))
			.and(path("/intent"))
			.respond_with(ResponseTemplate::new(200).set_body_json(&expected_response))
			.expect(1)
			.mount(&mock_server)
			.await;

		let discovery_url = format!("{}/intent", mock_server.uri());
		let state = build_test_app_state(Some(discovery_url)).await;

		let response =
			super::forward_to_discovery_service(&state, &sample_post_order_request()).await;

		assert_eq!(response.status(), StatusCode::OK);

		let body_bytes = body::to_bytes(response.into_body(), usize::MAX)
			.await
			.expect("body");
		let parsed: PostOrderResponse = serde_json::from_slice(&body_bytes).expect("parse body");
		assert_eq!(parsed.status, PostOrderResponseStatus::Received);
		assert_eq!(parsed.order_id.as_deref(), Some("order-123"));
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn forward_to_discovery_service_returns_bad_gateway_on_invalid_payload() {
		let mock_server = MockServer::start().await;

		Mock::given(method("POST"))
			.and(path("/intent"))
			.respond_with(ResponseTemplate::new(200).set_body_string("not-json"))
			.expect(1)
			.mount(&mock_server)
			.await;

		let discovery_url = format!("{}/intent", mock_server.uri());
		let state = build_test_app_state(Some(discovery_url)).await;

		let response =
			super::forward_to_discovery_service(&state, &sample_post_order_request()).await;

		assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

		let body_bytes = body::to_bytes(response.into_body(), usize::MAX)
			.await
			.expect("body");
		let parsed: PostOrderResponse = serde_json::from_slice(&body_bytes).expect("parse body");
		assert_eq!(parsed.status, PostOrderResponseStatus::Error);
		assert!(parsed
			.message
			.as_deref()
			.unwrap_or_default()
			.contains("Failed to parse response from discovery service"));
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn create_intent_from_quote_errors_without_quote_id() {
		let state = build_test_app_state(None).await;
		let payload = json!({ "signature": "0x1234" });

		let error = super::create_intent_from_quote(payload, &state, "eip7683")
			.await
			.expect_err("expected missing quoteId error");

		assert!(matches!(
			error,
			APIError::BadRequest {
				error_type: ApiErrorType::MissingSignature,
				..
			}
		));
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn create_intent_from_quote_errors_without_signature() {
		let state = build_test_app_state(None).await;
		let payload = json!({ "quoteId": "quote-123" });

		let error = super::create_intent_from_quote(payload, &state, "eip7683")
			.await
			.expect_err("expected missing signature error");

		assert!(matches!(
			error,
			APIError::BadRequest {
				error_type: ApiErrorType::MissingSignature,
				..
			}
		));
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn create_intent_from_quote_errors_when_quote_not_found() {
		let state = build_test_app_state(None).await;
		let payload = json!({
			"quoteId": "missing-quote",
			"signature": "0x1234"
		});

		let error = super::create_intent_from_quote(payload, &state, "eip7683")
			.await
			.expect_err("expected quote not found error");

		assert!(matches!(
			error,
			APIError::BadRequest {
				error_type: ApiErrorType::QuoteNotFound,
				..
			}
		));
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn extract_intent_request_returns_direct_payload_unchanged() {
		let state = build_test_app_state(None).await;
		let resource_order_payload = OrderPayload {
			signature_type: SignatureType::Eip712,
			domain: json!({
				"name": "ResourceLock",
				"version": "1",
				"chainId": "1"
			}),
			primary_type: "BatchCompact".to_string(),
			message: json!({
				"sponsor": "0x1111111111111111111111111111111111111111",
				"nonce": "1",
				"expires": "1700000000",
				"mandate": {
					"fillDeadline": "1700000100",
					"inputOracle": "0x2222222222222222222222222222222222222222",
					"outputs": []
				},
				"commitments": []
			}),
			types: None,
		};

		let original_request = PostOrderRequest {
			order: OifOrder::OifResourceLockV0 {
				payload: resource_order_payload,
			},
			signature: alloy_primitives::Bytes::from(vec![0xAA, 0xBB]),
			quote_id: None,
			origin_submission: None,
		};

		let payload_value = to_value(&original_request).expect("serialize request");
		let result = super::extract_intent_request(payload_value.clone(), &state, "eip7683")
			.await
			.expect("expected successful extraction");

		let result_value = to_value(&result).expect("serialize result");
		assert_eq!(result_value, payload_value);
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn extract_intent_request_errors_when_signature_recovery_fails() {
		let state = build_test_app_state(None).await;
		let mut request = sample_post_order_request();
		request.signature = alloy_primitives::Bytes::from(Vec::<u8>::new());
		let payload = to_value(&request).expect("serialize request");

		let error = super::extract_intent_request(payload, &state, "eip7683")
			.await
			.expect_err("expected sponsor extraction failure");

		assert!(matches!(
			error,
			APIError::BadRequest {
				error_type: ApiErrorType::OrderValidationFailed,
				..
			}
		));
	}
}
