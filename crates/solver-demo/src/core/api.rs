//! HTTP API client for solver service communication
//!
//! This module provides the ApiClient for interacting with the OIF Solver
//! service over HTTP, including quote requests, order submissions, and
//! order status queries. Supports JWT authentication.

use crate::types::error::{Error, Result};
use reqwest::{Client, Response};
use serde::{de::DeserializeOwned, Serialize};
use solver_types::api::{
	GetOrderResponse, GetQuoteRequest, GetQuoteResponse, PostOrderRequest, PostOrderResponse,
};
use std::time::Duration;

/// HTTP client for communicating with the OIF Solver service
///
/// Provides methods for making authenticated requests to the solver API
/// including quote generation, order submission, and order status queries.
/// Supports JWT bearer token authentication.
#[derive(Debug, Clone)]
pub struct ApiClient {
	client: Client,
	base_url: String,
	jwt_token: Option<String>,
}

impl ApiClient {
	/// Creates a new API client with specified base URL
	///
	/// # Arguments
	/// * `base_url` - Base URL of the solver service API
	///
	/// # Returns
	/// New API client instance with 30-second timeout
	///
	/// # Errors
	/// Returns error if HTTP client construction fails
	pub fn new(base_url: &str) -> Result<Self> {
		let client = Client::builder().timeout(Duration::from_secs(30)).build()?;

		Ok(Self {
			client,
			base_url: base_url.trim_end_matches('/').to_string(),
			jwt_token: None,
		})
	}

	/// Sets JWT token for authenticated requests
	///
	/// # Arguments
	/// * `token` - JWT bearer token for authentication
	///
	/// # Returns
	/// Updated API client with authentication configured
	pub fn with_jwt(mut self, token: String) -> Self {
		self.jwt_token = Some(token);
		self
	}

	/// Requests a quote from the solver service
	///
	/// # Arguments
	/// * `request` - Quote request containing intent details
	///
	/// # Returns
	/// Quote response with available quotes and pricing
	///
	/// # Errors
	/// Returns error if HTTP request fails or response parsing fails
	pub async fn get_quote(&self, request: GetQuoteRequest) -> Result<GetQuoteResponse> {
		self.post("/api/v1/quotes", &request).await
	}

	/// Submits a signed order to the solver service
	///
	/// # Arguments
	/// * `request` - Post order request with signed order data
	///
	/// # Returns
	/// Order response with submission status and order ID
	///
	/// # Errors
	/// Returns error if HTTP request fails or response parsing fails
	pub async fn submit_order(&self, request: PostOrderRequest) -> Result<PostOrderResponse> {
		self.post("/api/v1/orders", &request).await
	}

	/// Retrieves order status and details by order ID
	///
	/// # Arguments
	/// * `order_id` - Unique identifier for the order
	///
	/// # Returns
	/// Order response with current status and execution details
	///
	/// # Errors
	/// Returns error if order not found, HTTP request fails, or response parsing fails
	pub async fn get_order(&self, order_id: &str) -> Result<GetOrderResponse> {
		self.get(&format!("/api/v1/orders/{order_id}")).await
	}

	/// Executes a generic POST request with JSON serialization
	///
	/// # Arguments
	/// * `path` - API endpoint path relative to base URL
	/// * `body` - Request payload to be JSON-serialized
	///
	/// # Returns
	/// Deserialized response of specified type
	///
	/// # Errors
	/// Returns error if serialization fails, HTTP request fails, or response parsing fails
	async fn post<Req, Res>(&self, path: &str, body: &Req) -> Result<Res>
	where
		Req: Serialize,
		Res: DeserializeOwned,
	{
		let url = format!("{}{}", self.base_url, path);

		let mut request = self.client.post(&url).json(body);

		if let Some(token) = &self.jwt_token {
			request = request.bearer_auth(token);
		}

		let response = request.send().await?;
		self.handle_response(response).await
	}

	/// Generic GET request
	async fn get<Res>(&self, path: &str) -> Result<Res>
	where
		Res: DeserializeOwned,
	{
		let url = format!("{}{}", self.base_url, path);

		let mut request = self.client.get(&url);

		if let Some(token) = &self.jwt_token {
			request = request.bearer_auth(token);
		}

		let response = request.send().await?;
		self.handle_response(response).await
	}

	/// Handle API response
	async fn handle_response<T: DeserializeOwned>(&self, response: Response) -> Result<T> {
		if !response.status().is_success() {
			let status = response.status();
			let text = response
				.text()
				.await
				.unwrap_or_else(|_| "Unknown error".to_string());
			return Err(Error::ApiRequestFailed(format!("{status}: {text}")));
		}

		response
			.json::<T>()
			.await
			.map_err(|e| Error::InvalidApiResponse(e.to_string()))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use solver_types::api::PostOrderResponseStatus;
	use wiremock::matchers::{method, path};
	use wiremock::{Mock, MockServer, ResponseTemplate};

	#[tokio::test]
	async fn get_quote_uses_v1_api_path() {
		let mock_server = MockServer::start().await;

		// Use JSON directly to avoid complex type construction
		let response = serde_json::json!({
			"quotes": []
		});

		Mock::given(method("POST"))
			.and(path("/api/v1/quotes"))
			.respond_with(ResponseTemplate::new(200).set_body_json(&response))
			.expect(1)
			.mount(&mock_server)
			.await;

		let client = ApiClient::new(&mock_server.uri()).expect("client creation");

		// Construct a minimal valid GetQuoteRequest using JSON deserialization
		// EIP-7930 InteropAddress format: Version(2)|ChainType(2)|ChainRefLen(1)|ChainRef|AddrLen(1)|Address
		// For Ethereum chain 1: 0x0001 | 0x0000 | 0x01 | 0x01 | 0x14 | <20 bytes address>
		let interop_addr = "0x000100000101141111111111111111111111111111111111111111";
		let request: GetQuoteRequest = serde_json::from_value(serde_json::json!({
			"user": interop_addr,
			"intent": {
				"intentType": "oif-swap",
				"inputs": [],
				"outputs": []
			},
			"supportedTypes": ["permit2"]
		}))
		.expect("valid request json");

		let result = client.get_quote(request).await;
		assert!(result.is_ok());
	}

	#[tokio::test]
	async fn submit_order_uses_v1_api_path() {
		let mock_server = MockServer::start().await;

		let response = solver_types::api::PostOrderResponse {
			order_id: Some("order-456".to_string()),
			status: PostOrderResponseStatus::Received,
			message: None,
			order: None,
		};

		Mock::given(method("POST"))
			.and(path("/api/v1/orders"))
			.respond_with(ResponseTemplate::new(200).set_body_json(&response))
			.expect(1)
			.mount(&mock_server)
			.await;

		let client = ApiClient::new(&mock_server.uri()).expect("client creation");

		let payload = solver_types::api::OrderPayload {
			signature_type: solver_types::api::SignatureType::Eip712,
			domain: serde_json::json!({}),
			primary_type: "Test".to_string(),
			message: serde_json::json!({}),
			types: None,
		};

		let request = PostOrderRequest {
			order: solver_types::api::OifOrder::OifEscrowV0 { payload },
			signature: alloy_primitives::Bytes::from(vec![0u8; 65]),
			quote_id: None,
			origin_submission: None,
		};

		let result = client.submit_order(request).await;
		assert!(result.is_ok());
		assert_eq!(result.unwrap().order_id, Some("order-456".to_string()));
	}

	#[tokio::test]
	async fn get_order_uses_v1_api_path() {
		let mock_server = MockServer::start().await;

		// Use JSON directly - the GetOrderResponse flattens an OrderResponse
		let response = serde_json::json!({
			"id": "order-789",
			"status": "created",
			"createdAt": 1704067200,
			"updatedAt": 1704067200,
			"inputAmounts": [],
			"outputAmounts": [],
			"settlement": {
				"type": "escrow",
				"data": {}
			}
		});

		Mock::given(method("GET"))
			.and(path("/api/v1/orders/order-789"))
			.respond_with(ResponseTemplate::new(200).set_body_json(&response))
			.expect(1)
			.mount(&mock_server)
			.await;

		let client = ApiClient::new(&mock_server.uri()).expect("client creation");
		let result = client.get_order("order-789").await;
		assert!(result.is_ok());
		assert_eq!(result.unwrap().order.id, "order-789");
	}
}
