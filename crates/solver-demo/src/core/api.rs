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
		self.post("/api/quotes", &request).await
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
		self.post("/api/orders", &request).await
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
		self.get(&format!("/api/orders/{}", order_id)).await
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
			return Err(Error::ApiRequestFailed(format!("{}: {}", status, text)));
		}

		response
			.json::<T>()
			.await
			.map_err(|e| Error::InvalidApiResponse(e.to_string()))
	}
}
