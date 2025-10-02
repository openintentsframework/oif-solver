use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

use crate::services::JwtService;
use solver_types::{
	api::{
		GetOrderResponse, GetQuoteRequest, GetQuoteResponse, PostOrderRequest, PostOrderResponse,
		Quote,
	},
	AssetAmount, OriginSubmission,
};

#[derive(Clone)]
pub struct ApiClient {
	client: Client,
	base_url: String,
	jwt_service: Option<Arc<JwtService>>,
}

impl ApiClient {
	pub fn new(base_url: String) -> Self {
		let client = Client::builder()
			.timeout(Duration::from_secs(30))
			.build()
			.expect("Failed to build HTTP client");

		Self {
			client,
			base_url,
			jwt_service: None,
		}
	}

	pub fn with_jwt_service(mut self, jwt_service: Arc<JwtService>) -> Self {
		self.jwt_service = Some(jwt_service);
		self
	}

	/// Get a valid authentication token
	async fn get_auth_token(&self) -> Result<Option<String>> {
		if let Some(jwt_service) = &self.jwt_service {
			jwt_service.get_valid_token().await.map(Some)
		} else {
			Ok(None)
		}
	}

	pub async fn request_quote(&self, request: GetQuoteRequest) -> Result<GetQuoteResponse> {
		info!("Requesting quote for intent");

		let url = format!("{}/api/quotes", self.base_url);
		let mut req = self.client.post(&url).json(&request);

		// Add authentication if available
		if let Some(token) = self.get_auth_token().await? {
			req = req.bearer_auth(token);
		}

		let response = req
			.send()
			.await
			.map_err(|e| anyhow!("Failed to send quote request: {}", e))?;

		if !response.status().is_success() {
			let status = response.status();
			let text = response.text().await.unwrap_or_default();
			return Err(anyhow!(
				"Quote request failed with status {}: {}",
				status,
				text
			));
		}

		let quote_response: GetQuoteResponse = response
			.json()
			.await
			.map_err(|e| anyhow!("Failed to parse quote response: {}", e))?;

		Ok(quote_response)
	}

	pub async fn submit_order(
		&self,
		quote: &Quote,
		signature: String,
	) -> Result<PostOrderResponse> {
		info!("Submitting order for quote {}", quote.quote_id);

		let url = format!("{}/api/orders", self.base_url);
		let origin_submission: Option<OriginSubmission> = (&quote.order).into();
		// Create new PostOrderRequest with structured order
		let post_order_request = PostOrderRequest {
			order: quote.order.clone(),
			signature: alloy_primitives::Bytes::from(
				hex::decode(signature.trim_start_matches("0x"))
					.map_err(|e| anyhow!("Invalid signature hex: {}", e))?,
			),
			quote_id: Some(quote.quote_id.clone()),
			origin_submission,
		};

		let mut req = self.client.post(&url).json(&post_order_request);

		// Add authentication if available
		if let Some(token) = self.get_auth_token().await? {
			req = req.bearer_auth(token);
		}

		let response = req
			.send()
			.await
			.map_err(|e| anyhow!("Failed to submit order: {}", e))?;

		if !response.status().is_success() {
			let status = response.status();
			let text = response.text().await.unwrap_or_default();
			return Err(anyhow!(
				"Order submission failed with status {}: {}",
				status,
				text
			));
		}

		// Parse PostOrderResponse
		let order_response: PostOrderResponse = response
			.json()
			.await
			.map_err(|e| anyhow!("Failed to parse order response: {}", e))?;

		debug!("Order submission response: {:?}", order_response);
		Ok(order_response)
	}

	/// Submit an intent directly without getting quotes
	/// Note: This submits to /api/orders as a direct PostOrderRequest
	pub async fn post_intent(&self, request: PostOrderRequest) -> Result<PostOrderResponse> {
		info!("Submitting intent directly to orders endpoint");
		let url = format!("{}/api/orders", self.base_url);
		let mut req = self.client.post(&url).json(&request);

		// Add authentication if available
		if let Some(token) = self.get_auth_token().await? {
			req = req.bearer_auth(token);
		}

		let response = req
			.send()
			.await
			.map_err(|e| anyhow!("Failed to submit intent: {}", e))?;

		if !response.status().is_success() {
			let status = response.status();
			let text = response.text().await.unwrap_or_default();
			return Err(anyhow!(
				"Intent submission failed with status {}: {}",
				status,
				text
			));
		}

		let result = response
			.json::<PostOrderResponse>()
			.await
			.map_err(|e| anyhow!("Failed to parse intent response: {}", e))?;

		debug!("Intent submitted successfully");
		Ok(result)
	}

	pub async fn get_order_status(&self, order_id: &str) -> Result<OrderStatus> {
		debug!("Getting status for order {}", order_id);

		let url = format!("{}/api/orders/{}", self.base_url, order_id);
		let mut req = self.client.get(&url);

		// Add authentication if available
		if let Some(token) = self.get_auth_token().await? {
			req = req.bearer_auth(token);
		}

		let response = req
			.send()
			.await
			.map_err(|e| anyhow!("Failed to get order status: {}", e))?;

		if !response.status().is_success() {
			let status = response.status();
			let text = response.text().await.unwrap_or_default();
			return Err(anyhow!(
				"Status request failed with status {}: {}",
				status,
				text
			));
		}

		// Parse the actual API response format: GetOrderResponse
		let order_response: GetOrderResponse = response
			.json()
			.await
			.map_err(|e| anyhow!("Failed to parse status response: {}", e))?;

		// Convert OrderResponse to our OrderStatus format
		let status = OrderStatus {
			order_id: order_response.order.id,
			status: format!("{:?}", order_response.order.status),
			created_at: order_response.order.created_at,
			updated_at: order_response.order.updated_at,
			tx_hash: order_response
				.order
				.fill_transaction
				.as_ref()
				.and_then(|tx| tx.get("hash"))
				.and_then(|h| h.as_str())
				.map(|h| h.to_string()),
			quote_id: order_response.order.quote_id,
			input_amount: order_response.order.input_amount,
			output_amount: order_response.order.output_amount,
		};

		Ok(status)
	}
}

// Removed SubmitOrderRequest and SubmitOrderResponse - using PostOrderRequest from solver_types

#[derive(Debug, Serialize, Deserialize)]
pub struct OrderStatus {
	pub order_id: String,
	pub status: String,
	pub created_at: u64,
	pub updated_at: u64,
	pub tx_hash: Option<String>,
	pub quote_id: Option<String>,
	pub input_amount: AssetAmount,
	pub output_amount: AssetAmount,
}
