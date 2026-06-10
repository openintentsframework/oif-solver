//! Intent discovery module for the OIF solver system.
//!
//! This module handles the discovery of new intents from various implementations.
//! It provides abstractions for different discovery mechanisms such as
//! on-chain event monitoring, off-chain APIs, or other intent implementations.

use async_trait::async_trait;
use solver_types::{
	api::PostOrderRequest, ConfigSchema, ImplementationRegistry, Intent, NetworksConfig,
};
use std::collections::HashMap;
use thiserror::Error;
use tokio::sync::mpsc;

/// Re-export implementations
pub mod implementations {
	pub mod onchain {
		pub mod _7683;
	}
	pub mod offchain {
		pub mod _7683;
	}
}

/// Errors that can occur during intent discovery operations.
#[derive(Debug, Error)]
pub enum DiscoveryError {
	/// Error that occurs when connecting to a discovery implementation fails.
	#[error("Connection error: {0}")]
	Connection(String),
	/// Error that occurs when trying to start monitoring on an already active implementation.
	#[error("Already monitoring")]
	AlreadyMonitoring,
	/// Error that occurs when parsing or decoding data fails.
	#[error("Parse error: {0}")]
	ParseError(String),
	/// Error that occurs when validating intent data.
	#[error("Validation error: {0}")]
	ValidationError(String),
}

/// A successfully admitted in-process intent submission.
#[derive(Debug, Clone)]
pub struct IntentSubmission {
	/// The computed order id for the submitted intent.
	pub order_id: String,
	/// The parsed order echoed back to the submitter (JSON form), when available.
	pub order: Option<serde_json::Value>,
	/// Human-readable status message.
	pub message: String,
}

/// Error returned when an in-process intent submission is not admitted.
#[derive(Debug, Error)]
pub enum IntentSubmissionError {
	/// The order failed parsing. Maps to HTTP 400 at the API layer.
	#[error("{message}")]
	Rejected {
		message: String,
		/// The parsed order, when parsing succeeded far enough to echo it.
		order: Option<serde_json::Value>,
	},
	/// The submission pipeline is unavailable (monitoring not started, queue
	/// full, or queue closed). Maps to HTTP 503 at the API layer.
	#[error("{message}")]
	Unavailable {
		message: String,
		order_id: Option<String>,
		order: Option<serde_json::Value>,
	},
	/// The implementation does not accept direct submissions.
	#[error("intent submission not supported by this discovery implementation")]
	NotSupported,
}

/// Trait defining the interface for intent discovery implementations.
///
/// This trait must be implemented by any discovery implementation that wants to
/// integrate with the solver system. It provides methods for starting and
/// stopping intent monitoring.
#[async_trait]
pub trait DiscoveryInterface: Send + Sync {
	/// Returns the configuration schema for this discovery implementation.
	///
	/// This allows each implementation to define its own configuration requirements
	/// with specific validation rules. The schema is used to validate TOML configuration
	/// before initializing the discovery implementation.
	fn config_schema(&self) -> Box<dyn ConfigSchema>;

	/// Starts monitoring for new intents from this implementation.
	///
	/// Discovered intents are sent through the provided channel. The implementation
	/// should continue monitoring until stop_monitoring is called or an error occurs.
	async fn start_monitoring(&self, sender: mpsc::Sender<Intent>) -> Result<(), DiscoveryError>;

	/// Stops monitoring for new intents from this implementation.
	///
	/// This method should cleanly shut down any active monitoring tasks
	/// and release associated resources.
	async fn stop_monitoring(&self) -> Result<(), DiscoveryError>;

	/// Submits an already-validated order to this discovery implementation, in-process.
	///
	/// # TRUST BOUNDARY — read before calling
	/// This is a **trusted internal method, NOT a self-validating boundary.**
	/// It does NOT verify the sponsor signature, allocator authorization, or
	/// user balance/capacity. Callers MUST run full intake validation first —
	/// in this codebase that is `solver-service`'s `validate_intent_request`
	/// (sponsor EIP-712 sig, allocator auth, capacity). Calling this with
	/// unvalidated input reopens audit findings C-02/C-04 (principal loss on
	/// resource-lock fills). The only sanctioned caller is `POST /api/v1/orders`.
	///
	/// Implementations that do not accept direct submissions return
	/// `IntentSubmissionError::NotSupported`.
	async fn submit_order(
		&self,
		_request: &PostOrderRequest,
	) -> Result<IntentSubmission, IntentSubmissionError> {
		Err(IntentSubmissionError::NotSupported)
	}
}

/// Type alias for discovery factory functions.
///
/// This is the function signature that all discovery implementations must provide
/// to create instances of their discovery interface.
pub type DiscoveryFactory =
	fn(&serde_json::Value, &NetworksConfig) -> Result<Box<dyn DiscoveryInterface>, DiscoveryError>;

/// Registry trait for discovery implementations.
///
/// This trait extends the base ImplementationRegistry to specify that
/// discovery implementations must provide a DiscoveryFactory.
pub trait DiscoveryRegistry: ImplementationRegistry<Factory = DiscoveryFactory> {}

/// Get all registered discovery implementations.
///
/// Returns a vector of (name, factory) tuples for all available discovery implementations.
/// This is used by the factory registry to automatically register all implementations.
pub fn get_all_implementations() -> Vec<(&'static str, DiscoveryFactory)> {
	use implementations::{offchain, onchain};

	vec![
		(
			onchain::_7683::Registry::NAME,
			onchain::_7683::Registry::factory(),
		),
		(
			offchain::_7683::Registry::NAME,
			offchain::_7683::Registry::factory(),
		),
	]
}

/// Service that manages multiple intent discovery implementations.
///
/// The DiscoveryService coordinates multiple discovery implementations, allowing
/// the solver to find intents from various channels simultaneously.
pub struct DiscoveryService {
	/// Map of implementation names to their interfaces.
	implementations: HashMap<String, Box<dyn DiscoveryInterface>>,
}

impl DiscoveryService {
	/// Creates a new DiscoveryService with the specified implementations.
	///
	/// Each implementation will be monitored independently when monitoring is started.
	pub fn new(implementations: HashMap<String, Box<dyn DiscoveryInterface>>) -> Self {
		Self { implementations }
	}

	/// Gets a specific discovery implementation by name.
	///
	/// Returns None if the implementation doesn't exist.
	pub fn get(&self, name: &str) -> Option<&dyn DiscoveryInterface> {
		self.implementations.get(name).map(|b| b.as_ref())
	}

	/// Submits an order to a specific discovery implementation, in-process.
	///
	/// Returns `NotSupported` if the implementation doesn't exist or doesn't
	/// accept direct submissions.
	pub async fn submit_order(
		&self,
		implementation_name: &str,
		request: &PostOrderRequest,
	) -> Result<IntentSubmission, IntentSubmissionError> {
		match self.implementations.get(implementation_name) {
			Some(implementation) => implementation.submit_order(request).await,
			None => Err(IntentSubmissionError::NotSupported),
		}
	}

	/// Starts monitoring on all configured discovery implementations.
	///
	/// All discovered intents from any implementation will be sent through the
	/// provided channel. If any implementation fails to start, the entire operation
	/// fails and no implementations will be monitoring.
	pub async fn start_all(&self, sender: mpsc::Sender<Intent>) -> Result<(), DiscoveryError> {
		for implementation in self.implementations.values() {
			implementation.start_monitoring(sender.clone()).await?;
		}
		Ok(())
	}

	/// Stops monitoring on all active discovery implementations.
	///
	/// This method attempts to stop all implementations, even if some fail.
	/// The first error encountered is returned, but all implementations are
	/// attempted to be stopped.
	pub async fn stop_all(&self) -> Result<(), DiscoveryError> {
		for implementation in self.implementations.values() {
			implementation.stop_monitoring().await?;
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::Bytes;
	use solver_types::api::{OifOrder, OrderPayload, SignatureType};

	fn sample_request() -> PostOrderRequest {
		PostOrderRequest {
			order: OifOrder::OifResourceLockV0 {
				payload: OrderPayload {
					signature_type: SignatureType::Eip712,
					domain: serde_json::json!({}),
					primary_type: "BatchCompact".to_string(),
					message: serde_json::json!({}),
					types: None,
				},
			},
			signature: Bytes::from(vec![0u8; 65]),
			quote_id: None,
			origin_submission: None,
		}
	}

	#[tokio::test]
	async fn submit_order_returns_not_supported_for_unknown_implementation() {
		let service = DiscoveryService::new(HashMap::new());
		let result = service
			.submit_order("offchain_eip7683", &sample_request())
			.await;
		assert!(matches!(result, Err(IntentSubmissionError::NotSupported)));
	}
}
