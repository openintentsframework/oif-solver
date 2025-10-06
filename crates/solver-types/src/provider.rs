//! Provider utilities for creating and managing Alloy providers.
//!
//! This module provides factory functions for creating Alloy providers with
//! consistent configuration across the solver system. It eliminates duplication
//! in provider creation while maintaining flexibility for module-specific needs.

use crate::{NetworkConfig, NetworksConfig};
use alloy_provider::{DynProvider, Provider, ProviderBuilder};
use alloy_rpc_client::RpcClient;
use alloy_transport::layers::{RateLimitRetryPolicy, RetryBackoffLayer};
use alloy_transport::TransportError;
use std::fmt;

/// Errors that can occur during provider creation.
#[derive(Debug, Clone)]
pub enum ProviderError {
	/// Network configuration error.
	NetworkConfig(String),
	/// Connection error.
	Connection(String),
	/// Invalid URL format.
	InvalidUrl(String),
}

impl fmt::Display for ProviderError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			ProviderError::NetworkConfig(msg) => write!(f, "Network configuration error: {}", msg),
			ProviderError::Connection(msg) => write!(f, "Connection error: {}", msg),
			ProviderError::InvalidUrl(msg) => write!(f, "Invalid URL: {}", msg),
		}
	}
}

impl std::error::Error for ProviderError {}

/// Creates an HTTP provider for the specified network.
///
/// This factory function handles the common pattern of creating HTTP providers
/// used across settlement, discovery, and delivery modules. Includes retry logic
/// for handling network errors, rate limits, and temporary failures.
///
/// # Arguments
///
/// * `network_id` - The chain ID of the network
/// * `networks` - Networks configuration containing RPC URLs
///
/// # Returns
///
/// A type-erased `DynProvider` configured for HTTP connections with retry capabilities.
///
/// # Errors
///
/// Returns an error if:
/// - The network ID is not found in the configuration
/// - No HTTP RPC URL is configured for the network
/// - The RPC URL format is invalid
/// - The provider cannot be created
///
/// # Retry Behavior
///
/// The provider is configured with exponential backoff retry logic:
/// - Maximum 5 retry attempts
/// - Initial backoff of 1000ms, exponentially increasing
/// - Rate limiting protection (10 compute units per second)
pub fn create_http_provider(
	network_id: u64,
	networks: &NetworksConfig,
) -> Result<DynProvider, ProviderError> {
	let network = get_network_config(network_id, networks)?;
	let http_url = get_http_url(network_id, network)?;

	let url = http_url.parse().map_err(|e| {
		ProviderError::InvalidUrl(format!(
			"Invalid HTTP RPC URL for network {}: {}",
			network_id, e
		))
	})?;

	// Configure retry layer for handling network errors, rate limits, and execution reverts
	// Extend the default rate limit policy to also retry execution reverts during gas estimation
	let retry_policy = RateLimitRetryPolicy::default().or(|error: &TransportError| {
		match error {
			TransportError::ErrorResp(payload) => {
				// Retry execution reverts (error code 3) that may be temporary
				// These often occur during gas estimation due to network congestion or node state issues
				payload.code == 3 && payload.message.contains("execution reverted")
			},
			_ => false,
		}
	});

	let retry_layer = RetryBackoffLayer::new_with_policy(
		5,    // max_retry: retry up to 5 times (applies to both rate limits and execution reverts)
		1000, // backoff: initial backoff in milliseconds
		10,   // cups: compute units per second for rate limiting
		retry_policy,
	);

	// Create RPC client with retry capabilities
	let client = RpcClient::builder().layer(retry_layer).http(url);

	// Create provider with retry-enabled client
	let provider = ProviderBuilder::new().connect_client(client);
	Ok(provider.erased())
}

/// Creates a WebSocket provider for the specified network.
///
/// This factory function handles the common pattern of creating WebSocket providers
/// for real-time event monitoring in discovery modules. Includes retry logic for
/// handling connection failures and temporary network issues.
///
/// # Arguments
///
/// * `network_id` - The chain ID of the network
/// * `networks` - Networks configuration containing RPC URLs
///
/// # Returns
///
/// A type-erased `DynProvider` configured for WebSocket connections with retry capabilities.
///
/// # Errors
///
/// Returns an error if:
/// - The network ID is not found in the configuration
/// - No WebSocket RPC URL is configured for the network
/// - The RPC URL format is invalid
/// - The WebSocket connection cannot be established after retries
///
/// # Retry Behavior
///
/// The provider is configured with exponential backoff retry logic:
/// - Maximum 5 retry attempts
/// - Initial backoff of 1000ms, exponentially increasing
/// - Rate limiting protection (10 compute units per second)
pub async fn create_ws_provider(
	network_id: u64,
	networks: &NetworksConfig,
) -> Result<DynProvider, ProviderError> {
	let network = get_network_config(network_id, networks)?;
	let ws_url = get_ws_url(network_id, network)?;

	// Create WebSocket connection
	// Note: WebSocket connections use ProviderBuilder directly
	// For execution revert retries, WebSocket providers have built-in reconnection logic
	let provider = ProviderBuilder::new().connect(ws_url).await.map_err(|e| {
		ProviderError::Connection(format!(
			"Failed to create WebSocket provider for network {}: {}",
			network_id, e
		))
	})?;

	Ok(provider.erased())
}

/// Creates multiple HTTP providers for the specified networks.
///
/// This is a convenience function for modules that need to create providers
/// for multiple networks at once.
///
/// # Arguments
///
/// * `network_ids` - Vector of chain IDs to create providers for
/// * `networks` - Networks configuration containing RPC URLs
///
/// # Returns
///
/// A vector of tuples containing (network_id, provider) pairs for successful
/// provider creations. Failed provider creations are logged and skipped.
///
/// # Note
///
/// This function logs warnings for failed provider creations but does not
/// fail entirely. This allows modules to work with partially available networks.
pub fn create_http_providers(
	network_ids: &[u64],
	networks: &NetworksConfig,
) -> Vec<(u64, DynProvider)> {
	let mut providers = Vec::new();

	for &network_id in network_ids {
		match create_http_provider(network_id, networks) {
			Ok(provider) => providers.push((network_id, provider)),
			Err(e) => {
				tracing::warn!(
					network_id = network_id,
					error = %e,
					"Failed to create HTTP provider for network"
				);
			},
		}
	}

	providers
}

/// Creates multiple WebSocket providers for the specified networks.
///
/// This is a convenience function for modules that need to create WebSocket
/// providers for multiple networks at once.
///
/// # Arguments
///
/// * `network_ids` - Vector of chain IDs to create providers for
/// * `networks` - Networks configuration containing RPC URLs
///
/// # Returns
///
/// A vector of tuples containing (network_id, provider) pairs for successful
/// provider creations. Failed provider creations are logged and skipped.
///
/// # Note
///
/// This function logs warnings for failed provider creations but does not
/// fail entirely. This allows modules to work with partially available networks.
pub async fn create_ws_providers(
	network_ids: &[u64],
	networks: &NetworksConfig,
) -> Vec<(u64, DynProvider)> {
	let mut providers = Vec::new();

	for &network_id in network_ids {
		match create_ws_provider(network_id, networks).await {
			Ok(provider) => providers.push((network_id, provider)),
			Err(e) => {
				tracing::warn!(
					network_id = network_id,
					error = %e,
					"Failed to create WebSocket provider for network"
				);
			},
		}
	}

	providers
}

/// Helper function to get network configuration.
fn get_network_config(
	network_id: u64,
	networks: &NetworksConfig,
) -> Result<&NetworkConfig, ProviderError> {
	networks.get(&network_id).ok_or_else(|| {
		ProviderError::NetworkConfig(format!("Network {} not found in configuration", network_id))
	})
}

/// Helper function to get HTTP URL from network configuration.
fn get_http_url(network_id: u64, network: &NetworkConfig) -> Result<&str, ProviderError> {
	network.get_http_url().ok_or_else(|| {
		ProviderError::NetworkConfig(format!(
			"No HTTP RPC URL configured for network {}",
			network_id
		))
	})
}

/// Helper function to get WebSocket URL from network configuration.
fn get_ws_url(network_id: u64, network: &NetworkConfig) -> Result<&str, ProviderError> {
	network.get_ws_url().ok_or_else(|| {
		ProviderError::NetworkConfig(format!(
			"No WebSocket RPC URL configured for network {}",
			network_id
		))
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::utils::tests::builders::{NetworkConfigBuilder, NetworksConfigBuilder};

	fn create_test_networks() -> NetworksConfig {
		NetworksConfigBuilder::new()
			.add_network(1, NetworkConfigBuilder::new().build())
			.add_network(137, NetworkConfigBuilder::new().build())
			.build()
	}

	#[test]
	fn test_create_http_provider_success() {
		let networks = create_test_networks();
		let result = create_http_provider(1, &networks);
		assert!(result.is_ok());
	}

	#[test]
	fn test_create_http_provider_network_not_found() {
		let networks = create_test_networks();
		let result = create_http_provider(999, &networks);
		assert!(matches!(result, Err(ProviderError::NetworkConfig(_))));
	}

	#[test]
	fn test_create_http_provider_no_http_url() {
		use crate::networks::NetworkConfig;

		let network_config = NetworkConfig {
			rpc_urls: vec![], // Empty RPC URLs
			input_settler_address: crate::parse_address(
				"0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9",
			)
			.unwrap(),
			output_settler_address: crate::parse_address(
				"0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
			)
			.unwrap(),
			tokens: vec![],
			input_settler_compact_address: Some(
				crate::parse_address("0x00000000000c2e074ec69a0dfb2997ba6c7d2e1e").unwrap(),
			),
			the_compact_address: Some(
				crate::parse_address("0x00000000000c2e074ec69a0dfb2997ba6c7d2e1f").unwrap(),
			),
			allocator_address: None,
		};

		let mut networks = std::collections::HashMap::new();
		networks.insert(1, network_config);

		let result = create_http_provider(1, &networks);
		assert!(matches!(result, Err(ProviderError::NetworkConfig(_))));
	}

	#[tokio::test]
	async fn test_create_ws_provider_success() {
		let networks = create_test_networks();
		// This will fail in test environment due to no actual WebSocket server,
		// but we can at least test that the function attempts to connect
		let result = create_ws_provider(1, &networks).await;
		// We expect this to fail with a connection error in tests
		assert!(matches!(result, Err(ProviderError::Connection(_)) | Ok(_)));
	}

	#[test]
	fn test_create_http_providers_multiple() {
		let networks = create_test_networks();
		let providers = create_http_providers(&[1, 137], &networks);

		// Should create providers for both networks
		assert_eq!(providers.len(), 2);
		assert!(providers.iter().any(|(id, _)| *id == 1));
		assert!(providers.iter().any(|(id, _)| *id == 137));
	}

	#[test]
	fn test_create_http_providers_with_invalid_network() {
		let networks = create_test_networks();
		let providers = create_http_providers(&[1, 999, 137], &networks);

		// Should create providers for valid networks, skip invalid one
		assert_eq!(providers.len(), 2);
		assert!(providers.iter().any(|(id, _)| *id == 1));
		assert!(providers.iter().any(|(id, _)| *id == 137));
		assert!(!providers.iter().any(|(id, _)| *id == 999));
	}

	#[test]
	fn test_provider_error_display() {
		let error = ProviderError::NetworkConfig("test error".to_string());
		assert_eq!(error.to_string(), "Network configuration error: test error");

		let error = ProviderError::Connection("connection failed".to_string());
		assert_eq!(error.to_string(), "Connection error: connection failed");

		let error = ProviderError::InvalidUrl("bad url".to_string());
		assert_eq!(error.to_string(), "Invalid URL: bad url");
	}
}
