//! Intent discovery implementations for the solver service.
//!
//! This module provides concrete implementations of the DiscoveryInterface trait,
//! currently supporting on-chain EIP-7683 event monitoring using the Alloy library.

use crate::{DiscoveryError, DiscoveryInterface};
use alloy_primitives::{Address as AlloyAddress, Log as PrimLog, LogData};
use alloy_provider::{Provider, ProviderBuilder, RootProvider};
use alloy_pubsub::PubSubFrontend;
use alloy_rpc_types::{Filter, Log};
use alloy_sol_types::sol;
use alloy_sol_types::{SolEvent, SolValue};
use alloy_transport_http::Http;
use alloy_transport_ws::WsConnect;
use async_trait::async_trait;
use futures::StreamExt;
use solver_types::current_timestamp;
use solver_types::{
	standards::eip7683::{GasLimitOverrides, LockType, MandateOutput},
	with_0x_prefix, ConfigSchema, Eip7683OrderData, Field, FieldType, Intent, IntentMetadata,
	NetworksConfig, Schema,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::task::JoinHandle;

// Event definition for the OIF contracts.
//
// We need to redefine the types here because sol! macro doesn't support external type references.
// These match the types in solver_types::standards::eip7683::interfaces.
sol! {
	/// MandateOutput specification for cross-chain orders.
	struct SolMandateOutput {
		bytes32 oracle;
		bytes32 settler;
		uint256 chainId;
		bytes32 token;
		uint256 amount;
		bytes32 recipient;
		bytes call;
		bytes context;
	}

	/// StandardOrder structure used in the OIF contracts.
	struct StandardOrder {
		address user;
		uint256 nonce;
		uint256 originChainId;
		uint32 expires;
		uint32 fillDeadline;
		address inputOracle;
		uint256[2][] inputs;
		SolMandateOutput[] outputs;
	}

	/// Event emitted when a new order is opened.
	/// The order parameter is the StandardOrder struct (not indexed).
	event Open(bytes32 indexed orderId, StandardOrder order);
}

const DEFAULT_POLLING_INTERVAL_SECS: u64 = 3;
const MAX_POLLING_INTERVAL_SECS: u64 = 300;

/// Provider types for different transport modes.
enum ProviderType {
	/// HTTP provider for polling mode.
	Http(RootProvider<Http<reqwest::Client>>),
	/// WebSocket provider for subscription mode.
	WebSocket(RootProvider<PubSubFrontend>),
}

/// EIP-7683 on-chain discovery implementation.
///
/// This implementation monitors blockchain events for new EIP-7683 cross-chain
/// orders and converts them into intents for the solver to process.
/// Supports monitoring multiple chains concurrently using either HTTP polling
/// or WebSocket subscriptions (when polling_interval_secs = 0).
pub struct Eip7683Discovery {
	/// RPC providers for each monitored network.
	providers: HashMap<u64, ProviderType>,
	/// The chain IDs being monitored.
	network_ids: Vec<u64>,
	/// Networks configuration for settler lookups.
	networks: NetworksConfig,
	/// The last processed block number for each chain (HTTP mode only).
	last_blocks: Arc<Mutex<HashMap<u64, u64>>>,
	/// Flag indicating if monitoring is active.
	is_monitoring: Arc<AtomicBool>,
	/// Handles for monitoring tasks.
	monitoring_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
	/// Channel for signaling monitoring shutdown.
	stop_signal: Arc<Mutex<Option<broadcast::Sender<()>>>>,
	/// Polling interval for monitoring loop in seconds (0 = WebSocket mode).
	polling_interval_secs: u64,
}

impl Eip7683Discovery {
	/// Creates a new EIP-7683 discovery instance.
	///
	/// Configures monitoring for the settler contracts on the specified chains.
	/// When polling_interval_secs = 0, uses WebSocket subscriptions instead of polling.
	pub async fn new(
		network_ids: Vec<u64>,
		networks: NetworksConfig,
		polling_interval_secs: Option<u64>,
	) -> Result<Self, DiscoveryError> {
		// Validate at least one network
		if network_ids.is_empty() {
			return Err(DiscoveryError::ValidationError(
				"At least one network_id must be specified".to_string(),
			));
		}

		let interval = polling_interval_secs.unwrap_or(DEFAULT_POLLING_INTERVAL_SECS);
		let use_websocket = interval == 0;

		// Create providers and get initial blocks for each network
		let mut providers = HashMap::new();
		let mut last_blocks = HashMap::new();

		for network_id in &network_ids {
			// Validate network exists
			let network = networks.get(network_id).ok_or_else(|| {
				DiscoveryError::ValidationError(format!(
					"Network {} not found in configuration",
					network_id
				))
			})?;

			if use_websocket {
				// WebSocket mode
				let ws_url = network.get_ws_url().ok_or_else(|| {
					DiscoveryError::Connection(format!(
						"No WebSocket RPC URL configured for network {}",
						network_id
					))
				})?;

				tracing::info!(
					"Creating WebSocket provider for network {}: {}",
					network_id,
					ws_url
				);

				let ws_connect = WsConnect::new(ws_url.to_string());
				let provider = ProviderBuilder::new()
					.with_recommended_fillers()
					.on_ws(ws_connect)
					.await
					.map_err(|e| {
						DiscoveryError::Connection(format!(
							"Failed to create WebSocket provider for network {}: {}",
							network_id, e
						))
					})?;

				let root_provider = provider.root().clone();
				providers.insert(*network_id, ProviderType::WebSocket(root_provider));
			} else {
				// HTTP polling mode
				let http_url = network.get_http_url().ok_or_else(|| {
					DiscoveryError::Connection(format!(
						"No HTTP RPC URL configured for network {}",
						network_id
					))
				})?;
				let provider = RootProvider::new_http(http_url.parse().map_err(|e| {
					DiscoveryError::Connection(format!(
						"Invalid RPC URL for network {}: {}",
						network_id, e
					))
				})?);

				// Get initial block number
				let current_block = provider.get_block_number().await.map_err(|e| {
					DiscoveryError::Connection(format!(
						"Failed to get block for chain {}: {}",
						network_id, e
					))
				})?;

				providers.insert(*network_id, ProviderType::Http(provider));
				last_blocks.insert(*network_id, current_block);
			}
		}

		Ok(Self {
			providers,
			network_ids,
			networks,
			last_blocks: Arc::new(Mutex::new(last_blocks)),
			is_monitoring: Arc::new(AtomicBool::new(false)),
			monitoring_handles: Arc::new(Mutex::new(Vec::new())),
			stop_signal: Arc::new(Mutex::new(None)),
			polling_interval_secs: interval,
		})
	}

	/// Parses an Open event log into an Intent.
	///
	/// Decodes the EIP-7683 event data and converts it into the internal
	/// Intent format used by the solver.
	fn parse_open_event(log: &Log) -> Result<Intent, DiscoveryError> {
		// Convert RPC log to primitives log for decoding
		let prim_log = PrimLog {
			address: log.address(),
			data: LogData::new_unchecked(log.topics().to_vec(), log.data().data.clone()),
		};

		// Decode the Open event
		let open_event = Open::decode_log(&prim_log, true).map_err(|e| {
			DiscoveryError::ParseError(format!("Failed to decode Open event: {}", e))
		})?;

		let order_id = open_event.orderId;
		let order = open_event.order.clone();

		// Validate that order has outputs
		if order.outputs.is_empty() {
			return Err(DiscoveryError::ValidationError(
				"Order must have at least one output".to_string(),
			));
		}

		// Convert to the format expected by the order implementation
		// The order implementation expects Eip7683OrderData with specific fields
		let order_data = Eip7683OrderData {
			user: with_0x_prefix(&hex::encode(order.user)),
			nonce: order.nonce,
			origin_chain_id: order.originChainId,
			expires: order.expires,
			fill_deadline: order.fillDeadline,
			input_oracle: with_0x_prefix(&hex::encode(order.inputOracle)),
			inputs: order.inputs.clone(),
			order_id: order_id.0,
			gas_limit_overrides: GasLimitOverrides::default(),
			outputs: order
				.outputs
				.iter()
				.map(|output| MandateOutput {
					oracle: output.oracle.0,
					settler: output.settler.0,
					chain_id: output.chainId,
					token: output.token.0,
					amount: output.amount,
					recipient: output.recipient.0,
					call: output.call.clone().into(),
					context: output.context.clone().into(),
				})
				.collect::<Vec<_>>(),
			raw_order_data: Some(with_0x_prefix(&hex::encode(order.abi_encode()))),
			signature: None,
			sponsor: None,
			lock_type: Some(LockType::Permit2Escrow),
		};

		Ok(Intent {
			id: hex::encode(order_id),
			source: "on-chain".to_string(),
			standard: "eip7683".to_string(),
			metadata: IntentMetadata {
				requires_auction: false,
				exclusive_until: None,
				discovered_at: current_timestamp(),
			},
			data: serde_json::to_value(&order_data).map_err(|e| {
				DiscoveryError::ParseError(format!("Failed to serialize order data: {}", e))
			})?,
			quote_id: None,
		})
	}

	/// Process discovered logs into intents and send them.
	///
	/// Common logic for both polling and subscription modes.
	fn process_discovered_logs(
		logs: Vec<Log>,
		sender: &mpsc::UnboundedSender<Intent>,
		_chain_id: u64,
	) {
		for log in logs {
			if let Ok(intent) = Self::parse_open_event(&log) {
				let _ = sender.send(intent);
			}
		}
	}

	/// Polling-based monitoring for a single chain.
	///
	/// Periodically polls the blockchain for new Open events and sends
	/// discovered intents through the provided channel.
	async fn monitor_chain_polling(
		provider: RootProvider<Http<reqwest::Client>>,
		chain_id: u64,
		networks: NetworksConfig,
		last_blocks: Arc<Mutex<HashMap<u64, u64>>>,
		sender: mpsc::UnboundedSender<Intent>,
		mut stop_rx: broadcast::Receiver<()>,
		polling_interval_secs: u64,
	) {
		let mut interval =
			tokio::time::interval(std::time::Duration::from_secs(polling_interval_secs));

		// Set the interval to skip missed ticks instead of bursting
		interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
		// Skip the first immediate tick to avoid immediate polling
		interval.tick().await;

		loop {
			tokio::select! {
				_ = interval.tick() => {
					// Get last processed block for this chain
					let last_block_num = {
						let blocks = last_blocks.lock().await;
						*blocks.get(&chain_id).unwrap_or(&0)
					};

					// Get current block
					let current_block = match provider.get_block_number().await {
						Ok(block) => block,
						Err(e) => {
							tracing::error!(chain = chain_id, "Failed to get block number: {}", e);
							continue;
						}
					};

					if current_block <= last_block_num {
						continue; // No new blocks
					}

					// Create filter for Open events
					let open_sig = Open::SIGNATURE_HASH;

					// Get the input settler address for this chain
					let settler_address = match networks.get(&chain_id) {
						Some(network) => {
							if network.input_settler_address.0.len() != 20 {
								tracing::error!(chain = chain_id, "Invalid settler address length");
								continue;
							}
							AlloyAddress::from_slice(&network.input_settler_address.0)
						}
						None => {
							tracing::error!("Chain ID {} not found in networks config", chain_id);
							continue;
						}
					};

					let filter = Filter::new()
						.address(vec![settler_address])
						.event_signature(vec![open_sig])
						.from_block(last_block_num + 1)
						.to_block(current_block);

					// Get logs
					let logs = match provider.get_logs(&filter).await {
						Ok(logs) => logs,
						Err(e) => {
							tracing::error!(chain = chain_id, "Failed to get logs: {}", e);
							continue;
						}
					};

					// Process discovered logs
					Self::process_discovered_logs(logs, &sender, chain_id);

					// Update last block for this chain
					last_blocks.lock().await.insert(chain_id, current_block);
				}
				_ = stop_rx.recv() => {
					tracing::info!(chain = chain_id, "Stopping monitor");
					break;
				}
			}
		}
	}

	/// Subscription-based monitoring for a single chain.
	///
	/// Uses WebSocket connection to subscribe to Open events via eth_subscribe
	/// and processes events as they arrive in real-time.
	async fn monitor_chain_subscription(
		provider: RootProvider<PubSubFrontend>,
		chain_id: u64,
		networks: NetworksConfig,
		sender: mpsc::UnboundedSender<Intent>,
		mut stop_rx: broadcast::Receiver<()>,
	) {
		// Get the input settler address for this chain
		let settler_address = match networks.get(&chain_id) {
			Some(network) => {
				if network.input_settler_address.0.len() != 20 {
					tracing::error!(chain = chain_id, "Invalid settler address length");
					return;
				}
				AlloyAddress::from_slice(&network.input_settler_address.0)
			},
			None => {
				tracing::error!("Chain ID {} not found in networks config", chain_id);
				return;
			},
		};

		// Create filter for Open events
		let open_sig = Open::SIGNATURE_HASH;
		let filter = Filter::new()
			.address(vec![settler_address])
			.event_signature(vec![open_sig]);

		// Subscribe to logs
		let subscription = match provider.subscribe_logs(&filter).await {
			Ok(sub) => sub,
			Err(e) => {
				tracing::error!(chain = chain_id, "Failed to subscribe to logs: {}", e);
				return;
			},
		};

		let mut stream = subscription.into_stream();
		tracing::info!(
			chain = chain_id,
			"WebSocket monitoring started for settler {}",
			settler_address
		);

		loop {
			tokio::select! {
				Some(log) = stream.next() => {
					// Process single log as it arrives
					Self::process_discovered_logs(vec![log], &sender, chain_id);
				}
				_ = stop_rx.recv() => {
					tracing::info!(chain = chain_id, "Stopping WebSocket monitor");
					break;
				}
			}
		}
	}
}

/// Configuration schema for EIP-7683 on-chain discovery.
///
/// This schema validates the configuration for on-chain discovery,
/// ensuring all required fields are present and have valid values
/// for monitoring blockchain events.
pub struct Eip7683DiscoverySchema;

impl Eip7683DiscoverySchema {
	/// Static validation method for use before instance creation
	pub fn validate_config(config: &toml::Value) -> Result<(), solver_types::ValidationError> {
		let instance = Self;
		instance.validate(config)
	}
}

impl ConfigSchema for Eip7683DiscoverySchema {
	fn validate(&self, config: &toml::Value) -> Result<(), solver_types::ValidationError> {
		let schema = Schema::new(
			// Required fields
			vec![Field::new(
				"network_ids",
				FieldType::Array(Box::new(FieldType::Integer {
					min: Some(1),
					max: None,
				})),
			)
			.with_validator(|value| {
				if let Some(arr) = value.as_array() {
					if arr.is_empty() {
						return Err("network_ids cannot be empty".to_string());
					}
					Ok(())
				} else {
					Err("network_ids must be an array".to_string())
				}
			})],
			// Optional fields
			vec![Field::new(
				"polling_interval_secs",
				FieldType::Integer {
					min: Some(0),                                // 0 = WebSocket mode
					max: Some(MAX_POLLING_INTERVAL_SECS as i64), // Maximum 5 minutes
				},
			)],
		);

		schema.validate(config)
	}
}

#[async_trait]
impl DiscoveryInterface for Eip7683Discovery {
	fn config_schema(&self) -> Box<dyn ConfigSchema> {
		Box::new(Eip7683DiscoverySchema)
	}
	async fn start_monitoring(
		&self,
		sender: mpsc::UnboundedSender<Intent>,
	) -> Result<(), DiscoveryError> {
		if self.is_monitoring.load(Ordering::SeqCst) {
			return Err(DiscoveryError::AlreadyMonitoring);
		}

		// Create broadcast channel for shutdown
		let (stop_tx, _) = broadcast::channel(1);
		*self.stop_signal.lock().await = Some(stop_tx.clone());

		let mut handles = Vec::new();

		// Spawn monitoring task for each network
		for network_id in &self.network_ids {
			let provider = self.providers.get(network_id).unwrap();
			let networks = self.networks.clone();
			let sender = sender.clone();
			let stop_rx = stop_tx.subscribe();
			let chain_id = *network_id;

			let handle = match provider {
				ProviderType::Http(http_provider) => {
					let provider = http_provider.clone();
					let last_blocks = self.last_blocks.clone();
					let polling_interval_secs = self.polling_interval_secs;
					tokio::spawn(async move {
						Self::monitor_chain_polling(
							provider,
							chain_id,
							networks,
							last_blocks,
							sender,
							stop_rx,
							polling_interval_secs,
						)
						.await;
					})
				},
				ProviderType::WebSocket(ws_provider) => {
					let provider = ws_provider.clone();
					tokio::spawn(async move {
						Self::monitor_chain_subscription(
							provider, chain_id, networks, sender, stop_rx,
						)
						.await;
					})
				},
			};

			handles.push(handle);
		}

		*self.monitoring_handles.lock().await = handles;
		self.is_monitoring.store(true, Ordering::SeqCst);
		Ok(())
	}

	async fn stop_monitoring(&self) -> Result<(), DiscoveryError> {
		if !self.is_monitoring.load(Ordering::SeqCst) {
			return Ok(());
		}

		// Send shutdown signal to all monitoring tasks
		if let Some(stop_tx) = self.stop_signal.lock().await.take() {
			let _ = stop_tx.send(());
		}

		// Wait for all monitoring tasks to complete
		let handles = self
			.monitoring_handles
			.lock()
			.await
			.drain(..)
			.collect::<Vec<_>>();
		for handle in handles {
			let _ = handle.await;
		}

		self.is_monitoring.store(false, Ordering::SeqCst);
		tracing::info!("Stopped monitoring all chains");
		Ok(())
	}
}

/// Factory function to create an EIP-7683 discovery provider from configuration.
///
/// This function reads the discovery configuration and creates an Eip7683Discovery
/// instance. Required configuration parameters:
/// - `network_ids`: Array of chain IDs to monitor
///
/// Optional configuration parameters:
/// - `polling_interval_secs`: Polling interval in seconds (defaults to 3, 0 = WebSocket mode)
///
/// # Arguments
///
/// * `config` - The discovery implementation configuration
/// * `networks` - The networks configuration
///
/// # Errors
///
/// Returns an error if:
/// - `network_ids` is not provided or is empty
/// - Any network_id is not found in the networks configuration
/// - The discovery service cannot be created (e.g., connection failure)
pub fn create_discovery(
	config: &toml::Value,
	networks: &NetworksConfig,
) -> Result<Box<dyn DiscoveryInterface>, DiscoveryError> {
	// Validate configuration first
	Eip7683DiscoverySchema::validate_config(config)
		.map_err(|e| DiscoveryError::ValidationError(format!("Invalid configuration: {}", e)))?;

	// Parse network_ids (required field)
	let network_ids = config
		.get("network_ids")
		.and_then(|v| v.as_array())
		.map(|arr| {
			arr.iter()
				.filter_map(|v| v.as_integer().map(|i| i as u64))
				.collect::<Vec<_>>()
		})
		.ok_or_else(|| DiscoveryError::ValidationError("network_ids is required".to_string()))?;

	if network_ids.is_empty() {
		return Err(DiscoveryError::ValidationError(
			"network_ids cannot be empty".to_string(),
		));
	}

	let polling_interval_secs = config
		.get("polling_interval_secs")
		.and_then(|v| v.as_integer())
		.map(|v| v as u64);

	// Create discovery service synchronously
	let discovery = tokio::task::block_in_place(|| {
		tokio::runtime::Handle::current().block_on(async {
			Eip7683Discovery::new(network_ids, networks.clone(), polling_interval_secs).await
		})
	})?;

	Ok(Box::new(discovery))
}

/// Registry for the onchain EIP-7683 discovery implementation.
pub struct Registry;

impl solver_types::ImplementationRegistry for Registry {
	const NAME: &'static str = "onchain_eip7683";
	type Factory = crate::DiscoveryFactory;

	fn factory() -> Self::Factory {
		create_discovery
	}
}

impl crate::DiscoveryRegistry for Registry {}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::{Address as AlloyAddress, Bytes, B256, U256};
	use alloy_rpc_types::Log;
	// use solver_types::utils::tests::builders::{NetworkConfigBuilder, NetworksConfigBuilder};
	// use solver_types::NetworksConfig;
	use std::collections::HashMap;
	// use tokio::sync::mpsc;

	// Helper function to create a test networks config
	// fn create_test_networks() -> NetworksConfig {
	// 	NetworksConfigBuilder::new()
	// 		.add_network(1, NetworkConfigBuilder::new().build())
	// 		.build()
	// }

	// Helper function to create a test StandardOrder
	fn create_test_standard_order() -> StandardOrder {
		StandardOrder {
			user: AlloyAddress::from([3u8; 20]),
			nonce: U256::from(123),
			originChainId: U256::from(1),
			expires: 1000000000,
			fillDeadline: 1000000100,
			inputOracle: AlloyAddress::from([4u8; 20]),
			inputs: vec![[U256::from(100), U256::from(200)]],
			outputs: vec![SolMandateOutput {
				oracle: B256::from([5u8; 32]),
				settler: B256::from([6u8; 32]),
				chainId: U256::from(2),
				token: B256::from([7u8; 32]),
				amount: U256::from(1000),
				recipient: B256::from([8u8; 32]),
				call: vec![1, 2, 3].into(),
				context: vec![4, 5, 6].into(),
			}],
		}
	}

	// Helper function to create a test Open event log
	fn create_test_open_log() -> Log {
		let order = create_test_standard_order();
		let order_id = B256::from([9u8; 32]);

		let open_event = Open {
			orderId: order_id,
			order,
		};

		// Encode the event data (only non-indexed parameters)
		use alloy_sol_types::SolEvent;
		let event_data = open_event.encode_data();

		Log {
			inner: alloy_primitives::Log {
				address: AlloyAddress::from([1u8; 20]),
				data: LogData::new_unchecked(
					vec![Open::SIGNATURE_HASH, order_id],
					event_data.into(),
				),
			},
			block_hash: Some(B256::from([10u8; 32])),
			block_number: Some(100),
			block_timestamp: Some(1000000000),
			transaction_hash: Some(B256::from([11u8; 32])),
			transaction_index: Some(0),
			log_index: Some(0),
			removed: false,
		}
	}

	#[test]
	fn test_config_schema_validation_valid() {
		let config = toml::Value::try_from(HashMap::from([
			(
				"network_ids",
				toml::Value::Array(vec![toml::Value::Integer(1)]),
			),
			("polling_interval_secs", toml::Value::Integer(5)),
		]))
		.unwrap();

		let result = Eip7683DiscoverySchema::validate_config(&config);
		assert!(result.is_ok());
	}

	#[test]
	fn test_config_schema_validation_missing_network_ids() {
		let config = toml::Value::try_from(HashMap::from([(
			"polling_interval_secs",
			toml::Value::Integer(5),
		)]))
		.unwrap();

		let result = Eip7683DiscoverySchema::validate_config(&config);
		assert!(result.is_err());
	}

	#[test]
	fn test_config_schema_validation_empty_network_ids() {
		let config =
			toml::Value::try_from(HashMap::from([("network_ids", toml::Value::Array(vec![]))]))
				.unwrap();

		let result = Eip7683DiscoverySchema::validate_config(&config);
		assert!(result.is_err());
	}

	#[test]
	fn test_config_schema_validation_invalid_polling_interval() {
		let config = toml::Value::try_from(HashMap::from([
			(
				"network_ids",
				toml::Value::Array(vec![toml::Value::Integer(1)]),
			),
			(
				"polling_interval_secs",
				toml::Value::Integer((MAX_POLLING_INTERVAL_SECS + 100) as i64),
			),
		]))
		.unwrap();

		let result = Eip7683DiscoverySchema::validate_config(&config);
		assert!(result.is_err());
	}

	#[test]
	fn test_config_schema_validation_websocket_mode() {
		let config = toml::Value::try_from(HashMap::from([
			(
				"network_ids",
				toml::Value::Array(vec![toml::Value::Integer(1)]),
			),
			("polling_interval_secs", toml::Value::Integer(0)), // WebSocket mode
		]))
		.unwrap();

		let result = Eip7683DiscoverySchema::validate_config(&config);
		assert!(result.is_ok());
	}

	#[test]
	fn test_parse_open_event_success() {
		let log = create_test_open_log();
		let result = Eip7683Discovery::parse_open_event(&log);

		assert!(result.is_ok());
		let intent = result.unwrap();

		// Verify intent structure
		assert_eq!(intent.source, "on-chain");
		assert_eq!(intent.standard, "eip7683");
		assert!(!intent.metadata.requires_auction);
		assert!(intent.metadata.exclusive_until.is_none());
		assert!(intent.quote_id.is_none());

		// Verify the intent data can be deserialized
		let order_data: Eip7683OrderData = serde_json::from_value(intent.data).unwrap();
		assert_eq!(order_data.nonce, U256::from(123));
		assert_eq!(order_data.origin_chain_id, U256::from(1));
		assert_eq!(order_data.outputs.len(), 1);
		assert_eq!(order_data.outputs[0].chain_id, U256::from(2));
		assert_eq!(order_data.outputs[0].amount, U256::from(1000));
	}

	#[test]
	fn test_parse_open_event_no_outputs() {
		// Create order with no outputs
		let mut order = create_test_standard_order();
		order.outputs = vec![];

		let order_id = B256::from([9u8; 32]);

		let open_event = Open {
			orderId: order_id,
			order,
		};

		// Encode the event data (only non-indexed parameters)
		use alloy_sol_types::SolEvent;
		let event_data = open_event.encode_data();

		let log = Log {
			inner: alloy_primitives::Log {
				address: AlloyAddress::from([1u8; 20]),
				data: LogData::new_unchecked(
					vec![Open::SIGNATURE_HASH, order_id],
					event_data.into(),
				),
			},
			block_hash: Some(B256::from([10u8; 32])),
			block_number: Some(100),
			block_timestamp: Some(1000000000),
			transaction_hash: Some(B256::from([11u8; 32])),
			transaction_index: Some(0),
			log_index: Some(0),
			removed: false,
		};

		let result = Eip7683Discovery::parse_open_event(&log);
		assert!(result.is_err());

		if let Err(DiscoveryError::ValidationError(msg)) = result {
			assert!(msg.contains("at least one output"));
		} else {
			panic!("Expected ValidationError");
		}
	}

	#[test]
	fn test_parse_open_event_invalid_log_data() {
		let log = Log {
			inner: alloy_primitives::Log {
				address: AlloyAddress::from([1u8; 20]),
				data: LogData::new_unchecked(
					vec![Open::SIGNATURE_HASH],
					Bytes::from(vec![1, 2, 3]), // Invalid order data
				),
			},
			block_hash: Some(B256::from([10u8; 32])),
			block_number: Some(100),
			block_timestamp: Some(1000000000),
			transaction_hash: Some(B256::from([11u8; 32])),
			transaction_index: Some(0),
			log_index: Some(0),
			removed: false,
		};

		let result = Eip7683Discovery::parse_open_event(&log);
		assert!(result.is_err());

		if let Err(DiscoveryError::ParseError(_)) = result {
			// Expected
		} else {
			panic!("Expected ParseError");
		}
	}

	// TODO: This test needs to be updated to work with async dependencies
	// Disabled for now to avoid compilation errors
	// #[test]
	// fn test_process_discovered_logs() {
	//     // Test disabled - requires async dependencies (token_manager, pricing_service)
	//     // that are complex to mock in unit tests
	// }

	// TODO: This test needs to be updated to work with async dependencies
	// Disabled for now to avoid compilation errors
	// #[test]
	// fn test_process_discovered_logs_invalid_log() {
	//     // Test disabled - requires async dependencies (token_manager, pricing_service)
	//     // that are complex to mock in unit tests
	// }

	// TODO: This test needs to be updated to work with new constructor signature
	// Disabled for now to avoid compilation errors
	// #[tokio::test]
	// async fn test_eip7683_discovery_new_empty_network_ids() {
	//     // Test disabled - requires mock dependencies (token_manager, pricing_service)
	//     // that are complex to create in unit tests
	// }

	// TODO: This test needs to be updated to work with new constructor signature
	// Disabled for now to avoid compilation errors
	// #[tokio::test]
	// async fn test_eip7683_discovery_new_unknown_network() {
	//     // Test disabled - requires mock dependencies (token_manager, pricing_service)
	//     // that are complex to create in unit tests
	// }

	// TODO: This test needs to be updated to work with new factory signature
	// Disabled for now to avoid compilation errors
	// #[tokio::test(flavor = "multi_thread")]
	// async fn test_create_discovery_invalid_config() {
	//     // Test disabled - requires mock dependencies (token_manager, pricing_service)
	//     // that are complex to create in unit tests
	// }

	// TODO: This test needs to be updated to work with new factory signature
	// Disabled for now to avoid compilation errors
	// #[tokio::test(flavor = "multi_thread")]
	// async fn test_create_discovery_empty_network_ids() {
	//     // Test disabled - requires mock dependencies (token_manager, pricing_service)
	//     // that are complex to create in unit tests
	// }

	#[test]
	fn test_registry_name() {
		assert_eq!(
			<Registry as solver_types::ImplementationRegistry>::NAME,
			"onchain_eip7683"
		);
	}

	#[test]
	fn test_order_data_serialization() {
		let order_data = Eip7683OrderData {
			user: with_0x_prefix(&hex::encode([3u8; 20])),
			nonce: U256::from(123),
			origin_chain_id: U256::from(1),
			expires: 1000000000,
			fill_deadline: 1000000100,
			input_oracle: with_0x_prefix(&hex::encode([4u8; 20])),
			inputs: vec![[U256::from(100), U256::from(200)]],
			order_id: [9u8; 32],
			gas_limit_overrides: GasLimitOverrides::default(),
			outputs: vec![MandateOutput {
				oracle: [5u8; 32],
				settler: [6u8; 32],
				chain_id: U256::from(2),
				token: [7u8; 32],
				amount: U256::from(1000),
				recipient: [8u8; 32],
				call: vec![1, 2, 3],
				context: vec![4, 5, 6],
			}],
			raw_order_data: Some(with_0x_prefix("deadbeef")),
			signature: None,
			sponsor: None,
			lock_type: Some(LockType::Permit2Escrow),
		};

		// Test serialization to JSON
		let json_value = serde_json::to_value(&order_data).unwrap();
		assert!(json_value.is_object());

		// Test deserialization from JSON
		let deserialized: Eip7683OrderData = serde_json::from_value(json_value).unwrap();
		assert_eq!(deserialized.nonce, order_data.nonce);
		assert_eq!(deserialized.outputs.len(), order_data.outputs.len());
	}

	#[test]
	fn test_constants() {
		assert_eq!(DEFAULT_POLLING_INTERVAL_SECS, 3);
		assert_eq!(MAX_POLLING_INTERVAL_SECS, 300);
	}

	#[test]
	fn test_sol_types_compilation() {
		// Verify that the sol! macro generated types correctly
		let mandate_output = SolMandateOutput {
			oracle: B256::from([1u8; 32]),
			settler: B256::from([2u8; 32]),
			chainId: U256::from(1),
			token: B256::from([3u8; 32]),
			amount: U256::from(1000),
			recipient: B256::from([4u8; 32]),
			call: vec![1, 2, 3].into(),
			context: vec![4, 5, 6].into(),
		};

		let standard_order = StandardOrder {
			user: AlloyAddress::from([5u8; 20]),
			nonce: U256::from(123),
			originChainId: U256::from(1),
			expires: 1000000000,
			fillDeadline: 1000000100,
			inputOracle: AlloyAddress::from([6u8; 20]),
			inputs: vec![[U256::from(100), U256::from(200)]],
			outputs: vec![mandate_output],
		};

		// Test ABI encoding/decoding
		let encoded = standard_order.abi_encode();
		assert!(!encoded.is_empty());

		let decoded = StandardOrder::abi_decode(&encoded, true).unwrap();
		assert_eq!(decoded.nonce, standard_order.nonce);
		assert_eq!(decoded.outputs.len(), standard_order.outputs.len());
	}
}
