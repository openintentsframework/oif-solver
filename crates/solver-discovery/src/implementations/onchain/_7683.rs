//! Intent discovery implementations for the solver service.
//!
//! This module provides concrete implementations of the DiscoveryInterface trait,
//! currently supporting on-chain EIP-7683 event monitoring using the Alloy library.

use crate::{DiscoveryError, DiscoveryInterface};
use alloy_primitives::{Address as AlloyAddress, Log as PrimLog, LogData};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types::{Filter, Log};
use alloy_sol_types::{sol, SolEvent, SolValue};
use alloy_transport_http::Http;
use async_trait::async_trait;
use solver_types::current_timestamp;
use solver_types::{
	standards::eip7683::{GasLimitOverrides, MandateOutput},
	with_0x_prefix, ConfigSchema, Eip7683OrderData, Field, FieldType, Intent, IntentMetadata,
	NetworksConfig, Schema,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::task::JoinHandle;

// Solidity type definitions for the OIF contracts.
//
// These types match the on-chain contract ABI for proper event decoding.
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
	/// The order parameter contains the encoded StandardOrder.
	event Open(bytes32 indexed orderId, bytes order);
}

/// EIP-7683 on-chain discovery implementation.
///
/// This implementation monitors blockchain events for new EIP-7683 cross-chain
/// orders and converts them into intents for the solver to process.
/// Supports monitoring multiple chains concurrently.
pub struct Eip7683Discovery {
	/// RPC providers for each monitored network.
	providers: HashMap<u64, RootProvider<Http<reqwest::Client>>>,
	/// The chain IDs being monitored.
	network_ids: Vec<u64>,
	/// Networks configuration for settler lookups.
	networks: NetworksConfig,
	/// The last processed block number for each chain.
	last_blocks: Arc<Mutex<HashMap<u64, u64>>>,
	/// Flag indicating if monitoring is active.
	is_monitoring: Arc<AtomicBool>,
	/// Handles for monitoring tasks.
	monitoring_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
	/// Channel for signaling monitoring shutdown.
	stop_signal: Arc<Mutex<Option<broadcast::Sender<()>>>>,
	/// Polling interval for monitoring loop in seconds.
	polling_interval_secs: u64,
}

impl Eip7683Discovery {
	/// Creates a new EIP-7683 discovery instance.
	///
	/// Configures monitoring for the settler contracts on the specified chains.
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

			// Create provider
			let provider = RootProvider::new_http(network.rpc_url.parse().map_err(|e| {
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

			providers.insert(*network_id, provider);
			last_blocks.insert(*network_id, current_block);
		}

		Ok(Self {
			providers,
			network_ids,
			networks,
			last_blocks: Arc::new(Mutex::new(last_blocks)),
			is_monitoring: Arc::new(AtomicBool::new(false)),
			monitoring_handles: Arc::new(Mutex::new(Vec::new())),
			stop_signal: Arc::new(Mutex::new(None)),
			polling_interval_secs: polling_interval_secs.unwrap_or(3), // Default to 3 seconds
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
		let order_bytes = &open_event.order;

		// Decode the StandardOrder from bytes
		let order = StandardOrder::abi_decode(order_bytes, true).map_err(|e| {
			DiscoveryError::ParseError(format!("Failed to decode StandardOrder: {}", e))
		})?;

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
			// Store the raw order data for reference
			raw_order_data: Some(with_0x_prefix(&hex::encode(order_bytes))),
			signature: None,
			sponsor: None,
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

	/// Monitoring loop for a single chain.
	///
	/// Polls the blockchain for new Open events and sends discovered
	/// intents through the provided channel.
	async fn monitor_single_chain(
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

					// Parse logs into intents
					for log in logs {
						if let Ok(intent) = Self::parse_open_event(&log) {
							let _ = sender.send(intent);
						}
					}

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
					min: Some(1),
					max: Some(300), // Maximum 5 minutes
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
			let provider = self.providers.get(network_id).unwrap().clone();
			let networks = self.networks.clone();
			let last_blocks = self.last_blocks.clone();
			let sender = sender.clone();
			let stop_rx = stop_tx.subscribe();
			let polling_interval_secs = self.polling_interval_secs;
			let chain_id = *network_id;

			let handle = tokio::spawn(async move {
				Self::monitor_single_chain(
					provider,
					chain_id,
					networks,
					last_blocks,
					sender,
					stop_rx,
					polling_interval_secs,
				)
				.await;
			});

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
/// - `polling_interval_secs`: Polling interval in seconds (defaults to 3)
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
