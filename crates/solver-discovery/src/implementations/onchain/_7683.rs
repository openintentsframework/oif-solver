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
use solver_types::{
	standards::eip7683::MandateOutput, ConfigSchema, Eip7683OrderData, Field, FieldType, Intent,
	IntentMetadata, Schema,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

/// Helper function to get current timestamp, returns 0 if system time is before UNIX epoch
fn current_timestamp() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

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
pub struct Eip7683Discovery {
	/// The Alloy provider for blockchain interaction.
	provider: RootProvider<Http<reqwest::Client>>,
	/// Contract addresses to monitor for Open events.
	settler_addresses: Vec<AlloyAddress>,
	/// The last processed block number.
	last_block: Arc<Mutex<u64>>,
	/// Flag indicating if monitoring is active.
	is_monitoring: Arc<AtomicBool>,
	/// Channel for signaling monitoring shutdown.
	stop_signal: Arc<Mutex<Option<mpsc::Sender<()>>>>,
}

impl Eip7683Discovery {
	/// Creates a new EIP-7683 discovery instance.
	///
	/// Configures monitoring for the specified settler contract addresses
	/// on the blockchain accessible via the RPC URL.
	pub async fn new(
		rpc_url: &str,
		settler_addresses: Vec<String>,
	) -> Result<Self, DiscoveryError> {
		// Create provider
		let provider = RootProvider::new_http(
			rpc_url
				.parse()
				.map_err(|e| DiscoveryError::Connection(format!("Invalid RPC URL: {}", e)))?,
		);

		// Parse settler addresses
		let addresses: Vec<AlloyAddress> = settler_addresses
			.iter()
			.filter_map(|addr| addr.parse().ok())
			.collect();

		if addresses.is_empty() {
			return Err(DiscoveryError::ValidationError(
				"No valid settler addresses provided".to_string(),
			));
		}

		// Get current block
		let current_block = provider.get_block_number().await.map_err(|e| {
			DiscoveryError::Connection(format!("Failed to get block number: {}", e))
		})?;

		Ok(Self {
			provider,
			settler_addresses: addresses,
			last_block: Arc::new(Mutex::new(current_block)),
			is_monitoring: Arc::new(AtomicBool::new(false)),
			stop_signal: Arc::new(Mutex::new(None)),
		})
	}

	/// Parses an Open event log into an Intent.
	///
	/// Decodes the EIP-7683 event data and converts it into the internal
	/// Intent format used by the solver.
	async fn parse_open_event(&self, log: &Log) -> Result<Intent, DiscoveryError> {
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
			user: format!("0x{}", hex::encode(order.user)),
			nonce: order.nonce,
			origin_chain_id: order.originChainId,
			expires: order.expires,
			fill_deadline: order.fillDeadline,
			input_oracle: format!("0x{}", hex::encode(order.inputOracle)),
			inputs: order.inputs.clone(),
			order_id: order_id.0,
			settle_gas_limit: 200_000u64, // TODO: calculate exactly
			fill_gas_limit: 200_000u64,   // TODO: calculate exactly
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
			raw_order_data: Some(format!("0x{}", hex::encode(order_bytes))),
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

	/// Main monitoring loop for discovering new intents.
	///
	/// Polls the blockchain for new Open events and sends discovered
	/// intents through the provided channel.
	async fn monitoring_loop(
		provider: RootProvider<Http<reqwest::Client>>,
		settler_addresses: Vec<AlloyAddress>,
		last_block: Arc<Mutex<u64>>,
		sender: mpsc::UnboundedSender<Intent>,
		mut stop_rx: mpsc::Receiver<()>,
	) {
		// TODO: make this configurable
		let mut interval = tokio::time::interval(std::time::Duration::from_secs(3));

		loop {
			tokio::select! {
				_ = interval.tick() => {
					let mut last_block_num = last_block.lock().await;

					// Get current block
					let current_block = match provider.get_block_number().await {
						Ok(block) => block,
						Err(e) => {
							tracing::error!("Failed to get block number: {}", e);
							continue;
						}
					};

					if current_block <= *last_block_num {
						continue; // No new blocks
					}

					// Create filter for Open events
					let open_sig = Open::SIGNATURE_HASH;

					let filter = Filter::new()
						.address(settler_addresses.clone())
						.event_signature(vec![open_sig])
						.from_block(*last_block_num + 1)
						.to_block(current_block);

					// Get logs
					let logs = match provider.get_logs(&filter).await {
						Ok(logs) => logs,
						Err(_) => {
							continue;
						}
					};

					// Parse logs into intents
					for log in logs {
						if let Ok(intent) = Self::parse_open_event(&Eip7683Discovery {
							provider: provider.clone(),
							settler_addresses: settler_addresses.clone(),
							last_block: last_block.clone(),
							is_monitoring: Arc::new(AtomicBool::new(true)),
							stop_signal: Arc::new(Mutex::new(None)),
						}, &log).await {
							let _ = sender.send(intent);
						}
					}

					// Update last block
					*last_block_num = current_block;
				}
				_ = stop_rx.recv() => {
					break;
				}
			}
		}
	}
}

/// Configuration schema for EIP-7683 discovery.
pub struct Eip7683DiscoverySchema;

impl ConfigSchema for Eip7683DiscoverySchema {
	fn validate(&self, config: &toml::Value) -> Result<(), solver_types::ValidationError> {
		let schema = Schema::new(
			// Required fields
			vec![
				Field::new("rpc_url", FieldType::String).with_validator(|value| {
					match value.as_str() {
						Some(url) => {
							if url.starts_with("http://") || url.starts_with("https://") {
								Ok(())
							} else {
								Err("RPC URL must start with http:// or https://".to_string())
							}
						}
						None => Err("Expected string value for rpc_url".to_string()),
					}
				}),
				Field::new(
					"settler_addresses",
					FieldType::Array(Box::new(FieldType::String)),
				)
				.with_validator(|value| match value.as_array() {
					Some(array) => {
						if array.is_empty() {
							return Err("At least one settler address is required".to_string());
						}
						for (i, addr) in array.iter().enumerate() {
							let addr_str = addr.as_str().ok_or_else(|| {
								format!("settler_addresses[{}] must be a string", i)
							})?;
							if addr_str.len() != 42 || !addr_str.starts_with("0x") {
								return Err(format!(
									"settler_addresses[{}] must be a valid Ethereum address",
									i
								));
							}
						}
						Ok(())
					}
					None => Err("Expected array value for settler_addresses".to_string()),
				}),
			],
			// Optional fields
			vec![
				Field::new(
					"start_block",
					FieldType::Integer {
						min: Some(0),
						max: None,
					},
				),
				Field::new(
					"block_confirmations",
					FieldType::Integer {
						min: Some(0),
						max: Some(100),
					},
				),
			],
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

		let (stop_tx, stop_rx) = mpsc::channel(1);
		*self.stop_signal.lock().await = Some(stop_tx);

		// Spawn monitoring task
		let provider = self.provider.clone();
		let settler_addresses = self.settler_addresses.clone();
		let last_block = self.last_block.clone();

		tokio::spawn(async move {
			Self::monitoring_loop(provider, settler_addresses, last_block, sender, stop_rx).await;
		});

		self.is_monitoring.store(true, Ordering::SeqCst);
		Ok(())
	}

	async fn stop_monitoring(&self) -> Result<(), DiscoveryError> {
		if !self.is_monitoring.load(Ordering::SeqCst) {
			return Ok(());
		}

		if let Some(stop_tx) = self.stop_signal.lock().await.take() {
			let _ = stop_tx.send(()).await;
		}

		self.is_monitoring.store(false, Ordering::SeqCst);
		Ok(())
	}
}

/// Factory function to create an EIP-7683 discovery provider from configuration.
///
/// This function reads the discovery configuration and creates an Eip7683Discovery
/// instance. Required configuration parameters:
/// - `rpc_url`: The HTTP RPC endpoint URL
/// - `settler_addresses`: Array of contract addresses to monitor
///
/// # Errors
///
/// Returns an error if:
/// - `rpc_url` is not provided in the configuration
/// - The discovery service cannot be created (e.g., connection failure)
pub fn create_discovery(
	config: &toml::Value,
) -> Result<Box<dyn DiscoveryInterface>, DiscoveryError> {
	let rpc_url = config
		.get("rpc_url")
		.and_then(|v| v.as_str())
		.ok_or_else(|| DiscoveryError::ValidationError("rpc_url is required".to_string()))?;

	let settler_addresses = config
		.get("settler_addresses")
		.and_then(|v| v.as_array())
		.map(|arr| {
			arr.iter()
				.filter_map(|v| v.as_str().map(String::from))
				.collect()
		})
		.unwrap_or_default();

	// Create discovery service synchronously
	let discovery = tokio::task::block_in_place(|| {
		tokio::runtime::Handle::current()
			.block_on(async { Eip7683Discovery::new(rpc_url, settler_addresses).await })
	})?;

	Ok(Box::new(discovery))
}
