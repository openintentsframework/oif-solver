//! Intent discovery implementations for the solver service.
//!
//! This module provides concrete implementations of the DiscoveryInterface trait,
//! currently supporting on-chain EIP-7683 event monitoring using the Alloy library.

use crate::{DiscoveryError, DiscoveryInterface};
use alloy_primitives::{Address as AlloyAddress, Log as PrimLog, LogData, U256};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types::{Filter, Log};
use alloy_sol_types::{sol, SolEvent};
use alloy_transport_http::Http;
use async_trait::async_trait;
use solver_types::{ConfigSchema, Field, FieldType, Intent, IntentMetadata, Schema};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

// Solidity type definitions for EIP-7683 cross-chain order events.
//
// These types match the on-chain contract ABI for proper event decoding.
sol! {
	/// Output specification for cross-chain orders.
	struct Output {
		bytes32 token;
		uint256 amount;
		bytes32 recipient;
		uint256 chainId;
	}

	/// Fill instruction for cross-chain execution.
	struct FillInstruction {
		uint64 destinationChainId;
		bytes32 destinationSettler;
		bytes originData;
	}

	/// Resolved cross-chain order structure.
	struct ResolvedCrossChainOrder {
		address user;
		uint256 originChainId;
		uint32 openDeadline;
		uint32 fillDeadline;
		bytes32 orderId;
		Output[] maxSpent;
		Output[] minReceived;
		FillInstruction[] fillInstructions;
	}

	/// Event emitted when a new cross-chain order is opened.
	event Open(bytes32 indexed orderId, ResolvedCrossChainOrder order);
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
			return Err(DiscoveryError::Connection(
				"No valid settler addresses".to_string(),
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
		let open_event = Open::decode_log(&prim_log, true)
			.map_err(|e| DiscoveryError::Connection(format!("Failed to decode event: {}", e)))?;

		let order = &open_event.order;
		let order_id = open_event.orderId;

		// Extract destination chain ID from the first output (assuming single-output for now)
		let destination_chain_id = if !order.maxSpent.is_empty() {
			order.maxSpent[0].chainId
		} else {
			return Err(DiscoveryError::Connection(
				"No outputs in order".to_string(),
			));
		};

		// Convert to the format expected by the order implementation
		// The order implementation expects Eip7683OrderData with specific fields
		let order_data = serde_json::json!({
			"user": order.user.to_string(),
			"nonce": 0u64, // For onchain orders, nonce is always 0
			"origin_chain_id": order.originChainId.to::<u64>(),
			"destination_chain_id": destination_chain_id.to::<u64>(),
			"expires": if order.openDeadline == 0 { order.fillDeadline } else { order.openDeadline }, // For onchain orders with openDeadline=0, use fillDeadline
			"fill_deadline": order.fillDeadline,
			"local_oracle": "0x0000000000000000000000000000000000000000", // Default to zero address
			"inputs": order.minReceived.iter().map(|input| {
				// Create [token, amount] array where token is bytes32 converted to U256
				// The token is already in bytes32 format, just use it as U256
				[
					serde_json::to_value(U256::from_be_bytes(input.token.0)).unwrap(),
					serde_json::to_value(input.amount).unwrap()
				]
			}).collect::<Vec<_>>(),
			"order_id": order_id.0,
			"settle_gas_limit": 200_000u64, // Default gas limit
			"fill_gas_limit": 200_000u64, // Default gas limit
			"outputs": order.maxSpent.iter().map(|output| {
				serde_json::json!({
					"token": format!("0x{}", hex::encode(&output.token.0[12..])), // Convert bytes32 to address
					"amount": output.amount.to_string(),
					"recipient": format!("0x{}", hex::encode(&output.recipient.0[12..])), // Convert bytes32 to address
					"chain_id": output.chainId.to::<u64>()
				})
			}).collect::<Vec<_>>()
		});

		// Convert to intent
		Ok(Intent {
			id: hex::encode(order_id),
			source: "eip7683".to_string(),
			standard: "eip7683".to_string(),
			metadata: IntentMetadata {
				requires_auction: false,
				exclusive_until: None,
				discovered_at: std::time::SystemTime::now()
					.duration_since(std::time::UNIX_EPOCH)
					.unwrap()
					.as_secs(),
			},
			data: order_data,
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
					let url = value.as_str().unwrap();
					if url.starts_with("http://") || url.starts_with("https://") {
						Ok(())
					} else {
						Err("RPC URL must start with http:// or https://".to_string())
					}
				}),
				Field::new(
					"settler_addresses",
					FieldType::Array(Box::new(FieldType::String)),
				)
				.with_validator(|value| {
					let array = value.as_array().unwrap();
					if array.is_empty() {
						return Err("At least one settler address is required".to_string());
					}
					for (i, addr) in array.iter().enumerate() {
						let addr_str = addr
							.as_str()
							.ok_or_else(|| format!("settler_addresses[{}] must be a string", i))?;
						if addr_str.len() != 42 || !addr_str.starts_with("0x") {
							return Err(format!(
								"settler_addresses[{}] must be a valid Ethereum address",
								i
							));
						}
					}
					Ok(())
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
pub fn create_discovery(config: &toml::Value) -> Box<dyn DiscoveryInterface> {
	let rpc_url = config
		.get("rpc_url")
		.and_then(|v| v.as_str())
		.expect("rpc_url is required");

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
	});

	Box::new(discovery.expect("Failed to create discovery service"))
}
