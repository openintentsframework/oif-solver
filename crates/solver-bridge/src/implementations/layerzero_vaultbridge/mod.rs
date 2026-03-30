//! LayerZero VaultBridge implementation.
//!
//! Handles bridging USDC (Ethereum) <-> vbUSDC (Katana) via:
//! - ETH -> Katana: OVault Composer depositAndSend (vault deposit + OFT bridge)
//! - Katana -> ETH: OFT send() on Share OFT, then vault redeem() on Ethereum

pub mod contracts;
pub mod types;

use crate::types::{
	BridgeDepositResult, BridgeRequest, BridgeTransferStatus, PendingBridgeTransfer,
};
use crate::{BridgeError, BridgeInterface};
use alloy_primitives::{Address, U256};
use alloy_sol_types::SolCall;
use async_trait::async_trait;
use contracts::*;
use solver_delivery::DeliveryService;
use solver_types::Transaction;
use std::sync::Arc;
use types::LayerZeroVaultBridgeConfig;

/// LayerZero VaultBridge bridge implementation.
pub struct LayerZeroVaultBridge {
	config: LayerZeroVaultBridgeConfig,
	delivery: Arc<DeliveryService>,
	solver_address: Address,
}

impl LayerZeroVaultBridge {
	pub fn new(
		config: LayerZeroVaultBridgeConfig,
		delivery: Arc<DeliveryService>,
		solver_address: Address,
	) -> Self {
		Self {
			config,
			delivery,
			solver_address,
		}
	}

	/// Get the LayerZero EID for a chain, or error.
	fn get_eid(&self, chain_id: u64) -> Result<u32, BridgeError> {
		self.config
			.endpoint_ids
			.get(&chain_id)
			.copied()
			.ok_or_else(|| {
				BridgeError::Config(format!(
					"No LayerZero endpoint ID configured for chain {chain_id}"
				))
			})
	}

	/// Parse a hex address string from config.
	fn parse_config_address(hex_str: &str) -> Result<Address, BridgeError> {
		let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
		let bytes = hex::decode(hex_str)
			.map_err(|e| BridgeError::Config(format!("Invalid address hex: {e}")))?;
		let arr: [u8; 20] = bytes
			.try_into()
			.map_err(|_| BridgeError::Config("Address must be 20 bytes".to_string()))?;
		Ok(Address::from(arr))
	}

	/// Quote the LayerZero messaging fee for an OFT send.
	async fn quote_send(
		&self,
		chain_id: u64,
		oft_address: &Address,
		send_param: &SendParam,
	) -> Result<U256, BridgeError> {
		let call_data = IOFT::quoteSendCall {
			_sendParam: send_param.clone(),
			_payInLzToken: false,
		};

		let tx = Transaction {
			to: Some(solver_types::Address(oft_address.as_slice().to_vec())),
			data: call_data.abi_encode(),
			value: U256::ZERO,
			chain_id,
			nonce: None,
			gas_limit: None,
			gas_price: None,
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
		};

		let result = self
			.delivery
			.contract_call(chain_id, tx)
			.await
			.map_err(|e| BridgeError::FeeEstimation(format!("quoteSend failed: {e}")))?;

		// Decode MessagingFee from result (first 32 bytes = nativeFee)
		if result.len() < 32 {
			return Err(BridgeError::FeeEstimation(format!(
				"quoteSend returned {} bytes, expected >= 32",
				result.len()
			)));
		}

		let native_fee = U256::from_be_slice(&result[..32]);
		Ok(native_fee)
	}

	/// Build a SendParam struct for OFT send.
	fn build_send_param(
		&self,
		dest_eid: u32,
		recipient: &Address,
		amount: U256,
		min_amount: Option<U256>,
	) -> SendParam {
		let extra_options = build_lz_receive_option(self.config.lz_receive_gas);

		SendParam {
			dstEid: dest_eid,
			to: address_to_bytes32(*recipient),
			amountLD: amount,
			minAmountLD: min_amount.unwrap_or(amount),
			extraOptions: extra_options.into(),
			composeMsg: Vec::new().into(),
			oftCmd: Vec::new().into(),
		}
	}

	/// Execute Katana -> Ethereum: OFT send() on Share OFT.
	/// After delivery, shares will need vault.redeem() on Ethereum (handled by monitor).
	async fn bridge_katana_to_ethereum(
		&self,
		request: &BridgeRequest,
	) -> Result<BridgeDepositResult, BridgeError> {
		let dest_eid = self.get_eid(request.dest_chain)?;
		let oft_address = request.source_token; // On Katana, source_token is vbUSDC = the OFT

		// Build SendParam
		let send_param = self.build_send_param(
			dest_eid,
			&self.solver_address,
			request.amount,
			request.min_amount,
		);

		// Quote the fee
		let native_fee = self
			.quote_send(request.source_chain, &oft_address, &send_param)
			.await?;

		// Build the send() call
		let call_data = IOFT::sendCall {
			_sendParam: send_param,
			_fee: MessagingFee {
				nativeFee: native_fee,
				lzTokenFee: U256::ZERO,
			},
			_refundAddress: self.solver_address,
		};

		let tx = Transaction {
			to: Some(solver_types::Address(oft_address.as_slice().to_vec())),
			data: call_data.abi_encode(),
			value: native_fee,
			chain_id: request.source_chain,
			nonce: None,
			gas_limit: Some(300_000),
			gas_price: None,
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
		};

		let tx_hash = self
			.delivery
			.deliver(tx, None)
			.await
			.map_err(|e| BridgeError::TransactionFailed(format!("OFT send failed: {e}")))?;

		let tx_hash_hex = format!("0x{}", hex::encode(&tx_hash.0));
		tracing::info!(
			pair = %request.pair_symbol,
			source = request.source_chain,
			dest = request.dest_chain,
			amount = %request.amount,
			tx_hash = %tx_hash_hex,
			"Submitted Katana -> Ethereum bridge transfer"
		);

		Ok(BridgeDepositResult {
			tx_hash: tx_hash_hex,
			message_guid: None, // Parsed from receipt later by monitor
			estimated_arrival: None,
		})
	}

	/// Execute Ethereum -> Katana: Approve USDC + call OVault Composer.
	async fn bridge_ethereum_to_katana(
		&self,
		request: &BridgeRequest,
	) -> Result<BridgeDepositResult, BridgeError> {
		let dest_eid = self.get_eid(request.dest_chain)?;

		// Get composer address for the source chain
		let composer_addr_str = self
			.config
			.composer_addresses
			.get(&request.source_chain)
			.ok_or_else(|| {
				BridgeError::Config(format!(
					"No composer address for chain {}",
					request.source_chain
				))
			})?;
		let composer_addr = Self::parse_config_address(composer_addr_str)?;

		// Approve USDC spending by Composer
		let approve_call = IERC20::approveCall {
			spender: composer_addr,
			amount: request.amount,
		};

		let approve_tx = Transaction {
			to: Some(solver_types::Address(
				request.source_token.as_slice().to_vec(),
			)),
			data: approve_call.abi_encode(),
			value: U256::ZERO,
			chain_id: request.source_chain,
			nonce: None,
			gas_limit: Some(100_000),
			gas_price: None,
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
		};

		self.delivery
			.deliver(approve_tx, None)
			.await
			.map_err(|e| BridgeError::TransactionFailed(format!("USDC approve failed: {e}")))?;

		// Quote the LZ fee via the OFT Adapter
		let oft_address = request.source_token; // OFT Adapter address from pair config
		let send_param = self.build_send_param(
			dest_eid,
			&self.solver_address,
			request.amount,
			request.min_amount,
		);
		let native_fee = self
			.quote_send(request.source_chain, &oft_address, &send_param)
			.await?;

		// Call Composer depositAndSend
		let extra_options = build_lz_receive_option(self.config.lz_receive_gas);
		let composer_call = IOVaultComposer::depositAndSendCall {
			token: request.source_token,
			amount: request.amount,
			dstEid: dest_eid,
			to: address_to_bytes32(self.solver_address),
			minAmountLD: request.min_amount.unwrap_or(request.amount),
			extraOptions: extra_options.into(),
		};

		let bridge_tx = Transaction {
			to: Some(solver_types::Address(composer_addr.as_slice().to_vec())),
			data: composer_call.abi_encode(),
			value: native_fee,
			chain_id: request.source_chain,
			nonce: None,
			gas_limit: Some(500_000),
			gas_price: None,
			max_fee_per_gas: None,
			max_priority_fee_per_gas: None,
		};

		let tx_hash = self.delivery.deliver(bridge_tx, None).await.map_err(|e| {
			BridgeError::TransactionFailed(format!("Composer depositAndSend failed: {e}"))
		})?;

		let tx_hash_hex = format!("0x{}", hex::encode(&tx_hash.0));
		tracing::info!(
			pair = %request.pair_symbol,
			source = request.source_chain,
			dest = request.dest_chain,
			amount = %request.amount,
			tx_hash = %tx_hash_hex,
			"Submitted Ethereum -> Katana bridge transfer"
		);

		Ok(BridgeDepositResult {
			tx_hash: tx_hash_hex,
			message_guid: None,
			estimated_arrival: None,
		})
	}
}

#[async_trait]
impl BridgeInterface for LayerZeroVaultBridge {
	fn supported_routes(&self) -> Vec<(u64, u64)> {
		// Build routes from configured endpoint IDs
		let chain_ids: Vec<u64> = self.config.endpoint_ids.keys().copied().collect();
		let mut routes = Vec::new();
		for &a in &chain_ids {
			for &b in &chain_ids {
				if a != b {
					routes.push((a, b));
				}
			}
		}
		routes
	}

	async fn bridge_asset(
		&self,
		request: &BridgeRequest,
	) -> Result<BridgeDepositResult, BridgeError> {
		// Validate route
		let routes = self.supported_routes();
		if !routes.contains(&(request.source_chain, request.dest_chain)) {
			return Err(BridgeError::UnsupportedRoute(
				request.source_chain,
				request.dest_chain,
			));
		}

		// Determine direction based on whether source chain has a composer
		// (Composer = Ethereum side = deposit + bridge)
		if self
			.config
			.composer_addresses
			.contains_key(&request.source_chain)
		{
			self.bridge_ethereum_to_katana(request).await
		} else {
			self.bridge_katana_to_ethereum(request).await
		}
	}

	async fn check_status(
		&self,
		transfer: &PendingBridgeTransfer,
	) -> Result<BridgeTransferStatus, BridgeError> {
		// Status checking based on current state
		match &transfer.status {
			BridgeTransferStatus::Submitted => {
				// Check if source tx has been confirmed
				if let Some(tx_hash) = &transfer.tx_hash {
					let hash_bytes = hex::decode(tx_hash.strip_prefix("0x").unwrap_or(tx_hash))
						.map_err(|e| BridgeError::Config(format!("Invalid tx hash: {e}")))?;
					let tx_hash_obj = solver_types::TransactionHash(hash_bytes);

					match self
						.delivery
						.get_receipt(&tx_hash_obj, transfer.source_chain)
						.await
					{
						Ok(receipt) => {
							if receipt.success {
								Ok(BridgeTransferStatus::Relaying)
							} else {
								Ok(BridgeTransferStatus::Failed(
									"Source transaction reverted".to_string(),
								))
							}
						},
						Err(e) => {
							tracing::debug!(
								transfer_id = %transfer.id,
								"Receipt not yet available: {e}"
							);
							Ok(BridgeTransferStatus::Submitted) // Still pending
						},
					}
				} else {
					Ok(BridgeTransferStatus::Submitted)
				}
			},
			BridgeTransferStatus::Relaying => {
				// TODO: Implement event-log based completion detection.
				// The monitor will scan Transfer events on the destination chain
				// from dest_scan_from_block forward.
				// For now, return Relaying (monitor handles timeout -> NeedsIntervention).
				Ok(BridgeTransferStatus::Relaying)
			},
			BridgeTransferStatus::PendingRedemption => {
				// Check redeem tx receipt if submitted
				if let Some(redeem_hash) = &transfer.redeem_tx_hash {
					let hash_bytes =
						hex::decode(redeem_hash.strip_prefix("0x").unwrap_or(redeem_hash))
							.map_err(|e| {
								BridgeError::Config(format!("Invalid redeem tx hash: {e}"))
							})?;
					let tx_hash_obj = solver_types::TransactionHash(hash_bytes);

					match self
						.delivery
						.get_receipt(&tx_hash_obj, transfer.dest_chain)
						.await
					{
						Ok(receipt) => {
							if receipt.success {
								Ok(BridgeTransferStatus::Completed)
							} else {
								Ok(BridgeTransferStatus::PendingRedemption) // Will retry
							}
						},
						Err(_) => Ok(BridgeTransferStatus::PendingRedemption), // Not yet confirmed
					}
				} else {
					// Shares arrived but redeem not yet submitted
					Ok(BridgeTransferStatus::PendingRedemption)
				}
			},
			// Terminal states don't change
			other => Ok(other.clone()),
		}
	}

	async fn estimate_fee(&self, request: &BridgeRequest) -> Result<U256, BridgeError> {
		let dest_eid = self.get_eid(request.dest_chain)?;

		// Use the OFT address from the source side for fee estimation
		let oft_address = if self
			.config
			.composer_addresses
			.contains_key(&request.source_chain)
		{
			// Ethereum side: use OFT Adapter address (from pair config)
			request.source_token
		} else {
			// Katana side: use Share OFT address (from pair config)
			request.source_token
		};

		let send_param = self.build_send_param(
			dest_eid,
			&self.solver_address,
			request.amount,
			request.min_amount,
		);

		self.quote_send(request.source_chain, &oft_address, &send_param)
			.await
	}
}

/// Factory function for creating a LayerZeroVaultBridge from config JSON.
pub fn create_bridge(
	config_json: &serde_json::Value,
	delivery: Arc<DeliveryService>,
) -> Result<Box<dyn BridgeInterface>, BridgeError> {
	let config: LayerZeroVaultBridgeConfig = serde_json::from_value(config_json.clone())
		.map_err(|e| BridgeError::Config(format!("Failed to parse VaultBridge config: {e}")))?;

	// TODO: Get solver address from AccountService
	// For now, use a placeholder that will be set during actual construction
	let solver_address = Address::ZERO;

	Ok(Box::new(LayerZeroVaultBridge::new(
		config,
		delivery,
		solver_address,
	)))
}
