//! LayerZero bridge implementation.
//!
//! Handles bridging USDC (Ethereum) <-> vbUSDC (Katana) via:
//! - ETH -> Katana: OVault Composer `depositAndSend` (vault deposit + OFT bridge)
//! - Katana -> ETH: OFT `send()` on Share OFT, then vault `redeem()` on Ethereum

pub mod contracts;
pub mod types;

use crate::types::{
	BridgeDepositResult, BridgeRequest, BridgeTransferStatus, PendingBridgeTransfer,
};
use crate::{BridgeError, BridgeInterface};
use alloy_primitives::{Address, U256};
use alloy_sol_types::SolCall;
use async_trait::async_trait;
use contracts::{address_to_bytes32, encode_lz_receive_option};
use solver_delivery::DeliveryService;
use std::sync::Arc;
use types::LayerZeroBridgeConfig;

/// LayerZero bridge implementation.
pub struct LayerZeroBridge {
	delivery: Arc<DeliveryService>,
	config: LayerZeroBridgeConfig,
	solver_address: Address,
}

/// Convert alloy Address to solver_types Address.
fn to_solver_addr(addr: Address) -> solver_types::Address {
	solver_types::Address(addr.as_slice().to_vec())
}

/// Build a solver_types Transaction for contract calls.
fn build_tx(chain_id: u64, to: Address, data: Vec<u8>, value: U256) -> solver_types::Transaction {
	// Convert U256 to solver_types U256 via bytes
	solver_types::Transaction {
		to: Some(to_solver_addr(to)),
		data,
		value,
		chain_id,
		nonce: None,
		gas_limit: None,
		gas_price: None,
		max_fee_per_gas: None,
		max_priority_fee_per_gas: None,
	}
}

impl LayerZeroBridge {
	fn get_eid(&self, chain_id: u64) -> Result<u32, BridgeError> {
		self.config
			.endpoint_ids
			.get(&chain_id)
			.copied()
			.ok_or_else(|| {
				BridgeError::Config(format!("No LayerZero EID configured for chain {chain_id}"))
			})
	}

	fn get_composer(&self, chain_id: u64) -> Result<Address, BridgeError> {
		let addr_str = self
			.config
			.composer_addresses
			.get(&chain_id)
			.ok_or_else(|| {
				BridgeError::Config(format!("No Composer address for chain {chain_id}"))
			})?;
		parse_address(addr_str)
	}

	#[allow(dead_code)]
	fn get_vault(&self, chain_id: u64) -> Result<Address, BridgeError> {
		let addr_str =
			self.config.vault_addresses.get(&chain_id).ok_or_else(|| {
				BridgeError::Config(format!("No Vault address for chain {chain_id}"))
			})?;
		parse_address(addr_str)
	}

	fn build_extra_options(&self) -> Vec<u8> {
		encode_lz_receive_option(self.config.lz_receive_gas)
	}

	/// Returns true if source chain has a composer (ETH→Katana path).
	fn is_composer_flow(&self, source_chain: u64) -> bool {
		self.config.composer_addresses.contains_key(&source_chain)
	}

	/// ETH → Katana: approve USDC to Composer, then call depositAndSend.
	async fn bridge_via_composer(
		&self,
		request: &BridgeRequest,
	) -> Result<BridgeDepositResult, BridgeError> {
		let composer_addr = self.get_composer(request.source_chain)?;
		let dest_eid = self.get_eid(request.dest_chain)?;
		let to_bytes32 = address_to_bytes32(self.solver_address);
		let extra_options = self.build_extra_options();

		// Step 1: Approve USDC to Composer
		let approve_data = contracts::approveCall {
			spender: composer_addr,
			amount: request.amount,
		}
		.abi_encode();

		let approve_tx = build_tx(
			request.source_chain,
			request.source_token,
			approve_data,
			U256::ZERO,
		);
		self.delivery
			.deliver(approve_tx, None)
			.await
			.map_err(|e| BridgeError::TransactionFailed(format!("Approve failed: {e}")))?;

		// Step 2: Estimate fee
		let fee = self.estimate_fee(request).await?;

		// Step 3: depositAndSend on Composer
		let messaging_fee = contracts::MessagingFee {
			nativeFee: fee,
			lzTokenFee: U256::ZERO,
		};

		let deposit_data = contracts::depositAndSendCall {
			assets: request.amount,
			dstEid: dest_eid,
			to: to_bytes32.into(),
			extraOptions: extra_options.into(),
			fee: messaging_fee,
			refundAddress: self.solver_address,
		}
		.abi_encode();

		let deposit_tx = build_tx(request.source_chain, composer_addr, deposit_data, fee);
		let tx_hash =
			self.delivery.deliver(deposit_tx, None).await.map_err(|e| {
				BridgeError::TransactionFailed(format!("depositAndSend failed: {e}"))
			})?;

		Ok(BridgeDepositResult {
			tx_hash: format!("0x{}", hex::encode(&tx_hash.0)),
			message_guid: None,
			estimated_arrival: None,
		})
	}

	/// Katana → ETH: approve shares to OFT, then call send().
	async fn bridge_via_oft_send(
		&self,
		request: &BridgeRequest,
	) -> Result<BridgeDepositResult, BridgeError> {
		let dest_eid = self.get_eid(request.dest_chain)?;
		let to_bytes32 = address_to_bytes32(self.solver_address);
		let extra_options = self.build_extra_options();
		let min_amount = request
			.min_amount
			.unwrap_or(request.amount * U256::from(95) / U256::from(100));

		// Step 1: Approve shares to OFT
		let approve_data = contracts::approveCall {
			spender: request.source_oft,
			amount: request.amount,
		}
		.abi_encode();

		let approve_tx = build_tx(
			request.source_chain,
			request.source_token,
			approve_data,
			U256::ZERO,
		);
		self.delivery
			.deliver(approve_tx, None)
			.await
			.map_err(|e| BridgeError::TransactionFailed(format!("Approve failed: {e}")))?;

		// Step 2: Estimate fee
		let fee = self.estimate_fee(request).await?;

		// Step 3: OFT send()
		let send_param = contracts::SendParam {
			dstEid: dest_eid,
			to: to_bytes32.into(),
			amountLD: request.amount,
			minAmountLD: min_amount,
			extraOptions: extra_options.into(),
			composeMsg: Vec::new().into(),
			oftCmd: Vec::new().into(),
		};

		let messaging_fee = contracts::MessagingFee {
			nativeFee: fee,
			lzTokenFee: U256::ZERO,
		};

		let send_data = contracts::sendCall {
			sendParam: send_param,
			fee: messaging_fee,
			refundAddress: self.solver_address,
		}
		.abi_encode();

		let send_tx = build_tx(request.source_chain, request.source_oft, send_data, fee);
		let tx_hash = self
			.delivery
			.deliver(send_tx, None)
			.await
			.map_err(|e| BridgeError::TransactionFailed(format!("OFT send failed: {e}")))?;

		Ok(BridgeDepositResult {
			tx_hash: format!("0x{}", hex::encode(&tx_hash.0)),
			message_guid: None,
			estimated_arrival: None,
		})
	}
}

#[async_trait]
impl BridgeInterface for LayerZeroBridge {
	fn supported_routes(&self) -> Vec<(u64, u64)> {
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
		if self.is_composer_flow(request.source_chain) {
			self.bridge_via_composer(request).await
		} else {
			self.bridge_via_oft_send(request).await
		}
	}

	async fn check_status(
		&self,
		transfer: &PendingBridgeTransfer,
	) -> Result<BridgeTransferStatus, BridgeError> {
		match &transfer.status {
			BridgeTransferStatus::Submitted => {
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
							Ok(BridgeTransferStatus::Submitted)
						},
					}
				} else {
					Ok(BridgeTransferStatus::Submitted)
				}
			},
			BridgeTransferStatus::Relaying => {
				// The monitor handles the Relaying → Completed/PendingRedemption
				// transition based on destination chain event scanning.
				// The driver returns Relaying; the monitor's timeout catches stalls.
				Ok(BridgeTransferStatus::Relaying)
			},
			BridgeTransferStatus::PendingRedemption => {
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
								// Signal failure so the monitor can handle retry logic
								Ok(BridgeTransferStatus::Failed(
									"Redeem transaction reverted".to_string(),
								))
							}
						},
						Err(_) => Ok(BridgeTransferStatus::PendingRedemption),
					}
				} else {
					Ok(BridgeTransferStatus::PendingRedemption)
				}
			},
			other => Ok(other.clone()),
		}
	}

	async fn estimate_fee(&self, request: &BridgeRequest) -> Result<U256, BridgeError> {
		let dest_eid = self.get_eid(request.dest_chain)?;
		let to_bytes32 = address_to_bytes32(self.solver_address);
		let extra_options = self.build_extra_options();
		let min_amount = request
			.min_amount
			.unwrap_or(request.amount * U256::from(95) / U256::from(100));

		let send_param = contracts::SendParam {
			dstEid: dest_eid,
			to: to_bytes32.into(),
			amountLD: request.amount,
			minAmountLD: min_amount,
			extraOptions: extra_options.into(),
			composeMsg: Vec::new().into(),
			oftCmd: Vec::new().into(),
		};

		let quote_data = contracts::quoteSendCall {
			sendParam: send_param,
			payInLzToken: false,
		}
		.abi_encode();

		let call_tx = build_tx(
			request.source_chain,
			request.source_oft,
			quote_data,
			U256::ZERO,
		);

		let result = self
			.delivery
			.contract_call(request.source_chain, call_tx)
			.await
			.map_err(|e| BridgeError::FeeEstimation(format!("quoteSend failed: {e}")))?;

		let decoded = contracts::quoteSendCall::abi_decode_returns(&result)
			.map_err(|e| BridgeError::FeeEstimation(format!("Failed to decode fee: {e}")))?;

		// quoteSend returns (MessagingFee), the decoded struct has the fee directly
		Ok(decoded.nativeFee)
	}
}

/// Factory function for creating a LayerZero bridge implementation.
pub fn create_bridge(
	config: &serde_json::Value,
	delivery: Arc<DeliveryService>,
	solver_address: Address,
) -> Result<Box<dyn BridgeInterface>, BridgeError> {
	if solver_address == Address::ZERO {
		return Err(BridgeError::Config(
			"Cannot create LayerZero bridge with zero solver address".to_string(),
		));
	}

	let bridge_config: LayerZeroBridgeConfig = serde_json::from_value(config.clone())
		.map_err(|e| BridgeError::Config(format!("Invalid LayerZero config: {e}")))?;

	if bridge_config.endpoint_ids.is_empty() {
		return Err(BridgeError::Config(
			"LayerZero config must have at least one endpoint_id".to_string(),
		));
	}

	Ok(Box::new(LayerZeroBridge {
		delivery,
		config: bridge_config,
		solver_address,
	}))
}

fn parse_address(s: &str) -> Result<Address, BridgeError> {
	let hex_str = s.strip_prefix("0x").unwrap_or(s);
	let bytes = hex::decode(hex_str)
		.map_err(|e| BridgeError::Config(format!("Invalid address hex '{s}': {e}")))?;
	let arr: [u8; 20] = bytes
		.try_into()
		.map_err(|_| BridgeError::Config(format!("Address must be 20 bytes: {s}")))?;
	Ok(Address::from(arr))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::test_support::bridge_request;
	use alloy_primitives::{Address, U256};
	use serde_json::json;
	use solver_delivery::MockDeliveryInterface;
	use solver_types::{Transaction, TransactionHash, TransactionReceipt};
	use std::collections::HashMap;
	use std::sync::{Arc, Mutex};

	fn solver_address() -> Address {
		Address::from([0xAA; 20])
	}

	fn zero_address() -> Address {
		Address::ZERO
	}

	fn bridge_config(composer: Option<Address>) -> serde_json::Value {
		let mut composer_addresses = serde_json::Map::new();
		if let Some(addr) = composer {
			composer_addresses.insert("1".to_string(), json!(format!("0x{}", hex::encode(addr.as_slice()))));
		}

		json!({
			"endpoint_ids": {
				"1": 100,
				"747474": 200
			},
			"lz_receive_gas": 200000u128,
			"composer_addresses": composer_addresses,
			"vault_addresses": {}
		})
	}

	fn bridge_with_two_chain_delivery(
		mock: MockDeliveryInterface,
		composer: Option<Address>,
	) -> LayerZeroBridge {
		let shared = Arc::new(mock);
		LayerZeroBridge {
			delivery: Arc::new(DeliveryService::new(
				HashMap::from([
					(1_u64, shared.clone() as Arc<dyn solver_delivery::DeliveryInterface>),
					(
						747474_u64,
						shared.clone() as Arc<dyn solver_delivery::DeliveryInterface>,
					),
				]),
				3,
				300,
			)),
			config: serde_json::from_value(bridge_config(composer)).unwrap(),
			solver_address: solver_address(),
		}
	}

	fn tx_to(tx: &Transaction) -> Address {
		tx.to
			.as_ref()
			.map(|addr| Address::from_slice(addr.0.as_slice()))
			.expect("transaction should have a recipient")
	}

	fn decode_submit<T: alloy_sol_types::SolCall>(tx: &Transaction) -> T {
		T::abi_decode(&tx.data).expect("failed to decode call data")
	}

	fn quote_fee_bytes(native_fee: U256) -> Vec<u8> {
		contracts::quoteSendCall::abi_encode_returns(&contracts::MessagingFee {
			nativeFee: native_fee,
			lzTokenFee: U256::ZERO,
		})
	}

	#[tokio::test]
	async fn test_bridge_via_composer_approves_source_token_and_calls_deposit_and_send_on_composer() {
		let request = bridge_request();
		let composer = Address::from([0xCC; 20]);
		let fee = U256::from(12345u64);
		let submitted = Arc::new(Mutex::new(Vec::<Transaction>::new()));
		let mut mock = MockDeliveryInterface::new();

		{
			let submitted = submitted.clone();
			mock.expect_submit().times(2).returning(move |tx, _| {
				let submitted = submitted.clone();
				Box::pin(async move {
					submitted.lock().unwrap().push(tx.clone());
					Ok(TransactionHash(vec![0x11; 32]))
				})
			});
		}

		let expected_oft = request.source_oft;
		mock.expect_eth_call().returning(move |tx| {
			assert_eq!(
				tx.to.as_ref().map(|addr| Address::from_slice(addr.0.as_slice())),
				Some(expected_oft)
			);
			Box::pin(async move { Ok(alloy_primitives::Bytes::from(quote_fee_bytes(fee))) })
		});

		let bridge = bridge_with_two_chain_delivery(mock, Some(composer));
		let result = bridge.bridge_asset(&request).await.unwrap();

		assert_eq!(result.tx_hash, format!("0x{}", hex::encode(vec![0x11; 32])));
		let submitted = submitted.lock().unwrap();
		assert_eq!(submitted.len(), 2);

		assert_eq!(tx_to(&submitted[0]), request.source_token);
		let approve_call: contracts::approveCall = decode_submit(&submitted[0]);
		assert_eq!(approve_call.spender, composer);
		assert_eq!(approve_call.amount, request.amount);

		assert_eq!(tx_to(&submitted[1]), composer);
		let deposit_call: contracts::depositAndSendCall = decode_submit(&submitted[1]);
		assert_eq!(deposit_call.refundAddress, solver_address());
		assert_eq!(deposit_call.to, contracts::address_to_bytes32(solver_address()));
		assert_eq!(deposit_call.dstEid, 200);
		assert_eq!(deposit_call.fee.nativeFee, fee);
	}

	#[tokio::test]
	async fn test_bridge_via_oft_send_approves_source_token_and_calls_send_on_source_oft() {
		let request = bridge_request();
		let fee = U256::from(12345u64);
		let submitted = Arc::new(Mutex::new(Vec::<Transaction>::new()));
		let mut mock = MockDeliveryInterface::new();

		{
			let submitted = submitted.clone();
			mock.expect_submit().times(2).returning(move |tx, _| {
				let submitted = submitted.clone();
				Box::pin(async move {
					submitted.lock().unwrap().push(tx.clone());
					Ok(TransactionHash(vec![0x22; 32]))
				})
			});
		}

		let expected_oft = request.source_oft;
		mock.expect_eth_call().returning(move |tx| {
			assert_eq!(
				tx.to.as_ref().map(|addr| Address::from_slice(addr.0.as_slice())),
				Some(expected_oft)
			);
			Box::pin(async move { Ok(alloy_primitives::Bytes::from(quote_fee_bytes(fee))) })
		});

		let bridge = bridge_with_two_chain_delivery(mock, None);
		let result = bridge.bridge_asset(&request).await.unwrap();

		assert_eq!(result.tx_hash, format!("0x{}", hex::encode(vec![0x22; 32])));
		let submitted = submitted.lock().unwrap();
		assert_eq!(submitted.len(), 2);

		assert_eq!(tx_to(&submitted[0]), request.source_token);
		let approve_call: contracts::approveCall = decode_submit(&submitted[0]);
		assert_eq!(approve_call.spender, request.source_oft);
		assert_eq!(approve_call.amount, request.amount);

		assert_eq!(tx_to(&submitted[1]), request.source_oft);
		let send_call: contracts::sendCall = decode_submit(&submitted[1]);
		assert_eq!(send_call.refundAddress, solver_address());
		assert_eq!(send_call.sendParam.to, contracts::address_to_bytes32(solver_address()));
		assert_eq!(send_call.sendParam.dstEid, 200);
		assert_eq!(send_call.fee.nativeFee, fee);
	}

	#[tokio::test]
	async fn test_check_status_submitted_becomes_relaying_on_successful_receipt() {
		let transfer = crate::test_support::pending_transfer(BridgeTransferStatus::Submitted);
		let mut transfer = transfer;
		transfer.tx_hash = Some("0x01".to_string());
		let mut mock = MockDeliveryInterface::new();
		mock.expect_get_receipt().returning(|_, _| {
			Box::pin(async move {
				Ok(TransactionReceipt {
					hash: TransactionHash(vec![0x01; 32]),
					block_number: 42,
					success: true,
					logs: vec![],
					block_timestamp: None,
				})
			})
		});

		let bridge = bridge_with_two_chain_delivery(mock, None);
		let status = bridge.check_status(&transfer).await.unwrap();
		assert!(matches!(status, BridgeTransferStatus::Relaying));
	}

	#[tokio::test]
	async fn test_check_status_submitted_becomes_failed_on_reverted_receipt() {
		let transfer = crate::test_support::pending_transfer(BridgeTransferStatus::Submitted);
		let mut transfer = transfer;
		transfer.tx_hash = Some("0x02".to_string());
		let mut mock = MockDeliveryInterface::new();
		mock.expect_get_receipt().returning(|_, _| {
			Box::pin(async move {
				Ok(TransactionReceipt {
					hash: TransactionHash(vec![0x02; 32]),
					block_number: 42,
					success: false,
					logs: vec![],
					block_timestamp: None,
				})
			})
		});

		let bridge = bridge_with_two_chain_delivery(mock, None);
		let status = bridge.check_status(&transfer).await.unwrap();
		assert!(matches!(status, BridgeTransferStatus::Failed(reason) if reason == "Source transaction reverted"));
	}

	#[tokio::test]
	async fn test_check_status_pending_redemption_becomes_completed_on_successful_redeem_receipt() {
		let mut transfer = crate::test_support::pending_transfer(BridgeTransferStatus::PendingRedemption);
		transfer.redeem_tx_hash = Some("0x03".to_string());
		let mut mock = MockDeliveryInterface::new();
		mock.expect_get_receipt().returning(|_, _| {
			Box::pin(async move {
				Ok(TransactionReceipt {
					hash: TransactionHash(vec![0x03; 32]),
					block_number: 43,
					success: true,
					logs: vec![],
					block_timestamp: None,
				})
			})
		});

		let bridge = bridge_with_two_chain_delivery(mock, None);
		let status = bridge.check_status(&transfer).await.unwrap();
		assert!(matches!(status, BridgeTransferStatus::Completed));
	}

	#[tokio::test]
	async fn test_check_status_pending_redemption_returns_failed_on_reverted_redeem_receipt() {
		let mut transfer = crate::test_support::pending_transfer(BridgeTransferStatus::PendingRedemption);
		transfer.redeem_tx_hash = Some("0x04".to_string());
		let mut mock = MockDeliveryInterface::new();
		mock.expect_get_receipt().returning(|_, _| {
			Box::pin(async move {
				Ok(TransactionReceipt {
					hash: TransactionHash(vec![0x04; 32]),
					block_number: 43,
					success: false,
					logs: vec![],
					block_timestamp: None,
				})
			})
		});

		let bridge = bridge_with_two_chain_delivery(mock, None);
		let status = bridge.check_status(&transfer).await.unwrap();
		assert!(matches!(status, BridgeTransferStatus::Failed(reason) if reason == "Redeem transaction reverted"));
	}

	#[test]
	fn test_create_bridge_rejects_zero_solver_address() {
		let mut mock = MockDeliveryInterface::new();
		mock.expect_submit().times(0);
		mock.expect_get_receipt().times(0);
		mock.expect_eth_call().times(0);
		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(1_u64, Arc::new(mock) as Arc<dyn solver_delivery::DeliveryInterface>)]),
			3,
			300,
		));

		let result = create_bridge(&bridge_config(Some(Address::from([0xCC; 20]))), delivery, zero_address());
		assert!(matches!(result, Err(BridgeError::Config(msg)) if msg.contains("zero solver address")));
	}

	#[tokio::test]
	async fn test_estimate_fee_uses_the_same_directional_contract_as_bridge_asset() {
		let request = bridge_request();
		let fee = U256::from(777u64);
		let call_target = Arc::new(Mutex::new(None));
		let mut mock = MockDeliveryInterface::new();
		{
			let call_target = call_target.clone();
			mock.expect_eth_call().returning(move |tx| {
				*call_target.lock().unwrap() = Some(tx.clone());
				Box::pin(async move { Ok(alloy_primitives::Bytes::from(quote_fee_bytes(fee))) })
			});
		}

		let bridge = bridge_with_two_chain_delivery(mock, Some(Address::from([0xCC; 20])));
		let quoted = bridge.estimate_fee(&request).await.unwrap();

		assert_eq!(quoted, fee);
		let tx = call_target.lock().unwrap().clone().expect("missing contract call");
		assert_eq!(tx_to(&tx), request.source_oft);
		assert_ne!(tx_to(&tx), request.source_token);
	}
}
