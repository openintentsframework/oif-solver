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

/// OFT send() is still kept on a fixed gas limit to avoid changing the
/// Katana -> Ethereum path while fixing the composer-only regression.
const OFT_BRIDGE_TX_GAS_LIMIT: u64 = 500_000;
/// Gas limit for ERC-20 `approve` txs. A real approve costs ~46k gas; 100k
/// gives ~2× headroom. The wider `OFT_BRIDGE_TX_GAS_LIMIT` was historically
/// reused for approves, but every signed tx forces the RPC to reserve
/// `gas_limit × max_fee_per_gas` of native balance — so a 500k limit
/// reservation is ~5× more native ETH than the operation actually needs.
/// On a thin balance, this can push the reservation above on-hand funds and
/// cause the upstream pool to silently drop the tx (returning a hash but
/// never propagating).
const ERC20_APPROVE_GAS_LIMIT: u64 = 100_000;
/// Add 25% headroom on top of the estimated composer gas.
const COMPOSER_GAS_BUFFER_BPS: u64 = 2_500;
/// If estimateGas fails, still submit with a higher cap than the old 500k.
const COMPOSER_FALLBACK_GAS_LIMIT: u64 = 1_200_000;
/// Guardrail against a pathological estimate response.
const COMPOSER_MAX_GAS_LIMIT: u64 = 2_000_000;
/// Historical submit-and-confirm receipt polling budget.
#[cfg(not(test))]
const SUBMIT_CONFIRM_ATTEMPTS: u32 = 12;
#[cfg(test)]
const SUBMIT_CONFIRM_ATTEMPTS: u32 = 3;
/// Historical submit-and-confirm receipt polling interval.
#[cfg(not(test))]
const SUBMIT_CONFIRM_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
#[cfg(test)]
const SUBMIT_CONFIRM_INTERVAL: std::time::Duration = std::time::Duration::from_millis(1);

fn build_tx(
	chain_id: u64,
	to: Address,
	data: Vec<u8>,
	value: U256,
	gas_limit: Option<u64>,
) -> solver_types::Transaction {
	solver_types::Transaction {
		to: Some(to_solver_addr(to)),
		data,
		value,
		chain_id,
		nonce: None,
		gas_limit,
		gas_price: None,
		max_fee_per_gas: None,
		max_priority_fee_per_gas: None,
	}
}

fn map_delivery_error(label: &str, error: solver_delivery::DeliveryError) -> BridgeError {
	let msg = format!("{label} submit failed: {error}");
	match error {
		solver_delivery::DeliveryError::InsufficientNativeGas(_) => {
			BridgeError::InsufficientNativeGas(msg)
		},
		_ => BridgeError::TransactionFailed(msg),
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

	fn build_extra_options(&self) -> Vec<u8> {
		encode_lz_receive_option(self.config.lz_receive_gas)
	}

	/// Returns true if source chain has a composer (ETH→Katana path).
	fn is_composer_flow(&self, source_chain: u64) -> bool {
		self.config.composer_addresses.contains_key(&source_chain)
	}

	async fn resolve_composer_gas_limit(
		&self,
		chain_id: u64,
		tx: solver_types::Transaction,
	) -> u64 {
		match self.delivery.estimate_gas(chain_id, tx).await {
			Ok(estimated) => estimated
				.saturating_mul(10_000 + COMPOSER_GAS_BUFFER_BPS)
				.saturating_div(10_000)
				.min(COMPOSER_MAX_GAS_LIMIT),
			Err(e) => {
				tracing::info!(
					chain_id,
					fallback_gas_limit = COMPOSER_FALLBACK_GAS_LIMIT,
					error = %e,
					"Falling back to fixed composer gas limit after estimate_gas failure"
				);
				COMPOSER_FALLBACK_GAS_LIMIT
			},
		}
	}

	/// Submit a transaction and poll for receipt confirmation.
	async fn submit_and_confirm(
		&self,
		tx: solver_types::Transaction,
		label: &str,
	) -> Result<solver_types::TransactionHash, BridgeError> {
		let chain_id = tx.chain_id;
		let hash = self
			.delivery
			.deliver(tx, None)
			.await
			.map_err(|e| map_delivery_error(label, e))?;

		for attempt in 1..=SUBMIT_CONFIRM_ATTEMPTS {
			match self.delivery.get_receipt(&hash, chain_id).await {
				Ok(receipt) => {
					if receipt.success {
						return Ok(hash);
					} else {
						return Err(BridgeError::TransactionFailed(format!(
							"{label} reverted on-chain"
						)));
					}
				},
				Err(_) if attempt < SUBMIT_CONFIRM_ATTEMPTS => {
					tokio::time::sleep(SUBMIT_CONFIRM_INTERVAL).await;
				},
				Err(e) => {
					return Err(BridgeError::TransactionFailed(format!(
						"{label} receipt not found after {SUBMIT_CONFIRM_ATTEMPTS} attempts: {e}"
					)));
				},
			}
		}
		unreachable!()
	}

	/// ETH → Katana: approve USDC to Composer (skipping when the existing
	/// allowance is already sufficient), then call depositAndSend.
	///
	/// The approve phase intentionally uses the historical synchronous
	/// submit-and-confirm path. A timed-out approve is a pre-deposit failure,
	/// not a durable bridge attempt, so it should not leave the transfer in an
	/// approval-resume loop.
	async fn bridge_via_composer(
		&self,
		request: &BridgeRequest,
	) -> Result<BridgeDepositResult, BridgeError> {
		let composer_addr = self.get_composer(request.source_chain)?;
		let dest_eid = self.get_eid(request.dest_chain)?;
		let to_bytes32 = address_to_bytes32(self.solver_address);
		let extra_options = self.build_extra_options();
		let min_amount = request
			.min_amount
			.unwrap_or(request.amount * U256::from(95) / U256::from(100));

		// Step 1: allowance precheck. If we already have enough allowance,
		// skip approve entirely.
		//
		// On RPC failure we MUST NOT promote to NeedsIntervention via the
		// generic-error arm in rebalance_token. ERC-20 `approve` is a `set`,
		// not an `add` — some tokens (e.g. USDT) revert on nonzero-to-nonzero
		// approvals — so this is a *safe operational fallback*, not strict
		// idempotency. Any approve failure surfaces cleanly through the
		// existing ApproveSubmitFailed / ApproveReverted arms instead of
		// silently stranding the transfer due to a precheck RPC blip.
		let current_allowance = match self
			.read_allowance(
				request.source_chain,
				request.source_token,
				self.solver_address,
				composer_addr,
			)
			.await
		{
			Ok(a) => a,
			Err(e) => {
				tracing::warn!(
					chain_id = request.source_chain,
					error = %e,
					"read_allowance failed; falling through to approve path"
				);
				U256::ZERO
			},
		};

		if current_allowance >= request.amount {
			tracing::info!(
				chain_id = request.source_chain,
				current_allowance = %current_allowance,
				requested = %request.amount,
				"Allowance already sufficient; skipping Composer approve"
			);
		} else {
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
				Some(ERC20_APPROVE_GAS_LIMIT),
			);

			self.submit_and_confirm(approve_tx, "Composer approve")
				.await
				.map_err(|e| match e {
					BridgeError::InsufficientNativeGas(_) => e,
					other => BridgeError::ApproveSubmitFailed {
						error: other.to_string(),
					},
				})?;
		}

		// Step 2: Estimate fee
		let fee = self.estimate_fee(request).await?;

		// Step 3: depositAndSend on Composer
		let send_param = contracts::SendParam {
			dstEid: dest_eid,
			to: to_bytes32.into(),
			amountLD: request.amount,
			minAmountLD: min_amount,
			extraOptions: extra_options.into(),
			composeMsg: Vec::new().into(),
			oftCmd: Vec::new().into(),
		};

		let deposit_data = contracts::IVaultComposerSync::depositAndSendCall {
			assetAmount: request.amount,
			sendParam: send_param,
			refundAddress: self.solver_address,
		}
		.abi_encode();

		let deposit_tx = build_tx(request.source_chain, composer_addr, deposit_data, fee, None);
		let composer_gas_limit = self
			.resolve_composer_gas_limit(request.source_chain, deposit_tx.clone())
			.await;
		let mut deposit_tx = deposit_tx;
		deposit_tx.gas_limit = Some(composer_gas_limit);
		let tx_hash = self
			.delivery
			.deliver(deposit_tx, None)
			.await
			.map_err(|e| map_delivery_error("depositAndSend", e))?;

		Ok(BridgeDepositResult {
			tx_hash: format!("0x{}", hex::encode(&tx_hash.0)),
			message_guid: None,
			estimated_arrival: None,
		})
	}

	/// Katana → ETH: approve shares to OFT (skipping when the existing
	/// allowance is already sufficient), then call send().
	///
	/// The approve phase intentionally uses the historical synchronous
	/// submit-and-confirm path. A timed-out approve is a pre-deposit failure,
	/// not a durable bridge attempt, so it should not leave the transfer in an
	/// approval-resume loop.
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

		// Step 1: allowance precheck. If we already have enough allowance,
		// skip approve entirely.
		//
		// Same safe-operational-fallback rationale as bridge_via_composer:
		// a transient RPC failure on the precheck must not promote to
		// NeedsIntervention. See bridge_via_composer for the full comment.
		let current_allowance = match self
			.read_allowance(
				request.source_chain,
				request.source_token,
				self.solver_address,
				request.source_oft,
			)
			.await
		{
			Ok(a) => a,
			Err(e) => {
				tracing::warn!(
					chain_id = request.source_chain,
					error = %e,
					"read_allowance failed; falling through to approve path"
				);
				U256::ZERO
			},
		};

		if current_allowance >= request.amount {
			tracing::info!(
				chain_id = request.source_chain,
				current_allowance = %current_allowance,
				requested = %request.amount,
				"Allowance already sufficient; skipping OFT approve"
			);
		} else {
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
				Some(ERC20_APPROVE_GAS_LIMIT),
			);

			self.submit_and_confirm(approve_tx, "OFT approve")
				.await
				.map_err(|e| match e {
					BridgeError::InsufficientNativeGas(_) => e,
					other => BridgeError::ApproveSubmitFailed {
						error: other.to_string(),
					},
				})?;
		}

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

		let send_data = contracts::IOFT::sendCall {
			sendParam: send_param,
			fee: messaging_fee,
			refundAddress: self.solver_address,
		}
		.abi_encode();

		let send_tx = build_tx(
			request.source_chain,
			request.source_oft,
			send_data,
			fee,
			Some(OFT_BRIDGE_TX_GAS_LIMIT),
		);
		let tx_hash = self
			.delivery
			.deliver(send_tx, None)
			.await
			.map_err(|e| map_delivery_error("OFT send", e))?;

		Ok(BridgeDepositResult {
			tx_hash: format!("0x{}", hex::encode(&tx_hash.0)),
			message_guid: None,
			estimated_arrival: None,
		})
	}

	/// Reads the ERC-20 allowance for `owner -> spender` on `token` via the
	/// public `DeliveryService::get_allowance` API.
	///
	/// Wraps the decimal string return value as `U256` so callers can compare
	/// it directly against `request.amount`. No raw `eth_call` and no new ABI
	/// binding — the bridge defers ERC-20 ABI encoding/decoding to the delivery
	/// layer.
	async fn read_allowance(
		&self,
		chain_id: u64,
		token: alloy_primitives::Address,
		owner: alloy_primitives::Address,
		spender: alloy_primitives::Address,
	) -> Result<U256, BridgeError> {
		// Format addresses in the canonical "0x…" form get_allowance expects.
		let owner_str = format!("0x{}", hex::encode(owner.as_slice()));
		let spender_str = format!("0x{}", hex::encode(spender.as_slice()));
		let token_str = format!("0x{}", hex::encode(token.as_slice()));

		let allowance_str = self
			.delivery
			.get_allowance(chain_id, &owner_str, &spender_str, &token_str)
			.await
			.map_err(|e| BridgeError::TransactionFailed(format!("get_allowance failed: {e}")))?;

		U256::from_str_radix(&allowance_str, 10).map_err(|e| {
			BridgeError::TransactionFailed(format!(
				"get_allowance returned non-numeric '{allowance_str}': {e}"
			))
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
						Err(_) => {
							// No receipt — check if tx is still in mempool or was dropped
							match self
								.delivery
								.tx_exists(&tx_hash_obj, transfer.source_chain)
								.await
							{
								Ok(true) => {
									// Tx exists (pending or in mempool) — keep waiting
									tracing::debug!(
										transfer_id = %transfer.id,
										"Source tx pending, receipt not yet available"
									);
									Ok(BridgeTransferStatus::Submitted)
								},
								Ok(false) => {
									// Tx not found on chain — signal to monitor for threshold tracking.
									// The monitor decides whether enough misses have accumulated to fail.
									Ok(BridgeTransferStatus::Failed(
										"Source transaction not found".to_string(),
									))
								},
								Err(e) => {
									// RPC error — don't make a decision, stay Submitted
									tracing::debug!(
										transfer_id = %transfer.id,
										"tx_exists check failed: {e}"
									);
									Ok(BridgeTransferStatus::Submitted)
								},
							}
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
						Err(_) => {
							// Receipt unavailable — distinguish "still pending in
							// mempool" from "stored hash refers to a tx that never
							// propagated / was dropped". The latter must surface so
							// the monitor can clear the stale hash and resubmit;
							// otherwise the transfer stays stuck waiting on a hash
							// that will never resolve.
							match self
								.delivery
								.tx_exists(&tx_hash_obj, transfer.dest_chain)
								.await
							{
								Ok(true) => {
									tracing::debug!(
										transfer_id = %transfer.id,
										redeem_tx_hash = %redeem_hash,
										"Redeem tx pending, receipt not yet available"
									);
									Ok(BridgeTransferStatus::PendingRedemption)
								},
								Ok(false) => {
									tracing::warn!(
										transfer_id = %transfer.id,
										redeem_tx_hash = %redeem_hash,
										"Redeem tx hash not found on chain"
									);
									Ok(BridgeTransferStatus::Failed(
										"Redeem transaction not found".to_string(),
									))
								},
								Err(e) => {
									tracing::debug!(
										transfer_id = %transfer.id,
										redeem_tx_hash = %redeem_hash,
										"redeem tx_exists check failed: {e}"
									);
									Ok(BridgeTransferStatus::PendingRedemption)
								},
							}
						},
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

		if self.is_composer_flow(request.source_chain) {
			// Composer has its own quoteSend with different params
			let quote_data = contracts::IVaultComposerSync::quoteSendCall {
				from: self.solver_address,
				targetOft: request.source_oft,
				vaultInAmount: request.amount,
				sendParam: send_param,
			}
			.abi_encode();

			let call_tx = build_tx(
				request.source_chain,
				self.get_composer(request.source_chain)?,
				quote_data,
				U256::ZERO,
				None,
			);

			let result = self
				.delivery
				.contract_call(request.source_chain, call_tx)
				.await
				.map_err(|e| BridgeError::FeeEstimation(format!("quoteSend failed: {e}")))?;

			let decoded = contracts::IVaultComposerSync::quoteSendCall::abi_decode_returns(&result)
				.map_err(|e| BridgeError::FeeEstimation(format!("Failed to decode fee: {e}")))?;

			Ok(decoded.nativeFee)
		} else {
			// Direct OFT quoteSend
			let quote_data = contracts::IOFT::quoteSendCall {
				sendParam: send_param,
				payInLzToken: false,
			}
			.abi_encode();

			let call_tx = build_tx(
				request.source_chain,
				request.source_oft,
				quote_data,
				U256::ZERO,
				None,
			);

			let result = self
				.delivery
				.contract_call(request.source_chain, call_tx)
				.await
				.map_err(|e| BridgeError::FeeEstimation(format!("quoteSend failed: {e}")))?;

			let decoded = contracts::IOFT::quoteSendCall::abi_decode_returns(&result)
				.map_err(|e| BridgeError::FeeEstimation(format!("Failed to decode fee: {e}")))?;

			Ok(decoded.nativeFee)
		}
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
	use solver_delivery::{DeliveryError, MockDeliveryInterface};
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
			composer_addresses.insert(
				"1".to_string(),
				json!(format!("0x{}", hex::encode(addr.as_slice()))),
			);
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
					(
						1_u64,
						shared.clone() as Arc<dyn solver_delivery::DeliveryInterface>,
					),
					(
						747474_u64,
						shared.clone() as Arc<dyn solver_delivery::DeliveryInterface>,
					),
				]),
				3,
				300,
				60,
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

	fn oft_quote_fee_bytes(native_fee: U256) -> Vec<u8> {
		contracts::IOFT::quoteSendCall::abi_encode_returns(&contracts::MessagingFee {
			nativeFee: native_fee,
			lzTokenFee: U256::ZERO,
		})
	}

	fn composer_quote_fee_bytes(native_fee: U256) -> Vec<u8> {
		contracts::IVaultComposerSync::quoteSendCall::abi_encode_returns(&contracts::MessagingFee {
			nativeFee: native_fee,
			lzTokenFee: U256::ZERO,
		})
	}

	#[tokio::test]
	async fn test_bridge_via_composer_approves_source_token_and_calls_deposit_and_send_on_composer()
	{
		let request = bridge_request();
		let composer = Address::from([0xCC; 20]);
		let fee = U256::from(12345u64);
		let submitted = Arc::new(Mutex::new(Vec::<Transaction>::new()));
		let mut mock = MockDeliveryInterface::new();

		// Allowance precheck returns 0 -> approve path is exercised.
		mock.expect_get_allowance()
			.returning(|_, _, _, _| Box::pin(async move { Ok("0".to_string()) }));

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

		// Approve receipt poll
		mock.expect_get_receipt().returning(|_, _| {
			Box::pin(async move {
				Ok(TransactionReceipt {
					hash: TransactionHash(vec![0x11; 32]),
					block_number: 1,
					success: true,
					logs: vec![],
					block_timestamp: None,
				})
			})
		});

		let expected_composer = composer;
		mock.expect_eth_call().returning(move |tx| {
			// Composer flow calls quoteSend on the composer address
			assert_eq!(
				tx.to
					.as_ref()
					.map(|addr| Address::from_slice(addr.0.as_slice())),
				Some(expected_composer)
			);
			Box::pin(
				async move { Ok(alloy_primitives::Bytes::from(composer_quote_fee_bytes(fee))) },
			)
		});
		mock.expect_estimate_gas().times(1).returning(move |tx| {
			assert_eq!(tx_to(&tx), composer);
			assert_eq!(tx.value, fee);
			assert_eq!(tx.gas_limit, None);
			Box::pin(async move { Ok(900_000) })
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
		let deposit_call: contracts::IVaultComposerSync::depositAndSendCall =
			decode_submit(&submitted[1]);
		assert_eq!(deposit_call.refundAddress, solver_address());
		assert_eq!(deposit_call.assetAmount, request.amount);
		assert_eq!(deposit_call.sendParam.dstEid, 200);
		assert_eq!(
			deposit_call.sendParam.to,
			contracts::address_to_bytes32(solver_address())
		);
		assert_eq!(submitted[1].gas_limit, Some(1_125_000));
	}

	#[tokio::test]
	async fn test_bridge_via_composer_uses_estimated_gas_with_buffer() {
		let request = bridge_request();
		let composer = Address::from([0xCC; 20]);
		let fee = U256::from(12345u64);
		let submitted = Arc::new(Mutex::new(Vec::<Transaction>::new()));
		let mut mock = MockDeliveryInterface::new();

		mock.expect_get_allowance()
			.returning(|_, _, _, _| Box::pin(async move { Ok("0".to_string()) }));

		{
			let submitted = submitted.clone();
			mock.expect_submit().times(2).returning(move |tx, _| {
				let submitted = submitted.clone();
				Box::pin(async move {
					submitted.lock().unwrap().push(tx.clone());
					Ok(TransactionHash(vec![0x33; 32]))
				})
			});
		}

		mock.expect_get_receipt().returning(|_, _| {
			Box::pin(async move {
				Ok(TransactionReceipt {
					hash: TransactionHash(vec![0x33; 32]),
					block_number: 1,
					success: true,
					logs: vec![],
					block_timestamp: None,
				})
			})
		});

		let expected_composer = composer;
		mock.expect_eth_call().returning(move |tx| {
			assert_eq!(
				tx.to
					.as_ref()
					.map(|addr| Address::from_slice(addr.0.as_slice())),
				Some(expected_composer)
			);
			Box::pin(
				async move { Ok(alloy_primitives::Bytes::from(composer_quote_fee_bytes(fee))) },
			)
		});

		let expected_composer = composer;
		mock.expect_estimate_gas().times(1).returning(move |tx| {
			assert_eq!(tx.value, fee);
			assert_eq!(tx.gas_limit, None);
			assert_eq!(tx_to(&tx), expected_composer);
			let deposit_call: contracts::IVaultComposerSync::depositAndSendCall =
				decode_submit(&tx);
			assert_eq!(deposit_call.assetAmount, request.amount);
			Box::pin(async move { Ok(900_000) })
		});

		let bridge = bridge_with_two_chain_delivery(mock, Some(composer));
		bridge.bridge_asset(&request).await.unwrap();

		let submitted = submitted.lock().unwrap();
		assert_eq!(submitted.len(), 2);
		assert_eq!(submitted[1].gas_limit, Some(1_125_000));
	}

	#[tokio::test]
	async fn test_bridge_via_composer_falls_back_when_estimate_gas_fails() {
		let request = bridge_request();
		let composer = Address::from([0xCC; 20]);
		let fee = U256::from(12345u64);
		let submitted = Arc::new(Mutex::new(Vec::<Transaction>::new()));
		let mut mock = MockDeliveryInterface::new();

		mock.expect_get_allowance()
			.returning(|_, _, _, _| Box::pin(async move { Ok("0".to_string()) }));

		{
			let submitted = submitted.clone();
			mock.expect_submit().times(2).returning(move |tx, _| {
				let submitted = submitted.clone();
				Box::pin(async move {
					submitted.lock().unwrap().push(tx.clone());
					Ok(TransactionHash(vec![0x44; 32]))
				})
			});
		}

		mock.expect_get_receipt().returning(|_, _| {
			Box::pin(async move {
				Ok(TransactionReceipt {
					hash: TransactionHash(vec![0x44; 32]),
					block_number: 1,
					success: true,
					logs: vec![],
					block_timestamp: None,
				})
			})
		});

		let expected_composer = composer;
		mock.expect_eth_call().returning(move |tx| {
			assert_eq!(
				tx.to
					.as_ref()
					.map(|addr| Address::from_slice(addr.0.as_slice())),
				Some(expected_composer)
			);
			Box::pin(
				async move { Ok(alloy_primitives::Bytes::from(composer_quote_fee_bytes(fee))) },
			)
		});

		mock.expect_estimate_gas().times(1).returning(|tx| {
			assert_eq!(tx.gas_limit, None);
			Box::pin(async move { Err(DeliveryError::Network("boom".to_string())) })
		});

		let bridge = bridge_with_two_chain_delivery(mock, Some(composer));
		bridge.bridge_asset(&request).await.unwrap();

		let submitted = submitted.lock().unwrap();
		assert_eq!(submitted.len(), 2);
		assert_eq!(submitted[1].gas_limit, Some(1_200_000));
	}

	#[tokio::test]
	async fn test_bridge_via_oft_send_approves_source_token_and_calls_send_on_source_oft() {
		let request = bridge_request();
		let fee = U256::from(12345u64);
		let submitted = Arc::new(Mutex::new(Vec::<Transaction>::new()));
		let mut mock = MockDeliveryInterface::new();

		// Allowance precheck: zero -> proceed with approve.
		mock.expect_get_allowance()
			.times(1)
			.returning(|_, _, _, _| Box::pin(async move { Ok("0".to_string()) }));

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

		// submit_and_confirm polls get_receipt for the approve tx
		mock.expect_get_receipt().returning(|_, _| {
			Box::pin(async move {
				Ok(TransactionReceipt {
					hash: TransactionHash(vec![0x22; 32]),
					block_number: 1,
					success: true,
					logs: vec![],
					block_timestamp: None,
				})
			})
		});

		let expected_oft = request.source_oft;
		mock.expect_eth_call().returning(move |tx| {
			assert_eq!(
				tx.to
					.as_ref()
					.map(|addr| Address::from_slice(addr.0.as_slice())),
				Some(expected_oft)
			);
			Box::pin(async move { Ok(alloy_primitives::Bytes::from(oft_quote_fee_bytes(fee))) })
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
		let send_call: contracts::IOFT::sendCall = decode_submit(&submitted[1]);
		assert_eq!(send_call.refundAddress, solver_address());
		assert_eq!(
			send_call.sendParam.to,
			contracts::address_to_bytes32(solver_address())
		);
		assert_eq!(send_call.sendParam.dstEid, 200);
		assert_eq!(send_call.fee.nativeFee, fee);
	}

	#[tokio::test]
	async fn test_bridge_via_oft_send_keeps_fixed_gas_limit() {
		let request = bridge_request();
		let fee = U256::from(12345u64);
		let submitted = Arc::new(Mutex::new(Vec::<Transaction>::new()));
		let mut mock = MockDeliveryInterface::new();

		// Allowance precheck: zero -> proceed with approve.
		mock.expect_get_allowance()
			.times(1)
			.returning(|_, _, _, _| Box::pin(async move { Ok("0".to_string()) }));

		{
			let submitted = submitted.clone();
			mock.expect_submit().times(2).returning(move |tx, _| {
				let submitted = submitted.clone();
				Box::pin(async move {
					submitted.lock().unwrap().push(tx.clone());
					Ok(TransactionHash(vec![0x55; 32]))
				})
			});
		}

		mock.expect_get_receipt().returning(|_, _| {
			Box::pin(async move {
				Ok(TransactionReceipt {
					hash: TransactionHash(vec![0x55; 32]),
					block_number: 1,
					success: true,
					logs: vec![],
					block_timestamp: None,
				})
			})
		});

		let expected_oft = request.source_oft;
		mock.expect_eth_call().returning(move |tx| {
			assert_eq!(
				tx.to
					.as_ref()
					.map(|addr| Address::from_slice(addr.0.as_slice())),
				Some(expected_oft)
			);
			Box::pin(async move { Ok(alloy_primitives::Bytes::from(oft_quote_fee_bytes(fee))) })
		});
		mock.expect_estimate_gas().times(0);

		let bridge = bridge_with_two_chain_delivery(mock, None);
		bridge.bridge_asset(&request).await.unwrap();

		let submitted = submitted.lock().unwrap();
		assert_eq!(submitted.len(), 2);
		assert_eq!(submitted[1].gas_limit, Some(500_000));
	}

	#[tokio::test]
	async fn test_bridge_via_composer_falls_through_to_approve_when_read_allowance_fails() {
		// Regression: a transient read_allowance failure must NOT promote
		// the transfer to NeedsIntervention. The bridge must fall through to
		// the approve path; if approve+deposit both succeed, bridge_asset
		// returns Ok and the transfer continues normally.
		let request = bridge_request();
		let composer = Address::from([0xCC; 20]);
		let fee = U256::from(12345u64);
		let submitted = Arc::new(Mutex::new(Vec::<Transaction>::new()));
		let mut mock = MockDeliveryInterface::new();

		// Allowance precheck FAILS with a transient RPC error. The bridge must
		// fall through to approve (treating the unknown allowance as 0).
		mock.expect_get_allowance()
			.times(1)
			.returning(|_, _, _, _| {
				Box::pin(async move {
					Err(DeliveryError::Network(
						"transient gateway timeout".to_string(),
					))
				})
			});

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

		mock.expect_get_receipt().returning(|_, _| {
			Box::pin(async move {
				Ok(TransactionReceipt {
					hash: TransactionHash(vec![0x11; 32]),
					block_number: 1,
					success: true,
					logs: vec![],
					block_timestamp: None,
				})
			})
		});

		let expected_composer = composer;
		mock.expect_eth_call().returning(move |tx| {
			assert_eq!(
				tx.to
					.as_ref()
					.map(|addr| Address::from_slice(addr.0.as_slice())),
				Some(expected_composer)
			);
			Box::pin(
				async move { Ok(alloy_primitives::Bytes::from(composer_quote_fee_bytes(fee))) },
			)
		});
		mock.expect_estimate_gas()
			.times(1)
			.returning(move |_tx| Box::pin(async move { Ok(900_000) }));

		let bridge = bridge_with_two_chain_delivery(mock, Some(composer));
		let result = bridge
			.bridge_asset(&request)
			.await
			.expect("bridge_asset must succeed by falling through to approve");

		assert_eq!(result.tx_hash, format!("0x{}", hex::encode(vec![0x11; 32])));

		// Approve + deposit were both submitted (i.e. precheck did not abort).
		let submitted = submitted.lock().unwrap();
		assert_eq!(
			submitted.len(),
			2,
			"expected approve + deposit submissions after precheck fallback"
		);
		assert_eq!(tx_to(&submitted[0]), request.source_token);
		let approve_call: contracts::approveCall = decode_submit(&submitted[0]);
		assert_eq!(approve_call.spender, composer);
		assert_eq!(approve_call.amount, request.amount);
	}

	#[tokio::test]
	async fn test_bridge_via_oft_send_falls_through_to_approve_when_read_allowance_fails() {
		// Regression mirror of the composer test, for the OFT-send path.
		let request = bridge_request();
		let fee = U256::from(12345u64);
		let submitted = Arc::new(Mutex::new(Vec::<Transaction>::new()));
		let mut mock = MockDeliveryInterface::new();

		// Allowance precheck FAILS with a transient RPC error.
		mock.expect_get_allowance()
			.times(1)
			.returning(|_, _, _, _| {
				Box::pin(async move {
					Err(DeliveryError::Network(
						"transient gateway timeout".to_string(),
					))
				})
			});

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

		mock.expect_get_receipt().returning(|_, _| {
			Box::pin(async move {
				Ok(TransactionReceipt {
					hash: TransactionHash(vec![0x22; 32]),
					block_number: 1,
					success: true,
					logs: vec![],
					block_timestamp: None,
				})
			})
		});

		let expected_oft = request.source_oft;
		mock.expect_eth_call().returning(move |tx| {
			assert_eq!(
				tx.to
					.as_ref()
					.map(|addr| Address::from_slice(addr.0.as_slice())),
				Some(expected_oft)
			);
			Box::pin(async move { Ok(alloy_primitives::Bytes::from(oft_quote_fee_bytes(fee))) })
		});

		let bridge = bridge_with_two_chain_delivery(mock, None);
		let result = bridge
			.bridge_asset(&request)
			.await
			.expect("bridge_asset must succeed by falling through to approve");

		assert_eq!(result.tx_hash, format!("0x{}", hex::encode(vec![0x22; 32])));

		let submitted = submitted.lock().unwrap();
		assert_eq!(
			submitted.len(),
			2,
			"expected approve + send submissions after precheck fallback"
		);
		assert_eq!(tx_to(&submitted[0]), request.source_token);
		let approve_call: contracts::approveCall = decode_submit(&submitted[0]);
		assert_eq!(approve_call.spender, request.source_oft);
		assert_eq!(approve_call.amount, request.amount);
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
		assert!(
			matches!(status, BridgeTransferStatus::Failed(reason) if reason == "Source transaction reverted")
		);
	}

	#[tokio::test]
	async fn test_check_status_pending_redemption_becomes_completed_on_successful_redeem_receipt() {
		let mut transfer =
			crate::test_support::pending_transfer(BridgeTransferStatus::PendingRedemption);
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
		let mut transfer =
			crate::test_support::pending_transfer(BridgeTransferStatus::PendingRedemption);
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
		assert!(
			matches!(status, BridgeTransferStatus::Failed(reason) if reason == "Redeem transaction reverted")
		);
	}

	#[tokio::test]
	async fn test_check_status_pending_redemption_reports_missing_redeem_tx() {
		// When the redeem receipt lookup fails AND tx_exists confirms the tx is
		// not on chain, surface a structured "Redeem transaction not found"
		// signal so the monitor can clear the stale hash and resubmit.
		let mut transfer =
			crate::test_support::pending_transfer(BridgeTransferStatus::PendingRedemption);
		transfer.redeem_tx_hash =
			Some("0x0505050505050505050505050505050505050505050505050505050505050505".to_string());

		let mut mock = MockDeliveryInterface::new();
		mock.expect_get_receipt().returning(|_, _| {
			Box::pin(async move {
				Err(solver_delivery::DeliveryError::Network(
					"receipt not found".to_string(),
				))
			})
		});
		mock.expect_tx_exists()
			.returning(|_, _| Box::pin(async move { Ok(false) }));

		let bridge = bridge_with_two_chain_delivery(mock, None);
		let status = bridge.check_status(&transfer).await.unwrap();

		assert!(
			matches!(&status, BridgeTransferStatus::Failed(reason) if reason == "Redeem transaction not found"),
			"expected Failed(\"Redeem transaction not found\"), got {status:?}"
		);
	}

	#[tokio::test]
	async fn test_check_status_pending_redemption_waits_when_redeem_tx_exists_without_receipt() {
		// Receipt missing but tx_exists == true means the redeem tx is sitting
		// in the mempool — keep waiting in PendingRedemption.
		let mut transfer =
			crate::test_support::pending_transfer(BridgeTransferStatus::PendingRedemption);
		transfer.redeem_tx_hash =
			Some("0x0606060606060606060606060606060606060606060606060606060606060606".to_string());

		let mut mock = MockDeliveryInterface::new();
		mock.expect_get_receipt().returning(|_, _| {
			Box::pin(async move {
				Err(solver_delivery::DeliveryError::Network(
					"receipt not found".to_string(),
				))
			})
		});
		mock.expect_tx_exists()
			.returning(|_, _| Box::pin(async move { Ok(true) }));

		let bridge = bridge_with_two_chain_delivery(mock, None);
		let status = bridge.check_status(&transfer).await.unwrap();

		assert!(
			matches!(status, BridgeTransferStatus::PendingRedemption),
			"expected PendingRedemption, got {status:?}"
		);
	}

	#[tokio::test]
	async fn test_check_status_pending_redemption_stays_unknown_when_redeem_tx_exists_check_errors()
	{
		// If tx_exists itself errors, treat the state as unknown and stay in
		// PendingRedemption rather than escalating to a missing-tx failure.
		let mut transfer =
			crate::test_support::pending_transfer(BridgeTransferStatus::PendingRedemption);
		transfer.redeem_tx_hash =
			Some("0x0707070707070707070707070707070707070707070707070707070707070707".to_string());

		let mut mock = MockDeliveryInterface::new();
		mock.expect_get_receipt().returning(|_, _| {
			Box::pin(async move {
				Err(solver_delivery::DeliveryError::Network(
					"receipt not found".to_string(),
				))
			})
		});
		mock.expect_tx_exists().returning(|_, _| {
			Box::pin(async move {
				Err(solver_delivery::DeliveryError::Network(
					"rpc unavailable".to_string(),
				))
			})
		});

		let bridge = bridge_with_two_chain_delivery(mock, None);
		let status = bridge.check_status(&transfer).await.unwrap();

		assert!(
			matches!(status, BridgeTransferStatus::PendingRedemption),
			"expected PendingRedemption, got {status:?}"
		);
	}

	#[test]
	fn test_create_bridge_rejects_zero_solver_address() {
		let mut mock = MockDeliveryInterface::new();
		mock.expect_submit().times(0);
		mock.expect_get_receipt().times(0);
		mock.expect_eth_call().times(0);
		let delivery = Arc::new(DeliveryService::new(
			HashMap::from([(
				1_u64,
				Arc::new(mock) as Arc<dyn solver_delivery::DeliveryInterface>,
			)]),
			3,
			300,
			60,
		));

		let result = create_bridge(
			&bridge_config(Some(Address::from([0xCC; 20]))),
			delivery,
			zero_address(),
		);
		assert!(
			matches!(result, Err(BridgeError::Config(msg)) if msg.contains("zero solver address"))
		);
	}

	#[tokio::test]
	async fn test_estimate_fee_composer_calls_composer_address() {
		let request = bridge_request();
		let fee = U256::from(777u64);
		let composer = Address::from([0xCC; 20]);
		let call_target = Arc::new(Mutex::new(None));
		let mut mock = MockDeliveryInterface::new();
		{
			let call_target = call_target.clone();
			mock.expect_eth_call().returning(move |tx| {
				*call_target.lock().unwrap() = Some(tx.clone());
				Box::pin(
					async move { Ok(alloy_primitives::Bytes::from(composer_quote_fee_bytes(fee))) },
				)
			});
		}

		let bridge = bridge_with_two_chain_delivery(mock, Some(composer));
		let quoted = bridge.estimate_fee(&request).await.unwrap();

		assert_eq!(quoted, fee);
		let tx = call_target
			.lock()
			.unwrap()
			.clone()
			.expect("missing contract call");
		// Composer flow: quoteSend is called on the composer contract
		assert_eq!(tx_to(&tx), composer);
	}

	#[tokio::test]
	async fn test_estimate_fee_oft_calls_source_oft() {
		let request = bridge_request();
		let fee = U256::from(888u64);
		let call_target = Arc::new(Mutex::new(None));
		let mut mock = MockDeliveryInterface::new();
		{
			let call_target = call_target.clone();
			mock.expect_eth_call().returning(move |tx| {
				*call_target.lock().unwrap() = Some(tx.clone());
				Box::pin(async move { Ok(alloy_primitives::Bytes::from(oft_quote_fee_bytes(fee))) })
			});
		}

		let bridge = bridge_with_two_chain_delivery(mock, None);
		let quoted = bridge.estimate_fee(&request).await.unwrap();

		assert_eq!(quoted, fee);
		let tx = call_target
			.lock()
			.unwrap()
			.clone()
			.expect("missing contract call");
		// OFT flow: quoteSend is called on source_oft
		assert_eq!(tx_to(&tx), request.source_oft);
	}

	#[tokio::test]
	async fn read_allowance_returns_value_from_delivery_get_allowance() {
		let mut mock = MockDeliveryInterface::new();
		mock.expect_get_allowance()
			.times(1)
			.returning(|owner, spender, token, _chain_id| {
				// Sanity-check the arg formatting expected by the production helper.
				assert!(owner.starts_with("0x"));
				assert!(spender.starts_with("0x"));
				assert!(token.starts_with("0x"));
				// 2.5 USDC = 2_500_000 (6 decimals), as a decimal string.
				Box::pin(async move { Ok("2500000".to_string()) })
			});

		let bridge = bridge_with_two_chain_delivery(mock, None);

		let token = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
			.parse()
			.unwrap();
		let owner = "0x33848cc530581b2cefef58cc9d3c935311d4b940"
			.parse()
			.unwrap();
		let spender = "0x0000000000000000000000000000000000000001"
			.parse()
			.unwrap();

		let allowance = bridge
			.read_allowance(1, token, owner, spender)
			.await
			.unwrap();
		assert_eq!(allowance, U256::from(2_500_000u64));
	}

	#[tokio::test]
	async fn bridge_via_composer_skips_approve_when_allowance_sufficient() {
		let composer = Address::from([0xCC; 20]);
		let mut mock = MockDeliveryInterface::new();

		// (1) Allowance precheck: huge value -> skip approve.
		mock.expect_get_allowance()
			.times(1)
			.returning(|_, _, _, _| {
				Box::pin(async move { Ok("999999999999999999999999".to_string()) })
			});

		// (2) eth_call covers ONLY the quoteSend (allowance no longer eth_call).
		mock.expect_eth_call().times(1).returning(|_tx| {
			let fee = contracts::MessagingFee {
				nativeFee: U256::from(1u64),
				lzTokenFee: U256::ZERO,
			};
			let bytes = contracts::IVaultComposerSync::quoteSendCall::abi_encode_returns(&fee);
			Box::pin(async move { Ok(alloy_primitives::Bytes::from(bytes)) })
		});

		// (3) Deposit submit -- no approve submit.
		mock.expect_submit()
			.times(1)
			.returning(|_, _| Box::pin(async move { Ok(TransactionHash(vec![0xde; 32])) }));
		mock.expect_estimate_gas()
			.returning(|_| Box::pin(async move { Ok(800_000u64) }));

		let bridge = bridge_with_two_chain_delivery(mock, Some(composer));
		let request = bridge_request();

		let result = bridge.bridge_via_composer(&request).await;
		assert!(result.is_ok(), "expected Ok, got {:?}", result.err());
	}

	#[tokio::test]
	async fn bridge_via_composer_returns_approve_submit_failed_on_receipt_timeout() {
		let composer = Address::from([0xCC; 20]);
		let mut mock = MockDeliveryInterface::new();

		mock.expect_get_allowance()
			.times(1)
			.returning(|_, _, _, _| Box::pin(async move { Ok("0".to_string()) }));

		let approve_hash = TransactionHash(vec![0xaa; 32]);
		let approve_hash_clone = approve_hash.clone();
		mock.expect_submit().times(1).returning(move |_, _| {
			let h = approve_hash_clone.clone();
			Box::pin(async move { Ok(h) })
		});
		mock.expect_get_receipt().returning(|_, _| {
			Box::pin(async move { Err(DeliveryError::Network("not found".into())) })
		});

		let bridge = bridge_with_two_chain_delivery(mock, Some(composer));
		let request = bridge_request();

		let result = bridge.bridge_via_composer(&request).await;
		let err = result.expect_err("expected Err");
		match err {
			BridgeError::ApproveSubmitFailed { error } => {
				assert!(
					error.contains("Composer approve receipt not found after"),
					"unexpected error: {error}"
				);
			},
			other => panic!("expected ApproveSubmitFailed, got {other:?}"),
		}
	}

	#[test]
	fn map_delivery_error_preserves_insufficient_native_gas() {
		let err = DeliveryError::InsufficientNativeGas(Box::new(
			solver_delivery::InsufficientNativeGasInfo {
				chain_id: 1,
				signer: "0xsolver".to_string(),
				balance_wei: "10".to_string(),
				required_wei: "30".to_string(),
				shortfall_wei: "20".to_string(),
				gas_limit: Some(100_000),
				max_fee_per_gas: Some(2_000_000_000),
				gas_price: None,
				value_wei: "0".to_string(),
			},
		));

		let bridge_error = map_delivery_error("Composer approve", err);

		assert!(matches!(
			bridge_error,
			BridgeError::InsufficientNativeGas(reason)
				if reason.contains("Composer approve submit failed")
					&& reason.contains("shortfall 20 wei")
		));
	}

	#[test]
	fn map_delivery_error_preserves_transaction_failed_for_other_errors() {
		let bridge_error = map_delivery_error(
			"Composer approve",
			DeliveryError::Network("rpc down".into()),
		);

		assert!(matches!(
			bridge_error,
			BridgeError::TransactionFailed(reason)
				if reason.contains("Composer approve submit failed")
					&& reason.contains("rpc down")
		));
	}

	#[tokio::test]
	async fn bridge_via_oft_send_skips_approve_when_allowance_sufficient() {
		let mut mock = MockDeliveryInterface::new();

		// (1) Allowance precheck: huge value -> skip approve.
		mock.expect_get_allowance()
			.times(1)
			.returning(|_, _, _, _| {
				Box::pin(async move { Ok("999999999999999999999999".to_string()) })
			});

		// (2) eth_call covers ONLY the OFT quoteSend (allowance no longer eth_call).
		mock.expect_eth_call().times(1).returning(|_tx| {
			let fee = contracts::MessagingFee {
				nativeFee: U256::from(1u64),
				lzTokenFee: U256::ZERO,
			};
			let bytes = contracts::IOFT::quoteSendCall::abi_encode_returns(&fee);
			Box::pin(async move { Ok(alloy_primitives::Bytes::from(bytes)) })
		});

		// (3) Send submit -- no approve submit.
		mock.expect_submit()
			.times(1)
			.returning(|_, _| Box::pin(async move { Ok(TransactionHash(vec![0xde; 32])) }));

		let bridge = bridge_with_two_chain_delivery(mock, None);
		let request = bridge_request();

		let result = bridge.bridge_via_oft_send(&request).await;
		assert!(result.is_ok(), "expected Ok, got {:?}", result.err());
	}

	#[tokio::test]
	async fn bridge_via_oft_send_returns_approve_submit_failed_on_receipt_timeout() {
		let mut mock = MockDeliveryInterface::new();

		mock.expect_get_allowance()
			.times(1)
			.returning(|_, _, _, _| Box::pin(async move { Ok("0".to_string()) }));

		let approve_hash = TransactionHash(vec![0xaa; 32]);
		let approve_hash_clone = approve_hash.clone();
		mock.expect_submit().times(1).returning(move |_, _| {
			let h = approve_hash_clone.clone();
			Box::pin(async move { Ok(h) })
		});
		mock.expect_get_receipt().returning(|_, _| {
			Box::pin(async move { Err(DeliveryError::Network("not found".into())) })
		});

		let bridge = bridge_with_two_chain_delivery(mock, None);
		let request = bridge_request();

		let result = bridge.bridge_via_oft_send(&request).await;
		let err = result.expect_err("expected Err");
		match err {
			BridgeError::ApproveSubmitFailed { error } => {
				assert!(
					error.contains("OFT approve receipt not found after"),
					"unexpected error: {error}"
				);
			},
			other => panic!("expected ApproveSubmitFailed, got {other:?}"),
		}
	}
}
