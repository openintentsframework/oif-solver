//! Order-gated pushing of L1 block hashes into L2 buffer contracts.
//!
//! A push is triggered by the settlement monitor on a per-order basis when
//! `buffer_newest < required_block` (the L1 block of the PostFill broadcast).
//! Push is still gated by a per-direction cooldown to prevent tx spam.
//!
//! Push behaviour is determined by the `PusherL2Params` variant on the direction:
//!
//! - `Arbitrum` → `IArbitrumPusher.pushHashes(inbox, batchSize, gasPriceBid, gasLimit, submissionCost, isERC20Inbox)`
//!   `msg.value = gasLimit * gasPriceBid + submissionCost`
//! - `OpStack`  → `IPusher.pushHashes(buffer, firstBlock, batchSize, abi.encode(uint32 gasLimit))`
//!   `msg.value = 0`
//! - `Linea`    → `IPusher.pushHashes(buffer, firstBlock, batchSize, abi.encode(uint256 fee))`
//!   `msg.value = fee`
//! - `Raw`      → `IPusher.pushHashes(buffer, firstBlock, batchSize, data)`
//!   `msg.value = value_wei` (defaults to 0)

use alloy_primitives::U256;
use alloy_provider::{DynProvider, Provider};
use alloy_sol_types::{sol, SolCall};
use solver_delivery::DeliveryService;
use solver_types::{NetworksConfig, PusherL2Params, Transaction};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::{utils::create_providers_for_chains, PusherDirection};

sol! {
	interface IBuffer {
		function newestBlockNumber() external view returns (uint256);
	}

	/// Generic multi-chain pusher interface (OP Stack, Linea, Scroll, ZkSync …).
	interface IPusher {
		function pushHashes(
			address buffer,
			uint256 firstBlockNumber,
			uint256 batchSize,
			bytes calldata l2TransactionData
		) external payable;
	}

	/// Arbitrum-specific pusher interface.
	/// The deployed ETH Sepolia contract (0x5a5c4f3d…) uses this ABI.
	interface IArbitrumPusher {
		function pushHashes(
			address inbox,
			uint256 batchSize,
			uint256 gasPriceBid,
			uint256 gasLimit,
			uint256 submissionCost,
			bool isERC20Inbox
		) external payable;
	}
}

/// Read the newest block number stored in an L2 buffer contract.
async fn read_buffer_newest(
	provider: &DynProvider,
	buffer_addr: &solver_types::Address,
) -> Result<u64, String> {
	let call_data = IBuffer::newestBlockNumberCall {};
	let request = alloy_rpc_types::eth::transaction::TransactionRequest {
		to: Some(alloy_primitives::TxKind::Call(
			alloy_primitives::Address::from_slice(&buffer_addr.0),
		)),
		input: call_data.abi_encode().into(),
		..Default::default()
	};

	let result = provider
		.call(request)
		.await
		.map_err(|e| format!("Failed to call newestBlockNumber: {e}"))?;

	if result.len() < 32 {
		return Err(format!(
			"newestBlockNumber returned {} bytes, expected ≥32",
			result.len()
		));
	}

	// ABI-encoded uint256 is 32 big-endian bytes; read the lower 8 bytes as u64.
	let mut arr = [0u8; 8];
	arr.copy_from_slice(&result[result.len() - 8..]);
	Ok(u64::from_be_bytes(arr))
}

/// Derive the `msg.value` required for a `pushHashes` call from typed `PusherL2Params`.
fn derive_msg_value(l2_params: &PusherL2Params) -> U256 {
	match l2_params {
		PusherL2Params::OpStack { .. } => U256::ZERO,
		PusherL2Params::Linea { fee } => U256::from(*fee),
		PusherL2Params::Arbitrum {
			gas_price_bid,
			gas_limit,
			submission_cost,
			..
		} => U256::from(*gas_limit) * U256::from(*gas_price_bid) + U256::from(*submission_cost),
		PusherL2Params::Raw { value_wei, .. } => value_wei.map(U256::from).unwrap_or(U256::ZERO),
	}
}

/// Build a push transaction for the given direction starting at `first_block`.
///
/// Returns `None` only when `Raw` l2_params hex decoding fails;
/// all typed variants always produce a valid transaction.
fn build_push_tx(direction: &PusherDirection, first_block: u64) -> Option<Transaction> {
	let value = derive_msg_value(&direction.l2_params);

	let call_data = match &direction.l2_params {
		PusherL2Params::Arbitrum {
			inbox,
			gas_price_bid,
			gas_limit,
			submission_cost,
			is_erc20_inbox,
		} => IArbitrumPusher::pushHashesCall {
			inbox: *inbox,
			batchSize: U256::from(direction.batch_size),
			gasPriceBid: U256::from(*gas_price_bid),
			gasLimit: U256::from(*gas_limit),
			submissionCost: U256::from(*submission_cost),
			isERC20Inbox: *is_erc20_inbox,
		}
		.abi_encode(),
		PusherL2Params::OpStack { gas_limit } => {
			// l2TransactionData = abi.encode(uint32 gasLimit) = 28 zero bytes + 4 bytes
			let mut l2_tx_data = [0u8; 32];
			l2_tx_data[28..32].copy_from_slice(&gas_limit.to_be_bytes());
			IPusher::pushHashesCall {
				buffer: alloy_primitives::Address::from_slice(&direction.buffer_address.0),
				firstBlockNumber: U256::from(first_block),
				batchSize: U256::from(direction.batch_size),
				l2TransactionData: l2_tx_data.to_vec().into(),
			}
			.abi_encode()
		},
		PusherL2Params::Linea { fee } => {
			// l2TransactionData = abi.encode(uint256 fee) = 32-byte big-endian uint256.
			// fee is u64 (8 bytes); right-align in the 32-byte word at [24..32].
			let mut l2_tx_data = [0u8; 32];
			l2_tx_data[24..32].copy_from_slice(&fee.to_be_bytes());
			IPusher::pushHashesCall {
				buffer: alloy_primitives::Address::from_slice(&direction.buffer_address.0),
				firstBlockNumber: U256::from(first_block),
				batchSize: U256::from(direction.batch_size),
				l2TransactionData: l2_tx_data.to_vec().into(),
			}
			.abi_encode()
		},
		PusherL2Params::Raw { data, .. } => {
			let bytes = match alloy_primitives::hex::decode(data.trim_start_matches("0x")) {
				Ok(b) => b,
				Err(e) => {
					tracing::error!(
						label = %direction.label,
						error = %e,
						"Raw l2_params hex decode failed, skipping push"
					);
					return None;
				},
			};
			IPusher::pushHashesCall {
				buffer: alloy_primitives::Address::from_slice(&direction.buffer_address.0),
				firstBlockNumber: U256::from(first_block),
				batchSize: U256::from(direction.batch_size),
				l2TransactionData: bytes.into(),
			}
			.abi_encode()
		},
	};

	Some(Transaction {
		to: Some(direction.pusher_address.clone()),
		data: call_data,
		value,
		chain_id: direction.l1_chain_id,
		nonce: None,
		gas_limit: None,
		gas_price: None,
		max_fee_per_gas: None,
		max_priority_fee_per_gas: None,
	})
}

/// Check buffer coverage and push L1 hashes if needed for a specific order.
///
/// `required_block` is the L1 block number that must be present in the L2 buffer
/// before a storage proof can be generated. Push is skipped if the buffer already
/// covers the required block or if the cooldown has not yet elapsed.
///
/// The two-phase cooldown check (read-only, then under write lock) prevents
/// concurrent monitor tasks from submitting duplicate pushes.
pub async fn push_if_needed(
	direction: &PusherDirection,
	required_block: u64,
	delivery: &Arc<DeliveryService>,
	networks: &NetworksConfig,
	cooldowns: &Arc<tokio::sync::Mutex<HashMap<String, Instant>>>,
) {
	// Step 1: optimistic cooldown check (read-only, no reservation yet).
	{
		let map = cooldowns.lock().await;
		if let Some(t) = map.get(&direction.label) {
			if t.elapsed() < Duration::from_secs(direction.push_cooldown_seconds) {
				tracing::debug!(label = %direction.label, "Push skipped: cooldown active");
				return;
			}
		}
	}

	// Step 2: read buffer newest — before reserving cooldown so transient errors
	// don't consume the cooldown slot.
	let providers = match create_providers_for_chains(
		&[direction.l1_chain_id, direction.l2_chain_id],
		networks,
	) {
		Ok(p) => p,
		Err(e) => {
			tracing::error!(error = %e, "Failed to create providers for push check");
			return;
		},
	};

	let buffer_newest = match read_buffer_newest(
		&providers[&direction.l2_chain_id],
		&direction.buffer_address,
	)
	.await
	{
		Ok(n) => n,
		Err(e) => {
			tracing::warn!(error = %e, label = %direction.label, "Failed to read buffer newest");
			return;
		},
	};

	// Step 3: buffer already covers the required block — nothing to do.
	if buffer_newest >= required_block {
		tracing::debug!(
			label = %direction.label,
			buffer_newest,
			required_block,
			"Buffer already covers required block"
		);
		return;
	}

	// Step 4: buffer is behind — reserve cooldown under write lock, then submit.
	// Re-check cooldown under write lock to handle concurrent monitor tasks.
	{
		let mut map = cooldowns.lock().await;
		if let Some(t) = map.get(&direction.label) {
			if t.elapsed() < Duration::from_secs(direction.push_cooldown_seconds) {
				tracing::debug!(label = %direction.label, "Push skipped: cooldown active (re-check)");
				return;
			}
		}
		map.insert(direction.label.clone(), Instant::now());
	}

	tracing::info!(
		label = %direction.label,
		buffer_newest,
		required_block,
		lag = required_block - buffer_newest,
		"Buffer behind required block — submitting push"
	);

	let first_block = buffer_newest + 1;
	let tx = match build_push_tx(direction, first_block) {
		Some(tx) => tx,
		None => {
			// Build failure (ARB decode error) — clear reservation so retry is possible.
			cooldowns.lock().await.remove(&direction.label);
			return;
		},
	};

	match delivery.deliver(tx, None).await {
		Ok(hash) => {
			tracing::info!(label = %direction.label, ?hash, "Push tx submitted");
		},
		Err(e) => {
			// Clear cooldown reservation on delivery failure so a retry can occur next poll.
			cooldowns.lock().await.remove(&direction.label);
			tracing::error!(label = %direction.label, error = %e, "Push tx failed");
		},
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn make_direction(l2_params: PusherL2Params) -> PusherDirection {
		PusherDirection {
			label: "test".to_string(),
			l1_chain_id: 1,
			l2_chain_id: 59144,
			pusher_address: solver_types::Address(vec![0xAA; 20]),
			buffer_address: solver_types::Address(vec![0xBB; 20]),
			push_cooldown_seconds: 600,
			batch_size: 256,
			l2_params,
		}
	}

	#[test]
	fn test_build_push_tx_arb() {
		use alloy_sol_types::SolCall;
		let inbox = alloy_primitives::Address::from([0x11u8; 20]);
		let direction = make_direction(PusherL2Params::Arbitrum {
			inbox,
			gas_price_bid: 100_000_000,
			gas_limit: 16_000_000,
			submission_cost: 1_000_000_000_000_000,
			is_erc20_inbox: false,
		});
		let tx = build_push_tx(&direction, 100).expect("should build");
		// msg.value = gas_limit * gas_price_bid + submission_cost
		assert_eq!(tx.value, U256::from(2_600_000_000_000_000u64));
		assert_eq!(tx.chain_id, 1);
		let decoded =
			IArbitrumPusher::pushHashesCall::abi_decode(&tx.data).expect("abi_decode failed");
		assert_eq!(decoded.inbox, inbox);
		assert_eq!(decoded.batchSize, U256::from(256u64));
		assert_eq!(decoded.gasPriceBid, U256::from(100_000_000u64));
		assert_eq!(decoded.gasLimit, U256::from(16_000_000u64));
		assert_eq!(decoded.submissionCost, U256::from(1_000_000_000_000_000u64));
		assert!(!decoded.isERC20Inbox);
	}

	#[test]
	fn test_build_push_tx_op_stack() {
		use alloy_sol_types::SolCall;
		let gas_limit: u32 = 200_000;
		let direction = make_direction(PusherL2Params::OpStack { gas_limit });
		let tx = build_push_tx(&direction, 50).expect("should build");
		assert_eq!(tx.value, U256::ZERO);
		let decoded = IPusher::pushHashesCall::abi_decode(&tx.data).expect("abi_decode failed");
		let l2_data = decoded.l2TransactionData.as_ref();
		assert_eq!(l2_data.len(), 32);
		assert_eq!(&l2_data[0..28], &[0u8; 28], "high bytes must be zero");
		assert_eq!(
			&l2_data[28..32],
			&gas_limit.to_be_bytes(),
			"gas_limit bytes mismatch"
		);
		assert_eq!(decoded.firstBlockNumber, U256::from(50u64));
		assert_eq!(decoded.batchSize, U256::from(256u64));
	}

	#[test]
	fn test_build_push_tx_raw_valid() {
		use alloy_sol_types::SolCall;
		let direction = make_direction(PusherL2Params::Raw {
			data: "0xdeadbeef".to_string(),
			value_wei: Some(12345),
		});
		let tx = build_push_tx(&direction, 1).expect("should build");
		assert_eq!(tx.value, U256::from(12345u64));
		let decoded = IPusher::pushHashesCall::abi_decode(&tx.data).expect("abi_decode failed");
		assert_eq!(
			decoded.l2TransactionData.as_ref(),
			&[0xde, 0xad, 0xbe, 0xef]
		);
	}

	#[test]
	fn test_build_push_tx_raw_invalid_hex() {
		let direction = make_direction(PusherL2Params::Raw {
			data: "0xZZZZ".to_string(),
			value_wei: None,
		});
		assert!(
			build_push_tx(&direction, 1).is_none(),
			"invalid hex must return None"
		);
	}

	#[test]
	fn test_derive_msg_value_op_stack() {
		assert_eq!(
			derive_msg_value(&PusherL2Params::OpStack { gas_limit: 200000 }),
			U256::ZERO
		);
	}

	#[test]
	fn test_derive_msg_value_linea() {
		assert_eq!(
			derive_msg_value(&PusherL2Params::Linea {
				fee: 1_000_000_000_000_000
			}),
			U256::from(1_000_000_000_000_000u64)
		);
	}

	#[test]
	fn test_derive_msg_value_linea_zero() {
		assert_eq!(
			derive_msg_value(&PusherL2Params::Linea { fee: 0 }),
			U256::ZERO
		);
	}

	#[test]
	fn test_derive_msg_value_arb() {
		// value = 16M * 0.1gwei + 0.001 ETH = 2_600_000_000_000_000 wei
		let p = PusherL2Params::Arbitrum {
			inbox: alloy_primitives::Address::ZERO,
			gas_price_bid: 100_000_000,
			gas_limit: 16_000_000,
			submission_cost: 1_000_000_000_000_000,
			is_erc20_inbox: false,
		};
		assert_eq!(derive_msg_value(&p), U256::from(2_600_000_000_000_000u64));
	}

	#[test]
	fn test_derive_msg_value_raw_with_value() {
		let p = PusherL2Params::Raw {
			data: "0x".to_string(),
			value_wei: Some(42),
		};
		assert_eq!(derive_msg_value(&p), U256::from(42u64));
	}

	#[test]
	fn test_derive_msg_value_raw_no_value() {
		let p = PusherL2Params::Raw {
			data: "0x".to_string(),
			value_wei: None,
		};
		assert_eq!(derive_msg_value(&p), U256::ZERO);
	}

	#[test]
	fn test_build_push_tx_linea_encoding() {
		use alloy_sol_types::SolCall;
		let fee: u64 = 1_000_000_000_000_000; // 0.001 ETH

		let direction = PusherDirection {
			label: "test".to_string(),
			l1_chain_id: 1,
			l2_chain_id: 59144,
			pusher_address: solver_types::Address(vec![0xAA; 20]),
			buffer_address: solver_types::Address(vec![0xBB; 20]),
			push_cooldown_seconds: 600,
			batch_size: 256,
			l2_params: PusherL2Params::Linea { fee },
		};

		let tx = build_push_tx(&direction, 100).expect("should build");

		// msg.value must equal fee
		assert_eq!(tx.value, U256::from(fee));

		// Decode the call data to inspect l2TransactionData
		let decoded = IPusher::pushHashesCall::abi_decode(&tx.data).expect("decode failed");
		let l2_data = decoded.l2TransactionData.as_ref();

		// Must be exactly 32 bytes (ABI uint256)
		assert_eq!(l2_data.len(), 32, "l2TransactionData must be 32 bytes");
		// High 24 bytes must be zero
		assert_eq!(&l2_data[0..24], &[0u8; 24], "high bytes must be zero");
		// Low 8 bytes must encode fee big-endian
		assert_eq!(&l2_data[24..32], &fee.to_be_bytes(), "fee bytes mismatch");
	}

	#[tokio::test]
	async fn test_push_if_needed_skips_when_cooldown_active() {
		let direction = make_direction(PusherL2Params::Raw {
			data: "0x".to_string(),
			value_wei: None,
		});
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20));
		let cooldowns = Arc::new(tokio::sync::Mutex::new(HashMap::<String, Instant>::from([
			(direction.label.clone(), Instant::now()),
		])));

		push_if_needed(&direction, 12345, &delivery, &HashMap::new(), &cooldowns).await;

		let guard = cooldowns.lock().await;
		assert_eq!(guard.len(), 1);
		assert!(guard.contains_key("test"));
	}

	#[tokio::test]
	async fn test_push_if_needed_returns_on_provider_creation_failure() {
		let direction = make_direction(PusherL2Params::Raw {
			data: "0x".to_string(),
			value_wei: None,
		});
		let delivery = Arc::new(DeliveryService::new(HashMap::new(), 1, 20));
		let cooldowns = Arc::new(tokio::sync::Mutex::new(HashMap::<String, Instant>::new()));

		push_if_needed(&direction, 12345, &delivery, &HashMap::new(), &cooldowns).await;

		let guard = cooldowns.lock().await;
		assert!(guard.is_empty());
	}
}
