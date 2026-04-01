#![allow(dead_code)]

use crate::types::{BridgeRequest, BridgeTransferStatus, PendingBridgeTransfer, RebalanceTrigger};
use alloy_primitives::{Address, U256};
use solver_config::{RebalanceConfig, RebalancePairConfig, RebalancePairSideConfig};
use solver_delivery::{DeliveryService, MockDeliveryInterface};
use solver_storage::{MockStorageInterface, StorageService};
use std::collections::HashMap;
use std::sync::Arc;

pub fn bridge_request() -> BridgeRequest {
	BridgeRequest {
		pair_id: "eth-katana".to_string(),
		source_chain: 1,
		dest_chain: 747474,
		source_token: Address::from([0x11; 20]),
		source_oft: Address::from([0x22; 20]),
		dest_token: Address::from([0x33; 20]),
		dest_oft: Address::from([0x44; 20]),
		amount: U256::from(1_000_000u64),
		min_amount: None,
		recipient: Address::from([0x55; 20]),
	}
}

pub fn pending_transfer(status: BridgeTransferStatus) -> PendingBridgeTransfer {
	let mut transfer = PendingBridgeTransfer::new(
		"eth-katana".to_string(),
		1,
		747474,
		"1000000".to_string(),
		RebalanceTrigger::Auto,
		None,
		None,
		None,
	);
	transfer.id = "00000000-0000-0000-0000-000000000001".to_string();
	transfer.created_at = 1_700_000_000;
	transfer.updated_at = 1_700_000_000;
	match status {
		BridgeTransferStatus::NeedsIntervention(reason) => {
			transfer.status = BridgeTransferStatus::NeedsIntervention(reason);
			transfer.status_before_intervention = Some(BridgeTransferStatus::Submitted);
		},
		other => transfer.status = other,
	}
	transfer
}

pub fn rebalance_config() -> RebalanceConfig {
	RebalanceConfig {
		enabled: true,
		implementation: "mock-bridge".to_string(),
		monitor_interval_seconds: 15,
		cooldown_seconds: 60,
		max_pending_transfers: 1,
		min_native_gas_reserve: HashMap::from([(1_u64, "10000000000000000".to_string())]),
		max_fee_bps: Some(100),
		pairs: vec![RebalancePairConfig {
			pair_id: "eth-katana".to_string(),
			chain_a: RebalancePairSideConfig {
				chain_id: 1,
				token_address: "0x1111111111111111111111111111111111111111".to_string(),
				oft_address: "0x2222222222222222222222222222222222222222".to_string(),
			},
			chain_b: RebalancePairSideConfig {
				chain_id: 747474,
				token_address: "0x3333333333333333333333333333333333333333".to_string(),
				oft_address: "0x4444444444444444444444444444444444444444".to_string(),
			},
			target_balance_a: "1000000".to_string(),
			target_balance_b: "1000000".to_string(),
			deviation_band_bps: 2000,
			max_bridge_amount: "500000".to_string(),
		}],
		bridge_config: None,
	}
}

pub fn delivery_service_from_mock(mock: MockDeliveryInterface) -> Arc<DeliveryService> {
	let implementations = HashMap::from([(
		1_u64,
		Arc::new(mock) as Arc<dyn solver_delivery::DeliveryInterface>,
	)]);
	Arc::new(DeliveryService::new(implementations, 3, 300))
}

pub fn storage_service_from_mock(mock: MockStorageInterface) -> Arc<StorageService> {
	Arc::new(StorageService::new(Box::new(mock)))
}
