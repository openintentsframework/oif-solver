//! Event types for inter-service communication.
//!
//! This module defines the event system used by the solver for asynchronous
//! communication between different components. Events flow through an event bus
//! allowing services to react to state changes in other parts of the system.

use crate::{
	Address, ExecutionParams, FillProof, Intent, Order, TransactionHash, TransactionReceipt,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Main event type encompassing all solver events.
///
/// Events are categorized by the service that produces them, allowing
/// consumers to filter and handle specific event types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum SolverEvent {
	/// Events from the discovery service.
	Discovery(DiscoveryEvent),
	/// Events from the order processing service.
	Order(OrderEvent),
	/// Events from the delivery service.
	Delivery(DeliveryEvent),
	/// Events from the settlement service.
	Settlement(SettlementEvent),
}

/// Events related to intent discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum DiscoveryEvent {
	/// A new intent has been discovered.
	IntentDiscovered { intent: Intent },
	/// An intent has been validated and converted to an order.
	IntentValidated { intent_id: String, order: Order },
	/// An intent has been rejected during validation.
	IntentRejected { intent_id: String, reason: String },
}

/// Events related to order processing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum OrderEvent {
	/// An order is being prepared for execution (e.g., openFor for off-chain orders).
	Preparing {
		intent: Intent,
		order: Order,
		params: ExecutionParams,
	},
	/// An order is being executed with the specified parameters.
	Executing {
		order: Order,
		params: ExecutionParams,
	},
	/// An order has been skipped due to strategy decision.
	Skipped { order_id: String, reason: String },
	/// An order execution has been deferred.
	Deferred {
		order_id: String,
		retry_after: Duration,
	},
}

/// Events related to transaction delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeliveryEvent {
	/// A transaction has been submitted and is pending confirmation.
	TransactionPending {
		order_id: String,
		tx_hash: TransactionHash,
		tx_type: TransactionType,
		tx_chain_id: u64,
	},
	/// A transaction has been confirmed on-chain.
	TransactionConfirmed {
		order_id: String,
		tx_hash: TransactionHash,
		tx_type: TransactionType,
		receipt: TransactionReceipt,
	},
	/// A transaction has failed.
	TransactionFailed {
		order_id: String,
		tx_hash: TransactionHash,
		tx_type: TransactionType,
		error: String,
	},
	/// Emitted when the live tx-confirmation monitor gives up before
	/// reaching `min_confirmations`. Order stays in its current status;
	/// recovery reconciles via direct chain query.
	TransactionIndeterminate {
		order_id: String,
		tx_hash: TransactionHash,
		tx_type: TransactionType,
		reason: String,
	},
	/// Bump sweeper found that the bumped fees exceed a per-chain cap.
	/// Operator intervention required (raise the cap or wait).
	BumpCapReached {
		order_id: String,
		attempt_id: String,
		chain_id: u64,
		tx_type: TransactionType,
		cap_field: BumpCapField,
		computed_fee_wei: String,
		cap_wei: String,
	},
	/// Bump sweeper found that the proposed bumped transaction's total cost
	/// exceeds the available profitability headroom (gas_buffer + min_profit)
	/// over the stage's original quote-time gas budget. Operator intervention
	/// required (raise headroom or accept loss).
	BumpExceedsProfitability {
		order_id: String,
		attempt_id: String,
		chain_id: u64,
		tx_type: TransactionType,
		/// Proposed total cost of the bumped tx, in `currency`.
		/// Decimal string for serde stability (mirrors `CostBreakdown` fields).
		proposed_cost: String,
		/// The stage's original quote-time gas budget, in `currency`.
		original_stage_budget: String,
		/// Available headroom (gas_buffer + min_profit), in `currency`.
		headroom: String,
		/// Currency code from the order's CostBreakdown (e.g., "USD").
		currency: String,
	},
	/// Bump sweeper found that the lineage has reached the configured
	/// max-replacements limit. Operator intervention required.
	BumpMaxReplacementsReached {
		order_id: String,
		attempt_id: String,
		chain_id: u64,
		tx_type: TransactionType,
		lineage_depth: u32,
	},
	/// Bump sweeper found that the chain's currently-configured signer
	/// no longer matches the original signer of the lineage tip.
	/// Same-signer invariant prevents bumping.
	BumpSignerMismatch {
		order_id: String,
		attempt_id: String,
		chain_id: u64,
		tx_type: TransactionType,
		expected_signer: Address,
		submission_signer: Address,
	},
	/// Bump sweeper found a non-terminal lineage tip whose `signer`
	/// field is `None`. Abnormal for EVM attempts.
	BumpMissingSigner {
		order_id: String,
		attempt_id: String,
		chain_id: u64,
		tx_type: TransactionType,
	},
}

/// Which EIP-1559 cap was the binding constraint on a blocked bump.
/// Legacy chains report `MaxFeePerGas` (gas_price cap).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BumpCapField {
	MaxFeePerGas,
	MaxPriorityFeePerGas,
}

/// Events related to settlement operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SettlementEvent {
	/// A fill transaction has been detected on-chain.
	FillDetected {
		order_id: String,
		tx_hash: TransactionHash,
	},
	/// Fill proof has been generated and is ready.
	ProofReady { order_id: String, proof: FillProof },
	/// Emitted after Fill confirmation to trigger post-fill processing.
	PostFillReady { order_id: String },
	/// Emitted when ready for pre-claim processing.
	PreClaimReady { order_id: String },
	/// Start monitoring for settlement readiness.
	StartMonitoring {
		order_id: String,
		fill_tx_hash: TransactionHash,
	},
	/// Order is ready to be claimed.
	ClaimReady { order_id: String },
	/// Order settlement has been completed.
	Completed { order_id: String },
}

/// Types of transactions in the solver system.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum TransactionType {
	/// Transaction that prepares an off-chain order on-chain (e.g., openFor).
	Prepare,
	/// Transaction that fills an order on the destination chain.
	Fill,
	/// Transaction that executes after fill confirmation (optional).
	PostFill,
	/// Transaction that executes before claiming (optional).
	PreClaim,
	/// Transaction that claims rewards on the origin chain.
	Claim,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn bump_exceeds_profitability_event_round_trips() {
		let ev = DeliveryEvent::BumpExceedsProfitability {
			order_id: "order-1".into(),
			attempt_id: "attempt-1".into(),
			chain_id: 1,
			tx_type: TransactionType::Fill,
			proposed_cost: "1.50".into(),
			original_stage_budget: "0.10".into(),
			headroom: "0.09".into(),
			currency: "USD".into(),
		};
		let json = serde_json::to_string(&ev).unwrap();
		let de: DeliveryEvent = serde_json::from_str(&json).unwrap();
		assert!(matches!(de, DeliveryEvent::BumpExceedsProfitability { .. }));
	}
}
