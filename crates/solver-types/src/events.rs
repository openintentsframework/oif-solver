//! Event types for inter-service communication.
//!
//! This module defines the event system used by the solver for asynchronous
//! communication between different components. Events flow through an event bus
//! allowing services to react to state changes in other parts of the system.

use crate::{ExecutionParams, FillProof, Intent, Order, TransactionHash, TransactionReceipt};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Main event type encompassing all solver events.
///
/// Events are categorized by the service that produces them, allowing
/// consumers to filter and handle specific event types.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
	/// Transaction that claims rewards on the origin chain.
	Claim,
}
