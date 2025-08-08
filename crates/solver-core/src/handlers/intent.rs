//! Intent handler for processing discovered intents.
//!
//! Responsible for validating intents, creating orders, storing them,
//! and determining execution strategy through the order service.

use crate::engine::{context::ContextBuilder, event_bus::EventBus};
use crate::state::OrderStateMachine;
use crate::utils::truncate_id;
use solver_order::OrderService;
use solver_storage::StorageService;
use solver_types::{
	DiscoveryEvent, ExecutionDecision, Intent, OrderEvent, SolverEvent, StorageKey,
};
use std::sync::Arc;
use thiserror::Error;
use tracing::instrument;

#[derive(Debug, Error)]
pub enum IntentError {
	#[error("Validation error: {0}")]
	Validation(String),
	#[error("Storage error: {0}")]
	Storage(String),
	#[error("Service error: {0}")]
	Service(String),
}

pub struct IntentHandler {
	order_service: Arc<OrderService>,
	storage: Arc<StorageService>,
	state_machine: Arc<OrderStateMachine>,
	event_bus: EventBus,
}

impl IntentHandler {
	pub fn new(
		order_service: Arc<OrderService>,
		storage: Arc<StorageService>,
		state_machine: Arc<OrderStateMachine>,
		event_bus: EventBus,
	) -> Self {
		Self {
			order_service,
			storage,
			state_machine,
			event_bus,
		}
	}

	/// Handles a newly discovered intent.
	#[instrument(skip_all, fields(order_id = %truncate_id(&intent.id)))]
	pub async fn handle(&self, intent: Intent) -> Result<(), IntentError> {
		// Prevent duplicate order processing when multiple discovery modules for the same standard are active.
		//
		// When an off-chain 7683 order is submitted via the API, it triggers an `openFor` transaction
		// which emits an `Open` event identical to regular on-chain orders. This causes both
		// the off-chain module (which initiated it) and the on-chain module (monitoring events)
		// to attempt processing the same order.
		//
		// By checking if the intent already exists in storage, we ensure each order is only
		// processed once, regardless of which discovery module receives it first.
		let exists = self
			.storage
			.exists(StorageKey::Intents.as_str(), &intent.id)
			.await
			.map_err(|e| {
				IntentError::Storage(format!("Failed to check intent existence: {}", e))
			})?;
		if exists {
			tracing::debug!(
				"Intent ({}) already exists, skipping duplicate processing",
				truncate_id(&intent.id)
			);
			return Ok(());
		}

		tracing::info!("Discovered intent");

		// Validate intent
		match self.order_service.validate_intent(&intent).await {
			Ok(order) => {
				self.event_bus
					.publish(SolverEvent::Discovery(DiscoveryEvent::IntentValidated {
						intent_id: intent.id.clone(),
						order: order.clone(),
					}))
					.ok();

				// Store order
				self.state_machine
					.store_order(&order)
					.await
					.map_err(|e| IntentError::Storage(e.to_string()))?;

				// Store intent for later use
				self.storage
					.store(StorageKey::Intents.as_str(), &order.id, &intent)
					.await
					.map_err(|e| IntentError::Storage(e.to_string()))?;

				// Check execution strategy
				let context = ContextBuilder::build().await;
				match self.order_service.should_execute(&order, &context).await {
					ExecutionDecision::Execute(params) => {
						tracing::info!("Preparing order for execution");
						self.event_bus
							.publish(SolverEvent::Order(OrderEvent::Preparing {
								intent: intent.clone(),
								order,
								params,
							}))
							.ok();
					}
					ExecutionDecision::Skip(reason) => {
						self.event_bus
							.publish(SolverEvent::Order(OrderEvent::Skipped {
								order_id: order.id,
								reason,
							}))
							.ok();
					}
					ExecutionDecision::Defer(duration) => {
						self.event_bus
							.publish(SolverEvent::Order(OrderEvent::Deferred {
								order_id: order.id,
								retry_after: duration,
							}))
							.ok();
					}
				}
			}
			Err(e) => {
				self.event_bus
					.publish(SolverEvent::Discovery(DiscoveryEvent::IntentRejected {
						intent_id: intent.id,
						reason: e.to_string(),
					}))
					.ok();
			}
		}

		Ok(())
	}
}
