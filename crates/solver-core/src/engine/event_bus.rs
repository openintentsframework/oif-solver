//! Event bus implementation for inter-service communication.
//!
//! This module provides a broadcast-based event bus that allows different
//! services within the solver to communicate asynchronously through events.

use solver_types::SolverEvent;
use tokio::sync::broadcast;

/// Event bus for broadcasting solver events to multiple subscribers.
///
/// The EventBus uses tokio's broadcast channel to allow multiple services
/// to subscribe to and publish events. This enables loose coupling between
/// services while maintaining a clear communication pattern.
pub struct EventBus {
	/// The broadcast sender used to publish events.
	sender: broadcast::Sender<SolverEvent>,
}

impl EventBus {
	/// Creates a new EventBus with the specified channel capacity.
	///
	/// The capacity determines how many events can be buffered in the channel
	/// before old events start being dropped when the channel is full.
	pub fn new(capacity: usize) -> Self {
		let (sender, _) = broadcast::channel(capacity);
		Self { sender }
	}

	/// Creates a new subscriber to receive events from this bus.
	///
	/// Each subscriber receives its own copy of all events published
	/// after the subscription is created.
	pub fn subscribe(&self) -> broadcast::Receiver<SolverEvent> {
		self.sender.subscribe()
	}

	/// Publishes an event to all current subscribers.
	///
	/// Returns an error if there are no active subscribers, though
	/// this is typically not a critical error in the solver context.
	pub fn publish(
		&self,
		event: SolverEvent,
	) -> Result<(), broadcast::error::SendError<SolverEvent>> {
		self.sender.send(event)?;
		Ok(())
	}
}

/// Implementation of Clone for EventBus to allow sharing across services.
///
/// Cloning an EventBus creates a new handle to the same underlying
/// broadcast channel, allowing multiple services to publish events.
impl Clone for EventBus {
	fn clone(&self) -> Self {
		Self {
			sender: self.sender.clone(),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use solver_types::{
		utils::builders::{IntentBuilder, OrderBuilder},
		DeliveryEvent, ExecutionParams, OrderEvent, SolverEvent,
	};

	#[test]
	fn test_new_event_bus() {
		let event_bus = EventBus::new(10);

		// EventBus should be created successfully
		assert!(event_bus.sender.receiver_count() == 0); // No subscribers initially
	}

	#[test]
	fn test_subscribe_creates_receiver() {
		let event_bus = EventBus::new(10);

		let _receiver = event_bus.subscribe();

		// Should have one subscriber now
		assert_eq!(event_bus.sender.receiver_count(), 1);
	}

	#[test]
	fn test_multiple_subscribers() {
		let event_bus = EventBus::new(10);

		let _receiver1 = event_bus.subscribe();
		let _receiver2 = event_bus.subscribe();
		let _receiver3 = event_bus.subscribe();

		// Should have three subscribers
		assert_eq!(event_bus.sender.receiver_count(), 3);
	}

	#[tokio::test]
	async fn test_publish_and_receive_event() {
		let event_bus = EventBus::new(10);
		let mut receiver = event_bus.subscribe();

		let test_event = SolverEvent::Order(OrderEvent::Preparing {
			intent: IntentBuilder::new().with_id("test-intent").build(),
			order: OrderBuilder::new().with_id("test-order").build(),
			params: ExecutionParams {
				gas_price: alloy_primitives::U256::from(20_000_000_000u64),
				priority_fee: None,
			},
		});

		// Publish the event
		let result = event_bus.publish(test_event.clone());
		assert!(result.is_ok());

		// Receive the event
		let received_event = receiver.recv().await.unwrap();

		// Verify the event matches
		match (&test_event, &received_event) {
			(
				SolverEvent::Order(OrderEvent::Preparing {
					intent: i1,
					order: o1,
					..
				}),
				SolverEvent::Order(OrderEvent::Preparing {
					intent: i2,
					order: o2,
					..
				}),
			) => {
				assert_eq!(i1.id, i2.id);
				assert_eq!(o1.id, o2.id);
			},
			_ => panic!("Event types don't match"),
		}
	}

	#[tokio::test]
	async fn test_multiple_subscribers_receive_same_event() {
		let event_bus = EventBus::new(10);
		let mut receiver1 = event_bus.subscribe();
		let mut receiver2 = event_bus.subscribe();

		let test_event = SolverEvent::Delivery(DeliveryEvent::TransactionPending {
			order_id: "test-order".to_string(),
			tx_hash: solver_types::TransactionHash([0x12; 32].to_vec()),
			tx_type: solver_types::TransactionType::Prepare,
			tx_chain_id: 1,
		});

		// Publish the event
		event_bus.publish(test_event.clone()).unwrap();

		// Both receivers should get the event
		let received1 = receiver1.recv().await.unwrap();
		let received2 = receiver2.recv().await.unwrap();

		// Verify both received the same event
		match (&received1, &received2) {
			(
				SolverEvent::Delivery(DeliveryEvent::TransactionPending { order_id: id1, .. }),
				SolverEvent::Delivery(DeliveryEvent::TransactionPending { order_id: id2, .. }),
			) => {
				assert_eq!(id1, id2);
			},
			_ => panic!("Events don't match"),
		}
	}

	#[test]
	fn test_publish_with_no_subscribers() {
		let event_bus = EventBus::new(10);

		let test_event = SolverEvent::Delivery(DeliveryEvent::TransactionPending {
			order_id: "test-order".to_string(),
			tx_hash: solver_types::TransactionHash([0x12; 32].to_vec()),
			tx_type: solver_types::TransactionType::Prepare,
			tx_chain_id: 1,
		});

		// Publishing with no subscribers should return an error
		let result = event_bus.publish(test_event);
		assert!(result.is_err());
	}

	#[tokio::test]
	async fn test_receiver_dropped_before_publish() {
		let event_bus = EventBus::new(10);

		{
			let _receiver = event_bus.subscribe();
			// receiver is dropped here
		}

		let test_event = SolverEvent::Delivery(DeliveryEvent::TransactionPending {
			order_id: "test-order".to_string(),
			tx_hash: solver_types::TransactionHash([0x12; 32].to_vec()),
			tx_type: solver_types::TransactionType::Prepare,
			tx_chain_id: 1,
		});

		// Should return error since no active subscribers
		let result = event_bus.publish(test_event);
		assert!(result.is_err());
	}

	#[tokio::test]
	async fn test_late_subscriber_misses_previous_events() {
		let event_bus = EventBus::new(10);
		let mut early_receiver = event_bus.subscribe();

		let test_event = SolverEvent::Delivery(DeliveryEvent::TransactionPending {
			order_id: "test-order".to_string(),
			tx_hash: solver_types::TransactionHash([0x12; 32].to_vec()),
			tx_type: solver_types::TransactionType::Prepare,
			tx_chain_id: 1,
		});

		// Publish event
		event_bus.publish(test_event.clone()).unwrap();

		// Early receiver gets the event
		let _received = early_receiver.recv().await.unwrap();

		// Late subscriber created after event was published
		let mut late_receiver = event_bus.subscribe();

		// Late receiver should not receive the previous event
		// We can't easily test this without timing issues, but we can test
		// that it receives new events
		let new_event = SolverEvent::Delivery(DeliveryEvent::TransactionPending {
			order_id: "new-order".to_string(),
			tx_hash: solver_types::TransactionHash([0x34; 32].to_vec()),
			tx_type: solver_types::TransactionType::Fill,
			tx_chain_id: 2,
		});

		event_bus.publish(new_event.clone()).unwrap();

		// Both should receive the new event
		let early_received = early_receiver.recv().await.unwrap();
		let late_received = late_receiver.recv().await.unwrap();

		match (&early_received, &late_received) {
			(
				SolverEvent::Delivery(DeliveryEvent::TransactionPending { order_id: id1, .. }),
				SolverEvent::Delivery(DeliveryEvent::TransactionPending { order_id: id2, .. }),
			) => {
				assert_eq!(id1, "new-order");
				assert_eq!(id2, "new-order");
			},
			_ => panic!("Events don't match"),
		}
	}

	#[test]
	fn test_event_bus_clone() {
		let event_bus1 = EventBus::new(10);
		let event_bus2 = event_bus1.clone();

		// Both should share the same underlying channel
		let _receiver1 = event_bus1.subscribe();
		let _receiver2 = event_bus2.subscribe();

		// Both event buses should see both subscribers
		assert_eq!(event_bus1.sender.receiver_count(), 2);
		assert_eq!(event_bus2.sender.receiver_count(), 2);
	}

	#[tokio::test]
	async fn test_cloned_event_bus_publishes_to_all_subscribers() {
		let event_bus1 = EventBus::new(10);
		let event_bus2 = event_bus1.clone();

		let mut receiver1 = event_bus1.subscribe();
		let mut receiver2 = event_bus2.subscribe();

		let test_event = SolverEvent::Delivery(DeliveryEvent::TransactionPending {
			order_id: "test-order".to_string(),
			tx_hash: solver_types::TransactionHash([0x12; 32].to_vec()),
			tx_type: solver_types::TransactionType::Prepare,
			tx_chain_id: 1,
		});

		// Publish from cloned event bus
		event_bus2.publish(test_event.clone()).unwrap();

		// Both receivers should get the event
		let received1 = receiver1.recv().await.unwrap();
		let received2 = receiver2.recv().await.unwrap();

		match (&received1, &received2) {
			(
				SolverEvent::Delivery(DeliveryEvent::TransactionPending { order_id: id1, .. }),
				SolverEvent::Delivery(DeliveryEvent::TransactionPending { order_id: id2, .. }),
			) => {
				assert_eq!(id1, id2);
			},
			_ => panic!("Events don't match"),
		}
	}
}
