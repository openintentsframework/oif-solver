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
