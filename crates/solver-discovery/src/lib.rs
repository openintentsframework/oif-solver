//! Intent discovery module for the OIF solver system.
//!
//! This module handles the discovery of new intents from various sources.
//! It provides abstractions for different discovery mechanisms such as
//! on-chain event monitoring, off-chain APIs, or other intent sources.

use async_trait::async_trait;
use solver_types::{ConfigSchema, Intent};
use thiserror::Error;
use tokio::sync::mpsc;

/// Re-export implementations
pub mod implementations {
	pub mod onchain {
		pub mod _7683;
	}
	pub mod offchain {
		pub mod _7683;
	}
}

/// Errors that can occur during intent discovery operations.
#[derive(Debug, Error)]
pub enum DiscoveryError {
	/// Error that occurs when connecting to a discovery source fails.
	#[error("Connection error: {0}")]
	Connection(String),
	/// Error that occurs when trying to start monitoring on an already active source.
	#[error("Already monitoring")]
	AlreadyMonitoring,
	/// Error that occurs when parsing or decoding data fails.
	#[error("Parse error: {0}")]
	ParseError(String),
	/// Error that occurs when validating intent data.
	#[error("Validation error: {0}")]
	ValidationError(String),
}

/// Trait defining the interface for intent discovery sources.
///
/// This trait must be implemented by any discovery source that wants to
/// integrate with the solver system. It provides methods for starting and
/// stopping intent monitoring.
#[async_trait]
pub trait DiscoveryInterface: Send + Sync {
	/// Returns the configuration schema for this discovery implementation.
	///
	/// This allows each implementation to define its own configuration requirements
	/// with specific validation rules. The schema is used to validate TOML configuration
	/// before initializing the discovery source.
	fn config_schema(&self) -> Box<dyn ConfigSchema>;

	/// Starts monitoring for new intents from this source.
	///
	/// Discovered intents are sent through the provided channel. The implementation
	/// should continue monitoring until stop_monitoring is called or an error occurs.
	async fn start_monitoring(
		&self,
		sender: mpsc::UnboundedSender<Intent>,
	) -> Result<(), DiscoveryError>;

	/// Stops monitoring for new intents from this source.
	///
	/// This method should cleanly shut down any active monitoring tasks
	/// and release associated resources.
	async fn stop_monitoring(&self) -> Result<(), DiscoveryError>;
}

/// Service that manages multiple intent discovery sources.
///
/// The DiscoveryService coordinates multiple discovery sources, allowing
/// the solver to find intents from various channels simultaneously.
pub struct DiscoveryService {
	/// Collection of discovery sources to monitor.
	sources: Vec<Box<dyn DiscoveryInterface>>,
}

impl DiscoveryService {
	/// Creates a new DiscoveryService with the specified sources.
	///
	/// Each source will be monitored independently when monitoring is started.
	pub fn new(sources: Vec<Box<dyn DiscoveryInterface>>) -> Self {
		Self { sources }
	}

	/// Starts monitoring on all configured discovery sources.
	///
	/// All discovered intents from any source will be sent through the
	/// provided channel. If any source fails to start, the entire operation
	/// fails and no sources will be monitoring.
	pub async fn start_all(
		&self,
		sender: mpsc::UnboundedSender<Intent>,
	) -> Result<(), DiscoveryError> {
		for source in &self.sources {
			source.start_monitoring(sender.clone()).await?;
		}
		Ok(())
	}

	/// Stops monitoring on all active discovery sources.
	///
	/// This method attempts to stop all sources, even if some fail.
	/// The first error encountered is returned, but all sources are
	/// attempted to be stopped.
	pub async fn stop_all(&self) -> Result<(), DiscoveryError> {
		for source in &self.sources {
			source.stop_monitoring().await?;
		}
		Ok(())
	}
}
