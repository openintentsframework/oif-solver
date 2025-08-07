//! Lifecycle management for the solver engine.
//!
//! Handles initialization and shutdown procedures for the solver engine,
//! ensuring proper startup and cleanup of all services.

use super::SolverEngine;

impl SolverEngine {
	/// Performs any initialization required before running
	pub async fn initialize(&self) -> Result<(), super::EngineError> {
		tracing::info!("Initializing solver engine");
		Ok(())
	}

	/// Performs cleanup operations
	pub async fn shutdown(&self) -> Result<(), super::EngineError> {
		tracing::info!("Shutting down solver engine");

		// Stop discovery sources
		self.discovery
			.stop_all()
			.await
			.map_err(|e| super::EngineError::Service(e.to_string()))?;

		Ok(())
	}
}
