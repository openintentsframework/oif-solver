//! Core solver engine for the OIF solver system.
//!
//! This module provides the main orchestration logic for the solver, coordinating
//! between all the various services (discovery, order processing, delivery, settlement)
//! to execute the complete order lifecycle. It includes the event-driven architecture
//! and modular design for building solver instances.

pub mod builder;
pub mod engine;
pub mod handlers;
pub mod monitoring;
pub mod state;
pub mod utils;

// Re-export main types
pub use builder::{BuilderError, SolverBuilder, SolverFactories};
pub use engine::event_bus::EventBus;
pub use engine::{EngineError, SolverEngine};

// Re-export error types
pub use handlers::intent::IntentError;
pub use handlers::order::OrderError;
pub use handlers::settlement::SettlementError;
pub use handlers::transaction::TransactionError;
pub use state::OrderStateError;

// Re-export old SolverError for compatibility
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SolverError {
	#[error("Configuration error: {0}")]
	Config(String),
	#[error("Service error: {0}")]
	Service(String),
}
