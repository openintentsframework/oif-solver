//! State management for orders within the solver.
//!
//! This module provides the state machine implementation for managing order
//! lifecycle transitions and persistence, ensuring valid state changes and
//! maintaining data consistency.

pub mod order;
pub mod transaction_attempt;

pub use order::{OrderStateError, OrderStateMachine};
