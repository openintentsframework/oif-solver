//! Centralized logging utilities for the solver demo
//!
//! This module provides wrapper functions that combine user-facing CLI output
//! with structured tracing for comprehensive logging coverage. It maintains
//! the excellent CLI user experience while adding rich debugging capabilities.

use crate::cli::output::Display;
use tracing::{error, info, warn};

/// High-level operation result with both user and developer logging
///
/// Provides user feedback through Display while recording structured logs
/// for debugging and monitoring purposes.
///
/// # Arguments
/// * `operation` - Name of the operation that completed
/// * `details` - Additional context for logging
pub fn operation_success(operation: &str, details: &str) {
	Display::success(&format!("{} completed successfully", operation));
	info!(
		operation = operation,
		details = details,
		"Operation completed successfully"
	);
}

/// High-level operation error with both user and developer logging
///
/// Shows user-friendly error message while capturing full error context
/// for debugging and monitoring purposes.
///
/// # Arguments
/// * `operation` - Name of the operation that failed
/// * `error` - Error that caused the failure
pub fn operation_error(operation: &str, error: &anyhow::Error) {
	Display::error(&format!("{} failed: {}", operation, error));
	error!(
		operation = operation,
		error = %error,
		"Operation failed"
	);
}

/// Operation warning with both user and developer logging
///
/// Shows user-friendly warning message while capturing context
/// for debugging and monitoring purposes.
///
/// # Arguments
/// * `operation` - Name of the operation with warning
/// * `message` - Warning message to display
/// * `context` - Additional context for logging
pub fn operation_warning(operation: &str, message: &str, context: &str) {
	Display::warning(message);
	warn!(
		operation = operation,
		message = message,
		context = context,
		"Operation warning"
	);
}

/// Progress update for long-running operations
///
/// Logs operation progress without user output (preserves CLI cleanliness)
/// while providing structured progress tracking for debugging.
///
/// # Arguments
/// * `operation` - Name of the operation in progress
/// * `step` - Current step description
/// * `progress` - Optional progress tuple (current, total)
pub fn operation_progress(operation: &str, step: &str, progress: Option<(u64, u64)>) {
	match progress {
		Some((current, total)) => {
			info!(
				operation = operation,
				step = step,
				current = current,
				total = total,
				progress_percent = (current as f64 / total as f64 * 100.0) as u8,
				"Operation progress"
			);
		},
		None => {
			info!(operation = operation, step = step, "Operation step");
		},
	}
}

/// Log operation start with structured context
///
/// Records the beginning of an operation with relevant parameters
/// for debugging and performance monitoring.
///
/// # Arguments
/// * `operation` - Name of the operation starting
/// * `context` - Additional context for the operation
pub fn operation_start(operation: &str, context: &str) {
	info!(
		operation = operation,
		context = context,
		"Operation started"
	);
}

/// Log operation completion with timing information
///
/// Records the completion of an operation with duration
/// for performance monitoring and debugging.
///
/// # Arguments
/// * `operation` - Name of the completed operation
/// * `duration_ms` - Operation duration in milliseconds
pub fn operation_complete(operation: &str, duration_ms: u64) {
	info!(
		operation = operation,
		duration_ms = duration_ms,
		"Operation completed"
	);
}
