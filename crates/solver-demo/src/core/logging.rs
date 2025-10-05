//! Centralized logging utilities for the solver demo
//!
//! This module provides a clear separation between user-facing CLI output
//! and technical debug logging using tracing levels:
//!
//! - INFO: Clean user-facing messages (guided workflow output)
//! - DEBUG: Technical details (IDs, payloads, function flow)
//! - TRACE: Verbose debugging (full data structures, performance)
//!
//! Three-layer architecture:
//! 1. USER: Clean workflow guidance (always visible)
//! 2. VERBOSE: Operational details (--verbose flag)
//! 3. DEBUG: Development debugging (RUST_LOG=debug)

use tracing::{debug, error, info, warn};

// =============================================================================
// USER INTERFACE LAYER (INFO level - always visible)
// Clean, actionable messages that guide users through workflows
// =============================================================================

/// Display operation start message
pub fn operation_start(operation: &str) {
	info!("{}", operation);
}

/// Display success message with checkmark
pub fn success(message: &str) {
	info!("✓ {}", message);
}

/// Display error message with X mark  
pub fn error_msg(message: &str) {
	error!("✗ {}", message);
}

/// Display warning message with warning symbol
pub fn warning(message: &str) {
	warn!("⚠ {}", message);
}

/// Display next step guidance with arrow
pub fn next_step(message: &str) {
	info!("→ Next: {}", message);
}

/// Display information bullet point
pub fn info_bullet(message: &str) {
	info!("• {}", message);
}

/// Display key-value information
pub fn info_kv(key: &str, value: &str) {
	info!("• {}: {}", key, value);
}

/// Display section header for grouped information
pub fn section_header(title: &str) {
	info!("\n{}:", title);
}

/// Display subsection with indentation
pub fn subsection(title: &str) {
	info!("  {}:", title);
}

/// Display indented item
pub fn item(message: &str) {
	info!("    • {}", message);
}

// =============================================================================
// VERBOSE LAYER (DEBUG level - only with --verbose flag)
// Technical details for troubleshooting and operations
// =============================================================================

/// Log verbose operational context
pub fn verbose_operation(operation: &str, details: &str) {
	debug!("• {}: {}", operation, details);
}

/// Log verbose success with additional context
pub fn verbose_success(operation: &str, details: &str) {
	debug!("✓ {}: {}", operation, details);
}

/// Log verbose transaction or technical details
pub fn verbose_tech(label: &str, value: &str) {
	debug!("• {}: {}", label, value);
}

/// Log verbose timing information
pub fn verbose_timing(operation: &str, duration_ms: u64) {
	debug!("• {}: completed in {}ms", operation, duration_ms);
}

/// Log verbose count/progress information
pub fn verbose_progress(operation: &str, current: usize, total: usize) {
	debug!("• {}: {}/{}", operation, current, total);
}

// =============================================================================
// DEBUG LAYER (DEBUG level - development debugging)
// Technical details for developers working on the codebase
// =============================================================================

/// Log technical operation context for debugging
pub fn debug_operation(operation: &str, context: &str) {
	debug!(
		operation = operation,
		context = context,
		"Operation context"
	);
}

/// Log technical success with full context  
pub fn debug_success(operation: &str, details: &str) {
	debug!(
		operation = operation,
		details = details,
		"Operation completed with context"
	);
}

/// Log technical error with full error context
pub fn debug_error(operation: &str, error: &anyhow::Error) {
	debug!(
		operation = operation,
		error = %error,
		"Operation failed with error context"
	);
}

/// Log function entry with parameters (for flow tracking)
pub fn debug_function_entry(function: &str, params: &str) {
	debug!(function = function, params = params, "Function entry");
}

/// Log data structure for debugging (selective fields only)
pub fn debug_data(operation: &str, data_type: &str, summary: &str) {
	debug!(
		operation = operation,
		data_type = data_type,
		summary = summary,
		"Data context"
	);
}

// =============================================================================
// ERROR HANDLING UTILITIES
// =============================================================================

/// Display error with resolution guidance
pub fn error_with_guidance(error: &str, guidance: &str) {
	error!("✗ {}", error);
	info!("→ {}", guidance);
}

/// Display validation error with example
pub fn validation_error(field: &str, issue: &str, example: &str) {
	error!("✗ Invalid {}: {}", field, issue);
	info!("→ Example: {}", example);
}

/// Display file error with suggested action
pub fn file_error(operation: &str, path: &str, suggestion: &str) {
	error!("✗ {} file not found: {}", operation, path);
	info!("→ {}", suggestion);
}

/// Display error with symbol
pub fn error_message(message: &str) {
	error!("✗ {}", message);
}

/// Display simple error without guidance
pub fn simple_error(message: &str) {
	error!("✗ {}", message);
}
