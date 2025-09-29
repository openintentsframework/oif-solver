//! Comprehensive logging and progress visualization module.
//!
//! This module provides extensive logging capabilities and visual feedback systems for the
//! OIF Solver demonstration system. It includes structured logging configuration, progress
//! tracking with spinners and progress bars, formatted output utilities for tables and
//! trees, and specialized logging for different types of operations. The module ensures
//! that users receive clear, informative feedback about system operations while maintaining
//! detailed logs for debugging and troubleshooting purposes.
//!
//! The logging system integrates with the tracing ecosystem to provide structured logging
//! with configurable verbosity levels, while the display utilities offer rich visual
//! formatting for command-line interfaces. Progress tracking components provide real-time
//! feedback for long-running operations, enhancing the user experience during complex
//! solver operations.

use anyhow::Result;
use colored::Colorize;
use comfy_table::Table;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, span, warn, Level};
use tracing_subscriber::{
	fmt::{self, format::FmtSpan},
	layer::SubscriberExt,
	util::SubscriberInitExt,
	EnvFilter, Registry,
};

/// Initializes the global logging system with appropriate configuration.
///
/// Sets up the tracing subscriber with the specified verbosity level and formatting
/// options. In debug mode, enables detailed span events and debug-level logging.
/// In normal mode, focuses on essential information with info-level logging.
/// The configuration includes terminal color support and compact formatting
/// optimized for command-line interfaces.
pub fn init_logging(debug: bool) -> Result<()> {
	let env_filter = if debug {
		EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"))
	} else {
		EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
	};

	let fmt_layer = fmt::layer()
		.with_target(false)
		.with_thread_ids(false)
		.with_thread_names(false)
		.with_file(false)
		.with_line_number(false)
		.with_ansi(true)
		.with_span_events(if debug { FmtSpan::CLOSE } else { FmtSpan::NONE })
		.without_time()
		.compact();

	Registry::default().with(env_filter).with(fmt_layer).init();

	Ok(())
}

/// Manager for progress tracking and visual feedback during long-running operations.
///
/// The ProgressManager coordinates multiple progress indicators including spinners
/// for indeterminate operations and progress bars for operations with known durations.
/// It provides a unified interface for creating and managing visual feedback elements
/// while ensuring proper cleanup and formatting. The manager integrates with the
/// terminal to provide smooth, non-flickering progress updates.
pub struct ProgressManager {
	/// Thread-safe multi-progress coordinator for managing multiple progress indicators.
	///
	/// Enables concurrent display of multiple progress bars and spinners while
	/// maintaining proper terminal output coordination and preventing visual conflicts.
	multi_progress: Arc<MultiProgress>,
}

impl Default for ProgressManager {
	fn default() -> Self {
		Self::new()
	}
}

impl ProgressManager {
	/// Creates a new ProgressManager instance.
	///
	/// Initializes the multi-progress coordinator for managing multiple
	/// concurrent progress indicators in a terminal-friendly manner.
	pub fn new() -> Self {
		Self {
			multi_progress: Arc::new(MultiProgress::new()),
		}
	}

	/// Creates a new spinner for indeterminate progress operations.
	///
	/// Returns a progress bar configured as a spinner with rotating animation
	/// characters and the specified message. Spinners are ideal for operations
	/// where the total duration or progress cannot be determined in advance.
	pub fn spinner(&self, message: impl Into<String>) -> ProgressBar {
		let pb = self.multi_progress.add(ProgressBar::new_spinner());
		pb.set_style(
			ProgressStyle::default_spinner()
				.template("{spinner:.green} {msg}")
				.unwrap()
				.tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
		);
		pb.set_message(message.into());
		pb.enable_steady_tick(Duration::from_millis(80));
		pb
	}

	/// Creates a new progress bar for operations with known total work.
	///
	/// Returns a progress bar configured with the specified length and message.
	/// Progress bars provide visual indication of completion percentage and
	/// estimated time remaining for operations with deterministic progress.
	pub fn progress_bar(&self, len: u64, message: impl Into<String>) -> ProgressBar {
		let pb = self.multi_progress.add(ProgressBar::new(len));
		pb.set_style(
            ProgressStyle::default_bar()
                .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                .unwrap()
                .progress_chars("#>-"),
        );
		pb.set_message(message.into());
		pb
	}

	/// Completes a progress indicator with a success message.
	///
	/// Finalizes the progress bar or spinner with a green checkmark and
	/// the specified success message, providing clear indication of
	/// successful operation completion.
	pub fn finish_with_success(&self, pb: ProgressBar, message: impl Into<String>) {
		pb.finish_with_message(format!("✓ {}", message.into()));
	}

	/// Completes a progress indicator with an error message.
	///
	/// Finalizes the progress bar or spinner with a red X mark and
	/// the specified error message, providing clear indication of
	/// operation failure.
	pub fn finish_with_error(&self, pb: ProgressBar, message: impl Into<String>) {
		pb.finish_with_message(format!("✗ {}", message.into().red()));
	}
}

/// Utility struct providing formatted output and display functions.
///
/// DisplayUtils offers a comprehensive set of methods for creating visually
/// appealing command-line output including tables, trees, sections, and
/// specialized formatting for different types of information. The utilities
/// use consistent styling and colors to provide a professional appearance
/// while maintaining readability across different terminal configurations.
pub struct DisplayUtils;

impl Default for DisplayUtils {
	fn default() -> Self {
		Self::new()
	}
}

impl DisplayUtils {
	/// Creates a new DisplayUtils instance.
	///
	/// Initializes the display utilities for formatted output operations.
	/// The instance can be reused across multiple formatting operations.
	pub fn new() -> Self {
		DisplayUtils
	}

	/// Displays data in a formatted table structure.
	///
	/// Creates and prints a table with the specified headers and row data,
	/// automatically handling column sizing and alignment for optimal
	/// readability in terminal output.
	pub fn table(&self, headers: Vec<&str>, rows: Vec<Vec<String>>) {
		let mut table = Table::new();
		table.set_header(headers);
		for row in rows {
			table.add_row(row);
		}
		println!("{}", table);
	}

	/// Displays an information section with key-value pairs.
	///
	/// Creates a titled section containing formatted key-value pairs,
	/// useful for displaying configuration information, status details,
	/// or other structured data.
	pub fn info_section(&self, title: &str, items: Vec<(&str, String)>) {
		println!("\n{}", title.bold().underline());
		for (key, value) in items {
			println!("  {} {}", format!("{}:", key).bright_black(), value);
		}
	}

	/// Displays a success message with green formatting.
	///
	/// Prints the message with a green checkmark and appropriate
	/// formatting to indicate successful operation completion.
	pub fn success(&self, message: &str) {
		println!("│ {} {}", "✓".green().bold(), message);
	}

	/// Displays an error message with red formatting.
	///
	/// Prints the message to stderr with a red X mark and error
	/// formatting to indicate operation failure or critical issues.
	pub fn error(&self, message: &str) {
		eprintln!("│ {} {}", "✗".red().bold(), message.red());
	}

	/// Displays a warning message with yellow formatting.
	///
	/// Prints the message with a yellow warning symbol and appropriate
	/// formatting to indicate potential issues or important notices.
	pub fn warning(&self, message: &str) {
		println!("│ {} {}", "⚠".yellow().bold(), message.yellow());
	}

	/// Displays an informational message with standard formatting.
	///
	/// Prints the message with consistent formatting for general
	/// information and status updates.
	pub fn info(&self, message: &str) {
		println!("│ {}", message);
	}

	/// Displays a prominent header with decorative border.
	///
	/// Creates a visually striking header with box-drawing characters
	/// and bold formatting, ideal for marking major sections or
	/// operation phases.
	pub fn header(&self, message: &str) {
		let msg = format!(" {} ", message.to_uppercase());
		let width = 64;
		// let padding = (width - msg.len()) / 2;
		let padded = format!("{:^width$}", msg, width = width);

		println!("\n╔{}╗", "═".repeat(width));
		println!("║{}║", padded.bold());
		println!("╚{}╝", "═".repeat(width));
	}

	/// Displays a section title with consistent formatting.
	///
	/// Creates a section header with bold formatting, used to
	/// organize information into logical groups within the output.
	pub fn section(&self, title: &str) {
		println!("\n│ {}:", title.bold());
	}

	/// Displays a formatted list of notes with tree-style formatting.
	///
	/// Creates a "Notes" section containing the provided items formatted
	/// as a tree structure with appropriate branching characters.
	pub fn notes(&self, items: Vec<&str>) {
		self.section("Notes");
		for (i, item) in items.iter().enumerate() {
			let prefix = if i == items.len() - 1 {
				"└─"
			} else {
				"├─"
			};
			println!("{} {}", prefix, item);
		}
	}

	/// Displays a numbered list of next steps with tree formatting.
	///
	/// Creates a "Next Steps" section containing numbered action items
	/// formatted as a tree structure for clear visual organization.
	pub fn next_steps(&self, steps: Vec<&str>) {
		self.section("Next Steps");
		for (i, step) in steps.iter().enumerate() {
			let prefix = if i == steps.len() - 1 {
				"└─"
			} else {
				"├─"
			};
			println!("{} {}. {}", prefix, i + 1, step);
		}
	}

	/// Displays operation results with success indicators.
	///
	/// Creates a "Results" section showing labeled results with
	/// green checkmarks, ideal for displaying operation outcomes.
	pub fn results(&self, items: Vec<(&str, String)>) {
		self.section("Results");
		for (i, (label, value)) in items.iter().enumerate() {
			let prefix = if i == items.len() - 1 {
				"└─"
			} else {
				"├─"
			};
			println!("{} {} {}: {}", prefix, "✓".green().bold(), label, value);
		}
	}

	/// Displays a titled list with tree-style formatting.
	///
	/// Creates a section with the specified title containing the
	/// provided items formatted as a tree structure.
	pub fn list(&self, title: &str, items: Vec<&str>) {
		self.section(title);
		for (i, item) in items.iter().enumerate() {
			let prefix = if i == items.len() - 1 {
				"└─"
			} else {
				"├─"
			};
			println!("{} {}", prefix, item);
		}
	}

	/// Displays a horizontal divider line.
	///
	/// Prints a line of dashes to create visual separation between
	/// different sections of output.
	pub fn divider(&self) {
		println!("\n{}", "─".repeat(64));
	}

	/// Displays content within a decorative box with title.
	///
	/// Creates a bordered box with the specified title and content
	/// lines, providing clear visual separation and emphasis.
	pub fn box_content(&self, title: &str, lines: Vec<&str>) {
		let width = 64;
		println!("\n┌─{}─┐", title.bold());
		for line in lines {
			println!("│ {:<width$} │", line, width = width - 2);
		}
		println!("└{}┘", "─".repeat(width));
	}

	/// Displays a single tree item with appropriate branching.
	///
	/// Renders a tree item with the correct branching character
	/// based on its position within the tree structure.
	pub fn tree_item(&self, content: &str, position: TreePosition) {
		let prefix = match position {
			TreePosition::First | TreePosition::Middle => "├─",
			TreePosition::Last | TreePosition::Only => "└─",
		};
		println!("{} {}", prefix, content);
	}

	/// Displays a nested tree item with custom indentation.
	///
	/// Renders a tree item with the specified indentation and
	/// appropriate branching character for nested tree structures.
	pub fn tree_item_nested(&self, content: &str, position: TreePosition, indent: &str) {
		let prefix = match position {
			TreePosition::First | TreePosition::Middle => "├─",
			TreePosition::Last | TreePosition::Only => "└─",
		};
		println!("{} {} {}", indent, prefix, content);
	}

	/// Displays a key-value pair as a tree item.
	///
	/// Renders a formatted key-value pair with appropriate tree
	/// branching for structured data display.
	pub fn tree_kv(&self, key: &str, value: &str, position: TreePosition) {
		self.tree_item(&format!("{}: {}", key, value), position);
	}

	/// Displays content with a bullet point.
	///
	/// Renders the content with a bullet character for simple
	/// list formatting.
	pub fn bullet(&self, content: &str) {
		println!("• {}", content);
	}

	/// Displays content as a continuation line.
	///
	/// Renders the content with a vertical bar prefix to indicate
	/// continuation or membership in a larger structure.
	pub fn line(&self, content: &str) {
		println!("│ {}", content);
	}

	/// Displays a tree separator line.
	///
	/// Prints a vertical bar character to create visual separation
	/// within tree structures.
	pub fn tree_separator(&self) {
		println!("│");
	}

	/// Displays a complete tree structure with title and items.
	///
	/// Creates a titled tree containing the specified items, automatically
	/// handling position calculations and appropriate branching for each item
	/// based on its type and position within the tree.
	pub fn tree(&self, title: &str, items: Vec<TreeItem>) {
		self.section(title);
		for (i, item) in items.iter().enumerate() {
			let position = if i == 0 && items.len() == 1 {
				TreePosition::Only
			} else if i == 0 {
				TreePosition::First
			} else if i == items.len() - 1 {
				TreePosition::Last
			} else {
				TreePosition::Middle
			};

			match item {
				TreeItem::Text(text) => self.tree_item(text, position),
				TreeItem::KeyValue(key, value) => self.tree_kv(key, value, position),
				TreeItem::Success(text) => self.tree_item(&format!("✓ {}", text), position),
				TreeItem::Error(text) => self.tree_item(&format!("✗ {}", text), position),
				TreeItem::Info(text) => self.tree_item(&format!("• {}", text), position),
			}
		}
	}
}

/// Enumeration representing the position of an item within a tree structure.
///
/// TreePosition determines the appropriate branching character to use when
/// rendering tree items, ensuring proper visual representation of hierarchical
/// relationships and tree boundaries.
#[derive(Clone, Copy, Debug)]
pub enum TreePosition {
	/// First item in a multi-item tree.
	///
	/// Uses branching characters appropriate for the beginning of a tree.
	First,

	/// Middle item in a multi-item tree.
	///
	/// Uses branching characters appropriate for items in the middle of a tree.
	Middle,

	/// Last item in a multi-item tree.
	///
	/// Uses branching characters appropriate for the end of a tree.
	Last,

	/// Single item in a tree (both first and last).
	///
	/// Uses branching characters appropriate for standalone items.
	Only,
}

/// Enumeration representing different types of items that can be displayed in trees.
///
/// TreeItem provides various formatting options for tree content including plain text,
/// key-value pairs, and status-specific formatting with appropriate visual indicators.
/// Each variant applies different styling and symbols to convey information type.
#[derive(Debug)]
pub enum TreeItem {
	/// Plain text item without special formatting.
	///
	/// Displays the text content as-is within the tree structure.
	Text(String),

	/// Key-value pair item with formatted display.
	///
	/// Displays the key and value in a standardized "key: value" format.
	KeyValue(String, String),

	/// Success item with green checkmark.
	///
	/// Displays the text with a green checkmark prefix to indicate success.
	Success(String),

	/// Error item with red X mark.
	///
	/// Displays the text with a red X mark prefix to indicate error or failure.
	Error(String),

	/// Informational item with bullet point.
	///
	/// Displays the text with a bullet point prefix for general information.
	Info(String),
}

/// Specialized logging events module for structured operation tracking.
///
/// This module provides structured logging functions for specific types of operations
/// within the solver system. Each function creates appropriately tagged log entries
/// with relevant context information, enabling detailed operation tracking and
/// debugging capabilities.
pub mod events {
	use super::*;

	/// Logs a contract deployment event with structured context.
	///
	/// Records the successful deployment of a smart contract with chain ID,
	/// contract name, deployed address, and transaction hash for tracking
	/// and audit purposes.
	#[tracing::instrument(skip_all, fields(chain_id = %chain_id, contract = %contract_name))]
	pub fn deployment(chain_id: u64, contract_name: &str, address: &str, tx_hash: &str) {
		info!(
			address = %address,
			tx_hash = %tx_hash,
			"Contract deployed successfully"
		);
	}

	/// Logs an API request event with method and endpoint context.
	///
	/// Records the initiation of an API request with HTTP method and
	/// endpoint information for request tracking and debugging.
	#[tracing::instrument(skip_all, fields(method = %method, endpoint = %endpoint))]
	pub fn api_request(method: &str, endpoint: &str) {
		debug!("Making API request");
	}

	/// Logs an API response event with status and timing information.
	///
	/// Records the completion of an API request with HTTP status code
	/// and response duration for performance monitoring and debugging.
	#[tracing::instrument(skip_all, fields(status = %status))]
	pub fn api_response(status: u16, duration_ms: u64) {
		debug!(duration_ms = duration_ms, "API response received");
	}

	/// Logs a blockchain transaction event with execution details.
	///
	/// Records the submission of a blockchain transaction with chain ID,
	/// transaction hash, and gas usage information for transaction tracking.
	#[tracing::instrument(skip_all, fields(chain_id = %chain_id))]
	pub fn transaction(chain_id: u64, tx_hash: &str, gas_used: Option<u64>) {
		info!(
			tx_hash = %tx_hash,
			gas_used = ?gas_used,
			"Transaction submitted"
		);
	}

	/// Creates a tracing span for command execution tracking.
	///
	/// Returns a span configured for tracking the execution of a specific
	/// command, enabling hierarchical operation monitoring.
	pub fn command_span(command: &str) -> tracing::Span {
		span!(Level::INFO, "command", name = %command)
	}

	/// Creates a tracing span for service operation tracking.
	///
	/// Returns a span configured for tracking operations within a specific
	/// service, enabling detailed service-level monitoring and debugging.
	pub fn service_span(service: &str, operation: &str) -> tracing::Span {
		span!(Level::DEBUG, "service", name = %service, op = %operation)
	}
}

/// Macro for logging success messages with checkmark formatting.
///
/// Creates a formatted success log entry with a green checkmark prefix,
/// targeting the "oif_demo" log target for consistent message filtering.
#[macro_export]
macro_rules! log_success {
    ($($arg:tt)*) => {
        tracing::info!(target: "oif_demo", "✓ {}", format!($($arg)*))
    };
}

/// Macro for logging error messages with X mark formatting.
///
/// Creates a formatted error log entry with a red X mark prefix,
/// targeting the "oif_demo" log target for consistent message filtering.
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        tracing::error!(target: "oif_demo", "✗ {}", format!($($arg)*))
    };
}

/// Macro for logging warning messages with warning symbol formatting.
///
/// Creates a formatted warning log entry with a yellow warning symbol prefix,
/// targeting the "oif_demo" log target for consistent message filtering.
#[macro_export]
macro_rules! log_warning {
    ($($arg:tt)*) => {
        tracing::warn!(target: "oif_demo", "⚠ {}", format!($($arg)*))
    };
}
