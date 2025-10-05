//! Terminal output utilities and formatting
//!
//! Provides consistent formatting and display utilities for CLI output including
//! colored messages, tables, progress bars, and structured information display.
//! Uses colored text, Unicode symbols, and progress indicators for enhanced
//! user experience in terminal interfaces.

use colored::Colorize;

/// Terminal display utilities for formatted CLI output
///
/// Provides static methods for consistent terminal output formatting including
/// colored status messages, structured data display, tables, and progress indicators.
/// Uses Unicode symbols and color coding for enhanced readability.
pub struct Display;

impl Display {
	/// Displays a formatted section header with underline
	///
	/// # Arguments
	/// * `text` - Header text to display
	pub fn header(text: &str) {
		println!("\n{}", text.bold().cyan());
		println!("{}", "─".repeat(text.len()).cyan());
	}

	/// Displays a success message with green checkmark
	///
	/// # Arguments
	/// * `message` - Success message to display
	pub fn success(message: &str) {
		println!("{} {}", "✓".green().bold(), message);
	}

	/// Displays an error message with red X symbol to stderr
	///
	/// # Arguments
	/// * `message` - Error message to display
	pub fn error(message: &str) {
		eprintln!("{} {}", "✗".red().bold(), message.red());
	}

	/// Displays a warning message with yellow warning symbol
	///
	/// # Arguments
	/// * `message` - Warning message to display
	pub fn warning(message: &str) {
		println!("{} {}", "⚠".yellow().bold(), message.yellow());
	}

	/// Displays an informational message with blue info symbol
	///
	/// # Arguments
	/// * `message` - Information message to display
	pub fn info(message: &str) {
		println!("{} {}", "ℹ".blue().bold(), message);
	}

	/// Displays a key-value pair with formatted labels
	///
	/// # Arguments
	/// * `key` - Label or key name
	/// * `value` - Associated value to display
	pub fn kv(key: &str, value: &str) {
		println!("  {} {}", format!("{}:", key).bold(), value);
	}

	/// Displays a formatted section title with arrow prefix
	///
	/// # Arguments
	/// * `title` - Section title text to display
	pub fn section(title: &str) {
		println!("\n{}", format!("▸ {}", title).bold());
	}

	/// Displays a numbered list of next steps
	///
	/// # Arguments
	/// * `steps` - Array of step descriptions to display
	pub fn next_steps(steps: &[&str]) {
		Self::section("Next Steps");
		for (i, step) in steps.iter().enumerate() {
			println!("  {}. {}", i + 1, step);
		}
	}
}
