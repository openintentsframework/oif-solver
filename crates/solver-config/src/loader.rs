//! Configuration loader module for handling modular configuration files.
//!
//! This module provides functionality to load configuration from multiple files
//! and validate that sections are unique across files to prevent merge conflicts.

use crate::{resolve_env_vars, Config, ConfigError};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Configuration loader that handles multi-file configurations with includes.
pub struct ConfigLoader {
	/// Base path for resolving relative includes
	base_path: PathBuf,
	/// Track loaded files to prevent circular includes
	loaded_files: HashSet<PathBuf>,
	/// Track which sections come from which files for error reporting
	section_sources: HashMap<String, PathBuf>,
}

impl ConfigLoader {
	/// Creates a new ConfigLoader with the given base path.
	pub fn new(base_path: impl AsRef<Path>) -> Self {
		Self {
			base_path: base_path.as_ref().to_path_buf(),
			loaded_files: HashSet::new(),
			section_sources: HashMap::new(),
		}
	}

	/// Loads environment variables from .env files in the current working directory.
	///
	/// This method attempts to load .env files in the following order:
	/// 1. .env.local (highest priority)
	/// 2. .env
	///
	/// Later files override earlier ones.
	fn load_env_files_from_cwd(&self) -> Result<(), ConfigError> {
		let env_files = [".env", ".env.local"];

		for env_file in &env_files {
			let env_path = PathBuf::from(env_file);
			if env_path.exists() {
				dotenvy::from_path(&env_path).map_err(|e| {
					ConfigError::Validation(format!(
						"Failed to load environment file {}: {}",
						env_path.display(),
						e
					))
				})?;
			}
		}

		Ok(())
	}

	/// Loads a configuration file and all its includes, loading .env files first.
	pub async fn load_config(
		&mut self,
		config_path: impl AsRef<Path>,
	) -> Result<Config, ConfigError> {
		// Load environment variables first
		self.load_env_files_from_cwd()?;

		// Then load the config
		self.load_config_without_env(config_path).await
	}

	/// Loads a configuration file and all its includes without loading .env files.
	/// Assumes environment variables have already been loaded.
	async fn load_config_without_env(
		&mut self,
		config_path: impl AsRef<Path>,
	) -> Result<Config, ConfigError> {
		let config_path = self.resolve_path(config_path)?;

		// Load the main configuration file
		let main_content = self.load_file(&config_path).await?;
		let main_toml: toml::Value = toml::from_str(&main_content)?;

		// Check for includes
		let includes = self.extract_includes(&main_toml)?;

		// If no includes, just parse and return the main config
		if includes.is_empty() {
			let config: Config = main_content.parse()?;
			return Ok(config);
		}

		// Build combined TOML with validation
		let combined_toml = self
			.load_and_combine(main_toml, includes, config_path.clone())
			.await?;

		// Convert to Config and validate
		let config_str = toml::to_string(&combined_toml)
			.map_err(|e| ConfigError::Parse(format!("Failed to serialize combined config: {e}")))?;
		let config: Config = config_str.parse()?;

		Ok(config)
	}

	/// Loads a file and resolves environment variables.
	async fn load_file(&mut self, path: &Path) -> Result<String, ConfigError> {
		// Check for circular includes
		let canonical_path = path.canonicalize().map_err(|e| {
			ConfigError::Io(std::io::Error::new(
				std::io::ErrorKind::NotFound,
				format!("Cannot resolve path {}: {}", path.display(), e),
			))
		})?;

		if !self.loaded_files.insert(canonical_path.clone()) {
			return Err(ConfigError::Validation(format!(
				"Circular include detected: {} was already loaded",
				canonical_path.display()
			)));
		}

		let content = std::fs::read_to_string(path)?;
		resolve_env_vars(&content)
	}

	/// Extracts include directives from the configuration.
	fn extract_includes(&self, toml: &toml::Value) -> Result<Vec<PathBuf>, ConfigError> {
		let mut includes = Vec::new();

		// Check for include array
		if let Some(include_value) = toml.get("include") {
			if let Some(include_array) = include_value.as_array() {
				for item in include_array {
					if let Some(path_str) = item.as_str() {
						includes.push(PathBuf::from(path_str));
					} else {
						return Err(ConfigError::Validation(
							"Include array must contain only strings".into(),
						));
					}
				}
			} else if let Some(path_str) = include_value.as_str() {
				includes.push(PathBuf::from(path_str));
			} else {
				return Err(ConfigError::Validation(
					"Include must be a string or array of strings".into(),
				));
			}
		}

		Ok(includes)
	}

	/// Loads and combines configuration files with section uniqueness validation.
	async fn load_and_combine(
		&mut self,
		mut main_toml: toml::Value,
		includes: Vec<PathBuf>,
		main_file_path: PathBuf,
	) -> Result<toml::Value, ConfigError> {
		// Remove include directives from main config
		if let Some(table) = main_toml.as_table_mut() {
			table.remove("include");
		}

		// Track sections in main file
		if let Some(main_table) = main_toml.as_table() {
			for key in main_table.keys() {
				self.section_sources
					.insert(key.clone(), main_file_path.clone());
			}
		}

		// Load and validate each included file
		for include_path in includes {
			let resolved_path = self.resolve_path(&include_path)?;
			let include_content = self.load_file(&resolved_path).await?;
			let include_toml: toml::Value = toml::from_str(&include_content)?;

			// Validate no duplicate sections
			if let Some(include_table) = include_toml.as_table() {
				for key in include_table.keys() {
					if let Some(existing_source) = self.section_sources.get(key) {
						return Err(ConfigError::Validation(format!(
							"Duplicate section '{}' found in {} and {}. \
							Each top-level section must be unique across all configuration files.",
							key,
							existing_source.display(),
							resolved_path.display()
						)));
					}
					self.section_sources
						.insert(key.clone(), resolved_path.clone());
				}

				// Merge the tables
				if let Some(main_table) = main_toml.as_table_mut() {
					for (key, value) in include_table {
						main_table.insert(key.clone(), value.clone());
					}
				}
			}
		}

		Ok(main_toml)
	}

	/// Resolves a path relative to the base path.
	fn resolve_path(&self, path: impl AsRef<Path>) -> Result<PathBuf, ConfigError> {
		let path = path.as_ref();

		let resolved = if path.is_absolute() {
			path.to_path_buf()
		} else {
			self.base_path.join(path)
		};

		// Verify the file exists
		if !resolved.exists() {
			return Err(ConfigError::Io(std::io::Error::new(
				std::io::ErrorKind::NotFound,
				format!("Configuration file not found: {}", resolved.display()),
			)));
		}

		Ok(resolved)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs;
	use tempfile::TempDir;

	#[tokio::test]
	async fn test_single_file_config() {
		let temp_dir = TempDir::new().unwrap();
		let config_path = temp_dir.path().join("config.toml");

		let config_content = r#"
[solver]
id = "test-solver"
monitoring_timeout_minutes = 5
min_profitability_pct = 1.0

[networks.1]
input_settler_address = "0x1234567890123456789012345678901234567890"
output_settler_address = "0x0987654321098765432109876543210987654321"
[[networks.1.rpc_urls]]
http = "http://localhost:8545"
[[networks.1.tokens]]
address = "0xabcdef1234567890abcdef1234567890abcdef12"
symbol = "TEST"
decimals = 18

[networks.2]
input_settler_address = "0x1234567890123456789012345678901234567890"
output_settler_address = "0x0987654321098765432109876543210987654321"
[[networks.2.rpc_urls]]
http = "http://localhost:8546"
[[networks.2.tokens]]
address = "0xabcdef1234567890abcdef1234567890abcdef12"
symbol = "TEST"
decimals = 18

[storage]
primary = "memory"
cleanup_interval_seconds = 3600
[storage.implementations.memory]

[delivery]
[delivery.implementations.test]

[account]
primary = "local"
[account.implementations.local]
private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

[discovery]
[discovery.implementations.test]

[order]
[order.implementations.test]
[order.strategy]
primary = "simple"
[order.strategy.implementations.simple]

[settlement]
[settlement.implementations.test]
order = "test"
network_ids = [1, 2]
"#;

		fs::write(&config_path, config_content).unwrap();

		let mut loader = ConfigLoader::new(temp_dir.path());
		let config = loader.load_config(&config_path).await.unwrap();

		assert_eq!(config.solver.id, "test-solver");
	}

	#[tokio::test]
	async fn test_config_with_includes() {
		let temp_dir = TempDir::new().unwrap();

		// Main config
		let main_config = r#"
include = ["networks.toml", "storage.toml"]
[solver]
id = "test-solver"
monitoring_timeout_minutes = 5
min_profitability_pct = 1.0
"#;

		// Networks config
		let networks_config = r#"
[networks.1]
input_settler_address = "0x1234567890123456789012345678901234567890"
output_settler_address = "0x0987654321098765432109876543210987654321"
[[networks.1.rpc_urls]]
http = "http://localhost:8545"
[[networks.1.tokens]]
address = "0xabcdef1234567890abcdef1234567890abcdef12"
symbol = "TEST"
decimals = 18

[networks.2]
input_settler_address = "0x1234567890123456789012345678901234567890"
output_settler_address = "0x0987654321098765432109876543210987654321"
[[networks.2.rpc_urls]]
http = "http://localhost:8546"
[[networks.2.tokens]]
address = "0xabcdef1234567890abcdef1234567890abcdef12"
symbol = "TEST"
decimals = 18
"#;

		// Storage config
		let storage_config = r#"
[storage]
primary = "memory"
cleanup_interval_seconds = 3600
[storage.implementations.memory]

[delivery]
[delivery.implementations.test]

[account]
primary = "local"
[account.implementations.local]
private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

[discovery]
[discovery.implementations.test]

[order]
[order.implementations.test]
[order.strategy]
primary = "simple"
[order.strategy.implementations.simple]

[settlement]
[settlement.implementations.test]
order = "test"
network_ids = [1, 2]
"#;

		fs::write(temp_dir.path().join("main.toml"), main_config).unwrap();
		fs::write(temp_dir.path().join("networks.toml"), networks_config).unwrap();
		fs::write(temp_dir.path().join("storage.toml"), storage_config).unwrap();

		let mut loader = ConfigLoader::new(temp_dir.path());
		let config = loader.load_config("main.toml").await.unwrap();

		assert_eq!(config.solver.id, "test-solver");
		assert_eq!(config.storage.primary, "memory");
	}

	#[tokio::test]
	async fn test_duplicate_section_error() {
		let temp_dir = TempDir::new().unwrap();

		// Main config with solver section
		let main_config = r#"
include = ["duplicate.toml"]

[solver]
id = "test-solver"
"#;

		// Include with duplicate solver section (should cause error)
		let duplicate_config = r#"
[solver]
id = "another-solver"
"#;

		fs::write(temp_dir.path().join("main.toml"), main_config).unwrap();
		fs::write(temp_dir.path().join("duplicate.toml"), duplicate_config).unwrap();

		let mut loader = ConfigLoader::new(temp_dir.path());
		let result = loader.load_config("main.toml").await;

		assert!(result.is_err());
		let error_msg = result.unwrap_err().to_string();
		assert!(error_msg.contains("Duplicate section 'solver'"));
	}

	#[tokio::test]
	async fn test_self_include_detection() {
		let temp_dir = TempDir::new().unwrap();

		// Create a config that includes itself
		let config = r#"
include = ["self.toml"]

[solver]
id = "test-solver"
"#;

		fs::write(temp_dir.path().join("self.toml"), config).unwrap();

		let mut loader = ConfigLoader::new(temp_dir.path());
		let result = loader.load_config("self.toml").await;

		assert!(result.is_err());
		let error_msg = result.unwrap_err().to_string();
		assert!(error_msg.contains("already loaded"));
	}
}
