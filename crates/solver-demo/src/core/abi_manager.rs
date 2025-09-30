//! Application Binary Interface (ABI) management module for smart contract interactions.
//!
//! This module provides comprehensive ABI and contract artifact management capabilities for
//! the OIF Solver demonstration system. It handles loading, parsing, caching, and validation
//! of smart contract ABIs from various sources including Foundry build outputs and custom
//! artifact files. The AbiManager ensures that all contract interactions use correct interface
//! definitions while providing efficient caching to minimize file system operations.
//!
//! The module supports both Foundry-style compilation artifacts (in "out" directories) and
//! custom artifact formats, enabling flexibility in how contract information is stored and
//! accessed throughout the solver system.

use anyhow::{anyhow, Result};
use ethers::abi::Abi;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;

use crate::models::ContractArtifact;

/// Manager for contract Application Binary Interfaces and compilation artifacts.
///
/// The AbiManager provides centralized management of smart contract ABIs and bytecode,
/// supporting both Foundry-generated artifacts and custom artifact formats. It maintains
/// an in-memory cache of loaded artifacts to optimize performance and provides thread-safe
/// access through Arc and RwLock primitives. The manager automatically handles different
/// artifact directory structures and formats, ensuring compatibility with various
/// compilation toolchains.
pub struct AbiManager {
	/// Path to the directory containing contract artifacts.
	///
	/// This directory may contain either Foundry-style "out" structures with
	/// subdirectories for each contract, or flat artifact files with JSON
	/// contract definitions.
	contracts_dir: PathBuf,

	/// Thread-safe cache of loaded contract artifacts.
	///
	/// Maps contract names to their complete artifact information including
	/// ABI definitions and bytecode. Protected by RwLock to allow concurrent
	/// reads while ensuring exclusive writes during cache updates.
	cache: Arc<RwLock<HashMap<String, ContractArtifact>>>,
}

impl AbiManager {
	/// Creates a new AbiManager with the specified contracts directory.
	///
	/// Initializes the manager with the provided directory path and ensures
	/// the directory exists. If the directory doesn't exist, it will be
	/// created automatically to support dynamic artifact storage.
	pub fn new(contracts_dir: PathBuf) -> Result<Self> {
		if !contracts_dir.exists() {
			std::fs::create_dir_all(&contracts_dir)?;
		}

		Ok(Self {
			contracts_dir,
			cache: Arc::new(RwLock::new(HashMap::new())),
		})
	}

	/// Loads all contract artifacts from the configured directory.
	///
	/// Scans the contracts directory for artifact files and loads them into
	/// the internal cache. Supports both Foundry-style "out" directory structures
	/// (with contract subdirectories containing JSON files) and flat directory
	/// structures with direct JSON artifact files. Only contracts with valid
	/// deployable bytecode are loaded to ensure successful deployment operations.
	pub async fn load_all(&self) -> Result<()> {
		debug!("Loading contract artifacts from {:?}", self.contracts_dir);

		let mut cache = self.cache.write().await;

		if self.contracts_dir.ends_with("out") {
			let entries = std::fs::read_dir(&self.contracts_dir)?;

			for entry in entries {
				let entry = entry?;
				let path = entry.path();

				if path.is_dir() {
					let sol_entries = std::fs::read_dir(&path)?;

					for sol_entry in sol_entries {
						let sol_entry = sol_entry?;
						let json_path = sol_entry.path();

						if json_path.extension().and_then(|s| s.to_str()) == Some("json") {
							let name = json_path
								.file_stem()
								.and_then(|s| s.to_str())
								.ok_or_else(|| anyhow!("Invalid file name"))?
								.to_string();

							debug!("Loading Foundry artifact: {}", name);

							let contents = tokio::fs::read_to_string(&json_path).await?;

							let json_value: serde_json::Value = serde_json::from_str(&contents)?;

							let abi = json_value["abi"].clone();

							let bytecode = if let Some(bytecode_obj) = json_value.get("bytecode") {
								if let Some(object) = bytecode_obj.get("object") {
									object.as_str().unwrap_or("").to_string()
								} else {
									String::new()
								}
							} else {
								String::new()
							};

							if bytecode.is_empty() || bytecode == "0x" {
								debug!("Skipping {} - no deployable bytecode", name);
								continue;
							}

							let artifact = ContractArtifact {
								abi,
								bytecode,
								name: name.clone(),
							};

							cache.insert(name.clone(), artifact);
							debug!("Loaded contract: {}", name);
						}
					}
				}
			}
		} else {
			let entries = std::fs::read_dir(&self.contracts_dir)?;

			for entry in entries {
				let entry = entry?;
				let path = entry.path();

				if path.extension().and_then(|s| s.to_str()) == Some("json") {
					let name = path
						.file_stem()
						.and_then(|s| s.to_str())
						.ok_or_else(|| anyhow!("Invalid file name"))?
						.to_string();

					debug!("Loading contract artifact: {}", name);

					let contents = tokio::fs::read_to_string(&path).await?;
					let artifact: ContractArtifact = serde_json::from_str(&contents)?;

					cache.insert(name.clone(), artifact);
					debug!("Loaded contract: {}", name);
				}
			}
		}

		debug!("Loaded {} contract artifacts", cache.len());
		Ok(())
	}

	/// Retrieves a complete contract artifact by name.
	///
	/// Returns the full ContractArtifact structure containing ABI, bytecode,
	/// and metadata for the specified contract. The artifact is retrieved
	/// from the in-memory cache for optimal performance.
	pub async fn get_artifact(&self, name: &str) -> Result<ContractArtifact> {
		let cache = self.cache.read().await;
		cache
			.get(name)
			.cloned()
			.ok_or_else(|| anyhow!("Contract artifact '{}' not found", name))
	}

	/// Retrieves the parsed ABI for a specific contract.
	///
	/// Returns the contract's Application Binary Interface as a parsed Abi
	/// structure, ready for use in contract interactions. The ABI is parsed
	/// from the JSON representation stored in the artifact.
	pub async fn get_abi(&self, name: &str) -> Result<Abi> {
		let artifact = self.get_artifact(name).await?;
		let abi: Abi = serde_json::from_value(artifact.abi)?;
		Ok(abi)
	}

	/// Retrieves the compiled bytecode for a specific contract.
	///
	/// Returns the contract's deployment bytecode as a byte vector, ready
	/// for deployment transactions. The method handles hex decoding and
	/// validates that deployable bytecode is available for the contract.
	pub async fn get_bytecode(&self, name: &str) -> Result<Vec<u8>> {
		let artifact = self.get_artifact(name).await?;

		if artifact.bytecode.is_empty() {
			return Err(anyhow!("No bytecode found for contract {}", name));
		}

		debug!(
			"Bytecode for {} starts with: {}",
			name,
			&artifact.bytecode[..20.min(artifact.bytecode.len())]
		);

		let bytecode_str = if artifact.bytecode.starts_with("0x") {
			&artifact.bytecode[2..]
		} else {
			&artifact.bytecode
		};

		hex::decode(bytecode_str)
			.map_err(|e| anyhow!("Failed to decode bytecode for {}: {}", name, e))
	}

	/// Lists all available contract names in the cache.
	///
	/// Returns a vector of contract names that have been successfully
	/// loaded and are available for retrieval. Useful for discovery
	/// and validation of available contracts.
	pub async fn list_contracts(&self) -> Vec<String> {
		let cache = self.cache.read().await;
		cache.keys().cloned().collect()
	}

	/// Adds a new contract artifact to the manager.
	///
	/// Stores the provided artifact both in the in-memory cache and
	/// persists it to disk as a JSON file. This enables dynamic addition
	/// of contracts during runtime, such as when deploying new contracts
	/// or loading artifacts from external sources.
	pub async fn add_artifact(&self, name: String, artifact: ContractArtifact) -> Result<()> {
		let mut cache = self.cache.write().await;

		let file_path = self.contracts_dir.join(format!("{}.json", name));
		let contents = serde_json::to_string_pretty(&artifact)?;
		tokio::fs::write(&file_path, contents).await?;

		cache.insert(name, artifact);
		Ok(())
	}

	/// Loads a specific contract artifact from disk into the cache.
	///
	/// Reads the specified contract artifact file from the contracts
	/// directory and adds it to the in-memory cache. Useful for loading
	/// individual contracts on-demand rather than loading all artifacts
	/// at startup.
	pub async fn load_artifact(&self, name: &str) -> Result<()> {
		let file_path = self.contracts_dir.join(format!("{}.json", name));

		if !file_path.exists() {
			return Err(anyhow!("Contract file not found: {:?}", file_path));
		}

		let contents = tokio::fs::read_to_string(&file_path).await?;
		let artifact: ContractArtifact = serde_json::from_str(&contents)?;

		let mut cache = self.cache.write().await;
		cache.insert(name.to_string(), artifact);

		Ok(())
	}

	/// Checks if a contract is available in the cache.
	///
	/// Returns true if the specified contract name exists in the
	/// loaded artifact cache, false otherwise. Provides a quick
	/// way to verify contract availability before attempting retrieval.
	pub async fn has_contract(&self, name: &str) -> bool {
		let cache = self.cache.read().await;
		cache.contains_key(name)
	}

	/// Clears all cached contract artifacts from memory.
	///
	/// Removes all loaded artifacts from the in-memory cache, forcing
	/// subsequent requests to reload from disk. Useful for refreshing
	/// the cache when artifacts have been updated externally.
	pub async fn clear_cache(&self) {
		let mut cache = self.cache.write().await;
		cache.clear();
	}
}
