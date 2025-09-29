use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::sync::RwLock;

/// Tracks indices for different types of API requests to ensure sequential naming
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IndexState {
	/// Map of endpoint type to current index
	indices: HashMap<String, u64>,
}

pub struct FileIndexer {
	state: RwLock<IndexState>,
	index_file: PathBuf,
}

impl FileIndexer {
	/// Create a new file indexer with persistent state
	pub async fn new(data_dir: &Path) -> Result<Self> {
		let index_file = data_dir.join(".api_indices.json");

		// Load existing state or create new
		let state = if index_file.exists() {
			let content = fs::read_to_string(&index_file).await?;
			serde_json::from_str(&content).unwrap_or_default()
		} else {
			IndexState::default()
		};

		Ok(Self {
			state: RwLock::new(state),
			index_file,
		})
	}

	/// Get the next index for a given endpoint and increment it
	pub async fn next_index(&self, endpoint: &str) -> Result<u64> {
		let mut state = self.state.write().await;
		let index = state.indices.entry(endpoint.to_string()).or_insert(0);
		*index += 1;
		let current = *index;

		// Save state
		let json = serde_json::to_string_pretty(&*state)?;
		fs::write(&self.index_file, json).await?;

		Ok(current)
	}

	/// Get current index without incrementing
	pub async fn current_index(&self, endpoint: &str) -> u64 {
		let state = self.state.read().await;
		state.indices.get(endpoint).copied().unwrap_or(0)
	}

	/// Generate a filename for a request
	pub async fn generate_request_filename(&self, endpoint: &str) -> Result<String> {
		let index = self.next_index(endpoint).await?;
		Ok(format!("{}.{}.req.json", index, endpoint))
	}

	/// Generate a filename for a response (uses same index as request)
	pub fn generate_response_filename(index: u64, endpoint: &str) -> String {
		format!("{}.{}.res.json", index, endpoint)
	}
}

/// Helper to determine endpoint name from operation
pub fn endpoint_from_operation(operation: &str) -> &str {
	match operation {
		"quote" | "get_quote" => "get_quote",
		"order" | "post_order" | "accept" => "post_order",
		"status" | "get_order" => "get_order",
		_ => operation,
	}
}
