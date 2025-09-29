use alloy_primitives::Address;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractArtifact {
	pub abi: serde_json::Value,
	pub bytecode: String,
	pub name: String,
}

#[derive(Debug, Clone)]
pub struct DeploymentResult {
	pub address: Address,
	pub tx_hash: String,
	pub gas_used: Option<u64>,
}
