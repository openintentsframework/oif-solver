use crate::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Oracle information combining chain and address
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleInfo {
	pub chain_id: u64,
	pub oracle: Address,
}

/// Simple oracle route validation data
#[derive(Debug, Clone)]
pub struct OracleRoutes {
	/// Valid routes: input oracle info -> [output oracle infos]
	pub supported_routes: HashMap<OracleInfo, Vec<OracleInfo>>,
}

/// Transaction types for oracle operations
pub enum SettlementTransaction {
	PostFill {
		order_id: String,
		fill_proof: crate::FillProof,
		settlement_type: String,
	},
	PreClaim {
		order_id: String,
		attestation: Vec<u8>,
		settlement_type: String,
	},
}
