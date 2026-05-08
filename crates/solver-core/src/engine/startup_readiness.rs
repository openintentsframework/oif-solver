//! Public-facing startup readiness state.
//!
//! Exposed via the health endpoint so operators and frontends can detect
//! "process is up but waiting on signer funding" without inferring it from
//! downstream order failures.

use serde::Serialize;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Snapshot of whether the solver completed its startup approval pass.
///
/// `approvals_ready == true` is the steady state. When the signer lacks
/// native gas at startup, the builder records a non-ready state with the
/// list of blocked signers so a frontend can surface a "fund this address"
/// prompt without parsing log lines.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StartupReadiness {
	pub approvals_ready: bool,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub reason: Option<String>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub blocked_signers: Vec<BlockedSigner>,
}

/// Per-signer reason a startup approval could not run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlockedSigner {
	pub chain_id: u64,
	pub signer: String,
	pub balance_wei: String,
}

impl StartupReadiness {
	pub fn ready() -> Self {
		Self {
			approvals_ready: true,
			reason: None,
			blocked_signers: Vec::new(),
		}
	}

	pub fn waiting_for_native_gas(blocked_signers: Vec<BlockedSigner>) -> Self {
		Self {
			approvals_ready: false,
			reason: Some("waiting_for_native_gas".to_string()),
			blocked_signers,
		}
	}
}

/// Shared handle to the startup readiness state. The engine owns one of
/// these; the builder hands a clone to its retry task so updates flow back
/// to the health endpoint.
pub type SharedStartupReadiness = Arc<RwLock<StartupReadiness>>;

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn ready_serializes_with_minimal_fields() {
		let json = serde_json::to_string(&StartupReadiness::ready()).unwrap();

		assert!(json.contains("\"approvals_ready\":true"));
		assert!(!json.contains("reason"));
		assert!(!json.contains("blocked_signers"));
	}

	#[test]
	fn waiting_for_native_gas_serializes_with_blocked_signer_details() {
		let status = StartupReadiness::waiting_for_native_gas(vec![BlockedSigner {
			chain_id: 8453,
			signer: "0xsolver".to_string(),
			balance_wei: "1000000000000".to_string(),
		}]);

		let json = serde_json::to_string(&status).unwrap();

		assert!(json.contains("\"approvals_ready\":false"));
		assert!(json.contains("\"reason\":\"waiting_for_native_gas\""));
		assert!(json.contains("\"chain_id\":8453"));
		assert!(json.contains("\"signer\":\"0xsolver\""));
		assert!(json.contains("\"balance_wei\":\"1000000000000\""));
	}

	#[test]
	fn waiting_for_native_gas_omits_required_and_shortfall() {
		let status = StartupReadiness::waiting_for_native_gas(vec![BlockedSigner {
			chain_id: 1,
			signer: "0xsolver".to_string(),
			balance_wei: "0".to_string(),
		}]);

		let json = serde_json::to_string(&status).unwrap();

		assert!(!json.contains("required_wei"));
		assert!(!json.contains("shortfall_wei"));
	}
}
