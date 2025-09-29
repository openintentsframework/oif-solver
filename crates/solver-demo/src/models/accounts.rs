use alloy_primitives::Address;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountsConfig {
    pub user: AccountEntry,
    pub recipient: AccountEntry,
    pub solver: SolverAccountEntry,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountEntry {
    pub address: Address,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolverAccountEntry {
    pub address: Address,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AccountInfo {
    pub address: Address,
    pub private_key: Option<String>,
    pub label: String,
}

impl Default for AccountsConfig {
    fn default() -> Self {
        let user = AccountEntry {
            address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
                .parse()
                .expect("Valid address"),
            private_key: Some(
                "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d".to_string(),
            ),
        };

        let recipient = AccountEntry {
            address: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
                .parse()
                .expect("Valid address"),
            private_key: None,
        };

        let solver = SolverAccountEntry {
            address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
                .parse()
                .expect("Valid address"),
            private_key: None,
            note: Some("Solver key is read from solver config, not stored here".to_string()),
        };

        Self {
            user,
            recipient,
            solver,
        }
    }
}

impl AccountEntry {
    pub fn new(address: Address, private_key: Option<String>) -> Self {
        Self {
            address,
            private_key,
        }
    }
}

impl SolverAccountEntry {
    pub fn new(address: Address, note: Option<String>) -> Self {
        Self { 
            address, 
            private_key: None,
            note 
        }
    }
}