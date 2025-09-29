use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use super::accounts::AccountsConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    pub session: SessionData,
    pub defaults: DefaultSettings,
    pub accounts: AccountsConfig,
    #[serde(rename = "auth_tokens")]
    pub tokens: HashMap<String, JwtTokenEntry>,
    #[serde(skip)]
    pub networks_config: HashMap<u64, NetworkConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    pub active_config: Option<PathBuf>,
    pub environment_type: Environment,
    pub chain_ids: Vec<u64>,
    pub rpc_urls: HashMap<u64, String>,
    pub contract_addresses: HashMap<u64, ContractAddresses>,
    pub includes: IncludeFiles,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Local,
    Production,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultSettings {
    pub swap_type: SwapType,
    pub settler_type: SettlerType,
    pub auth_type: AuthType,
    pub output_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SwapType {
    ExactInput,
    ExactOutput,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SettlerType {
    Escrow,
    Compact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    Permit2,
    Eip3009,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IncludeFiles {
    #[serde(flatten)]
    pub files: HashMap<String, PathBuf>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub section_sources: HashMap<String, PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtTokenEntry {
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenInfo {
    pub address: String,
    pub decimals: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContractAddresses {
    pub input_settler: Option<String>,
    pub output_settler: Option<String>,
    pub permit2: Option<String>,
    pub tokens: HashMap<String, TokenInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allocator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oracle: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub chain_id: u64,
    pub name: String,
    pub rpc_url: String,
    pub explorer_url: Option<String>,
    pub contracts: ContractAddresses,
}

impl JwtTokenEntry {
    pub fn new(token: String, expires_at: DateTime<Utc>) -> Self {
        Self { token, expires_at }
    }
    
    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            session: SessionData {
                active_config: None,
                environment_type: Environment::Production,
                chain_ids: vec![],
                rpc_urls: HashMap::new(),
                contract_addresses: HashMap::new(),
                includes: IncludeFiles::default(),
                last_updated: Utc::now(),
            },
            defaults: DefaultSettings {
                swap_type: SwapType::ExactInput,
                settler_type: SettlerType::Escrow,
                auth_type: AuthType::Permit2,
                output_dir: PathBuf::from("./.oif-demo"),
            },
            accounts: AccountsConfig::default(),
            tokens: HashMap::new(),
            networks_config: HashMap::new(),
        }
    }
}

impl IncludeFiles {
    pub fn get(&self, key: &str) -> Option<&PathBuf> {
        self.files.get(key)
    }

    pub fn networks(&self) -> Option<&PathBuf> {
        self.section_sources.get("networks")
    }

    pub fn api(&self) -> Option<&PathBuf> {
        self.section_sources.get("api")
    }

  
    pub fn gas(&self) -> Option<&PathBuf> {
        self.section_sources.get("gas")
    }

    pub fn get_all_files(&self) -> &HashMap<String, PathBuf> {
        &self.files
    }

    pub fn get_section_sources(&self) -> &HashMap<String, PathBuf> {
        &self.section_sources
    }

    pub fn find_section_source(&self, section: &str) -> Option<&PathBuf> {
        self.section_sources.get(section)
    }
}