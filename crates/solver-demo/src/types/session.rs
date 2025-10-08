//! Session management and persistent state types
//!
//! This module defines data structures for maintaining state across command
//! invocations, including configuration paths, deployed contracts, JWT tokens,
//! and environment settings. Sessions provide persistence for the CLI workflow.

use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf};

use super::chain::ChainId;

/// Persistent session state maintained across CLI command invocations
///
/// Contains configuration paths, environment settings, deployed contract
/// addresses, JWT tokens, and other state that needs to persist between
/// separate command executions in the solver demo workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
	pub config_path: PathBuf,
	pub config_sections: HashMap<String, PathBuf>, // Mapping of section names to their file paths
	pub placeholder_map: HashMap<String, String>, // Mapping of placeholder keys to placeholder addresses
	pub environment: Environment,
	pub chains: Vec<ChainId>,
	pub jwt_tokens: HashMap<String, JwtToken>,
	pub deployed_contracts: HashMap<String, ContractSet>, // Use String keys instead of ChainId
}

impl Session {
	pub fn new(
		config_path: PathBuf,
		config_sections: HashMap<String, PathBuf>,
		placeholder_map: HashMap<String, String>,
		environment: Environment,
	) -> Self {
		Self {
			config_path,
			config_sections,
			placeholder_map,
			environment,
			chains: Vec::new(),
			jwt_tokens: HashMap::new(),
			deployed_contracts: HashMap::new(),
		}
	}
}

/// Runtime environment configuration for the solver demo
///
/// Determines whether the application runs in local development mode
/// with Anvil chains or production mode with live networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Environment {
	Local,
	Production,
}

impl Environment {
	pub fn is_local(&self) -> bool {
		matches!(self, Self::Local)
	}

	pub fn is_production(&self) -> bool {
		matches!(self, Self::Production)
	}
}

/// JWT authentication token with expiration tracking
///
/// Stores a JWT token string along with its expiration timestamp
/// for API authentication with the solver service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtToken {
	pub token: String,
	pub expires_at: i64,
}

impl JwtToken {
	pub fn new(token: String, expires_at: i64) -> Self {
		Self { token, expires_at }
	}

	pub fn is_expired(&self) -> bool {
		let now = chrono::Utc::now().timestamp();
		now >= self.expires_at
	}
}

/// Token metadata stored in session for persistence
///
/// Contains essential token information including address and decimal
/// places for tokens used across different chains in the session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTokenInfo {
	pub address: String,
	pub decimals: u8,
}

/// Collection of deployed contract addresses for a specific chain
///
/// Stores addresses for all deployed solver contracts including settlers,
/// oracles, allocators, and tokens. Used for session persistence.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContractSet {
	pub input_settler: Option<String>,
	pub input_settler_compact: Option<String>,
	pub output_settler: Option<String>,
	pub permit2: Option<String>,
	pub compact: Option<String>,
	pub allocator: Option<String>,
	pub input_oracle: Option<String>,
	pub output_oracle: Option<String>,
	pub tokens: HashMap<String, SessionTokenInfo>, // symbol -> TokenInfo with decimals
}

impl ContractSet {
	/// Get all contract addresses as a vector (excluding permit2 which is always canonical)
	pub fn all_addresses(&self) -> Vec<&str> {
		let mut addresses = Vec::new();

		// Add contract addresses (excluding permit2 since it's always canonical)
		if let Some(addr) = &self.input_settler {
			addresses.push(addr.as_str());
		}
		if let Some(addr) = &self.input_settler_compact {
			addresses.push(addr.as_str());
		}
		if let Some(addr) = &self.output_settler {
			addresses.push(addr.as_str());
		}
		// Skip permit2 - it's always the canonical address, not a placeholder
		if let Some(addr) = &self.compact {
			addresses.push(addr.as_str());
		}
		if let Some(addr) = &self.allocator {
			addresses.push(addr.as_str());
		}
		if let Some(addr) = &self.input_oracle {
			addresses.push(addr.as_str());
		}
		if let Some(addr) = &self.output_oracle {
			addresses.push(addr.as_str());
		}

		// Add token addresses
		for token in self.tokens.values() {
			addresses.push(&token.address);
		}

		addresses
	}
}

/// Runtime contract addresses for a specific blockchain
///
/// Contains parsed Address instances for deployed contracts on a chain.
/// Converted from ContractSet for use in blockchain operations.
#[derive(Debug, Clone)]
pub struct ContractAddresses {
	pub chain: ChainId,
	pub permit2: Option<Address>,
	pub input_settler: Option<Address>,
	pub input_settler_compact: Option<Address>,
	pub output_settler: Option<Address>,
	pub the_compact: Option<Address>,
	pub allocator: Option<Address>,
	pub input_oracle: Option<Address>,
	pub output_oracle: Option<Address>,
	pub tokens: HashMap<String, (Address, u8)>, // symbol -> (address, decimals)
}
