//! Error types and result handling for the solver demo
//!
//! This module defines the comprehensive error handling system used throughout
//! the solver demo application. It includes domain-specific error variants
//! for different subsystems and conversions from external error types.

use alloy_primitives::B256;
use std::path::PathBuf;

/// Convenience Result type alias using the local Error type
pub type Result<T> = std::result::Result<T, Error>;

/// Comprehensive error type for all solver demo operations
///
/// This enum covers error cases across all subsystems including chain operations,
/// configuration management, API interactions, storage, token handling, session
/// management, contract operations, signing, environment setup, and validation.
#[derive(thiserror::Error, Debug)]
pub enum Error {
	// Chain errors
	#[error("Chain not found: {0}")]
	ChainNotFound(crate::types::chain::ChainId),

	#[error("Invalid chain ID: {0}")]
	InvalidChain(u64),

	#[error("RPC connection failed: {0}")]
	RpcError(String),

	#[error("Transaction not found: {0:?}")]
	TxNotFound(B256),

	// Config errors
	#[error("Configuration file not found: {0}")]
	ConfigNotFound(PathBuf),

	#[error("Invalid configuration format: {0}")]
	InvalidConfig(String),

	#[error("Missing required field: {0}")]
	MissingField(String),

	#[error("Configuration already exists at: {0}")]
	ConfigExists(PathBuf),

	// API errors
	#[error("API request failed: {0}")]
	ApiRequestFailed(String),

	#[error("Authentication failed")]
	AuthFailed,

	#[error("Invalid API response: {0}")]
	InvalidApiResponse(String),

	// Storage errors
	#[error("Storage error: {0}")]
	StorageError(String),

	#[error("Failed to create directory: {0}")]
	DirectoryCreationFailed(PathBuf),

	// Token errors
	#[error("Token not found: {0} on chain {1}")]
	TokenNotFound(String, u64),

	#[error("Invalid token address: {0}")]
	InvalidTokenAddress(String),

	// Session errors
	#[error("Session not initialized")]
	SessionNotInitialized,

	#[error("Invalid environment for operation")]
	InvalidEnvironment,

	// Contract errors
	#[error("Contract not deployed on chain {0}")]
	ContractNotDeployed(u64),

	#[error("Invalid ABI: {0}")]
	InvalidAbi(String),

	#[error("Contract call failed: {0}")]
	ContractCallFailed(String),

	// Signing errors
	#[error("Invalid private key")]
	InvalidPrivateKey,

	#[error("Signing failed: {0}")]
	SigningFailed(String),

	// Environment errors
	#[error("Anvil not running on chain {0}")]
	AnvilNotRunning(u64),

	#[error("Failed to start Anvil: {0}")]
	AnvilStartFailed(String),

	#[error("Deployment failed: {0}")]
	DeploymentFailed(String),

	#[error("Command failed: {0}")]
	CommandFailed(String),

	#[error("Chain already running: {0}")]
	ChainAlreadyRunning(crate::types::chain::ChainId),

	#[error("Not a local chain: {0}")]
	NotLocalChain(crate::types::chain::ChainId),

	#[error("Chain not ready: {0}")]
	ChainNotReady(crate::types::chain::ChainId),

	#[error("Not in local mode")]
	NotLocalMode,

	// Validation errors
	#[error("Invalid hex string: {0}")]
	InvalidHex(String),

	#[error("Invalid address: {0}")]
	InvalidAddress(String),

	#[error("Invalid amount: {0}")]
	InvalidAmount(String),

	// IO errors
	#[error("IO error: {0}")]
	Io(#[from] std::io::Error),

	// JSON errors
	#[error("JSON error: {0}")]
	Json(#[from] serde_json::Error),

	// TOML errors
	#[error("TOML error: {0}")]
	Toml(#[from] toml::de::Error),

	// HTTP errors
	#[error("HTTP error: {0}")]
	Http(#[from] reqwest::Error),

	// Generic error for unexpected cases
	#[error(transparent)]
	Other(#[from] anyhow::Error),
}

// Convenience conversions
impl From<String> for Error {
	fn from(msg: String) -> Self {
		Error::Other(anyhow::anyhow!("{msg}"))
	}
}

impl From<&'static str> for Error {
	fn from(msg: &'static str) -> Self {
		Error::Other(anyhow::anyhow!("{msg}"))
	}
}

impl From<solver_config::ConfigError> for Error {
	fn from(err: solver_config::ConfigError) -> Self {
		Error::InvalidConfig(err.to_string())
	}
}
