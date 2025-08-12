//! Custody Strategy Decision Logic
//!
//! This module implements the core logic for deciding between different custody
//! strategies based on the ERC-7683 standard and available input locks.

use alloy_primitives::Address;
use solver_types::{AvailableInput, LockKind as ApiLockKind, QuoteError};
use std::collections::HashMap;

/// Types of resource locks supported
#[derive(Debug, Clone)]
pub enum LockKind {
	/// The Compact protocol lock
	TheCompact { params: serde_json::Value },
}

/// Types of escrow mechanisms
#[derive(Debug, Clone)]
pub enum EscrowKind {
	/// Permit2 SignatureTransfer (works with any ERC-20)
	Permit2,
	/// ERC-3009 native token authorization (USDC-style)
	Erc3009,
}

/// Custody strategy decision
#[derive(Debug, Clone)]
pub enum CustodyDecision {
	/// Use resource lock - funds stay with user but locked
	ResourceLock { kind: LockKind },
	/// Use escrow - funds transferred to settlement contract
	Escrow { kind: EscrowKind },
}

/// Token capabilities for settlement decisions
#[derive(Debug, Clone)]
pub struct TokenCapabilities {
	pub supports_erc3009: bool,
	pub permit2_available: bool,
}

/// Custody strategy decision engine
pub struct CustodyStrategy {
	/// Permit2 contract addresses per chain
	permit2_addresses: HashMap<u64, Address>,
	/// Token capabilities cache
	token_capabilities: HashMap<String, TokenCapabilities>,
}

impl CustodyStrategy {
	/// Create new custody strategy engine
	pub fn new() -> Self {
		Self {
			permit2_addresses: Self::default_permit2_addresses(),
			token_capabilities: HashMap::new(),
		}
	}

	/// Decide custody strategy for a given input
	pub async fn decide_custody(
		&self,
		input: &AvailableInput,
	) -> Result<CustodyDecision, QuoteError> {
		// Step 1: Check if input has a lock (resource lock path)
		if let Some(lock) = &input.lock {
			return self.handle_resource_lock(lock);
		}

		// Step 2: No lock present - use escrow path
		self.decide_escrow_strategy(input).await
	}

	/// Handle resource lock cases
	fn handle_resource_lock(
		&self,
		lock: &solver_types::Lock,
	) -> Result<CustodyDecision, QuoteError> {
		// Map the API lock kind to our internal lock kind
		let lock_kind = match lock.kind {
			ApiLockKind::TheCompact => LockKind::TheCompact {
				params: lock.params.clone().unwrap_or_default(),
			},
		};

		Ok(CustodyDecision::ResourceLock { kind: lock_kind })
	}

	/// Decide between Permit2 and ERC-3009 for escrow
	async fn decide_escrow_strategy(
		&self,
		input: &AvailableInput,
	) -> Result<CustodyDecision, QuoteError> {
		let chain_id = input.asset.ethereum_chain_id().map_err(|e| {
			QuoteError::InvalidRequest(format!("Invalid chain ID in asset address: {}", e))
		})?;
		let token_address = input
			.asset
			.ethereum_address()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid Ethereum address: {}", e)))?;

		// Check token capabilities
		let capabilities = self.get_token_capabilities(chain_id, token_address).await?;

		// Prefer ERC-3009 if supported, fallback to Permit2
		if capabilities.supports_erc3009 {
			Ok(CustodyDecision::Escrow {
				kind: EscrowKind::Erc3009,
			})
		} else if capabilities.permit2_available {
			Ok(CustodyDecision::Escrow {
				kind: EscrowKind::Permit2,
			})
		} else {
			Err(QuoteError::UnsupportedSettlement(
				"No supported settlement mechanism available for this token".to_string(),
			))
		}
	}

	/// Get token capabilities (with caching)
	async fn get_token_capabilities(
		&self,
		chain_id: u64,
		token_address: Address,
	) -> Result<TokenCapabilities, QuoteError> {
		let cache_key = format!("{}:{:?}", chain_id, token_address);

		if let Some(capabilities) = self.token_capabilities.get(&cache_key) {
			return Ok(capabilities.clone());
		}

		// Detect capabilities
		let capabilities = self
			.detect_token_capabilities(chain_id, token_address)
			.await?;

		// Cache for future use
		// Note: In a real implementation, you'd want a proper cache with TTL
		// self.token_capabilities.insert(cache_key, capabilities.clone());

		Ok(capabilities)
	}

	/// Detect token capabilities on-chain
	async fn detect_token_capabilities(
		&self,
		chain_id: u64,
		_token_address: Address,
	) -> Result<TokenCapabilities, QuoteError> {
		// TODO: Implement actual on-chain detection
		// For now, return conservative defaults

		let permit2_available = self.permit2_addresses.contains_key(&chain_id);

		// TODO: Implement ERC-3009 detection
		let supports_erc3009 = false; // Conservative default

		Ok(TokenCapabilities {
			supports_erc3009,
			permit2_available,
		})
	}

	/// Default Permit2 contract addresses per chain
	fn default_permit2_addresses() -> HashMap<u64, Address> {
		let mut addresses = HashMap::new();

		// Ethereum Mainnet
		addresses.insert(
			1,
			"0x000000000022D473030F116dDEE9F6B43aC78BA3"
				.parse()
				.unwrap(),
		);
		// Polygon
		addresses.insert(
			137,
			"0x000000000022D473030F116dDEE9F6B43aC78BA3"
				.parse()
				.unwrap(),
		);
		// Arbitrum
		addresses.insert(
			42161,
			"0x000000000022D473030F116dDEE9F6B43aC78BA3"
				.parse()
				.unwrap(),
		);
		// Optimism
		addresses.insert(
			10,
			"0x000000000022D473030F116dDEE9F6B43aC78BA3"
				.parse()
				.unwrap(),
		);
		// Base
		addresses.insert(
			8453,
			"0x000000000022D473030F116dDEE9F6B43aC78BA3"
				.parse()
				.unwrap(),
		);

		addresses
	}
}

impl Default for CustodyStrategy {
	fn default() -> Self {
		Self::new()
	}
}
