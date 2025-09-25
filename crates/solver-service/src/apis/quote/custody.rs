//! Custody decision engine for cross-chain token transfers.
//!
//! This module implements the logic for determining how tokens should be secured
//! during cross-chain transfers. It analyzes token capabilities, user preferences,
//! and protocol availability to select the optimal custody mechanism for each quote.
//!
//! ## Overview
//!
//! The custody module makes intelligent decisions about:
//! - Whether to use resource locks (pre-authorized funds) or escrow mechanisms
//! - Which specific protocol to use (Permit2, EIP-3009, TheCompact, etc.)
//! - How to optimize for gas costs, security, and user experience
//!
//! ## Custody Mechanisms
//!
//! ### Resource Locks
//! Pre-authorized fund allocations that don't require token movement:
//! - **TheCompact**: Advanced resource locking with allocation proofs
//! - **Custom Locks**: Protocol-specific locking mechanisms
//!
//! ### Escrow Mechanisms
//! Traditional token custody through smart contracts:
//! - **Permit2**: Universal approval system with signature-based transfers
//! - **EIP-3009**: Native gasless transfers for supported tokens (USDC, etc.)
//!
//! ## Decision Process
//!
//! 1. **Check for existing locks**: If user has pre-authorized funds, prefer using them
//! 2. **Analyze token capabilities**: Determine which protocols the token supports
//! 3. **Evaluate chain support**: Ensure the protocol is available on the source chain
//! 4. **Optimize selection**: Choose based on gas costs, security, and UX preferences
//!
//! ## Token Analysis
//!
//! The module maintains knowledge about token capabilities:
//! - EIP-3009 support (primarily USDC and similar tokens)
//! - Permit2 availability (universal but requires deployment)
//! - Custom protocol support (token-specific features)

use solver_types::{AvailableInput, LockKind as ApiLockKind, QuoteError};

use super::registry::PROTOCOL_REGISTRY;

/// Types of resource locks supported
#[derive(Debug, Clone)]
pub enum LockKind {
	TheCompact { params: serde_json::Value },
}

/// Types of escrow mechanisms
#[derive(Debug, Clone)]
pub enum EscrowKind {
	Permit2,
	Eip3009,
}

/// Custody strategy decision
#[derive(Debug, Clone)]
pub enum CustodyDecision {
	ResourceLock { kind: LockKind },
	Escrow { kind: EscrowKind },
}

/// Custody strategy decision engine
pub struct CustodyStrategy {}

impl CustodyStrategy {
	pub fn new() -> Self {
		Self {}
	}

	pub async fn decide_custody(
		&self,
		input: &AvailableInput,
	) -> Result<CustodyDecision, QuoteError> {
		if let Some(lock) = &input.lock {
			return self.handle_explicit_lock(lock);
		}
		self.decide_escrow_strategy(input).await
	}

	fn handle_explicit_lock(
		&self,
		lock: &solver_types::Lock,
	) -> Result<CustodyDecision, QuoteError> {
		match lock.kind {
			ApiLockKind::TheCompact => {
				let lock_kind = LockKind::TheCompact {
					params: lock.params.clone().unwrap_or_default(),
				};
				Ok(CustodyDecision::ResourceLock { kind: lock_kind })
			},
			// Permit2 and EIP3009 are escrow mechanisms, not resource locks
			ApiLockKind::Permit2 => Ok(CustodyDecision::Escrow {
				kind: EscrowKind::Permit2,
			}),
			ApiLockKind::Eip3009 => Ok(CustodyDecision::Escrow {
				kind: EscrowKind::Eip3009,
			}),
		}
	}

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

		let capabilities = PROTOCOL_REGISTRY.get_token_capabilities(chain_id, token_address);

		if capabilities.supports_eip3009 {
			Ok(CustodyDecision::Escrow {
				kind: EscrowKind::Eip3009,
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
}

impl Default for CustodyStrategy {
	fn default() -> Self {
		Self::new()
	}
}
