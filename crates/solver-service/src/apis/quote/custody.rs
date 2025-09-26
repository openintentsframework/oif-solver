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

use solver_types::standards::eip7683::LockType;
use solver_types::{AssetLockReference, LockKind, OrderInput, QuoteError};

use super::registry::PROTOCOL_REGISTRY;

/// Custody strategy decision
#[derive(Debug, Clone)]
pub enum CustodyDecision {
	ResourceLock { lock: AssetLockReference },
	Escrow { lock_type: LockType },
}

/// Custody strategy decision engine
pub struct CustodyStrategy {}

impl CustodyStrategy {
	pub fn new() -> Self {
		Self {}
	}

	pub async fn decide_custody(
		&self,
		input: &OrderInput,
		origin_submission: Option<&solver_types::OriginSubmission>,
	) -> Result<CustodyDecision, QuoteError> {
		if let Some(lock) = &input.lock {
			return self.handle_explicit_lock(lock);
		}
		self.decide_escrow_strategy(input, origin_submission).await
	}

	fn handle_explicit_lock(
		&self,
		lock: &solver_types::AssetLockReference,
	) -> Result<CustodyDecision, QuoteError> {
		match lock.kind {
			LockKind::TheCompact => Ok(CustodyDecision::ResourceLock { lock: lock.clone() }),
			LockKind::Rhinestone => Ok(CustodyDecision::ResourceLock { lock: lock.clone() }),
		}
	}

	async fn decide_escrow_strategy(
		&self,
		input: &OrderInput,
		origin_submission: Option<&solver_types::OriginSubmission>,
	) -> Result<CustodyDecision, QuoteError> {
		let chain_id = input.asset.ethereum_chain_id().map_err(|e| {
			QuoteError::InvalidRequest(format!("Invalid chain ID in asset address: {}", e))
		})?;

		let token_address = input
			.asset
			.ethereum_address()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid Ethereum address: {}", e)))?;

		let capabilities = PROTOCOL_REGISTRY.get_token_capabilities(chain_id, token_address);

		// Respect user's explicit auth scheme preference from originSubmission
		if let Some(origin) = origin_submission {
			if let Some(schemes) = &origin.schemes {
				// Check for explicit EIP-3009 preference
				if schemes.contains(&solver_types::AuthScheme::Eip3009) {
					if capabilities.supports_eip3009 {
						return Ok(CustodyDecision::Escrow {
							lock_type: LockType::Eip3009Escrow,
						});
					} else {
						return Err(QuoteError::UnsupportedSettlement(
							"EIP-3009 requested but not supported by this token".to_string(),
						));
					}
				}

				// Check for explicit Permit2 preference
				if schemes.contains(&solver_types::AuthScheme::Permit2) {
					if capabilities.permit2_available {
						return Ok(CustodyDecision::Escrow {
							lock_type: LockType::Permit2Escrow,
						});
					} else {
						return Err(QuoteError::UnsupportedSettlement(
							"Permit2 requested but not available on this chain".to_string(),
						));
					}
				}
			}
		}

		// Fallback to automatic selection if no explicit preference
		if capabilities.supports_eip3009 {
			Ok(CustodyDecision::Escrow {
				lock_type: LockType::Eip3009Escrow,
			})
		} else if capabilities.permit2_available {
			Ok(CustodyDecision::Escrow {
				lock_type: LockType::Permit2Escrow,
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
