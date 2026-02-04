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

use std::sync::Arc;

use solver_delivery::DeliveryService;
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
pub struct CustodyStrategy {
	/// Reference to delivery service for contract calls.
	delivery_service: Arc<DeliveryService>,
}

impl CustodyStrategy {
	pub fn new(delivery_service: Arc<DeliveryService>) -> Self {
		Self { delivery_service }
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
			QuoteError::InvalidRequest(format!("Invalid chain ID in asset address: {e}"))
		})?;

		let token_address = input
			.asset
			.ethereum_address()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid Ethereum address: {e}")))?;

		let capabilities = PROTOCOL_REGISTRY
			.get_token_capabilities(chain_id, token_address, self.delivery_service.clone())
			.await;

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

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::{Address as AlloyAddress, U256};
	use solver_types::{
		standards::eip7930::InteropAddress, AuthScheme, LockKind, OriginMode, OriginSubmission,
	};
	use std::collections::HashMap;
	use std::str::FromStr;

	/// Creates a mock DeliveryService for testing
	fn create_mock_delivery_service() -> Arc<DeliveryService> {
		Arc::new(DeliveryService::new(HashMap::new(), 1, 20))
	}

	/// Creates a test OrderInput with the given asset address and chain ID
	fn create_test_order_input(chain_id: u64, token_address: &str) -> OrderInput {
		OrderInput {
			user: InteropAddress::new_ethereum(chain_id, AlloyAddress::from([1u8; 20])),
			asset: InteropAddress::new_ethereum(
				chain_id,
				AlloyAddress::from_str(token_address)
					.unwrap_or_else(|_| AlloyAddress::from([2u8; 20])),
			),
			amount: U256::from(1000000u64), // 1 USDC (6 decimals)
			lock: None,
		}
	}

	/// Creates a test OrderInput with an explicit lock
	fn create_test_order_input_with_lock(
		chain_id: u64,
		token_address: &str,
		lock_kind: LockKind,
	) -> OrderInput {
		let mut input = create_test_order_input(chain_id, token_address);
		input.lock = Some(AssetLockReference {
			kind: lock_kind,
			params: None,
		});
		input
	}

	/// Creates a test OriginSubmission with the given auth schemes
	fn create_origin_submission(schemes: Vec<AuthScheme>) -> OriginSubmission {
		OriginSubmission {
			mode: OriginMode::User,
			schemes: Some(schemes),
		}
	}

	#[tokio::test]
	async fn test_handle_explicit_thecompact_lock() {
		let delivery = create_mock_delivery_service();
		let strategy = CustodyStrategy::new(delivery);

		let input = create_test_order_input_with_lock(
			1,
			"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
			LockKind::TheCompact,
		);

		let result = strategy.decide_custody(&input, None).await;

		assert!(result.is_ok());
		match result.unwrap() {
			CustodyDecision::ResourceLock { lock } => {
				assert_eq!(lock.kind, LockKind::TheCompact);
			},
			_ => panic!("Expected ResourceLock decision"),
		}
	}

	#[tokio::test]
	async fn test_handle_explicit_rhinestone_lock() {
		let delivery = create_mock_delivery_service();
		let strategy = CustodyStrategy::new(delivery);

		let input = create_test_order_input_with_lock(
			1,
			"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
			LockKind::Rhinestone,
		);

		let result = strategy.decide_custody(&input, None).await;

		assert!(result.is_ok());
		match result.unwrap() {
			CustodyDecision::ResourceLock { lock } => {
				assert_eq!(lock.kind, LockKind::Rhinestone);
			},
			_ => panic!("Expected ResourceLock decision"),
		}
	}

	#[tokio::test]
	async fn test_escrow_strategy_eip3009_preference() {
		let delivery = create_mock_delivery_service();
		let strategy = CustodyStrategy::new(delivery);

		// Test with USDC on Ethereum mainnet (known EIP-3009 token)
		let input = create_test_order_input(1, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
		let origin = create_origin_submission(vec![AuthScheme::Eip3009]);

		let result = strategy.decide_custody(&input, Some(&origin)).await;

		assert!(result.is_ok());
		match result.unwrap() {
			CustodyDecision::Escrow { lock_type } => {
				assert_eq!(lock_type, LockType::Eip3009Escrow);
			},
			_ => panic!("Expected Escrow decision with EIP-3009"),
		}
	}

	#[tokio::test]
	async fn test_escrow_strategy_permit2_preference() {
		let delivery = create_mock_delivery_service();
		let strategy = CustodyStrategy::new(delivery);

		// Test with any token on Ethereum mainnet (Permit2 is available)
		let input = create_test_order_input(1, "0x1234567890123456789012345678901234567890");
		let origin = create_origin_submission(vec![AuthScheme::Permit2]);

		let result = strategy.decide_custody(&input, Some(&origin)).await;

		assert!(result.is_ok());
		match result.unwrap() {
			CustodyDecision::Escrow { lock_type } => {
				assert_eq!(lock_type, LockType::Permit2Escrow);
			},
			_ => panic!("Expected Escrow decision with Permit2"),
		}
	}

	#[tokio::test]
	async fn test_escrow_strategy_automatic_eip3009_selection() {
		let delivery = create_mock_delivery_service();
		let strategy = CustodyStrategy::new(delivery);

		// Test with USDC on Ethereum mainnet (known EIP-3009 token) without explicit preference
		let input = create_test_order_input(1, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");

		let result = strategy.decide_custody(&input, None).await;

		assert!(result.is_ok());
		match result.unwrap() {
			CustodyDecision::Escrow { lock_type } => {
				assert_eq!(lock_type, LockType::Eip3009Escrow);
			},
			_ => panic!("Expected automatic EIP-3009 selection"),
		}
	}

	#[tokio::test]
	async fn test_escrow_strategy_automatic_permit2_fallback() {
		let delivery = create_mock_delivery_service();
		let strategy = CustodyStrategy::new(delivery);

		let input = create_test_order_input(1, "0x1234567890123456789012345678901234567890");

		let result = strategy.decide_custody(&input, None).await;

		assert!(result.is_ok());
		match result.unwrap() {
			CustodyDecision::Escrow { lock_type } => {
				assert_eq!(lock_type, LockType::Permit2Escrow);
			},
			_ => panic!("Expected automatic Permit2 fallback"),
		}
	}

	#[tokio::test]
	async fn test_error_eip3009_requested_but_not_supported() {
		let delivery = create_mock_delivery_service();
		let strategy = CustodyStrategy::new(delivery);

		// Test with non-EIP-3009 token but explicit EIP-3009 preference
		let input = create_test_order_input(1, "0x1234567890123456789012345678901234567890");
		let origin = create_origin_submission(vec![AuthScheme::Eip3009]);

		let result = strategy.decide_custody(&input, Some(&origin)).await;

		assert!(result.is_err());
		match result.unwrap_err() {
			QuoteError::UnsupportedSettlement(msg) => {
				assert!(msg.contains("EIP-3009 requested but not supported"));
			},
			_ => panic!("Expected UnsupportedSettlement error for EIP-3009"),
		}
	}

	#[tokio::test]
	async fn test_error_permit2_requested_but_not_available() {
		let delivery = create_mock_delivery_service();
		let strategy = CustodyStrategy::new(delivery);

		// Test with token on unsupported chain (no Permit2 deployment)
		let input = create_test_order_input(999, "0x1234567890123456789012345678901234567890");
		let origin = create_origin_submission(vec![AuthScheme::Permit2]);

		let result = strategy.decide_custody(&input, Some(&origin)).await;

		assert!(result.is_err());
		match result.unwrap_err() {
			QuoteError::UnsupportedSettlement(msg) => {
				assert!(msg.contains("Permit2 requested but not available"));
			},
			_ => panic!("Expected UnsupportedSettlement error for Permit2"),
		}
	}

	#[tokio::test]
	async fn test_error_no_supported_settlement_mechanism() {
		let delivery = create_mock_delivery_service();
		let strategy = CustodyStrategy::new(delivery);

		// Test with token on unsupported chain (no Permit2, no EIP-3009)
		let input = create_test_order_input(999, "0x1234567890123456789012345678901234567890");

		let result = strategy.decide_custody(&input, None).await;

		assert!(result.is_err());
		match result.unwrap_err() {
			QuoteError::UnsupportedSettlement(msg) => {
				assert!(msg.contains("No supported settlement mechanism available"));
			},
			_ => panic!("Expected UnsupportedSettlement error for no mechanisms"),
		}
	}

	#[tokio::test]
	async fn test_multiple_auth_schemes_eip3009_priority() {
		let delivery = create_mock_delivery_service();
		let strategy = CustodyStrategy::new(delivery);

		// Test with USDC and multiple auth schemes (EIP-3009 should have priority)
		let input = create_test_order_input(1, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
		let origin = create_origin_submission(vec![AuthScheme::Permit2, AuthScheme::Eip3009]);

		let result = strategy.decide_custody(&input, Some(&origin)).await;

		assert!(result.is_ok());
		match result.unwrap() {
			CustodyDecision::Escrow { lock_type } => {
				assert_eq!(lock_type, LockType::Eip3009Escrow);
			},
			_ => panic!("Expected EIP-3009 to have priority"),
		}
	}

	#[tokio::test]
	async fn test_multiple_auth_schemes_permit2_fallback() {
		let delivery = create_mock_delivery_service();
		let strategy = CustodyStrategy::new(delivery);

		// Test with non-EIP-3009 token and multiple auth schemes
		let input = create_test_order_input(1, "0x1234567890123456789012345678901234567890");
		let origin = create_origin_submission(vec![AuthScheme::Eip3009, AuthScheme::Permit2]);

		let result = strategy.decide_custody(&input, Some(&origin)).await;

		// Should fail on EIP-3009 first, then not try Permit2 in current implementation
		assert!(result.is_err());
		match result.unwrap_err() {
			QuoteError::UnsupportedSettlement(msg) => {
				assert!(msg.contains("EIP-3009 requested but not supported"));
			},
			_ => panic!("Expected EIP-3009 error (current implementation checks in order)"),
		}
	}

	#[tokio::test]
	async fn test_polygon_usdc_eip3009_support() {
		let delivery = create_mock_delivery_service();
		let strategy = CustodyStrategy::new(delivery);

		// Test with USDC on Polygon (known EIP-3009 token)
		let input = create_test_order_input(137, "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359");

		let result = strategy.decide_custody(&input, None).await;

		assert!(result.is_ok());
		match result.unwrap() {
			CustodyDecision::Escrow { lock_type } => {
				assert_eq!(lock_type, LockType::Eip3009Escrow);
			},
			_ => panic!("Expected EIP-3009 for Polygon USDC"),
		}
	}

	#[tokio::test]
	async fn test_arbitrum_usdc_eip3009_support() {
		let delivery = create_mock_delivery_service();
		let strategy = CustodyStrategy::new(delivery);

		// Test with USDC on Arbitrum (known EIP-3009 token)
		let input = create_test_order_input(42161, "0xaf88d065e77c8cC2239327C5EDb3A432268e5831");

		let result = strategy.decide_custody(&input, None).await;

		assert!(result.is_ok());
		match result.unwrap() {
			CustodyDecision::Escrow { lock_type } => {
				assert_eq!(lock_type, LockType::Eip3009Escrow);
			},
			_ => panic!("Expected EIP-3009 for Arbitrum USDC"),
		}
	}

	#[tokio::test]
	async fn test_unsupported_chain_error() {
		let delivery = create_mock_delivery_service();
		let strategy = CustodyStrategy::new(delivery);

		// Test with token on unsupported chain (no Permit2, no EIP-3009)
		let input = create_test_order_input(999, "0x1234567890123456789012345678901234567890");

		let result = strategy.decide_custody(&input, None).await;

		assert!(result.is_err());
		match result.unwrap_err() {
			QuoteError::UnsupportedSettlement(msg) => {
				assert!(msg.contains("No supported settlement mechanism available"));
			},
			_ => panic!("Expected UnsupportedSettlement error for unsupported chain"),
		}
	}

	#[test]
	fn test_custody_decision_debug() {
		// Test Debug implementation for CustodyDecision
		let resource_lock = CustodyDecision::ResourceLock {
			lock: AssetLockReference {
				kind: LockKind::TheCompact,
				params: None,
			},
		};

		let escrow = CustodyDecision::Escrow {
			lock_type: LockType::Permit2Escrow,
		};

		// Should not panic when formatting
		let _resource_str = format!("{resource_lock:?}");
		let _escrow_str = format!("{escrow:?}");
	}

	#[test]
	fn test_custody_decision_clone() {
		// Test Clone implementation for CustodyDecision
		let original = CustodyDecision::Escrow {
			lock_type: LockType::Eip3009Escrow,
		};

		let cloned = original.clone();

		match (original, cloned) {
			(
				CustodyDecision::Escrow { lock_type: lt1 },
				CustodyDecision::Escrow { lock_type: lt2 },
			) => {
				assert_eq!(lt1, lt2);
			},
			_ => panic!("Clone should preserve the decision type"),
		}
	}
}
