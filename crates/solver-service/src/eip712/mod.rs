//! EIP-712 signature validation and message hash computation
//!
//! This module provides generic EIP-712 interfaces and TheCompact protocol-specific implementations.

use alloy_primitives::{Address as AlloyAddress, Bytes, FixedBytes};
use alloy_sol_types::SolCall;
use solver_delivery::DeliveryService;
use solver_types::{Address, APIError, ApiErrorType, Transaction};
use std::sync::Arc;

pub mod compact;

// Generic EIP-712 interfaces

/// Trait for computing EIP-712 message hashes
pub trait MessageHashComputer {
    /// Compute the struct hash for the given order data
    fn compute_message_hash(
        &self,
        order_bytes: &[u8],
        contract_address: AlloyAddress,
    ) -> Result<FixedBytes<32>, APIError>;
}

/// Trait for EIP-712 signature validation
pub trait SignatureValidator {
    /// Validate EIP-712 signature against expected signer
    fn validate_signature(
        &self,
        domain_separator: FixedBytes<32>,
        struct_hash: FixedBytes<32>,
        signature: &Bytes,
        expected_signer: AlloyAddress,
    ) -> Result<bool, APIError>;

    /// Extract signature from encoded signature data
    fn extract_signature(&self, signature: &Bytes) -> Bytes;
}

// Generic domain separator functionality

/// Get domain separator from TheCompact contract
pub async fn get_domain_separator(
    delivery: &Arc<DeliveryService>,
    contract_address: &Address,
    chain_id: u64,
) -> Result<FixedBytes<32>, APIError> {
    use solver_types::standards::eip7683::interfaces::ITheCompact::DOMAIN_SEPARATORCall;

    let call = DOMAIN_SEPARATORCall {};
    let encoded = call.abi_encode();

    // Create transaction for contract call
    let tx = Transaction {
        to: Some(contract_address.clone()),
        data: encoded,
        value: alloy_primitives::U256::ZERO,
        chain_id,
        nonce: None,
        gas_limit: None,
        gas_price: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
    };

    let result = delivery
        .contract_call(chain_id, tx)
        .await
        .map_err(|e| APIError::BadRequest {
            error_type: ApiErrorType::OrderValidationFailed,
            message: format!("Failed to get domain separator: {}", e),
            details: None,
        })?;

    // Decode the result using ITheCompact DOMAIN_SEPARATOR response
    let domain_separator = DOMAIN_SEPARATORCall::abi_decode_returns(&result, false)
        .map_err(|e| APIError::BadRequest {
            error_type: ApiErrorType::OrderValidationFailed,
            message: format!("Failed to decode domain separator: {}", e),
            details: None,
        })?
        ._0;

    Ok(domain_separator)
}