//! Permit2 signature payload generation for cross-chain token transfers.
//!
//! This module implements the EIP-712 structured data signing for Uniswap's Permit2 protocol,
//! enabling gasless and secure token transfers across chains. It generates the necessary
//! cryptographic digests and message payloads that users sign to authorize token movements.
//!
//! ## Overview
//!
//! Permit2 is a token approval contract that enables:
//! - Signature-based approvals instead of on-chain transactions
//! - Batch token transfers with a single signature
//! - Witness data for additional validation logic
//! - Cross-chain intent execution through oracle verification
//!
//! ## Key Components
//!
//! - **Batch Witness Digest**: Combines token permissions with cross-chain output specifications
//! - **Domain Separation**: EIP-712 domain binding to prevent signature replay attacks
//! - **Oracle Integration**: Embeds oracle addresses for settlement verification

use crate::apis::quote::registry::PROTOCOL_REGISTRY;
use alloy_primitives::{keccak256, B256, U256};
use serde_json::json;
use solver_config::Config;
use solver_settlement::SettlementInterface;
use solver_types::utils::{
	bytes20_to_alloy_address, DOMAIN_TYPE, MANDATE_OUTPUT_TYPE, NAME_PERMIT2, PERMIT2_WITNESS_TYPE,
	PERMIT_BATCH_WITNESS_TYPE, TOKEN_PERMISSIONS_TYPE,
};
use solver_types::{
	utils::{compute_final_digest, Eip712AbiEncoder},
	GetQuoteRequest, InteropAddress, QuoteError,
};

pub fn build_permit2_batch_witness_digest(
	request: &GetQuoteRequest,
	config: &Config,
	_settlement: &dyn SettlementInterface, // Kept for potential future use
	selected_oracle: solver_types::Address,
) -> Result<(B256, serde_json::Value), QuoteError> {
	// TODO: Implement support for multi-input/outputs
	let input = &request.available_inputs[0];
	let output = &request.requested_outputs.first().ok_or_else(|| {
		QuoteError::InvalidRequest("At least one requested output is required".to_string())
	})?;

	let origin_chain_id = input.asset.ethereum_chain_id().map_err(|e| {
		QuoteError::InvalidRequest(format!("Invalid origin chain ID in asset address: {}", e))
	})?;
	let dest_chain_id = output
		.asset
		.ethereum_chain_id()
		.map_err(|e| QuoteError::InvalidRequest(format!("Invalid destination chain ID: {}", e)))?;

	let origin_token = input
		.asset
		.ethereum_address()
		.map_err(|e| QuoteError::InvalidRequest(format!("Invalid origin token address: {}", e)))?;
	let dest_token = output.asset.ethereum_address().map_err(|e| {
		QuoteError::InvalidRequest(format!("Invalid destination token address: {}", e))
	})?;
	let recipient = output
		.receiver
		.ethereum_address()
		.map_err(|e| QuoteError::InvalidRequest(format!("Invalid recipient address: {}", e)))?;

	let amount: U256 = input.amount;

	// Spender = INPUT settler on origin chain
	let origin_net = config.networks.get(&origin_chain_id).ok_or_else(|| {
		QuoteError::InvalidRequest(format!(
			"Origin chain {} missing from networks config",
			origin_chain_id
		))
	})?;
	let spender = bytes20_to_alloy_address(&origin_net.input_settler_address.0)
		.map_err(QuoteError::InvalidRequest)?;

	// Output settler = OUTPUT settler on destination chain
	let dest_net = config.networks.get(&dest_chain_id).ok_or_else(|| {
		QuoteError::InvalidRequest(format!(
			"Destination chain {} missing from networks config",
			dest_chain_id
		))
	})?;
	let output_settler = bytes20_to_alloy_address(&dest_net.output_settler_address.0)
		.map_err(QuoteError::InvalidRequest)?;

	// Permit2 verifying contract address for origin chain
	let permit2 = PROTOCOL_REGISTRY
		.get_permit2_address(origin_chain_id)
		.ok_or_else(|| {
			QuoteError::InvalidRequest(format!("Permit2 not deployed on chain {}", origin_chain_id))
		})?;

	// Use the pre-selected oracle address
	let input_oracle = bytes20_to_alloy_address(&selected_oracle.0)
		.map_err(|e| QuoteError::InvalidRequest(format!("Invalid oracle address: {}", e)))?;

	// Nonce and deadlines
	let now_secs = chrono::Utc::now().timestamp() as u64;
	let nonce_ms: U256 = U256::from((chrono::Utc::now().timestamp_millis()) as u128);
	let deadline_secs: U256 = U256::from(now_secs + 300);
	let expires_u32: u32 = (now_secs + 300) as u32;

	// Type hashes
	let domain_type_hash = keccak256(DOMAIN_TYPE.as_bytes());
	let name_hash = keccak256(NAME_PERMIT2.as_bytes());
	let mandate_output_type_hash = keccak256(MANDATE_OUTPUT_TYPE.as_bytes());
	let permit2_witness_type_hash =
		keccak256(format!("{}{}", PERMIT2_WITNESS_TYPE, MANDATE_OUTPUT_TYPE).as_bytes());
	let token_permissions_type_hash = keccak256(TOKEN_PERMISSIONS_TYPE.as_bytes());
	let permit_batch_witness_type_hash = keccak256(
		format!(
			"{}{}{}{}",
			PERMIT_BATCH_WITNESS_TYPE,
			MANDATE_OUTPUT_TYPE,
			TOKEN_PERMISSIONS_TYPE,
			PERMIT2_WITNESS_TYPE
		)
		.as_bytes(),
	);

	let empty_bytes_hash = keccak256([]);

	// MandateOutput hash
	let mut enc = Eip712AbiEncoder::new();
	enc.push_b256(&mandate_output_type_hash);
	enc.push_b256(&B256::ZERO);
	enc.push_address32(&output_settler);
	enc.push_u256(U256::from(dest_chain_id));
	enc.push_address32(&dest_token);
	enc.push_u256(amount);
	enc.push_address32(&recipient);
	enc.push_b256(&empty_bytes_hash);
	enc.push_b256(&empty_bytes_hash);
	let mandate_output_hash = keccak256(enc.finish());

	let outputs_hash = keccak256(mandate_output_hash.as_slice());

	// Permit2Witness hash
	let mut enc = Eip712AbiEncoder::new();
	enc.push_b256(&permit2_witness_type_hash);
	enc.push_u32(expires_u32);
	enc.push_address(&input_oracle);
	enc.push_b256(&outputs_hash);
	let witness_hash = keccak256(enc.finish());

	// TokenPermissions hash
	let mut enc = Eip712AbiEncoder::new();
	enc.push_b256(&token_permissions_type_hash);
	enc.push_address(&origin_token);
	enc.push_u256(amount);
	let token_perm_hash = keccak256(enc.finish());

	let permitted_array_hash = keccak256(token_perm_hash.as_slice());

	// Main struct hash
	let mut enc = Eip712AbiEncoder::new();
	enc.push_b256(&permit_batch_witness_type_hash);
	enc.push_b256(&permitted_array_hash);
	enc.push_address(&spender);
	enc.push_u256(nonce_ms);
	enc.push_u256(deadline_secs);
	enc.push_b256(&witness_hash);
	let main_struct_hash = keccak256(enc.finish());

	// Domain separator hash
	let mut enc = Eip712AbiEncoder::new();
	enc.push_b256(&domain_type_hash);
	enc.push_b256(&name_hash);
	enc.push_u256(U256::from(origin_chain_id));
	enc.push_address(&permit2);
	let domain_separator_hash = keccak256(enc.finish());

	let final_digest = compute_final_digest(&domain_separator_hash, &main_struct_hash);

	let message_json = json!({
		"digest": final_digest,
		"signing": {
			"scheme": "eip-712",
			"noPrefix": true,
			"domain": {
				"name": "Permit2",
				"chainId": origin_chain_id,
				"verifyingContract": format!("0x{:x}", permit2),
			},
			"primaryType": "PermitBatchWitnessTransferFrom",
		},
		"permitted": [{
			"token": format!("0x{:x}", origin_token),
			"amount": amount.to_string(),
		}],
		"spender": format!("0x{:x}", spender),
		"nonce": nonce_ms.to_string(),
		"deadline": deadline_secs.to_string(),
		"witness": {
			"expires": expires_u32,
			"inputOracle": format!("0x{:x}", input_oracle),
			"outputs": [{
				"oracle": format!("0x{:064x}", 0),
				"settler": format!("0x{}{:x}", "0".repeat(24), output_settler),
				"chainId": dest_chain_id,
				"token": format!("0x{}{:x}", "0".repeat(24), dest_token),
				"amount": amount.to_string(),
				"recipient": format!("0x{}{:x}", "0".repeat(24), recipient),
				"call": "0x",
				"context": "0x"
			}]
		}
	});

	Ok((final_digest, message_json))
}

/// Build an ERC-7930 interop address for Permit2 domain (no name/version carried here).
pub fn permit2_domain_address_from_config(
	_config: &Config,
	chain_id: u64,
) -> Result<InteropAddress, QuoteError> {
	let permit2 = PROTOCOL_REGISTRY
		.get_permit2_address(chain_id)
		.ok_or_else(|| {
			QuoteError::InvalidRequest(format!("Permit2 not deployed on chain {}", chain_id))
		})?;
	Ok(InteropAddress::new_ethereum(chain_id, permit2))
}
