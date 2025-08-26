//! EIP-712 helpers for Quote API: builds Permit2 batch-witness digest.
//! Uses generic EIP-712 utilities from `solver-types`.

use alloy_primitives::{keccak256, Address as AlloyAddress, B256, U256};
use serde_json::json;
use solver_config::Config;
use solver_types::{
	utils::{compute_final_digest, Eip712AbiEncoder},
	GetQuoteRequest, InteropAddress, QuoteError,
};

/// Computes the EIP-712 final digest for Permit2's
/// `PermitBatchWitnessTransferFrom` with a single permitted token and single output.
/// Returns `(final_digest_hex, message_json)` used for client signing and verification.
pub fn build_permit2_batch_witness_digest(
	request: &GetQuoteRequest,
	config: &Config,
) -> Result<(String, serde_json::Value), QuoteError> {
	// Resolve origin/destination context
	let input = &request.available_inputs[0];
	let output = &request.requested_outputs.get(0).ok_or_else(|| {
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
	let spender = bytes20_to_address(&origin_net.input_settler_address.0)?;

	// Output settler = OUTPUT settler on destination chain
	let dest_net = config.networks.get(&dest_chain_id).ok_or_else(|| {
		QuoteError::InvalidRequest(format!(
			"Destination chain {} missing from networks config",
			dest_chain_id
		))
	})?;
	let output_settler = bytes20_to_address(&dest_net.output_settler_address.0)?;

	// Permit2 verifying contract address for origin chain (STRICTLY from config; no fallback)
	let permit2 = resolve_permit2_address(config, origin_chain_id)?;

	// Oracle address (per origin chain) from settlement implementation config.
	let input_oracle = resolve_oracle_address(config, origin_chain_id)?;

	// Nonce and deadlines
	let now_secs = chrono::Utc::now().timestamp() as u64;
	let nonce_ms: U256 = U256::from((chrono::Utc::now().timestamp_millis()) as u128);
	let deadline_secs: U256 = U256::from(now_secs + 300);
	let expires_u32: u32 = (now_secs + 300) as u32;

	// Type strings
	const DOMAIN_TYPE: &str = "EIP712Domain(string name,uint256 chainId,address verifyingContract)";
	const NAME_PERMIT2: &str = "Permit2";
	const MANDATE_OUTPUT_TYPE: &str = "MandateOutput(bytes32 oracle,bytes32 settler,uint256 chainId,bytes32 token,uint256 amount,bytes32 recipient,bytes call,bytes context)";
	const PERMIT2_WITNESS_TYPE: &str =
		"Permit2Witness(uint32 expires,address inputOracle,MandateOutput[] outputs)";
	const TOKEN_PERMISSIONS_TYPE: &str = "TokenPermissions(address token,uint256 amount)";
	const PERMIT_BATCH_WITNESS_TYPE: &str =
        "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,Permit2Witness witness)";

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

	let empty_bytes_hash = keccak256(&[]);

	// MandateOutput hash
	let mut enc = Eip712AbiEncoder::new();
	enc.push_b256(&mandate_output_type_hash);
	enc.push_b256(&B256::ZERO);
	enc.push_address(&output_settler);
	enc.push_u256(U256::from(dest_chain_id));
	enc.push_address(&dest_token);
	enc.push_u256(amount);
	enc.push_address(&recipient);
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

	// Message JSON
	let message_json = json!({
		"digest": format_hex(&final_digest),
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

	Ok((format_hex(&final_digest), message_json))
}

/// Resolve the oracle address for a given chain from settlement implementation config.
fn resolve_oracle_address(config: &Config, chain_id: u64) -> Result<AlloyAddress, QuoteError> {
	let Some(impl_val) = config.settlement.implementations.get("eip7683") else {
		return Err(QuoteError::InvalidRequest(
			"Missing settlement.implementations.eip7683 in config".to_string(),
		));
	};
	let Some(table) = impl_val.as_table() else {
		return Err(QuoteError::InvalidRequest(
			"Invalid eip7683 settlement implementation format".to_string(),
		));
	};
	let Some(oracle_map) = table.get("oracle_addresses").and_then(|v| v.as_table()) else {
		return Err(QuoteError::InvalidRequest(
			"Missing oracle_addresses in eip7683 settlement implementation".to_string(),
		));
	};
	let key = chain_id.to_string();
	let Some(addr_str) = oracle_map.get(&key).and_then(|v| v.as_str()) else {
		return Err(QuoteError::InvalidRequest(format!(
			"Oracle address not configured for chain {}",
			chain_id
		)));
	};
	addr_str
		.parse::<AlloyAddress>()
		.map_err(|e| QuoteError::InvalidRequest(format!("Invalid oracle address: {}", e)))
}

/// Resolve the Permit2 address for a given chain strictly from config.
/// Looks under `settlement.implementations.eip7683.permit2_addresses`.
pub fn resolve_permit2_address(config: &Config, chain_id: u64) -> Result<AlloyAddress, QuoteError> {
	// Use default Permit2 address mapping from CustodyStrategy
	use super::custody::CustodyStrategy;
	let map = CustodyStrategy::default_permit2_addresses();
	let solver_address = map.get(&chain_id).ok_or_else(|| {
		QuoteError::InvalidRequest(format!("No default Permit2 address for chain {}", chain_id))
	})?;

	// Convert solver_types::Address to alloy_primitives::Address
	if solver_address.0.len() != 20 {
		return Err(QuoteError::InvalidRequest(
			"Invalid address length".to_string(),
		));
	}
	let mut addr_bytes = [0u8; 20];
	addr_bytes.copy_from_slice(&solver_address.0);
	Ok(AlloyAddress::from(addr_bytes))
}
fn bytes20_to_address(bytes: &[u8]) -> Result<AlloyAddress, QuoteError> {
	if bytes.len() != 20 {
		return Err(QuoteError::InvalidRequest(format!(
			"Expected 20-byte address, got {}",
			bytes.len()
		)));
	}
	let mut arr = [0u8; 20];
	arr.copy_from_slice(bytes);
	Ok(AlloyAddress::from(arr))
}

fn format_hex(b: &B256) -> String {
	format!("0x{:x}", b)
}

/// Build an ERC-7930 interop address for Permit2 domain (no name/version carried here).
pub fn permit2_domain_address_from_config(
	config: &Config,
	chain_id: u64,
) -> Result<InteropAddress, QuoteError> {
	let permit2 = resolve_permit2_address(config, chain_id)?;
	Ok(InteropAddress::new_ethereum(chain_id, permit2))
}
