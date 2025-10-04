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
use solver_config::{Config, QuoteConfig};
use solver_settlement::SettlementInterface;
use solver_types::utils::{
	bytes20_to_alloy_address, DOMAIN_TYPE, MANDATE_OUTPUT_TYPE, NAME_PERMIT2, PERMIT2_WITNESS_TYPE,
	PERMIT_BATCH_WITNESS_TYPE, TOKEN_PERMISSIONS_TYPE, ZERO_BYTES32,
};
use solver_types::{
	utils::{compute_final_digest, Eip712AbiEncoder},
	GetQuoteRequest, QuoteError,
};

pub fn build_permit2_batch_witness_digest(
	request: &GetQuoteRequest,
	config: &Config,
	_settlement: &dyn SettlementInterface, // Kept for potential future use
	selected_oracle: solver_types::Address,
) -> Result<(B256, serde_json::Value), QuoteError> {
	// TODO: Implement support for multi-input/outputs
	let input = &request.intent.inputs[0];
	let output = &request.intent.outputs.first().ok_or_else(|| {
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

	// Input amount should always be set after cost adjustment
	let input_amount: U256 = input
		.amount
		.as_ref()
		.ok_or_else(|| {
			QuoteError::InvalidRequest("Input amount not set after cost adjustment".to_string())
		})?
		.parse()
		.map_err(|e| QuoteError::InvalidRequest(format!("Invalid input amount format: {}", e)))?;

	// Get output amount from request (this should be our adjusted amount)
	let output_amount: U256 = output
		.amount
		.as_ref()
		.and_then(|s| U256::from_str_radix(s, 10).ok())
		.unwrap_or(U256::ZERO);

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

	// Use minValidUntil from request if provided (as absolute timestamp), otherwise use configured validity duration
	let deadline_timestamp = if let Some(min_valid_until) = request.intent.min_valid_until {
		// min_valid_until is an absolute timestamp
		min_valid_until
	} else {
		// Use configured validity duration added to current time
		let validity_seconds = config
			.api
			.as_ref()
			.and_then(|api| api.quote.as_ref())
			.map(|quote| quote.validity_seconds)
			.unwrap_or_else(|| QuoteConfig::default().validity_seconds);
		now_secs + validity_seconds
	};
	let deadline_secs: U256 = U256::from(deadline_timestamp);
	let expires_secs: u32 = deadline_timestamp as u32;

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
	enc.push_address(&output_settler);
	enc.push_u256(U256::from(dest_chain_id));
	enc.push_address(&dest_token);
	enc.push_u256(output_amount);
	enc.push_address(&recipient);
	enc.push_b256(&empty_bytes_hash);
	enc.push_b256(&empty_bytes_hash);
	let mandate_output_hash = keccak256(enc.finish());

	let outputs_hash = keccak256(mandate_output_hash.as_slice());

	// Permit2Witness hash
	let mut enc = Eip712AbiEncoder::new();
	enc.push_b256(&permit2_witness_type_hash);
	enc.push_u32(expires_secs);
	enc.push_address(&input_oracle);
	enc.push_b256(&outputs_hash);
	let witness_hash = keccak256(enc.finish());

	// TokenPermissions hash
	let mut enc = Eip712AbiEncoder::new();
	enc.push_b256(&token_permissions_type_hash);
	enc.push_address(&origin_token);
	enc.push_u256(input_amount);
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
			"amount": input_amount.to_string(),
		}],
		"spender": format!("0x{:x}", spender),
		"nonce": nonce_ms.to_string(),
		"deadline": deadline_secs.to_string(),
		"witness": {
			"expires": expires_secs,
			"inputOracle": format!("0x{:x}", input_oracle),
			"outputs": [{
				"oracle": ZERO_BYTES32,
				"settler": format!("0x{}{:x}", "0".repeat(24), output_settler),
				"chainId": dest_chain_id,
				"token": format!("0x{}{:x}", "0".repeat(24), dest_token),
				"amount": output_amount.to_string(),
				"recipient": format!("0x{}{:x}", "0".repeat(24), recipient),
				"call": "0x",
				"context": "0x"
			}]
		}
	});

	Ok((final_digest, message_json))
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloy_primitives::{address, U256};
	use solver_config::{ApiConfig, Config, ConfigBuilder, QuoteConfig, SettlementConfig};
	use solver_settlement::MockSettlementInterface;
	use solver_types::{
		parse_address,
		standards::eip7930::InteropAddress,
		utils::tests::builders::{NetworkConfigBuilder, NetworksConfigBuilder},
		IntentRequest, IntentType, QuoteInput, QuoteOutput,
	};
	use std::collections::HashMap;

	const TEST_CHAIN_ID_1: u64 = 1; // Ethereum mainnet
	const TEST_CHAIN_ID_137: u64 = 137; // Polygon

	fn create_test_config() -> Config {
		let api_config = ApiConfig {
			enabled: true,
			host: "127.0.0.1".to_string(),
			port: 8080,
			timeout_seconds: 30,
			max_request_size: 1048576,
			implementations: Default::default(),
			rate_limiting: None,
			cors: None,
			auth: None,
			quote: Some(QuoteConfig {
				validity_seconds: 300, // 5 minutes
			}),
		};

		let settlement_config = SettlementConfig {
			implementations: HashMap::new(),
			settlement_poll_interval_seconds: 3,
		};

		let networks = NetworksConfigBuilder::new()
			.add_network(TEST_CHAIN_ID_1, NetworkConfigBuilder::new().build())
			.add_network(TEST_CHAIN_ID_137, NetworkConfigBuilder::new().build())
			.build();

		ConfigBuilder::new()
			.api(Some(api_config))
			.settlement(settlement_config)
			.networks(networks)
			.build()
	}

	fn create_test_quote_request() -> GetQuoteRequest {
		let eth_usdc = InteropAddress::new_ethereum(
			TEST_CHAIN_ID_1,
			address!("A0b86a33E6417c4c2f4066Ca7e40d36c4D5f8E1a"), // USDC on Ethereum
		);

		let polygon_usdc = InteropAddress::new_ethereum(
			TEST_CHAIN_ID_137,
			address!("2791Bca1f2de4661ED88A30C99A7a9449Aa84174"), // USDC on Polygon
		);

		let user_address = InteropAddress::new_ethereum(
			TEST_CHAIN_ID_1,
			address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
		);

		let quote_input = QuoteInput {
			user: user_address.clone(),
			asset: eth_usdc,
			amount: Some("1000000000".to_string()), // 1000 USDC (6 decimals)
			lock: None,
		};

		let quote_output = QuoteOutput {
			receiver: user_address.clone(),
			asset: polygon_usdc,
			amount: Some("995000000".to_string()), // 995 USDC after fees
			calldata: None,
		};

		GetQuoteRequest {
			user: user_address,
			intent: IntentRequest {
				intent_type: IntentType::OifSwap,
				inputs: vec![quote_input],
				outputs: vec![quote_output],
				swap_type: None,
				min_valid_until: None,
				preference: None,
				origin_submission: None,
				failure_handling: None,
				partial_fill: None,
				metadata: None,
			},
			supported_types: vec!["oif-escrow-v0".to_string()],
		}
	}

	#[test]
	fn test_build_permit2_batch_witness_digest_success() {
		let config = create_test_config();
		let request = create_test_quote_request();
		let settlement = MockSettlementInterface::new();
		let oracle_address = parse_address("0x9999999999999999999999999999999999999999").unwrap();

		let result =
			build_permit2_batch_witness_digest(&request, &config, &settlement, oracle_address);

		assert!(result.is_ok(), "Expected successful digest generation");

		let (digest, message_json) = result.unwrap();

		// Verify digest is not zero
		assert_ne!(digest, B256::ZERO, "Digest should not be zero");

		// Verify message structure
		assert!(message_json["digest"].is_string());
		assert!(message_json["signing"].is_object());
		assert!(message_json["permitted"].is_array());
		assert!(message_json["spender"].is_string());
		assert!(message_json["nonce"].is_string());
		assert!(message_json["deadline"].is_string());
		assert!(message_json["witness"].is_object());

		// Verify EIP-712 signing details
		let signing = &message_json["signing"];
		assert_eq!(signing["scheme"], "eip-712");
		assert_eq!(signing["noPrefix"], true);
		assert_eq!(signing["primaryType"], "PermitBatchWitnessTransferFrom");

		// Verify domain
		let domain = &signing["domain"];
		assert_eq!(domain["name"], "Permit2");
		assert_eq!(domain["chainId"], TEST_CHAIN_ID_1);

		// Verify witness structure
		let witness = &message_json["witness"];
		assert!(witness["expires"].is_number());
		assert!(witness["inputOracle"].is_string());
		assert!(witness["outputs"].is_array());

		let outputs = witness["outputs"].as_array().unwrap();
		assert_eq!(outputs.len(), 1);

		let output = &outputs[0];
		assert_eq!(output["chainId"], TEST_CHAIN_ID_137);
		assert!(output["token"].is_string());
		assert!(output["amount"].is_string());
		assert!(output["recipient"].is_string());
	}

	#[test]
	fn test_build_permit2_batch_witness_digest_no_outputs() {
		let config = create_test_config();
		let mut request = create_test_quote_request();
		request.intent.outputs.clear(); // Remove all outputs
		let settlement = MockSettlementInterface::new();
		let oracle_address = parse_address("0x9999999999999999999999999999999999999999").unwrap();

		let result =
			build_permit2_batch_witness_digest(&request, &config, &settlement, oracle_address);

		assert!(result.is_err());
		match result.err().unwrap() {
			QuoteError::InvalidRequest(msg) => {
				assert!(msg.contains("At least one requested output is required"));
			},
			_ => panic!("Expected InvalidRequest error"),
		}
	}

	#[test]
	fn test_build_permit2_batch_witness_digest_invalid_origin_chain() {
		let config = create_test_config();
		let mut request = create_test_quote_request();

		// Set invalid chain ID in input asset
		let invalid_asset = InteropAddress::new_ethereum(
			999, // Chain not in config
			address!("A0b86a33E6417c4c2f4066Ca7e40d36c4D5f8E1a"),
		);
		request.intent.inputs[0].asset = invalid_asset;

		let settlement = MockSettlementInterface::new();
		let oracle_address = parse_address("0x9999999999999999999999999999999999999999").unwrap();

		let result =
			build_permit2_batch_witness_digest(&request, &config, &settlement, oracle_address);

		assert!(result.is_err());
		match result.err().unwrap() {
			QuoteError::InvalidRequest(msg) => {
				assert!(msg.contains("Origin chain 999 missing from networks config"));
			},
			_ => panic!("Expected InvalidRequest error for missing origin chain"),
		}
	}

	#[test]
	fn test_build_permit2_batch_witness_digest_invalid_dest_chain() {
		let config = create_test_config();
		let mut request = create_test_quote_request();

		// Set invalid chain ID in output asset
		let invalid_asset = InteropAddress::new_ethereum(
			999, // Chain not in config
			address!("2791Bca1f2de4661ED88A30C99A7a9449Aa84174"),
		);
		request.intent.outputs[0].asset = invalid_asset;

		let settlement = MockSettlementInterface::new();
		let oracle_address = parse_address("0x9999999999999999999999999999999999999999").unwrap();

		let result =
			build_permit2_batch_witness_digest(&request, &config, &settlement, oracle_address);

		assert!(result.is_err());
		match result.err().unwrap() {
			QuoteError::InvalidRequest(msg) => {
				assert!(msg.contains("Destination chain 999 missing from networks config"));
			},
			_ => panic!("Expected InvalidRequest error for missing destination chain"),
		}
	}

	#[test]
	fn test_build_permit2_batch_witness_digest_permit2_not_deployed() {
		let config = create_test_config();
		let mut request = create_test_quote_request();

		// Use a chain ID where Permit2 is not deployed (according to registry)
		let unsupported_chain = InteropAddress::new_ethereum(
			56, // BSC - assume not in permit2 registry
			address!("A0b86a33E6417c4c2f4066Ca7e40d36c4D5f8E1a"),
		);
		request.intent.inputs[0].asset = unsupported_chain;

		// Need to add this chain to networks config to get past that check
		let mut config = config;
		let bsc_network = NetworkConfigBuilder::new()
			.input_settler_address(
				parse_address("0x5555555555555555555555555555555555555555").unwrap(),
			)
			.output_settler_address(
				parse_address("0x6666666666666666666666666666666666666666").unwrap(),
			)
			.build();

		config.networks.insert(56, bsc_network);

		let settlement = MockSettlementInterface::new();
		let oracle_address = parse_address("0x9999999999999999999999999999999999999999").unwrap();

		let result =
			build_permit2_batch_witness_digest(&request, &config, &settlement, oracle_address);

		// This will likely fail because Permit2 is not deployed on chain 56
		// The exact error depends on the protocol registry implementation
		assert!(result.is_err());
	}

	#[test]
	fn test_build_permit2_batch_witness_digest_uses_config_validity() {
		let mut config = create_test_config();
		config
			.api
			.as_mut()
			.unwrap()
			.quote
			.as_mut()
			.unwrap()
			.validity_seconds = 600; // 10 minutes

		let request = create_test_quote_request();
		let settlement = MockSettlementInterface::new();
		let oracle_address = parse_address("0x9999999999999999999999999999999999999999").unwrap();

		let result =
			build_permit2_batch_witness_digest(&request, &config, &settlement, oracle_address);

		assert!(result.is_ok());

		let (_digest, message_json) = result.unwrap();

		// Verify that the deadline reflects the configured validity
		let deadline_str = message_json["deadline"].as_str().unwrap();
		let _deadline = U256::from_str_radix(deadline_str, 10).unwrap();

		let expires_u32 = message_json["witness"]["expires"].as_u64().unwrap() as u32;
		let now = chrono::Utc::now().timestamp() as u32;

		// Allow some tolerance for test execution time
		assert!(
			expires_u32 >= now + 580 && expires_u32 <= now + 620,
			"Expected expiry around {} seconds from now, got {}",
			600,
			expires_u32 - now
		);
	}

	#[test]
	fn test_build_permit2_batch_witness_digest_deterministic() {
		let config = create_test_config();
		let request = create_test_quote_request();
		let settlement = MockSettlementInterface::new();
		let oracle_address = parse_address("0x9999999999999999999999999999999999999999").unwrap();

		// Build digest twice with same inputs
		let result1 = build_permit2_batch_witness_digest(
			&request,
			&config,
			&settlement,
			oracle_address.clone(),
		);

		// Wait a moment to ensure different timestamp
		std::thread::sleep(std::time::Duration::from_millis(1));

		let result2 =
			build_permit2_batch_witness_digest(&request, &config, &settlement, oracle_address);

		assert!(result1.is_ok());
		assert!(result2.is_ok());

		let (digest1, _) = result1.unwrap();
		let (digest2, _) = result2.unwrap();

		// Digests should be different due to timestamp-based nonce
		assert_ne!(
			digest1, digest2,
			"Digests should differ due to timestamp nonces"
		);
	}

	#[test]
	fn test_build_permit2_batch_witness_digest_message_format() {
		let config = create_test_config();
		let request = create_test_quote_request();
		let settlement = MockSettlementInterface::new();
		let oracle_address = parse_address("0x9999999999999999999999999999999999999999").unwrap();

		let result =
			build_permit2_batch_witness_digest(&request, &config, &settlement, oracle_address);

		assert!(result.is_ok());

		let (_digest, message_json) = result.unwrap();

		// Verify all required fields are present and properly formatted
		assert!(message_json["digest"].is_string());

		let permitted = message_json["permitted"].as_array().unwrap();
		assert_eq!(permitted.len(), 1);

		let token = permitted[0]["token"].as_str().unwrap();
		assert!(token.starts_with("0x"));
		assert_eq!(token.len(), 42); // 0x + 40 hex characters

		let amount = permitted[0]["amount"].as_str().unwrap();
		assert!(amount.parse::<u64>().is_ok());

		let spender = message_json["spender"].as_str().unwrap();
		assert!(spender.starts_with("0x"));
		assert_eq!(spender.len(), 42);

		let witness = &message_json["witness"];
		let input_oracle = witness["inputOracle"].as_str().unwrap();
		assert!(input_oracle.starts_with("0x"));
		assert_eq!(input_oracle.len(), 42);

		let outputs = witness["outputs"].as_array().unwrap();
		let output = &outputs[0];

		// Verify addresses are properly padded to 32 bytes
		let settler = output["settler"].as_str().unwrap();
		assert!(settler.starts_with("0x"));
		assert_eq!(settler.len(), 66); // 0x + 64 hex characters (32 bytes)

		let token = output["token"].as_str().unwrap();
		assert!(token.starts_with("0x"));
		assert_eq!(token.len(), 66);

		let recipient = output["recipient"].as_str().unwrap();
		assert!(recipient.starts_with("0x"));
		assert_eq!(recipient.len(), 66);
	}
}
