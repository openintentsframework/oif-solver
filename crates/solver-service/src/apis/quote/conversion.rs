//! Quote to Intent conversion utilities.
//!
//! This module provides functionality to convert stored quotes back to StandardOrder
//! and Intent formats for submission to the discovery service.

use alloy_primitives::{hex, Address, Bytes, U256};
use alloy_sol_types::sol;
use serde_json;
use solver_types::{
	api::Quote,
	current_timestamp, normalize_bytes32_address,
	standards::eip7683::{GasLimitOverrides, LockType, MandateOutput},
	standards::eip7930::InteropAddress,
	with_0x_prefix, Eip7683OrderData, Intent, IntentMetadata, QuoteError,
};

// Solidity type definitions for ABI encoding
sol! {
	/// StandardOrder for the OIF contracts
	struct StandardOrder {
		address user;
		uint256 nonce;
		uint256 originChainId;
		uint32 expires;
		uint32 fillDeadline;
		address inputOracle;
		uint256[2][] inputs;
		SolMandateOutput[] outputs;
	}

	/// MandateOutput structure
	struct SolMandateOutput {
		bytes32 oracle;
		bytes32 settler;
		uint256 chainId;
		bytes32 token;
		uint256 amount;
		bytes32 recipient;
		bytes call;
		bytes context;
	}
}

/// Rust StandardOrder structure for internal use
#[derive(Debug, Clone)]
pub struct RustStandardOrder {
	pub user: Address,
	pub nonce: U256,
	pub origin_chain_id: U256,
	pub expires: u32,
	pub fill_deadline: u32,
	pub input_oracle: Address,
	pub inputs: Vec<[U256; 2]>,
	pub outputs: Vec<MandateOutput>,
}

/// Solidity MandateOutput structure
#[derive(Debug, Clone)]
pub struct SolMandateOutput {
	pub oracle: [u8; 32],
	pub settler: [u8; 32],
	pub chain_id: U256,
	pub token: [u8; 32],
	pub amount: U256,
	pub recipient: [u8; 32],
	pub call: Bytes,
	pub context: Bytes,
}

impl From<&SolMandateOutput> for MandateOutput {
	fn from(sol_output: &SolMandateOutput) -> Self {
		Self {
			oracle: sol_output.oracle,
			settler: normalize_bytes32_address(sol_output.settler),
			chain_id: sol_output.chain_id,
			token: normalize_bytes32_address(sol_output.token),
			amount: sol_output.amount,
			recipient: normalize_bytes32_address(sol_output.recipient),
			call: sol_output.call.to_vec(),
			context: sol_output.context.to_vec(),
		}
	}
}

/// Converts quote details to RustStandardOrder
///
/// This function converts a Quote with its details into a RustStandardOrder struct
/// that can be used with the settler contracts.
pub fn quote_to_standard_order(quote: &Quote) -> Result<RustStandardOrder, QuoteError> {
	// Extract the first order from the quote (assuming single order quotes for now)
	let quote_order = quote.orders.first().ok_or_else(|| {
		QuoteError::InvalidRequest("Quote must contain at least one order".to_string())
	})?;

	// Parse the message to extract EIP-712 fields
	let message_data = quote_order.message.as_object().ok_or_else(|| {
		QuoteError::InvalidRequest("Invalid EIP-712 message structure".to_string())
	})?;

	// Navigate to the nested eip712 object
	let eip712_data = message_data
		.get("eip712")
		.and_then(|e| e.as_object())
		.ok_or_else(|| {
			QuoteError::InvalidRequest("Missing 'eip712' object in message".to_string())
		})?;

	// Extract required fields from the nested EIP-712 message
	let permitted = eip712_data
		.get("permitted")
		.and_then(|p| p.as_array())
		.ok_or_else(|| {
			QuoteError::InvalidRequest("Missing 'permitted' array in EIP-712 message".to_string())
		})?;

	let witness = eip712_data
		.get("witness")
		.and_then(|w| w.as_object())
		.ok_or_else(|| {
			QuoteError::InvalidRequest("Missing 'witness' object in EIP-712 message".to_string())
		})?;

	// Extract user from first available input
	let user_str = &quote.details.available_inputs.first().ok_or_else(|| {
		QuoteError::InvalidRequest("Quote must have at least one available input".to_string())
	})?.user;
	
	let user = parse_interop_address(&user_str.to_string())?.1; // Get address part

	// Extract nonce and deadline from EIP-712 message
	let nonce = eip712_data
		.get("nonce")
		.and_then(|n| n.as_str())
		.and_then(|s| U256::from_str_radix(s, 10).ok())
		.unwrap_or_default();

	let deadline = eip712_data
		.get("deadline")
		.and_then(|d| d.as_str())
		.and_then(|s| s.parse::<u32>().ok())
		.unwrap_or(0);

	// Extract expires from witness
	let expires = witness
		.get("expires")
		.and_then(|e| e.as_u64())
		.unwrap_or(0) as u32;

	// Extract input oracle from witness
	let input_oracle_str = witness
		.get("inputOracle")
		.and_then(|o| o.as_str())
		.unwrap_or("0x0000000000000000000000000000000000000000");
	let input_oracle = input_oracle_str.parse::<Address>().map_err(|e| {
		QuoteError::InvalidRequest(format!("Invalid input oracle address: {}", e))
	})?;

	// Build inputs array from permitted tokens
	let mut inputs = Vec::new();
	for permitted_item in permitted {
		let token_str = permitted_item
			.get("token")
			.and_then(|t| t.as_str())
			.unwrap_or("0x0000000000000000000000000000000000000000");
		let amount_str = permitted_item
			.get("amount")
			.and_then(|a| a.as_str())
			.unwrap_or("0");

		let token = token_str.parse::<Address>().map_err(|e| {
			QuoteError::InvalidRequest(format!("Invalid token address: {}", e))
		})?;
		let amount = U256::from_str_radix(amount_str, 10).map_err(|e| {
			QuoteError::InvalidRequest(format!("Invalid amount: {}", e))
		})?;

		// Convert 20-byte address to 32-byte array for U256
		let mut token_bytes = [0u8; 32];
		token_bytes[12..].copy_from_slice(token.as_slice()); // Right-pad address to 32 bytes
		inputs.push([U256::from_be_bytes(token_bytes), amount]);
	}

	// Build outputs array from witness outputs
	let default_outputs = Vec::new();
	let witness_outputs = witness
		.get("outputs")
		.and_then(|o| o.as_array())
		.unwrap_or(&default_outputs);

	let mut outputs = Vec::new();
	for output_item in witness_outputs {
		let oracle_str = output_item
			.get("oracle")
			.and_then(|o| o.as_str())
			.unwrap_or("0x0000000000000000000000000000000000000000000000000000000000000000");
		let settler_str = output_item
			.get("settler")
			.and_then(|s| s.as_str())
			.unwrap_or("0x0000000000000000000000000000000000000000000000000000000000000000");
		let chain_id = output_item
			.get("chainId")
			.and_then(|c| c.as_u64())
			.unwrap_or(0);
		let token_str = output_item
			.get("token")
			.and_then(|t| t.as_str())
			.unwrap_or("0x0000000000000000000000000000000000000000000000000000000000000000");
		let amount_str = output_item
			.get("amount")
			.and_then(|a| a.as_str())
			.unwrap_or("0");
		let recipient_str = output_item
			.get("recipient")
			.and_then(|r| r.as_str())
			.unwrap_or("0x0000000000000000000000000000000000000000000000000000000000000000");
		
		// Parse hex strings to bytes32
		let oracle = parse_bytes32(oracle_str)?;
		let settler = parse_bytes32(settler_str)?;
		let token = parse_bytes32(token_str)?;
		let recipient = parse_bytes32(recipient_str)?;
		let amount = U256::from_str_radix(amount_str, 10).map_err(|e| {
			QuoteError::InvalidRequest(format!("Invalid output amount: {}", e))
		})?;

		let call_data = output_item
			.get("call")
			.and_then(|c| c.as_str())
			.and_then(|s| hex::decode(s.strip_prefix("0x").unwrap_or(s)).ok())
			.unwrap_or_default();
		
		let context_data = output_item
			.get("context")
			.and_then(|c| c.as_str())
			.and_then(|s| hex::decode(s.strip_prefix("0x").unwrap_or(s)).ok())
			.unwrap_or_default();

		outputs.push(SolMandateOutput {
			oracle,
			settler,
			chain_id: U256::from(chain_id),
			token,
			amount,
			recipient,
			call: call_data.into(),
			context: context_data.into(),
		});
	}

	// Extract origin chain ID from first available input
	let origin_chain_id = parse_interop_address(&user_str.to_string())?.0; // Get chain ID part

	Ok(StandardOrder {
		user,
		nonce,
		origin_chain_id: U256::from(origin_chain_id),
		expires,
		fill_deadline: deadline,
		input_oracle,
		inputs,
		outputs: outputs.iter().map(MandateOutput::from).collect(),
	})
}

/// Converts a Quote and signature to an Intent for discovery service submission
pub fn quote_to_intent(quote: &Quote, signature: &str) -> Result<Intent, QuoteError> {
	let standard_order = quote_to_standard_order(quote)?;
	
	// Encode the StandardOrder to bytes (this would need alloy_sol_types integration)
	let order_bytes = encode_standard_order(&standard_order)?;
	
	// Extract user address from the first available input
	let user_str = &quote.details.available_inputs.first().ok_or_else(|| {
		QuoteError::InvalidRequest("Quote must have at least one available input".to_string())
	})?.user;
	let (_, user_address) = parse_interop_address(&user_str.to_string())?;
	
	// Determine lock type from quote (default to Permit2Escrow for now)
	let lock_type = LockType::Permit2Escrow;
	
	// Build the order data
	let order_data = Eip7683OrderData {
		user: with_0x_prefix(&hex::encode(standard_order.user)),
		nonce: standard_order.nonce,
		origin_chain_id: standard_order.origin_chain_id,
		expires: standard_order.expires,
		fill_deadline: standard_order.fill_deadline,
		input_oracle: with_0x_prefix(&hex::encode(standard_order.input_oracle)),
		inputs: standard_order.inputs,
		order_id: [0u8; 32], // Will be computed by discovery service
		gas_limit_overrides: GasLimitOverrides::default(),
		outputs: standard_order.outputs,
		raw_order_data: Some(with_0x_prefix(&hex::encode(&order_bytes))),
		signature: Some(signature.to_string()),
		sponsor: Some(user_address.to_string()),
		lock_type: Some(lock_type),
	};

	Ok(Intent {
		id: quote.quote_id.clone(), // Use quote ID as temporary intent ID
		source: "off-chain".to_string(), // Must be "off-chain" to trigger openFor
		standard: "eip7683".to_string(),
		metadata: IntentMetadata {
			requires_auction: false,
			exclusive_until: None,
			discovered_at: current_timestamp(),
		},
		data: serde_json::to_value(&order_data).map_err(|e| {
			QuoteError::Internal(format!("Failed to serialize order data: {}", e))
		})?,
		quote_id: Some(quote.quote_id.clone()),
	})
}

/// Parse EIP-7930 interop address format into components
fn parse_interop_address(interop_addr: &str) -> Result<(u64, Address), QuoteError> {
	let interop = InteropAddress::from_hex(interop_addr).map_err(|e| {
		QuoteError::InvalidRequest(format!("Invalid EIP-7930 interop address: {}", e))
	})?;

	let chain_id = interop.ethereum_chain_id().map_err(|e| {
		QuoteError::InvalidRequest(format!("Failed to extract chain ID: {}", e))
	})?;

	let address = interop.ethereum_address().map_err(|e| {
		QuoteError::InvalidRequest(format!("Failed to extract address: {}", e))
	})?;

	Ok((chain_id, address))
}

/// Parse bytes32 hex string
fn parse_bytes32(hex_str: &str) -> Result<[u8; 32], QuoteError> {
	let s = hex_str.strip_prefix("0x").unwrap_or(hex_str);
	if s.len() != 64 {
		return Err(QuoteError::InvalidRequest(format!(
			"Invalid bytes32: expected 64 hex chars, got {}",
			s.len()
		)));
	}

	let mut bytes = [0u8; 32];
	hex::decode_to_slice(s, &mut bytes).map_err(|e| {
		QuoteError::InvalidRequest(format!("Invalid hex in bytes32: {}", e))
	})?;

	Ok(bytes)
}

/// Encode StandardOrder to bytes using alloy_sol_types
pub fn encode_standard_order(order: &StandardOrder) -> Result<Vec<u8>, QuoteError> {
	// Convert MandateOutput to SolMandateOutput for ABI encoding
	let sol_outputs: Vec<SolMandateOutput> = order.outputs
		.iter()
		.map(|output| {
			SolMandateOutput {
				oracle: output.oracle,
				settler: output.settler,
				chain_id: U256::from(output.chain_id),
				token: output.token,
				amount: U256::from(output.amount),
				recipient: output.recipient,
				call: output.call.clone().into(),
				context: output.context.clone().into(),
			}
		})
		.collect();

	// Create the Solidity StandardOrder struct
	let sol_order = StandardOrder {
		user: order.user,
		nonce: order.nonce,
		originChainId: order.origin_chain_id,
		expires: order.expires,
		fillDeadline: order.fill_deadline,
		inputOracle: order.input_oracle,
		inputs: order.inputs.clone(),
		outputs: sol_outputs,
	};

	// ABI encode the StandardOrder
	Ok(sol_order.abi_encode())
}