//! EIP-7683 Cross-Chain Order Types
//!
//! This module defines the data structures for EIP-7683 cross-chain orders
//! that are shared across the solver system. Updated to match the new OIF
//! contracts structure with StandardOrder and MandateOutput types.

use alloy_primitives::U256;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Type alias for EIP-712 data extraction result
type Eip712ExtractionResult<'a> = Result<(&'a serde_json::Map<String, serde_json::Value>, &'a str), Box<dyn std::error::Error>>;

/// Lock type for cross-chain orders, determining the custody mechanism used.
///
/// This enum represents the different ways user funds can be locked/held
/// during the cross-chain order lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LockType {
	/// Permit2-based escrow mechanism
	/// Uses Permit2 signatures for gasless token approvals
	#[serde(rename = "permit2_escrow")]
	#[default]
	Permit2Escrow = 1,
	/// EIP-3009 based escrow mechanism  
	/// Uses transferWithAuthorization for gasless transfers
	#[serde(rename = "eip3009_escrow")]
	Eip3009Escrow = 2,
	/// Resource lock mechanism (The Compact)
	/// Uses TheCompact protocol for resource locking
	#[serde(rename = "compact_resource_lock")]
	ResourceLock = 3,
}

impl LockType {
	/// Convert from u8 representation for backward compatibility
	pub fn from_u8(value: u8) -> Option<Self> {
		match value {
			1 => Some(LockType::Permit2Escrow),
			2 => Some(LockType::Eip3009Escrow),
			3 => Some(LockType::ResourceLock),
			_ => None,
		}
	}

	/// Convert to u8 representation for backward compatibility
	pub fn to_u8(self) -> u8 {
		self as u8
	}

	/// Returns true if this lock type uses compact settlement
	pub fn is_compact(&self) -> bool {
		matches!(self, LockType::ResourceLock)
	}

	/// Returns true if this lock type uses escrow settlement
	pub fn is_escrow(&self) -> bool {
		matches!(self, LockType::Permit2Escrow | LockType::Eip3009Escrow)
	}

	/// Get the string representation for this lock type
	pub fn as_str(&self) -> &'static str {
		match self {
			LockType::Permit2Escrow => "permit2_escrow",
			LockType::Eip3009Escrow => "eip3009_escrow",
			LockType::ResourceLock => "compact_resource_lock",
		}
	}
}

impl FromStr for LockType {
	type Err = String;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			// String representations
			"permit2_escrow" => Ok(LockType::Permit2Escrow),
			"eip3009_escrow" => Ok(LockType::Eip3009Escrow),
			"compact_resource_lock" => Ok(LockType::ResourceLock),
			// Numeric string representations
			"1" => Ok(LockType::Permit2Escrow),
			"2" => Ok(LockType::Eip3009Escrow),
			"3" => Ok(LockType::ResourceLock),
			_ => Err(format!("Invalid lock type: {}", s)),
		}
	}
}

impl std::fmt::Display for LockType {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.as_str())
	}
}
/// Gas limit overrides for various transaction types
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct GasLimitOverrides {
	/// Gas limit for settlement transaction
	#[serde(skip_serializing_if = "Option::is_none")]
	pub settle_gas_limit: Option<u64>,
	/// Gas limit for fill transaction
	#[serde(skip_serializing_if = "Option::is_none")]
	pub fill_gas_limit: Option<u64>,
	/// Gas limit for prepare transaction
	#[serde(skip_serializing_if = "Option::is_none")]
	pub prepare_gas_limit: Option<u64>,
}

/// EIP-7683 specific order data structure.
///
/// Contains all the necessary information for processing a cross-chain order
/// based on the StandardOrder format from the OIF contracts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip7683OrderData {
	/// The address of the user initiating the cross-chain order
	pub user: String,
	/// Unique nonce to prevent order replay attacks
	pub nonce: U256,
	/// Chain ID where the order originates
	pub origin_chain_id: U256,
	/// Unix timestamp when the order expires
	pub expires: u32,
	/// Deadline by which the order must be filled
	pub fill_deadline: u32,
	/// Address of the oracle responsible for validating fills
	pub input_oracle: String,
	/// Input tokens and amounts as tuples of [token_address, amount]
	/// Format: Vec<[token_as_U256, amount_as_U256]>
	pub inputs: Vec<[U256; 2]>,
	/// Unique 32-byte identifier for the order
	pub order_id: [u8; 32],
	/// Gas limit overrides for transaction execution
	pub gas_limit_overrides: GasLimitOverrides,
	/// List of outputs specifying tokens, amounts, and recipients
	pub outputs: Vec<MandateOutput>,
	/// Optional raw order data (StandardOrder encoded as bytes)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub raw_order_data: Option<String>,
	/// Optional signature for off-chain order validation (Permit2Witness signature)
	#[serde(skip_serializing_if = "Option::is_none")]
	pub signature: Option<String>,
	/// Optional sponsor address for off-chain orders
	#[serde(skip_serializing_if = "Option::is_none")]
	pub sponsor: Option<String>,
	/// Optional lock type determining the custody mechanism
	#[serde(skip_serializing_if = "Option::is_none")]
	pub lock_type: Option<LockType>,
}

/// Represents a MandateOutput of the OIF contracts.
///
/// Outputs define the tokens and amounts that should be received by recipients
/// as a result of executing the cross-chain order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MandateOutput {
	/// Oracle implementation responsible for collecting proof (bytes32)
	/// Zero value indicates same-chain or default oracle
	pub oracle: [u8; 32],
	/// Output Settler on the output chain responsible for settling (bytes32)
	pub settler: [u8; 32],
	/// The chain ID where the output should be delivered
	pub chain_id: U256,
	/// The token to be received (bytes32 - padded address)
	pub token: [u8; 32],
	/// The amount of tokens to be received
	pub amount: U256,
	/// The recipient that should receive the tokens (bytes32 - padded address)
	pub recipient: [u8; 32],
	/// Data delivered to recipient through settlement callback
	#[serde(with = "hex_string")]
	pub call: Vec<u8>,
	/// Additional output context for settlement
	#[serde(with = "hex_string")]
	pub context: Vec<u8>,
}

/// Alias for backward compatibility
pub type Output = MandateOutput;

#[cfg(feature = "oif-interfaces")]
use crate::api::{Quote, QuoteParsable};
use crate::order::OrderParsable;
use crate::standards::eip7930::InteropAddress;
use crate::{
	bytes32_to_address, parse_address, with_0x_prefix, Address, AvailableInput, RequestedOutput,
};

#[cfg(feature = "oif-interfaces")]
use crate::{Order, OrderStatus};

/// Implementation of OrderParsable for EIP-7683 orders
impl OrderParsable for Eip7683OrderData {
	fn parse_available_inputs(&self) -> Vec<AvailableInput> {
		let origin_chain = self.origin_chain_id.try_into().unwrap_or(1);

		self.inputs
			.iter()
			.map(|input| {
				// input is [token_address, amount] as [U256; 2]
				let token_u256_bytes = input[0].to_be_bytes::<32>();
				let token_address_hex = bytes32_to_address(&token_u256_bytes);
				let token_addr =
					parse_address(&token_address_hex).unwrap_or(Address(vec![0u8; 20]));

				// Create interop addresses
				let asset = InteropAddress::from((origin_chain, token_addr));

				let user_addr = parse_address(&self.user).unwrap_or(Address(vec![0u8; 20]));
				let user = InteropAddress::from((origin_chain, user_addr));

				AvailableInput {
					user,
					asset,
					amount: input[1],
					lock: None, // EIP-7683 doesn't specify lock info in inputs
				}
			})
			.collect()
	}

	fn parse_requested_outputs(&self) -> Vec<RequestedOutput> {
		self.outputs
			.iter()
			.map(|output| {
				// Get chain ID from the output
				let chain_id = output.chain_id.try_into().unwrap_or(1);

				// Convert bytes32 token address to hex string and then Address
				let token_address_hex = bytes32_to_address(&output.token);
				let token_addr =
					parse_address(&token_address_hex).unwrap_or(Address(vec![0u8; 20]));

				// Convert bytes32 recipient address to hex string and then Address
				let recipient_address_hex = bytes32_to_address(&output.recipient);
				let recipient_addr =
					parse_address(&recipient_address_hex).unwrap_or(Address(vec![0u8; 20]));

				// Create interop addresses
				let asset = InteropAddress::from((chain_id, token_addr));
				let receiver = InteropAddress::from((chain_id, recipient_addr));

				RequestedOutput {
					receiver,
					asset,
					amount: output.amount,
					calldata: if output.call.is_empty() {
						None
					} else {
						Some(with_0x_prefix(&hex::encode(&output.call)))
					},
				}
			})
			.collect()
	}

	fn parse_lock_type(&self) -> Option<String> {
		self.lock_type.map(|lt| lt.as_str().to_string())
	}

	fn origin_chain_id(&self) -> u64 {
		self.origin_chain_id.try_into().unwrap_or(1)
	}

	fn destination_chain_ids(&self) -> Vec<u64> {
		self.outputs
			.iter()
			.map(|output| output.chain_id.try_into().unwrap_or(1))
			.collect()
	}
}

/// Hex string serialization helper
mod hex_string {
	use crate::with_0x_prefix;
	use serde::{Deserialize, Deserializer, Serializer};

	pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&with_0x_prefix(&hex::encode(bytes)))
	}

	pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
	where
		D: Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		let s = s.strip_prefix("0x").unwrap_or(&s);
		hex::decode(s).map_err(serde::de::Error::custom)
	}
}

// Solidity struct definitions for ABI encoding with OIF contracts
#[cfg(feature = "oif-interfaces")]
#[allow(clippy::too_many_arguments)]
pub mod interfaces {
	use alloy_sol_types::sol;

	sol! {
		/// StandardOrder for the OIF contracts (used for ABI encoding)
		#[derive(Debug)]
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

		/// MandateOutput for the OIF contracts (used for ABI encoding)
		#[derive(Debug)]
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

		/// Solve parameters combining timestamp and solver.
		struct SolveParams {
			uint32 timestamp;
			bytes32 solver;
		}

		/// IInputSettlerEscrow interface for the OIF contracts.
		#[sol(rpc)]
		interface IInputSettlerEscrow {
			function finalise(StandardOrder calldata order, SolveParams[] calldata solveParams, bytes32 destination, bytes calldata call) external;
			function finaliseWithSignature(StandardOrder calldata order, SolveParams[] calldata solveParams, bytes32 destination, bytes calldata call, bytes calldata signature) external;
			function open(StandardOrder calldata order) external;
			function openFor(StandardOrder calldata order, address sponsor, bytes calldata signature) external;
			function orderIdentifier(StandardOrder calldata order) external view returns (bytes32);
		}

		/// IInputSettlerCompact interface for Compact-based settlement.
		#[sol(rpc)]
		interface IInputSettlerCompact {
			function finalise(StandardOrder calldata order, bytes calldata signatures, SolveParams[] calldata solveParams, bytes32 destination, bytes calldata call) external;
			function finaliseWithSignature(StandardOrder calldata order, bytes calldata signatures, SolveParams[] calldata solveParams, bytes32 destination, bytes calldata call, bytes calldata orderOwnerSignature) external;
			function orderIdentifier(StandardOrder calldata order) external view returns (bytes32);
		}

		/// OutputSettlerSimple interface for filling orders.
		interface IOutputSettlerSimple {
			function fill(bytes32 orderId, SolMandateOutput calldata output, uint48 fillDeadline, bytes calldata fillerData) external returns (bytes32);
			function fillOrderOutputs(bytes32 orderId, SolMandateOutput[] calldata outputs, bytes calldata fillerData) external;
		}

		/// TheCompact contract interface for domain separator fetching.
		#[sol(rpc)]
		interface ITheCompact {
			function DOMAIN_SEPARATOR() external view returns (bytes32);
		}
	}
}

/// Convert Quote to StandardOrder
#[cfg(feature = "oif-interfaces")]
impl TryFrom<&Quote> for interfaces::StandardOrder {
	type Error = Box<dyn std::error::Error>;

	fn try_from(quote: &Quote) -> Result<Self, Self::Error> {
		use crate::standards::eip7930::InteropAddress;
		use crate::utils::parse_bytes32_from_hex;
		use alloy_primitives::{Address, U256};
		use interfaces::SolMandateOutput;

		// Extract user address from the first available input
		let user_str = &quote
			.details
			.available_inputs
			.first()
			.ok_or("Quote must have at least one available input")?
			.user;
		let interop_address = InteropAddress::from_hex(&user_str.to_string())?;
		let user_address = interop_address.ethereum_address()?;

		// Extract order data from quote
		let quote_order = quote
			.orders
			.first()
			.ok_or("Quote must contain at least one order")?;
		let message_data = quote_order
			.message
			.as_object()
			.ok_or("Invalid EIP-712 message structure")?;
		let eip712_data = message_data
			.get("eip712")
			.and_then(|e| e.as_object())
			.ok_or("Missing 'eip712' object in message")?;

		// Extract nonce
		let nonce_str = eip712_data
			.get("nonce")
			.and_then(|n| n.as_str())
			.ok_or("Missing nonce in EIP-712 data")?;
		let nonce = U256::from_str_radix(nonce_str, 10)?;

		// Extract witness data
		let witness = eip712_data
			.get("witness")
			.and_then(|w| w.as_object())
			.ok_or("Missing 'witness' object in EIP-712 message")?;

		// Get origin chain ID
		let origin_chain_id = U256::from(interop_address.ethereum_chain_id()?);

		// Extract timing data
		let expires = witness
			.get("expires")
			.and_then(|e| e.as_u64())
			.unwrap_or(quote.valid_until.unwrap_or(0)) as u32;
		let fill_deadline = expires;

		// Extract input oracle
		let input_oracle_str = witness
			.get("inputOracle")
			.and_then(|o| o.as_str())
			.ok_or("Missing 'inputOracle' in witness data")?;
		let input_oracle =
			Address::from_slice(&hex::decode(input_oracle_str.trim_start_matches("0x"))?);

		// Extract input data from permitted array
		let permitted = eip712_data
			.get("permitted")
			.and_then(|p| p.as_array())
			.ok_or("Missing permitted array in EIP-712 data")?;
		let first_permitted = permitted
			.first()
			.ok_or("Empty permitted array in EIP-712 data")?;

		let input_amount_str = first_permitted
			.get("amount")
			.and_then(|a| a.as_str())
			.ok_or("Missing amount in permitted token")?;
		let input_amount = U256::from_str_radix(input_amount_str, 10)?;

		let input_token_str = first_permitted
			.get("token")
			.and_then(|t| t.as_str())
			.ok_or("Missing token in permitted array")?;
		let input_token =
			Address::from_slice(&hex::decode(input_token_str.trim_start_matches("0x"))?);

		// Convert input token address to U256
		let mut token_bytes = [0u8; 32];
		token_bytes[12..32].copy_from_slice(&input_token.0 .0);
		let input_token_u256 = U256::from_be_bytes(token_bytes);
		let inputs = vec![[input_token_u256, input_amount]];

		// Extract outputs from witness
		let default_outputs = Vec::new();
		let witness_outputs = witness
			.get("outputs")
			.and_then(|o| o.as_array())
			.unwrap_or(&default_outputs);

		// Parse outputs
		let mut sol_outputs = Vec::new();
		for output_item in witness_outputs {
			if let Some(output_obj) = output_item.as_object() {
				let chain_id = output_obj
					.get("chainId")
					.and_then(|c| c.as_u64())
					.unwrap_or(0);
				let amount_str = output_obj
					.get("amount")
					.and_then(|a| a.as_str())
					.unwrap_or("0");
				let token_str = output_obj.get("token").and_then(|t| t.as_str()).unwrap();
				let recipient_str = output_obj
					.get("recipient")
					.and_then(|r| r.as_str())
					.unwrap();
				let oracle_str = output_obj.get("oracle").and_then(|o| o.as_str()).unwrap();
				let settler_str = output_obj.get("settler").and_then(|s| s.as_str()).unwrap();

				if let Ok(amount) = U256::from_str_radix(amount_str, 10) {
					let token_bytes = parse_bytes32_from_hex(token_str).unwrap_or([0u8; 32]);
					let recipient_bytes =
						parse_bytes32_from_hex(recipient_str).unwrap_or([0u8; 32]);
					let oracle_bytes = parse_bytes32_from_hex(oracle_str).unwrap_or([0u8; 32]);
					let settler_bytes = parse_bytes32_from_hex(settler_str).unwrap_or([0u8; 32]);

					sol_outputs.push(SolMandateOutput {
						oracle: oracle_bytes.into(),
						settler: settler_bytes.into(),
						chainId: U256::from(chain_id),
						token: token_bytes.into(),
						amount,
						recipient: recipient_bytes.into(),
						call: Vec::new().into(),
						context: Vec::new().into(),
					});
				}
			}
		}

		// Create the StandardOrder
		Ok(interfaces::StandardOrder {
			user: user_address,
			nonce,
			originChainId: origin_chain_id,
			expires,
			fillDeadline: fill_deadline,
			inputOracle: input_oracle,
			inputs,
			outputs: sol_outputs,
		})
	}
}

/// Helper functions for BatchCompact quote processing
#[cfg(feature = "oif-interfaces")]
impl Eip7683OrderData {
	/// Extract and validate EIP-712 data from quote to detect order type
	fn extract_eip712_data(
		quote: &Quote,
	) -> Eip712ExtractionResult<'_> {
		let quote_order = quote
			.orders
			.first()
			.ok_or("Quote must contain at least one order")?;
		let message_data = quote_order
			.message
			.as_object()
			.ok_or("Invalid EIP-712 message structure")?;
		let eip712_data = message_data
			.get("eip712")
			.and_then(|e| e.as_object())
			.ok_or("Missing 'eip712' object in message")?;

		let primary_type = eip712_data
			.get("primaryType")
			.and_then(|p| p.as_str())
			.unwrap_or("PermitBatchWitnessTransferFrom");

		Ok((eip712_data, primary_type))
	}

	/// Handle BatchCompact order conversion for cost estimation
	fn handle_batch_compact_quote_conversion(
		quote: &Quote,
		eip712_data: &serde_json::Map<String, serde_json::Value>,
	) -> Result<interfaces::StandardOrder, Box<dyn std::error::Error>> {
		use crate::standards::eip7683::interfaces::{SolMandateOutput, StandardOrder};
		use crate::standards::eip7930::InteropAddress;
		use crate::utils::parse_bytes32_from_hex;
		use alloy_primitives::{Address, U256};

		// Extract user address from quote
		let user_str = &quote
			.details
			.available_inputs
			.first()
			.ok_or("Quote must have at least one available input")?
			.user;
		let interop_address = InteropAddress::from_hex(&user_str.to_string())?;
		let user_address = interop_address.ethereum_address()?;
		let origin_chain_id = U256::from(interop_address.ethereum_chain_id()?);

		let message = eip712_data
			.get("message")
			.and_then(|m| m.as_object())
			.ok_or("Missing 'message' object in BatchCompact EIP-712 data")?;

		// Extract nonce from BatchCompact message
		let nonce_str = message
			.get("nonce")
			.and_then(|n| n.as_str())
			.ok_or("Missing nonce in BatchCompact message")?;
		let nonce = U256::from_str_radix(nonce_str, 10)?;

		let mandate = message
			.get("mandate")
			.and_then(|m| m.as_object())
			.ok_or("Missing 'mandate' object in BatchCompact message")?;

		let expires_str = message
			.get("expires")
			.and_then(|e| e.as_str())
			.ok_or("Missing 'expires' in BatchCompact message")?;
		let expires = expires_str
			.parse::<u64>()
			.map_err(|e| format!("Invalid expires: {}", e))? as u32;

		let fill_deadline_str = mandate
			.get("fillDeadline")
			.and_then(|f| f.as_str())
			.ok_or("Missing 'fillDeadline' in mandate")?;
		let fill_deadline = fill_deadline_str
			.parse::<u64>()
			.map_err(|e| format!("Invalid fillDeadline: {}", e))? as u32;

		let input_oracle_str = mandate
			.get("inputOracle")
			.and_then(|o| o.as_str())
			.ok_or("Missing 'inputOracle' in mandate")?;
		let input_oracle =
			Address::from_slice(&hex::decode(input_oracle_str.trim_start_matches("0x"))?);

		// Extract from commitments array
		let commitments = message
			.get("commitments")
			.and_then(|c| c.as_array())
			.ok_or("Missing commitments array in BatchCompact message")?;
		let first_commitment = commitments
			.first()
			.ok_or("Empty commitments array in BatchCompact message")?;

		let input_amount_str = first_commitment
			.get("amount")
			.and_then(|a| a.as_str())
			.ok_or("Missing amount in commitment")?;
		let input_amount = U256::from_str_radix(input_amount_str, 10)?;

		let input_token_str = first_commitment
			.get("token")
			.and_then(|t| t.as_str())
			.ok_or("Missing token in commitment")?;
		let input_token =
			Address::from_slice(&hex::decode(input_token_str.trim_start_matches("0x"))?);

		// For BatchCompact, build TOKEN_ID = lockTag (12 bytes) + token address (20 bytes)
		let lock_tag_str = first_commitment
			.get("lockTag")
			.and_then(|t| t.as_str())
			.ok_or("Missing lockTag in commitment")?;
		let lock_tag_hex = lock_tag_str.trim_start_matches("0x");
		let token_hex = hex::encode(input_token.0 .0);
		let token_id_hex = format!("{}{}", lock_tag_hex, token_hex);
		let input_token_u256 = U256::from_str_radix(&token_id_hex, 16)
			.map_err(|e| format!("Failed to parse TOKEN_ID: {}", e))?;

		let inputs = vec![[input_token_u256, input_amount]];

		// Extract outputs from mandate
		let outputs_value = mandate.get("outputs").ok_or("Missing outputs in mandate")?;
		let mut sol_outputs = Vec::new();

		if let Some(outputs_array) = outputs_value.as_array() {
			for output_item in outputs_array {
				if let Some(output_obj) = output_item.as_object() {
					let chain_id = output_obj
						.get("chainId")
						.and_then(|c| {
							if let Some(s) = c.as_str() {
								s.parse::<u64>().ok()
							} else {
								c.as_u64()
							}
						})
						.unwrap_or(0);
					let amount_str = output_obj
						.get("amount")
						.and_then(|a| a.as_str())
						.unwrap_or("0");
					let token_str = output_obj.get("token").and_then(|t| t.as_str()).unwrap();
					let recipient_str = output_obj
						.get("recipient")
						.and_then(|r| r.as_str())
						.unwrap();
					let oracle_str = output_obj.get("oracle").and_then(|o| o.as_str()).unwrap();
					let settler_str = output_obj.get("settler").and_then(|s| s.as_str()).unwrap();

					if let Ok(amount) = U256::from_str_radix(amount_str, 10) {
						let token_bytes = parse_bytes32_from_hex(token_str).unwrap_or([0u8; 32]);
						let recipient_bytes =
							parse_bytes32_from_hex(recipient_str).unwrap_or([0u8; 32]);
						let oracle_bytes = parse_bytes32_from_hex(oracle_str).unwrap_or([0u8; 32]);
						let settler_bytes =
							parse_bytes32_from_hex(settler_str).unwrap_or([0u8; 32]);

						sol_outputs.push(SolMandateOutput {
							oracle: oracle_bytes.into(),
							settler: settler_bytes.into(),
							chainId: U256::from(chain_id),
							token: token_bytes.into(),
							amount,
							recipient: recipient_bytes.into(),
							call: Vec::new().into(),
							context: Vec::new().into(),
						});
					}
				}
			}
		}

		Ok(StandardOrder {
			user: user_address,
			nonce,
			originChainId: origin_chain_id,
			expires,
			fillDeadline: fill_deadline,
			inputOracle: input_oracle,
			inputs,
			outputs: sol_outputs,
		})
	}
}

/// Implementation of QuoteParsable for EIP-7683 orders
#[cfg(feature = "oif-interfaces")]
impl QuoteParsable for Eip7683OrderData {
	fn quote_to_order_for_estimation(quote: &Quote) -> Order {
		use std::convert::TryFrom;

		// Detect order type from EIP-712 data to handle BatchCompact properly
		let standard_order =
			if let Ok((eip712_data, primary_type)) = Eip7683OrderData::extract_eip712_data(quote) {
				if primary_type == "BatchCompact" {
					// Handle BatchCompact orders using specialized parsing
					Eip7683OrderData::handle_batch_compact_quote_conversion(quote, eip712_data)
						.expect("Failed to convert BatchCompact quote to StandardOrder")
				} else {
					// Handle Permit2/EIP3009 orders using existing implementation
					interfaces::StandardOrder::try_from(quote)
						.expect("Failed to convert quote to StandardOrder")
				}
			} else {
				// Fallback to existing implementation if detection fails
				interfaces::StandardOrder::try_from(quote)
					.expect("Failed to convert quote to StandardOrder")
			};

		// Convert StandardOrder to Eip7683OrderData
		let mut order_data = Eip7683OrderData::from(standard_order.clone());

		// Add the lock type from the quote
		let lock_type = quote
			.lock_type
			.parse::<LockType>()
			.unwrap_or_else(|_| LockType::default());
		order_data.lock_type = Some(lock_type);

		// Extract chain IDs for the Order
		let input_chain_ids = vec![order_data.origin_chain_id.try_into().unwrap_or(1)];
		let output_chain_ids: Vec<u64> = order_data
			.outputs
			.iter()
			.map(|output| output.chain_id.try_into().unwrap_or(1))
			.collect();

		Order {
			// Use a clearly marked estimation-only ID
			id: format!("ESTIMATION_ONLY_quote_{}", quote.quote_id),
			standard: "eip7683".to_string(), // Use real standard for proper processing
			created_at: crate::current_timestamp(),
			updated_at: crate::current_timestamp(),
			status: OrderStatus::Created,
			data: serde_json::to_value(&order_data).unwrap_or(serde_json::Value::Null),
			solver_address: Address(vec![0u8; 20]), // Dummy address
			quote_id: Some(quote.quote_id.clone()),
			input_chain_ids,
			output_chain_ids,
			execution_params: None,
			prepare_tx_hash: None,
			fill_tx_hash: None,
			post_fill_tx_hash: None,
			pre_claim_tx_hash: None,
			claim_tx_hash: None,
			fill_proof: None,
		}
	}
}

/// Convert SolMandateOutput to MandateOutput
#[cfg(feature = "oif-interfaces")]
impl From<interfaces::SolMandateOutput> for MandateOutput {
	fn from(output: interfaces::SolMandateOutput) -> Self {
		MandateOutput {
			oracle: output.oracle.0,
			settler: output.settler.0,
			chain_id: output.chainId,
			token: output.token.0,
			amount: output.amount,
			recipient: output.recipient.0,
			call: output.call.to_vec(),
			context: output.context.to_vec(),
		}
	}
}

/// Convert MandateOutput to SolMandateOutput
#[cfg(feature = "oif-interfaces")]
impl From<MandateOutput> for interfaces::SolMandateOutput {
	fn from(output: MandateOutput) -> Self {
		use alloy_primitives::FixedBytes;
		interfaces::SolMandateOutput {
			oracle: FixedBytes::<32>::from(output.oracle),
			settler: FixedBytes::<32>::from(output.settler),
			chainId: output.chain_id,
			token: FixedBytes::<32>::from(output.token),
			amount: output.amount,
			recipient: FixedBytes::<32>::from(output.recipient),
			call: output.call.into(),
			context: output.context.into(),
		}
	}
}

/// Implement conversion from StandardOrder to Eip7683OrderData
#[cfg(feature = "oif-interfaces")]
impl From<interfaces::StandardOrder> for Eip7683OrderData {
	fn from(order: interfaces::StandardOrder) -> Self {
		use crate::utils::with_0x_prefix;
		use alloy_primitives::hex;

		// Convert outputs from SolMandateOutput to MandateOutput using From trait
		let outputs = order.outputs.into_iter().map(Into::into).collect();

		Eip7683OrderData {
			user: with_0x_prefix(&hex::encode(order.user)),
			nonce: order.nonce,
			origin_chain_id: order.originChainId,
			expires: order.expires,
			fill_deadline: order.fillDeadline,
			input_oracle: with_0x_prefix(&hex::encode(order.inputOracle)),
			inputs: order.inputs,
			order_id: [0u8; 32], // Will be computed separately
			gas_limit_overrides: GasLimitOverrides::default(),
			outputs,
			raw_order_data: None,
			signature: None,
			sponsor: None,
			lock_type: None,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::utils::tests::builders::{Eip7683OrderDataBuilder, MandateOutputBuilder};
	use alloy_primitives::U256;
	use serde_json;

	#[test]
	fn test_lock_type_default() {
		let lock_type = LockType::default();
		assert_eq!(lock_type, LockType::Permit2Escrow);
	}

	#[test]
	fn test_lock_type_from_u8() {
		assert_eq!(LockType::from_u8(1), Some(LockType::Permit2Escrow));
		assert_eq!(LockType::from_u8(2), Some(LockType::Eip3009Escrow));
		assert_eq!(LockType::from_u8(3), Some(LockType::ResourceLock));
		assert_eq!(LockType::from_u8(0), None);
		assert_eq!(LockType::from_u8(4), None);
		assert_eq!(LockType::from_u8(255), None);
	}

	#[test]
	fn test_lock_type_to_u8() {
		assert_eq!(LockType::Permit2Escrow.to_u8(), 1);
		assert_eq!(LockType::Eip3009Escrow.to_u8(), 2);
		assert_eq!(LockType::ResourceLock.to_u8(), 3);
	}

	#[test]
	fn test_lock_type_is_compact() {
		assert!(!LockType::Permit2Escrow.is_compact());
		assert!(!LockType::Eip3009Escrow.is_compact());
		assert!(LockType::ResourceLock.is_compact());
	}

	#[test]
	fn test_lock_type_is_escrow() {
		assert!(LockType::Permit2Escrow.is_escrow());
		assert!(LockType::Eip3009Escrow.is_escrow());
		assert!(!LockType::ResourceLock.is_escrow());
	}

	#[test]
	fn test_lock_type_serialization() {
		let permit2 = LockType::Permit2Escrow;
		let json = serde_json::to_string(&permit2).unwrap();
		assert_eq!(json, "\"permit2_escrow\"");

		let eip3009 = LockType::Eip3009Escrow;
		let json = serde_json::to_string(&eip3009).unwrap();
		assert_eq!(json, "\"eip3009_escrow\"");

		let resource_lock = LockType::ResourceLock;
		let json = serde_json::to_string(&resource_lock).unwrap();
		assert_eq!(json, "\"compact_resource_lock\"");
	}

	#[test]
	fn test_lock_type_deserialization() {
		let permit2: LockType = serde_json::from_str("\"permit2_escrow\"").unwrap();
		assert_eq!(permit2, LockType::Permit2Escrow);

		let eip3009: LockType = serde_json::from_str("\"eip3009_escrow\"").unwrap();
		assert_eq!(eip3009, LockType::Eip3009Escrow);

		let resource_lock: LockType = serde_json::from_str("\"compact_resource_lock\"").unwrap();
		assert_eq!(resource_lock, LockType::ResourceLock);
	}

	#[test]
	fn test_gas_limit_overrides_default() {
		let overrides = GasLimitOverrides::default();
		assert_eq!(overrides.settle_gas_limit, None);
		assert_eq!(overrides.fill_gas_limit, None);
		assert_eq!(overrides.prepare_gas_limit, None);
	}

	#[test]
	fn test_gas_limit_overrides_serialization_empty() {
		let overrides = GasLimitOverrides::default();
		let json = serde_json::to_string(&overrides).unwrap();
		assert_eq!(json, "{}");
	}

	#[test]
	fn test_gas_limit_overrides_serialization_with_values() {
		let overrides = GasLimitOverrides {
			settle_gas_limit: Some(100000),
			fill_gas_limit: Some(200000),
			prepare_gas_limit: None,
		};
		let json = serde_json::to_string(&overrides).unwrap();
		let expected = r#"{"settle_gas_limit":100000,"fill_gas_limit":200000}"#;
		assert_eq!(json, expected);
	}

	#[test]
	fn test_gas_limit_overrides_deserialization() {
		let json = r#"{"settle_gas_limit":100000,"fill_gas_limit":200000}"#;
		let overrides: GasLimitOverrides = serde_json::from_str(json).unwrap();
		assert_eq!(overrides.settle_gas_limit, Some(100000));
		assert_eq!(overrides.fill_gas_limit, Some(200000));
		assert_eq!(overrides.prepare_gas_limit, None);
	}

	#[test]
	fn test_mandate_output_serialization() {
		let output = MandateOutputBuilder::new()
			.oracle([1u8; 32])
			.settler([2u8; 32])
			.chain_id(U256::from(1))
			.token([3u8; 32])
			.amount(U256::from(1000))
			.recipient([4u8; 32])
			.call(vec![0xab, 0xcd])
			.context(vec![0x12, 0x34])
			.build();

		let json = serde_json::to_string(&output).unwrap();
		assert!(json.contains("\"call\":\"0xabcd\""));
		assert!(json.contains("\"context\":\"0x1234\""));
	}

	#[test]
	fn test_mandate_output_deserialization_with_0x_prefix() {
		let json = r#"{
			"oracle": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
			"settler": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
			"chain_id": "1",
			"token": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
			"amount": "1000",
			"recipient": [4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4],
			"call": "0xabcd",
			"context": "0x1234"
		}"#;

		let output: MandateOutput = serde_json::from_str(json).unwrap();
		assert_eq!(output.call, vec![0xab, 0xcd]);
		assert_eq!(output.context, vec![0x12, 0x34]);
	}

	#[test]
	fn test_mandate_output_deserialization_without_0x_prefix() {
		let json = r#"{
			"oracle": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
			"settler": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
			"chain_id": "1",
			"token": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
			"amount": "1000",
			"recipient": [4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4],
			"call": "abcd",
			"context": "1234"
		}"#;

		let output: MandateOutput = serde_json::from_str(json).unwrap();
		assert_eq!(output.call, vec![0xab, 0xcd]);
		assert_eq!(output.context, vec![0x12, 0x34]);
	}

	#[test]
	fn test_mandate_output_empty_hex_fields() {
		let output = MandateOutputBuilder::new()
			.oracle([0u8; 32])
			.settler([0u8; 32])
			.chain_id(U256::from(1))
			.token([0u8; 32])
			.amount(U256::from(0))
			.recipient([0u8; 32])
			.build();

		let json = serde_json::to_string(&output).unwrap();
		assert!(json.contains("\"call\":\"0x\""));
		assert!(json.contains("\"context\":\"0x\""));

		// Test round-trip
		let deserialized: MandateOutput = serde_json::from_str(&json).unwrap();
		assert_eq!(deserialized.call, Vec::<u8>::new());
		assert_eq!(deserialized.context, Vec::<u8>::new());
	}

	#[test]
	fn test_eip7683_order_data_serialization() {
		let output = MandateOutputBuilder::new()
			.oracle([1u8; 32])
			.settler([2u8; 32])
			.chain_id(U256::from(1))
			.token([3u8; 32])
			.amount(U256::from(1000))
			.recipient([4u8; 32])
			.call(vec![0xab, 0xcd])
			.context(vec![0x12, 0x34])
			.build();

		let order = Eip7683OrderDataBuilder::new()
			.user("0x1234567890123456789012345678901234567890")
			.nonce(U256::from(123))
			.origin_chain_id(U256::from(1))
			.expires(1234567890)
			.fill_deadline(1234567900)
			.input_oracle("0xoracle123")
			.add_input(U256::from(1), U256::from(1000))
			.order_id([5u8; 32])
			.add_output(output)
			.raw_order_data("0xrawdata")
			.signature("0xsignature")
			.lock_type(LockType::Permit2Escrow)
			.build();

		let json = serde_json::to_string(&order).unwrap();
		assert!(json.contains("\"user\":"));
		assert!(json.contains("\"raw_order_data\":\"0xrawdata\""));
		assert!(json.contains("\"signature\":\"0xsignature\""));
		assert!(json.contains("\"lock_type\":\"permit2_escrow\""));
		assert!(!json.contains("\"sponsor\":")); // Should be omitted when None
	}

	#[test]
	fn test_eip7683_order_data_deserialization() {
		let json = r#"{
			"user": "0x1234567890123456789012345678901234567890",
			"nonce": "123",
			"origin_chain_id": "1",
			"expires": 1234567890,
			"fill_deadline": 1234567900,
			"input_oracle": "0xoracle123",
			"inputs": [["1", "1000"]],
			"order_id": [5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5],
			"gas_limit_overrides": {},
			"outputs": [{
				"oracle": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
				"settler": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
				"chain_id": "1",
				"token": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
				"amount": "1000",
				"recipient": [4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4],
				"call": "0xabcd",
				"context": "0x1234"
			}]
		}"#;

		let order: Eip7683OrderData = serde_json::from_str(json).unwrap();
		assert_eq!(order.user, "0x1234567890123456789012345678901234567890");
		assert_eq!(order.nonce, U256::from(123));
		assert_eq!(order.inputs.len(), 1);
		assert_eq!(order.inputs[0], [U256::from(1), U256::from(1000)]);
		assert_eq!(order.outputs.len(), 1);
		assert_eq!(order.raw_order_data, None);
		assert_eq!(order.signature, None);
		assert_eq!(order.sponsor, None);
		assert_eq!(order.lock_type, None);
	}

	#[test]
	fn test_output_type_alias() {
		// Test that Output is indeed an alias for MandateOutput
		let output: Output = MandateOutputBuilder::new()
			.oracle([1u8; 32])
			.settler([2u8; 32])
			.chain_id(U256::from(1))
			.token([3u8; 32])
			.amount(U256::from(1000))
			.recipient([4u8; 32])
			.call(vec![0xab, 0xcd])
			.context(vec![0x12, 0x34])
			.build();

		assert_eq!(output.amount, U256::from(1000));
		assert_eq!(output.call, vec![0xab, 0xcd]);
	}

	#[test]
	fn test_hex_string_serialization_empty() {
		use super::hex_string;
		use serde_json;

		#[derive(Serialize)]
		struct TestStruct {
			#[serde(with = "hex_string")]
			data: Vec<u8>,
		}

		let test = TestStruct { data: vec![] };
		let json = serde_json::to_string(&test).unwrap();
		assert_eq!(json, r#"{"data":"0x"}"#);
	}

	#[allow(clippy::clone_on_copy)]
	#[test]
	fn test_clone_and_debug() {
		let lock_type = LockType::Permit2Escrow;
		let cloned = lock_type.clone();
		assert_eq!(lock_type, cloned);

		let debug_str = format!("{:?}", lock_type);
		assert!(debug_str.contains("Permit2Escrow"));

		let overrides = GasLimitOverrides::default();
		let cloned_overrides = overrides.clone();
		assert_eq!(
			overrides.settle_gas_limit,
			cloned_overrides.settle_gas_limit
		);

		let output = MandateOutputBuilder::new()
			.oracle([1u8; 32])
			.settler([2u8; 32])
			.chain_id(U256::from(1))
			.token([3u8; 32])
			.amount(U256::from(1000))
			.recipient([4u8; 32])
			.call(vec![0xab, 0xcd])
			.context(vec![0x12, 0x34])
			.build();
		let cloned_output = output.clone();
		assert_eq!(output.amount, cloned_output.amount);
		assert_eq!(output.call, cloned_output.call);
	}

	#[test]
	fn test_large_values() {
		let large_u256 = U256::MAX;
		let output = MandateOutputBuilder::new()
			.oracle([255u8; 32])
			.settler([0u8; 32])
			.chain_id(large_u256)
			.token([128u8; 32])
			.amount(large_u256)
			.recipient([64u8; 32])
			.call(vec![0; 1000])     // Large call data
			.context(vec![255; 500]) // Large context
			.build();

		// Test serialization/deserialization with large values
		let json = serde_json::to_string(&output).unwrap();
		let deserialized: MandateOutput = serde_json::from_str(&json).unwrap();

		assert_eq!(deserialized.chain_id, large_u256);
		assert_eq!(deserialized.amount, large_u256);
		assert_eq!(deserialized.call.len(), 1000);
		assert_eq!(deserialized.context.len(), 500);
	}
}
