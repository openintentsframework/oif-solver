//! Quote generation engine for cross-chain intent execution.
//!
//! This module orchestrates the creation of executable quotes for cross-chain token transfers.
//! It combines custody decisions, settlement mechanisms, and signature requirements to produce
//! complete quote objects that users can sign and submit for execution.
//!
//! ## Overview
//!
//! The quote generator:
//! - Analyzes available inputs and requested outputs
//! - Determines optimal custody and settlement strategies
//! - Generates appropriate signature payloads
//! - Calculates execution timelines and expiry
//! - Produces multiple quote options when available
//!
//! ## Quote Structure
//!
//! Each generated quote contains:
//! - **Orders**: Signature requirements (EIP-712, ERC-3009, etc.)
//! - **Details**: Input/output specifications
//! - **Validity**: Expiry times and execution windows
//! - **ETA**: Estimated completion time based on chain characteristics
//! - **Provider**: Solver identification
//!
//! ## Generation Process
//!
//! 1. **Input Analysis**: Evaluate each available input for capabilities
//! 2. **Custody Decision**: Determine optimal token custody mechanism
//! 3. **Order Creation**: Generate appropriate signature payloads
//! 4. **Quote Assembly**: Combine all components into executable quotes
//! 5. **Preference Sorting**: Order quotes based on user preferences
//!
//! ## Supported Order Types
//!
//! ### Resource Locks
//! - TheCompact orders with allocation proofs
//! - Custom protocol-specific lock orders
//!
//! ### Escrow Orders
//! - Permit2 batch witness transfers
//! - ERC-3009 authorization transfers
//!
//! ## Optimization Strategies
//!
//! The generator optimizes for:
//! - **Speed**: Minimal execution time across chains
//! - **Cost**: Lowest gas fees and protocol costs
//! - **Trust**: Minimal trust assumptions
//! - **Input Priority**: Preference for specific input tokens

use super::custody::{CustodyDecision, CustodyStrategy, EscrowKind, LockKind};
use crate::apis::quote::permit2::{
	build_permit2_batch_witness_digest, permit2_domain_address_from_config,
};
use crate::eip712::{compact, get_domain_separator};
use solver_config::{Config, QuoteConfig};
use solver_delivery::DeliveryService;
use solver_settlement::{SettlementInterface, SettlementService};
use solver_types::{
	with_0x_prefix, GetQuoteRequest, InteropAddress, Quote, QuoteDetails, QuoteError, QuoteOrder,
	QuotePreference, SignatureType,
};
use std::sync::Arc;
use uuid::Uuid;

/// Quote generation engine with settlement service integration.
pub struct QuoteGenerator {
	custody_strategy: CustodyStrategy,
	/// Reference to settlement service for implementation lookup.
	settlement_service: Arc<SettlementService>,
	/// Reference to delivery service for contract calls.
	delivery_service: Arc<DeliveryService>,
}

impl QuoteGenerator {
	/// Creates a new quote generator.
	///
	/// # Arguments
	/// * `settlement_service` - Service managing settlement implementations
	/// * `delivery_service` - Service for making contract calls
	pub fn new(
		settlement_service: Arc<SettlementService>,
		delivery_service: Arc<DeliveryService>,
	) -> Self {
		Self {
			custody_strategy: CustodyStrategy::new(),
			settlement_service,
			delivery_service,
		}
	}

	pub async fn generate_quotes(
		&self,
		request: &GetQuoteRequest,
		config: &Config,
	) -> Result<Vec<Quote>, QuoteError> {
		let mut quotes = Vec::new();
		for input in &request.available_inputs {
			let custody_decision = self.custody_strategy.decide_custody(input).await?;
			if let Ok(quote) = self
				.generate_quote_for_settlement(request, config, &custody_decision)
				.await
			{
				quotes.push(quote);
			}
		}
		if quotes.is_empty() {
			return Err(QuoteError::InsufficientLiquidity);
		}
		self.sort_quotes_by_preference(&mut quotes, &request.preference);
		Ok(quotes)
	}

	async fn generate_quote_for_settlement(
		&self,
		request: &GetQuoteRequest,
		config: &Config,
		custody_decision: &CustodyDecision,
	) -> Result<Quote, QuoteError> {
		let quote_id = Uuid::new_v4().to_string();
		let order = match custody_decision {
			CustodyDecision::ResourceLock { kind } => {
				self.generate_resource_lock_order(request, config, kind)
					.await?
			},
			CustodyDecision::Escrow { kind } => {
				self.generate_escrow_order(request, config, kind)?
			},
		};
		let details = QuoteDetails {
			requested_outputs: request.requested_outputs.clone(),
			available_inputs: request.available_inputs.clone(),
		};
		let eta = self.calculate_eta(&request.preference);
		let lock_type = match custody_decision {
			CustodyDecision::ResourceLock { .. } => "compact_resource_lock".to_string(),
			CustodyDecision::Escrow { kind } => match kind {
				EscrowKind::Permit2 => "permit2_escrow".to_string(),
				EscrowKind::Erc3009 => "erc3009_escrow".to_string(),
			},
		};
		let validity_seconds = self.get_quote_validity_seconds(config);
		Ok(Quote {
			orders: vec![order],
			details,
			valid_until: Some(chrono::Utc::now().timestamp() as u64 + validity_seconds),
			eta: Some(eta),
			quote_id,
			provider: "oif-solver".to_string(),
			cost: None,
			lock_type,
		})
	}

	async fn generate_resource_lock_order(
		&self,
		request: &GetQuoteRequest,
		config: &Config,
		lock_kind: &LockKind,
	) -> Result<QuoteOrder, QuoteError> {
		let domain_address = self.get_lock_domain_address(config, lock_kind)?;
		let (primary_type, message) = match lock_kind {
			LockKind::TheCompact { params } => (
				"CompactLock".to_string(),
				self.build_compact_message(request, config, params).await?,
			),
		};
		Ok(QuoteOrder {
			signature_type: SignatureType::Eip712,
			domain: domain_address,
			primary_type,
			message,
		})
	}

	fn generate_escrow_order(
		&self,
		request: &GetQuoteRequest,
		config: &Config,
		escrow_kind: &EscrowKind,
	) -> Result<QuoteOrder, QuoteError> {
		// Standard determined by business logic context
		// Currently we only support EIP7683
		let _standard = "eip7683"; // Currently only supporting eip7683

		// Extract chain from first output to find appropriate settlement
		// TODO: Implement support for multiple destination chains
		let chain_id = request
			.requested_outputs
			.first()
			.ok_or_else(|| QuoteError::InvalidRequest("No requested outputs".to_string()))?
			.asset
			.ethereum_chain_id()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid chain ID: {}", e)))?;

		// Get settlement AND selected oracle for consistency
		let (settlement, selected_oracle) = self
			.settlement_service
			.get_any_settlement_for_chain(chain_id)
			.ok_or_else(|| {
				QuoteError::InvalidRequest(format!(
					"No settlement available for chain {}",
					chain_id
				))
			})?;

		match escrow_kind {
			EscrowKind::Permit2 => {
				self.generate_permit2_order(request, config, settlement, selected_oracle)
			},
			EscrowKind::Erc3009 => self.generate_erc3009_order(request, config),
		}
	}

	fn generate_permit2_order(
		&self,
		request: &GetQuoteRequest,
		config: &Config,
		settlement: &dyn SettlementInterface,
		selected_oracle: solver_types::Address,
	) -> Result<QuoteOrder, QuoteError> {
		use alloy_primitives::hex;

		let chain_id = request.available_inputs[0]
			.asset
			.ethereum_chain_id()
			.map_err(|e| {
				QuoteError::InvalidRequest(format!("Invalid chain ID in asset address: {}", e))
			})?;
		let domain_address = permit2_domain_address_from_config(config, chain_id)?;
		let (final_digest, message_obj) =
			build_permit2_batch_witness_digest(request, config, settlement, selected_oracle)?;
		let message = serde_json::json!({ "digest": with_0x_prefix(&hex::encode(final_digest)), "eip712": message_obj });
		Ok(QuoteOrder {
			signature_type: SignatureType::Eip712,
			domain: domain_address,
			primary_type: "PermitBatchWitnessTransferFrom".to_string(),
			message,
		})
	}

	fn generate_erc3009_order(
		&self,
		request: &GetQuoteRequest,
		config: &Config,
	) -> Result<QuoteOrder, QuoteError> {
		let input = &request.available_inputs[0];
		let domain_address = input.asset.clone();
		let validity_seconds = self.get_quote_validity_seconds(config);
		let message = serde_json::json!({
			"from": input.user.ethereum_address().map_err(|e| QuoteError::InvalidRequest(format!("Invalid Ethereum address: {}", e)))?,
			"to": self.get_escrow_address(config)?,
			"value": input.amount.to_string(),
			"validAfter": 0,
			"validBefore": chrono::Utc::now().timestamp() + validity_seconds as i64,
			"nonce": format!("0x{:064x}", chrono::Utc::now().timestamp() as u64)
		});
		Ok(QuoteOrder {
			signature_type: SignatureType::Erc3009,
			domain: domain_address,
			primary_type: "ReceiveWithAuthorization".to_string(),
			message,
		})
	}

	async fn build_compact_message(
		&self,
		request: &GetQuoteRequest,
		config: &Config,
		_params: &serde_json::Value,
	) -> Result<serde_json::Value, QuoteError> {
		use alloy_primitives::{hex, U256};
		use solver_types::utils::bytes20_to_alloy_address;
		use std::str::FromStr;

		let validity_seconds = self.get_quote_validity_seconds(config);
		let current_time = chrono::Utc::now().timestamp() as u64;
		let expires = current_time + validity_seconds;
		let nonce = chrono::Utc::now().timestamp_millis() as u64; // Use milliseconds timestamp as nonce for uniqueness (matching direct intent flow)

		// Get user address
		let user_address = request
			.user
			.ethereum_address()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid user address: {}", e)))?;

		// Get TheCompact domain address (arbiter)
		let domain_address = self.get_lock_domain_address(
			config,
			&super::custody::LockKind::TheCompact {
				params: serde_json::json!({}),
			},
		)?;
		let _arbiter_address = domain_address
			.ethereum_address()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid domain address: {}", e)))?;

		// Get input chain ID from first available input
		let input_chain_id = request
			.available_inputs
			.first()
			.ok_or_else(|| QuoteError::InvalidRequest("No available inputs".to_string()))?
			.asset
			.ethereum_chain_id()
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid input chain ID: {}", e)))?;

		// Get addresses from network configuration
		let network = config.networks.get(&input_chain_id).ok_or_else(|| {
			QuoteError::InvalidRequest(format!("Network {} not found in config", input_chain_id))
		})?;

		// Get settlement and selected oracle for input chain (similar to permit2 flow)
		let (_input_settlement, input_selected_oracle) = self
			.settlement_service
			.get_any_settlement_for_chain(input_chain_id)
			.ok_or_else(|| {
				QuoteError::InvalidRequest(format!(
					"No settlement available for input chain {}",
					input_chain_id
				))
			})?;

		// Convert inputs to the format expected by TheCompact
		// For ResourceLock orders, we need to build the proper token IDs and amounts
		let mut inputs_array = Vec::new();
		for input in &request.available_inputs {
			let token_address = input.asset.ethereum_address().map_err(|e| {
				QuoteError::InvalidRequest(format!("Invalid input token address: {}", e))
			})?;

			// Generate allocator lock tag from address (0x00 + last 11 bytes of address)
			// If allocator address is not configured, fall back to zeroed tag for tests/back-compat
			let allocator_tag = if let Some(allocator_address) = network.allocator_address.as_ref()
			{
				let address_hex = hex::encode(&allocator_address.0);
				format!("0x00{}", &address_hex[address_hex.len() - 22..])
			} else {
				// 12 bytes zero value prefixed with 0x
				"0x000000000000000000000000".to_string()
			};

			// Build token ID by concatenating allocator tag (12 bytes) + token address (20 bytes)
			let token_address_hex = hex::encode(token_address.0);
			let token_id_hex = format!("{}{}", allocator_tag, token_address_hex);
			let token_id = U256::from_str(&token_id_hex).map_err(|e| {
				QuoteError::InvalidRequest(format!("Failed to create token ID: {}", e))
			})?;

			inputs_array.push(serde_json::json!([
				token_id.to_string(),
				input.amount.to_string()
			]));
		}

		// Convert outputs to MandateOutput format
		let mut outputs_array = Vec::new();
		for output in &request.requested_outputs {
			let output_token_address = output.asset.ethereum_address().map_err(|e| {
				QuoteError::InvalidRequest(format!("Invalid output token address: {}", e))
			})?;
			let recipient_address = output.receiver.ethereum_address().map_err(|e| {
				QuoteError::InvalidRequest(format!("Invalid recipient address: {}", e))
			})?;
			let output_chain_id = output.asset.ethereum_chain_id().map_err(|e| {
				QuoteError::InvalidRequest(format!("Invalid output chain ID: {}", e))
			})?;

			// Get settlement and selected oracle for the output chain (like permit2 flow)
			let (_output_settlement, output_selected_oracle) = self
				.settlement_service
				.get_any_settlement_for_chain(output_chain_id)
				.ok_or_else(|| {
					QuoteError::InvalidRequest(format!(
						"No settlement available for output chain {}",
						output_chain_id
					))
				})?;

			// Get output settler from config (like permit2 flow)
			let dest_net = config.networks.get(&output_chain_id).ok_or_else(|| {
				QuoteError::InvalidRequest(format!(
					"Destination chain {} missing from networks config",
					output_chain_id
				))
			})?;
			let output_settler = bytes20_to_alloy_address(&dest_net.output_settler_address.0)
				.map_err(QuoteError::InvalidRequest)?;

			// Convert oracle address (like permit2 flow)
			let output_oracle =
				bytes20_to_alloy_address(&output_selected_oracle.0).map_err(|e| {
					QuoteError::InvalidRequest(format!("Invalid output oracle address: {}", e))
				})?;

			// Build MandateOutput with proper oracle and settler addresses
			outputs_array.push(serde_json::json!({
				"oracle": format!("0x000000000000000000000000{:040x}", output_oracle),
				"settler": format!("0x000000000000000000000000{:040x}", output_settler),
				"chainId": output_chain_id.to_string(),
				"token": format!("0x000000000000000000000000{:040x}", output_token_address),
				"amount": output.amount.to_string(),
				"recipient": format!("0x000000000000000000000000{:040x}", recipient_address),
				"call": output.calldata.as_ref().map(|cd| format!("0x{}", hex::encode(cd))).unwrap_or_else(|| "0x".to_string()),
				"context": "0x" // Context is typically empty for standard flows
			}));
		}

		// Use the selected oracle for input chain as the inputOracle (like permit2 flow)
		let input_oracle = bytes20_to_alloy_address(&input_selected_oracle.0).map_err(|e| {
			QuoteError::InvalidRequest(format!("Invalid input oracle address: {}", e))
		})?;

		// Build the EIP-712 message structure (like permit2 flow)
		// The scripts will compute the digest from this data
		let eip712_message = serde_json::json!({
			"types": {
				"EIP712Domain": [
					{"name": "name", "type": "string"},
					{"name": "version", "type": "string"},
					{"name": "chainId", "type": "uint256"},
					{"name": "verifyingContract", "type": "address"}
				],
				"BatchCompact": [
					{"name": "arbiter", "type": "address"},
					{"name": "sponsor", "type": "address"},
					{"name": "nonce", "type": "uint256"},
					{"name": "expires", "type": "uint256"},
					{"name": "commitments", "type": "Lock[]"},
					{"name": "mandate", "type": "Mandate"}
				],
				"Lock": [
					{"name": "lockTag", "type": "bytes12"},
					{"name": "token", "type": "address"},
					{"name": "amount", "type": "uint256"}
				],
				"Mandate": [
					{"name": "fillDeadline", "type": "uint32"},
					{"name": "inputOracle", "type": "address"},
					{"name": "outputs", "type": "MandateOutput[]"}
				],
				"MandateOutput": [
					{"name": "oracle", "type": "bytes32"},
					{"name": "settler", "type": "bytes32"},
					{"name": "chainId", "type": "uint256"},
					{"name": "token", "type": "bytes32"},
					{"name": "amount", "type": "uint256"},
					{"name": "recipient", "type": "bytes32"},
					{"name": "call", "type": "bytes"},
					{"name": "context", "type": "bytes"}
				]
			},
			"domain": {
				"name": "TheCompact",
				"version": "1",
				"chainId": input_chain_id.to_string(),
				"verifyingContract": format!("0x{:040x}", alloy_primitives::Address::from_slice(&network.the_compact_address.as_ref().unwrap().0))
			},
			"primaryType": "BatchCompact",
			"message": {
				"arbiter": format!("0x{:040x}", alloy_primitives::Address::from_slice(&network.input_settler_compact_address.as_ref().unwrap_or(&network.input_settler_address).0)),
				"sponsor": format!("0x{:040x}", user_address),
				"nonce": nonce.to_string(),
				"expires": expires.to_string(),
				"commitments": inputs_array.iter().map(|input| {
					let input_array = input.as_array().unwrap();
					let token_id_str = input_array[0].as_str().unwrap();
					let amount_str = input_array[1].as_str().unwrap();

					// Extract allocator tag (first 12 bytes) and token address (last 20 bytes) from token ID
					let token_id = U256::from_str(token_id_str).unwrap();
					let token_id_bytes = token_id.to_be_bytes::<32>();
					let lock_tag_hex = format!("0x{}", hex::encode(&token_id_bytes[0..12]));
					let token_addr_hex = format!("0x{}", hex::encode(&token_id_bytes[12..32]));

					serde_json::json!({
						"lockTag": lock_tag_hex,
						"token": token_addr_hex,
						"amount": amount_str
					})
				}).collect::<Vec<_>>(),
				"mandate": {
					"fillDeadline": (current_time + validity_seconds).to_string(),
					"inputOracle": format!("0x{:040x}", input_oracle),
					"outputs": outputs_array
				}
			}
		});

		// Try to compute the digest the same way the tests/contracts expect
		// If this fails, fall back to just providing the EIP-712 structure
		let result_with_digest = match self
			.try_compute_server_digest(&eip712_message, request, network, input_chain_id)
			.await
		{
			Ok(digest) => {
				tracing::debug!(
					"Quote generation: Successfully computed BatchCompact digest: 0x{}",
					alloy_primitives::hex::encode(digest)
				);
				// Return message with both EIP-712 structure and pre-computed digest (like permit2)
				Ok(serde_json::json!({
					"digest": with_0x_prefix(&alloy_primitives::hex::encode(digest)),
					"eip712": eip712_message
				}))
			},
			Err(e) => {
				tracing::warn!("Quote generation: Failed to compute BatchCompact digest, falling back to EIP-712 only: {}", e);
				// Return message in the same format as before (with eip712 field, scripts will compute digest)
				Ok(serde_json::json!({
					"eip712": eip712_message
				}))
			},
		}?;

		// Backward-compatible top-level fields expected by older tests/tools
		let flat_message = serde_json::json!({
			"user": format!("0x{:040x}", user_address),
			"inputs": inputs_array,
			"outputs": outputs_array,
			"nonce": nonce.to_string(),
			"deadline": expires.to_string()
		});

		// Merge flat fields with result (which contains eip712 and optional digest)
		let mut merged = result_with_digest.as_object().cloned().unwrap_or_default();
		if let Some(obj) = flat_message.as_object() {
			for (k, v) in obj.iter() {
				merged.entry(k.clone()).or_insert(v.clone());
			}
		}

		Ok(serde_json::Value::Object(merged))
	}

	/// Try to compute the digest using the existing eip712/compact module
	async fn try_compute_server_digest(
		&self,
		eip712_message: &serde_json::Value,
		_request: &GetQuoteRequest,
		network: &solver_types::NetworkConfig,
		input_chain_id: u64,
	) -> Result<[u8; 32], QuoteError> {
		use alloy_primitives::{keccak256, Address as AlloyAddress, FixedBytes, Uint};
		use alloy_sol_types::SolType;
		use solver_types::standards::eip7683::interfaces::StandardOrder as OifStandardOrder;
		use std::str::FromStr;

		// Build a StandardOrder from the EIP-712 message to use with the compact module
		let message = eip712_message.get("message").ok_or_else(|| {
			QuoteError::InvalidRequest("Missing message in EIP-712 structure".to_string())
		})?;

		// Extract basic fields
		let sponsor_str = message
			.get("sponsor")
			.and_then(|v| v.as_str())
			.ok_or_else(|| QuoteError::InvalidRequest("Missing sponsor in message".to_string()))?;
		let sponsor = AlloyAddress::from_str(&sponsor_str[2..])
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid sponsor address: {}", e)))?;

		let nonce_str = message
			.get("nonce")
			.and_then(|v| v.as_str())
			.ok_or_else(|| QuoteError::InvalidRequest("Missing nonce in message".to_string()))?;
		let nonce = Uint::<256, 4>::from_str(nonce_str)
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid nonce: {}", e)))?;

		let expires_str = message
			.get("expires")
			.and_then(|v| v.as_str())
			.ok_or_else(|| QuoteError::InvalidRequest("Missing expires in message".to_string()))?;
		let expires = u32::from_str(expires_str)
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid expires: {}", e)))?;

		// Extract mandate fields
		let mandate = message
			.get("mandate")
			.ok_or_else(|| QuoteError::InvalidRequest("Missing mandate in message".to_string()))?;
		let fill_deadline_str = mandate
			.get("fillDeadline")
			.and_then(|v| v.as_str())
			.ok_or_else(|| {
				QuoteError::InvalidRequest("Missing fillDeadline in mandate".to_string())
			})?;
		let fill_deadline = u32::from_str(fill_deadline_str)
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid fillDeadline: {}", e)))?;

		let input_oracle_str = mandate
			.get("inputOracle")
			.and_then(|v| v.as_str())
			.ok_or_else(|| {
				QuoteError::InvalidRequest("Missing inputOracle in mandate".to_string())
			})?;
		let input_oracle = AlloyAddress::from_str(&input_oracle_str[2..])
			.map_err(|e| QuoteError::InvalidRequest(format!("Invalid inputOracle: {}", e)))?;

		// Extract inputs from commitments
		let commitments = message
			.get("commitments")
			.and_then(|v| v.as_array())
			.ok_or_else(|| {
				QuoteError::InvalidRequest("Missing commitments in message".to_string())
			})?;

		let mut inputs = Vec::new();
		for commitment in commitments {
			let lock_tag_str = commitment
				.get("lockTag")
				.and_then(|v| v.as_str())
				.ok_or_else(|| {
					QuoteError::InvalidRequest("Missing lockTag in commitment".to_string())
				})?;
			let token_str = commitment
				.get("token")
				.and_then(|v| v.as_str())
				.ok_or_else(|| {
					QuoteError::InvalidRequest("Missing token in commitment".to_string())
				})?;
			let amount_str = commitment
				.get("amount")
				.and_then(|v| v.as_str())
				.ok_or_else(|| {
					QuoteError::InvalidRequest("Missing amount in commitment".to_string())
				})?;

			// Reconstruct token ID from lock_tag + token_address
			let lock_tag_bytes = alloy_primitives::hex::decode(&lock_tag_str[2..])
				.map_err(|e| QuoteError::InvalidRequest(format!("Invalid lockTag hex: {}", e)))?;
			let token_bytes = alloy_primitives::hex::decode(&token_str[2..])
				.map_err(|e| QuoteError::InvalidRequest(format!("Invalid token hex: {}", e)))?;

			// Combine lock_tag (12 bytes) + token_address (20 bytes) to form token_id (32 bytes)
			let mut token_id_bytes = [0u8; 32];
			token_id_bytes[0..12].copy_from_slice(&lock_tag_bytes);
			token_id_bytes[12..32].copy_from_slice(&token_bytes);
			let token_id = Uint::<256, 4>::from_be_bytes(token_id_bytes);

			let amount = Uint::<256, 4>::from_str(amount_str)
				.map_err(|e| QuoteError::InvalidRequest(format!("Invalid amount: {}", e)))?;

			inputs.push([token_id, amount]);
		}

		// Extract outputs
		let outputs_array = mandate
			.get("outputs")
			.and_then(|v| v.as_array())
			.ok_or_else(|| QuoteError::InvalidRequest("Missing outputs in mandate".to_string()))?;

		use solver_types::standards::eip7683::interfaces::SolMandateOutput as MandateOutput;
		let mut outputs = Vec::new();
		for output in outputs_array {
			let oracle_str = output
				.get("oracle")
				.and_then(|v| v.as_str())
				.ok_or_else(|| {
					QuoteError::InvalidRequest("Missing oracle in output".to_string())
				})?;
			let oracle = FixedBytes::<32>::from_str(oracle_str)
				.map_err(|e| QuoteError::InvalidRequest(format!("Invalid oracle: {}", e)))?;

			let settler_str = output
				.get("settler")
				.and_then(|v| v.as_str())
				.ok_or_else(|| {
					QuoteError::InvalidRequest("Missing settler in output".to_string())
				})?;
			let settler = FixedBytes::<32>::from_str(settler_str)
				.map_err(|e| QuoteError::InvalidRequest(format!("Invalid settler: {}", e)))?;

			let chain_id_str = output
				.get("chainId")
				.and_then(|v| v.as_str())
				.ok_or_else(|| {
					QuoteError::InvalidRequest("Missing chainId in output".to_string())
				})?;
			let chain_id = Uint::<256, 4>::from_str(chain_id_str)
				.map_err(|e| QuoteError::InvalidRequest(format!("Invalid chainId: {}", e)))?;

			let token_str = output
				.get("token")
				.and_then(|v| v.as_str())
				.ok_or_else(|| QuoteError::InvalidRequest("Missing token in output".to_string()))?;
			let token = FixedBytes::<32>::from_str(token_str)
				.map_err(|e| QuoteError::InvalidRequest(format!("Invalid token: {}", e)))?;

			let amount_str = output
				.get("amount")
				.and_then(|v| v.as_str())
				.ok_or_else(|| {
					QuoteError::InvalidRequest("Missing amount in output".to_string())
				})?;
			let amount = Uint::<256, 4>::from_str(amount_str)
				.map_err(|e| QuoteError::InvalidRequest(format!("Invalid amount: {}", e)))?;

			let recipient_str = output
				.get("recipient")
				.and_then(|v| v.as_str())
				.ok_or_else(|| {
					QuoteError::InvalidRequest("Missing recipient in output".to_string())
				})?;
			let recipient = FixedBytes::<32>::from_str(recipient_str)
				.map_err(|e| QuoteError::InvalidRequest(format!("Invalid recipient: {}", e)))?;

			let call_str = output.get("call").and_then(|v| v.as_str()).unwrap_or("0x");
			let call = if call_str == "0x" {
				alloy_primitives::Bytes::new()
			} else {
				alloy_primitives::Bytes::from(
					alloy_primitives::hex::decode(&call_str[2..]).map_err(|e| {
						QuoteError::InvalidRequest(format!("Invalid call data: {}", e))
					})?,
				)
			};

			let context_str = output
				.get("context")
				.and_then(|v| v.as_str())
				.unwrap_or("0x");
			let context = if context_str == "0x" {
				alloy_primitives::Bytes::new()
			} else {
				alloy_primitives::Bytes::from(
					alloy_primitives::hex::decode(&context_str[2..]).map_err(|e| {
						QuoteError::InvalidRequest(format!("Invalid context data: {}", e))
					})?,
				)
			};

			outputs.push(MandateOutput {
				oracle,
				settler,
				chainId: chain_id,
				token,
				amount,
				recipient,
				call,
				context,
			});
		}

		// Build the StandardOrder
		let standard_order = OifStandardOrder {
			user: sponsor,
			nonce,
			originChainId: Uint::<256, 4>::from(input_chain_id),
			expires,
			fillDeadline: fill_deadline,
			inputOracle: input_oracle,
			inputs,
			outputs,
		};

		// Encode the order to use with the compact module
		let order_bytes = OifStandardOrder::abi_encode(&standard_order);

		// Use the same contract address logic as the signature validator
		let contract_address = {
			let addr = network
				.input_settler_compact_address
				.clone()
				.unwrap_or_else(|| network.input_settler_address.clone());
			AlloyAddress::from_slice(&addr.0)
		};

		// Use the existing compact module to compute the message hash
		let struct_hash = compact::compute_batch_compact_hash(&order_bytes, contract_address)
			.map_err(|e| {
				QuoteError::InvalidRequest(format!("Failed to compute batch compact hash: {}", e))
			})?;

		// Get domain separator from TheCompact contract
		let the_compact_address = network.the_compact_address.as_ref().ok_or_else(|| {
			QuoteError::InvalidRequest("TheCompact address not configured".to_string())
		})?;
		let domain_separator =
			get_domain_separator(&self.delivery_service, the_compact_address, input_chain_id)
				.await
				.map_err(|e| {
					QuoteError::InvalidRequest(format!("Failed to get domain separator: {}", e))
				})?;

		// Compute final EIP-712 digest
		let digest_data = [&[0x19, 0x01][..], &domain_separator[..], &struct_hash[..]].concat();
		let final_digest = keccak256(&digest_data);

		Ok(final_digest.into())
	}

	fn get_lock_domain_address(
		&self,
		config: &Config,
		lock_kind: &LockKind,
	) -> Result<InteropAddress, QuoteError> {
		match &config.settlement.domain {
			Some(domain_config) => {
				let address = domain_config.address.parse().map_err(|e| {
					QuoteError::InvalidRequest(format!("Invalid domain address in config: {}", e))
				})?;
				Ok(InteropAddress::new_ethereum(
					domain_config.chain_id,
					address,
				))
			},
			None => Err(QuoteError::InvalidRequest(format!(
				"Domain configuration required for lock type: {:?}",
				lock_kind
			))),
		}
	}

	fn get_escrow_address(&self, config: &Config) -> Result<alloy_primitives::Address, QuoteError> {
		match &config.settlement.domain {
			Some(domain_config) => domain_config.address.parse().map_err(|e| {
				QuoteError::InvalidRequest(format!("Invalid escrow address in config: {}", e))
			}),
			None => Err(QuoteError::InvalidRequest(
				"Escrow address configuration required".to_string(),
			)),
		}
	}

	fn calculate_eta(&self, preference: &Option<QuotePreference>) -> u64 {
		let base_eta = 120u64;
		match preference {
			Some(QuotePreference::Speed) => (base_eta as f64 * 0.8) as u64,
			Some(QuotePreference::Price) => (base_eta as f64 * 1.2) as u64,
			Some(QuotePreference::TrustMinimization) => (base_eta as f64 * 1.5) as u64,
			_ => base_eta,
		}
	}

	fn sort_quotes_by_preference(
		&self,
		quotes: &mut [Quote],
		preference: &Option<QuotePreference>,
	) {
		match preference {
			Some(QuotePreference::Speed) => quotes.sort_by(|a, b| match (a.eta, b.eta) {
				(Some(eta_a), Some(eta_b)) => eta_a.cmp(&eta_b),
				(Some(_), None) => std::cmp::Ordering::Less,
				(None, Some(_)) => std::cmp::Ordering::Greater,
				(None, None) => std::cmp::Ordering::Equal,
			}),
			Some(QuotePreference::InputPriority) => {},
			Some(QuotePreference::Price) | Some(QuotePreference::TrustMinimization) | None => {},
		}
	}

	/// Gets the quote validity duration from configuration.
	///
	/// Returns the configured validity seconds from api.quote config or default.
	fn get_quote_validity_seconds(&self, config: &Config) -> u64 {
		config
			.api
			.as_ref()
			.and_then(|api| api.quote.as_ref())
			.map(|quote| quote.validity_seconds)
			.unwrap_or_else(|| QuoteConfig::default().validity_seconds)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::apis::quote::custody::{CustodyDecision, EscrowKind, LockKind};
	use alloy_primitives::address;
	use alloy_primitives::U256;
	use solver_config::{
		ApiConfig, Config, ConfigBuilder, DomainConfig, QuoteConfig, SettlementConfig,
	};
	use solver_settlement::{MockSettlementInterface, SettlementInterface};
	use solver_types::parse_address;
	use solver_types::{
		utils::tests::builders::{NetworkConfigBuilder, NetworksConfigBuilder},
		AvailableInput, QuotePreference, RequestedOutput, SignatureType,
	};
	use std::collections::HashMap;

	fn create_test_config() -> Config {
		// Create API configuration with quote settings
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
				validity_seconds: 300,
			}),
		};

		// Create settlement configuration with domain
		let settlement_config = SettlementConfig {
			implementations: HashMap::new(),
			domain: Some(DomainConfig {
				chain_id: 1,
				address: "0x1234567890123456789012345678901234567890".to_string(),
			}),
			settlement_poll_interval_seconds: 3,
		};

		// Build network configurations using builder pattern
		let networks = NetworksConfigBuilder::new()
			.add_network(1, NetworkConfigBuilder::new().build())
			.add_network(137, NetworkConfigBuilder::new().build())
			.build();

		// Create config using ConfigBuilder with complete fluent API
		ConfigBuilder::new()
			.api(Some(api_config))
			.settlement(settlement_config)
			.networks(networks)
			.build()
	}

	fn create_test_request() -> GetQuoteRequest {
		GetQuoteRequest {
			user: InteropAddress::new_ethereum(
				1,
				address!("1111111111111111111111111111111111111111"),
			),
			available_inputs: vec![AvailableInput {
				user: InteropAddress::new_ethereum(
					1,
					address!("1111111111111111111111111111111111111111"),
				),
				asset: InteropAddress::new_ethereum(
					1,
					address!("A0b86a33E6441b8C6A7f4C5C1C5C5C5C5C5C5C5C"),
				),
				amount: U256::from(1000),
				lock: None,
			}],
			requested_outputs: vec![RequestedOutput {
				receiver: InteropAddress::new_ethereum(
					137,
					address!("2222222222222222222222222222222222222222"),
				),
				asset: InteropAddress::new_ethereum(
					137,
					address!("B0b86a33E6441b8C6A7f4C5C1C5C5C5C5C5C5C5C"),
				),
				amount: U256::from(950),
				calldata: None,
			}],
			min_valid_until: None,
			preference: Some(QuotePreference::Speed),
		}
	}

	fn create_test_settlement_service(with_oracles: bool) -> Arc<SettlementService> {
		use solver_types::Address;

		let mut input_oracles = HashMap::new();
		let mut output_oracles = HashMap::new();
		let mut routes = HashMap::new();

		if with_oracles {
			// Add input oracles for both chains (since get_any_settlement_for_chain looks for input oracles)
			input_oracles.insert(1, vec![Address(vec![0xaa; 20])]);
			input_oracles.insert(137, vec![Address(vec![0xcc; 20])]);
			// Add output oracles for both chains
			output_oracles.insert(1, vec![Address(vec![0xbb; 20])]);
			output_oracles.insert(137, vec![Address(vec![0xdd; 20])]);
			// Add routes between chains
			routes.insert(1, vec![137]);
			routes.insert(137, vec![1]);
		}

		let mut mock_settlement = MockSettlementInterface::new();
		mock_settlement
			.expect_oracle_config()
			.return_const(solver_settlement::OracleConfig {
				input_oracles,
				output_oracles,
				routes,
				selection_strategy: solver_settlement::OracleSelectionStrategy::First,
			});

		if with_oracles {
			// Mock the select_oracle method to return the first oracle
			mock_settlement
				.expect_select_oracle()
				.returning(|oracles, _context| oracles.first().cloned());
		}

		let mut implementations: HashMap<String, Box<dyn SettlementInterface>> = HashMap::new();
		implementations.insert("test".to_string(), Box::new(mock_settlement));

		Arc::new(SettlementService::new(implementations, 3))
	}

	#[tokio::test]
	async fn test_generate_quotes_success() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service = Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);
		let config = create_test_config();
		let request = create_test_request();

		let result = generator.generate_quotes(&request, &config).await;

		// Should succeed since we have properly configured oracles
		assert!(result.is_ok());
		let quotes = result.unwrap();
		assert!(!quotes.is_empty());

		let quote = &quotes[0];
		assert_eq!(quote.provider, "oif-solver");
		assert!(quote.valid_until.is_some());
		assert!(quote.eta.is_some());
		assert_eq!(quote.eta.unwrap(), 96); // Speed preference: 120 * 0.8
		assert!(!quote.orders.is_empty());
		assert!(!quote.quote_id.is_empty());

		// Verify quote details
		assert_eq!(quote.details.available_inputs.len(), 1);
		assert_eq!(quote.details.requested_outputs.len(), 1);
	}

	#[tokio::test]
	async fn test_generate_quotes_no_oracles_configured() {
		let settlement_service = create_test_settlement_service(false);
		let delivery_service = Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);
		let config = create_test_config();
		let request = create_test_request();

		let result = generator.generate_quotes(&request, &config).await;

		// Should fail with insufficient liquidity since our mock settlement has no oracles configured
		assert!(matches!(result, Err(QuoteError::InsufficientLiquidity)));
	}

	#[tokio::test]
	async fn test_generate_quotes_insufficient_liquidity() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service = Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);
		let config = create_test_config();

		// Create request with no available inputs
		let request = GetQuoteRequest {
			user: InteropAddress::new_ethereum(
				1,
				address!("1111111111111111111111111111111111111111"),
			),
			available_inputs: vec![],
			requested_outputs: vec![RequestedOutput {
				receiver: InteropAddress::new_ethereum(
					137,
					address!("2222222222222222222222222222222222222222"),
				),
				asset: InteropAddress::new_ethereum(
					137,
					address!("B0b86a33E6441b8C6A7f4C5C1C5C5C5C5C5C5C5C"),
				),
				amount: U256::from(950),
				calldata: None,
			}],
			min_valid_until: None,
			preference: Some(QuotePreference::Speed),
		};

		let result = generator.generate_quotes(&request, &config).await;
		assert!(matches!(result, Err(QuoteError::InsufficientLiquidity)));
	}

	#[tokio::test]
	async fn test_generate_resource_lock_order_the_compact() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service = Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);
		let config = create_test_config();
		let request = create_test_request();

		let lock_kind = LockKind::TheCompact {
			params: serde_json::json!({"test": "value"}),
		};

		let result = generator
			.generate_resource_lock_order(&request, &config, &lock_kind)
			.await;

		match result {
			Ok(order) => {
				assert_eq!(order.signature_type, SignatureType::Eip712);
				assert_eq!(order.primary_type, "CompactLock");
				assert!(order.message.is_object());
			},
			Err(e) => {
				// Expected if domain configuration is missing
				assert!(matches!(e, QuoteError::InvalidRequest(_)));
			},
		}
	}

	#[test]
	fn test_generate_erc3009_order() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service = Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);
		let config = create_test_config();
		let request = create_test_request();

		let result = generator.generate_erc3009_order(&request, &config);

		match result {
			Ok(order) => {
				assert_eq!(order.signature_type, SignatureType::Erc3009);
				assert_eq!(order.primary_type, "ReceiveWithAuthorization");
				assert!(order.message.is_object());

				// Verify message structure
				let message = order.message.as_object().unwrap();
				assert!(message.contains_key("from"));
				assert!(message.contains_key("to"));
				assert!(message.contains_key("value"));
				assert!(message.contains_key("validAfter"));
				assert!(message.contains_key("validBefore"));
				assert!(message.contains_key("nonce"));
			},
			Err(e) => {
				// Expected if escrow address configuration is missing
				assert!(matches!(e, QuoteError::InvalidRequest(_)));
			},
		}
	}

	#[tokio::test]
	async fn test_build_compact_message() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service = Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);
		let request = create_test_request();
		let params = serde_json::json!({"test": "value"});
		let mut config = create_test_config();
		let bsc_network = NetworkConfigBuilder::new()
			.input_settler_address(
				parse_address("0x5555555555555555555555555555555555555555").unwrap(),
			)
			.output_settler_address(
				parse_address("0x6666666666666666666666666666666666666666").unwrap(),
			)
			.allocator_address(parse_address("0x7777777777777777777777777777777777777777").unwrap())
			.build();

		config.networks.insert(56, bsc_network);

		let result = generator
			.build_compact_message(&request, &config, &params)
			.await;

		assert!(result.is_ok());
		let message = result.unwrap();
		assert!(message.is_object());

		let message_obj = message.as_object().unwrap();
		assert!(message_obj.contains_key("user"));
		assert!(message_obj.contains_key("inputs"));
		assert!(message_obj.contains_key("outputs"));
		assert!(message_obj.contains_key("nonce"));
		assert!(message_obj.contains_key("deadline"));
	}

	#[test]
	fn test_calculate_eta_with_preferences() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service = Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);

		// Test speed preference
		let speed_eta = generator.calculate_eta(&Some(QuotePreference::Speed));
		assert_eq!(speed_eta, 96); // 120 * 0.8

		// Test price preference
		let price_eta = generator.calculate_eta(&Some(QuotePreference::Price));
		assert_eq!(price_eta, 144); // 120 * 1.2

		// Test trust minimization preference
		let trust_eta = generator.calculate_eta(&Some(QuotePreference::TrustMinimization));
		assert_eq!(trust_eta, 180); // 120 * 1.5

		// Test no preference
		let default_eta = generator.calculate_eta(&None);
		assert_eq!(default_eta, 120);

		// Test input priority (should use default)
		let input_eta = generator.calculate_eta(&Some(QuotePreference::InputPriority));
		assert_eq!(input_eta, 120);
	}

	#[test]
	fn test_sort_quotes_by_preference_speed() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service = Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);

		let mut quotes = vec![
			Quote {
				orders: vec![],
				details: QuoteDetails {
					requested_outputs: vec![],
					available_inputs: vec![],
				},
				valid_until: None,
				eta: Some(200),
				quote_id: "quote1".to_string(),
				provider: "test".to_string(),
				cost: None,
				lock_type: "permit2_escrow".to_string(),
			},
			Quote {
				orders: vec![],
				details: QuoteDetails {
					requested_outputs: vec![],
					available_inputs: vec![],
				},
				valid_until: None,
				eta: Some(100),
				quote_id: "quote2".to_string(),
				provider: "test".to_string(),
				cost: None,
				lock_type: "permit2_escrow".to_string(),
			},
			Quote {
				orders: vec![],
				details: QuoteDetails {
					requested_outputs: vec![],
					available_inputs: vec![],
				},
				valid_until: None,
				eta: None,
				quote_id: "quote3".to_string(),
				provider: "test".to_string(),
				cost: None,
				lock_type: "permit2_escrow".to_string(),
			},
		];

		generator.sort_quotes_by_preference(&mut quotes, &Some(QuotePreference::Speed));

		// Should be sorted by ETA ascending (fastest first)
		assert_eq!(quotes[0].eta, Some(100));
		assert_eq!(quotes[1].eta, Some(200));
		assert_eq!(quotes[2].eta, None); // None should be last
	}

	#[test]
	fn test_sort_quotes_by_preference_other() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service = Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);

		let mut quotes = vec![
			Quote {
				orders: vec![],
				details: QuoteDetails {
					requested_outputs: vec![],
					available_inputs: vec![],
				},
				valid_until: None,
				eta: Some(200),
				quote_id: "quote1".to_string(),
				provider: "test".to_string(),
				cost: None,
				lock_type: "permit2_escrow".to_string(),
			},
			Quote {
				orders: vec![],
				details: QuoteDetails {
					requested_outputs: vec![],
					available_inputs: vec![],
				},
				valid_until: None,
				eta: Some(100),
				quote_id: "quote2".to_string(),
				provider: "test".to_string(),
				cost: None,
				lock_type: "permit2_escrow".to_string(),
			},
		];

		let original_order = quotes.clone();

		// Test that other preferences don't change order
		generator.sort_quotes_by_preference(&mut quotes, &Some(QuotePreference::Price));
		assert_eq!(quotes[0].quote_id, original_order[0].quote_id);
		assert_eq!(quotes[1].quote_id, original_order[1].quote_id);

		generator.sort_quotes_by_preference(&mut quotes, &Some(QuotePreference::TrustMinimization));
		assert_eq!(quotes[0].quote_id, original_order[0].quote_id);
		assert_eq!(quotes[1].quote_id, original_order[1].quote_id);

		generator.sort_quotes_by_preference(&mut quotes, &Some(QuotePreference::InputPriority));
		assert_eq!(quotes[0].quote_id, original_order[0].quote_id);
		assert_eq!(quotes[1].quote_id, original_order[1].quote_id);

		generator.sort_quotes_by_preference(&mut quotes, &None);
		assert_eq!(quotes[0].quote_id, original_order[0].quote_id);
		assert_eq!(quotes[1].quote_id, original_order[1].quote_id);
	}

	#[test]
	fn test_get_quote_validity_seconds() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service = Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);

		// Test with configured validity
		let config = create_test_config();
		let validity = generator.get_quote_validity_seconds(&config);
		assert_eq!(validity, 300);

		// Test with no API config (should use default)
		let config_no_api = ConfigBuilder::new().build();
		let validity_default = generator.get_quote_validity_seconds(&config_no_api);
		assert_eq!(validity_default, 20); // if API none, use default 20
	}

	#[test]
	fn test_get_lock_domain_address_success() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service = Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);
		let config = create_test_config();
		let lock_kind = LockKind::TheCompact {
			params: serde_json::json!({}),
		};

		let result = generator.get_lock_domain_address(&config, &lock_kind);
		assert!(result.is_ok());

		let domain = result.unwrap();
		assert_eq!(domain.ethereum_chain_id().unwrap(), 1);
	}

	#[test]
	fn test_get_lock_domain_address_missing_config() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service = Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);
		let mut config = create_test_config();
		config.settlement.domain = None;

		let lock_kind = LockKind::TheCompact {
			params: serde_json::json!({}),
		};

		let result = generator.get_lock_domain_address(&config, &lock_kind);
		assert!(matches!(result, Err(QuoteError::InvalidRequest(_))));
	}

	#[test]
	fn test_get_escrow_address_success() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service = Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);
		let config = create_test_config();

		let result = generator.get_escrow_address(&config);
		assert!(result.is_ok());
	}

	#[test]
	fn test_get_escrow_address_missing_config() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service = Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);
		let mut config = create_test_config();
		config.settlement.domain = None;

		let result = generator.get_escrow_address(&config);
		assert!(matches!(result, Err(QuoteError::InvalidRequest(_))));
	}

	#[test]
	fn test_get_escrow_address_invalid_address() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service = Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);
		let mut config = create_test_config();
		config.settlement.domain.as_mut().unwrap().address = "invalid_address".to_string();

		let result = generator.get_escrow_address(&config);
		assert!(matches!(result, Err(QuoteError::InvalidRequest(_))));
	}

	#[tokio::test]
	async fn test_generate_quote_for_settlement_resource_lock() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service = Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);
		let config = create_test_config();
		let request = create_test_request();

		let custody_decision = CustodyDecision::ResourceLock {
			kind: LockKind::TheCompact {
				params: serde_json::json!({}),
			},
		};

		let result = generator
			.generate_quote_for_settlement(&request, &config, &custody_decision)
			.await;

		match result {
			Ok(quote) => {
				assert!(!quote.quote_id.is_empty());
				assert_eq!(quote.provider, "oif-solver");
				assert!(quote.valid_until.is_some());
				assert!(quote.eta.is_some());
				assert_eq!(quote.orders.len(), 1);
				assert_eq!(quote.orders[0].signature_type, SignatureType::Eip712);
			},
			Err(e) => {
				// Expected if domain configuration is incomplete
				assert!(matches!(e, QuoteError::InvalidRequest(_)));
			},
		}
	}

	#[tokio::test]
	async fn test_generate_quote_for_settlement_escrow() {
		let settlement_service = create_test_settlement_service(true);
		let delivery_service = Arc::new(solver_delivery::DeliveryService::new(HashMap::new(), 1));
		let generator = QuoteGenerator::new(settlement_service, delivery_service);
		let config = create_test_config();
		let request = create_test_request();

		let custody_decision = CustodyDecision::Escrow {
			kind: EscrowKind::Erc3009,
		};

		let result = generator
			.generate_quote_for_settlement(&request, &config, &custody_decision)
			.await;

		match result {
			Ok(quote) => {
				assert!(!quote.quote_id.is_empty());
				assert_eq!(quote.provider, "oif-solver");
				assert!(quote.valid_until.is_some());
				assert!(quote.eta.is_some());
				assert_eq!(quote.orders.len(), 1);
				assert_eq!(quote.orders[0].signature_type, SignatureType::Erc3009);
			},
			Err(e) => {
				// Expected due to missing settlement service setup or invalid request
				assert!(matches!(
					e,
					QuoteError::InvalidRequest(_) | QuoteError::UnsupportedSettlement(_)
				));
			},
		}
	}
}
